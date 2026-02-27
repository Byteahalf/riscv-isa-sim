// See LICENSE for license details.

#include "config.h"
#include "processor.h"
#include "mmu.h"
#include "disasm.h"
#include "decode_macros.h"
#include <cassert>

static void commit_log_reset(processor_t* p)
{
  p->get_state()->log_reg_write.clear();
  p->get_state()->log_mem_read.clear();
  p->get_state()->log_mem_write.clear();
}

static void commit_log_stash_privilege(processor_t* p)
{
  state_t* state = p->get_state();
  state->last_inst_priv = state->prv;
  state->last_inst_xlen = p->get_xlen();
  state->last_inst_flen = p->get_flen();
}

static void commit_log_print_value(FILE *log_file, int width, const void *data)
{
  assert(log_file);

  switch (width) {
    case 8:
      fprintf(log_file, "0x%02" PRIx8, *(const uint8_t *)data);
      break;
    case 16:
      fprintf(log_file, "0x%04" PRIx16, *(const uint16_t *)data);
      break;
    case 32:
      fprintf(log_file, "0x%08" PRIx32, *(const uint32_t *)data);
      break;
    case 64:
      fprintf(log_file, "0x%016" PRIx64, *(const uint64_t *)data);
      break;
    default:
      if (width % 8 == 0) {
        const uint8_t *arr = (const uint8_t *)data;

        fprintf(log_file, "0x");
        for (int idx = width / 8 - 1; idx >= 0; --idx) {
          fprintf(log_file, "%02" PRIx8, arr[idx]);
        }
      } else {
        abort();
      }
      break;
  }
}

static void commit_log_print_value(FILE *log_file, int width, uint64_t val)
{
  commit_log_print_value(log_file, width, &val);
}

static void commit_log_print_insn(processor_t *p, reg_t pc, insn_t insn)
{
  FILE *log_file = p->get_log_file();

  auto& reg = p->get_state()->log_reg_write;
  auto& load = p->get_state()->log_mem_read;
  auto& store = p->get_state()->log_mem_write;
  int priv = p->get_state()->last_inst_priv;
  int xlen = p->get_state()->last_inst_xlen;
  int flen = p->get_state()->last_inst_flen;

  // print core id on all lines so it is easy to grep
  fprintf(log_file, "core%4" PRId32 ": ", p->get_id());

  fprintf(log_file, "%1d ", priv);
  commit_log_print_value(log_file, xlen, pc);
  fprintf(log_file, " (");
  commit_log_print_value(log_file, insn.length() * 8, insn.bits());
  fprintf(log_file, ")");
  bool show_vec = false;

  for (auto item : reg) {
    if (item.first == 0)
      continue;

    char prefix = ' ';
    int size;
    int rd = item.first >> 4;
    bool is_vec = false;
    bool is_vreg = false;
    switch (item.first & 0xf) {
    case 0:
      size = xlen;
      prefix = 'x';
      break;
    case 1:
      size = flen;
      prefix = 'f';
      break;
    case 2:
      size = p->VU.VLEN;
      prefix = 'v';
      is_vreg = true;
      break;
    case 3:
      is_vec = true;
      break;
    case 4:
      size = xlen;
      prefix = 'c';
      break;
    default:
      assert("can't been here" && 0);
      break;
    }

    if (!show_vec && (is_vreg || is_vec)) {
        fprintf(log_file, " e%ld %s%ld l%ld",
                (long)p->VU.vsew,
                p->VU.vflmul < 1 ? "mf" : "m",
                p->VU.vflmul < 1 ? (long)(1 / p->VU.vflmul) : (long)p->VU.vflmul,
                (long)p->VU.vl->read());
        show_vec = true;
    }

    if (!is_vec) {
      if (prefix == 'c')
        fprintf(log_file, " c%d_%s ", rd, csr_name(rd));
      else
        fprintf(log_file, " %c%-2d ", prefix, rd);
      if (is_vreg)
        commit_log_print_value(log_file, size, &p->VU.elt<uint8_t>(rd, 0));
      else
        commit_log_print_value(log_file, size, item.second.v);
    }
  }

  for (auto item : load) {
    fprintf(log_file, " mem ");
    commit_log_print_value(log_file, xlen, std::get<0>(item));
  }

  for (auto item : store) {
    fprintf(log_file, " mem ");
    commit_log_print_value(log_file, xlen, std::get<0>(item));
    fprintf(log_file, " ");
    commit_log_print_value(log_file, std::get<2>(item) << 3, std::get<1>(item));
  }
  fprintf(log_file, "\n");
}

inline void processor_t::update_histogram(reg_t pc)
{
  if (histogram_enabled)
    pc_histogram[pc]++;
}

// These two functions are expected to be inlined by the compiler separately in
// the processor_t::step() loop. The logged variant is used in the slow path
static inline reg_t execute_insn_fast(processor_t* p, reg_t pc, insn_fetch_t fetch) {
  return fetch.func(p, fetch.insn, pc);
}
static inline reg_t execute_insn_logged(processor_t* p, reg_t pc, insn_fetch_t fetch)
{
  if (p->get_log_commits_enabled()) {
    commit_log_reset(p);
    commit_log_stash_privilege(p);
  }

  reg_t npc;

  try {
    npc = fetch.func(p, fetch.insn, pc);
    if (npc != PC_SERIALIZE_BEFORE) {
      if (p->get_log_commits_enabled()) {
        commit_log_print_insn(p, pc, fetch.insn);
      }
     }
  } catch (wait_for_interrupt_t &t) {
      if (p->get_log_commits_enabled()) {
        commit_log_print_insn(p, pc, fetch.insn);
      }
      throw;
  } catch(mem_trap_t& t) {
      //handle segfault in midlle of vector load/store
      if (p->get_log_commits_enabled()) {
        for (auto item : p->get_state()->log_reg_write) {
          if ((item.first & 3) == 3) {
            commit_log_print_insn(p, pc, fetch.insn);
            break;
          }
        }
      }
      throw;
  } catch(...) {
    throw;
  }
  p->update_histogram(pc);

  return npc;
}

bool processor_t::slow_path() const
{
  return debug || state.single_step != state.STEP_NONE || state.debug_mode ||
         log_commits_enabled || histogram_enabled || in_wfi || check_triggers_icount;
}

static bool insn_is_read(insn_t insn)
{
    if (insn.length() == 2)
    {
        // Compressed (C extension)
        uint64_t op = insn.rvc_opcode();
        uint64_t f3 = insn.funct3();
        // Quadrant 0 (00)
        if (op == 0b00)
        {
            // C.LW / C.LD / C.FLW / C.FLD
            if (f3 == 0b010 || f3 == 0b011)
                return true;
        }
        // Quadrant 2 (10)
        if (op == 0b10)
        {
            // C.LWSP / C.LDSP / C.FLWSP / C.FLDSP
            if (f3 == 0b010 || f3 == 0b011)
                return true;
        }
        return false;
    }
    uint64_t opc = insn.opcode();
    switch (opc)
    {
        case 0x03: // Integer Load
            return true;
        case 0x07: // Float / Vector Load
            return true;
        case 0x2F: // Atomic
        {
            uint64_t funct5 = insn.funct7() >> 2;
            // LR: funct5 == 0b00010
            if (funct5 == 0b00010)
                return true;
            // AMO: all others except SC
            // SC: funct5 == 0b00011
            if (funct5 != 0b00011)
                return true;
            return false;
        }
        default:
            return false;
    }
}
static bool insn_is_write(insn_t insn)
{
    if (insn.length() == 2)
    {
        // Compressed (C extension)
        uint64_t op = insn.rvc_opcode();
        uint64_t f3 = insn.funct3();
        // Quadrant 0 (00)
        if (op == 0b00)
        {
            // C.SW / C.SD / C.FSW / C.FSD
            if (f3 == 0b110 || f3 == 0b111)
                return true;
        }
        // Quadrant 2 (10)
        if (op == 0b10)
        {
            // C.SWSP / C.SDSP / C.FSWSP / C.FSDSP
            if (f3 == 0b110 || f3 == 0b111)
                return true;
        }
        return false;
    }

    uint64_t opc = insn.opcode();

    switch (opc)
    {
        case 0x23: // Integer Store
            return true;
        case 0x27: // Float / Vector Store
            return true;
        case 0x2F: // Atomic
        {
            uint64_t funct5 = insn.funct7() >> 2;

            // SC
            if (funct5 == 0b00011)
                return true;

            // AMO (read + write)
            if (funct5 != 0b00010)
                return true;

            return false;
        }
        default:
            return false;
    }
}

static int64_t sign_extend_u64(uint64_t v, unsigned bits)
{
    uint64_t mask = (bits == 64) ? ~0ull : ((1ull << bits) - 1ull);
    uint64_t x = v & mask;
    uint64_t sign = 1ull << (bits - 1);
    if (x & sign)
        x |= ~mask;
    return static_cast<int64_t>(x);
}

void processor_t::read_next_trace()
{
  static reg_t mem_addr_ref = 0;

  if (current_trace_index < static_cast<int64_t>(trace_data.size()) - 1)
  {
    current_trace_index++;
    current_trace = trace_data[current_trace_index];
    trace_finish = false;
    printf("Trace Recovered @ %ld: PC=%lx, retire=%ld, type=%ld\n", trace_finish, current_trace.pc, current_trace.retire, current_trace.trace_type);

    if (current_trace.trace_type == 1) { // For mem, recover original address
      if (auto* mp = std::get_if<mem_payload_t>(&current_trace.payload)){
        switch (mp->compress_mode & 0x3) {
          case 0: // ABS
            mem_addr_ref = mp->mem_addr;
            break;

          case 1: // 8-bit offset
          {
            int64_t off = sign_extend_u64(mp->mem_addr, 8);
            reg_t abs = static_cast<reg_t>(mem_addr_ref + static_cast<reg_t>(off));
            mp->mem_addr = abs;
            mem_addr_ref = abs;
            break;
          }

          case 2: // 16-bit offset
          {
            int64_t off = sign_extend_u64(mp->mem_addr, 16);
            reg_t abs = static_cast<reg_t>(mem_addr_ref + static_cast<reg_t>(off));
            mp->mem_addr = abs;
            mem_addr_ref = abs;
            break;
          }

          case 3: // 32-bit offset (kept for completeness)
          {
            int64_t off = sign_extend_u64(mp->mem_addr, 32);
            reg_t abs = static_cast<reg_t>(mem_addr_ref + static_cast<reg_t>(off));
            mp->mem_addr = abs;
            mem_addr_ref = abs;
            break;
          }

          default:
            throw std::runtime_error("Invalid compress mode in trace");
        }
      }
    }
  }
  else {
    current_trace_index = -2;
    trace_finish = true;
    printf("Trace finish");
  }
}

void processor_t::after_fetch(insn_t insn){
  reg_t pc = state.pc;
  static reg_t last_pc = -1;
  static reg_t mem_addr_ref;

  if (current_trace_index == -1) {
    read_next_trace();
  }

  if(pc != last_pc) {
    retire++;
    retire_diff++;
    printf("AF @ %lx: retire=%ld, retire_diff=%ld\n", pc, retire, retire_diff);
    // Check mem event
    if (!trace_finish && current_trace.trace_type == 1) {
      if (current_trace.pc == pc && current_trace.retire == retire_diff) {
        auto payload = std::get<mem_payload_t>(current_trace.payload);
        reg_t mem_addr;
        // Recover address
        if (insn_is_read(insn) && (payload.bus_mode & 0x2)) { // Read Event, change MMU to simulate
          mmu->store<uint32_t>(payload.mem_addr, payload.mem_data);
          read_next_trace();
          retire_diff = 0;
        }
        else if (insn_is_write(insn) && (payload.bus_mode & 0x1)) { // Write Event, Just for validate
          //
          read_next_trace();
          retire_diff = 0;
        }
        else if(insn_is_read(insn) && insn_is_write(insn) && (payload.bus_mode & 0x3 == 0x3)) { // AMO, treat as read and write
          mmu->store<uint32_t>(payload.mem_addr, payload.mem_data);
          read_next_trace();
          retire_diff = 0;
        }
        else {
          printf("Trace mismatch (Mem type mismatch) at %lx: retire=%ld\n busmode=%ld, insn=<%lx>",
               pc, retire_diff, payload.bus_mode, insn);
          throw std::runtime_error("Trace mismatch");
        }
      }
      else if (current_trace.retire < retire_diff) {
        printf("Trace mismatch at %lx: expected pc=%lx retire=%ld, got pc=%lx retire=%ld\n",
               pc, current_trace.pc, current_trace.retire, pc, retire_diff);
        throw std::runtime_error("Trace mismatch");
      }
    }
  }

  last_pc = pc;
}

bool processor_t::after_exec() {
  reg_t pc = state.pc;
  printf("AE @ %lx: retire=%ld\n", pc, retire);
  if ((in_wfi || in_trap) & trace_finish) {
    printf("Meet trap but trace end\n");
    exit(0);
  }
  if (!trace_finish && current_trace.trace_type == 2) { // Trap
    auto payload = std::get<trap_payload_t>(current_trace.payload);
    if (pc == payload.mepc && (current_trace.retire - 1) == retire_diff) {
      ext_trap_t ext_trap(payload.mcause, payload.mtval, payload.mtinst);
      take_trap(ext_trap, payload.mepc);
      if (state.pc != current_trace.pc) {
        printf("Trace mismatch after trap at %lx: expected pc=%lx, got pc=%lx\n",
             state.pc, current_trace.pc, state.pc);
        throw std::runtime_error("Trace mismatch");
      }
      retire_diff = -1;
      in_wfi = false;
      if ((payload.mcause & (1ull << 31)) == 0) {
        in_trap = false;
      }
      read_next_trace();
      return true;
    }
    else if ((current_trace.retire - 1) < retire_diff) {
      printf("Trace mismatch at %lx: expected pc=%lx, got pc=%lx\n",
             pc, payload.mepc, pc);
      throw std::runtime_error("Trace mismatch");
    }
  }
  if (in_wfi) {
    throw std::runtime_error("WFI but no interrupt");
  }
  if (in_trap) {
    throw std::runtime_error("In trap but no trap trace taken");
  }
}

// fetch/decode/execute loop
void processor_t::step(size_t n)
{
  mmu_t* _mmu = mmu;

  if (!state.debug_mode) {
    if (halt_request == HR_REGULAR) {
      enter_debug_mode(DCSR_CAUSE_DEBUGINT, 0);
    } else if (halt_request == HR_GROUP) {
      enter_debug_mode(DCSR_CAUSE_GROUP, 0);
    } else if (halt_on_reset) {
      halt_on_reset = false;
      enter_debug_mode(DCSR_CAUSE_HALT, 0);
    }
  }

  while (n > 0) {
    size_t instret = 0;
    reg_t pc = state.pc;
    state.prv_changed = false;
    state.v_changed = false;

    #define advance_pc() { \
      if (unlikely(invalid_pc(pc))) { \
        switch (pc) { \
          case PC_SERIALIZE_BEFORE: state.serialized = true; break; \
          case PC_SERIALIZE_AFTER: ++instret; after_exec(); break; \
          default: abort(); \
        } \
        pc = state.pc; \
        goto serialize; \
      } else { \
        state.pc = pc; \
        instret++; \
      }}

    try
    {
      take_pending_interrupt();

      check_if_lpad_required();

      if (unlikely(slow_path()))
      {
        // Main simulation loop, slow path.
        while (instret < n)
        {
          if (unlikely(!state.serialized && state.single_step == state.STEP_STEPPED)) {
            state.single_step = state.STEP_NONE;
            if (!state.debug_mode) {
              enter_debug_mode(DCSR_CAUSE_STEP, 0);
              // enter_debug_mode changed state.pc, so we can't just continue.
              break;
            }
          }

          if (unlikely(state.single_step == state.STEP_STEPPING)) {
            state.single_step = state.STEP_STEPPED;
          }

          if (!state.serialized && check_triggers_icount) {
            auto match = TM.detect_icount_match();
            if (match.has_value()) {
              assert(match->timing == triggers::TIMING_BEFORE);
              throw triggers::matched_t((triggers::operation_t)0, 0, match->action, state.v);
            }
          }

          // debug mode wfis must nop
          if (unlikely(in_wfi && !state.debug_mode)) {
            throw wait_for_interrupt_t();
          }

          in_wfi = false;
          insn_fetch_t fetch = mmu->load_insn(pc);
          after_fetch(fetch.insn);
          if (debug && !state.serialized)
            disasm(fetch.insn);
          pc = execute_insn_logged(this, pc, fetch);
          advance_pc();
          after_exec();

          // Resume from debug mode in critical error
          if (state.critical_error && !state.debug_mode) {
            if (state.dcsr->read() & DCSR_CETRIG) {
              enter_debug_mode(DCSR_CAUSE_EXTCAUSE, DCSR_EXTCAUSE_CRITERR);
            } else {
              // Handling of critical error is implementation defined
              // For now just enter debug mode
              enter_debug_mode(DCSR_CAUSE_HALT, 0);
            }
          }
        }
      }
      else while (instret < n)
      {
        // Main simulation loop, fast path.
        for (auto ic_entry = _mmu->access_icache(pc); instret < n; instret++) {
          auto fetch = ic_entry->data;
          ic_entry = ic_entry->next;
          auto new_pc = execute_insn_fast(this, pc, fetch);
          if (unlikely(ic_entry->tag != new_pc)) {
            ic_entry = &_mmu->icache[_mmu->icache_index(new_pc)];
            _mmu->icache[_mmu->icache_index(pc)].next = ic_entry;
            if (ic_entry->tag != new_pc) {
              pc = new_pc;
              advance_pc();
              break;
            }
          }
          state.pc = pc = ic_entry->tag;
        }
      }
    }
    catch(trap_t& t)
    {
      in_trap = true;
      if (after_exec()) {
        continue;
      }
      take_trap(t, pc);
      n = instret;

      // If critical error then enter debug mode critical error trigger enabled
      if (state.critical_error) {
        if (state.dcsr->read() & DCSR_CETRIG) {
          enter_debug_mode(DCSR_CAUSE_EXTCAUSE, DCSR_EXTCAUSE_CRITERR);
        } else {
          // Handling of critical error is implementation defined
          // For now just enter debug mode
          enter_debug_mode(DCSR_CAUSE_HALT, 0);
        }
      }
      // Trigger action takes priority over single step
      auto match = TM.detect_trap_match(t);
      if (match.has_value())
        take_trigger_action(match->action, 0, state.pc, 0);
      else if (unlikely(state.single_step == state.STEP_STEPPED)) {
        state.single_step = state.STEP_NONE;
        enter_debug_mode(DCSR_CAUSE_STEP, 0);
      }
    }
    catch (triggers::matched_t& t)
    {
      take_trigger_action(t.action, t.address, pc, t.gva);
    }
    catch(trap_debug_mode&)
    {
      enter_debug_mode(DCSR_CAUSE_SWBP, 0);
    }
    catch (wait_for_interrupt_t &t)
    {
      // Return to the outer simulation loop, which gives other devices/harts a
      // chance to generate interrupts.
      //
      // In the debug ROM this prevents us from wasting time looping, but also
      // allows us to switch to other threads only once per idle loop in case
      // there is activity.
      in_wfi = true;
      if(after_exec()) {
        continue;
      }
      n = ++instret;
    }

serialize:
    state.minstret->bump((state.mcountinhibit->read() & MCOUNTINHIBIT_IR) ? 0 : instret);

    // Model a hart whose CPI is 1.
    state.mcycle->bump((state.mcountinhibit->read() & MCOUNTINHIBIT_CY) ? 0 : instret);

    n -= instret;
  }
}
