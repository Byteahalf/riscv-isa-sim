#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <optional>
#include <cstdlib>
#include <cerrno>
#include <cstring>
#include <iomanip>
#include <cmath>
#include <cstdint>
#include <stdexcept> 
#include <iostream>
#include "processor.h"

static log_item::fmt_spec parse_fmt(const std::string& s)
{
    log_item::fmt_spec spec;

    if (s.empty())
        return spec;

    size_t i = 0;

    // '#'
    if (i < s.size() && s[i] == '#')
    {
        spec.show_prefix = true;
        i++;
    }

    // '0'
    if (i < s.size() && s[i] == '0')
    {
        spec.pad_zero = true;
        i++;
    }

    // width
    while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i])))
    {
        spec.width = spec.width * 10 + (s[i] - '0');
        i++;
    }

    // precision
    if (i < s.size() && s[i] == '.')
    {
        i++;
        spec.precision = 0;

        while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i])))
        {
            spec.precision = spec.precision * 10 + (s[i] - '0');
            i++;
        }
    }

    // type
    if (i < s.size())
    {
        char t = s[i];

        if (t == 'x')
            spec.base = log_item::fmt_spec::base_t::HEX_LOWER;
        else if (t == 'X')
            spec.base = log_item::fmt_spec::base_t::HEX_UPPER;
        else if (t == 'b')
            spec.base = log_item::fmt_spec::base_t::BIN;
        else if (t == 's')
        {
            spec.base = log_item::fmt_spec::base_t::DEC;
            spec.is_signed = true;
        }
        else if (t == 'f')
            spec.float_mode = log_item::fmt_spec::float_t::FIXED;
        else if (t == 'e')
            spec.float_mode = log_item::fmt_spec::float_t::SCI;
        else if (t == 'g')
            spec.float_mode = log_item::fmt_spec::float_t::GENERAL;
        else
            spec.base = log_item::fmt_spec::base_t::DEC;
    }

    return spec;
}

void processor_t::load_trace_format()
{
    advanced_log_items.clear();

    std::stringstream ss(debug_log_format);
    std::string token;

    while (std::getline(ss, token, ','))
    {
        // trim
        token.erase(0, token.find_first_not_of(" \t"));
        token.erase(token.find_last_not_of(" \t") + 1);

        if (token.empty())
            continue;

        std::string expr;
        std::string fmt_str;

        size_t colon = token.find(':');
        if (colon != std::string::npos)
        {
            expr = token.substr(0, colon);
            fmt_str = token.substr(colon + 1);
        }
        else
        {
            expr = token;
        }

        log_item item;
        item.fmt = parse_fmt(fmt_str);
        item.header = expr;

        std::string lower = expr;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

        // --------- PC ----------
        if (lower == "pc")
        {
            item.kind = log_item::kind_t::PC;
        }
        else if (lower == "retire")
        {
            item.kind = log_item::kind_t::RETIRE;
        }
        else if (lower == "insn")
        {
            item.kind = log_item::kind_t::INSN;
        }
        else if (lower == "priv")
        {
            item.kind = log_item::kind_t::PRIV;
        }
        // --------- CSR ----------
        else if (lower.rfind("csr(", 0) == 0 && lower.back() == ')')
        {
            std::string num = lower.substr(4, lower.size() - 5);
            item.kind = log_item::kind_t::CSR;
            item.csr_addr = std::stoul(num, nullptr, 0);
        }
        // --------- x1-x32 ----------
        else if (lower[0] == 'x' && lower.size() > 1)
        {
            int idx = std::stoi(lower.substr(1));
            if (idx >= 0 && idx <= 31)
            {
                item.kind = log_item::kind_t::GPR;
                item.gpr_index = idx;
            }
            else
                continue;
        }

        // --------- f0-f31 ----------
        else if (lower[0] == 'f' && lower.size() > 1 && std::isdigit(lower[1]))
        {
            int idx = std::stoi(lower.substr(1));
            if (idx >= 0 && idx <= 31)
            {
                item.kind = log_item::kind_t::FPR;
                item.gpr_index = idx;   // 可复用该字段
            }
            else
                continue;
        }
        // --------- alias ----------
        else
        {
            static std::unordered_map<std::string,int> gpr_alias =
            {
                {"ra",1},{"sp",2},{"gp",3},{"tp",4},
                {"t0",5},{"t1",6},{"t2",7},
                {"s0",8},{"fp",8},{"s1",9},
                {"a0",10},{"a1",11},{"a2",12},{"a3",13},
                {"a4",14},{"a5",15},{"a6",16},{"a7",17},
                {"s2",18},{"s3",19},{"s4",20},{"s5",21},
                {"s6",22},{"s7",23},{"s8",24},{"s9",25},
                {"s10",26},{"s11",27},
                {"t3",28},{"t4",29},{"t5",30},{"t6",31}
            };

            static std::unordered_map<std::string,int> fpr_alias =
            {
                {"ft0",0},{"ft1",1},{"ft2",2},{"ft3",3},
                {"ft4",4},{"ft5",5},{"ft6",6},{"ft7",7},
                {"fs0",8},{"fs1",9},
                {"fa0",10},{"fa1",11},{"fa2",12},{"fa3",13},
                {"fa4",14},{"fa5",15},{"fa6",16},{"fa7",17},
                {"fs2",18},{"fs3",19},{"fs4",20},{"fs5",21},
                {"fs6",22},{"fs7",23},{"fs8",24},{"fs9",25},
                {"fs10",26},{"fs11",27},
                {"ft8",28},{"ft9",29},{"ft10",30},{"ft11",31}
            };

            // GPR alias
            if (gpr_alias.count(lower))
            {
                item.kind = log_item::kind_t::GPR;
                item.gpr_index = gpr_alias[lower];
            }
            // FPR alias
            else if (fpr_alias.count(lower))
            {
                item.kind = log_item::kind_t::FPR;
                item.gpr_index = fpr_alias[lower];
            }
            // 浮点 CSR 快捷名
            else if (lower == "frm")
            {
                item.kind = log_item::kind_t::CSR;
                item.csr_addr = 0x002;   // frm
            }
            else if (lower == "fflags")
            {
                item.kind = log_item::kind_t::CSR;
                item.csr_addr = 0x001;   // fflags
            }
            else if (lower == "fcsr")
            {
                item.kind = log_item::kind_t::CSR;
                item.csr_addr = 0x003;   // fcsr
            }
            else
            {
                throw std::runtime_error("Unknown log item: " + expr);
                exit(-1);
            }
        }
        advanced_log_items.push_back(item);
    }
}


template<typename T>
static std::string format_int(reg_t raw,
                              const log_item::fmt_spec& spec)
{
    static_assert(
        std::is_same_v<T, uint32_t> ||
        std::is_same_v<T, int32_t>  ||
        std::is_same_v<T, uint64_t> ||
        std::is_same_v<T, int64_t>,
        "Unsupported type"
    );

    constexpr int BITW = int(sizeof(T) * 8);

    // ---- bit-extract payload from wrapper ----
    uint64_t bits = 0;
    std::memcpy(&bits, &raw, sizeof(uint64_t)); // reg_t assumed to store at least 64 bits

    if constexpr (BITW == 32)
        bits &= 0xFFFFFFFFull;

    // ---- form T by bit-cast to avoid numeric conversion issues (esp. signed) ----
    T value{};
    if constexpr (BITW == 32)
    {
        uint32_t b32 = static_cast<uint32_t>(bits);
        std::memcpy(&value, &b32, sizeof(T));
    }
    else
    {
        uint64_t b64 = bits;
        std::memcpy(&value, &b64, sizeof(T));
    }

    // ---------- BIN ----------
    if (spec.base == log_item::fmt_spec::base_t::BIN)
    {
        using U = std::make_unsigned_t<T>;
        U u;

        if constexpr (BITW == 32)
            u = static_cast<U>(static_cast<uint32_t>(bits));
        else
            u = static_cast<U>(static_cast<uint64_t>(bits));

        std::string s;
        do
        {
            s = char('0' + (u & 1)) + s;
            u >>= 1;
        } while (u);

        if (spec.show_prefix)
            s = "0b" + s;

        if (spec.width > 0 && s.size() < (size_t)spec.width)
        {
            char pad = spec.pad_zero ? '0' : ' ';
            s = std::string(spec.width - s.size(), pad) + s;
        }

        return s;
    }

    std::stringstream ss;

    // ---------- DEC ----------
    if (spec.base == log_item::fmt_spec::base_t::DEC)
    {
        ss << std::dec;
        ss << value;   // signed/unsigned depends on T
    }
    else
    {
        // HEX: output as unsigned two's complement of payload width
        using U = std::make_unsigned_t<T>;
        U u;

        if constexpr (BITW == 32)
            u = static_cast<U>(static_cast<uint32_t>(bits));
        else
            u = static_cast<U>(static_cast<uint64_t>(bits));

        ss << std::hex
           << (spec.base == log_item::fmt_spec::base_t::HEX_UPPER
               ? std::uppercase
               : std::nouppercase);

        ss << u;
    }

    std::string s = ss.str();

    if (spec.show_prefix &&
        spec.base != log_item::fmt_spec::base_t::DEC)
    {
        s = "0x" + s;
    }

    // python-like: width is min width only
    if (spec.width > 0 && s.size() < (size_t)spec.width)
    {
        char pad = spec.pad_zero ? '0' : ' ';
        s = std::string(spec.width - s.size(), pad) + s;
    }

    return s;
}

template<typename T>
static std::string format_float(freg_t raw,
                                const log_item::fmt_spec& spec)
{
    static_assert(
        std::is_same_v<T, float> ||
        std::is_same_v<T, double>,
        "T must be float or double"
    );

    constexpr int PAYLOAD_BITS = std::is_same_v<T, float> ? 32 : 64;

    // ---- extract payload bits from wrapper (extra bits are assumed zero-filled) ----
    uint64_t payload = 0;
    if constexpr (PAYLOAD_BITS == 32)
    {
        uint32_t b32 = 0;
        std::memcpy(&b32, &raw, sizeof(uint32_t));
        payload = b32;
    }
    else
    {
        uint64_t b64 = 0;
        std::memcpy(&b64, &raw, sizeof(uint64_t));
        payload = b64;
    }

    // =====================================================
    // HEX / BIN: dump raw payload bits (works for float too)
    // =====================================================
    if (spec.base == log_item::fmt_spec::base_t::HEX_LOWER ||
        spec.base == log_item::fmt_spec::base_t::HEX_UPPER ||
        spec.base == log_item::fmt_spec::base_t::BIN)
    {
        std::string s;

        if (spec.base == log_item::fmt_spec::base_t::BIN)
        {
            for (int i = PAYLOAD_BITS - 1; i >= 0; --i)
            {
                s += ((payload >> i) & 1ull) ? '1' : '0';
            }

            if (spec.show_prefix)
                s = "0b" + s;
        }
        else
        {
            int hex_digits = PAYLOAD_BITS / 4;

            std::stringstream ss;
            ss << std::hex
               << (spec.base == log_item::fmt_spec::base_t::HEX_UPPER
                   ? std::uppercase
                   : std::nouppercase)
               << std::setfill('0')
               << std::setw(hex_digits);

            ss << payload;

            s = ss.str();

            if (spec.show_prefix)
                s = "0x" + s;
        }

        // python-like: width is min width only
        if (spec.width > 0 && s.size() < (size_t)spec.width)
        {
            char pad = spec.pad_zero ? '0' : ' ';
            s = std::string(spec.width - s.size(), pad) + s;
        }

        return s;
    }

    // ---- build T by bit-cast (no numeric cast from wrapper) ----
    T tv{};
    if constexpr (PAYLOAD_BITS == 32)
        std::memcpy(&tv, &payload, sizeof(uint32_t));
    else
        std::memcpy(&tv, &payload, sizeof(uint64_t));

    if (std::isnan(tv))  return "nan";
    if (std::isinf(tv))  return (tv > 0) ? "inf" : "-inf";

    // ---------- precision handling ----------
    // Defaults per requirements:
    // - g: sig=10
    // - e: after-dot=9 (=> 10 significant digits)
    // - f: after-dot=1, but for tiny values increase until first non-zero (cap 10)
    int user_p = spec.precision;

    int g_sig = 10;
    int e_after = 9;
    int f_after = 1;

    if (user_p >= 0)
    {
        g_sig = user_p;
        e_after = user_p;
        f_after = user_p;
    }

    auto to_string_stream = [&](std::ios_base& (*mode)(std::ios_base&),
                                int setprec) -> std::string
    {
        std::stringstream ss;
        ss << mode;
        ss << std::setprecision(setprec);
        ss << tv;
        return ss.str();
    };

    using float_t = log_item::fmt_spec::float_t;

    // =====================================================
    // e: forced scientific, precision is digits after '.'
    // =====================================================
    if (spec.float_mode == float_t::SCI)
    {
        std::stringstream ss;
        ss << std::scientific;
        ss << std::setprecision(e_after);
        ss << tv;

        std::string s = ss.str();

        if (spec.width > 0 && s.size() < (size_t)spec.width)
        {
            char pad = spec.pad_zero ? '0' : ' ';
            s = std::string(spec.width - s.size(), pad) + s;
        }

        return s;
    }

    // =====================================================
    // f: fixed; tiny values increase decimals until first non-zero (cap 10)
    // =====================================================
    if (spec.float_mode == float_t::FIXED)
    {
        int after = f_after;

        T av = std::fabs(tv);
        if (av != 0.0 && av < 1.0)
        {
            // find first non-zero decimal position, cap at 10
            // Need k such that av * 10^k >= 1
            T t = av;
            int k = 0;
            while (t < 1.0 && k < 10)
            {
                t *= 10.0;
                k++;
            }
            // want to include that first non-zero digit, plus 0 extra (so k decimals),
            // but at least default after
            if (k > after) after = k;
        }

        if (after > 10) after = 10;

        std::stringstream ss;
        ss << std::fixed;
        ss << std::setprecision(after);
        ss << tv;

        std::string s = ss.str();

        if (spec.width > 0 && s.size() < (size_t)spec.width)
        {
            char pad = spec.pad_zero ? '0' : ' ';
            s = std::string(spec.width - s.size(), pad) + s;
        }

        return s;
    }

    // =====================================================
    // g (GENERAL) or NONE: try compact within sig digits; if not meaningful, use scientific
    // =====================================================
    {
        int sig = g_sig;

        // First attempt: defaultfloat with sig significant digits
        std::stringstream ss;
        ss << std::defaultfloat;
        ss << std::setprecision(sig);
        ss << tv;
        std::string s = ss.str();

        // If defaultfloat produced a fixed-style number with too many integer digits
        // such that significant digits are mostly consumed and fractional info lost,
        // or if it still looks "too long" to represent meaningfully, force scientific.
        //
        // Heuristic:
        // - compute decimal exponent = floor(log10(|v|)) for |v| != 0
        // - if exponent >= sig or exponent <= -sig, scientific is better.
        bool force_scientific = false;
        T av = std::fabs(tv);

        if (av != 0.0L)
        {
            T lg = std::log10(av);
            int exp10 = (int)std::floor(lg);

            if (exp10 >= sig || exp10 <= -sig)
                force_scientific = true;
        }

        if (force_scientific)
        {
            std::stringstream se;
            se << std::scientific;
            // To get ~sig significant digits: digits after '.' = sig-1
            int after = sig - 1;
            if (after < 0) after = 0;
            se << std::setprecision(after);
            se << tv;
            s = se.str();
        }
        else
        {
            // trim trailing zeros if there is a decimal point and not scientific
            auto pos_e = s.find_first_of("eE");
            if (pos_e == std::string::npos)
            {
                auto pos = s.find('.');
                if (pos != std::string::npos)
                {
                    while (!s.empty() && s.back() == '0')
                        s.pop_back();
                    if (!s.empty() && s.back() == '.')
                        s.pop_back();
                }
            }
        }

        if (spec.width > 0 && s.size() < (size_t)spec.width)
        {
            char pad = spec.pad_zero ? '0' : ' ';
            s = std::string(spec.width - s.size(), pad) + s;
        }

        return s;
    }
}

void processor_t::init_advanced_log(const std::string& path)
{
    s_log.open(path, std::ios::out | std::ios::trunc);

    for (size_t i = 0; i < advanced_log_items.size(); i++)
    {
        if (i) s_log << ",";
        s_log << advanced_log_items[i].header;
    }
    s_log << "\n";
}

void processor_t::advanced_log(reg_t pc, reg_t retire, insn_t insn)
{
    for (size_t i = 0; i < advanced_log_items.size(); i++)
    {
        if (i) s_log << ",";

        const log_item& item = advanced_log_items[i];
        uint64_t v = 0;

        switch (item.kind)
        {
            case log_item::kind_t::PC:
                v = pc;
                break;
            
            case log_item::kind_t::RETIRE:
                v = retire;
                break;

            case log_item::kind_t::PRIV:
                v = state.prv;
                break;

            case log_item::kind_t::INSN:
                v = insn.bits();
                break;

            case log_item::kind_t::GPR:
                v = state.XPR[item.gpr_index];
                break;

            case log_item::kind_t::CSR:
                v = get_csr(item.csr_addr);
                break;
        }
        
        if (item.fmt.is_signed)
            s_log << ((xlen == 64) ? format_int<int64_t>(v, item.fmt) : format_int<int32_t>(v, item.fmt));
        else
            s_log << ((xlen == 64) ? format_int<uint64_t>(v, item.fmt) : format_int<uint32_t>(v, item.fmt));

    }

    s_log << "\n";
}