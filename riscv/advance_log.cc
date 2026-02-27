#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <optional>
#include <cstdlib>
#include <cerrno>
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

    if (i < s.size() && s[i] == '#')
    {
        spec.show_prefix = true;
        i++;
    }

    if (i < s.size() && s[i] == '0')
    {
        spec.pad_zero = true;
        i++;
    }

    // width
    while (i < s.size() && std::isdigit(s[i]))
    {
        spec.width = spec.width * 10 + (s[i] - '0');
        i++;
    }

    if (i < s.size())
    {
        char t = s[i];

        if (t == 'x') spec.base = log_item::fmt_spec::base_t::HEX_LOWER;
        else if (t == 'X') spec.base = log_item::fmt_spec::base_t::HEX_UPPER;
        else if (t == 'b') spec.base = log_item::fmt_spec::base_t::BIN;
        else spec.base = log_item::fmt_spec::base_t::DEC;
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
        else if (lower[0] == 'x')
        {
            int idx = std::stoi(lower.substr(1));
            item.kind = log_item::kind_t::GPR;
            item.gpr_index = idx;
        }
        // --------- alias ----------
        else
        {
            static std::unordered_map<std::string,int> alias =
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

            if (alias.count(lower))
            {
                item.kind = log_item::kind_t::GPR;
                item.gpr_index = alias[lower];
            }
            else
            {
                continue; // ignore unknown
            }
        }

        advanced_log_items.push_back(item);
    }
}

static std::string format_u64(uint64_t v, const log_item::fmt_spec& spec)
{
    if (spec.base == log_item::fmt_spec::base_t::BIN)
    {
        std::string s;
        do
        {
            s = char('0' + (v & 1)) + s;
            v >>= 1;
        } while (v);

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

    if (spec.base == log_item::fmt_spec::base_t::DEC)
        ss << std::dec;
    else
        ss << std::hex << (spec.base == log_item::fmt_spec::base_t::HEX_UPPER ? std::uppercase : std::nouppercase);

    ss << v;

    std::string s = ss.str();

    if (spec.show_prefix && spec.base != log_item::fmt_spec::base_t::DEC)
        s = "0x" + s;

    if (spec.width > 0 && s.size() < (size_t)spec.width)
    {
        char pad = spec.pad_zero ? '0' : ' ';
        s = std::string(spec.width - s.size(), pad) + s;
    }

    return s;
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

void processor_t::advanced_log(reg_t pc, reg_t retire)
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

            case log_item::kind_t::GPR:
                v = state.XPR[item.gpr_index];  // 按你的Spike版本修改
                break;

            case log_item::kind_t::CSR:
                v = get_csr(item.csr_addr);
                break;
        }

        s_log << format_u64(v, item.fmt);
    }

    s_log << "\n";
}