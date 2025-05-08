#include "dex/disasm.h"

namespace aid {

namespace dalvik {

Bytecode::Bytecode(const std::vector<uint8_t>& bc)
    : m_code{bc} {}

Bytecode::Iter::Iter(size_t pos, const std::span<uint8_t>& vec)
    : m_pos(pos), m_code(vec), m_insn(pos, vec) {}

Bytecode::Iter::pointer Bytecode::Iter::operator->() {
    return &m_insn;
}

Bytecode::Iter::reference Bytecode::Iter::operator*() {
    return m_insn;
}

Bytecode::Iter& Bytecode::Iter::operator++() {
    if (m_insn.length() > 0) {
        m_pos += m_insn.length();
        m_insn = Instruction(m_pos, m_code);
    }
    return *this;
}

Bytecode::Iter Bytecode::Iter::operator++(int) {
    Bytecode::Iter tmp = *this;
    ++(*this);
    return tmp;
}

Bytecode::iterator Bytecode::begin() {
    return Bytecode::Iter(0, std::span<uint8_t>(m_code));
}

Bytecode::iterator Bytecode::end() {
    return Bytecode::Iter(m_code.size(), std::span<uint8_t>(m_code));
}

Instruction::Instruction(size_t pos, const std::span<uint8_t>& code)
    : m_pos(pos), m_regs(), m_arg(0), m_code(), m_opcode(Opcode::INVALID)
{
    parse(pos, code);
}

// Hell begins here

int Instruction::getLength(Opcode op, size_t pos, const std::span<uint8_t>& code) {
    if (op == Opcode::INVALID)
        return -1;
    int len = 0, width = 0;
    switch (op) {
        case Opcode::PACKED_SWITCH_PAYLOAD:
            if (code.subspan(pos).size() < 4)
                return -1;
            len = *reinterpret_cast<const uint16_t*>(&code[pos + 2]);
            return (len * 4) + 8;
        case Opcode::SPARSE_SWITCH_PAYLOAD:
            if (code.subspan(pos).size() < 4)
                return -1;
            len = *reinterpret_cast<const uint16_t*>(&code[pos + 2]);
            return (len * 8) + 4;
        case Opcode::FILL_ARRAY_DATA_PAYLOAD:
            if (code.subspan(pos).size() < 8)
                return -1;
            width = *reinterpret_cast<const uint16_t*>(&code[pos + 2]);
            len = *reinterpret_cast<const uint32_t*>(&code[pos + 4]);
            return ((len * width + 1) / 2 + 4) * 2;
        default:
            break;
    }
    const auto fmt = instrInfo[op].fmt;
    //std::cout << "Fmt: " << int(fmt) << std::endl;
    switch (fmt) {
        case InstrFormat::FMT_10x:
        case InstrFormat::FMT_10t:
        case InstrFormat::FMT_11x:
        case InstrFormat::FMT_11n:
        case InstrFormat::FMT_12x:
            len = sizeof(Instruction::word);
            break;
        case InstrFormat::FMT_20t:
        case InstrFormat::FMT_21c:
        case InstrFormat::FMT_21h:
        case InstrFormat::FMT_21t:
        case InstrFormat::FMT_21s:
        case InstrFormat::FMT_22b:
        case InstrFormat::FMT_22c:
        case InstrFormat::FMT_22t:
        case InstrFormat::FMT_22s:
        case InstrFormat::FMT_22x:
        case InstrFormat::FMT_23x:
            len = sizeof(Instruction::word) * 2;
            break;
        case InstrFormat::FMT_30t:
        case InstrFormat::FMT_31c:
        case InstrFormat::FMT_31i:
        case InstrFormat::FMT_31t:
        case InstrFormat::FMT_32x:
        case InstrFormat::FMT_35c:
        case InstrFormat::FMT_3rc:
            len = sizeof(Instruction::word) * 3;
            break;
        case InstrFormat::FMT_45cc:
        case InstrFormat::FMT_4rcc:
            len = sizeof(Instruction::word) * 4;
            break;
        case InstrFormat::FMT_51l:
            len = sizeof(Instruction::word) * 5;
            break;
        default:
            //std::cout << "WTF\n";
            return -1;
    }
    //std::cout << "calc len: " << len << std::endl;
    return len;
}

void Instruction::parse(size_t pos, const std::span<uint8_t>& code) {
    // 1) bounds check
    if (code.size() < 2 || pos >= code.size() - 1)
        return; 

    // get opcode
    Opcode opc = Opcode{code[pos]};
    if (opc == Opcode::NOP) {
        // validate opcode
        opc = Opcode{*reinterpret_cast<const uint16_t*>(&code[pos])};
        switch (opc) {
            case Opcode::NOP:
            case Opcode::PACKED_SWITCH_PAYLOAD:
            case Opcode::SPARSE_SWITCH_PAYLOAD:
            case Opcode::FILL_ARRAY_DATA_PAYLOAD:
                break;
            default:
                opc = Opcode::INVALID;
                break;
        }
    }
    // get length
    int len = getLength(opc, pos, code);
    /*std::cout << std::hex << "Opcode: " << opc << " len: " << len
        << " pos: " << pos << '/' << code.size() << std::endl;*/
    if (len == -1)
        return;
    m_code = code.subspan(pos, len);
    int regc = 0;
    // parse different formats
    const InstrLookup info = instrInfo[opc];
    m_name = info.name;
    switch (info.fmt) {
        case InstrFormat::FMT_10x:
            break;
        case InstrFormat::FMT_11x:
            m_regs = { m_code[1] };
            break;
        case InstrFormat::FMT_10t:
            m_arg = m_code[1];
            break;
        case InstrFormat::FMT_11n:
            m_regs = { m_code[1] & 0xF };
            m_arg = m_code[1] >> 4;
            break;
        case InstrFormat::FMT_12x:
           m_regs = { m_code[1] & 0xF, m_code[1] >> 4 }; 
           break;
        case InstrFormat::FMT_20t:
            m_arg = *reinterpret_cast<const uint16_t*>(&m_code[2]);
            break;
        case InstrFormat::FMT_22x:
            m_regs = { m_code[1], *reinterpret_cast<const uint16_t*>(&m_code[2]) };
            break;
        case InstrFormat::FMT_21t:
        case InstrFormat::FMT_21s:
        case InstrFormat::FMT_21c:
        case InstrFormat::FMT_21h:
            m_regs = { m_code[1] }; 
            m_arg = *reinterpret_cast<const uint16_t*>(&m_code[2]);
            break;
        case InstrFormat::FMT_23x:
            m_regs = { m_code[1], m_code[2], m_code[3] };
            break;
        case InstrFormat::FMT_22b:
            m_regs = { m_code[1], m_code[2] };
            m_arg = m_code[3];
            break;
        case InstrFormat::FMT_22t:
        case InstrFormat::FMT_22s:
        case InstrFormat::FMT_22c:
            m_regs = { m_code[1] & 0xF, m_code[1] >> 4 };
            m_arg = *reinterpret_cast<const uint16_t*>(&m_code[2]);
            break;
        case InstrFormat::FMT_30t:
            m_arg = *reinterpret_cast<const uint32_t*>(&m_code[2]);
            break;
        case InstrFormat::FMT_32x:
            m_regs = { *reinterpret_cast<const uint16_t*>(&m_code[4]), *reinterpret_cast<const uint16_t*>(&m_code[2]) };
            break;
        case InstrFormat::FMT_31c:
        case InstrFormat::FMT_31i:
        case InstrFormat::FMT_31t:
            m_regs = { m_code[1] };
            m_arg = *reinterpret_cast<const uint32_t*>(&m_code[2]);
            break;
        case InstrFormat::FMT_35c:
            m_arg = *reinterpret_cast<const uint16_t*>(&m_code[2]);
            regc = m_code[1] >> 4;
            m_regs = { m_code[4] & 0xF, m_code[4] >> 4, m_code[5] & 0xF, m_code[5] >> 4, m_code[1] & 0xF };
            m_regs.resize(regc);
            break;
        case InstrFormat::FMT_3rc:
            break;
        case InstrFormat::FMT_45cc:
            regc = m_code[1] >> 4;
            m_regs = { m_code[4] & 0xF, m_code[4] >> 4, m_code[5] & 0xF, m_code[5] >> 4, m_code[1] & 0xF };
            m_regs.resize(regc);
            m_arg = (*reinterpret_cast<const uint16_t*>(&m_code[2]) << 16) | *reinterpret_cast<const uint16_t*>(&m_code[6]);
            break;
        case InstrFormat::FMT_4rcc:
            break;
        case InstrFormat::FMT_51l:
            m_regs = { m_code[1] };
            m_arg = *reinterpret_cast<const uint64_t*>(&m_code[2]);
            break;
        default:
            return;
    }
    m_opcode = opc;
}

} // namespace dalvik

} // namespace aid
