#include "dex/disasm.h"
#include "obfus.h"

namespace aid {

XorDetector::XorDetector() noexcept
    : m_gotoTargets{}, m_xor{false}, m_det{false} {}

void XorDetector::reset() {
    m_gotoTargets.clear();
    m_xor = false;
    m_det = false;
}

bool XorDetector::visit(dalvik::Bytecode::iterator it) {
    if (m_det)
        return false;
    const auto op = it->opcode();
    const size_t pos = it->pos();
    if (op == dalvik::Opcode::ARRAY_LENGTH) {
        const auto nextOp = (++it)->opcode();
        if (nextOp == dalvik::Opcode::IF_LT || nextOp == dalvik::Opcode::IF_GE)
            m_gotoTargets.insert(pos);
        return true;
    }
    if (op == dalvik::Opcode::IF_GE) {
        m_gotoTargets.insert(pos);
        return true;
    }
    if (op == dalvik::Opcode::XOR_INT || op == dalvik::Opcode::XOR_INT_2ADDR) {
        m_xor = true;
        return true;
    }
    if (op == dalvik::Opcode::GOTO) {
        const int8_t offset = static_cast<int8_t>(it->arg());
        m_det = m_xor && m_gotoTargets.contains(it->pos() + offset * 2);
        return !m_det;
    }
    return true;
}

bool XorDetector::detect() const {
    return m_det;
}

bool isAbnormal(const LIEF::DEX::Method& m,
    std::vector<std::unique_ptr<IAnomalyDetector>>& d)
{
    // 1) check if method has code
    const auto& code = m.bytecode();
    if (code.empty())
        return false;

    // 2) scan instructions
    auto bc = dalvik::Bytecode(code);
    bool abnormal = false;
    for (auto it = bc.begin(); it != bc.end() && !abnormal; ++it) {
        for (auto& det : d) {
            if (abnormal)
                break;
            det->visit(it);
            if (det->detect())
                abnormal = true;
        }
    }
    // reset state machines
    for (auto& det : d)
        det->reset();
    return abnormal;
}

} // namespace aid
