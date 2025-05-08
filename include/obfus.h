#ifndef INCLUDE_OBFUS_H_
#define INCLUDE_OBFUS_H_

// STL headers
#include <memory>
#include <unordered_set>
#include <vector>
// LIEF
#include <LIEF/LIEF.hpp>
// AID
#include "dex/disasm.h"

namespace aid {

// something like a state machine
class IAnomalyDetector {
public:
    virtual ~IAnomalyDetector() noexcept = default;
    // reset state
    virtual void reset() = 0;
    // return true if should continue visiting
    virtual bool visit(dalvik::Bytecode::iterator it) = 0;
    // has anomaly?
    virtual bool detect() const = 0;
}; // class AnomalyDetector

// detect xor crypt
class XorDetector final : public IAnomalyDetector {
public:
    explicit XorDetector() noexcept;
    void reset() override;
    bool visit(dalvik::Bytecode::iterator it) override;
    bool detect() const override;
    virtual ~XorDetector() noexcept = default;
private:
    std::unordered_set<int32_t> m_gotoTargets;
    bool m_xor;
    bool m_det;
}; // class XorCrypt

// called per-method
// m - method to be scanned
// d - std::vector of IAnomalyDetector implemetations
bool isAbnormal(const LIEF::DEX::Method& m,
    std::vector<std::unique_ptr<IAnomalyDetector>>& d);

} // namespace aid

#endif // INCLUDE_OBFUS_H_
