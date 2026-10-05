#ifndef NETGUARD_STATISTICS_HPP
#define NETGUARD_STATISTICS_HPP

#include <string>
#include <chrono>
#include <cstdint>
#include "../common/netguard_uapi.h"

namespace netguard {

struct RateMetrics {
    double packetsPerSec;
    double bytesPerSec;
    double acceptedPerSec;
    double droppedPerSec;
    double rejectedPerSec;
};

class Statistics {
public:
    Statistics();

    void update(const struct netguard_stats &newStats);
    const struct netguard_stats& current() const { return m_currentStats; }
    RateMetrics getRates() const { return m_rates; }

    static std::string formatBytes(uint64_t bytes);
    static std::string formatPackets(uint64_t packets);
    static std::string formatUptime(uint64_t seconds);

    std::string formatSummary(bool colored = true) const;
    std::string formatProtocolBreakdown(bool colored = true) const;
    std::string formatSystemStatus(bool colored = true) const;

private:
    struct netguard_stats m_currentStats;
    struct netguard_stats m_previousStats;
    std::chrono::steady_clock::time_point m_lastUpdateTime;
    RateMetrics m_rates;
    bool m_hasPrevious;
};

} // namespace netguard

#endif // NETGUARD_STATISTICS_HPP
