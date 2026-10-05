#include "Statistics.hpp"
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cmath>

namespace netguard {

// ANSI Colors
static const std::string COLOR_RESET   = "\033[0m";
static const std::string COLOR_BOLD    = "\033[1m";
static const std::string COLOR_RED     = "\033[31m";
static const std::string COLOR_GREEN   = "\033[32m";
static const std::string COLOR_YELLOW  = "\033[33m";
static const std::string COLOR_BLUE    = "\033[34m";
static const std::string COLOR_MAGENTA = "\033[35m";
static const std::string COLOR_CYAN    = "\033[36m";
static const std::string COLOR_GRAY    = "\033[90m";

Statistics::Statistics()
    : m_hasPrevious(false)
{
    std::memset(&m_currentStats, 0, sizeof(m_currentStats));
    std::memset(&m_previousStats, 0, sizeof(m_previousStats));
    std::memset(&m_rates, 0, sizeof(m_rates));
}

void Statistics::update(const struct netguard_stats &newStats)
{
    auto now = std::chrono::steady_clock::now();

    if (m_hasPrevious) {
        std::chrono::duration<double> elapsed = now - m_lastUpdateTime;
        double dt = elapsed.count();

        if (dt > 0.05) {
            uint64_t dPkt = (newStats.total_packets >= m_previousStats.total_packets) ?
                            (newStats.total_packets - m_previousStats.total_packets) : 0;
            uint64_t dBytes = (newStats.total_bytes >= m_previousStats.total_bytes) ?
                              (newStats.total_bytes - m_previousStats.total_bytes) : 0;
            uint64_t dAcc = (newStats.accepted_packets >= m_previousStats.accepted_packets) ?
                            (newStats.accepted_packets - m_previousStats.accepted_packets) : 0;
            uint64_t dDrop = (newStats.dropped_packets >= m_previousStats.dropped_packets) ?
                             (newStats.dropped_packets - m_previousStats.dropped_packets) : 0;
            uint64_t dRej = (newStats.rejected_packets >= m_previousStats.rejected_packets) ?
                            (newStats.rejected_packets - m_previousStats.rejected_packets) : 0;

            m_rates.packetsPerSec  = dPkt / dt;
            m_rates.bytesPerSec    = dBytes / dt;
            m_rates.acceptedPerSec = dAcc / dt;
            m_rates.droppedPerSec  = dDrop / dt;
            m_rates.rejectedPerSec = dRej / dt;
        }
    } else {
        m_hasPrevious = true;
    }

    m_previousStats = m_currentStats;
    m_currentStats = newStats;
    m_lastUpdateTime = now;
}

std::string Statistics::formatBytes(uint64_t bytes)
{
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2);
    if (bytes < 1024ULL) {
        oss << bytes << " B";
    } else if (bytes < 1024ULL * 1024ULL) {
        oss << (double)bytes / 1024.0 << " KB";
    } else if (bytes < 1024ULL * 1024ULL * 1024ULL) {
        oss << (double)bytes / (1024.0 * 1024.0) << " MB";
    } else {
        oss << (double)bytes / (1024.0 * 1024.0 * 1024.0) << " GB";
    }
    return oss.str();
}

std::string Statistics::formatPackets(uint64_t packets)
{
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1);
    if (packets < 1000ULL) {
        oss << packets;
    } else if (packets < 1000000ULL) {
        oss << (double)packets / 1000.0 << " K";
    } else {
        oss << (double)packets / 1000000.0 << " M";
    }
    return oss.str();
}

std::string Statistics::formatUptime(uint64_t seconds)
{
    uint64_t hrs  = seconds / 3600;
    uint64_t mins = (seconds % 3600) / 60;
    uint64_t secs = seconds % 60;
    std::ostringstream oss;
    oss << std::setfill('0') << std::setw(2) << hrs << ":"
        << std::setfill('0') << std::setw(2) << mins << ":"
        << std::setfill('0') << std::setw(2) << secs;
    return oss.str();
}

std::string Statistics::formatSystemStatus(bool colored) const
{
    std::ostringstream oss;
    if (colored) oss << COLOR_BOLD << COLOR_CYAN << "=== NETGUARD SYSTEM STATUS ===" << COLOR_RESET << "\n";
    else oss << "=== NETGUARD SYSTEM STATUS ===\n";

    oss << "  Kernel Module:     " << (colored ? COLOR_GREEN : "") << "● ACTIVE" << (colored ? COLOR_RESET : "") << "\n";
    oss << "  Netfilter Hooks:   " << (m_currentStats.hooks_active ? ((colored ? COLOR_GREEN : "") + "● REGISTERED (IN, OUT, FWD)" + (colored ? COLOR_RESET : "")) : ((colored ? COLOR_RED : "") + "● INACTIVE" + (colored ? COLOR_RESET : ""))) << "\n";
    oss << "  Netlink Socket:    " << (colored ? COLOR_GREEN : "") << "● CONNECTED" << (colored ? COLOR_RESET : "") << "\n";
    oss << "  Default Policy:    " << ((m_currentStats.default_policy == NETGUARD_POLICY_ACCEPT) ? ((colored ? COLOR_GREEN : "") + "ACCEPT") : ((colored ? COLOR_RED : "") + "DROP")) << (colored ? COLOR_RESET : "") << "\n";
    oss << "  Active Rules:      " << m_currentStats.active_rules_count << "\n";
    oss << "  Module Uptime:     " << formatUptime(m_currentStats.module_uptime_sec) << "\n";

    return oss.str();
}

std::string Statistics::formatSummary(bool colored) const
{
    std::ostringstream oss;

    if (colored) oss << COLOR_BOLD << COLOR_CYAN << "=== TRAFFIC METRICS & STATISTICS ===" << COLOR_RESET << "\n";
    else oss << "=== TRAFFIC METRICS & STATISTICS ===\n";

    oss << std::left
        << std::setw(22) << "Total Packets:"   << std::setw(16) << m_currentStats.total_packets
        << std::setw(20) << "Total Data Volume:" << formatBytes(m_currentStats.total_bytes) << "\n";

    oss << std::left
        << std::setw(22) << "Accepted Packets:" << (colored ? COLOR_GREEN : "") << std::setw(16) << m_currentStats.accepted_packets << (colored ? COLOR_RESET : "")
        << std::setw(20) << "Accepted Bytes:"   << formatBytes(m_currentStats.accepted_bytes) << "\n";

    oss << std::left
        << std::setw(22) << "Dropped Packets:"  << (colored ? COLOR_RED : "") << std::setw(16) << m_currentStats.dropped_packets << (colored ? COLOR_RESET : "")
        << std::setw(20) << "Dropped Bytes:"    << formatBytes(m_currentStats.dropped_bytes) << "\n";

    oss << std::left
        << std::setw(22) << "Rejected Packets:" << (colored ? COLOR_YELLOW : "") << std::setw(16) << m_currentStats.rejected_packets << (colored ? COLOR_RESET : "")
        << std::setw(20) << "Rejected Bytes:"   << formatBytes(m_currentStats.rejected_bytes) << "\n";

    oss << std::string(60, '-') << "\n";
    oss << std::left
        << std::setw(22) << "Live Throughput:"  << std::fixed << std::setprecision(1) << m_rates.packetsPerSec << " pkts/s (" << formatBytes(static_cast<uint64_t>(m_rates.bytesPerSec)) << "/s)\n";
    oss << std::left
        << std::setw(22) << "Drop Rate:"        << (colored ? COLOR_RED : "") << std::fixed << std::setprecision(1) << m_rates.droppedPerSec << " drops/s" << (colored ? COLOR_RESET : "") << "\n";

    return oss.str();
}

std::string Statistics::formatProtocolBreakdown(bool colored) const
{
    std::ostringstream oss;
    uint64_t total = m_currentStats.total_packets ? m_currentStats.total_packets : 1;

    double tcpPct   = (double)m_currentStats.tcp_packets * 100.0 / total;
    double udpPct   = (double)m_currentStats.udp_packets * 100.0 / total;
    double icmpPct  = (double)m_currentStats.icmp_packets * 100.0 / total;
    double otherPct = (double)m_currentStats.other_packets * 100.0 / total;

    if (colored) oss << COLOR_BOLD << COLOR_CYAN << "=== PROTOCOL DISTRIBUTION ===" << COLOR_RESET << "\n";
    else oss << "=== PROTOCOL DISTRIBUTION ===\n";

    auto drawBar = [](double pct, const std::string &color, bool colored) {
        int width = 30;
        int filled = static_cast<int>(std::round((pct / 100.0) * width));
        if (filled > width) filled = width;
        std::string bar = "[";
        if (colored) bar += color;
        bar += std::string(filled, '#');
        if (colored) bar += COLOR_RESET;
        bar += std::string(width - filled, ' ') + "]";
        return bar;
    };

    oss << std::left << std::setw(8) << "TCP:"
        << drawBar(tcpPct, COLOR_CYAN, colored) << " "
        << std::fixed << std::setprecision(1) << std::setw(6) << tcpPct << "% ("
        << m_currentStats.tcp_packets << " pkts, " << formatBytes(m_currentStats.tcp_bytes) << ")\n";

    oss << std::left << std::setw(8) << "UDP:"
        << drawBar(udpPct, COLOR_YELLOW, colored) << " "
        << std::fixed << std::setprecision(1) << std::setw(6) << udpPct << "% ("
        << m_currentStats.udp_packets << " pkts, " << formatBytes(m_currentStats.udp_bytes) << ")\n";

    oss << std::left << std::setw(8) << "ICMP:"
        << drawBar(icmpPct, COLOR_MAGENTA, colored) << " "
        << std::fixed << std::setprecision(1) << std::setw(6) << icmpPct << "% ("
        << m_currentStats.icmp_packets << " pkts, " << formatBytes(m_currentStats.icmp_bytes) << ")\n";

    oss << std::left << std::setw(8) << "OTHER:"
        << drawBar(otherPct, COLOR_GRAY, colored) << " "
        << std::fixed << std::setprecision(1) << std::setw(6) << otherPct << "% ("
        << m_currentStats.other_packets << " pkts, " << formatBytes(m_currentStats.other_bytes) << ")\n";

    return oss.str();
}

} // namespace netguard
