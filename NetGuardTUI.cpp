#include "NetGuardTUI.hpp"
#include <ncurses.h>
#include <iostream>
#include <thread>
#include <chrono>
#include <arpa/inet.h>
#include <iomanip>
#include <sstream>

namespace netguard {

NetGuardTUI::NetGuardTUI()
    : m_running(true)
{
}

NetGuardTUI::~NetGuardTUI() {
    endwin();
    m_client.disconnect();
}

bool NetGuardTUI::init() {
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    nodelay(stdscr, TRUE);
    curs_set(0);

    if (has_colors()) {
        start_color();
        init_pair(1, COLOR_CYAN, COLOR_BLACK);
        init_pair(2, COLOR_GREEN, COLOR_BLACK);
        init_pair(3, COLOR_RED, COLOR_BLACK);
        init_pair(4, COLOR_YELLOW, COLOR_BLACK);
        init_pair(5, COLOR_MAGENTA, COLOR_BLACK);
        init_pair(6, COLOR_WHITE, COLOR_BLUE);
        init_pair(7, COLOR_BLACK, COLOR_CYAN);
    }

    m_client.connect();
    updateData();
    return true;
}

void NetGuardTUI::updateData() {
    if (!m_client.isConnected()) {
        m_client.connect();
    }

    if (m_client.isConnected()) {
        struct netguard_stats st;
        std::string err;
        if (m_client.getStats(st, err)) {
            m_stats.update(st);
        }
        m_client.getRules(m_rules, err);
        m_client.getRecentEvents(m_events, err);
    }
}

void NetGuardTUI::render() {
    erase();
    int rows, cols;
    getmaxyx(stdscr, rows, cols);

    // Top Header Banner
    attron(COLOR_PAIR(7) | A_BOLD);
    mvhline(0, 0, ' ', cols);
    mvprintw(0, 2, "NETGUARD: KERNEL-SPACE PACKET FILTER & RULE ENFORCEMENT AGENT NOC");
    std::string uptimeStr = "UPTIME: " + Statistics::formatUptime(m_stats.current().module_uptime_sec);
    mvprintw(0, cols - (int)uptimeStr.length() - 2, "%s", uptimeStr.c_str());
    attroff(COLOR_PAIR(7) | A_BOLD);

    // System Status Card (Left top)
    const auto &st = m_stats.current();
    auto rates = m_stats.getRates();

    attron(COLOR_PAIR(1) | A_BOLD);
    mvprintw(2, 2, "[ SYSTEM & KERNEL STATUS ]");
    attroff(COLOR_PAIR(1) | A_BOLD);

    mvprintw(3, 4, "Kernel Module:    ");
    if (m_client.isConnected()) {
        attron(COLOR_PAIR(2) | A_BOLD); printw("ACTIVE (GPL)"); attroff(COLOR_PAIR(2) | A_BOLD);
    } else {
        attron(COLOR_PAIR(3) | A_BOLD); printw("OFFLINE"); attroff(COLOR_PAIR(3) | A_BOLD);
    }

    mvprintw(4, 4, "Netfilter Hooks:  ");
    if (st.hooks_active) {
        attron(COLOR_PAIR(2) | A_BOLD); printw("REGISTERED (IN, OUT, FWD)"); attroff(COLOR_PAIR(2) | A_BOLD);
    } else {
        attron(COLOR_PAIR(3) | A_BOLD); printw("INACTIVE"); attroff(COLOR_PAIR(3) | A_BOLD);
    }

    mvprintw(5, 4, "Netlink Socket:   ");
    attron(COLOR_PAIR(1)); printw("CONNECTED (FAMILY 31)"); attroff(COLOR_PAIR(1));

    mvprintw(6, 4, "Default Policy:   ");
    if (st.default_policy == NETGUARD_POLICY_ACCEPT) {
        attron(COLOR_PAIR(2) | A_BOLD); printw("ACCEPT (Permissive)"); attroff(COLOR_PAIR(2) | A_BOLD);
    } else {
        attron(COLOR_PAIR(3) | A_BOLD); printw("DROP (Zero-Trust)"); attroff(COLOR_PAIR(3) | A_BOLD);
    }

    mvprintw(7, 4, "Active Rules:     %u", st.active_rules_count);

    // Traffic Overview (Right top)
    int midX = cols / 2;
    attron(COLOR_PAIR(1) | A_BOLD);
    mvprintw(2, midX, "[ TRAFFIC OVERVIEW & VOLUMES ]");
    attroff(COLOR_PAIR(1) | A_BOLD);

    mvprintw(3, midX + 2, "Total Packets:    %llu (%s)", (unsigned long long)st.total_packets, Statistics::formatBytes(st.total_bytes).c_str());
    mvprintw(4, midX + 2, "Accepted:         ");
    attron(COLOR_PAIR(2)); printw("%llu (%s)", (unsigned long long)st.accepted_packets, Statistics::formatBytes(st.accepted_bytes).c_str()); attroff(COLOR_PAIR(2));

    mvprintw(5, midX + 2, "Dropped:          ");
    attron(COLOR_PAIR(3) | A_BOLD); printw("%llu (%s)", (unsigned long long)st.dropped_packets, Statistics::formatBytes(st.dropped_bytes).c_str()); attroff(COLOR_PAIR(3) | A_BOLD);

    mvprintw(6, midX + 2, "Throughput:       %.1f pkts/s (%.1f KB/s)", rates.packetsPerSec, rates.bytesPerSec / 1024.0);
    mvprintw(7, midX + 2, "Drop Rate:        ");
    attron(COLOR_PAIR(3)); printw("%.1f drops/s", rates.droppedPerSec); attroff(COLOR_PAIR(3));

    // Protocol Breakdown (Row 9)
    attron(COLOR_PAIR(1) | A_BOLD);
    mvprintw(9, 2, "[ PROTOCOL DISTRIBUTION ]");
    attroff(COLOR_PAIR(1) | A_BOLD);

    uint64_t total = st.total_packets ? st.total_packets : 1;
    mvprintw(10, 4, "TCP: %llu (%.1f%%)  |  UDP: %llu (%.1f%%)  |  ICMP: %llu (%.1f%%)  |  OTHER: %llu (%.1f%%)",
             (unsigned long long)st.tcp_packets, (double)st.tcp_packets * 100.0 / total,
             (unsigned long long)st.udp_packets, (double)st.udp_packets * 100.0 / total,
             (unsigned long long)st.icmp_packets, (double)st.icmp_packets * 100.0 / total,
             (unsigned long long)st.other_packets, (double)st.other_packets * 100.0 / total);

    // Active Rules Table
    attron(COLOR_PAIR(1) | A_BOLD);
    mvprintw(12, 2, "[ CONFIGURED PACKET FILTERING RULES (%zu) ]", m_rules.size());
    attroff(COLOR_PAIR(1) | A_BOLD);

    attron(A_UNDERLINE);
    mvprintw(13, 2, "%-6s %-8s %-5s %-16s %-16s %-6s %-8s %-6s %-8s %-9s %s",
             "ID", "STATUS", "PRIO", "SOURCE", "DESTINATION", "PROTO", "PORT", "DIR", "ACTION", "PACKETS", "DESCRIPTION");
    attroff(A_UNDERLINE);

    int rRow = 14;
    for (size_t i = 0; i < m_rules.size() && rRow < 22; i++) {
        const auto &r = m_rules[i];
        int colPair = (r.action == NETGUARD_ACTION_DROP) ? 3 : (r.action == NETGUARD_ACTION_ACCEPT ? 2 : 4);
        if (!r.enabled) colPair = 0;

        attron(COLOR_PAIR(colPair));
        mvprintw(rRow, 2, "%-6u %-8s %-5u %-16s %-16s %-6s %-8s %-6s %-8s %-9llu %s",
                 r.id, r.enabled ? "ENABLED" : "DISABLED", r.priority,
                 RuleManager::formatIpCidr(r.src_ip, r.src_mask).c_str(),
                 RuleManager::formatIpCidr(r.dst_ip, r.dst_mask).c_str(),
                 RuleManager::formatProtocol(r.protocol).c_str(),
                 RuleManager::formatPortRange(r.dst_port_min, r.dst_port_max).c_str(),
                 RuleManager::formatDirection(r.direction).c_str(),
                 RuleManager::formatAction(r.action).c_str(),
                 (unsigned long long)r.packet_count, r.description);
        attroff(COLOR_PAIR(colPair));
        rRow++;
    }

    if (m_rules.empty()) {
        mvprintw(14, 4, "(No rules configured)");
        rRow = 15;
    }

    // Live Activity Stream
    int actStart = rRow + 1;
    if (actStart < rows - 3) {
        attron(COLOR_PAIR(1) | A_BOLD);
        mvprintw(actStart, 2, "[ RECENT NETFILTER PACKET EVENTS ]");
        attroff(COLOR_PAIR(1) | A_BOLD);

        attron(A_UNDERLINE);
        mvprintw(actStart + 1, 2, "%-10s %-18s %-18s %-6s %-12s %-8s %-8s %s",
                 "TIME", "SOURCE", "DESTINATION", "PROTO", "PORTS", "ACTION", "RULE", "LENGTH");
        attroff(A_UNDERLINE);

        int evRow = actStart + 2;
        for (int i = (int)m_events.size() - 1; i >= 0 && evRow < rows - 2; i--, evRow++) {
            const auto &e = m_events[i];
            char sBuf[32], dBuf[32];
            struct in_addr sa, da;
            sa.s_addr = e.src_ip;
            da.s_addr = e.dst_ip;
            inet_ntop(AF_INET, &sa, sBuf, sizeof(sBuf));
            inet_ntop(AF_INET, &da, dBuf, sizeof(dBuf));

            int actCol = (e.action == NETGUARD_ACTION_DROP) ? 3 : (e.action == NETGUARD_ACTION_ACCEPT ? 2 : 4);
            std::string portStr = std::to_string(e.src_port) + "->" + std::to_string(e.dst_port);

            mvprintw(evRow, 2, "%-10llu %-18s %-18s %-6s %-12s ",
                     (unsigned long long)(e.timestamp_sec % 1000), sBuf, dBuf,
                     RuleManager::formatProtocol(e.protocol).c_str(),
                     portStr.c_str());

            attron(COLOR_PAIR(actCol) | A_BOLD);
            printw("%-8s ", RuleManager::formatAction(e.action).c_str());
            attroff(COLOR_PAIR(actCol) | A_BOLD);

            printw("%-8s %u B", e.matched_rule_id ? ("#" + std::to_string(e.matched_rule_id)).c_str() : "DEFAULT", e.packet_len);
        }
    }

    // Bottom Status / Help bar
    attron(COLOR_PAIR(6) | A_BOLD);
    mvhline(rows - 1, 0, ' ', cols);
    mvprintw(rows - 1, 2, " [Q] Quit  |  [R] Reset Stats  |  [P] Toggle Default Policy (ACCEPT/DROP)  |  [C] Clear Rules ");
    attroff(COLOR_PAIR(6) | A_BOLD);

    refresh();
}

void NetGuardTUI::handleInput(int ch) {
    if (ch == 'q' || ch == 'Q') {
        m_running = false;
    } else if (ch == 'r' || ch == 'R') {
        std::string err;
        m_client.resetStats(err);
        updateData();
    } else if (ch == 'p' || ch == 'P') {
        bool isAccept = (m_stats.current().default_policy == NETGUARD_POLICY_ACCEPT);
        std::string err;
        m_client.setDefaultPolicy(isAccept ? NETGUARD_POLICY_DROP : NETGUARD_POLICY_ACCEPT, err);
        updateData();
    } else if (ch == 'c' || ch == 'C') {
        std::string err;
        m_client.clearRules(err);
        updateData();
    }
}

void NetGuardTUI::run() {
    auto lastUpdate = std::chrono::steady_clock::now();

    while (m_running) {
        int ch = getch();
        if (ch != ERR) {
            handleInput(ch);
        }

        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::milliseconds>(now - lastUpdate).count() >= 500) {
            updateData();
            lastUpdate = now;
        }

        render();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

} // namespace netguard
