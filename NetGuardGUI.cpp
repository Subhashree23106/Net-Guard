#include "NetGuardGUI.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <thread>
#include <chrono>
#include <cmath>
#include <cstring>
#include <algorithm>
#include <arpa/inet.h>
#include <X11/keysym.h>

namespace netguard {

// Premium Cybersecurity Modern Dark Palette
static const Color BG_DARK        = Color(11, 15, 23);       // #0b0f17
static const Color BG_PANEL       = Color(20, 27, 40);       // #141b28
static const Color BG_CARD        = Color(28, 38, 55);       // #1c2637
static const Color BG_INPUT       = Color(15, 21, 33);       // #0f1521
static const Color BG_ZEBRA       = Color(16, 23, 35);       // #101723
static const Color BG_HOVER       = Color(38, 52, 75);       // #26344b
static const Color BORDER_SUBTLE  = Color(42, 57, 82);       // #2a3952
static const Color BORDER_ACCENT  = Color(0, 229, 255);      // #00e5ff
static const Color TEXT_PRIMARY   = Color(245, 247, 250);    // #f5f7fa
static const Color TEXT_MUTED     = Color(148, 163, 184);    // #94a3b8
static const Color TEXT_CYAN      = Color(0, 229, 255);      // #00e5ff
static const Color COLOR_CYAN     = Color(0, 229, 255);      // #00e5ff
static const Color COLOR_GREEN    = Color(0, 230, 118);      // #00e676
static const Color COLOR_RED      = Color(255, 23, 68);       // #ff1744
static const Color COLOR_YELLOW   = Color(255, 171, 0);      // #ffab00
static const Color COLOR_BLUE     = Color(41, 121, 255);     // #2979ff
static const Color COLOR_PURPLE   = Color(179, 136, 255);    // #b388ff
static const Color BADGE_DROP_BG  = Color(90, 15, 30);       // Dark red pill
static const Color BADGE_ACCEPT_BG= Color(15, 75, 40);       // Dark green pill

NetGuardGUI::NetGuardGUI(int width, int height)
    : m_canvas(width, height, "NetGuard - Kernel-Space Packet Filter & NOC Console"),
      m_currentTab(GuiTab::DASHBOARD),
      m_running(true),
      m_showAddDialog(false),
      m_showEditDialog(false),
      m_selectedRuleId(0),
      m_statusMessage("NetGuard Kernel Agent Ready"),
      m_statusColor(COLOR_GREEN),
      m_isEditMode(false),
      m_selectedProtoIdx(0),
      m_selectedActionIdx(0),
      m_selectedDirIdx(0),
      m_ruleEnabled(true),
      m_pausedStream(false),
      m_mouseX(0),
      m_mouseY(0)
{
    m_statusTime = std::chrono::steady_clock::now();

    // Initialize Add/Edit Rule Fields
    m_fieldId        = { "Rule ID", "101", "e.g. 101", 0, 0, 0, 0, false };
    m_fieldPriority  = { "Priority", "100", "1-1000", 0, 0, 0, 0, false };
    m_fieldSrcIp     = { "Source IP / CIDR", "any", "e.g. 192.168.1.100 or any", 0, 0, 0, 0, false };
    m_fieldDstIp     = { "Dest IP / CIDR", "any", "e.g. 10.0.0.1 or any", 0, 0, 0, 0, false };
    m_fieldDstPort   = { "Dest Port", "22", "e.g. 22, 80, any", 0, 0, 0, 0, false };
    m_fieldDesc      = { "Description", "Block SSH Traffic", "Rule description", 0, 0, 0, 0, false };

    // Search Fields
    m_ruleSearchField   = { "Filter Rules", "", "Search rules...", 0, 0, 0, 0, false };
    m_packetSearchField = { "Filter Stream", "", "Search packets...", 0, 0, 0, 0, false };

    // Rate history initialization
    for (int i = 0; i < 60; i++) {
        m_rateHistory.push_back(0.0);
    }
}

NetGuardGUI::~NetGuardGUI() {
    m_client.disconnect();
}

bool NetGuardGUI::init() {
    if (!m_canvas.init()) {
        std::cerr << "Failed to initialize X11 canvas\n";
        return false;
    }

    if (!m_client.connect()) {
        setStatus("Warning: Kernel module not connected. Load netguard_mod.ko as root.", COLOR_RED);
    } else {
        setStatus("Connected to NetGuard Kernel Netfilter Hook Engine.", COLOR_GREEN);
    }

    updateData();
    return true;
}

void NetGuardGUI::setStatus(const std::string &msg, const Color &c) {
    m_statusMessage = msg;
    m_statusColor = c;
    m_statusTime = std::chrono::steady_clock::now();
}

void NetGuardGUI::updateData() {
    if (!m_client.isConnected()) {
        m_client.connect();
    }

    if (m_client.isConnected()) {
        struct netguard_stats st;
        std::string err;
        if (m_client.getStats(st, err)) {
            m_stats.update(st);

            m_rateHistory.pop_front();
            m_rateHistory.push_back(m_stats.getRates().packetsPerSec);
        }

        m_client.getRules(m_rules, err);
        if (!m_pausedStream) {
            m_client.getRecentEvents(m_events, err);
        }
    }
}

void NetGuardGUI::handleMouseMove(int x, int y) {
    m_mouseX = x;
    m_mouseY = y;
}

void NetGuardGUI::run() {
    auto lastUpdate = std::chrono::steady_clock::now();

    while (m_running) {
        // Process X11 Events
        while (XPending(m_canvas.display())) {
            XEvent ev;
            XNextEvent(m_canvas.display(), &ev);

            if (ev.type == ClientMessage) {
                m_running = false;
                break;
            } else if (ev.type == ButtonPress) {
                if (ev.xbutton.button == Button1) {
                    handleMouseClick(ev.xbutton.x, ev.xbutton.y);
                }
            } else if (ev.type == MotionNotify) {
                handleMouseMove(ev.xmotion.x, ev.xmotion.y);
            } else if (ev.type == ConfigureNotify) {
                m_canvas.handleResize(ev.xconfigure.width, ev.xconfigure.height);
            } else if (ev.type == KeyPress) {
                char buf[32];
                KeySym sym;
                int len = XLookupString(&ev.xkey, buf, sizeof(buf) - 1, &sym, nullptr);
                buf[std::max(0, len)] = '\0';
                handleKeyPress(sym, std::string(buf));
            } else if (ev.type == Expose) {
                // Redraw handled in main loop
            }
        }

        // Periodic 500ms kernel data update
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::milliseconds>(now - lastUpdate).count() >= 500) {
            updateData();
            lastUpdate = now;
        }

        render();
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
}

void NetGuardGUI::render() {
    m_canvas.beginFrame();
    m_canvas.clear(BG_DARK);

    renderHeader();
    renderTabs();

    if (m_currentTab == GuiTab::DASHBOARD) {
        renderDashboardTab();
    } else if (m_currentTab == GuiTab::RULES) {
        renderRulesTab();
    } else if (m_currentTab == GuiTab::LIVE_PACKETS) {
        renderLivePacketsTab();
    } else if (m_currentTab == GuiTab::QUICK_DEFENSE) {
        renderQuickDefenseTab();
    }

    renderFooter();

    if (m_showAddDialog) {
        renderAddRuleModal();
    }

    m_canvas.endFrame();
}

void NetGuardGUI::renderHeader() {
    int w = m_canvas.width();

    // Top navigation bar background
    m_canvas.fillRect(0, 0, w, 56, BG_PANEL);
    m_canvas.drawLine(0, 56, w, 56, BORDER_SUBTLE, 1);

    // Brand Title & Shield Icon
    m_canvas.fillRoundedRect(16, 12, 32, 32, 6, BG_CARD);
    m_canvas.drawRoundedRect(16, 12, 32, 32, 6, TEXT_CYAN, 1);
    m_canvas.drawTextCentered(16, 12, 32, 32, "NG", TEXT_CYAN, 12, true);

    m_canvas.drawText(58, 28, "NETGUARD NOC CONSOLE", TEXT_PRIMARY, 14, true);
    m_canvas.drawText(58, 44, "KERNEL PACKET FILTER & POLICY ENFORCEMENT ENGINE", TEXT_MUTED, 8, false);

    // Status Badges (Right side)
    int badgeX = w - 460;
    bool kmodActive = m_client.isConnected();
    m_canvas.fillRoundedRect(badgeX, 16, 130, 24, 4, BG_CARD);
    m_canvas.fillRoundedRect(badgeX + 8, 24, 8, 8, 4, kmodActive ? COLOR_GREEN : COLOR_RED);
    m_canvas.drawText(badgeX + 22, 33, kmodActive ? "KERNEL: ACTIVE" : "KERNEL: OFFLINE", kmodActive ? COLOR_GREEN : COLOR_RED, 9, true);

    badgeX += 140;
    bool hooksActive = m_stats.current().hooks_active;
    m_canvas.fillRoundedRect(badgeX, 16, 140, 24, 4, BG_CARD);
    m_canvas.fillRoundedRect(badgeX + 8, 24, 8, 8, 4, hooksActive ? COLOR_GREEN : COLOR_YELLOW);
    m_canvas.drawText(badgeX + 22, 33, hooksActive ? "NETFILTER: HOOKED" : "NETFILTER: IDLE", hooksActive ? COLOR_GREEN : COLOR_YELLOW, 9, true);

    badgeX += 150;
    m_canvas.fillRoundedRect(badgeX, 16, 150, 24, 4, BG_CARD);
    m_canvas.drawText(badgeX + 12, 33, "UPTIME: " + Statistics::formatUptime(m_stats.current().module_uptime_sec), TEXT_CYAN, 9, true);
}

void NetGuardGUI::renderTabs() {
    int w = m_canvas.width();
    m_canvas.fillRect(0, 57, w, 42, BG_PANEL);
    m_canvas.drawLine(0, 99, w, 99, BORDER_SUBTLE, 1);

    struct TabItem {
        GuiTab tab;
        std::string label;
        int x, w;
    };

    std::vector<TabItem> tabs = {
        { GuiTab::DASHBOARD,     "DASHBOARD & MONITOR",   20, 200 },
        { GuiTab::RULES,         "RULE MANAGEMENT (" + std::to_string(m_rules.size()) + ")", 230, 210 },
        { GuiTab::LIVE_PACKETS,  "LIVE PACKET STREAM",       450, 190 },
        { GuiTab::QUICK_DEFENSE, "QUICK DEFENSE / SHIELD",   650, 210 }
    };

    for (const auto &t : tabs) {
        bool active = (m_currentTab == t.tab);
        bool hovered = (m_mouseX >= t.x && m_mouseX <= t.x + t.w && m_mouseY >= 64 && m_mouseY <= 94);

        if (active) {
            m_canvas.fillRoundedRect(t.x, 64, t.w, 30, 4, BG_CARD);
            m_canvas.drawRoundedRect(t.x, 64, t.w, 30, 4, TEXT_CYAN, 1);
            m_canvas.drawTextCentered(t.x, 64, t.w, 30, t.label, TEXT_CYAN, 10, true);
        } else if (hovered) {
            m_canvas.fillRoundedRect(t.x, 64, t.w, 30, 4, BG_HOVER);
            m_canvas.drawRoundedRect(t.x, 64, t.w, 30, 4, BORDER_SUBTLE, 1);
            m_canvas.drawTextCentered(t.x, 64, t.w, 30, t.label, TEXT_PRIMARY, 10, true);
        } else {
            m_canvas.drawTextCentered(t.x, 64, t.w, 30, t.label, TEXT_MUTED, 10, false);
        }
    }
}

void NetGuardGUI::renderDashboardTab() {
    int w = m_canvas.width();
    int h = m_canvas.height();
    const auto &st = m_stats.current();
    auto rates = m_stats.getRates();

    // 3 Equal Top Cards
    int gap = 16;
    int topW = (w - 40 - 2 * gap) / 3;

    // 1. System Status Card (Top Left)
    m_canvas.drawCard(20, 110, topW, 220, "SYSTEM & KERNEL STATUS", BG_PANEL, BORDER_SUBTLE);
    int sy = 152;
    auto drawStatusRow = [&](const std::string &lbl, const std::string &val, const Color &valColor) {
        m_canvas.drawText(36, sy, lbl, TEXT_MUTED, 9, false);
        m_canvas.drawText(200, sy, val, valColor, 9, true);
        sy += 25;
    };

    drawStatusRow("Kernel Module:", m_client.isConnected() ? "● ACTIVE (GPL)" : "● OFFLINE", m_client.isConnected() ? COLOR_GREEN : COLOR_RED);
    drawStatusRow("Netfilter Hooks:", st.hooks_active ? "● REGISTERED" : "● INACTIVE", st.hooks_active ? COLOR_GREEN : COLOR_RED);
    drawStatusRow("Netlink Protocol:", "● FAMILY 31 (NETGUARD)", COLOR_CYAN);
    drawStatusRow("Default Policy:", (st.default_policy == NETGUARD_POLICY_ACCEPT) ? "ACCEPT (Permissive)" : "DROP (Zero-Trust)", (st.default_policy == NETGUARD_POLICY_ACCEPT) ? COLOR_GREEN : COLOR_RED);
    drawStatusRow("Active Rule Count:", std::to_string(st.active_rules_count) + " Rules", TEXT_PRIMARY);
    drawStatusRow("Agent Lifecycle:", "● RUNNING (C++17)", COLOR_GREEN);

    // 2. Traffic Overview Card (Top Center)
    int top2X = 20 + topW + gap;
    m_canvas.drawCard(top2X, 110, topW, 220, "TRAFFIC OVERVIEW & VOLUMES", BG_PANEL, BORDER_SUBTLE);
    int ty = 152;
    auto drawTrafficRow = [&](const std::string &lbl, const std::string &pkts, const std::string &bytes, const Color &c) {
        m_canvas.drawText(top2X + 16, ty, lbl, TEXT_MUTED, 9, false);
        m_canvas.drawText(top2X + 150, ty, pkts, c, 9, true);
        m_canvas.drawText(top2X + 270, ty, bytes, TEXT_PRIMARY, 9, false);
        ty += 25;
    };

    drawTrafficRow("Total Inspected:", std::to_string(st.total_packets), Statistics::formatBytes(st.total_bytes), TEXT_CYAN);
    drawTrafficRow("Accepted Packets:", std::to_string(st.accepted_packets), Statistics::formatBytes(st.accepted_bytes), COLOR_GREEN);
    drawTrafficRow("Dropped Packets:", std::to_string(st.dropped_packets), Statistics::formatBytes(st.dropped_bytes), COLOR_RED);
    drawTrafficRow("Rejected Packets:", std::to_string(st.rejected_packets), Statistics::formatBytes(st.rejected_bytes), COLOR_YELLOW);
    drawTrafficRow("Live Throughput:", std::to_string((int)rates.packetsPerSec) + " pkts/s", Statistics::formatBytes((uint64_t)rates.bytesPerSec) + "/s", COLOR_PURPLE);
    drawTrafficRow("Drop Rate:", std::to_string((int)rates.droppedPerSec) + " drops/s", "", COLOR_RED);

    // 3. Protocol Breakdown Card (Top Right)
    int top3X = 20 + 2 * (topW + gap);
    int top3W = w - 20 - top3X;
    m_canvas.drawCard(top3X, 110, top3W, 220, "PROTOCOL STATISTICS", BG_PANEL, BORDER_SUBTLE);
    uint64_t total = st.total_packets ? st.total_packets : 1;
    double tcpPct  = (double)st.tcp_packets * 100.0 / total;
    double udpPct  = (double)st.udp_packets * 100.0 / total;
    double icmpPct = (double)st.icmp_packets * 100.0 / total;
    double othPct  = (double)st.other_packets * 100.0 / total;

    int py = 152;
    int pBarW = std::max(60, top3W - 200);
    auto drawProtoRow = [&](const std::string &name, double pct, uint64_t pkts, const Color &col) {
        m_canvas.drawText(top3X + 16, py, name, TEXT_PRIMARY, 9, true);
        m_canvas.drawProgressBar(top3X + 70, py - 10, pBarW, 12, pct / 100.0, col, BG_CARD);
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(1) << pct << "% (" << pkts << ")";
        m_canvas.drawText(top3X + 75 + pBarW, py, ss.str(), TEXT_MUTED, 8, false);
        py += 33;
    };

    drawProtoRow("TCP", tcpPct, st.tcp_packets, TEXT_CYAN);
    drawProtoRow("UDP", udpPct, st.udp_packets, COLOR_YELLOW);
    drawProtoRow("ICMP", icmpPct, st.icmp_packets, COLOR_PURPLE);
    drawProtoRow("OTHER", othPct, st.other_packets, TEXT_MUTED);

    // Bottom Row Layout
    int botY = 345;
    int botH = h - botY - 45;
    int botW1 = static_cast<int>((w - 40 - gap) * 0.48);
    int botW2 = w - 40 - gap - botW1;

    // 4. Real-time Live Throughput Line Graph (Bottom Left)
    m_canvas.drawCard(20, botY, botW1, botH, "REAL-TIME TRAFFIC THROUGHPUT (PACKETS / SEC)", BG_PANEL, BORDER_SUBTLE);

    int gx = 35, gy = botY + 45, gw = botW1 - 30, gh = botH - 65;
    m_canvas.fillRect(gx, gy, gw, gh, BG_INPUT);
    m_canvas.drawRect(gx, gy, gw, gh, BORDER_SUBTLE, 1);

    // Grid lines
    for (int i = 1; i <= 4; i++) {
        int y = gy + (gh * i / 5);
        m_canvas.drawLine(gx, y, gx + gw, y, Color(22, 32, 48), 1);
    }

    double maxVal = 10.0;
    for (double val : m_rateHistory) {
        if (val > maxVal) maxVal = val;
    }

    // Draw sparkline / chart
    int n = m_rateHistory.size();
    if (n > 1) {
        double stepX = (double)gw / (n - 1);
        for (int i = 0; i < n - 1; i++) {
            int x1 = gx + (int)(i * stepX);
            int y1 = gy + gh - (int)((m_rateHistory[i] / maxVal) * (gh - 20)) - 10;
            int x2 = gx + (int)((i + 1) * stepX);
            int y2 = gy + gh - (int)((m_rateHistory[i + 1] / maxVal) * (gh - 20)) - 10;
            m_canvas.drawLine(x1, y1, x2, y2, TEXT_CYAN, 2);
        }
    }

    m_canvas.drawText(gx + 10, gy + 20, "Peak: " + std::to_string((int)maxVal) + " pkts/s", TEXT_MUTED, 9, false);
    m_canvas.drawText(gx + gw - 130, gy + 20, "Current: " + std::to_string((int)rates.packetsPerSec) + " pps", TEXT_CYAN, 9, true);

    // 5. Recent Packet Activity Table (Bottom Right)
    int bot2X = 20 + botW1 + gap;
    m_canvas.drawCard(bot2X, botY, botW2, botH, "LIVE PACKET ACTIVITY STREAM", BG_PANEL, BORDER_SUBTLE);

    // Table Header
    int thY = botY + 45;
    m_canvas.drawText(bot2X + 16, thY, "TIME", TEXT_MUTED, 8, true);
    m_canvas.drawText(bot2X + 75, thY, "SOURCE", TEXT_MUTED, 8, true);
    m_canvas.drawText(bot2X + 195, thY, "DESTINATION", TEXT_MUTED, 8, true);
    m_canvas.drawText(bot2X + 315, thY, "PROTO", TEXT_MUTED, 8, true);
    m_canvas.drawText(bot2X + 375, thY, "PORT", TEXT_MUTED, 8, true);
    m_canvas.drawText(bot2X + 435, thY, "ACTION", TEXT_MUTED, 8, true);
    m_canvas.drawText(bot2X + 515, thY, "RULE", TEXT_MUTED, 8, true);
    m_canvas.drawLine(bot2X + 10, thY + 8, bot2X + botW2 - 10, thY + 8, BORDER_SUBTLE, 1);

    int rowY = thY + 28;
    int maxRows = (botH - 85) / 25;
    int displayed = 0;
    for (int i = (int)m_events.size() - 1; i >= 0 && displayed < maxRows; i--, displayed++) {
        const auto &e = m_events[i];
        char sBuf[32], dBuf[32];
        struct in_addr sa, da;
        sa.s_addr = e.src_ip;
        da.s_addr = e.dst_ip;
        inet_ntop(AF_INET, &sa, sBuf, sizeof(sBuf));
        inet_ntop(AF_INET, &da, dBuf, sizeof(dBuf));

        Color actColor = (e.action == NETGUARD_ACTION_DROP) ? COLOR_RED :
                         (e.action == NETGUARD_ACTION_ACCEPT) ? COLOR_GREEN : COLOR_YELLOW;

        if (displayed % 2 == 1) {
            m_canvas.fillRect(bot2X + 10, rowY - 14, botW2 - 20, 22, BG_ZEBRA);
        }

        std::string timeStr = std::to_string(e.timestamp_sec % 1000) + "." + std::to_string(e.timestamp_usec / 100000);
        m_canvas.drawText(bot2X + 16, rowY, timeStr, TEXT_MUTED, 8, false);
        m_canvas.drawText(bot2X + 75, rowY, sBuf, TEXT_PRIMARY, 8, false);
        m_canvas.drawText(bot2X + 195, rowY, dBuf, TEXT_PRIMARY, 8, false);
        m_canvas.drawText(bot2X + 315, rowY, RuleManager::formatProtocol(e.protocol), TEXT_CYAN, 8, false);
        m_canvas.drawText(bot2X + 375, rowY, std::to_string(e.dst_port), TEXT_PRIMARY, 8, false);
        m_canvas.drawPillBadge(bot2X + 435, rowY - 12, 65, 18, RuleManager::formatAction(e.action), (e.action == NETGUARD_ACTION_DROP) ? BADGE_DROP_BG : BADGE_ACCEPT_BG, actColor, true);
        m_canvas.drawText(bot2X + 515, rowY, e.matched_rule_id ? ("#" + std::to_string(e.matched_rule_id)) : "DEF", TEXT_MUTED, 8, false);

        rowY += 25;
    }

    if (m_events.empty()) {
        m_canvas.drawTextCentered(bot2X, botY + 150, botW2, 30, "No packet activity captured yet", TEXT_MUTED, 11, false);
    }
}

void NetGuardGUI::renderRulesTab() {
    int w = m_canvas.width();
    int h = m_canvas.height();

    // Top Action Bar for Rules
    m_canvas.fillRect(20, 110, w - 40, 50, BG_PANEL);
    m_canvas.drawRect(20, 110, w - 40, 50, BORDER_SUBTLE, 1);

    auto drawBtn = [&](int x, int y, int bw, int bh, const std::string &lbl, const Color &fillC, const Color &borderC, const Color &textC, bool bold) {
        bool hovered = (m_mouseX >= x && m_mouseX <= x + bw && m_mouseY >= y && m_mouseY <= y + bh);
        Color c = hovered ? BG_HOVER : fillC;
        m_canvas.fillRoundedRect(x, y, bw, bh, 4, c);
        m_canvas.drawRoundedRect(x, y, bw, bh, 4, hovered ? COLOR_CYAN : borderC, 1);
        m_canvas.drawTextCentered(x, y, bw, bh, lbl, textC, 9, bold);
    };

    // Organized Button Bar
    drawBtn(35, 120, 105, 30, "+ ADD RULE", COLOR_BLUE, COLOR_BLUE, TEXT_PRIMARY, true);
    drawBtn(148, 120, 95, 30, "EDIT RULE", BG_CARD, BORDER_SUBTLE, TEXT_CYAN, true);
    drawBtn(251, 120, 130, 30, "ENABLE/DISABLE", BG_CARD, BORDER_SUBTLE, TEXT_PRIMARY, false);
    drawBtn(389, 120, 100, 30, "DELETE RULE", BG_CARD, COLOR_RED, COLOR_RED, true);
    drawBtn(497, 120, 75, 30, "EXPORT", BG_CARD, BORDER_SUBTLE, TEXT_MUTED, false);
    drawBtn(580, 120, 75, 30, "IMPORT", BG_CARD, BORDER_SUBTLE, TEXT_MUTED, false);
    drawBtn(663, 120, 75, 30, "REFRESH", BG_CARD, BORDER_SUBTLE, TEXT_MUTED, false);
    drawBtn(746, 120, 90, 30, "CLEAR ALL", BG_CARD, COLOR_YELLOW, COLOR_YELLOW, false);

    // Search Field Input Box
    m_ruleSearchField.x = w - 370;
    m_ruleSearchField.y = 120;
    m_ruleSearchField.w = 150;
    m_ruleSearchField.h = 30;
    m_canvas.fillRoundedRect(m_ruleSearchField.x, m_ruleSearchField.y, m_ruleSearchField.w, m_ruleSearchField.h, 4, BG_INPUT);
    m_canvas.drawRoundedRect(m_ruleSearchField.x, m_ruleSearchField.y, m_ruleSearchField.w, m_ruleSearchField.h, 4, m_ruleSearchField.active ? TEXT_CYAN : BORDER_SUBTLE, 1);
    std::string sDisp = m_ruleSearchField.value.empty() ? m_ruleSearchField.placeholder : m_ruleSearchField.value;
    m_canvas.drawText(m_ruleSearchField.x + 8, m_ruleSearchField.y + 20, sDisp + (m_ruleSearchField.active ? "|" : ""), m_ruleSearchField.value.empty() ? TEXT_MUTED : TEXT_PRIMARY, 9, false);

    // Default Policy Button
    bool isAccept = (m_stats.current().default_policy == NETGUARD_POLICY_ACCEPT);
    drawBtn(w - 205, 120, 170, 30, isAccept ? "POLICY: ACCEPT" : "POLICY: DROP", isAccept ? BG_CARD : BADGE_DROP_BG, isAccept ? COLOR_GREEN : COLOR_RED, isAccept ? COLOR_GREEN : TEXT_PRIMARY, true);

    // Main Rules Table Card
    int tableH = h - 220;
    m_canvas.drawCard(20, 170, w - 40, tableH, "ACTIVE KERNEL NETFILTER FILTERING RULES (" + std::to_string(m_rules.size()) + " CONFIGURED)", BG_PANEL, BORDER_SUBTLE);

    // Columns Header
    int ry = 210;
    m_canvas.drawText(35, ry, "ID", TEXT_MUTED, 9, true);
    m_canvas.drawText(85, ry, "STATUS", TEXT_MUTED, 9, true);
    m_canvas.drawText(160, ry, "PRIO", TEXT_MUTED, 9, true);
    m_canvas.drawText(220, ry, "SOURCE IP/CIDR", TEXT_MUTED, 9, true);
    m_canvas.drawText(380, ry, "DEST IP/CIDR", TEXT_MUTED, 9, true);
    m_canvas.drawText(540, ry, "PROTO", TEXT_MUTED, 9, true);
    m_canvas.drawText(610, ry, "DPORT", TEXT_MUTED, 9, true);
    m_canvas.drawText(690, ry, "DIR", TEXT_MUTED, 9, true);
    m_canvas.drawText(750, ry, "ACTION", TEXT_MUTED, 9, true);
    m_canvas.drawText(840, ry, "PACKETS", TEXT_MUTED, 9, true);
    m_canvas.drawText(930, ry, "BYTES", TEXT_MUTED, 9, true);
    m_canvas.drawText(1040, ry, "DESCRIPTION", TEXT_MUTED, 9, true);
    m_canvas.drawLine(30, ry + 8, w - 30, ry + 8, BORDER_SUBTLE, 1);

    std::string searchQ = m_ruleSearchField.value;
    std::transform(searchQ.begin(), searchQ.end(), searchQ.begin(), ::tolower);

    int rowY = 240;
    int renderedRules = 0;
    for (size_t i = 0; i < m_rules.size() && rowY < h - 70; i++) {
        const auto &r = m_rules[i];

        // Search Filter Logic
        if (!searchQ.empty()) {
            std::string haystack = std::to_string(r.id) + " " +
                                   RuleManager::formatIpCidr(r.src_ip, r.src_mask) + " " +
                                   RuleManager::formatIpCidr(r.dst_ip, r.dst_mask) + " " +
                                   RuleManager::formatProtocol(r.protocol) + " " +
                                   RuleManager::formatAction(r.action) + " " +
                                   r.description;
            std::transform(haystack.begin(), haystack.end(), haystack.begin(), ::tolower);
            if (haystack.find(searchQ) == std::string::npos) {
                continue;
            }
        }

        renderedRules++;
        bool selected = (m_selectedRuleId == r.id);
        bool hovered = (m_mouseX >= 30 && m_mouseX <= w - 30 && m_mouseY >= rowY - 14 && m_mouseY <= rowY + 10);

        if (selected) {
            m_canvas.fillRect(30, rowY - 14, w - 60, 24, BG_CARD);
            m_canvas.drawRect(30, rowY - 14, w - 60, 24, TEXT_CYAN, 1);
        } else if (hovered) {
            m_canvas.fillRect(30, rowY - 14, w - 60, 24, BG_HOVER);
        } else if (i % 2 == 1) {
            m_canvas.fillRect(30, rowY - 14, w - 60, 24, BG_ZEBRA);
        }

        Color actColor = (r.action == NETGUARD_ACTION_DROP) ? COLOR_RED :
                         (r.action == NETGUARD_ACTION_ACCEPT) ? COLOR_GREEN : COLOR_YELLOW;

        m_canvas.drawText(35, rowY, std::to_string(r.id), TEXT_CYAN, 9, true);
        m_canvas.drawPillBadge(85, rowY - 12, 60, 18, r.enabled ? "ENABLED" : "DISABLED", r.enabled ? BADGE_ACCEPT_BG : BG_INPUT, r.enabled ? COLOR_GREEN : TEXT_MUTED, false);
        m_canvas.drawText(160, rowY, std::to_string(r.priority), TEXT_PRIMARY, 9, false);
        m_canvas.drawText(220, rowY, RuleManager::formatIpCidr(r.src_ip, r.src_mask), TEXT_PRIMARY, 9, false);
        m_canvas.drawText(380, rowY, RuleManager::formatIpCidr(r.dst_ip, r.dst_mask), TEXT_PRIMARY, 9, false);
        m_canvas.drawText(540, rowY, RuleManager::formatProtocol(r.protocol), TEXT_CYAN, 9, false);
        m_canvas.drawText(610, rowY, RuleManager::formatPortRange(r.dst_port_min, r.dst_port_max), TEXT_PRIMARY, 9, false);
        m_canvas.drawText(690, rowY, RuleManager::formatDirection(r.direction), TEXT_MUTED, 9, false);
        m_canvas.drawPillBadge(750, rowY - 12, 65, 18, RuleManager::formatAction(r.action), (r.action == NETGUARD_ACTION_DROP) ? BADGE_DROP_BG : BADGE_ACCEPT_BG, actColor, true);
        m_canvas.drawText(840, rowY, std::to_string(r.packet_count), TEXT_PRIMARY, 9, false);
        m_canvas.drawText(930, rowY, Statistics::formatBytes(r.byte_count), TEXT_PRIMARY, 9, false);
        m_canvas.drawText(1040, rowY, r.description, TEXT_MUTED, 9, false);

        rowY += 28;
    }

    if (m_rules.empty()) {
        m_canvas.drawTextCentered(20, 400, w - 40, 40, "No filtering rules configured. Click [+ ADD RULE] above or use Quick Defense.", TEXT_MUTED, 12, false);
    } else if (renderedRules == 0) {
        m_canvas.drawTextCentered(20, 400, w - 40, 40, "No rules matched your filter query: '" + m_ruleSearchField.value + "'", TEXT_MUTED, 12, false);
    }
}

void NetGuardGUI::renderLivePacketsTab() {
    int w = m_canvas.width();
    int h = m_canvas.height();
    int cardH = h - 155;
    m_canvas.drawCard(20, 110, w - 40, cardH, "REAL-TIME PACKET ACTIVITY LOG (NETFILTER HOOK EVENTS)", BG_PANEL, BORDER_SUBTLE);

    // Controls at top right of Card
    int pBtnX = w - 160;
    bool pbtnHover = (m_mouseX >= pBtnX && m_mouseX <= pBtnX + 130 && m_mouseY >= 118 && m_mouseY <= 142);
    m_canvas.fillRoundedRect(pBtnX, 118, 130, 24, 4, m_pausedStream ? COLOR_YELLOW : (pbtnHover ? BG_HOVER : BG_CARD));
    m_canvas.drawRoundedRect(pBtnX, 118, 130, 24, 4, m_pausedStream ? COLOR_YELLOW : BORDER_SUBTLE, 1);
    m_canvas.drawTextCentered(pBtnX, 118, 130, 24, m_pausedStream ? "▶ RESUME STREAM" : "⏸ PAUSE STREAM", m_pausedStream ? BG_DARK : TEXT_PRIMARY, 9, true);

    // Search filter input
    m_packetSearchField.x = w - 370;
    m_packetSearchField.y = 118;
    m_packetSearchField.w = 190;
    m_packetSearchField.h = 24;
    m_canvas.fillRoundedRect(m_packetSearchField.x, m_packetSearchField.y, m_packetSearchField.w, m_packetSearchField.h, 4, BG_INPUT);
    m_canvas.drawRoundedRect(m_packetSearchField.x, m_packetSearchField.y, m_packetSearchField.w, m_packetSearchField.h, 4, m_packetSearchField.active ? TEXT_CYAN : BORDER_SUBTLE, 1);
    std::string pDisp = m_packetSearchField.value.empty() ? m_packetSearchField.placeholder : m_packetSearchField.value;
    m_canvas.drawText(m_packetSearchField.x + 8, m_packetSearchField.y + 16, pDisp + (m_packetSearchField.active ? "|" : ""), m_packetSearchField.value.empty() ? TEXT_MUTED : TEXT_PRIMARY, 8, false);

    int ry = 150;
    m_canvas.drawText(35, ry, "TIMESTAMP", TEXT_MUTED, 9, true);
    m_canvas.drawText(140, ry, "SOURCE IP", TEXT_MUTED, 9, true);
    m_canvas.drawText(280, ry, "DESTINATION IP", TEXT_MUTED, 9, true);
    m_canvas.drawText(420, ry, "PROTO", TEXT_MUTED, 9, true);
    m_canvas.drawText(490, ry, "PORTS (SRC->DST)", TEXT_MUTED, 9, true);
    m_canvas.drawText(640, ry, "DIRECTION", TEXT_MUTED, 9, true);
    m_canvas.drawText(740, ry, "ACTION", TEXT_MUTED, 9, true);
    m_canvas.drawText(840, ry, "MATCHED RULE", TEXT_MUTED, 9, true);
    m_canvas.drawText(960, ry, "LENGTH", TEXT_MUTED, 9, true);
    m_canvas.drawText(1060, ry, "INTERFACE", TEXT_MUTED, 9, true);
    m_canvas.drawLine(30, ry + 8, w - 30, ry + 8, BORDER_SUBTLE, 1);

    std::string searchQ = m_packetSearchField.value;
    std::transform(searchQ.begin(), searchQ.end(), searchQ.begin(), ::tolower);

    int rowY = 180;
    for (int i = (int)m_events.size() - 1; i >= 0 && rowY < h - 65; i--) {
        const auto &e = m_events[i];
        char sBuf[32], dBuf[32];
        struct in_addr sa, da;
        sa.s_addr = e.src_ip;
        da.s_addr = e.dst_ip;
        inet_ntop(AF_INET, &sa, sBuf, sizeof(sBuf));
        inet_ntop(AF_INET, &da, dBuf, sizeof(dBuf));

        if (!searchQ.empty()) {
            std::string haystack = std::string(sBuf) + " " + std::string(dBuf) + " " +
                                   RuleManager::formatProtocol(e.protocol) + " " +
                                   std::to_string(e.dst_port) + " " +
                                   RuleManager::formatAction(e.action);
            std::transform(haystack.begin(), haystack.end(), haystack.begin(), ::tolower);
            if (haystack.find(searchQ) == std::string::npos) {
                continue;
            }
        }

        bool hovered = (m_mouseX >= 30 && m_mouseX <= w - 30 && m_mouseY >= rowY - 12 && m_mouseY <= rowY + 10);
        if (hovered) {
            m_canvas.fillRect(30, rowY - 12, w - 60, 22, BG_HOVER);
        } else if (i % 2 == 1) {
            m_canvas.fillRect(30, rowY - 12, w - 60, 22, BG_ZEBRA);
        }

        Color actColor = (e.action == NETGUARD_ACTION_DROP) ? COLOR_RED :
                         (e.action == NETGUARD_ACTION_ACCEPT) ? COLOR_GREEN : COLOR_YELLOW;

        std::string timeStr = std::to_string(e.timestamp_sec % 10000) + "." + std::to_string(e.timestamp_usec / 1000);
        m_canvas.drawText(35, rowY, timeStr, TEXT_MUTED, 9, false);
        m_canvas.drawText(140, rowY, sBuf, TEXT_PRIMARY, 9, false);
        m_canvas.drawText(280, rowY, dBuf, TEXT_PRIMARY, 9, false);
        m_canvas.drawText(420, rowY, RuleManager::formatProtocol(e.protocol), TEXT_CYAN, 9, false);
        m_canvas.drawText(490, rowY, std::to_string(e.src_port) + " -> " + std::to_string(e.dst_port), TEXT_PRIMARY, 9, false);
        m_canvas.drawText(640, rowY, RuleManager::formatDirection(e.direction), TEXT_MUTED, 9, false);
        m_canvas.drawPillBadge(740, rowY - 12, 65, 18, RuleManager::formatAction(e.action), (e.action == NETGUARD_ACTION_DROP) ? BADGE_DROP_BG : BADGE_ACCEPT_BG, actColor, true);
        m_canvas.drawText(840, rowY, e.matched_rule_id ? ("Rule #" + std::to_string(e.matched_rule_id)) : "Default Policy", TEXT_CYAN, 9, false);
        m_canvas.drawText(960, rowY, std::to_string(e.packet_len) + " B", TEXT_PRIMARY, 9, false);
        m_canvas.drawText(1060, rowY, e.iface_in[0] ? e.iface_in : (e.iface_out[0] ? e.iface_out : "local"), TEXT_MUTED, 9, false);

        rowY += 24;
    }

    if (m_events.empty()) {
        m_canvas.drawTextCentered(20, 400, w - 40, 40, "Listening for network traffic events on Linux Netfilter hooks...", TEXT_MUTED, 12, false);
    }
}

void NetGuardGUI::renderQuickDefenseTab() {
    int w = m_canvas.width();
    int h = m_canvas.height();

    m_canvas.drawCard(20, 110, w - 40, h - 155, "QUICK DEFENSE POLICIES & INSTANT MITIGATION", BG_PANEL, BORDER_SUBTLE);

    m_canvas.drawText(40, 155, "Instant Rule Deployment (One-Click Kernel Enforcement):", TEXT_CYAN, 12, true);

    int cardGap = 20;
    int cardW = (w - 80 - 2 * cardGap) / 3;
    int cardH = 80;

    struct QuickBtn {
        int col, row;
        std::string title;
        std::string desc;
        uint16_t port;
        std::string proto;
        std::string tag;
    };

    std::vector<QuickBtn> btns = {
        { 0, 0, "🛡 BLOCK INBOUND SSH (PORT 22)", "Drops all unauthorized TCP connection attempts to port 22", 22, "tcp", "Block SSH" },
        { 1, 0, "🛡 BLOCK HTTP TRAFFIC (PORT 80)", "Blocks unencrypted web traffic to destination port 80", 80, "tcp", "Block HTTP" },
        { 2, 0, "🛡 BLOCK DNS TRAFFIC (PORT 53)", "Drops UDP domain name lookups on port 53", 53, "udp", "Block DNS" },
        { 0, 1, "🛡 BLOCK HTTPS TRAFFIC (PORT 443)", "Blocks TLS/SSL web traffic to destination port 443", 443, "tcp", "Block HTTPS" },
        { 1, 1, "🛡 BLOCK TELNET TRAFFIC (PORT 23)", "Drops legacy unencrypted telnet port 23 traffic", 23, "tcp", "Block Telnet" },
        { 2, 1, "🛡 BLOCK ICMP PING ECHO (ALL)", "Blocks all ping requests & echo replies", 0, "icmp", "Block Ping" }
    };

    for (const auto &b : btns) {
        int bx = 40 + b.col * (cardW + cardGap);
        int by = 180 + b.row * (cardH + 15);
        bool hovered = (m_mouseX >= bx && m_mouseX <= bx + cardW && m_mouseY >= by && m_mouseY <= by + cardH);

        m_canvas.fillRoundedRect(bx, by, cardW, cardH, 6, hovered ? BG_HOVER : BG_CARD);
        m_canvas.drawRoundedRect(bx, by, cardW, cardH, 6, hovered ? COLOR_CYAN : BORDER_SUBTLE, 1);
        m_canvas.drawText(bx + 16, by + 28, b.title, COLOR_RED, 10, true);
        m_canvas.drawText(bx + 16, by + 52, b.desc, TEXT_MUTED, 8, false);
    }

    // Diagnostics and Reset Operations
    int adminY = 385;
    m_canvas.drawText(40, adminY, "System Administration & Health Actions:", TEXT_CYAN, 12, true);

    int actionW = (w - 80 - cardGap) / 2;

    bool resHover = (m_mouseX >= 40 && m_mouseX <= 40 + actionW && m_mouseY >= adminY + 25 && m_mouseY <= adminY + 70);
    m_canvas.fillRoundedRect(40, adminY + 25, actionW, 45, 6, resHover ? BG_HOVER : BG_CARD);
    m_canvas.drawRoundedRect(40, adminY + 25, actionW, 45, 6, COLOR_YELLOW, 1);
    m_canvas.drawTextCentered(40, adminY + 25, actionW, 45, "RESET PACKET COUNTERS", COLOR_YELLOW, 10, true);

    int clrX = 40 + actionW + cardGap;
    bool clrHover = (m_mouseX >= clrX && m_mouseX <= clrX + actionW && m_mouseY >= adminY + 25 && m_mouseY <= adminY + 70);
    m_canvas.fillRoundedRect(clrX, adminY + 25, actionW, 45, 6, clrHover ? BG_HOVER : BG_CARD);
    m_canvas.drawRoundedRect(clrX, adminY + 25, actionW, 45, 6, COLOR_RED, 1);
    m_canvas.drawTextCentered(clrX, adminY + 25, actionW, 45, "FLUSH ALL KERNEL RULES", COLOR_RED, 10, true);
}

void NetGuardGUI::renderAddRuleModal() {
    int w = m_canvas.width();
    int h = m_canvas.height();

    // Dark transparent overlay
    m_canvas.fillRect(0, 0, w, h, Color(0, 0, 0, 210));

    // Modal Box
    int mw = 680, mh = 540;
    int mx = (w - mw) / 2;
    int my = (h - mh) / 2;

    m_canvas.fillRoundedRect(mx, my, mw, mh, 8, BG_PANEL);
    m_canvas.drawRoundedRect(mx, my, mw, mh, 8, TEXT_CYAN, 2);

    // Modal Header
    std::string modalTitle = m_isEditMode ? ("EDIT FILTERING RULE #" + m_fieldId.value) : "ADD NEW PACKET FILTERING RULE";
    m_canvas.drawText(mx + 24, my + 34, modalTitle, TEXT_CYAN, 13, true);
    m_canvas.drawLine(mx + 20, my + 46, mx + mw - 20, my + 46, BORDER_SUBTLE, 1);

    // Close 'X'
    bool closeHover = (m_mouseX >= mx + mw - 40 && m_mouseX <= mx + mw - 10 && m_mouseY >= my + 10 && m_mouseY <= my + 45);
    m_canvas.drawText(mx + mw - 36, my + 34, "✕", closeHover ? COLOR_RED : TEXT_MUTED, 14, true);

    // Grid Layout for Text Inputs
    auto drawInputGroup = [&](TextInputField &f, int x, int y, int width, bool disabled = false) {
        f.x = x;
        f.y = y + 16;
        f.w = width;
        f.h = 30;

        m_canvas.drawText(x, y + 10, f.label, disabled ? TEXT_MUTED : TEXT_MUTED, 9, false);
        m_canvas.fillRoundedRect(f.x, f.y, f.w, f.h, 4, disabled ? BG_PANEL : BG_INPUT);
        m_canvas.drawRoundedRect(f.x, f.y, f.w, f.h, 4, f.active ? TEXT_CYAN : BORDER_SUBTLE, 1);

        std::string disp = f.value.empty() ? f.placeholder : f.value;
        Color tc = f.value.empty() ? TEXT_MUTED : (disabled ? TEXT_MUTED : TEXT_PRIMARY);
        m_canvas.drawText(f.x + 8, f.y + 19, disp + (f.active ? "|" : ""), tc, 9, false);
    };

    // Form Rows
    int r1Y = my + 60;
    drawInputGroup(m_fieldId, mx + 24, r1Y, 150, m_isEditMode);
    drawInputGroup(m_fieldPriority, mx + 190, r1Y, 150);

    int r2Y = r1Y + 54;
    drawInputGroup(m_fieldSrcIp, mx + 24, r2Y, 316);

    int r3Y = r2Y + 54;
    drawInputGroup(m_fieldDstIp, mx + 24, r3Y, 316);

    int r4Y = r3Y + 54;
    drawInputGroup(m_fieldDstPort, mx + 24, r4Y, 150);

    int r5Y = r4Y + 54;
    drawInputGroup(m_fieldDesc, mx + 24, r5Y, 316);

    // Right Column: Selector Pills
    int px = mx + 365;

    // Protocol Selector
    int py = r1Y;
    m_canvas.drawText(px, py + 10, "Protocol:", TEXT_MUTED, 9, false);
    const char *protos[] = { "TCP", "UDP", "ICMP", "ANY" };
    for (int i = 0; i < 4; i++) {
        int bx = px + (i * 68);
        bool sel = (m_selectedProtoIdx == i);
        bool hovered = (m_mouseX >= bx && m_mouseX <= bx + 62 && m_mouseY >= py + 18 && m_mouseY <= py + 46);
        m_canvas.fillRoundedRect(bx, py + 18, 62, 28, 4, sel ? BG_CARD : (hovered ? BG_HOVER : BG_INPUT));
        m_canvas.drawRoundedRect(bx, py + 18, 62, 28, 4, sel ? TEXT_CYAN : BORDER_SUBTLE, 1);
        m_canvas.drawTextCentered(bx, py + 18, 62, 28, protos[i], sel ? TEXT_CYAN : TEXT_MUTED, 9, sel);
    }

    // Action Selector
    py += 65;
    m_canvas.drawText(px, py + 10, "Action:", TEXT_MUTED, 9, false);
    const char *actions[] = { "DROP", "ACCEPT", "REJECT", "LOG" };
    Color actColors[] = { COLOR_RED, COLOR_GREEN, COLOR_YELLOW, TEXT_CYAN };
    for (int i = 0; i < 4; i++) {
        int bx = px + (i * 68);
        bool sel = (m_selectedActionIdx == i);
        bool hovered = (m_mouseX >= bx && m_mouseX <= bx + 62 && m_mouseY >= py + 18 && m_mouseY <= py + 46);
        m_canvas.fillRoundedRect(bx, py + 18, 62, 28, 4, sel ? BG_CARD : (hovered ? BG_HOVER : BG_INPUT));
        m_canvas.drawRoundedRect(bx, py + 18, 62, 28, 4, sel ? actColors[i] : BORDER_SUBTLE, 1);
        m_canvas.drawTextCentered(bx, py + 18, 62, 28, actions[i], sel ? actColors[i] : TEXT_MUTED, 9, sel);
    }

    // Direction Selector
    py += 65;
    m_canvas.drawText(px, py + 10, "Direction:", TEXT_MUTED, 9, false);
    const char *dirs[] = { "IN", "OUT", "FWD", "ANY" };
    for (int i = 0; i < 4; i++) {
        int bx = px + (i * 68);
        bool sel = (m_selectedDirIdx == i);
        bool hovered = (m_mouseX >= bx && m_mouseX <= bx + 62 && m_mouseY >= py + 18 && m_mouseY <= py + 46);
        m_canvas.fillRoundedRect(bx, py + 18, 62, 28, 4, sel ? BG_CARD : (hovered ? BG_HOVER : BG_INPUT));
        m_canvas.drawRoundedRect(bx, py + 18, 62, 28, 4, sel ? TEXT_CYAN : BORDER_SUBTLE, 1);
        m_canvas.drawTextCentered(bx, py + 18, 62, 28, dirs[i], sel ? TEXT_CYAN : TEXT_MUTED, 9, sel);
    }

    // Buttons: [SAVE / INJECT RULE] & [CANCEL]
    int by = my + mh - 50;
    bool subHover = (m_mouseX >= mx + mw - 250 && m_mouseX <= mx + mw - 110 && m_mouseY >= by && m_mouseY <= by + 34);
    m_canvas.fillRoundedRect(mx + mw - 250, by, 140, 34, 4, subHover ? BG_HOVER : COLOR_BLUE);
    m_canvas.drawRoundedRect(mx + mw - 250, by, 140, 34, 4, COLOR_BLUE, 1);
    m_canvas.drawTextCentered(mx + mw - 250, by, 140, 34, m_isEditMode ? "✓ SAVE RULE" : "✓ INJECT RULE", TEXT_PRIMARY, 10, true);

    bool canHover = (m_mouseX >= mx + mw - 95 && m_mouseX <= mx + mw - 20 && m_mouseY >= by && m_mouseY <= by + 34);
    m_canvas.fillRoundedRect(mx + mw - 95, by, 75, 34, 4, canHover ? BG_HOVER : BG_CARD);
    m_canvas.drawRoundedRect(mx + mw - 95, by, 75, 34, 4, BORDER_SUBTLE, 1);
    m_canvas.drawTextCentered(mx + mw - 95, by, 75, 34, "CANCEL", TEXT_MUTED, 9, false);
}

void NetGuardGUI::renderFooter() {
    int w = m_canvas.width();
    int h = m_canvas.height();

    m_canvas.fillRect(0, h - 32, w, 32, BG_PANEL);
    m_canvas.drawLine(0, h - 32, w, h - 32, BORDER_SUBTLE, 1);

    m_canvas.drawText(20, h - 12, m_statusMessage, m_statusColor, 9, true);

    std::string statsStr = "Total Pkts: " + std::to_string(m_stats.current().total_packets) +
                           " | Drops: " + std::to_string(m_stats.current().dropped_packets) +
                           " | Rules: " + std::to_string(m_rules.size());
    m_canvas.drawText(w - 380, h - 12, statsStr, TEXT_MUTED, 9, false);
}

void NetGuardGUI::handleMouseClick(int x, int y) {
    if (m_showAddDialog) {
        int w = m_canvas.width();
        int h = m_canvas.height();
        int mw = 680, mh = 540;
        int mx = (w - mw) / 2;
        int my = (h - mh) / 2;

        // Close X
        if (x >= mx + mw - 40 && x <= mx + mw - 10 && y >= my + 10 && y <= my + 45) {
            m_showAddDialog = false;
            return;
        }

        // Cancel button
        if (x >= mx + mw - 95 && x <= mx + mw - 20 && y >= my + mh - 50 && y <= my + mh - 16) {
            m_showAddDialog = false;
            return;
        }

        // Submit button
        if (x >= mx + mw - 250 && x <= mx + mw - 110 && y >= my + mh - 50 && y <= my + mh - 16) {
            submitAddRule();
            return;
        }

        // Field Focus Toggles
        auto checkFocus = [&](TextInputField &f, bool disabled = false) {
            if (disabled) return;
            f.active = (x >= f.x && x <= f.x + f.w && y >= f.y && y <= f.y + f.h);
        };
        checkFocus(m_fieldId, m_isEditMode);
        checkFocus(m_fieldPriority);
        checkFocus(m_fieldSrcIp);
        checkFocus(m_fieldDstIp);
        checkFocus(m_fieldDstPort);
        checkFocus(m_fieldDesc);

        // Protocol Selector
        int px = mx + 365, py = my + 60;
        for (int i = 0; i < 4; i++) {
            int bx = px + (i * 68);
            if (x >= bx && x <= bx + 62 && y >= py + 18 && y <= py + 46) {
                m_selectedProtoIdx = i;
            }
        }

        // Action Selector
        py += 65;
        for (int i = 0; i < 4; i++) {
            int bx = px + (i * 68);
            if (x >= bx && x <= bx + 62 && y >= py + 18 && y <= py + 46) {
                m_selectedActionIdx = i;
            }
        }

        // Direction Selector
        py += 65;
        for (int i = 0; i < 4; i++) {
            int bx = px + (i * 68);
            if (x >= bx && x <= bx + 62 && y >= py + 18 && y <= py + 46) {
                m_selectedDirIdx = i;
            }
        }

        return;
    }

    // Tab Navigation
    if (y >= 57 && y <= 99) {
        if (x >= 20 && x <= 220) m_currentTab = GuiTab::DASHBOARD;
        else if (x >= 230 && x <= 440) m_currentTab = GuiTab::RULES;
        else if (x >= 450 && x <= 640) m_currentTab = GuiTab::LIVE_PACKETS;
        else if (x >= 650 && x <= 860) m_currentTab = GuiTab::QUICK_DEFENSE;
        return;
    }

    if (m_currentTab == GuiTab::RULES) {
        int w = m_canvas.width();

        // [+ ADD RULE]
        if (x >= 35 && x <= 140 && y >= 120 && y <= 150) {
            m_isEditMode = false;
            m_fieldId.value = std::to_string(100 + m_rules.size() + 1);
            m_fieldId.active = true;
            m_showAddDialog = true;
            return;
        }

        // [EDIT RULE]
        if (x >= 148 && x <= 243 && y >= 120 && y <= 150) {
            openEditModal();
            return;
        }

        // [ENABLE / DISABLE]
        if (x >= 251 && x <= 381 && y >= 120 && y <= 150) {
            toggleSelectedRule();
            return;
        }

        // [DELETE RULE]
        if (x >= 389 && x <= 489 && y >= 120 && y <= 150) {
            deleteSelectedRule();
            return;
        }

        // [EXPORT]
        if (x >= 497 && x <= 572 && y >= 120 && y <= 150) {
            exportRulesToFile();
            return;
        }

        // [IMPORT]
        if (x >= 580 && x <= 655 && y >= 120 && y <= 150) {
            importRulesFromFile();
            return;
        }

        // [REFRESH]
        if (x >= 663 && x <= 738 && y >= 120 && y <= 150) {
            updateData();
            setStatus("Refreshed rules and statistics from Linux kernel Netfilter.", COLOR_GREEN);
            return;
        }

        // [CLEAR ALL]
        if (x >= 746 && x <= 836 && y >= 120 && y <= 150) {
            std::string err;
            if (m_client.clearRules(err)) {
                setStatus("Cleared all filtering rules from Linux kernel.", COLOR_GREEN);
                updateData();
            } else {
                setStatus("Error: " + err, COLOR_RED);
            }
            return;
        }

        // Rule search field focus
        if (x >= m_ruleSearchField.x && x <= m_ruleSearchField.x + m_ruleSearchField.w &&
            y >= m_ruleSearchField.y && y <= m_ruleSearchField.y + m_ruleSearchField.h) {
            m_ruleSearchField.active = true;
            return;
        } else {
            m_ruleSearchField.active = false;
        }

        // [TOGGLE POLICY]
        if (x >= w - 205 && x <= w - 35 && y >= 120 && y <= 150) {
            toggleDefaultPolicy();
            return;
        }

        // Rule table row selection
        int rowY = 240;
        for (const auto &r : m_rules) {
            if (y >= rowY - 14 && y <= rowY + 10) {
                m_selectedRuleId = r.id;
                setStatus("Selected Rule #" + std::to_string(r.id), TEXT_CYAN);
                break;
            }
            rowY += 28;
        }
    } else if (m_currentTab == GuiTab::LIVE_PACKETS) {
        int w = m_canvas.width();
        int pBtnX = w - 160;
        if (x >= pBtnX && x <= pBtnX + 130 && y >= 118 && y <= 142) {
            m_pausedStream = !m_pausedStream;
            setStatus(m_pausedStream ? "Paused live packet activity stream view." : "Resumed live packet activity stream view.", COLOR_YELLOW);
            return;
        }

        if (x >= m_packetSearchField.x && x <= m_packetSearchField.x + m_packetSearchField.w &&
            y >= m_packetSearchField.y && y <= m_packetSearchField.y + m_packetSearchField.h) {
            m_packetSearchField.active = true;
        } else {
            m_packetSearchField.active = false;
        }
    } else if (m_currentTab == GuiTab::QUICK_DEFENSE) {
        int w = m_canvas.width();
        int cardGap = 20;
        int cardW = (w - 80 - 2 * cardGap) / 3;
        int cardH = 80;

        auto isClicked = [&](int col, int row) {
            int bx = 40 + col * (cardW + cardGap);
            int by = 180 + row * (cardH + 15);
            return (x >= bx && x <= bx + cardW && y >= by && y <= by + cardH);
        };

        // Quick Defense Buttons
        if (isClicked(0, 0)) quickBlockPort(22, "tcp", "Block SSH");
        else if (isClicked(1, 0)) quickBlockPort(80, "tcp", "Block HTTP");
        else if (isClicked(2, 0)) quickBlockPort(53, "udp", "Block DNS");
        else if (isClicked(0, 1)) quickBlockPort(443, "tcp", "Block HTTPS");
        else if (isClicked(1, 1)) quickBlockPort(23, "tcp", "Block Telnet");
        else if (isClicked(2, 1)) {
            // Block ICMP Ping
            struct netguard_rule r;
            std::memset(&r, 0, sizeof(r));
            r.id = 200 + (uint32_t)(m_rules.size() + 1);
            r.priority = 10;
            r.enabled = 1;
            r.protocol = NETGUARD_PROTO_ICMP;
            r.action = NETGUARD_ACTION_DROP;
            r.direction = NETGUARD_DIR_IN;
            strncpy(r.description, "Block All ICMP Ping", sizeof(r.description) - 1);
            std::string err;
            if (m_client.addRule(r, err)) {
                setStatus("✓ Deployed instant rule: Block All ICMP Ping", COLOR_GREEN);
                updateData();
            } else {
                setStatus("Failed: " + err, COLOR_RED);
            }
        }

        int adminY = 385;
        int actionW = (w - 80 - cardGap) / 2;
        if (x >= 40 && x <= 40 + actionW && y >= adminY + 25 && y <= adminY + 70) {
            std::string err;
            if (m_client.resetStats(err)) {
                setStatus("✓ Reset all packet statistics in Linux kernel.", COLOR_GREEN);
                updateData();
            }
        }

        int clrX = 40 + actionW + cardGap;
        if (x >= clrX && x <= clrX + actionW && y >= adminY + 25 && y <= adminY + 70) {
            std::string err;
            if (m_client.clearRules(err)) {
                setStatus("✓ Flushed all filtering rules from kernel.", COLOR_GREEN);
                updateData();
            }
        }
    }
}

void NetGuardGUI::cycleModalFocus(bool reverse) {
    if (!m_showAddDialog) return;
    TextInputField* fields[] = {
        &m_fieldId, &m_fieldPriority, &m_fieldSrcIp, &m_fieldDstIp, &m_fieldDstPort, &m_fieldDesc
    };
    int total = 6;
    int current = -1;
    for (int i = 0; i < total; i++) {
        if (fields[i]->active) {
            current = i;
            fields[i]->active = false;
            break;
        }
    }
    if (current == -1) {
        fields[m_isEditMode ? 1 : 0]->active = true;
    } else {
        int next = reverse ? (current - 1 + total) % total : (current + 1) % total;
        if (m_isEditMode && fields[next] == &m_fieldId) {
            next = reverse ? (next - 1 + total) % total : (next + 1) % total;
        }
        fields[next]->active = true;
    }
}

void NetGuardGUI::handleKeyPress(KeySym sym, const std::string &text) {
    if (!m_showAddDialog) {
        if (m_ruleSearchField.active) {
            if (sym == XK_BackSpace) {
                if (!m_ruleSearchField.value.empty()) m_ruleSearchField.value.pop_back();
            } else if (sym == XK_Escape || sym == XK_Return) {
                m_ruleSearchField.active = false;
            } else if (!text.empty() && text[0] >= 32 && text[0] <= 126) {
                m_ruleSearchField.value += text;
            }
            return;
        }

        if (m_packetSearchField.active) {
            if (sym == XK_BackSpace) {
                if (!m_packetSearchField.value.empty()) m_packetSearchField.value.pop_back();
            } else if (sym == XK_Escape || sym == XK_Return) {
                m_packetSearchField.active = false;
            } else if (!text.empty() && text[0] >= 32 && text[0] <= 126) {
                m_packetSearchField.value += text;
            }
            return;
        }

        if (sym == XK_Escape || sym == XK_q || sym == XK_Q) {
            m_running = false;
        } else if (sym == XK_1) m_currentTab = GuiTab::DASHBOARD;
        else if (sym == XK_2) m_currentTab = GuiTab::RULES;
        else if (sym == XK_3) m_currentTab = GuiTab::LIVE_PACKETS;
        else if (sym == XK_4) m_currentTab = GuiTab::QUICK_DEFENSE;
        return;
    }

    if (sym == XK_Tab) {
        cycleModalFocus(false);
        return;
    }

    if (sym == XK_Escape) {
        m_showAddDialog = false;
        return;
    }

    if (sym == XK_Return) {
        submitAddRule();
        return;
    }

    auto handleFieldInput = [&](TextInputField &f, bool disabled = false) {
        if (!f.active || disabled) return;
        if (sym == XK_BackSpace) {
            if (!f.value.empty()) f.value.pop_back();
        } else if (!text.empty() && text[0] >= 32 && text[0] <= 126) {
            f.value += text;
        }
    };

    handleFieldInput(m_fieldId, m_isEditMode);
    handleFieldInput(m_fieldPriority);
    handleFieldInput(m_fieldSrcIp);
    handleFieldInput(m_fieldDstIp);
    handleFieldInput(m_fieldDstPort);
    handleFieldInput(m_fieldDesc);
}

void NetGuardGUI::openEditModal() {
    if (m_selectedRuleId == 0) {
        setStatus("Please select a rule from the table first.", COLOR_YELLOW);
        return;
    }

    for (const auto &r : m_rules) {
        if (r.id == m_selectedRuleId) {
            m_isEditMode = true;
            m_fieldId.value = std::to_string(r.id);
            m_fieldPriority.value = std::to_string(r.priority);
            m_fieldSrcIp.value = RuleManager::formatIpCidr(r.src_ip, r.src_mask);
            m_fieldDstIp.value = RuleManager::formatIpCidr(r.dst_ip, r.dst_mask);
            m_fieldDstPort.value = RuleManager::formatPortRange(r.dst_port_min, r.dst_port_max);
            m_fieldDesc.value = r.description;
            m_ruleEnabled = (r.enabled != 0);

            if (r.protocol == NETGUARD_PROTO_TCP) m_selectedProtoIdx = 0;
            else if (r.protocol == NETGUARD_PROTO_UDP) m_selectedProtoIdx = 1;
            else if (r.protocol == NETGUARD_PROTO_ICMP) m_selectedProtoIdx = 2;
            else m_selectedProtoIdx = 3;

            if (r.action == NETGUARD_ACTION_DROP) m_selectedActionIdx = 0;
            else if (r.action == NETGUARD_ACTION_ACCEPT) m_selectedActionIdx = 1;
            else if (r.action == NETGUARD_ACTION_REJECT) m_selectedActionIdx = 2;
            else m_selectedActionIdx = 3;

            if (r.direction == NETGUARD_DIR_IN) m_selectedDirIdx = 0;
            else if (r.direction == NETGUARD_DIR_OUT) m_selectedDirIdx = 1;
            else if (r.direction == NETGUARD_DIR_FWD) m_selectedDirIdx = 2;
            else m_selectedDirIdx = 3;

            m_showAddDialog = true;
            m_fieldPriority.active = true;
            m_fieldId.active = false;
            setStatus("Editing Rule #" + std::to_string(r.id), COLOR_CYAN);
            return;
        }
    }
    setStatus("Rule #" + std::to_string(m_selectedRuleId) + " not found.", COLOR_RED);
}

void NetGuardGUI::submitAddRule() {
    struct netguard_rule r;
    std::memset(&r, 0, sizeof(r));
    r.enabled = 1;

    try {
        r.id = std::stoul(m_fieldId.value);
        r.priority = std::stoul(m_fieldPriority.value);
    } catch (...) {
        setStatus("Error: Invalid numeric ID or priority", COLOR_RED);
        return;
    }

    std::string err;
    if (!RuleManager::parseIpCidr(m_fieldSrcIp.value, r.src_ip, r.src_mask, err) ||
        !RuleManager::parseIpCidr(m_fieldDstIp.value, r.dst_ip, r.dst_mask, err) ||
        !RuleManager::parsePortRange(m_fieldDstPort.value, r.dst_port_min, r.dst_port_max, err)) {
        setStatus("Error: " + err, COLOR_RED);
        return;
    }

    uint8_t protos[] = { NETGUARD_PROTO_TCP, NETGUARD_PROTO_UDP, NETGUARD_PROTO_ICMP, NETGUARD_PROTO_ANY };
    r.protocol = protos[m_selectedProtoIdx];

    uint8_t actions[] = { NETGUARD_ACTION_DROP, NETGUARD_ACTION_ACCEPT, NETGUARD_ACTION_REJECT, NETGUARD_ACTION_LOG };
    r.action = actions[m_selectedActionIdx];

    uint8_t dirs[] = { NETGUARD_DIR_IN, NETGUARD_DIR_OUT, NETGUARD_DIR_FWD, NETGUARD_DIR_ANY };
    r.direction = dirs[m_selectedDirIdx];

    strncpy(r.description, m_fieldDesc.value.c_str(), sizeof(r.description) - 1);

    if (m_isEditMode) {
        if (!m_client.updateRule(r, err)) {
            setStatus("Kernel rejected rule update: " + err, COLOR_RED);
            return;
        }
        setStatus("✓ Rule #" + std::to_string(r.id) + " successfully updated in Linux Netfilter engine!", COLOR_GREEN);
    } else {
        if (!m_client.addRule(r, err)) {
            setStatus("Kernel rejected rule injection: " + err, COLOR_RED);
            return;
        }
        setStatus("✓ Rule #" + std::to_string(r.id) + " successfully injected into Linux Netfilter engine!", COLOR_GREEN);
    }

    m_showAddDialog = false;
    updateData();

    if (!m_isEditMode) {
        m_fieldId.value = std::to_string(r.id + 1);
    }
}

void NetGuardGUI::deleteSelectedRule() {
    if (m_selectedRuleId == 0) {
        setStatus("Please select a rule from the table first.", COLOR_YELLOW);
        return;
    }

    std::string err;
    if (m_client.deleteRule(m_selectedRuleId, err)) {
        setStatus("✓ Deleted rule #" + std::to_string(m_selectedRuleId) + " from kernel.", COLOR_GREEN);
        m_selectedRuleId = 0;
        updateData();
    } else {
        setStatus("Failed to delete rule: " + err, COLOR_RED);
    }
}

void NetGuardGUI::toggleSelectedRule() {
    if (m_selectedRuleId == 0) {
        setStatus("Please select a rule from the table first.", COLOR_YELLOW);
        return;
    }

    bool currentlyEnabled = true;
    for (const auto &r : m_rules) {
        if (r.id == m_selectedRuleId) {
            currentlyEnabled = (r.enabled != 0);
            break;
        }
    }

    std::string err;
    if (m_client.enableRule(m_selectedRuleId, !currentlyEnabled, err)) {
        setStatus("✓ Rule #" + std::to_string(m_selectedRuleId) + " is now " + (!currentlyEnabled ? "ENABLED" : "DISABLED"), COLOR_GREEN);
        updateData();
    } else {
        setStatus("Error: " + err, COLOR_RED);
    }
}

void NetGuardGUI::toggleDefaultPolicy() {
    bool isAccept = (m_stats.current().default_policy == NETGUARD_POLICY_ACCEPT);
    uint8_t newPolicy = isAccept ? NETGUARD_POLICY_DROP : NETGUARD_POLICY_ACCEPT;

    std::string err;
    if (m_client.setDefaultPolicy(newPolicy, err)) {
        setStatus("✓ Changed kernel default packet policy to: " + std::string(newPolicy == NETGUARD_POLICY_ACCEPT ? "ACCEPT" : "DROP"), COLOR_GREEN);
        updateData();
    } else {
        setStatus("Error setting policy: " + err, COLOR_RED);
    }
}

void NetGuardGUI::exportRulesToFile() {
    std::string err;
    if (RuleManager::exportToFile("/tmp/netguard_rules.json", m_rules, err)) {
        setStatus("✓ Exported " + std::to_string(m_rules.size()) + " rules to /tmp/netguard_rules.json", COLOR_GREEN);
    } else {
        setStatus("Export failed: " + err, COLOR_RED);
    }
}

void NetGuardGUI::importRulesFromFile() {
    std::string err;
    std::vector<struct netguard_rule> imported;
    if (RuleManager::importFromFile("/tmp/netguard_rules.json", imported, err)) {
        int count = 0;
        for (const auto &r : imported) {
            std::string addErr;
            if (m_client.addRule(r, addErr)) count++;
        }
        setStatus("✓ Imported " + std::to_string(count) + " rules from /tmp/netguard_rules.json", COLOR_GREEN);
        updateData();
    } else {
        setStatus("Import failed: " + err, COLOR_RED);
    }
}

void NetGuardGUI::quickBlockPort(uint16_t port, const std::string &protoStr, const std::string &desc) {
    struct netguard_rule r;
    std::memset(&r, 0, sizeof(r));
    r.id = 100 + (uint32_t)(m_rules.size() + 1);
    r.priority = 10;
    r.enabled = 1;
    r.dst_port_min = port;
    r.dst_port_max = port;
    r.protocol = (protoStr == "udp") ? NETGUARD_PROTO_UDP : NETGUARD_PROTO_TCP;
    r.action = NETGUARD_ACTION_DROP;
    r.direction = NETGUARD_DIR_IN;
    strncpy(r.description, desc.c_str(), sizeof(r.description) - 1);

    std::string err;
    if (m_client.addRule(r, err)) {
        setStatus("✓ Deployed instant rule: " + desc + " (Port " + std::to_string(port) + ")", COLOR_GREEN);
        updateData();
    } else {
        setStatus("Failed: " + err, COLOR_RED);
    }
}

void NetGuardGUI::quickBlockIp(const std::string &ip, const std::string &desc) {
    struct netguard_rule r;
    std::memset(&r, 0, sizeof(r));
    r.id = 100 + (uint32_t)(m_rules.size() + 1);
    r.priority = 10;
    r.enabled = 1;
    std::string err;
    RuleManager::parseIpCidr(ip, r.src_ip, r.src_mask, err);
    r.action = NETGUARD_ACTION_DROP;
    r.direction = NETGUARD_DIR_IN;
    strncpy(r.description, desc.c_str(), sizeof(r.description) - 1);

    if (m_client.addRule(r, err)) {
        setStatus("✓ Deployed instant rule: Block Source " + ip, COLOR_GREEN);
        updateData();
    } else {
        setStatus("Failed: " + err, COLOR_RED);
    }
}

} // namespace netguard
