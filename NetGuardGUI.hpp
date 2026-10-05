#ifndef NETGUARD_GUI_HPP
#define NETGUARD_GUI_HPP

#include <vector>
#include <string>
#include <chrono>
#include <deque>
#include "X11Canvas.hpp"
#include "../agent/NetlinkClient.hpp"
#include "../agent/RuleManager.hpp"
#include "../agent/Statistics.hpp"

namespace netguard {

enum class GuiTab {
    DASHBOARD,
    RULES,
    LIVE_PACKETS,
    QUICK_DEFENSE
};

struct TextInputField {
    std::string label;
    std::string value;
    std::string placeholder;
    int x, y, w, h;
    bool active;
};

class NetGuardGUI {
public:
    NetGuardGUI(int width = 1280, int height = 820);
    ~NetGuardGUI();

    bool init();
    void run();

private:
    X11Canvas m_canvas;
    NetlinkClient m_client;
    Statistics m_stats;

    GuiTab m_currentTab;
    bool m_running;
    bool m_showAddDialog;
    bool m_showEditDialog;
    uint32_t m_selectedRuleId;

    std::vector<struct netguard_rule> m_rules;
    std::vector<struct netguard_packet_event> m_events;
    std::deque<double> m_rateHistory; // Last 60 seconds pps

    std::string m_statusMessage;
    Color m_statusColor;
    std::chrono::steady_clock::time_point m_statusTime;

    // Add/Edit Rule Form Fields & State
    bool m_isEditMode;
    TextInputField m_fieldId;
    TextInputField m_fieldPriority;
    TextInputField m_fieldSrcIp;
    TextInputField m_fieldDstIp;
    TextInputField m_fieldDstPort;
    TextInputField m_fieldDesc;
    int m_selectedProtoIdx;   // 0=TCP, 1=UDP, 2=ICMP, 3=ANY
    int m_selectedActionIdx;  // 0=DROP, 1=ACCEPT, 2=REJECT, 3=LOG
    int m_selectedDirIdx;     // 0=IN, 1=OUT, 2=FWD, 3=ANY
    bool m_ruleEnabled;

    // Search and Filtering
    TextInputField m_ruleSearchField;
    TextInputField m_packetSearchField;
    bool m_pausedStream;

    // Mouse & Hover state
    int m_mouseX;
    int m_mouseY;

    // Rendering Methods
    void render();
    void renderHeader();
    void renderTabs();
    void renderDashboardTab();
    void renderRulesTab();
    void renderLivePacketsTab();
    void renderQuickDefenseTab();
    void renderAddRuleModal();
    void renderFooter();

    // Event Handlers
    void handleMouseClick(int x, int y);
    void handleMouseMove(int x, int y);
    void handleKeyPress(KeySym sym, const std::string &text);
    void updateData();
    void setStatus(const std::string &msg, const Color &c = Color(0, 230, 118));
    void cycleModalFocus(bool reverse);

    // Actions
    void openEditModal();
    void submitAddRule();
    void deleteSelectedRule();
    void toggleSelectedRule();
    void toggleDefaultPolicy();
    void exportRulesToFile();
    void importRulesFromFile();
    void quickBlockPort(uint16_t port, const std::string &proto, const std::string &desc);
    void quickBlockIp(const std::string &ip, const std::string &desc);
};

} // namespace netguard

#endif // NETGUARD_GUI_HPP
