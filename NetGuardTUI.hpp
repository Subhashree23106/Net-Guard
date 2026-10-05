#ifndef NETGUARD_TUI_HPP
#define NETGUARD_TUI_HPP

#include <vector>
#include <string>
#include <chrono>
#include "../agent/NetlinkClient.hpp"
#include "../agent/RuleManager.hpp"
#include "../agent/Statistics.hpp"

namespace netguard {

class NetGuardTUI {
public:
    NetGuardTUI();
    ~NetGuardTUI();

    bool init();
    void run();

private:
    NetlinkClient m_client;
    Statistics m_stats;
    bool m_running;

    std::vector<struct netguard_rule> m_rules;
    std::vector<struct netguard_packet_event> m_events;

    void render();
    void updateData();
    void handleInput(int ch);
};

} // namespace netguard

#endif // NETGUARD_TUI_HPP
