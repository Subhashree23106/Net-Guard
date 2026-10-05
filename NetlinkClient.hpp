#ifndef NETGUARD_NETLINK_CLIENT_HPP
#define NETGUARD_NETLINK_CLIENT_HPP

#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <system_error>
#include "../common/netguard_uapi.h"

namespace netguard {

class NetlinkClient {
public:
    NetlinkClient();
    ~NetlinkClient();

    // Connect to NetGuard kernel module via Netlink socket
    bool connect();
    void disconnect();
    bool isConnected() const { return m_sockFd >= 0; }

    // Health check ping
    bool ping();

    // Rule management
    bool addRule(const struct netguard_rule &rule, std::string &errorMsg);
    bool deleteRule(uint32_t ruleId, std::string &errorMsg);
    bool updateRule(const struct netguard_rule &rule, std::string &errorMsg);
    bool enableRule(uint32_t ruleId, bool enable, std::string &errorMsg);
    bool clearRules(std::string &errorMsg);
    bool getRules(std::vector<struct netguard_rule> &rules, std::string &errorMsg);

    // Statistics
    bool getStats(struct netguard_stats &stats, std::string &errorMsg);
    bool resetStats(std::string &errorMsg);

    // Policy & Configuration
    bool setDefaultPolicy(uint8_t policy, std::string &errorMsg);
    bool setLogLevel(uint8_t level, std::string &errorMsg);

    // Events & Live Monitor
    bool getRecentEvents(std::vector<struct netguard_packet_event> &events, std::string &errorMsg);
    bool subscribeEvents();
    bool receiveEvent(struct netguard_packet_event &event, int timeoutMs = 1000);

    // Helper to format error codes
    static std::string statusToString(int32_t status);

private:
    int m_sockFd;
    uint32_t m_pid;
    uint32_t m_seq;
    int m_activeProto;

    bool sendRequest(uint16_t msgType, const void *payload, uint32_t payloadLen,
                     uint16_t expectedResp, std::vector<uint8_t> &respPayload,
                     int32_t &outStatus, std::string &errorMsg);
    
    bool initSocket(int proto);
};

} // namespace netguard

#endif // NETGUARD_NETLINK_CLIENT_HPP
