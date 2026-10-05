#ifndef NETGUARD_RULE_MANAGER_HPP
#define NETGUARD_RULE_MANAGER_HPP

#include <string>
#include <vector>
#include <cstdint>
#include "../common/netguard_uapi.h"

namespace netguard {

class RuleManager {
public:
    // Helper conversion utilities
    static bool parseIpCidr(const std::string &input, uint32_t &outIp, uint32_t &outMask, std::string &error);
    static std::string formatIpCidr(uint32_t ip, uint32_t mask);

    static bool parsePortRange(const std::string &input, uint16_t &outMin, uint16_t &outMax, std::string &error);
    static std::string formatPortRange(uint16_t minPort, uint16_t maxPort);

    static bool parseProtocol(const std::string &input, uint8_t &outProto, std::string &error);
    static std::string formatProtocol(uint8_t proto);

    static bool parseDirection(const std::string &input, uint8_t &outDir, std::string &error);
    static std::string formatDirection(uint8_t dir);

    static bool parseAction(const std::string &input, uint8_t &outAction, std::string &error);
    static std::string formatAction(uint8_t action);

    // Rule validation
    static bool validateRule(const struct netguard_rule &rule, std::string &error);

    // Formatted rule table printing
    static std::string formatRuleTable(const std::vector<struct netguard_rule> &rules, bool colored = true);
    static std::string formatSingleRule(const struct netguard_rule &rule, bool colored = true);

    // Configuration file export/import
    static bool exportToFile(const std::string &filename, const std::vector<struct netguard_rule> &rules, std::string &error);
    static bool importFromFile(const std::string &filename, std::vector<struct netguard_rule> &rules, std::string &error);
};

} // namespace netguard

#endif // NETGUARD_RULE_MANAGER_HPP
