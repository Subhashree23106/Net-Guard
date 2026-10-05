#include "RuleManager.hpp"
#include <arpa/inet.h>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <algorithm>
#include <cstring>

namespace netguard {

// ANSI Color codes
static const std::string COLOR_RESET   = "\033[0m";
static const std::string COLOR_BOLD    = "\033[1m";
static const std::string COLOR_RED     = "\033[31m";
static const std::string COLOR_GREEN   = "\033[32m";
static const std::string COLOR_YELLOW  = "\033[33m";
static const std::string COLOR_BLUE    = "\033[34m";
static const std::string COLOR_MAGENTA = "\033[35m";
static const std::string COLOR_CYAN    = "\033[36m";
static const std::string COLOR_GRAY    = "\033[90m";

static std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

bool RuleManager::parseIpCidr(const std::string &input, uint32_t &outIp, uint32_t &outMask, std::string &error)
{
    std::string s = toLower(input);
    if (s.empty() || s == "any" || s == "*" || s == "0.0.0.0/0" || s == "0.0.0.0") {
        outIp = 0;
        outMask = 0;
        return true;
    }

    size_t slashPos = s.find('/');
    std::string ipPart = (slashPos != std::string::npos) ? s.substr(0, slashPos) : s;
    std::string maskPart = (slashPos != std::string::npos) ? s.substr(slashPos + 1) : "32";

    struct in_addr addr;
    if (inet_pton(AF_INET, ipPart.c_str(), &addr) != 1) {
        error = "Invalid IPv4 address: " + ipPart;
        return false;
    }
    outIp = addr.s_addr;

    int cidrBits = 32;
    try {
        cidrBits = std::stoi(maskPart);
    } catch (...) {
        error = "Invalid CIDR prefix: " + maskPart;
        return false;
    }

    if (cidrBits < 0 || cidrBits > 32) {
        error = "CIDR prefix must be between 0 and 32";
        return false;
    }

    if (cidrBits == 0) {
        outMask = 0;
    } else {
        uint32_t hostMask = (cidrBits == 32) ? 0xFFFFFFFFU : ~((1U << (32 - cidrBits)) - 1);
        outMask = htonl(hostMask);
    }

    return true;
}

std::string RuleManager::formatIpCidr(uint32_t ip, uint32_t mask)
{
    if (mask == 0) return "ANY";

    struct in_addr addr;
    addr.s_addr = ip;
    char ipStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, ipStr, sizeof(ipStr));

    uint32_t hostMask = ntohl(mask);
    int bits = 0;
    while (hostMask) {
        bits += (hostMask & 1);
        hostMask >>= 1;
    }

    if (bits == 32)
        return std::string(ipStr);
    else
        return std::string(ipStr) + "/" + std::to_string(bits);
}

bool RuleManager::parsePortRange(const std::string &input, uint16_t &outMin, uint16_t &outMax, std::string &error)
{
    std::string s = toLower(input);
    if (s.empty() || s == "any" || s == "*" || s == "0") {
        outMin = 0;
        outMax = 0;
        return true;
    }

    // Common port aliases
    if (s == "http")  { outMin = outMax = 80; return true; }
    if (s == "https") { outMin = outMax = 443; return true; }
    if (s == "ssh")   { outMin = outMax = 22; return true; }
    if (s == "dns")   { outMin = outMax = 53; return true; }
    if (s == "ftp")   { outMin = outMax = 21; return true; }
    if (s == "telnet"){ outMin = outMax = 23; return true; }

    size_t dashPos = s.find('-');
    if (dashPos != std::string::npos) {
        try {
            int p1 = std::stoi(s.substr(0, dashPos));
            int p2 = std::stoi(s.substr(dashPos + 1));
            if (p1 < 1 || p1 > 65535 || p2 < 1 || p2 > 65535 || p1 > p2) {
                error = "Port range out of valid bounds (1-65535)";
                return false;
            }
            outMin = static_cast<uint16_t>(p1);
            outMax = static_cast<uint16_t>(p2);
            return true;
        } catch (...) {
            error = "Invalid port range format: " + s;
            return false;
        }
    }

    try {
        int p = std::stoi(s);
        if (p < 0 || p > 65535) {
            error = "Port must be 0-65535";
            return false;
        }
        outMin = static_cast<uint16_t>(p);
        outMax = static_cast<uint16_t>(p);
        return true;
    } catch (...) {
        error = "Invalid port number: " + s;
        return false;
    }
}

std::string RuleManager::formatPortRange(uint16_t minPort, uint16_t maxPort)
{
    if (minPort == 0 && maxPort == 0) return "ANY";
    if (maxPort == 0 || maxPort == minPort) return std::to_string(minPort);
    return std::to_string(minPort) + "-" + std::to_string(maxPort);
}

bool RuleManager::parseProtocol(const std::string &input, uint8_t &outProto, std::string &error)
{
    std::string s = toLower(input);
    if (s == "tcp" || s == "6") {
        outProto = NETGUARD_PROTO_TCP;
    } else if (s == "udp" || s == "17") {
        outProto = NETGUARD_PROTO_UDP;
    } else if (s == "icmp" || s == "1") {
        outProto = NETGUARD_PROTO_ICMP;
    } else if (s == "any" || s == "*" || s == "0") {
        outProto = NETGUARD_PROTO_ANY;
    } else {
        error = "Unknown protocol: " + input + " (supported: tcp, udp, icmp, any)";
        return false;
    }
    return true;
}

std::string RuleManager::formatProtocol(uint8_t proto)
{
    switch (proto) {
    case NETGUARD_PROTO_TCP:  return "TCP";
    case NETGUARD_PROTO_UDP:  return "UDP";
    case NETGUARD_PROTO_ICMP: return "ICMP";
    default:                  return "ANY";
    }
}

bool RuleManager::parseDirection(const std::string &input, uint8_t &outDir, std::string &error)
{
    std::string s = toLower(input);
    if (s == "in" || s == "inbound" || s == "input") {
        outDir = NETGUARD_DIR_IN;
    } else if (s == "out" || s == "outbound" || s == "output") {
        outDir = NETGUARD_DIR_OUT;
    } else if (s == "fwd" || s == "forward") {
        outDir = NETGUARD_DIR_FWD;
    } else if (s == "any" || s == "*") {
        outDir = NETGUARD_DIR_ANY;
    } else {
        error = "Invalid direction: " + input + " (supported: in, out, fwd, any)";
        return false;
    }
    return true;
}

std::string RuleManager::formatDirection(uint8_t dir)
{
    if (dir == NETGUARD_DIR_IN)  return "IN";
    if (dir == NETGUARD_DIR_OUT) return "OUT";
    if (dir == NETGUARD_DIR_FWD) return "FWD";
    return "ANY";
}

bool RuleManager::parseAction(const std::string &input, uint8_t &outAction, std::string &error)
{
    std::string s = toLower(input);
    if (s == "accept" || s == "allow" || s == "pass") {
        outAction = NETGUARD_ACTION_ACCEPT;
    } else if (s == "drop" || s == "block" || s == "deny") {
        outAction = NETGUARD_ACTION_DROP;
    } else if (s == "reject") {
        outAction = NETGUARD_ACTION_REJECT;
    } else if (s == "log") {
        outAction = NETGUARD_ACTION_LOG;
    } else {
        error = "Invalid action: " + input + " (supported: accept, drop, reject, log)";
        return false;
    }
    return true;
}

std::string RuleManager::formatAction(uint8_t action)
{
    switch (action) {
    case NETGUARD_ACTION_ACCEPT: return "ACCEPT";
    case NETGUARD_ACTION_DROP:   return "DROP";
    case NETGUARD_ACTION_REJECT: return "REJECT";
    case NETGUARD_ACTION_LOG:    return "LOG";
    default:                     return "UNKNOWN";
    }
}

bool RuleManager::validateRule(const struct netguard_rule &rule, std::string &error)
{
    if (rule.id == 0) {
        error = "Rule ID must be greater than 0";
        return false;
    }
    if (rule.action < NETGUARD_ACTION_ACCEPT || rule.action > NETGUARD_ACTION_LOG) {
        error = "Invalid action specified";
        return false;
    }
    if (rule.src_port_max > 0 && rule.src_port_max < rule.src_port_min) {
        error = "Source port max cannot be less than source port min";
        return false;
    }
    if (rule.dst_port_max > 0 && rule.dst_port_max < rule.dst_port_min) {
        error = "Destination port max cannot be less than destination port min";
        return false;
    }
    return true;
}

std::string RuleManager::formatRuleTable(const std::vector<struct netguard_rule> &rules, bool colored)
{
    std::ostringstream oss;

    if (rules.empty()) {
        oss << (colored ? COLOR_YELLOW : "")
            << "No packet filtering rules configured in kernel."
            << (colored ? COLOR_RESET : "") << "\n";
        return oss.str();
    }

    // Header
    if (colored) oss << COLOR_BOLD << COLOR_CYAN;
    oss << std::left
        << std::setw(6)  << "ID"
        << std::setw(8)  << "STATUS"
        << std::setw(6)  << "PRIO"
        << std::setw(18) << "SOURCE"
        << std::setw(18) << "DESTINATION"
        << std::setw(8)  << "PROTO"
        << std::setw(12) << "DPORT"
        << std::setw(6)  << "DIR"
        << std::setw(10) << "ACTION"
        << std::setw(10) << "PACKETS"
        << std::setw(12) << "BYTES"
        << "DESCRIPTION";
    if (colored) oss << COLOR_RESET;
    oss << "\n";

    oss << std::string(116, '-') << "\n";

    for (const auto &r : rules) {
        std::string statusStr = r.enabled ? "ENABLED" : "DISABLED";
        std::string srcStr    = formatIpCidr(r.src_ip, r.src_mask);
        std::string dstStr    = formatIpCidr(r.dst_ip, r.dst_mask);
        std::string protoStr  = formatProtocol(r.protocol);
        std::string portStr   = formatPortRange(r.dst_port_min, r.dst_port_max);
        std::string dirStr    = formatDirection(r.direction);
        std::string actStr    = formatAction(r.action);

        std::string rowColor = "";
        if (colored) {
            if (!r.enabled) rowColor = COLOR_GRAY;
            else if (r.action == NETGUARD_ACTION_DROP) rowColor = COLOR_RED;
            else if (r.action == NETGUARD_ACTION_ACCEPT) rowColor = COLOR_GREEN;
            else if (r.action == NETGUARD_ACTION_REJECT) rowColor = COLOR_YELLOW;
            else rowColor = COLOR_CYAN;
            oss << rowColor;
        }

        oss << std::left
            << std::setw(6)  << r.id
            << std::setw(8)  << statusStr
            << std::setw(6)  << r.priority
            << std::setw(18) << srcStr
            << std::setw(18) << dstStr
            << std::setw(8)  << protoStr
            << std::setw(12) << portStr
            << std::setw(6)  << dirStr
            << std::setw(10) << actStr
            << std::setw(10) << r.packet_count
            << std::setw(12) << r.byte_count
            << r.description;

        if (colored) oss << COLOR_RESET;
        oss << "\n";
    }

    return oss.str();
}

std::string RuleManager::formatSingleRule(const struct netguard_rule &rule, bool colored)
{
    std::ostringstream oss;
    if (colored) oss << COLOR_BOLD << COLOR_CYAN;
    oss << "Rule #" << rule.id << " Details:\n";
    if (colored) oss << COLOR_RESET;

    oss << "  Status:      " << (rule.enabled ? "ENABLED" : "DISABLED") << "\n"
        << "  Priority:    " << rule.priority << "\n"
        << "  Action:      " << formatAction(rule.action) << "\n"
        << "  Direction:   " << formatDirection(rule.direction) << "\n"
        << "  Protocol:    " << formatProtocol(rule.protocol) << "\n"
        << "  Source IP:   " << formatIpCidr(rule.src_ip, rule.src_mask) << "\n"
        << "  Dest IP:     " << formatIpCidr(rule.dst_ip, rule.dst_mask) << "\n"
        << "  Src Ports:   " << formatPortRange(rule.src_port_min, rule.src_port_max) << "\n"
        << "  Dst Ports:   " << formatPortRange(rule.dst_port_min, rule.dst_port_max) << "\n"
        << "  Packets:     " << rule.packet_count << "\n"
        << "  Bytes:       " << rule.byte_count << "\n"
        << "  Description: " << rule.description << "\n";
    return oss.str();
}

bool RuleManager::exportToFile(const std::string &filename, const std::vector<struct netguard_rule> &rules, std::string &error)
{
    std::ofstream ofs(filename);
    if (!ofs.is_open()) {
        error = "Failed to open file for writing: " + filename;
        return false;
    }

    ofs << "# NetGuard Rule Configuration Export\n";
    ofs << "# ID,PRIORITY,ENABLED,DIR,PROTO,ACTION,SRC_IP,DST_IP,SPORT,DPORT,DESCRIPTION\n";

    for (const auto &r : rules) {
        ofs << r.id << ","
            << r.priority << ","
            << (r.enabled ? 1 : 0) << ","
            << formatDirection(r.direction) << ","
            << formatProtocol(r.protocol) << ","
            << formatAction(r.action) << ","
            << formatIpCidr(r.src_ip, r.src_mask) << ","
            << formatIpCidr(r.dst_ip, r.dst_mask) << ","
            << formatPortRange(r.src_port_min, r.src_port_max) << ","
            << formatPortRange(r.dst_port_min, r.dst_port_max) << ","
            << r.description << "\n";
    }

    return true;
}

bool RuleManager::importFromFile(const std::string &filename, std::vector<struct netguard_rule> &rules, std::string &error)
{
    std::ifstream ifs(filename);
    if (!ifs.is_open()) {
        error = "Failed to open rule configuration file: " + filename;
        return false;
    }

    rules.clear();
    std::string line;
    int lineNum = 0;

    while (std::getline(ifs, line)) {
        lineNum++;
        if (line.empty() || line[0] == '#')
            continue;

        std::stringstream ss(line);
        std::string token;
        std::vector<std::string> tokens;
        while (std::getline(ss, token, ',')) {
            tokens.push_back(token);
        }

        if (tokens.size() < 10) {
            error = "Line " + std::to_string(lineNum) + ": Malformed CSV rule format";
            return false;
        }

        struct netguard_rule r;
        std::memset(&r, 0, sizeof(r));

        try {
            r.id = std::stoul(tokens[0]);
            r.priority = std::stoul(tokens[1]);
            r.enabled = (tokens[2] == "1" || tokens[2] == "true");
        } catch (...) {
            error = "Line " + std::to_string(lineNum) + ": Invalid numeric ID/priority";
            return false;
        }

        std::string subErr;
        if (!parseDirection(tokens[3], r.direction, subErr) ||
            !parseProtocol(tokens[4], r.protocol, subErr) ||
            !parseAction(tokens[5], r.action, subErr) ||
            !parseIpCidr(tokens[6], r.src_ip, r.src_mask, subErr) ||
            !parseIpCidr(tokens[7], r.dst_ip, r.dst_mask, subErr) ||
            !parsePortRange(tokens[8], r.src_port_min, r.src_port_max, subErr) ||
            !parsePortRange(tokens[9], r.dst_port_min, r.dst_port_max, subErr)) {
            error = "Line " + std::to_string(lineNum) + ": " + subErr;
            return false;
        }

        if (tokens.size() >= 11) {
            strncpy(r.description, tokens[10].c_str(), sizeof(r.description) - 1);
        }

        rules.push_back(r);
    }

    return true;
}

} // namespace netguard
