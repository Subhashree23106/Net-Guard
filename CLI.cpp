#include "CLI.hpp"
#include <iostream>
#include <sstream>
#include <csignal>
#include <thread>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <arpa/inet.h>

namespace netguard {

// Colors
static const std::string COLOR_RESET   = "\033[0m";
static const std::string COLOR_BOLD    = "\033[1m";
static const std::string COLOR_RED     = "\033[31m";
static const std::string COLOR_GREEN   = "\033[32m";
static const std::string COLOR_YELLOW  = "\033[33m";
static const std::string COLOR_BLUE    = "\033[34m";
static const std::string COLOR_MAGENTA = "\033[35m";
static const std::string COLOR_CYAN    = "\033[36m";
static const std::string COLOR_GRAY    = "\033[90m";

static volatile sig_atomic_t g_running = 1;

static void sigHandler(int) {
    g_running = 0;
}

CLI::CLI() {}

CLI::~CLI() {
    m_client.disconnect();
}

bool CLI::ensureConnected() {
    if (!m_client.isConnected()) {
        if (!m_client.connect()) {
            std::cerr << COLOR_RED << "[ERROR] Unable to connect to NetGuard kernel module via Netlink." << COLOR_RESET << "\n";
            std::cerr << "Make sure 'netguard_mod.ko' is loaded (sudo insmod kernel/netguard_mod.ko) and you have root privileges.\n";
            return false;
        }
    }
    return true;
}

void CLI::printHelp() {
    std::cout << COLOR_BOLD << COLOR_CYAN
              << "NetGuard: Kernel-Space Network Packet Filter & Rule Enforcement Agent\n"
              << COLOR_RESET
              << "Usage:\n"
              << "  netguard [command] [options]\n\n"
              << "Commands:\n"
              << "  add [options]        Add a new packet filtering rule\n"
              << "  list                 List all active filtering rules\n"
              << "  delete <id>          Delete rule by ID\n"
              << "  enable <id>          Enable rule by ID\n"
              << "  disable <id>         Disable rule by ID\n"
              << "  clear                Clear all rules\n"
              << "  stats [--reset]      Display traffic metrics and counters\n"
              << "  stats --watch        Continuous real-time traffic statistics\n"
              << "  status               Show kernel module & netfilter status\n"
              << "  monitor [--count N]  Live packet inspection event stream\n"
              << "  policy <accept|drop> Set kernel default policy\n"
              << "  export <file.csv>    Export current rules to a CSV file\n"
              << "  import <file.csv>    Import and load rules from a CSV file\n"
              << "  help                 Display this help message\n\n"
              << "Add Rule Options:\n"
              << "  --id <num>           Unique rule ID (required)\n"
              << "  --prio, --priority   Rule priority (1-1000, lower is evaluated first)\n"
              << "  --src <ip/cidr>      Source IPv4 or CIDR (e.g. 192.168.1.100 or 10.0.0.0/24, default: any)\n"
              << "  --dst <ip/cidr>      Destination IPv4 or CIDR (default: any)\n"
              << "  --proto <proto>      Protocol: tcp, udp, icmp, any (default: any)\n"
              << "  --sport <port/range> Source port or range (e.g. 80, 1000-2000, default: any)\n"
              << "  --dport <port/range> Destination port or range (e.g. 22, 80, default: any)\n"
              << "  --action <act>       Action: drop, accept, reject, log (default: drop)\n"
              << "  --dir <direction>    Direction: in, out, fwd, any (default: in)\n"
              << "  --desc <text>        Rule description text note\n\n"
              << "Examples:\n"
              << "  sudo ./netguard add --id 101 --src 192.168.1.100 --dst any --proto tcp --dport 22 --action drop\n"
              << "  sudo ./netguard add --id 102 --prio 10 --proto udp --dport 53 --action drop --desc 'Block DNS'\n"
              << "  sudo ./netguard list\n"
              << "  sudo ./netguard stats\n"
              << "  sudo ./netguard monitor\n";
}

int CLI::run(int argc, char *argv[]) {
    if (argc < 2) {
        runInteractiveShell();
        return 0;
    }

    std::string cmd = argv[1];
    std::vector<std::string> args;
    for (int i = 2; i < argc; i++) {
        args.push_back(argv[i]);
    }

    if (cmd == "help" || cmd == "--help" || cmd == "-h") {
        printHelp();
        return 0;
    }

    if (!ensureConnected()) {
        return 1;
    }

    if (cmd == "add" || cmd == "add-rule") {
        return handleAddRule(args) ? 0 : 1;
    } else if (cmd == "list" || cmd == "list-rules" || cmd == "ls" || cmd == "show") {
        return handleListRules() ? 0 : 1;
    } else if (cmd == "del" || cmd == "delete" || cmd == "delete-rule" || cmd == "rm") {
        return handleDeleteRule(args) ? 0 : 1;
    } else if (cmd == "enable" || cmd == "enable-rule") {
        return handleEnableRule(args, true) ? 0 : 1;
    } else if (cmd == "disable" || cmd == "disable-rule") {
        return handleEnableRule(args, false) ? 0 : 1;
    } else if (cmd == "clear" || cmd == "flush") {
        return handleClearRules() ? 0 : 1;
    } else if (cmd == "stats" || cmd == "statistics") {
        bool reset = false, watch = false;
        for (const auto &a : args) {
            if (a == "--reset" || a == "-r") reset = true;
            if (a == "--watch" || a == "-w") watch = true;
        }
        return handleStats(reset, watch) ? 0 : 1;
    } else if (cmd == "status") {
        return handleStatus() ? 0 : 1;
    } else if (cmd == "monitor" || cmd == "watch") {
        int count = 0;
        for (size_t i = 0; i < args.size(); i++) {
            if (args[i] == "--count" && i + 1 < args.size()) {
                count = std::stoi(args[++i]);
            }
        }
        return handleMonitor(count) ? 0 : 1;
    } else if (cmd == "policy") {
        return handlePolicy(args) ? 0 : 1;
    } else if (cmd == "export") {
        return handleExport(args) ? 0 : 1;
    } else if (cmd == "import") {
        return handleImport(args) ? 0 : 1;
    } else if (cmd == "interactive" || cmd == "shell") {
        runInteractiveShell();
        return 0;
    } else {
        std::cerr << COLOR_RED << "Unknown command: " << cmd << COLOR_RESET << "\n";
        printHelp();
        return 1;
    }
}

bool CLI::handleAddRule(const std::vector<std::string> &args) {
    if (args.empty()) {
        return handleInteractiveAddRule();
    }

    struct netguard_rule rule;
    std::memset(&rule, 0, sizeof(rule));
    rule.enabled   = 1;
    rule.priority  = 100;
    rule.action    = NETGUARD_ACTION_DROP;
    rule.direction = NETGUARD_DIR_IN;
    rule.protocol  = NETGUARD_PROTO_ANY;

    std::string err;

    for (size_t i = 0; i < args.size(); i++) {
        const std::string &arg = args[i];
        if ((arg == "--id" || arg == "-i") && i + 1 < args.size()) {
            rule.id = std::stoul(args[++i]);
        } else if ((arg == "--prio" || arg == "--priority" || arg == "-p") && i + 1 < args.size()) {
            rule.priority = std::stoul(args[++i]);
        } else if ((arg == "--src" || arg == "-s") && i + 1 < args.size()) {
            if (!RuleManager::parseIpCidr(args[++i], rule.src_ip, rule.src_mask, err)) {
                std::cerr << COLOR_RED << "[ERROR] " << err << COLOR_RESET << "\n";
                return false;
            }
        } else if ((arg == "--dst" || arg == "-d") && i + 1 < args.size()) {
            if (!RuleManager::parseIpCidr(args[++i], rule.dst_ip, rule.dst_mask, err)) {
                std::cerr << COLOR_RED << "[ERROR] " << err << COLOR_RESET << "\n";
                return false;
            }
        } else if ((arg == "--proto" || arg == "--protocol") && i + 1 < args.size()) {
            if (!RuleManager::parseProtocol(args[++i], rule.protocol, err)) {
                std::cerr << COLOR_RED << "[ERROR] " << err << COLOR_RESET << "\n";
                return false;
            }
        } else if ((arg == "--sport") && i + 1 < args.size()) {
            if (!RuleManager::parsePortRange(args[++i], rule.src_port_min, rule.src_port_max, err)) {
                std::cerr << COLOR_RED << "[ERROR] " << err << COLOR_RESET << "\n";
                return false;
            }
        } else if ((arg == "--dport") && i + 1 < args.size()) {
            if (!RuleManager::parsePortRange(args[++i], rule.dst_port_min, rule.dst_port_max, err)) {
                std::cerr << COLOR_RED << "[ERROR] " << err << COLOR_RESET << "\n";
                return false;
            }
        } else if ((arg == "--action" || arg == "-a") && i + 1 < args.size()) {
            if (!RuleManager::parseAction(args[++i], rule.action, err)) {
                std::cerr << COLOR_RED << "[ERROR] " << err << COLOR_RESET << "\n";
                return false;
            }
        } else if ((arg == "--dir" || arg == "--direction") && i + 1 < args.size()) {
            if (!RuleManager::parseDirection(args[++i], rule.direction, err)) {
                std::cerr << COLOR_RED << "[ERROR] " << err << COLOR_RESET << "\n";
                return false;
            }
        } else if ((arg == "--desc" || arg == "--description") && i + 1 < args.size()) {
            std::string d = args[++i];
            strncpy(rule.description, d.c_str(), sizeof(rule.description) - 1);
        } else if (arg == "--disabled") {
            rule.enabled = 0;
        }
    }

    if (rule.id == 0) {
        std::cerr << COLOR_RED << "[ERROR] Please specify a valid non-zero Rule ID using --id <num>" << COLOR_RESET << "\n";
        return false;
    }

    if (!RuleManager::validateRule(rule, err)) {
        std::cerr << COLOR_RED << "[ERROR] Rule validation failed: " << err << COLOR_RESET << "\n";
        return false;
    }

    if (!m_client.addRule(rule, err)) {
        std::cerr << COLOR_RED << "[ERROR] Failed to add rule to kernel: " << err << COLOR_RESET << "\n";
        return false;
    }

    std::cout << COLOR_GREEN << "✓ Rule #" << rule.id << " added successfully to Linux kernel Netfilter engine." << COLOR_RESET << "\n";
    std::cout << RuleManager::formatSingleRule(rule);
    return true;
}

bool CLI::handleInteractiveAddRule() {
    struct netguard_rule rule;
    std::memset(&rule, 0, sizeof(rule));
    rule.enabled = 1;
    rule.priority = 100;
    rule.action = NETGUARD_ACTION_DROP;
    rule.direction = NETGUARD_DIR_IN;
    rule.protocol = NETGUARD_PROTO_ANY;

    std::cout << COLOR_BOLD << COLOR_CYAN << "--- Add New NetGuard Filter Rule ---" << COLOR_RESET << "\n";

    std::string input, err;

    std::cout << "Rule ID (e.g. 101): ";
    std::getline(std::cin, input);
    try { rule.id = std::stoul(input); } catch (...) { std::cerr << "Invalid ID\n"; return false; }

    std::cout << "Priority (1-1000, default 100): ";
    std::getline(std::cin, input);
    if (!input.empty()) {
        try { rule.priority = std::stoul(input); } catch (...) {}
    }

    std::cout << "Source IP / CIDR (e.g. 192.168.1.100 or any): ";
    std::getline(std::cin, input);
    if (!RuleManager::parseIpCidr(input, rule.src_ip, rule.src_mask, err)) {
        std::cerr << COLOR_RED << err << COLOR_RESET << "\n"; return false;
    }

    std::cout << "Destination IP / CIDR (e.g. 10.0.0.1 or any): ";
    std::getline(std::cin, input);
    if (!RuleManager::parseIpCidr(input, rule.dst_ip, rule.dst_mask, err)) {
        std::cerr << COLOR_RED << err << COLOR_RESET << "\n"; return false;
    }

    std::cout << "Protocol (tcp, udp, icmp, any): ";
    std::getline(std::cin, input);
    if (!RuleManager::parseProtocol(input, rule.protocol, err)) {
        std::cerr << COLOR_RED << err << COLOR_RESET << "\n"; return false;
    }

    std::cout << "Destination Port / Range (e.g. 22, 80, 1000-2000, any): ";
    std::getline(std::cin, input);
    if (!RuleManager::parsePortRange(input, rule.dst_port_min, rule.dst_port_max, err)) {
        std::cerr << COLOR_RED << err << COLOR_RESET << "\n"; return false;
    }

    std::cout << "Direction (in, out, fwd, any) [default: in]: ";
    std::getline(std::cin, input);
    if (input.empty()) input = "in";
    if (!RuleManager::parseDirection(input, rule.direction, err)) {
        std::cerr << COLOR_RED << err << COLOR_RESET << "\n"; return false;
    }

    std::cout << "Action (drop, accept, reject, log) [default: drop]: ";
    std::getline(std::cin, input);
    if (input.empty()) input = "drop";
    if (!RuleManager::parseAction(input, rule.action, err)) {
        std::cerr << COLOR_RED << err << COLOR_RESET << "\n"; return false;
    }

    std::cout << "Description / Tag: ";
    std::getline(std::cin, input);
    strncpy(rule.description, input.c_str(), sizeof(rule.description) - 1);

    if (!m_client.addRule(rule, err)) {
        std::cerr << COLOR_RED << "[ERROR] Kernel rejected rule: " << err << COLOR_RESET << "\n";
        return false;
    }

    std::cout << COLOR_GREEN << "✓ Rule #" << rule.id << " added successfully!" << COLOR_RESET << "\n";
    return true;
}

bool CLI::handleListRules() {
    std::vector<struct netguard_rule> rules;
    std::string err;
    if (!m_client.getRules(rules, err)) {
        std::cerr << COLOR_RED << "[ERROR] Failed to query rules from kernel: " << err << COLOR_RESET << "\n";
        return false;
    }

    std::cout << RuleManager::formatRuleTable(rules, true);
    return true;
}

bool CLI::handleDeleteRule(const std::vector<std::string> &args) {
    if (args.empty()) {
        std::cerr << COLOR_RED << "Usage: netguard delete <rule_id>" << COLOR_RESET << "\n";
        return false;
    }

    uint32_t id = 0;
    try {
        id = std::stoul(args[0]);
    } catch (...) {
        std::cerr << COLOR_RED << "Invalid rule ID: " << args[0] << COLOR_RESET << "\n";
        return false;
    }

    std::string err;
    if (!m_client.deleteRule(id, err)) {
        std::cerr << COLOR_RED << "[ERROR] Failed to delete rule #" << id << ": " << err << COLOR_RESET << "\n";
        return false;
    }

    std::cout << COLOR_GREEN << "✓ Rule #" << id << " deleted successfully from kernel." << COLOR_RESET << "\n";
    return true;
}

bool CLI::handleEnableRule(const std::vector<std::string> &args, bool enable) {
    if (args.empty()) {
        std::cerr << COLOR_RED << "Usage: netguard " << (enable ? "enable" : "disable") << " <rule_id>" << COLOR_RESET << "\n";
        return false;
    }

    uint32_t id = 0;
    try {
        id = std::stoul(args[0]);
    } catch (...) {
        std::cerr << COLOR_RED << "Invalid rule ID: " << args[0] << COLOR_RESET << "\n";
        return false;
    }

    std::string err;
    if (!m_client.enableRule(id, enable, err)) {
        std::cerr << COLOR_RED << "[ERROR] Failed to " << (enable ? "enable" : "disable") << " rule #" << id << ": " << err << COLOR_RESET << "\n";
        return false;
    }

    std::cout << COLOR_GREEN << "✓ Rule #" << id << " is now " << (enable ? "ENABLED" : "DISABLED") << "." << COLOR_RESET << "\n";
    return true;
}

bool CLI::handleClearRules() {
    std::string err;
    if (!m_client.clearRules(err)) {
        std::cerr << COLOR_RED << "[ERROR] Failed to clear rules: " << err << COLOR_RESET << "\n";
        return false;
    }

    std::cout << COLOR_GREEN << "✓ All NetGuard packet filtering rules cleared from kernel." << COLOR_RESET << "\n";
    return true;
}

bool CLI::handleStats(bool reset, bool watch) {
    std::string err;

    if (reset) {
        if (!m_client.resetStats(err)) {
            std::cerr << COLOR_RED << "[ERROR] Failed to reset statistics: " << err << COLOR_RESET << "\n";
            return false;
        }
        std::cout << COLOR_GREEN << "✓ Kernel packet statistics reset to zero." << COLOR_RESET << "\n";
        return true;
    }

    if (watch) {
        signal(SIGINT, sigHandler);
        std::cout << "\033[2J\033[H"; // Clear screen
        std::cout << "Starting live statistics monitor (Press Ctrl+C to stop)...\n";
        while (g_running) {
            struct netguard_stats st;
            if (m_client.getStats(st, err)) {
                m_stats.update(st);
                std::cout << "\033[H"; // Move cursor to top
                std::cout << m_stats.formatSystemStatus(true) << "\n";
                std::cout << m_stats.formatSummary(true) << "\n";
                std::cout << m_stats.formatProtocolBreakdown(true) << "\n";
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
        std::cout << "\nMonitor stopped.\n";
        return true;
    }

    struct netguard_stats st;
    if (!m_client.getStats(st, err)) {
        std::cerr << COLOR_RED << "[ERROR] Failed to fetch stats: " << err << COLOR_RESET << "\n";
        return false;
    }

    m_stats.update(st);
    std::cout << m_stats.formatSummary(true) << "\n";
    std::cout << m_stats.formatProtocolBreakdown(true) << "\n";
    return true;
}

bool CLI::handleStatus() {
    struct netguard_stats st;
    std::string err;
    if (!m_client.getStats(st, err)) {
        std::cerr << COLOR_RED << "[ERROR] Failed to get kernel status: " << err << COLOR_RESET << "\n";
        return false;
    }

    m_stats.update(st);
    std::cout << m_stats.formatSystemStatus(true) << "\n";
    return true;
}

bool CLI::handleMonitor(int count) {
    std::string err;
    signal(SIGINT, sigHandler);

    std::cout << COLOR_BOLD << COLOR_CYAN << "=== NetGuard Live Packet Activity Monitor ===" << COLOR_RESET << "\n";
    std::cout << "Capturing real-time packet enforcement events from Linux kernel Netfilter (Press Ctrl+C to stop)...\n\n";

    std::cout << std::left
              << std::setw(10) << "TIME"
              << std::setw(18) << "SOURCE"
              << std::setw(18) << "DESTINATION"
              << std::setw(8)  << "PROTO"
              << std::setw(12) << "PORTS"
              << std::setw(8)  << "DIR"
              << std::setw(10) << "ACTION"
              << std::setw(8)  << "RULE"
              << "LEN"
              << "\n";
    std::cout << std::string(90, '-') << "\n";

    int displayed = 0;

    // First fetch recent backlog
    std::vector<struct netguard_packet_event> events;
    if (m_client.getRecentEvents(events, err)) {
        for (const auto &e : events) {
            char srcBuf[INET_ADDRSTRLEN], dstBuf[INET_ADDRSTRLEN];
            struct in_addr sa, da;
            sa.s_addr = e.src_ip;
            da.s_addr = e.dst_ip;
            inet_ntop(AF_INET, &sa, srcBuf, sizeof(srcBuf));
            inet_ntop(AF_INET, &da, dstBuf, sizeof(dstBuf));

            std::string actColor = (e.action == NETGUARD_ACTION_DROP) ? COLOR_RED :
                                   (e.action == NETGUARD_ACTION_ACCEPT) ? COLOR_GREEN : COLOR_YELLOW;

            std::cout << std::left
                      << std::setw(10) << (std::to_string(e.timestamp_sec % 10000) + "." + std::to_string(e.timestamp_usec / 1000))
                      << std::setw(18) << srcBuf
                      << std::setw(18) << dstBuf
                      << std::setw(8)  << RuleManager::formatProtocol(e.protocol)
                      << std::setw(12) << (std::to_string(e.src_port) + "->" + std::to_string(e.dst_port))
                      << std::setw(8)  << RuleManager::formatDirection(e.direction)
                      << actColor << std::setw(10) << RuleManager::formatAction(e.action) << COLOR_RESET
                      << std::setw(8)  << (e.matched_rule_id ? std::to_string(e.matched_rule_id) : "DEFAULT")
                      << e.packet_len << "B\n";

            displayed++;
            if (count > 0 && displayed >= count) return true;
        }
    }

    // Subscribe to live Netlink multicast events
    m_client.subscribeEvents();

    while (g_running) {
        struct netguard_packet_event e;
        if (m_client.receiveEvent(e, 500)) {
            char srcBuf[INET_ADDRSTRLEN], dstBuf[INET_ADDRSTRLEN];
            struct in_addr sa, da;
            sa.s_addr = e.src_ip;
            da.s_addr = e.dst_ip;
            inet_ntop(AF_INET, &sa, srcBuf, sizeof(srcBuf));
            inet_ntop(AF_INET, &da, dstBuf, sizeof(dstBuf));

            std::string actColor = (e.action == NETGUARD_ACTION_DROP) ? COLOR_RED :
                                   (e.action == NETGUARD_ACTION_ACCEPT) ? COLOR_GREEN : COLOR_YELLOW;

            std::cout << std::left
                      << std::setw(10) << (std::to_string(e.timestamp_sec % 10000) + "." + std::to_string(e.timestamp_usec / 1000))
                      << std::setw(18) << srcBuf
                      << std::setw(18) << dstBuf
                      << std::setw(8)  << RuleManager::formatProtocol(e.protocol)
                      << std::setw(12) << (std::to_string(e.src_port) + "->" + std::to_string(e.dst_port))
                      << std::setw(8)  << RuleManager::formatDirection(e.direction)
                      << actColor << std::setw(10) << RuleManager::formatAction(e.action) << COLOR_RESET
                      << std::setw(8)  << (e.matched_rule_id ? std::to_string(e.matched_rule_id) : "DEFAULT")
                      << e.packet_len << "B\n";

            displayed++;
            if (count > 0 && displayed >= count) break;
        }
    }

    return true;
}

bool CLI::handlePolicy(const std::vector<std::string> &args) {
    if (args.empty()) {
        std::cerr << "Usage: netguard policy <accept|drop>\n";
        return false;
    }

    uint8_t pol = (args[0] == "drop" || args[0] == "DROP") ? NETGUARD_POLICY_DROP : NETGUARD_POLICY_ACCEPT;
    std::string err;
    if (!m_client.setDefaultPolicy(pol, err)) {
        std::cerr << COLOR_RED << "[ERROR] Failed to set default policy: " << err << COLOR_RESET << "\n";
        return false;
    }

    std::cout << COLOR_GREEN << "✓ Kernel default packet policy set to: "
              << ((pol == NETGUARD_POLICY_ACCEPT) ? "ACCEPT" : "DROP") << COLOR_RESET << "\n";
    return true;
}

bool CLI::handleExport(const std::vector<std::string> &args) {
    if (args.empty()) {
        std::cerr << "Usage: netguard export <filename.csv>\n";
        return false;
    }

    std::vector<struct netguard_rule> rules;
    std::string err;
    if (!m_client.getRules(rules, err)) {
        std::cerr << COLOR_RED << "[ERROR] Failed to query rules: " << err << COLOR_RESET << "\n";
        return false;
    }

    if (!RuleManager::exportToFile(args[0], rules, err)) {
        std::cerr << COLOR_RED << "[ERROR] Export failed: " << err << COLOR_RESET << "\n";
        return false;
    }

    std::cout << COLOR_GREEN << "✓ Exported " << rules.size() << " rules to " << args[0] << COLOR_RESET << "\n";
    return true;
}

bool CLI::handleImport(const std::vector<std::string> &args) {
    if (args.empty()) {
        std::cerr << "Usage: netguard import <filename.csv>\n";
        return false;
    }

    std::vector<struct netguard_rule> rules;
    std::string err;
    if (!RuleManager::importFromFile(args[0], rules, err)) {
        std::cerr << COLOR_RED << "[ERROR] Import parse error: " << err << COLOR_RESET << "\n";
        return false;
    }

    int success = 0;
    for (const auto &r : rules) {
        if (m_client.addRule(r, err)) {
            success++;
        } else {
            std::cerr << COLOR_YELLOW << "Warning: Failed to add rule #" << r.id << ": " << err << COLOR_RESET << "\n";
        }
    }

    std::cout << COLOR_GREEN << "✓ Imported " << success << " / " << rules.size() << " rules successfully." << COLOR_RESET << "\n";
    return true;
}

void CLI::runInteractiveShell() {
    std::cout << COLOR_BOLD << COLOR_CYAN
              << "============================================================\n"
              << "  NetGuard: Kernel Packet Filter Administration Console     \n"
              << "============================================================\n"
              << COLOR_RESET
              << "Type 'help' for commands, 'status' for health, 'exit' to quit.\n\n";

    if (!ensureConnected()) {
        std::cerr << COLOR_RED << "Kernel module not loaded. Starting in offline shell mode.\n" << COLOR_RESET;
    }

    std::string line;
    while (true) {
        std::cout << COLOR_BOLD << COLOR_CYAN << "netguard> " << COLOR_RESET;
        if (!std::getline(std::cin, line))
            break;

        std::stringstream ss(line);
        std::string cmd;
        ss >> cmd;
        if (cmd.empty()) continue;

        if (cmd == "exit" || cmd == "quit" || cmd == "q") {
            std::cout << "Exiting NetGuard console.\n";
            break;
        }

        std::vector<std::string> args;
        std::string arg;
        while (ss >> arg) {
            args.push_back(arg);
        }

        if (cmd == "help" || cmd == "?") {
            printHelp();
        } else if (cmd == "status") {
            handleStatus();
        } else if (cmd == "list" || cmd == "list-rules" || cmd == "show") {
            handleListRules();
        } else if (cmd == "add" || cmd == "add-rule") {
            handleAddRule(args);
        } else if (cmd == "delete" || cmd == "delete-rule" || cmd == "del" || cmd == "rm") {
            handleDeleteRule(args);
        } else if (cmd == "enable" || cmd == "enable-rule") {
            handleEnableRule(args, true);
        } else if (cmd == "disable" || cmd == "disable-rule") {
            handleEnableRule(args, false);
        } else if (cmd == "clear" || cmd == "flush") {
            handleClearRules();
        } else if (cmd == "stats" || cmd == "statistics") {
            bool reset = false, watch = false;
            for (const auto &a : args) {
                if (a == "--reset" || a == "-r") reset = true;
                if (a == "--watch" || a == "-w") watch = true;
            }
            handleStats(reset, watch);
        } else if (cmd == "reset-statistics" || cmd == "reset-stats") {
            handleStats(true, false);
        } else if (cmd == "monitor" || cmd == "logs") {
            int count = (args.size() > 0) ? std::stoi(args[0]) : 0;
            handleMonitor(count);
        } else if (cmd == "policy") {
            handlePolicy(args);
        } else if (cmd == "export") {
            handleExport(args);
        } else if (cmd == "import") {
            handleImport(args);
        } else {
            std::cout << COLOR_RED << "Unknown command: '" << cmd << "'. Type 'help' for command list." << COLOR_RESET << "\n";
        }
        std::cout << "\n";
    }
}

} // namespace netguard
