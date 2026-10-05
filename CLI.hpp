#ifndef NETGUARD_CLI_HPP
#define NETGUARD_CLI_HPP

#include <string>
#include <vector>
#include "NetlinkClient.hpp"
#include "RuleManager.hpp"
#include "Statistics.hpp"

namespace netguard {

class CLI {
public:
    CLI();
    ~CLI();

    // Run non-interactive or interactive based on argc/argv
    int run(int argc, char *argv[]);

    // Interactive REPL Shell
    void runInteractiveShell();

    // Command handlers
    bool handleAddRule(const std::vector<std::string> &args);
    bool handleInteractiveAddRule();
    bool handleListRules();
    bool handleDeleteRule(const std::vector<std::string> &args);
    bool handleEnableRule(const std::vector<std::string> &args, bool enable);
    bool handleClearRules();
    bool handleStats(bool reset, bool watch);
    bool handleStatus();
    bool handleMonitor(int count = 0);
    bool handlePolicy(const std::vector<std::string> &args);
    bool handleExport(const std::vector<std::string> &args);
    bool handleImport(const std::vector<std::string> &args);
    void printHelp();

private:
    NetlinkClient m_client;
    Statistics    m_stats;

    bool ensureConnected();
};

} // namespace netguard

#endif // NETGUARD_CLI_HPP
