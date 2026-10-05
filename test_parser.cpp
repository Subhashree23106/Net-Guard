#include <iostream>
#include <vector>
#include <cassert>
#include <cstring>
#include <arpa/inet.h>
#include "../agent/RuleManager.hpp"

void run_parser_tests(int &passed, int &failed) {
    std::cout << "[TEST] Running CLI & Argument Parser Tests...\n";

    std::string err;
    uint32_t ip = 0, mask = 0;
    uint16_t minP = 0, maxP = 0;
    uint8_t proto = 0, dir = 0, act = 0;

    // Test 1: IP Parsing "192.168.1.100"
    if (netguard::RuleManager::parseIpCidr("192.168.1.100", ip, mask, err) &&
        ip == inet_addr("192.168.1.100") && mask == 0xFFFFFFFF) {
        std::cout << "  ✓ Test 1 Passed: Single IPv4 host parse\n";
        passed++;
    } else {
        std::cerr << "  ✗ Test 1 Failed: " << err << "\n";
        failed++;
    }

    // Test 2: CIDR Parsing "10.0.0.0/16"
    if (netguard::RuleManager::parseIpCidr("10.0.0.0/16", ip, mask, err) &&
        ip == inet_addr("10.0.0.0") && mask == htonl(0xFFFF0000)) {
        std::cout << "  ✓ Test 2 Passed: CIDR /16 subnet parse\n";
        passed++;
    } else {
        std::cerr << "  ✗ Test 2 Failed: " << err << "\n";
        failed++;
    }

    // Test 3: Port Range Parsing "1000-2000" and Port Alias "ssh"
    if (netguard::RuleManager::parsePortRange("1000-2000", minP, maxP, err) && minP == 1000 && maxP == 2000 &&
        netguard::RuleManager::parsePortRange("ssh", minP, maxP, err) && minP == 22 && maxP == 22) {
        std::cout << "  ✓ Test 3 Passed: Port range and service alias parse\n";
        passed++;
    } else {
        std::cerr << "  ✗ Test 3 Failed: " << err << "\n";
        failed++;
    }

    // Test 4: Protocol and Action Parsing
    if (netguard::RuleManager::parseProtocol("tcp", proto, err) && proto == NETGUARD_PROTO_TCP &&
        netguard::RuleManager::parseAction("drop", act, err) && act == NETGUARD_ACTION_DROP &&
        netguard::RuleManager::parseDirection("inbound", dir, err) && dir == NETGUARD_DIR_IN) {
        std::cout << "  ✓ Test 4 Passed: Protocol, Action, and Direction tokens\n";
        passed++;
    } else {
        std::cerr << "  ✗ Test 4 Failed: " << err << "\n";
        failed++;
    }

    // Test 5: CSV Export & Re-import round-trip
    std::vector<struct netguard_rule> rulesOut;
    struct netguard_rule r;
    std::memset(&r, 0, sizeof(r));
    r.id = 999;
    r.priority = 1;
    r.enabled = 1;
    r.direction = NETGUARD_DIR_IN;
    r.protocol = NETGUARD_PROTO_TCP;
    r.action = NETGUARD_ACTION_DROP;
    r.dst_port_min = r.dst_port_max = 8080;
    strncpy(r.description, "Test Web Block", sizeof(r.description) - 1);
    rulesOut.push_back(r);

    std::string tmpFile = "/tmp/netguard_test_rules.csv";
    if (netguard::RuleManager::exportToFile(tmpFile, rulesOut, err)) {
        std::vector<struct netguard_rule> rulesIn;
        if (netguard::RuleManager::importFromFile(tmpFile, rulesIn, err) &&
            rulesIn.size() == 1 && rulesIn[0].id == 999 && rulesIn[0].dst_port_min == 8080) {
            std::cout << "  ✓ Test 5 Passed: CSV Rule file export/import round-trip\n";
            passed++;
        } else {
            std::cerr << "  ✗ Test 5 Failed import: " << err << "\n";
            failed++;
        }
    } else {
        std::cerr << "  ✗ Test 5 Failed export: " << err << "\n";
        failed++;
    }
}
