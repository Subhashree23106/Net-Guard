#include <cassert>
#include <iostream>
#include <vector>
#include <algorithm>
#include <cstring>
#include <arpa/inet.h>
#include "../common/netguard_uapi.h"

// Simulated userspace rule evaluation mirroring kernel rule_engine.c
static inline bool test_match_ip(uint32_t packet_ip, uint32_t rule_ip, uint32_t rule_mask) {
    if (rule_mask == 0) return true;
    return (packet_ip & rule_mask) == (rule_ip & rule_mask);
}

static inline bool test_match_port(uint16_t packet_port, uint16_t min_port, uint16_t max_port) {
    if (min_port == 0 && max_port == 0) return true;
    if (max_port == 0 || max_port < min_port) return packet_port == min_port;
    return (packet_port >= min_port && packet_port <= max_port);
}

uint8_t evaluate_rules_sim(const std::vector<struct netguard_rule> &rules,
                           uint32_t src_ip, uint32_t dst_ip,
                           uint16_t src_port, uint16_t dst_port,
                           uint8_t protocol, uint8_t direction,
                           uint32_t &matched_id)
{
    matched_id = 0;
    for (const auto &r : rules) {
        if (!r.enabled) continue;
        if (r.direction != NETGUARD_DIR_ANY && !(r.direction & direction)) continue;
        if (r.protocol != NETGUARD_PROTO_ANY && r.protocol != protocol) continue;
        if (!test_match_ip(src_ip, r.src_ip, r.src_mask)) continue;
        if (!test_match_ip(dst_ip, r.dst_ip, r.dst_mask)) continue;
        if (protocol == NETGUARD_PROTO_TCP || protocol == NETGUARD_PROTO_UDP) {
            if (!test_match_port(src_port, r.src_port_min, r.src_port_max)) continue;
            if (!test_match_port(dst_port, r.dst_port_min, r.dst_port_max)) continue;
        }

        matched_id = r.id;
        return r.action;
    }
    return NETGUARD_ACTION_ACCEPT; // default
}

void run_rule_engine_tests(int &passed, int &failed) {
    std::cout << "[TEST] Running Rule Engine Logic & Priority Tests...\n";

    std::vector<struct netguard_rule> rules;

    // Rule 1: High Priority (10) - DROP SSH port 22
    struct netguard_rule r1;
    std::memset(&r1, 0, sizeof(r1));
    r1.id = 101;
    r1.priority = 10;
    r1.enabled = 1;
    r1.protocol = NETGUARD_PROTO_TCP;
    r1.dst_port_min = 22;
    r1.dst_port_max = 22;
    r1.direction = NETGUARD_DIR_IN;
    r1.action = NETGUARD_ACTION_DROP;
    rules.push_back(r1);

    // Rule 2: Low Priority (100) - ACCEPT all TCP
    struct netguard_rule r2;
    std::memset(&r2, 0, sizeof(r2));
    r2.id = 102;
    r2.priority = 100;
    r2.enabled = 1;
    r2.protocol = NETGUARD_PROTO_TCP;
    r2.direction = NETGUARD_DIR_IN;
    r2.action = NETGUARD_ACTION_ACCEPT;
    rules.push_back(r2);

    // Sort by priority (same as kernel)
    std::sort(rules.begin(), rules.end(), [](const struct netguard_rule &a, const struct netguard_rule &b) {
        return a.priority < b.priority;
    });

    uint32_t matched = 0;
    uint32_t src = inet_addr("192.168.1.50");
    uint32_t dst = inet_addr("192.168.1.1");

    // Test 1: SSH (Port 22) -> should be DROPPED by Rule 101
    uint8_t act = evaluate_rules_sim(rules, src, dst, 54321, 22, NETGUARD_PROTO_TCP, NETGUARD_DIR_IN, matched);
    if (act == NETGUARD_ACTION_DROP && matched == 101) {
        std::cout << "  ✓ Test 1 Passed: SSH Port 22 matched Rule #101 (DROP)\n";
        passed++;
    } else {
        std::cerr << "  ✗ Test 1 Failed: Expected DROP by 101, got action " << (int)act << " rule " << matched << "\n";
        failed++;
    }

    // Test 2: HTTP (Port 80) -> should be ACCEPTED by Rule 102
    act = evaluate_rules_sim(rules, src, dst, 54322, 80, NETGUARD_PROTO_TCP, NETGUARD_DIR_IN, matched);
    if (act == NETGUARD_ACTION_ACCEPT && matched == 102) {
        std::cout << "  ✓ Test 2 Passed: HTTP Port 80 matched Rule #102 (ACCEPT)\n";
        passed++;
    } else {
        std::cerr << "  ✗ Test 2 Failed: Expected ACCEPT by 102, got " << (int)act << "\n";
        failed++;
    }

    // Test 3: Disable Rule 101 -> SSH Port 22 should now match Rule 102 (ACCEPT)
    rules[0].enabled = 0;
    act = evaluate_rules_sim(rules, src, dst, 54321, 22, NETGUARD_PROTO_TCP, NETGUARD_DIR_IN, matched);
    if (act == NETGUARD_ACTION_ACCEPT && matched == 102) {
        std::cout << "  ✓ Test 3 Passed: Disabled Rule #101 allows traffic to fall through to Rule #102\n";
        passed++;
    } else {
        std::cerr << "  ✗ Test 3 Failed: Expected fallback ACCEPT by 102, got " << (int)act << "\n";
        failed++;
    }

    // Test 4: Subnet CIDR match (10.0.0.0/24)
    struct netguard_rule r3;
    std::memset(&r3, 0, sizeof(r3));
    r3.id = 103;
    r3.priority = 5;
    r3.enabled = 1;
    r3.src_ip = inet_addr("10.0.0.0");
    r3.src_mask = inet_addr("255.255.255.0");
    r3.protocol = NETGUARD_PROTO_ANY;
    r3.direction = NETGUARD_DIR_ANY;
    r3.action = NETGUARD_ACTION_DROP;
    rules.insert(rules.begin(), r3);

    act = evaluate_rules_sim(rules, inet_addr("10.0.0.45"), dst, 1000, 1000, NETGUARD_PROTO_UDP, NETGUARD_DIR_IN, matched);
    if (act == NETGUARD_ACTION_DROP && matched == 103) {
        std::cout << "  ✓ Test 4 Passed: CIDR Subnet match (10.0.0.45 in 10.0.0.0/24) DROPPED\n";
        passed++;
    } else {
        std::cerr << "  ✗ Test 4 Failed: Expected DROP by 103, got " << (int)act << "\n";
        failed++;
    }
}
