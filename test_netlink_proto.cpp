#include <iostream>
#include <vector>
#include <cassert>
#include <cstring>
#include <linux/netlink.h>
#include "../common/netguard_uapi.h"

void run_netlink_proto_tests(int &passed, int &failed) {
    std::cout << "[TEST] Running Netlink Protocol & Struct Alignment Tests...\n";

    // Test 1: Size & Alignment of Structs
    if (sizeof(struct netguard_rule) > 0 && sizeof(struct netguard_stats) > 0 &&
        sizeof(struct netguard_nl_hdr) == 16) {
        std::cout << "  ✓ Test 1 Passed: Struct sizing (netguard_rule=" << sizeof(struct netguard_rule)
                  << " bytes, netguard_stats=" << sizeof(struct netguard_stats)
                  << " bytes, netguard_nl_hdr=" << sizeof(struct netguard_nl_hdr) << " bytes)\n";
        passed++;
    } else {
        std::cerr << "  ✗ Test 1 Failed: Unexpected struct size\n";
        failed++;
    }

    // Test 2: Netlink Header Framing
    uint32_t payloadLen = sizeof(struct netguard_rule);
    uint32_t totalLen = NLMSG_SPACE(sizeof(struct netguard_nl_hdr) + payloadLen);
    std::vector<uint8_t> buf(totalLen, 0);

    struct nlmsghdr *nlh = reinterpret_cast<struct nlmsghdr *>(buf.data());
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct netguard_nl_hdr) + payloadLen);
    nlh->nlmsg_type = NETGUARD_NL_MSG_ADD_RULE;
    nlh->nlmsg_seq = 42;

    struct netguard_nl_hdr *ghdr = reinterpret_cast<struct netguard_nl_hdr *>(NLMSG_DATA(nlh));
    ghdr->msg_type = NETGUARD_NL_MSG_ADD_RULE;
    ghdr->payload_len = payloadLen;
    ghdr->status = NETGUARD_OK;

    struct netguard_rule *r = reinterpret_cast<struct netguard_rule *>(ghdr + 1);
    r->id = 777;
    r->priority = 50;

    // Verify extraction
    if (NLMSG_OK(nlh, (unsigned int)totalLen) && ghdr->msg_type == NETGUARD_NL_MSG_ADD_RULE &&
        r->id == 777 && r->priority == 50) {
        std::cout << "  ✓ Test 2 Passed: Netlink message framing and payload extraction\n";
        passed++;
    } else {
        std::cerr << "  ✗ Test 2 Failed: Netlink header framing error\n";
        failed++;
    }
}
