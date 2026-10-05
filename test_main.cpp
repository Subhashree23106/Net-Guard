#include <iostream>

void run_rule_engine_tests(int &passed, int &failed);
void run_parser_tests(int &passed, int &failed);
void run_netlink_proto_tests(int &passed, int &failed);

int main() {
    std::cout << "============================================================\n";
    std::cout << "         NETGUARD CAPSTONE UNIT TEST SUITE RUNNER           \n";
    std::cout << "============================================================\n\n";

    int passed = 0;
    int failed = 0;

    run_rule_engine_tests(passed, failed);
    std::cout << "\n";
    run_parser_tests(passed, failed);
    std::cout << "\n";
    run_netlink_proto_tests(passed, failed);
    std::cout << "\n";

    std::cout << "============================================================\n";
    std::cout << "TEST RESULTS SUMMARY:\n";
    std::cout << "  Passed: " << passed << "\n";
    std::cout << "  Failed: " << failed << "\n";
    std::cout << "  Total:  " << (passed + failed) << "\n";
    std::cout << "============================================================\n";

    if (failed == 0) {
        std::cout << ">>> ALL UNIT TESTS PASSED SUCCESSFULLY! <<<\n";
        return 0;
    } else {
        std::cerr << ">>> UNIT TESTS FAILED! <<<\n";
        return 1;
    }
}
