#include "NetGuardTUI.hpp"
#include <iostream>

int main() {
    try {
        netguard::NetGuardTUI tui;
        if (!tui.init()) {
            std::cerr << "Failed to initialize terminal interface.\n";
            return 1;
        }
        tui.run();
        return 0;
    } catch (const std::exception &ex) {
        std::cerr << "TUI Exception: " << ex.what() << "\n";
        return 1;
    }
}
