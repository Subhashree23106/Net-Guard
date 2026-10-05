#include "NetGuardGUI.hpp"
#include <iostream>

int main() {
    std::cout << "Starting NetGuard Technical NOC GUI Dashboard...\n";
    try {
        netguard::NetGuardGUI gui(1280, 800);
        if (!gui.init()) {
            std::cerr << "Failed to initialize GUI display.\n";
            return 1;
        }
        gui.run();
        return 0;
    } catch (const std::exception &ex) {
        std::cerr << "GUI exception: " << ex.what() << "\n";
        return 1;
    }
}
