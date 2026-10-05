#include "CLI.hpp"
#include <iostream>

int main(int argc, char *argv[]) {
    try {
        netguard::CLI cli;
        return cli.run(argc, argv);
    } catch (const std::exception &ex) {
        std::cerr << "Fatal error: " << ex.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "Fatal unknown error occurred.\n";
        return 1;
    }
}
