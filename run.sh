#!/usr/bin/env bash

COLOR_GREEN="\033[32m"
COLOR_CYAN="\033[36m"
COLOR_YELLOW="\033[33m"
COLOR_RESET="\033[0m"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${PROJECT_ROOT}"

echo -e "${COLOR_CYAN}============================================================${COLOR_RESET}"
echo -e "${COLOR_CYAN}      NetGuard: Network Security Agent Launcher             ${COLOR_RESET}"
echo -e "${COLOR_CYAN}============================================================${COLOR_RESET}"
echo "Select an interface to launch:"
echo "  1) NetGuard Graphical NOC Dashboard (C++ / X11 GUI)"
echo "  2) NetGuard Interactive Administration Shell (CLI)"
echo "  3) NetGuard Terminal NOC Dashboard (C++ / NCurses TUI)"
echo "  4) NetGuard Live Packet Stream (Monitor Mode)"
echo "  5) NetGuard Current Traffic Statistics"
echo "  6) Run Unit & System Tests"
echo "  7) Run Demonstration Scenario"
echo "  8) Exit"
echo -n "Enter choice [1-8]: "
read -r choice

case "$choice" in
    1)
        echo "Launching NetGuard Graphical NOC Dashboard..."
        ./bin/netguard-gui
        ;;
    2)
        echo "Launching NetGuard CLI Shell..."
        sudo ./bin/netguard
        ;;
    3)
        echo "Launching NetGuard Terminal Dashboard..."
        sudo ./bin/netguard-tui
        ;;
    4)
        echo "Starting live packet stream monitor..."
        sudo ./bin/netguard monitor
        ;;
    5)
        echo "Displaying traffic statistics..."
        sudo ./bin/netguard stats --watch
        ;;
    6)
        ./scripts/test.sh
        ;;
    7)
        sudo ./scripts/demo.sh
        ;;
    *)
        echo "Exiting."
        ;;
esac
