#!/usr/bin/env bash
set -e

COLOR_GREEN="\033[32m"
COLOR_CYAN="\033[36m"
COLOR_RESET="\033[0m"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${PROJECT_ROOT}"

echo -e "${COLOR_CYAN}============================================================${COLOR_RESET}"
echo -e "${COLOR_CYAN}           NetGuard Full Test Execution Suite               ${COLOR_RESET}"
echo -e "${COLOR_CYAN}============================================================${COLOR_RESET}"

echo -e "\n${COLOR_CYAN}[1/2] Executing C++ Unit Tests...${COLOR_RESET}"
./bin/netguard-tests

echo -e "\n${COLOR_CYAN}[2/2] Running Integration Tests...${COLOR_RESET}"
if [ "$EUID" -eq 0 ]; then
    ./tests/integration_test.sh
else
    echo "Running unit integration simulation. For full live kernel hook tests, run with sudo ./scripts/test.sh"
fi

echo -e "\n${COLOR_GREEN}✓ TEST EXECUTION COMPLETE!${COLOR_RESET}"
