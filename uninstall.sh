#!/usr/bin/env bash
set -e

COLOR_GREEN="\033[32m"
COLOR_CYAN="\033[36m"
COLOR_RED="\033[31m"
COLOR_RESET="\033[0m"

echo -e "${COLOR_CYAN}============================================================${COLOR_RESET}"
echo -e "${COLOR_CYAN}   NetGuard: System Uninstallation & Module Removal         ${COLOR_RESET}"
echo -e "${COLOR_CYAN}============================================================${COLOR_RESET}"

if [ "$EUID" -ne 0 ]; then
    echo -e "${COLOR_RED}[ERROR] This uninstallation script must be run as root (sudo ./scripts/uninstall.sh)${COLOR_RESET}"
    exit 1
fi

echo -e "\n${COLOR_CYAN}[1/3] Unloading Linux Kernel Module...${COLOR_RESET}"
if lsmod | grep -q netguard_mod; then
    rmmod netguard_mod
    echo -e "${COLOR_GREEN}✓ netguard_mod kernel module unloaded cleanly${COLOR_RESET}"
else
    echo "netguard_mod was not currently loaded in kernel."
fi

echo -e "\n${COLOR_CYAN}[2/3] Removing installed binaries from /usr/local/bin/...${COLOR_RESET}"
rm -f /usr/local/bin/netguard /usr/local/bin/netguard-gui /usr/local/bin/netguard-tui
echo -e "${COLOR_GREEN}✓ Binaries removed${COLOR_RESET}"

echo -e "\n${COLOR_CYAN}[3/3] Cleaning temporary files...${COLOR_RESET}"
rm -f /tmp/netguard_test_rules.csv

echo -e "\n${COLOR_GREEN}============================================================${COLOR_RESET}"
echo -e "${COLOR_GREEN}✓ NETGUARD UNINSTALLATION COMPLETED CLEANLY!${COLOR_RESET}"
echo -e "${COLOR_GREEN}============================================================${COLOR_RESET}"
