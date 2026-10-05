#!/usr/bin/env bash
set -e

COLOR_GREEN="\033[32m"
COLOR_CYAN="\033[36m"
COLOR_RESET="\033[0m"

echo -e "${COLOR_CYAN}============================================================${COLOR_RESET}"
echo -e "${COLOR_CYAN}   NetGuard: Complete System Build Script (C/C++)           ${COLOR_RESET}"
echo -e "${COLOR_CYAN}============================================================${COLOR_RESET}"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${PROJECT_ROOT}"

echo -e "\n${COLOR_CYAN}[1/5] Building Linux Kernel Module...${COLOR_RESET}"
make kernel

echo -e "\n${COLOR_CYAN}[2/5] Building C++ User-Space CLI Agent...${COLOR_RESET}"
make agent

echo -e "\n${COLOR_CYAN}[3/5] Building C++ Graphical NOC Dashboard...${COLOR_RESET}"
make gui

echo -e "\n${COLOR_CYAN}[4/5] Building C++ Terminal NOC Dashboard...${COLOR_RESET}"
make tui

echo -e "\n${COLOR_CYAN}[5/5] Building Unit Test Suite...${COLOR_RESET}"
make tests

echo -e "\n${COLOR_GREEN}============================================================${COLOR_RESET}"
echo -e "${COLOR_GREEN}✓ ALL NETGUARD COMPONENTS BUILT SUCCESSFULLY!${COLOR_RESET}"
echo -e "${COLOR_GREEN}============================================================${COLOR_RESET}"
echo -e "Binaries generated in ${PROJECT_ROOT}/bin:"
ls -lh bin/
echo -e "Kernel Module: ${PROJECT_ROOT}/kernel/netguard_mod.ko"
