#!/usr/bin/env bash
set -e

COLOR_GREEN="\033[32m"
COLOR_CYAN="\033[36m"
COLOR_RED="\033[31m"
COLOR_YELLOW="\033[33m"
COLOR_RESET="\033[0m"

echo -e "${COLOR_CYAN}============================================================${COLOR_RESET}"
echo -e "${COLOR_CYAN}   NetGuard: System Installation & Kernel Module Loader     ${COLOR_RESET}"
echo -e "${COLOR_CYAN}============================================================${COLOR_RESET}"

if [ "$EUID" -ne 0 ]; then
    echo -e "${COLOR_RED}[ERROR] This installation script must be run as root (sudo ./scripts/install.sh)${COLOR_RESET}"
    exit 1
fi

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${PROJECT_ROOT}"

echo -e "\n${COLOR_CYAN}[1/4] Ensuring all binaries and kernel module are compiled...${COLOR_RESET}"
make all

echo -e "\n${COLOR_CYAN}[2/4] Installing binaries to /usr/local/bin/...${COLOR_RESET}"
cp -f bin/netguard /usr/local/bin/netguard
chmod 755 /usr/local/bin/netguard

if [ -f bin/netguard-gui ]; then
    cp -f bin/netguard-gui /usr/local/bin/netguard-gui
    chmod 755 /usr/local/bin/netguard-gui
fi

if [ -f bin/netguard-tui ]; then
    cp -f bin/netguard-tui /usr/local/bin/netguard-tui
    chmod 755 /usr/local/bin/netguard-tui
fi

echo -e "\n${COLOR_CYAN}[3/4] Loading Linux Kernel Module (netguard_mod.ko)...${COLOR_RESET}"
# Remove existing module if loaded
if lsmod | grep -q netguard_mod; then
    echo "Unloading previous netguard_mod instance..."
    rmmod netguard_mod || true
    sleep 1
fi

insmod kernel/netguard_mod.ko default_policy=1 log_level=2

echo -e "\n${COLOR_CYAN}[4/4] Verifying Kernel Netfilter Hooks and Diagnostics...${COLOR_RESET}"
if lsmod | grep -q netguard_mod; then
    echo -e "${COLOR_GREEN}✓ Kernel Module is ACTIVE (loaded in Linux kernel)${COLOR_RESET}"
else
    echo -e "${COLOR_RED}✗ Kernel Module failed to load${COLOR_RESET}"
    exit 1
fi

if [ -d "/proc/netguard" ]; then
    echo -e "${COLOR_GREEN}✓ /proc/netguard/ diagnostic filesystem initialized:${COLOR_RESET}"
    cat /proc/netguard/status
else
    echo -e "${COLOR_YELLOW}! Warning: /proc/netguard not present yet${COLOR_RESET}"
fi

echo -e "\n${COLOR_GREEN}============================================================${COLOR_RESET}"
echo -e "${COLOR_GREEN}✓ NETGUARD INSTALLATION SUCCESSFUL!${COLOR_RESET}"
echo -e "${COLOR_GREEN}============================================================${COLOR_RESET}"
echo -e "You can now run:"
echo -e "  sudo netguard           (Interactive CLI Administration Shell)"
echo -e "  sudo netguard list      (List filtering rules)"
echo -e "  sudo netguard stats     (Inspect packet metrics)"
echo -e "  netguard-gui            (Launch Technical NOC GUI Dashboard)"
echo -e "  sudo netguard-tui       (Launch Terminal NOC Dashboard)"
