# NetGuard Installation & Setup Guide

## System Requirements

* **Operating System**: Linux (Ubuntu 22.04 LTS, 24.04 LTS, 26.04 LTS, Debian 11+, Fedora 38+, Arch Linux)
* **Kernel Version**: Linux Kernel 5.4+ up to 7.0+ (Tested on Linux 7.0.0-27-generic x86_64)
* **Compilers**: GCC 9+ (C11), G++ 9+ (C++17)
* **Required Packages**:
  ```bash
  sudo apt-get update
  sudo apt-get install -y build-essential linux-headers-$(uname -r) libx11-dev libxft-dev libfreetype6-dev libncurses-dev pkg-config
  ```

---

## Build Steps

Clone or navigate to the project directory:

```bash
cd /home/adyasha/Documents/Wipro
```

Build all components using the master Makefile:

```bash
make all
```

Or build components individually:

```bash
make kernel   # Compiles kernel/netguard_mod.ko
make agent    # Compiles bin/netguard (CLI)
make gui      # Compiles bin/netguard-gui (X11 NOC Dashboard)
make tui      # Compiles bin/netguard-tui (NCurses Terminal Dashboard)
make tests    # Compiles bin/netguard-tests
```

---

## Loading & Installing the Kernel Module

To install binaries to `/usr/local/bin` and load the kernel module:

```bash
sudo ./scripts/install.sh
```

Or manually:

```bash
sudo insmod kernel/netguard_mod.ko default_policy=1 log_level=2
```

Verify the module is loaded:

```bash
lsmod | grep netguard_mod
cat /proc/netguard/status
```

---

## Uninstallation

To cleanly unload the module and remove binaries:

```bash
sudo ./scripts/uninstall.sh
```
