# Kernel-Space Network Packet Filter & Rule Enforcement Agent (NetGuard)

[![Linux](https://img.shields.io/badge/Platform-Linux-orange.svg)](https://kernel.org)
[![Kernel](https://img.shields.io/badge/Kernel-5.4--7.0+-blue.svg)](https://kernel.org)
[![Languages](https://img.shields.io/badge/Languages-C%20%7C%20C%2B%2B17-blue.svg)](https://isocpp.org)
[![Netfilter](https://img.shields.io/badge/Framework-Netfilter%20Hooks-green.svg)](https://netfilter.org)
[![IPC](https://img.shields.io/badge/IPC-AF__NETLINK-red.svg)](https://man7.org/linux/man-pages/man7/netlink.7.html)

A production-quality Linux capstone project implementing a real **Kernel-Space Network Packet Filter & Policy Enforcement Agent** written exclusively in **C and C++**.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Problem Statement](#2-problem-statement)
3. [Objectives](#3-objectives)
4. [Technologies Used](#4-technologies-used)
5. [Why Kernel Space?](#5-why-kernel-space)
6. [Why Netfilter?](#6-why-netfilter)
7. [System Architecture](#7-system-architecture)
8. [Kernel Module Design](#8-kernel-module-design)
9. [User-Space Architecture](#9-user-space-architecture)
10. [Netlink Communication Protocol](#10-netlink-communication-protocol)
11. [Rule Engine & Evaluation Logic](#11-rule-engine--evaluation-logic)
12. [Packet Processing Flow Diagram](#12-packet-processing-flow-diagram)
13. [Security Considerations & Safe Kernel Practices](#13-security-considerations--safe-kernel-practices)
14. [Build Instructions](#14-build-instructions)
15. [Installation & Module Loading](#15-installation--module-loading)
16. [User-Space CLI & Administration Agent](#16-user-space-cli--administration-agent)
17. [Technical NOC Graphical Dashboard (GUI)](#17-technical-noc-graphical-dashboard-gui)
18. [Terminal NOC Dashboard (TUI)](#18-terminal-noc-dashboard-tui)
19. [Testing & Network Verification](#19-testing--network-verification)
20. [Demonstration Scenario](#20-demonstration-scenario)
21. [Viva & Technical Interview Q&A](#21-viva--technical-interview-qa)
22. [Limitations, Compatibility & Conclusion](#22-limitations-compatibility--conclusion)

---

## 1. Project Overview

**NetGuard** is an end-to-end network security enforcement agent designed to operate natively within the Linux kernel networking layer. The system combines a high-performance **Linux Kernel Module (`netguard_mod.ko`)** hooked into the kernel's **Netfilter** pipeline with a modern **C++ User-Space Agent (`netguard`)** and a **Cybersecurity NOC Dashboard (`netguard-gui` / `netguard-tui`)**.

Unlike user-space packet capturing proxies (like `libpcap` or userspace firewalls) which suffer from context-switching overhead and cannot stop malicious packets before they reach internal sockets, NetGuard performs **in-situ packet inspection and deterministic dropping directly at the kernel hook points**.

---

## 2. Problem Statement

Modern high-bandwidth network infrastructures face persistent security threats such as port scanning, unauthorized remote access attempts, distributed denial-of-service (DDoS) vectors, and rogue traffic. 

Purely user-space packet filtering applications face severe architectural drawbacks:
1. **Context Switch Overhead**: For every packet, the kernel must transition from kernel space to user space, incurring costly CPU context switches and cache invalidations.
2. **Buffer Memory Copies**: Packet payloads must be copied across the user/kernel memory boundary via system calls, throttling throughput.
3. **Late Enforcement**: User-space filters often receive packets *after* the kernel networking stack has already processed IP/TCP headers and allocated socket buffers (`sk_buff`), consuming kernel resources.

---

## 3. Objectives

* **Kernel-Level Packet Inspection**: Inspect IP headers, TCP/UDP transport headers, ICMP codes, packet lengths, and network interfaces in real time.
* **Deterministic Policy Enforcement**: Enforce `ACCEPT`, `DROP`, `REJECT`, and `LOG` actions on incoming, outgoing, and forwarded packets.
* **Dynamic Rule Management**: Allow administrators to dynamically inject, update, delete, enable, and disable filtering rules via IPC without unloading the module.
* **Lock-Free Concurrency**: Utilize Linux kernel **RCU (Read-Copy-Update)** for the packet processing fast path and atomic 64-bit counters for lockless metrics aggregation.
* **Native Netlink IPC**: Implement real bidirectional user <-> kernel communication using raw Netlink sockets (`NETLINK_NETGUARD` / `AF_NETLINK`).
* **Multi-Interface Technical UI**: Provide a dark cybersecurity NOC Graphical Dashboard (C++ / X11 / Xft) and Terminal Dashboard (C++ / NCurses) with live throughput charts, protocol distributions, and packet stream tables.

---

## 4. Technologies Used

* **Programming Languages**: 100% **C** (Kernel Module) and **C++17** (User-Space Agent, CLI, GUI, TUI, Test Suite).
* **Linux Kernel Subsystems**: Netfilter Hooks (`NF_INET_LOCAL_IN`, `NF_INET_LOCAL_OUT`, `NF_INET_FORWARD`), `struct sk_buff`, RCU (`rcupdate.h`), Mutexes (`mutex.h`), Spinlocks (`spinlock.h`), Atomic64 (`atomic.h`), Seq_File ProcFS (`proc_fs.h`).
* **Kernel/User-Space IPC**: Linux Netlink Sockets (`AF_NETLINK`, `netlink_kernel_create`, `nlmsg_unicast`, `nlmsg_multicast`).
* **Graphical UI**: Native Linux X11 (`libX11`), Xft anti-aliased font engine (`libXft`), FreeType 2 (`libfreetype`).
* **Terminal UI**: Linux NCurses (`libncurses`).
* **Build System**: GNU Make, CMake 3.16+, GCC / G++ 9+.

---

## 5. Why Kernel Space?

Operating in kernel space provides fundamental security and performance advantages:
1. **Early Packet Discard**: Packets matching a `DROP` rule are discarded before socket buffers, TCP connection states, or socket queues are instantiated.
2. **Zero-Copy Performance**: Packet inspection operates directly on the kernel's native `struct sk_buff` pointers without copying data to user space.
3. **Protection from Tampering**: The filtering engine runs in Ring 0 (kernel privilege), preventing unprivileged user-space processes from bypassing or tampering with policies.

---

## 6. Why Netfilter?

**Netfilter** is the canonical, battle-tested packet filtering and manipulation framework built into the Linux kernel since Linux 2.4. It defines well-established hook points across the kernel's protocol stack:
* `NF_INET_PRE_ROUTING`: Before routing decisions.
* `NF_INET_LOCAL_IN`: Inbound packets destined for the local host.
* `NF_INET_FORWARD`: Packets traversing the host to another destination.
* `NF_INET_LOCAL_OUT`: Outbound packets generated by local processes.
* `NF_INET_POST_ROUTING`: Right before transmitting packets over the physical wire.

NetGuard hooks into `NF_INET_LOCAL_IN`, `NF_INET_LOCAL_OUT`, and `NF_INET_FORWARD`, inspecting and filtering all IPv4 traffic with surgical precision.

---

## 7. System Architecture

```
                     ┌────────────────────────────────┐
                     │    C++ Graphical Dashboard     │
                     │  (X11/Xft / Dark NOC Styling)  │
                     └───────────────┬────────────────┘
                                     │
                                     │ User Action / Netlink
                                     ▼
                     ┌────────────────────────────────┐
                     │      C++ User-Space Agent      │
                     │  (CLI / RuleManager / Stats)   │
                     └───────────────┬────────────────┘
                                     │
                                     │ AF_NETLINK (Family 31)
                                     ▼
 =========================================================================
                               KERNEL SPACE
 =========================================================================
                                     │
                     ┌───────────────▼────────────────┐
                     │      Netlink Handler Core      │
                     │  (Message Dispatch / Security) │
                     └───────┬───────────────┬────────┘
                             │               │
            ┌────────────────┴─────┐   ┌─────┴────────────────┐
            │   RCU Rule Engine    │   │  Atomic Statistics   │
            │ (Priority Match List)│   │  (64-bit Counters)   │
            └──────────────┬───────┘   └─────┬────────────────┘
                           │                 │
                           └────────┬────────┘
                                    │
                                    ▼
                     ┌────────────────────────────────┐
                     │     Netfilter Hook Callbacks   │
                     │ (LOCAL_IN, LOCAL_OUT, FORWARD) │
                     └──────────────┬─────────────────┘
                                    │
                                    ▼
                          Linux Network Stack
                        (struct sk_buff / IPv4)
```

---

## 8. Kernel Module Design

The kernel module source resides in `kernel/`:

| File | Purpose |
|---|---|
| `netguard_main.c` | Module init (`module_init`), exit (`module_exit`), parameters, lifecycle. |
| `netfilter_hooks.c` | `nf_hook_ops` registration and packet parsing from `struct sk_buff`. |
| `rule_engine.c` | RCU-protected doubly linked list for rules, priority evaluation, and IP/port matching. |
| `netlink_comm.c` | Netlink socket server, message routing, permission validation, response framing. |
| `stats.c` | Lock-free traffic accounting via `atomic64_t`. |
| `proc_diag.c` | `/proc/netguard/` diagnostic filesystem (`status`, `stats`, `rules`, `events`). |
| `log.c` | Kernel event ring buffer and rate-limited logging (`pr_info_ratelimited`). |

---

## 9. User-Space Architecture

The user-space agent and UI components reside in `agent/` and `ui/`:

* **`NetlinkClient`**: C++ interface communicating with the kernel module over `AF_NETLINK`.
* **`RuleManager`**: High-level rule management, CIDR mask conversions, port range calculation, rule validation, and configuration file export/import.
* **`Statistics`**: Metric tracking, live throughput calculation (packets/sec, bytes/sec), and protocol percentage calculation.
* **`CLI`**: Interactive REPL shell (`netguard>`) and direct CLI argument parser.
* **`NetGuardGUI`**: Double-buffered native Linux X11/Xft graphical NOC dashboard.
* **`NetGuardTUI`**: NCurses-based terminal dashboard.

---

## 10. Netlink Communication Protocol

Communication between user-space and kernel-space utilizes structured Netlink messages defined in `common/netguard_uapi.h`:

```c
struct netguard_nl_hdr {
    uint16_t msg_type;      /* e.g., NETGUARD_NL_MSG_ADD_RULE */
    uint16_t msg_flags;     /* Flags */
    int32_t  status;        /* Return status (NETGUARD_OK or error code) */
    uint32_t payload_len;   /* Length of trailing payload */
    uint32_t seq;           /* Sequence number */
};
```

### Supported Message Commands:
* `NETGUARD_NL_MSG_ADD_RULE`: Injects a new rule into the kernel.
* `NETGUARD_NL_MSG_DEL_RULE`: Deletes a rule by ID.
* `NETGUARD_NL_MSG_UPDATE_RULE`: Updates an existing rule.
* `NETGUARD_NL_MSG_ENABLE_RULE`: Enables a rule by ID.
* `NETGUARD_NL_MSG_DISABLE_RULE`: Disables a rule by ID.
* `NETGUARD_NL_MSG_GET_RULES`: Dumps all active kernel rules.
* `NETGUARD_NL_MSG_CLEAR_RULES`: Flushes all rules.
* `NETGUARD_NL_MSG_GET_STATS`: Retrieves 64-bit atomic statistics.
* `NETGUARD_NL_MSG_RESET_STATS`: Resets counters.
* `NETGUARD_NL_MSG_SET_POLICY`: Changes default action (`ACCEPT` / `DROP`).
* `NETGUARD_NL_MSG_GET_EVENTS`: Reads recent packet events from the ring buffer.
* `NETGUARD_NL_MSG_PING`: Health check probe.

---

## 11. Rule Engine & Evaluation Logic

Each filtering rule contains:

```c
struct netguard_rule {
    uint32_t id;                /* Unique Rule ID */
    uint32_t priority;          /* 1..1000 (lower number = higher priority) */
    uint8_t  enabled;           /* 1=Active, 0=Disabled */
    uint8_t  direction;         /* IN, OUT, FWD, ANY */
    uint8_t  protocol;          /* TCP, UDP, ICMP, ANY */
    uint8_t  action;            /* ACCEPT, DROP, REJECT, LOG */
    
    uint32_t src_ip;            /* IPv4 network byte order */
    uint32_t src_mask;          /* IPv4 subnet mask */
    uint32_t dst_ip;            /* IPv4 network byte order */
    uint32_t dst_mask;          /* IPv4 subnet mask */
    
    uint16_t src_port_min;      /* Port range start (0 = ANY) */
    uint16_t src_port_max;      /* Port range end */
    uint16_t dst_port_min;      /* Port range start (0 = ANY) */
    uint16_t dst_port_max;      /* Port range end */
    
    uint64_t packet_count;      /* Matched packet count */
    uint64_t byte_count;        /* Matched byte count */
    char     description[64];   /* Human-readable note */
};
```

### Matching Algorithm:
1. Traverse rules in **priority order** (lowest priority number evaluated first).
2. Skip rules where `enabled == 0`.
3. Check packet direction against `rule->direction`.
4. Check IP protocol against `rule->protocol`.
5. Check source IP: `(packet_src_ip & rule->src_mask) == (rule->src_ip & rule->src_mask)`.
6. Check destination IP: `(packet_dst_ip & rule->dst_mask) == (rule->dst_ip & rule->dst_mask)`.
7. Check transport ports for TCP/UDP: `packet_port >= min_port && packet_port <= max_port`.
8. Upon match:
   * Increment `node->packet_count` and `node->byte_count` atomically.
   * Return `rule->action` (`NF_ACCEPT` or `NF_DROP`).
9. If no rule matches: Return configured `netguard_default_policy` (default: `ACCEPT`).

---

## 12. Packet Processing Flow Diagram

```
 Packet Arrives at NIC
          │
          ▼
 Netfilter Hook Point (e.g., LOCAL_IN)
          │
          ▼
 Is Packet IPv4? (skb->protocol == ETH_P_IP)
       ├── No  ──► Return NF_ACCEPT
       │
      Yes
       │
       ▼
 Extract IP Header (iph = ip_hdr(skb))
 Extract Protocol (TCP / UDP / ICMP)
 Extract Ports & Flags via skb_header_pointer()
          │
          ▼
 Enter RCU Read Lock (rcu_read_lock())
          │
          ▼
 Iterate Priority-Sorted Rule List:
   ├── Match Direction?
   ├── Match Protocol?
   ├── Match Source IP/CIDR?
   ├── Match Dest IP/CIDR?
   └── Match Port Range?
          │
    ┌─────┴──────────────────┐
    │                        │
  Match                    No Match
    │                        │
    ▼                        ▼
 Increment Rule Stats   Apply Default Policy
 Set out_rule_id        (ACCEPT or DROP)
    │                        │
    └──────────┬─────────────┘
               │
               ▼
 Exit RCU Read Lock (rcu_read_unlock())
               │
               ▼
 Update Global Atomic Counters (atomic64_add)
 Log Event to Ring Buffer & Netlink Multicast
               │
               ▼
 Action == DROP ?
   ├── Yes ──► Return NF_DROP (Packet Destroyed)
   └── No  ──► Return NF_ACCEPT (Packet Traverses Stack)
```

---

## 13. Security Considerations & Safe Kernel Practices

1. **Boundary Validation**: All inputs from user space are rigorously validated inside `netlink_comm.c` before passing to the rule engine.
2. **Safe Memory Access**: Network headers are accessed using `skb_header_pointer()` to prevent out-of-bounds pointer arithmetic on paged buffers.
3. **Lock-Free Fast Path**: RCU eliminates deadlocks and spinlock contention on multi-core processors in softirq context.
4. **Log Rate Limiting**: `pr_info_ratelimited()` prevents kernel log ring buffer exhaustion under heavy traffic loads.
5. **Clean Unloading**: `synchronize_rcu()` guarantees all readers have exited before memory is reclaimed during module unload.

---

## 14. Build Instructions

### Prerequisites
Install the standard Linux development headers and libraries:
```bash
sudo apt-get update
sudo apt-get install -y build-essential linux-headers-$(uname -r) libx11-dev libxft-dev libfreetype6-dev libncurses-dev pkg-config
```

### Building the Entire Project
```bash
make all
```

This generates:
* `kernel/netguard_mod.ko` - Linux Kernel Module
* `bin/netguard` - C++ CLI Administration Agent
* `bin/netguard-gui` - C++ Graphical NOC Dashboard
* `bin/netguard-tui` - C++ Terminal NOC Dashboard
* `bin/netguard-tests` - C++ Unit Test Suite

---

## 15. Installation & Module Loading

To automatically install binaries and load the kernel module:
```bash
sudo ./scripts/install.sh
```

### Verifying Installation:
```bash
lsmod | grep netguard_mod
cat /proc/netguard/status
```

Expected output:
```text
=== NetGuard Kernel Module Status ===
Version:         1.0.0
Module State:    ACTIVE
Netfilter Hooks: REGISTERED (LOCAL_IN, LOCAL_OUT, FORWARD)
Default Policy:  ACCEPT
Log Level:       2 (INFO)
Active Rules:    0
Uptime:          12 seconds (00:00:12)
```

---

## 16. User-Space CLI & Administration Agent

### Interactive Console Shell
Start the interactive management shell:
```bash
sudo netguard
```

```text
============================================================
  NetGuard: Kernel Packet Filter Administration Console     
============================================================
Type 'help' for commands, 'status' for health, 'exit' to quit.

netguard> status
netguard> add-rule
netguard> list-rules
netguard> stats
netguard> monitor
netguard> exit
```

### Direct CLI Commands:
```bash
# 1. Block inbound SSH (Port 22) from all IPs
sudo netguard add --id 101 --prio 10 --proto tcp --dport 22 --action drop --dir in --desc "Block SSH"

# 2. Block all traffic from subnet 10.0.0.0/24
sudo netguard add --id 102 --prio 20 --src 10.0.0.0/24 --action drop --desc "Block Rogue Subnet"

# 3. Block UDP DNS (Port 53)
sudo netguard add --id 103 --prio 30 --proto udp --dport 53 --action drop --desc "Block DNS"

# 4. List all active rules
sudo netguard list

# 5. Disable / Enable a rule
sudo netguard disable 101
sudo netguard enable 101

# 6. Delete a rule
sudo netguard delete 101

# 7. View live statistics
sudo netguard stats
sudo netguard stats --watch

# 8. Real-time live packet streaming
sudo netguard monitor

# 9. Clear all rules
sudo netguard clear
```

---

## 17. Technical NOC Graphical Dashboard (GUI)

Launch the native Linux X11/Xft graphical dashboard:
```bash
./bin/netguard-gui
```

### Dashboard Features:
* **Dark Cybersecurity NOC Theme**: High-contrast obsidian background with neon cyan, emerald green, and crimson indicators.
* **Double-Buffered Rendering**: Smooth 60 FPS animation with zero flicker.
* **System Status Card**: Real-time health indicators for Kernel Module, Netfilter Hooks, Netlink Socket, and Uptime.
* **Traffic Overview Card**: Real-time counters for Total Inspected, Accepted, Dropped, Rejected, Throughput (PPS & KB/s).
* **Protocol Statistics Card**: Animated horizontal progress bars for TCP, UDP, ICMP, and other protocols.
* **Real-Time Throughput Line Graph**: 60-second scrolling sparkline chart tracking network activity.
* **Rule Management Tab**: Interactive table with rule selection, toggle, delete, and policy buttons.
* **Interactive Modal Dialog**: Comprehensive rule injection dialog with validation for IP, CIDR, Port ranges, Protocol, Action, and Priority.
* **Quick Defense Shield**: One-click instant mitigation buttons for SSH (22), HTTP (80), DNS (53), HTTPS (443), and Telnet (23).

---

## 18. Terminal NOC Dashboard (TUI)

For headless servers or remote SSH sessions:
```bash
sudo ./bin/netguard-tui
```

Provides a live, auto-refreshing console dashboard featuring system status cards, traffic volumes, protocol breakdown gauges, active rules table, and real-time Netfilter event logs.

---

## 19. Testing & Network Verification

### Running the C++ Unit Test Suite
```bash
make test
```

### Live Network Verification Commands

| Goal | Command | Expected Result |
|---|---|---|
| Block SSH | `sudo netguard add --id 101 --proto tcp --dport 22 --action drop` | Rule #101 created |
| Test SSH Drop | `nc -zv -w 2 127.0.0.1 22` | Connection timed out / Dropped |
| Verify Counters | `sudo netguard stats` | Dropped Packets incremented |
| Block Web HTTP | `sudo netguard add --id 102 --proto tcp --dport 80 --action drop` | Rule #102 created |
| Test Web Drop | `curl -m 2 http://example.com` | `curl: (28) Connection timed out` |
| Block ICMP Ping | `sudo netguard add --id 103 --proto icmp --action drop` | Rule #103 created |
| Test Ping Drop | `ping -c 2 -W 1 127.0.0.1` | 100% packet loss |
| Restore Ping | `sudo netguard disable 103` | Ping succeeds (0% loss) |

---

## 20. Demonstration Scenario

An automated demonstration script is provided for presentations and viva exams:
```bash
sudo ./scripts/demo.sh
```

### Demonstration Steps:
1. **System Health Check**: Verifies kernel module load and Netfilter hook status.
2. **Initial State**: Shows zero rules and initial counters.
3. **Policy Deployment**: Injects `DROP TCP destination port 22`.
4. **Network Verification**: Executes `nc` / `curl` and demonstrates immediate kernel packet drop.
5. **Telemetry Verification**: Displays incremented drop counter and live event ring buffer.
6. **Policy Modification**: Disables Rule #101 and verifies that traffic is immediately restored.
7. **Cleanup**: Removes test rules and leaves the system clean.

---

## 21. Viva & Technical Interview Q&A

**Q1: What is the difference between NetGuard and iptables/nftables?**  
*A:* While `iptables` and `nftables` are general-purpose user-space tools managing the kernel's xtables subsystem, NetGuard is a custom-engineered kernel agent with its own dedicated Netfilter hook handlers, custom RCU rule engine, specialized Netlink IPC protocol, and integrated C++ NOC dashboard designed specifically for high-speed policy enforcement.

**Q2: Why is RCU (Read-Copy-Update) essential in the kernel packet path?**  
*A:* Packet inspection occurs in softirq / atomic context on multiple CPU cores simultaneously. Traditional mutexes cannot be used in atomic context, and spinlocks cause severe CPU cache line bouncing and lock contention. RCU allows lock-free read access for millions of packets per second while safely handling rule additions and deletions.

**Q3: How does NetGuard safely handle non-linear socket buffers (`sk_buff`)?**  
*A:* NetGuard uses `skb_header_pointer()` instead of direct pointer arithmetic. If a packet header is split across non-contiguous memory pages (paged buffers), `skb_header_pointer()` safely copies the requested header bytes into a stack-allocated buffer without causing kernel page faults.

**Q4: How does NetGuard communicate between user space and kernel space?**  
*A:* NetGuard implements a raw Netlink socket interface (`AF_NETLINK`) using a custom protocol family (`NETLINK_NETGUARD = 31`). Netlink provides asynchronous, message-based IPC without the overhead of system call polling or file locking.

---

## 22. Limitations, Compatibility & Conclusion

### Compatibility Notes:
* **Tested Kernel**: Linux 7.0.0-27-generic (Ubuntu 26.04 LTS x86_64).
* **Supported Kernels**: Linux 5.4+ through 7.x+.
* **Networking Protocol**: IPv4 (TCP, UDP, ICMP, and raw protocols).

### Future Enhancements:
* Support for IPv6 (`NFPROTO_IPV6`) packet inspection.
* Stateful connection tracking (TCP conntrack table / SYN-ACK state inspection).
* eBPF / XDP (eXpress Data Path) kernel bypass acceleration.

### Conclusion
NetGuard demonstrates the full power of native Linux kernel networking. By coupling Netfilter hooks with lock-free RCU synchronization, atomic metrics, raw Netlink IPC, and a responsive C++ NOC dashboard, NetGuard delivers an enterprise-grade network security solution.
