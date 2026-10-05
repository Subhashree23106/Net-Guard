# NetGuard System Architecture

## Overview

NetGuard is a high-performance, kernel-level network security and packet filtering agent designed specifically for Linux environments. It leverages native Linux kernel subsystems including **Netfilter hooks**, **Netlink sockets**, **RCU-synchronized rule linked lists**, and atomic traffic accounting to provide real-time, deterministic packet filtering with near-zero latency overhead.

---

## Architectural Diagram

```
 +-------------------------------------------------------------------------+
 |                               USER SPACE                                |
 |                                                                         |
 |  +--------------------------+             +--------------------------+  |
 |  |     C++ Graphical NOC    |             |      C++ CLI / TUI       |  |
 |  |    Dashboard (X11/Xft)   |             |   Administration Agent   |  |
 |  +-------------+------------+             +------------+-------------+  |
 |                |                                       |                |
 |                +-------------------+-------------------+                |
 |                                    |                                    |
 |                                    v                                    |
 |                        +-----------------------+                        |
 |                        |  NetlinkClient (C++)  |                        |
 |                        |  (AF_NETLINK / Prot31)|                        |
 |                        +-----------+-----------+                        |
 +------------------------------------|------------------------------------+
                                      | Netlink IPC Framing
 =====================================|=====================================
                                      | /proc/netguard/
 +------------------------------------|------------------------------------+
 |                                    v                                    |
 |                        +-----------------------+                        |
 |                        |  Netlink Socket Layer |                        |
 |                        |  (netlink_comm.c)     |                        |
 |                        +-----------+-----------+                        |
 |                                    |                                    |
 |          +-------------------------+-------------------------+          |
 |          |                         |                         |          |
 |          v                         v                         v          |
 |  +---------------+        +-----------------+        +---------------+  |
 |  |  Rule Engine  |        | Statistics Core |        |  Log / Events |  |
 |  | (RCU List)    |        | (atomic64_t)    |        | (Ring Buffer) |  |
 |  +-------+-------+        +--------+--------+        +-------+-------+  |
 |          |                         |                         |          |
 |          +--------------------+----+-------------------------+          |
 |                               |                                         |
 |                               v                                         |
 |                   +-----------------------+                             |
 |                   | Netfilter Hook Engine |                             |
 |                   | (LOCAL_IN, OUT, FWD)  |                             |
 |                   +-----------+-----------+                             |
 |                               |                                         |
 |                               v                                         |
 |                     Linux Networking Stack                              |
 |                   (sk_buff / IP / TCP / UDP)                            |
 |                                                                         |
 |                              KERNEL SPACE                               |
 +-------------------------------------------------------------------------+
```

---

## Component Descriptions

### 1. Kernel-Space Components

* **`netguard_main.c`**: Module lifecycle management, parameter registration, subsystem initialization and graceful teardown.
* **`netfilter_hooks.c`**: Registers hook operations with `nf_register_net_hooks` at `NF_INET_LOCAL_IN`, `NF_INET_LOCAL_OUT`, and `NF_INET_FORWARD`. Performs safe header extraction from `struct sk_buff`.
* **`rule_engine.c`**: Maintains an RCU-protected doubly-linked list of rules sorted by priority. Evaluates packets in atomic softirq context without taking sleepable locks.
* **`netlink_comm.c`**: Implements raw Netlink socket message handling (`NETLINK_NETGUARD` = 31), permission validation (`capable(CAP_NET_ADMIN)`), and async multicast event notification.
* **`stats.c`**: Implements 64-bit atomic counters (`atomic64_t`) for lockless traffic metric aggregation.
* **`proc_diag.c`**: Exposes `/proc/netguard/status`, `/proc/netguard/stats`, `/proc/netguard/rules`, and `/proc/netguard/events` for introspection.
* **`log.c`**: Circular ring buffer for packet events with rate-limited `pr_info_ratelimited` logging.

### 2. User-Space Components

* **`NetlinkClient`**: C++ class encapsulating raw AF_NETLINK socket communication with timeouts, serialization, and deserialization.
* **`RuleManager`**: High-level rule configuration, CIDR IP parsing, port range expansion, rule validation, and CSV export/import.
* **`Statistics`**: Traffic metrics tracking, throughput calculation (packets/sec, bytes/sec), and protocol percentage calculation.
* **`CLI`**: Command-line administrative utility with both non-interactive CLI arguments and interactive REPL shell.
* **`NetGuardGUI`**: Native Linux X11/Xft double-buffered graphical dashboard providing real-time monitoring and rule control.
* **`NetGuardTUI`**: NCurses-based terminal dashboard for console / SSH administration.
