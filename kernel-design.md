# NetGuard Kernel Design & Implementation Deep Dive

## 1. Netfilter Hook Points and Packet Traversal

NetGuard attaches callback hooks into the Linux kernel network stack using the native Netfilter framework (`nf_register_net_hooks`).

```
                    Network Interface (NIC)
                              |
                              v
                     [NF_INET_PRE_ROUTING]
                              |
                     Routing Decision
                       /             \
                      v               v
             [NF_INET_LOCAL_IN]   [NF_INET_FORWARD]
                      |                   |
               Local Sockets              v
                      |          [NF_INET_POST_ROUTING]
                      v                   |
             [NF_INET_LOCAL_OUT]          v
                      |             Network Cable
                      v
             [NF_INET_POST_ROUTING]
```

NetGuard registers hooks at:
1. **`NF_INET_LOCAL_IN`**: Evaluates all inbound packets destined for local processes on the host.
2. **`NF_INET_LOCAL_OUT`**: Evaluates all outbound packets generated locally before they leave the host.
3. **`NF_INET_FORWARD`**: Evaluates forwarded packets traversing the host acting as a router/gateway.

---

## 2. Safe Packet Inspection via `struct sk_buff`

Linux kernel packets are encapsulated in `struct sk_buff` (socket buffer). Direct memory access to non-linear buffers (`paged skbs`) can trigger kernel page faults. NetGuard uses `skb_header_pointer()` to ensure linear access:

```c
struct iphdr *iph = ip_hdr(skb);
struct tcphdr _tcph, *th = skb_header_pointer(skb, iph->ihl * 4, sizeof(_tcph), &_tcph);
if (th) {
    uint16_t src_port = ntohs(th->source);
    uint16_t dst_port = ntohs(th->dest);
    /* Inspect TCP flags safely */
}
```

---

## 3. RCU (Read-Copy-Update) Concurrency

Network packet inspection occurs in softirq / atomic context, where sleepable locks (mutexes, semaphores) are prohibited and spinlocks introduce CPU cache contention across cores.

NetGuard utilizes **RCU** for its rule list:
* **Readers (Packet Processing Path)**: Run lock-free under `rcu_read_lock()` and `rcu_read_unlock()`. Multiple CPU cores inspect rules simultaneously without waiting.
* **Writers (User-Space Management)**: Guarded by `rules_mutex`. Modifications update pointers using `list_add_tail_rcu()` or `list_del_rcu()`, followed by `synchronize_rcu()` before reclaiming memory via `kfree()`.

---

## 4. Atomic 64-bit Statistics Accounting

To prevent race conditions during high-throughput packet processing:
* Global metrics use `atomic64_t` counters (`atomic64_inc`, `atomic64_add`, `atomic64_read`).
* Per-rule metrics (`packet_count`, `byte_count`) use `atomic64_t` inside `struct netguard_rule_node`.
* Counter queries from user space are non-blocking and read atomic values directly.

---

## 5. Netlink Protocol Architecture

NetGuard registers a custom Netlink protocol family (`NETLINK_NETGUARD = 31`) with fallback to `NETLINK_USERSOCK (2)`:
* Kernel listener created via `netlink_kernel_create(&init_net, active_nl_proto, &cfg)`.
* Unicast responses dispatched via `nlmsg_unicast()`.
* Real-time packet event notifications broadcasted via `nlmsg_multicast()` to group `NETGUARD_NL_GROUP_EVENTS`.
