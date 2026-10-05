#include "include/proc_diag.h"
#include "include/rule_engine.h"
#include "include/stats.h"
#include "include/log.h"
#include "include/netfilter_hooks.h"

static struct proc_dir_entry *proc_netguard_dir = NULL;

/* 1. Status Proc File */
static int proc_status_show(struct seq_file *m, void *v)
{
    struct netguard_stats st;
    netguard_stats_get(&st);

    seq_printf(m, "=== NetGuard Kernel Module Status ===\n");
    seq_printf(m, "Version:         %s\n", NETGUARD_VERSION_STRING);
    seq_printf(m, "Module State:    ACTIVE\n");
    seq_printf(m, "Netfilter Hooks: %s\n", st.hooks_active ? "REGISTERED (LOCAL_IN, LOCAL_OUT, FORWARD)" : "INACTIVE");
    seq_printf(m, "Default Policy:  %s\n", (st.default_policy == NETGUARD_POLICY_ACCEPT) ? "ACCEPT" : "DROP");
    seq_printf(m, "Log Level:       %u (%s)\n", st.log_level,
               (st.log_level == NETGUARD_LOG_ERROR) ? "ERROR" :
               (st.log_level == NETGUARD_LOG_WARN) ? "WARN" :
               (st.log_level == NETGUARD_LOG_INFO) ? "INFO" : "DEBUG");
    seq_printf(m, "Active Rules:    %u\n", st.active_rules_count);
    seq_printf(m, "Uptime:          %llu seconds (%02llu:%02llu:%02llu)\n",
               st.module_uptime_sec,
               st.module_uptime_sec / 3600,
               (st.module_uptime_sec % 3600) / 60,
               st.module_uptime_sec % 60);

    return 0;
}

static int proc_status_open(struct inode *inode, struct file *file)
{
    return single_open(file, proc_status_show, NULL);
}

static const struct proc_ops proc_status_ops = {
    .proc_open    = proc_status_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

/* 2. Stats Proc File */
static int proc_stats_show(struct seq_file *m, void *v)
{
    struct netguard_stats st;
    netguard_stats_get(&st);

    seq_printf(m, "=== NetGuard Network Traffic Statistics ===\n");
    seq_printf(m, "Total Packets:    %llu\n", st.total_packets);
    seq_printf(m, "Total Bytes:      %llu\n", st.total_bytes);
    seq_printf(m, "Accepted Packets: %llu\n", st.accepted_packets);
    seq_printf(m, "Accepted Bytes:   %llu\n", st.accepted_bytes);
    seq_printf(m, "Dropped Packets:  %llu\n", st.dropped_packets);
    seq_printf(m, "Dropped Bytes:    %llu\n", st.dropped_bytes);
    seq_printf(m, "Rejected Packets: %llu\n", st.rejected_packets);
    seq_printf(m, "Rejected Bytes:   %llu\n", st.rejected_bytes);
    seq_printf(m, "--------------------------------------------\n");
    seq_printf(m, "TCP Packets:      %llu (%llu bytes)\n", st.tcp_packets, st.tcp_bytes);
    seq_printf(m, "UDP Packets:      %llu (%llu bytes)\n", st.udp_packets, st.udp_bytes);
    seq_printf(m, "ICMP Packets:     %llu (%llu bytes)\n", st.icmp_packets, st.icmp_bytes);
    seq_printf(m, "Other Packets:    %llu (%llu bytes)\n", st.other_packets, st.other_bytes);
    seq_printf(m, "--------------------------------------------\n");
    seq_printf(m, "Inbound:          %llu (%llu bytes)\n", st.in_packets, st.in_bytes);
    seq_printf(m, "Outbound:         %llu (%llu bytes)\n", st.out_packets, st.out_bytes);
    seq_printf(m, "Forwarded:        %llu (%llu bytes)\n", st.fwd_packets, st.fwd_bytes);

    return 0;
}

static int proc_stats_open(struct inode *inode, struct file *file)
{
    return single_open(file, proc_stats_show, NULL);
}

static const struct proc_ops proc_stats_ops = {
    .proc_open    = proc_stats_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

/* 3. Rules Proc File */
static int proc_rules_show(struct seq_file *m, void *v)
{
    struct netguard_rule *rules;
    uint32_t count = 0, i;

    rules = kmalloc(sizeof(struct netguard_rule) * NETGUARD_MAX_RULES, GFP_KERNEL);
    if (!rules)
        return -ENOMEM;

    netguard_rule_dump(rules, NETGUARD_MAX_RULES, &count);

    seq_printf(m, "%-5s %-6s %-4s %-18s %-18s %-5s %-11s %-5s %-6s %-10s %-10s %s\n",
               "ID", "STATUS", "PRIO", "SOURCE", "DESTINATION", "PROTO", "PORTS", "DIR", "ACTION", "PACKETS", "BYTES", "DESCRIPTION");
    seq_printf(m, "------------------------------------------------------------------------------------------------------------------------\n");

    for (i = 0; i < count; i++) {
        char src_buf[32], dst_buf[32], port_buf[24];
        const struct netguard_rule *r = &rules[i];

        if (r->src_ip == 0 && r->src_mask == 0)
            snprintf(src_buf, sizeof(src_buf), "ANY");
        else
            snprintf(src_buf, sizeof(src_buf), "%pI4", &r->src_ip);

        if (r->dst_ip == 0 && r->dst_mask == 0)
            snprintf(dst_buf, sizeof(dst_buf), "ANY");
        else
            snprintf(dst_buf, sizeof(dst_buf), "%pI4", &r->dst_ip);

        if (r->dst_port_min == 0 && r->dst_port_max == 0)
            snprintf(port_buf, sizeof(port_buf), "ANY");
        else if (r->dst_port_max == 0 || r->dst_port_max == r->dst_port_min)
            snprintf(port_buf, sizeof(port_buf), "%u", r->dst_port_min);
        else
            snprintf(port_buf, sizeof(port_buf), "%u-%u", r->dst_port_min, r->dst_port_max);

        seq_printf(m, "%-5u %-6s %-4u %-18s %-18s %-5s %-11s %-5s %-6s %-10llu %-10llu %s\n",
                   r->id,
                   r->enabled ? "ENA" : "DIS",
                   r->priority,
                   src_buf,
                   dst_buf,
                   (r->protocol == NETGUARD_PROTO_TCP) ? "TCP" :
                   (r->protocol == NETGUARD_PROTO_UDP) ? "UDP" :
                   (r->protocol == NETGUARD_PROTO_ICMP) ? "ICMP" : "ANY",
                   port_buf,
                   (r->direction == NETGUARD_DIR_IN) ? "IN" :
                   (r->direction == NETGUARD_DIR_OUT) ? "OUT" :
                   (r->direction == NETGUARD_DIR_FWD) ? "FWD" : "ANY",
                   (r->action == NETGUARD_ACTION_ACCEPT) ? "ACCEPT" :
                   (r->action == NETGUARD_ACTION_DROP) ? "DROP" :
                   (r->action == NETGUARD_ACTION_REJECT) ? "REJECT" : "LOG",
                   r->packet_count,
                   r->byte_count,
                   r->description);
    }

    kfree(rules);
    return 0;
}

static int proc_rules_open(struct inode *inode, struct file *file)
{
    return single_open(file, proc_rules_show, NULL);
}

static const struct proc_ops proc_rules_ops = {
    .proc_open    = proc_rules_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

/* 4. Events Proc File */
static int proc_events_show(struct seq_file *m, void *v)
{
    struct netguard_packet_event *events;
    uint32_t count = 0, i;

    events = kmalloc(sizeof(struct netguard_packet_event) * NETGUARD_MAX_EVENTS, GFP_KERNEL);
    if (!events)
        return -ENOMEM;

    netguard_log_get_events(events, NETGUARD_MAX_EVENTS, &count);

    seq_printf(m, "%-10s %-20s %-20s %-5s %-6s %-6s %-6s %s\n",
               "TIME(s)", "SOURCE", "DESTINATION", "PROTO", "PORTS", "ACTION", "RULE", "IFACE");
    seq_printf(m, "----------------------------------------------------------------------------------------\n");

    for (i = 0; i < count; i++) {
        const struct netguard_packet_event *e = &events[i];
        char src_buf[24], dst_buf[24], port_buf[16];

        snprintf(src_buf, sizeof(src_buf), "%pI4", &e->src_ip);
        snprintf(dst_buf, sizeof(dst_buf), "%pI4", &e->dst_ip);
        snprintf(port_buf, sizeof(port_buf), "%u->%u", e->src_port, e->dst_port);

        seq_printf(m, "%-10llu %-20s %-20s %-5s %-6s %-6s %-6u %s\n",
                   e->timestamp_sec,
                   src_buf,
                   dst_buf,
                   (e->protocol == NETGUARD_PROTO_TCP) ? "TCP" :
                   (e->protocol == NETGUARD_PROTO_UDP) ? "UDP" :
                   (e->protocol == NETGUARD_PROTO_ICMP) ? "ICMP" : "OTHER",
                   port_buf,
                   (e->action == NETGUARD_ACTION_ACCEPT) ? "ACCEPT" :
                   (e->action == NETGUARD_ACTION_DROP) ? "DROP" :
                   (e->action == NETGUARD_ACTION_REJECT) ? "REJECT" : "LOG",
                   e->matched_rule_id,
                   e->iface_in[0] ? e->iface_in : (e->iface_out[0] ? e->iface_out : "local"));
    }

    kfree(events);
    return 0;
}

static int proc_events_open(struct inode *inode, struct file *file)
{
    return single_open(file, proc_events_show, NULL);
}

static const struct proc_ops proc_events_ops = {
    .proc_open    = proc_events_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

int netguard_proc_init(void)
{
    proc_netguard_dir = proc_mkdir("netguard", NULL);
    if (!proc_netguard_dir) {
        pr_err("netguard: Failed to create /proc/netguard directory\n");
        return -ENOMEM;
    }

    proc_create("status", 0444, proc_netguard_dir, &proc_status_ops);
    proc_create("stats", 0444, proc_netguard_dir, &proc_stats_ops);
    proc_create("rules", 0444, proc_netguard_dir, &proc_rules_ops);
    proc_create("events", 0444, proc_netguard_dir, &proc_events_ops);

    pr_info("netguard: /proc/netguard/ initialized\n");
    return 0;
}

void netguard_proc_cleanup(void)
{
    if (proc_netguard_dir) {
        remove_proc_subtree("netguard", NULL);
        proc_netguard_dir = NULL;
        pr_info("netguard: /proc/netguard/ removed\n");
    }
}
