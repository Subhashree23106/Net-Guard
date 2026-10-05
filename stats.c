#include "include/stats.h"
#include "include/rule_engine.h"
#include "include/netfilter_hooks.h"

static atomic64_t stat_total_packets;
static atomic64_t stat_total_bytes;
static atomic64_t stat_accepted_packets;
static atomic64_t stat_accepted_bytes;
static atomic64_t stat_dropped_packets;
static atomic64_t stat_dropped_bytes;
static atomic64_t stat_rejected_packets;
static atomic64_t stat_rejected_bytes;

static atomic64_t stat_tcp_packets;
static atomic64_t stat_tcp_bytes;
static atomic64_t stat_udp_packets;
static atomic64_t stat_udp_bytes;
static atomic64_t stat_icmp_packets;
static atomic64_t stat_icmp_bytes;
static atomic64_t stat_other_packets;
static atomic64_t stat_other_bytes;

static atomic64_t stat_in_packets;
static atomic64_t stat_in_bytes;
static atomic64_t stat_out_packets;
static atomic64_t stat_out_bytes;
static atomic64_t stat_fwd_packets;
static atomic64_t stat_fwd_bytes;

void netguard_stats_init(void)
{
    atomic64_set(&stat_total_packets, 0);
    atomic64_set(&stat_total_bytes, 0);
    atomic64_set(&stat_accepted_packets, 0);
    atomic64_set(&stat_accepted_bytes, 0);
    atomic64_set(&stat_dropped_packets, 0);
    atomic64_set(&stat_dropped_bytes, 0);
    atomic64_set(&stat_rejected_packets, 0);
    atomic64_set(&stat_rejected_bytes, 0);

    atomic64_set(&stat_tcp_packets, 0);
    atomic64_set(&stat_tcp_bytes, 0);
    atomic64_set(&stat_udp_packets, 0);
    atomic64_set(&stat_udp_bytes, 0);
    atomic64_set(&stat_icmp_packets, 0);
    atomic64_set(&stat_icmp_bytes, 0);
    atomic64_set(&stat_other_packets, 0);
    atomic64_set(&stat_other_bytes, 0);

    atomic64_set(&stat_in_packets, 0);
    atomic64_set(&stat_in_bytes, 0);
    atomic64_set(&stat_out_packets, 0);
    atomic64_set(&stat_out_bytes, 0);
    atomic64_set(&stat_fwd_packets, 0);
    atomic64_set(&stat_fwd_bytes, 0);
}

void netguard_stats_reset(void)
{
    netguard_stats_init();
}

void netguard_stats_inc_packet(uint8_t proto, uint8_t direction, uint8_t action, uint32_t len)
{
    atomic64_inc(&stat_total_packets);
    atomic64_add(len, &stat_total_bytes);

    if (action == NETGUARD_ACTION_ACCEPT) {
        atomic64_inc(&stat_accepted_packets);
        atomic64_add(len, &stat_accepted_bytes);
    } else if (action == NETGUARD_ACTION_DROP) {
        atomic64_inc(&stat_dropped_packets);
        atomic64_add(len, &stat_dropped_bytes);
    } else if (action == NETGUARD_ACTION_REJECT) {
        atomic64_inc(&stat_rejected_packets);
        atomic64_add(len, &stat_rejected_bytes);
    }

    switch (proto) {
    case NETGUARD_PROTO_TCP:
        atomic64_inc(&stat_tcp_packets);
        atomic64_add(len, &stat_tcp_bytes);
        break;
    case NETGUARD_PROTO_UDP:
        atomic64_inc(&stat_udp_packets);
        atomic64_add(len, &stat_udp_bytes);
        break;
    case NETGUARD_PROTO_ICMP:
        atomic64_inc(&stat_icmp_packets);
        atomic64_add(len, &stat_icmp_bytes);
        break;
    default:
        atomic64_inc(&stat_other_packets);
        atomic64_add(len, &stat_other_bytes);
        break;
    }

    if (direction & NETGUARD_DIR_IN) {
        atomic64_inc(&stat_in_packets);
        atomic64_add(len, &stat_in_bytes);
    } else if (direction & NETGUARD_DIR_OUT) {
        atomic64_inc(&stat_out_packets);
        atomic64_add(len, &stat_out_bytes);
    } else if (direction & NETGUARD_DIR_FWD) {
        atomic64_inc(&stat_fwd_packets);
        atomic64_add(len, &stat_fwd_bytes);
    }
}

void netguard_stats_get(struct netguard_stats *out_stats)
{
    struct timespec64 ts;
    if (!out_stats)
        return;

    memset(out_stats, 0, sizeof(*out_stats));

    out_stats->total_packets    = atomic64_read(&stat_total_packets);
    out_stats->total_bytes      = atomic64_read(&stat_total_bytes);
    out_stats->accepted_packets = atomic64_read(&stat_accepted_packets);
    out_stats->accepted_bytes   = atomic64_read(&stat_accepted_bytes);
    out_stats->dropped_packets  = atomic64_read(&stat_dropped_packets);
    out_stats->dropped_bytes    = atomic64_read(&stat_dropped_bytes);
    out_stats->rejected_packets = atomic64_read(&stat_rejected_packets);
    out_stats->rejected_bytes   = atomic64_read(&stat_rejected_bytes);

    out_stats->tcp_packets      = atomic64_read(&stat_tcp_packets);
    out_stats->tcp_bytes        = atomic64_read(&stat_tcp_bytes);
    out_stats->udp_packets      = atomic64_read(&stat_udp_packets);
    out_stats->udp_bytes        = atomic64_read(&stat_udp_bytes);
    out_stats->icmp_packets     = atomic64_read(&stat_icmp_packets);
    out_stats->icmp_bytes       = atomic64_read(&stat_icmp_bytes);
    out_stats->other_packets    = atomic64_read(&stat_other_packets);
    out_stats->other_bytes      = atomic64_read(&stat_other_bytes);

    out_stats->in_packets       = atomic64_read(&stat_in_packets);
    out_stats->in_bytes         = atomic64_read(&stat_in_bytes);
    out_stats->out_packets      = atomic64_read(&stat_out_packets);
    out_stats->out_bytes        = atomic64_read(&stat_out_bytes);
    out_stats->fwd_packets      = atomic64_read(&stat_fwd_packets);
    out_stats->fwd_bytes        = atomic64_read(&stat_fwd_bytes);

    out_stats->active_rules_count = netguard_rule_count();
    out_stats->default_policy     = netguard_default_policy;
    out_stats->logging_enabled    = 1;
    out_stats->log_level          = netguard_log_level;
    out_stats->hooks_active       = netguard_get_hooks_active();

    ktime_get_real_ts64(&ts);
    if ((uint64_t)ts.tv_sec >= netguard_load_time_sec)
        out_stats->module_uptime_sec = (uint64_t)ts.tv_sec - netguard_load_time_sec;
    else
        out_stats->module_uptime_sec = 0;
}
