#include "include/log.h"
#include "include/netlink_comm.h"

#define NETGUARD_EVENT_RING_SIZE 256

static struct netguard_packet_event event_ring[NETGUARD_EVENT_RING_SIZE];
static uint32_t ring_head = 0;
static uint32_t ring_count = 0;
static spinlock_t ring_lock;

void netguard_log_init(void)
{
    spin_lock_init(&ring_lock);
    ring_head = 0;
    ring_count = 0;
    memset(event_ring, 0, sizeof(event_ring));
}

void netguard_log_cleanup(void)
{
    /* No dynamic allocations in static ring buffer */
}

void netguard_log_event(const struct netguard_packet_event *event)
{
    unsigned long flags;
    uint32_t idx;

    if (!event)
        return;

    spin_lock_irqsave(&ring_lock, flags);
    idx = (ring_head + ring_count) % NETGUARD_EVENT_RING_SIZE;
    if (ring_count < NETGUARD_EVENT_RING_SIZE) {
        ring_count++;
    } else {
        /* Overwrite oldest entry */
        ring_head = (ring_head + 1) % NETGUARD_EVENT_RING_SIZE;
    }
    memcpy(&event_ring[idx], event, sizeof(*event));
    spin_unlock_irqrestore(&ring_lock, flags);

    /* Rate-limited dmesg output */
    if (netguard_log_level >= NETGUARD_LOG_INFO) {
        const char *proto_str = (event->protocol == NETGUARD_PROTO_TCP) ? "TCP" :
                                (event->protocol == NETGUARD_PROTO_UDP) ? "UDP" :
                                (event->protocol == NETGUARD_PROTO_ICMP) ? "ICMP" : "OTHER";
        const char *act_str   = (event->action == NETGUARD_ACTION_ACCEPT) ? "ACCEPT" :
                                (event->action == NETGUARD_ACTION_DROP) ? "DROP" :
                                (event->action == NETGUARD_ACTION_REJECT) ? "REJECT" : "LOG";

        if (event->action == NETGUARD_ACTION_DROP || event->action == NETGUARD_ACTION_REJECT || netguard_log_level >= NETGUARD_LOG_DEBUG) {
            pr_info_ratelimited("netguard: [%s] %s %pI4:%u -> %pI4:%u len=%u rule=%u\n",
                                act_str, proto_str,
                                &event->src_ip, event->src_port,
                                &event->dst_ip, event->dst_port,
                                event->packet_len, event->matched_rule_id);
        }
    }

    /* Broadcast live event to Netlink multicast group */
    netguard_netlink_broadcast_event(event);
}

int netguard_log_get_events(struct netguard_packet_event *buf, uint32_t max_count, uint32_t *out_count)
{
    unsigned long flags;
    uint32_t i, count;

    if (!buf || !out_count || max_count == 0)
        return -EINVAL;

    spin_lock_irqsave(&ring_lock, flags);
    count = ring_count;
    if (count > max_count)
        count = max_count;

    for (i = 0; i < count; i++) {
        uint32_t idx = (ring_head + ring_count - count + i) % NETGUARD_EVENT_RING_SIZE;
        memcpy(&buf[i], &event_ring[idx], sizeof(struct netguard_packet_event));
    }
    *out_count = count;
    spin_unlock_irqrestore(&ring_lock, flags);

    return 0;
}
