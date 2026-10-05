#include "include/netfilter_hooks.h"
#include "include/rule_engine.h"
#include "include/stats.h"
#include "include/log.h"

static struct nf_hook_ops netguard_nf_ops[3];
static uint8_t hooks_registered = 0;

static unsigned int netguard_hookfn(void *priv,
                                   struct sk_buff *skb,
                                   const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr _tcph, *th = NULL;
    struct udphdr _udph, *uh = NULL;
    struct icmphdr _icmph, *ih = NULL;
    uint32_t src_ip, dst_ip;
    uint16_t src_port = 0, dst_port = 0;
    uint8_t proto_code = NETGUARD_PROTO_ANY;
    uint8_t direction = NETGUARD_DIR_IN;
    uint8_t tcp_flags = 0;
    uint32_t pkt_len = 0;
    uint32_t matched_rule_id = 0;
    uint8_t action;
    struct netguard_packet_event event;
    struct timespec64 ts;

    if (!skb)
        return NF_ACCEPT;

    /* Only handle IPv4 packets */
    if (skb->protocol != htons(ETH_P_IP))
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;

    src_ip = iph->saddr;
    dst_ip = iph->daddr;
    pkt_len = skb->len;

    /* Determine direction */
    if (state->hook == NF_INET_LOCAL_IN) {
        direction = NETGUARD_DIR_IN;
    } else if (state->hook == NF_INET_LOCAL_OUT) {
        direction = NETGUARD_DIR_OUT;
    } else if (state->hook == NF_INET_FORWARD) {
        direction = NETGUARD_DIR_FWD;
    }

    /* Extract protocol & transport headers */
    switch (iph->protocol) {
    case IPPROTO_TCP:
        proto_code = NETGUARD_PROTO_TCP;
        th = skb_header_pointer(skb, iph->ihl * 4, sizeof(_tcph), &_tcph);
        if (th) {
            src_port = ntohs(th->source);
            dst_port = ntohs(th->dest);
            if (th->syn) tcp_flags |= 0x02;
            if (th->ack) tcp_flags |= 0x10;
            if (th->fin) tcp_flags |= 0x01;
            if (th->rst) tcp_flags |= 0x04;
            if (th->psh) tcp_flags |= 0x08;
            if (th->urg) tcp_flags |= 0x20;
        }
        break;

    case IPPROTO_UDP:
        proto_code = NETGUARD_PROTO_UDP;
        uh = skb_header_pointer(skb, iph->ihl * 4, sizeof(_udph), &_udph);
        if (uh) {
            src_port = ntohs(uh->source);
            dst_port = ntohs(uh->dest);
        }
        break;

    case IPPROTO_ICMP:
        proto_code = NETGUARD_PROTO_ICMP;
        ih = skb_header_pointer(skb, iph->ihl * 4, sizeof(_icmph), &_icmph);
        if (ih) {
            src_port = ih->type;
            dst_port = ih->code;
        }
        break;

    default:
        proto_code = iph->protocol;
        break;
    }

    /* Evaluate rules */
    action = netguard_rule_evaluate(src_ip, dst_ip, src_port, dst_port,
                                    proto_code, direction, tcp_flags,
                                    pkt_len, &matched_rule_id);

    /* Update atomic statistics */
    netguard_stats_inc_packet(proto_code, direction, action, pkt_len);

    /* Prepare packet event log */
    ktime_get_real_ts64(&ts);
    memset(&event, 0, sizeof(event));
    event.timestamp_sec   = (uint64_t)ts.tv_sec;
    event.timestamp_usec  = (uint32_t)(ts.tv_nsec / 1000);
    event.src_ip          = src_ip;
    event.dst_ip          = dst_ip;
    event.src_port        = src_port;
    event.dst_port        = dst_port;
    event.protocol        = proto_code;
    event.direction       = direction;
    event.action          = action;
    event.tcp_flags       = tcp_flags;
    event.matched_rule_id = matched_rule_id;
    event.packet_len      = pkt_len;

    if (state->in)
        strncpy(event.iface_in, state->in->name, NETGUARD_IFACE_MAX_LEN - 1);
    if (state->out)
        strncpy(event.iface_out, state->out->name, NETGUARD_IFACE_MAX_LEN - 1);

    netguard_log_event(&event);

    /* Enforce decision */
    if (action == NETGUARD_ACTION_DROP || action == NETGUARD_ACTION_REJECT)
        return NF_DROP;

    return NF_ACCEPT;
}

int netguard_netfilter_init(void)
{
    int ret;

    /* 1. Inbound Hook (LOCAL_IN) */
    netguard_nf_ops[0].hook     = netguard_hookfn;
    netguard_nf_ops[0].pf       = NFPROTO_IPV4;
    netguard_nf_ops[0].hooknum  = NF_INET_LOCAL_IN;
    netguard_nf_ops[0].priority = NF_IP_PRI_FIRST;

    /* 2. Outbound Hook (LOCAL_OUT) */
    netguard_nf_ops[1].hook     = netguard_hookfn;
    netguard_nf_ops[1].pf       = NFPROTO_IPV4;
    netguard_nf_ops[1].hooknum  = NF_INET_LOCAL_OUT;
    netguard_nf_ops[1].priority = NF_IP_PRI_FIRST;

    /* 3. Forward Hook (FORWARD) */
    netguard_nf_ops[2].hook     = netguard_hookfn;
    netguard_nf_ops[2].pf       = NFPROTO_IPV4;
    netguard_nf_ops[2].hooknum  = NF_INET_FORWARD;
    netguard_nf_ops[2].priority = NF_IP_PRI_FIRST;

    ret = nf_register_net_hooks(&init_net, netguard_nf_ops, ARRAY_SIZE(netguard_nf_ops));
    if (ret < 0) {
        pr_err("netguard: Failed to register netfilter hooks: %d\n", ret);
        hooks_registered = 0;
        return ret;
    }

    hooks_registered = 1;
    pr_info("netguard: Netfilter hooks registered successfully (LOCAL_IN, LOCAL_OUT, FORWARD)\n");
    return 0;
}

void netguard_netfilter_cleanup(void)
{
    if (hooks_registered) {
        nf_unregister_net_hooks(&init_net, netguard_nf_ops, ARRAY_SIZE(netguard_nf_ops));
        hooks_registered = 0;
        pr_info("netguard: Netfilter hooks unregistered\n");
    }
}

uint8_t netguard_get_hooks_active(void)
{
    return hooks_registered;
}
