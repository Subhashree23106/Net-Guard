#include "include/netlink_comm.h"
#include "include/rule_engine.h"
#include "include/stats.h"
#include "include/log.h"

static struct sock *netguard_nl_sk = NULL;
static int active_nl_proto = NETLINK_NETGUARD;

static int send_nl_response(uint32_t pid, uint32_t seq, uint16_t resp_type,
                            int32_t status, const void *payload, uint32_t payload_len)
{
    struct sk_buff *skb_out;
    struct nlmsghdr *nlh;
    struct netguard_nl_hdr *ghdr;
    size_t total_size = NLMSG_SPACE(sizeof(struct netguard_nl_hdr) + payload_len);
    int res;

    if (!netguard_nl_sk || pid == 0)
        return -EINVAL;

    skb_out = nlmsg_new(total_size, GFP_KERNEL);
    if (!skb_out)
        return -ENOMEM;

    nlh = nlmsg_put(skb_out, pid, seq, resp_type, sizeof(struct netguard_nl_hdr) + payload_len, 0);
    if (!nlh) {
        kfree_skb(skb_out);
        return -EMSGSIZE;
    }

    ghdr = (struct netguard_nl_hdr *)nlmsg_data(nlh);
    ghdr->msg_type    = resp_type;
    ghdr->msg_flags   = 0;
    ghdr->status      = status;
    ghdr->payload_len = payload_len;
    ghdr->seq         = seq;

    if (payload && payload_len > 0)
        memcpy((void *)(ghdr + 1), payload, payload_len);

    res = nlmsg_unicast(netguard_nl_sk, skb_out, pid);
    if (res < 0)
        pr_debug("netguard: nlmsg_unicast to pid %u failed: %d\n", pid, res);

    return res;
}

void netguard_netlink_broadcast_event(const struct netguard_packet_event *event)
{
    struct sk_buff *skb_out;
    struct nlmsghdr *nlh;
    struct netguard_nl_hdr *ghdr;
    size_t payload_len = sizeof(struct netguard_packet_event);
    size_t total_size = NLMSG_SPACE(sizeof(struct netguard_nl_hdr) + payload_len);

    if (!netguard_nl_sk || !event)
        return;

    skb_out = nlmsg_new(total_size, GFP_ATOMIC);
    if (!skb_out)
        return;

    nlh = nlmsg_put(skb_out, 0, 0, NETGUARD_NL_EVENT_NOTIFY, sizeof(struct netguard_nl_hdr) + payload_len, 0);
    if (!nlh) {
        kfree_skb(skb_out);
        return;
    }

    ghdr = (struct netguard_nl_hdr *)nlmsg_data(nlh);
    ghdr->msg_type    = NETGUARD_NL_EVENT_NOTIFY;
    ghdr->msg_flags   = 0;
    ghdr->status      = NETGUARD_OK;
    ghdr->payload_len = payload_len;
    ghdr->seq         = 0;

    memcpy((void *)(ghdr + 1), event, payload_len);

    /* Multicast to group NETGUARD_NL_GROUP_EVENTS */
    nlmsg_multicast(netguard_nl_sk, skb_out, 0, NETGUARD_NL_GROUP_EVENTS, GFP_ATOMIC);
}

static void netguard_nl_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    struct netguard_nl_hdr *ghdr;
    uint32_t pid;
    uint32_t seq;
    void *payload;
    int32_t status = NETGUARD_OK;

    if (!skb)
        return;

    nlh = (struct nlmsghdr *)skb->data;
    if (!nlh || skb->len < NLMSG_HDRLEN + sizeof(struct netguard_nl_hdr)) {
        pr_warn("netguard: Malformed netlink packet received (len=%u)\n", skb->len);
        return;
    }

    pid = nlh->nlmsg_pid;
    seq = nlh->nlmsg_seq;
    ghdr = (struct netguard_nl_hdr *)NLMSG_DATA(nlh);
    payload = (void *)(ghdr + 1);

    switch (ghdr->msg_type) {
    case NETGUARD_NL_MSG_PING:
        send_nl_response(pid, seq, NETGUARD_NL_RESP_PONG, NETGUARD_OK, NULL, 0);
        break;

    case NETGUARD_NL_MSG_ADD_RULE: {
        struct netguard_rule *r;
        if (ghdr->payload_len < sizeof(struct netguard_rule)) {
            status = NETGUARD_ERR_INVALID_PARAM;
        } else {
            r = (struct netguard_rule *)payload;
            status = netguard_rule_add(r);
        }
        send_nl_response(pid, seq, (status == NETGUARD_OK) ? NETGUARD_NL_RESP_OK : NETGUARD_NL_RESP_ERROR,
                         status, NULL, 0);
        break;
    }

    case NETGUARD_NL_MSG_DEL_RULE: {
        struct netguard_req_rule_id *req;
        if (ghdr->payload_len < sizeof(struct netguard_req_rule_id)) {
            status = NETGUARD_ERR_INVALID_PARAM;
        } else {
            req = (struct netguard_req_rule_id *)payload;
            status = netguard_rule_del(req->rule_id);
        }
        send_nl_response(pid, seq, (status == NETGUARD_OK) ? NETGUARD_NL_RESP_OK : NETGUARD_NL_RESP_ERROR,
                         status, NULL, 0);
        break;
    }

    case NETGUARD_NL_MSG_UPDATE_RULE: {
        struct netguard_rule *r;
        if (ghdr->payload_len < sizeof(struct netguard_rule)) {
            status = NETGUARD_ERR_INVALID_PARAM;
        } else {
            r = (struct netguard_rule *)payload;
            status = netguard_rule_update(r);
        }
        send_nl_response(pid, seq, (status == NETGUARD_OK) ? NETGUARD_NL_RESP_OK : NETGUARD_NL_RESP_ERROR,
                         status, NULL, 0);
        break;
    }

    case NETGUARD_NL_MSG_ENABLE_RULE: {
        struct netguard_req_rule_id *req;
        if (ghdr->payload_len < sizeof(struct netguard_req_rule_id)) {
            status = NETGUARD_ERR_INVALID_PARAM;
        } else {
            req = (struct netguard_req_rule_id *)payload;
            status = netguard_rule_set_enabled(req->rule_id, 1);
        }
        send_nl_response(pid, seq, (status == NETGUARD_OK) ? NETGUARD_NL_RESP_OK : NETGUARD_NL_RESP_ERROR,
                         status, NULL, 0);
        break;
    }

    case NETGUARD_NL_MSG_DISABLE_RULE: {
        struct netguard_req_rule_id *req;
        if (ghdr->payload_len < sizeof(struct netguard_req_rule_id)) {
            status = NETGUARD_ERR_INVALID_PARAM;
        } else {
            req = (struct netguard_req_rule_id *)payload;
            status = netguard_rule_set_enabled(req->rule_id, 0);
        }
        send_nl_response(pid, seq, (status == NETGUARD_OK) ? NETGUARD_NL_RESP_OK : NETGUARD_NL_RESP_ERROR,
                         status, NULL, 0);
        break;
    }

    case NETGUARD_NL_MSG_CLEAR_RULES:
        status = netguard_rule_clear();
        send_nl_response(pid, seq, NETGUARD_NL_RESP_OK, status, NULL, 0);
        break;

    case NETGUARD_NL_MSG_GET_RULES: {
        struct netguard_rule *rules_buf;
        uint32_t count = 0;
        rules_buf = kmalloc(sizeof(struct netguard_rule) * NETGUARD_MAX_RULES, GFP_KERNEL);
        if (!rules_buf) {
            send_nl_response(pid, seq, NETGUARD_NL_RESP_ERROR, NETGUARD_ERR_NO_MEM, NULL, 0);
        } else {
            netguard_rule_dump(rules_buf, NETGUARD_MAX_RULES, &count);
            send_nl_response(pid, seq, NETGUARD_NL_RESP_RULES, NETGUARD_OK,
                             rules_buf, count * sizeof(struct netguard_rule));
            kfree(rules_buf);
        }
        break;
    }

    case NETGUARD_NL_MSG_GET_STATS: {
        struct netguard_stats st;
        netguard_stats_get(&st);
        send_nl_response(pid, seq, NETGUARD_NL_RESP_STATS, NETGUARD_OK, &st, sizeof(st));
        break;
    }

    case NETGUARD_NL_MSG_RESET_STATS:
        netguard_stats_reset();
        send_nl_response(pid, seq, NETGUARD_NL_RESP_OK, NETGUARD_OK, NULL, 0);
        break;

    case NETGUARD_NL_MSG_SET_POLICY: {
        struct netguard_req_policy *req;
        if (ghdr->payload_len < sizeof(struct netguard_req_policy)) {
            status = NETGUARD_ERR_INVALID_PARAM;
        } else {
            req = (struct netguard_req_policy *)payload;
            if (req->policy == NETGUARD_POLICY_ACCEPT || req->policy == NETGUARD_POLICY_DROP) {
                netguard_default_policy = req->policy;
                status = NETGUARD_OK;
                pr_info("netguard: Default policy changed to %s\n",
                        (req->policy == NETGUARD_POLICY_ACCEPT) ? "ACCEPT" : "DROP");
            } else {
                status = NETGUARD_ERR_INVALID_PARAM;
            }
        }
        send_nl_response(pid, seq, (status == NETGUARD_OK) ? NETGUARD_NL_RESP_OK : NETGUARD_NL_RESP_ERROR,
                         status, NULL, 0);
        break;
    }

    case NETGUARD_NL_MSG_SET_LOG_LEVEL: {
        struct netguard_req_log_level *req;
        if (ghdr->payload_len < sizeof(struct netguard_req_log_level)) {
            status = NETGUARD_ERR_INVALID_PARAM;
        } else {
            req = (struct netguard_req_log_level *)payload;
            netguard_log_level = req->log_level;
            status = NETGUARD_OK;
        }
        send_nl_response(pid, seq, NETGUARD_NL_RESP_OK, status, NULL, 0);
        break;
    }

    case NETGUARD_NL_MSG_GET_EVENTS: {
        struct netguard_packet_event *events_buf;
        uint32_t count = 0;
        events_buf = kmalloc(sizeof(struct netguard_packet_event) * NETGUARD_MAX_EVENTS, GFP_KERNEL);
        if (!events_buf) {
            send_nl_response(pid, seq, NETGUARD_NL_RESP_ERROR, NETGUARD_ERR_NO_MEM, NULL, 0);
        } else {
            netguard_log_get_events(events_buf, NETGUARD_MAX_EVENTS, &count);
            send_nl_response(pid, seq, NETGUARD_NL_RESP_EVENTS, NETGUARD_OK,
                             events_buf, count * sizeof(struct netguard_packet_event));
            kfree(events_buf);
        }
        break;
    }

    default:
        pr_warn("netguard: Unknown netlink message type: 0x%x\n", ghdr->msg_type);
        send_nl_response(pid, seq, NETGUARD_NL_RESP_ERROR, NETGUARD_ERR_INVALID_PARAM, NULL, 0);
        break;
    }
}

int netguard_netlink_init(void)
{
    struct netlink_kernel_cfg cfg = {
        .groups = NETGUARD_NL_GROUP_EVENTS,
        .input  = netguard_nl_recv_msg,
    };

    active_nl_proto = NETLINK_NETGUARD;
    netguard_nl_sk = netlink_kernel_create(&init_net, active_nl_proto, &cfg);
    if (!netguard_nl_sk) {
        pr_warn("netguard: Failed to bind protocol %d, falling back to %d\n",
                NETLINK_NETGUARD, NETLINK_NETGUARD_FALLBACK);
        active_nl_proto = NETLINK_NETGUARD_FALLBACK;
        netguard_nl_sk = netlink_kernel_create(&init_net, active_nl_proto, &cfg);
    }

    if (!netguard_nl_sk) {
        pr_err("netguard: Failed to create Netlink socket\n");
        return -ENOMEM;
    }

    pr_info("netguard: Netlink socket initialized on family %d\n", active_nl_proto);
    return 0;
}

void netguard_netlink_cleanup(void)
{
    if (netguard_nl_sk) {
        netlink_kernel_release(netguard_nl_sk);
        netguard_nl_sk = NULL;
        pr_info("netguard: Netlink socket released\n");
    }
}
