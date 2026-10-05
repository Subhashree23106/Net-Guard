#include "include/rule_engine.h"

static LIST_HEAD(rule_list);
static DEFINE_MUTEX(rules_mutex);
static uint32_t current_rule_count = 0;

int netguard_rule_engine_init(void)
{
    INIT_LIST_HEAD(&rule_list);
    current_rule_count = 0;
    return 0;
}

void netguard_rule_engine_cleanup(void)
{
    struct netguard_rule_node *node, *tmp;

    mutex_lock(&rules_mutex);
    list_for_each_entry_safe(node, tmp, &rule_list, list) {
        list_del_rcu(&node->list);
        synchronize_rcu();
        kfree(node);
    }
    current_rule_count = 0;
    mutex_unlock(&rules_mutex);
}

static struct netguard_rule_node *find_rule_node_locked(uint32_t rule_id)
{
    struct netguard_rule_node *node;
    list_for_each_entry(node, &rule_list, list) {
        if (node->rule.id == rule_id)
            return node;
    }
    return NULL;
}

int netguard_rule_add(const struct netguard_rule *rule)
{
    struct netguard_rule_node *new_node, *pos;
    struct timespec64 ts;

    if (!rule || rule->id == 0)
        return NETGUARD_ERR_INVALID_PARAM;

    mutex_lock(&rules_mutex);

    if (current_rule_count >= NETGUARD_MAX_RULES) {
        mutex_unlock(&rules_mutex);
        return NETGUARD_ERR_MAX_RULES;
    }

    if (find_rule_node_locked(rule->id) != NULL) {
        mutex_unlock(&rules_mutex);
        return NETGUARD_ERR_RULE_EXISTS;
    }

    new_node = kzalloc(sizeof(*new_node), GFP_KERNEL);
    if (!new_node) {
        mutex_unlock(&rules_mutex);
        return NETGUARD_ERR_NO_MEM;
    }

    memcpy(&new_node->rule, rule, sizeof(struct netguard_rule));
    ktime_get_real_ts64(&ts);
    new_node->rule.created_time = (uint64_t)ts.tv_sec;
    new_node->rule.last_matched_time = 0;

    atomic64_set(&new_node->packet_count, 0);
    atomic64_set(&new_node->byte_count, 0);
    atomic64_set(&new_node->last_matched, 0);

    /* Insert in priority order: lower priority number comes first */
    if (list_empty(&rule_list)) {
        list_add_tail_rcu(&new_node->list, &rule_list);
    } else {
        bool inserted = false;
        list_for_each_entry(pos, &rule_list, list) {
            if (new_node->rule.priority < pos->rule.priority) {
                list_add_tail_rcu(&new_node->list, &pos->list);
                inserted = true;
                break;
            }
        }
        if (!inserted)
            list_add_tail_rcu(&new_node->list, &rule_list);
    }

    current_rule_count++;
    mutex_unlock(&rules_mutex);

    pr_info("netguard: Added rule ID=%u (priority=%u, action=%u)\n",
            rule->id, rule->priority, rule->action);
    return NETGUARD_OK;
}

int netguard_rule_del(uint32_t rule_id)
{
    struct netguard_rule_node *node;

    if (rule_id == 0)
        return NETGUARD_ERR_INVALID_PARAM;

    mutex_lock(&rules_mutex);
    node = find_rule_node_locked(rule_id);
    if (!node) {
        mutex_unlock(&rules_mutex);
        return NETGUARD_ERR_RULE_NOT_FOUND;
    }

    list_del_rcu(&node->list);
    current_rule_count--;
    mutex_unlock(&rules_mutex);

    synchronize_rcu();
    kfree(node);

    pr_info("netguard: Deleted rule ID=%u\n", rule_id);
    return NETGUARD_OK;
}

int netguard_rule_update(const struct netguard_rule *rule)
{
    struct netguard_rule_node *node;

    if (!rule || rule->id == 0)
        return NETGUARD_ERR_INVALID_PARAM;

    mutex_lock(&rules_mutex);
    node = find_rule_node_locked(rule->id);
    if (!node) {
        mutex_unlock(&rules_mutex);
        return NETGUARD_ERR_RULE_NOT_FOUND;
    }

    node->rule.priority       = rule->priority;
    node->rule.enabled        = rule->enabled;
    node->rule.direction      = rule->direction;
    node->rule.protocol       = rule->protocol;
    node->rule.action         = rule->action;
    node->rule.src_ip         = rule->src_ip;
    node->rule.src_mask       = rule->src_mask;
    node->rule.dst_ip         = rule->dst_ip;
    node->rule.dst_mask       = rule->dst_mask;
    node->rule.src_port_min   = rule->src_port_min;
    node->rule.src_port_max   = rule->src_port_max;
    node->rule.dst_port_min   = rule->dst_port_min;
    node->rule.dst_port_max   = rule->dst_port_max;
    node->rule.tcp_flags_mask = rule->tcp_flags_mask;
    node->rule.tcp_flags_val  = rule->tcp_flags_val;
    strncpy(node->rule.description, rule->description, NETGUARD_DESC_MAX_LEN - 1);
    node->rule.description[NETGUARD_DESC_MAX_LEN - 1] = '\0';

    mutex_unlock(&rules_mutex);

    pr_info("netguard: Updated rule ID=%u\n", rule->id);
    return NETGUARD_OK;
}

int netguard_rule_set_enabled(uint32_t rule_id, uint8_t enabled)
{
    struct netguard_rule_node *node;

    if (rule_id == 0)
        return NETGUARD_ERR_INVALID_PARAM;

    mutex_lock(&rules_mutex);
    node = find_rule_node_locked(rule_id);
    if (!node) {
        mutex_unlock(&rules_mutex);
        return NETGUARD_ERR_RULE_NOT_FOUND;
    }

    node->rule.enabled = enabled ? 1 : 0;
    mutex_unlock(&rules_mutex);

    pr_info("netguard: Set rule ID=%u enabled=%u\n", rule_id, enabled ? 1 : 0);
    return NETGUARD_OK;
}

int netguard_rule_clear(void)
{
    struct netguard_rule_node *node, *tmp;
    LIST_HEAD(free_list);

    mutex_lock(&rules_mutex);
    list_for_each_entry_safe(node, tmp, &rule_list, list) {
        list_del_rcu(&node->list);
        list_add_tail(&node->list, &free_list);
    }
    current_rule_count = 0;
    mutex_unlock(&rules_mutex);

    synchronize_rcu();
    list_for_each_entry_safe(node, tmp, &free_list, list) {
        list_del(&node->list);
        kfree(node);
    }

    pr_info("netguard: Cleared all rules\n");
    return NETGUARD_OK;
}

int netguard_rule_dump(struct netguard_rule *out_rules, uint32_t max_count, uint32_t *out_count)
{
    struct netguard_rule_node *node;
    uint32_t count = 0;

    if (!out_rules || !out_count || max_count == 0)
        return -EINVAL;

    rcu_read_lock();
    list_for_each_entry_rcu(node, &rule_list, list) {
        if (count >= max_count)
            break;
        memcpy(&out_rules[count], &node->rule, sizeof(struct netguard_rule));
        out_rules[count].packet_count = atomic64_read(&node->packet_count);
        out_rules[count].byte_count = atomic64_read(&node->byte_count);
        out_rules[count].last_matched_time = atomic64_read(&node->last_matched);
        count++;
    }
    rcu_read_unlock();

    *out_count = count;
    return 0;
}

uint32_t netguard_rule_count(void)
{
    return current_rule_count;
}

static inline bool match_ip(uint32_t packet_ip, uint32_t rule_ip, uint32_t rule_mask)
{
    if (rule_mask == 0)
        return true; /* Match any */
    return (packet_ip & rule_mask) == (rule_ip & rule_mask);
}

static inline bool match_port(uint16_t packet_port, uint16_t min_port, uint16_t max_port)
{
    if (min_port == 0 && max_port == 0)
        return true; /* Match any */
    if (max_port == 0 || max_port < min_port)
        return packet_port == min_port;
    return (packet_port >= min_port && packet_port <= max_port);
}

uint8_t netguard_rule_evaluate(uint32_t src_ip, uint32_t dst_ip,
                              uint16_t src_port, uint16_t dst_port,
                              uint8_t protocol, uint8_t direction,
                              uint8_t tcp_flags, uint32_t pkt_len,
                              uint32_t *out_rule_id)
{
    struct netguard_rule_node *node;
    uint8_t action = netguard_default_policy;
    struct timespec64 ts;

    *out_rule_id = 0;

    rcu_read_lock();
    list_for_each_entry_rcu(node, &rule_list, list) {
        const struct netguard_rule *r = &node->rule;

        if (!r->enabled)
            continue;

        /* Check direction */
        if (r->direction != NETGUARD_DIR_ANY && !(r->direction & direction))
            continue;

        /* Check protocol */
        if (r->protocol != NETGUARD_PROTO_ANY && r->protocol != protocol)
            continue;

        /* Check source IP */
        if (!match_ip(src_ip, r->src_ip, r->src_mask))
            continue;

        /* Check destination IP */
        if (!match_ip(dst_ip, r->dst_ip, r->dst_mask))
            continue;

        /* Check transport ports (TCP/UDP) */
        if (protocol == NETGUARD_PROTO_TCP || protocol == NETGUARD_PROTO_UDP) {
            if (!match_port(src_port, r->src_port_min, r->src_port_max))
                continue;
            if (!match_port(dst_port, r->dst_port_min, r->dst_port_max))
                continue;
        }

        /* Check TCP flags */
        if (protocol == NETGUARD_PROTO_TCP && r->tcp_flags_mask != 0) {
            if ((tcp_flags & r->tcp_flags_mask) != r->tcp_flags_val)
                continue;
        }

        /* Match found! */
        atomic64_inc(&node->packet_count);
        atomic64_add(pkt_len, &node->byte_count);

        ktime_get_real_ts64(&ts);
        atomic64_set(&node->last_matched, (uint64_t)ts.tv_sec);

        *out_rule_id = r->id;
        action = r->action;
        break;
    }
    rcu_read_unlock();

    return action;
}
