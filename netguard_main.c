#include "include/netguard_kernel.h"
#include "include/rule_engine.h"
#include "include/netfilter_hooks.h"
#include "include/netlink_comm.h"
#include "include/stats.h"
#include "include/proc_diag.h"
#include "include/log.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NetGuard Security Systems");
MODULE_DESCRIPTION("Kernel-Space Network Packet Filter & Rule Enforcement Agent");
MODULE_VERSION(NETGUARD_VERSION_STRING);

uint8_t netguard_default_policy = NETGUARD_POLICY_ACCEPT;
uint8_t netguard_log_level = NETGUARD_LOG_INFO;
uint64_t netguard_load_time_sec = 0;

static int param_default_policy = NETGUARD_POLICY_ACCEPT;
module_param_named(default_policy, param_default_policy, int, 0644);
MODULE_PARM_DESC(default_policy, "Default packet action: 1=ACCEPT, 2=DROP (default: 1)");

static int param_log_level = NETGUARD_LOG_INFO;
module_param_named(log_level, param_log_level, int, 0644);
MODULE_PARM_DESC(log_level, "Log level: 0=ERROR, 1=WARN, 2=INFO, 3=DEBUG (default: 2)");

static int __init netguard_init(void)
{
    int ret;
    struct timespec64 ts;

    pr_info("====================================================\n");
    pr_info("netguard: Initializing Kernel Packet Filter v%s\n", NETGUARD_VERSION_STRING);
    pr_info("====================================================\n");

    ktime_get_real_ts64(&ts);
    netguard_load_time_sec = (uint64_t)ts.tv_sec;

    netguard_default_policy = (param_default_policy == NETGUARD_POLICY_DROP) ?
                               NETGUARD_POLICY_DROP : NETGUARD_POLICY_ACCEPT;
    netguard_log_level = (param_log_level >= 0 && param_log_level <= 3) ?
                          (uint8_t)param_log_level : NETGUARD_LOG_INFO;

    /* 1. Initialize statistics */
    netguard_stats_init();

    /* 2. Initialize log ring buffer */
    netguard_log_init();

    /* 3. Initialize rule engine */
    ret = netguard_rule_engine_init();
    if (ret < 0) {
        pr_err("netguard: Failed to initialize rule engine\n");
        return ret;
    }

    /* 4. Initialize /proc diagnostics */
    ret = netguard_proc_init();
    if (ret < 0) {
        pr_warn("netguard: Failed to create proc entries, continuing\n");
    }

    /* 5. Initialize Netlink socket */
    ret = netguard_netlink_init();
    if (ret < 0) {
        pr_err("netguard: Failed to create Netlink socket\n");
        goto err_proc;
    }

    /* 6. Register Netfilter hooks */
    ret = netguard_netfilter_init();
    if (ret < 0) {
        pr_err("netguard: Failed to register netfilter hooks\n");
        goto err_nl;
    }

    pr_info("netguard: Loaded successfully. Default Policy=%s, LogLevel=%u\n",
            (netguard_default_policy == NETGUARD_POLICY_ACCEPT) ? "ACCEPT" : "DROP",
            netguard_log_level);
    return 0;

err_nl:
    netguard_netlink_cleanup();
err_proc:
    netguard_proc_cleanup();
    netguard_rule_engine_cleanup();
    netguard_log_cleanup();
    return ret;
}

static void __exit netguard_exit(void)
{
    pr_info("netguard: Unloading module...\n");

    netguard_netfilter_cleanup();
    netguard_netlink_cleanup();
    netguard_proc_cleanup();
    netguard_rule_engine_cleanup();
    netguard_log_cleanup();

    pr_info("netguard: Module unloaded cleanly\n");
}

module_init(netguard_init);
module_exit(netguard_exit);
