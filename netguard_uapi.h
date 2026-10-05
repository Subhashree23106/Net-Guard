#ifndef NETGUARD_UAPI_H
#define NETGUARD_UAPI_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Netlink Family Protocol Number (custom protocol or fallback to USERSOCK) */
#define NETLINK_NETGUARD        31
#define NETLINK_NETGUARD_FALLBACK 2  /* NETLINK_USERSOCK */
#define NETGUARD_NL_GROUP_EVENTS 1

#define NETGUARD_VERSION_MAJOR  1
#define NETGUARD_VERSION_MINOR  0
#define NETGUARD_VERSION_PATCH  0
#define NETGUARD_VERSION_STRING "1.0.0"

#define NETGUARD_MAX_RULES      256
#define NETGUARD_MAX_EVENTS     128
#define NETGUARD_DESC_MAX_LEN   64
#define NETGUARD_IFACE_MAX_LEN  16

/* Rule Directions */
#define NETGUARD_DIR_IN         0x01
#define NETGUARD_DIR_OUT        0x02
#define NETGUARD_DIR_FWD        0x04
#define NETGUARD_DIR_ANY        (NETGUARD_DIR_IN | NETGUARD_DIR_OUT | NETGUARD_DIR_FWD)

/* Rule Actions */
#define NETGUARD_ACTION_ACCEPT  1
#define NETGUARD_ACTION_DROP    2
#define NETGUARD_ACTION_REJECT  3
#define NETGUARD_ACTION_LOG     4

/* Rule Protocols */
#define NETGUARD_PROTO_ANY      0
#define NETGUARD_PROTO_ICMP     1
#define NETGUARD_PROTO_TCP      6
#define NETGUARD_PROTO_UDP      17

/* Log Levels */
#define NETGUARD_LOG_ERROR      0
#define NETGUARD_LOG_WARN       1
#define NETGUARD_LOG_INFO       2
#define NETGUARD_LOG_DEBUG      3

/* Default Policy */
#define NETGUARD_POLICY_ACCEPT  1
#define NETGUARD_POLICY_DROP    2

/* Status / Error Codes */
#define NETGUARD_OK                  0
#define NETGUARD_ERR_GENERIC        -1
#define NETGUARD_ERR_RULE_EXISTS    -2
#define NETGUARD_ERR_RULE_NOT_FOUND -3
#define NETGUARD_ERR_INVALID_PARAM  -4
#define NETGUARD_ERR_NO_MEM         -5
#define NETGUARD_ERR_PERMISSION     -6
#define NETGUARD_ERR_MAX_RULES      -7

/* Netlink Message Types */
enum netguard_msg_type {
    /* Requests from user-space */
    NETGUARD_NL_MSG_ADD_RULE        = 0x10,
    NETGUARD_NL_MSG_DEL_RULE        = 0x11,
    NETGUARD_NL_MSG_UPDATE_RULE     = 0x12,
    NETGUARD_NL_MSG_ENABLE_RULE     = 0x13,
    NETGUARD_NL_MSG_DISABLE_RULE    = 0x14,
    NETGUARD_NL_MSG_GET_RULES       = 0x15,
    NETGUARD_NL_MSG_CLEAR_RULES     = 0x16,
    NETGUARD_NL_MSG_GET_STATS       = 0x17,
    NETGUARD_NL_MSG_RESET_STATS     = 0x18,
    NETGUARD_NL_MSG_SET_POLICY      = 0x19,
    NETGUARD_NL_MSG_GET_EVENTS      = 0x1A,
    NETGUARD_NL_MSG_PING            = 0x1B,
    NETGUARD_NL_MSG_SET_LOG_LEVEL   = 0x1C,

    /* Responses from kernel */
    NETGUARD_NL_RESP_OK             = 0x80,
    NETGUARD_NL_RESP_ERROR          = 0x81,
    NETGUARD_NL_RESP_RULES          = 0x82,
    NETGUARD_NL_RESP_STATS          = 0x83,
    NETGUARD_NL_RESP_EVENTS         = 0x84,
    NETGUARD_NL_RESP_PONG           = 0x85,
    NETGUARD_NL_EVENT_NOTIFY        = 0x86
};

/* Rule Definition Structure */
struct netguard_rule {
    uint32_t id;                    /* Unique Rule Identifier (1..UINT32_MAX) */
    uint32_t priority;              /* Priority: lower number evaluated first (e.g. 1..1000) */
    uint8_t  enabled;               /* 1 = Enabled, 0 = Disabled */
    uint8_t  direction;             /* Bitmask of NETGUARD_DIR_* */
    uint8_t  protocol;              /* NETGUARD_PROTO_* or IPPROTO_* */
    uint8_t  action;                /* NETGUARD_ACTION_* */
    
    uint32_t src_ip;                /* Network byte order IPv4 (0 = ANY) */
    uint32_t src_mask;              /* Network byte order subnet mask (e.g. 0xFFFFFFFF for /32) */
    uint32_t dst_ip;                /* Network byte order IPv4 (0 = ANY) */
    uint32_t dst_mask;              /* Network byte order subnet mask */
    
    uint16_t src_port_min;          /* Host byte order port range start (0 = ANY) */
    uint16_t src_port_max;          /* Host byte order port range end */
    uint16_t dst_port_min;          /* Host byte order port range start (0 = ANY) */
    uint16_t dst_port_max;          /* Host byte order port range end */
    
    uint8_t  tcp_flags_mask;        /* Mask of TCP flags to match (0 = ignore) */
    uint8_t  tcp_flags_val;         /* Required value of TCP flags */
    uint16_t _reserved;
    
    uint64_t packet_count;          /* Number of matched packets */
    uint64_t byte_count;            /* Number of matched bytes */
    uint64_t created_time;          /* Epoch seconds when rule was created */
    uint64_t last_matched_time;     /* Epoch seconds when rule was last triggered */
    char     description[NETGUARD_DESC_MAX_LEN]; /* Human-friendly description / tag */
};

/* Global Statistics Structure */
struct netguard_stats {
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t accepted_packets;
    uint64_t accepted_bytes;
    uint64_t dropped_packets;
    uint64_t dropped_bytes;
    uint64_t rejected_packets;
    uint64_t rejected_bytes;
    
    uint64_t tcp_packets;
    uint64_t tcp_bytes;
    uint64_t udp_packets;
    uint64_t udp_bytes;
    uint64_t icmp_packets;
    uint64_t icmp_bytes;
    uint64_t other_packets;
    uint64_t other_bytes;
    
    uint64_t in_packets;
    uint64_t in_bytes;
    uint64_t out_packets;
    uint64_t out_bytes;
    uint64_t fwd_packets;
    uint64_t fwd_bytes;
    
    uint32_t active_rules_count;
    uint8_t  default_policy;        /* NETGUARD_POLICY_ACCEPT or NETGUARD_POLICY_DROP */
    uint8_t  logging_enabled;
    uint8_t  log_level;             /* NETGUARD_LOG_* */
    uint8_t  hooks_active;          /* 1 = Netfilter hooks registered */
    uint64_t module_uptime_sec;     /* Module load uptime in seconds */
};

/* Packet Live Event Structure */
struct netguard_packet_event {
    uint64_t timestamp_sec;
    uint32_t timestamp_usec;
    uint32_t src_ip;                /* Network byte order */
    uint32_t dst_ip;                /* Network byte order */
    uint16_t src_port;              /* Host byte order */
    uint16_t dst_port;              /* Host byte order */
    uint8_t  protocol;
    uint8_t  direction;
    uint8_t  action;
    uint8_t  tcp_flags;
    uint32_t matched_rule_id;       /* Rule ID that matched or 0 for default policy */
    uint32_t packet_len;
    char     iface_in[NETGUARD_IFACE_MAX_LEN];
    char     iface_out[NETGUARD_IFACE_MAX_LEN];
};

/* Netlink Request/Response Header */
struct netguard_nl_hdr {
    uint16_t msg_type;              /* enum netguard_msg_type */
    uint16_t msg_flags;             /* Flags (reserved) */
    int32_t  status;                /* Return status (NETGUARD_OK or error code) */
    uint32_t payload_len;           /* Length of following payload */
    uint32_t seq;                   /* Sequence number */
};

/* Specific request payloads */
struct netguard_req_rule_id {
    uint32_t rule_id;
};

struct netguard_req_policy {
    uint8_t policy;                 /* NETGUARD_POLICY_ACCEPT or NETGUARD_POLICY_DROP */
};

struct netguard_req_log_level {
    uint8_t log_level;              /* NETGUARD_LOG_* */
};

#ifdef __cplusplus
}
#endif

#endif /* NETGUARD_UAPI_H */
