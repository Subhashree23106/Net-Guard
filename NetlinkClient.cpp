#include "NetlinkClient.hpp"
#include <sys/socket.h>
#include <linux/netlink.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <poll.h>
#include <arpa/inet.h>

namespace netguard {

#define MAX_NL_PAYLOAD 65536

NetlinkClient::NetlinkClient()
    : m_sockFd(-1), m_pid(0), m_seq(1), m_activeProto(NETLINK_NETGUARD)
{
    m_pid = static_cast<uint32_t>(getpid());
}

NetlinkClient::~NetlinkClient()
{
    disconnect();
}

bool NetlinkClient::initSocket(int proto)
{
    if (m_sockFd >= 0) {
        close(m_sockFd);
        m_sockFd = -1;
    }

    m_sockFd = socket(AF_NETLINK, SOCK_RAW, proto);
    if (m_sockFd < 0) {
        return false;
    }

    struct sockaddr_nl src_addr;
    std::memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid    = m_pid;
    src_addr.nl_groups = 0; /* Unicast by default */

    if (bind(m_sockFd, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0) {
        /* Retry with random pid if port in use */
        src_addr.nl_pid = m_pid + (getpid() % 10000) * 100 + 1;
        m_pid = src_addr.nl_pid;
        if (bind(m_sockFd, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0) {
            close(m_sockFd);
            m_sockFd = -1;
            return false;
        }
    }

    /* Set default socket timeout (1.5 seconds) */
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 500000;
    setsockopt(m_sockFd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(m_sockFd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    m_activeProto = proto;
    return true;
}

bool NetlinkClient::connect()
{
    /* First try custom protocol NETLINK_NETGUARD (31) */
    if (initSocket(NETLINK_NETGUARD)) {
        if (ping())
            return true;
    }

    /* Fallback to NETLINK_NETGUARD_FALLBACK (2 - USERSOCK) */
    if (initSocket(NETLINK_NETGUARD_FALLBACK)) {
        if (ping())
            return true;
    }

    disconnect();
    return false;
}

void NetlinkClient::disconnect()
{
    if (m_sockFd >= 0) {
        close(m_sockFd);
        m_sockFd = -1;
    }
}

bool NetlinkClient::ping()
{
    if (m_sockFd < 0) return false;

    std::vector<uint8_t> resp;
    int32_t status = NETGUARD_OK;
    std::string err;
    return sendRequest(NETGUARD_NL_MSG_PING, nullptr, 0,
                       NETGUARD_NL_RESP_PONG, resp, status, err);
}

bool NetlinkClient::sendRequest(uint16_t msgType, const void *payload, uint32_t payloadLen,
                                uint16_t expectedResp, std::vector<uint8_t> &respPayload,
                                int32_t &outStatus, std::string &errorMsg)
{
    if (m_sockFd < 0) {
        errorMsg = "Netlink socket is not connected";
        return false;
    }

    uint32_t totalLen = NLMSG_SPACE(sizeof(struct netguard_nl_hdr) + payloadLen);
    std::vector<uint8_t> sendBuf(totalLen, 0);

    struct nlmsghdr *nlh = reinterpret_cast<struct nlmsghdr *>(sendBuf.data());
    nlh->nlmsg_len   = NLMSG_LENGTH(sizeof(struct netguard_nl_hdr) + payloadLen);
    nlh->nlmsg_pid   = m_pid;
    nlh->nlmsg_flags = 0;
    nlh->nlmsg_type  = msgType;
    nlh->nlmsg_seq   = ++m_seq;

    struct netguard_nl_hdr *ghdr = reinterpret_cast<struct netguard_nl_hdr *>(NLMSG_DATA(nlh));
    ghdr->msg_type    = msgType;
    ghdr->msg_flags   = 0;
    ghdr->status      = 0;
    ghdr->payload_len = payloadLen;
    ghdr->seq         = nlh->nlmsg_seq;

    if (payload && payloadLen > 0) {
        std::memcpy(reinterpret_cast<void *>(ghdr + 1), payload, payloadLen);
    }

    struct sockaddr_nl dest_addr;
    std::memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid    = 0; /* Kernel */
    dest_addr.nl_groups = 0;

    struct iovec iov;
    iov.iov_base = (void *)nlh;
    iov.iov_len  = nlh->nlmsg_len;

    struct msghdr msg;
    std::memset(&msg, 0, sizeof(msg));
    msg.msg_name    = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov     = &iov;
    msg.msg_iovlen  = 1;

    if (sendmsg(m_sockFd, &msg, 0) < 0) {
        errorMsg = "Failed to send Netlink message: " + std::string(strerror(errno));
        return false;
    }

    /* Receive Response */
    std::vector<uint8_t> recvBuf(MAX_NL_PAYLOAD, 0);
    struct iovec recv_iov;
    recv_iov.iov_base = recvBuf.data();
    recv_iov.iov_len  = recvBuf.size();

    struct msghdr recv_msg;
    std::memset(&recv_msg, 0, sizeof(recv_msg));
    recv_msg.msg_name    = (void *)&dest_addr;
    recv_msg.msg_namelen = sizeof(dest_addr);
    recv_msg.msg_iov     = &recv_iov;
    recv_msg.msg_iovlen  = 1;

    ssize_t bytesRecv = recvmsg(m_sockFd, &recv_msg, 0);
    if (bytesRecv < 0) {
        errorMsg = "Netlink receive timed out or failed: " + std::string(strerror(errno));
        return false;
    }

    struct nlmsghdr *respNlh = reinterpret_cast<struct nlmsghdr *>(recvBuf.data());
    if (!NLMSG_OK(respNlh, (unsigned int)bytesRecv)) {
        errorMsg = "Invalid Netlink message received from kernel";
        return false;
    }

    if (respNlh->nlmsg_type == NLMSG_ERROR) {
        errorMsg = "Netlink returned NLMSG_ERROR";
        return false;
    }

    struct netguard_nl_hdr *respGhdr = reinterpret_cast<struct netguard_nl_hdr *>(NLMSG_DATA(respNlh));
    outStatus = respGhdr->status;

    if (respGhdr->msg_type != expectedResp && respGhdr->msg_type != NETGUARD_NL_RESP_OK) {
        if (respGhdr->msg_type == NETGUARD_NL_RESP_ERROR) {
            errorMsg = "Kernel error: " + statusToString(outStatus);
            return false;
        }
        errorMsg = "Unexpected response type: " + std::to_string(respGhdr->msg_type);
        return false;
    }

    if (outStatus != NETGUARD_OK) {
        errorMsg = statusToString(outStatus);
        return false;
    }

    if (respGhdr->payload_len > 0) {
        const uint8_t *respData = reinterpret_cast<const uint8_t *>(respGhdr + 1);
        respPayload.assign(respData, respData + respGhdr->payload_len);
    } else {
        respPayload.clear();
    }

    return true;
}

bool NetlinkClient::addRule(const struct netguard_rule &rule, std::string &errorMsg)
{
    std::vector<uint8_t> resp;
    int32_t status = NETGUARD_OK;
    return sendRequest(NETGUARD_NL_MSG_ADD_RULE, &rule, sizeof(rule),
                       NETGUARD_NL_RESP_OK, resp, status, errorMsg);
}

bool NetlinkClient::deleteRule(uint32_t ruleId, std::string &errorMsg)
{
    struct netguard_req_rule_id req = { ruleId };
    std::vector<uint8_t> resp;
    int32_t status = NETGUARD_OK;
    return sendRequest(NETGUARD_NL_MSG_DEL_RULE, &req, sizeof(req),
                       NETGUARD_NL_RESP_OK, resp, status, errorMsg);
}

bool NetlinkClient::updateRule(const struct netguard_rule &rule, std::string &errorMsg)
{
    std::vector<uint8_t> resp;
    int32_t status = NETGUARD_OK;
    return sendRequest(NETGUARD_NL_MSG_UPDATE_RULE, &rule, sizeof(rule),
                       NETGUARD_NL_RESP_OK, resp, status, errorMsg);
}

bool NetlinkClient::enableRule(uint32_t ruleId, bool enable, std::string &errorMsg)
{
    struct netguard_req_rule_id req = { ruleId };
    std::vector<uint8_t> resp;
    int32_t status = NETGUARD_OK;
    uint16_t msgType = enable ? NETGUARD_NL_MSG_ENABLE_RULE : NETGUARD_NL_MSG_DISABLE_RULE;
    return sendRequest(msgType, &req, sizeof(req),
                       NETGUARD_NL_RESP_OK, resp, status, errorMsg);
}

bool NetlinkClient::clearRules(std::string &errorMsg)
{
    std::vector<uint8_t> resp;
    int32_t status = NETGUARD_OK;
    return sendRequest(NETGUARD_NL_MSG_CLEAR_RULES, nullptr, 0,
                       NETGUARD_NL_RESP_OK, resp, status, errorMsg);
}

bool NetlinkClient::getRules(std::vector<struct netguard_rule> &rules, std::string &errorMsg)
{
    rules.clear();
    std::vector<uint8_t> resp;
    int32_t status = NETGUARD_OK;
    if (!sendRequest(NETGUARD_NL_MSG_GET_RULES, nullptr, 0,
                     NETGUARD_NL_RESP_RULES, resp, status, errorMsg)) {
        return false;
    }

    size_t numRules = resp.size() / sizeof(struct netguard_rule);
    const struct netguard_rule *ruleArr = reinterpret_cast<const struct netguard_rule *>(resp.data());
    for (size_t i = 0; i < numRules; i++) {
        rules.push_back(ruleArr[i]);
    }
    return true;
}

bool NetlinkClient::getStats(struct netguard_stats &stats, std::string &errorMsg)
{
    std::vector<uint8_t> resp;
    int32_t status = NETGUARD_OK;
    if (!sendRequest(NETGUARD_NL_MSG_GET_STATS, nullptr, 0,
                     NETGUARD_NL_RESP_STATS, resp, status, errorMsg)) {
        return false;
    }

    if (resp.size() < sizeof(struct netguard_stats)) {
        errorMsg = "Stats response size mismatch";
        return false;
    }

    std::memcpy(&stats, resp.data(), sizeof(struct netguard_stats));
    return true;
}

bool NetlinkClient::resetStats(std::string &errorMsg)
{
    std::vector<uint8_t> resp;
    int32_t status = NETGUARD_OK;
    return sendRequest(NETGUARD_NL_MSG_RESET_STATS, nullptr, 0,
                       NETGUARD_NL_RESP_OK, resp, status, errorMsg);
}

bool NetlinkClient::setDefaultPolicy(uint8_t policy, std::string &errorMsg)
{
    struct netguard_req_policy req = { policy };
    std::vector<uint8_t> resp;
    int32_t status = NETGUARD_OK;
    return sendRequest(NETGUARD_NL_MSG_SET_POLICY, &req, sizeof(req),
                       NETGUARD_NL_RESP_OK, resp, status, errorMsg);
}

bool NetlinkClient::setLogLevel(uint8_t level, std::string &errorMsg)
{
    struct netguard_req_log_level req = { level };
    std::vector<uint8_t> resp;
    int32_t status = NETGUARD_OK;
    return sendRequest(NETGUARD_NL_MSG_SET_LOG_LEVEL, &req, sizeof(req),
                       NETGUARD_NL_RESP_OK, resp, status, errorMsg);
}

bool NetlinkClient::getRecentEvents(std::vector<struct netguard_packet_event> &events, std::string &errorMsg)
{
    events.clear();
    std::vector<uint8_t> resp;
    int32_t status = NETGUARD_OK;
    if (!sendRequest(NETGUARD_NL_MSG_GET_EVENTS, nullptr, 0,
                     NETGUARD_NL_RESP_EVENTS, resp, status, errorMsg)) {
        return false;
    }

    size_t numEvents = resp.size() / sizeof(struct netguard_packet_event);
    const struct netguard_packet_event *eventArr = reinterpret_cast<const struct netguard_packet_event *>(resp.data());
    for (size_t i = 0; i < numEvents; i++) {
        events.push_back(eventArr[i]);
    }
    return true;
}

bool NetlinkClient::subscribeEvents()
{
    if (m_sockFd < 0) return false;

    struct sockaddr_nl src_addr;
    std::memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid    = m_pid;
    src_addr.nl_groups = NETGUARD_NL_GROUP_EVENTS;

    return bind(m_sockFd, (struct sockaddr *)&src_addr, sizeof(src_addr)) == 0;
}

bool NetlinkClient::receiveEvent(struct netguard_packet_event &event, int timeoutMs)
{
    if (m_sockFd < 0) return false;

    struct pollfd pfd;
    pfd.fd = m_sockFd;
    pfd.events = POLLIN;
    pfd.revents = 0;

    int ret = poll(&pfd, 1, timeoutMs);
    if (ret <= 0 || !(pfd.revents & POLLIN))
        return false;

    std::vector<uint8_t> recvBuf(MAX_NL_PAYLOAD, 0);
    struct sockaddr_nl nladdr;
    struct iovec iov = { recvBuf.data(), recvBuf.size() };
    struct msghdr msg;
    std::memset(&msg, 0, sizeof(msg));
    msg.msg_name    = &nladdr;
    msg.msg_namelen = sizeof(nladdr);
    msg.msg_iov     = &iov;
    msg.msg_iovlen  = 1;

    ssize_t len = recvmsg(m_sockFd, &msg, 0);
    if (len < 0) return false;

    struct nlmsghdr *nlh = reinterpret_cast<struct nlmsghdr *>(recvBuf.data());
    if (!NLMSG_OK(nlh, (unsigned int)len)) return false;

    if (nlh->nlmsg_type == NETGUARD_NL_EVENT_NOTIFY) {
        struct netguard_nl_hdr *ghdr = reinterpret_cast<struct netguard_nl_hdr *>(NLMSG_DATA(nlh));
        if (ghdr->payload_len >= sizeof(struct netguard_packet_event)) {
            const struct netguard_packet_event *ev = reinterpret_cast<const struct netguard_packet_event *>(ghdr + 1);
            event = *ev;
            return true;
        }
    }

    return false;
}

std::string NetlinkClient::statusToString(int32_t status)
{
    switch (status) {
    case NETGUARD_OK:                  return "Success";
    case NETGUARD_ERR_GENERIC:        return "Generic kernel error";
    case NETGUARD_ERR_RULE_EXISTS:    return "Rule ID already exists";
    case NETGUARD_ERR_RULE_NOT_FOUND: return "Rule ID not found";
    case NETGUARD_ERR_INVALID_PARAM:  return "Invalid parameter or rule configuration";
    case NETGUARD_ERR_NO_MEM:         return "Kernel out of memory";
    case NETGUARD_ERR_PERMISSION:     return "Permission denied (root / CAP_NET_ADMIN required)";
    case NETGUARD_ERR_MAX_RULES:      return "Maximum rule capacity reached";
    default:                          return "Error code " + std::to_string(status);
    }
}

} // namespace netguard
