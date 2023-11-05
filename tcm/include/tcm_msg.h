// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#ifndef TCM_MSG_H_
#define TCM_MSG_H_

#include <stdint.h>

#include "tcm_comm.h"
#include "tcm_version.h"

/* These values should not be changed */

typedef uint8_t  tcm_msg_type;
typedef uint16_t tcm_token;
typedef uint32_t tcm_magic;

/* These values may be changed if more complex data types are needed */

typedef uint64_t tcm_msg_type_flag;
typedef uint8_t  tcm_addr_fmt;
typedef uint8_t  tcm_tid;
typedef int8_t   tcm_mv_result;
typedef uint16_t tcm_version_part;
typedef uint16_t tcm_retcode;

enum : tcm_addr_fmt { TCM_AF_INVALID, TCM_AF_INET = 1, TCM_AF_MAX };

enum : tcm_msg_type {
    TCM_MSG_ANY = 0,

    /* Fixed values for client and server ping: 1 and 2 */

    TCM_MSG_CLIENT_PING = 1,
    TCM_MSG_SERVER_PING = 2,

    /* Below values are arbitrary for each version */

    TCM_MSG_STATUS        = 3,
    TCM_MSG_METADATA_REQ  = 4,
    TCM_MSG_METADATA_RESP = 5,
    TCM_MSG_CONN_REQ      = 6,
    TCM_MSG_CONN_RESP     = 7,
    TCM_MSG_FABRIC_PING   = 8,

    TCM_MSG_MAX,
};

/*  This prevents TCM_MSG_* from accidentally being used in functions expecting
    TCM_MFLAG_* (throw an error) */
const tcm_msg_type_flag TCM_MFLAG_BASE         = (1 << 7);
const tcm_msg_type_flag TCM_MFLAG_INVALID_BITS = (1 << 8) - 1;

/* These flags are used in message verification functions */
enum : tcm_msg_type_flag {
    TCM_MFLAG_CLIENT_PING   = (TCM_MFLAG_BASE << TCM_MSG_CLIENT_PING),
    TCM_MFLAG_SERVER_PING   = (TCM_MFLAG_BASE << TCM_MSG_SERVER_PING),
    TCM_MFLAG_STATUS        = (TCM_MFLAG_BASE << TCM_MSG_STATUS),
    TCM_MFLAG_METADATA_REQ  = (TCM_MFLAG_BASE << TCM_MSG_METADATA_REQ),
    TCM_MFLAG_METADATA_RESP = (TCM_MFLAG_BASE << TCM_MSG_METADATA_RESP),
    TCM_MFLAG_CONN_REQ      = (TCM_MFLAG_BASE << TCM_MSG_CONN_REQ),
    TCM_MFLAG_CONN_RESP     = (TCM_MFLAG_BASE << TCM_MSG_CONN_RESP),
    TCM_MFLAG_FABRIC_PING   = (TCM_MFLAG_BASE << TCM_MSG_FABRIC_PING),
    TCM_MFLAG_ANY           = UINT64_MAX
};

/* Get the type flag corresponding to the message type ID. */
static inline tcm_msg_type_flag tcm_msg_type_to_flag(tcm_msg_type type) {
    if (type == TCM_MSG_ANY)
        return TCM_MFLAG_ANY;
    if (type >= TCM_MSG_MAX)
        return 0;
    return TCM_MFLAG_BASE << type;
}

enum : tcm_tid {
    TCM_TID_INVALID,
    TCM_TID_TCP_RXM   = (1 << 0), /* Libfabric RXM over TCP */
    TCM_TID_VERBS_RXM = (1 << 1), /* Libfabric RXM over Verbs RDMA */
    TCM_TID_TCP       = (1 << 2), /* Libfabric datagram TCP (v1.18+) */
    TCM_TID_MAX
};

static inline int tcm_conv_fi_addr_fmt(uint32_t addr_fmt) {
    switch (addr_fmt) {
        case FI_SOCKADDR_IN:
            return TCM_AF_INET;
        default:
            return -EINVAL;
    }
}

static inline tcm_tid prov_name_to_id(char * prov_name) {
    if (strcmp("verbs;ofi_rxm", prov_name) == 0 ||
        strcmp("ofi_rxm;verbs", prov_name) == 0)
        return TCM_TID_VERBS_RXM;
    if (strcmp("tcp;ofi_rxm", prov_name) == 0 ||
        strcmp("ofi_rxm;tcp", prov_name) == 0)
        return TCM_TID_TCP_RXM;
    if (strcmp("tcp", prov_name) == 0)
        return TCM_TID_TCP;
    return TCM_TID_INVALID;
}

static inline char * id_to_prov_name(tcm_tid id) {
    switch (id) {
        case TCM_TID_TCP_RXM:
            return strdup("tcp;ofi_rxm");
        case TCM_TID_VERBS_RXM:
            return strdup("verbs;ofi_rxm");
        case TCM_TID_TCP:
            return strdup("tcp");
        default:
            errno = EINVAL;
            return 0;
    }
}

static inline const char * id_to_prov_name_static(tcm_tid id) {
    switch (id) {
        case TCM_TID_TCP_RXM:
            return "tcp;ofi_rxm";
        case TCM_TID_VERBS_RXM:
            return "verbs;ofi_rxm";
        case TCM_TID_TCP:
            return "tcp";
        default:
            return "unknown";
    }
}

#pragma pack(push, 1)

/* ---------------------------- Address Formats ---------------------------- */

struct tcm_addr_inet {
    uint32_t addr;
    uint16_t port;
    tcm_addr_inet() { return; }
    tcm_addr_inet(uint32_t addr, uint16_t port) {
        this->addr = addr;
        this->port = port;
    }
};

struct tcm_addr_inet6 {
    uint8_t  addr[16];
    uint16_t port;
    tcm_addr_inet6() { return; }
    tcm_addr_inet6(in6_addr * addr_, uint16_t port_) {
        memcpy((void *) addr, (void *) addr_->s6_addr, 16);
        port = port_;
    }
};

/* ----------------------------- Common Items ----------------------------- */

struct tcm_msg_header {
    tcm_magic    magic;
    tcm_msg_type type;
    tcm_token    token;
    tcm_msg_header() { return; }
    tcm_msg_header(tcm_msg_type type, tcm_token token) {
        this->magic = TCM_MAGIC;
        this->type  = type;
        this->token = token;
    }
};

struct tcm_msg_version {
    tcm_version_part major;
    tcm_version_part minor;
    tcm_version_part patch;
    tcm_msg_version() { return; }
    tcm_msg_version(int val) {
        if (val) {
            uint64_t v = tcm_get_version();
            major      = TCM_MAJOR(v);
            minor      = TCM_MINOR(v);
            patch      = TCM_PATCH(v);
        } else {
            major = 0;
            minor = 0;
            patch = 0;
        }
    }
};

struct tcm_msg_ext_header {
    struct tcm_msg_header  hdr;
    struct tcm_msg_version ver;
};

/* -------------------------- Message Definitions -------------------------- */

/* Client ping and server ping should ideally never change - the peers should
   know whether the TCM versions match using these two stable messages */

struct tcm_msg_client_ping {
    struct tcm_msg_header  common;
    struct tcm_msg_version version;
    int8_t                 val; // client ping -> value -1
    tcm_msg_client_ping() { return; }
    tcm_msg_client_ping(tcm_token token_) {
        common  = tcm_msg_header(TCM_MSG_CLIENT_PING, token_);
        version = tcm_msg_version(1);
        val     = -1;
    }
};

struct tcm_msg_server_ping {
    struct tcm_msg_header  common;
    struct tcm_msg_version version;
    /* Whether the server is busy servicing another client - if so don't submit
     * a connection request */
    int8_t                 busy;
    tcm_msg_server_ping() { return; }
    tcm_msg_server_ping(tcm_token token_, bool busy_) {
        common  = tcm_msg_header(TCM_MSG_SERVER_PING, token_);
        version = tcm_msg_version(1);
        busy    = busy_;
    }
};

/* The below messages may change at any time */

struct tcm_msg_return_value {
    struct tcm_msg_header  common;
    struct tcm_msg_version version;
    tcm_retcode            retcode;
};

struct tcm_msg_metadata_req {
    struct tcm_msg_header  common;
    struct tcm_msg_version version;
    uint8_t                pad[16];
    tcm_msg_metadata_req(uint16_t token_) {
        common  = tcm_msg_header(TCM_MSG_METADATA_REQ, token_);
        version = tcm_msg_version(1);
        for (int i = 0; i < 16; i++) {
            pad[i] = i;
        }
    }
};

struct tcm_msg_metadata_resp {
    struct tcm_msg_header  common;
    struct tcm_msg_version version;
    uint32_t               fabric_min;
    uint32_t               fabric_max;
    tcm_addr_fmt           addr_fmt;
    tcm_tid                tids;
    tcm_msg_metadata_resp(uint32_t fabric_min_, uint32_t fabric_max_,
                          tcm_addr_fmt addr_fmt_, tcm_tid tids_,
                          tcm_token token_) {
        common     = tcm_msg_header(TCM_MSG_METADATA_RESP, token_);
        version    = tcm_msg_version(1);
        fabric_max = fabric_max_;
        fabric_min = fabric_min_;
        addr_fmt   = addr_fmt_;
        tids       = tids_;
    }
};

struct tcm_msg_status {
    struct tcm_msg_header  common;
    struct tcm_msg_version version;
    uint16_t               retcode;
    tcm_msg_status() { return; }
    tcm_msg_status(uint16_t token, uint16_t retcode) {
        common  = tcm_msg_header(TCM_MSG_STATUS, token);
        version = tcm_msg_version(1);
        retcode = retcode;
    }
};

struct tcm_msg_conn_req {
    struct tcm_msg_header  common;
    struct tcm_msg_version version;
    uint32_t               fabric_version; // Libfabric version
    tcm_tid                tid;            // Transport ID
    tcm_addr_fmt           addr_fmt;       // Address format
    uint16_t               addr_len;       // Address length
    uint8_t                addr[0];        // Variable length address data
};

struct tcm_msg_conn_resp {
    struct tcm_msg_header  common;
    struct tcm_msg_version version;
    /* Transport ID (field of supported IDs if request could not be satisfied)
     */
    tcm_tid                tid;
    /* Address format (TCM_AF_INVALID if request could not be satisfied) */
    tcm_addr_fmt           addr_fmt;
    /* Address length (0 if request could not be satisfied) */
    uint16_t               addr_len;
    uint8_t                addr[0];
};

struct tcm_msg_conn_req_ipv4 {
    struct tcm_msg_conn_req cr;
    struct tcm_addr_inet    addr;
    tcm_msg_conn_req_ipv4() { return; }
    tcm_msg_conn_req_ipv4(uint16_t token_, struct sockaddr_in * addr_,
                          uint32_t fabric_version_, uint16_t tid_) {
        cr.common         = tcm_msg_header(TCM_MSG_CONN_REQ, token_);
        cr.version        = tcm_msg_version(1);
        cr.fabric_version = fabric_version_;
        cr.addr_fmt       = TCM_AF_INET;
        cr.addr_len       = sizeof(tcm_addr_inet);
        cr.tid            = tid_;
        addr = tcm_addr_inet(addr_->sin_addr.s_addr, addr_->sin_port);
    }
};

struct tcm_msg_conn_resp_ipv4 {
    struct tcm_msg_conn_resp cr;
    tcm_addr_inet            addr;
    tcm_msg_conn_resp_ipv4();
    tcm_msg_conn_resp_ipv4(uint16_t token_, uint16_t tid_,
                           sockaddr_in * addr_) {
        cr.common   = tcm_msg_header(TCM_MSG_CONN_RESP, token_);
        cr.version  = tcm_msg_version(1);
        cr.addr_fmt = TCM_AF_INET;
        cr.tid      = tid_;
        if (addr_) {
            cr.addr_len = sizeof(struct tcm_addr_inet);
            addr = tcm_addr_inet(addr_->sin_addr.s_addr, addr_->sin_port);
        } else {
            cr.addr_len = 0;
            addr        = tcm_addr_inet(0, 0);
        }
    }
};

struct tcm_msg_fabric_ping {
    struct tcm_msg_header  common;
    struct tcm_msg_version version;
    uint8_t                direction;
    tcm_msg_fabric_ping() { return; }
    tcm_msg_fabric_ping(uint16_t token_, uint8_t direction_) {
        common    = tcm_msg_header(TCM_MSG_FABRIC_PING, token_);
        version   = tcm_msg_version(1);
        direction = direction_;
    }
};

union tcm_msg_container {
    struct tcm_msg_client_ping    u1;
    struct tcm_msg_server_ping    u2;
    struct tcm_msg_status         u3;
    struct tcm_msg_metadata_req   u4;
    struct tcm_msg_metadata_resp  u5;
    struct tcm_msg_conn_req_ipv4  u6;
    struct tcm_msg_conn_resp_ipv4 u7;
    struct tcm_msg_fabric_ping    u8;
};

#define TCM_LARGEST_MESSAGE_SIZE sizeof(tcm_msg_container)

#pragma pack(pop)

namespace tcm_mv {

enum : tcm_mv_result {
    VALID = 0,
    INVALID_TYPE,
    UNEXPECTED_TYPE,
    INVALID_SIZE,
    INVALID_MAGIC,
    INVALID_TRANSPORT,
    UNEXPECTED_TRANSPORT,
    INVALID_TOKEN,
    UNEXPECTED_TOKEN,
    INVALID_VERSION,
    UNEXPECTED_VERSION,
    INVALID_ADDRESS_LENGTH,
    INVALID_ADDRESS_FORMAT,
    UNEXPECTED_ADDRESS_FORMAT,
    INVALID_CONTENTS,
    USER_ERROR,
    MAX
};

const char * stringify(tcm_mv_result res);

} // namespace tcm_mv

int tcm_msg_check_version(tcm_msg_version * ver);

/**
 * @brief Verify the contents of a message.
 *
 * This function only verifies that the message is a valid TCM message, but does
 * not validate whether, for example, the requested transport is supported by
 * the system, only that it is well-known.
 *
 * @param msg       TCM message
 * @param msize     Message size
 * @param token     Token (optional for validation, ignored if 0)
 * @param type      Flags of the allowed message types
 * @return tcm_mv_result
 */
tcm_mv_result tcm_msg_verify(void * msg, size_t msize, uint16_t token,
                             tcm_msg_type_flag type);

#endif
