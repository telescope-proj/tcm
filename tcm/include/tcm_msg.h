// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#ifndef TCM_MSG_H_
#define TCM_MSG_H_

#include <stdint.h>

#include "tcm_comm.h"
#include "tcm_version.h"

typedef enum { TCM_AF_INVALID, TCM_AF_INET = 1, TCM_AF_MAX } tcm_addr_format;

typedef enum {
    TCM_MSG_INVALID       = 0,
    TCM_MSG_ANY           = 1,
    TCM_MSG_CLIENT_PING   = 2,
    TCM_MSG_SERVER_STATUS = 3,
    TCM_MSG_METADATA_REQ  = 4,
    TCM_MSG_METADATA_RESP = 5,
    TCM_MSG_CONN_REQ      = 6,
    TCM_MSG_CONN_RESP     = 7,
    TCM_MSG_FABRIC_PING   = 8,
    TCM_MSG_MAX
} tcm_msg_type;

typedef enum {
    TCM_TID_INVALID,
    TCM_TID_TCP_RXM   = 1,
    TCM_TID_VERBS_RXM = 2,
    TCM_TID_MAX
} tcm_transport_id;

static inline int prov_name_to_id(char * prov_name) {
    if (strncmp("verbs;ofi_rxm", prov_name, 13) == 0 ||
        strncmp("ofi_rxm;verbs", prov_name, 13) == 0)
        return TCM_TID_VERBS_RXM;
    if (strncmp("tcp;ofi_rxm", prov_name, 11) == 0 ||
        strncmp("ofi_rxm;tcp", prov_name, 11) == 0)
        return TCM_TID_TCP_RXM;
    return -EINVAL;
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

/* ----------------------------- Common Items ----------------------------- */

struct tcm_msg_header {
    uint32_t magic;
    uint16_t id;
    uint16_t token;
    tcm_msg_header() { return; }
    tcm_msg_header(uint16_t id, uint16_t token) {
        this->magic = TCM_MAGIC;
        this->id    = id;
        this->token = token;
    }
};

struct tcm_msg_version {
    uint16_t major;
    uint16_t minor;
    uint16_t patch;
    tcm_msg_version() { return; }
    tcm_msg_version(int val) {
        if (val) {
            major = TCM_VERSION_MAJOR;
            minor = TCM_VERSION_MINOR;
            patch = TCM_VERSION_PATCH;
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

struct tcm_msg_client_ping {
    struct tcm_msg_header  common;
    struct tcm_msg_version version;
    tcm_msg_client_ping();
    tcm_msg_client_ping(uint16_t token) {
        common  = tcm_msg_header(TCM_MSG_CLIENT_PING, token);
        version = tcm_msg_version(1);
    }
};

struct tcm_msg_server_status {
    struct tcm_msg_header  common;
    struct tcm_msg_version version;
    uint16_t               retcode;
    tcm_msg_server_status();
    tcm_msg_server_status(uint16_t token, uint16_t retcode) {
        common  = tcm_msg_header(TCM_MSG_SERVER_STATUS, token);
        version = tcm_msg_version(1);
        retcode = retcode;
    }
};

struct tcm_msg_conn_req {
    struct tcm_msg_header  common;
    struct tcm_msg_version version;
    uint16_t               fabric_major;
    uint16_t               fabric_minor;
    uint16_t               tid;
    uint16_t               addr_fmt;
    uint16_t               addr_len;
    uint16_t               cid;
    uint8_t                addr[0];
};

struct tcm_msg_conn_resp {
    struct tcm_msg_header common;
    uint16_t              addr_len;
    uint8_t               addr[0];
};

struct tcm_msg_conn_req_ipv4 {
    struct tcm_msg_conn_req cr;
    struct tcm_addr_inet    addr;
    tcm_msg_conn_req_ipv4() { return; }
    tcm_msg_conn_req_ipv4(uint16_t token, struct sockaddr_in * addr_,
                          uint32_t fabric_version, uint16_t transport_id,
                          uint16_t channel_id) {
        cr.common       = tcm_msg_header(TCM_MSG_CONN_REQ, token);
        cr.version      = tcm_msg_version(1);
        cr.fabric_major = FI_MAJOR(fabric_version);
        cr.fabric_minor = FI_MINOR(fabric_version);
        cr.addr_fmt     = TCM_AF_INET;
        cr.addr_len     = sizeof(struct tcm_addr_inet);
        cr.cid          = channel_id;
        cr.tid          = transport_id;
        addr = tcm_addr_inet(addr_->sin_addr.s_addr, addr_->sin_port);
    }
};

struct tcm_msg_conn_resp_ipv4 {
    struct tcm_msg_conn_resp cr;
    tcm_addr_inet            addr;
    tcm_msg_conn_resp_ipv4();
    tcm_msg_conn_resp_ipv4(uint16_t token_, struct sockaddr_in * addr_) {
        cr.common   = tcm_msg_header(TCM_MSG_CONN_RESP, token_);
        cr.addr_len = sizeof(struct tcm_addr_inet);
        addr        = tcm_addr_inet(addr_->sin_addr.s_addr, addr_->sin_port);
    }
};

struct tcm_msg_fabric_ping {
    struct tcm_msg_header common;
    uint16_t              direction;
    tcm_msg_fabric_ping();
    tcm_msg_fabric_ping(uint16_t token_, uint16_t direction_) {
        common    = tcm_msg_header(TCM_MSG_FABRIC_PING, token_);
        direction = direction_;
    }
};

#pragma pack(pop)

int tcm_msg_check_version(tcm_msg_version * ver);
int tcm_msg_verify(void * msg, size_t msize, uint16_t token, tcm_msg_type type);

#endif
