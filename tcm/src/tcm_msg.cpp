// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#include "tcm_msg.h"
#include "tcm_log.h"
#include "tcm_util.h"
#include <assert.h>
namespace tcm_mv {

static const char * strs[] = {"Valid",
                              "Invalid message type",
                              "Unexpected message type",
                              "Invalid message size",
                              "Invalid magic number",
                              "Invalid transport ID",
                              "Unexpected/unsupported transport",
                              "Invalid token",
                              "Unexpected token",
                              "Invalid version",
                              "Unexpected version",
                              "Invalid address length",
                              "Invalid address format",
                              "Unexpected address format",
                              "Invalid message contents",
                              "Programming error"};

const char * stringify(tcm_mv_result res) {
    assert(res >= VALID);
    assert(res <= MAX);
    return strs[res];
}

} // namespace tcm_mv

int tcm_msg_check_version(tcm_msg_version * ver) {
    uint64_t current = tcm_get_version();
    return ver->major == TCM_MAJOR(current) &&
           ver->minor == TCM_MINOR(current) && ver->patch == TCM_PATCH(current);
}

tcm_mv_result tcm_msg_verify(void * msg, size_t msize, uint16_t token,
                             tcm_msg_type_flag allowed_types) {

    /* Programming error checks */

    if (!msg) {
        tcm__log_trace("Programming error: message not provided");
        return tcm_mv::USER_ERROR;
    }
    if (allowed_types & TCM_MFLAG_INVALID_BITS) {
        tcm__log_trace("Programming error: invalid flag bits set");
        return tcm_mv::USER_ERROR;
    }

    /* Common message header checks */

    tcm_msg_ext_header * hdr = reinterpret_cast<tcm_msg_ext_header *>(msg);
    if (msize < sizeof(tcm_msg_header)) {
        tcm__log_trace("Message size %d invalid", msize);
        return tcm_mv::INVALID_SIZE;
    }
    if (hdr->hdr.magic != TCM_MAGIC) {
        tcm__log_trace("Invalid header magic number %d (exp. %d)",
                       hdr->hdr.magic, TCM_MAGIC);
        return tcm_mv::INVALID_MAGIC;
    }
    if (!hdr->hdr.type || hdr->hdr.type >= TCM_MSG_MAX) {
        tcm__log_trace("Unknown message type %d", hdr->hdr.type);
        return tcm_mv::INVALID_TYPE;
    }
    if ((allowed_types & tcm_msg_type_to_flag(hdr->hdr.type)) == 0) {
        tcm__log_trace("Unexpected message type %d", hdr->hdr.type);
        return tcm_mv::UNEXPECTED_TYPE;
    }
    if (token && hdr->hdr.token != token) {
        tcm__log_trace("Unexpected token %d (exp. %d)", hdr->hdr.token, token);
        return tcm_mv::INVALID_TOKEN;
    }
    if (!tcm_msg_check_version(&hdr->ver)) {
        tcm__log_trace("Version mismatch (peer: %d.%d.%d, local: %d.%d.%d)",
                       hdr->ver.major, hdr->ver.minor, hdr->ver.patch,
                       TCM_VERSION_MAJOR, TCM_VERSION_MINOR, TCM_VERSION_PATCH);
        return tcm_mv::UNEXPECTED_VERSION;
    }

    /* Message-specific checks */

    size_t exp_size = 0;
    switch (hdr->hdr.type) {

        /* Fixed-length messages */
        case TCM_MSG_CLIENT_PING: {
            if (msize > sizeof(tcm_msg_client_ping) ||
                msize <= sizeof(tcm_msg_client_ping) + TCM_MAX_PRV_DATA_SIZE) {
                return tcm_mv::VALID;
            }
            return tcm_mv::INVALID_SIZE;
        }
        case TCM_MSG_SERVER_PING: {
            if (msize > sizeof(tcm_msg_server_ping) ||
                msize <= sizeof(tcm_msg_server_ping) + TCM_MAX_PRV_DATA_SIZE) {
                return tcm_mv::VALID;
            }
            return tcm_mv::INVALID_SIZE;
            break;
        }
        case TCM_MSG_STATUS:
            exp_size = sizeof(tcm_msg_status);
            break;
        case TCM_MSG_METADATA_RESP:
            exp_size = sizeof(tcm_msg_metadata_resp);
            break;

        /* Fixed-length messages with extra validity checks */
        case TCM_MSG_FABRIC_PING:
            if (msize == sizeof(tcm_msg_fabric_ping)) {
                tcm_msg_fabric_ping * ping =
                    reinterpret_cast<tcm_msg_fabric_ping *>(msg);
                if (ping->direction > 1)
                    return tcm_mv::INVALID_CONTENTS;
                return tcm_mv::VALID;
            }
            return tcm_mv::INVALID_SIZE;
            break;
        case TCM_MSG_METADATA_REQ:
            if (msize == sizeof(tcm_msg_metadata_req)) {
                tcm_msg_metadata_req * req =
                    reinterpret_cast<tcm_msg_metadata_req *>(msg);
                for (int i = 0; i < 16; i++) {
                    if (req->pad[i] != i)
                        return tcm_mv::INVALID_CONTENTS;
                }
                return tcm_mv::VALID;
            }
            return tcm_mv::INVALID_SIZE;

        /* Variable-length messages */
        case TCM_MSG_CONN_REQ: {
            tcm_msg_conn_req * req = static_cast<tcm_msg_conn_req *>(msg);
            if (tcm_internal::popcnt8(req->tid) != 1)
                return tcm_mv::UNEXPECTED_TRANSPORT;
            switch (req->addr_fmt) {
                case TCM_AF_INET:
                    if (req->addr_len != sizeof(tcm_addr_inet))
                        return tcm_mv::INVALID_ADDRESS_LENGTH;
                    exp_size = sizeof(tcm_msg_conn_req) + sizeof(tcm_addr_inet);
                    break;
                default:
                    return tcm_mv::INVALID_ADDRESS_FORMAT;
            }
            break;
        }
        case TCM_MSG_CONN_RESP: {
            tcm_msg_conn_resp * resp = static_cast<tcm_msg_conn_resp *>(msg);
            switch (resp->addr_fmt) {
                case TCM_AF_INET:
                    if (resp->addr_len != sizeof(tcm_addr_inet))
                        return tcm_mv::INVALID_ADDRESS_LENGTH;
                    exp_size =
                        sizeof(tcm_msg_conn_resp) + sizeof(tcm_addr_inet);
                    break;
                default:
                    return tcm_mv::INVALID_ADDRESS_FORMAT;
            }
            break;
        }

        /* Invalid */
        default:
            return tcm_mv::INVALID_TYPE;
    }

    if (msize == exp_size)
        return tcm_mv::VALID;
    return tcm_mv::INVALID_SIZE;
}

int tcm_serialize_addr(sockaddr * addr, void * buf, tcm_addr_fmt * out_fmt,
                       size_t * buf_size) {
    assert(addr);
    assert(buf);
    assert(buf_size);
    switch (addr->sa_family) {
        case AF_INET: {
            *out_fmt = TCM_AF_INET;
            if (*buf_size < sizeof(tcm_addr_inet)) {
                *buf_size = sizeof(tcm_addr_inet);
                return -ENOBUFS;
            }
            *buf_size        = sizeof(tcm_addr_inet);
            sockaddr_in * sa = (sockaddr_in *) addr;
            tcm_addr_inet ai(sa->sin_addr.s_addr, sa->sin_port);
            memcpy(buf, &ai, sizeof(ai));
            return 0;
        }
        case AF_INET6: {
            *out_fmt = TCM_AF_INET6;
            if (*buf_size < sizeof(tcm_addr_inet6)) {
                *buf_size = sizeof(tcm_addr_inet6);
                return -ENOBUFS;
            }
            *buf_size         = sizeof(tcm_addr_inet6);
            sockaddr_in6 * sa = (sockaddr_in6 *) addr;
            tcm_addr_inet6 ai(&sa->sin6_addr, sa->sin6_port);
            memcpy(buf, &ai, sizeof(ai));
            return 0;
        }
        case AF_IB: {
            *out_fmt = TCM_AF_IB;
            if (*buf_size < sizeof(tcm_addr_ib)) {
                *buf_size = sizeof(tcm_addr_ib);
                return -ENOBUFS;
            }
            *buf_size        = sizeof(tcm_addr_ib);
            sockaddr_ib * sa = (sockaddr_ib *) addr;
            tcm_addr_ib   ai(&sa->sib_addr, sa->sib_pkey);
            memcpy(buf, &ai, sizeof(ai));
            return 0;
        }
        default:
            return -EINVAL;
    }
}

int tcm_deserialize_addr(void * addr, int addr_len, uint32_t addr_fmt,
                         void * out_buf, size_t * buf_size) {
    if (!addr || !addr_len || !out_buf || !buf_size || !*buf_size)
        return -EINVAL;

    switch (addr_fmt) {
        case TCM_AF_INET: {
            if (*buf_size < sizeof(sockaddr_in)) {
                *buf_size = sizeof(sockaddr_in);
                return -ENOBUFS;
            }
            sockaddr_in *   sa   = (sockaddr_in *) out_buf;
            tcm_addr_inet * inet = (tcm_addr_inet *) addr;
            memset(sa, 0, sizeof(*sa));
            sa->sin_family      = AF_INET;
            sa->sin_addr.s_addr = inet->addr;
            sa->sin_port        = inet->port;
            *buf_size           = sizeof(sockaddr_in);
            return FI_SOCKADDR_IN;
        }
        case TCM_AF_INET6: {
            if (*buf_size < sizeof(sockaddr_in)) {
                *buf_size = sizeof(sockaddr_in);
                return -ENOBUFS;
            }
            sockaddr_in6 *   sa   = (sockaddr_in6 *) out_buf;
            tcm_addr_inet6 * inet = (tcm_addr_inet6 *) addr;
            memset(sa, 0, sizeof(*sa));
            sa->sin6_family = AF_INET6;
            memcpy(&sa->sin6_addr, inet->addr, sizeof(inet->addr));
            sa->sin6_port = inet->port;
            *buf_size     = sizeof(sockaddr_in6);
            return FI_SOCKADDR_IN6;
        }
        case TCM_AF_IB: {
            if (*buf_size < sizeof(sockaddr_ib)) {
                *buf_size = sizeof(sockaddr_ib);
                return -ENOBUFS;
            }
            sockaddr_ib * sa   = (sockaddr_ib *) out_buf;
            tcm_addr_ib * inet = (tcm_addr_ib *) addr;
            memset(sa, 0, sizeof(*sa));
            sa->sib_family = AF_IB;
            memcpy(&sa->sib_addr, inet->addr, sizeof(inet->addr));
            sa->sib_pkey = inet->pkey;
            *buf_size    = sizeof(sockaddr_ib);
            return FI_SOCKADDR_IB;
        }
        default:
            return -EINVAL;
    }
}

namespace tcm_internal {

tcm_addr_fmt fabric_to_tcm_af(uint32_t af) {
    switch (af) {
        case FI_SOCKADDR_IN:
            return TCM_AF_INET;
        case FI_SOCKADDR_IN6:
            return TCM_AF_INET6;
        case FI_SOCKADDR_IB:
            return TCM_AF_IB;
        default:
            return TCM_AF_INVALID;
    }
}

uint32_t tcm_to_fabric_af(tcm_addr_fmt af) {
    switch (af) {
        case TCM_AF_INET:
            return FI_SOCKADDR_IN;
        case TCM_AF_INET6:
            return FI_SOCKADDR_IN6;
        case TCM_AF_IB:
            return FI_SOCKADDR_IB;
        default:
            return FI_FORMAT_UNSPEC;
    }
}

tcm_tid prov_name_to_tid(char * prov_name) {
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

char * tid_to_prov_name(tcm_tid id) {
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

const char * tid_to_prov_name_static(tcm_tid id) {
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

tcm_addr_fmt sys_to_tcm_af(int af) {
    switch (af) {
        case AF_INET:
            return TCM_AF_INET;
        case AF_INET6:
            return TCM_AF_INET6;
        case AF_IB:
            return TCM_AF_IB;
        default:
            return TCM_AF_INVALID;
    }
}

} // namespace tcm_internal