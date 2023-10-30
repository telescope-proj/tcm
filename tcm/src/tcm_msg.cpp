// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#include "tcm_msg.h"
#include "tcm_log.h"
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
        case TCM_MSG_CLIENT_PING:
            exp_size = sizeof(tcm_msg_client_ping);
            break;
        case TCM_MSG_SERVER_PING:
            exp_size = sizeof(tcm_msg_server_ping);
            break;
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