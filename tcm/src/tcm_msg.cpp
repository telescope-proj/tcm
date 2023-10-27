// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#include "tcm_msg.h"
#include "tcm_log.h"

int tcm_msg_check_version(tcm_msg_version * ver) {
    return ver->major == TCM_VERSION_MAJOR && ver->minor == TCM_VERSION_MINOR &&
           ver->patch == TCM_VERSION_PATCH;
}

int tcm_msg_verify(void * msg, size_t msize, uint16_t token,
                   tcm_msg_type type) {
    if (!msg || !msize) {
        tcm__log_trace("Programming error: message/message size not provided");
        return -EINVAL;
    }
    tcm_msg_ext_header * hdr = (tcm_msg_ext_header *) msg;
    if (msize < sizeof(tcm_msg_header)) {
        tcm__log_trace("Message size %d invalid", msize);
        return -ENOBUFS;
    }
    if (hdr->hdr.id < 2 || hdr->hdr.id >= TCM_MSG_MAX) {
        tcm__log_trace("Unknown message type %d", hdr->hdr.id);
        return -EBADMSG;
    }
    if (hdr->hdr.id != type) {
        tcm__log_trace("Unexpected message type %d (exp. %d)", hdr->hdr.id,
                       type);
        return -EBADF;
    }
    if (hdr->hdr.magic != TCM_MAGIC) {
        tcm__log_trace("Invalid header magic number %d (exp. %d)",
                       hdr->hdr.magic, TCM_MAGIC);
        return -EBADMSG;
    }
    if (token && hdr->hdr.token != token) {
        tcm__log_trace("Unexpected token %d (exp. %d)", hdr->hdr.token, token);
        return -EBADMSG;
    }
    switch (hdr->hdr.id) {
        case TCM_MSG_CLIENT_PING:
        case TCM_MSG_SERVER_STATUS:
        case TCM_MSG_CONN_REQ:
            if (!tcm_msg_check_version(&hdr->ver)) {
                tcm__log_trace(
                    "Version mismatch (peer: %d.%d.%d, local: %d.%d.%d)",
                    hdr->ver.major, hdr->ver.minor, hdr->ver.patch,
                    TCM_VERSION_MAJOR, TCM_VERSION_MINOR, TCM_VERSION_PATCH);
                return -ENOTSUP;
            }
        default:
            break;
    }
    switch (hdr->hdr.id) {
        /* Fixed-length messages */
        case TCM_MSG_CLIENT_PING:
            return msize == sizeof(tcm_msg_client_ping) ? 1 : -EMSGSIZE;
        case TCM_MSG_SERVER_STATUS:
            return msize == sizeof(tcm_msg_server_status) ? 1 : -EMSGSIZE;
        case TCM_MSG_FABRIC_PING:
            return msize == sizeof(tcm_msg_fabric_ping) ? 1 : -EMSGSIZE;

        /* Fixed-length for now */
        case TCM_MSG_CONN_REQ:
            return msize == sizeof(tcm_msg_conn_req_ipv4) ? 1 : -EMSGSIZE;
        case TCM_MSG_CONN_RESP:
            return msize == sizeof(tcm_msg_conn_resp_ipv4) ? 1 : -EMSGSIZE;

        default:
            return -EBADMSG;
    }
}