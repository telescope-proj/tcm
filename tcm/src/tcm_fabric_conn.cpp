// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#include "tcm_errno.h"
#include "tcm_fabric.h"
#include "tcm_log.h"

enum { OP_MODE_SERVER = 1, OP_MODE_CLIENT = 2 };

int tcm_fabric::accept_client(tcm_beacon & beacon, struct sockaddr * peer,
                              fi_addr_t * addr) {
    struct sockaddr_in * sin = (struct sockaddr_in *) peer;
    int                  ret;

    if (sin && sin->sin_family == AF_INET) {
        ret = beacon.set_peer(peer);
        if (ret < 0)
            tcm__log_warn("Failed to set peer address - handshake might fail");
    }

    tcm__log_trace("Set peer address");
    uint16_t                     token;
    struct sockaddr_in           p;
    struct tcm_msg_conn_req_ipv4 cr;
    memset((void *) &cr, 0, sizeof(cr));
    memset((void *) &p, 0, sizeof(p));
    ret = (int) beacon.recv_dgram((sockaddr *) &p, (void *) &cr, sizeof(cr));
    if (ret < 0) {
        tcm__log_warn("Datagram receive failed: %s", strerror(-ret));
        return ret;
    }
    token = cr.cr.common.token;

    /* Add the peer */
    if (!sin) {
        int ret2 = beacon.set_peer((sockaddr *) &p);
        if (ret2 < 0)
            tcm__log_warn("Failed to set peer address - handshake might fail");
    }

    /* Check the received message */
    ret = tcm_msg_verify(&cr, (size_t) ret, 0, TCM_MSG_CONN_REQ);
    if (ret < 1) {
        tcm__log_debug("Client sent invalid data (err %d)", ret);
        return ret;
    }
    if (cr.cr.addr_fmt != TCM_AF_INET) {
        tcm__log_error(
            "This version of TCM only supports the AF_INET address family");
        ret = -TCM_ERR_INVALID_ADDRESS;
        goto reject;
    }
    if ((uint32_t) (FI_VERSION(cr.cr.fabric_major, cr.cr.fabric_minor)) !=
        this->fabric_version) {
        tcm__log_error("Libfabric version mismatch");
        tcm__log_error("This: %d.%d, Peer: %d.%d",
                       FI_MAJOR(this->fabric_version),
                       FI_MINOR(this->fabric_version), cr.cr.fabric_major,
                       cr.cr.fabric_minor);
        ret = -TCM_ERR_INVALID_FABRIC_VER;
        goto reject;
    }

    /* Add peer to fabric */
    tcm__log_debug("Attempting to add peer to fabric");
    struct sockaddr_in fpeer;
    memset(&fpeer, 0, sizeof(fpeer));
    fpeer.sin_family      = AF_INET;
    fpeer.sin_addr.s_addr = cr.addr.addr;
    fpeer.sin_port        = cr.addr.port;
    *addr                 = this->add_peer((struct sockaddr *) &fpeer);
    if (*addr == FI_ADDR_UNSPEC) {
        tcm__log_error("Failed to add peer address to fabric");
        ret = -ECOMM;
        goto reject;
    }

    {
        /* Send confirmation over beacon */
        tcm__log_debug("Address added, sending own address");
        struct tcm_msg_conn_resp_ipv4 cr(cr.cr.common.token,
                                         (struct sockaddr_in *) this->src_addr);
        ret =
            (int) beacon.send_dgram((sockaddr *) &p, (void *) &cr, sizeof(cr));
        if (ret < 0)
            return ret;

        /* Wait for fabric response */
        auto                  mem  = tcm_mem(this->shared_from_this(), 4096);
        tcm_msg_fabric_ping * ping = (tcm_msg_fabric_ping *) mem.get_ptr();
        ssize_t               l    = this->srecv(mem, *addr, 0, sizeof(*ping));
        if (l < 0) {
            tcm__log_error("Failed to queue recv: %s", fi_strerror(-l));
            ret = -ECOMM;
            goto reject;
        }

        if (!tcm_msg_verify(mem.get_ptr(), sizeof(*ping), 0,
                            TCM_MSG_FABRIC_PING) ||
            ping->direction != 0) {
            tcm__log_debug("Client sent invalid data");
            ret = -ECOMM;
            goto reject;
        }

        ping->direction = 1;
        l               = this->ssend(mem, *addr, 0, sizeof(*ping));
        if (l < 0) {
            tcm__log_error("Failed to queue send: %s", fi_strerror(-l));
            ret = -ECOMM;
            goto reject;
        }
    }

    this->op_mode = OP_MODE_SERVER;
    return (int) cr.cr.cid;

reject:
    if (*addr != FI_ADDR_UNSPEC) {
        this->remove_peer(*addr);
        *addr = FI_ADDR_UNSPEC;
    }

    if (ret == -EBADMSG)
        return ret;

    struct tcm_msg_server_status stat(token, tcm_abs(ret));
    int r2 = beacon.send_dgram((sockaddr *) &p, &stat, sizeof(stat));
    if (r2 < 0)
        tcm__log_error("Failed to send connection rejection: %s",
                       strerror(errno));

    return ret;
}

int tcm_fabric::client(tcm_beacon & beacon, struct sockaddr * peer,
                       fi_addr_t * addr, uint16_t cid) {
    struct sockaddr_in * sin = (struct sockaddr_in *) peer;
    int                  ret;

    if (sin && sin->sin_family == AF_INET) {
        ret = beacon.set_peer(peer);
        if (ret < 0)
            tcm__log_warn("Failed to set peer address - handshake might fail");
    }

    struct sockaddr_in * f_addr = (struct sockaddr_in *) this->src_addr;
    if (!f_addr)
        throw EINVAL;

    struct tcm_msg_conn_req_ipv4 cr(0x1234, f_addr, this->fabric_version,
                                    this->transport_id, cid);

    ssize_t l = beacon.send_dgram(peer, (void *) &cr, sizeof(cr));
    if (l < 0) {
        tcm__log_error("Failed to send datagram");
        return -ECOMM;
    }

    memset((void *) &cr, 0, sizeof(cr));
    l = beacon.recv_dgram(peer, (void *) &cr, sizeof(cr));
    if (l < 0) {
        tcm__log_error("Failed to receive datagram");
        return -ECOMM;
    }

    if (cr.cr.common.id != TCM_MSG_SERVER_STATUS &&
        cr.cr.common.id != TCM_MSG_CONN_RESP) {
        tcm__log_error("Unexpected message type %d", cr.cr.common.id);
    }

    ret = tcm_msg_verify(&cr, (size_t) l, 0, (tcm_msg_type) cr.cr.common.id);
    if (ret < 1) {
        tcm__log_error("Invalid data received: %d", ret);
        return ret == 0 ? -ECOMM : ret;
    }

    fi_addr_t faddr = FI_ADDR_UNSPEC;

    if (cr.cr.common.id == TCM_MSG_SERVER_STATUS) {
        tcm_msg_server_status * stat = (tcm_msg_server_status *) &cr;
        if (stat->retcode != 0) {
            tcm__log_error("Peer rejected connection: %s",
                           stat->retcode >= TCM_ERR_UNSPECIFIED
                               ? tcm_err_string(stat->retcode)
                               : fi_strerror(stat->retcode));
            return -ECONNREFUSED;
        }
    } else {
        tcm_msg_conn_resp_ipv4 * resp = (tcm_msg_conn_resp_ipv4 *) &cr;
        struct sockaddr_in       in;
        memset(&in, 0, sizeof(in));
        in.sin_family      = AF_INET;
        in.sin_addr.s_addr = resp->addr.addr;
        in.sin_port        = resp->addr.port;
        faddr              = this->add_peer((struct sockaddr *) &in);
        if (faddr == FI_ADDR_UNSPEC) {
            tcm__log_error("Failed to add peer address: %s", strerror(errno));
            return errno == 0 ? -ECOMM : -errno;
        }
    }

    auto     mem = tcm_mem(this->shared_from_this(), 4096);
    uint64_t pl  = sizeof(tcm_msg_fabric_ping);

    tcm_msg_fabric_ping * ping = (tcm_msg_fabric_ping *) mem.get_ptr();
    ping->common.id            = TCM_MSG_FABRIC_PING;
    ping->common.magic         = TCM_MAGIC;
    ping->common.token         = 0x2345;
    ping->direction            = 0;

    struct fi_cq_err_entry err;
    tcm_msg_fabric_ping *  resp = (ping + 1);
    memset((void *) resp, 0, pl);

    ret = this->recv(mem, faddr, 0, pl, pl);
    if (ret < 0) {
        tcm__log_error("Failed to queue recv: %d", ret);
        return -ECOMM;
    }

    ret = this->send(mem, faddr, 0, 0, pl);
    if (ret < 0) {
        tcm__log_error("Failed to queue send: %d", ret);
        return -ECOMM;
    }

    ret = this->poll_tx(&err);
    if (ret < 0) {
        tcm__log_error("Failed to poll TX queue: %d", ret);
        return -ECOMM;
    }

    ret = this->poll_rx(&err);
    if (ret < 0) {
        tcm__log_error("Failed to poll RX queue: %d", ret);
        return -ECOMM;
    }

    ret = tcm_msg_verify(resp, pl, 0x2345, TCM_MSG_FABRIC_PING);
    if (ret < 1) {
        tcm__log_error("Invalid data received: %d", ret);
        return ret == 0 ? -ECOMM : ret;
    }

    *addr         = faddr;
    this->op_mode = OP_MODE_CLIENT;
    return 0;
}

std::shared_ptr<tcm_fabric> tcm_fabric::split_conn(fi_addr_t   peer,
                                                   uint16_t    port,
                                                   uint8_t     shared,
                                                   fi_addr_t * new_peer) {
    if (peer == FI_ADDR_UNSPEC)
        throw EINVAL;

    auto mem = tcm_mem(this->shared_from_this(), 4096);

    if (this->addr_fmt != FI_SOCKADDR_IN)
        throw EPFNOSUPPORT;
    if (!this->src_addr || this->src_addrlen != sizeof(struct sockaddr_in))
        throw EINVAL;

    struct sockaddr_in addr = *(struct sockaddr_in *) this->src_addr;
    addr.sin_port           = port;

    std::shared_ptr<tcm_fabric> f2;

    /* A shared tcm_fabric object shares the top-level libfabric fabric and
     * domain objects with other tcm_fabric objects. This is more efficient and
     * allows for features like wait sets across tcm_fabric objects */

    if (shared) {
        tcm_fabric_child_opts opts = {
            .fi = this->top, .port = 0, .timeout = &this->timeout};

        f2 = std::make_shared<tcm_fabric>(opts, this);
    } else {
        tcm_fabric_init_opts opts = {.version = this->fabric_version,
                                     .flags   = this->fabric_flags,
                                     .hints   = fi_dupinfo(this->fi),
                                     .timeout = &this->timeout};

        opts.hints->src_addr = &addr;
        f2                   = std::make_shared<tcm_fabric>(opts);
        opts.hints->src_addr = 0;
        fi_freeinfo(opts.hints);
    }

    int       ret;
    fi_addr_t peer2;

    struct sockaddr_in f2_addr;
    size_t             f2_size = sizeof(f2_addr);
    ret = f2.get()->get_name((void *) &f2_addr, &f2_size);
    if (ret < 0) {
        tcm__log_error("Unable to get current address: %s", fi_strerror(-ret));
        errno = -ret;
        return 0;
    }

    if (this->op_mode == OP_MODE_CLIENT) {
        struct tcm_msg_conn_req_ipv4 * req =
            (struct tcm_msg_conn_req_ipv4 *) mem.get_ptr();
        struct tcm_msg_conn_resp_ipv4 * resp =
            (struct tcm_msg_conn_resp_ipv4 *) (req + 1);
        *req = tcm_msg_conn_req_ipv4(0x9999, (struct sockaddr_in *) &f2_addr,
                                     this->fabric_version, this->transport_id,
                                     port);

        ret = this->ssend(mem, peer, 0, sizeof(*req));
        if (ret < 0) {
            tcm__log_error("Send failed: %s", fi_strerror(tcm_abs(ret)));
            errno = -ret;
            return 0;
        }

        ret = this->srecv(mem, peer, sizeof(*req), sizeof(*resp));
        if (ret < 0) {
            tcm__log_error("Receive failed: %s", fi_strerror(tcm_abs(ret)));
            errno = -ret;
            return 0;
        }

        ret = tcm_msg_verify((void *) resp, sizeof(*resp), 0x9999,
                             TCM_MSG_CONN_RESP);
        if (ret < 0) {
            tcm__log_error("Peer sent invalid message");
            errno = EBADMSG;
            return 0;
        }

        struct sockaddr_in p2;
        memset(&p2, 0, sizeof(p2));
        p2.sin_family      = AF_INET;
        p2.sin_addr.s_addr = resp->addr.addr;
        p2.sin_port        = resp->addr.port;
        peer2              = f2.get()->add_peer((sockaddr *) &p2);
        if (peer2 == FI_ADDR_UNSPEC) {
            tcm__log_error("Unable to add peer to new fabric connection");
            return 0;
        }

        auto                         mem2 = tcm_mem(f2, 4096);
        struct tcm_msg_fabric_ping * ping =
            (tcm_msg_fabric_ping *) mem2.get_ptr();
        *ping = tcm_msg_fabric_ping(0x8888, 0);
        ret   = f2.get()->ssend(mem2, peer2, 0, sizeof(*ping));
        if (ret < 0) {
            tcm__log_error("Unable to send fabric ping: %s",
                           fi_strerror(tcm_abs(ret)));
            return 0;
        }

        ret = f2.get()->srecv(mem2, peer2, sizeof(*ping), sizeof(*ping));
        tcm_msg_fabric_ping * ping_resp = (tcm_msg_fabric_ping *) (ping + 1);

        ret = tcm_msg_verify((void *) ping_resp, sizeof(*ping), 0x8888,
                             TCM_MSG_FABRIC_PING);
        if (ret < 0) {
            tcm__log_error("Peer sent invalid message");
            errno = EBADMSG;
            return 0;
        }

    } else if (this->op_mode == OP_MODE_SERVER) {

        struct tcm_msg_conn_req_ipv4 * req =
            (struct tcm_msg_conn_req_ipv4 *) mem.get_ptr();
        struct tcm_msg_conn_resp_ipv4 * resp =
            (struct tcm_msg_conn_resp_ipv4 *) (req + 1);

        ret = this->srecv(mem, peer, 0, sizeof(*req));
        if (ret < 0) {
            tcm__log_error("Receive failed: %s", fi_strerror(tcm_abs(ret)));
            errno = -ret;
            return 0;
        }

        ret = tcm_msg_verify((void *) req, sizeof(*req), 0x9999,
                             TCM_MSG_CONN_REQ);
        if (ret < 0) {
            tcm__log_error("Peer sent invalid message");
            errno = EBADMSG;
            return 0;
        }

        struct sockaddr_in p2;
        memset(&p2, 0, sizeof(p2));
        p2.sin_family      = AF_INET;
        p2.sin_addr.s_addr = req->addr.addr;
        p2.sin_port        = req->addr.port;
        peer2              = f2.get()->add_peer((sockaddr *) &p2);
        if (peer2 == FI_ADDR_UNSPEC) {
            tcm__log_error("Unable to add peer to new fabric connection");
            return 0;
        }

        *resp = tcm_msg_conn_resp_ipv4(0x9999, (struct sockaddr_in *) &f2_addr);
        ret   = this->ssend(mem, peer, sizeof(*req), sizeof(*resp));
        if (ret < 0) {
            tcm__log_error("Send failed: %s", fi_strerror(tcm_abs(ret)));
            errno = -ret;
            return 0;
        }

        auto                  mem2 = tcm_mem(f2, 4096);
        tcm_msg_fabric_ping * ping = (tcm_msg_fabric_ping *) mem2.get_ptr();
        tcm_msg_fabric_ping * ping_resp = (tcm_msg_fabric_ping *) (ping + 1);

        ret = f2.get()->srecv(mem2, peer2, 0, sizeof(*ping));

        ret = tcm_msg_verify((void *) ping, sizeof(*ping), 0x8888,
                             TCM_MSG_FABRIC_PING);
        if (ret < 0) {
            tcm__log_error("Peer sent invalid message");
            errno = EBADMSG;
            return 0;
        }

        *ping_resp = tcm_msg_fabric_ping(ping->common.token, 1);
        ret        = f2.get()->ssend(mem2, peer2, sizeof(*ping), sizeof(*ping));
        if (ret < 0) {
            tcm__log_error("Unable to send fabric ping: %s",
                           fi_strerror(tcm_abs(ret)));
            return 0;
        }

    } else {
        tcm__log_error("Invalid state: operating mode not client or server");
        throw EINVAL;
    }

    fi_freeinfo(hints);
    *new_peer = peer2;
    return f2;
}