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

    /* Clients may send pings and metadata requests to the server. Respond to
     * them, but do not progress the connection state */

    uint16_t           token;
    struct sockaddr_in p;
    char               mbuf[64];
    memset((void *) &p, 0, sizeof(p));
    memset((void *) mbuf, 0, sizeof(mbuf));
    int inv_msg_count = 0;

    while (1) {
        int send_size = 0;

        ret = (int) beacon.recv_dgram((sockaddr *) &p, (void *) mbuf,
                                      sizeof(mbuf));
        if (ret < 0) {
            if (ret != -EINTR)
                tcm__log_debug("Datagram receive failed: %s", strerror(-ret));
            return ret;
        }

        tcm_msg_type_flag allowed =
            TCM_MFLAG_CLIENT_PING | TCM_MFLAG_METADATA_REQ | TCM_MFLAG_CONN_REQ;
        ret = tcm_msg_verify(mbuf, (size_t) ret, 0, allowed);
        if (ret != tcm_mv::VALID) {
            if (inv_msg_count < 5) {
                tcm__log_debug("Message parsing failed: %s",
                               tcm_mv::stringify(ret));
                inv_msg_count++;
            }
            if (inv_msg_count == 5) {
                tcm__log_debug("Further invalid message warnings suppressed");
            }
            continue;
        }

        tcm_msg_ext_header * hdr = reinterpret_cast<tcm_msg_ext_header *>(mbuf);
        token = reinterpret_cast<tcm_msg_ext_header *>(mbuf)->hdr.token;
        if (hdr->hdr.type == TCM_MSG_CONN_REQ)
            break;

        switch (hdr->hdr.type) {
            case TCM_MSG_CLIENT_PING: {
                tcm_msg_server_ping * p =
                    reinterpret_cast<tcm_msg_server_ping *>(mbuf);
                memset((void *) p, 0, sizeof(*p));
                send_size = sizeof(*p);
                *p        = tcm_msg_server_ping(token, 0);
                break;
            }
            case TCM_MSG_METADATA_REQ: {
                tcm_msg_metadata_resp * r =
                    reinterpret_cast<tcm_msg_metadata_resp *>(mbuf);
                memset((void *) r, 0, sizeof(*r));
                send_size = sizeof(*r);
                *r = tcm_msg_metadata_resp(this->fabric_version, TCM_AF_INET,
                                           this->transport_id, token);
                break;
            }
            default:
                assert(false && "Invalid state reached");
        }

        /* Send a response to stateless info messages */
        ret =
            (int) beacon.send_dgram((sockaddr *) &p, (void *) mbuf, send_size);
        if (ret < 0) {
            if (ret != -EINTR)
                tcm__log_debug("Datagram send failed: %s", strerror(-ret));
            return ret;
        }

        /* Limit the number of messages sent in case of bugs or intentional
         * flooding of messages */
        ret = tcm_sleep(20);
        if (ret < 0) {
            if (ret != -EINTR) {
                tcm__log_debug("Sleep failed: %s", strerror(-ret));
                return ret;
            }
        }
    }

    /* Add the peer */
    if (!sin) {
        int ret2 = beacon.set_peer((sockaddr *) &p);
        if (ret2 < 0)
            tcm__log_debug("Failed to set peer address - handshake might fail");
    }

    /* Check client version */

    tcm_msg_conn_req_ipv4 * cr =
        reinterpret_cast<tcm_msg_conn_req_ipv4 *>(mbuf);
    if (cr->cr.addr_fmt != TCM_AF_INET) {
        tcm__log_debug(
            "This version of TCM only supports the AF_INET address family");
        ret = -TCM_ERR_INVALID_ADDRESS;
        goto reject;
    }
    if ((uint32_t) (FI_VERSION(cr->cr.fabric_major, cr->cr.fabric_minor)) !=
        this->fabric_version) {
        tcm__log_debug("Libfabric version mismatch");
        tcm__log_debug("This: %d.%d, Peer: %d.%d",
                       FI_MAJOR(this->fabric_version),
                       FI_MINOR(this->fabric_version), cr->cr.fabric_major,
                       cr->cr.fabric_minor);
        ret = -TCM_ERR_INVALID_FABRIC_VER;
        goto reject;
    }

    /* Add peer to fabric */

    tcm__log_debug("Attempting to add peer to fabric");
    struct sockaddr_in fpeer;
    memset(&fpeer, 0, sizeof(fpeer));
    fpeer.sin_family      = AF_INET;
    fpeer.sin_addr.s_addr = cr->addr.addr;
    fpeer.sin_port        = cr->addr.port;
    *addr                 = this->add_peer((struct sockaddr *) &fpeer);
    if (*addr == FI_ADDR_UNSPEC) {
        tcm__log_debug("Failed to add peer address to fabric");
        ret = -ECOMM;
        goto reject;
    }

    {
        /* Send confirmation over beacon */
        tcm__log_debug("Address added, sending own address");
        tcm_token                token = cr->cr.common.token;
        tcm_msg_conn_resp_ipv4 * resp =
            reinterpret_cast<tcm_msg_conn_resp_ipv4 *>(mbuf);
        *resp =
            tcm_msg_conn_resp_ipv4(token, tcm_conv_fi_addr_fmt(this->addr_fmt),
                                   (sockaddr_in *) this->src_addr);
        ret = (int) beacon.send_dgram((sockaddr *) &p, (void *) resp,
                                      sizeof(*resp));
        if (ret < 0) {
            if (ret != -EINTR)
                tcm__log_debug("Datagram send failed: %s", strerror(-ret));
            return ret;
        }

        /* Wait for fabric response */
        auto                  mem  = tcm_mem(this->shared_from_this(), 4096);
        tcm_msg_fabric_ping * ping = (tcm_msg_fabric_ping *) mem.get_ptr();
        ssize_t               l    = this->srecv(mem, *addr, 0, sizeof(*ping));
        if (l < 0) {
            tcm__log_debug("Failed to queue recv: %s", fi_strerror(-l));
            ret = -ECOMM;
            goto reject;
        }

        ret = tcm_msg_verify(mem.get_ptr(), sizeof(*ping), 0,
                             TCM_MFLAG_FABRIC_PING);
        if (ret) {
            tcm__log_debug("Client fabric ping invalid: %s",
                           tcm_mv::stringify(ret));
            ret = -ECOMM;
            goto reject;
        }
        if (ping->direction != 0) {
            tcm__log_debug("Client sent invalid ping");
            ret = -EBADMSG;
            goto reject;
        }

        ping->direction = 1;
        l               = this->ssend(mem, *addr, 0, sizeof(*ping));
        if (l < 0) {
            tcm__log_debug("Failed to queue send: %s", fi_strerror(-l));
            ret = -ECOMM;
            goto reject;
        }
    }

    this->op_mode = OP_MODE_SERVER;
    return 0;

reject:
    if (*addr != FI_ADDR_UNSPEC) {
        this->remove_peer(*addr);
        *addr = FI_ADDR_UNSPEC;
    }

    if (ret == -EBADMSG)
        return ret;

    struct tcm_msg_status st(token, tcm_sys_to_err(tcm_abs(ret)));
    int r2 = beacon.send_dgram((sockaddr *) &p, &st, sizeof(st));
    if (r2 < 0)
        tcm__log_error("Failed to send connection rejection: %s",
                       strerror(errno));

    return ret;
}

int tcm_fabric::client(tcm_beacon & beacon, struct sockaddr * peer,
                       fi_addr_t * addr, bool fast) {
    sockaddr_in * sin = (sockaddr_in *) peer;
    int           ret;
    ssize_t       mlen;

    if (beacon.get_timeout() == 0) {
        tcm__log_warn("Beacon operating mode must be blocking");
        return -EINVAL;
    }

    if (sin && sin->sin_family == AF_INET) {
        ret = beacon.set_peer(peer);
        if (ret < 0)
            tcm__log_warn("Failed to set peer address - handshake might fail");
    }

    char mbuf[TCM_LARGEST_MESSAGE_SIZE];
    memset((void *) mbuf, 0, TCM_LARGEST_MESSAGE_SIZE);

    /*  Fast connection mode can be used if the client already knows the server
        has supported features / compatible versions ahead of time. */

    if (!fast) {
        /* Probe the server for details */

        *(tcm_msg_client_ping *) mbuf = tcm_msg_client_ping(1);

        mlen =
            beacon.send_dgram(peer, (void *) mbuf, sizeof(tcm_msg_client_ping));
        if (mlen < 0) {
            tcm__log_error("Failed to send ping: %s", strerror(-mlen));
            return mlen;
        }

        memset((void *) mbuf, 0, TCM_LARGEST_MESSAGE_SIZE);
        mlen = beacon.recv_dgram(peer, (void *) mbuf, TCM_LARGEST_MESSAGE_SIZE);
        if (mlen < 0) {
            tcm__log_error("Failed to receive response: %s", strerror(-mlen));
            return mlen;
        }

        ret = tcm_msg_verify((void *) mbuf, mlen, 1, TCM_MFLAG_SERVER_PING);
        if (ret != tcm_mv::VALID) {
            tcm__log_error("Peer sent invalid message: %s",
                           tcm_mv::stringify(ret));
            return -EBADMSG;
        }

        /* Get extended metadata */

        *(tcm_msg_metadata_req *) mbuf = tcm_msg_metadata_req(2);

        mlen = beacon.send_dgram(peer, (void *) mbuf,
                                 sizeof(tcm_msg_metadata_req));
        if (mlen < 0) {
            tcm__log_error("Failed to send metadata request: %s",
                           strerror(-mlen));
            return mlen;
        }

        memset((void *) mbuf, 0, TCM_LARGEST_MESSAGE_SIZE);
        mlen = beacon.recv_dgram(peer, (void *) mbuf, TCM_LARGEST_MESSAGE_SIZE);
        if (mlen < 0) {
            tcm__log_error("Failed to receive response: %s", strerror(-mlen));
            return mlen;
        }

        ret = tcm_msg_verify((void *) mbuf, mlen, 2,
                             TCM_MFLAG_METADATA_RESP | TCM_MFLAG_STATUS);
        if (ret != tcm_mv::VALID) {
            tcm__log_error("Peer sent invalid message: %s",
                           tcm_mv::stringify(ret));
            return -EBADMSG;
        }

        tcm_msg_ext_header * hdr = reinterpret_cast<tcm_msg_ext_header *>(mbuf);
        switch (hdr->hdr.type) {
            case TCM_MSG_METADATA_RESP: {
                tcm_msg_metadata_resp * resp =
                    reinterpret_cast<tcm_msg_metadata_resp *>(mbuf);
                if ((uint32_t) FI_VERSION(resp->fabric_major,
                                          resp->fabric_minor) !=
                    this->fabric_version) {
                    tcm__log_error(
                        "Libfabric version mismatch! Local: %d.%d, Peer: %d.%d",
                        FI_MAJOR(this->fabric_version),
                        FI_MINOR(this->fabric_version), resp->fabric_major,
                        resp->fabric_minor);
                    return -ENOTSUP;
                }
                if (resp->tid != this->transport_id) {
                    tcm__log_error(
                        "Transport type mismatch! Local: %s, Peer: %s",
                        id_to_prov_name_static(this->transport_id),
                        id_to_prov_name_static(resp->tid));
                    return -ENOTSUP;
                }
                if (resp->addr_fmt != tcm_conv_fi_addr_fmt(this->addr_fmt)) {
                    tcm__log_error(
                        "Address format mismatch! Local: %d, Peer: %d",
                        tcm_conv_fi_addr_fmt(this->addr_fmt), resp->addr_fmt);
                    return -ENOTSUP;
                }
                break;
            }
            case TCM_MSG_STATUS: {
                tcm_msg_status * s = reinterpret_cast<tcm_msg_status *>(mbuf);
                tcm__log_error(
                    "Peer closed connection with return code %d (%s)",
                    s->retcode, tcm_err_string(s->retcode));
                return -ECONNRESET;
            }
            default:
                assert(false);
        }
    }

    /* Send a connection request */

    sockaddr_in * f_addr = (sockaddr_in *) this->src_addr;
    if (!f_addr)
        throw EINVAL;

    *(tcm_msg_conn_req_ipv4 *) mbuf = tcm_msg_conn_req_ipv4(
        0x1234, f_addr, this->fabric_version, this->transport_id);

    mlen =
        beacon.send_dgram(peer, (void *) mbuf, sizeof(tcm_msg_conn_req_ipv4));
    if (mlen < 0) {
        tcm__log_error("Failed to send datagram: %s", strerror(-mlen));
        return -ECOMM;
    }

    memset((void *) mbuf, 0, TCM_LARGEST_MESSAGE_SIZE);
    mlen =
        beacon.recv_dgram(peer, (void *) mbuf, sizeof(tcm_msg_conn_resp_ipv4));
    if (mlen < 0) {
        tcm__log_error("Failed to receive datagram: %s", strerror(-mlen));
        return -ECOMM;
    }

    ret = tcm_msg_verify((void *) mbuf, mlen, 0x1234,
                         TCM_MFLAG_CONN_RESP | TCM_MFLAG_STATUS);
    if (ret != tcm_mv::VALID) {
        tcm__log_error("Peer sent invalid message: %s", tcm_mv::stringify(ret));
        return -EBADMSG;
    }

    fi_addr_t faddr = FI_ADDR_UNSPEC;

    tcm_msg_ext_header * hdr = reinterpret_cast<tcm_msg_ext_header *>(mbuf);
    switch (hdr->hdr.type) {
        case TCM_MSG_STATUS: {
            tcm_msg_status * s = reinterpret_cast<tcm_msg_status *>(mbuf);
            tcm__log_error("Peer closed connection with return code %d (%s)",
                           s->retcode, tcm_err_string(s->retcode));
            return -ECONNRESET;
        }
        case TCM_MSG_CONN_RESP: {
            tcm_msg_conn_resp_ipv4 * resp =
                reinterpret_cast<tcm_msg_conn_resp_ipv4 *>(mbuf);
            if (resp->cr.tid != this->transport_id) {
                tcm__log_error("Transport type mismatch! Local: %s, Peer: %s",
                               id_to_prov_name_static(this->transport_id),
                               id_to_prov_name_static(resp->cr.tid));
                return -ENOTSUP;
            }
            if (resp->cr.addr_fmt != tcm_conv_fi_addr_fmt(this->addr_fmt)) {
                tcm__log_error("Address format mismatch! Local: %d, Peer: %d",
                               tcm_conv_fi_addr_fmt(this->addr_fmt),
                               resp->cr.addr_fmt);
                return -ENOTSUP;
            }
            struct sockaddr_in in;
            memset(&in, 0, sizeof(in));
            in.sin_family      = AF_INET;
            in.sin_addr.s_addr = resp->addr.addr;
            in.sin_port        = resp->addr.port;
            faddr              = this->add_peer((sockaddr *) &in);
            break;
        }
        default:
            assert(false);
    }

    /* Allocate RDMA memory and send fabric pings */

    if (faddr == FI_ADDR_UNSPEC) {
        tcm__log_error("Failed to add peer address: %s", fi_strerror(errno));
        return -EIO;
    }

    auto     mem = tcm_mem(this->shared_from_this(), 4096);
    uint64_t pl  = sizeof(tcm_msg_fabric_ping);

    tcm_msg_fabric_ping * ping = (tcm_msg_fabric_ping *) mem.get_ptr();
    *ping                      = tcm_msg_fabric_ping(0x2345, 0);

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

    ret = tcm_msg_verify(resp, pl, 0x2345, TCM_MFLAG_FABRIC_PING);
    if (ret != tcm_mv::VALID) {
        tcm__log_error("Peer sent invalid message: %s", tcm_mv::stringify(ret));
        return -EBADMSG;
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

    sockaddr_in addr = *(sockaddr_in *) this->src_addr;
    addr.sin_port    = port;

    std::shared_ptr<tcm_fabric> f2;

    /* A shared tcm_fabric object shares the top-level libfabric fabric and
     * domain objects with other tcm_fabric objects. This is more efficient
     * and allows for features like wait sets across tcm_fabric objects */

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

    sockaddr_in f2_addr;
    size_t      f2_size = sizeof(f2_addr);
    ret                 = f2.get()->get_name((void *) &f2_addr, &f2_size);
    if (ret < 0) {
        tcm__log_error("Unable to get current address: %s", fi_strerror(-ret));
        errno = -ret;
        return 0;
    }

    if (this->op_mode == OP_MODE_CLIENT) {
        tcm_msg_conn_req_ipv4 *  req  = (tcm_msg_conn_req_ipv4 *) mem.get_ptr();
        tcm_msg_conn_resp_ipv4 * resp = (tcm_msg_conn_resp_ipv4 *) (req + 1);

        *req = tcm_msg_conn_req_ipv4(0x9999, (sockaddr_in *) &f2_addr,
                                     this->fabric_version, this->transport_id);

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
                             TCM_MFLAG_CONN_RESP);
        if (ret < 0) {
            tcm__log_error("Peer sent invalid message");
            errno = EBADMSG;
            return 0;
        }

        sockaddr_in p2;
        memset(&p2, 0, sizeof(p2));
        p2.sin_family      = AF_INET;
        p2.sin_addr.s_addr = resp->addr.addr;
        p2.sin_port        = resp->addr.port;
        peer2              = f2.get()->add_peer((sockaddr *) &p2);
        if (peer2 == FI_ADDR_UNSPEC) {
            tcm__log_error("Unable to add peer to new fabric connection");
            return 0;
        }

        auto                  mem2 = tcm_mem(f2, 4096);
        tcm_msg_fabric_ping * ping = (tcm_msg_fabric_ping *) mem2.get_ptr();
        *ping                      = tcm_msg_fabric_ping(0x8888, 0);
        ret = f2.get()->ssend(mem2, peer2, 0, sizeof(*ping));
        if (ret < 0) {
            tcm__log_error("Unable to send fabric ping: %s",
                           fi_strerror(tcm_abs(ret)));
            return 0;
        }

        ret = f2.get()->srecv(mem2, peer2, sizeof(*ping), sizeof(*ping));
        tcm_msg_fabric_ping * ping_resp = (tcm_msg_fabric_ping *) (ping + 1);

        ret = tcm_msg_verify((void *) ping_resp, sizeof(*ping), 0x8888,
                             TCM_MFLAG_FABRIC_PING);
        if (ret < 0) {
            tcm__log_error("Peer sent invalid message");
            errno = EBADMSG;
            return 0;
        }

    } else if (this->op_mode == OP_MODE_SERVER) {

        tcm_msg_conn_req_ipv4 *  req  = (tcm_msg_conn_req_ipv4 *) mem.get_ptr();
        tcm_msg_conn_resp_ipv4 * resp = (tcm_msg_conn_resp_ipv4 *) (req + 1);

        ret = this->srecv(mem, peer, 0, sizeof(*req));
        if (ret < 0) {
            tcm__log_error("Receive failed: %s", fi_strerror(tcm_abs(ret)));
            errno = -ret;
            return 0;
        }

        ret = tcm_msg_verify((void *) req, sizeof(*req), 0x9999,
                             TCM_MFLAG_CONN_REQ);
        if (ret < 0) {
            tcm__log_error("Peer sent invalid message");
            errno = EBADMSG;
            return 0;
        }

        sockaddr_in p2;
        memset(&p2, 0, sizeof(p2));
        p2.sin_family      = AF_INET;
        p2.sin_addr.s_addr = req->addr.addr;
        p2.sin_port        = req->addr.port;
        peer2              = f2.get()->add_peer((sockaddr *) &p2);
        if (peer2 == FI_ADDR_UNSPEC) {
            tcm__log_error("Unable to add peer to new fabric connection");
            return 0;
        }

        *resp = tcm_msg_conn_resp_ipv4(0x9999, f2.get()->_get_tid(),
                                       (sockaddr_in *) &f2_addr);
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
                             TCM_MFLAG_FABRIC_PING);
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