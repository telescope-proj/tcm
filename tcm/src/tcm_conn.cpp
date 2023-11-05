// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#include "tcm_conn.h"

using std::make_shared;
using std::shared_ptr;

/* If interrupted by the flag stop, cleanup and return immediately */
#define CHECK_EXIT                                                             \
    do {                                                                       \
        if (exit_flag && *exit_flag > 0) {                                     \
            ret = -ECANCELED;                                                  \
            goto cleanup;                                                      \
        }                                                                      \
    } while (0);

static inline fi_info * get_index(fi_info * head, int index) {
    fi_info * tmp = head;
    for (int i = 0; i < index; i++) {
        tmp = tmp->next;
        if (!tmp)
            break;
    }
    return tmp;
}

static inline void append_fi(fi_info ** head, fi_info * item) {
    assert(head);
    assert(item);
    if (!*head) {
        *head = item;
        return;
    }
    fi_info * tmp = *head;
    while (tmp) {
        if (!tmp->next) {
            tmp->next = item;
            return;
        }
        tmp = tmp->next;
    }
}

int tcm_test_conns(fi_info * hints, fi_info ** param_out, int flags,
                   sockaddr * local_addr, tcm_tid * tids,
                   shared_ptr<tcm_fabric> * f_out) {

    shared_ptr<tcm_fabric> f;
    int                    v = 0, ttl = 0;
    if (!f_out)
        *tids = 0;
    fi_info * tmp_hints = 0;
    for (fi_info * tmp = hints; tmp; tmp = tmp->next) {
        ttl++;
        tcm__log_trace("Testing fabric %s", tmp->fabric_attr->prov_name);

        /* Try to create a fabric connection with this peer */

        if (local_addr)
            tmp_hints = fi_dupinfo(tmp);
        else
            tmp_hints = tmp;

        try {
            tcm_time             t(3000, 500);
            tcm_fabric_init_opts opts;
            opts.flags      = 0;
            opts.tcm_flags  = 0;
            opts.timeout    = &t;
            opts.hints      = tmp_hints;
            opts.no_getinfo = (flags & TCM_CONN_FLAG_PARAM) > 0;
            opts.version    = fi_version();
            if (local_addr) {
                if (tmp_hints->src_addr) {
                    tcm_free_unset(tmp_hints->src_addr);
                }
                tmp_hints->src_addr = malloc(sizeof(struct sockaddr_in));
                if (!tmp_hints->src_addr)
                    throw ENOMEM;
                memcpy((void *) tmp_hints->src_addr, local_addr,
                       sizeof(struct sockaddr_in));
                tmp_hints->src_addrlen = sizeof(struct sockaddr_in);
            }
            f = make_shared<tcm_fabric>(opts);
        } catch (int e) {
            tcm__log_trace("Failed to create fabric connection: %s",
                           fi_strerror(e));
            if (local_addr) {
                fi_freeinfo(tmp_hints);
                tmp_hints = 0;
            }
            continue;
        }

        /* Check if this transport is supported by tcm */
        fi_info * fi = (fi_info *) f->_get_fi_resource(TCM_RESRC_PARAM);
        assert(fi);

        tcm_tid tid = prov_name_to_id(fi->fabric_attr->prov_name);
        if (tid == TCM_TID_INVALID) {
            tcm__log_trace("Provider %s not supported",
                           tmp->fabric_attr->prov_name);
            continue;
        }
        if (f_out && !(*tids & tid)) {
            tcm__log_trace("Ignoring transport %s",
                           tmp->fabric_attr->prov_name);
            continue;
        }
        if (!f_out && (*tids & tid) && (flags & TCM_CONN_FLAG_ONCE)) {
            tcm__log_trace("Ignoring transport %s, a valid instance in the "
                           "list has already been found",
                           tmp->fabric_attr->prov_name);
            continue;
        }

        if (f_out) {
            if (param_out)
                *param_out = tmp_hints;
            else if (local_addr) {
                fi_freeinfo(tmp_hints);
                tmp_hints = 0;
            }

            *f_out = f;
            *tids  = tid;
            return 1;
        } else {
            if (local_addr)
                fi_freeinfo(tmp_hints);
            if (param_out) {
                fi = fi_dupinfo(fi);
                append_fi(param_out, fi);
            }
            *tids |= tid;
            f = 0;
            v++;
        }
    }

    f = 0;
    tcm__log_debug("%d of %d transports usable", v, ttl);
    return v == 0 ? -ENOTSUP : v;
}

int tcm_accept_client_dynamic(tcm_beacon & beacon, fi_info * hints,
                              sockaddr * local, sockaddr * peer,
                              shared_ptr<tcm_fabric> *   fabric_out,
                              shared_ptr<tcm_endpoint> * ep_out,
                              fi_addr_t * peer_out, int timeout,
                              volatile int * exit_flag) {

    ssize_t ret;

    /* Extract the transports returned in fi_info into TCM transport ID flags */
    tcm_tid                  tid_flags = 0;
    tcm_tid                  tid_sel   = 0;
    shared_ptr<tcm_fabric>   f;
    shared_ptr<tcm_endpoint> ep;
    shared_ptr<tcm_mem>      mem;
    tcm_msg_conn_req_ipv4 *  req         = 0;
    tcm_msg_conn_resp_ipv4 * resp        = 0;
    fi_info *                valid_hints = 0;
    fi_addr_t                f_addr      = FI_ADDR_UNSPEC;
    uint16_t                 token;
    sockaddr_in              p;
    char                     mbuf[64];
    memset((void *) &p, 0, sizeof(p));
    memset((void *) mbuf, 0, sizeof(mbuf));
    int inv_msg_count = 0;
    int mcount        = 0;

    CHECK_EXIT;

    if (peer && peer->sa_family == AF_INET) {
        ret = beacon.set_peer((sockaddr *) peer);
        if (ret < 0)
            tcm__log_warn("Failed to set peer address!");
    }
    tcm__log_trace("Set peer address");

    /* Clients may send pings and metadata requests to the server. Respond to
     * them, but do not progress the connection state */

    ret = tcm_test_conns(hints, &valid_hints, TCM_CONN_FLAG_ONCE, local,
                         &tid_flags, nullptr);
    if (ret < 0) {
        tcm__log_error("Unable to find working fabrics: %s", fi_strerror(-ret));
        return ret;
    }

    beacon.set_timeout(timeout);

    while (1) {

        CHECK_EXIT;
        int send_size = 0;
        ret = beacon.recv_dgram((sockaddr *) &p, (void *) mbuf, sizeof(mbuf));
        if (ret < 0) {
            if (ret != -EINTR)
                tcm__log_debug("Datagram receive failed: %s", strerror(-ret));
            goto cleanup;
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

                *r = tcm_msg_metadata_resp(TCM_DEFAULT_FABRIC_VERSION,
                                           fi_version(), TCM_AF_INET, tid_flags,
                                           token);
                break;
            }
            default:
                assert(false && "Invalid state reached");
        }

        mcount++;

        /* Send a response to stateless info messages */
        ret = beacon.send_dgram((sockaddr *) &p, (void *) mbuf, send_size);
        if (ret < 0) {
            if (ret != -EINTR)
                tcm__log_debug("Datagram send failed: %s", strerror(-ret));
            return ret;
        }

        /* Limit the number of messages sent in case of bugs or intentional
         * flooding of messages */
        if (mcount >= 5) {
            ret = tcm_sleep(50);
            if (ret < 0) {
                if (ret != -EINTR) {
                    tcm__log_debug("Sleep failed: %s", strerror(-ret));
                    return ret;
                }
            }
            mcount = 0;
        }
    }

    /* If a connection request was received, create a fabric connection */
    ret = -1;
    req = reinterpret_cast<tcm_msg_conn_req_ipv4 *>(mbuf);
    if (req->cr.addr_fmt != TCM_AF_INET) {
        tcm__log_debug("Unsupported address format: %d");
        goto cleanup;
    }

    ret = tcm_test_conns(valid_hints, nullptr,
                         TCM_CONN_FLAG_ONCE | TCM_CONN_FLAG_PARAM, local,
                         &tid_flags, &f);
    if (ret < 0) {
        tcm__log_debug("Fabric creation failed: %s", fi_strerror(-ret));
        goto cleanup;
    }

    CHECK_EXIT;

    try {
        struct sockaddr_in dst;
        memset((void *) &dst, 0, sizeof(dst));
        dst.sin_family      = AF_INET;
        dst.sin_addr.s_addr = req->addr.addr;
        dst.sin_port        = req->addr.port;
        f_addr              = f->add_peer((sockaddr *) &dst);
        if (f_addr == FI_ADDR_UNSPEC) {
            tcm__log_error("Failed to add peer to fabric: %s",
                           fi_strerror(errno));
            goto cleanup;
        }
        tcm_time t(3000, 500);
        ep = make_shared<tcm_endpoint>(f, local, &t);
    } catch (int e) {
        tcm__log_error("Failed to create endpoint: %s", fi_strerror(e));
        goto cleanup;
    }

    CHECK_EXIT;

    /* Send a response */
    resp = reinterpret_cast<tcm_msg_conn_resp_ipv4 *>(mbuf);
    {
        sockaddr_in name;
        size_t      buf_size = sizeof(sockaddr_in);
        ret                  = ep->get_name((void *) &name, &buf_size);
        if (ret < 0) {
            tcm__log_error("Unable to get fabric endpoint name: %s",
                           fi_strerror(-ret));
            goto cleanup;
        }

        tcm__log_debug("Transport id = %d", f->_get_tid());

        *resp =
            tcm_msg_conn_resp_ipv4(token, f->_get_tid(), (sockaddr_in *) &name);
        ret = beacon.send_dgram((sockaddr *) &p, mbuf, sizeof(*resp));
        if (ret < 0) {
            tcm__log_error("Unable to send datagram: %s", strerror(-ret));
            goto cleanup;
        }
    }

    CHECK_EXIT;

    /* Wait for a fabric ping */
    try {
        mem = make_shared<tcm_mem>(f, 4096);
    } catch (int e) {
        tcm__log_error("Unable to register memory: %s", fi_strerror(e));
        goto cleanup;
    }

    CHECK_EXIT;

    {
        tcm_msg_fabric_ping * ping =
            reinterpret_cast<tcm_msg_fabric_ping *>(**mem);

        ret = ep->srecv(*mem, f_addr, 0, sizeof(tcm_msg_fabric_ping));
        if (ret < 0) {
            tcm__log_error("Failed to receive ping: %s", fi_strerror(ret));
            goto cleanup;
        }

        CHECK_EXIT;

        ret = tcm_msg_verify((void *) ping, ret, 0, TCM_MFLAG_FABRIC_PING);
        if (ret != tcm_mv::VALID) {
            tcm__log_error("Fabric ping invalid: %s", tcm_mv::stringify(ret));
            goto cleanup;
        }

        token = ping->common.token;
        *ping = tcm_msg_fabric_ping(token, 1);

        ret = ep->ssend(*mem, f_addr, 0, sizeof(tcm_msg_fabric_ping));
        if (ret < 0) {
            tcm__log_error("Failed to send ping: %s", fi_strerror(ret));
            goto cleanup;
        }

        CHECK_EXIT;
    }

    /* Success */
    *fabric_out = f;
    *ep_out     = ep;
    *peer_out   = f_addr;
    if (peer && peer->sa_family == AF_UNSPEC) {
        *(sockaddr_in *) peer = p;
    }
    if (valid_hints)
        fi_freeinfo(valid_hints);
    return 0;

cleanup:
    if (f_addr != FI_ADDR_UNSPEC)
        f->remove_peer(f_addr);
    mem = 0;
    ep  = 0;
    f   = 0;
    if (valid_hints)
        fi_freeinfo(valid_hints);
    return ret;
}

int tcm_client_dynamic(tcm_beacon & beacon, fi_info * hints, sockaddr * local,
                       sockaddr * peer, shared_ptr<tcm_fabric> * fabric_out,
                       shared_ptr<tcm_endpoint> * ep_out, fi_addr_t * peer_out,
                       bool fast, int timeout, volatile int * exit_flag) {
    assert(local);
    assert(peer);
    assert(peer_out);

    shared_ptr<tcm_fabric>   f  = 0;
    shared_ptr<tcm_endpoint> ep = 0;

    char mbuf[64];
    memset((void *) mbuf, 0, 64);
    ssize_t   ret;
    ssize_t   mlen;
    fi_info * valid_conns = 0;
    tcm_tid   tid_flags   = 0;
    fi_addr_t f_peer      = FI_ADDR_UNSPEC;

    CHECK_EXIT;

    ret = tcm_test_conns(hints, &valid_conns, TCM_CONN_FLAG_ONCE, local,
                         &tid_flags, nullptr);
    if (ret < 0) {
        tcm__log_error("Unable to find working fabrics: %s", fi_strerror(-ret));
        return ret;
    }

    CHECK_EXIT;

    beacon.set_timeout(timeout);

    /*  Fast connection mode can be used if the client already knows the server
        has supported features / compatible versions ahead of time. */

    if (!fast) {
        *(tcm_msg_client_ping *) mbuf = tcm_msg_client_ping(1);

        mlen =
            beacon.send_dgram(peer, (void *) mbuf, sizeof(tcm_msg_client_ping));
        if (mlen < 0) {
            tcm__log_error("Failed to send ping: %s", strerror(-mlen));
            return mlen;
        }

        CHECK_EXIT;

        memset((void *) mbuf, 0, TCM_LARGEST_MESSAGE_SIZE);
        mlen = beacon.recv_dgram(peer, (void *) mbuf, TCM_LARGEST_MESSAGE_SIZE);
        if (mlen < 0) {
            tcm__log_error("Failed to receive response: %s", strerror(-mlen));
            return mlen;
        }

        CHECK_EXIT;

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

        CHECK_EXIT;

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
                if (resp->fabric_min > fi_version()) {
                    tcm__log_error(
                        "Unable to find a supported Libfabric version! Local: "
                        "%d.%d, Peer: min %d.%d - max %d.%d",
                        FI_MAJOR(fi_version()), FI_MINOR(fi_version()),
                        FI_MAJOR(resp->fabric_min), FI_MINOR(resp->fabric_min),
                        FI_MAJOR(resp->fabric_max), FI_MINOR(resp->fabric_min));
                    return -ENOTSUP;
                }
                if (!(tid_flags & resp->tids)) {
                    tcm__log_error(
                        "Transport type flag mismatch! Local: %d, Peer: %d",
                        tid_flags, resp->tids);
                }
                if (resp->addr_fmt != TCM_AF_INET) {
                    tcm__log_error("Address format unsupported!");
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

    try {
        /* Create the fabric connection */
        tcm_msg_metadata_resp * resp =
            reinterpret_cast<tcm_msg_metadata_resp *>(mbuf);

        CHECK_EXIT;

        tcm_tid s_tid = resp->tids;
        ret           = tcm_test_conns(valid_conns, nullptr,
                                       TCM_CONN_FLAG_ONCE | TCM_CONN_FLAG_PARAM, local,
                                       &s_tid, &f);
        if (ret < 0) {
            tcm__log_error("Failed to create any fabric connection: %s",
                           fi_strerror(-ret));
            goto cleanup;
        }

        CHECK_EXIT;

        /* Create an endpoint and get the local address */
        ep = make_shared<tcm_endpoint>(f, local, (tcm_time *) nullptr);
        sockaddr_storage name;
        size_t           size = sizeof(struct sockaddr_storage);
        ret                   = ep->get_name(&name, &size);
        if (ret < 0) {
            tcm__log_error("Failed to get endpoint name: %s",
                           fi_strerror(-ret));
            goto cleanup;
        }
        if (name.ss_family != AF_INET) {
            tcm__log_error("Invalid address family %d", name.ss_family);
            ret = -EIO;
            goto cleanup;
        }

        CHECK_EXIT;

        /* Send local address details to peer */
        *(tcm_msg_conn_req_ipv4 *) mbuf = tcm_msg_conn_req_ipv4(
            0x1234, (sockaddr_in *) &name, f->get_version(), f->_get_tid());

        mlen = beacon.send_dgram(peer, (void *) mbuf,
                                 sizeof(tcm_msg_conn_req_ipv4));
        if (mlen < 0) {
            tcm__log_error("Failed to send datagram: %s", strerror(-mlen));
            ret = -ECOMM;
            goto cleanup;
        }

        CHECK_EXIT;
        memset((void *) mbuf, 0, TCM_LARGEST_MESSAGE_SIZE);
        mlen = beacon.recv_dgram(peer, (void *) mbuf,
                                 sizeof(tcm_msg_conn_resp_ipv4));
        if (mlen < 0) {
            tcm__log_error("Failed to receive datagram: %s", strerror(-mlen));
            ret = -ECOMM;
            goto cleanup;
        }

        ret = tcm_msg_verify((void *) mbuf, mlen, 0x1234,
                             TCM_MFLAG_CONN_RESP | TCM_MFLAG_STATUS);
        if (ret != tcm_mv::VALID) {
            tcm__log_error("Peer sent invalid message: %s",
                           tcm_mv::stringify(ret));
            ret = -EBADMSG;
            goto cleanup;
        }

        tcm_msg_ext_header * hdr = reinterpret_cast<tcm_msg_ext_header *>(mbuf);
        switch (hdr->hdr.type) {
            case TCM_MSG_STATUS: {
                tcm_msg_status * s = reinterpret_cast<tcm_msg_status *>(mbuf);
                tcm__log_error(
                    "Peer closed connection with return code %d (%s)",
                    s->retcode, tcm_err_string(s->retcode));
                ret = -ECONNRESET;
                goto cleanup;
            }
            case TCM_MSG_CONN_RESP: {
                tcm_msg_conn_resp_ipv4 * resp =
                    reinterpret_cast<tcm_msg_conn_resp_ipv4 *>(mbuf);
                if (!(tid_flags & resp->cr.tid)) {
                    tcm__log_error(
                        "Transport type flag mismatch! Local: %d, Peer: %d",
                        tid_flags, resp->cr.tid);
                    ret = -ENOTSUP;
                    goto cleanup;
                }
                if (resp->cr.addr_fmt != TCM_AF_INET) {
                    tcm__log_error("Address format unsupported!");
                    ret = -EPFNOSUPPORT;
                    goto cleanup;
                }
                struct sockaddr_in in;
                memset(&in, 0, sizeof(in));
                in.sin_family      = AF_INET;
                in.sin_addr.s_addr = resp->addr.addr;
                in.sin_port        = resp->addr.port;
                f_peer             = f->add_peer((sockaddr *) &in);
                if (f_peer == FI_ADDR_UNSPEC) {
                    tcm__log_error("Failed to add peer: %s",
                                   fi_strerror(errno));
                    ret = -errno;
                    goto cleanup;
                }
                break;
            }
            default:
                assert(false);
        }
    } catch (int e) {
        tcm__log_error("Failed to create connection: %s", fi_strerror(e));
        ret = -e;
        goto cleanup;
    }

    /* The response is correct, create EP, allocate RDMA memory and send fabric
     * pings */
    {
        CHECK_EXIT;
        const size_t          pl = sizeof(tcm_msg_fabric_ping);
        tcm_time              t(3000, 500);
        auto                  mem = tcm_mem(f, 4096);
        tcm_msg_fabric_ping * ping =
            reinterpret_cast<tcm_msg_fabric_ping *>(*mem);
        *ping                       = tcm_msg_fabric_ping(0x2345, 0);
        tcm_msg_fabric_ping *  resp = (ping + 1);
        struct fi_cq_err_entry err;
        memset((void *) resp, 0, pl);

        ret = ep->recv(mem, f_peer, (void *) (uintptr_t) 1, pl, pl);
        if (ret < 0) {
            tcm__log_error("Failed to queue recv: %s", fi_strerror(-ret));
            goto cleanup;
        }

        ret = ep->send(mem, f_peer, (void *) (uintptr_t) 2, 0, pl);
        if (ret < 0) {
            tcm__log_error("Failed to queue send: %s", fi_strerror(-ret));
            goto cleanup;
        }

        for (int i = 0; i < 2; i++) {
            CHECK_EXIT;
            ret = f->poll_cq(&err, &t);
            if (ret < 0) {
                tcm__log_error("Failed to poll CQ (%d): %s", i,
                               fi_strerror(-ret));
                goto cleanup;
            }
        }

        ret = tcm_msg_verify(resp, pl, 0x2345, TCM_MFLAG_FABRIC_PING);
        if (ret != tcm_mv::VALID) {
            tcm__log_error("Peer sent invalid message: %s",
                           tcm_mv::stringify(ret));
            return -EBADMSG;
        }
    }

    *peer_out   = f_peer;
    *fabric_out = f;
    *ep_out     = ep;
    if (valid_conns)
        fi_freeinfo(valid_conns);
    return 0;

cleanup:
    ep = 0;
    if (f_peer != FI_ADDR_UNSPEC)
        f->remove_peer(f_peer);
    f = 0;
    if (valid_conns)
        fi_freeinfo(valid_conns);
    return ret;
}