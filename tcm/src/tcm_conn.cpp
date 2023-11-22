// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#include "tcm_conn.h"
#include "tcm_msg.h"

enum tcm_conn_flags {
    /* Once a valid instance with a specific transport type has been created, do
       not test more instances of that type. */
    TCM_CONN_FLAG_ONCE  = (1 << 0),
    /* Interpret the hints parameter as actual fabric parameters, bypassing
       fi_getinfo. */
    TCM_CONN_FLAG_PARAM = (1 << 2),
};

#define SA_CAST(x) reinterpret_cast<sockaddr *>(x)
#define CTX_CAST(x) ((void *) (uintptr_t) x)

using std::make_shared;
using std::shared_ptr;
using std::weak_ptr;

union msg_container {
    char             buf[TCM_MAX_MSG_SIZE];
    void             clear() { memset(buf, 0, sizeof(buf)); }
    void *           mbuf() { return (void *) buf; }
    tcm_msg_header * hdr() {
        return reinterpret_cast<tcm_msg_header *>(this->buf);
    }
    tcm_msg_ext_header * e_hdr() {
        return reinterpret_cast<tcm_msg_ext_header *>(this->buf);
    }
    tcm_msg_client_ping * c_ping() {
        return reinterpret_cast<tcm_msg_client_ping *>(this->buf);
    }
    tcm_msg_server_ping * s_ping() {
        return reinterpret_cast<tcm_msg_server_ping *>(this->buf);
    }
    tcm_msg_status * status() {
        return reinterpret_cast<tcm_msg_status *>(this->buf);
    }
    tcm_msg_metadata_req * mtd_req() {
        return reinterpret_cast<tcm_msg_metadata_req *>(this->buf);
    }
    tcm_msg_metadata_resp * mtd_resp() {
        return reinterpret_cast<tcm_msg_metadata_resp *>(this->buf);
    }
    tcm_msg_conn_req_storage * conn_req() {
        return reinterpret_cast<tcm_msg_conn_req_storage *>(this->buf);
    }
    tcm_msg_conn_resp_storage * conn_resp() {
        return reinterpret_cast<tcm_msg_conn_resp_storage *>(this->buf);
    }
    tcm_msg_fabric_ping * f_ping() {
        return reinterpret_cast<tcm_msg_fabric_ping *>(this->buf);
    }
    msg_container() { this->clear(); }
};

#define CAST_BUF(name, type, buf) type * name = reinterpret_cast<type *>(buf);

/* If interrupted by the flag stop, cleanup and return immediately */
#define CHECK_EXIT(flag)                                                       \
    do {                                                                       \
        if (flag && *flag > 0) {                                               \
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

/* Prune the fi_info list according to the specified flags. Creates and returns
 * a copy of the input p, with unwanted elements filtered out. */
fi_info * prune_param(fi_info * p, tcm_tid tids, tcm_addr_fmt afs) {
    using tcm_internal::fabric_to_tcm_af;
    using tcm_internal::prov_name_to_tid;
    fi_info * out = 0;
    for (fi_info * tmp = p; tmp; tmp = tmp->next) {
        tcm_addr_fmt af = fabric_to_tcm_af(tmp->addr_format);
        if (!(afs & af))
            continue;

        tcm_tid tid = prov_name_to_tid(tmp->fabric_attr->prov_name);
        if (!(tids & tid))
            continue;

        append_fi(&out, fi_dupinfo(tmp));
    }
    return out;
}

sockaddr_storage * prune_addrs(std::vector<tcm_conn_hints> & hints,
                               tcm_addr_fmt                  afs) {
    using tcm_internal::get_sa_size;
    using tcm_internal::sys_to_tcm_af;
    sockaddr_storage * out = (sockaddr_storage *) calloc(9, sizeof(*out));
    if (!out) {
        return 0;
    }
    int i = 0;
    for (auto iter : hints) {
        int sa_size = get_sa_size(iter._sa());
        if (sa_size < 0) {
            tcm__log_debug("Invalid sockaddr size!");
            continue;
        }
        tcm_addr_fmt af = sys_to_tcm_af(iter._sa()->sa_family);
        if (!(afs & af)) {
            tcm__log_debug("Invalid address format!");
            continue;
        }
        memcpy(&out[i++], iter.addr, sa_size);
        if (i == 8)
            return out;
    }
    return out;
}

ssize_t recv_and_verify(tcm_beacon * beacon, sockaddr * peer, void * mbuf,
                        size_t max_size, uint16_t token,
                        tcm_msg_type_flag flags) {
    ssize_t mlen = beacon->recv_dgram(peer, mbuf, max_size);
    if (mlen < 0) {
        return mlen;
    }

    tcm_mv_result res = tcm_msg_verify(mbuf, mlen, token, flags);
    if (res != tcm_mv::VALID) {
        tcm__log_debug("Message invalid: %s", tcm_mv::stringify(res));
        errno = res;
        return -EBADMSG;
    }

    return mlen;
}

int tcm_test_conns(fi_info * params, fi_info ** param_out, int flags,
                   sockaddr * local_addr, tcm_tid * tids, tcm_addr_fmt * afs,
                   shared_ptr<tcm_fabric> * f_out) {
    using tcm_internal::fabric_to_sys_af;
    using tcm_internal::fabric_to_tcm_af;
    using tcm_internal::get_sa_size;
    using tcm_internal::prov_name_to_tid;
    using tcm_internal::sys_to_fabric_af;
    shared_ptr<tcm_fabric> f;
    int                    v = 0, ttl = 0, dups = 0;
    int                    sa_size = 0;

    if (local_addr)
        sa_size = get_sa_size(local_addr);
    if (sa_size < 0)
        return -EINVAL;
    if (!f_out) {
        *tids = 0;
        *afs  = 0;
    }

    fi_info * tmp_p = 0;
    for (fi_info * tmp = params; tmp; tmp = tmp->next) {
        ttl++;
        tcm__log_trace("Testing fabric %s", tmp->fabric_attr->prov_name);

        /* Try to create a fabric connection with this peer */

        if (local_addr)
            tmp_p = fi_dupinfo(tmp);
        else
            tmp_p = tmp;

        try {
            tcm_time             t(3000, 500);
            tcm_fabric_init_opts opts;
            opts.flags      = 0;
            opts.tcm_flags  = 0;
            opts.timeout    = &t;
            opts.hints      = tmp_p;
            opts.no_getinfo = (flags & TCM_CONN_FLAG_PARAM) > 0;
            opts.version    = fi_version();
            if (local_addr) {
                int af = fabric_to_sys_af(tmp_p->addr_format);
                if (af != AF_UNSPEC && af != local_addr->sa_family) {
                    tcm__log_trace("Mismatched address format, fabric: %d, "
                                   "bind: %d, skipping",
                                   af, local_addr->sa_family);
                    continue;
                }
                if (tmp_p->src_addr) {
                    tcm_free_unset(tmp_p->src_addr);
                }
                tmp_p->src_addr = malloc(sa_size);
                if (!tmp_p->src_addr)
                    throw tcm_exception(ENOMEM, __FILE__, __LINE__,
                                        "Source address allocation failed");
                memcpy((void *) tmp_p->src_addr, local_addr, sa_size);
                tmp_p->src_addrlen = sa_size;
                tmp_p->addr_format = sys_to_fabric_af(local_addr->sa_family);
            }
            f = make_shared<tcm_fabric>(opts);
        } catch (std::exception & exc) {
            tcm__log_debug("Fabric creation failed: %s", exc.what());
            if (local_addr) {
                fi_freeinfo(tmp_p);
                tmp_p = 0;
            }
            continue;
        }

        /* Check if this transport is supported by tcm */
        fi_info * fi = (fi_info *) f->_get_fi_resource(TCM_RESRC_PARAM);
        assert(fi);

        tcm_tid tid = prov_name_to_tid(fi->fabric_attr->prov_name);
        if (tid == TCM_TID_INVALID) {
            tcm__log_trace("Provider %s not supported",
                           tmp->fabric_attr->prov_name);
            continue;
        }
        tcm_addr_fmt af = fabric_to_tcm_af(fi->addr_format);
        if (f_out) {
            if (!(*tids & tid)) {
                tcm__log_trace("Ignoring transport %s",
                               tmp->fabric_attr->prov_name);
                continue;
            }
            if (!(*afs & af)) {
                tcm__log_trace("Ignoring address format %d", fi->addr_format);
                continue;
            }
        }
        if (!f_out && (*tids & tid) && (flags & TCM_CONN_FLAG_ONCE)) {
            tcm__log_trace("Ignoring transport %s, a valid instance in the "
                           "list has already been found",
                           tmp->fabric_attr->prov_name);
            dups++;
            continue;
        }

        if (f_out) {
            if (param_out)
                *param_out = tmp_p;
            else if (local_addr) {
                fi_freeinfo(tmp_p);
                tmp_p = 0;
            }

            *f_out = f;
            *tids  = tid;
            return 1;
        } else {
            if (local_addr)
                fi_freeinfo(tmp_p);
            if (param_out) {
                fi = fi_dupinfo(fi);
                append_fi(param_out, fi);
            }
            *tids |= tid;
            *afs |= af;
            f = 0;
            v++;
        }
    }

    f = 0;
    tcm__log_debug("%d of %d transports usable (%d duplicates)", v, ttl, dups);
    return v == 0 ? -ENOTSUP : v;
}

/* Get working connections based on user input */
int get_working_conns(std::vector<tcm_conn_hints> & hints, tcm_tid * tids_out,
                      tcm_addr_fmt * afs_out, fi_info ** out) {
    fi_info * working = 0;
    fi_info * params  = 0;
    char      addr[INET6_ADDRSTRLEN];
    char      port[6];
    int       ret;
    size_t    size = sizeof(addr);

    tcm_addr_fmt afs  = 0;
    tcm_tid      tids = 0;

    uint32_t v     = fi_version();
    uint64_t flags = FI_SOURCE | FI_NUMERICHOST;

    int i = 0;
    for (auto iter : hints) {

        if (iter.addr) {
            size = sizeof(addr);
            ret  = tcm_internal::ntop(iter._sa(), addr, port, &size);
            if (ret < 0) {
                tcm__log_debug("Could not convert address!");
                continue;
            }
        }

        if (iter.addr && iter.hints) {
            tcm__log_debug("Hints+addr mode");
            tcm_internal::merge_tcm_hints(iter.hints);
            ret = fi_getinfo(v, addr, port, flags, iter.hints, &params);
        } else if (iter.hints) {
            tcm__log_debug("Hints-only mode");
            ret = fi_getinfo(v, NULL, NULL, 0, iter.hints, &params);
        } else {
            tcm__log_debug("Bind-only mode");
            fi_info * h = tcm_internal::get_tcm_hints(iter._sa());
            ret         = fi_getinfo(v, addr, port, flags, h, &params);
            fi_freeinfo(h);
        }

        if (ret < 0) {
            tcm__log_error("fi_getinfo() failed: %s", fi_strerror(-ret));
        }

        tcm_tid      tmp_tid = 0;
        tcm_addr_fmt tmp_af  = 0;
        int          flags   = TCM_CONN_FLAG_ONCE | TCM_CONN_FLAG_PARAM;
        ret = tcm_test_conns(params, &working, flags, nullptr, &tmp_tid,
                             &tmp_af, nullptr);
        if (ret < 0) {
            tcm__log_debug("Hint invalid at index %d", i);
        }

        if (params)
            fi_freeinfo(params);
        else
            assert(false && "Unexpected code path!");

        tids |= tmp_tid;
        afs |= tmp_af;
        params = 0;
        i++;
    }
    *out      = working;
    *tids_out = tids;
    *afs_out  = afs;
    return ret;
}

int tcm_accept_client_dynamic(tcm_accept_client_dynamic_param * p) {
    ssize_t ret, mlen;

    /* Extract the transports returned in fi_info into TCM transport ID flags */
    shared_ptr<tcm_fabric>   f;
    shared_ptr<tcm_endpoint> ep;
    shared_ptr<tcm_mem>      mem;
    sockaddr_storage         peer;
    memset((void *) &peer, 0, sizeof(peer));

    tcm_tid      tid_flags = 0, tid_sel = 0;
    tcm_addr_fmt af_flags = 0, af_sel = 0;

    fi_info *     valid_param = 0;
    fi_info *     pruned      = 0;
    fi_addr_t     f_addr      = FI_ADDR_UNSPEC;
    uint16_t      token;
    msg_container msg;

    sockaddr_storage * pruned_addrs = 0;

    int inv_msg_count = 0;
    int mcount        = 0;

    if (p->prv_data && p->prv_data->size > TCM_MAX_PRV_DATA_SIZE)
        return -EINVAL;

    CHECK_EXIT(p->exit_flag);

    if (p->peer && tcm_internal::check_af_support(p->peer->sa_family)) {
        ret = p->beacon->set_peer((sockaddr *) p->peer);
        if (ret < 0)
            tcm__log_warn("Failed to set peer address!");
    }
    tcm__log_trace("Set peer address");

    ret = get_working_conns(*p->hints, &tid_flags, &af_flags, &valid_param);
    if (ret < 0) {
        tcm__log_error("Failed to find a working transport: %s",
                       fi_strerror(-ret));
        return ret;
    }

    p->beacon->set_timeout(p->timeout_ms);

    while (1) {

        CHECK_EXIT(p->exit_flag);
        tcm_msg_type_flag allowed =
            TCM_MFLAG_CLIENT_PING | TCM_MFLAG_METADATA_REQ | TCM_MFLAG_CONN_REQ;
        ret = recv_and_verify(p->beacon, SA_CAST(&peer), msg.mbuf(),
                              TCM_MAX_MSG_SIZE, 0, allowed);
        if (ret == -EBADMSG) {
            if (inv_msg_count < 5) {
                tcm__log_debug("Message parsing failed: %s",
                               tcm_mv::stringify(ret));
                inv_msg_count++;
            }
            continue;
        }
        if (ret < 0) {
            goto cleanup;
        }

        token = msg.hdr()->token;
        if (msg.hdr()->type == TCM_MSG_CONN_REQ)
            break;

        bool   flag      = false;
        size_t send_size = 0;
        switch (msg.hdr()->type) {
            case TCM_MSG_CLIENT_PING: {
                tcm_ping_status st = TCM_PING_OK;
                if (p->prv_data && p->prv_data->validator) {
                    ret =
                        p->prv_data->validator(p->prv_data, &msg.c_ping()->prv,
                                               mlen - sizeof(*msg.c_ping()));
                    switch (ret) {
                        case TCM_PRV_INVALID:
                            return -EPROTO;
                        case TCM_PRV_INVALID_WITH_RESP:
                            st = TCM_PING_INVALID_PRV_DATA;
                            break;
                        case TCM_PRV_VALID:
                            break;
                        default:
                            assert(false && "Invalid state reached");
                            break;
                    }
                }
                msg.clear();
                send_size     = sizeof(*msg.s_ping());
                *msg.s_ping() = tcm_msg_server_ping(token, st);
                if (p->prv_data && p->prv_data->data && p->prv_data->size) {
                    tcm__log_trace("Including %d bytes private data",
                                   p->prv_data->size);
                    memcpy(&msg.s_ping()->prv, p->prv_data->data,
                           p->prv_data->size);
                    send_size += p->prv_data->size;
                }
                break;
            }
            case TCM_MSG_METADATA_REQ: {
                msg.clear();
                *msg.mtd_resp() = tcm_msg_metadata_resp(
                    TCM_DEFAULT_FABRIC_VERSION, fi_version(), af_flags,
                    tid_flags, token);
                send_size = sizeof(*msg.mtd_resp());
                break;
            }
            case TCM_MSG_CONN_REQ: {
                flag = true;
                break;
            }
            default:
                assert(false && "Invalid state reached");
        }

        if (flag)
            break;

        mcount++;

        /* Send a response to stateless info messages */
        mlen = p->beacon->send_dgram(SA_CAST(&peer), msg.mbuf(), send_size);
        if (mlen < 0) {
            if (mlen != -EINTR)
                tcm__log_debug("Datagram send failed: %s", strerror(-mlen));
            return mlen;
        }

        /* If we need to exit because the private data validation failed, exit
         * here */
        if (p->prv_data && ret == TCM_PRV_INVALID_WITH_RESP) {
            return -EPROTO;
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
    p->beacon->set_peer((sockaddr *) &peer);
    if (!(msg.conn_req()->addr_fmt & TCM_SUPPORTED_AFS)) {
        tcm__log_debug("Unsupported address format: %d");
        ret = -ENOTSUP;
        goto cleanup;
    }

    tid_sel = tid_flags & msg.conn_req()->tid;
    if (!tid_sel) {
        tcm__log_debug("Failed to find common transport protocol");
        tcm__log_debug("Local: %d, Peer: %d", tid_flags, msg.conn_req()->tid);
        ret = -EBADMSG;
        goto cleanup;
    }

    af_sel = af_flags & msg.conn_req()->addr_fmt;
    if (!af_sel) {
        tcm__log_debug("Failed to find common address format");
        tcm__log_debug("Local: %d, Peer: %d", af_flags,
                       msg.conn_req()->addr_fmt);
        ret = -EBADMSG;
        goto cleanup;
    }

    if (tcm_internal::popcnt8(tid_sel) != 1 ||
        tcm_internal::popcnt8(af_sel) != 1) {
        tcm__log_debug(
            "Client requested more than one transport or address format!");
        ret = -EBADMSG;
        goto cleanup;
    }

    pruned = prune_param(valid_param, tid_sel, af_sel);
    if (!pruned) {
        tcm__log_debug("No matching transports or address formats found!");
        ret = -ENOTSUP;
        goto cleanup;
    }
    pruned_addrs = prune_addrs(*p->hints, af_sel);
    if (!pruned_addrs) {
        tcm__log_debug("No valid bind address found!");
        ret = -ENOTSUP;
        goto cleanup;
    }

    ret = tcm_test_conns(pruned, nullptr,
                         TCM_CONN_FLAG_ONCE | TCM_CONN_FLAG_PARAM, nullptr,
                         &tid_sel, &af_sel, &f);
    if (ret < 0) {
        tcm__log_debug("Fabric creation failed: %s", fi_strerror(-ret));
        goto cleanup;
    }

    CHECK_EXIT(p->exit_flag);

    try {
        sockaddr_storage sa;
        size_t           size = sizeof(sa);
        ret =
            tcm_deserialize_addr(msg.conn_req()->addr, msg.conn_req()->addr_len,
                                 msg.conn_req()->addr_fmt, &sa, &size);
        if (ret < 0) {
            tcm__log_debug("Address decode failed: %s", strerror(-ret));
            goto cleanup;
        }
        f_addr = f->add_peer((sockaddr *) &sa);
        if (f_addr == FI_ADDR_UNSPEC) {
            tcm__log_error("Failed to add peer to fabric: %s",
                           fi_strerror(errno));
            goto cleanup;
        }
        tcm_time t(3000, 500);
        ep = make_shared<tcm_endpoint>(f, SA_CAST(pruned_addrs), &t);
    } catch (tcm_exception & exc) {
        ret = -exc.return_code();
        tcm__log_error("Failed to create endpoint: %s", exc.what());
        goto cleanup;
    }

    CHECK_EXIT(p->exit_flag);

    /* Send a response */
    {
        sockaddr_storage name;
        size_t           buf_size = sizeof(sockaddr_in6);
        ret                       = ep->get_name((void *) &name, &buf_size);
        if (ret < 0) {
            tcm__log_error("Unable to get fabric endpoint name: %s",
                           fi_strerror(-ret));
            goto cleanup;
        }

        tcm__log_debug("Transport id = %d", f->_get_tid());

        *msg.conn_resp() =
            tcm_msg_conn_resp_storage(token, f->_get_tid(), SA_CAST(&name));
        ret = p->beacon->send_dgram(SA_CAST(&peer), msg.mbuf(),
                                    msg.conn_resp()->get_size());
        if (ret < 0) {
            tcm__log_error("Unable to send datagram: %s", strerror(-ret));
            goto cleanup;
        }
    }

    CHECK_EXIT(p->exit_flag);

    /* Wait for a fabric ping */
    try {
        mem = make_shared<tcm_mem>(f, tcm_get_page_size());
    } catch (tcm_exception & exc) {
        ret = -exc.return_code();
        tcm__log_error("Unable to register memory: %s", exc.what());
        goto cleanup;
    }

    CHECK_EXIT(p->exit_flag);

    {
        tcm_msg_fabric_ping * ping =
            reinterpret_cast<tcm_msg_fabric_ping *>(**mem);

        ret = ep->srecv(*mem, f_addr, 0, sizeof(tcm_msg_fabric_ping));
        if (ret < 0) {
            tcm__log_error("Failed to receive ping: %s", fi_strerror(ret));
            goto cleanup;
        }

        CHECK_EXIT(p->exit_flag);

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

        CHECK_EXIT(p->exit_flag);
    }

    /* Success */
    p->beacon->reset_peer();
    p->fabric_out      = f;
    p->ep_out          = ep;
    p->fabric_peer_out = f_addr;
    if (p->peer && p->peer->sa_family == AF_UNSPEC) {
        int sa_size = tcm_internal::get_sa_size((sockaddr *) &peer);
        if (sa_size < 0) {
            tcm__log_warn("Could not get peer information!");
        }
        memcpy(p->peer, &p, sa_size);
    }
    if (pruned) {
        fi_freeinfo(pruned);
        pruned = 0;
    }
    if (valid_param) {
        fi_freeinfo(valid_param);
        valid_param = 0;
    }
    if (pruned_addrs) {
        free(pruned_addrs);
    }
    return 0;

cleanup:
    p->beacon->reset_peer();
    if (f_addr != FI_ADDR_UNSPEC)
        f->remove_peer(f_addr);
    mem = 0;
    ep  = 0;
    f   = 0;
    if (pruned) {
        fi_freeinfo(pruned);
        pruned = 0;
    }
    if (valid_param) {
        fi_freeinfo(valid_param);
        valid_param = 0;
    }
    if (pruned_addrs) {
        free(pruned_addrs);
    }
    return ret;
}

int tcm_client_dynamic(tcm_client_dynamic_param * p) {
    assert(p);
    assert(p->beacon);
    assert(p->peer);

    shared_ptr<tcm_fabric>   f  = 0;
    shared_ptr<tcm_endpoint> ep = 0;

    msg_container msg;
    ssize_t       ret;
    ssize_t       mlen;
    fi_info *     valid_param = 0;
    fi_addr_t     f_peer      = FI_ADDR_UNSPEC;

    fi_info *          pruned       = 0;
    sockaddr_storage * pruned_addrs = 0;
    tcm_tid            tid_flags = 0, tid_sel = 0;
    tcm_addr_fmt       af_flags = 0, af_sel = 0;

    ret = get_working_conns(*p->hints, &tid_flags, &af_flags, &valid_param);
    if (ret < 0) {
        tcm__log_error("Failed to find a working transport: %s",
                       fi_strerror(-ret));
        return ret;
    }

    CHECK_EXIT(p->exit_flag);

    p->beacon->set_timeout(p->timeout_ms);
    p->beacon->set_peer(p->peer);

    /* Fast connection mode can be used if the client already knows the server
       has supported features / compatible versions ahead of time (e.g. the
       information was exchanged manually or outside the control of TCM) */
    if (!p->fast) {
        *msg.c_ping()    = tcm_msg_client_ping(1);
        size_t send_size = sizeof(*msg.c_ping());
        if (p->prv_data && p->prv_data->data && p->prv_data->size) {
            tcm__log_trace("Including %d bytes private data",
                           p->prv_data->size);
            memcpy(&msg.c_ping()->prv, p->prv_data->data, p->prv_data->size);
            send_size += p->prv_data->size;
        }

        mlen = p->beacon->send_dgram(p->peer, msg.mbuf(), send_size);
        if (mlen < 0) {
            tcm__log_error("Failed to send ping: %s", strerror(-mlen));
            return mlen;
        }

        CHECK_EXIT(p->exit_flag);

        memset(msg.mbuf(), 0, TCM_MAX_MSG_SIZE);
        mlen = p->beacon->recv_dgram(p->peer, msg.mbuf(), TCM_MAX_MSG_SIZE);
        if (mlen < 0) {
            tcm__log_error("Failed to receive response: %s", strerror(-mlen));
            return mlen;
        }

        CHECK_EXIT(p->exit_flag);

        ret = tcm_msg_verify(msg.mbuf(), mlen, 1, TCM_MFLAG_SERVER_PING);
        if (ret != tcm_mv::VALID) {
            tcm__log_error("Peer sent invalid message: %s",
                           tcm_mv::stringify(ret));
            return -EBADMSG;
        }

        /* Verify private data if any. The TCM_PRV_INVALID_WITH_RESP option is
         * ignored here, it's only for the server */
        if (p->prv_data && p->prv_data->validator) {
            if (p->prv_data->validator(p->prv_data, &msg.s_ping()->prv,
                                       mlen - sizeof(*msg.s_ping())) !=
                TCM_PRV_VALID) {
                return -EPROTO;
            }
        }

        /* Get extended metadata */
        *msg.mtd_req() = tcm_msg_metadata_req(2);

        mlen =
            p->beacon->send_dgram(p->peer, msg.mbuf(), sizeof(*msg.mtd_req()));
        if (mlen < 0) {
            tcm__log_error("Failed to send metadata request: %s",
                           strerror(-mlen));
            return mlen;
        }

        CHECK_EXIT(p->exit_flag);
        memset(msg.mbuf(), 0, TCM_MAX_MSG_SIZE);

        mlen = p->beacon->recv_dgram(p->peer, msg.mbuf(), TCM_MAX_MSG_SIZE);
        if (mlen < 0) {
            tcm__log_error("Failed to receive response: %s", strerror(-mlen));
            return mlen;
        }

        ret = tcm_msg_verify(msg.mbuf(), mlen, 2,
                             TCM_MFLAG_METADATA_RESP | TCM_MFLAG_STATUS);
        if (ret != tcm_mv::VALID) {
            tcm__log_error("Peer sent invalid message: %s",
                           tcm_mv::stringify(ret));
            return -EBADMSG;
        }

        switch (msg.hdr()->type) {
            case TCM_MSG_METADATA_RESP: {

                if (msg.mtd_resp()->fabric_min > fi_version()) {
                    tcm__log_error(
                        "Unable to find a supported Libfabric version! Local: "
                        "%d.%d, Peer: min %d.%d - max %d.%d",
                        FI_MAJOR(fi_version()), FI_MINOR(fi_version()),
                        FI_MAJOR(msg.mtd_resp()->fabric_min),
                        FI_MINOR(msg.mtd_resp()->fabric_min),
                        FI_MAJOR(msg.mtd_resp()->fabric_max),
                        FI_MINOR(msg.mtd_resp()->fabric_min));
                    return -ENOTSUP;
                }
                if (!(tid_flags & msg.mtd_resp()->tids)) {
                    tcm__log_error(
                        "Transport type flag mismatch! Local: %d, Peer: %d",
                        tid_flags, msg.mtd_resp()->tids);
                }
                if (msg.mtd_resp()->addr_fmt != TCM_AF_INET) {
                    tcm__log_error("Address format unsupported!");
                    return -ENOTSUP;
                }
                break;
            }
            case TCM_MSG_STATUS: {
                tcm__log_error(
                    "Peer closed connection with return code %d (%s)",
                    msg.status()->retcode,
                    tcm_err_string(msg.status()->retcode));
                return -ECONNRESET;
            }
            default:
                assert(false);
        }
    }

    /* Remove addresses and fi_info structs with parameters incompatible with
     * the peer */

    tid_sel = tid_flags & msg.mtd_resp()->tids;
    if (!tid_sel) {
        tcm__log_debug("No compatible transport found!");
        goto cleanup;
    }
    af_sel = af_flags & msg.mtd_resp()->addr_fmt;
    if (!af_sel) {
        tcm__log_debug("No compatible address format found!");
        goto cleanup;
    }
    pruned = prune_param(valid_param, tid_sel, af_sel);
    if (!pruned) {
        tcm__log_debug("No matching transports or address formats found!");
        tcm__log_debug("Local/Peer Address: %d/%d, Transport: %d/%d", af_flags,
                       msg.mtd_resp()->addr_fmt, tid_flags,
                       msg.mtd_resp()->tids);
        ret = -ENOTSUP;
        goto cleanup;
    }
    pruned_addrs = prune_addrs(*p->hints, af_sel);
    if (!pruned_addrs) {
        tcm__log_debug("No valid bind address found!");
        ret = -ENOTSUP;
        goto cleanup;
    }

    try {
        CHECK_EXIT(p->exit_flag);
        ret = tcm_test_conns(pruned, nullptr,
                             TCM_CONN_FLAG_ONCE | TCM_CONN_FLAG_PARAM,
                             SA_CAST(pruned_addrs), &tid_sel, &af_sel, &f);
        if (ret < 0) {
            tcm__log_error("Failed to create any fabric connection: %s",
                           fi_strerror(-ret));
            goto cleanup;
        }

        f->bind_exit_flag(p->exit_flag);
        CHECK_EXIT(p->exit_flag);

        /* Create an endpoint and get the local address */
        ep = make_shared<tcm_endpoint>(f, SA_CAST(pruned_addrs), TCM_TIME_NULL);
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

        CHECK_EXIT(p->exit_flag);

        /* Send local address details to peer */
        *msg.conn_req() = tcm_msg_conn_req_storage(
            0x1234, f->get_version(), f->_get_tid(), (sockaddr *) &name);

        mlen = p->beacon->send_dgram(p->peer, msg.mbuf(),
                                     msg.conn_req()->get_size());
        if (mlen < 0) {
            tcm__log_error("Failed to send datagram: %s", strerror(-mlen));
            ret = -ECOMM;
            goto cleanup;
        }

        CHECK_EXIT(p->exit_flag);

        mlen = p->beacon->recv_dgram(p->peer, msg.mbuf(), TCM_MAX_MSG_SIZE);
        if (mlen < 0) {
            tcm__log_error("Failed to receive datagram: %s", strerror(-mlen));
            ret = -ECOMM;
            goto cleanup;
        }

        ret = tcm_msg_verify(msg.mbuf(), mlen, 0x1234,
                             TCM_MFLAG_CONN_RESP | TCM_MFLAG_STATUS);
        if (ret != tcm_mv::VALID) {
            tcm__log_error("Peer sent invalid message: %s",
                           tcm_mv::stringify(ret));
            ret = -EBADMSG;
            goto cleanup;
        }

        switch (msg.hdr()->type) {
            case TCM_MSG_STATUS: {
                tcm__log_error(
                    "Peer closed connection with return code %d (%s)",
                    msg.status()->retcode,
                    tcm_err_string(msg.status()->retcode));
                ret = -ECONNRESET;
                goto cleanup;
            }
            case TCM_MSG_CONN_RESP: {
                if (!(tid_flags & msg.conn_resp()->tid)) {
                    tcm__log_error(
                        "Transport type flag mismatch! Local: %d, Peer: %d",
                        tid_flags, msg.conn_resp()->tid);
                    ret = -ENOTSUP;
                    goto cleanup;
                }
                if (!(msg.conn_resp()->addr_fmt & TCM_SUPPORTED_AFS)) {
                    tcm__log_error("Address format unsupported!");
                    ret = -EPFNOSUPPORT;
                    goto cleanup;
                }
                sockaddr_storage sa;
                size_t           sa_size = sizeof(sa);
                memset(&sa, 0, sa_size);
                ret = tcm_deserialize_addr(
                    msg.conn_resp()->addr, msg.conn_resp()->addr_len,
                    msg.conn_resp()->addr_fmt, &sa, &sa_size);
                if (ret < 0) {
                    tcm__log_error("Could not decode address: %s",
                                   strerror(-ret));
                    goto cleanup;
                }
                f_peer = f->add_peer(SA_CAST(&sa));
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
    } catch (tcm_exception & exc) {
        ret = -exc.return_code();
        tcm__log_error("Failed to create connection: %s", exc.what());
        goto cleanup;
    }

    /* The response is correct, create EP, allocate RDMA memory and send fabric
     * pings */
    {
        CHECK_EXIT(p->exit_flag);
        const size_t          pl = sizeof(tcm_msg_fabric_ping);
        tcm_time              t(3000, 500);
        auto                  mem = tcm_mem(f, tcm_get_page_size());
        tcm_msg_fabric_ping * ping =
            reinterpret_cast<tcm_msg_fabric_ping *>(*mem);
        *ping                      = tcm_msg_fabric_ping(0x2345, 0);
        tcm_msg_fabric_ping * resp = (ping + 1);
        memset((void *) resp, 0, pl);

        ret = ep->recv(mem, f_peer, CTX_CAST(1), pl, pl);
        if (ret < 0) {
            tcm__log_error("Failed to queue recv: %s", fi_strerror(-ret));
            goto cleanup;
        }

        ret = ep->send(mem, f_peer, CTX_CAST(2), 0, pl);
        if (ret < 0) {
            tcm__log_error("Failed to queue send: %s", fi_strerror(-ret));
            goto cleanup;
        }

        shared_ptr<tcm_cq> cq = ep->get_cq().lock();

        for (int i = 0; i < 2; i++) {
            CHECK_EXIT(p->exit_flag);
            tcm_time        t(p->timeout_ms, 0);
            fi_cq_err_entry err;
            ret = cq->spoll(&err, &err, 1, nullptr, 0, &t);
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

    p->peer_out   = f_peer;
    p->fabric_out = f;
    p->ep_out     = ep;
    if (valid_param)
        fi_freeinfo(valid_param);
    return 0;

cleanup:
    ep = 0;
    if (f_peer != FI_ADDR_UNSPEC)
        f->remove_peer(f_peer);
    f = 0;
    if (valid_param)
        fi_freeinfo(valid_param);
    return ret;
}