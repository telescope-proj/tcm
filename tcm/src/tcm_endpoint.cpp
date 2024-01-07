// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#include "tcm_errno.h"
#include "tcm_fabric.h"
#include "tcm_log.h"

using std::make_shared;
using std::shared_ptr;

enum data_xfer_type {
    XFER_INVALID    = 0,
    XFER_SEND       = 1,
    XFER_TSEND      = 2,
    XFER_RECV       = 3,
    XFER_TRECV      = 4,
    XFER_RDMA_READ  = 5,
    XFER_RDMA_WRITE = 6,
    XFER_MAX
};

static const char * xfer_type_str(uint8_t type) {
    switch (type) {
        case XFER_SEND:
            return "send";
        case XFER_TSEND:
            return "tagged send";
        case XFER_RECV:
            return "recv";
        case XFER_TRECV:
            return "tagged recv";
        case XFER_RDMA_READ:
            return "RDMA read";
        case XFER_RDMA_WRITE:
            return "RDMA write";
        default:
            return "invalid";
    }
}

void tcm_endpoint::bind_exit_flag(volatile int * exit_flag) {
    this->exit_flag = exit_flag;
}

void tcm_endpoint::clear_fields() {
    this->cq          = 0;
    this->rx_cq       = 0;
    this->fabric      = 0;
    this->ep          = 0;
    this->src_addr    = 0;
    this->src_addrlen = 0;
    this->exit_flag   = 0;
    this->timeout.unset();
}

tcm_endpoint::~tcm_endpoint() {
    if (this->ep) {
        fi_close(&this->ep->fid);
    }
    tcm_free_unset(this->src_addr);
    this->src_addrlen = 0;
    this->fabric      = 0;
}

int tcm_endpoint::init(shared_ptr<tcm_fabric> fab, sockaddr * addr,
                       tcm_time * timeo, shared_ptr<tcm_cq> cq,
                       shared_ptr<tcm_cq> rx_cq) {
    ssize_t   ret;
    fi_info * info = 0;
    assert(cq.get());
    this->unified_cq = (rx_cq.get() == 0);
    if (timeo)
        this->timeout = *timeo;
    else
        this->timeout = tcm_time(3000, 500);

    if (addr) {
        info = fi_dupinfo(fab->fi);
        if (!info)
            throw tcm_exception(ENOMEM, __FILE__, __LINE__,
                                "Fabric info structure duplication failed");
        tcm_free_unset(info->src_addr);
        int sa_size = tcm_internal::get_sa_size(addr);
        if (sa_size < 0) {
            ret = sa_size;
            goto err;
        }
        info->src_addr = malloc(sa_size);
        if (!info->src_addr) {
            throw tcm_exception(ENOMEM, __FILE__, __LINE__,
                                "Source address buffer allocation failed");
        }
        memcpy((void *) info->src_addr, addr, sa_size);
        info->src_addrlen = sa_size;
    } else {
        info = fab->fi;
    }

    ret = fi_endpoint(fab->top->domain, info, &this->ep, (void *) this);
    if (ret < 0) {
        tcm__log_error("Failed to create endpoint: %s", fi_strerror(-ret));
        goto err;
    }

    ret = fi_ep_bind(this->ep, &fab->av->fid, 0);
    if (ret < 0) {
        tcm__log_error("Error binding AV to endpoint: %s", fi_strerror(-ret));
        goto err;
    }

    if (this->unified_cq) {
        ret = fi_ep_bind(this->ep, &cq->cq->fid, FI_TRANSMIT | FI_RECV);
        if (ret < 0) {
            tcm__log_error("Error binding CQ to endpoint: %s",
                           fi_strerror(tcm_abs(ret)));
            goto err;
        }
        this->cq = cq;
    } else {
        ret = fi_ep_bind(this->ep, &cq->cq->fid, FI_TRANSMIT);
        if (ret < 0) {
            tcm__log_error("Error binding TX CQ to endpoint: %s",
                           fi_strerror(tcm_abs(ret)));
            goto err;
        }
        ret = fi_ep_bind(this->ep, &rx_cq->cq->fid, FI_RECV);
        if (ret < 0) {
            tcm__log_error("Error binding RX CQ to endpoint: %s",
                           fi_strerror(tcm_abs(ret)));
            goto err;
        }
        this->cq    = cq;
        this->rx_cq = cq;
    }

    ret = fi_enable(this->ep);
    if (ret < 0) {
        tcm__log_error("Fabric enable failed: %s", fi_strerror(tcm_abs(ret)));
        goto err;
    }

    /* Get address (for dynamic endpoints) */

    this->src_addrlen = 0;
    ret               = fi_getname(&this->ep->fid, NULL, &this->src_addrlen);
    if (ret != -FI_ETOOSMALL) {
        tcm__log_error("Failed to get endpoint name: %s",
                       fi_strerror(tcm_abs(ret)));
        goto err;
    }

    this->src_addr = malloc(this->src_addrlen);
    if (!this->src_addr) {
        tcm__log_error("Memory allocation failed");
        goto err;
    }

    ret = fi_getname(&this->ep->fid, this->src_addr, &this->src_addrlen);
    if (ret < 0) {
        tcm__log_error("Failed to get endpoint name: %s",
                       fi_strerror(tcm_abs(ret)));
        goto err;
    }

    {
        char   host[INET6_ADDRSTRLEN];
        char   port[6];
        size_t size    = sizeof(host);
        int    sa_size = tcm_internal::get_sa_size((sockaddr *) this->src_addr);
        ret            = tcm_internal::ntop(this->src_addr, host, port, &size);
        if (ret == 0) {
            tcm__log_debug("Endpoint address (%d): %s:%s", sa_size, host, port);
        } else {
            tcm__log_debug("Unable to display fabric address");
        }
    }

    this->fabric = fab;
    return 0;

err:
    if (addr && info) {
        fi_freeinfo(info);
    }
    this->~tcm_endpoint();
    return ret;
}

tcm_endpoint::tcm_endpoint(shared_ptr<tcm_fabric> fab, sockaddr * addr,
                           tcm_time * timeo) {
    this->clear_fields();
    shared_ptr<tcm_cq> icq = make_shared<tcm_cq>(fab, 128);
    int                ret = this->init(fab, addr, timeo, icq, 0);
    if (ret < 0)
        throw tcm_exception(-ret, __FILE__, __LINE__,
                            "Endpoint creation failed");
}

tcm_endpoint::tcm_endpoint(shared_ptr<tcm_fabric> fab, sockaddr * addr,
                           tcm_time * timeo, shared_ptr<tcm_cq> cq_) {
    this->clear_fields();
    int ret = this->init(fab, addr, timeo, cq_, 0);
    if (ret < 0)
        throw tcm_exception(-ret, __FILE__, __LINE__,
                            "Endpoint creation failed");
}

tcm_endpoint::tcm_endpoint(shared_ptr<tcm_fabric> fab, sockaddr * addr,
                           tcm_time * timeo, shared_ptr<tcm_cq> txcq,
                           shared_ptr<tcm_cq> rxcq) {
    this->clear_fields();
    int ret = this->init(fab, addr, timeo, txcq, rxcq);
    if (ret < 0)
        throw tcm_exception(-ret, __FILE__, __LINE__,
                            "Endpoint creation failed");
}

int tcm_endpoint::get_name(void * buf, size_t * buf_size) noexcept {
    int ret;
    ret = fi_getname(&this->ep->fid, buf, buf_size);
    if (ret != 0) {
        tcm__log_debug("fi_getname failed: %s", fi_strerror(tcm_abs(ret)));
        return ret;
    }

    if (this->src_addrlen < *buf_size) {
        void * p = realloc(this->src_addr, *buf_size);
        if (!p) {
            tcm__log_debug("Memory allocation failed");
            return -ENOMEM;
        }
        this->src_addr = p;
    }

    this->src_addrlen = *buf_size;
    memcpy((void *) this->src_addr, buf, *buf_size);

    tcm__log_debug("Read fabric endpoint address buf=%p, size=%lu", buf,
                   *buf_size);
    return 0;
}

int tcm_endpoint::set_name(void * buf, size_t buf_size) noexcept {
    tcm__log_debug("Modifying fabric endpoint address buf=%p, size=%lu", buf,
                   buf_size);
    int ret = fi_setname(&this->ep->fid, buf, buf_size);
    if (ret < 0)
        return ret;

    if (this->src_addrlen < buf_size) {
        void * p = realloc(this->src_addr, buf_size);
        if (!p) {
            tcm__log_debug("Memory allocation failed");
            return -ENOMEM;
        }
        this->src_addr = p;
    }

    this->src_addrlen = buf_size;
    memcpy((void *) this->src_addr, buf, buf_size);

    return 0;
}

void tcm_endpoint::set_timeout(tcm_time & time) noexcept {
    this->timeout = time;
}

const tcm_time & tcm_endpoint::get_timeout() noexcept { return this->timeout; }

ssize_t tcm_endpoint::data_xfer_rdma(uint8_t type, fi_addr_t peer,
                                     tcm_mem & mem, tcm_remote_mem & rmem,
                                     uint64_t local_offset,
                                     uint64_t remote_offset, uint64_t len,
                                     void * ctx) {
    if (!mem.check_parent(this->fabric.get())) {
        throw tcm_exception(EINVAL, __FILE__, __LINE__,
                            "Attempt to use invalid memory object "
                            "would result in a program crash");
    }
    if (rmem.raw) {
        throw tcm_exception(ENOTSUP, __FILE__, __LINE__,
                            "TCM does not currently support raw memory keys");
    }

    uint64_t rbuf    = rmem.addr + remote_offset;
    void *   buf     = (void *) (((uint8_t *) *mem) + local_offset);
    uint64_t buf_len = mem.get_len();
    void *   desc    = mem.get_mr_desc();
    if (local_offset + len > buf_len || local_offset > buf_len || len > buf_len)
        throw tcm_exception(
            EINVAL, __FILE__, __LINE__,
            "Requested local memory buffer offset out of range");
    if (remote_offset + len > rmem.len || remote_offset > rmem.len ||
        len > rmem.len)
        throw tcm_exception(
            EINVAL, __FILE__, __LINE__,
            "Requested remote memory buffer offset out of range");
    switch (type) {
        case XFER_RDMA_READ:
            return fi_read(this->ep, buf, len, desc, peer, rbuf, rmem.u.rkey,
                           ctx);
        case XFER_RDMA_WRITE:
            return fi_write(this->ep, buf, len, desc, peer, rbuf, rmem.u.rkey,
                            ctx);
        default:
            throw tcm_exception(EINVAL, __FILE__, __LINE__,
                                "Invalid RDMA data transfer type");
    }
}

ssize_t tcm_endpoint::data_xfer(uint8_t type, fi_addr_t peer, tcm_mem & mem,
                                uint64_t offset, uint64_t len, uint64_t tag,
                                uint64_t mask, uint8_t sync, void * ctx) {
    if (!mem.check_parent(this->fabric.get())) {
        throw tcm_exception(EINVAL, __FILE__, __LINE__,
                            "Attempt to use invalid memory object "
                            "would result in a program crash");
    }
    ssize_t         ret;
    struct timespec dl;
    tcm_get_abs_time(&this->timeout, &dl);
    void *   buf     = (void *) (((uint8_t *) *mem) + offset);
    uint64_t buf_len = mem.get_len();
    void *   desc    = mem.get_mr_desc();
    int      tcat    = 0;
    /* Check individually too in case of overflow */
    if (offset + len > buf_len || offset > buf_len || len > buf_len)
        throw tcm_exception(
            EINVAL, __FILE__, __LINE__,
            "Requested local memory buffer offset out of range");
    do {
        if (this->exit_flag && *this->exit_flag > 0) {
            ret = -ECANCELED;
            return ret;
        }

        switch (type) {
            case XFER_SEND:
                ret  = fi_send(this->ep, buf, len, desc, peer, ctx);
                tcat = 0;
                break;
            case XFER_TSEND:
                ret  = fi_tsend(this->ep, buf, len, desc, peer, tag, ctx);
                tcat = 0;
                break;
            case XFER_RECV:
                ret  = fi_recv(this->ep, buf, len, desc, peer, ctx);
                tcat = 1;
                break;
            case XFER_TRECV:
                ret  = fi_trecv(this->ep, buf, len, desc, peer, tag, mask, ctx);
                tcat = 1;
                break;
            default:
                throw tcm_exception(EINVAL, __FILE__, __LINE__,
                                    "Invalid data transfer type");
        }
        if (ret == 0) {
            if (sync)
                break;
            return 1;
        } else if (ret == -FI_EAGAIN || ret == -FI_EWOULDBLOCK) {
            tcm_usleep(this->timeout.interval);
            continue;
        } else {
            tcm__log_error("Fabric %s failed: %s", xfer_type_str(type),
                           fi_strerror(-ret));
            return ret;
        }
    } while (!tcm_check_deadline(&dl));

    if (sync && !tcm_check_deadline(&dl)) {
        if (this->exit_flag && *this->exit_flag > 0) {
            ret = -ECANCELED;
            return ret;
        }

        tcm_cq * tcq = 0;
        switch (tcat) {
            case 0:
                tcq = this->cq.get();
                break;
            case 1:
                if (unified_cq)
                    tcq = this->cq.get();
                else
                    tcq = this->rx_cq.get();
                break;
            default:
                assert(false && "Invalid state!");
                throw tcm_exception(EINVAL, __FILE__, __LINE__,
                                    "Invalid system state!");
        }

        tcm_time               abst(&dl);
        struct fi_cq_err_entry err;
        ret = tcq->spoll(&err, &err, 1, nullptr, 0, &abst);
        switch (ret) {
            case 0:
            case -FI_EAGAIN:
                break;
            case 1:
                return err.len;
            default:
                return ret;
        }
    }

    tcm__log_trace("Timed out %d %d %lu.%lu %lu.%lu %d", this->timeout.timeout,
                   this->timeout.interval, this->timeout.ts.tv_sec,
                   this->timeout.ts.tv_nsec, dl.tv_sec, dl.tv_nsec,
                   this->timeout.mode);
    return -ETIMEDOUT;
}

ssize_t tcm_endpoint::send(tcm_mem & mem, fi_addr_t peer, void * ctx,
                           uint64_t offset, uint64_t len) {
    return this->data_xfer(XFER_SEND, peer, mem, offset, len, 0, 0, 0, ctx);
}

ssize_t tcm_endpoint::recv(tcm_mem & mem, fi_addr_t peer, void * ctx,
                           uint64_t offset, uint64_t len) {
    return this->data_xfer(XFER_RECV, peer, mem, offset, len, 0, 0, 0, ctx);
}

ssize_t tcm_endpoint::tsend(tcm_mem & mem, fi_addr_t peer, void * ctx,
                            uint64_t offset, uint64_t len, uint64_t tag) {
    return this->data_xfer(XFER_TSEND, peer, mem, offset, len, tag, 0, 0, ctx);
}

ssize_t tcm_endpoint::trecv(tcm_mem & mem, fi_addr_t peer, void * ctx,
                            uint64_t offset, uint64_t len, uint64_t tag,
                            uint64_t mask) {
    return this->data_xfer(XFER_TRECV, peer, mem, offset, len, tag, mask, 0,
                           ctx);
}

ssize_t tcm_endpoint::ssend(tcm_mem & mem, fi_addr_t peer, uint64_t offset,
                            uint64_t len) {
    return this->data_xfer(XFER_SEND, peer, mem, offset, len, 0, 0, 1, 0);
}

ssize_t tcm_endpoint::srecv(tcm_mem & mem, fi_addr_t peer, uint64_t offset,
                            uint64_t len) {
    return this->data_xfer(XFER_RECV, peer, mem, offset, len, 0, 0, 1, 0);
}

ssize_t tcm_endpoint::rwrite(tcm_mem & mem, tcm_remote_mem & rmem, void * ctx,
                             uint64_t local_offset, uint64_t remote_offset,
                             uint64_t len) {
    return this->data_xfer_rdma(XFER_RDMA_WRITE, rmem.peer, mem, rmem,
                                local_offset, remote_offset, len, ctx);
}

ssize_t tcm_endpoint::rread(tcm_mem & mem, tcm_remote_mem & rmem, void * ctx,
                            uint64_t local_offset, uint64_t remote_offset,
                            uint64_t len) {
    return this->data_xfer_rdma(XFER_RDMA_READ, rmem.peer, mem, rmem,
                                local_offset, remote_offset, len, ctx);
}