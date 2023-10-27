// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#include "tcm_errno.h"
#include "tcm_fabric.h"
#include "tcm_log.h"

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

ssize_t tcm_fabric::data_xfer_rdma(uint8_t type, tcm_mem & mem,
                                   tcm_remote_mem & rmem, uint64_t local_offset,
                                   uint64_t remote_offset, uint64_t len,
                                   fi_addr_t peer, void * ctx) {
    if (!mem._check_parent(this)) {
        tcm__log_error("Invalid memory region used for fabric object");
        throw EINVAL;
    }

    uint64_t rbuf    = rmem.addr + remote_offset;
    void *   buf     = (void *) (((uint8_t *) mem.get_ptr()) + local_offset);
    uint64_t buf_len = mem.get_len();
    void *   desc    = mem.get_mr_desc();
    if (local_offset + len > buf_len || local_offset > buf_len || len > buf_len)
        throw EINVAL;
    if (remote_offset + len > rmem.len || remote_offset > rmem.len ||
        len > rmem.len)
        throw EINVAL;
    switch (type) {
        case XFER_RDMA_READ:
            return fi_read(this->ep, buf, len, desc, peer, rbuf, rmem.rkey,
                           ctx);
        case XFER_RDMA_WRITE:
            return fi_write(this->ep, buf, len, desc, peer, rbuf, rmem.rkey,
                            ctx);
        default:
            throw EINVAL;
    }
}

ssize_t tcm_fabric::data_xfer(uint8_t type, tcm_mem & mem, uint64_t offset,
                              uint64_t len, uint64_t tag, uint64_t mask,
                              fi_addr_t peer, uint8_t sync, void * ctx) {
    ssize_t         ret;
    struct timespec dl;
    ret = tcm_conv_time(&this->timeout, &dl);
    if (ret < 0)
        throw ret;

    if (!mem._check_parent(this)) {
        tcm__log_error("Invalid memory region used for fabric object");
        throw EINVAL;
    }

    void *   buf     = (void *) (((uint8_t *) mem.get_ptr()) + offset);
    uint64_t buf_len = mem.get_len();
    void *   desc    = mem.get_mr_desc();
    /* Check individually too in case of overflow */
    if (offset + len > buf_len || offset > buf_len || len > buf_len)
        throw EINVAL;
    do {
        switch (type) {
            case XFER_SEND:
                ret = fi_send(this->ep, buf, len, desc, peer, ctx);
                break;
            case XFER_TSEND:
                ret = fi_tsend(this->ep, buf, len, desc, peer, tag, ctx);
                break;
            case XFER_RECV:
                ret = fi_recv(this->ep, buf, len, desc, peer, ctx);
                break;
            case XFER_TRECV:
                ret = fi_trecv(this->ep, buf, len, desc, peer, tag, mask, ctx);
                break;
            default:
                throw EINVAL;
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

    if (sync) {
        do {
            struct fi_cq_err_entry err;
            switch (type) {
                case XFER_SEND:
                case XFER_TSEND:
                    ret = this->poll_tx(&err);
                    if (ret == 1)
                        return err.len;
                    break;
                case XFER_RECV:
                case XFER_TRECV:
                    ret = this->poll_rx(&err);
                    if (ret == 1)
                        return err.len;
                    break;
            }
            if (ret != 0)
                return ret;
        } while (!tcm_check_deadline(&dl));
    }

    return -ETIMEDOUT;
}

ssize_t tcm_fabric::send(tcm_mem & mem, fi_addr_t peer, void * ctx,
                         uint64_t offset, uint64_t len) {
    return this->data_xfer(XFER_SEND, mem, offset, len, 0, 0, peer, 0, ctx);
}

ssize_t tcm_fabric::recv(tcm_mem & mem, fi_addr_t peer, void * ctx,
                         uint64_t offset, uint64_t len) {
    return this->data_xfer(XFER_RECV, mem, offset, len, 0, 0, peer, 0, ctx);
}

ssize_t tcm_fabric::tsend(tcm_mem & mem, fi_addr_t peer, void * ctx,
                          uint64_t offset, uint64_t len, uint64_t tag) {
    return this->data_xfer(XFER_TSEND, mem, offset, len, tag, 0, peer, 0, ctx);
}

ssize_t tcm_fabric::trecv(tcm_mem & mem, fi_addr_t peer, void * ctx,
                          uint64_t offset, uint64_t len, uint64_t tag,
                          uint64_t mask) {
    return this->data_xfer(XFER_TRECV, mem, offset, len, tag, mask, peer, 0,
                           ctx);
}

ssize_t tcm_fabric::ssend(tcm_mem & mem, fi_addr_t peer, uint64_t offset,
                          uint64_t len) {
    return this->data_xfer(XFER_SEND, mem, offset, len, 0, 0, peer, 1, 0);
}

ssize_t tcm_fabric::srecv(tcm_mem & mem, fi_addr_t peer, uint64_t offset,
                          uint64_t len) {
    return this->data_xfer(XFER_RECV, mem, offset, len, 0, 0, peer, 1, 0);
}

ssize_t tcm_fabric::rwrite(tcm_mem & mem, fi_addr_t peer, void * ctx,
                           uint64_t local_offset, uint64_t remote_offset,
                           uint64_t len, tcm_remote_mem & rmem) {
    return this->data_xfer_rdma(XFER_RDMA_WRITE, mem, rmem, local_offset,
                                remote_offset, len, peer, ctx);
}

ssize_t tcm_fabric::rread(tcm_mem & mem, fi_addr_t peer, void * ctx,
                          uint64_t local_offset, uint64_t remote_offset,
                          uint64_t len, tcm_remote_mem & rmem) {
    return this->data_xfer_rdma(XFER_RDMA_READ, mem, rmem, local_offset,
                                remote_offset, len, peer, ctx);
}