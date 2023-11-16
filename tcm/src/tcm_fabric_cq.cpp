// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#include "tcm_fabric.h"
#include "tcm_log.h"

int tcm_cq::init(std::shared_ptr<tcm_fabric> f, fi_cq_attr & cq_attr) {
    memcpy(&this->attr, &cq_attr, sizeof(this->attr));

    int ret;
    ret = fi_cq_open(f->top->domain, &cq_attr, &this->cq, this);
    if (ret < 0)
        tcm__log_debug("Could not create TX CQ: %s", fi_strerror(-ret));
    return ret;
}

tcm_cq::tcm_cq(std::shared_ptr<tcm_fabric> f, size_t entries) {
    const char * mode_str[] = {"FI_WAIT_FD", "FI_WAIT_UNSPEC", "FI_WAIT_NONE"};
    fi_wait_obj  modes[]    = {FI_WAIT_FD, FI_WAIT_UNSPEC, FI_WAIT_NONE};
    fi_cq_attr   cq_attr;
    memset(&cq_attr, 0, sizeof(cq_attr));
    cq_attr.flags     = 0;
    cq_attr.size      = entries;
    cq_attr.wait_cond = FI_CQ_COND_NONE;
    if (f->fi->caps & FI_TAGGED)
        cq_attr.format = FI_CQ_FORMAT_TAGGED;
    else if (f->fi->caps & FI_MSG)
        cq_attr.format = FI_CQ_FORMAT_MSG;
    else
        cq_attr.format = FI_CQ_FORMAT_CONTEXT;

    int ret = -1;
    for (uint8_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
        tcm__log_trace("Trying CQ of size %lu with wait object type %s",
                       cq_attr.size, mode_str[i]);
        cq_attr.wait_obj = modes[i];
        ret              = this->init(f, cq_attr);
        if (ret < 0)
            continue;
        break;
    }

    if (ret < 0)
        throw -ret;
}

size_t tcm_cq::get_cqe_size() {
    switch (this->attr.format) {
        case FI_CQ_FORMAT_UNSPEC:
            return 0;
        case FI_CQ_FORMAT_CONTEXT:
            return sizeof(fi_cq_entry);
        case FI_CQ_FORMAT_MSG:
            return sizeof(fi_cq_msg_entry);
        case FI_CQ_FORMAT_DATA:
            return sizeof(fi_cq_data_entry);
        case FI_CQ_FORMAT_TAGGED:
            return sizeof(fi_cq_tagged_entry);
        default:
            assert(false && "Invalid CQ format!");
    }
}

ssize_t tcm_cq::spoll(void * buf, void * ebuf, size_t entries, size_t * offset,
                      uint32_t flags, tcm_time * t) {
    assert(buf);
    assert(t);
    timespec dl;
    ssize_t  ret;
    tcm_get_abs_time(t, &dl);
    size_t cqe_size = this->get_cqe_size();
    if (offset)
        *offset = cqe_size;
    if (this->attr.wait_obj != FI_WAIT_NONE && t->timeout > 2 &&
        t->interval > 1000) {
        while (1) {
            int ms = static_cast<int>(tcm_get_sec_left(&dl) * 1000.0);
            if (ms > 0) {
                ret = fi_cq_sread(cq, buf, entries, NULL, ms);
                if (ret == 0 || ret == -FI_EAGAIN)
                    continue;
                if (offset)
                    *offset = sizeof(fi_cq_err_entry);
                return tcm_get_cq_error(ret, cq, (fi_cq_err_entry *) ebuf);
            }
            break;
        }
    } else {
        do {
            ret = this->poll(buf, ebuf, entries, offset, flags);
            if (ret == 0 || ret == -FI_EAGAIN)
                continue;
            return ret;
        } while (!tcm_check_deadline(&dl));
    }
    return -ETIMEDOUT;
}

ssize_t tcm_cq::poll(void * buf, void * ebuf, size_t entries, size_t * offset,
                     uint32_t flags) {
    (void) flags;
    ssize_t ret;
    size_t  cqe_size = this->get_cqe_size();
    if (offset)
        *offset = cqe_size;
    ret = fi_cq_read(this->cq, buf, entries);
    if (ret == -FI_EAVAIL && ebuf) {
        for (size_t i = 0; i < entries; i++) {
            ret = fi_cq_read(this->cq, NULL, 0);
            if (ret == -FI_EAVAIL) {
                ret = tcm_get_cq_error(ret, this->cq,
                                       &((fi_cq_err_entry *) ebuf)[i]);
                if (ret < 0)
                    return ret;
                continue;
            }
            break;
        }
        return -FI_EAVAIL;
    }
    return ret;
}

std::weak_ptr<tcm_cq> tcm_endpoint::get_cq() { return this->cq; }

std::weak_ptr<tcm_cq> tcm_endpoint::get_tx_cq() { return this->cq; }

std::weak_ptr<tcm_cq> tcm_endpoint::get_rx_cq() { return this->rx_cq; }

tcm_cq::tcm_cq(std::shared_ptr<tcm_fabric> f, fi_cq_attr & attr) {
    int ret = this->init(f, attr);
    if (ret < 0)
        throw -ret;
}

tcm_cq::~tcm_cq() {
    if (this->cq) {
        fi_close(&this->cq->fid);
    }
    this->fabric = 0;
    this->cq     = 0;
}

void tcm_cq::get_attr(fi_cq_attr * out) {
    memcpy(out, &this->attr, sizeof(this->attr));
}

int tcm_cq::get_fd() {
    if (this->attr.wait_obj != FI_WAIT_FD)
        return -ENOTSUP;

    int fd;
    int ret = fi_control(&this->cq->fid, FI_GETWAIT, (void *) &fd);
    if (ret < 0) {
        if (ret != -FI_EAGAIN)
            tcm__log_debug("Failed to get CQ wait object: %s",
                           fi_strerror(-ret));
        return ret;
    }

    fid * fids[1] = {&this->cq->fid};
    ret           = fi_trywait(this->fabric->top->fabric, fids, 1);
    if (ret != FI_SUCCESS) {
        if (ret != -FI_EAGAIN)
            tcm__log_debug("Failed to perform trywait: %s", fi_strerror(-ret));
        return -tcm_abs(ret);
    }

    return fd;
}