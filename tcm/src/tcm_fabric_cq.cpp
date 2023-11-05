// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#include "tcm_fabric.h"
#include "tcm_log.h"

int tcm_fabric::get_cq_fd() {
    if (this->wait_type != FI_WAIT_FD)
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
    ret           = fi_trywait(this->top->fabric, fids, 1);
    if (ret != FI_SUCCESS) {
        if (ret != -FI_EAGAIN)
            tcm__log_debug("Failed to perform trywait: %s", fi_strerror(-ret));
        return -tcm_abs(ret);
    }

    return fd;
}

ssize_t tcm_fabric::poll_cq(fi_cq_err_entry * err) {
    tcm_time t(0, 0);
    return this->poll_cq(this->cq, err, 1, &t);
}

ssize_t tcm_fabric::poll_cq(fi_cq_err_entry * err, tcm_time * timeout) {
    return this->poll_cq(this->cq, err, 1, timeout);
}

ssize_t tcm_fabric::poll_cq(fid_cq * cq, fi_cq_err_entry * err, size_t n,
                            tcm_time * timeout) {

    ssize_t         ret;
    tcm_time        t = timeout ? *timeout : this->timeout;
    struct timespec dl;
    tcm_get_abs_time(&t, &dl);
    if (!this->exit_flag && this->wait_type != FI_WAIT_NONE && t.timeout > 2 &&
        t.interval > 1000) {
        while (1) {
            int ms = (int) (tcm_get_sec_left(&dl) * 1000.0);
            if (ms > 0) {
                ret = fi_cq_sread(cq, err, n, NULL, ms);
                if (ret == 0 || ret == -FI_EAGAIN)
                    continue;
                return tcm_get_cq_error(ret, cq, err);
            }
            break;
        }
    } else {
        /* For short polling intervals, it's assumed that latency is more
         * important than CPU usage, and polling is used instead of interrupts.
         */
        do {
            if (this->exit_flag && *this->exit_flag > 0) {
                ret = -ECANCELED;
                return ret;
            }
            ret = fi_cq_read(cq, err, n);
            if (ret == 0 || ret == -FI_EAGAIN) {
                if (t.timeout > 0)
                    tcm_usleep(t.interval);
                continue;
            }
            return tcm_get_cq_error(ret, cq, err);
        } while (!tcm_check_deadline(&dl));
    }

    if (t.timeout == 0)
        return -EAGAIN;
    return -ETIMEDOUT;
}