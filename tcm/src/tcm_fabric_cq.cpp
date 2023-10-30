// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#include "tcm_fabric.h"
#include "tcm_log.h"

int tcm_fabric::cq_waitable(int * out) {
    fid * fids[2] = {&this->rx_cq->fid, &this->tx_cq->fid};
    int   ret1, ret2;

    ret1 = fi_trywait(this->top.get()->fabric, &fids[0], 1);
    if (ret1 == FI_SUCCESS)
        *out |= TCM_RESRC_RX_CQ;
    ret2 = fi_trywait(this->top.get()->fabric, &fids[1], 1);
    if (ret2 == FI_SUCCESS)
        *out |= TCM_RESRC_TX_CQ;

    if (ret1 < 0 && ret1 != -FI_EAGAIN) {
        *out = TCM_RESRC_RX_CQ;
        return ret1;
    }
    if (ret2 < 0 && ret2 != -FI_EAGAIN) {
        *out = TCM_RESRC_TX_CQ;
        return ret2;
    }

    return 0;
}

int tcm_fabric::get_cq_fds(tcm_fabric_cq_fds * out) {
    assert(out);
    int ret1, ret2, bad = 0;
    ret1 = fi_control(&this->rx_cq->fid, FI_GETWAIT, (void *) &out->rx);
    ret2 = fi_control(&this->tx_cq->fid, FI_GETWAIT, (void *) &out->tx);

    if (ret1 < 0) {
        tcm__log_debug("Failed to get RX wait object: %s", fi_strerror(-ret1));
        out->rx = ret1;
        bad = 1;
    }
    if (ret2 < 0) {
        tcm__log_debug("Failed to get TX wait object: %s", fi_strerror(-ret2));
        out->tx = ret2;
        bad = 1;
    }

    if (bad)
        return -1;
    return 0;
}

ssize_t tcm_fabric::poll_cq(struct fid_cq * cq, struct fi_cq_err_entry * err,
                            tcm_time * timeout) {

    ssize_t         ret;
    tcm_time        t = timeout ? *timeout : this->timeout;
    struct timespec dl;
    tcm_get_abs_time(&t, &dl);
    if (t.timeout > 2 && t.interval > 1000) {
        while (1) {
            int ms = (int) (tcm_get_sec_left(&dl) * 1000.0);
            if (ms > 0) {
                ret = fi_cq_sread(cq, err, 1, NULL, ms);
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
            ret = fi_cq_read(cq, err, 1);
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

ssize_t tcm_fabric::poll_tx(struct fi_cq_err_entry * err) {
    return this->poll_cq(this->tx_cq, err, NULL);
}

ssize_t tcm_fabric::poll_rx(struct fi_cq_err_entry * err) {
    return this->poll_cq(this->rx_cq, err, NULL);
}