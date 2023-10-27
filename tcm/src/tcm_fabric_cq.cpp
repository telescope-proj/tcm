// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#include "tcm_fabric.h"
#include "tcm_log.h"

ssize_t tcm_fabric::poll_cq(struct fid_cq * cq, struct fi_cq_err_entry * err,
                            tcm_time * timeout) {

    ssize_t  ret;
    tcm_time t = timeout ? *timeout : this->timeout;
    if (t.interval < 0) {
        int ms = (int) (t.ts.tv_sec * 1000) + (int) (t.ts.tv_nsec / 1000000);
        if (ms == 0)
            ms = -1; // Enable indefinite wait

        return tcm_get_cq_error(fi_cq_sread(cq, err, 1, NULL, ms), cq, err);
    }

    struct timespec ts;
    ret = tcm_conv_time(&t, &ts);
    if (ret < 0)
        return ret;
    do {
        ret = fi_cq_read(cq, err, 1);
        if (ret == 0 || ret == -FI_EAGAIN) {
            tcm_usleep(t.interval);
            continue;
        } else {
            return tcm_get_cq_error(ret, cq, err);
        }
    } while (!tcm_check_deadline(&ts));
    return -ETIMEDOUT;
}

ssize_t tcm_fabric::poll_tx(struct fi_cq_err_entry * err) {
    return this->poll_cq(this->tx_cq, err, NULL);
}

ssize_t tcm_fabric::poll_rx(struct fi_cq_err_entry * err) {
    return this->poll_cq(this->rx_cq, err, NULL);
}
