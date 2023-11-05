// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#include "tcm_fabric.h"

using namespace tcm_internal;

shared_fi::shared_fi(struct fid_fabric * fabric, struct fid_domain * domain) {
    this->fabric = fabric;
    this->domain = domain;
    rkey_counter = 0;
}

shared_fi::~shared_fi() {
    int  ret;
    bool flag = 0;
    if (this->domain) {
        tcm__log_trace("Closing domain");
        ret = fi_close(&this->domain->fid);
        if (ret < 0) {
            tcm__log_warn("Failed to close domain: %s",
                          fi_strerror(tcm_abs(ret)));
            flag = 1;
        }
        this->domain = 0;
    }
    if (this->fabric) {
        tcm__log_trace("Closing fabric");
        ret = fi_close(&this->fabric->fid);
        if (ret < 0) {
            tcm__log_warn("Failed to close fabric: %s",
                          fi_strerror(tcm_abs(ret)));
            flag = 1;
        }
        this->fabric = 0;
    }
    if (flag) {
        tcm__log_trace("Shared fabric/domain could not be closed cleanly");
    } else {
        tcm__log_trace("Shared fabric/domain closed");
    }
}