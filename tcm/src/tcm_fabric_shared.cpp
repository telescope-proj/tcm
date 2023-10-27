// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#include "tcm_fabric.h"

tcm_internal::shared_fi::shared_fi(struct fid_fabric * fabric,
                                   struct fid_domain * domain) {
    this->fabric = fabric;
    this->domain = domain;
}

tcm_internal::shared_fi::~shared_fi() {
    int ret;
    if (this->domain) {
        tcm__log_trace("Closing domain");
        ret = fi_close(&this->domain->fid);
        if (ret < 0) {
            tcm__log_warn("Failed to close domain: %s",
                          fi_strerror(tcm_abs(ret)));
        }
        this->domain = 0;
    }
    if (this->fabric) {
        tcm__log_trace("Closing fabric");
        ret = fi_close(&this->fabric->fid);
        if (ret < 0) {
            tcm__log_warn("Failed to close fabric: %s",
                          fi_strerror(tcm_abs(ret)));
        }
        this->fabric = 0;
    }
    tcm__log_trace("Shared fabric/domain closed");
}