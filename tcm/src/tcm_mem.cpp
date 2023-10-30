// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#include "tcm_fabric.h"

void tcm_mem::clear_fields() {
    this->ptr       = 0;
    this->len       = 0;
    this->alignment = 0;
    this->mr        = 0;
    this->own       = 0;
}

void tcm_mem::free_mgd_mem() {
    switch (this->own) {
        case 1:
            free(this->ptr);
            break;
        case 2:
            tcm_mem_free(this->ptr);
            break;
        default:
            break;
    }
    this->ptr = 0;
}

tcm_mem::tcm_mem(std::shared_ptr<tcm_fabric> fabric, uint64_t size) {
    this->clear_fields();
    this->ptr = tcm_mem_align_page(size);
    if (!this->ptr) {
        throw errno;
    }
    this->len    = size;
    this->own    = 2;
    this->parent = fabric;
    this->refresh_mr(this->ptr, this->len, FI_SEND | FI_RECV, 0);
}

tcm_mem::tcm_mem(std::shared_ptr<tcm_fabric> fabric, uint64_t size,
                 uint64_t acs) {
    this->clear_fields();
    this->ptr = tcm_mem_align_page(size);
    if (!this->ptr) {
        throw errno;
    }
    this->len    = size;
    this->own    = 2;
    this->parent = fabric;
    this->refresh_mr(this->ptr, this->len, acs, 0);
}

tcm_mem::tcm_mem(std::shared_ptr<tcm_fabric> fabric, void * ptr, uint64_t len,
                 uint8_t own) {
    this->clear_fields();
    this->len    = len;
    this->own    = own;
    this->parent = fabric;
    this->refresh_mr(ptr, len, FI_SEND | FI_RECV, 0);
}

tcm_mem::tcm_mem(std::shared_ptr<tcm_fabric> fabric, void * ptr, uint64_t len,
                 uint64_t acs, uint8_t own) {
    this->clear_fields();
    this->len    = len;
    this->own    = own;
    this->parent = fabric;
    this->refresh_mr(ptr, len, acs, 0);
}

tcm_mem::~tcm_mem() {
    this->dereg_internal_buffer();
    this->free_mgd_mem();
    this->parent = 0;
}

void * tcm_mem::get_ptr() { return this->ptr; }

struct fid_mr * tcm_mem::get_mr() { return this->mr; }

void * tcm_mem::get_mr_desc() { return fi_mr_desc(this->mr); }

uint64_t tcm_mem::get_len() { return this->len; }

int tcm_mem::_check_parent(tcm_fabric * p) { return this->parent.get() == p; }

void tcm_mem::refresh_mr(void * ptr, uint64_t len) {
    this->refresh_mr(ptr, len, FI_SEND | FI_RECV, 0);
}

void tcm_mem::refresh_mr(void * ptr, uint64_t len, uint64_t acs,
                         uint64_t flags) {
    this->dereg_internal_buffer();
    if (this->own && this->ptr != ptr) {
        free(this->ptr);
    }
    this->ptr = ptr;
    this->len = len;
    this->reg_internal_buffer(acs, flags);
};

void tcm_mem::reg_internal_buffer() {
    return this->reg_internal_buffer(FI_SEND | FI_RECV, 0);
}

void tcm_mem::reg_internal_buffer(uint64_t acs, uint64_t flags) {
    tcm__log_trace("Registering MR: %p, len %lu, acs %lu, flags %lu", this->ptr,
                   this->len, acs, flags);
    if (!this->ptr)
        throw ENOBUFS;
    if (this->mr)
        throw EINVAL;
    fid_domain * d =
        (fid_domain *) this->parent.get()->_get_fi_resource(TCM_RESRC_DOMAIN);
    assert(d);
    int ret = fi_mr_reg(d, this->ptr, this->len, acs, 0, 0, flags, &this->mr,
                        (void *) this);
    if (ret != 0)
        throw tcm_abs(ret);
    tcm__log_trace("Registered MR:  %p, key %lu", this->ptr,
                   fi_mr_key(this->mr));
}

void tcm_mem::dereg_internal_buffer() {
    if (this->mr) {
        int ret = fi_close(&this->mr->fid);
        if (ret != 0)
            throw ret;
    }
    this->mr = 0;
}
