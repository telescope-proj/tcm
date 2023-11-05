// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#include "tcm_fabric.h"

using std::shared_ptr;

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

uint64_t tcm_mem::get_offset(void * ptr) {
    int64_t diff = (int64_t) ptr - (int64_t) this->get_ptr();
    if (diff < 0 || diff > (int64_t) this->get_len())
        return (uint64_t) -1;
    return diff;
}

tcm_mem::tcm_mem(shared_ptr<tcm_fabric> fabric, uint64_t size) {
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

tcm_mem::tcm_mem(shared_ptr<tcm_fabric> fabric, uint64_t size, uint64_t acs) {
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

tcm_mem::tcm_mem(shared_ptr<tcm_fabric> fabric, void * ptr, uint64_t len,
                 uint8_t own) {
    this->clear_fields();
    this->len    = len;
    this->own    = own;
    this->parent = fabric;
    this->refresh_mr(ptr, len, FI_SEND | FI_RECV, 0);
}

tcm_mem::tcm_mem(shared_ptr<tcm_fabric> fabric, void * ptr, uint64_t len,
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

void * tcm_mem::operator*() { return this->ptr; }

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
    /* Some providers, notably the TCP provider, ignore the FI_MR_PROV_KEY
     * attribute for MR registration and require the user to provide unique
     * rkeys, while the Verbs provider cannot accept user-provided rkeys. We
     * first try to let the provider choose an rkey, and if it returns
     * -FI_ENOKEY, try a couple domain-unique rkey values. This allows for
     * migration away from the deprecated FI_MR_BASIC memory registration mode.
     */
    int ret = -1;
    for (int att = 0; att < 256; att++) {
        uint64_t rkey_counter;
        if (att == 0) {
            rkey_counter = 0;
        } else {
            rkey_counter = ++this->parent->top->rkey_counter;
        }
        int ret =
            fi_mr_reg(this->parent->top->domain, this->ptr, this->len, acs, 0,
                      rkey_counter, flags, &this->mr, (void *) this);
        if (ret == 0) {
            tcm__log_trace("Registered MR:  %p, key %lu", this->ptr,
                           fi_mr_key(this->mr));
            return;
        }
        if (ret == -FI_ENOKEY)
            continue;
        throw ret;
    }
    throw ret;
}

void tcm_mem::dereg_internal_buffer() {
    if (this->mr) {
        int ret = fi_close(&this->mr->fid);
        if (ret != 0)
            throw ret;
    }
    this->mr = 0;
}
