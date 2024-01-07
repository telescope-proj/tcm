// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#include "tcm_fabric.h"

#define KEY_SIZE_LIMIT 1024

using std::shared_ptr;

void tcm_mem::clear_fields() {
    this->ptr       = 0;
    this->len       = 0;
    this->alignment = 0;
    this->mr        = 0;
    this->mode      = TCM_MEM_UNMANAGED;
    this->key_buf   = 0;
    this->key_size  = 8;
    this->parent    = 0;
}

void tcm_mem::free_mgd_mem() {
    switch (this->mode) {
        case TCM_MEM_PLAIN:
            free(this->ptr);
            break;
        case TCM_MEM_PLAIN_ALIGNED:
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
        throw tcm_exception(errno, __FILE__, __LINE__,
                            "Aligned memory allocation failed");
    }
    this->len    = size;
    this->mode   = TCM_MEM_PLAIN_ALIGNED;
    this->parent = fabric;
    this->refresh_mr(this->ptr, this->len, FI_SEND | FI_RECV, 0);
}

tcm_mem::tcm_mem(shared_ptr<tcm_fabric> fabric, uint64_t size, uint64_t acs) {
    this->clear_fields();
    this->ptr = tcm_mem_align_page(size);
    if (!this->ptr) {
        throw tcm_exception(errno, __FILE__, __LINE__,
                            "Aligned memory allocation failed");
    }
    this->len    = size;
    this->mode   = TCM_MEM_PLAIN_ALIGNED;
    this->parent = fabric;
    this->refresh_mr(this->ptr, this->len, acs, 0);
}

tcm_mem::tcm_mem(shared_ptr<tcm_fabric> fabric, void * ptr, uint64_t len,
                 tcm_mem_bind mode) {
    this->clear_fields();
    this->len    = len;
    this->mode   = mode;
    this->parent = fabric;
    this->refresh_mr(ptr, len, FI_SEND | FI_RECV, 0);
}

tcm_mem::tcm_mem(shared_ptr<tcm_fabric> fabric, void * ptr, uint64_t len,
                 uint64_t acs, tcm_mem_bind mode) {
    this->clear_fields();
    this->len    = len;
    this->mode   = mode;
    this->parent = fabric;
    this->refresh_mr(ptr, len, acs, 0);
}

tcm_mem::~tcm_mem() {
    tcm_free_unset(this->key_buf);
    this->key_size = 0;
    this->dereg_internal_buffer();
    this->free_mgd_mem();
    this->parent = 0;
}

void * tcm_mem::offset(uint64_t offset, uint64_t length) {
    if (offset + length > this->len)
        throw tcm_exception(EINVAL, __FILE__, __LINE__,
                            "Out of bounds memory access");
    return (uint8_t *) this->ptr + offset;
}

void * tcm_mem::operator*() { return this->ptr; }

void * tcm_mem::get_ptr() { return this->ptr; }

fid_mr * tcm_mem::get_mr() { return this->mr; }

void * tcm_mem::get_mr_desc() { return fi_mr_desc(this->mr); }

uint64_t tcm_mem::get_len() { return this->len; }

int tcm_mem::get_rkey(uint64_t * buf) {
    uint64_t key = fi_mr_key(this->mr);
    if (key == FI_KEY_NOTAVAIL)
        return -FI_ETOOSMALL;
    *buf = key;
    return 0;
}

int tcm_mem::get_rkey_long(void * buf, size_t * size) {
    uint64_t key = fi_mr_key(this->mr);
    if (key != FI_KEY_NOTAVAIL) {
        if (*size < 8) {
            *size = 8;
            return -FI_ETOOSMALL;
        }
        *(uint64_t *) buf = key;
        return 0;
    }
    if (this->key_buf && this->key_size <= *size) {
        memcpy(buf, this->key_buf, this->key_size);
        return 1;
    }
    return -FI_ETOOSMALL;
}

bool tcm_mem::check_parent(tcm_fabric * p) { return this->parent.get() == p; }

void tcm_mem::refresh_mr(void * ptr, uint64_t len) {
    this->refresh_mr(ptr, len, FI_SEND | FI_RECV, 0);
}

void tcm_mem::refresh_mr(void * ptr, uint64_t len, uint64_t acs,
                         uint64_t flags) {
    this->dereg_internal_buffer();
    if (this->ptr != ptr)
        this->free_mgd_mem();
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
        throw tcm_exception(EINVAL, __FILE__, __LINE__,
                            "No buffer was registered by this object");
    if (this->mr)
        throw tcm_exception(EINVAL, __FILE__, __LINE__,
                            "A MR was already registered by this object");

    tcm_free_unset(this->key_buf);
    this->key_size = 0;

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
            /* In order to support providers with long remote access keys, we
             * first check if there exists a standard 64-bit key. If not, we
             * allocate a buffer to store the raw key data. Support for raw
             * rkeys in TCM is currently incomplete and none of Telescope's
             * target fabric providers require them.
             */
            uint64_t rkey = fi_mr_key(this->mr);
            if (rkey == FI_KEY_NOTAVAIL) {
                this->key_size = 0;
                uint64_t base  = 0;
                ret = fi_mr_raw_attr(this->mr, &base, nullptr, &this->key_size,
                                     0);
                if (ret != -FI_ETOOSMALL) {
                    throw tcm_exception(ret, __FILE__, __LINE__,
                                        "Failed to get raw rkey data");
                }
                if (this->key_size > KEY_SIZE_LIMIT) {
                    throw tcm_exception(
                        ret, __FILE__, __LINE__,
                        "Remote key size exceeds available buffer space");
                }
                this->key_buf = (uint8_t *) calloc(1, this->key_size);
                if (!this->key_buf) {
                    throw tcm_exception(ENOMEM, __FILE__, __LINE__,
                                        "Remote key buffer allocation failed");
                }
                ret = fi_mr_raw_attr(this->mr, &base, this->key_buf,
                                     &this->key_size, 0);
                if (ret < 0) {
                    tcm_free_unset(this->key_buf);
                    throw tcm_exception(ret, __FILE__, __LINE__,
                                        "Could not get raw rkey");
                }
            } else {
                this->key_buf  = 0;
                this->key_size = 8;
            }
            return;
        }
        if (ret == -FI_ENOKEY)
            continue;
        throw tcm_exception(tcm_abs(ret), __FILE__, __LINE__,
                            "Memory registration failed");
    }
    throw tcm_exception(tcm_abs(ret), __FILE__, __LINE__,
                        "Memory registration failed");
}

void tcm_mem::dereg_internal_buffer() {
    if (this->mr) {
        int ret = fi_close(&this->mr->fid);
        if (ret != 0)
            throw tcm_exception(ret, __FILE__, __LINE__,
                                "Memory deregistration error");
        this->mr = 0;
    }
    if (this->key_buf) {
        tcm_free_unset(this->key_buf);
    }
    this->key_size = 0;
}