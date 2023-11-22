// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#include "tcm_mm.h"
#include "tcm_exception.h"
#include "tcm_util.h"

tcm_managed_mem::tcm_managed_mem(size_t size, size_t alignment) {
    this->ptr = tcm_mem_align(size, alignment);
    if (!this->ptr) {
        throw tcm_exception(ENOMEM, __FILE__, __LINE__,
                            "Managed memory allocation failed");
    }
    this->alignment = alignment;
    this->size      = size;
}

tcm_managed_mem::tcm_managed_mem(size_t size) {
    this->ptr = malloc(size);
    if (!this->ptr) {
        throw tcm_exception(ENOMEM, __FILE__, __LINE__,
                            "Managed memory allocation failed");
    }
    this->alignment = 0;
    this->size      = size;
}

tcm_managed_mem::~tcm_managed_mem() {
    if (this->alignment) {
        tcm_mem_free(this->ptr);
    } else {
        free(this->ptr);
    }
    this->ptr       = 0;
    this->alignment = 0;
    this->size      = 0;
}

size_t tcm_get_page_size() {
#if TCM_OS_IS_WINDOWS
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return si.dwPageSize;
#else
    return sysconf(_SC_PAGESIZE);
#endif
}

void * tcm_mem_align(size_t size, size_t alignment) {
#if TCM_OS_IS_WINDOWS
    errno = ENOSYS;
    return NULL;
#else
    void * memptr = NULL;
    int    ret    = posix_memalign(&memptr, alignment, size);
    if (ret != 0) {
        errno = tcm_abs(ret);
        return NULL;
    }
    return memptr;
#endif
}

void * tcm_mem_align_page(size_t size) {
    return tcm_mem_align(size, tcm_get_page_size());
}

/* Allocate an aligned memory region for optimal RDMA access. Hugepages support
 * will be used if the system is correctly configured for RDMA hugepages. */
void * tcm_mem_align_rdma(size_t size) {
#if TCM_OS_IS_WINDOWS
    errno = ENOSYS;
    return NULL;
#else
    int ps  = 0;
    int adv = 0;
    if (tcm_can_use_hugepages()) {
        char * e = getenv("TCM_PAGE_SIZE");
        if (e) {
            ps = atoi(e);
            if (!ps)
                ps = tcm_get_page_size();
        } else {
            if (TCM_DEFAULT_HUGEPAGE_SIZE) {
                ps = TCM_DEFAULT_HUGEPAGE_SIZE;
            } else {
                ps = tcm_get_page_size();
            }
        }
        adv = MADV_HUGEPAGE;
    } else {
        ps  = tcm_get_page_size();
        adv = MADV_NOHUGEPAGE;
    }
    void * memptr = tcm_mem_align(size, ps);
    if (!memptr)
        return NULL;
    if (madvise(memptr, size, adv) < 0) {
        free(memptr);
        return NULL;
    }
    return memptr;
#endif
}

void tcm_mem_free(void * ptr) {
    /* Only Windows has a different implementation for aligned memory frees,
       but tcm_mem_free should always be called to clean up aligned memory
       allocations */
#if TCM_OS_IS_WINDOWS
    throw tcm_exception(ENOSYS, __FILE__, __LINE__,
                        "TCM Windows support is incomplete");
#else
    free(ptr);
#endif
}