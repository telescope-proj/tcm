// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#ifndef TCM_MM_H_
#define TCM_MM_H_

#include "compat/tcmc_os.h"

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>

#if TCM_OS_IS_WINDOWS
#include <memoryapi.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

#ifndef TCM_DEFAULT_HUGEPAGE_SIZE
#define TCM_DEFAULT_HUGEPAGE_SIZE 2097152
#endif

/* Check if the RDMA subsystem can use hugepages */

static inline int tcm_can_use_hugepages() {
    char * e = getenv("RDMAV_HUGEPAGES_SAFE");
    if (e) {
        return atoi(e);
    }
    return 0;
}

/* RAII style heap memory class */

class tcm_managed_mem {

  public:
    void * ptr;
    size_t size;
    size_t alignment;

    tcm_managed_mem(size_t size, size_t alignment);
    tcm_managed_mem(size_t size);
    ~tcm_managed_mem();
};

size_t tcm_get_page_size();
void * tcm_mem_align(size_t size, size_t alignment);
void * tcm_mem_align_page(size_t size);
void * tcm_mem_align_rdma(size_t size);
void   tcm_mem_free(void * ptr);

#endif