#ifndef _TCM_UTIL_H_
#define _TCM_UTIL_H_

#include <stdlib.h>
#include <errno.h>

#define tcm_abs(x)                  (x >= 0 ? x : -x)
#define tcm_negabs(x)               (x <= 0 ? x : -x)
#define TCM_MAX_ADDR_LEN            128

static inline void * tcm_mem_align(size_t size, size_t alignment)
{
    void * memptr = NULL;
    int ret = posix_memalign(&memptr, alignment, size);
    if (ret != 0)
    {
        errno = tcm_abs(ret);
        return NULL;
    }
    return memptr;
}

static inline void tcm_mem_free(void * ptr)
{
    free(ptr); // todo windows has a different implementation for aligned mem
}

#endif