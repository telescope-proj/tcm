// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#ifndef TCM_COMM_H_
#define TCM_COMM_H_

#include "compat/tcmc_net.h"

#define TCM_MAGIC 0x52415054
namespace tcm_internal {

static inline int get_sa_size(struct sockaddr * sa) {
    switch (sa->sa_family) {
        case AF_INET:
            return sizeof(struct sockaddr_in);
        case AF_INET6:
            return sizeof(struct sockaddr_in6);
        default:
            return 0;
    }
}

} // namespace tcm_internal

#endif