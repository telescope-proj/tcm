/*
    Telescope Connection Manager
    Communication Routines
    Copyright (c) 2023 Tim Dettmar
    SPDX-License-Identifier: MIT
*/

#ifndef _TCM_COMM_H_
#define _TCM_COMM_H_

#include "compat/tcmc_net.h"

#define TCM_MAGIC 0x52415054

static inline int tcm__get_sa_size(struct sockaddr * sa)
{
    switch (sa->sa_family)
    {
        case AF_INET:
            return sizeof(struct sockaddr_in);
        case AF_INET6:
            return sizeof(struct sockaddr_in6);
        default:
            return -EINVAL;
    }
}

#endif