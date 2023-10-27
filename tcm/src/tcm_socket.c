// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#include <errno.h>

#include "tcm_socket.h"

int tcm_set_sock_mode(tcm_sock sock, tcm_sock_mode mode)
{
    if (!sock)
        return -EINVAL;


    int flags = fcntl(sock, F_GETFL, 0);
        if (flags < 0)
            return -errno;

    switch (mode)
    {
        case TCM_SOCK_MODE_SYNC:
            flags = flags & ~O_NONBLOCK;
            break;
        case TCM_SOCK_MODE_ASYNC:
            flags = flags | O_NONBLOCK;
            break;
        default:
            return -EINVAL;
    }

    return 0;
}