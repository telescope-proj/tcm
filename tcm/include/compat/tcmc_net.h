// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#ifndef TCM_COMPAT_NET_H_
#define TCM_COMPAT_NET_H_

#include <rdma/fi_cm.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdio.h>

#include "compat/tcmc_os.h"

#if TCM_OS_IS_WINDOWS

#include <winsock2.h>

typedef SOCKET tcm_sock;
#define tcm_last_sock_err WSAGetLastError()
#define tcm_sock_valid(x) (x != INVALID_SOCKET)
#define tcm_sock_close(x) closesocket(x)
#define tcm_invalid_sock INVALID_SOCKET

static inline int tcm_sock_poll(struct pollfd * pfd, unsigned long fds,
                                int timeout) {
    return WSAPoll(pfd, fds, timeout);
}

#else

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

typedef int tcm_sock;
#define tcm_last_sock_err errno
#define tcm_sock_valid(x) (x > 0)
#define tcm_sock_close(x) close(x)
#define tcm_invalid_sock -1

static inline int tcm_get_sock_err(tcm_sock sock) {
    int err;
    socklen_t errlen = sizeof(int);
    int ret = getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &errlen);
    if (ret < 0)
        return -errno;
    return err;
}
static inline int tcm_sock_poll(struct pollfd * pfd, unsigned long fds,
                                int timeout) {
    return poll(pfd, fds, timeout);
}

#endif

#endif