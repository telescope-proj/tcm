#ifndef TCM_COMPAT_NET_H_
#define TCM_COMPAT_NET_H_

#include <rdma/fi_cm.h>
#include <stdlib.h>
#include <sys/types.h>

#include "compat/tcmc_os.h"

#if TCM_OS_IS_WINDOWS

#include <winsock2.h>
#define tcm_sock SOCKET
#define tcm_sock_err WSAGetLastError()
#define tcm_sock_valid(x) (x != INVALID_SOCKET)
#define tcm_sock_close(x) closesocket(x)
#define tcm_invalid_sock INVALID_SOCKET

#else

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#define tcm_sock int
#define tcm_sock_err errno
#define tcm_sock_valid(x) (x > 0)
#define tcm_sock_close(x) close(x)
#define tcm_invalid_sock -1

#endif

#endif