#ifndef _TCM_COMPAT_NET_H_
#define _TCM_COMPAT_NET_H_

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <fcntl.h>

#include <rdma/fi_cm.h>

#include <stdlib.h>
#include <unistd.h>

#define tcm_sock                    int
#define tcm_sock_err                errno
#define tcm_sock_valid(x)           (x > 0)

// tbd for Windows

#endif