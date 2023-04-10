#ifndef _TCM_SOCKET_H_
#define _TCM_SOCKET_H_

#include "compat/tcmc_net.h"

typedef enum {
    TCM_SOCK_MODE_INVALID,
    TCM_SOCK_MODE_SYNC,
    TCM_SOCK_MODE_ASYNC,
    TCM_SOCK_MODE_MAX
} tcm_sock_mode;

int tcm_set_sock_mode(tcm_sock sock, tcm_sock_mode mode);

#endif