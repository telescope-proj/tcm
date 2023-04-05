#ifndef _TCM_UDP_H_
#define _TCM_UDP_H_

#include "compat/tcmc_net.h"
#include "tcm_time.h"

#include <errno.h>

ssize_t tcm_send_udp(tcm_sock sock, void * buf, uint64_t buf_size,
                     struct sockaddr * peer, tcm_time * timing);

ssize_t tcm_recv_udp(tcm_sock sock, void * buf, uint64_t buf_size,
                     struct sockaddr * peer, tcm_time * timing);


ssize_t tcm_exch_udp(tcm_sock sock, void * send_buf, uint64_t send_buf_size,
                     void * recv_buf, uint64_t recv_buf_size,
                     struct sockaddr * peer, tcm_time * timing);

#endif