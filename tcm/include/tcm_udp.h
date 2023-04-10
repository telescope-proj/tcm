#ifndef _TCM_UDP_H_
#define _TCM_UDP_H_

#include "tcm_socket.h"
#include "tcm_time.h"

int tcm_setup_udp(struct sockaddr * sa, tcm_sock_mode mode, tcm_sock * sock_out);

ssize_t tcm_send_udp(tcm_sock sock, void * buf, uint64_t buf_size,
                     struct sockaddr * peer, tcm_time * timing);

ssize_t tcm_recv_udp(tcm_sock sock, void * buf, uint64_t buf_size,
                     struct sockaddr * peer, tcm_time * timing);


ssize_t tcm_exch_udp(tcm_sock sock, void * send_buf, uint64_t send_buf_size,
                     void * recv_buf, uint64_t recv_buf_size,
                     struct sockaddr * peer, tcm_time * timing);

int tcm_set_timeout_udp(tcm_sock sock, size_t send_ms, size_t recv_ms);

#endif