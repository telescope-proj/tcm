// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#include "compat/tcmc_net.h"
#include "tcm_time.h"

class tcm_beacon {
    struct sockaddr_storage sa;
    tcm_sock                sock;
    int                     timeout;

    void clear_fields();
    void create_sock(struct sockaddr * sa);
    void close_sock();

  public:
    /* Client only! */
    tcm_beacon();

    tcm_beacon(struct sockaddr * sa);
    tcm_beacon(struct sockaddr * sa, int timeout);

    ~tcm_beacon();

    int set_peer(struct sockaddr * sa);
    int reset_peer();

    void set_timeout(int ms);
    int get_timeout();

    /* Get the underlying socket descriptor. */
    tcm_sock get_sock();

    ssize_t send_dgram(struct sockaddr * peer, void * data, ssize_t len);
    ssize_t send_dgram(struct sockaddr * peer, void * data, ssize_t len,
                       int timeout);

    ssize_t recv_dgram(struct sockaddr * peer, void * data, ssize_t maxlen);
    ssize_t recv_dgram(struct sockaddr * peer, void * data, ssize_t maxlen,
                       int timeout);
};