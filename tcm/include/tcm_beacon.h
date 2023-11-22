// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#include "compat/tcmc_net.h"
#include "tcm_time.h"
#include "tcm_exception.h"

class tcm_beacon {
    sockaddr_storage sa;
    tcm_sock         sock;
    int              timeout;
    unsigned int     domain;
    bool             mapping;

    void clear_fields();
    void create_sock(sockaddr * sa);
    void close_sock();

  public:
    /* Client only! */
    tcm_beacon();

    tcm_beacon(sockaddr * sa);
    tcm_beacon(sockaddr * sa, int timeout);

    ~tcm_beacon();

    int reset_peer();

    int  set_peer(sockaddr * sa);
    void set_mapping(bool opt);
    void set_timeout(int ms);

    bool     get_mapping();
    int      get_timeout();
    int      get_family();
    tcm_sock get_sock();

    ssize_t send_dgram(sockaddr * peer, void * data, ssize_t len);
    ssize_t send_dgram(sockaddr * peer, void * data, ssize_t len, int timeout);

    ssize_t recv_dgram(sockaddr * peer, void * data, ssize_t maxlen);
    ssize_t recv_dgram(sockaddr * peer, void * data, ssize_t maxlen,
                       int timeout);
};