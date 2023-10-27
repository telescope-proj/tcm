// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#include "tcm_time.h"
#include "tcm_udp.h"

class tcm_beacon {
    struct sockaddr_storage sa;
    tcm_sock_mode           mode;
    tcm_sock                sock;
    tcm_time                timeout;
    uint8_t                 timeout_active;

    void clear_fields();
    void create_sock(struct sockaddr * sa, tcm_sock_mode mode);
    void close_sock();

  public:
    /* Client only! */
    tcm_beacon();
    
    tcm_beacon(struct sockaddr * sa);
    tcm_beacon(struct sockaddr * sa, tcm_sock_mode mode);
    tcm_beacon(struct sockaddr * sa, tcm_sock_mode mode, tcm_time * timeout);

    ~tcm_beacon();

    int set_peer(struct sockaddr * sa);
    int reset_peer();

    void set_timeout(tcm_time * time);

    ssize_t send_dgram(struct sockaddr * peer, void * data, ssize_t len);
    ssize_t send_dgram(struct sockaddr * peer, void * data, ssize_t len,
                       tcm_time * timeout);

    ssize_t recv_dgram(struct sockaddr * peer, void * data, ssize_t maxlen);
    ssize_t recv_dgram(struct sockaddr * peer, void * data, ssize_t maxlen,
                       tcm_time * timeout);
};