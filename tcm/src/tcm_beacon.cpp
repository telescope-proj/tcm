// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#include "tcm_beacon.h"
#include "tcm_comm.h"
#include "tcm_log.h"
#include "tcm_socket.h"

tcm_sock tcm_beacon::get_sock() {
    return this->sock;
}

void tcm_beacon::clear_fields() {
    memset(&this->sa, 0, sizeof(this->sa));
    this->sock    = tcm_invalid_sock;
    this->timeout = 0;
}

void tcm_beacon::create_sock(struct sockaddr * sa) {
    int sa_size = -1;

    if (sa) {
        sa_size = tcm_internal::get_sa_size(sa);
        if (sa_size <= 0)
            throw EINVAL;
    }

    tcm_sock sock = socket(sa ? sa->sa_family : AF_INET,
                           SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
    if (!tcm_sock_valid(sock))
        throw tcm_last_sock_err;

    this->sock = sock;
    if (sa) {
        int ret = bind(sock, sa, sa_size);
        if (ret < 0) {
            tcm__log_error("Socket bind failed: %s",
                           strerror(tcm_last_sock_err));
            throw tcm_last_sock_err;
        }
    }

    if (sa)
        memcpy(&this->sa, sa, sa_size);
}

void tcm_beacon::close_sock() {
    if (tcm_sock_valid(this->sock))
        tcm_sock_close(this->sock);
    this->sock = tcm_invalid_sock;
}

tcm_beacon::tcm_beacon() {
    this->clear_fields();
    this->create_sock(NULL);
    this->timeout = -1;
}

tcm_beacon::tcm_beacon(struct sockaddr * sa) {
    this->clear_fields();
    this->create_sock(sa);
    this->timeout = -1;
}

tcm_beacon::tcm_beacon(struct sockaddr * sa, int timeout_ms) {
    this->clear_fields();
    this->create_sock(sa);
    this->timeout = timeout_ms;
}

tcm_beacon::~tcm_beacon() {
    this->close_sock();
    this->clear_fields();
}

int tcm_beacon::set_peer(struct sockaddr * sa) {
    int sa_size = tcm_internal::get_sa_size(sa);
    if (sa_size < 0)
        return -EINVAL;
    int ret = connect(this->sock, sa, sa_size);
    if (ret < 0)
        return -errno;
    memcpy(&this->sa, sa, sa_size);
    return 0;
}

int tcm_beacon::reset_peer() {
    int ret = connect(this->sock, 0, 0);
    if (ret < 0)
        return -errno;
    return 0;
}

void tcm_beacon::set_timeout(int ms) { this->timeout = ms; }

int tcm_beacon::get_timeout() { return this->timeout; }

ssize_t tcm_beacon::send_dgram(struct sockaddr * peer, void * data,
                               ssize_t len) {
    return this->send_dgram(peer, data, len, this->timeout);
}

ssize_t tcm_beacon::send_dgram(struct sockaddr * peer, void * data, ssize_t len,
                               int timeout_) {

    if (this->sa.ss_family && (this->sa.ss_family != peer->sa_family)) {
        tcm__log_error(
            "Peer address family does not match this address family");
        throw EINVAL;
    }

    ssize_t ret;
    int     sa_size = tcm_internal::get_sa_size(peer);
    if (sa_size < 0) {
        tcm__log_error("Peer address size invalid");
        throw EINVAL;
    }

    struct pollfd pfd;
    pfd.fd      = this->sock;
    pfd.events  = POLLOUT;
    pfd.revents = 0;

    ret = poll(&pfd, 1, timeout_);
    if (ret < 0)
        return ret;
    if (ret == 0)
        return -EAGAIN;

    if (pfd.revents & POLLOUT) {
        ret = sendto(this->sock, data, len, 0, peer, sa_size);
        if (ret < 0)
            return -tcm_last_sock_err;
    } else {
        if (pfd.revents & POLLERR)
            return tcm_get_sock_err(this->sock);
        if (pfd.events & POLLNVAL)
            return -EINVAL;
        assert(false && "Unexpected event");
    }

    return ret;
}

ssize_t tcm_beacon::recv_dgram(struct sockaddr * peer, void * data,
                               ssize_t maxlen) {
    return this->recv_dgram(peer, data, maxlen, this->timeout);
}

ssize_t tcm_beacon::recv_dgram(struct sockaddr * peer, void * data,
                               ssize_t maxlen, int timeout_) {
    ssize_t   ret;
    socklen_t sas;
    if (this->sa.ss_family) {
        sas = tcm_internal::get_sa_size((struct sockaddr *) &this->sa);
        if (sas == 0) {
            tcm__log_error("Beacon in invalid state");
            throw ENOTCONN;
        }
    } else {
        sas = sizeof(this->sa);
    }

    struct pollfd pfd;
    pfd.fd      = this->sock;
    pfd.events  = POLLIN;
    pfd.revents = 0;

    ret = poll(&pfd, 1, timeout_);
    if (ret < 0)
        return ret;
    if (ret == 0)
        return -EAGAIN;

    if (pfd.revents & POLLIN) {
        ret = recvfrom(sock, data, maxlen, 0, peer, &sas);
        if (ret < 0)
            return -tcm_last_sock_err;
    } else {
        if (pfd.revents & POLLERR)
            return -tcm_get_sock_err(this->sock);
        if (pfd.events & POLLNVAL)
            return -EINVAL;
        assert(false && "Unexpected event");
    }

    return ret;
}