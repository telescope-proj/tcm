// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#include "tcm_beacon.h"
#include "tcm_comm.h"
#include "tcm_log.h"
#include "tcm_socket.h"

bool is_mapped(sockaddr_in6 * v6) {
    const uint8_t addr[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF};
    for (int i = 0; i < 12; i++) {
        if (v6->sin6_addr.s6_addr[i] != addr[i])
            return false;
    }
    return true;
}

void map_v4tov6(sockaddr_in * v4, sockaddr_in6 * v6) {
    assert(v4);
    assert(v6);
    assert(v4->sin_family == AF_INET);
    uint8_t *     v4addr   = (uint8_t *) &v4->sin_addr;
    const uint8_t addr[16] = {
        0, 0, 0,    0,    0,         0,         0,         0,
        0, 0, 0xFF, 0xFF, v4addr[0], v4addr[1], v4addr[2], v4addr[3]};
    v6->sin6_family   = AF_INET6;
    v6->sin6_scope_id = 0;
    v6->sin6_flowinfo = 0;
    v6->sin6_port     = v4->sin_port;
    memcpy((void *) &v6->sin6_addr.s6_addr, addr, 16);
}

void unmap_v6tov4(sockaddr_in6 * v6, sockaddr_in * v4) {
    assert(v4);
    assert(v6);
    assert(v6->sin6_family == AF_INET6);
    v4->sin_addr.s_addr = *(uint32_t *) &v6->sin6_addr.s6_addr[12];
}

void tcm_beacon::set_mapping(bool opt) { this->mapping = opt; }

bool tcm_beacon::get_mapping() { return this->mapping; }

tcm_sock tcm_beacon::get_sock() { return this->sock; }

int tcm_beacon::get_family() { return this->domain; }

void tcm_beacon::clear_fields() {
    memset(&this->sa, 0, sizeof(this->sa));
    this->sock    = tcm_invalid_sock;
    this->timeout = 0;
    this->domain  = AF_UNSPEC;
}

void tcm_beacon::create_sock(sockaddr * sa) {
    int sa_size = -1;

    if (sa) {
        sa_size = tcm_internal::get_sa_size(sa);
        if (sa_size <= 0)
            throw EINVAL;
    }

    this->domain  = sa ? sa->sa_family : AF_INET6;
    tcm_sock sock = socket(domain, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
    if (!tcm_sock_valid(sock))
        throw tcm_last_sock_err;

    if (domain == AF_INET6) {
        int flag = 0;
        int ret  = setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (void *) &flag,
                              sizeof(flag));
        if (ret < 0) {
            tcm__log_error("Failed to enable dual-stack socket mode, incoming "
                           "IPv4 connections may fail to work: %s",
                           strerror(errno));
        }
    }

    this->sock = sock;
    if (sa) {
        int ret = bind(sock, sa, sa_size);
        if (ret < 0) {
            tcm__log_error("Socket bind failed: %s",
                           strerror(tcm_last_sock_err));
            tcm_sock_close(sock);
            throw tcm_last_sock_err;
        }
    }

    if (sa)
        memcpy(&this->sa, sa, sa_size);

    if (domain == AF_INET6)
        this->mapping = true;
    else
        this->mapping = false;
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

tcm_beacon::tcm_beacon(sockaddr * sa) {
    this->clear_fields();
    this->create_sock(sa);
    this->timeout = -1;
}

tcm_beacon::tcm_beacon(sockaddr * sa, int timeout_ms) {
    this->clear_fields();
    this->create_sock(sa);
    this->timeout = timeout_ms;
}

tcm_beacon::~tcm_beacon() {
    this->close_sock();
    this->clear_fields();
}

int tcm_beacon::set_peer(sockaddr * sa) {
    int sa_size = tcm_internal::get_sa_size(sa);
    if (sa_size < 0)
        return -EINVAL;

    sockaddr_in6 * ap = 0;
    sockaddr_in6   addr;

    if (mapping && this->domain == AF_INET6 && sa->sa_family == AF_INET) {
        map_v4tov6((sockaddr_in *) sa, &addr);
        ap = &addr;
    } else if (this->domain != sa->sa_family) {
        return -ENOPROTOOPT;
    } else {
        ap = (sockaddr_in6 *) sa;
    }

    int ret = connect(this->sock, (sockaddr *) ap, sa_size);
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

ssize_t tcm_beacon::send_dgram(sockaddr * peer, void * data, ssize_t len) {
    return this->send_dgram(peer, data, len, this->timeout);
}

ssize_t tcm_beacon::send_dgram(sockaddr * peer, void * data, ssize_t len,
                               int timeout_) {
    if (!tcm_internal::check_af_support(peer->sa_family))
        return -ENOPROTOOPT;

    sockaddr_in6 * ap = 0;
    sockaddr_in6   addr;

    if (mapping && this->domain == AF_INET6 && peer->sa_family == AF_INET) {
        tcm__log_trace("Mapping v4 to v6 address");
        map_v4tov6((sockaddr_in *) peer, &addr);
        ap = &addr;
    } else if (this->domain != peer->sa_family) {
        return -ENOPROTOOPT;
    } else {
        ap = (sockaddr_in6 *) peer;
    }

    ssize_t ret;
    int     sa_size = tcm_internal::get_sa_size((sockaddr *) ap);
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
        return -tcm_last_sock_err;
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

ssize_t tcm_beacon::recv_dgram(sockaddr * peer, void * data, ssize_t maxlen) {
    return this->recv_dgram(peer, data, maxlen, this->timeout);
}

ssize_t tcm_beacon::recv_dgram(sockaddr * peer, void * data, ssize_t maxlen,
                               int timeout_) {
    ssize_t      ret;
    socklen_t    sas = sizeof(sockaddr_in6);
    sockaddr_in6 sai6;
    pollfd       pfd;
    pfd.fd      = this->sock;
    pfd.events  = POLLIN;
    pfd.revents = 0;

    ret = poll(&pfd, 1, timeout_);
    if (ret < 0)
        return -tcm_last_sock_err;
    if (ret == 0)
        return -EAGAIN;

    if (pfd.revents & POLLIN) {
        ret = recvfrom(sock, data, maxlen, 0, (sockaddr *) &sai6, &sas);
        if (ret < 0)
            return -tcm_last_sock_err;
        if (sai6.sin6_family == AF_INET6 && is_mapped(&sai6)) {
            tcm__log_trace("Unmapping v6 to v4 address");
            unmap_v6tov4(&sai6, (sockaddr_in *) peer);
        } else {
            memcpy(peer, &sai6, sas);
        }
    } else {
        if (pfd.revents & POLLERR)
            return -tcm_get_sock_err(this->sock);
        if (pfd.events & POLLNVAL)
            return -EINVAL;
        assert(false && "Unexpected event");
    }

    return ret;
}