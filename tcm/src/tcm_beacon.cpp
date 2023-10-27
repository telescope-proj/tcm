// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#include "tcm_beacon.h"
#include "tcm_comm.h"
#include "tcm_log.h"
#include "tcm_socket.h"

void tcm_beacon::clear_fields() {
    memset(&this->sa, 0, sizeof(this->sa));
    this->mode               = TCM_SOCK_MODE_INVALID;
    this->sock               = tcm_invalid_sock;
    this->timeout.delta      = 0;
    this->timeout.interval   = 0;
    this->timeout.ts.tv_sec  = 0;
    this->timeout.ts.tv_nsec = 0;
    this->timeout_active     = 0;
}

void tcm_beacon::create_sock(struct sockaddr * sa, tcm_sock_mode mode) {
    int sa_size = -1;

    if (sa) {
        sa_size = tcm_internal::get_sa_size(sa);
        if (sa_size <= 0)
            throw EINVAL;
    }

    this->mode    = mode;
    tcm_sock sock = socket(
        sa ? sa->sa_family : AF_INET,
        SOCK_DGRAM | (this->mode == TCM_SOCK_MODE_ASYNC ? SOCK_NONBLOCK : 0),
        IPPROTO_UDP);
    if (!tcm_sock_valid(sock))
        throw tcm_sock_err;

    this->sock = sock;
    if (sa) {
        int ret = bind(sock, sa, sa_size);
        if (ret < 0) {
            tcm__log_error("Socket bind failed: %s", strerror(tcm_sock_err));
            throw tcm_sock_err;
        }
    }

    if (sa)
        memcpy(&this->sa, sa, sa_size);
}

void tcm_beacon::close_sock() { tcm_sock_close(this->sock); }

tcm_beacon::tcm_beacon() {
    this->clear_fields();
    this->create_sock(NULL, TCM_SOCK_MODE_SYNC);
}

tcm_beacon::tcm_beacon(struct sockaddr * sa) {
    this->clear_fields();
    this->create_sock(sa, TCM_SOCK_MODE_SYNC);
}

tcm_beacon::tcm_beacon(struct sockaddr * sa, tcm_sock_mode mode) {
    this->clear_fields();
    this->create_sock(sa, mode);
}

tcm_beacon::tcm_beacon(struct sockaddr * sa, tcm_sock_mode mode,
                       tcm_time * timeout) {
    this->clear_fields();
    this->create_sock(sa, mode);
    this->set_timeout(timeout);
}

tcm_beacon::~tcm_beacon() { this->close_sock(); }

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

void tcm_beacon::set_timeout(tcm_time * time) {
    this->timeout = *time;
    struct timeval timeout;
    timeout.tv_sec  = time->ts.tv_sec;
    timeout.tv_usec = time->ts.tv_nsec / 1000;

    if (setsockopt(this->sock, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof(timeout)) < 0) {
        tcm__log_error("Failed to set receive timeout");
        throw errno;
    }

    if (setsockopt(this->sock, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                   sizeof(timeout)) < 0) {
        tcm__log_error("Failed to set send timeout");
        throw errno;
    }

    this->timeout_active = 1;
}

ssize_t tcm_beacon::send_dgram(struct sockaddr * peer, void * data,
                               ssize_t len) {
    return this->send_dgram(peer, data, len, NULL);
}

ssize_t tcm_beacon::send_dgram(struct sockaddr * peer, void * data, ssize_t len,
                               tcm_time * timeout) {

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

    if (!this->timeout_active && !timeout) {
        ret = sendto(sock, data, len, 0, peer, sa_size);
        if (ret < 0) {
            int err = tcm_sock_err;
            switch (err) {
                case EAGAIN:
                case ENOBUFS:
                case ETIMEDOUT:
                    return -err;
                default:
                    throw err;
            }
        }
        return ret;
    } else {
        tcm_time        t;
        struct timespec dl;
        int             flag = 0;
        if (timeout)
            t = *timeout;
        else
            t = this->timeout;
        ret = tcm_conv_time(&t, &dl);
        if (ret < 0)
            throw EINVAL;

        while (!tcm_check_deadline(&dl)) {
            ret = sendto(sock, data, len, 0, peer, sa_size);
            if (ret < 0) {
                if (tcm_sock_err == EAGAIN || tcm_sock_err == EWOULDBLOCK) {
                    tcm_sleep(t.interval);
                    continue;
                }
                tcm__log_error("Failed to send message: %s",
                               strerror(tcm_sock_err));
                return -tcm_sock_err;
            }
            flag = 1;
            break;
        }

        if (flag == 0)
            return -ETIMEDOUT;
        return ret;
    }
}

ssize_t tcm_beacon::recv_dgram(struct sockaddr * peer, void * data,
                               ssize_t maxlen) {
    return this->recv_dgram(peer, data, maxlen, NULL);
}

ssize_t tcm_beacon::recv_dgram(struct sockaddr * peer, void * data,
                               ssize_t maxlen, tcm_time * timeout) {
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

    if (!this->timeout_active && !timeout) {
        ret = recvfrom(sock, data, maxlen, 0, peer, &sas);
        if (ret < 0) {
            int err = tcm_sock_err;
            switch (err) {
                case EAGAIN:
                case ENOBUFS:
                case ETIMEDOUT:
                    return -err;
                default:
                    throw err;
            }
        }
        return ret;
    } else {
        tcm_time        t;
        struct timespec dl;
        int             flag = 0;
        if (timeout)
            t = *timeout;
        else
            t = this->timeout;
        ret = tcm_conv_time(&t, &dl);
        if (ret < 0)
            throw EINVAL;

        do {
            ret = recvfrom(sock, data, maxlen, 0, peer, &sas);
            if (ret < 0) {
                if (tcm_sock_err == EAGAIN || tcm_sock_err == EWOULDBLOCK) {
                    tcm_sleep(t.interval);
                    continue;
                }
                tcm__log_error("Failed to send message: %s",
                               strerror(tcm_sock_err));
                return -tcm_sock_err;
            }
            flag = 1;
            break;
        } while (!tcm_check_deadline(&dl));

        if (flag == 0)
            return -ETIMEDOUT;
        return ret;
    }
}