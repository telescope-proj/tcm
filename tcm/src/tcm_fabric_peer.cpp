// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#include "tcm_fabric.h"
#include "tcm_log.h"
#include <assert.h>

fi_addr_t tcm_fabric::add_peer(sockaddr * peer) {
    assert(peer);
    fi_addr_t out;
    int       ret, sas;
    sas = tcm_internal::get_sa_size(peer);
    if (sas <= 0)
        throw tcm_exception(-sas, __FILE__, __LINE__,
                            "Invalid address structure");

    char addr[INET6_ADDRSTRLEN];
    tcm__log_debug("Adding peer to AV: %s:%d",
                   inet_ntop(peer->sa_family, &((sockaddr_in *) peer)->sin_addr,
                             addr, sas),
                   ntohs(((sockaddr_in *) peer)->sin_port));

    int retv = 0;
    ret      = fi_av_insert(this->av, peer, 1, &out, FI_SYNC_ERR, &retv);
    if (ret != 1) {
        errno = tcm_get_av_error(ret, retv);
        return FI_ADDR_UNSPEC;
    }

    return out;
}

int tcm_fabric::remove_peer(fi_addr_t peer) {
    return fi_av_remove(this->av, &peer, 1, 0);
}

int tcm_fabric::lookup_peer(fi_addr_t peer, sockaddr * out, size_t * size) {
    assert(out);
    assert(size);
    if (peer == FI_ADDR_UNSPEC)
        return -EINVAL;
    return fi_av_lookup(this->av, peer, (void *) out, size);
}