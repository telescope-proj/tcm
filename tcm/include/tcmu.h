#ifndef _TCMU_H_
#define _TCMU_H_

#include "tcm_fabric.h"
#include "tcm_comm.h"

#include <stdlib.h>
#include "compat/tcmc_net.h"

int tcmu_create_endpoint( struct sockaddr * bind_addr,
                        const char * prov_name,
                        uint32_t version,
                        tcm_fabric * out, size_t mbuf_size);

int tcmu_add_peer(tcm_fabric * fabric, struct sockaddr * peer, fi_addr_t * out);

int tcmu_remove_peer(tcm_fabric * fabric, fi_addr_t peer);

ssize_t tcmu_accept(tcm_fabric * fabric, fi_addr_t peer, tcm_time * timeout);

ssize_t tcmu_connect(tcm_fabric * fabric, fi_addr_t peer, tcm_time * timeout);

#endif