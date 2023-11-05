// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#include "tcm_conn.h"
#include "tcm_fabric.h"

#include <memory>
#include <stdio.h>

using std::make_shared;
using std::shared_ptr;

enum { BEACON_ADDR = 1, BEACON_PORT, TRANSPORT_NAME, FABRIC_ADDR, FABRIC_PORT };

int main(int argc, char ** argv) {
    if (argc < 3) {
        printf("Invalid arguments\n"
               "Usage: %s beacon_addr beacon_port "
               "[transport_name] [fabric_addr] [fabric_port]\n",
               argv[0]);
        return EINVAL;
    }

    tcm__log_set_color_mode(1);
    tcm__log_set_level(TCM__LOG_TRACE);

    int ret;

    struct sockaddr_in b_addr;
    struct sockaddr_in f_addr;
    memset(&b_addr, 0, sizeof(b_addr));
    memset(&f_addr, 0, sizeof(f_addr));

    b_addr.sin_family      = AF_INET;
    b_addr.sin_addr.s_addr = inet_addr(argv[BEACON_ADDR]);
    b_addr.sin_port        = htons(atoi(argv[BEACON_PORT]));

    if (argc <= FABRIC_PORT) {
        f_addr.sin_family      = AF_INET;
        f_addr.sin_addr.s_addr = inet_addr(argv[BEACON_ADDR]);
        f_addr.sin_port        = 0;
    } else {
        f_addr.sin_family      = AF_INET;
        f_addr.sin_addr.s_addr = inet_addr(argv[FABRIC_ADDR]);
        f_addr.sin_port        = htons(atoi(argv[FABRIC_PORT]));
    }

    struct fi_info * hints        = fi_allocinfo();
    hints->ep_attr->type          = FI_EP_RDM;
    hints->addr_format            = FI_SOCKADDR_IN;
    hints->src_addrlen            = sizeof(struct sockaddr_in);
    hints->src_addr               = &f_addr;
    hints->fabric_attr->prov_name = 0;
    if (argc > TRANSPORT_NAME)
        hints->fabric_attr->prov_name = strdup(argv[TRANSPORT_NAME]);

    fi_addr_t p_addr  = FI_ADDR_UNSPEC;
    fi_addr_t p2_addr = FI_ADDR_UNSPEC;

    shared_ptr<tcm_beacon>   beacon = 0;
    shared_ptr<tcm_fabric>   fabric = 0;
    shared_ptr<tcm_endpoint> ep     = 0;
    shared_ptr<tcm_endpoint> ep2    = 0;

    try {
        beacon = make_shared<tcm_beacon>((sockaddr *) &b_addr);
    } catch (int e) {
        printf("System init failed: %s\n", strerror(e));
        return 1;
    }

    ret = tcm_accept_client_dynamic(*beacon, hints, nullptr, nullptr, &fabric,
                                    &ep, &p_addr, -1, nullptr);
    if (ret < 0) {
        printf("Failed to accept client: %s\n", fi_strerror(-ret));
        return 1;
    }

    struct sockaddr_in addr;
    size_t             as = sizeof(addr);
    ret                   = ep->get_name(&addr, &as);
    if (ret < 0) {
        printf("Failed to get endpoint name: %s", fi_strerror(-ret));
        return 1;
    }

    addr.sin_port = htons(ntohs(addr.sin_port) + 1);
    ep2 = make_shared<tcm_endpoint>(fabric, (sockaddr *) &addr, nullptr);

    tcm_mem mem(fabric, 4096);

    as  = sizeof(addr);
    ret = fabric->lookup_peer(p_addr, (sockaddr *) &addr, &as);
    if (ret < 0) {
        printf("Failed to get peer address: %s\n", fi_strerror(-ret));
        return 1;
    }

    addr.sin_port = htons(ntohs(addr.sin_port) + 1);
    p2_addr       = fabric->add_peer((sockaddr *) &addr);
    if (p2_addr == FI_ADDR_UNSPEC) {
        printf("Failed to get peer address: %s\n", fi_strerror(-ret));
        return 1;
    }

    ret = ep->srecv(mem, p_addr, 0, sizeof("hello"));
    if (ret < 0 ) {
        printf("Failed to receive data: %s\n", fi_strerror(-ret));
        return 1;
    }

    ret = ep2->srecv(mem, p2_addr, sizeof("hello"), sizeof("hello"));
    if (ret < 0) {
        printf("Failed to receive data: %s\n", fi_strerror(-ret));
        return 1;
    }

    char * h = (char*) *mem;

    printf("Message: %s %s\n", h, &h[7]);

    return 0;
}