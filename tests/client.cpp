// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#include "tcm_conn.h"
#include "tcm_fabric.h"

#include <memory>
#include <stdio.h>

using std::make_shared;
using std::shared_ptr;

enum {
    SERVER_ADDR = 1,
    SERVER_PORT,
    FABRIC_ADDR,
    FABRIC_PORT,
    TRANSPORT_NAME,
    BEACON_ADDR,
    BEACON_PORT
};

int main(int argc, char ** argv) {

    if (argc < 3) {
        printf("Invalid arguments\n"
               "Usage: %s server_addr server_port fabric_addr [fabric_port]"
               "[transport_name] [beacon_addr] "
               "[beacon_port]\n",
               argv[0]);
        return EINVAL;
    }

    tcm__log_set_color_mode(1);
    tcm__log_set_level(TCM__LOG_TRACE);

    int                ret;
    struct sockaddr_in s_addr;
    struct sockaddr_in b_addr;
    struct sockaddr_in f_addr;
    memset(&s_addr, 0, sizeof(s_addr));
    memset(&f_addr, 0, sizeof(f_addr));
    memset(&b_addr, 0, sizeof(b_addr));

    s_addr.sin_family      = AF_INET;
    s_addr.sin_addr.s_addr = inet_addr(argv[SERVER_ADDR]);
    s_addr.sin_port        = htons(atoi(argv[SERVER_PORT]));

    if (argc > BEACON_PORT) {
        b_addr.sin_family      = AF_INET;
        b_addr.sin_addr.s_addr = inet_addr(argv[BEACON_ADDR]);
        b_addr.sin_port        = htons(atoi(argv[BEACON_PORT]));
    }

    f_addr.sin_family      = AF_INET;
    f_addr.sin_addr.s_addr = inet_addr(argv[FABRIC_ADDR]);
    f_addr.sin_port        = 0;
    if (argc > FABRIC_PORT)
        f_addr.sin_port = htons(atoi(argv[FABRIC_PORT]));

    struct fi_info * hints = fi_allocinfo();
    hints->ep_attr->type   = FI_EP_RDM;
    hints->addr_format     = FI_SOCKADDR_IN;
    hints->src_addrlen     = sizeof(struct sockaddr_in);
    hints->src_addr        = &f_addr;
    if (argc > TRANSPORT_NAME)
        hints->fabric_attr->prov_name = strdup(argv[TRANSPORT_NAME]);

    fi_info * info = 0;
    ret            = fi_getinfo(fi_version(), NULL, NULL, 0, hints, &info);
    if (ret < 0) {
        printf("Could not get fabric hints: %s", fi_strerror(-ret));
        return 1;
    }

    fi_addr_t p_addr  = FI_ADDR_UNSPEC;
    fi_addr_t p2_addr = FI_ADDR_UNSPEC;

    shared_ptr<tcm_beacon>   beacon = 0;
    shared_ptr<tcm_fabric>   fabric = 0;
    shared_ptr<tcm_endpoint> ep     = 0;
    shared_ptr<tcm_endpoint> ep2    = 0;

    struct tcm_fabric_init_opts opts = {.version = TCM_DEFAULT_FABRIC_VERSION,
                                        .flags   = 0,
                                        .hints   = hints,
                                        .timeout = 0};

    try {
        if (argc > BEACON_PORT)
            beacon = make_shared<tcm_beacon>((sockaddr *) &b_addr);
        else
            beacon = make_shared<tcm_beacon>();
    } catch (int e) {
        printf("System init failed: %s\n", strerror(e));
        return 1;
    }

    ret = tcm_client_dynamic(*beacon, hints, (sockaddr *) &f_addr,
                             (sockaddr *) &s_addr, &fabric, &ep, &p_addr, 0,
                             3000, nullptr);
    if (ret < 0) {
        printf("Connection failed: %s\n", fi_strerror(-ret));
        return 1;
    }

    tcm_mem mem(fabric, 4096);
    strcpy((char*) *mem, "hello");
    strcpy((char*) *mem + 7, "world");
    
    struct sockaddr_in addr;
    size_t             as = sizeof(addr);

    ret = ep->get_name(&addr, &as);
    if (ret < 0) {
        printf("Failed to get endpoint name: %s", fi_strerror(-ret));
        return 1;
    }

    addr.sin_port = 0;
    ep2 = make_shared<tcm_endpoint>(fabric, (sockaddr *) &addr, nullptr);

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

    ret = ep->ssend(mem, p_addr, 0, sizeof("hello"));
    if (ret < 0) {
        printf("Failed to send data: %s\n", fi_strerror(-ret));
        return 1;
    }

    ret = ep2->ssend(mem, p2_addr, sizeof("hello"), sizeof("hello"));
    if (ret < 0) {
        printf("Failed to send data: %s\n", fi_strerror(-ret));
        return 1;
    }

    printf("Sent messages\n");

    return 0;
}