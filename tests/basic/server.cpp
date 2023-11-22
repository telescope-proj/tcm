// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#include "common.h"

int main() {
    if (tcm_init(nullptr) < 0) {
        printf("TCM init failed!");
        return 1;
    }

    tcm__log_set_color_mode(1);
    tcm__log_set_level(TCM__LOG_TRACE);
    int ret;

    /* Required */
    const char * beacon_addr = getenv("BEACON_ADDR");
    const char * beacon_port = getenv("BEACON_PORT");

    /* Optional */
    const char * fabric_addr    = getenv("FABRIC_ADDR");
    const char * fabric_port    = getenv("FABRIC_PORT");
    const char * transport_name = getenv("TRANSPORT_NAME");

    if (!beacon_addr || !beacon_port)
        return EINVAL;

    sockaddr_in b_addr;
    sockaddr_in f_addr;
    memset(&b_addr, 0, sizeof(b_addr));
    memset(&f_addr, 0, sizeof(f_addr));

    b_addr.sin_family      = AF_INET;
    b_addr.sin_addr.s_addr = inet_addr(beacon_addr);
    b_addr.sin_port        = htons(atoi(beacon_port));

    if (fabric_addr) {
        f_addr.sin_family      = AF_INET;
        f_addr.sin_addr.s_addr = inet_addr(fabric_addr);
        f_addr.sin_port        = fabric_port ? htons(atoi(fabric_port)) : 0;
    } else {
        f_addr.sin_family      = AF_INET;
        f_addr.sin_addr.s_addr = inet_addr(beacon_addr);
        f_addr.sin_port        = 0;
    }

    fi_addr_t p_addr  = FI_ADDR_UNSPEC;
    fi_addr_t p2_addr = FI_ADDR_UNSPEC;

    shared_ptr<tcm_beacon>   beacon = 0;
    shared_ptr<tcm_fabric>   fabric = 0;
    shared_ptr<tcm_endpoint> ep     = 0;
    shared_ptr<tcm_endpoint> ep2    = 0;

    try {
        beacon = make_shared<tcm_beacon>((sockaddr *) &b_addr);
    } catch (std::exception & exc) {
        printf("System init failed: %s\n", exc.what());
        return 1;
    }

    {
        fi_info * fhints               = fi_allocinfo();
        fhints->fabric_attr->prov_name = strdup(transport_name);
        tcm_conn_hints h = {.addr = &f_addr, .hints = fhints, .flags = 0};
        std::vector<tcm_conn_hints> hints;
        hints.push_back(h);

        tcm_accept_client_dynamic_param p;
        p.clear();
        p.beacon     = beacon.get();
        p.hints      = &hints;
        p.timeout_ms = -1;

        ret = tcm_accept_client_dynamic(&p);
        if (ret < 0) {
            printf("Failed to accept client: %s\n", fi_strerror(-ret));
            return 1;
        }

        fabric = p.fabric_out;
        ep     = p.ep_out;
        p_addr = p.fabric_peer_out;
        fi_freeinfo(fhints);
    }

    /* Set up the message buffer. */
    tcm_mem mem(fabric, 4096);

    sockaddr_storage addr;
    size_t           as = sizeof(addr);

    /* Create a new endpoint locally with port num of original endpoint + 1 */

    ret = ep->get_name(&addr, &as);
    if (ret < 0) {
        printf("Failed to get endpoint name: %s", fi_strerror(-ret));
        return 1;
    }

    increment_port(SA_CAST(&addr), 1);
    ep2 = make_shared<tcm_endpoint>(fabric, SA_CAST(&addr), nullptr);

    /* The peer also does port num + 1 for the second endpoint */

    as  = sizeof(addr);
    ret = fabric->lookup_peer(p_addr, SA_CAST(&addr), &as);
    if (ret < 0) {
        printf("Failed to get peer address: %s\n", fi_strerror(-ret));
        return 1;
    }

    increment_port(SA_CAST(&addr), 1);
    p2_addr = fabric->add_peer(SA_CAST(&addr));
    if (p2_addr == FI_ADDR_UNSPEC) {
        printf("Failed to get peer address: %s\n", fi_strerror(-ret));
        return 1;
    }

    /* Receive the client's hello world message over two separate endpoints */

    ret = ep->srecv(mem, p_addr, 0, sizeof("hello"));
    if (ret < 0) {
        printf("Failed to receive data: %s\n", fi_strerror(-ret));
        return 1;
    }

    ret = ep2->srecv(mem, p2_addr, sizeof("world"), sizeof("world") + 1);
    if (ret < 0) {
        printf("Failed to receive data: %s\n", fi_strerror(-ret));
        return 1;
    }

    char * h = (char *) *mem;
    printf("Message: %s\n", h);

    return 0;
}