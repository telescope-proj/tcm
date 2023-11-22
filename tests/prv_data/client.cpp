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

    /* Required */
    const char * server_addr = getenv("SERVER_ADDR");
    const char * server_port = getenv("SERVER_PORT");

    /* At least one required */
    const char * beacon_addr = getenv("BEACON_ADDR");
    const char * fabric_addr = getenv("FABRIC_ADDR");

    /* Optional */
    const char * beacon_port    = getenv("BEACON_PORT");
    const char * fabric_port    = getenv("FABRIC_PORT");
    const char * transport_name = getenv("TRANSPORT_NAME");
    if (transport_name) {
        setenv("FI_PROVIDER", transport_name, 0);
    }

    if (!server_addr || !server_port) {
        printf("Server address and port must be provided");
        return EINVAL;
    }
    if (!beacon_addr && !fabric_addr) {
        printf("A beacon, fabric address, or both must be provided");
        return EINVAL;
    }
    if (beacon_addr && !fabric_addr) {
        fabric_addr = beacon_addr;
    }

    int         ret;
    sockaddr_in s_addr;
    sockaddr_in b_addr;
    sockaddr_in f_addr;
    memset(&s_addr, 0, sizeof(s_addr));
    memset(&f_addr, 0, sizeof(f_addr));
    memset(&b_addr, 0, sizeof(b_addr));

    s_addr.sin_family      = AF_INET;
    s_addr.sin_addr.s_addr = inet_addr(server_addr);
    s_addr.sin_port        = htons(atoi(server_port));

    b_addr.sin_family = AF_INET;
    if (beacon_addr)
        b_addr.sin_addr.s_addr = inet_addr(beacon_addr);
    if (beacon_port)
        b_addr.sin_port = htons(atoi(beacon_port));

    f_addr.sin_family      = AF_INET;
    f_addr.sin_addr.s_addr = inet_addr(fabric_addr);
    f_addr.sin_port        = fabric_port ? htons(atoi(fabric_port)) : 0;

    fi_addr_t p_addr  = FI_ADDR_UNSPEC;
    fi_addr_t p2_addr = FI_ADDR_UNSPEC;

    shared_ptr<tcm_beacon>   beacon = 0;
    shared_ptr<tcm_fabric>   fabric = 0;
    shared_ptr<tcm_endpoint> ep     = 0;
    shared_ptr<tcm_endpoint> ep2    = 0;

    /* Create a beacon object for handshake */

    try {
        if (beacon_addr || beacon_port)
            beacon = make_shared<tcm_beacon>((sockaddr *) &b_addr);
        else
            beacon = make_shared<tcm_beacon>();
    } catch (std::exception & exc) {
        printf("System init failed: %s\n", exc.what());
        return 1;
    }

    /* Create a dynamic fabric connection */

    {
        char         str[]  = "TCM Hello World Application (Client)";
        char         resp[] = "TCM Hello World Application (Server)";
        tcm_prv_data prv;
        prv.data      = str;
        prv.size      = strlen(str) + 1;
        prv.params    = resp;
        prv.validator = sample_validator;

        fi_info * fhints               = fi_allocinfo();
        fhints->fabric_attr->prov_name = strdup(transport_name);
        tcm_conn_hints h = {.addr = &f_addr, .hints = fhints, .flags = 0};
        std::vector<tcm_conn_hints> hints;
        hints.push_back(h);

        tcm_client_dynamic_param p;
        p.clear();
        p.beacon     = beacon.get();
        p.hints      = &hints;
        p.timeout_ms = 3000;
        p.peer       = SA_CAST(&s_addr);
        p.prv_data   = &prv;
        p.fast       = 0;

        ret = tcm_client_dynamic(&p);
        if (ret < 0) {
            printf("Unable to establish connection: %s", fi_strerror(-ret));
            return ret;
        }

        fabric = p.fabric_out;
        ep     = p.ep_out;
        p_addr = p.peer_out;
        fi_freeinfo(fhints);
    }

    tcm_mem mem(fabric, 4096);
    strcpy((char *) *mem, "hello world");

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

    /* Send "hello world" over two separate endpoints */

    ret = ep->ssend(mem, p_addr, 0, sizeof("hello"));
    if (ret < 0) {
        printf("Failed to send data: %s\n", fi_strerror(-ret));
        return 1;
    }

    ret = ep2->ssend(mem, p2_addr, sizeof("hello"), sizeof("world"));
    if (ret < 0) {
        printf("Failed to send data: %s\n", fi_strerror(-ret));
        return 1;
    }

    printf("Sent messages from buffer: %s\n", (char *) *mem);

    return 0;
}