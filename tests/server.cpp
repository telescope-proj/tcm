// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#include "tcm_fabric.h"

#include <memory>
#include <stdio.h>

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

    struct fi_info * hints = fi_allocinfo();
    hints->addr_format     = FI_SOCKADDR_IN;
    hints->src_addrlen     = sizeof(struct sockaddr_in);
    hints->src_addr        = &f_addr;
    if (argc > TRANSPORT_NAME)
        hints->fabric_attr->prov_name = strdup(argv[TRANSPORT_NAME]);

    fi_addr_t p_addr  = FI_ADDR_UNSPEC;
    fi_addr_t p2_addr = FI_ADDR_UNSPEC;

    std::shared_ptr<tcm_beacon> beacon = 0;
    std::shared_ptr<tcm_fabric> fabric = 0;

    struct tcm_fabric_init_opts opts = {.version = TCM_DEFAULT_FABRIC_VERSION,
                                        .flags   = 0,
                                        .hints   = hints,
                                        .timeout = 0};

    try {
        beacon = std::make_shared<tcm_beacon>((sockaddr *) &b_addr);
        fabric = std::make_shared<tcm_fabric>(opts);
    } catch (int e) {
        printf("System init failed: %s\n", strerror(e));
        return 1;
    }

    ret = fabric.get()->accept_client(*beacon.get(), NULL, &p_addr);
    if (ret < 0) {
        printf("Error creating fabric server: %s\n", fi_strerror(-ret));
        return 1;
    }

    auto fabric2 = fabric.get()->split_conn(p_addr, 0, 0, &p2_addr);
    if (!fabric2) {
        printf("Error splitting fabric connection: %s\n", fi_strerror(errno));
        return 1;
    }

    auto mem  = tcm_mem(fabric, 4096);
    auto mem2 = tcm_mem(fabric2, 4096);

    ret = fabric.get()->srecv(mem, p_addr, 0, sizeof("hello1"));
    if (ret < 0) {
        printf("Receive failed: %s", fi_strerror(-ret));
        return 1;
    }

    ret = fabric2.get()->srecv(mem2, p2_addr, 0, sizeof("hello2"));
    if (ret < 0) {
        printf("Receive failed: %s", fi_strerror(-ret));
        return 1;
    }

    char * h1 = (char *) mem.get_ptr();
    char * h2 = (char *) mem2.get_ptr();

    h1[sizeof("hello1")] = '\0';
    h2[sizeof("hello2")] = '\0';

    printf("Message 1 = %s, 2 = %s\n", h1, h2);

    if (strcmp(h1, "hello1") == 0 && strcmp(h2, "hello2") == 0) {
        return 0;
    }

    return 1;
}