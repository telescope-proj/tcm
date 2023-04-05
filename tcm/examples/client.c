#include "tcmu.h"
#include "tcm_util.h"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>

#include "conf.h"

// ./client <client_addr> <client_port> <peer_addr> <peer_port>
int main(int argc, char ** argv)
{
    if (argc != 5)
    {
        puts("Invalid arguments");
        return EINVAL;
    }

    ssize_t ret;

    char sin_zero[8] = {0};
    struct sockaddr_in faddr;
    faddr.sin_family      = AF_INET;
    faddr.sin_addr.s_addr = inet_addr(argv[1]);
    faddr.sin_port        = htons(atoi(argv[2]));
    memcpy(&faddr.sin_zero, sin_zero, 8);

    struct sockaddr_in peer;
    peer.sin_family      = AF_INET;
    peer.sin_addr.s_addr = inet_addr(argv[3]);
    peer.sin_port        = htons(atoi(argv[4]));
    memcpy(&peer.sin_zero, sin_zero, 8);

    tcm_fabric * fabric = calloc(1, sizeof(*fabric));
    if (!fabric)
    {
        return ENOMEM;
    }

    ret = tcmu_create_endpoint( (ssap) &faddr, TRANSPORT,
                                TCM_DEFAULT_FABRIC_VERSION, fabric);
    if (ret < 0)
    {
        puts("Create failed");
        free(fabric);
        return -ret;
    }

    fi_addr_t peer_fi = FI_ADDR_UNSPEC;
    ret = tcmu_add_peer(fabric, (ssap) &peer, &peer_fi);
    if (ret < 0)
    {
        fprintf(stderr, "Peer add failed: %s\n", fi_strerror(-ret));
        tcm_destroy_fabric(fabric, 1);
        return -ret;
    }
    if (peer_fi == FI_ADDR_UNSPEC)
    {
        fprintf(stderr, "Peer add failed: address not updated\n");
        tcm_destroy_fabric(fabric, 1);
        return -ret;
    }

    puts("Client created. Attempting to connect...");

    tcm_time timeout;
    timeout.delta       = 1;
    timeout.interval    = 10;
    timeout.ts.tv_sec   = 3;
    timeout.ts.tv_nsec  = 0;

    ret = tcmu_connect(fabric, peer_fi, &timeout);
    if (ret < 0)
    {
        tcm_destroy_fabric(fabric, 1);
        return -ret;
    }

    puts("It works");

    timeout.interval = 0;

    size_t i = 0;
    struct fid_mr * mr = NULL;
    ret = tcm_create_mr(fabric, MSIZE, 4096, &mr);
    if (ret < 0)
    {
        fprintf(stderr, "MR creation failed: %s\n", fi_strerror(-ret));
        tcm_destroy_fabric(fabric, 1);
        return -ret;
    }

    timeout.ts.tv_sec = 3;
    void * msg = mr->fid.context;

    for (i = 0; i < MCOUNT; i++)
    {
        ret = tcm_recv_fabric(fabric, msg, MSIZE, mr, peer_fi, NULL, &timeout);
        if (ret < 0)
            goto cleanup;

        struct fi_cq_data_entry de;
        struct fi_cq_err_entry err;
        ret = tcm_poll_fabric(fabric->rx_cq, &de, &err, &timeout);
        if (ret < 0)
            goto cleanup;
    }

    fi_close(&mr->fid);
    tcm_mem_free(msg);
    tcm_destroy_fabric(fabric, 1);
    return 0;

cleanup:
    fprintf(stderr, "Send iteration %d failed: %s", i, fi_strerror(-ret));
    fi_close(&mr->fid);
    tcm_mem_free(msg);
    tcm_destroy_fabric(fabric, 1);
    return -ret;
}