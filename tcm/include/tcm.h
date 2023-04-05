#ifndef _TCM_H_
#define _TCM_H_

#include <stdlib.h>
#include <stdint.h>

#include "compat/tcmc_net.h"

#include "tcm_fabric.h"
#include "tcm_time.h"
#include "tcm_msg.h"

/*  Byte order in network data is assumed to be little-endian unless specified.
    Message structs are also packed unless specified.
    See the TCM Core Specification for details.
*/

typedef struct {
    struct sockaddr     * beacon_addr;
    struct sockaddr     * client_addr;
    struct sockaddr     * fabric_addr;
    struct fi_info      * fabric_hints;
    uint32_t            fabric_version;
    uint32_t            timeout_ms;
} tcm_server_opts;

typedef struct {
    struct sockaddr     * fabric_src;
    struct sockaddr     * fabric_dst;
    struct sockaddr     * beacon_addr;
    struct sockaddr     * client_addr;
    struct fi_info      * fabric_hints;
    uint32_t            fabric_version;
    uint32_t            fabric_min_version;
    uint64_t            fabric_flags;
} tcm_client_opts;

typedef enum {
    TCM_SOCK_MODE_INVALID,
    TCM_SOCK_MODE_SYNC,
    TCM_SOCK_MODE_ASYNC,
    TCM_SOCK_MODE_MAX
} tcm_sock_mode;

typedef struct {
    struct sockaddr     * beacon_addr;
    tcm_sock            sock;
    tcm_sock_mode       sock_mode;
    uint32_t            timeout_ms;
    uint32_t            poll_rate;
    tcm_fabric          * fabric;
} tcm_server;

typedef struct {
    struct sockaddr     * beacon_addr;
    struct sockaddr     * fabric_addr;
    struct fi_info      * hints;
    uint32_t            fabric_version;
    uint32_t            timeout_ms;
    uint32_t            poll_rate;
    tcm_sock            sock;
    tcm_sock_mode       sock_mode;
    tcm_fabric          * fabric;
    fi_addr_t           peer_addr;
} tcm_client;

int tcm_create_server(tcm_server_opts * opts, tcm_server ** server_out);

void tcm_destroy_server(tcm_server * server);

int tcm_wait_client(tcm_server * server, tcm_time * timeout);

#endif