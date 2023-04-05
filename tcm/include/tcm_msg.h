#ifndef _TCM_MSG_H_
#define _TCM_MSG_H_

#include <stdint.h>

#include "tcm_comm.h"
#include "tcm_version.h"

typedef enum {
    TCM_AF_INVALID,
    TCM_AF_INET = 1,
    TCM_AF_MAX
} tcm_addr_format;

typedef enum {
    TCM_MSG_INVALID,
    TCM_MSG_CLIENT_PING     = 1,
    TCM_MSG_SERVER_STATUS   = 2,
    TCM_MSG_METADATA_REQ    = 3,
    TCM_MSG_METADATA_RESP   = 4,
    TCM_MSG_CONN_REQ        = 5,
    TCM_MSG_FABRIC_PING     = 6,
    TCM_MSG_MAX
} tcm_msg_type;

typedef enum {
    TCM_TID_INVALID,
    TCM_TID_TCP_RXM     = 1,
    TCM_TID_VERBS_RXM   = 2,
    TCM_TID_MAX
} tcm_transport_id;


#pragma pack(push, 1)

/* ---------------------------- Address Formats ---------------------------- */

typedef struct {
    uint32_t addr;
    uint16_t port;
} tcm_addr_inet;

/* ----------------------------- Common Items ----------------------------- */

typedef struct {
    uint32_t magic;
    uint16_t id;
    uint16_t token;
} tcm_msg_header;

typedef struct {
    uint16_t major;
    uint16_t minor;
    uint16_t patch;
} tcm_msg_version;

/* -------------------------- Message Definitions -------------------------- */

typedef struct {
    tcm_msg_header  common;
    tcm_msg_version version;
    uint16_t        pad;
} tcm_msg_client_ping;

typedef struct {
    tcm_msg_header  common;
    tcm_msg_version version;
    uint16_t        retcode;
} tcm_msg_server_status;

typedef struct {
    tcm_msg_header  common;
    tcm_msg_version version;
    uint16_t        pad;
} tcm_msg_metadata_req;

typedef struct {
    tcm_msg_header      common;
    uint16_t            fabric_major;
    uint16_t            fabric_minor;
    tcm_transport_id    tid;
    tcm_addr_format     addr_fmt;
    uint16_t            addr_len;
    uint8_t             pad[6];
    uint8_t             addr[0];
} tcm_msg_metadata_resp;

typedef struct {
    tcm_msg_header      common;
    tcm_msg_version     version;
    uint16_t            fabric_major;
    uint16_t            fabric_minor;
    tcm_transport_id    transport_id;
    tcm_addr_format     addr_fmt;
    uint16_t            addr_len;
    uint8_t             addr[0];
} tcm_msg_conn_req;

typedef struct {
    tcm_msg_header      common;
    uint16_t            fabric_major;
    uint16_t            fabric_minor;
    uint16_t            direction;
    uint8_t             pad[6];
} tcm_msg_fabric_ping;

#pragma pack(pop)

typedef union {
    tcm_msg_client_ping     * s1;
    tcm_msg_server_status   * s2;
    tcm_msg_metadata_req    * s3;
    tcm_msg_metadata_resp   * s4;
    tcm_msg_conn_req        * s5;
    tcm_msg_fabric_ping     * s6;
} tcm__msg_val_u;

void tcm_msg_init(void * msg, int token);

#endif