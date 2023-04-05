#include "tcm_msg.h"

void tcm_msg_init(void * msg, int token)
{
    tcm_msg_header * header = (tcm_msg_header *) msg;

    if (!header || !header->id)
        return;

    int set_ver = 0;
    switch (header->id)
    {
        case TCM_MSG_CLIENT_PING:
        case TCM_MSG_SERVER_STATUS:
        case TCM_MSG_METADATA_REQ:
        case TCM_MSG_CONN_REQ:
            set_ver = 1;
            break;
        case TCM_MSG_FABRIC_PING:
        case TCM_MSG_METADATA_RESP:
            break;
        default:
            return;
    }

    header->magic = TCM_MAGIC;
    header->token = token;

    if (set_ver)
    {
        // Get offset
        tcm_msg_version * ver = (tcm_msg_version *) \
            (((uint8_t *) header) + sizeof(tcm_msg_header));
        ver->major = TCM_VERSION_MAJOR;
        ver->minor = TCM_VERSION_MINOR;
        ver->patch = TCM_VERSION_PATCH;
    }

    return;
}