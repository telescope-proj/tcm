#include "tcm.h"
#include "tcm_log.h"
#include "tcm_comm.h"
#include "tcm_util.h"
#include "tcm_udp.h"
#include "tcm_fabric.h"

#include <rdma/fabric.h>

static inline struct fi_info * tcm_get_fabric_hints(uint32_t addr_fmt, 
                                                    char * prov_name)
{
    struct fi_info * hints = fi_allocinfo();
    if (!hints)
    {
        return NULL;
    }

    hints->ep_attr->type            = FI_EP_RDM;
    hints->caps                     = FI_MSG | FI_RMA;
    hints->addr_format              = addr_fmt;
    hints->mode                     = FI_LOCAL_MR;
    hints->domain_attr->mr_mode     = FI_MR_BASIC;
    hints->fabric_attr->prov_name   = prov_name;
    return hints;
}

void tcm_destroy_fabric(tcm_fabric * fabric, int free_struct)
{
    int ret;
    if (!fabric)
        return;

    if (fabric->ep)
    {
        ret = fi_close((fid_t) fabric->ep);
        if (ret < 0)
            tcm__log_warn("Endpoint deallocation failed: %s", fi_strerror(-ret));
        fabric->ep = NULL;
    }
    if (fabric->mr)
    {
        ret = fi_close((fid_t) fabric->mr);
        if (ret < 0)
            tcm__log_warn("MR deallocation failed: %s", fi_strerror(-ret));
        tcm_mem_free(fabric->mr_info.ptr);
        fabric->mr = NULL;
        fabric->mr_info.ptr = NULL;
    }
    if (fabric->av)
    {
        ret = fi_close((fid_t) fabric->av); 
        if (ret < 0)
            tcm__log_warn("AV deallocation failed: %s", fi_strerror(-ret));
        fabric->av = NULL;
    }  
    if(fabric->rx_cq)
    {
        ret = fi_close((fid_t) fabric->rx_cq);
        if (ret < 0)
            tcm__log_warn("Receive CQ deallocation failed: %s", fi_strerror(-ret));
        fabric->rx_cq = NULL;
    }
    if (fabric->tx_cq)
    {
        ret = fi_close((fid_t) fabric->tx_cq);
        if (ret < 0)
            tcm__log_warn("Send CQ deallocation failed: %s", fi_strerror(-ret));
        fabric->tx_cq = NULL;
    }
    if (fabric->domain)
    {
        ret = fi_close((fid_t) fabric->domain);
        if (ret < 0)
            tcm__log_warn("Domain deallocation failed: %s", fi_strerror(-ret));
        fabric->domain = NULL;
    }
    if (fabric->fabric)
    {
        ret = fi_close((fid_t) fabric->fabric);
        if (ret < 0)
            tcm__log_warn("Fabric deallocation failed: %s", fi_strerror(-ret));
        fabric->fabric = NULL;
    }
    if (free_struct)
    {
        free(fabric);
    }
}

void tcm_destroy_server(tcm_server * server)
{
    tcm_destroy_fabric(server->fabric, 1);
    close(server->sock);
}

int tcm__node_service_to_sa(const char * node, const char * service, struct
                            sockaddr_storage * addr_out)
{
    int ret;
    struct addrinfo * ai;
    ret = getaddrinfo(node, service, NULL, &ai);
    if (ret != 0)
    {
        return -ret;
    }

    for (struct addrinfo * ai_tmp = ai; ai_tmp; ai_tmp = ai_tmp->ai_next)
    {
        switch (ai->ai_family)
        {
            case AF_INET:
            case AF_INET6:
                memcpy(addr_out, ai->ai_addr, ai->ai_addrlen);
                ret = 1;
                break;
            default:
                break;  // Unsupported format
        }
        if (ret == 1)
        {
            break;
        }   
    }

    freeaddrinfo(ai);
    if (ret == 1)
    {
        return 0;
    }

    return -EINVAL;
}

int tcm_create_server(tcm_server_opts * opts, tcm_server ** server_out)
{
    int ret;

    if (!opts || !opts->beacon_addr)
    {
        return -EINVAL;
    }

    tcm_server * svr = calloc(1, sizeof(tcm_server));
    if (!svr)
    {
        return -ENOMEM;
    }

    /* Create beacon */

    ret = tcm_setup_udp( opts->beacon_addr, TCM_SOCK_MODE_ASYNC, 
                                &svr->sock);
    if (ret < 0)
    {
        tcm__log_error("Beacon creation failed: %s", strerror(tcm_abs(ret)));
        goto err;
    }

    /* Create fabric resources */

    svr->fabric = calloc(1, sizeof(*svr->fabric));
    if (!svr->fabric)
    {
        ret = -ENOMEM;
        goto err;
    }

    ret = tcm_setup_fabric( opts->fabric_version, FI_SOURCE,
                            opts->fabric_hints, svr->fabric);
    if (ret < 0)
    {
        tcm__log_error("Fabric creation failed: %s", strerror(tcm_abs(ret)));
        goto err_fabric;
    }

    * server_out = svr;
    return 0;

err_fabric:
    free(svr->fabric);
err:
    free(svr);
    return ret;
}

int tcm_create_client(tcm_client_opts * opts, tcm_client ** client_out)
{

    ssize_t ret;
    tcm_client * cli = calloc(1, sizeof(*cli));
    if (!cli)
    {
        return -ENOMEM;
    }

    int token = 1;
    int dst_size = tcm__get_sa_size(opts->beacon_addr);
    if (dst_size < 0)
    {
        ret = dst_size;
        goto err;
    }

    /* Create socket to connect to beacon */

    tcm_sock sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (!tcm_sock_valid(sock))
    {
        tcm__log_error("UDP socket creation failed: %s", strerror(tcm_sock_err));
        ret = -tcm_sock_err;
        goto err;
    }

    /* Set message handling timer */

    tcm_time timing = {
        .ts.tv_sec  = 3,
        .ts.tv_nsec = 0,
        .interval   = 1,
        .delta      = 1,
    };

    /* First contact with beacon */

    tcm_msg_client_ping ping;
    ping.common.id = TCM_MSG_CLIENT_PING;
    ping.pad = 0;
    tcm_msg_init(&ping, token++);

    tcm_msg_server_status stat;
    memset(&stat, 0, sizeof(stat));

    ret = tcm_exch_udp( cli->sock, &ping, sizeof(ping), &stat, sizeof(stat),
                        opts->beacon_addr, &timing);
    if (ret < 0)
    {
        tcm__log_error("Ping message failure: %s", strerror(tcm_abs(ret)));
        goto err_socket;
    }

    /* Check version */

    if (stat.common.magic != TCM_MAGIC 
        || ret != sizeof(tcm_msg_server_status)
        || stat.common.id != TCM_MSG_SERVER_STATUS 
        || stat.common.token != ping.common.token)
    {
        tcm__log_error("Response message garbled");
        goto err_socket;
    }

    if (stat.version.major != TCM_VERSION_MAJOR
        || stat.version.minor != TCM_VERSION_MINOR
        || stat.version.patch != TCM_VERSION_PATCH)
    {
        tcm__log_error( "Version mismatch: Client: %d.%d.%d, Server: %d.%d.%d",
                        TCM_VERSION_MAJOR, TCM_VERSION_MINOR, TCM_VERSION_PATCH,
                        stat.version.major, stat.version.minor, stat.version.patch);
        goto err_socket;
    }

    /* Request fabric information */

    tcm_msg_metadata_req req;
    req.common.id = TCM_MSG_METADATA_REQ;
    tcm_msg_init(&req, token++);

    tcm_msg_metadata_resp meta;
    memset(&meta, 0, sizeof(tcm_msg_metadata_resp));

    ret = tcm_exch_udp( cli->sock, &req, sizeof(req), &meta, sizeof(meta),
                        opts->beacon_addr, &timing);
    if (ret < 0)
    {
        tcm__log_error("Metadata request failure: %s", strerror(tcm_abs(ret)));
    }
    
    /* Check metadata response valid */

    if (meta.common.magic != TCM_MAGIC 
        || meta.common.id != TCM_MSG_SERVER_STATUS 
        || meta.common.token != req.common.token)
    {
        tcm__log_error("Response message garbled");
        goto err_socket;
    }
    if (ret - meta.addr_len != sizeof(meta))
    {
        tcm__log_error( "Server address invalid: msg bytes: %d, expected: %d",
                        ret, meta.addr_len + sizeof(meta));
        goto err_socket;
    }
    if (meta.addr_fmt != TCM_AF_INET || meta.addr_len != sizeof(tcm_addr_inet))
    {
        tcm__log_error("Server sent invalid address format or address garbled");
        ret = -EINVAL;
        goto err_socket;
    }

    /* Verify transport */

    // todo

    /* Verify matching Libfabric version and change if necessary */
    
    cli->fabric_version = opts->fabric_version;

    if (meta.fabric_major > FI_MAJOR(opts->fabric_version)
        || meta.fabric_minor > FI_MINOR(opts->fabric_version))
    {
        tcm__log_error("Server Libfabric version newer than client version");
        tcm__log_error( "Use Libfabric version %d.%d.x, "
                        "or set server version to %d.%d.x", 
                        meta.fabric_major, meta.fabric_minor,
                        FI_MAJOR(opts->fabric_version), 
                        FI_MINOR(opts->fabric_version));
        goto err_socket;
    }
    
    if (   (meta.fabric_major != FI_MAJOR(opts->fabric_version)
        || meta.fabric_minor != FI_MINOR(opts->fabric_version))
        && (FI_MAJOR(opts->fabric_min_version) >= meta.fabric_major)
        && (FI_MINOR(opts->fabric_min_version) >= meta.fabric_minor))
    {
        tcm__log_warn(  "Server Libfabric version: %d.%d, auto-downgrading",
                        meta.fabric_major, meta.fabric_minor);
        tcm__log_warn(  "Performance may be lower than expected. "
                        "Server Libfabric version upgrade recommended");
        cli->fabric_version = FI_VERSION(meta.fabric_major, meta.fabric_minor);
    }
    else
    {
        tcm__log_error( "Server (%d.%d) and client (%d.%d) Libfabric version "
                        "mismatched, minimum version %d.%d not satisfied",
                        meta.fabric_major, meta.fabric_minor, 
                        FI_MAJOR(opts->fabric_version), 
                        FI_MINOR(opts->fabric_version),
                        FI_MAJOR(opts->fabric_min_version), 
                        FI_MINOR(opts->fabric_min_version));
        goto err_socket;
    }

    /* Create fabric resources */

    cli->fabric = calloc(1, sizeof(*cli->fabric));
    if (!cli->fabric)
    {
        ret = -ENOMEM;
        goto err_socket;
    }

    /*  Copy destination information from server or, if user forced TCM to use a
        specific address, use it */

    int dest_alloc = 0;
    struct sockaddr_in * sai = NULL;

    if (!opts->fabric_hints->dest_addr)
    {
        tcm__log_trace("Using server-suggested fabric address");
        dest_alloc = 1;
        opts->fabric_hints->dest_addr = calloc(1, sizeof(struct sockaddr_in));
        if (!opts->fabric_hints->dest_addr)
        {
            goto err_fabric;
        }
        opts->fabric_hints->dest_addrlen    = sizeof(struct sockaddr_in);
        tcm_addr_inet inet                  = * (tcm_addr_inet *) (&meta.addr);
        sai                                 = opts->fabric_hints->dest_addr;
        sai->sin_addr.s_addr                = inet.addr;
        sai->sin_port                       = inet.port;
    }
    else
    {
        tcm__log_trace("Overriding server fabric address with user value");
    }

    ret = tcm_setup_fabric( cli->fabric_version, 0, opts->fabric_hints, 
                            cli->fabric);
    if (ret < 0)
    {
        goto err_fabric;
    }

    /*  Create default message MR */

    ret = tcm_create_mr(cli->fabric, 4096, 4096, &cli->fabric->mr);
    if (ret < 0)
    {
        goto err_fabric;
    }

    cli->fabric->mr_info.alignment  = 4096;
    cli->fabric->mr_info.len        = 4096;
    cli->fabric->mr_info.ptr        = cli->fabric->mr->fid.context;
    cli->fabric->mr->fid.context    = 0;

    /* Add peer to fabric AV */
    
    fi_addr_t peer_addr = FI_ADDR_UNSPEC;
    ret = fi_av_insert(cli->fabric->av, sai, 1, &peer_addr, 0, NULL);
    if (ret < 0 || peer_addr == FI_ADDR_UNSPEC)
    {
        tcm__log_error( "Address insertion failed: %s",
                        ret < 0 ? fi_strerror(tcm_abs(ret))
                                : "Address unmodified");
        goto err_fabric;
    }

    tcm_msg_fabric_ping * fping = \
        (tcm_msg_fabric_ping *) cli->fabric->mr_info.ptr;
    tcm_msg_init(fping, token++);
    fping->fabric_major     = FI_MAJOR(cli->fabric_version);
    fping->fabric_minor     = FI_MINOR(cli->fabric_version);
    fping->direction        = 0;
    tcm_msg_fabric_ping * fresp = fping + 1;
    
    struct fi_cq_err_entry err;
    memset(&err, 0, sizeof(err));

    ret = tcm_exch_fabric(cli->fabric, 
                          fping, sizeof(tcm_msg_fabric_ping), cli->fabric->mr,
                          fresp, sizeof(tcm_msg_fabric_ping), cli->fabric->mr,
                          peer_addr, &timing, &err);
    if (ret < 0)
    {
        tcm__log_error("Fabric exchange error: %s", fi_strerror(tcm_abs(ret)));
        goto err_fabric;
    }

    tcm__log_info("ok");
    return 0;

err_fabric:
    if (dest_alloc)
    {
        free(opts->fabric_hints->dest_addr);
        opts->fabric_hints->dest_addrlen = 0;
    }
    free(cli->fabric);
err_socket:
    close(cli->sock);
err:
    free(cli);
    return ret;
}

