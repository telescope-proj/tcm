#include "tcmu.h"
#include "tcm_msg.h"
#include "tcm_log.h"
#include "tcm_util.h"

int tcmu_create_endpoint(struct sockaddr * bind_addr, const char * prov_name, 
                         uint32_t version, tcm_fabric * out, size_t mbuf_size)
{
    int ret;
    struct fi_info * hints = fi_allocinfo();

    hints->fabric_attr->prov_name = strdup(prov_name);
    hints->src_addr = bind_addr;
    hints->src_addrlen = tcm__get_sa_size(bind_addr);
    hints->addr_format = FI_SOCKADDR_IN;
    
    hints->ep_attr->type        = FI_EP_RDM;
    hints->caps                 = FI_MSG | FI_RMA | FI_TAGGED;
    hints->mode                 = FI_RX_CQ_DATA | FI_LOCAL_MR;
    hints->domain_attr->mr_mode = FI_MR_BASIC;

    hints->tx_attr->caps          = FI_TAGGED;
    hints->tx_attr->size          = 128;
    hints->tx_attr->iov_limit     = 1;
    hints->tx_attr->rma_iov_limit = 1;
    hints->tx_attr->inject_size   = 0;

    hints->rx_attr->caps = FI_TAGGED;
    hints->rx_attr->size = 128;
    hints->rx_attr->iov_limit = 1;

    hints->ep_attr->max_msg_size = 512;
    hints->domain_attr->cq_cnt = 2;

    if (!hints->src_addrlen)
    {
        ret = -EINVAL;
        goto cleanup;
    }

    ret = tcm_setup_fabric(version, 0, hints, out);
    if (ret < 0)
        goto cleanup;

    if (mbuf_size)
    {
        ret = tcm_create_mr(out, mbuf_size, tcm_get_page_size(), &out->mr);
        if (ret < 0)
        {
            tcm_destroy_fabric(out, 0);
            tcm__log_error("MR creation failed: %s", fi_strerror(-ret));
            return ret;
        }
        out->mr_info.ptr        = out->mr->fid.context;
        out->mr_info.alignment  = tcm_get_page_size();
        out->mr_info.len        = mbuf_size;
    }

cleanup:
    hints->src_addr = NULL;
    hints->src_addrlen = 0;
    fi_freeinfo(hints);
    return ret;
}

int tcmu_add_peer(tcm_fabric * fabric, struct sockaddr * peer, fi_addr_t * out)
{
    int ret, sas;
    sas = tcm__get_sa_size(peer);
    if (!sas)
        return -EINVAL;

    char addr[INET6_ADDRSTRLEN];
    tcm__log_debug("Adding peer to AV: %s:%d", 
        inet_ntop(peer->sa_family,
                  &((struct sockaddr_in *) peer)->sin_addr, addr, sas),
        ntohs(((struct sockaddr_in *) peer)->sin_port)
    );

    int retv = 0;
    ret = fi_av_insert(fabric->av, peer, 1, out, FI_SYNC_ERR, &retv);
    if (ret != 1)
        return (retv == 0 ? (ret == 0 ? -FI_EOTHER : ret) : tcm_negabs(retv));

    return 0;
}

int tcmu_remove_peer(tcm_fabric * fabric, fi_addr_t peer)
{
    struct sockaddr_storage sa;
    memset(&sa, 0, sizeof(sa));
    fi_addr_t tmp_addr = peer;
    size_t tmp_addrlen = sizeof(sa);
    int ret;
    
    /* Verify this peer actually exists */
    ret = fi_av_lookup(fabric->av, peer, &sa, &tmp_addrlen);
    if (ret < 0)
        return ret;

    char addr[INET6_ADDRSTRLEN];
    tcm__log_debug("Removing peer (fid: %lu) from AV: %s:%d", 
        peer,
        inet_ntop(sa.ss_family, 
                  &((struct sockaddr_in *) &sa)->sin_family, addr, tmp_addrlen),
        ntohs(((struct sockaddr_in *) &sa)->sin_port)
    );

    ret = fi_av_remove(fabric->av, &tmp_addr, 1, FI_SYNC_ERR);
    return ret;
}

/*  Call tcmu_add_peer before running! Not to be used on already connected peers! */
ssize_t tcmu_accept(tcm_fabric * fabric, fi_addr_t peer, tcm_time * timeout)
{
    ssize_t ret;
    tcm_msg_fabric_ping * ping = fabric->mr_info.ptr;
    ret = tcm_recv_fabric(fabric, fabric->mr_info.ptr, sizeof(*ping), 
                          fabric->mr, peer, NULL, timeout);
    if (ret < 0)
    {
        tcm__log_error("Recv failed: %s", fi_strerror(-ret));
        return ret;
    }

    struct fi_cq_data_entry de;
    struct fi_cq_err_entry err;
    ret = tcm_poll_fabric(fabric->rx_cq, &de, &err, timeout);
    if (ret == -FI_EAVAIL)
        return (err.err == 0 ? -FI_EOTHER : -err.err);

    if (ping->common.magic != TCM_MAGIC
        || ping->common.id != TCM_MSG_FABRIC_PING
        || ping->direction != 0)
    {
        tcm__log_error("Client sent invalid/corrupt message");
        return -EBADMSG;
    }

    uint16_t token = ping->common.token;
    uint32_t fver = FI_VERSION(ping->fabric_major, ping->fabric_minor);
    if (fver != fabric->fabric->api_version)
    {
        tcm__log_error( "Accept error, version mismatch. "
                        "Server: %d.%d, Client: %d.%d", 
                        FI_MAJOR(fabric->fabric->api_version),
                        FI_MINOR(fabric->fabric->api_version),
                        ping->fabric_major, ping->fabric_minor);
        return -ENOTSUP;
    }

    memset(fabric->mr_info.ptr, 0, sizeof(*ping));
    ping->common.id = TCM_MSG_FABRIC_PING;
    tcm_msg_init(ping, token);
    ping->direction = 1;
    ping->fabric_major = FI_MAJOR(fabric->fabric->api_version);
    ping->fabric_minor = FI_MINOR(fabric->fabric->api_version);

    ret = tcm_send_fabric(fabric, fabric->mr_info.ptr, sizeof(*ping),
                          fabric->mr, peer, NULL, timeout);
    if (ret < 0)
    {
        tcm__log_error("Send failed: %s", fi_strerror(-ret));
        return ret;
    }

    ret = tcm_poll_fabric(fabric->tx_cq, &de, &err, timeout);
    if (ret == -FI_EAVAIL)
        return (err.err == 0 ? -FI_EOTHER : -err.err);

    return ret;
}

ssize_t tcmu_connect(tcm_fabric * fabric, fi_addr_t peer, tcm_time * timeout)
{
    tcm_msg_fabric_ping * ping = fabric->mr_info.ptr;
    tcm_msg_fabric_ping * resp = (ping + 1);
    ping->common.id = TCM_MSG_FABRIC_PING;
    tcm_msg_init(ping, 0xFABC);
    ping->direction = 0;
    ping->fabric_major = FI_MAJOR(fabric->fabric->api_version);
    ping->fabric_minor = FI_MINOR(fabric->fabric->api_version);
    
    ssize_t ret;
    ret = tcm_send_fabric(fabric, fabric->mr_info.ptr, sizeof(*ping),
                          fabric->mr, peer, NULL, timeout);
    if (ret < 0)
    {
        tcm__log_error("Send failed: %s", fi_strerror(-ret));
        return ret;
    }

    ret = tcm_recv_fabric(fabric, resp, sizeof(*ping),
                          fabric->mr, peer, NULL, timeout);
    if (ret < 0)
    {
        tcm__log_error("Recv failed: %s", fi_strerror(-ret));
        return ret;
    }

    struct fi_cq_data_entry de;
    struct fi_cq_err_entry err;
    memset(&err, 0, sizeof(err));
    ret = tcm_poll_fabric(fabric->tx_cq, &de, &err, timeout);
    if (ret == -FI_EAVAIL)
        return (err.err == 0 ? -FI_EOTHER : -err.err);

    ret = tcm_poll_fabric(fabric->rx_cq, &de, &err, timeout);
    if (ret == -FI_EAVAIL)
        return (err.err == 0 ? -FI_EOTHER : -err.err);

    if (resp->common.magic != TCM_MAGIC
        || resp->common.id != TCM_MSG_FABRIC_PING
        || resp->direction != 1)
    {
        tcm__log_error("Server sent invalid/corrupt message"); 
        tcm__log_error("ID: %d, Magic: %d, Direction: %d", resp->common.id, resp->common.magic, resp->direction);
        return -EBADMSG;
    }

    if (resp->fabric_major != FI_MAJOR(fabric->fabric->api_version)
        || resp->fabric_minor != FI_MINOR(fabric->fabric->api_version))
    {
        tcm__log_error( "Accept error, version mismatch. "
                        "Client: %d.%d, Server: %d.%d", 
                        FI_MAJOR(fabric->fabric->api_version),
                        FI_MINOR(fabric->fabric->api_version),
                        resp->fabric_major, resp->fabric_minor);
        return -ENOTSUP;
    }

    return 0;
}