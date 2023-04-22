#include "tcm_fabric.h"
#include "tcm_log.h"
#include "tcm_util.h"
#include "tcm_msg.h"
#include "tcm_comm.h"

#include "compat/tcmc_net.h"

int tcm_create_mr(  tcm_fabric * fabric, size_t size, size_t alignment, 
                    struct fid_mr ** mr)
{
    ssize_t ret;
    void * mem = tcm_mem_align(size, alignment);
    if (!mem)
    {
        tcm__log_error("Aligned memory alloc failed: %s", strerror(errno));
        return -errno;
    }

    ret = fi_mr_reg(fabric->domain, mem, size, FI_SEND | FI_RECV, 0, 0, 0, mr, mem);
    if (ret < 0)
    {
        tcm__log_error( "Memory registration failed: %s", 
                        fi_strerror(tcm_abs(ret)));
        tcm_mem_free(mem);
        return ret;
    }

    tcm__log_debug( "Created memory region %p, size %lu, alignment %lu", 
                    mem, size, alignment);
    return 0;

}

int tcm_serialize_addr( void * addr, int addr_len, uint32_t addr_fmt,
                        void * out_buf, int * buf_size)
{
    if (!addr || !addr_len || !out_buf || !buf_size || !*buf_size)
        return -EINVAL;

    switch (addr_fmt)
    {
        case FI_SOCKADDR_IN:
            if (*buf_size < 6)
            {
                *buf_size = 6;
                return -ENOBUFS;
            }
            struct sockaddr_in * sai = (struct sockaddr_in *) addr;
            if (sai->sin_family != AF_INET)
                return -EINVAL;

            tcm_addr_inet * inet = (tcm_addr_inet *) out_buf;
            inet->addr = sai->sin_addr.s_addr;
            inet->port = sai->sin_port;
            *buf_size = sizeof(tcm_addr_inet);
            return TCM_AF_INET;
        default:
            return -EINVAL;
    }
}

int tcm_deserialize_addr(   void * addr, int addr_len, uint32_t addr_fmt,
                            void * out_buf, int * buf_size)
{
    if (!addr || !addr_len || !out_buf || !buf_size || !*buf_size)
        return -EINVAL;

    switch (addr_fmt)
    {
        case TCM_AF_INET:
            if (*buf_size < sizeof(struct sockaddr_in))
            {
                *buf_size = sizeof(struct sockaddr_in);
                return -ENOBUFS;
            }
            struct sockaddr_in * sai = (struct sockaddr_in *) out_buf;
            tcm_addr_inet * inet = (tcm_addr_inet *) addr;
            sai->sin_family = AF_INET;
            sai->sin_addr.s_addr = inet->addr;
            sai->sin_port = inet->port;
            *buf_size = sizeof(struct sockaddr_in);
            return FI_SOCKADDR_IN;
        default:
            return -EINVAL;
    }
}

int tcm_setup_fabric(uint32_t version,
                     uint64_t flags, struct fi_info * hints, 
                     tcm_fabric * fabric_out)
{
    struct fi_info * fi = NULL;
    int ret, defaults = 0;

    if (hints->src_addrlen == 0 && hints->dest_addrlen == 0)
    {
        tcm__log_error("Invalid fabric hints: No valid address found");
        return -EINVAL;
    }

    ret = fi_getinfo(version ? version : TCM_DEFAULT_FABRIC_VERSION,
                     NULL, NULL, flags, hints, &fi);
    if (ret < 0)
    {
        tcm__log_error("Error running fi_getinfo: %s", fi_strerror(tcm_abs(ret)));
        goto err_fabric;
    }

    ret = fi_fabric(fi->fabric_attr, &fabric_out->fabric, NULL);
    if (ret < 0)
    {
        tcm__log_error("Error creating fabric: %s", fi_strerror(tcm_abs(ret)));
        goto err_fabric;
    }

    ret = fi_domain(fabric_out->fabric, fi, &fabric_out->domain, NULL);
    if (ret < 0)
    {
        tcm__log_error("Error creating fabric domain: %s", fi_strerror(tcm_abs(ret)));
        goto err_fabric;
    }

    struct fi_cq_attr cq_attr;
    memset(&cq_attr, 0, sizeof(cq_attr));
    cq_attr.size        = fi->tx_attr->size;
    cq_attr.wait_obj    = FI_WAIT_UNSPEC;
    cq_attr.format      = FI_CQ_FORMAT_TAGGED;
    cq_attr.wait_cond   = FI_CQ_COND_NONE;
    ret = fi_cq_open(fabric_out->domain, &cq_attr, &fabric_out->tx_cq, NULL);
    if (ret < 0)
    {
        tcm__log_error("Error creating TX CQ: %s", fi_strerror(tcm_abs(ret)));
        goto err_fabric;
    }
    cq_attr.size        = fi->rx_attr->size;
    ret = fi_cq_open(fabric_out->domain, &cq_attr, &fabric_out->rx_cq, NULL);
    if (ret < 0)
    {
        tcm__log_error("Error creating RX CQ: %s", fi_strerror(tcm_abs(ret)));
        goto err_fabric;
    }

    struct fi_av_attr av_attr;
    memset(&av_attr, 0, sizeof(av_attr));
    av_attr.type    = FI_AV_UNSPEC;
    av_attr.count   = 1;
    ret = fi_av_open(fabric_out->domain, &av_attr, &fabric_out->av, NULL);
    if (ret < 0)
    {
        tcm__log_error("Error creating AV: %s", fi_strerror(tcm_abs(ret)));
        goto err_fabric;
    }

    ret = fi_endpoint(fabric_out->domain, fi, &fabric_out->ep, NULL);
    if (ret < 0)
    {
        tcm__log_error("Error creating endpoint: %s", fi_strerror(tcm_abs(ret)));
        goto err_fabric;
    }
    ret = fi_ep_bind(fabric_out->ep, &fabric_out->av->fid, 0);
    if (ret < 0)
    {
        tcm__log_error("Error binding AV to endpoint: %s", fi_strerror(tcm_abs(ret)));
        goto err_fabric;
    }
    ret = fi_ep_bind(fabric_out->ep, &fabric_out->rx_cq->fid, FI_RECV);
    if (ret < 0)
    {
        tcm__log_error("Error binding RX CQ to endpoint: %s", fi_strerror(tcm_abs(ret)));
        goto err_fabric;
    }
    ret = fi_ep_bind(fabric_out->ep, &fabric_out->tx_cq->fid, FI_TRANSMIT);
    if (ret < 0)
    {
        tcm__log_error("Error binding TX CQ to endpoint: %s", fi_strerror(tcm_abs(ret)));
        goto err_fabric;
    }

    ret = fi_enable(fabric_out->ep);
    if (ret < 0)
    {
        tcm__log_error("Fabric enable failed: %s", fi_strerror(tcm_abs(ret)));
        goto err_fabric;
    }

    if (strlen(fi->fabric_attr->prov_name) > 15)
    {
        tcm__log_warn("Fabric provider name %s truncated!", fi->fabric_attr->prov_name);
    }
    strncpy(fabric_out->prov_name, fi->fabric_attr->prov_name, 15);
    fabric_out->proto = fi->ep_attr->protocol;
    fabric_out->addr_fmt = fi->addr_format;
    fi_freeinfo(fi);
    return 0;

err_fabric:
    tcm_destroy_fabric(fabric_out, 0);
    if (defaults)
    {
        free(hints);
    }
    if (fi)
    {
        fi_freeinfo(fi);
    }
    return ret;
}

ssize_t tcm_poll_fabric(struct fid_cq * cq,
                        struct fi_cq_data_entry * data, 
                        struct fi_cq_err_entry * err,
                        tcm_time * timeout)
{
    ssize_t ret;
    struct timespec ts;
    ret = tcm_conv_time(timeout, &ts);
    if (ret < 0)
        return ret;

    do
    {
        ret = fi_cq_read(cq, data, 1);
        if (ret == 0 || ret == -FI_EAGAIN)
        {
            tcm_sleep(timeout->interval);
            continue;
        }
        if (ret == -FI_EAVAIL)
        {
            ret = fi_cq_readerr(cq, err, 0);
            if (ret != 1)
                return (ret == 0 ? -1 : ret);
            
            tcm__log_error("CQ %p | Error: %d (%s) | ProvErr: %d",
                            cq, err->err, fi_strerror(err->err),
                            err->prov_errno);
            return -FI_EAVAIL;
        }
        return 0;
    } while (!tcm_check_deadline(&ts));
    return -ETIMEDOUT;
}

ssize_t tcm_tsend_fabric(tcm_fabric * fabric, void * buf, size_t len, 
                         struct fid_mr * mr, fi_addr_t peer, uint64_t tag,
                         void * ctx, tcm_time * timing)
{
    ssize_t ret;
    struct timespec dl;
    ret = tcm_conv_time(timing, &dl);
    if (ret < 0)
        return ret;

    do
    {
        ret = fi_tsend(fabric->ep, buf, len, fi_mr_desc(mr), peer, tag, ctx);
        if (ret == -FI_EAGAIN || ret == -FI_EWOULDBLOCK)
        {
            tcm_sleep(timing->interval);
            continue;
        }
        else if (ret == 0)
        {
            return 0;
        }
        else
        {
            tcm__log_error("Fabric send failed: %s", fi_strerror(-ret));
            return ret;
        }
    } while (!tcm_check_deadline(&dl));
    return -ETIMEDOUT;
}

ssize_t tcm_send_fabric(tcm_fabric * fabric, void * buf, size_t len,
                        struct fid_mr * mr, fi_addr_t peer, void * ctx,
                        tcm_time * timing)
{
    ssize_t ret;
    struct timespec dl;
    ret = tcm_conv_time(timing, &dl);
    if (ret < 0)
        return ret;

    do
    {
        ret = fi_send(fabric->ep, buf, len, fi_mr_desc(mr), peer, ctx);
        if (ret == -FI_EAGAIN || ret == -FI_EWOULDBLOCK)
        {
            tcm_sleep(timing->interval);
            continue;
        }
        else if (ret == 0)
        {
            return 0;
        }
        else
        {
            tcm__log_error("Fabric send failed: %s", fi_strerror(-ret));
            return ret;
        }
    } while (!tcm_check_deadline(&dl));
    return -ETIMEDOUT;
}

ssize_t tcm_trecv_fabric(tcm_fabric * fabric, void * buf, size_t len, 
                         struct fid_mr * mr, fi_addr_t peer, uint64_t tag,
                         uint64_t mask, void * ctx, tcm_time * timing)
{
    ssize_t ret;
    struct timespec dl;
    ret = tcm_conv_time(timing, &dl);
    if (ret < 0)
        return ret;

    do
    {
        ret = fi_trecv(fabric->ep, buf, len, fi_mr_desc(mr), peer, tag, mask, ctx);
        if (ret == -FI_EAGAIN || ret == -FI_EWOULDBLOCK)
        {
            tcm_sleep(timing->interval);
            continue;
        }
        else if (ret == 0)
        {
            return 0;
        }
        else
        {
            tcm__log_error("Fabric send failed: %s", fi_strerror(-ret));
            return ret;
        }
    } while (!tcm_check_deadline(&dl));
    return -ETIMEDOUT;
}

ssize_t tcm_recv_fabric(tcm_fabric * fabric, void * buf, size_t len,
                        struct fid_mr * mr, fi_addr_t peer, void * ctx,
                        tcm_time * timing)
{
    ssize_t ret;
    struct timespec dl;
    ret = tcm_conv_time(timing, &dl);
    if (ret < 0)
        return ret;

    do
    {
        ret = fi_recv(fabric->ep, buf, len, fi_mr_desc(mr), peer, ctx);
        if (ret == -FI_EAGAIN || ret == -FI_EWOULDBLOCK)
        {
            tcm_sleep(timing->interval);
            continue;
        }
        else if (ret == 0)
        {
            return 0;
        }
        else
        {
            tcm__log_error("Fabric receive failed: %s", fi_strerror(-ret));
            return ret;
        }
    } while (!tcm_check_deadline(&dl));
    return -ETIMEDOUT;
}

ssize_t tcm_write_fabric(tcm_fabric * fabric, void * buf, size_t len,
                         struct fid_mr * mr, fi_addr_t peer, 
                         uint64_t rbuf, uint64_t rkey, void * ctx, 
                         tcm_time * timing)
{
    ssize_t ret;
    struct timespec dl;
    ret = tcm_conv_time(timing, &dl);
    if (ret < 0)
        return ret;

    do
    {
        ret = fi_write(fabric->ep, buf, len, fi_mr_desc(mr), peer, rbuf, rkey,
                       ctx);
        if (ret == -FI_EAGAIN || ret == -FI_EWOULDBLOCK)
        {
            tcm_sleep(timing->interval);
            continue;
        }
        else if (ret == 0)
        {
            return 0;
        }
        else
        {
            tcm__log_error("Fabric receive failed: %s", fi_strerror(-ret));
            return ret;
        }
    } while (!tcm_check_deadline(&dl));
    return -ETIMEDOUT;
}

ssize_t tcm_read_fabric(tcm_fabric * fabric, void * buf, size_t len,
                        struct fid_mr * mr, fi_addr_t peer, 
                        uint64_t rbuf, uint64_t rkey, void * ctx, 
                        tcm_time * timing)
{
    ssize_t ret;
    struct timespec dl;
    ret = tcm_conv_time(timing, &dl);
    if (ret < 0)
        return ret;

    do
    {
        ret = fi_read(fabric->ep, buf, len, fi_mr_desc(mr), peer, rbuf, rkey,
                      ctx);
        if (ret == -FI_EAGAIN || ret == -FI_EWOULDBLOCK)
        {
            tcm_sleep(timing->interval);
            continue;
        }
        else if (ret == 0)
        {
            return 0;
        }
        else
        {
            tcm__log_error("Fabric receive failed: %s", fi_strerror(-ret));
            return ret;
        }
    } while (!tcm_check_deadline(&dl));
    return -ETIMEDOUT;
}

ssize_t tcm_exch_fabric(tcm_fabric * fabric,
                        void * send_buf, uint64_t send_buf_size, 
                        struct fid_mr * send_mr,
                        void * recv_buf, uint64_t recv_buf_size,
                        struct fid_mr * recv_mr,
                        fi_addr_t peer, tcm_time * timing,
                        struct fi_cq_err_entry * err)
{
    ssize_t ret;
    tcm_time timer;
    timer.interval  = timing->interval;
    timer.delta     = 0;
    ret = tcm_conv_time(timing, &timer.ts);
    if (ret < 0)
        return ret;

    ret = tcm_send_fabric(fabric, send_buf, send_buf_size, send_mr, peer, NULL, 
                          &timer);
    if (ret < 0)
        return ret;

    ret = tcm_wait_fabric(fabric->tx_cq, &timer, err);
    if (ret < 0)
        return ret;

    ret = tcm_recv_fabric(fabric, recv_buf, recv_buf_size, recv_mr, peer, NULL, 
                          &timer);
    if (ret < 0)
        return ret;

    ret = tcm_wait_fabric(fabric->rx_cq, &timer, err);
    return ret;
}

ssize_t tcm_exch_fabric_rev(tcm_fabric * fabric,
                            void * send_buf, uint64_t send_buf_size, 
                            struct fid_mr * send_mr,
                            void * recv_buf, uint64_t recv_buf_size,
                            struct fid_mr * recv_mr,
                            fi_addr_t peer, tcm_time * timing,
                            struct fi_cq_err_entry * err)
{
    ssize_t ret;
    tcm_time timer;
    timer.interval  = timing->interval;
    timer.delta     = 0;
    ret = tcm_conv_time(timing, &timer.ts);
    if (ret < 0)
        return ret;

    ret = tcm_recv_fabric(fabric, recv_buf, recv_buf_size, recv_mr, peer, NULL, 
                          &timer);
    if (ret < 0)
        return ret;

    ret = tcm_wait_fabric(fabric->rx_cq, &timer, err);
    if (ret < 0)
        return ret;

    ret = tcm_send_fabric(fabric, send_buf, send_buf_size, send_mr, peer, NULL, 
                          &timer);
    if (ret < 0)
        return ret;

    ret = tcm_wait_fabric(fabric->tx_cq, &timer, err);
    return ret;
}

ssize_t tcm_wait_fabric(struct fid_cq * cq, tcm_time * timing,
                        struct fi_cq_err_entry * err)
{
    ssize_t ret;
    struct timespec dl;
    ret = tcm_conv_time(timing, &dl);
    if (ret < 0)
    {
        return ret;
    }

    do
    {
        ret = fi_cq_read(cq, err, 1);
        if (ret == 0 || ret == -FI_EAGAIN || ret == -FI_EWOULDBLOCK)
        {
            tcm_sleep(timing->interval);
            continue;
        }
        else if (ret == 1)
        {
            return 1;
        }
        else if (ret == -FI_EAVAIL)
        {
            tcm__log_error("Error reading CQ");
            ret = fi_cq_readerr(cq, err, 0);
            if (ret < 0)
            {
                tcm__log_error("Could not determine error details");
                return ret;
            }
            return -err->err;
        }
        else
        {
            tcm__log_error("Error reading CQ: %s", fi_strerror(tcm_abs(ret)));
            return ret;
        }
    } while (!tcm_check_deadline(&dl));
    return -ETIMEDOUT;
}

/* Send one byte of meaningless data to keep the connection state active */
ssize_t tcm_send_dummy_message(tcm_fabric * fabric, fi_addr_t peer, 
                               tcm_time * timing)
{
    ssize_t ret;
    /* Make sure we don't leak some old data there */
    ((uint8_t *) fabric->mr_info.ptr)[0] = 0;
    ret = tcm_tsend_fabric(fabric, fabric->mr_info.ptr, 1, fabric->mr, peer, 
                           0, NULL, timing);
    if (ret < 0)
        return ret;
    
    struct fi_cq_err_entry err;
    ret = tcm_wait_fabric(fabric->tx_cq, timing, &err);
    return ret;
}