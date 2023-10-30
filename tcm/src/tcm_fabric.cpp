// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#include "tcm_fabric.h"
#include "tcm_comm.h"
#include "tcm_errno.h"
#include "tcm_log.h"
#include "tcm_util.h"

#include "compat/tcmc_net.h"

/* --- Fabric Management --- */

void tcm_fabric::clear_fields() {
    this->ep             = 0;
    this->fi             = 0;
    this->hints          = 0;
    this->top            = 0;
    this->tx_cq          = 0;
    this->rx_cq          = 0;
    this->av             = 0;
    this->proto          = 0;
    this->addr_fmt       = 0;
    this->transport_id   = 0;
    this->fabric_version = 0;
    memset(this->prov_name, 0, sizeof(this->prov_name));
}

int tcm_fabric::init_fabric_domain(uint32_t version, uint64_t flags,
                                   struct fi_info * hints) {
    struct fi_info * fi     = NULL;
    struct fi_info * tmp_fi = NULL;
    int              ret;

    this->fabric_flags   = flags;
    this->fabric_version = version;
    if (hints->src_addrlen == 0 && hints->dest_addrlen == 0) {
        tcm__log_error("Invalid fabric hints: No valid address found");
        throw EINVAL;
    }

    if (hints->addr_format != FI_SOCKADDR_IN) {
        tcm__log_error("Invalid address type %d", hints->addr_format);
        throw EINVAL;
    }

    /* Add the features required by the fabric abstraction, overwriting if
       the user provided something different */

    hints->ep_attr->type = FI_EP_RDM;
    hints->domain_attr->mr_mode =
        FI_MR_VIRT_ADDR | FI_MR_ALLOCATED | FI_MR_PROV_KEY | FI_MR_LOCAL;
    hints->mode |= FI_RX_CQ_DATA | FI_LOCAL_MR;
    hints->caps |= FI_MSG | FI_RMA | FI_TAGGED;
    hints->tx_attr->caps |= FI_MSG | FI_RMA | FI_TAGGED;
    hints->rx_attr->caps |= FI_MSG | FI_RMA | FI_TAGGED;

    ret = fi_getinfo(version ? version : TCM_DEFAULT_FABRIC_VERSION, NULL, NULL,
                     flags, hints, &fi);
    if (ret < 0) {
        tcm__log_error("Error running fi_getinfo: %s",
                       fi_strerror(tcm_abs(ret)));
        goto err_fabric;
    }

    for (tmp_fi = fi; tmp_fi; tmp_fi = tmp_fi->next) {
        struct fid_fabric * fabric = 0;
        struct fid_domain * domain = 0;
        tcm__log_debug("Attempting to use fabric provider: %s",
                       tmp_fi->fabric_attr->prov_name);
        ret = fi_fabric(tmp_fi->fabric_attr, &fabric, NULL);
        if (ret < 0) {
            tcm__log_warn("Error creating fabric: %s",
                          fi_strerror(tcm_abs(ret)));
            continue;
        }

        ret = fi_domain(fabric, tmp_fi, &domain, NULL);
        if (ret < 0) {
            tcm__log_warn("Error creating fabric domain: %s",
                          fi_strerror(tcm_abs(ret)));
            fi_close(&fabric->fid);
            continue;
        }

        tcm__log_debug("Fabric provider functional");
        this->top = std::make_shared<tcm_internal::shared_fi>(fabric, domain);
        break;
    }

    if (!tmp_fi) {
        tcm__log_error("No functional fabric providers found!");
        goto err_fabric;
    }

    this->fi = fi_dupinfo(tmp_fi);
    fi_freeinfo(fi);
    return 0;

err_fabric:
    this->~tcm_fabric();
    if (fi) {
        fi_freeinfo(fi);
    }
    return ret;
}

int tcm_fabric::init(std::shared_ptr<tcm_internal::shared_fi> shrd,
                     struct sockaddr_in * addr, tcm_time * timeout) {

    struct sockaddr_in * sa = NULL;
    int                  ret;

    if (shrd)
        this->top = shrd;

    if (!this->top) {
        tcm__log_error("Top-level fabric objects not initialized");
        return -EINVAL;
    }

    if (timeout) {
        this->timeout = *timeout;
    } else {
        this->timeout.interval   = 500;
        this->timeout.timeout    = 3000;
        this->timeout.mode       = TCM_TIME_MODE_RELATIVE;
        this->timeout.ts.tv_sec  = 0;
        this->timeout.ts.tv_nsec = 0;
    }

    tcm__log_debug("CQ size: RX %d, TX %d", this->fi->rx_attr->size,
                   this->fi->tx_attr->size);
    struct fi_cq_attr cq_attr;
    memset(&cq_attr, 0, sizeof(cq_attr));
    cq_attr.size      = this->fi->tx_attr->size;
    cq_attr.wait_obj  = FI_WAIT_FD;
    cq_attr.format    = FI_CQ_FORMAT_TAGGED;
    cq_attr.wait_cond = FI_CQ_COND_NONE;
    ret = fi_cq_open(this->top.get()->domain, &cq_attr, &this->tx_cq, NULL);
    if (ret < 0) {
        tcm__log_error("Error creating TX CQ: %s", fi_strerror(tcm_abs(ret)));
        goto err_fabric;
    }
    cq_attr.size = this->fi->rx_attr->size;
    ret = fi_cq_open(this->top.get()->domain, &cq_attr, &this->rx_cq, NULL);
    if (ret < 0) {
        tcm__log_error("Error creating RX CQ: %s", fi_strerror(tcm_abs(ret)));
        goto err_fabric;
    }

    struct fi_av_attr av_attr;
    memset(&av_attr, 0, sizeof(av_attr));
    av_attr.type  = FI_AV_UNSPEC;
    av_attr.count = 1;
    ret = fi_av_open(this->top.get()->domain, &av_attr, &this->av, NULL);
    if (ret < 0) {
        tcm__log_error("Error creating AV: %s", fi_strerror(tcm_abs(ret)));
        goto err_fabric;
    }

    ret = fi_endpoint(this->top.get()->domain, this->fi, &this->ep, NULL);
    if (ret < 0) {
        tcm__log_error("Error creating endpoint: %s",
                       fi_strerror(tcm_abs(ret)));
        goto err_fabric;
    }
    ret = fi_ep_bind(this->ep, &this->av->fid, 0);
    if (ret < 0) {
        tcm__log_error("Error binding AV to endpoint: %s",
                       fi_strerror(tcm_abs(ret)));
        goto err_fabric;
    }
    ret = fi_ep_bind(this->ep, &this->rx_cq->fid, FI_RECV);
    if (ret < 0) {
        tcm__log_error("Error binding RX CQ to endpoint: %s",
                       fi_strerror(tcm_abs(ret)));
        goto err_fabric;
    }
    ret = fi_ep_bind(this->ep, &this->tx_cq->fid, FI_TRANSMIT);
    if (ret < 0) {
        tcm__log_error("Error binding TX CQ to endpoint: %s",
                       fi_strerror(tcm_abs(ret)));
        goto err_fabric;
    }

    if (addr) {
        ret = fi_setname(&this->ep->fid, addr, sizeof(*addr));
        if (ret < 0) {
            tcm__log_error("Failed to set local address: %s",
                           fi_strerror(tcm_abs(ret)));
            goto err_fabric;
        }
    }

    ret = fi_enable(this->ep);
    if (ret < 0) {
        tcm__log_error("Fabric enable failed: %s", fi_strerror(tcm_abs(ret)));
        goto err_fabric;
    }

    /* Get address (for dynamic endpoints) */

    this->src_addrlen = 0;
    ret               = fi_getname(&this->ep->fid, NULL, &this->src_addrlen);
    if (ret != -FI_ETOOSMALL) {
        tcm__log_error("Failed to get endpoint name: %s",
                       fi_strerror(tcm_abs(ret)));
        goto err_fabric;
    }

    this->src_addr = malloc(this->src_addrlen);
    if (!this->src_addr) {
        tcm__log_error("Memory allocation failed");
        goto err_fabric;
    }

    ret = fi_getname(&this->ep->fid, this->src_addr, &this->src_addrlen);
    if (ret < 0) {
        tcm__log_error("Failed to get endpoint name: %s",
                       fi_strerror(tcm_abs(ret)));
        goto err_fabric;
    }

    char tmp_addr[INET_ADDRSTRLEN];
    sa = (struct sockaddr_in *) this->src_addr;
    tcm__log_debug("Endpoint address (%d): %s:%d", this->src_addrlen,
                   inet_ntop(sa->sin_family,
                             &((struct sockaddr_in *) sa)->sin_addr, tmp_addr,
                             INET_ADDRSTRLEN),
                   ntohs(((struct sockaddr_in *) sa)->sin_port));

    if (this->fi->addr_format == FI_SOCKADDR_IN) {
        sa = (struct sockaddr_in *) this->src_addr;
        if (sa->sin_family != AF_INET || sa->sin_port == 0) {
            tcm__log_error("Invalid address family (%d) or port (%d)",
                           sa->sin_family, sa->sin_port);
            goto err_fabric;
        }
    }

    tcm__log_debug("Endpoint created and resources bound");

    if (strlen(this->fi->fabric_attr->prov_name) >
        sizeof(this->prov_name) - 1) {
        tcm__log_warn("Fabric provider name %s truncated!",
                      this->fi->fabric_attr->prov_name);
    }
    strncpy(this->prov_name, this->fi->fabric_attr->prov_name,
            sizeof(this->prov_name) - 1);
    this->proto        = this->fi->ep_attr->protocol;
    this->addr_fmt     = this->fi->addr_format;
    this->transport_id = prov_name_to_id(this->fi->fabric_attr->prov_name);
    return 0;

err_fabric:
    this->~tcm_fabric();
    return ret;
}

tcm_fabric::tcm_fabric(tcm_fabric_init_opts & opts) {
    this->clear_fields();
    int ret = this->init_fabric_domain(opts.version, opts.flags, opts.hints);
    if (ret < 0)
        throw -ret;
    ret = this->init(0, 0, opts.timeout);
    if (ret < 0)
        throw -ret;
}

tcm_fabric::tcm_fabric(tcm_fabric_child_opts & opts, tcm_fabric * parent) {
    this->clear_fields();
    if (!parent)
        throw EINVAL;

    assert(opts.fi);
    this->top              = opts.fi;
    this->fi               = fi_dupinfo(parent->fi);
    struct sockaddr_in sai = *(struct sockaddr_in *) parent->src_addr;
    sai.sin_port           = opts.port;
    this->fi->src_addrlen  = 0;
    int ret                = this->init(opts.fi, &sai, opts.timeout);
    if (ret < 0) {
        fi_freeinfo(this->fi);
        throw -ret;
    }
}

tcm_fabric::~tcm_fabric() {
    tcm__log_debug("Cleaning up fabric resources");
    int ret;
    if (this->fi) {
        fi_freeinfo(this->fi);
        this->fi = 0;
    }
    if (this->hints) {
        fi_freeinfo(this->hints);
        this->hints = 0;
    }
    if (this->src_addr) {
        tcm__log_trace("Freeing source address data");
        tcm_free_unset(this->src_addr);
        this->src_addrlen = 0;
    }
    if (this->ep) {
        tcm__log_trace("Cleaning up endpoint");
        ret = fi_close((fid_t) this->ep);
        if (ret < 0)
            tcm__log_warn("Endpoint deallocation failed: %s",
                          fi_strerror(-ret));
        this->ep = NULL;
    }
    if (this->av) {
        tcm__log_trace("Cleaning up address vector");
        ret = fi_close((fid_t) this->av);
        if (ret < 0)
            tcm__log_warn("AV deallocation failed: %s", fi_strerror(-ret));
        this->av = NULL;
    }
    if (this->rx_cq) {
        tcm__log_trace("Cleaning up receive CQ");
        ret = fi_close((fid_t) this->rx_cq);
        if (ret < 0)
            tcm__log_warn("Receive CQ deallocation failed: %s",
                          fi_strerror(-ret));
        this->rx_cq = NULL;
    }
    if (this->tx_cq) {
        tcm__log_trace("Cleaning up transmit CQ");
        ret = fi_close((fid_t) this->tx_cq);
        if (ret < 0)
            tcm__log_warn("Send CQ deallocation failed: %s", fi_strerror(-ret));
        this->tx_cq = NULL;
    }
    tcm__log_trace("Releasing fabric/domain objects");
    this->top = 0;
    tcm__log_trace("Fabric resources cleaned up");
}

void tcm_fabric::set_timeout(tcm_time & timeout) { this->timeout = timeout; }

int tcm_fabric::get_name(void * buf, size_t * buf_size) {
    int ret;
    ret = fi_getname(&this->ep->fid, buf, buf_size);
    if (ret != 0) {
        tcm__log_debug("fi_getname failed: %s", fi_strerror(tcm_abs(ret)));
        return ret;
    }

    if (this->src_addrlen < *buf_size) {
        void * p = realloc(this->src_addr, *buf_size);
        if (!p) {
            tcm__log_debug("Memory allocation failed");
            return -ENOMEM;
        }
        this->src_addr = p;
    }

    this->src_addrlen = *buf_size;
    memcpy((void *) this->src_addr, buf, *buf_size);

    tcm__log_debug("Read fabric endpoint address buf=%p, size=%lu", buf,
                   *buf_size);
    return 0;
}

int tcm_fabric::set_name(void * buf, size_t buf_size) {
    tcm__log_debug("Modifying fabric endpoint address buf=%p, size=%lu", buf,
                   buf_size);
    int ret = fi_setname(&this->ep->fid, buf, buf_size);
    if (ret < 0)
        return ret;

    if (this->src_addrlen < buf_size) {
        void * p = realloc(this->src_addr, buf_size);
        if (!p) {
            tcm__log_debug("Memory allocation failed");
            return -ENOMEM;
        }
        this->src_addr = p;
    }

    this->src_addrlen = buf_size;
    memcpy((void *) this->src_addr, buf, buf_size);

    return 0;
}

void * tcm_fabric::_get_fi_resource(tcm_fabric_resource res) {
    switch (res) {
        case TCM_RESRC_FABRIC:
            return (void *) this->top.get()->fabric;
        case TCM_RESRC_DOMAIN:
            return (void *) this->top.get()->domain;
        case TCM_RESRC_RX_CQ:
            return (void *) this->rx_cq;
        case TCM_RESRC_TX_CQ:
            return (void *) this->tx_cq;
        case TCM_RESRC_PARAM:
            return (void *) this->fi;
        default:
            errno = EINVAL;
            return 0;
    }
}

tcm_tid tcm_fabric::_get_tid() { return this->transport_id; }

int tcm_serialize_addr(void * addr, int addr_len, uint32_t addr_fmt,
                       void * out_buf, int * buf_size) {
    if (!addr || !addr_len || !out_buf || !buf_size || !*buf_size)
        return -EINVAL;

    switch (addr_fmt) {
        default:
            return -EINVAL;
        case FI_SOCKADDR_IN:
            if (*buf_size < 6) {
                *buf_size = 6;
                return -ENOBUFS;
            }
            struct sockaddr_in * sai = (struct sockaddr_in *) addr;
            if (sai->sin_family != AF_INET)
                return -EINVAL;

            tcm_addr_inet * inet = (tcm_addr_inet *) out_buf;
            inet->addr           = sai->sin_addr.s_addr;
            inet->port           = sai->sin_port;
            *buf_size            = sizeof(tcm_addr_inet);
            return TCM_AF_INET;
    }
}

int tcm_deserialize_addr(void * addr, int addr_len, uint32_t addr_fmt,
                         void * out_buf, int * buf_size) {
    if (!addr || !addr_len || !out_buf || !buf_size || !*buf_size)
        return -EINVAL;

    switch (addr_fmt) {
        default:
            return -EINVAL;
        case TCM_AF_INET:
            if (*buf_size < (int) sizeof(struct sockaddr_in)) {
                *buf_size = (int) sizeof(struct sockaddr_in);
                return -ENOBUFS;
            }
            struct sockaddr_in * sai  = (struct sockaddr_in *) out_buf;
            tcm_addr_inet *      inet = (tcm_addr_inet *) addr;
            sai->sin_family           = AF_INET;
            sai->sin_addr.s_addr      = inet->addr;
            sai->sin_port             = inet->port;
            *buf_size                 = sizeof(struct sockaddr_in);
            return FI_SOCKADDR_IN;
    }
}
