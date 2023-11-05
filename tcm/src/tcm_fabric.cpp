// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#include "tcm_fabric.h"
#include "tcm_comm.h"
#include "tcm_errno.h"
#include "tcm_log.h"
#include "tcm_util.h"

#include "compat/tcmc_net.h"

using std::shared_ptr;

/* --- Fabric Management --- */

void tcm_fabric::bind_exit_flag(volatile int * flag) { this->exit_flag = flag; }

void tcm_fabric::clear_fields() {
    this->fi             = 0;
    this->hints          = 0;
    this->top            = 0;
    this->cq             = 0;
    this->av             = 0;
    this->proto          = 0;
    this->addr_fmt       = 0;
    this->transport_id   = 0;
    this->fabric_version = 0;
    this->src_addr       = 0;
    this->src_addrlen    = 0;
    this->exit_flag      = 0;
    memset(this->prov_name, 0, sizeof(this->prov_name));
}

int tcm_fabric::init_fabric_domain(uint32_t version, uint64_t flags,
                                   fi_info * hints, bool no_getinfo) {
    fi_info * fi     = NULL;
    fi_info * tmp_fi = NULL;
    int       ret;

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

    if (no_getinfo) {
        fi = hints;
    } else {
        ret = fi_getinfo(version ? version : TCM_DEFAULT_FABRIC_VERSION, NULL,
                         NULL, flags, hints, &fi);
        if (ret < 0) {
            tcm__log_error("Error running fi_getinfo: %s",
                           fi_strerror(tcm_abs(ret)));
            goto err_fabric;
        }
    }

    this->top = 0;
    for (tmp_fi = fi; tmp_fi; tmp_fi = tmp_fi->next) {
        fid_fabric * fabric = 0;
        fid_domain * domain = 0;
        tcm__log_debug("Attempting to use fabric provider: %s",
                       tmp_fi->fabric_attr->prov_name);
        ret = fi_fabric(tmp_fi->fabric_attr, &fabric, NULL);
        if (ret < 0) {
            tcm__log_warn("Error creating fabric: %s",
                          fi_strerror(tcm_abs(ret)));
            if (no_getinfo)
                break;
            continue;
        }

        ret = fi_domain(fabric, tmp_fi, &domain, NULL);
        if (ret < 0) {
            tcm__log_warn("Error creating fabric domain: %s",
                          fi_strerror(tcm_abs(ret)));
            fi_close(&fabric->fid);
            if (no_getinfo)
                break;
            continue;
        }

        tcm__log_debug("Fabric provider functional");
        this->top = std::make_shared<tcm_internal::shared_fi>(fabric, domain);
        break;
    }

    if (!this->top) {
        tcm__log_error("No functional fabric providers found!");
        goto err_fabric;
    }

    this->fi                = fi_dupinfo(tmp_fi);
    this->fi->ep_attr->type = FI_EP_RDM;
    if (fi && !no_getinfo) {
        fi_freeinfo(fi);
    }
    return 0;

err_fabric:
    this->~tcm_fabric();
    if (fi && !no_getinfo) {
        fi_freeinfo(fi);
    }
    return ret;
}

int tcm_fabric::init(shared_ptr<tcm_internal::shared_fi> shrd,
                     tcm_time *                               timeout) {
    int ret;

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

    /* Try to create the CQ with different wait objects */
    tcm__log_debug("CQ size: %lu entries", this->fi->tx_attr->size);
    fi_wait_obj modes[] = {FI_WAIT_FD, FI_WAIT_UNSPEC, FI_WAIT_NONE};
    fi_cq_attr  cq_attr;
    memset(&cq_attr, 0, sizeof(cq_attr));
    cq_attr.size      = this->fi->tx_attr->size;
    cq_attr.format    = FI_CQ_FORMAT_TAGGED;
    cq_attr.wait_cond = FI_CQ_COND_NONE;
    bool flag         = 0;
    for (unsigned int i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
        tcm__log_trace("Trying CQ wait mode %d", modes[i]);
        cq_attr.wait_obj = modes[i];
        ret = fi_cq_open(this->top->domain, &cq_attr, &this->cq, NULL);
        if (ret < 0) {
            tcm__log_trace("Error creating TX CQ: %s",
                           fi_strerror(tcm_abs(ret)));
            continue;
        }
        flag = 1;
        break;
    }

    if (!flag) {
        tcm__log_error("All CQ creation attempts failed");
        goto err_fabric;
    }

    this->wait_type = cq_attr.wait_obj;
    tcm__log_debug("CQ created with wait mode %d", this->wait_type);

    fi_av_attr av_attr;
    memset(&av_attr, 0, sizeof(av_attr));
    av_attr.type  = FI_AV_UNSPEC;
    av_attr.count = 4;
    ret           = fi_av_open(this->top->domain, &av_attr, &this->av, NULL);
    if (ret < 0) {
        tcm__log_error("Error creating AV: %s", fi_strerror(tcm_abs(ret)));
        goto err_fabric;
    }

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

    tcm__log_debug("Resources created");
    return 0;

err_fabric:
    this->~tcm_fabric();
    return ret;
}

tcm_fabric::tcm_fabric(tcm_fabric_init_opts & opts) {
    this->clear_fields();
    int ret = this->init_fabric_domain(opts.version, opts.flags, opts.hints,
                                       opts.no_getinfo);
    if (ret < 0)
        throw -ret;
    ret = this->init(0, opts.timeout);
    if (ret < 0)
        throw -ret;
}

tcm_fabric::~tcm_fabric() {
    tcm__log_debug("Cleaning up fabric resources");
    int  ret;
    bool flag = 0;
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
    if (this->av) {
        tcm__log_trace("Cleaning up address vector");
        ret = fi_close((fid_t) this->av);
        if (ret < 0) {
            tcm__log_warn("AV deallocation failed: %s", fi_strerror(-ret));
            flag = 1;
        }
        this->av = NULL;
    }
    if (this->cq) {
        tcm__log_trace("Cleaning up CQ");
        ret = fi_close((fid_t) this->cq);
        if (ret < 0) {
            tcm__log_warn("CQ deallocation failed: %s", fi_strerror(-ret));
            flag = 1;
        }
        this->cq = NULL;
    }
    tcm__log_trace("Releasing fabric/domain objects");
    this->top = 0;
    if (flag) {
        tcm__log_trace("Fabric resources could not be fully cleaned up");
    } else {
        tcm__log_trace("Fabric resources cleaned up");
    }
    this->clear_fields();
}

void tcm_fabric::set_timeout(tcm_time & timeout) { this->timeout = timeout; }

void * tcm_fabric::_get_fi_resource(tcm_fabric_resource res) {
    switch (res) {
        case TCM_RESRC_FABRIC:
            return (void *) this->top->fabric;
        case TCM_RESRC_DOMAIN:
            return (void *) this->top->domain;
        case TCM_RESRC_CQ:
            return (void *) this->cq;
        case TCM_RESRC_PARAM:
            return (void *) this->fi;
        case TCM_RESRC_AV:
            return (void *) this->av;
        case TCM_RESRC_RKEY_COUNTER:
            return (void *) (uintptr_t)++(this->top->rkey_counter);
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
            sockaddr_in * sai = (sockaddr_in *) addr;
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
            if (*buf_size < (int) sizeof(sockaddr_in)) {
                *buf_size = (int) sizeof(sockaddr_in);
                return -ENOBUFS;
            }
            sockaddr_in *   sai  = (sockaddr_in *) out_buf;
            tcm_addr_inet * inet = (tcm_addr_inet *) addr;
            sai->sin_family      = AF_INET;
            sai->sin_addr.s_addr = inet->addr;
            sai->sin_port        = inet->port;
            *buf_size            = sizeof(sockaddr_in);
            return FI_SOCKADDR_IN;
    }
}
