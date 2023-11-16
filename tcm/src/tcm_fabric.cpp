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

namespace tcm_internal {

size_t BASIC_PAGE_SIZE = 0;
size_t HUGE_PAGE_SIZE  = 0;
size_t MLOCK_LIMIT     = 0;

} // namespace tcm_internal

/* --- Initialization --- */

int tcm_init(tcm_init_param * p) {
    (void) p;
#ifdef __linux__
    const char * log_level = getenv("TCM_LOG_LEVEL");
    if (!log_level) {
        tcm__log_set_level(TCM__LOG_FATAL);
    } else {
        if (strcmp(log_level, "trace") == 0) {
            tcm__log_set_level(TCM__LOG_TRACE);
        } else if (strcmp(log_level, "debug") == 0) {
            tcm__log_set_level(TCM__LOG_DEBUG);
        } else if (strcmp(log_level, "info") == 0) {
            tcm__log_set_level(TCM__LOG_INFO);
        } else if (strcmp(log_level, "warn") == 0) {
            tcm__log_set_level(TCM__LOG_WARN);
        } else if (strcmp(log_level, "error") == 0) {
            tcm__log_set_level(TCM__LOG_ERROR);
        } else if (strcmp(log_level, "fatal") == 0) {
            tcm__log_set_level(TCM__LOG_FATAL);
        }
    }
    setenv("FI_UNIVERSE_SIZE", "4", 0);
    tcm_internal::BASIC_PAGE_SIZE = tcm_get_page_size();
    FILE * f                      = fopen("/proc/meminfo", "r");
    if (!f) {
        tcm__log_warn("Could not open /proc/meminfo");
    } else {
        char buf[128];
        while (fgets(buf, sizeof(buf), f)) {
            size_t hps = 0;
            if (sscanf(buf, "Hugepagesize: %lu kB", &hps) == 1) {
                tcm_internal::HUGE_PAGE_SIZE = hps * 1024;
                break;
            }
        }
    }
    fclose(f);
    struct rlimit lim;
    int           ret = getrlimit(RLIMIT_MEMLOCK, &lim);
    if (ret < 0) {
        tcm__log_warn("Could not get memlock limit: %s", strerror(errno));
    } else {
        tcm_internal::MLOCK_LIMIT = lim.rlim_cur;
    }
#else
    return -ENOSYS;
#endif
    return 0;
}

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
    tcm_internal::merge_tcm_hints(hints);

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
                     tcm_time *                          timeout) {
    using tcm_internal::prov_name_to_tid;
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
    this->transport_id = prov_name_to_tid(this->fi->fabric_attr->prov_name);

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
