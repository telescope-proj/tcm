// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#include "tcm_fabric.h"

namespace tcm_internal {

void merge_tcm_hints(fi_info * info) {
    info->ep_attr->type = FI_EP_RDM;
    info->domain_attr->mr_mode =
        FI_MR_VIRT_ADDR | FI_MR_ALLOCATED | FI_MR_PROV_KEY | FI_MR_LOCAL;
    info->mode          = FI_RX_CQ_DATA | FI_LOCAL_MR;
    info->caps          = FI_MSG | FI_RMA;
    info->tx_attr->caps = FI_MSG | FI_RMA;
    info->rx_attr->caps = FI_MSG | FI_RMA;
    if (info->tx_attr->size < 64)
        info->tx_attr->size = 64;
    if (info->rx_attr->size < 64)
        info->rx_attr->size = 64;
}

fi_info * get_tcm_hints(sockaddr * src_addr) {
    fi_info * info = fi_allocinfo();
    merge_tcm_hints(info);
    if (src_addr) {
        info->src_addrlen = tcm_internal::get_sa_size(src_addr);
        if (info->src_addrlen <= 0) {
            tcm__log_error("Invalid address length");
            errno = EINVAL;
            return 0;
        }
        info->src_addr = malloc(info->src_addrlen);
        memcpy(info->src_addr, src_addr, info->src_addrlen);
        info->addr_format = tcm_internal::sys_to_fabric_af(src_addr->sa_family);
    } else {
        info->addr_format = FI_FORMAT_UNSPEC;
    }
    return info;
}

} // namespace tcm_internal