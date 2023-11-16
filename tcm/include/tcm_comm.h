// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#ifndef TCM_COMM_H_
#define TCM_COMM_H_

#include "compat/tcmc_net.h"
#include <infiniband/ib.h>

#define TCM_MAGIC 0x52415054
namespace tcm_internal {

int  get_sa_size(sockaddr * sa);
bool check_af_support(unsigned int sa_family);
int  fabric_to_sys_af(uint32_t af);
int  sys_to_fabric_af(int af);
int  ntop(const void * addr, char * host, char * port, size_t * host_size);
int pton(const char * host, const char * port, void * addr, size_t * addr_size);

} // namespace tcm_internal

#endif