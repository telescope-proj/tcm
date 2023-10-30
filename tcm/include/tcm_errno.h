// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#ifndef TCM_ERRNO_H_
#define TCM_ERRNO_H_

#include <compat/tcmc_stable_errno.h>
#include <rdma/fi_errno.h>
#include <string.h>

/* ----- Additional errno values for internal tcm errors ----- */

enum {
    TCM_ERR_UNSPECIFIED = 32768,
    TCM_ERR_VERSION_MISMATCH,
    TCM_ERR_INVALID_ADDRESS,
    TCM_ERR_INVALID_FABRIC_VER
};

int tcm_err_to_sys(unsigned int tcm_errno);

int tcm_sys_to_err(unsigned int sys_errno);

const char * tcm_err_string(unsigned int tcm_errno);

#endif