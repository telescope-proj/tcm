// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#include "tcm_version.h"

uint64_t tcm_get_version() {
    return (uint64_t) TCM_VERSION_MAJOR << 32 |
           (uint64_t) TCM_VERSION_MINOR << 16 | (uint64_t) TCM_VERSION_PATCH;
}