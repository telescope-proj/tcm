// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#ifndef TCM_VERSION_H_
#define TCM_VERSION_H_

#include <stdint.h>

#define TCM_VERSION_MAJOR 0
#define TCM_VERSION_MINOR 4
#define TCM_VERSION_PATCH 5

#define TCM_MAJOR(x) ((x >> 32) & 0xFFFF)
#define TCM_MINOR(x) ((x >> 16) & 0xFFFF)
#define TCM_PATCH(x) (x & 0xFFFF)

uint64_t tcm_get_version();

#endif