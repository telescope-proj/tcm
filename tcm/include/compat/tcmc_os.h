// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#ifndef TCM_COMPAT_OS_H_
#define TCM_COMPAT_OS_H_

#if defined(__linux__)
    #define TCM_OS_IS_LINUX         1
    #define TCM_OS_IS_MACOS         0
    #define TCM_OS_IS_GENERIC_UNIX  0
    #define TCM_OS_IS_WINDOWS       0
#elif defined(__APPLE__)
    #define TCM_OS_IS_LINUX         0
    #define TCM_OS_IS_MACOS         1
    #define TCM_OS_IS_GENERIC_UNIX  0
    #define TCM_OS_IS_WINDOWS       0
#elif defined(__unix__)
    #define TCM_OS_IS_LINUX         0
    #define TCM_OS_IS_MACOS         0
    #define TCM_OS_IS_GENERIC_UNIX  1
    #define TCM_OS_IS_WINDOWS       0
#elif defined(_WIN32)
    #define TCM_OS_IS_LINUX         0
    #define TCM_OS_IS_MACOS         0
    #define TCM_OS_IS_GENERIC_UNIX  0
    #define TCM_OS_IS_WINDOWS       1
#endif

#endif