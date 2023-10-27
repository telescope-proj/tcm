// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#ifndef TCM_UTIL_H_
#define TCM_UTIL_H_

#define tcm_abs(x) (x >= 0 ? x : -x)
#define tcm_negabs(x) (x <= 0 ? x : -x)
#define TCM_MAX_ADDR_LEN 128
#define tcm_free_unset(x) free(x); x = 0;

// int tcm_validate_ipv4_addr(uint32_t addr) {
//     in_addr_t ranges[] = {
//         inet_addr("10.0.0.0"),
//         inet_addr("172.16.0.0"),
//         inet_addr("192.168.0.0"),
//         0
//     };

//     in_addr_t masks[] = {
//         inet_addr("255.0.0.0"),
//         inet_addr("255.240.0.0"),
//         inet_addr("255.255.0.0"),
//         0
//     };

//     for (int i = 0; masks[i] > 0; i++) {
//         if (ranges[i] & masks[i] == addr & masks[i])
//             return 1;
//     }
//     return 0;
// }

#endif