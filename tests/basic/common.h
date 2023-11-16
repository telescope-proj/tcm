#include "tcm_conn.h"
#include "tcm_fabric.h"

#include <memory>
#include <stdio.h>

using std::make_shared;
using std::shared_ptr;

#define SA_CAST(x) reinterpret_cast<sockaddr *>(x)

static inline uint16_t get_port(sockaddr * sa) {
    switch (sa->sa_family) {
        case AF_INET:
            return reinterpret_cast<sockaddr_in *>(sa)->sin_port;
            break;
        case AF_INET6:
            return reinterpret_cast<sockaddr_in6 *>(sa)->sin6_port;
            break;
        default:
            printf("Unsupported address format %d", sa->sa_family);
            assert(false);
    }
}

static inline void set_port(sockaddr * sa, uint16_t port) {
    switch (sa->sa_family) {
        case AF_INET:
            reinterpret_cast<sockaddr_in *>(sa)->sin_port = port;
            break;
        case AF_INET6:
            reinterpret_cast<sockaddr_in6 *>(sa)->sin6_port = port;
            break;
        default:
            printf("Unsupported address format %d", sa->sa_family);
            assert(false);
    }
}

static inline void increment_port(sockaddr * sa, uint16_t val) {
    set_port(sa, htons(ntohs(get_port(sa)) + val));
}