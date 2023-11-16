#include "tcm_comm.h"
#include <assert.h>

namespace tcm_internal {

int get_sa_size(sockaddr * sa) {
    if (!sa)
        return 0;
    switch (sa->sa_family) {
        case AF_INET:
            return sizeof(sockaddr_in);
        case AF_INET6:
            return sizeof(sockaddr_in6);
        default:
            return -EINVAL;
    }
}

bool check_af_support(unsigned int sa_family) {
    switch (sa_family) {
        case AF_INET:
        case AF_INET6:
            return 1;
        default:
            return 0;
    }
}

int fabric_to_sys_af(uint32_t af) {
    switch (af) {
        case FI_FORMAT_UNSPEC:
            return AF_UNSPEC;
        case FI_SOCKADDR_IN:
            return AF_INET;
        case FI_SOCKADDR_IN6:
            return AF_INET6;
        case FI_SOCKADDR_IB:
            return AF_IB;
        default:
            return -EINVAL;
    }
}

int sys_to_fabric_af(int af) {
    switch (af) {
        case AF_UNSPEC:
            return FI_FORMAT_UNSPEC;
        case AF_INET:
            return FI_SOCKADDR_IN;
        case AF_INET6:
            return FI_SOCKADDR_IN6;
        case AF_IB:
            return FI_SOCKADDR_IB;
        default:
            return -EINVAL;
    }
}

int ntop(const void * addr, char * host, char * port, size_t * host_size) {
    if (!addr)
        return -EINVAL;
    int sa_size = get_sa_size((sockaddr *) addr);
    if (sa_size <= 0)
        return -EINVAL;
    if (!check_af_support(((sockaddr *) addr)->sa_family))
        return -EINVAL;
    if (!host && !port)
        return -EINVAL;
    if (host && !*host_size)
        return -EINVAL;

    int    ret;
    void * ptr = 0;
    switch (((sockaddr *) addr)->sa_family) {
        case AF_INET:
            if (host) {
                if (*host_size < INET6_ADDRSTRLEN) {
                    *host_size = INET6_ADDRSTRLEN;
                    return -ENOBUFS;
                }
                ptr = (void *) &((sockaddr_in *) addr)->sin_addr;
            }
            if (port) {
                ret = sprintf(port, "%d",
                              ntohs(((sockaddr_in *) addr)->sin_port));
                if (ret < 0) {
                    return ret;
                }
            }
            break;
        case AF_INET6:
            if (host) {
                if (*host_size < INET_ADDRSTRLEN) {
                    *host_size = INET_ADDRSTRLEN;
                    return -ENOBUFS;
                }
                ptr = (void *) &((sockaddr_in6 *) addr)->sin6_addr;
            }
            if (port) {
                ret = sprintf(port, "%d",
                              ntohs(((sockaddr_in6 *) addr)->sin6_port));
                if (ret < 0) {
                    return ret;
                }
            }
            break;
        default:
            // todo af_ib
            return -EPROTONOSUPPORT;
    }
    assert(ptr);

    if (!host)
        return 0;

    int          af  = ((sockaddr *) addr)->sa_family;
    const char * res = inet_ntop(af, ptr, host, *host_size);
    if (!res)
        return -errno;

    return 0;
}

int pton(const char * host, const char * port, void * addr,
         size_t * addr_size) {
    if (!host && !port)
        return -EINVAL;
    if (!addr || !addr_size)
        return -EINVAL;

    uint16_t p = 0;
    if (port) {
        long pt = strtol(port, nullptr, 10);
        if (pt <= 0 || pt >= 65535) {
            return -EINVAL;
        }
        p = (uint16_t) pt;
    }

    int     af = AF_INET;
    in_addr ia;
    if (inet_pton(af, host, &ia) == 1) {
        if (*addr_size < sizeof(sockaddr_in)) {
            *addr_size = sizeof(sockaddr_in);
            return -ENOBUFS;
        }
        sockaddr_in * sa = reinterpret_cast<sockaddr_in *>(addr);
        memset(sa, 0, sizeof(*sa));
        sa->sin_family      = AF_INET;
        sa->sin_port        = htons(p);
        sa->sin_addr.s_addr = ia.s_addr;
        return 0;
    }

    af = AF_INET6;
    in6_addr ia6;
    if (inet_pton(af, host, &ia6) == 1) {
        if (*addr_size < sizeof(sockaddr_in6)) {
            *addr_size = sizeof(sockaddr_in6);
            return -ENOBUFS;
        }
        sockaddr_in6 * sa = reinterpret_cast<sockaddr_in6 *>(addr);
        memset(sa, 0, sizeof(*sa));
        sa->sin6_family = AF_INET6;
        sa->sin6_addr   = ia6;
        sa->sin6_port   = htons(p);
        return 0;
    }

    // todo af_ib

    return -EPROTONOSUPPORT;
}

} // namespace tcm_internal