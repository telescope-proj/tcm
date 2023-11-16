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

int ntop(void * addr, char * host, char * port, size_t * host_size) {
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
            assert(false);
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

} // namespace tcm_internal