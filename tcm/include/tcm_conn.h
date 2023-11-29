// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#ifndef TCM_CONN_H_
#define TCM_CONN_H_

#include "tcm_errno.h"
#include "tcm_fabric.h"
#include "tcm_log.h"

#include <vector>

enum tcm_prv_result {
    TCM_PRV_INVALID_WITH_RESP = -1, // Private data invalid, but send a response
    TCM_PRV_INVALID           = 0,  // Private data invalid
    TCM_PRV_VALID             = 1   // Valid
};

/**
 * @brief Private data
 *
 * Private data, or user data, can optionally be sent along with client/server
 * ping messages to be interpreted by higher-level protocols. TCM does not check
 * the contents of the private data field for validity.
 *
 * Up to 128 bytes of private data is supported.
 */
struct tcm_prv_data {
    /**
     * @brief Pointer to a region of data to send.
     */
    void * data;
    /**
     * @brief Size of the data field.
     */
    size_t size;
    /**
     * @brief User-specified validation function
     *
     * @param self  This structure
     *
     * @param data  The peer's private data
     *
     * @param size  Length of the private data field
     *
     * @return The return value should be one in tcm_prv_result. The pointer
     * to self->data and self->size may be modified in this call.
     */
    int (*validator)(tcm_prv_data * self, void * data, size_t size);
    /**
     * @brief User specified variables/parameters that can be used to store
     * state for the validator function.
     */
    void * params;
};

/**
 * @brief Connection setup hints
 *
 * Either hints, addr, or both must be set. The end of the array is signalled by
 * setting both hints and addr to 0.
 *
 * The underscored functions are for internal use.
 */
struct tcm_conn_hints {
    /**
     * @brief Local bind address.
     *
     * This must be one of the supported TCM addresses.
     */
    void *    addr;
    /**
     * @brief Libfabric hints
     *
     * These hints will be overwritten if parameters do not match the TCM
     * requirements.
     */
    fi_info * hints;
    /**
     * @brief Connection setup flags
     *
     * This is currently unused.
     */
    uint32_t  flags;

    sockaddr * _sa() {
        assert(addr);
        return reinterpret_cast<sockaddr *>(addr);
    }
    sockaddr_in * _sa_i() {
        assert(addr);
        assert(reinterpret_cast<sockaddr_in *>(addr)->sin_family == AF_INET);
        return reinterpret_cast<sockaddr_in *>(addr);
    }
    sockaddr_in6 * _sa_i6() {
        assert(addr);
        assert(reinterpret_cast<sockaddr_in *>(addr)->sin_family == AF_INET6);
        return reinterpret_cast<sockaddr_in6 *>(addr);
    }
    sockaddr_ib * _sa_ib() {
        assert(addr);
        assert(reinterpret_cast<sockaddr_in *>(addr)->sin_family == AF_IB);
        return reinterpret_cast<sockaddr_ib *>(addr);
    }
    bool _is_end() { return !(addr || hints); }
};

struct tcm_client_dynamic_param {
    /**
     * @brief TCM beacon object
     */
    tcm_beacon *                  beacon;
    /**
     * @brief User-specified data
     *
     * Up to 128 bytes of arbitrary data may be provided in this parameter,
     * which is sent along with the client ping.
     *
     * A validator may optionally be provided here in prv->validator. This
     * validates the user data, if any, in the server ping response.
     */
    tcm_prv_data *                prv_data;
    /**
     * @brief Array of connection setup hints.
     *
     * The last element of the array must have all its values set to zero, which
     * indicates the end of the array.
     */
    std::vector<tcm_conn_hints> * hints;
    /**
     * @brief Peer (server) address
     */
    sockaddr *                    peer;
    /**
     * @brief Output peer fabric address. This address is bound to the output
     * endpoint.
     */
    fi_addr_t                     peer_out;
    /**
     * @brief Fast connection mode
     *
     * This mode is currently not tested and should not be used.
     */
    bool                          fast;
    /**
     * @brief Connection timeout in milliseconds
     */
    int                           timeout_ms;
    /**
     * @brief Exit flag. Must either be NULL or point to an int initialized to
     * zero. It can be set to 1 to signal the client to terminate while a
     * connection is in progress.
     */
    volatile int *                exit_flag;
    /**
     * @brief Output fabric object
     */
    std::shared_ptr<tcm_fabric>   fabric_out;
    /**
     * @brief Output endpoint object
     */
    std::shared_ptr<tcm_endpoint> ep_out;
    void clear() { memset((void *) this, 0, sizeof(*this)); }
};

struct tcm_accept_client_dynamic_param {
    /**
     * @brief Beacon object
     */
    tcm_beacon *                  beacon;
    /**
     * @brief User-specified data
     *
     * Up to 128 bytes of arbitrary data may be provided in this parameter,
     * which is sent along with the server ping.
     *
     * A validator may optionally be provided here in prv->validator. This
     * validates the incoming user data, if any, in the incoming client ping.
     */
    tcm_prv_data *                prv_data;
    /**
     * @brief Connection setup hints
     */
    std::vector<tcm_conn_hints> * hints;
    /**
     * @brief Optional remote peer address
     *
     * If this value is nonzero and the address family is set to AF_UNSPEC,
     * the beacon address of the connecting peer will be returned in this
     * parameter. Otherwise, if the address family is one of the supported TCM
     * formats, the beacon will only accept datagrams from the specified peer.
     */
    sockaddr *                    peer;
    /**
     * @brief Output fabric address of the peer.
     */
    fi_addr_t                     fabric_peer_out;
    /**
     * @brief Timeout in milliseconds. Use -1 for an infinite timeout.
     */
    int                           timeout_ms;
    /**
     * @brief Pointer to an optional flag used to control early exit
     *
     * The exit flag may be used to interrupt the function while it is in
     * progress, for instance if a signal to terminate the program is received.
     * This value must be set to zero before calling the function, and any
     * positive value will cause the function to clean up its resources and
     * return.
     */
    volatile int *                exit_flag;
    std::shared_ptr<tcm_fabric>   fabric_out;
    std::shared_ptr<tcm_endpoint> ep_out;

    void clear() {
        beacon          = 0;
        prv_data        = 0;
        hints           = 0;
        peer            = 0;
        fabric_peer_out = 0;
        timeout_ms      = 0;
        exit_flag       = 0;
        fabric_out      = 0;
        ep_out          = 0;
    }
};

/**
 * @brief Test the setup of one or more fabric connections based on the input
 * hints parameter.
 *
 * @param hints Linked list of fabric creation parameters, returned by
 * fi_getinfo(). This may contain any number of fabrics.
 *
 * @param hints_out Optional pointer to linked list where the valid hints will
 * be output. Memory will be allocated for fi_info structures automatically.
 *
 * @param flags Flags used to control the operation. See the enum for details.
 *
 * By default, if no flags are provided, every single transport in hints is
 * tested, even if some are of the same type. This can significantly prolong the
 * test duration, since Libfabric often provides several copies of the same
 * transport hints with small differences.
 *
 * @param local_addr Local bind address.
 *
 * It is strongly recommended that this address match the source address in the
 * provided hints - the setup is not reliable if the source address does not
 * match that of the NIC.
 *
 * @param tids Transport ID flags.
 *
 * When f_out is non-zero this is an input parameter corresponding to the
 * allowed transport types. Otherwise, this is an output parameter corresponding
 * to the transport types tested to be functional.
 *
 * @param afs  Address formats.
 *
 * When f_out is non-zero this is an input parameter corresponding to the
 * allowed address format(s) for fabric setup. Otherwise, this is an output
 * parameter corresponding to the address format(s) tested to be functional
 * given the input hints. However, if the user did not specify multiple/wildcard
 * address formats in the hints, or a local bind address, the afs parameter will
 * always output the address format type of the user's hints.
 *
 * @param f_out Optional pointer where the created fabric will be output.
 *
 * If this value is zero, all connections will be tested and the number of valid
 * connections will be returned.
 *
 * If this value is non-zero, the first functional connection that matches the
 * input criteria will be returned in this parameter, and the function returns
 * 1.
 *
 * @return  The number of valid connections, or a negative error code. If no
 * valid connections were found, -ENOTSUP is returned.
 */
int tcm_test_conns(fi_info * params, fi_info ** param_out, int flags,
                   sockaddr * local_addr, tcm_tid * tids, tcm_addr_fmt * afs,
                   std::shared_ptr<tcm_fabric> * f_out);

/**
 * @brief Accept a client, creating a fabric connection on-demand.
 *
 * This function will create a fabric connection type as requested by the
 * client, as long as the type is supported by the server.
 *
 * @return 0 on success, negative error code on failure. If the function
 * terminated because exit_flag was changed, -ECANCELED is returned. If both the
 * exit_flag is 1 and a signal has been received, the function may return either
 * -ECANCELED or -EINTR.
 */
int tcm_accept_client_dynamic(tcm_accept_client_dynamic_param * p);

/**
 * @brief Negotiate transport type details with the server and create a fabric
 * connection on-demand.
 *
 * @return 0 on success, negative error code on failure. If the function
 * terminated because exit_flag was changed, -ECANCELED is returned. If both the
 * exit_flag is 1 and a signal has been received, the function may return either
 * -ECANCELED or -EINTR.
 */
int tcm_client_dynamic(tcm_client_dynamic_param * p);

#endif