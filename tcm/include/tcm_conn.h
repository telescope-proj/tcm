// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#include "tcm_errno.h"
#include "tcm_fabric.h"
#include "tcm_log.h"

enum tcm_conn_flags {
    /* Once a valid instance with a specific transport type has been created, do
       not test more instances of that type. */
    TCM_CONN_FLAG_ONCE  = (1 << 0),
    /* Interpret the hints parameter as actual fabric parameters, bypassing
       fi_getinfo. */
    TCM_CONN_FLAG_PARAM = (1 << 1)
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
 * @param f_out Optional pointer where the created fabric will be output.
 *
 * If this value is zero, all connections will be tested and the number of valid
 * connections will be returned.
 *
 * If this value is non-zero, the first functional connection that matches the
 * input criteria will be returned in this parameter, and the function
 * returns 1.
 *
 * @return  The number of valid connections, or a negative error code. If no
 * valid connections were found, -ENOTSUP is returned.
 */
int tcm_test_conns(fi_info * hints, fi_info ** hints_out, int flags,
                   sockaddr * local_addr, tcm_tid * tids,
                   std::shared_ptr<tcm_fabric> * f_out);

/**
 * @brief Accept a client, creating a fabric connection on-demand.
 *
 * This function will create a fabric connection type as requested by the
 * client, as long as the type is supported by the server.
 *
 * @param beacon TCM beacon connection
 *
 * @param hints Fabric hints, returned by fi_getinfo() and (optionally) modified
 *
 * @param local Local address
 *
 * If this value is not set, the src_addr field in the hints parameter is used
 * instead.
 *
 * @param peer Optional remote peer address
 *
 * If this value is nonzero and the address family is not set to AF_UNSPEC, the
 * beacon address of the connecting peer will be returned in this parameter.
 *
 * If the address family is AF_INET, the beacon will only accept datagrams
 * from the specified peer.
 *
 * @param fabric_out Output fabric object
 *
 * @param ep_out Output fabric endpoint
 *
 * @param peer_out Output peer address handle
 *
 * @param timeout Timeout in milliseconds. -1 -> infinite timeout
 *
 * @param exit_flag Pointer to an optional flag used to control early exit
 *
 * The exit flag may be used to interrupt the function while it is in progress,
 * for instance if a signal to terminate the program is received. This value
 * must be set to zero before calling the function, and any positive value will
 * cause the function to clean up its resources and return.
 *
 * @return 0 on success, negative error code on failure. If the function
 * terminated because exit_flag was changed, -ECANCELED is returned. If both the
 * exit_flag is 1 and a signal has been received, the function may return either
 * -ECANCELED or -EINTR.
 */
int tcm_accept_client_dynamic(tcm_beacon & beacon, fi_info * hints,
                              sockaddr * local, sockaddr * peer,
                              std::shared_ptr<tcm_fabric> *   fabric_out,
                              std::shared_ptr<tcm_endpoint> * ep_out,
                              fi_addr_t * peer_out, int timeout,
                              volatile int * exit_flag);

/**
 * @brief Negotiate transport type details with the server and create a fabric
 * connection on-demand.
 *
 * @param beacon TCM beacon connection
 *
 * @param hints Fabric hints, returned by fi_getinfo() and (optionally) modified
 *
 * @param local Local address
 *
 * If this value is not set, the src_addr field in the hints parameter is used
 * instead.
 *
 * @param peer Optional remote peer address
 *
 * If this value is nonzero and the address family is not set to AF_UNSPEC, the
 * beacon address of the peer will be returned in this parameter.
 *
 * If the address family is AF_INET, the beacon will only accept datagrams
 * from the specified peer.
 *
 * @param fabric_out Output fabric object
 *
 * @param ep_out Output fabric endpoint
 *
 * @param peer_out Output peer address handle
 *
 * @param fast Fast connection mode
 *
 * Fast connection mode skips the capability probe to the server if the fabric
 * details are known ahead of time. In this case, the length of the hints list
 * should be 1, or there should only be a single transport type as supported by
 * the server.
 *
 * When this is set, the function will not re-probe the server if the connection
 * parameters mismatch.
 *
 * @param exit_flag Pointer to an optional flag used to control early exit
 *
 * The exit flag may be used to interrupt the function while it is in progress,
 * for instance if a signal to terminate the program is received. This value
 * must be set to zero before calling the function, and any positive value will
 * cause the function to clean up its resources and return.
 *
 * @param timeout Timeout in milliseconds. -1 -> infinite timeout
 *
 * @return 0 on success, negative error code on failure. If the function
 * terminated because exit_flag was changed, -ECANCELED is returned. If both the
 * exit_flag is 1 and a signal has been received, the function may return either
 * -ECANCELED or -EINTR.
 */
int tcm_client_dynamic(tcm_beacon & beacon, fi_info * hints, sockaddr * local,
                       sockaddr *                      peer,
                       std::shared_ptr<tcm_fabric> *   fabric_out,
                       std::shared_ptr<tcm_endpoint> * ep_out,
                       fi_addr_t * peer_out, bool fast, int timeout,
                       volatile int * exit_flag);