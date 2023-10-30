// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#ifndef TCM_FABRIC_H_
#define TCM_FABRIC_H_

#include <memory>
#include <stdexcept>
#include <stdint.h>

#include <rdma/fabric.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_eq.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_tagged.h>

#include "tcm_beacon.h"
#include "tcm_log.h"
#include "tcm_mm.h"
#include "tcm_msg.h"
#include "tcm_time.h"
#include "tcm_util.h"

#define TCM_DEFAULT_FABRIC_VERSION FI_VERSION(1, 10)

enum tcm_fabric_resource : uint64_t {
    TCM_RESRC_INVALID = 0,
    TCM_RESRC_FABRIC  = (1 << 0),
    TCM_RESRC_DOMAIN  = (1 << 1),
    TCM_RESRC_TX_CQ   = (1 << 2),
    TCM_RESRC_RX_CQ   = (1 << 3),
    TCM_RESRC_AV      = (1 << 4),
    TCM_RESRC_PARAM   = (1 << 5),
};

class tcm_mem;
class tcm_fabric;

static inline int tcm_get_av_error(int ret, int fret) {
    return -tcm_abs(fret == 0 ? (ret == 0 ? FI_EOTHER : ret) : fret);
}

/* Get the last CQ error.
   If ret is any value except -FI_EAVAIL, then the function returns ret (i.e.,
   this function can be safely used even if there was no error). Otherwise, the
   function checks the CQ for the last error and returns it, unless an error
   occurred, in which case it returns the error that occurred while trying to
   read from the CQ.
*/
static inline int tcm_get_cq_error(int ret, struct fid_cq * cq,
                                   struct fi_cq_err_entry * err) {
    struct fi_cq_err_entry lerr;
    if (ret >= 0)
        return ret;
    if (!err)
        err = &lerr;
    if (ret == -FI_EAVAIL) {
        ret = fi_cq_readerr(cq, err, 0);
        if (ret != 1)
            return -tcm_abs(ret == 0 ? 1 : ret);

        tcm__log_error("CQ %p | Error: %d (%s)", cq, err->err,
                       fi_strerror(err->err));
        if (err->err_data && err->err_data_size) {
            tcm__log_error(
                "Fabric provider error: %s",
                fi_cq_strerror(cq, err->prov_errno, err->err_data, NULL, 0));
        }

        return -tcm_abs(err->err);
    }
    return ret;
}

class tcm_mem {
  private:
    void *          ptr;
    uint64_t        len;
    uint64_t        alignment;
    struct fid_mr * mr;
    uint8_t own; // Whether ptr lifecycle should be managed by this class: 0 =
                 // no, 1 = yes (regular memory), 2 = yes (aligned memory)
    std::shared_ptr<tcm_fabric> parent;

    void clear_fields();

    void free_mgd_mem();

    void reg_internal_buffer();
    void reg_internal_buffer(uint64_t acs, uint64_t flags);

    void dereg_internal_buffer();

  public:
    tcm_mem(std::shared_ptr<tcm_fabric> fabric, uint64_t size);
    tcm_mem(std::shared_ptr<tcm_fabric> fabric, uint64_t size, uint64_t acs);
    tcm_mem(std::shared_ptr<tcm_fabric> fabric, void * ptr, uint64_t len,
            uint8_t own);
    tcm_mem(std::shared_ptr<tcm_fabric> fabric, void * ptr, uint64_t len,
            uint64_t acs, uint8_t own);

    ~tcm_mem();

    void *          get_ptr();
    struct fid_mr * get_mr();
    void *          get_mr_desc();
    uint64_t        get_len();

    void refresh_mr(void * ptr, uint64_t len);
    void refresh_mr(void * ptr, uint64_t len, uint64_t acs, uint64_t flags);

    int _check_parent(tcm_fabric * p);
};

struct tcm_remote_mem {
    fi_addr_t peer;
    uint64_t  addr;
    uint64_t  rkey;
    uint64_t  len;
    tcm_remote_mem(fi_addr_t peer, uint64_t addr, uint64_t len, uint64_t rkey) {
        this->peer = peer;
        this->addr = addr;
        this->rkey = rkey;
        this->len  = len;
    }
};

namespace tcm_internal {
class shared_fi {
  public:
    struct fid_fabric * fabric;
    struct fid_domain * domain;

    shared_fi(struct fid_fabric * fabric, struct fid_domain * domain);
    ~shared_fi();
};

} // namespace tcm_internal

struct tcm_fabric_cq_fds {
    int tx;
    int rx;
};

struct tcm_fabric_init_opts {
    uint32_t         version;
    uint64_t         flags;
    struct fi_info * hints;
    tcm_time *       timeout;
};

struct tcm_fabric_child_opts {
    std::shared_ptr<tcm_internal::shared_fi> fi;
    uint16_t                                 port;
    tcm_time *                               timeout;
};

class tcm_fabric : public std::enable_shared_from_this<tcm_fabric> {
    std::shared_ptr<tcm_internal::shared_fi> top; // Shareable top level objects
    struct fid_cq *                          tx_cq; // Transmit completion queue
    struct fid_cq *                          rx_cq; // Receive completion queue
    struct fid_av *                          av;    // Address vector
    struct fid_ep *                          ep;    // Endpoint
    uint32_t                                 proto; // Libfabric protocol
    uint32_t         addr_fmt;                      // Libfabric address format
    uint32_t         transport_id;                  // TCM Transport ID
    char             prov_name[32];                 // Libfabric provider name
    tcm_time         timeout;                       // Default timeout
    uint32_t         fabric_version; // Libfabric API version used
    uint64_t         fabric_flags;   // Init flags
    void *           src_addr;       // Source address
    size_t           src_addrlen;    // Source address length
    struct fi_info * hints;          // Fabric creation hints
    struct fi_info * fi;             // Created fabric details
    int              op_mode;        // Operation mode (1=server, 2=client)

    int init(std::shared_ptr<tcm_internal::shared_fi> fi,
             struct sockaddr_in * addr, tcm_time * timeout);
    int init_fabric_domain(uint32_t version, uint64_t flags,
                           struct fi_info * hints);

    void    clear_fields();
    ssize_t poll_cq(struct fid_cq * cq, struct fi_cq_err_entry * err,
                    tcm_time * timeout);
    ssize_t data_xfer(uint8_t type, tcm_mem & mem, uint64_t offset,
                      uint64_t len, uint64_t tag, uint64_t mask, fi_addr_t peer,
                      uint8_t sync, void * context);
    ssize_t data_xfer_rdma(uint8_t type, tcm_mem & mem, tcm_remote_mem & rmem,
                           uint64_t local_offset, uint64_t remote_offset,
                           uint64_t len, fi_addr_t peer, void * ctx);

  public:
    tcm_fabric(struct tcm_fabric_init_opts & opts);
    tcm_fabric(struct tcm_fabric_child_opts & opts, tcm_fabric * parent);

    ~tcm_fabric();

    /* Connection setup */
    int accept_client(tcm_beacon & beacon, struct sockaddr * peer,
                      fi_addr_t * addr);
    int client(tcm_beacon & beacon, struct sockaddr * peer, fi_addr_t * addr,
               bool fast);

    /* Other control functions */

    /* Set the timeout of the fabric for managed data transfer functions. Has no
     * effect if Libfabric functions are called directly. */
    void set_timeout(tcm_time & timeout);

    /* Get the address of the active fabric. */
    int get_name(void * buf, size_t * buf_size);

    /* Set the address of the active fabric. */
    int set_name(void * buf, size_t buf_size);

    /* Peer management functions */
    fi_addr_t add_peer(struct sockaddr * peer);
    int       remove_peer(fi_addr_t peer);

    /* CQ functions */

    /* Poll the transmit queue (regular/tagged send, RDMA read/write ops) */
    ssize_t poll_tx(struct fi_cq_err_entry * err);

    /* Poll the receive queue (regular/tagged recv ops) */
    ssize_t poll_rx(struct fi_cq_err_entry * err);

    /* Check if the underlying CQs can be waited on using poll().
       This function returns a bit field where TCM_RESRC_TX_CQ and
       TCM_RESRC_RX_CQ flags can be set, indicating the specific CQ can
       be blocked on using poll(), select(), etc.

       If an error occurred on either CQ, a negative error code is returned,
       and the value out will be set to one of the failed CQs (priority RX CQ).
    */
    int cq_waitable(int * out);

    /* Get underlying wait objects. Sets the parameter out to the file
       descriptors of the CQs. If an error occurred, -1 is returned and
       out->tx/rx is set to a negative error number that occurred while trying
       to get the wait object for that CQ.
     */
    int get_cq_fds(tcm_fabric_cq_fds * out);

    /* Standard data transfer functions */
    ssize_t send(tcm_mem & mem, fi_addr_t peer, void * ctx, uint64_t offset,
                 uint64_t len);
    ssize_t recv(tcm_mem & mem, fi_addr_t peer, void * ctx, uint64_t offset,
                 uint64_t len);

    /* Tagged data transfer functions */
    ssize_t tsend(tcm_mem & mem, fi_addr_t peer, void * ctx, uint64_t offset,
                  uint64_t len, uint64_t tag);
    ssize_t trecv(tcm_mem & mem, fi_addr_t peer, void * ctx, uint64_t offset,
                  uint64_t len, uint64_t tag, uint64_t mask);

    /* Synchronous data transfer functions (used for bootstrapping) */
    ssize_t ssend(tcm_mem & mem, fi_addr_t peer, uint64_t offset, uint64_t len);
    ssize_t srecv(tcm_mem & mem, fi_addr_t peer, uint64_t offset, uint64_t len);

    /* One-sided RDMA transfer functions */
    ssize_t rwrite(tcm_mem & mem, fi_addr_t peer, void * ctx,
                   uint64_t local_offset, uint64_t remote_offset, uint64_t len,
                   tcm_remote_mem & rmem);
    ssize_t rread(tcm_mem & mem, fi_addr_t peer, void * ctx,
                  uint64_t local_offset, uint64_t remote_offset, uint64_t len,
                  tcm_remote_mem & rmem);

    /* Create a new fabric connection with the same features as the
     * existing connection (on a different port). */
    std::shared_ptr<tcm_fabric> split_conn(fi_addr_t peer, uint16_t port,
                                           uint8_t     shared,
                                           fi_addr_t * new_peer);

    /* Functions only to be called internally by library functions */
    void *  _get_fi_resource(tcm_fabric_resource resource);
    tcm_tid _get_tid();
};

#endif