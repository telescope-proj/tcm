// SPDX-License-Identifier: MIT
// Telescope Connection Manager
// Copyright (c) 2023 Tim Dettmar

#ifndef TCM_FABRIC_H_
#define TCM_FABRIC_H_

#include <memory>
#include <stdint.h>

#include <infiniband/ib.h>
#include <rdma/fabric.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_eq.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_tagged.h>

#ifdef __linux__
#include <sys/resource.h>
#endif

#include "tcm_beacon.h"
#include "tcm_exception.h"
#include "tcm_log.h"
#include "tcm_mm.h"
#include "tcm_msg.h"
#include "tcm_time.h"
#include "tcm_util.h"

#define TCM_DEFAULT_FABRIC_VERSION FI_VERSION(1, 10)

enum tcm_fabric_resource : uint64_t {
    TCM_RESRC_INVALID = 0,
    TCM_RESRC_FABRIC  = (1 << 0), // Fabric (fid_fabric)
    TCM_RESRC_DOMAIN  = (1 << 1), // Domain (fid_domain)
    TCM_RESRC_TX_CQ   = (1 << 2), // Transmit CQ (fid_cq)
    TCM_RESRC_RX_CQ   = (1 << 3), // Receive CQ (fid_cq)
    TCM_RESRC_CQ    = (1 << 4), // Combined CQ (if both rx/tx are bound to 1 cq)
    TCM_RESRC_AV    = (1 << 5), // Address vector (fid_av)
    TCM_RESRC_PARAM = (1 << 6), // Connection parameters (fi_info struct)
    TCM_RESRC_RKEY_COUNTER = (1 << 7) // Remote key counter
};

namespace tcm_internal {

void      merge_tcm_hints(fi_info * info);
fi_info * get_tcm_hints(sockaddr * src_addr);

extern size_t BASIC_PAGE_SIZE;
extern size_t HUGE_PAGE_SIZE;
extern size_t MLOCK_LIMIT;

} // namespace tcm_internal

/**
 * @brief Lifecycle management options
 */
enum tcm_mem_bind {
    /**
     * @brief Do not manage the memory region. The input pointer is not freed
     * when the tcm_mem object bound to it goes out of scope.
     */
    TCM_MEM_UNMANAGED,
    /**
     * @brief Plain heap memory allocated using malloc(). The free() function is
     * called when the tcm_mem object goes out of scope.
     */
    TCM_MEM_PLAIN,
    /**
     * @brief Aligned heap memory allocated using OS-specific memalign function.
     * This only requires a separate free function on Windows, but it should
     * anyway be set if the memory region is aligned.
     */
    TCM_MEM_PLAIN_ALIGNED,
    /**
     * @brief Memory allocated using mmap(), anonymous
     */
    TCM_MEM_MMAP_ANON,
    /**
     * @brief Memory allocated using mmap(), with a file descriptor
     *
     * @warning Do not use mmap'd regions backed by files on disk, since this
     * can cause `corruption <https://lwn.net/Articles/930667/>`_ of the
     * provided file. This option is designed for files backed by RAM in
     * /dev/shm or similar regions.
     */
    TCM_MEM_MMAP_FD,
    /**
     * @brief Sentinel value
     */
    TCM_MEM_MAX
};

struct tcm_init_param {
    int unused;
};

int tcm_init(tcm_init_param * p);

class tcm_cq;
class tcm_mem;
class tcm_fabric;
class tcm_endpoint;

static inline int tcm_get_av_error(int ret, int fret) {
    return -tcm_abs(fret == 0 ? (ret == 0 ? FI_EOTHER : ret) : fret);
}

/**
 * @brief Get the last CQ error.
 *
 * @param ret   Return value from fi_cq_[s]read()
 * @param cq    CQ to collect errors from
 * @param err   Buffer to store errors
 *
 * @return      A return code corresponding to the last CQ error, if any.
 *
 * If ret is any value except -FI_EAVAIL, then the function returns ret (i.e.,
 * this function can be safely used even if there was no error). Otherwise, the
 * function checks the CQ for the last error and returns it, unless an error
 * occurred, in which case it returns the error that occurred while trying to
 * read from the CQ.
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
    friend tcm_endpoint;

  private:
    void *                      ptr;
    uint64_t                    len;
    uint64_t                    alignment;
    uint8_t *                   key_buf;
    size_t                      key_size;
    tcm_mem_bind                mode;
    struct fid_mr *             mr;
    std::shared_ptr<tcm_fabric> parent;

    bool check_parent(tcm_fabric * fabric);

    void clear_fields();

    void free_mgd_mem();

    void reg_internal_buffer();
    void reg_internal_buffer(uint64_t acs, uint64_t flags);

    void dereg_internal_buffer();

  public:
    tcm_mem(std::shared_ptr<tcm_fabric> fabric, uint64_t size);
    tcm_mem(std::shared_ptr<tcm_fabric> fabric, uint64_t size, uint64_t acs);
    tcm_mem(std::shared_ptr<tcm_fabric> fabric, void * ptr, uint64_t len,
            tcm_mem_bind mode);
    tcm_mem(std::shared_ptr<tcm_fabric> fabric, void * ptr, uint64_t len,
            uint64_t acs, tcm_mem_bind mode);

    ~tcm_mem();

    /**
     * @brief Pointer arithmetic with bounds checking.
     *
     * @param offset Offset in bytes.
     * 
     * @param length Optional length parameter. This parameter can be used to
     * verify that the entire subregion fits within the allocated memory region.
     *
     * @return void*
     */
    void *   offset(uint64_t offset, uint64_t length = 0);
    /**
     * @brief Get the pointer to the start of the raw buffer.
     *
     * @return void*
     */
    void *   operator*();
    /**
     * @brief Get the pointer to the start of the raw buffer.
     *
     * @return void*
     */
    void *   get_ptr();
    /**
     * @brief Get the Libfabric memory region object, for custom data transfer
     * operations.
     *
     * Typically, it is not required that you use this function, and it can make
     * your program more error-prone. TCM data transfer functions can accept the
     * tcm_mem object directly, ensuring the MR is always valid.
     *
     * @return fid_mr*
     */
    fid_mr * get_mr();
    /**
     * @brief Get the Libfabric memory region descriptor, for custom data
     * transfer operations.
     *
     * Typically, it is not required that you use this function, and it can make
     * your program more error-prone. TCM data transfer functions can accept the
     * tcm_mem object directly, ensuring the MR is always valid.
     *
     * @return fid_mr*
     */
    void *   get_mr_desc();
    /**
     * @brief Get the length of the memory buffer in bytes.
     *
     * @return uint64_t
     */
    uint64_t get_len();
    /**
     * @brief Determine the offset within the memory region of the provided
     * pointer.
     *
     * @param ptr Pointer
     *
     * @return The offset in bytes. If the pointer is not within the memory
     * region managed by this object, UINT64_MAX aka. (uint64_t) -1 is
     * returned.
     */
    uint64_t get_offset(void * ptr);
    /**
     * @brief Get the remote access key.
     *
     * @param key Output buffer for the remote access key.
     * @return 0 on success, -FI_ETOOSMALL if the rkey is longer than 64 bits,
     * in which case get_rkey_long() is required.
     */
    int      get_rkey(uint64_t * key);
    /**
     * @brief Get the raw remote access key.
     *
     * For keys <= 64 bits, this behaves similarly to get_rkey.
     *
     * @param buffer Buffer to store the key data
     *
     * @param size   Size of the buffer (input/output)
     *
     * *size should be equal to the size of the buffer. If the buffer size is
     * too small, this value will be set to the minimum buffer size required to
     * store the rkey.
     *
     * @return 0 on success, -FI_ETOOSMALL if the provided buffer is too small.
     */
    int      get_rkey_long(void * buffer, size_t * size);

    /**
     * @brief Refresh the memory region.
     *
     * Typically this function is only needed if the memory region size or
     * location changes. Page mapping changes are handled by the driver.
     *
     * @param ptr Pointer to the start of the new buffer, which can be the same
     * as the existing buffer
     *
     * @param len Length of the new buffer
     */
    void refresh_mr(void * ptr, uint64_t len);

    /**
     * @brief Refresh the memory region, with new access rights
     *
     * @param ptr Pointer to the start of the new buffer, which can be the same
     * as the existing buffer
     * @param len Length of the new buffer
     * @param acs Access control flags
     * @param flags Optional Libfabric flags
     */
    void refresh_mr(void * ptr, uint64_t len, uint64_t acs, uint64_t flags);
};

struct tcm_remote_mem {
    fi_addr_t peer; // The peer that this memory region belongs to
    uint64_t  addr; // Base address or IOVA of the memory region
    uint64_t  len;  // Length of the buffer
    bool      raw;  // Raw key (>64 bit)
    union {
        uint64_t rkey;
        struct raw_key {
            uint8_t * key;
            uint64_t  len;
        } raw_key;
    } u;

    tcm_remote_mem() {
        addr   = 0;
        raw    = 0;
        u.rkey = 0;
        len    = 0;
        peer   = FI_ADDR_UNSPEC;
    }

    tcm_remote_mem(fi_addr_t peer, uint64_t addr, uint64_t len, uint64_t rkey) {
        this->peer   = peer;
        this->addr   = addr;
        this->raw    = false;
        this->u.rkey = rkey;
        this->len    = len;
    }

    tcm_remote_mem(fi_addr_t peer, uint64_t addr, uint64_t len, uint8_t * rkey,
                   uint64_t rkey_len) {
        this->peer          = peer;
        this->addr          = addr;
        this->raw           = true;
        this->u.raw_key.key = (uint8_t *) calloc(1, rkey_len);
        if (!this->u.raw_key.key)
            throw tcm_exception(ENOMEM, __FILE__, __LINE__,
                                "Allocation of rkey buffer failed");
        memcpy(this->u.raw_key.key, rkey, rkey_len);
        this->u.raw_key.len = rkey_len;
        this->len           = len;
    }
};

namespace tcm_internal {
class shared_fi {
  public:
    fid_fabric * fabric;
    fid_domain * domain;
    uint64_t     rkey_counter;

    shared_fi(fid_fabric * fabric, fid_domain * domain);
    ~shared_fi();
};

} // namespace tcm_internal

struct tcm_fabric_init_opts {
    uint32_t         version;
    uint64_t         flags;
    struct fi_info * hints;
    bool             no_getinfo; // Use hints directly, don't run fi_getinfo
    tcm_time *       timeout;
    uint64_t         tcm_flags;
};

class tcm_endpoint : public std::enable_shared_from_this<tcm_endpoint> {
    std::shared_ptr<tcm_cq>     cq;
    std::shared_ptr<tcm_cq>     rx_cq;
    bool                        unified_cq;
    std::shared_ptr<tcm_fabric> fabric;

    fid_ep *       ep;
    tcm_time       timeout;
    void *         src_addr;
    size_t         src_addrlen;
    volatile int * exit_flag;

    /**
     * @brief Internal data transfer function (read/write and tagged
     * equivalents)
     *
     * @param type      Transfer type
     *
     * @param peer      Fabric peer
     *
     * @param mem       Memory region
     *
     * @param offset    Offset within the memory region provided
     *
     * @param len       Length of the message to send / maximum length of the
     *                  message to receive
     *
     * @param tag       Message tag (ignored for non-tagged ops)
     *
     * @param mask      Message tag mask (ignored except for tagged recv ops)
     *
     * @param sync      Synchronous mode
     *
     * In synchronous mode, the CQ is immediately read after posting the data
     * transfer operation. Note that this mode is not thread safe; synchronous
     * mode is primarily intended for connection bootstrapping before multiple
     * threads access the same fabric resources.
     *
     * @param ctx       Optional context to associate with the operation. This
     *                  context is returned on completions.
     *
     * @return In async mode: 0 on success, negative error code on failure.
     *
     * In sync mode: the number of bytes transferred, or -ETIMEDOUT/-EAGAIN
     * in case a completion was not generated in time.
     */
    ssize_t data_xfer(uint8_t type, fi_addr_t peer, tcm_mem & mem,
                      uint64_t offset, uint64_t len, uint64_t tag,
                      uint64_t mask, uint8_t sync, void * ctx);

    /**
     * @brief Internal RDMA data transfer function (read/write functions)
     *
     * @param type          Transfer type
     *
     * @param peer          Fabric peer
     *
     * @param mem           Memory region
     *
     * @param rmem          Remote memory region handle containing peer address
     *
     * @param local_offset  The offset within the local memory buffer
     *
     * @param remote_offset The offset within the remote memory buffer
     *
     * @param len           The length of the data to read/write
     *
     * @param ctx           Optional context to associate with the operation.
     *                      This context is returned on completions.
     *
     * @return 0 on success, negative error code on failure. Async mode only.
     */
    ssize_t data_xfer_rdma(uint8_t type, fi_addr_t peer, tcm_mem & mem,
                           tcm_remote_mem & rmem, uint64_t local_offset,
                           uint64_t remote_offset, uint64_t len, void * ctx);

    int init(std::shared_ptr<tcm_fabric> fab, sockaddr * addr, tcm_time * timeo,
             std::shared_ptr<tcm_cq> cq, std::shared_ptr<tcm_cq> rx_cq);

    void clear_fields();

  public:
    tcm_endpoint(std::shared_ptr<tcm_fabric> fabric, sockaddr * src_addr,
                 tcm_time * timeout); // internal cq resource mgmt

    tcm_endpoint(std::shared_ptr<tcm_fabric> fabric, sockaddr * src_addr,
                 tcm_time * timeout, std::shared_ptr<tcm_cq> cq);

    /**
     * @brief Create a new endpoint bound to a fabric.
     *
     * @param fabric    The fabric object
     * @param src_addr  Source address
     *
     * If this value is unset, it relies on the fabric object containing the
     * source address, which is not guaranteed and will not work for multiple
     * endpoints attached to the same fabric.
     *
     * The source address should always be set to the address of a physical NIC.
     * However, the port may be 0 for dynamic port assignment.
     *
     * @param timeout   Timeout object
     *
     * This object will be used for all synchronous operations when a timeout is
     * unspecified.
     *
     * @param tx_cq      Completion queue where transmit completions will be
     * stored.
     *
     * @param rx_cq      Completion queue where receive completions will be
     * stored.
     */
    tcm_endpoint(std::shared_ptr<tcm_fabric> fabric, sockaddr * src_addr,
                 tcm_time * timeout, std::shared_ptr<tcm_cq> tx_cq,
                 std::shared_ptr<tcm_cq> rx_cq);

    ~tcm_endpoint();

    /* Bind a flag which can be used to interrupt fabric functions. */
    void bind_exit_flag(volatile int * flag);

    /* Get the address of the active fabric. */
    int get_name(void * buf, size_t * buf_size) noexcept;

    /* Set the address of the active fabric. */
    int set_name(void * buf, size_t buf_size) noexcept;

    /* Set the timeout for synchronous functions. */
    void set_timeout(tcm_time & time) noexcept;

    const tcm_time & get_timeout() noexcept;

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
    ssize_t rwrite(tcm_mem & mem, tcm_remote_mem & rmem, void * ctx,
                   uint64_t local_offset, uint64_t remote_offset, uint64_t len);
    ssize_t rread(tcm_mem & mem, tcm_remote_mem & rmem, void * ctx,
                  uint64_t local_offset, uint64_t remote_offset, uint64_t len);

    std::weak_ptr<tcm_cq> get_cq();
    std::weak_ptr<tcm_cq> get_tx_cq();
    std::weak_ptr<tcm_cq> get_rx_cq();
};

class tcm_cq : public std::enable_shared_from_this<tcm_cq> {
    friend class tcm_endpoint;

    std::shared_ptr<tcm_fabric> fabric;
    fid_cq *                    cq;
    fi_cq_attr                  attr;
    volatile int *              flag;

    size_t get_cqe_size();
    int    init(std::shared_ptr<tcm_fabric> f, fi_cq_attr & attr);

  public:
    tcm_cq(std::shared_ptr<tcm_fabric> fabric_, size_t entries);
    tcm_cq(std::shared_ptr<tcm_fabric> fabric_, fi_cq_attr & attr);

    void get_attr(fi_cq_attr * out);
    void bind_exit_flag(volatile int * flag);

    ssize_t spoll(void * buf, void * ebuf, size_t entries, size_t * offset,
                  uint32_t flags, tcm_time * t);

    ssize_t poll(void * buf, void * ebuf, size_t entries, size_t * offset,
                 uint32_t flags);

    int get_fd();

    ~tcm_cq();
};

class tcm_fabric : public std::enable_shared_from_this<tcm_fabric> {
    friend class tcm_endpoint;
    friend class tcm_mem;
    friend class tcm_cq;
    std::shared_ptr<tcm_internal::shared_fi> top; // Shareable top level objects
    fid_cq *                                 cq;  // Completion queue
    fid_av *                                 av;  // Address vector
    uint32_t                                 proto; // Libfabric protocol
    uint32_t       addr_fmt;                        // Libfabric address format
    uint32_t       transport_id;                    // TCM Transport ID
    char           prov_name[32];                   // Libfabric provider name
    tcm_time       timeout;                         // Default timeout
    uint32_t       fabric_version; // Libfabric API version used
    uint64_t       fabric_flags;   // Init flags
    void *         src_addr;       // Source address
    size_t         src_addrlen;    // Source address length
    fi_info *      hints;          // Fabric creation hints
    fi_info *      fi;             // Created fabric details
    int            op_mode;        // Operation mode (1=server, 2=client)
    fi_wait_obj    wait_type;      // Wait object type
    volatile int * exit_flag;      // Early exit broadcast flag

    int init(std::shared_ptr<tcm_internal::shared_fi> fi, tcm_time * timeout);
    int init_fabric_domain(uint32_t version, uint64_t flags, fi_info * hints,
                           bool no_getinfo);

    void    clear_fields();
    ssize_t poll_cq(fid_cq * cq, fi_cq_err_entry * err, size_t n,
                    tcm_time * timeout);

  public:
    tcm_fabric(tcm_fabric_init_opts & opts);

    ~tcm_fabric();

    /* Bind a flag which can be used to interrupt fabric functions. */
    void bind_exit_flag(volatile int * flag);

    /* Get Libfabric version of this specific fabric instance */
    uint32_t get_version() { return this->fabric_version; }

    /* Other control functions */

    /* Set the timeout of the fabric for managed data transfer functions. Has no
     * effect if Libfabric functions are called directly. */
    void set_timeout(tcm_time & timeout);

    /* Peer management functions */
    fi_addr_t add_peer(sockaddr * peer);
    int       remove_peer(fi_addr_t peer);
    int       lookup_peer(fi_addr_t peer, sockaddr * addr, size_t * size);

    /**
     * @brief Attempt to get the underlying CQ FD.
     * @return The file descriptor or a negative error code on error.
     *
     * If the CQ does not support FD wait objects, -ENOTSUP is returned.
     * If the CQ may not currently be waited on, -EAGAIN is returned.
     */
    int get_cq_fd();

    /* Advanced direct resource access functions */
    void *  _get_fi_resource(tcm_fabric_resource resource);
    tcm_tid _get_tid();
};

#endif