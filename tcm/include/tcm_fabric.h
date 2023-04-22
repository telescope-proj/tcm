#ifndef _TCM_FABRIC_H_
#define _TCM_FABRIC_H_

#include <rdma/fi_endpoint.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_tagged.h>
#include <rdma/fabric.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_eq.h>

#include "tcm_time.h"

#define TCM_DEFAULT_FABRIC_VERSION  FI_VERSION(1, 10)

typedef struct {
    void        * ptr;
    uint64_t    len;
    uint64_t    alignment;
} tcm_mem_context;

typedef struct {
    struct fid_ep       * ep;           // Endpoint
    struct fid_fabric   * fabric;       // Top-level fabric
    struct fid_domain   * domain;       // Libfabric domain object
    struct fid_cq       * tx_cq;        // Transmit completion queue
    struct fid_cq       * rx_cq;        // Receive completion queue
    struct fid_av       * av;           // Address vector
    uint32_t            proto;          // Libfabric protocol
    uint32_t            addr_fmt;       // Libfabric address format
    struct fid_mr       * mr;           // Default MR used for messages
    tcm_mem_context     mr_info;        // Metadata for above MR
    void                * src_addr;     // Source address in provider format
    size_t              src_addrlen;    // Source address length
    uint32_t            transport_id;   // TCM Transport ID
    char                prov_name[16];  // Libfabric provider name
} tcm_fabric;

#include "tcm_comm.h"

ssize_t tcm_tsend_fabric(tcm_fabric * fabric, void * buf, size_t len, 
                         struct fid_mr * mr, fi_addr_t peer, uint64_t tag,
                         void * ctx, tcm_time * timing);

ssize_t tcm_send_fabric(tcm_fabric * fabric, void * buf, size_t len,
                        struct fid_mr * mr, fi_addr_t peer, void * ctx,
                        tcm_time * timing);

ssize_t tcm_trecv_fabric(tcm_fabric * fabric, void * buf, size_t len, 
                         struct fid_mr * mr, fi_addr_t peer, uint64_t tag,
                         uint64_t mask, void * ctx, tcm_time * timing);

ssize_t tcm_recv_fabric(tcm_fabric * fabric, void * buf, size_t len,
                        struct fid_mr * mr, fi_addr_t peer, void * ctx,
                        tcm_time * timing);

ssize_t tcm_write_fabric(tcm_fabric * fabric, void * buf, size_t len,
                         struct fid_mr * mr, fi_addr_t peer, 
                         uint64_t rbuf, uint64_t rkey, void * ctx, 
                         tcm_time * timing);

ssize_t tcm_read_fabric(tcm_fabric * fabric, void * buf, size_t len,
                        struct fid_mr * mr, fi_addr_t peer, 
                        uint64_t rbuf, uint64_t rkey, void * ctx, 
                        tcm_time * timing);

ssize_t tcm_exch_fabric(tcm_fabric * fabric,
                        void * send_buf, uint64_t send_buf_size, 
                        struct fid_mr * send_mr,
                        void * recv_buf, uint64_t recv_buf_size,
                        struct fid_mr * recv_mr,
                        fi_addr_t peer, tcm_time * timing,
                        struct fi_cq_err_entry * err);

int tcm_setup_fabric(uint32_t version,
                     uint64_t flags, struct fi_info * hints, 
                     tcm_fabric * fabric_out);

int tcm_create_mr(tcm_fabric * fabric, size_t size, size_t alignment, 
                  struct fid_mr ** mr);

void tcm_destroy_fabric(tcm_fabric * fabric, int free_struct);

int tcm_serialize_addr(void * addr, int addr_len, uint32_t addr_fmt,
                       void * out_buf, int * buf_size);

ssize_t tcm_poll_fabric(struct fid_cq * cq,
                        struct fi_cq_data_entry * data, 
                        struct fi_cq_err_entry * err,
                        tcm_time * timeout);

ssize_t tcm_wait_fabric(struct fid_cq * cq, tcm_time * timing,
                        struct fi_cq_err_entry * err);

ssize_t tcm_send_dummy_message(tcm_fabric * fabric, fi_addr_t peer, 
                            tcm_time * timing);

ssize_t tcm_exch_fabric_rev(tcm_fabric * fabric,
                            void * send_buf, uint64_t send_buf_size, 
                            struct fid_mr * send_mr,
                            void * recv_buf, uint64_t recv_buf_size,
                            struct fid_mr * recv_mr,
                            fi_addr_t peer, tcm_time * timing,
                            struct fi_cq_err_entry * err);

#endif