/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * WS6 driver zone: RPC shim + backend interface.
 *
 * dz_handle() implements the C7 driver RPC contract (include/i1n1/driver_rpc.h,
 * owned by WS5) on top of a pluggable backend. Payload conventions below are
 * WS6-local v0 and documented in docs/driver-matrix.md; the wire header is WS5's.
 *
 * Backends: softvm (simulated NVMe, hardware-free) and vmx (stub that always
 * stops with a deterministic "unsupported" reason; never fakes success).
 *
 * DMA model: IOVA == offset into the shared window. Only ranges registered via
 * DMA_MAP are reachable by the device; everything else fails and is logged.
 */
#ifndef I1N1_DRIVERZONE_H
#define I1N1_DRIVERZONE_H

#include "i1n1/driver_rpc.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DZ_DEVICE_NVME_SIM 1u
#define DZ_DEVICE_XHCI_SIM 2u
#define DZ_MAX_DMA_RANGES 16u
#define DZ_OUT_MAX 64u
#define DZ_LOG_LINES 32u
#define DZ_LOG_WIDTH 120u

#define DZ_UNSUPPORTED_NO_VTX "unsupported: no VT-x on this host"

/* Payload layouts (little-endian):
 *  PROBE resp (16): u16 vendor, u16 device, u32 class(24b), u32 bar0_size,
 *                   u32 flags (bit0 = simulated)
 *  MMIO_*  req (16): u32 bar, u32 zero, u64 offset. Width = header.shm_length
 *                   (4 or 8); value bytes live at header.shm_offset in shm.
 *  DMA_MAP/UNMAP:   range = header.shm_offset/shm_length (UNMAP: exact match)
 *  IRQ_WAIT req (4): u32 timeout_ms (softvm never blocks); resp (4): u32 vector;
 *                   nothing pending -> STATUS_BUSY (timeout)
 *  IRQ_ACK req (4):  u32 vector
 *  DOORBELL:        header.doorbell must equal the token last passed to
 *                   dz_signal_doorbell(); consumed once
 *  INFO resp (32):  u32 info_version(1), u32 block_size, u64 nblocks, char name[16]
 *  unsupported:     response status UNSUPPORTED, payload = ASCII reason */

struct dz;

struct dz_op {
  uint16_t opcode;
  uint64_t device_id;
  const uint8_t *payload;
  size_t payload_size;
  uint8_t *shm; /* header range inside window, or NULL */
  uint64_t shm_len;
};

struct dz_out {
  uint8_t payload[DZ_OUT_MAX];
  size_t payload_size;
};

struct dz_backend {
  const char *name;
  /* Non-NULL: every valid request returns STATUS_UNSUPPORTED with this text. */
  const char *unsupported_reason;
  void *ctx;
  /* PROBE, MMIO_READ/WRITE, IRQ_WAIT/ACK, RESET, INFO. Returns dispatch status. */
  int32_t (*op)(struct dz *dz, void *ctx, const struct dz_op *op,
                struct dz_out *out);
  /* device_id this backend serves; 0 means DZ_DEVICE_NVME_SIM (legacy). */
  uint64_t device_id;
};

struct dz_dma_range {
  uint64_t offset;
  uint64_t length;
};

struct dz {
  const struct dz_backend *backend;
  uint8_t *shm;
  uint64_t shm_size;
  struct dz_dma_range dma[DZ_MAX_DMA_RANGES];
  unsigned int dma_count;
  int doorbell_pending;
  uint32_t doorbell_token;
  char log[DZ_LOG_LINES][DZ_LOG_WIDTH];
  unsigned int log_total;
};

void dz_init(struct dz *dz, const struct dz_backend *backend, void *shm,
             uint64_t shm_size);

/* Out-of-band doorbell signal carrying a token (see i1n1_drv_doorbell_signal). */
void dz_signal_doorbell(struct dz *dz, uint32_t token);

/* Handle one request message. On I1N1_DRV_OK a response was written to
 * response[0..*response_size). Codec failures (bad magic, unknown opcode, ...)
 * return the codec result and produce no response. */
enum i1n1_drv_result dz_handle(struct dz *dz, const void *request,
                               size_t request_size, void *response,
                               size_t response_capacity, size_t *response_size);

/* Device-side DMA. Fails (returns nonzero, logs) unless [addr, addr+len) lies
 * wholly inside one registered range. */
int dz_dma_read(struct dz *dz, uint64_t addr, void *dst, size_t len);
int dz_dma_write(struct dz *dz, uint64_t addr, const void *src, size_t len);

void dz_logf(struct dz *dz, const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 2, 3)))
#endif
    ;
const char *dz_log_line(const struct dz *dz, unsigned int index_from_newest);

/* little-endian helpers */
static inline uint32_t dz_rd32(const uint8_t *p)
{
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}
static inline uint64_t dz_rd64(const uint8_t *p)
{
  return (uint64_t)dz_rd32(p) | ((uint64_t)dz_rd32(p + 4) << 32);
}
static inline void dz_wr16(uint8_t *p, uint16_t v)
{
  p[0] = (uint8_t)v;
  p[1] = (uint8_t)(v >> 8);
}
static inline void dz_wr32(uint8_t *p, uint32_t v)
{
  p[0] = (uint8_t)v;
  p[1] = (uint8_t)(v >> 8);
  p[2] = (uint8_t)(v >> 16);
  p[3] = (uint8_t)(v >> 24);
}
static inline void dz_wr64(uint8_t *p, uint64_t v)
{
  dz_wr32(p, (uint32_t)v);
  dz_wr32(p + 4, (uint32_t)(v >> 32));
}

/* Backends. */
const struct dz_backend *dz_vmx_backend(void);

struct dz_nvme_sim;
struct dz_nvme_sim *dz_softvm_nvme_create(void);
void dz_softvm_nvme_destroy(struct dz_nvme_sim *sim);
void dz_softvm_backend_init(struct dz_backend *out, struct dz_nvme_sim *sim);

/* Simulated xHCI 1.2 controller (device id DZ_DEVICE_XHCI_SIM). */
struct dz_xhci_sim;
struct dz_xhci_sim *dz_softvm_xhci_create(void);
void dz_softvm_xhci_destroy(struct dz_xhci_sim *sim);
void dz_softvm_xhci_backend_init(struct dz_backend *out, struct dz_xhci_sim *sim);

#ifdef __cplusplus
}
#endif

#endif /* I1N1_DRIVERZONE_H */
