/* SPDX-License-Identifier: GPL-2.0-only */
/* WS6: C7 driver RPC <-> backend shim. Unregistered DMA is refused. */
#include "driverzone.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

void dz_init(struct dz *dz, const struct dz_backend *backend, void *shm,
             uint64_t shm_size)
{
  memset(dz, 0, sizeof(*dz));
  dz->backend = backend;
  dz->shm = (uint8_t *)shm;
  dz->shm_size = shm_size;
}

void dz_signal_doorbell(struct dz *dz, uint32_t token)
{
  dz->doorbell_pending = 1;
  dz->doorbell_token = token;
}

void dz_logf(struct dz *dz, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  (void)vsnprintf(dz->log[dz->log_total % DZ_LOG_LINES], DZ_LOG_WIDTH, fmt, ap);
  va_end(ap);
  dz->log_total++;
}

const char *dz_log_line(const struct dz *dz, unsigned int n)
{
  if (n >= dz->log_total || n >= DZ_LOG_LINES) {
    return NULL;
  }
  return dz->log[(dz->log_total - 1u - n) % DZ_LOG_LINES];
}

static int dma_covered(const struct dz *dz, uint64_t addr, size_t len)
{
  unsigned int i;
  if (len == 0) {
    return 0;
  }
  for (i = 0; i < dz->dma_count; ++i) {
    const struct dz_dma_range *r = &dz->dma[i];
    if (addr >= r->offset && addr - r->offset <= r->length &&
        len <= r->length - (addr - r->offset)) {
      return 1;
    }
  }
  return 0;
}

int dz_dma_read(struct dz *dz, uint64_t addr, void *dst, size_t len)
{
  if (!dma_covered(dz, addr, len)) {
    dz_logf(dz, "DMA read denied: unregistered 0x%llx+%zu",
            (unsigned long long)addr, len);
    return -1;
  }
  memcpy(dst, dz->shm + addr, len);
  return 0;
}

int dz_dma_write(struct dz *dz, uint64_t addr, const void *src, size_t len)
{
  if (!dma_covered(dz, addr, len)) {
    dz_logf(dz, "DMA write denied: unregistered 0x%llx+%zu",
            (unsigned long long)addr, len);
    return -1;
  }
  memcpy(dz->shm + addr, src, len);
  return 0;
}

static int32_t dma_map(struct dz *dz, const struct i1n1_drv_header *h)
{
  unsigned int i;
  for (i = 0; i < dz->dma_count; ++i) {
    const struct dz_dma_range *r = &dz->dma[i];
    if (h->shm_offset < r->offset + r->length &&
        r->offset < h->shm_offset + h->shm_length) {
      dz_logf(dz, "DMA_MAP rejected: overlaps 0x%llx",
              (unsigned long long)r->offset);
      return I1N1_DRV_STATUS_BAD_REQUEST;
    }
  }
  if (dz->dma_count >= DZ_MAX_DMA_RANGES) {
    dz_logf(dz, "DMA_MAP rejected: table full");
    return I1N1_DRV_STATUS_BUSY;
  }
  dz->dma[dz->dma_count].offset = h->shm_offset;
  dz->dma[dz->dma_count].length = h->shm_length;
  dz->dma_count++;
  return I1N1_DRV_STATUS_OK;
}

static int32_t dma_unmap(struct dz *dz, const struct i1n1_drv_header *h)
{
  unsigned int i;
  for (i = 0; i < dz->dma_count; ++i) {
    if (dz->dma[i].offset == h->shm_offset &&
        dz->dma[i].length == h->shm_length) {
      dz->dma[i] = dz->dma[dz->dma_count - 1u];
      dz->dma_count--;
      return I1N1_DRV_STATUS_OK;
    }
  }
  dz_logf(dz, "DMA_UNMAP rejected: no exact range 0x%llx+%llu",
          (unsigned long long)h->shm_offset, (unsigned long long)h->shm_length);
  return I1N1_DRV_STATUS_BAD_RANGE;
}

static int needs_shm(uint16_t op)
{
  return op == I1N1_DRV_OP_MMIO_READ || op == I1N1_DRV_OP_MMIO_WRITE ||
         op == I1N1_DRV_OP_DMA_MAP || op == I1N1_DRV_OP_DMA_UNMAP;
}

enum i1n1_drv_result dz_handle(struct dz *dz, const void *request,
                               size_t request_size, void *response,
                               size_t response_capacity, size_t *response_size)
{
  struct i1n1_drv_view view;
  struct i1n1_drv_header rh;
  struct dz_out out;
  struct dz_op op;
  enum i1n1_drv_result r;
  int32_t status;
  const char *reason;

  if (response_size == NULL || response == NULL) {
    return I1N1_DRV_ERR_ARGUMENT;
  }
  *response_size = 0;
  r = i1n1_drv_parse(request, request_size, &view);
  if (r != I1N1_DRV_OK) {
    dz_logf(dz, "reject message: %s", i1n1_drv_result_string(r));
    return r;
  }
  if (view.header.flags != I1N1_DRV_FLAG_REQUEST) {
    dz_logf(dz, "reject message: response flag on request path");
    return I1N1_DRV_ERR_FLAGS;
  }
  memset(&out, 0, sizeof(out));
  memset(&op, 0, sizeof(op));
  op.opcode = view.header.opcode;
  op.device_id = view.header.device_id;
  op.payload = view.payload;
  op.payload_size = view.payload_size;

  if (view.header.request_id == 0) {
    status = I1N1_DRV_STATUS_BAD_REQUEST;
    dz_logf(dz, "request_id 0 rejected");
  } else if ((reason = dz->backend->unsupported_reason) != NULL) {
    size_t n = strlen(reason);
    if (n > DZ_OUT_MAX) {
      n = DZ_OUT_MAX;
    }
    memcpy(out.payload, reason, n);
    out.payload_size = n;
    status = I1N1_DRV_STATUS_UNSUPPORTED;
    dz_logf(dz, "op %u stop: %s", (unsigned)op.opcode, reason);
  } else if (op.device_id != (dz->backend->device_id != 0
                                  ? dz->backend->device_id
                                  : DZ_DEVICE_NVME_SIM)) {
    status = I1N1_DRV_STATUS_NO_DEVICE;
    dz_logf(dz, "op %u: no device %llu", (unsigned)op.opcode,
            (unsigned long long)op.device_id);
  } else if (needs_shm(op.opcode) &&
             i1n1_drv_check_shm(&view.header, dz->shm_size) != I1N1_DRV_OK) {
    status = I1N1_DRV_STATUS_BAD_RANGE;
    dz_logf(dz, "op %u: shm range 0x%llx+%llu outside window",
            (unsigned)op.opcode, (unsigned long long)view.header.shm_offset,
            (unsigned long long)view.header.shm_length);
  } else {
    if (needs_shm(op.opcode)) {
      op.shm = dz->shm + view.header.shm_offset;
      op.shm_len = view.header.shm_length;
    }
    switch (op.opcode) {
    case I1N1_DRV_OP_DMA_MAP:
      status = dma_map(dz, &view.header);
      break;
    case I1N1_DRV_OP_DMA_UNMAP:
      status = dma_unmap(dz, &view.header);
      break;
    case I1N1_DRV_OP_DOORBELL:
      if (!dz->doorbell_pending || view.header.doorbell == 0 ||
          i1n1_drv_doorbell_check(dz->doorbell_token, &view.header) !=
              I1N1_DRV_OK) {
        status = I1N1_DRV_STATUS_BAD_REQUEST;
        dz_logf(dz, "doorbell token mismatch or no signal");
      } else {
        status = I1N1_DRV_STATUS_OK;
      }
      dz->doorbell_pending = 0;
      break;
    default:
      status = dz->backend->op(dz, dz->backend->ctx, &op, &out);
      break;
    }
  }

  rh = view.header;
  rh.flags = I1N1_DRV_FLAG_RESPONSE;
  rh.status = status;
  rh.total_size = (uint32_t)(I1N1_DRV_HEADER_SIZE + out.payload_size);
  if (response_capacity < rh.total_size) {
    return I1N1_DRV_ERR_TRUNCATED;
  }
  r = i1n1_drv_encode(&rh, response, response_capacity);
  if (r != I1N1_DRV_OK) {
    return r;
  }
  memcpy((uint8_t *)response + I1N1_DRV_HEADER_SIZE, out.payload,
         out.payload_size);
  *response_size = rh.total_size;
  return I1N1_DRV_OK;
}
