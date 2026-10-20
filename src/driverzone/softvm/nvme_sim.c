/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * WS6 softvm backend: simulated NVMe 1.4 controller behind the driver RPC
 * contract. Hardware-free; CI only. It is NOT an x86 interpreter and makes no
 * claim about real NVMe drivers: the "driver" is the RPC client (the test).
 *
 * Supported: CAP/VS/INTMS/INTMC/CC/CSTS/AQA/ASQ/ACQ, SQ0/CQ0 + one IO pair
 * (qid 1), admin Identify (CNS 0/1), Create IO CQ/SQ, Set Features(queues),
 * IO Read/Write with PRP1(+PRP2) page-aligned, 4 KiB pages, 512 B blocks.
 * Anything else completes with an error status (never faked success).
 * All queue/data access goes through dz_dma_*, so unregistered memory fails.
 */
#include "../driverzone.h"

#include <stdlib.h>
#include <string.h>

#define BAR0_SIZE 0x4000u
#define REG_CAP 0x00u
#define REG_VS 0x08u
#define REG_INTMS 0x0Cu
#define REG_INTMC 0x10u
#define REG_CC 0x14u
#define REG_CSTS 0x1Cu
#define REG_AQA 0x24u
#define REG_ASQ 0x28u
#define REG_ACQ 0x30u
#define REG_DB 0x1000u

#define CSTS_RDY 1u
#define CSTS_CFS 2u

#define BLOCK_SIZE 512u
#define NBLOCKS 64u
#define PAGE 4096u
#define SQE_SIZE 64u
#define CQE_SIZE 16u

/* generic command status codes */
#define SC_OK 0x00u
#define SC_INVALID_OPCODE 0x01u
#define SC_INVALID_FIELD 0x02u
#define SC_DATA_XFER_ERROR 0x04u
#define SC_LBA_RANGE 0x80u /* NVM command set: LBA out of range */

struct queue {
  uint64_t base;
  uint32_t size;
  uint32_t head;
  uint32_t tail;
  uint32_t phase; /* CQ only */
  uint32_t cqid;  /* SQ only */
  uint32_t iv;    /* CQ only */
  int ien;        /* CQ only */
  int valid;
};

struct dz_nvme_sim {
  uint32_t cc, csts, aqa, intms;
  uint64_t asq, acq;
  struct queue sq[2], cq[2];
  uint32_t irq_pending;
  uint8_t media[NBLOCKS * BLOCK_SIZE];
};

static void media_fill(struct dz_nvme_sim *s)
{
  uint32_t lba, i;
  for (lba = 0; lba < NBLOCKS; ++lba) {
    for (i = 0; i < BLOCK_SIZE; ++i) {
      s->media[lba * BLOCK_SIZE + i] = (uint8_t)(lba * 31u + i);
    }
  }
}

struct dz_nvme_sim *dz_softvm_nvme_create(void)
{
  struct dz_nvme_sim *s = (struct dz_nvme_sim *)calloc(1, sizeof(*s));
  if (s != NULL) {
    media_fill(s);
  }
  return s;
}

void dz_softvm_nvme_destroy(struct dz_nvme_sim *s) { free(s); }

static void ctrl_reset(struct dz_nvme_sim *s)
{
  s->csts = 0;
  s->irq_pending = 0;
  memset(s->sq, 0, sizeof(s->sq));
  memset(s->cq, 0, sizeof(s->cq));
}

/* ---- completion + interrupt ------------------------------------------ */

static void fatal(struct dz *dz, struct dz_nvme_sim *s, const char *why)
{
  s->csts |= CSTS_CFS;
  dz_logf(dz, "nvme: controller fatal: %s", why);
}

static int post_cqe(struct dz *dz, struct dz_nvme_sim *s, uint32_t qid,
                    uint32_t sqhead, uint16_t cid, uint32_t sc, uint32_t result)
{
  struct queue *cq = &s->cq[qid];
  uint8_t cqe[CQE_SIZE];
  dz_wr32(cqe, result);
  dz_wr32(cqe + 4, 0);
  dz_wr32(cqe + 8, (sqhead & 0xFFFFu) | (qid << 16));
  dz_wr32(cqe + 12, (uint32_t)cid | (cq->phase << 16) | (sc << 17));
  if (dz_dma_write(dz, cq->base + (uint64_t)cq->tail * CQE_SIZE, cqe,
                   CQE_SIZE) != 0) {
    fatal(dz, s, "CQ memory not DMA-registered");
    return -1;
  }
  cq->tail++;
  if (cq->tail == cq->size) {
    cq->tail = 0;
    cq->phase ^= 1u;
  }
  if (cq->ien && !(s->intms & (1u << cq->iv))) {
    s->irq_pending |= 1u << cq->iv;
  }
  return 0;
}

/* ---- data transfer via PRP1/PRP2 -------------------------------------- */

static int prp_xfer(struct dz *dz, uint64_t prp1, uint64_t prp2, size_t len,
                    uint8_t *buf, int to_host)
{
  size_t first = len < PAGE ? len : PAGE;
  if (len == 0 || len > 2u * PAGE || (prp1 & (PAGE - 1u)) != 0 ||
      (len > PAGE && (prp2 & (PAGE - 1u)) != 0)) {
    return 1; /* invalid field */
  }
  if (to_host) {
    if (dz_dma_write(dz, prp1, buf, first) != 0) {
      return 2;
    }
    if (len > PAGE && dz_dma_write(dz, prp2, buf + PAGE, len - PAGE) != 0) {
      return 2;
    }
  } else {
    if (dz_dma_read(dz, prp1, buf, first) != 0) {
      return 2;
    }
    if (len > PAGE && dz_dma_read(dz, prp2, buf + PAGE, len - PAGE) != 0) {
      return 2;
    }
  }
  return 0;
}

static uint32_t xfer_sc(int rc) { return rc == 1 ? SC_INVALID_FIELD : SC_DATA_XFER_ERROR; }

/* ---- command execution ------------------------------------------------ */

static uint32_t cmd_identify(struct dz *dz, const uint8_t *sqe)
{
  uint8_t page[PAGE];
  uint32_t cns = dz_rd32(sqe + 40) & 0xFFu;
  uint64_t prp1 = dz_rd64(sqe + 24), prp2 = dz_rd64(sqe + 32);
  int rc;
  memset(page, 0, sizeof(page));
  if (cns == 1) {
    dz_wr16(page + 0, 0x1B36);
    memset(page + 4, ' ', 20);
    memcpy(page + 4, "I1N1SIM0001", 11);
    memset(page + 24, ' ', 40);
    memcpy(page + 24, "i1n1 softvm NVMe simulator", 26);
    memset(page + 64, ' ', 8);
    memcpy(page + 64, "0.1", 3);
    page[77] = 0; /* MDTS 0: unlimited (sim limits to 2 pages) */
    dz_wr32(page + 516, 1); /* NN */
  } else if (cns == 0 && dz_rd32(sqe + 4) == 1) {
    dz_wr64(page + 0, NBLOCKS);
    dz_wr64(page + 8, NBLOCKS);
    dz_wr64(page + 16, NBLOCKS);
    page[25] = 0;   /* NLBAF: one format */
    page[26] = 0;   /* FLBAS: format 0 */
    page[128 + 2] = 9; /* LBAF0.LBADS = 2^9 */
  } else {
    return SC_INVALID_FIELD;
  }
  rc = prp_xfer(dz, prp1, prp2, sizeof(page), page, 1);
  return rc == 0 ? SC_OK : xfer_sc(rc);
}

static uint32_t cmd_admin(struct dz *dz, struct dz_nvme_sim *s,
                          const uint8_t *sqe, uint32_t *result)
{
  uint32_t cdw10 = dz_rd32(sqe + 40), cdw11 = dz_rd32(sqe + 44);
  uint64_t prp1 = dz_rd64(sqe + 24);
  uint32_t qid = cdw10 & 0xFFFFu, qsize = (cdw10 >> 16) + 1u;
  *result = 0;
  switch (sqe[0]) {
  case 0x06:
    return cmd_identify(dz, sqe);
  case 0x05: /* Create IO CQ */
    if (qid != 1 || s->cq[1].valid || qsize < 2 || qsize > 64 || !(cdw11 & 1u) ||
        (prp1 & (PAGE - 1u)) != 0) {
      return SC_INVALID_FIELD;
    }
    s->cq[1] = (struct queue){.base = prp1, .size = qsize, .phase = 1,
                              .iv = cdw11 >> 16, .ien = (int)((cdw11 >> 1) & 1u),
                              .valid = 1};
    if (s->cq[1].iv > 31u) {
      s->cq[1].valid = 0;
      return SC_INVALID_FIELD;
    }
    return SC_OK;
  case 0x01: /* Create IO SQ */
    if (qid != 1 || s->sq[1].valid || qsize < 2 || qsize > 64 || !(cdw11 & 1u) ||
        (cdw11 >> 16) != 1u || !s->cq[1].valid || (prp1 & (PAGE - 1u)) != 0) {
      return SC_INVALID_FIELD;
    }
    s->sq[1] = (struct queue){.base = prp1, .size = qsize, .cqid = 1, .valid = 1};
    return SC_OK;
  case 0x09: /* Set Features */
    if ((cdw10 & 0xFFu) == 7u) { /* number of queues: grant one pair */
      *result = 0;
      return SC_OK;
    }
    return SC_INVALID_FIELD;
  default:
    return SC_INVALID_OPCODE;
  }
}

static uint32_t cmd_io(struct dz *dz, struct dz_nvme_sim *s, const uint8_t *sqe)
{
  uint64_t slba = dz_rd64(sqe + 40);
  uint32_t nlb = (dz_rd32(sqe + 48) & 0xFFFFu) + 1u;
  uint64_t prp1 = dz_rd64(sqe + 24), prp2 = dz_rd64(sqe + 32);
  int rc;
  if (sqe[0] != 0x01 && sqe[0] != 0x02) { /* Write / Read only */
    return SC_INVALID_OPCODE;
  }
  if (dz_rd32(sqe + 4) != 1u) {
    return SC_INVALID_FIELD;
  }
  if (slba >= NBLOCKS || nlb > NBLOCKS - slba) {
    return SC_LBA_RANGE;
  }
  if (sqe[0] == 0x02) {
    rc = prp_xfer(dz, prp1, prp2, (size_t)nlb * BLOCK_SIZE,
                  s->media + slba * BLOCK_SIZE, 1);
  } else {
    uint8_t tmp[2 * PAGE];
    rc = prp_xfer(dz, prp1, prp2, (size_t)nlb * BLOCK_SIZE, tmp, 0);
    if (rc == 0) {
      memcpy(s->media + slba * BLOCK_SIZE, tmp, (size_t)nlb * BLOCK_SIZE);
    }
  }
  return rc == 0 ? SC_OK : xfer_sc(rc);
}

static void run_sq(struct dz *dz, struct dz_nvme_sim *s, uint32_t qid)
{
  struct queue *sq = &s->sq[qid];
  struct queue *cq = &s->cq[qid];
  while (sq->head != sq->tail && !(s->csts & CSTS_CFS)) {
    uint8_t sqe[SQE_SIZE];
    uint32_t sc, result = 0;
    uint32_t next_cq = (cq->tail + 1u) % cq->size;
    if (next_cq == cq->head) {
      dz_logf(dz, "nvme: CQ%u full, stalling", qid);
      return;
    }
    if (dz_dma_read(dz, sq->base + (uint64_t)sq->head * SQE_SIZE, sqe,
                    SQE_SIZE) != 0) {
      fatal(dz, s, "SQ memory not DMA-registered");
      return;
    }
    sc = qid == 0 ? cmd_admin(dz, s, sqe, &result) : cmd_io(dz, s, sqe);
    sq->head = (sq->head + 1u) % sq->size;
    if (post_cqe(dz, s, qid, sq->head, (uint16_t)(dz_rd32(sqe) >> 16), sc,
                 result) != 0) {
      return;
    }
  }
}

/* ---- register file ---------------------------------------------------- */

static int reg_read32(struct dz_nvme_sim *s, uint32_t off, uint32_t *v)
{
  switch (off) {
  case REG_CAP: *v = 63u | (1u << 16) | (1u << 24); return 0; /* MQES,CQR,TO */
  case REG_CAP + 4: *v = 1u << 5; return 0; /* CSS bit37 = NVM */
  case REG_VS: *v = 0x00010400u; return 0;
  case REG_INTMS:
  case REG_INTMC: *v = s->intms; return 0;
  case REG_CC: *v = s->cc; return 0;
  case REG_CSTS: *v = s->csts; return 0;
  case REG_AQA: *v = s->aqa; return 0;
  case REG_ASQ: *v = (uint32_t)s->asq; return 0;
  case REG_ASQ + 4: *v = (uint32_t)(s->asq >> 32); return 0;
  case REG_ACQ: *v = (uint32_t)s->acq; return 0;
  case REG_ACQ + 4: *v = (uint32_t)(s->acq >> 32); return 0;
  default: return -1;
  }
}

static void cc_write(struct dz *dz, struct dz_nvme_sim *s, uint32_t v)
{
  uint32_t was = s->cc & 1u;
  s->cc = v;
  if (!was && (v & 1u)) {
    uint32_t asqs = (s->aqa & 0xFFFu) + 1u, acqs = ((s->aqa >> 16) & 0xFFFu) + 1u;
    if (((v >> 7) & 0xFu) != 0 || asqs < 2 || acqs < 2 || asqs > 64 ||
        acqs > 64 || s->asq == 0 || s->acq == 0 || (s->asq & (PAGE - 1u)) ||
        (s->acq & (PAGE - 1u))) {
      fatal(dz, s, "bad CC.EN configuration (MPS/AQA/ASQ/ACQ)");
      return;
    }
    s->sq[0] = (struct queue){.base = s->asq, .size = asqs, .valid = 1};
    s->cq[0] = (struct queue){.base = s->acq, .size = acqs, .phase = 1,
                              .iv = 0, .ien = 1, .valid = 1};
    s->csts |= CSTS_RDY;
  } else if (was && !(v & 1u)) {
    ctrl_reset(s);
  }
}

static int32_t doorbell_write(struct dz *dz, struct dz_nvme_sim *s,
                              uint32_t off, uint32_t v)
{
  uint32_t idx = (off - REG_DB) / 4u;
  uint32_t qid = idx / 2u;
  if (!(s->csts & CSTS_RDY) || qid > 1u || (off & 3u)) {
    dz_logf(dz, "nvme: doorbell 0x%x while not ready / bad queue", off);
    return I1N1_DRV_STATUS_BAD_REQUEST;
  }
  if (idx & 1u) { /* CQ head */
    struct queue *cq = &s->cq[qid];
    if (!cq->valid || v >= cq->size) {
      dz_logf(dz, "nvme: bad CQ%u head %u", qid, v);
      return I1N1_DRV_STATUS_BAD_REQUEST;
    }
    cq->head = v;
    return I1N1_DRV_STATUS_OK;
  }
  if (!s->sq[qid].valid || v >= s->sq[qid].size) {
    dz_logf(dz, "nvme: bad SQ%u tail %u", qid, v);
    return I1N1_DRV_STATUS_BAD_REQUEST;
  }
  s->sq[qid].tail = v;
  run_sq(dz, s, qid);
  return I1N1_DRV_STATUS_OK;
}

static int32_t reg_write32(struct dz *dz, struct dz_nvme_sim *s, uint32_t off,
                           uint32_t v)
{
  if (off >= REG_DB) {
    return doorbell_write(dz, s, off, v);
  }
  switch (off) {
  case REG_INTMS: s->intms |= v; return 0;
  case REG_INTMC: s->intms &= ~v; return 0;
  case REG_CC: cc_write(dz, s, v); return 0;
  case REG_AQA: if (s->cc & 1u) goto ro; s->aqa = v; return 0;
  case REG_ASQ: if (s->cc & 1u) goto ro; s->asq = (s->asq & ~0xFFFFFFFFull) | v; return 0;
  case REG_ASQ + 4: if (s->cc & 1u) goto ro; s->asq = (s->asq & 0xFFFFFFFFull) | ((uint64_t)v << 32); return 0;
  case REG_ACQ: if (s->cc & 1u) goto ro; s->acq = (s->acq & ~0xFFFFFFFFull) | v; return 0;
  case REG_ACQ + 4: if (s->cc & 1u) goto ro; s->acq = (s->acq & 0xFFFFFFFFull) | ((uint64_t)v << 32); return 0;
  default:
    dz_logf(dz, "nvme: write to read-only/unknown reg 0x%x", off);
    return I1N1_DRV_STATUS_BAD_REQUEST;
  }
ro:
  dz_logf(dz, "nvme: admin queue register 0x%x written while enabled", off);
  return I1N1_DRV_STATUS_BAD_REQUEST;
}

static int32_t mmio(struct dz *dz, struct dz_nvme_sim *s, const struct dz_op *op,
                    int is_write)
{
  uint32_t bar, off;
  uint64_t off64;
  if (op->payload_size != 16u || op->shm == NULL) {
    return I1N1_DRV_STATUS_BAD_PAYLOAD;
  }
  bar = dz_rd32(op->payload);
  off64 = dz_rd64(op->payload + 8);
  if (dz_rd32(op->payload + 4) != 0) {
    return I1N1_DRV_STATUS_BAD_PAYLOAD;
  }
  if (bar != 0 || off64 > BAR0_SIZE || (op->shm_len != 4 && op->shm_len != 8) ||
      off64 + op->shm_len > BAR0_SIZE || (off64 & (op->shm_len - 1u)) != 0 ||
      (op->shm_len == 8 && off64 >= REG_DB)) {
    dz_logf(dz, "nvme: MMIO denied bar=%u off=0x%llx width=%llu", bar,
            (unsigned long long)off64, (unsigned long long)op->shm_len);
    return I1N1_DRV_STATUS_BAD_RANGE;
  }
  off = (uint32_t)off64;
  if (!is_write) {
    uint32_t lo = 0, hi = 0;
    if (off >= REG_DB || reg_read32(s, off, &lo) != 0 ||
        (op->shm_len == 8 && reg_read32(s, off + 4, &hi) != 0)) {
      dz_logf(dz, "nvme: MMIO read of unmodelled reg 0x%x", off);
      return I1N1_DRV_STATUS_BAD_RANGE; /* no fake zero */
    }
    dz_wr32(op->shm, lo);
    if (op->shm_len == 8) {
      dz_wr32(op->shm + 4, hi);
    }
    return I1N1_DRV_STATUS_OK;
  } else {
    int32_t st = reg_write32(dz, s, off, dz_rd32(op->shm));
    if (st == 0 && op->shm_len == 8) {
      st = reg_write32(dz, s, off + 4, dz_rd32(op->shm + 4));
    }
    return st;
  }
}

static int32_t sim_op(struct dz *dz, void *ctx, const struct dz_op *op,
                      struct dz_out *out)
{
  struct dz_nvme_sim *s = (struct dz_nvme_sim *)ctx;
  switch (op->opcode) {
  case I1N1_DRV_OP_PROBE:
    dz_wr16(out->payload + 0, 0x1B36);
    dz_wr16(out->payload + 2, 0x0010);
    dz_wr32(out->payload + 4, 0x010802u);
    dz_wr32(out->payload + 8, BAR0_SIZE);
    dz_wr32(out->payload + 12, 1u);
    out->payload_size = 16;
    return I1N1_DRV_STATUS_OK;
  case I1N1_DRV_OP_INFO:
    dz_wr32(out->payload + 0, 1u);
    dz_wr32(out->payload + 4, BLOCK_SIZE);
    dz_wr64(out->payload + 8, NBLOCKS);
    memcpy(out->payload + 16, "softvm-nvme-sim", 15);
    out->payload_size = 32;
    return I1N1_DRV_STATUS_OK;
  case I1N1_DRV_OP_MMIO_READ:
    return mmio(dz, s, op, 0);
  case I1N1_DRV_OP_MMIO_WRITE:
    return mmio(dz, s, op, 1);
  case I1N1_DRV_OP_IRQ_WAIT: {
    uint32_t v;
    if (op->payload_size != 4u) {
      return I1N1_DRV_STATUS_BAD_PAYLOAD;
    }
    if (s->irq_pending == 0) {
      return I1N1_DRV_STATUS_BUSY; /* timeout; softvm never blocks */
    }
    for (v = 0; !(s->irq_pending & (1u << v)); ++v) {
    }
    dz_wr32(out->payload, v);
    out->payload_size = 4;
    return I1N1_DRV_STATUS_OK;
  }
  case I1N1_DRV_OP_IRQ_ACK: {
    uint32_t v;
    if (op->payload_size != 4u) {
      return I1N1_DRV_STATUS_BAD_PAYLOAD;
    }
    v = dz_rd32(op->payload);
    if (v > 31u || !(s->irq_pending & (1u << v))) {
      dz_logf(dz, "nvme: IRQ_ACK for vector %u not pending", v);
      return I1N1_DRV_STATUS_BAD_REQUEST;
    }
    s->irq_pending &= ~(1u << v);
    return I1N1_DRV_STATUS_OK;
  }
  case I1N1_DRV_OP_RESET:
    ctrl_reset(s);
    s->cc = 0;
    s->aqa = 0;
    s->asq = 0;
    s->acq = 0;
    s->intms = 0;
    return I1N1_DRV_STATUS_OK;
  default:
    dz_logf(dz, "nvme: op %u not handled by backend", (unsigned)op->opcode);
    return I1N1_DRV_STATUS_UNSUPPORTED;
  }
}

void dz_softvm_backend_init(struct dz_backend *out, struct dz_nvme_sim *sim)
{
  out->name = "softvm";
  out->unsupported_reason = NULL;
  out->device_id = DZ_DEVICE_NVME_SIM;
  out->ctx = sim;
  out->op = sim_op;
}
