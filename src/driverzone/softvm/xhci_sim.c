/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * WS6 softvm backend: simulated xHCI 1.2 host controller behind the driver RPC
 * contract (device id DZ_DEVICE_XHCI_SIM). Hardware-free; CI only. It is NOT an
 * x86 interpreter and makes no claim about real xHCI drivers or controllers:
 * the "driver" is the RPC client (the test).
 *
 * Modelled (offsets per xHCI 1.2 section 5; 32-byte contexts, CSZ=0):
 *   capability regs, operational regs (USBCMD/USBSTS/PAGESIZE/DNCTRL/CRCR/
 *   DCBAAP/CONFIG), 2 root-hub ports (port 1 has a high-speed device attached,
 *   port 2 is empty), interrupter 0 (IMAN/IMOD/ERSTSZ/ERSTBA/ERDP, one ERST
 *   segment), doorbells 0..8.
 *   Command ring: Link, No-Op, Enable Slot, Address Device, Configure Endpoint.
 *   Transfer ring (EP0 only): Link, Setup, Data, Status; the attached device
 *   answers GET_DESCRIPTOR(DEVICE) only.
 *   Events: Command Completion, Port Status Change, Transfer.
 *   Interrupt: MSI vector 0 on IMAN.IP 0->1 when USBCMD.INTE && IMAN.IE.
 *
 * Failure policy (never a faked success):
 *   - unmodelled register / width            -> BAD_RANGE (reads), BAD_REQUEST (writes)
 *   - valid-per-spec but unmodelled TRB type -> UNSUPPORTED, TRB left unconsumed
 *   - reserved TRB type / bad TRB fields     -> TRB Error (5) event + BAD_REQUEST
 *   - DMA outside DMA_MAP ranges             -> Host System Error (USBSTS.HSE,
 *                                               controller halted) + BAD_RANGE
 *   - event ring full                        -> BUSY, TRB left unconsumed
 * Not modelled: IMOD timing, MFINDEX, multi-segment ERST, USB3 ports, streams,
 * Disable Slot/Evaluate Context/Reset Endpoint/etc, endpoints other than EP0.
 */
#include "../driverzone.h"

#include <stdlib.h>
#include <string.h>

#define BAR0_SIZE 0x1000u
#define MAX_SLOTS 8u
#define MAX_PORTS 2u
#define CAPLENGTH 0x20u
#define DBOFF 0x800u
#define RTSOFF 0x600u

/* operational */
#define R_USBCMD 0x20u
#define R_USBSTS 0x24u
#define R_PAGESIZE 0x28u
#define R_DNCTRL 0x34u
#define R_CRCR 0x38u
#define R_DCBAAP 0x50u
#define R_CONFIG 0x58u
#define R_PORTSC1 0x420u /* operational base + 0x400 + 0x10*(n-1) */
/* runtime, interrupter 0 */
#define R_IMAN 0x620u
#define R_IMOD 0x624u
#define R_ERSTSZ 0x628u
#define R_ERSTBA 0x630u
#define R_ERDP 0x638u

#define CMD_RS 0x01u
#define CMD_HCRST 0x02u
#define CMD_INTE 0x04u
#define CMD_HSEE 0x08u
#define CMD_ALLOWED (CMD_RS | CMD_HCRST | CMD_INTE | CMD_HSEE)

#define STS_HCH 0x01u
#define STS_HSE 0x04u
#define STS_EINT 0x08u
#define STS_PCD 0x10u
#define STS_W1C (STS_HSE | STS_EINT | STS_PCD)

#define PS_CCS 0x1u
#define PS_PED 0x2u
#define PS_PR 0x10u
#define PS_PP 0x200u
#define PS_SPEED_SHIFT 10
#define PS_LWS 0x10000u
#define PS_CSC 0x20000u
#define PS_PRC 0x200000u
#define PLS_U0 0u
#define PLS_RXDETECT 5u
#define PLS_POLLING 7u
#define SPEED_HS 3u

/* TRB types */
#define T_NORMAL 1u
#define T_SETUP 2u
#define T_DATA 3u
#define T_STATUS 4u
#define T_ISOCH 5u
#define T_LINK 6u
#define T_EVENT_DATA 7u
#define T_TR_NOOP 8u
#define T_CMD_ENABLE_SLOT 9u
#define T_CMD_ADDRESS 11u
#define T_CMD_CONFIGURE 12u
#define T_CMD_FIRST 9u
#define T_CMD_LAST 25u
#define T_CMD_NOOP 23u
#define T_EV_TRANSFER 32u
#define T_EV_CMD_DONE 33u
#define T_EV_PORT 34u

/* completion codes */
#define CC_SUCCESS 1u
#define CC_TRB_ERROR 5u
#define CC_STALL 6u
#define CC_NO_SLOTS 9u
#define CC_SLOT_NOT_ENABLED 11u
#define CC_SHORT_PACKET 13u
#define CC_PARAMETER 17u
#define CC_CONTEXT_STATE 19u

#define TRB_SIZE 16u
#define WALK_LIMIT 4096u
#define DEV_DESC_LEN 18u

enum slot_state { SL_DISABLED, SL_ENABLED, SL_DEFAULT, SL_ADDRESSED, SL_CONFIGURED };

/* device descriptor served by the attached device (USB 2.0 section 9.6.1) */
static const uint8_t dev_desc[DEV_DESC_LEN] = {
    0x12, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40, 0x6B,
    0x1D, 0x04, 0x01, 0x00, 0x01, 0x01, 0x02, 0x03, 0x01};

struct xh_slot {
  int state;
  uint64_t out_ctx;
  uint64_t ep0_deq;
  uint32_t ep0_dcs;
  int ep0_halted;
  uint32_t addr;
  /* control TD in progress */
  int have_setup, have_data;
  uint8_t setup[8];
  uint32_t resp_len;
};

struct dz_xhci_sim {
  uint32_t usbcmd, usbsts, dnctrl, config;
  uint64_t dcbaap, crcr_wr, erstba, erdp;
  uint32_t iman, imod, erstsz;
  int hse;
  /* command ring */
  int crcr_set, crr;
  uint64_t cr_deq;
  uint32_t ccs;
  /* event ring (single segment) */
  int er_ok, ehb;
  uint64_t er_base;
  uint32_t er_size, er_enq, er_deq, er_pcs;
  /* port 1 */
  int p1_ped, p1_csc, p1_prc;
  uint32_t p1_pls;
  int port_event_pending;
  struct xh_slot slot[MAX_SLOTS + 1u];
  uint32_t irq_pending;
};

/* HCRST / RPC RESET: all registers and internal state to reset values. The
 * device is (re)attached, so a new connect event is pending. */
static void hc_reset(struct dz_xhci_sim *s)
{
  memset(s, 0, sizeof(*s));
  s->usbsts = STS_HCH;
  s->imod = 0x0FA0u;
  s->p1_csc = 1;
  s->p1_pls = PLS_POLLING;
  s->port_event_pending = 1;
}

struct dz_xhci_sim *dz_softvm_xhci_create(void)
{
  struct dz_xhci_sim *s = (struct dz_xhci_sim *)calloc(1, sizeof(*s));
  if (s != NULL) {
    hc_reset(s);
  }
  return s;
}

void dz_softvm_xhci_destroy(struct dz_xhci_sim *s) { free(s); }

static void hse(struct dz *dz, struct dz_xhci_sim *s, const char *why)
{
  s->hse = 1;
  s->usbsts |= STS_HSE | STS_HCH;
  s->usbcmd &= ~CMD_RS;
  dz_logf(dz, "xhci: host system error: %s", why);
}

static int32_t bad(struct dz *dz, const char *what, uint32_t off, uint32_t v)
{
  dz_logf(dz, "xhci: %s (reg 0x%x value 0x%x)", what, off, v);
  return I1N1_DRV_STATUS_BAD_REQUEST;
}

/* ---- event ring ------------------------------------------------------- */

static int er_full(const struct dz_xhci_sim *s)
{
  return s->er_ok && ((s->er_enq + 1u) % s->er_size) == s->er_deq;
}

static int32_t post_event(struct dz *dz, struct dz_xhci_sim *s, uint64_t param,
                          uint32_t status, uint32_t dw3)
{
  uint8_t trb[TRB_SIZE];
  uint32_t next;
  if (!s->er_ok) {
    dz_logf(dz, "xhci: event ring not initialised");
    return I1N1_DRV_STATUS_BAD_REQUEST;
  }
  next = (s->er_enq + 1u) % s->er_size;
  if (next == s->er_deq) {
    dz_logf(dz, "xhci: event ring full");
    return I1N1_DRV_STATUS_BUSY;
  }
  dw3 = (dw3 & ~1u) | s->er_pcs;
  dz_wr64(trb, param);
  dz_wr32(trb + 8, status);
  dz_wr32(trb + 12, dw3);
  if (dz_dma_write(dz, s->er_base + (uint64_t)s->er_enq * TRB_SIZE, trb,
                   TRB_SIZE) != 0) {
    hse(dz, s, "event ring memory not DMA-registered");
    return I1N1_DRV_STATUS_BAD_RANGE;
  }
  s->er_enq = next;
  if (next == 0) {
    s->er_pcs ^= 1u;
  }
  s->usbsts |= STS_EINT;
  if (!(s->iman & 1u)) { /* IP 0 -> 1 */
    s->iman |= 1u;
    s->ehb = 1;
    if ((s->iman & 2u) && (s->usbcmd & CMD_INTE)) {
      s->irq_pending |= 1u;
    }
  }
  return I1N1_DRV_STATUS_OK;
}

static int32_t deliver_port_event(struct dz *dz, struct dz_xhci_sim *s)
{
  int32_t st;
  if (!s->port_event_pending || !(s->usbcmd & CMD_RS) || !s->er_ok) {
    return I1N1_DRV_STATUS_OK;
  }
  if (er_full(s)) {
    return I1N1_DRV_STATUS_BUSY;
  }
  st = post_event(dz, s, 0x01000000u /* port id 1 in bits 31:24 of dword0 */,
                  CC_SUCCESS << 24, T_EV_PORT << 10);
  if (st == I1N1_DRV_STATUS_OK) {
    s->port_event_pending = 0;
    s->usbsts |= STS_PCD;
  }
  return st;
}

static int32_t cmd_done(struct dz *dz, struct dz_xhci_sim *s, uint64_t trb_addr,
                        uint32_t cc, uint32_t slot_id)
{
  return post_event(dz, s, trb_addr, cc << 24,
                    (slot_id << 24) | (T_EV_CMD_DONE << 10));
}

/* ---- command execution ------------------------------------------------ */

static int cmd_known(uint32_t type)
{
  return type >= T_CMD_FIRST && type <= T_CMD_LAST;
}

static int32_t cmd_enable_slot(struct dz *dz, struct dz_xhci_sim *s,
                               uint64_t at)
{
  uint32_t id;
  for (id = 1; id <= (s->config & 0xFFu); ++id) {
    if (s->slot[id].state == SL_DISABLED) {
      memset(&s->slot[id], 0, sizeof(s->slot[id]));
      s->slot[id].state = SL_ENABLED;
      return cmd_done(dz, s, at, CC_SUCCESS, id);
    }
  }
  return cmd_done(dz, s, at, CC_NO_SLOTS, 0);
}

static int32_t cmd_address(struct dz *dz, struct dz_xhci_sim *s, uint64_t at,
                           uint64_t inptr, uint32_t dw3)
{
  uint32_t id = dw3 >> 24, bsr = (dw3 >> 9) & 1u;
  struct xh_slot *sl;
  uint8_t in[96], ent[8], out[64];
  uint32_t drop, add, sdw0, sdw1, e1;
  uint64_t trdeq, outp;
  if (id == 0 || id > MAX_SLOTS || s->slot[id].state == SL_DISABLED) {
    return cmd_done(dz, s, at, CC_SLOT_NOT_ENABLED, id);
  }
  sl = &s->slot[id];
  if (sl->state != SL_ENABLED && sl->state != SL_DEFAULT) {
    return cmd_done(dz, s, at, CC_CONTEXT_STATE, id);
  }
  if ((inptr & 0x3Fu) != 0 || inptr == 0 || s->dcbaap == 0) {
    return cmd_done(dz, s, at, CC_PARAMETER, id);
  }
  if (dz_dma_read(dz, inptr, in, sizeof(in)) != 0) {
    hse(dz, s, "input context not DMA-registered");
    return I1N1_DRV_STATUS_BAD_RANGE;
  }
  drop = dz_rd32(in);
  add = dz_rd32(in + 4);
  sdw0 = dz_rd32(in + 32);
  sdw1 = dz_rd32(in + 36);
  e1 = dz_rd32(in + 64 + 4);
  trdeq = dz_rd64(in + 64 + 8);
  /* A0|A1 only, root-hub port 1 (attached, enabled), HS, >= 1 context entry,
   * EP0 = control, non-zero MPS <= 64, non-null ring */
  if (drop != 0 || add != 3u || (sdw0 & 0xFFFFFu) != 0 ||
      ((sdw0 >> 20) & 0xFu) != SPEED_HS || (sdw0 >> 27) < 1u ||
      ((sdw1 >> 16) & 0xFFu) != 1u || !s->p1_ped || ((e1 >> 3) & 7u) != 4u ||
      (e1 >> 16) == 0 || (e1 >> 16) > 64u || (trdeq & ~0xFull) == 0) {
    return cmd_done(dz, s, at, CC_PARAMETER, id);
  }
  if (dz_dma_read(dz, s->dcbaap + 8u * id, ent, 8) != 0) {
    hse(dz, s, "DCBAA not DMA-registered");
    return I1N1_DRV_STATUS_BAD_RANGE;
  }
  outp = dz_rd64(ent);
  if (outp == 0 || (outp & 0x3Fu) != 0) {
    return cmd_done(dz, s, at, CC_PARAMETER, id);
  }
  memcpy(out, in + 32, 64);
  dz_wr32(out + 12, ((bsr ? 1u : 2u) << 27) | (bsr ? 0u : id));
  dz_wr32(out + 32, (dz_rd32(out + 32) & ~7u) | 1u); /* EP0 state Running */
  if (dz_dma_write(dz, outp, out, sizeof(out)) != 0) {
    hse(dz, s, "output device context not DMA-registered");
    return I1N1_DRV_STATUS_BAD_RANGE;
  }
  sl->addr = bsr ? 0u : id;
  sl->state = bsr ? SL_DEFAULT : SL_ADDRESSED;
  sl->out_ctx = outp;
  sl->ep0_deq = trdeq & ~0xFull;
  sl->ep0_dcs = (uint32_t)(trdeq & 1u);
  return cmd_done(dz, s, at, CC_SUCCESS, id);
}

/* *stop set -> the TRB stays unconsumed (deterministic stop). */
static int32_t cmd_configure(struct dz *dz, struct dz_xhci_sim *s, uint64_t at,
                             uint64_t inptr, uint32_t dw3, int *stop)
{
  uint32_t id = dw3 >> 24;
  struct xh_slot *sl;
  uint8_t icc[32], sctx[32], ep[32];
  uint32_t drop, add, dci, maxdci = 0;
  if (id == 0 || id > MAX_SLOTS || s->slot[id].state == SL_DISABLED) {
    return cmd_done(dz, s, at, CC_SLOT_NOT_ENABLED, id);
  }
  sl = &s->slot[id];
  if (dw3 & 0x200u) { /* DC: deconfigure */
    dz_logf(dz, "xhci: Configure Endpoint DC=1 unmodelled");
    *stop = 1;
    return I1N1_DRV_STATUS_UNSUPPORTED;
  }
  if (sl->state != SL_ADDRESSED && sl->state != SL_CONFIGURED) {
    return cmd_done(dz, s, at, CC_CONTEXT_STATE, id);
  }
  if ((inptr & 0x3Fu) != 0 || inptr == 0) {
    return cmd_done(dz, s, at, CC_PARAMETER, id);
  }
  if (dz_dma_read(dz, inptr, icc, 32) != 0 ||
      dz_dma_read(dz, inptr + 32, sctx, 32) != 0) {
    hse(dz, s, "input context not DMA-registered");
    return I1N1_DRV_STATUS_BAD_RANGE;
  }
  drop = dz_rd32(icc);
  add = dz_rd32(icc + 4);
  if (drop != 0) {
    dz_logf(dz, "xhci: Configure Endpoint with drop flags unmodelled");
    *stop = 1;
    return I1N1_DRV_STATUS_UNSUPPORTED;
  }
  if ((add & 2u) != 0) { /* A1 (EP0) is not valid for Configure Endpoint */
    return cmd_done(dz, s, at, CC_PARAMETER, id);
  }
  for (dci = 2; dci < 32; ++dci) {
    if (add & (1u << dci)) {
      maxdci = dci;
    }
  }
  if ((add & 1u) && (dz_rd32(sctx) >> 27) < maxdci) {
    return cmd_done(dz, s, at, CC_PARAMETER, id);
  }
  /* validate all endpoint contexts first, then commit */
  for (dci = 2; dci < 32; ++dci) {
    if (!(add & (1u << dci))) {
      continue;
    }
    if (dz_dma_read(dz, inptr + (uint64_t)(dci + 1u) * 32u, ep, 32) != 0) {
      hse(dz, s, "input endpoint context not DMA-registered");
      return I1N1_DRV_STATUS_BAD_RANGE;
    }
    if (((dz_rd32(ep + 4) >> 3) & 7u) == 0) { /* EP type "not valid" */
      return cmd_done(dz, s, at, CC_PARAMETER, id);
    }
  }
  for (dci = 2; dci < 32; ++dci) {
    if (!(add & (1u << dci))) {
      continue;
    }
    if (dz_dma_read(dz, inptr + (uint64_t)(dci + 1u) * 32u, ep, 32) != 0) {
      hse(dz, s, "input endpoint context not DMA-registered");
      return I1N1_DRV_STATUS_BAD_RANGE;
    }
    dz_wr32(ep, (dz_rd32(ep) & ~7u) | 1u); /* Running */
    if (dz_dma_write(dz, sl->out_ctx + (uint64_t)dci * 32u, ep, 32) != 0) {
      hse(dz, s, "output endpoint context not DMA-registered");
      return I1N1_DRV_STATUS_BAD_RANGE;
    }
  }
  if (add & 1u) {
    dz_wr32(sctx + 12, (3u << 27) | sl->addr);
    if (dz_dma_write(dz, sl->out_ctx, sctx, 32) != 0) {
      hse(dz, s, "output slot context not DMA-registered");
      return I1N1_DRV_STATUS_BAD_RANGE;
    }
  } else {
    uint8_t d3[4];
    dz_wr32(d3, (3u << 27) | sl->addr);
    if (dz_dma_write(dz, sl->out_ctx + 12, d3, 4) != 0) {
      hse(dz, s, "output slot context not DMA-registered");
      return I1N1_DRV_STATUS_BAD_RANGE;
    }
  }
  sl->state = SL_CONFIGURED;
  return cmd_done(dz, s, at, CC_SUCCESS, id);
}

static int32_t run_cmd_ring(struct dz *dz, struct dz_xhci_sim *s)
{
  unsigned int n;
  if (s->hse || !(s->usbcmd & CMD_RS) || !s->er_ok || !s->crcr_set) {
    dz_logf(dz, "xhci: DB0 rejected (hse=%d rs=%u er=%d crcr=%d)", s->hse,
            s->usbcmd & CMD_RS, s->er_ok, s->crcr_set);
    return I1N1_DRV_STATUS_BAD_REQUEST;
  }
  s->crr = 1;
  for (n = 0; n < WALK_LIMIT; ++n) {
    uint8_t trb[TRB_SIZE];
    uint64_t param, at = s->cr_deq;
    uint32_t dw3, type;
    int32_t st;
    int stop = 0;
    if (dz_dma_read(dz, at, trb, TRB_SIZE) != 0) {
      hse(dz, s, "command ring not DMA-registered");
      return I1N1_DRV_STATUS_BAD_RANGE;
    }
    param = dz_rd64(trb);
    dw3 = dz_rd32(trb + 12);
    if ((dw3 & 1u) != s->ccs) {
      return I1N1_DRV_STATUS_OK; /* ring empty: cycle bit mismatch */
    }
    type = (dw3 >> 10) & 0x3Fu;
    if (type == T_LINK) {
      if ((param & 0xFull) != 0 || param == 0) {
        s->cr_deq += TRB_SIZE;
        dz_logf(dz, "xhci: Link TRB with bad target 0x%llx",
                (unsigned long long)param);
        st = cmd_done(dz, s, at, CC_TRB_ERROR, 0);
        return st != I1N1_DRV_STATUS_OK ? st : I1N1_DRV_STATUS_BAD_REQUEST;
      }
      s->cr_deq = param;
      if (dw3 & 2u) {
        s->ccs ^= 1u;
      }
      continue;
    }
    if (er_full(s)) {
      dz_logf(dz, "xhci: event ring full, command ring stalled");
      return I1N1_DRV_STATUS_BUSY;
    }
    switch (type) {
    case T_CMD_NOOP:
      st = cmd_done(dz, s, at, CC_SUCCESS, 0);
      break;
    case T_CMD_ENABLE_SLOT:
      st = cmd_enable_slot(dz, s, at);
      break;
    case T_CMD_ADDRESS:
      st = cmd_address(dz, s, at, param, dw3);
      break;
    case T_CMD_CONFIGURE:
      st = cmd_configure(dz, s, at, param, dw3, &stop);
      break;
    default:
      if (cmd_known(type)) { /* valid xHCI command, not modelled */
        dz_logf(dz, "xhci: command TRB type %u unmodelled", type);
        return I1N1_DRV_STATUS_UNSUPPORTED;
      }
      dz_logf(dz, "xhci: reserved/invalid command TRB type %u", type);
      s->cr_deq += TRB_SIZE;
      st = cmd_done(dz, s, at, CC_TRB_ERROR, 0);
      return st != I1N1_DRV_STATUS_OK ? st : I1N1_DRV_STATUS_BAD_REQUEST;
    }
    if (stop) {
      return st;
    }
    s->cr_deq += TRB_SIZE;
    if (st != I1N1_DRV_STATUS_OK) {
      return st;
    }
  }
  hse(dz, s, "command ring walk limit exceeded");
  return I1N1_DRV_STATUS_BAD_REQUEST;
}

/* ---- EP0 control transfers -------------------------------------------- */

static int32_t xfer_event(struct dz *dz, struct dz_xhci_sim *s, uint32_t id,
                          uint64_t at, uint32_t cc, uint32_t residual)
{
  return post_event(dz, s, at, (cc << 24) | (residual & 0xFFFFFFu),
                    (id << 24) | (1u << 16) | (T_EV_TRANSFER << 10));
}

static int32_t run_ep0(struct dz *dz, struct dz_xhci_sim *s, uint32_t id)
{
  struct xh_slot *sl = &s->slot[id];
  unsigned int n;
  if (s->hse || !(s->usbcmd & CMD_RS) || !s->er_ok) {
    dz_logf(dz, "xhci: slot doorbell rejected (hse/rs/er)");
    return I1N1_DRV_STATUS_BAD_REQUEST;
  }
  if (sl->ep0_halted) {
    dz_logf(dz, "xhci: EP0 halted (Reset Endpoint unmodelled)");
    return I1N1_DRV_STATUS_UNSUPPORTED;
  }
  for (n = 0; n < WALK_LIMIT; ++n) {
    uint8_t trb[TRB_SIZE];
    uint64_t param, at = sl->ep0_deq;
    uint32_t dw2, dw3, type, len, ioc;
    int32_t st;
    if (dz_dma_read(dz, at, trb, TRB_SIZE) != 0) {
      hse(dz, s, "EP0 transfer ring not DMA-registered");
      return I1N1_DRV_STATUS_BAD_RANGE;
    }
    param = dz_rd64(trb);
    dw2 = dz_rd32(trb + 8);
    dw3 = dz_rd32(trb + 12);
    if ((dw3 & 1u) != sl->ep0_dcs) {
      return I1N1_DRV_STATUS_OK; /* nothing (more) queued */
    }
    type = (dw3 >> 10) & 0x3Fu;
    len = dw2 & 0x1FFFFu;
    ioc = (dw3 >> 5) & 1u;
    if (type == T_LINK) {
      if ((param & 0xFull) != 0 || param == 0) {
        goto trb_error;
      }
      sl->ep0_deq = param;
      if (dw3 & 2u) {
        sl->ep0_dcs ^= 1u;
      }
      continue;
    }
    if (er_full(s)) {
      dz_logf(dz, "xhci: event ring full, EP0 stalled");
      return I1N1_DRV_STATUS_BUSY;
    }
    if (type == T_NORMAL || type == T_ISOCH || type == T_EVENT_DATA ||
        type == T_TR_NOOP) {
      dz_logf(dz, "xhci: transfer TRB type %u unmodelled", type);
      return I1N1_DRV_STATUS_UNSUPPORTED;
    }
    if (type == T_SETUP) {
      uint32_t trt = (dw3 >> 16) & 3u, wlen;
      uint8_t rt, rq;
      if (!(dw3 & 0x40u) || len != 8u || sl->have_setup) {
        goto trb_error; /* IDT required, length 8, no TD already open */
      }
      if (trt == 2u) {
        dz_logf(dz, "xhci: OUT data stage (TRT=2) unmodelled");
        return I1N1_DRV_STATUS_UNSUPPORTED;
      }
      memcpy(sl->setup, trb, 8);
      rt = sl->setup[0];
      rq = sl->setup[1];
      wlen = (uint32_t)sl->setup[6] | ((uint32_t)sl->setup[7] << 8);
      if (trt == 1u || (trt == 3u) != (wlen != 0) ||
          (trt == 3u && !(rt & 0x80u))) {
        goto trb_error;
      }
      sl->ep0_deq += TRB_SIZE;
      if (rt == 0x80 && rq == 6 && sl->setup[2] == 0 && sl->setup[3] == 1 &&
          sl->setup[4] == 0 && sl->setup[5] == 0 && wlen != 0) {
        sl->have_setup = 1;
        sl->have_data = 0;
        sl->resp_len = wlen < DEV_DESC_LEN ? wlen : DEV_DESC_LEN;
        continue;
      }
      /* only GET_DESCRIPTOR(DEVICE, index 0, lang 0) is modelled: STALL */
      sl->ep0_halted = 1;
      dz_logf(dz, "xhci: control request %02x/%02x unmodelled, EP0 stalled",
              rt, rq);
      st = xfer_event(dz, s, id, at, CC_STALL, 0);
      return st != I1N1_DRV_STATUS_OK ? st : I1N1_DRV_STATUS_UNSUPPORTED;
    }
    if (type == T_DATA) {
      uint32_t xfer;
      if (!sl->have_setup || sl->have_data || !(dw3 & 0x10000u) ||
          (dw3 & 0x10u) /* CH */ || len == 0 || param == 0) {
        goto trb_error;
      }
      xfer = sl->resp_len < len ? sl->resp_len : len;
      if (dz_dma_write(dz, param, dev_desc, xfer) != 0) {
        hse(dz, s, "control data buffer not DMA-registered");
        return I1N1_DRV_STATUS_BAD_RANGE;
      }
      sl->have_data = 1;
      sl->ep0_deq += TRB_SIZE;
      if (ioc || ((dw3 & 4u) && xfer < len)) {
        st = xfer_event(dz, s, id, at,
                        xfer < len ? CC_SHORT_PACKET : CC_SUCCESS, len - xfer);
        if (st != I1N1_DRV_STATUS_OK) {
          return st;
        }
      }
      continue;
    }
    if (type == T_STATUS) {
      uint32_t wlen = (uint32_t)sl->setup[6] | ((uint32_t)sl->setup[7] << 8);
      uint32_t dir_in = (dw3 >> 16) & 1u;
      if (!sl->have_setup || !sl->have_data || dir_in != 0u || wlen == 0) {
        goto trb_error;
      }
      sl->have_setup = 0;
      sl->have_data = 0;
      sl->ep0_deq += TRB_SIZE;
      if (ioc) {
        st = xfer_event(dz, s, id, at, CC_SUCCESS, 0);
        if (st != I1N1_DRV_STATUS_OK) {
          return st;
        }
      }
      continue;
    }
    dz_logf(dz, "xhci: reserved/invalid transfer TRB type %u", type);
  trb_error:
    sl->ep0_deq += TRB_SIZE;
    sl->have_setup = 0;
    sl->have_data = 0;
    dz_logf(dz, "xhci: transfer TRB error (type %u)", type);
    st = xfer_event(dz, s, id, at, CC_TRB_ERROR, 0);
    return st != I1N1_DRV_STATUS_OK ? st : I1N1_DRV_STATUS_BAD_REQUEST;
  }
  hse(dz, s, "transfer ring walk limit exceeded");
  return I1N1_DRV_STATUS_BAD_REQUEST;
}

/* ---- register file ---------------------------------------------------- */

static uint32_t portsc1(const struct dz_xhci_sim *s)
{
  return PS_CCS | (s->p1_ped ? PS_PED : 0u) | (s->p1_pls << 5) | PS_PP |
         (s->p1_ped ? (SPEED_HS << PS_SPEED_SHIFT) : 0u) |
         (s->p1_csc ? PS_CSC : 0u) | (s->p1_prc ? PS_PRC : 0u);
}

static uint64_t erdp_cur(const struct dz_xhci_sim *s)
{
  return s->er_ok ? s->er_base + (uint64_t)s->er_deq * TRB_SIZE : s->erdp;
}

static int reg_read32(const struct dz_xhci_sim *s, uint32_t off, uint32_t *v)
{
  switch (off) {
  case 0x00: *v = 0x01200000u | CAPLENGTH; return 0; /* HCIVERSION 1.2.0 */
  case 0x04: *v = MAX_SLOTS | (1u << 8) | (MAX_PORTS << 24); return 0;
  case 0x08: *v = 4u << 4; return 0; /* ERST Max = 2^4, IST 0, no scratchpad */
  case 0x0C: *v = 0; return 0;
  case 0x10: *v = 1u; return 0; /* AC64, 32-byte contexts */
  case 0x14: *v = DBOFF; return 0;
  case 0x18: *v = RTSOFF; return 0;
  case 0x1C: *v = 0; return 0;
  case R_USBCMD: *v = s->usbcmd; return 0;
  case R_USBSTS: *v = s->usbsts; return 0;
  case R_PAGESIZE: *v = 1u; return 0; /* 4 KiB */
  case R_DNCTRL: *v = s->dnctrl; return 0;
  case R_CRCR: *v = s->crr ? 8u : 0u; return 0; /* only CRR reads back */
  case R_CRCR + 4: *v = 0; return 0;
  case R_DCBAAP: *v = (uint32_t)s->dcbaap; return 0;
  case R_DCBAAP + 4: *v = (uint32_t)(s->dcbaap >> 32); return 0;
  case R_CONFIG: *v = s->config; return 0;
  case R_PORTSC1: *v = portsc1(s); return 0;
  case R_PORTSC1 + 4:  /* PORTPMSC, PORTLI, PORTHLPMC: reset value 0 */
  case R_PORTSC1 + 8:
  case R_PORTSC1 + 12: *v = 0; return 0;
  case R_PORTSC1 + 16: *v = PS_PP | (PLS_RXDETECT << 5); return 0; /* port 2 */
  case R_PORTSC1 + 20:
  case R_PORTSC1 + 24:
  case R_PORTSC1 + 28: *v = 0; return 0;
  case R_IMAN: *v = s->iman; return 0;
  case R_IMOD: *v = s->imod; return 0;
  case R_ERSTSZ: *v = s->erstsz; return 0;
  case R_ERSTBA: *v = (uint32_t)s->erstba; return 0;
  case R_ERSTBA + 4: *v = (uint32_t)(s->erstba >> 32); return 0;
  case R_ERDP: *v = (uint32_t)erdp_cur(s) | (s->ehb ? 8u : 0u); return 0;
  case R_ERDP + 4: *v = (uint32_t)(erdp_cur(s) >> 32); return 0;
  default: return -1;
  }
}

static int32_t write_portsc1(struct dz *dz, struct dz_xhci_sim *s, uint32_t v)
{
  int32_t st = I1N1_DRV_STATUS_OK;
  /* PED=1 would disable the port; LWS/PLS write, PIC, CAS, wake bits, WPR and
   * power-off are all unmodelled: refuse rather than ignore. PLS without LWS
   * is ignored per spec (read-modify-write drivers). */
  if ((v & PS_PED) || (v & PS_LWS) || (v & 0xC000u) || (v & 0x1000000u) ||
      (v & 0x0E000000u) || (v & 0x80000000u) || !(v & PS_PP)) {
    return bad(dz, "PORTSC write with unmodelled/illegal bits", R_PORTSC1, v);
  }
  if (v & PS_CSC) {
    s->p1_csc = 0;
  }
  if (v & PS_PRC) {
    s->p1_prc = 0;
  }
  if (v & PS_PR) {
    s->p1_ped = 1;
    s->p1_pls = PLS_U0;
    s->p1_prc = 1;
    s->port_event_pending = 1;
    st = deliver_port_event(dz, s);
  }
  return st;
}

static int32_t apply_erstba(struct dz *dz, struct dz_xhci_sim *s)
{
  uint8_t ent[16];
  uint64_t base;
  uint32_t size;
  if (s->erstsz != 1u) {
    return bad(dz, "ERSTBA written with ERSTSZ != 1", R_ERSTBA, s->erstsz);
  }
  if ((s->erstba & 0x3Full) != 0 || s->erstba == 0) {
    return bad(dz, "ERSTBA not 64-byte aligned", R_ERSTBA, (uint32_t)s->erstba);
  }
  if (dz_dma_read(dz, s->erstba, ent, sizeof(ent)) != 0) {
    hse(dz, s, "ERST not DMA-registered");
    return I1N1_DRV_STATUS_BAD_RANGE;
  }
  base = dz_rd64(ent);
  size = dz_rd32(ent + 8) & 0xFFFFu;
  if ((base & 0x3Full) != 0 || base == 0 || size < 16u || size > 4096u) {
    return bad(dz, "bad ERST entry", R_ERSTBA, size);
  }
  if ((s->erdp & ~0xFull) != base) {
    return bad(dz, "ERDP != ERST segment base at init", R_ERDP,
               (uint32_t)s->erdp);
  }
  s->er_base = base;
  s->er_size = size;
  s->er_enq = s->er_deq = 0;
  s->er_pcs = 1;
  s->er_ok = 1;
  return deliver_port_event(dz, s);
}

static int32_t apply_erdp(struct dz *dz, struct dz_xhci_sim *s, uint64_t raw)
{
  uint64_t ptr = raw & ~0xFull;
  uint32_t idx, used, adv;
  if (raw & 7u) {
    return bad(dz, "ERDP DESI != 0 (single segment)", R_ERDP, (uint32_t)raw);
  }
  if (!s->er_ok) {
    s->erdp = raw & ~8ull;
    return I1N1_DRV_STATUS_OK;
  }
  if (ptr < s->er_base || ptr >= s->er_base + (uint64_t)s->er_size * TRB_SIZE) {
    return bad(dz, "ERDP outside event ring", R_ERDP, (uint32_t)raw);
  }
  idx = (uint32_t)((ptr - s->er_base) / TRB_SIZE);
  used = (s->er_enq + s->er_size - s->er_deq) % s->er_size;
  adv = (idx + s->er_size - s->er_deq) % s->er_size;
  if (adv > used) {
    return bad(dz, "ERDP beyond event ring enqueue pointer", R_ERDP,
               (uint32_t)raw);
  }
  s->er_deq = idx;
  if (raw & 8u) {
    s->ehb = 0;
  }
  return I1N1_DRV_STATUS_OK;
}

static int32_t apply_crcr(struct dz *dz, struct dz_xhci_sim *s, uint64_t raw)
{
  if (s->crr) {
    return bad(dz, "CRCR written while command ring running", R_CRCR,
               (uint32_t)raw);
  }
  if (raw & 6u) { /* CS / CA */
    return bad(dz, "CRCR CS/CA unmodelled", R_CRCR, (uint32_t)raw);
  }
  if ((raw & ~0x3Full) == 0) {
    return bad(dz, "CRCR null command ring pointer", R_CRCR, (uint32_t)raw);
  }
  s->crcr_wr = raw;
  s->cr_deq = raw & ~0x3Full;
  s->ccs = (uint32_t)(raw & 1u);
  s->crcr_set = 1;
  return I1N1_DRV_STATUS_OK;
}

/* 64-bit regs: lo/hi 32-bit writes update the raw value; hi_included marks the
 * write that completes it (ERSTBA is acted on then). */
static int32_t write64(struct dz *dz, struct dz_xhci_sim *s, uint32_t base,
                       uint64_t raw, int hi_included)
{
  switch (base) {
  case R_CRCR:
    return apply_crcr(dz, s, raw);
  case R_DCBAAP:
    if (raw & 0x3Fu) {
      return bad(dz, "DCBAAP not 64-byte aligned", base, (uint32_t)raw);
    }
    s->dcbaap = raw;
    return I1N1_DRV_STATUS_OK;
  case R_ERSTBA:
    s->erstba = raw;
    return hi_included ? apply_erstba(dz, s) : I1N1_DRV_STATUS_OK;
  default: /* R_ERDP */
    return apply_erdp(dz, s, raw);
  }
}

static int32_t doorbell_write(struct dz *dz, struct dz_xhci_sim *s,
                              uint32_t off, uint32_t v)
{
  uint32_t id = (off - DBOFF) / 4u;
  if (id > MAX_SLOTS) {
    return bad(dz, "doorbell for nonexistent slot", off, v);
  }
  if (id == 0) {
    if (v != 0) {
      return bad(dz, "DB0 target must be 0", off, v);
    }
    return run_cmd_ring(dz, s);
  }
  if (s->slot[id].state < SL_ADDRESSED) {
    return bad(dz, "slot doorbell for slot not addressed", off, v);
  }
  if ((v >> 16) != 0 || (v & 0xFFu) == 0 || (v & 0xFFu) > 31u) {
    return bad(dz, "bad doorbell target/stream", off, v);
  }
  if ((v & 0xFFu) != 1u) {
    dz_logf(dz, "xhci: doorbell target DCI %u unmodelled (EP0 only)",
            v & 0xFFu);
    return I1N1_DRV_STATUS_UNSUPPORTED;
  }
  return run_ep0(dz, s, id);
}

static int32_t reg_write32(struct dz *dz, struct dz_xhci_sim *s, uint32_t off,
                           uint32_t v)
{
  const uint64_t lo_mask = 0xFFFFFFFFull;
  if (off >= DBOFF) {
    return doorbell_write(dz, s, off, v);
  }
  switch (off) {
  case R_USBCMD: {
    int32_t st = I1N1_DRV_STATUS_OK;
    if (v & ~CMD_ALLOWED) {
      return bad(dz, "USBCMD unmodelled bits", off, v);
    }
    if (v & CMD_HCRST) {
      hc_reset(s);
      return st;
    }
    if (s->hse && (v & CMD_RS)) {
      return bad(dz, "USBCMD.RS while host system error (reset first)", off, v);
    }
    s->usbcmd = v;
    if (v & CMD_RS) {
      s->usbsts &= ~STS_HCH;
      st = deliver_port_event(dz, s);
    } else {
      s->usbsts |= STS_HCH;
    }
    return st;
  }
  case R_USBSTS:
    s->usbsts &= ~(v & STS_W1C); /* HCH etc are read-only */
    return 0;
  case R_DNCTRL:
    if (v & ~0xFFFFu) {
      return bad(dz, "DNCTRL reserved bits", off, v);
    }
    s->dnctrl = v;
    return 0;
  case R_CRCR:
    return write64(dz, s, R_CRCR, (s->crcr_wr & ~lo_mask) | v, 0);
  case R_CRCR + 4:
    return write64(dz, s, R_CRCR, (s->crcr_wr & lo_mask) | ((uint64_t)v << 32), 1);
  case R_DCBAAP:
    return write64(dz, s, R_DCBAAP, (s->dcbaap & ~lo_mask) | v, 0);
  case R_DCBAAP + 4:
    return write64(dz, s, R_DCBAAP, (s->dcbaap & lo_mask) | ((uint64_t)v << 32), 1);
  case R_CONFIG:
    if ((v & ~0xFFu) != 0 || v > MAX_SLOTS) {
      return bad(dz, "CONFIG slots > MaxSlots or U3E/CIE set", off, v);
    }
    s->config = v;
    return 0;
  case R_PORTSC1:
    return write_portsc1(dz, s, v);
  case R_IMAN:
    if (v & ~3u) {
      return bad(dz, "IMAN reserved bits", off, v);
    }
    if (v & 1u) {
      s->iman &= ~1u; /* IP is RW1C */
    }
    s->iman = (s->iman & ~2u) | (v & 2u);
    return 0;
  case R_IMOD:
    s->imod = v; /* stored only; moderation timing is not modelled */
    return 0;
  case R_ERSTSZ:
    if (v != 1u) {
      return bad(dz, "ERSTSZ != 1 (multi-segment ERST unmodelled)", off, v);
    }
    s->erstsz = v;
    return 0;
  case R_ERSTBA:
    return write64(dz, s, R_ERSTBA, (s->erstba & ~lo_mask) | v, 0);
  case R_ERSTBA + 4:
    return write64(dz, s, R_ERSTBA, (s->erstba & lo_mask) | ((uint64_t)v << 32), 1);
  case R_ERDP:
    return write64(dz, s, R_ERDP, (erdp_cur(s) & ~lo_mask) | v, 0);
  case R_ERDP + 4:
    return write64(dz, s, R_ERDP, (erdp_cur(s) & lo_mask) | ((uint64_t)v << 32), 1);
  default:
    return bad(dz, "write to read-only/unmodelled register", off, v);
  }
}

static int is_reg64(uint32_t off)
{
  return off == 0x00 || off == R_CRCR || off == R_DCBAAP || off == R_ERSTBA ||
         off == R_ERDP;
}

static int32_t mmio(struct dz *dz, struct dz_xhci_sim *s, const struct dz_op *op,
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
  if (bar != 0 || off64 >= BAR0_SIZE || (op->shm_len != 4 && op->shm_len != 8) ||
      off64 + op->shm_len > BAR0_SIZE || (off64 & (op->shm_len - 1u)) != 0 ||
      (op->shm_len == 8 && !is_reg64((uint32_t)off64))) {
    dz_logf(dz, "xhci: MMIO denied bar=%u off=0x%llx width=%llu", bar,
            (unsigned long long)off64, (unsigned long long)op->shm_len);
    return I1N1_DRV_STATUS_BAD_RANGE;
  }
  off = (uint32_t)off64;
  if (!is_write) {
    uint32_t lo = 0, hi = 0;
    if (reg_read32(s, off, &lo) != 0 ||
        (op->shm_len == 8 && reg_read32(s, off + 4, &hi) != 0)) {
      dz_logf(dz, "xhci: MMIO read of unmodelled reg 0x%x", off);
      return I1N1_DRV_STATUS_BAD_RANGE; /* no fake zero */
    }
    dz_wr32(op->shm, lo);
    if (op->shm_len == 8) {
      dz_wr32(op->shm + 4, hi);
    }
    return I1N1_DRV_STATUS_OK;
  }
  if (op->shm_len == 8) {
    uint64_t raw = dz_rd64(op->shm);
    if (off == 0x00) {
      return bad(dz, "write to read-only capability regs", off, (uint32_t)raw);
    }
    return write64(dz, s, off, raw, 1);
  }
  return reg_write32(dz, s, off, dz_rd32(op->shm));
}

static int32_t sim_op(struct dz *dz, void *ctx, const struct dz_op *op,
                      struct dz_out *out)
{
  struct dz_xhci_sim *s = (struct dz_xhci_sim *)ctx;
  switch (op->opcode) {
  case I1N1_DRV_OP_PROBE:
    dz_wr16(out->payload + 0, 0x1B36);
    dz_wr16(out->payload + 2, 0x000D);
    dz_wr32(out->payload + 4, 0x0C0330u); /* serial bus / USB / xHCI */
    dz_wr32(out->payload + 8, BAR0_SIZE);
    dz_wr32(out->payload + 12, 1u);
    out->payload_size = 16;
    return I1N1_DRV_STATUS_OK;
  case I1N1_DRV_OP_INFO:
    dz_wr32(out->payload + 0, 1u); /* not a block device: size fields 0 */
    memcpy(out->payload + 16, "softvm-xhci-sim", 15);
    out->payload_size = 32;
    return I1N1_DRV_STATUS_OK;
  case I1N1_DRV_OP_MMIO_READ:
    return mmio(dz, s, op, 0);
  case I1N1_DRV_OP_MMIO_WRITE:
    return mmio(dz, s, op, 1);
  case I1N1_DRV_OP_IRQ_WAIT:
    if (op->payload_size != 4u) {
      return I1N1_DRV_STATUS_BAD_PAYLOAD;
    }
    if (s->irq_pending == 0) {
      return I1N1_DRV_STATUS_BUSY; /* timeout; softvm never blocks */
    }
    dz_wr32(out->payload, 0);
    out->payload_size = 4;
    return I1N1_DRV_STATUS_OK;
  case I1N1_DRV_OP_IRQ_ACK: {
    uint32_t v;
    if (op->payload_size != 4u) {
      return I1N1_DRV_STATUS_BAD_PAYLOAD;
    }
    v = dz_rd32(op->payload);
    if (v != 0 || !(s->irq_pending & 1u)) {
      dz_logf(dz, "xhci: IRQ_ACK for vector %u not pending", v);
      return I1N1_DRV_STATUS_BAD_REQUEST;
    }
    s->irq_pending = 0;
    return I1N1_DRV_STATUS_OK;
  }
  case I1N1_DRV_OP_RESET:
    hc_reset(s);
    return I1N1_DRV_STATUS_OK;
  default:
    dz_logf(dz, "xhci: op %u not handled by backend", (unsigned)op->opcode);
    return I1N1_DRV_STATUS_UNSUPPORTED;
  }
}

void dz_softvm_xhci_backend_init(struct dz_backend *out, struct dz_xhci_sim *sim)
{
  out->name = "softvm-xhci";
  out->unsupported_reason = NULL;
  out->ctx = sim;
  out->op = sim_op;
  out->device_id = DZ_DEVICE_XHCI_SIM;
}
