/* SPDX-License-Identifier: GPL-2.0-only */
/* VM-exit decode and dispatch (SDM Vol 3 ch. 27 / appendix C). Unsupported
 * exits stop deterministically; no exit is ever silently "handled". */
#include "vmx_hw.h"

const char *vmx_exit_reason_name(uint32_t r)
{
  switch (r) {
  case 0: return "exception or NMI";
  case 1: return "external interrupt";
  case 2: return "triple fault";
  case 3: return "INIT signal";
  case 4: return "SIPI";
  case 7: return "interrupt window";
  case 8: return "NMI window";
  case 9: return "task switch";
  case 10: return "CPUID";
  case 12: return "HLT";
  case 13: return "INVD";
  case 14: return "INVLPG";
  case 15: return "RDPMC";
  case 16: return "RDTSC";
  case 18: return "VMCALL";
  case 19: return "VMCLEAR";
  case 20: return "VMLAUNCH";
  case 21: return "VMPTRLD";
  case 22: return "VMPTRST";
  case 23: return "VMREAD";
  case 24: return "VMRESUME";
  case 25: return "VMWRITE";
  case 26: return "VMXOFF";
  case 27: return "VMXON";
  case 28: return "control-register access";
  case 29: return "MOV DR";
  case 30: return "I/O instruction";
  case 31: return "RDMSR";
  case 32: return "WRMSR";
  case 33: return "VM-entry failure: invalid guest state";
  case 34: return "VM-entry failure: MSR loading";
  case 36: return "MWAIT";
  case 37: return "monitor trap flag";
  case 39: return "MONITOR";
  case 40: return "PAUSE";
  case 41: return "VM-entry failure: machine check";
  case 43: return "TPR below threshold";
  case 44: return "APIC access";
  case 48: return "EPT violation";
  case 49: return "EPT misconfiguration";
  case 50: return "INVEPT";
  case 51: return "RDTSCP";
  case 52: return "VMX-preemption timer";
  case 53: return "INVVPID";
  case 54: return "WBINVD";
  case 55: return "XSETBV";
  case 57: return "RDRAND";
  case 58: return "INVPCID";
  case 59: return "VMFUNC";
  case 61: return "RDSEED";
  case 62: return "PML full";
  case 63: return "XSAVES";
  case 64: return "XRSTORS";
  default: return "unknown exit reason";
  }
}

void vmx_exit_decode(uint32_t raw, struct vmx_exit_info *e)
{
  e->raw_reason = raw;
  e->basic = raw & 0xFFFFu;
  e->entry_failure = (raw >> 31) & 1u;
}

void vmx_ept_qual_decode(uint64_t q, struct vmx_ept_qual *o)
{
  o->read = (int)(q & 1u);
  o->write = (int)((q >> 1) & 1u);
  o->fetch = (int)((q >> 2) & 1u);
  o->r_ok = (int)((q >> 3) & 1u);
  o->w_ok = (int)((q >> 4) & 1u);
  o->x_ok = (int)((q >> 5) & 1u);
  o->linear_valid = (int)((q >> 7) & 1u);
  o->translation = (int)((q >> 8) & 1u);
  o->access = (uint32_t)(q & 7u);
}

void vmx_io_qual_decode(uint64_t q, struct vmx_io_qual *o)
{
  unsigned enc = (unsigned)(q & 7u);

  o->size = enc + 1;
  o->valid = enc != 2; /* encoding 2 is not defined */
  o->is_in = (int)((q >> 3) & 1u);
  o->string = (int)((q >> 4) & 1u);
  o->rep = (int)((q >> 5) & 1u);
  o->imm = (int)((q >> 6) & 1u);
  o->port = (uint16_t)(q >> 16);
}

void vmx_cr_qual_decode(uint64_t q, struct vmx_cr_qual *o)
{
  o->cr = (unsigned)(q & 0xFu);
  o->type = (unsigned)((q >> 4) & 3u);
  o->lmsw_mem = (int)((q >> 6) & 1u);
  o->gpr = (unsigned)((q >> 8) & 0xFu);
  o->lmsw_src = (uint16_t)(q >> 16);
}

static void stop(struct vmx_exit_result *r, const char *why, uint64_t detail)
{
  r->action = VMX_ACT_STOP;
  r->reason = why;
  r->advance = 0;
  r->detail = detail;
}

static void adv(struct vmx_exit_result *r, uint32_t len)
{
  r->action = VMX_ACT_RESUME_ADVANCE;
  r->reason = NULL;
  r->advance = len;
}

static void ept_violation(const struct vmx_exit_ops *ops,
                          const struct vmx_exit_info *e,
                          struct vmx_exit_result *r)
{
  struct vmx_ept_qual q;
  struct i1n1_ept_violation viol;
  uint64_t hpa, value = 0;
  unsigned width = 0;
  int is_write = 0, rc;
  uint32_t len = 0;

  vmx_ept_qual_decode(e->qual, &q);
  if (ops->ept_model == NULL || ops->router == NULL) {
    stop(r, "unsupported: EPT violation with no MMIO router wired", e->gpa);
    return;
  }
  if (q.access != I1N1_EPT_R && q.access != I1N1_EPT_W &&
      q.access != I1N1_EPT_X) {
    stop(r, "EPT violation with ambiguous access type", e->gpa);
    return;
  }
  rc = i1n1_ept_translate(ops->ept_model, e->gpa, 1, q.access, &hpa, &viol);
  if (rc == I1N1_EPT_OK) {
    stop(r, "EPT violation on a GPA the EPT model maps (model/HW divergence)",
         e->gpa);
    return;
  }
  if (rc != I1N1_EPT_VIOLATION || viol.reason != I1N1_EPT_VIOL_MMIO) {
    stop(r, rc == I1N1_EPT_VIOLATION ? i1n1_ept_reason_str(viol.reason)
                                     : "EPT model rejected violation query",
         e->gpa);
    return;
  }
  if (q.access == I1N1_EPT_X) {
    stop(r, "instruction fetch from MMIO", e->gpa);
    return;
  }
  if (ops->mmio_decode == NULL) {
    stop(r, "unsupported: no MMIO instruction decoder", e->gpa);
    return;
  }
  if (ops->mmio_decode(ops->ctx, e, &width, &is_write, &value, &len) != 0 ||
      len == 0 || is_write != (q.access == I1N1_EPT_W)) {
    stop(r, "MMIO instruction decode failed or disagrees with qualification",
         e->gpa);
    return;
  }
  if (!is_write && ops->mmio_complete == NULL) {
    stop(r, "unsupported: MMIO read with no completion path", e->gpa);
    return;
  }
  rc = i1n1_mmio_handle_violation(ops->router, &viol, width, &value);
  if (rc != I1N1_MMIO_OK) {
    stop(r, i1n1_mmio_status_str(rc), e->gpa);
    return;
  }
  if (!is_write) {
    ops->mmio_complete(ops->ctx, value);
  }
  adv(r, len);
}

static void io_exit(const struct vmx_exit_ops *ops,
                    const struct vmx_exit_info *e, struct vmx_guest_regs *g,
                    struct vmx_exit_result *r)
{
  struct vmx_io_qual q;
  uint64_t mask, v = 0;
  uint64_t *rax = &g->r[VMX_GPR_RAX];

  vmx_io_qual_decode(e->qual, &q);
  if (!q.valid) {
    stop(r, "I/O exit with undefined size encoding", e->qual);
  } else if (q.string) {
    stop(r, "unsupported: string I/O exit", q.port);
  } else if (ops->port_io == NULL) {
    stop(r, "unsupported: no port I/O handler", q.port);
  } else {
    mask = q.size == 4 ? UINT64_C(0xFFFFFFFF)
                       : (UINT64_C(1) << (8 * q.size)) - 1;
    if (!q.is_in) {
      v = *rax & mask;
    }
    if (ops->port_io(ops->ctx, q.port, q.size, q.is_in, &v) != 0) {
      stop(r, "port I/O refused by handler", q.port);
      return;
    }
    if (q.is_in) {
      /* 32-bit IN zero-extends into RAX; 8/16-bit keep the upper bits. */
      *rax = q.size == 4 ? (v & mask) : ((*rax & ~mask) | (v & mask));
    }
    adv(r, e->insn_len);
  }
}

void vmx_exit_dispatch(const struct vmx_exit_ops *ops,
                       const struct vmx_exit_info *e,
                       struct vmx_guest_regs *g, struct vmx_exit_result *r)
{
  uint64_t v;
  uint32_t msr;

  r->action = VMX_ACT_STOP;
  r->reason = "internal: dispatch fell through";
  r->advance = 0;
  r->detail = 0;
  if (ops == NULL || e == NULL || g == NULL) {
    return;
  }
  if (e->entry_failure) {
    stop(r, vmx_exit_reason_name(e->basic), e->basic);
    return;
  }
  switch (e->basic) {
  case VMX_EXIT_EPT_VIOLATION:
    ept_violation(ops, e, r);
    break;
  case VMX_EXIT_EPT_MISCONFIG:
    stop(r, "EPT misconfiguration", e->gpa);
    break;
  case VMX_EXIT_IO:
    io_exit(ops, e, g, r);
    break;
  case VMX_EXIT_CPUID:
    if (ops->cpuid == NULL) {
      stop(r, "unsupported: no CPUID policy", g->r[VMX_GPR_RAX]);
    } else if (ops->cpuid(ops->ctx, g) != 0) {
      stop(r, "CPUID leaf refused by policy", g->r[VMX_GPR_RAX]);
    } else {
      adv(r, e->insn_len);
    }
    break;
  case VMX_EXIT_RDMSR:
    msr = (uint32_t)g->r[VMX_GPR_RCX];
    if (ops->rdmsr == NULL || ops->rdmsr(ops->ctx, msr, &v) != 0) {
      stop(r, "unsupported: RDMSR (no value is invented)", msr);
    } else {
      g->r[VMX_GPR_RAX] = v & 0xFFFFFFFFu;
      g->r[VMX_GPR_RDX] = v >> 32;
      adv(r, e->insn_len);
    }
    break;
  case VMX_EXIT_WRMSR:
    msr = (uint32_t)g->r[VMX_GPR_RCX];
    v = (g->r[VMX_GPR_RAX] & 0xFFFFFFFFu) | (g->r[VMX_GPR_RDX] << 32);
    if (ops->wrmsr == NULL || ops->wrmsr(ops->ctx, msr, v) != 0) {
      stop(r, "unsupported: WRMSR (write is not dropped)", msr);
    } else {
      adv(r, e->insn_len);
    }
    break;
  case VMX_EXIT_CR_ACCESS: {
    struct vmx_cr_qual q;

    vmx_cr_qual_decode(e->qual, &q);
    if (ops->cr_access == NULL || ops->cr_access(ops->ctx, &q, g) != 0) {
      stop(r, "unsupported: control-register access", e->qual);
    } else {
      adv(r, e->insn_len);
    }
    break;
  }
  default:
    stop(r, vmx_exit_reason_name(e->basic), e->basic);
    break;
  }
}
