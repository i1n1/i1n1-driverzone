/* SPDX-License-Identifier: GPL-2.0-only */
/* VMX capability decode, control adjustment, VMCS region handling. */
#include <string.h>

#include "vmx_hw.h"

static int fail(struct vmx_caps *c, const char *why)
{
  c->usable = 0;
  c->reason = why;
  return -1;
}

int vmx_caps_decode(const struct vmx_msrs *m, uint32_t cpuid1_ecx,
                    struct vmx_caps *c)
{
  uint64_t cap;
  uint32_t proc_may1, proc2_may1;

  if (m == NULL || c == NULL) {
    return -2;
  }
  memset(c, 0, sizeof *c);
  c->vmx = (cpuid1_ecx & VMX_CPUID1_ECX_VMX) != 0;
  if (!c->vmx) {
    return fail(c, "unsupported: CPUID.1:ECX.VMX clear (no VT-x)");
  }
  /* VMXON outside SMX needs the lock bit and bit 2 (firmware-set; we do not
   * rewrite it: a locked-off MSR cannot be fixed by software anyway). */
  if ((m->feature_control & VMX_FEATCTL_LOCK) == 0 ||
      (m->feature_control & VMX_FEATCTL_VMXON_OUTSIDE_SMX) == 0) {
    return fail(c, "unsupported: IA32_FEATURE_CONTROL does not permit VMXON");
  }
  c->revision_id = VMX_BASIC_REVISION(m->basic);
  c->vmcs_size = VMX_BASIC_VMCS_SIZE(m->basic);
  c->true_ctls = (int)VMX_BASIC_TRUE_CTLS(m->basic);
  if (c->vmcs_size == 0 || c->vmcs_size > VMX_REGION_BYTES) {
    return fail(c, "unsupported: IA32_VMX_BASIC VMCS size out of range");
  }
  if (VMX_BASIC_PA32(m->basic)) {
    return fail(c, "unsupported: VMCS addresses limited to 32 bits");
  }
  if (VMX_BASIC_MEMTYPE(m->basic) != VMX_EPT_MT_WB) {
    return fail(c, "unsupported: VMCS memory type is not write-back");
  }
  proc_may1 = (uint32_t)((c->true_ctls ? m->true_proc : m->proc) >> 32);
  c->secondary = (proc_may1 & VMX_PROC_SECONDARY) != 0;
  if (c->secondary) {
    proc2_may1 = (uint32_t)(m->proc2 >> 32);
    cap = m->ept_vpid_cap;
    c->ept = (proc2_may1 & VMX_PROC2_EPT) != 0;
    c->vpid = (proc2_may1 & VMX_PROC2_VPID) != 0;
    c->unrestricted = (proc2_may1 & VMX_PROC2_UNRESTRICTED) != 0 && c->ept;
    if (c->ept || c->vpid) {
      c->ept_walk4 = (cap & VMX_EPTCAP_WALK4) != 0;
      c->ept_wb = (cap & VMX_EPTCAP_WB) != 0;
      c->ept_2m = (cap & VMX_EPTCAP_2M) != 0;
      c->ept_1g = (cap & VMX_EPTCAP_1G) != 0;
      c->ept_ad = (cap & VMX_EPTCAP_AD) != 0;
      c->ept_exec_only = (cap & VMX_EPTCAP_EXEC_ONLY) != 0;
      c->invept = (cap & VMX_EPTCAP_INVEPT) != 0;
      c->invvpid = (cap & VMX_EPTCAP_INVVPID) != 0;
    }
    if (c->ept && !(c->ept_walk4 && c->ept_wb)) {
      c->ept = 0; /* we only build 4-level WB EPT */
      c->unrestricted = 0;
    }
  }
  c->usable = 1;
  return 0;
}

int vmx_ctl_adjust(uint64_t msr, uint32_t want, uint32_t *out,
                   uint32_t *unsupported)
{
  uint32_t must1 = (uint32_t)msr;
  uint32_t may1 = (uint32_t)(msr >> 32);
  uint32_t bad = want & ~may1;

  if (out == NULL) {
    return -2;
  }
  if (must1 & ~may1) {
    return -3; /* malformed capability MSR: a must-be-1 bit that may not be 1 */
  }
  *out = (want | must1) & may1;
  if (unsupported != NULL) {
    *unsupported = bad;
  }
  return bad ? -1 : 0;
}

static int one(uint64_t msr, uint32_t want, uint32_t *out, const char *name,
               struct vmx_ctl_config *cfg)
{
  uint32_t bad = 0;
  int rc = vmx_ctl_adjust(msr, want, out, &bad);

  if (rc != 0) {
    cfg->which = rc == -3 ? "malformed capability MSR" : name;
    cfg->bad_bits = bad;
  }
  return rc;
}

int vmx_ctl_build(const struct vmx_msrs *m, const struct vmx_ctl_request *rq,
                  struct vmx_ctl_config *cfg)
{
  int t;
  uint32_t proc_want;

  if (m == NULL || rq == NULL || cfg == NULL) {
    return -2;
  }
  memset(cfg, 0, sizeof *cfg);
  t = (int)VMX_BASIC_TRUE_CTLS(m->basic);
  if (one(t ? m->true_pin : m->pin, rq->pin, &cfg->pin, "pin-based", cfg) ||
      one(t ? m->true_exit : m->exit, rq->exit, &cfg->exit, "vm-exit", cfg) ||
      one(t ? m->true_entry : m->entry, rq->entry, &cfg->entry, "vm-entry",
          cfg)) {
    return -1;
  }
  proc_want = rq->proc;
  if (rq->proc2 != 0) {
    proc_want |= VMX_PROC_SECONDARY;
  }
  if (one(t ? m->true_proc : m->proc, proc_want, &cfg->proc, "proc-based",
          cfg)) {
    return -1;
  }
  if (cfg->proc & VMX_PROC_SECONDARY) {
    if (one(m->proc2, rq->proc2, &cfg->proc2, "secondary", cfg)) {
      return -1;
    }
  } else if (rq->proc2 != 0) {
    cfg->which = "secondary";
    cfg->bad_bits = rq->proc2;
    return -1;
  }
  /* Architectural dependencies. */
  if ((cfg->proc2 & VMX_PROC2_UNRESTRICTED) && !(cfg->proc2 & VMX_PROC2_EPT)) {
    cfg->which = "secondary: unrestricted guest requires EPT";
    cfg->bad_bits = VMX_PROC2_UNRESTRICTED;
    return -1;
  }
  return 0;
}

uint64_t vmx_fix_cr0(const struct vmx_msrs *m, uint64_t cr0)
{
  return (cr0 | m->cr0_fixed0) & m->cr0_fixed1;
}

uint64_t vmx_fix_cr4(const struct vmx_msrs *m, uint64_t cr4)
{
  return ((cr4 | VMX_CR4_VMXE) | m->cr4_fixed0) & m->cr4_fixed1;
}

/* ---- VMCS region ---------------------------------------------------------- */
int vmx_region_init(void *region, size_t bytes, uint32_t revision_id)
{
  uint8_t *p = region;

  if (region == NULL || bytes < 8 || bytes > VMX_REGION_BYTES ||
      (revision_id & 0x80000000u) != 0) {
    return -1; /* bit 31 of the revision id is the shadow-VMCS indicator */
  }
  memset(p, 0, bytes);
  p[0] = (uint8_t)revision_id;
  p[1] = (uint8_t)(revision_id >> 8);
  p[2] = (uint8_t)(revision_id >> 16);
  p[3] = (uint8_t)(revision_id >> 24);
  return 0;
}

static uint32_t rd32(const uint8_t *p)
{
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

const char *vmx_abort_str(uint32_t a)
{
  switch (a) {
  case 0: return "no abort";
  case 1: return "VMX abort 1: saving guest MSRs on VM exit failed";
  case 2: return "VMX abort 2: loading host PDPTEs failed";
  default: return "VMX abort: other indicator (see SDM Vol 3 sec 27.7)";
  }
}

int vmx_region_check(const void *region, size_t bytes, uint32_t revision_id,
                     const char **reason)
{
  const uint8_t *p = region;
  const char *why = NULL;
  uint32_t abort_ind;

  if (region == NULL || bytes < 8) {
    why = "VMCS region missing";
  } else if (rd32(p) != revision_id) {
    why = "VMCS revision id mismatch";
  } else if ((abort_ind = rd32(p + 4)) != 0) {
    why = vmx_abort_str(abort_ind);
  }
  if (reason != NULL) {
    *reason = why;
  }
  return why ? -1 : 0;
}
