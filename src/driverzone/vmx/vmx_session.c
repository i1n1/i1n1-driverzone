/* SPDX-License-Identifier: GPL-2.0-only */
/* Recording mock instruction backend + bring-up session over any backend. */
#include <string.h>

#include "../driverzone.h"
#include "vmx_hw.h"

/* ---- mock -------------------------------------------------------------- */
static struct vmx_mock *M(void *ctx) { return ctx; }

static void rec(struct vmx_mock *m, enum vmx_mock_op op, uint64_t a, uint64_t b)
{
  if (m->nlog < VMX_MOCK_LOG) {
    m->log[m->nlog].op = op;
    m->log[m->nlog].a = a;
    m->log[m->nlog].b = b;
    m->nlog++;
  }
}

static int slot(struct vmx_mock *m, uint32_t f)
{
  unsigned i;

  for (i = 0; i < m->nfields; i++) {
    if (m->fields[i] == f) {
      return (int)i;
    }
  }
  return -1;
}

void vmx_mock_set_field(struct vmx_mock *m, uint32_t f, uint64_t v)
{
  int i = slot(m, f);

  if (i < 0 && m->nfields < VMX_MOCK_FIELDS) {
    i = (int)m->nfields++;
    m->fields[i] = f;
  }
  if (i >= 0) {
    m->values[i] = v;
  }
}

static int mk_vmxon(void *c, uint64_t pa)
{
  struct vmx_mock *m = M(c);

  rec(m, MOCK_VMXON, pa, 0);
  if (m->fail_next) {
    int rc = m->fail_next;

    m->fail_next = 0;
    return rc;
  }
  m->vmxon_active = 1;
  return VMX_OK;
}
static int mk_vmxoff(void *c)
{
  rec(M(c), MOCK_VMXOFF, 0, 0);
  M(c)->vmxon_active = 0;
  return VMX_OK;
}
static int mk_vmclear(void *c, uint64_t pa)
{
  rec(M(c), MOCK_VMCLEAR, pa, 0);
  return M(c)->vmxon_active ? VMX_OK : VMX_FAIL_INVALID;
}
static int mk_vmptrld(void *c, uint64_t pa)
{
  rec(M(c), MOCK_VMPTRLD, pa, 0);
  if (!M(c)->vmxon_active) {
    return VMX_FAIL_INVALID;
  }
  M(c)->current_vmcs = pa;
  return VMX_OK;
}
static int mk_vmwrite(void *c, uint32_t f, uint64_t v)
{
  rec(M(c), MOCK_VMWRITE, f, v);
  if (!M(c)->vmxon_active || M(c)->current_vmcs == 0 ||
      vmx_field_lookup(f) == NULL) {
    return VMX_FAIL_INVALID; /* unknown component: never silently accepted */
  }
  if (vmx_field_read_only(f)) {
    return VMX_FAIL_VALID; /* VMWRITE to a read-only component (SDM err 13) */
  }
  vmx_mock_set_field(M(c), f, v);
  return VMX_OK;
}
static int mk_vmread(void *c, uint32_t f, uint64_t *v)
{
  int i = slot(M(c), f);

  rec(M(c), MOCK_VMREAD, f, 0);
  if (i < 0) {
    return VMX_FAIL_VALID;
  }
  *v = M(c)->values[i];
  return VMX_OK;
}
static int mk_vmenter(void *c, int resume, struct vmx_guest_regs *regs)
{
  struct vmx_mock *m = M(c);
  const struct vmx_exit_info *x;

  (void)regs;
  rec(m, resume ? MOCK_RESUME : MOCK_LAUNCH, 0, 0);
  if (m->fail_next) {
    int rc = m->fail_next;

    m->fail_next = 0;
    return rc;
  }
  if (!m->vmxon_active || m->current_vmcs == 0) {
    return VMX_FAIL_INVALID;
  }
  if (m->next_script >= m->nscript) {
    return VMX_ERR_UNSUP; /* test script exhausted: no invented exits */
  }
  x = &m->script[m->next_script++];
  vmx_mock_set_field(m, VMCS_EXIT_REASON, x->raw_reason);
  vmx_mock_set_field(m, VMCS_EXIT_QUAL, x->qual);
  vmx_mock_set_field(m, VMCS_GUEST_PHYS_ADDR, x->gpa);
  vmx_mock_set_field(m, VMCS_EXIT_INSN_LEN, x->insn_len);
  return VMX_OK;
}
static uint64_t mk_rdmsr(void *c, uint32_t msr)
{
  return msr == VMX_MSR_FEATURE_CONTROL ? M(c)->msr_feature_control : 0;
}
static uint64_t mk_read_cr(void *c, unsigned n)
{
  return n < 5 ? M(c)->cr[n] : 0;
}
static void mk_write_cr(void *c, unsigned n, uint64_t v)
{
  rec(M(c), MOCK_WRCR, n, v);
  if (n < 5) {
    M(c)->cr[n] = v;
  }
}

void vmx_mock_init(struct vmx_mock *m)
{
  memset(m, 0, sizeof *m);
  m->ops.name = "mock";
  m->ops.ctx = m;
  m->ops.vmxon = mk_vmxon;
  m->ops.vmxoff = mk_vmxoff;
  m->ops.vmclear = mk_vmclear;
  m->ops.vmptrld = mk_vmptrld;
  m->ops.vmwrite = mk_vmwrite;
  m->ops.vmread = mk_vmread;
  m->ops.vmenter = mk_vmenter;
  m->ops.rdmsr = mk_rdmsr;
  m->ops.read_cr = mk_read_cr;
  m->ops.write_cr = mk_write_cr;
}

/* ---- session ----------------------------------------------------------- */
static int sfail(struct vmx_session *s, const char *why)
{
  s->stop_reason = why;
  return -1;
}

int vmx_session_enable(struct vmx_session *s, uint64_t vmxon_pa)
{
  if (s == NULL || s->ops == NULL || s->msrs == NULL) {
    return -2;
  }
  s->stop_reason = NULL;
  if (!s->caps.usable) {
    return sfail(s, s->caps.reason ? s->caps.reason : DZ_UNSUPPORTED_NO_VTX);
  }
  if (vmxon_pa & 0xFFFu) {
    return sfail(s, "VMXON region not 4 KiB aligned");
  }
  s->ops->write_cr(s->ops->ctx, 0, vmx_fix_cr0(s->msrs, s->ops->read_cr(s->ops->ctx, 0)));
  s->ops->write_cr(s->ops->ctx, 4, vmx_fix_cr4(s->msrs, s->ops->read_cr(s->ops->ctx, 4)));
  if (s->ops->vmxon(s->ops->ctx, vmxon_pa) != VMX_OK) {
    return sfail(s, "VMXON failed");
  }
  s->on = 1;
  return 0;
}

int vmx_session_load_vmcs(struct vmx_session *s, uint64_t vmcs_pa)
{
  if (s == NULL || !s->on) {
    return -2;
  }
  if (vmcs_pa & 0xFFFu) {
    return sfail(s, "VMCS region not 4 KiB aligned");
  }
  if (s->ops->vmclear(s->ops->ctx, vmcs_pa) != VMX_OK) {
    return sfail(s, "VMCLEAR failed");
  }
  if (s->ops->vmptrld(s->ops->ctx, vmcs_pa) != VMX_OK) {
    return sfail(s, "VMPTRLD failed");
  }
  s->launched = 0;
  return 0;
}

static int wr(struct vmx_session *s, uint32_t f, uint64_t v)
{
  return s->ops->vmwrite(s->ops->ctx, f, v) == VMX_OK
             ? 0
             : sfail(s, "VMWRITE failed");
}

int vmx_session_write_controls(struct vmx_session *s,
                               const struct vmx_ctl_config *cfg)
{
  if (s == NULL || !s->on || cfg == NULL || cfg->which != NULL) {
    return -2;
  }
  if (wr(s, VMCS_PIN_CTLS, cfg->pin) || wr(s, VMCS_PROC_CTLS, cfg->proc) ||
      ((cfg->proc & VMX_PROC_SECONDARY) && wr(s, VMCS_PROC2_CTLS, cfg->proc2)) ||
      wr(s, VMCS_EXIT_CTLS, cfg->exit) || wr(s, VMCS_ENTRY_CTLS, cfg->entry)) {
    return -1;
  }
  return 0;
}

static int rd(struct vmx_session *s, uint32_t f, uint64_t *v)
{
  return s->ops->vmread(s->ops->ctx, f, v) == VMX_OK
             ? 0
             : sfail(s, "VMREAD failed");
}

int vmx_session_run_once(struct vmx_session *s, const struct vmx_exit_ops *x,
                         struct vmx_guest_regs *regs,
                         struct vmx_exit_result *r)
{
  struct vmx_exit_info e;
  uint64_t v, rip;
  int rc;

  r->action = VMX_ACT_STOP;
  r->advance = 0;
  r->detail = 0;
  r->reason = "VMX session not active";
  if (s == NULL || !s->on) {
    return VMX_ACT_STOP;
  }
  rc = s->ops->vmenter(s->ops->ctx, s->launched, regs);
  if (rc != VMX_OK) {
    r->reason = rc == VMX_FAIL_VALID    ? "VM entry instruction failed (valid)"
                : rc == VMX_FAIL_INVALID ? "VM entry instruction failed (invalid VMCS)"
                                         : "VM entry unsupported";
    return VMX_ACT_STOP;
  }
  s->launched = 1;
  memset(&e, 0, sizeof e);
  if (rd(s, VMCS_EXIT_REASON, &v)) {
    r->reason = s->stop_reason;
    return VMX_ACT_STOP;
  }
  vmx_exit_decode((uint32_t)v, &e);
  if (rd(s, VMCS_EXIT_QUAL, &e.qual) || rd(s, VMCS_GUEST_PHYS_ADDR, &e.gpa) ||
      rd(s, VMCS_EXIT_INSN_LEN, &v)) {
    r->reason = s->stop_reason;
    return VMX_ACT_STOP;
  }
  e.insn_len = (uint32_t)v;
  vmx_exit_dispatch(x, &e, regs, r);
  if (r->action == VMX_ACT_RESUME_ADVANCE) {
    if (rd(s, VMCS_GUEST_RIP, &rip) ||
        wr(s, VMCS_GUEST_RIP, rip + r->advance)) {
      r->action = VMX_ACT_STOP;
      r->reason = s->stop_reason;
    }
  }
  return r->action;
}

int vmx_session_disable(struct vmx_session *s)
{
  if (s == NULL || !s->on) {
    return -2;
  }
  s->on = 0;
  return s->ops->vmxoff(s->ops->ctx) == VMX_OK ? 0 : sfail(s, "VMXOFF failed");
}

const char *dz_vmx_unsupported_reason(const struct vmx_caps *caps)
{
  if (caps == NULL || !caps->usable) {
    return (caps && caps->reason) ? caps->reason : DZ_UNSUPPORTED_NO_VTX;
  }
  return NULL;
}
