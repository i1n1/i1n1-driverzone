/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Intel VMX root-mode backend skeleton (driver zone / M-BOOT-INTEL).
 *
 * Pure freestanding C: every decision is a function of values passed in
 * (capability MSRs, VMCS field values, exit information). Privileged
 * instructions sit behind struct vmx_insn_ops: a recording mock (tests) and
 * an x86_64 inline-asm backend (vmx_insn_x86.c).
 *
 * STATUS: unit-tested against SDM-derived expectations; never executed on
 * VT-x. Nothing here is hardware evidence. Anything unsupported or unknown
 * yields a deterministic stop with a reason, and never reports success it did not achieve.
 */
#ifndef I1N1_VMX_HW_H
#define I1N1_VMX_HW_H

#include <stddef.h>
#include <stdint.h>

#include "ept.h"
#include "mmio_router.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Capability MSR indices (SDM Vol 4) --------------------------------- */
#define VMX_MSR_FEATURE_CONTROL 0x3Au
#define VMX_MSR_BASIC 0x480u
#define VMX_MSR_PINBASED 0x481u
#define VMX_MSR_PROCBASED 0x482u
#define VMX_MSR_EXIT 0x483u
#define VMX_MSR_ENTRY 0x484u
#define VMX_MSR_MISC 0x485u
#define VMX_MSR_CR0_FIXED0 0x486u
#define VMX_MSR_CR0_FIXED1 0x487u
#define VMX_MSR_CR4_FIXED0 0x488u
#define VMX_MSR_CR4_FIXED1 0x489u
#define VMX_MSR_PROCBASED2 0x48Bu
#define VMX_MSR_EPT_VPID_CAP 0x48Cu
#define VMX_MSR_TRUE_PINBASED 0x48Du
#define VMX_MSR_TRUE_PROCBASED 0x48Eu
#define VMX_MSR_TRUE_EXIT 0x48Fu
#define VMX_MSR_TRUE_ENTRY 0x490u

#define VMX_CPUID1_ECX_VMX (1u << 5)
#define VMX_FEATCTL_LOCK (1u << 0)
#define VMX_FEATCTL_VMXON_OUTSIDE_SMX (1u << 2)
#define VMX_CR4_VMXE (UINT64_C(1) << 13)

/* IA32_VMX_BASIC fields */
#define VMX_BASIC_REVISION(v) ((uint32_t)((v) & 0x7FFFFFFFu))
#define VMX_BASIC_VMCS_SIZE(v) ((uint32_t)(((v) >> 32) & 0x1FFFu))
#define VMX_BASIC_PA32(v) (((v) >> 48) & 1u)
#define VMX_BASIC_MEMTYPE(v) ((uint32_t)(((v) >> 50) & 0xFu))
#define VMX_BASIC_TRUE_CTLS(v) (((v) >> 55) & 1u)

/* ---- Control bits -------------------------------------------------------- */
#define VMX_PIN_EXT_INT (1u << 0)
#define VMX_PIN_NMI (1u << 3)
#define VMX_PIN_VIRT_NMI (1u << 5)
#define VMX_PIN_PREEMPT_TIMER (1u << 6)

#define VMX_PROC_INT_WINDOW (1u << 2)
#define VMX_PROC_TSC_OFFSET (1u << 3)
#define VMX_PROC_HLT (1u << 7)
#define VMX_PROC_INVLPG (1u << 9)
#define VMX_PROC_CR3_LOAD (1u << 15)
#define VMX_PROC_CR3_STORE (1u << 16)
#define VMX_PROC_MOV_DR (1u << 23)
#define VMX_PROC_UNCOND_IO (1u << 24)
#define VMX_PROC_IO_BITMAP (1u << 25)
#define VMX_PROC_MSR_BITMAP (1u << 28)
#define VMX_PROC_SECONDARY (1u << 31)

#define VMX_PROC2_EPT (1u << 1)
#define VMX_PROC2_RDTSCP (1u << 3)
#define VMX_PROC2_VPID (1u << 5)
#define VMX_PROC2_UNRESTRICTED (1u << 7)
#define VMX_PROC2_INVPCID (1u << 12)
#define VMX_PROC2_XSAVES (1u << 20)

#define VMX_EXIT_SAVE_DEBUG (1u << 2)
#define VMX_EXIT_HOST_64 (1u << 9)
#define VMX_EXIT_ACK_INT (1u << 15)
#define VMX_EXIT_SAVE_EFER (1u << 20)
#define VMX_EXIT_LOAD_EFER (1u << 21)

#define VMX_ENTRY_LOAD_DEBUG (1u << 2)
#define VMX_ENTRY_IA32E_GUEST (1u << 9)
#define VMX_ENTRY_LOAD_EFER (1u << 15)

/* IA32_VMX_EPT_VPID_CAP bits */
#define VMX_EPTCAP_EXEC_ONLY (UINT64_C(1) << 0)
#define VMX_EPTCAP_WALK4 (UINT64_C(1) << 6)
#define VMX_EPTCAP_UC (UINT64_C(1) << 8)
#define VMX_EPTCAP_WB (UINT64_C(1) << 14)
#define VMX_EPTCAP_2M (UINT64_C(1) << 16)
#define VMX_EPTCAP_1G (UINT64_C(1) << 17)
#define VMX_EPTCAP_INVEPT (UINT64_C(1) << 20)
#define VMX_EPTCAP_AD (UINT64_C(1) << 21)
#define VMX_EPTCAP_INVEPT_SINGLE (UINT64_C(1) << 25)
#define VMX_EPTCAP_INVEPT_ALL (UINT64_C(1) << 26)
#define VMX_EPTCAP_INVVPID (UINT64_C(1) << 32)

/* ---- Capability decode --------------------------------------------------- */
struct vmx_msrs {
  uint64_t basic, pin, proc, proc2, exit, entry, misc;
  uint64_t true_pin, true_proc, true_exit, true_entry;
  uint64_t ept_vpid_cap;
  uint64_t cr0_fixed0, cr0_fixed1, cr4_fixed0, cr4_fixed1;
  uint64_t feature_control;
};

struct vmx_caps {
  int vmx;          /* CPUID.1:ECX.VMX */
  int usable;       /* vmx && feature control permits VMXON && sane MSRs */
  uint32_t revision_id;
  uint32_t vmcs_size;
  int true_ctls;
  int secondary;    /* proc-based bit 31 may be 1 */
  int ept, vpid, unrestricted;
  int ept_2m, ept_1g, ept_ad, ept_exec_only, ept_wb, ept_walk4;
  int invept, invvpid;
  const char *reason; /* NULL when usable, else deterministic reason */
};

/* Returns 0 when usable; negative otherwise with caps->reason set. */
int vmx_caps_decode(const struct vmx_msrs *m, uint32_t cpuid1_ecx,
                    struct vmx_caps *caps);

/* Allowed-0 / allowed-1 adjustment of one control word. Low 32 bits of the
 * MSR are bits that MUST be 1; high 32 bits are bits that MAY be 1. */
int vmx_ctl_adjust(uint64_t msr, uint32_t want, uint32_t *out,
                   uint32_t *unsupported);

struct vmx_ctl_request {
  uint32_t pin, proc, proc2, exit, entry; /* desired settings */
};
struct vmx_ctl_config {
  uint32_t pin, proc, proc2, exit, entry; /* final values to write */
  const char *which;                      /* failing control, else NULL */
  uint32_t bad_bits;                      /* requested but not allowed */
};
int vmx_ctl_build(const struct vmx_msrs *m, const struct vmx_ctl_request *rq,
                  struct vmx_ctl_config *cfg);

/* CR0/CR4 as required for VMXON (fixed bits + CR4.VMXE). */
uint64_t vmx_fix_cr0(const struct vmx_msrs *m, uint64_t cr0);
uint64_t vmx_fix_cr4(const struct vmx_msrs *m, uint64_t cr4);

/* ---- VMCS field encodings (SDM Vol 3 Appendix B) -------------------------- */
#define VMX_FIELD_WIDTH(e) (((e) >> 13) & 3u)   /* 0=16 1=64 2=32 3=natural */
#define VMX_FIELD_TYPE(e) (((e) >> 10) & 3u)    /* 0=ctl 1=exit-info(RO) 2=guest 3=host */
#define VMX_FIELD_HIGH(e) ((e) & 1u)            /* access type: high 32 of 64-bit */
enum { VMX_W16 = 0, VMX_W64 = 1, VMX_W32 = 2, VMX_WNAT = 3 };
enum { VMX_T_CTL = 0, VMX_T_EXITINFO = 1, VMX_T_GUEST = 2, VMX_T_HOST = 3 };

struct vmx_field_desc {
  uint32_t encoding;
  const char *name;
};
extern const struct vmx_field_desc vmx_fields[];
extern const size_t vmx_field_count;
const struct vmx_field_desc *vmx_field_lookup(uint32_t encoding);
int vmx_field_read_only(uint32_t encoding);

#define VMCS_VPID 0x0000u
#define VMCS_GUEST_CS_SEL 0x0802u
#define VMCS_HOST_CS_SEL 0x0C02u
#define VMCS_IO_BITMAP_A 0x2000u
#define VMCS_IO_BITMAP_B 0x2002u
#define VMCS_MSR_BITMAP 0x2004u
#define VMCS_TSC_OFFSET 0x2010u
#define VMCS_EPT_POINTER 0x201Au
#define VMCS_GUEST_PHYS_ADDR 0x2400u
#define VMCS_LINK_POINTER 0x2800u
#define VMCS_GUEST_EFER 0x2806u
#define VMCS_HOST_EFER 0x2C02u
#define VMCS_PIN_CTLS 0x4000u
#define VMCS_PROC_CTLS 0x4002u
#define VMCS_EXC_BITMAP 0x4004u
#define VMCS_CR3_TARGET_COUNT 0x400Au
#define VMCS_EXIT_CTLS 0x400Cu
#define VMCS_ENTRY_CTLS 0x4012u
#define VMCS_ENTRY_INTR_INFO 0x4016u
#define VMCS_PROC2_CTLS 0x401Eu
#define VMCS_INSN_ERROR 0x4400u
#define VMCS_EXIT_REASON 0x4402u
#define VMCS_EXIT_INTR_INFO 0x4404u
#define VMCS_EXIT_INSN_LEN 0x440Cu
#define VMCS_EXIT_INSN_INFO 0x440Eu
#define VMCS_GUEST_ACTIVITY 0x4826u
#define VMCS_GUEST_INTERRUPTIBILITY 0x4824u
#define VMCS_CR0_MASK 0x6000u
#define VMCS_CR0_SHADOW 0x6004u
#define VMCS_EXIT_QUAL 0x6400u
#define VMCS_GUEST_LINEAR_ADDR 0x640Au
#define VMCS_GUEST_CR0 0x6800u
#define VMCS_GUEST_CR3 0x6802u
#define VMCS_GUEST_CR4 0x6804u
#define VMCS_GUEST_RSP 0x681Cu
#define VMCS_GUEST_RIP 0x681Eu
#define VMCS_GUEST_RFLAGS 0x6820u
#define VMCS_HOST_CR0 0x6C00u
#define VMCS_HOST_CR3 0x6C02u
#define VMCS_HOST_CR4 0x6C04u
#define VMCS_HOST_RSP 0x6C14u
#define VMCS_HOST_RIP 0x6C16u

/* ---- VMCS / VMXON region -------------------------------------------------- */
#define VMX_REGION_BYTES 4096u
/* Zero the region, write the revision id (bit 31 clear), abort indicator 0. */
int vmx_region_init(void *region, size_t bytes, uint32_t revision_id);
/* Check a region against the expected revision; abort indicator != 0 stops. */
int vmx_region_check(const void *region, size_t bytes, uint32_t revision_id,
                     const char **reason);
const char *vmx_abort_str(uint32_t abort_indicator);

/* ---- EPT page-table builder / walker ------------------------------------- */
#define VMX_EPT_MT_UC 0u
#define VMX_EPT_MT_WC 1u
#define VMX_EPT_MT_WT 4u
#define VMX_EPT_MT_WP 5u
#define VMX_EPT_MT_WB 6u
#define VMX_EPTE_R (UINT64_C(1) << 0)
#define VMX_EPTE_W (UINT64_C(1) << 1)
#define VMX_EPTE_X (UINT64_C(1) << 2)
#define VMX_EPTE_LARGE (UINT64_C(1) << 7)
#define VMX_EPTE_ACCESSED (UINT64_C(1) << 8)
#define VMX_EPTE_DIRTY (UINT64_C(1) << 9)
#define VMX_EPTE_ADDR_MASK UINT64_C(0x000FFFFFFFFFF000)
#define VMX_EPTP_AD (UINT64_C(1) << 6)

enum vmx_ept_status {
  VMX_EPT_OK = 0,
  VMX_EPT_ERR_ARG = -1,
  VMX_EPT_ERR_ALIGN = -2,
  VMX_EPT_ERR_OOM = -3,      /* page pool exhausted */
  VMX_EPT_ERR_OVERLAP = -4,  /* conflicts with existing mapping */
  VMX_EPT_ERR_PERM = -5,     /* W without R, or X-only without cap */
  VMX_EPT_ERR_MEMTYPE = -6,
  VMX_EPT_ERR_RANGE = -7
};

/* Page pool. Tables live at virt_base + n*4096 and are known to hardware at
 * phys_base + n*4096 (identity in a real deployment; arbitrary in tests). */
struct vmx_ept_builder {
  uint8_t *virt_base;
  uint64_t phys_base;
  unsigned pages, used;
  uint64_t pml4_phys;
  int allow_2m, allow_1g, ad_enable, allow_exec_only;
  uint64_t n_4k, n_2m, n_1g;
};

int vmx_ept_builder_init(struct vmx_ept_builder *b, void *pool, uint64_t phys,
                         unsigned pages, const struct vmx_caps *caps,
                         const struct vmx_msrs *m, int want_ad);
/* perm = I1N1_EPT_R|W|X. memtype = VMX_EPT_MT_*. Picks 1G/2M/4K greedily. */
int vmx_ept_map(struct vmx_ept_builder *b, uint64_t gpa, uint64_t hpa,
                uint64_t bytes, uint32_t perm, uint32_t memtype);
/* Program every non-MMIO extent of the WS3 model; MMIO holes stay unmapped. */
int vmx_ept_build_from_model(struct vmx_ept_builder *b,
                             const struct i1n1_ept *model, uint32_t memtype);
uint64_t vmx_eptp(const struct vmx_ept_builder *b, uint32_t memtype);

struct vmx_ept_walk {
  int ok;
  uint64_t hpa;
  uint64_t page_bytes;       /* 4K / 2M / 1G leaf */
  uint32_t perm;             /* leaf R/W/X */
  uint32_t memtype;
  /* on failure: SDM exit-qualification bits for the EPT violation */
  uint64_t qual;
  int misconfig;             /* reserved/illegal encoding found */
};
/* Software walk (what the MMU would do). update_ad sets A/D like hardware. */
int vmx_ept_walk_sw(const struct vmx_ept_builder *b, uint64_t gpa,
                    uint32_t access, int update_ad, struct vmx_ept_walk *w);

/* ---- VM-exit decode -------------------------------------------------------- */
enum {
  VMX_EXIT_EXC_NMI = 0, VMX_EXIT_EXT_INT = 1, VMX_EXIT_TRIPLE_FAULT = 2,
  VMX_EXIT_CPUID = 10, VMX_EXIT_HLT = 12, VMX_EXIT_INVLPG = 14,
  VMX_EXIT_RDTSC = 16, VMX_EXIT_VMCALL = 18, VMX_EXIT_CR_ACCESS = 28,
  VMX_EXIT_IO = 30, VMX_EXIT_RDMSR = 31, VMX_EXIT_WRMSR = 32,
  VMX_EXIT_INVALID_GUEST = 33, VMX_EXIT_MSR_LOAD_FAIL = 34,
  VMX_EXIT_MCE_ENTRY = 41, VMX_EXIT_EPT_VIOLATION = 48,
  VMX_EXIT_EPT_MISCONFIG = 49, VMX_EXIT_XSETBV = 55
};
const char *vmx_exit_reason_name(uint32_t basic_reason);

struct vmx_exit_info {
  uint32_t raw_reason;
  uint32_t basic;      /* bits 15:0 */
  int entry_failure;   /* bit 31 */
  uint64_t qual;
  uint64_t gpa;
  uint64_t guest_linear;
  uint32_t insn_len;
};
void vmx_exit_decode(uint32_t raw_reason, struct vmx_exit_info *e);

struct vmx_ept_qual {
  int read, write, fetch;        /* attempted access */
  int r_ok, w_ok, x_ok;          /* entry permissions */
  int linear_valid, translation; /* bits 7, 8 */
  uint32_t access;               /* I1N1_EPT_* mask */
};
void vmx_ept_qual_decode(uint64_t q, struct vmx_ept_qual *o);

struct vmx_io_qual {
  unsigned size;    /* 1,2,4 (encoding 3 is illegal) */
  int is_in, string, rep, imm;
  uint16_t port;
  int valid;
};
void vmx_io_qual_decode(uint64_t q, struct vmx_io_qual *o);

enum { VMX_CR_MOV_TO = 0, VMX_CR_MOV_FROM = 1, VMX_CR_CLTS = 2, VMX_CR_LMSW = 3 };
struct vmx_cr_qual {
  unsigned cr, type, gpr;
  int lmsw_mem;
  uint16_t lmsw_src;
};
void vmx_cr_qual_decode(uint64_t q, struct vmx_cr_qual *o);

/* ---- Exit dispatch ----------------------------------------------------------- */
struct vmx_guest_regs {
  uint64_t r[16]; /* rax rcx rdx rbx rsp rbp rsi rdi r8..r15 (hw numbering) */
};
enum { VMX_GPR_RAX = 0, VMX_GPR_RCX = 1, VMX_GPR_RDX = 2, VMX_GPR_RBX = 3 };

enum vmx_action {
  VMX_ACT_RESUME = 0,         /* resume at same RIP (e.g. retry) */
  VMX_ACT_RESUME_ADVANCE = 1, /* RIP += insn_len, resume */
  VMX_ACT_STOP = 2            /* deterministic stop; see reason */
};
struct vmx_exit_result {
  enum vmx_action action;
  const char *reason; /* non-NULL on STOP */
  uint32_t advance;
  uint64_t detail;    /* offending GPA / port / MSR / exit reason */
};

/* Policy callbacks. A NULL callback means "not supported": the exit stops. */
struct vmx_exit_ops {
  void *ctx;
  int (*cpuid)(void *ctx, struct vmx_guest_regs *regs);
  int (*port_io)(void *ctx, uint16_t port, unsigned size, int is_in,
                 uint64_t *value);
  int (*rdmsr)(void *ctx, uint32_t msr, uint64_t *value);
  int (*wrmsr)(void *ctx, uint32_t msr, uint64_t value);
  int (*cr_access)(void *ctx, const struct vmx_cr_qual *q,
                   struct vmx_guest_regs *regs);
  /* Decode the faulting instruction for an MMIO EPT violation. */
  int (*mmio_decode)(void *ctx, const struct vmx_exit_info *e, unsigned *width,
                     int *is_write, uint64_t *value, uint32_t *insn_len);
  void (*mmio_complete)(void *ctx, uint64_t value);
  /* WS3 plumbing */
  struct i1n1_ept *ept_model;
  struct i1n1_mmio_router *router;
};

void vmx_exit_dispatch(const struct vmx_exit_ops *ops,
                       const struct vmx_exit_info *e,
                       struct vmx_guest_regs *regs, struct vmx_exit_result *r);

/* ---- Instruction backend ---------------------------------------------------- */
enum { VMX_OK = 0, VMX_FAIL_INVALID = 1, VMX_FAIL_VALID = 2, VMX_ERR_UNSUP = -1 };

struct vmx_insn_ops {
  const char *name;
  void *ctx;
  int (*vmxon)(void *ctx, uint64_t pa);
  int (*vmxoff)(void *ctx);
  int (*vmclear)(void *ctx, uint64_t pa);
  int (*vmptrld)(void *ctx, uint64_t pa);
  int (*vmwrite)(void *ctx, uint32_t field, uint64_t value);
  int (*vmread)(void *ctx, uint32_t field, uint64_t *value);
  /* Returns VMX_OK after a VM exit (guest state saved in *regs), or
   * VMX_FAIL_* when the instruction itself failed. */
  int (*vmenter)(void *ctx, int resume, struct vmx_guest_regs *regs);
  uint64_t (*rdmsr)(void *ctx, uint32_t msr);
  uint64_t (*read_cr)(void *ctx, unsigned n);
  void (*write_cr)(void *ctx, unsigned n, uint64_t v);
};

/* Real backend (inline asm). NULL unless compiled for x86_64 SysV/ELF. It is
 * NEVER executed on the dev host; running it requires VT-x root mode. */
const struct vmx_insn_ops *vmx_insn_real(void);

/* Recording mock for tests. */
#define VMX_MOCK_LOG 256u
#define VMX_MOCK_FIELDS 128u
enum vmx_mock_op {
  MOCK_VMXON = 1, MOCK_VMXOFF, MOCK_VMCLEAR, MOCK_VMPTRLD, MOCK_VMWRITE,
  MOCK_VMREAD, MOCK_LAUNCH, MOCK_RESUME, MOCK_WRCR
};
struct vmx_mock_rec {
  enum vmx_mock_op op;
  uint64_t a, b;
};
struct vmx_mock {
  struct vmx_insn_ops ops;
  struct vmx_mock_rec log[VMX_MOCK_LOG];
  unsigned nlog;
  uint32_t fields[VMX_MOCK_FIELDS];
  uint64_t values[VMX_MOCK_FIELDS];
  unsigned nfields;
  uint64_t msr_feature_control;
  uint64_t cr[5];
  int vmxon_active;
  uint64_t current_vmcs;
  int fail_next; /* VMX_FAIL_* to return from the next vmenter/vmxon */
  struct vmx_exit_info script[8]; /* exits delivered by successive vmenter */
  unsigned nscript, next_script;
};
void vmx_mock_init(struct vmx_mock *m);
void vmx_mock_set_field(struct vmx_mock *m, uint32_t field, uint64_t v);

/* ---- Session: bring-up sequence over any backend ------------------------------ */
struct vmx_session {
  const struct vmx_insn_ops *ops;
  const struct vmx_msrs *msrs;
  struct vmx_caps caps;
  int on, launched;
  const char *stop_reason;
};
/* VMXON region must have been vmx_region_init'ed by the caller. */
int vmx_session_enable(struct vmx_session *s, uint64_t vmxon_pa);
int vmx_session_load_vmcs(struct vmx_session *s, uint64_t vmcs_pa);
int vmx_session_write_controls(struct vmx_session *s,
                               const struct vmx_ctl_config *cfg);
/* One enter + exit read + dispatch. Returns the action. */
int vmx_session_run_once(struct vmx_session *s, const struct vmx_exit_ops *x,
                         struct vmx_guest_regs *regs,
                         struct vmx_exit_result *r);
int vmx_session_disable(struct vmx_session *s);

/* Driver-zone glue: reason string when the host cannot do VMX, else NULL. */
const char *dz_vmx_unsupported_reason(const struct vmx_caps *caps);

#ifdef __cplusplus
}
#endif

#endif
