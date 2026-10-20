/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Real VMX instruction backend (inline asm). Compiled only for x86_64 ELF
 * (SysV) targets; on every other host vmx_insn_real() returns NULL so the
 * driver zone keeps its deterministic "unsupported: no VT-x" stop.
 *
 * NEVER EXECUTED on any VT-x host by this project yet. The VM-entry/exit
 * trampoline in particular is unreviewed by hardware.
 */
#include "vmx_hw.h"

#if defined(__x86_64__) && defined(__GNUC__) && !defined(__APPLE__)

#define SYSV __attribute__((sysv_abi))

static int flags_rc(uint8_t cf, uint8_t zf)
{
  return cf ? VMX_FAIL_INVALID : (zf ? VMX_FAIL_VALID : VMX_OK);
}

static int x_vmxon(void *c, uint64_t pa)
{
  uint8_t cf, zf;

  (void)c;
  __asm__ volatile("vmxon %2; setc %0; setz %1"
                   : "=q"(cf), "=q"(zf)
                   : "m"(pa)
                   : "cc", "memory");
  return flags_rc(cf, zf);
}

static int x_vmxoff(void *c)
{
  uint8_t cf, zf;

  (void)c;
  __asm__ volatile("vmxoff; setc %0; setz %1" : "=q"(cf), "=q"(zf)::"cc", "memory");
  return flags_rc(cf, zf);
}

static int x_vmclear(void *c, uint64_t pa)
{
  uint8_t cf, zf;

  (void)c;
  __asm__ volatile("vmclear %2; setc %0; setz %1"
                   : "=q"(cf), "=q"(zf)
                   : "m"(pa)
                   : "cc", "memory");
  return flags_rc(cf, zf);
}

static int x_vmptrld(void *c, uint64_t pa)
{
  uint8_t cf, zf;

  (void)c;
  __asm__ volatile("vmptrld %2; setc %0; setz %1"
                   : "=q"(cf), "=q"(zf)
                   : "m"(pa)
                   : "cc", "memory");
  return flags_rc(cf, zf);
}

static int x_vmwrite(void *c, uint32_t f, uint64_t v)
{
  uint8_t cf, zf;
  uint64_t field = f;

  (void)c;
  __asm__ volatile("vmwrite %3, %2; setc %0; setz %1"
                   : "=q"(cf), "=q"(zf)
                   : "r"(field), "r"(v)
                   : "cc", "memory");
  return flags_rc(cf, zf);
}

static int x_vmread(void *c, uint32_t f, uint64_t *v)
{
  uint8_t cf, zf;
  uint64_t field = f, out;

  (void)c;
  __asm__ volatile("vmread %3, %2; setc %0; setz %1"
                   : "=q"(cf), "=q"(zf), "=r"(out)
                   : "r"(field)
                   : "cc", "memory");
  *v = out;
  return flags_rc(cf, zf);
}

/*
 * int i1n1_vmx_run(struct vmx_guest_regs *regs, int resume)  [SysV]
 * Saves callee-saved regs and the regs pointer on the host stack, sets
 * HOST_RSP to that stack position, loads guest GPRs, VMLAUNCH/VMRESUME.
 * Reaching the instruction after it means the instruction failed (CF/ZF).
 * i1n1_vmx_exit_tramp is HOST_RIP: it stores guest GPRs back into *regs
 * (guest RSP lives in the VMCS, slot 4 is left untouched), returns 0.
 * Result: 0 exit taken, 1 VMfailInvalid, 2 VMfailValid.
 */
__asm__(
    ".text\n"
    ".globl i1n1_vmx_run\n"
    ".type i1n1_vmx_run,@function\n"
    "i1n1_vmx_run:\n"
    "  push %rbx\n  push %rbp\n  push %r12\n  push %r13\n  push %r14\n"
    "  push %r15\n"
    "  push %rdi\n"
    "  mov $0x6C14, %rax\n"
    "  mov %rsp, %rdx\n"
    "  vmwrite %rdx, %rax\n"
    "  test %esi, %esi\n"
    "  mov 8(%rdi), %rcx\n  mov 16(%rdi), %rdx\n  mov 24(%rdi), %rbx\n"
    "  mov 40(%rdi), %rbp\n  mov 48(%rdi), %rsi\n"
    "  mov 64(%rdi), %r8\n  mov 72(%rdi), %r9\n  mov 80(%rdi), %r10\n"
    "  mov 88(%rdi), %r11\n  mov 96(%rdi), %r12\n  mov 104(%rdi), %r13\n"
    "  mov 112(%rdi), %r14\n  mov 120(%rdi), %r15\n"
    "  mov 0(%rdi), %rax\n"
    "  mov 56(%rdi), %rdi\n"
    "  jnz 1f\n"
    "  vmlaunch\n"
    "  jmp 2f\n"
    "1:\n"
    "  vmresume\n"
    "2:\n"
    "  mov $1, %eax\n"
    "  jc 3f\n"
    "  mov $2, %eax\n"
    "3:\n"
    "  add $8, %rsp\n"
    "  pop %r15\n  pop %r14\n  pop %r13\n  pop %r12\n  pop %rbp\n  pop %rbx\n"
    "  ret\n"
    ".size i1n1_vmx_run,.-i1n1_vmx_run\n"
    ".globl i1n1_vmx_exit_tramp\n"
    ".type i1n1_vmx_exit_tramp,@function\n"
    "i1n1_vmx_exit_tramp:\n"
    "  push %rax\n"
    "  mov 8(%rsp), %rax\n"
    "  mov %rcx, 8(%rax)\n  mov %rdx, 16(%rax)\n  mov %rbx, 24(%rax)\n"
    "  mov %rbp, 40(%rax)\n  mov %rsi, 48(%rax)\n  mov %rdi, 56(%rax)\n"
    "  mov %r8, 64(%rax)\n  mov %r9, 72(%rax)\n  mov %r10, 80(%rax)\n"
    "  mov %r11, 88(%rax)\n  mov %r12, 96(%rax)\n  mov %r13, 104(%rax)\n"
    "  mov %r14, 112(%rax)\n  mov %r15, 120(%rax)\n"
    "  pop %rcx\n"
    "  mov %rcx, 0(%rax)\n"
    "  xor %eax, %eax\n"
    "  jmp 3b\n"
    ".size i1n1_vmx_exit_tramp,.-i1n1_vmx_exit_tramp\n");

extern SYSV int i1n1_vmx_run(struct vmx_guest_regs *regs, int resume);
extern SYSV void i1n1_vmx_exit_tramp(void);

static int x_vmenter(void *c, int resume, struct vmx_guest_regs *regs)
{
  (void)c;
  /* HOST_RIP must point at the trampoline before the first entry. */
  if (x_vmwrite(NULL, VMCS_HOST_RIP, (uint64_t)(uintptr_t)&i1n1_vmx_exit_tramp) !=
      VMX_OK) {
    return VMX_FAIL_INVALID;
  }
  return i1n1_vmx_run(regs, resume);
}

static uint64_t x_rdmsr(void *c, uint32_t msr)
{
  uint32_t lo, hi;

  (void)c;
  __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
  return ((uint64_t)hi << 32) | lo;
}

static uint64_t x_read_cr(void *c, unsigned n)
{
  uint64_t v = 0;

  (void)c;
  if (n == 0) {
    __asm__ volatile("mov %%cr0, %0" : "=r"(v));
  } else if (n == 3) {
    __asm__ volatile("mov %%cr3, %0" : "=r"(v));
  } else if (n == 4) {
    __asm__ volatile("mov %%cr4, %0" : "=r"(v));
  }
  return v;
}

static void x_write_cr(void *c, unsigned n, uint64_t v)
{
  (void)c;
  if (n == 0) {
    __asm__ volatile("mov %0, %%cr0" ::"r"(v) : "memory");
  } else if (n == 4) {
    __asm__ volatile("mov %0, %%cr4" ::"r"(v) : "memory");
  }
}

static const struct vmx_insn_ops real = {
    .name = "x86_64-vmx-asm",
    .ctx = NULL,
    .vmxon = x_vmxon,
    .vmxoff = x_vmxoff,
    .vmclear = x_vmclear,
    .vmptrld = x_vmptrld,
    .vmwrite = x_vmwrite,
    .vmread = x_vmread,
    .vmenter = x_vmenter,
    .rdmsr = x_rdmsr,
    .read_cr = x_read_cr,
    .write_cr = x_write_cr,
};

const struct vmx_insn_ops *vmx_insn_real(void) { return &real; }

#else

const struct vmx_insn_ops *vmx_insn_real(void) { return NULL; }

#endif
