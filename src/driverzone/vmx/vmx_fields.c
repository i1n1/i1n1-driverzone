/* SPDX-License-Identifier: GPL-2.0-only */
/* VMCS field encodings, SDM Vol 3 Appendix B (transcribed; unit-checked for
 * internal consistency of width/type bits, not run against hardware). */
#include "vmx_hw.h"

const struct vmx_field_desc vmx_fields[] = {
    {0x0000, "VPID"},
    {0x0800, "GUEST_ES_SEL"}, {0x0802, "GUEST_CS_SEL"}, {0x0804, "GUEST_SS_SEL"},
    {0x0806, "GUEST_DS_SEL"}, {0x0808, "GUEST_FS_SEL"}, {0x080A, "GUEST_GS_SEL"},
    {0x080C, "GUEST_LDTR_SEL"}, {0x080E, "GUEST_TR_SEL"},
    {0x0C00, "HOST_ES_SEL"}, {0x0C02, "HOST_CS_SEL"}, {0x0C04, "HOST_SS_SEL"},
    {0x0C06, "HOST_DS_SEL"}, {0x0C08, "HOST_FS_SEL"}, {0x0C0A, "HOST_GS_SEL"},
    {0x0C0C, "HOST_TR_SEL"},
    {0x2000, "IO_BITMAP_A"}, {0x2002, "IO_BITMAP_B"}, {0x2004, "MSR_BITMAP"},
    {0x2006, "EXIT_MSR_STORE_ADDR"}, {0x2008, "EXIT_MSR_LOAD_ADDR"},
    {0x200A, "ENTRY_MSR_LOAD_ADDR"}, {0x2010, "TSC_OFFSET"},
    {0x201A, "EPT_POINTER"},
    {0x2400, "GUEST_PHYS_ADDR"},
    {0x2800, "VMCS_LINK_POINTER"}, {0x2802, "GUEST_DEBUGCTL"},
    {0x2806, "GUEST_EFER"}, {0x2804, "GUEST_PAT"},
    {0x2C00, "HOST_PAT"}, {0x2C02, "HOST_EFER"},
    {0x4000, "PIN_CTLS"}, {0x4002, "PROC_CTLS"}, {0x4004, "EXC_BITMAP"},
    {0x4006, "PF_ERR_MASK"}, {0x4008, "PF_ERR_MATCH"},
    {0x400A, "CR3_TARGET_COUNT"}, {0x400C, "EXIT_CTLS"},
    {0x400E, "EXIT_MSR_STORE_COUNT"}, {0x4010, "EXIT_MSR_LOAD_COUNT"},
    {0x4012, "ENTRY_CTLS"}, {0x4014, "ENTRY_MSR_LOAD_COUNT"},
    {0x4016, "ENTRY_INTR_INFO"}, {0x4018, "ENTRY_EXC_ERR"},
    {0x401A, "ENTRY_INSN_LEN"}, {0x401E, "PROC2_CTLS"},
    {0x4400, "VM_INSN_ERROR"}, {0x4402, "EXIT_REASON"},
    {0x4404, "EXIT_INTR_INFO"}, {0x4406, "EXIT_INTR_ERR"},
    {0x4408, "IDT_VECTORING_INFO"}, {0x440A, "IDT_VECTORING_ERR"},
    {0x440C, "EXIT_INSN_LEN"}, {0x440E, "EXIT_INSN_INFO"},
    {0x4800, "GUEST_ES_LIMIT"}, {0x4802, "GUEST_CS_LIMIT"},
    {0x4804, "GUEST_SS_LIMIT"}, {0x4806, "GUEST_DS_LIMIT"},
    {0x4808, "GUEST_FS_LIMIT"}, {0x480A, "GUEST_GS_LIMIT"},
    {0x480C, "GUEST_LDTR_LIMIT"}, {0x480E, "GUEST_TR_LIMIT"},
    {0x4810, "GUEST_GDTR_LIMIT"}, {0x4812, "GUEST_IDTR_LIMIT"},
    {0x4814, "GUEST_ES_AR"}, {0x4816, "GUEST_CS_AR"}, {0x4818, "GUEST_SS_AR"},
    {0x481A, "GUEST_DS_AR"}, {0x481C, "GUEST_FS_AR"}, {0x481E, "GUEST_GS_AR"},
    {0x4820, "GUEST_LDTR_AR"}, {0x4822, "GUEST_TR_AR"},
    {0x4824, "GUEST_INTERRUPTIBILITY"}, {0x4826, "GUEST_ACTIVITY"},
    {0x482A, "GUEST_SYSENTER_CS"},
    {0x4C00, "HOST_SYSENTER_CS"},
    {0x6000, "CR0_GUEST_HOST_MASK"}, {0x6002, "CR4_GUEST_HOST_MASK"},
    {0x6004, "CR0_READ_SHADOW"}, {0x6006, "CR4_READ_SHADOW"},
    {0x6400, "EXIT_QUAL"}, {0x6402, "IO_RCX"}, {0x6404, "IO_RSI"},
    {0x6406, "IO_RDI"}, {0x6408, "IO_RIP"}, {0x640A, "GUEST_LINEAR_ADDR"},
    {0x6800, "GUEST_CR0"}, {0x6802, "GUEST_CR3"}, {0x6804, "GUEST_CR4"},
    {0x6806, "GUEST_ES_BASE"}, {0x6808, "GUEST_CS_BASE"},
    {0x680A, "GUEST_SS_BASE"}, {0x680C, "GUEST_DS_BASE"},
    {0x680E, "GUEST_FS_BASE"}, {0x6810, "GUEST_GS_BASE"},
    {0x6812, "GUEST_LDTR_BASE"}, {0x6814, "GUEST_TR_BASE"},
    {0x6816, "GUEST_GDTR_BASE"}, {0x6818, "GUEST_IDTR_BASE"},
    {0x681A, "GUEST_DR7"}, {0x681C, "GUEST_RSP"}, {0x681E, "GUEST_RIP"},
    {0x6820, "GUEST_RFLAGS"}, {0x6822, "GUEST_PENDING_DBG"},
    {0x6824, "GUEST_SYSENTER_ESP"}, {0x6826, "GUEST_SYSENTER_EIP"},
    {0x6C00, "HOST_CR0"}, {0x6C02, "HOST_CR3"}, {0x6C04, "HOST_CR4"},
    {0x6C06, "HOST_FS_BASE"}, {0x6C08, "HOST_GS_BASE"},
    {0x6C0A, "HOST_TR_BASE"}, {0x6C0C, "HOST_GDTR_BASE"},
    {0x6C0E, "HOST_IDTR_BASE"}, {0x6C10, "HOST_SYSENTER_ESP"},
    {0x6C12, "HOST_SYSENTER_EIP"}, {0x6C14, "HOST_RSP"}, {0x6C16, "HOST_RIP"},
};

const size_t vmx_field_count = sizeof vmx_fields / sizeof vmx_fields[0];

const struct vmx_field_desc *vmx_field_lookup(uint32_t encoding)
{
  size_t i;

  for (i = 0; i < vmx_field_count; i++) {
    if (vmx_fields[i].encoding == encoding) {
      return &vmx_fields[i];
    }
  }
  return NULL;
}

int vmx_field_read_only(uint32_t encoding)
{
  return VMX_FIELD_TYPE(encoding) == VMX_T_EXITINFO;
}
