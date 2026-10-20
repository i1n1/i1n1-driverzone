/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * WS6: vmx backend stub. VMXON/VMCS/EPT are NOT implemented. Every request
 * stops deterministically with an "unsupported" status and reason; there is
 * no success path, so a CI/QEMU run can never be mistaken for VT-x evidence.
 */
#include "driverzone.h"

static int32_t vmx_op(struct dz *dz, void *ctx, const struct dz_op *op,
                      struct dz_out *out)
{
  (void)dz;
  (void)ctx;
  (void)op;
  (void)out;
  return I1N1_DRV_STATUS_UNSUPPORTED; /* unreachable: reason short-circuits */
}

static const struct dz_backend vmx = {
    .name = "vmx",
    .unsupported_reason = DZ_UNSUPPORTED_NO_VTX,
    .ctx = NULL,
    .op = vmx_op,
};

const struct dz_backend *dz_vmx_backend(void) { return &vmx; }
