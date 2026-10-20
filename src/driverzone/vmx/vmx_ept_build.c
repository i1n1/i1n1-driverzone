/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * 4-level EPT builder + software walker. Layout per SDM Vol 3 ch. 29:
 * entry bits 2:0 R/W/X, 5:3 memory type (leaf), 7 large page (PDPTE/PDE),
 * 8 accessed, 9 dirty (leaf), 51:12 address. Not exercised by hardware.
 */
#include <string.h>

#include "vmx_hw.h"

#define PAGE UINT64_C(0x1000)
#define SZ_2M UINT64_C(0x200000)
#define SZ_1G UINT64_C(0x40000000)
#define ENT_PERM_MASK UINT64_C(7)

int vmx_ept_builder_init(struct vmx_ept_builder *b, void *pool, uint64_t phys,
                         unsigned pages, const struct vmx_caps *caps,
                         const struct vmx_msrs *m, int want_ad)
{
  (void)m;
  if (b == NULL || pool == NULL || caps == NULL || pages < 1) {
    return VMX_EPT_ERR_ARG;
  }
  if (((uintptr_t)pool | phys) & (PAGE - 1)) {
    return VMX_EPT_ERR_ALIGN;
  }
  if (!caps->usable || !caps->ept || (want_ad && !caps->ept_ad)) {
    return VMX_EPT_ERR_ARG; /* feature absent: never build what HW can't run */
  }
  memset(b, 0, sizeof *b);
  b->virt_base = pool;
  b->phys_base = phys;
  b->pages = pages;
  b->allow_2m = caps->ept_2m;
  b->allow_1g = caps->ept_1g;
  b->allow_exec_only = caps->ept_exec_only;
  b->ad_enable = want_ad;
  memset(pool, 0, (size_t)pages * PAGE);
  b->used = 1;
  b->pml4_phys = phys;
  return VMX_EPT_OK;
}

static uint64_t *table_at(const struct vmx_ept_builder *b, uint64_t phys)
{
  uint64_t off;

  if (phys < b->phys_base) {
    return NULL;
  }
  off = phys - b->phys_base;
  if ((off & (PAGE - 1)) || off / PAGE >= b->used) {
    return NULL;
  }
  return (uint64_t *)(void *)(b->virt_base + off);
}

static unsigned idx(uint64_t gpa, unsigned level) /* level 4..1 */
{
  return (unsigned)((gpa >> (12 + 9 * (level - 1))) & 0x1FFu);
}

static int install(struct vmx_ept_builder *b, uint64_t gpa, uint64_t hpa,
                   unsigned leaf_level, uint32_t perm, uint32_t memtype)
{
  uint64_t *t = table_at(b, b->pml4_phys);
  unsigned level;

  for (level = 4; level > leaf_level; level--) {
    uint64_t *e = &t[idx(gpa, level)];

    if ((*e & ENT_PERM_MASK) == 0) {
      uint64_t phys;

      if (b->used >= b->pages) {
        return VMX_EPT_ERR_OOM;
      }
      phys = b->phys_base + (uint64_t)b->used * PAGE;
      b->used++;
      *e = phys | ENT_PERM_MASK; /* permissive non-leaf; leaf enforces */
    } else if (level < 4 && (*e & VMX_EPTE_LARGE)) {
      return VMX_EPT_ERR_OVERLAP; /* a large leaf already covers this */
    }
    t = table_at(b, *e & VMX_EPTE_ADDR_MASK);
    if (t == NULL) {
      return VMX_EPT_ERR_ARG;
    }
  }
  {
    uint64_t *e = &t[idx(gpa, leaf_level)];

    if (*e & ENT_PERM_MASK) {
      return VMX_EPT_ERR_OVERLAP;
    }
    *e = (hpa & VMX_EPTE_ADDR_MASK) | (uint64_t)perm |
         ((uint64_t)memtype << 3) | (leaf_level > 1 ? VMX_EPTE_LARGE : 0);
  }
  return VMX_EPT_OK;
}

int vmx_ept_map(struct vmx_ept_builder *b, uint64_t gpa, uint64_t hpa,
                uint64_t bytes, uint32_t perm, uint32_t memtype)
{
  if (b == NULL || bytes == 0) {
    return VMX_EPT_ERR_ARG;
  }
  if ((gpa | hpa | bytes) & (PAGE - 1)) {
    return VMX_EPT_ERR_ALIGN;
  }
  if (gpa >= (UINT64_C(1) << I1N1_GPA_BITS) ||
      bytes > (UINT64_C(1) << I1N1_GPA_BITS) - gpa ||
      hpa > (VMX_EPTE_ADDR_MASK | (PAGE - 1)) - bytes + 1) {
    return VMX_EPT_ERR_RANGE;
  }
  if (perm == 0 || (perm & ~7u) != 0 || ((perm & 2u) && !(perm & 1u)) ||
      (!(perm & 1u) && (perm & 4u) && !b->allow_exec_only)) {
    return VMX_EPT_ERR_PERM;
  }
  if (!(memtype == VMX_EPT_MT_UC || memtype == VMX_EPT_MT_WC ||
        memtype == VMX_EPT_MT_WT || memtype == VMX_EPT_MT_WP ||
        memtype == VMX_EPT_MT_WB)) {
    return VMX_EPT_ERR_MEMTYPE;
  }
  while (bytes) {
    unsigned level = 1;
    uint64_t sz = PAGE;
    int rc;

    if (b->allow_1g && bytes >= SZ_1G && !((gpa | hpa) & (SZ_1G - 1))) {
      level = 3;
      sz = SZ_1G;
    } else if (b->allow_2m && bytes >= SZ_2M && !((gpa | hpa) & (SZ_2M - 1))) {
      level = 2;
      sz = SZ_2M;
    }
    rc = install(b, gpa, hpa, level, perm, memtype);
    if (rc != VMX_EPT_OK) {
      return rc; /* tables may be partially populated; caller discards */
    }
    if (level == 3) {
      b->n_1g++;
    } else if (level == 2) {
      b->n_2m++;
    } else {
      b->n_4k++;
    }
    gpa += sz;
    hpa += sz;
    bytes -= sz;
  }
  return VMX_EPT_OK;
}

int vmx_ept_build_from_model(struct vmx_ept_builder *b,
                             const struct i1n1_ept *model, uint32_t memtype)
{
  unsigned i;

  if (b == NULL || model == NULL) {
    return VMX_EPT_ERR_ARG;
  }
  for (i = 0; i < model->count; i++) {
    const struct i1n1_ept_extent *e = &model->ext[i];
    int rc;

    if (e->mmio) {
      continue; /* hole: stays not-present so access raises EPT violation */
    }
    rc = vmx_ept_map(b, e->gpa, e->hpa, e->bytes, e->perm, memtype);
    if (rc != VMX_EPT_OK) {
      return rc;
    }
  }
  return VMX_EPT_OK;
}

uint64_t vmx_eptp(const struct vmx_ept_builder *b, uint32_t memtype)
{
  return b->pml4_phys | (uint64_t)(memtype & 7u) | (UINT64_C(3) << 3) |
         (b->ad_enable ? VMX_EPTP_AD : 0);
}

int vmx_ept_walk_sw(const struct vmx_ept_builder *b, uint64_t gpa,
                    uint32_t access, int update_ad, struct vmx_ept_walk *w)
{
  uint64_t *ents[4];
  unsigned depth = 0, level;
  uint64_t *t;
  uint32_t eff = 7;

  if (b == NULL || w == NULL || access == 0 || (access & ~7u) != 0 ||
      gpa >= (UINT64_C(1) << I1N1_GPA_BITS)) {
    return VMX_EPT_ERR_ARG;
  }
  memset(w, 0, sizeof *w);
  w->qual = access; /* bits 2:0 = attempted R/W/X (same encoding) */
  t = table_at(b, b->pml4_phys);
  for (level = 4; level >= 1; level--) {
    uint64_t *e = &t[idx(gpa, level)];
    uint64_t v = *e;
    uint32_t p = (uint32_t)(v & ENT_PERM_MASK);
    int leaf = (level == 1) || (level < 4 && (v & VMX_EPTE_LARGE));

    if (p == 0) {
      w->qual |= 0; /* not present: entry R/W/X bits all clear */
      return 1;
    }
    if ((p & 2u) && !(p & 1u)) {
      w->misconfig = 1; /* W without R */
      return 1;
    }
    if (p == 4u && !b->allow_exec_only) {
      w->misconfig = 1;
      return 1;
    }
    if (level == 4 && (v & VMX_EPTE_LARGE)) {
      w->misconfig = 1;
      return 1;
    }
    eff &= p;
    ents[depth++] = e;
    if (leaf) {
      uint32_t mt = (uint32_t)((v >> 3) & 7u);
      uint64_t sz = level == 3 ? SZ_1G : level == 2 ? SZ_2M : PAGE;
      uint64_t base = (v & VMX_EPTE_ADDR_MASK) & ~(sz - 1);
      unsigned k;

      if (mt == 2 || mt == 3 || mt == 7) {
        w->misconfig = 1;
        return 1;
      }
      w->qual |= (uint64_t)eff << 3;
      if ((access & eff) != access) {
        return 1; /* permission violation */
      }
      if (b->ad_enable && update_ad) {
        for (k = 0; k < depth; k++) {
          *ents[k] |= VMX_EPTE_ACCESSED;
        }
        if (access & 2u) {
          *e |= VMX_EPTE_DIRTY;
        }
      }
      w->ok = 1;
      w->qual = 0;
      w->hpa = base + (gpa & (sz - 1));
      w->page_bytes = sz;
      w->perm = eff;
      w->memtype = mt;
      return 0;
    }
    t = table_at(b, v & VMX_EPTE_ADDR_MASK);
    if (t == NULL) {
      w->misconfig = 1; /* points outside the pool */
      return 1;
    }
  }
  w->misconfig = 1;
  return 1;
}
