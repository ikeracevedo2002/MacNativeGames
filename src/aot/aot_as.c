/*
 * G3 increment 1: guest address space with per-page Horizon permissions.
 * See src/aot/aot_as.h for the contract and the Mac reference.
 */
#include "aot_as.h"

#include <stdlib.h>
#include <string.h>

#include "host_vm.h"

typedef struct AotAsRegion {
    uint64_t base;          /* guest base (4 KiB aligned) */
    uint64_t size;          /* guest size (4 KiB multiple) */
    uint8_t *host;          /* host backing (page aligned) */
    host_vm_region *vm;     /* owned host reservation */
    uint32_t state;         /* AOT_AS_STATE_* or caller-defined */
    uint32_t page_count;
    uint8_t *perm;          /* per 4 KiB page: R|W|X plus ATTR_LOCKED */
} AotAsRegion;

struct AotAddressSpace {
    AotMemDomain *domain;
    uint32_t sealed;
    /* Set by aot_as_poison(): a failed load owns a space that must never be
     * sealable or growable afterwards (loader review fix 1). */
    uint32_t poisoned;
    uint32_t count;
    AotAsRegion region[AOT_AS_MAX_REGIONS];
};

/* ------------------------------------------------------------------ util -- */

static uint16_t le16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8));
}
static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}
static uint64_t le64(const uint8_t *p) {
    return (uint64_t)le32(p) | ((uint64_t)le32(p + 4) << 32);
}

/* TEST-ONLY wrong-implementation control (never defined for a shipping build).
 * It is compiled only into the aot_as_mut_no_perm probe and suppresses exactly
 * one behaviour: the per-page permission predicate. Region range checks, the
 * locked attribute, the page table and the host protections keep the same
 * shape, so the control cannot mask an infrastructure failure; it makes a
 * forbidden access succeed, which is what the probe must reject. */
static uint8_t as_effective_perm(uint8_t stored) {
#ifdef MN_AOT_MUTANT_NO_PERM
    (void)stored;
    return (uint8_t)AOT_AS_PERM_RW;
#else
    return stored;
#endif
}

static uint8_t as_access_bits(uint8_t perm) {
    return (uint8_t)(perm & (AOT_AS_PERM_R | AOT_AS_PERM_W | AOT_AS_PERM_X));
}

static int as_page_permits(const AotAsRegion *r, uint32_t page_index,
                           int for_write) {
    uint8_t p = as_access_bits(as_effective_perm(r->perm[page_index]));
    return for_write ? ((p & AOT_AS_PERM_W) != 0u)
                     : ((p & AOT_AS_PERM_R) != 0u);
}

/* Guest permission -> HOST protection of the backing page.
 *
 * The guest X bit is NOT a host-execute request. Guest text holds ARM64 bytes
 * that the host CPU can never execute, and the design forbids dynamically
 * created host-executable memory, so X is bookkeeping plus the dispatch-side
 * check only:
 *
 *     R-X -> host READ      (PAGE_READONLY: no EXECUTE bit)
 *     RW- -> host READ|WRITE
 *     R-- -> host READ
 *     --- -> host NOACCESS
 */
static unsigned as_host_prot(uint8_t perm) {
    unsigned p = as_access_bits(as_effective_perm(perm));
    unsigned out = 0u;
    if ((p & AOT_AS_PERM_R) != 0u) out |= HOST_VM_PROT_READ;
    if ((p & AOT_AS_PERM_W) != 0u) out |= HOST_VM_PROT_WRITE;
#ifdef MN_AOT_MUTANT_HOST_EXEC
    /* WRONG (lead finding): the guest X bit is forwarded to the host mapping, so
     * an ARM64 text page becomes host-executable (PAGE_EXECUTE_READ). The probe
     * check "guest text page is host READ-ONLY (no EXECUTE)" must reject this. */
    if ((p & AOT_AS_PERM_X) != 0u) out |= HOST_VM_PROT_EXEC;
#endif
    return out;
}

static int as_perm_value_valid(uint32_t perm) {
    return perm == AOT_AS_PERM_NONE || perm == AOT_AS_PERM_R ||
           perm == AOT_AS_PERM_RW || perm == AOT_AS_PERM_RX;
}

/* Index of the single region that fully contains [addr, addr+n), or -1.
 * An access may never straddle two regions: regions are independent mappings
 * with independent lifetimes and a straddling access has no defined host
 * bytes, so it fails closed as AOT_MEM_ERR_RANGE. */
static int as_region_index(const AotAddressSpace *as, uint64_t addr,
                           uint64_t n) {
    if (as == NULL || n == 0u) return -1;
    if (addr > UINT64_MAX - n) return -1;
    uint64_t end = addr + n;
    for (uint32_t i = 0; i < as->count; i++) {
        const AotAsRegion *r = &as->region[i];
        if (addr < r->base) return -1;   /* sorted: no later region can hold it */
        uint64_t r_end = r->base + r->size;
        if (addr < r_end) return (end <= r_end) ? (int)i : -1;
    }
    return -1;
}

static AotMemStatus as_apply_host_page(AotAsRegion *r, uint32_t page_index) {
    unsigned old_prot = 0u;
    host_vm_result hr = host_vm_protect(
        r->vm, (size_t)page_index << AOT_AS_PAGE_SHIFT,
        (size_t)AOT_AS_PAGE_BYTES,
        as_host_prot(r->perm[page_index]), &old_prot);
    /* No dedicated host-failure code exists in AotMemStatus (appending a new
     * value would change the enumerated contract), so a host refusal is
     * reported as AOT_MEM_ERR_RANGE with the software table left unchanged. */
    return (hr == HOST_VM_OK) ? AOT_MEM_OK : AOT_MEM_ERR_RANGE;
}

static AotMemStatus as_copy_in(const AotAddressSpace *as, uint64_t addr,
                               uint8_t *dst, uint64_t n) {
    int ri;
    if (n == 0u) return AOT_MEM_OK;
    ri = as_region_index(as, addr, n);
    if (ri < 0) return AOT_MEM_ERR_RANGE;
    const AotAsRegion *r = &as->region[ri];
    uint64_t first = (addr - r->base) >> AOT_AS_PAGE_SHIFT;
    uint64_t last = ((addr + n - 1u) - r->base) >> AOT_AS_PAGE_SHIFT;
    /* Every page is checked BEFORE a single byte is read. */
    for (uint64_t pg = first; pg <= last; pg++) {
        if (!as_page_permits(r, (uint32_t)pg, 0)) return AOT_MEM_ERR_PERM;
    }
    uint64_t done = 0;
    for (uint64_t pg = first; pg <= last; pg++) {
        uint64_t page_start = r->base + (pg << AOT_AS_PAGE_SHIFT);
        uint64_t off = (addr + done) - page_start;
        uint64_t chunk = AOT_AS_PAGE_BYTES - off;
        if (chunk > n - done) chunk = n - done;
        memcpy(dst + done, r->host + (page_start - r->base) + off,
               (size_t)chunk);
        done += chunk;
    }
    return AOT_MEM_OK;
}

static AotMemStatus as_copy_out(AotAddressSpace *as, uint64_t addr,
                                const uint8_t *src, uint64_t n) {
    int ri;
    if (n == 0u) return AOT_MEM_OK;
    ri = as_region_index(as, addr, n);
    if (ri < 0) return AOT_MEM_ERR_RANGE;
    AotAsRegion *r = &as->region[ri];
    uint64_t first = (addr - r->base) >> AOT_AS_PAGE_SHIFT;
    uint64_t last = ((addr + n - 1u) - r->base) >> AOT_AS_PAGE_SHIFT;
#ifndef MN_AOT_MUTANT_PARTIAL_STORE
    /* Fail closed: every page is checked BEFORE a single byte is written. */
    for (uint64_t pg = first; pg <= last; pg++) {
        if (!as_page_permits(r, (uint32_t)pg, 1)) return AOT_MEM_ERR_PERM;
    }
#endif
    uint64_t done = 0;
    for (uint64_t pg = first; pg <= last; pg++) {
#ifdef MN_AOT_MUTANT_PARTIAL_STORE
        /* TEST-ONLY wrong-implementation control: the per-page permission is
         * checked as each page is written, so a later failing page leaves the
         * earlier pages modified (a partial store). Compiled only into the
         * aot_as_mut_partial_store probe; it cannot cause a crash because only
         * permitted pages are written. */
        if (!as_page_permits(r, (uint32_t)pg, 1)) return AOT_MEM_ERR_PERM;
#endif
        uint64_t page_start = r->base + (pg << AOT_AS_PAGE_SHIFT);
        uint64_t off = (addr + done) - page_start;
        uint64_t chunk = AOT_AS_PAGE_BYTES - off;
        if (chunk > n - done) chunk = n - done;
        memcpy(r->host + (page_start - r->base) + off, src + done,
               (size_t)chunk);
        done += chunk;
    }
    return AOT_MEM_OK;
}

/* --------------------------------------------------------------- lifetime -- */

AotAddressSpace *aot_as_create(AotMemDomain *domain) {
    AotAddressSpace *as;
    if (domain == NULL) return NULL;
    as = (AotAddressSpace *)calloc(1, sizeof(AotAddressSpace));
    if (as == NULL) return NULL;
    as->domain = domain;
    return as;
}

void aot_as_destroy(AotAddressSpace *as) {
    if (as == NULL) return;
    for (uint32_t i = 0; i < as->count; i++) {
        if (as->region[i].vm != NULL) host_vm_release(as->region[i].vm);
        free(as->region[i].perm);
    }
    free(as);
}

AotMemDomain *aot_as_domain(const AotAddressSpace *as) {
    return (as == NULL) ? NULL : as->domain;
}

/* The seal/poison flags are written under the domain lock (aot_as_seal,
 * aot_as_poison), so the observers read them under the same lock: an unlocked
 * read could report a stale flag to a loader/runtime that then acts on it.
 * Neither accessor is called with the lock held. */
int aot_as_is_sealed(const AotAddressSpace *as) {
    int sealed;
    if (as == NULL) return 0;
    aot_mem_domain_lock(as->domain);
    sealed = (as->sealed != 0u);
    aot_mem_domain_unlock(as->domain);
    return sealed;
}

void aot_as_poison(AotAddressSpace *as) {
    if (as == NULL) return;
    aot_mem_domain_lock(as->domain);
    as->poisoned = 1u;
    aot_mem_domain_unlock(as->domain);
}

int aot_as_is_poisoned(const AotAddressSpace *as) {
    int poisoned;
    if (as == NULL) return 0;
    aot_mem_domain_lock(as->domain);
    poisoned = (as->poisoned != 0u);
    aot_mem_domain_unlock(as->domain);
    return poisoned;
}

/* ---------------------------------------------------------------- regions -- */

AotMemStatus aot_as_add_region(AotAddressSpace *as, uint64_t guest_base,
                               uint64_t size, uint32_t perm, uint32_t state,
                               void **out_host_base) {
    host_vm_region *vm = NULL;
    void *host = NULL;
    size_t host_size = 0;
    uint8_t *table = NULL;
    uint32_t page_count;
    size_t insert_at;

    if (out_host_base != NULL) *out_host_base = NULL;
    if (as == NULL) return AOT_MEM_ERR_RANGE;
    if (!as_perm_value_valid(perm)) return AOT_MEM_ERR_WIDTH;
    if (size == 0u) return AOT_MEM_ERR_RANGE;
    if ((guest_base & AOT_AS_PAGE_MASK) != 0u) return AOT_MEM_ERR_RANGE;
    if ((size & AOT_AS_PAGE_MASK) != 0u) return AOT_MEM_ERR_RANGE;
    if (guest_base < AOT_AS_MIN_ADDR) return AOT_MEM_ERR_RANGE;
    if (guest_base > UINT64_MAX - size) return AOT_MEM_ERR_RANGE;
    if (guest_base + size > AOT_AS_MAX_ADDR) return AOT_MEM_ERR_RANGE;
    if (size / AOT_AS_PAGE_BYTES > 0xffffffffull) return AOT_MEM_ERR_RANGE;

    /* `sealed` and `poisoned` are read ONLY under the lock: see
     * aot_as_is_sealed. */
    aot_mem_domain_lock(as->domain);
    if (as->sealed || as->poisoned || as->count >= AOT_AS_MAX_REGIONS) {
        aot_mem_domain_unlock(as->domain);
        return AOT_MEM_ERR_RANGE;
    }
    /* Cheap pre-check under the lock so a doomed region does not reserve host
     * address space; the insertion is re-verified after the reservation. */
    for (size_t i = 0; i < as->count; i++) {
        const AotAsRegion *r = &as->region[i];
        if (guest_base < r->base + r->size && r->base < guest_base + size) {
            aot_mem_domain_unlock(as->domain);
            return AOT_MEM_ERR_RANGE;
        }
    }
    aot_mem_domain_unlock(as->domain);

    /* Host reservation happens outside the domain lock: it is an init-only,
     * non-guest operation and nothing can observe the region until it is
     * published in the table below. */
    page_count = (uint32_t)(size / AOT_AS_PAGE_BYTES);
    if (host_vm_reserve((size_t)size, &vm) != HOST_VM_OK) return AOT_MEM_ERR_RANGE;
    if (host_vm_commit(vm, 0, (size_t)size) != HOST_VM_OK) {
        host_vm_release(vm);
        return AOT_MEM_ERR_RANGE;
    }
    if (host_vm_base(vm, &host, &host_size) != HOST_VM_OK || host == NULL ||
        host_size < (size_t)size) {
        host_vm_release(vm);
        return AOT_MEM_ERR_RANGE;
    }
    if ((uint64_t)(uintptr_t)host > UINT64_MAX - size) {
        host_vm_release(vm);
        return AOT_MEM_ERR_RANGE;
    }
    table = (uint8_t *)malloc((size_t)page_count);
    if (table == NULL) {
        host_vm_release(vm);
        return AOT_MEM_ERR_RANGE;
    }
    memset(table, (int)perm, (size_t)page_count);

    aot_mem_domain_lock(as->domain);
    if (as->sealed || as->poisoned || as->count >= AOT_AS_MAX_REGIONS) {
        aot_mem_domain_unlock(as->domain);
        free(table);
        host_vm_release(vm);
        return AOT_MEM_ERR_RANGE;
    }
    /* Sorted-by-base table: re-check overlap and find the insertion point. */
    insert_at = as->count;
    for (size_t i = 0; i < as->count; i++) {
        const AotAsRegion *r = &as->region[i];
        if (guest_base < r->base + r->size && r->base < guest_base + size) {
            aot_mem_domain_unlock(as->domain);
            free(table);
            host_vm_release(vm);
            return AOT_MEM_ERR_RANGE;
        }
        if (guest_base < r->base && i < insert_at) insert_at = i;
    }
    for (size_t i = as->count; i > insert_at; i--)
        as->region[i] = as->region[i - 1];
    as->region[insert_at].base = guest_base;
    as->region[insert_at].size = size;
    as->region[insert_at].host = (uint8_t *)host;
    as->region[insert_at].vm = vm;
    as->region[insert_at].state = state;
    as->region[insert_at].page_count = page_count;
    as->region[insert_at].perm = table;
    as->count++;
    aot_mem_domain_unlock(as->domain);

    if (out_host_base != NULL) *out_host_base = host;
    return AOT_MEM_OK;
}

AotMemStatus aot_as_seal(AotAddressSpace *as) {
    AotMemStatus st = AOT_MEM_OK;
    if (as == NULL) return AOT_MEM_ERR_RANGE;
    aot_mem_domain_lock(as->domain);
    if (as->poisoned) {
        /* A poisoned space is the residue of a failed load: never seal it. */
        aot_mem_domain_unlock(as->domain);
        return AOT_MEM_ERR_RANGE;
    }
    if (!as->sealed) {
        /* Apply the declared permissions to the host pages FIRST and publish
         * `sealed` only once every page honoured them: a partially applied
         * seal must stay retryable instead of freezing a half-protected
         * table (a retry re-applies the same declared permissions). */
        for (uint32_t i = 0; i < as->count && st == AOT_MEM_OK; i++) {
            for (uint32_t p = 0; p < as->region[i].page_count; p++) {
                st = as_apply_host_page(&as->region[i], p);
                if (st != AOT_MEM_OK) break;
            }
        }
        if (st == AOT_MEM_OK) as->sealed = 1u;
    }
    aot_mem_domain_unlock(as->domain);
    return st;
}

AotMemStatus aot_as_protect(AotAddressSpace *as, uint64_t addr, uint64_t size,
                            uint32_t perm) {
    AotMemStatus st = AOT_MEM_OK;
    int ri;
    uint64_t first, last;

    if (as == NULL) return AOT_MEM_ERR_RANGE;
    if ((addr & AOT_AS_PAGE_MASK) != 0u) return AOT_MEM_ERR_ALIGN;
    if (size == 0u || (size & AOT_AS_PAGE_MASK) != 0u) return AOT_MEM_ERR_ALIGN;
    if (perm != AOT_AS_PERM_NONE && perm != AOT_AS_PERM_R &&
        perm != AOT_AS_PERM_RW) {
        /* Data pages only: the executable permission is a seal-time property. */
        return AOT_MEM_ERR_WIDTH;
    }

    aot_mem_domain_lock(as->domain);
    if (!as->sealed) {
        /* The region table is frozen by seal; before that the declared
         * permissions are still being established and a mid-init protect
         * would race the seal's host-protection pass. */
        aot_mem_domain_unlock(as->domain);
        return AOT_MEM_ERR_RANGE;
    }
    ri = as_region_index(as, addr, size);
    if (ri < 0) {
        aot_mem_domain_unlock(as->domain);
        return AOT_MEM_ERR_RANGE;
    }
    {
        AotAsRegion *r = &as->region[ri];
        first = (addr - r->base) >> AOT_AS_PAGE_SHIFT;
        last = ((addr + size - 1u) - r->base) >> AOT_AS_PAGE_SHIFT;
        for (uint64_t pg = first; pg <= last; pg++) {
            uint8_t cur = r->perm[pg];
            if ((cur & AOT_AS_ATTR_LOCKED) != 0u ||
                (cur & AOT_AS_PERM_X) != 0u ||
                r->state == AOT_AS_STATE_TEXT) {
                /* Mac semantics: a RELRO-locked page, and any page that is
                 * currently executable, refuses a data permission change.
                 * A page of a TEXT-state region is executable by state even
                 * when its current permission byte is {0,1,3} (e.g. after a
                 * data write was granted), so it is refused too. */
                aot_mem_domain_unlock(as->domain);
                return AOT_MEM_ERR_PERM;
            }
        }
        /* Apply at the host level FIRST, with the table entry temporarily set
         * so the host page and the software table can never disagree; the
         * table is committed only when every page honours the change. */
        for (uint64_t pg = first; pg <= last; pg++) {
            uint8_t prev = r->perm[pg];
            r->perm[pg] = (uint8_t)perm;
            st = as_apply_host_page(r, (uint32_t)pg);
            r->perm[pg] = prev;
            if (st != AOT_MEM_OK) {
                /* Roll back the pages already changed, using the UNCHANGED
                 * table entry (still the old permission) for each of them:
                 * the new permission is never installed during rollback, so a
                 * failed protect leaves table and host pages as they were. */
                AotMemStatus rollback = AOT_MEM_OK;

                for (uint64_t q = first; q < pg; q++) {
                    AotMemStatus one = as_apply_host_page(r, (uint32_t)q);
                    if (one != AOT_MEM_OK) rollback = one;
                }
                if (rollback != AOT_MEM_OK) {
                    /* Review fix 6: a rollback that itself fails leaves the
                     * software table (old permissions) and the host pages
                     * (mixed) disagreeing, and no API caller can observe or
                     * repair that. Fail closed: poison the space so it can
                     * never be sealed, grown or run. */
                    as->poisoned = 1u;
                }
                aot_mem_domain_unlock(as->domain);
                return st;
            }
        }
        for (uint64_t pg = first; pg <= last; pg++) r->perm[pg] = (uint8_t)perm;
    }
    aot_mem_domain_unlock(as->domain);
    return AOT_MEM_OK;
}

AotMemStatus aot_as_lock(AotAddressSpace *as, uint64_t addr, uint64_t size) {
    int ri;
    uint64_t first, last;
    if (as == NULL) return AOT_MEM_ERR_RANGE;
    if ((addr & AOT_AS_PAGE_MASK) != 0u) return AOT_MEM_ERR_ALIGN;
    if (size == 0u || (size & AOT_AS_PAGE_MASK) != 0u) return AOT_MEM_ERR_ALIGN;
    aot_mem_domain_lock(as->domain);
    if (!as->sealed) {
        aot_mem_domain_unlock(as->domain);
        return AOT_MEM_ERR_RANGE;
    }
    ri = as_region_index(as, addr, size);
    if (ri < 0) {
        aot_mem_domain_unlock(as->domain);
        return AOT_MEM_ERR_RANGE;
    }
    {
        AotAsRegion *r = &as->region[ri];
        first = (addr - r->base) >> AOT_AS_PAGE_SHIFT;
        last = ((addr + size - 1u) - r->base) >> AOT_AS_PAGE_SHIFT;
        for (uint64_t pg = first; pg <= last; pg++)
            r->perm[pg] = (uint8_t)(r->perm[pg] | AOT_AS_ATTR_LOCKED);
    }
    aot_mem_domain_unlock(as->domain);
    return AOT_MEM_OK;
}

int aot_as_query(AotAddressSpace *as, uint64_t addr, AotAsQuery *out) {
    int ri;
    uint64_t page;
    uint64_t lo, hi;
    AotAsQuery q;
    if (as == NULL || out == NULL) return 0;
    aot_mem_domain_lock(as->domain);
    ri = as_region_index(as, addr, 1u);
    if (ri < 0) {
        aot_mem_domain_unlock(as->domain);
        return 0;
    }
    {
        const AotAsRegion *r = &as->region[ri];
        page = (addr - r->base) >> AOT_AS_PAGE_SHIFT;
        lo = page;
        hi = page + 1u;
        while (lo > 0u && r->perm[lo - 1u] == r->perm[page]) lo--;
        while (hi < r->page_count && r->perm[hi] == r->perm[page]) hi++;
        q.base = r->base + (lo << AOT_AS_PAGE_SHIFT);
        q.size = (hi - lo) << AOT_AS_PAGE_SHIFT;
        q.perm = (uint32_t)as_access_bits(r->perm[page]);
        q.state = r->state;
        q.attr = (uint32_t)(r->perm[page] & AOT_AS_ATTR_LOCKED);
    }
    aot_mem_domain_unlock(as->domain);
    *out = q;
    return 1;
}

int aot_as_host_page(const AotAddressSpace *as, uint64_t addr,
                     host_vm_region **out_vm, const uint8_t **out_page,
                     size_t *out_offset) {
    int ri;
    if (as == NULL) return 0;
    ri = as_region_index(as, addr, 1u);
    if (ri < 0) return 0;
    {
        const AotAsRegion *r = &as->region[ri];
        uint64_t page = (addr - r->base) >> AOT_AS_PAGE_SHIFT;
        if (out_vm != NULL) *out_vm = r->vm;
        if (out_page != NULL) {
            *out_page = r->host + (size_t)(page << AOT_AS_PAGE_SHIFT);
        }
        if (out_offset != NULL) {
            *out_offset = (size_t)(page << AOT_AS_PAGE_SHIFT);
        }
    }
    return 1;
}

/* ------------------------------------------------------- access (locked) -- */

AotMemStatus aot_as_range_locked(const AotAddressSpace *as, uint64_t addr,
                                 uint64_t n) {
    if (as == NULL) return AOT_MEM_ERR_RANGE;
    if (n == 0u) return AOT_MEM_OK;
    return (as_region_index(as, addr, n) < 0) ? AOT_MEM_ERR_RANGE : AOT_MEM_OK;
}

AotMemStatus aot_as_check_locked(const AotAddressSpace *as, uint64_t addr,
                                 uint64_t n, int for_write) {
    int ri;
    if (as == NULL) return AOT_MEM_ERR_RANGE;
    if (n == 0u) return AOT_MEM_OK;
    ri = as_region_index(as, addr, n);
    if (ri < 0) return AOT_MEM_ERR_RANGE;
    {
        const AotAsRegion *r = &as->region[ri];
        uint64_t first = (addr - r->base) >> AOT_AS_PAGE_SHIFT;
        uint64_t last = ((addr + n - 1u) - r->base) >> AOT_AS_PAGE_SHIFT;
        for (uint64_t pg = first; pg <= last; pg++) {
            if (!as_page_permits(r, (uint32_t)pg, for_write))
                return AOT_MEM_ERR_PERM;
        }
    }
    return AOT_MEM_OK;
}

AotMemStatus aot_as_read(AotAddressSpace *as, uint64_t addr, void *buf,
                         uint64_t n) {
    AotMemStatus st;
    if (as == NULL || (buf == NULL && n != 0u)) return AOT_MEM_ERR_RANGE;
    aot_mem_domain_lock(as->domain);
    st = as_copy_in(as, addr, (uint8_t *)buf, n);
    aot_mem_domain_unlock(as->domain);
    return st;
}

AotMemStatus aot_as_write(AotAddressSpace *as, uint64_t addr, const void *buf,
                          uint64_t n) {
    AotMemStatus st;
    if (as == NULL || (buf == NULL && n != 0u)) return AOT_MEM_ERR_RANGE;
    aot_mem_domain_lock(as->domain);
    st = as_copy_out(as, addr, (const uint8_t *)buf, n);
    aot_mem_domain_unlock(as->domain);
    return st;
}

AotMemStatus aot_as_ld_locked(const AotAddressSpace *as, uint64_t addr,
                              unsigned width, uint64_t *out) {
    uint8_t b[8];
    AotMemStatus st;
    if (out == NULL) return AOT_MEM_ERR_RANGE;
    if (width != 1u && width != 2u && width != 4u && width != 8u)
        return AOT_MEM_ERR_WIDTH;
    st = as_copy_in(as, addr, b, (uint64_t)width);
    if (st != AOT_MEM_OK) return st;
    switch (width) {
    case 1u: *out = (uint64_t)b[0]; break;
    case 2u: *out = (uint64_t)le16(b); break;
    case 4u: *out = (uint64_t)le32(b); break;
    default: *out = le64(b); break;
    }
    return AOT_MEM_OK;
}

AotMemStatus aot_as_st_locked(AotAddressSpace *as, uint64_t addr,
                              unsigned width, uint64_t value) {
    uint8_t b[8];
    if (width != 1u && width != 2u && width != 4u && width != 8u)
        return AOT_MEM_ERR_WIDTH;
    for (unsigned i = 0; i < width; i++)
        b[i] = (uint8_t)((value >> (8u * i)) & 0xffu);
    return as_copy_out(as, addr, b, (uint64_t)width);
}

int aot_as_range_mapped(AotAddressSpace *as, uint64_t addr, uint64_t n) {
    int mapped = 0;
    if (as == NULL || n == 0u) return 0;
    if (addr > UINT64_MAX - n) return 1;   /* wrapping range: fail closed */
    aot_mem_domain_lock(as->domain);
    for (uint32_t i = 0; i < as->count && !mapped; i++) {
        const AotAsRegion *r = &as->region[i];
        if (addr < r->base + r->size && r->base < addr + n) mapped = 1;
    }
    aot_mem_domain_unlock(as->domain);
    return mapped;
}
