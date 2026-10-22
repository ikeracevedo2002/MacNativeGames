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
    /* AS_KIND_HEAP: the single SetHeapSize window. It has NO perm table (max
     * may be 4 GiB); guest permission/state are derived from heap_size, which
     * keeps the table O(1) instead of one byte per 4 KiB page. The committed
     * set is always [0, heap_high_water) and is PRIVATE to the transition code
     * (host_vm_commit rejects already-committed pages, so a grow must never
     * re-commit the retained prefix). */
    uint32_t kind;
    uint32_t reserved_role;    /* AS_KIND_RESERVED: closed role id */
    uint64_t heap_size;        /* logical size (guest-visible) */
    uint64_t heap_high_water;  /* committed high-water mark (private) */
    uint64_t heap_commit_limit;
    /* AS_KIND_RESERVED, role ALIAS only: one occupancy byte per 4 KiB page
     * (AS_ALIAS_*), plus the mapped-byte counter Mac keeps in alias_bytes.
     * NULL for every other window/region (never dereferenced). */
    uint8_t *alias_page;
    uint64_t alias_bytes;
} AotAsRegion;

/* Alias page occupancy bits (Mac services.c alias_pages/alias_stale).
 * COMMITTED is the host-storage fact the Mac port derives from its mprotect/
 * mmap calls; it never reaches guest state. */
#define AS_ALIAS_MAPPED 1u
#define AS_ALIAS_STALE 2u
#define AS_ALIAS_COMMITTED 4u
/* Transient, only alive inside one map call so the rollback can tell a page
 * this call committed from a retained one. Never published or observed. */
#define AS_ALIAS_NEW 8u

#define AS_KIND_REGION 0u
#define AS_KIND_HEAP 1u
#define AS_KIND_RESERVED 2u

/* PRIVATE COMPILE-TIME FAULT SEAMS (test only, never a runtime setter).
 * MN_AOT_HEAP_FAULT_MODE injects one host refusal so the failure/rollback
 * protocol can be exercised deterministically:
 *   1 = fresh commit fails
 *   2 = retained protect fails after a successful fresh commit
 *   3 = retained protect fails AND the fresh-commit rollback fails (sticky)
 *   4 = shrink protect-to-NONE fails
 * MN_AOT_HEAP_MUT_* are wrong-implementation controls compiled only into the
 * dedicated mutant probes; each must be rejected by a semantic check. */
#ifdef MN_AOT_HEAP_FAULT_MODE
#define AS_HEAP_FAULT_MODE (MN_AOT_HEAP_FAULT_MODE)
#else
#define AS_HEAP_FAULT_MODE 0
#endif

#ifdef MN_AOT_ALIAS_FAULT_MODE
#define AS_ALIAS_FAULT_MODE (MN_AOT_ALIAS_FAULT_MODE)
#else
#define AS_ALIAS_FAULT_MODE 0
#endif

struct AotAddressSpace {
    AotMemDomain *domain;
    uint32_t sealed;
    /* Set by aot_as_poison(): a failed load owns a space that must never be
     * sealable or growable afterwards (loader review fix 1). */
    uint32_t poisoned;
    /* Set when a failed heap transition could not roll its new host pages
     * back: the software and host views can no longer be reconciled, so every
     * later heap request fails closed. */
    uint32_t heap_desync;
    /* Same protocol for the alias window: a host change that could not be
     * reverted makes every later alias map/unmap fail closed. */
    uint32_t alias_desync;
    uint32_t count;
    AotAsRegion region[AOT_AS_MAX_REGIONS];
};

/* Index of the (at most one) registered heap window, called with the domain
 * lock held. */
static AotAsRegion *as_heap_locked(AotAddressSpace *as);
static AotAsRegion *as_reserved_locked(AotAddressSpace *as, uint32_t role);
static AotAsRegion *as_alias_locked(AotAddressSpace *as);
static int as_alias_page_mapped(const AotAsRegion *r, uint32_t page_index);

/* A window is a whole-reservation role: HEAP (SetHeapSize prefix) or
 * RESERVED (immutable alias/ASLR geometry, prefix 0). Both have no per-page
 * perm table and share every null-perm guard. */
static int as_is_window(const AotAsRegion *r) {
    return r->kind == AS_KIND_HEAP || r->kind == AS_KIND_RESERVED;
}
static uint64_t as_window_prefix(const AotAsRegion *r) {
    return (r->kind == AS_KIND_HEAP) ? r->heap_size : 0u;
}

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
    uint8_t stored;
    if (as_is_window(r)) {
        /* Derived, never a table: the heap prefix [0,size) is RW. A reserved
         * window is NONE except for the pages MapPhysicalMemory mapped in the
         * alias window (Mac alias_pages). The refusal happens BEFORE any host
         * dereference because reserve-only pages must never be touched. */
        if (r->kind == AS_KIND_RESERVED && r->alias_page != NULL)
            stored = as_alias_page_mapped(r, page_index)
                         ? (uint8_t)AOT_AS_PERM_RW
                         : (uint8_t)AOT_AS_PERM_NONE;
        else
            stored = ((uint64_t)page_index << AOT_AS_PAGE_SHIFT) <
                             as_window_prefix(r)
                         ? (uint8_t)AOT_AS_PERM_RW
                         : (uint8_t)AOT_AS_PERM_NONE;
    } else {
        stored = r->perm[page_index];
    }
    uint8_t p = as_access_bits(as_effective_perm(stored));
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
    /* AOT_MEM_ERR_HOST exists for the newer heap transition. This legacy
     * per-page protect path keeps AOT_MEM_ERR_RANGE for compatibility with its
     * existing callers, not because no host-failure code is available. */
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
        free(as->region[i].alias_page);
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
    as->region[insert_at].kind = AS_KIND_REGION;
    as->region[insert_at].reserved_role = 0u;
    as->region[insert_at].heap_size = 0u;
    as->region[insert_at].heap_high_water = 0u;
    as->region[insert_at].heap_commit_limit = 0u;
    /* The table is shifted on insert, so an entry must never inherit the alias
     * occupancy table of a reserved window that moved (destroy() frees it). */
    as->region[insert_at].alias_page = NULL;
    as->region[insert_at].alias_bytes = 0u;
    as->count++;
    aot_mem_domain_unlock(as->domain);

    if (out_host_base != NULL) *out_host_base = host;
    return AOT_MEM_OK;
}

/* Overlap of [a0,a0+n0) and [a1,a1+n1), both already bounds-checked. */
static int as_ranges_overlap(uint64_t a0, uint64_t n0, uint64_t a1,
                             uint64_t n1) {
    return a0 < a1 + n1 && a1 < a0 + n0;
}

AotMemStatus aot_as_add_heap_window(AotAddressSpace *as, uint64_t guest_base,
                                    uint64_t max_size,
                                    uint64_t commit_limit) {
    host_vm_region *vm = NULL;
    void *host = NULL;
    size_t host_size = 0;
    size_t insert_at;
    uint32_t page_count;

    if (as == NULL) return AOT_MEM_ERR_RANGE;
    if (max_size == 0u) return AOT_MEM_ERR_RANGE;
    if ((guest_base & AOT_AS_PAGE_MASK) != 0u) return AOT_MEM_ERR_RANGE;
    if ((max_size & AOT_AS_PAGE_MASK) != 0u) return AOT_MEM_ERR_RANGE;
    if (guest_base < AOT_AS_MIN_ADDR) return AOT_MEM_ERR_RANGE;
    if (guest_base > UINT64_MAX - max_size) return AOT_MEM_ERR_RANGE;
    if (guest_base + max_size > AOT_AS_MAX_ADDR) return AOT_MEM_ERR_RANGE;
    if (max_size / AOT_AS_PAGE_BYTES > 0xffffffffull) return AOT_MEM_ERR_RANGE;

    aot_mem_domain_lock(as->domain);
    if (as->sealed || as->poisoned || as->count >= AOT_AS_MAX_REGIONS ||
        as_heap_locked(as) != NULL) {
        aot_mem_domain_unlock(as->domain);
        return AOT_MEM_ERR_RANGE;
    }
    for (uint32_t i = 0; i < as->count; i++) {
        const AotAsRegion *r = &as->region[i];
        if (as_ranges_overlap(guest_base, max_size, r->base, r->size)) {
            aot_mem_domain_unlock(as->domain);
            return AOT_MEM_ERR_RANGE;
        }
    }
    aot_mem_domain_unlock(as->domain);

    /* RESERVE-ONLY: no commit and no access. The window must stay
     * untouched by seal(), and every guest access is refused by the derived
     * NONE permission until aot_as_set_heap_size() commits bytes. */
    if (host_vm_reserve((size_t)max_size, &vm) != HOST_VM_OK)
        return AOT_MEM_ERR_HOST;
    if (host_vm_base(vm, &host, &host_size) != HOST_VM_OK || host == NULL ||
        host_size < (size_t)max_size) {
        host_vm_release(vm);
        return AOT_MEM_ERR_HOST;
    }
    page_count = (uint32_t)(max_size / AOT_AS_PAGE_BYTES);

    aot_mem_domain_lock(as->domain);
    if (as->sealed || as->poisoned || as->count >= AOT_AS_MAX_REGIONS ||
        as_heap_locked(as) != NULL) {
        aot_mem_domain_unlock(as->domain);
        host_vm_release(vm);
        return AOT_MEM_ERR_RANGE;
    }
    insert_at = as->count;
    for (size_t i = 0; i < as->count; i++) {
        const AotAsRegion *r = &as->region[i];
        if (as_ranges_overlap(guest_base, max_size, r->base, r->size)) {
            aot_mem_domain_unlock(as->domain);
            host_vm_release(vm);
            return AOT_MEM_ERR_RANGE;
        }
        if (guest_base < r->base && i < insert_at) insert_at = i;
    }
    for (size_t i = as->count; i > insert_at; i--)
        as->region[i] = as->region[i - 1];
    as->region[insert_at].base = guest_base;
    as->region[insert_at].size = max_size;
    as->region[insert_at].host = (uint8_t *)host;
    as->region[insert_at].vm = vm;
    as->region[insert_at].state = AOT_AS_STATE_HEAP;
    as->region[insert_at].page_count = page_count;
    as->region[insert_at].perm = NULL;   /* heap state is derived, not a table */
    as->region[insert_at].kind = AS_KIND_HEAP;
    as->region[insert_at].reserved_role = 0u;
    as->region[insert_at].heap_size = 0u;
    as->region[insert_at].heap_high_water = 0u;
    as->region[insert_at].heap_commit_limit = commit_limit;
    as->region[insert_at].alias_page = NULL;
    as->region[insert_at].alias_bytes = 0u;
    as->count++;
    aot_mem_domain_unlock(as->domain);
    return AOT_MEM_OK;
}

AotMemStatus aot_as_bounds(const AotAddressSpace *as, uint64_t *out_base,
                           uint64_t *out_size) {
    if (as == NULL || out_base == NULL || out_size == NULL)
        return AOT_MEM_ERR_RANGE;
    *out_base = AOT_AS_MIN_ADDR;
    *out_size = AOT_AS_MAX_ADDR - AOT_AS_MIN_ADDR;
    return AOT_MEM_OK;
}

AotMemStatus aot_as_add_reserved_window(AotAddressSpace *as,
                                       uint64_t guest_base, uint64_t size,
                                       uint32_t role) {
    host_vm_region *vm = NULL;
    void *host = NULL;
    size_t host_size = 0;
    size_t insert_at;
    uint32_t page_count;
    uint8_t *alias_page;

    if (as == NULL) return AOT_MEM_ERR_RANGE;
    /* Closed role enum: ALIAS and STACK exist in this capability. Unknown
     * roles are a width/contract error, never silently mapped. */
    if (role != AOT_AS_RESERVED_ROLE_ALIAS &&
        role != AOT_AS_RESERVED_ROLE_STACK)
        return AOT_MEM_ERR_WIDTH;
    if (size == 0u) return AOT_MEM_ERR_RANGE;
    if ((guest_base & AOT_AS_PAGE_MASK) != 0u) return AOT_MEM_ERR_RANGE;
    if ((size & AOT_AS_PAGE_MASK) != 0u) return AOT_MEM_ERR_RANGE;
    if (guest_base < AOT_AS_MIN_ADDR) return AOT_MEM_ERR_RANGE;
    if (guest_base > UINT64_MAX - size) return AOT_MEM_ERR_RANGE;
    if (guest_base + size > AOT_AS_MAX_ADDR) return AOT_MEM_ERR_RANGE;
    if (size / AOT_AS_PAGE_BYTES > 0xffffffffull) return AOT_MEM_ERR_RANGE;

    aot_mem_domain_lock(as->domain);
    if (as->sealed || as->poisoned || as->count >= AOT_AS_MAX_REGIONS ||
        as_reserved_locked(as, role) != NULL) {
        aot_mem_domain_unlock(as->domain);
        return AOT_MEM_ERR_RANGE;
    }
    for (uint32_t i = 0; i < as->count; i++) {
        const AotAsRegion *r = &as->region[i];
        if (as_ranges_overlap(guest_base, size, r->base, r->size)) {
            aot_mem_domain_unlock(as->domain);
            return AOT_MEM_ERR_RANGE;
        }
    }
    aot_mem_domain_unlock(as->domain);

    /* RESERVE-ONLY: no commit, no host pointer output, no access. */
    if (host_vm_reserve((size_t)size, &vm) != HOST_VM_OK)
        return AOT_MEM_ERR_HOST;
    if (host_vm_base(vm, &host, &host_size) != HOST_VM_OK || host == NULL ||
        host_size < (size_t)size) {
        host_vm_release(vm);
        return AOT_MEM_ERR_HOST;
    }
    page_count = (uint32_t)(size / AOT_AS_PAGE_BYTES);
    /* The ALIAS role is the only window whose pages MapPhysicalMemory can
     * commit later, so it owns the per-page occupancy table from the start
     * (Mac's static alias_pages[ALIAS_SIZE_MAX/4096]). The STACK role and every
     * ordinary region stay table-free. */
    alias_page = (role == AOT_AS_RESERVED_ROLE_ALIAS)
                     ? (uint8_t *)calloc((size_t)page_count, 1u)
                     : NULL;
    if (role == AOT_AS_RESERVED_ROLE_ALIAS && alias_page == NULL) {
        host_vm_release(vm);
        return AOT_MEM_ERR_HOST;
    }

    aot_mem_domain_lock(as->domain);
    if (as->sealed || as->poisoned || as->count >= AOT_AS_MAX_REGIONS ||
        as_reserved_locked(as, role) != NULL) {
        aot_mem_domain_unlock(as->domain);
        host_vm_release(vm);
        free(alias_page);
        return AOT_MEM_ERR_RANGE;
    }
    insert_at = as->count;
    for (size_t i = 0; i < as->count; i++) {
        const AotAsRegion *r = &as->region[i];
        if (as_ranges_overlap(guest_base, size, r->base, r->size)) {
            aot_mem_domain_unlock(as->domain);
            host_vm_release(vm);
            free(alias_page);
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
    as->region[insert_at].state = 0u;
    as->region[insert_at].page_count = page_count;
    as->region[insert_at].perm = NULL;
    as->region[insert_at].kind = AS_KIND_RESERVED;
    as->region[insert_at].reserved_role = role;
    as->region[insert_at].heap_size = 0u;
    as->region[insert_at].heap_high_water = 0u;
    as->region[insert_at].heap_commit_limit = 0u;
    as->region[insert_at].alias_page = alias_page;
    as->region[insert_at].alias_bytes = 0u;
    as->count++;
    aot_mem_domain_unlock(as->domain);
    return AOT_MEM_OK;
}

AotMemStatus aot_as_reserved_info(const AotAddressSpace *as, uint32_t role,
                                  uint64_t *out_base, uint64_t *out_size) {
    AotAsRegion *r;
    if (as == NULL || out_base == NULL || out_size == NULL)
        return AOT_MEM_ERR_RANGE;
    if (role != AOT_AS_RESERVED_ROLE_ALIAS &&
        role != AOT_AS_RESERVED_ROLE_STACK)
        return AOT_MEM_ERR_WIDTH;
    aot_mem_domain_lock(as->domain);
    r = as_reserved_locked((AotAddressSpace *)as, role);
    if (r == NULL) {
        aot_mem_domain_unlock(as->domain);
        return AOT_MEM_ERR_RANGE;
    }
    *out_base = r->base;
    *out_size = r->size;
    aot_mem_domain_unlock(as->domain);
    return AOT_MEM_OK;
}

AotMemStatus aot_as_heap_info(const AotAddressSpace *as, AotAsHeapInfo *out) {
    AotAsRegion *r;
    if (as == NULL || out == NULL) return AOT_MEM_ERR_RANGE;
    aot_mem_domain_lock(as->domain);
#ifdef MN_AOT_ALIAS_MUT_HEAP_SELECTS
    /* WRONG (controlled mutant): GetInfo(4/5) selects the alias role. */
    r = as_reserved_locked((AotAddressSpace *)as, AOT_AS_RESERVED_ROLE_ALIAS);
    if (r == NULL)
#endif
    r = as_heap_locked((AotAddressSpace *)as);
    if (r == NULL) {
        aot_mem_domain_unlock(as->domain);
        return AOT_MEM_ERR_RANGE;
    }
    out->base = r->base;
#ifdef MN_AOT_HEAP_MUT_INFO5_SIZE
    /* WRONG (controlled mutant): GetInfo(5) reports the current logical size
     * instead of the fixed 4 GiB-class window maximum. The Mac reference
     * always reports HEAP_CAP here. */
    out->max_size = r->heap_size;
#else
    out->max_size = r->size;
#endif
    out->size = r->heap_size;
    aot_mem_domain_unlock(as->domain);
    return AOT_MEM_OK;
}

AotMemStatus aot_as_set_heap_size(AotAddressSpace *as, uint64_t size,
                                  uint64_t *out_base) {
    AotAsRegion *r;
    uint64_t old_size, hw, t;

    if (as == NULL) return AOT_MEM_ERR_RANGE;
    /* Invalid guest request: typed BEFORE mutating or writing any output. */
    if ((size & (AOT_AS_HEAP_GRANULE - 1ull)) != 0u)
        return AOT_MEM_ERR_ALIGN;

    aot_mem_domain_lock(as->domain);
    if (as->poisoned) {
        /* Same lifecycle rule as add_region/seal: a poisoned space (failed
         * load residue) can never accept a heap transition. */
        aot_mem_domain_unlock(as->domain);
        return AOT_MEM_ERR_RANGE;
    }
    if (!as->sealed) {
        /* SetHeapSize is a post-seal operation: only then is the host
         * protection of every ordinary region final. */
        aot_mem_domain_unlock(as->domain);
        return AOT_MEM_ERR_RANGE;
    }
    r = as_heap_locked(as);
    if (r == NULL) {
        /* No heap window is an invalid request for this address space. */
        aot_mem_domain_unlock(as->domain);
        return AOT_MEM_ERR_RANGE;
    }
    if (as->heap_desync) {
        /* Unrepairable host/software divergence: fail closed. */
        aot_mem_domain_unlock(as->domain);
        return AOT_MEM_ERR_HOST;
    }
    if (size > r->size || size > r->heap_commit_limit) {
        aot_mem_domain_unlock(as->domain);
        return AOT_MEM_ERR_ALIGN;
    }
    old_size = r->heap_size;
    hw = r->heap_high_water;
    t = size;
    if (t == old_size) {
        if (out_base != NULL) *out_base = r->base;
        aot_mem_domain_unlock(as->domain);
        return AOT_MEM_OK;
    }
#ifdef MN_AOT_HEAP_MUT_PUBLISH_BEFORE_HOST
    /* WRONG (controlled mutant): the guest-visible size is published before
     * the host transition, so a host failure leaves a guest map that claims
     * bytes the host never provided. */
    r->heap_size = t;
#endif
    if (t > old_size) {
        /* Fresh pages are [max(old_size,hw), t) == [hw,t) because hw >= old_size.
         * Retained-but-shrunk pages [old_size, min(t,hw)) are committed with
         * NONE and only need their protection raised: host_vm_commit REJECTS
         * already-committed pages, so they must never be re-committed. */
#ifdef MN_AOT_HEAP_MUT_HW_AS_USED
        /* WRONG (controlled mutant): the logical size is used where the
         * committed high-water mark is required, so a grow over a retained
         * block re-commits committed pages and the host rejects it. */
        uint64_t fresh_lo = old_size;
#else
        uint64_t fresh_lo = hw;
#endif
        if (t > hw) {
            /* ONE shared production failure branch: the injected fault only
             * replaces the host RESULT, so the rollback/desync handling below
             * is the same code path a real commit refusal executes. */
            host_vm_result hc;
#if AS_HEAP_FAULT_MODE == 1
            (void)fresh_lo;   /* the host call itself is compiled out */
            hc = HOST_VM_ERR_PLATFORM;
#else
            hc = host_vm_commit(r->vm, (size_t)fresh_lo,
                                (size_t)(t - fresh_lo));
#endif
            if (hc != HOST_VM_OK) {
#ifdef MN_AOT_HEAP_MUT_PUBLISH_ON_COMMIT_FAIL
                /* WRONG (controlled mutant): publish the guest size even
                 * though the fresh commit was refused. */
                r->heap_size = t;
#endif
                aot_mem_domain_unlock(as->domain);
                return AOT_MEM_ERR_HOST;
            }
        }
        if (old_size < hw && old_size < t) {
            uint64_t r_end = (t < hw) ? t : hw;
            int fail_retained = 0;
#if AS_HEAP_FAULT_MODE == 2 || AS_HEAP_FAULT_MODE == 3
            /* ONE-SHOT injected retained-protect failure: the first attempt
             * fails, a later retry executes the real host protect so the
             * recovery path is observable (mode 3 stays sticky regardless). */
            static int fault_used = 0;
            fail_retained = (fault_used++ == 0);
#endif
#ifdef MN_AOT_HEAP_MUT_RECOMMIT_RETAINED
            /* WRONG (controlled mutant): re-commit the retained prefix. */
            fail_retained = (host_vm_commit(r->vm, (size_t)old_size,
                                            (size_t)(r_end - old_size)) !=
                             HOST_VM_OK);
#endif
            if (!fail_retained &&
                host_vm_protect(r->vm, (size_t)old_size,
                                (size_t)(r_end - old_size),
                                HOST_VM_PROT_READ | HOST_VM_PROT_WRITE,
                                NULL) != HOST_VM_OK) {
                fail_retained = 1;
            }
            if (fail_retained) {
                /* Roll back ONLY the fresh [hw,t) pages: they were never
                 * published and are still zero, so decommit restores the
                 * exact previous host state. If that rollback itself fails the
                 * software/host views are unreconcilable: fail closed. */
                if (t > hw) {
                    host_vm_result rb;
#if AS_HEAP_FAULT_MODE == 3
                    rb = HOST_VM_ERR_PLATFORM;
#else
                    rb = host_vm_decommit(r->vm, (size_t)hw,
                                          (size_t)(t - hw));
#endif
                    if (rb != HOST_VM_OK) {
#ifndef MN_AOT_HEAP_MUT_NO_DESYNC
                        as->heap_desync = 1u;
#endif
                    }
                }
                aot_mem_domain_unlock(as->domain);
                return AOT_MEM_ERR_HOST;
            }
        }
        r->heap_size = t;
        if (t > hw) r->heap_high_water = t;
    } else {
        /* Shrink: protect NONE FIRST, never decommit (Mac mprotect NONE keeps
         * the bytes for a later regrow). Only after the OS succeeds are the
         * guest map and exclusive monitors updated, in the same critical
         * section. */
#ifdef MN_AOT_HEAP_MUT_SHRINK_DECOMMIT
        /* WRONG (controlled mutant): decommit instead of protect NONE, which
         * discards retained bytes and loses Mac regrow-preserves-bytes. */
#if AS_HEAP_FAULT_MODE == 4
        int host_ok = 0;
#else
        int host_ok = host_vm_decommit(r->vm, (size_t)t,
                                       (size_t)(old_size - t)) == HOST_VM_OK;
#endif
#else
#if AS_HEAP_FAULT_MODE == 4
        int host_ok = 0;
#else
        int host_ok = host_vm_protect(r->vm, (size_t)t,
                                      (size_t)(old_size - t),
                                      HOST_VM_PROT_NONE, NULL) == HOST_VM_OK;
#endif
#endif
        if (!host_ok) {
            aot_mem_domain_unlock(as->domain);
            return AOT_MEM_ERR_HOST;
        }
        r->heap_size = t;
#ifndef MN_AOT_HEAP_MUT_NO_MONITOR_INVALIDATE
        aot_mem_domain_invalidate_range_locked(as->domain, r->base + t,
                                               old_size - t);
#endif
    }
    /* Publish the output only after every host operation succeeded. */
    if (out_base != NULL) *out_base = r->base;
    aot_mem_domain_unlock(as->domain);
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
            if (as_is_window(&as->region[i])) {
                /* A window was reserved without access: there is no declared
                 * per-page protection to apply, and reserve-only pages must
                 * not be touched. */
                continue;
            }
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
    if (!as->sealed || as->poisoned) {
        /* The region table is frozen by seal; before that the declared
         * permissions are still being established and a mid-init protect
         * would race the seal's host-protection pass. A poisoned space is the
         * residue of a failed load and must not mutate either. */
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
        if (as_is_window(r)) {
            /* A window never takes a module data permission: reject the whole
             * call before mutating anything. */
            aot_mem_domain_unlock(as->domain);
            return AOT_MEM_ERR_PERM;
        }
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
    if (!as->sealed || as->poisoned) {
        /* Same lifecycle guard as protect(): a poisoned sealed space must
         * stay fail-closed instead of accepting a RELRO attribute change. */
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
        if (as_is_window(r)) {
            /* Locking window pages is not a module RELRO operation. */
            aot_mem_domain_unlock(as->domain);
            return AOT_MEM_ERR_PERM;
        }
        first = (addr - r->base) >> AOT_AS_PAGE_SHIFT;
        last = ((addr + size - 1u) - r->base) >> AOT_AS_PAGE_SHIFT;
        for (uint64_t pg = first; pg <= last; pg++)
            r->perm[pg] = (uint8_t)(r->perm[pg] | AOT_AS_ATTR_LOCKED);
    }
    aot_mem_domain_unlock(as->domain);
    return AOT_MEM_OK;
}

/* Index of the (at most one) registered heap window, called with the domain
 * lock held. */
static AotAsRegion *as_reserved_locked(AotAddressSpace *as, uint32_t role) {
    for (uint32_t i = 0; i < as->count; i++) {
        if (as->region[i].kind == AS_KIND_RESERVED &&
            as->region[i].reserved_role == role)
            return &as->region[i];
    }
    return NULL;
}

static AotAsRegion *as_heap_locked(AotAddressSpace *as) {
    for (uint32_t i = 0; i < as->count; i++) {
        if (as->region[i].kind == AS_KIND_HEAP) return &as->region[i];
    }
    return NULL;
}

static AotAsRegion *as_alias_locked(AotAddressSpace *as) {
    AotAsRegion *r =
        as_reserved_locked(as, AOT_AS_RESERVED_ROLE_ALIAS);
    return (r != NULL && r->alias_page != NULL) ? r : NULL;
}

/* Mac alias_pages[]: the guest-visible occupancy bit only. STALE/COMMITTED
 * are host-storage facts and never change a QueryMemory answer, and the access
 * predicate is never mutated (only the query has its own wrong control). */
static int as_alias_page_mapped(const AotAsRegion *r, uint32_t page_index) {
    return (r->alias_page[page_index] & AS_ALIAS_MAPPED) != 0u;
}

/* Count MAPPED pages; callers convert the count to bytes ONCE afterwards.
 * MSVC 19.51.36248 /O2 miscompiles a conditional byte-table reduction weighted
 * by 4096: it zero-extends true comparison bytes to 0xff, then ANDs with 4096,
 * dropping the vector contribution and counting only the scalar tail. This
 * was reproduced independently over four patterns and counts 0..4096; /Od
 * and page-count-then-scale formulations were correct. Do not move the page
 * weight back inside this loop. Normalize the bit test to 0/1 so the helper
 * does not depend on the numeric value of AS_ALIAS_MAPPED. */
static uint64_t as_alias_mapped_pages(const uint8_t *bits, uint64_t count) {
    uint64_t i, mapped = 0u;
    for (i = 0u; i < count; i++)
        mapped += (uint64_t)((bits[i] & AS_ALIAS_MAPPED) != 0u);
    return mapped;
}

/* Query view of the occupancy bit. The wrong-implementation control reports
 * only the queried page instead of Mac's maximal run of equal occupancy. */
static int as_alias_query_mapped(const AotAsRegion *r, uint64_t page_index) {
#ifdef MN_AOT_ALIAS_MUT_QUERY_NO_RUN
    (void)page_index;
    (void)r;
    return 1;
#else
    return as_alias_page_mapped(r, (uint32_t)page_index);
#endif
}

/* Shared query body, called with the domain lock held so the heap size it
 * derives state from cannot change under the caller. */
static int as_query_locked(AotAddressSpace *as, uint64_t addr,
                           AotAsQuery *out) {
    int ri;
    uint64_t page;
    uint64_t lo, hi;
    ri = as_region_index(as, addr, 1u);
    if (ri < 0) return 0;
    {
        const AotAsRegion *r = &as->region[ri];
        if (r->kind == AS_KIND_RESERVED && r->alias_page != NULL) {
            /* Mac services.c:296-299: the answer is the run of equal alias
             * occupancy around addr, reported as the mapped block (state 5,
             * RW) or Free (state 0, NONE), attr 0. The STACK role has no
             * occupancy table and keeps the whole-window Free answer below. */
            uint64_t p = (addr - r->base) >> AOT_AS_PAGE_SHIFT;
            int mapped = as_alias_query_mapped(r, p);
            uint64_t low = p, high = p + 1u;
#ifdef MN_AOT_ALIAS_MUT_QUERY_STATE5
            /* WRONG (controlled mutant): the immutable alias window answers a
             * whole-window RW set-heap-size block instead of its real run. The
             * control lives on THIS branch on purpose: the STACK role has no
             * occupancy table and is queried by the check below, so putting the
             * mutant here is what makes it fail the alias check first. */
            mapped = 1;
            low = 0u;
            high = r->page_count;
#else
            while (low > 0u && as_alias_query_mapped(r, low - 1u) == mapped)
                low--;
            while (high < r->page_count &&
                   as_alias_query_mapped(r, high) == mapped)
                high++;
#endif
            out->base = r->base + (low << AOT_AS_PAGE_SHIFT);
            out->size = (high - low) << AOT_AS_PAGE_SHIFT;
            out->perm = mapped ? (uint32_t)AOT_AS_PERM_RW
                               : (uint32_t)AOT_AS_PERM_NONE;
            out->state = mapped ? AOT_AS_STATE_HEAP : AOT_AS_STATE_FREE;
            out->attr = 0u;
            return 1;
        }
        if (r->kind == AS_KIND_RESERVED) {
            /* A reserved window without an occupancy table (the STACK role)
             * keeps the truthful whole-window answer below. */
        }
        if (as_is_window(r)) {
            /* Truthful dynamic state, no invented Horizon sentinel: the
             * committed prefix (SetHeapSize block, or none for an immutable
             * reserved window) is RW/5, the rest is Free (NONE/0). Both
             * extents are positive and clipped to the prefix / window end. */
            uint64_t prefix = as_window_prefix(r);
            if (addr - r->base < prefix) {
                out->base = r->base;
                out->size = prefix;
                out->perm = AOT_AS_PERM_RW;
                out->state = AOT_AS_STATE_HEAP;
            } else {
                out->base = r->base + prefix;
                out->size = r->size - prefix;
                out->perm = AOT_AS_PERM_NONE;
                out->state = 0u;   /* Horizon Free */
            }
            out->attr = 0u;
            return 1;
        }
        page = (addr - r->base) >> AOT_AS_PAGE_SHIFT;
        lo = page;
        hi = page + 1u;
        while (lo > 0u && r->perm[lo - 1u] == r->perm[page]) lo--;
        while (hi < r->page_count && r->perm[hi] == r->perm[page]) hi++;
        out->base = r->base + (lo << AOT_AS_PAGE_SHIFT);
        out->size = (hi - lo) << AOT_AS_PAGE_SHIFT;
        out->perm = (uint32_t)as_access_bits(r->perm[page]);
        out->state = r->state;
        out->attr = (uint32_t)(r->perm[page] & AOT_AS_ATTR_LOCKED);
    }
    return 1;
}

int aot_as_query(AotAddressSpace *as, uint64_t addr, AotAsQuery *out) {
    int found;
    AotAsQuery q;
    if (as == NULL || out == NULL) return 0;
    aot_mem_domain_lock(as->domain);
    found = as_query_locked(as, addr, &q);
    aot_mem_domain_unlock(as->domain);
    if (!found) return 0;
    *out = q;
    return 1;
}

int aot_as_query_domain(AotAddressSpace *as, uint64_t addr, AotAsQuery *out) {
    AotAsQuery q = {0};
    uint64_t lo, hi;
    if (as == NULL || out == NULL) return 0;
    aot_mem_domain_lock(as->domain);
    if (!as->sealed || as->poisoned) {
        aot_mem_domain_unlock(as->domain);
        return 0;
    }
    if (addr < AOT_AS_MIN_ADDR) {
        q.base = 0u;
        q.size = AOT_AS_MIN_ADDR;
#ifdef MN_AOT_DOMAIN_MUT_LOW_FROM_ADDR
        q.base = addr & ~AOT_AS_PAGE_MASK;
        q.size -= q.base;
#endif
    } else if (addr >= AOT_AS_MAX_ADDR) {
        q.base = AOT_AS_MAX_ADDR;
        q.size = 0ull - AOT_AS_MAX_ADDR;
        q.state = AOT_AS_STATE_INACCESSIBLE;
#ifdef MN_AOT_DOMAIN_MUT_ABOVE_FREE
        q.state = AOT_AS_STATE_FREE;
#endif
    } else if (!as_query_locked(as, addr, &q)) {
        lo = AOT_AS_MIN_ADDR;
        hi = AOT_AS_MAX_ADDR;
        for (uint32_t i = 0u; i < as->count; i++) {
            const AotAsRegion *r = &as->region[i];
            uint64_t end = r->base + r->size; /* add-time checked <= MAX */
            if (end <= addr && end > lo) lo = end;
            if (r->base > addr && r->base < hi) hi = r->base;
        }
#ifdef MN_AOT_DOMAIN_MUT_GAP_PAGE
        lo = addr & ~AOT_AS_PAGE_MASK;
        hi = lo + AOT_AS_PAGE_BYTES;
#endif
        q.base = lo;
        q.size = hi - lo;
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
            /* Heap pages may be reserve-only or retained NONE and the
             * committed high-water mark is private, so never hand out a
             * directly dereferenceable heap page pointer. An alias page is
             * handed out only while it is MAPPED: then it is committed RW and
             * the guest may dereference it. An unmapped alias page is
             * RESERVE/retained-NONE and stays NULL. */
            if (r->kind == AS_KIND_RESERVED && r->alias_page != NULL)
                *out_page = as_alias_page_mapped(r, (uint32_t)page)
                                ? r->host + (size_t)(page << AOT_AS_PAGE_SHIFT)
                                : NULL;
            else
                *out_page = as_is_window(r)
                                ? NULL
                                : r->host + (size_t)(page << AOT_AS_PAGE_SHIFT);
        }
        if (out_offset != NULL) {
            *out_offset = (size_t)(page << AOT_AS_PAGE_SHIFT);
        }
    }
    return 1;
}

/* --------------------------------------- alias (MapPhysicalMemory, locked) -- */

/* Mac services.c:129 budget test, overflow-safe:
 *     fresh + alias_bytes + heap_size + pinned_bytes > pool  => LimitReached
 * Returns 1 when the request fits. The alias/heap terms come from the AS state
 * read under the same domain lock, so the decision cannot race a SetHeapSize or
 * a concurrent alias call. */
static int as_alias_fits(const AotAsRegion *alias, const AotAsRegion *heap,
                         uint64_t fresh, uint64_t pinned, uint64_t pool) {
#ifdef MN_AOT_ALIAS_MUT_NO_BUDGET
    /* WRONG (controlled mutant): the pool is never consulted. */
    (void)alias;
    (void)heap;
    (void)fresh;
    (void)pinned;
    (void)pool;
    return 1;
#else
    uint64_t used = pinned;
    uint64_t hs = (heap != NULL) ? heap->heap_size : 0u;
    if (used > pool) return 0;
    if (alias->alias_bytes > pool - used) return 0;
    used += alias->alias_bytes;
    if (hs > pool - used) return 0;
    used += hs;
    if (fresh > pool - used) return 0;
    return 1;
#endif
}

/* Shared request validation for map/unmap, called with the lock held.
 * Fills the region, the first page index and the page count; returns OK or the
 * contract status (PERM = lifecycle, RANGE = Mac geometry). */
static AotMemStatus as_alias_begin_locked(AotAddressSpace *as, uint64_t addr,
                                         uint64_t size, AotAsRegion **out_a,
                                         uint64_t *out_first,
                                         uint64_t *out_count) {
    AotAsRegion *a;
    if (as->poisoned || !as->sealed) return AOT_MEM_ERR_PERM;
    if (as->alias_desync) return AOT_MEM_ERR_HOST;
    a = as_alias_locked(as);
    if (a == NULL) return AOT_MEM_ERR_PERM;
    /* Mac: if(addr<start||size>ALIAS_SIZE||addr-start>ALIAS_SIZE-size) 0xdc01 */
    if (addr < a->base || size > a->size || addr - a->base > a->size - size)
        return AOT_MEM_ERR_RANGE;
    *out_a = a;
    *out_first = (addr - a->base) >> AOT_AS_PAGE_SHIFT;
    *out_count = size >> AOT_AS_PAGE_SHIFT;
    return AOT_MEM_OK;
}

/* Undo the host changes of pages [0, upto) of a failed map. Pages that were
 * already mapped at entry were never touched by the call and are skipped.
 * Sets *desync when a restore itself fails (unrecoverable divergence). */
static void as_alias_rollback_map(AotAsRegion *a, uint64_t first, uint64_t upto,
                                 int *desync) {
    uint64_t j;
    for (j = upto; j > 0u; j--) {
        uint8_t *b = &a->alias_page[first + j - 1u];
        size_t off = (size_t)((first + j - 1u) << AOT_AS_PAGE_SHIFT);
        if ((*b & AS_ALIAS_NEW) != 0u) {
            /* This call committed the page: return it to RESERVE (zero). */
            if (host_vm_decommit(a->vm, off, (size_t)AOT_AS_PAGE_BYTES) !=
                HOST_VM_OK)
                *desync = 1;
            *b = (uint8_t)(*b & ~(AS_ALIAS_COMMITTED | AS_ALIAS_NEW));
        } else if ((*b & AS_ALIAS_MAPPED) == 0u) {
            /* Retained (or stale) committed page: restore no-access. */
            if (host_vm_protect(a->vm, off, (size_t)AOT_AS_PAGE_BYTES,
                                HOST_VM_PROT_NONE, NULL) != HOST_VM_OK)
                *desync = 1;
        }
    }
}

AotMemStatus aot_as_alias_map(AotAddressSpace *as, uint64_t addr, uint64_t size,
                              uint64_t pinned_bytes, uint64_t pool,
                              uint64_t *out_fresh) {
    AotAsRegion *a = NULL;
    AotAsRegion *heap;
    uint64_t first = 0u, count = 0u, i, fresh = 0u, charge;
    uint8_t *bits;
    AotMemStatus st;
    int desync = 0;

    if (as == NULL) return AOT_MEM_ERR_RANGE;
    if (size == 0u || ((addr | size) & AOT_AS_PAGE_MASK) != 0u)
        return AOT_MEM_ERR_ALIGN;

    aot_mem_domain_lock(as->domain);
    st = as_alias_begin_locked(as, addr, size, &a, &first, &count);
    if (st != AOT_MEM_OK) {
        aot_mem_domain_unlock(as->domain);
        return st;
    }
    bits = a->alias_page + first;

    /* Mac counts only the still-unmapped pages: TOTK's physical-memory heaps
     * grow by re-mapping ranges they already own, and those bytes must not be
     * charged twice. Counted as pages, then converted to bytes once (see
     * as_alias_mapped_pages for why the weight stays out of the loop). */
    fresh = (count - as_alias_mapped_pages(bits, count)) * AOT_AS_PAGE_BYTES;
    charge = fresh;
#ifdef MN_AOT_ALIAS_MUT_CHARGE_ALL
    /* WRONG (controlled mutant): the whole range is charged, so a grow over an
     * owned range reports LimitReached. */
    charge = size;
#endif
    heap = as_heap_locked(as);
    if (!as_alias_fits(a, heap, charge, pinned_bytes, pool)) {
        aot_mem_domain_unlock(as->domain);
        return AOT_MEM_ERR_LIMIT;
    }

    /* Host phase: every page that becomes mapped first gains committed
     * storage (a fresh commit is zero-filled, a stale page is zero-filled
     * explicitly like Mac services.c:145) and RW access. The guest-visible
     * table is published only when the whole phase succeeded. */
    for (i = 0u; i < count; i++) {
        size_t off = (size_t)((first + i) << AOT_AS_PAGE_SHIFT);
        host_vm_result hc;
        if ((bits[i] & AS_ALIAS_MAPPED) != 0u) continue;
        if ((bits[i] & AS_ALIAS_COMMITTED) == 0u) {
#if AS_ALIAS_FAULT_MODE == 1 || AS_ALIAS_FAULT_MODE == 2
            hc = (i == (uint64_t)(AS_ALIAS_FAULT_MODE - 1))
                     ? HOST_VM_ERR_PLATFORM
                     : host_vm_commit(a->vm, off,
                                      (size_t)AOT_AS_PAGE_BYTES);
#else
            hc = host_vm_commit(a->vm, off, (size_t)AOT_AS_PAGE_BYTES);
#endif
            if (hc != HOST_VM_OK) {
                as_alias_rollback_map(a, first, i, &desync);
                if (desync) as->alias_desync = 1u;
                aot_mem_domain_unlock(as->domain);
                return AOT_MEM_ERR_HOST;
            }
            bits[i] |= AS_ALIAS_COMMITTED | AS_ALIAS_NEW;
        }
        if (host_vm_protect(a->vm, off, (size_t)AOT_AS_PAGE_BYTES,
                            HOST_VM_PROT_READ | HOST_VM_PROT_WRITE,
                            NULL) != HOST_VM_OK) {
            /* This page may already have been committed by this call, so it is
             * part of the rollback range; pages that were not touched (already
             * mapped) are skipped inside the helper. */
            as_alias_rollback_map(a, first, i + 1u, &desync);
            if (desync) as->alias_desync = 1u;
            aot_mem_domain_unlock(as->domain);
            return AOT_MEM_ERR_HOST;
        }
        if ((bits[i] & AS_ALIAS_STALE) != 0u) {
#ifdef MN_AOT_ALIAS_MUT_KEEP_STALE
            /* WRONG (controlled mutant): the released bytes are exposed again
             * instead of being zero-filled like a fresh pool page. */
            (void)0;
#else
            /* Mac services.c:145 zero-fills a stale page. It is writable now
             * (the protect above), which is also why the memset cannot be
             * hoisted before it: a released page is host NONE. */
            memset(a->host + off, 0, (size_t)AOT_AS_PAGE_BYTES);
#endif
        }
    }

    for (i = 0u; i < count; i++)
        bits[i] = (uint8_t)((bits[i] | AS_ALIAS_MAPPED) &
                            ~(AS_ALIAS_STALE | AS_ALIAS_NEW));
    a->alias_bytes += fresh;
    aot_mem_domain_unlock(as->domain);
    if (out_fresh != NULL) *out_fresh = fresh;
    return AOT_MEM_OK;
}

AotMemStatus aot_as_alias_unmap(AotAddressSpace *as, uint64_t addr,
                                uint64_t size, uint64_t *out_released) {
    AotAsRegion *a = NULL;
    uint64_t first = 0u, count = 0u, i, released = 0u;
    uint64_t group = (uint64_t)AOT_AS_ALIAS_GROUP_PAGES << AOT_AS_PAGE_SHIFT;
    uint64_t low, high, g;
    uint8_t *bits;
    AotMemStatus st;
#ifndef MN_AOT_ALIAS_MUT_KEEP_MAPPED
    int desync = 0;
#endif

    if (as == NULL) return AOT_MEM_ERR_RANGE;
    if (size == 0u || ((addr | size) & AOT_AS_PAGE_MASK) != 0u)
        return AOT_MEM_ERR_ALIGN;

    aot_mem_domain_lock(as->domain);
    st = as_alias_begin_locked(as, addr, size, &a, &first, &count);
    if (st != AOT_MEM_OK) {
        aot_mem_domain_unlock(as->domain);
        return st;
    }
    bits = a->alias_page + first;
    released = as_alias_mapped_pages(bits, count) * AOT_AS_PAGE_BYTES;

    /* Phase 1 (host): deny access to every mapped page. The guest table still
     * reports all of them mapped, so a refusal is fully revertible. */
#ifndef MN_AOT_ALIAS_MUT_KEEP_MAPPED
    for (i = 0u; i < count; i++) {
        size_t off;
        if ((bits[i] & AS_ALIAS_MAPPED) == 0u) continue;
        off = (size_t)((first + i) << AOT_AS_PAGE_SHIFT);
        if (host_vm_protect(a->vm, off, (size_t)AOT_AS_PAGE_BYTES,
                            HOST_VM_PROT_NONE, NULL) != HOST_VM_OK) {
            uint64_t j;
            for (j = i; j > 0u; j--) {
                size_t o2;
                if ((bits[j - 1u] & AS_ALIAS_MAPPED) == 0u) continue;
                o2 = (size_t)((first + j - 1u) << AOT_AS_PAGE_SHIFT);
                if (host_vm_protect(a->vm, o2, (size_t)AOT_AS_PAGE_BYTES,
                                    HOST_VM_PROT_READ | HOST_VM_PROT_WRITE,
                                    NULL) != HOST_VM_OK)
                    desync = 1;
            }
            if (desync) as->alias_desync = 1u;
            aot_mem_domain_unlock(as->domain);
            return AOT_MEM_ERR_HOST;
        }
    }
#endif

    /* Phase 2 (guest table): publish the release. A released page carries no
     * readable bytes afterwards; a later map zero-fills it. */
    for (i = 0u; i < count; i++)
        if ((bits[i] & AS_ALIAS_MAPPED) != 0u)
            bits[i] = (uint8_t)((bits[i] & ~AS_ALIAS_MAPPED) | AS_ALIAS_STALE);
    a->alias_bytes -= released;
#ifdef MN_AOT_ALIAS_MUT_KEEP_MAPPED
    /* WRONG (controlled mutant): the release forgets to deny host access and
     * forgets to clear MAPPED, so a released page still answers mapped, still
     * reads its old bytes and the counter is not reduced. The host protection
     * stays RW on purpose: otherwise the guest path would fault on the very
     * read the contract forbids, and the control must fail a check, not crash. */
    for (i = 0u; i < count; i++) bits[i] |= AS_ALIAS_MAPPED;
    a->alias_bytes += released;
#endif

    /* Phase 3: return 16 KiB groups whose four pages are all unmapped to the
     * host pool (Mac services.c:138-140 replaces the group with fresh anonymous
     * pages and clears their stale bits). Only the committed pages of the group
     * need a host call, which is equivalent because the decommitted pages read
     * zero either way. */
    low = addr & ~(group - 1u);
    high = (addr + size + group - 1u) & ~(group - 1u);
    if (high > a->base + a->size) high = a->base + a->size;
    for (g = low; g + group <= high; g += group) {
        uint64_t idx = (g - a->base) >> AOT_AS_PAGE_SHIFT;
        uint64_t k;
        if ((a->alias_page[idx] | a->alias_page[idx + 1u] |
             a->alias_page[idx + 2u] | a->alias_page[idx + 3u]) &
            AS_ALIAS_MAPPED)
            continue;
        for (k = 0u; k < (uint64_t)AOT_AS_ALIAS_GROUP_PAGES; k++) {
            size_t off = (size_t)((idx + k) << AOT_AS_PAGE_SHIFT);
            if ((a->alias_page[idx + k] & AS_ALIAS_COMMITTED) == 0u) continue;
#if AS_ALIAS_FAULT_MODE == 3
            if (k == 0u) {
                as->alias_desync = 1u;
                aot_mem_domain_unlock(as->domain);
                return AOT_MEM_ERR_HOST;
            }
#endif
            if (host_vm_decommit(a->vm, off, (size_t)AOT_AS_PAGE_BYTES) !=
                HOST_VM_OK) {
                /* Mac aborts the process here; the run must stop rather than
                 * continue with a host/software divergence. */
                as->alias_desync = 1u;
                aot_mem_domain_unlock(as->domain);
                return AOT_MEM_ERR_HOST;
            }
            a->alias_page[idx + k] =
                (uint8_t)(a->alias_page[idx + k] & ~AS_ALIAS_COMMITTED);
        }
        for (k = 0u; k < (uint64_t)AOT_AS_ALIAS_GROUP_PAGES; k++)
            a->alias_page[idx + k] =
                (uint8_t)(a->alias_page[idx + k] & ~AS_ALIAS_STALE);
    }
    aot_mem_domain_unlock(as->domain);
    if (out_released != NULL) *out_released = released;
    return AOT_MEM_OK;
}

AotMemStatus aot_as_usage(const AotAddressSpace *as, AotAsUsage *out) {
    AotAsRegion *a, *heap;
    if (as == NULL || out == NULL) return AOT_MEM_ERR_RANGE;
    aot_mem_domain_lock(as->domain);
    if (as->poisoned) {
        aot_mem_domain_unlock(as->domain);
        return AOT_MEM_ERR_PERM;
    }
    a = as_alias_locked((AotAddressSpace *)as);
    heap = as_heap_locked((AotAddressSpace *)as);
    /* An address space with no heap window cannot answer the budget query:
     * the heap term would be a silent zero that no later SetHeapSize could
     * correct (the window is immutable after seal). That is a lifecycle bug,
     * so it fails closed instead of reporting a plausible number. */
    if (heap == NULL) {
        aot_mem_domain_unlock(as->domain);
        return AOT_MEM_ERR_PERM;
    }
    out->heap_size = heap->heap_size;
#ifdef MN_AOT_ALIAS_MUT_OMIT_USAGE
    /* WRONG (controlled mutant): GetInfo 7/22 forgets the mapped alias bytes. */
    out->alias_bytes = 0u;
    (void)a;
#else
    out->alias_bytes = (a != NULL) ? a->alias_bytes : 0u;
#endif
    aot_mem_domain_unlock(as->domain);
    return AOT_MEM_OK;
}

AotMemStatus aot_as_alias_info(const AotAddressSpace *as, AotAsAliasInfo *out) {
    AotAsRegion *a;
    uint64_t i, mapped = 0u;
    if (as == NULL || out == NULL) return AOT_MEM_ERR_RANGE;
    aot_mem_domain_lock(as->domain);
    a = as_alias_locked((AotAddressSpace *)as);
    if (a == NULL) {
        aot_mem_domain_unlock(as->domain);
        return AOT_MEM_ERR_PERM;
    }
    out->base = a->base;
    out->size = a->size;
    out->mapped_bytes = a->alias_bytes;
    for (i = 0u; i < a->page_count; i++)
        if ((a->alias_page[i] & AS_ALIAS_MAPPED) != 0u) mapped++;
    out->mapped_pages = mapped;
    aot_mem_domain_unlock(as->domain);
    return AOT_MEM_OK;
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
#ifdef MN_AOT_ALIAS_MUT_RANGE_OMIT
        /* WRONG (controlled mutant): omit reserved windows, so a thunk/sentinel
         * could be placed over the immutable alias geometry. */
        if (r->kind == AS_KIND_RESERVED) continue;
#endif
        if (addr < r->base + r->size && r->base < addr + n) mapped = 1;
    }
    aot_mem_domain_unlock(as->domain);
    return mapped;
}
