#include "aot_mem.h"

#include <stdlib.h>
#include <string.h>

#include "aot_as.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define AOT_MEM_MAX_ARENAS 16u
/* Deliberately conservative reservation granule for this finite G2 proof.
 * The cited A57 TRM reports ERG4 => 64 bytes; this is the chosen proof
 * granule, not a cross-CPU guarantee or a claim of real-hardware parity.
 * Invalidation on the whole aligned granule is safe (a spurious failure only
 * retries); no CTR instruction/subset support is implied. The size is NOT
 * configurable: the shift is the single source of truth for the math below. */
#define AOT_MEM_GRANULE_SHIFT 6u
#define AOT_MEM_GRANULE_BYTES (1ull << AOT_MEM_GRANULE_SHIFT)

struct AotMemDomain {
    SRWLOCK lock;
    uint32_t next_token;
    struct {
        int active;
        uint32_t token;
        uint64_t addr;
        uint64_t size;   /* 0 => reservation not armed */
    } mon[AOT_MEM_MAX_MONITORS];
    /* Owned arena identities. aot_mem_init registers (base,size,guest_base)
     * and access validation requires an exact match, so a copied/mutated
     * AotMem cannot widen its bounds or retarget `base` behind the lock. */
    struct {
        const uint8_t *base;
        uint64_t size;
        uint64_t guest_base;
    } arena[AOT_MEM_MAX_ARENAS];
    size_t arena_count;
};

/* Registration is only performed by aot_mem_init, which must complete before
 * the domain is used concurrently (documented precondition). */
static int arena_registered_locked(const AotMemDomain *d, const uint8_t *base,
                                   uint64_t size, uint64_t guest_base) {
    for (size_t i = 0; i < d->arena_count; i++) {
        if (d->arena[i].base == base && d->arena[i].size == size &&
            d->arena[i].guest_base == guest_base)
            return 1;
    }
    return 0;
}

/* ------------------------------------------------------------ domain ---- */

AotMemDomain *aot_mem_domain_create(void) {
    AotMemDomain *d = (AotMemDomain *)calloc(1, sizeof(AotMemDomain));
    if (d == NULL) return NULL;
    InitializeSRWLock(&d->lock);
    d->next_token = 1u;
    return d;
}

void aot_mem_domain_destroy(AotMemDomain *d) {
    if (d == NULL) return;
    free(d);
}

uint32_t aot_mem_domain_attach(AotMemDomain *d) {
    if (d == NULL) return 0u;
    uint32_t token = 0u;
    AcquireSRWLockExclusive(&d->lock);
    for (size_t i = 0; i < AOT_MEM_MAX_MONITORS; i++) {
        if (!d->mon[i].active) {
            uint32_t t;
            int used;
            /* Token 0 is never valid. Skip collisions after uint32 wrap. */
            do {
                t = d->next_token++;
                if (d->next_token == 0u) d->next_token = 1u;
                used = 0;
                for (size_t j = 0; j < AOT_MEM_MAX_MONITORS; j++) {
                    if (d->mon[j].active && d->mon[j].token == t) { used = 1; break; }
                }
            } while (t == 0u || used);
            d->mon[i].active = 1;
            d->mon[i].token = t;
            d->mon[i].addr = 0;
            d->mon[i].size = 0;   /* attached, reservation not armed */
            token = t;
            break;
        }
    }
    ReleaseSRWLockExclusive(&d->lock);
    return token;
}

void aot_mem_domain_detach(AotMemDomain *d, uint32_t token) {
    if (d == NULL || token == 0u) return;
    AcquireSRWLockExclusive(&d->lock);
    for (size_t i = 0; i < AOT_MEM_MAX_MONITORS; i++) {
        if (d->mon[i].active && d->mon[i].token == token) {
            d->mon[i].active = 0;
            break;
        }
    }
    ReleaseSRWLockExclusive(&d->lock);
}

void aot_mem_domain_invalidate_all(AotMemDomain *d) {
    if (d == NULL) return;
    AcquireSRWLockExclusive(&d->lock);
    for (size_t i = 0; i < AOT_MEM_MAX_MONITORS; i++) {
        if (d->mon[i].active) d->mon[i].size = 0;
    }
    ReleaseSRWLockExclusive(&d->lock);
}

/* Program-mode serialization: the address space shares this domain lock with
 * every arena access, so one lock still defines the whole memory model (D013).
 * NULL is tolerated so a handle constructed without a domain fails closed with
 * a range error instead of dereferencing NULL. */
void aot_mem_domain_lock(AotMemDomain *d) {
    if (d == NULL) return;
    AcquireSRWLockExclusive(&d->lock);
}

void aot_mem_domain_unlock(AotMemDomain *d) {
    if (d == NULL) return;
    ReleaseSRWLockExclusive(&d->lock);
}

static int mon_find_locked(AotMemDomain *d, uint32_t token) {
    for (size_t i = 0; i < AOT_MEM_MAX_MONITORS; i++) {
        if (d->mon[i].active && d->mon[i].token == token) return (int)i;
    }
    return -1;
}

/* Disarm every reservation whose 64-byte reservation granule overlaps the
 * granule(s) touched by [addr, addr+n). Called with the domain lock held,
 * from every store path (ordinary, ordered, exclusive).
 *
 * The reservation itself still matches an STXR only on the exact address and
 * width; this granule rule targets invalidation, where being conservative is
 * architecturally safe (a spurious failure merely retries).
 *
 * A monitor slot encodes the runtime's attached TOKEN (lifetime managed by
 * attach/detach); only the reservation (`size`) is cleared here. Clearing
 * `active` here would free the runtime's token and break later LDXR/STXR. */
static void mon_invalidate_locked(AotMemDomain *d, uint64_t addr, uint64_t n) {
    if (d == NULL || n == 0u) return;
#ifdef AOT_MEM_TEST_NO_INVALIDATION
    /* TEST-ONLY wrong-backend control. This define is NEVER used by a shipping
     * build; it is compiled only for the aot_conc_control_noinv executable and
     * suppresses exactly one effect: the reservation clearing performed by a
     * store. Locks, arena registration checks and monitor-token lifetime are
     * untouched, so the control is race-free and cannot mask an infrastructure
     * failure. See tests/aot/aot_conc_wrongbackend_probe.c. */
    (void)addr;
    (void)n;
#else
    uint64_t g0 = addr >> AOT_MEM_GRANULE_SHIFT;
    /* (addr + n - 1) >> shift without a wrapping add. n is the caller's
     * validated length (stores use <=16 bytes; a heap resize may pass a large
     * retained range, and callers guarantee addr+n does not wrap). */
    uint64_t g1 = g0 +
        (((addr & (AOT_MEM_GRANULE_BYTES - 1ull)) + (n - 1u))
         >> AOT_MEM_GRANULE_SHIFT);
    for (size_t i = 0; i < AOT_MEM_MAX_MONITORS; i++) {
        if (!d->mon[i].active || d->mon[i].size == 0u) continue;
        uint64_t r0 = d->mon[i].addr;
        uint64_t r1 = r0 + d->mon[i].size - 1u;
        uint64_t rg0 = r0 >> AOT_MEM_GRANULE_SHIFT;
        uint64_t rg1 = r1 >> AOT_MEM_GRANULE_SHIFT;
        if (g0 <= rg1 && rg0 <= g1) d->mon[i].size = 0;
    }
#endif
}

void aot_mem_domain_invalidate_range_locked(AotMemDomain *d, uint64_t addr,
                                            uint64_t n) {
    /* mon_invalidate_locked expects the domain lock to be held. */
    mon_invalidate_locked(d, addr, n);
}

/* ------------------------------------------------------------- arena ---- */

AotMemStatus aot_mem_init(AotMem *m, AotMemDomain *domain, uint8_t *base,
                          uint64_t size, uint64_t guest_base) {
    if (m == NULL) return AOT_MEM_ERR_RANGE;
    m->base = NULL;
    m->size = 0;
    m->guest_base = 0;
    m->domain = NULL;
    m->as = NULL;
    if (domain == NULL || base == NULL || size == 0u)
        return AOT_MEM_ERR_RANGE;
    if (guest_base > UINT64_MAX - size) return AOT_MEM_ERR_RANGE;
    /* Host end-point arithmetic (arena registration/overlap) must not wrap.
     * Reject before any registration or dereference; the pointer is only
     * converted to an integer here. */
    uint64_t host_base = (uint64_t)(uintptr_t)base;
    if (host_base > UINT64_MAX - size) return AOT_MEM_ERR_RANGE;

    int ok = 0;
    AcquireSRWLockExclusive(&domain->lock);
    if (arena_registered_locked(domain, base, size, guest_base)) {
        ok = 1;   /* idempotent re-init with identical immutable bounds */
    } else {
        /* A reservation is keyed by GUEST address while invalidation also
         * compares GUEST ranges. Two registered views of the same host bytes
         * at different guest bases would let LDX on view A survive a store to
         * view B. Reject any host OR guest overlap (exact identity above is
         * the only accepted duplicate), so the domain stays alias-free.
         * Aliasing the same bytes across DIFFERENT domains is an ownership
         * precondition (see aot_mem.h), not enforced here. */
        uint64_t h0 = (uint64_t)(uintptr_t)base;
        uint64_t h1 = h0 + size;
        uint64_t g1 = guest_base + size;
        for (size_t i = 0; i < domain->arena_count; i++) {
            uint64_t bh0 = (uint64_t)(uintptr_t)domain->arena[i].base;
            uint64_t bh1 = bh0 + domain->arena[i].size;
            uint64_t bg0 = domain->arena[i].guest_base;
            uint64_t bg1 = bg0 + domain->arena[i].size;
            if ((h0 < bh1 && bh0 < h1) || (guest_base < bg1 && bg0 < g1)) ok = -1;
        }
        if (ok == 0 && domain->arena_count < AOT_MEM_MAX_ARENAS) {
            domain->arena[domain->arena_count].base = base;
            domain->arena[domain->arena_count].size = size;
            domain->arena[domain->arena_count].guest_base = guest_base;
            domain->arena_count++;
            ok = 1;
        }
    }
    ReleaseSRWLockExclusive(&domain->lock);
    if (ok < 0) return AOT_MEM_ERR_RANGE;   /* overlapping host/guest alias */
    if (!ok) return AOT_MEM_ERR_RANGE;   /* arena table exhausted */

    m->base = base;
    m->size = size;
    m->guest_base = guest_base;
    m->domain = domain;
    m->as = NULL;
    return AOT_MEM_OK;
}

AotMemStatus aot_mem_init_aspace(AotMem *m, AotAddressSpace *as) {
    if (m == NULL) return AOT_MEM_ERR_RANGE;
    m->base = NULL;
    m->size = 0;
    m->guest_base = 0;
    m->domain = NULL;
    m->as = NULL;
    if (as == NULL || aot_as_domain(as) == NULL) return AOT_MEM_ERR_RANGE;
    m->domain = aot_as_domain(as);
    m->as = as;
    return AOT_MEM_OK;
}

int aot_mem_is_aligned(uint64_t addr, uint64_t align) {
    if (align == 0u || align > 16u || (align & (align - 1u)) != 0u) return 0;
    return (addr & (align - 1u)) == 0u;
}

/* Handle identity for every locked entry point. In AS (Program) mode all
 * serialization and permission bookkeeping is keyed on the address space's own
 * domain: m->domain is the lock that is taken and the identity the monitor
 * table is looked up in, while the page table belongs to m->as. If a copied or
 * forged AotMem made those diverge, the access would take a lock that does not
 * order against the address space and would read the page table without that
 * ordering, so the pair is verified on every call and fails closed
 * (AOT_MEM_ERR_RANGE) instead of running unserialized. */
static int mem_handle_ok(const AotMem *m) {
    if (m == NULL || m->domain == NULL) return 0;
    if (m->as != NULL && aot_as_domain(m->as) != m->domain) return 0;
    return 1;
}

/* Arena bounds check. Called with the domain lock held (or during
 * init/quiescent public use, as documented). */
static AotMemStatus arena_check(const AotMem *m, uint64_t addr, uint64_t n) {
    if (m == NULL || m->base == NULL || m->domain == NULL)
        return AOT_MEM_ERR_RANGE;
    /* The domain, not the copied AotMem value, owns the arena identity. */
    if (!arena_registered_locked(m->domain, m->base, m->size, m->guest_base))
        return AOT_MEM_ERR_RANGE;
    if (addr < m->guest_base) return AOT_MEM_ERR_RANGE;
    uint64_t off = addr - m->guest_base;
    if (off > m->size) return AOT_MEM_ERR_RANGE;
    if (n > m->size - off) return AOT_MEM_ERR_RANGE;
    return AOT_MEM_OK;
}

/* Does [addr, addr+n) resolve to guest memory this handle may address? NOT a
 * permission check: in AS mode it only proves the range is fully inside one
 * mapped region (taken under the address space's domain lock); in arena mode
 * it is the registered-arena bounds check, taken WITHOUT the lock per the
 * documented quiescent-use precondition. Callers that need R/W enforcement use
 * the ld/st helpers (or aot_as_check_locked for an explicit probe). */
AotMemStatus aot_mem_check(const AotMem *m, uint64_t addr, uint64_t n) {
    if (!mem_handle_ok(m)) return AOT_MEM_ERR_RANGE;
    if (m->as != NULL) {
        AotMemStatus s;
        aot_mem_domain_lock(m->domain);
        s = aot_as_range_locked(m->as, addr, n);
        aot_mem_domain_unlock(m->domain);
        return s;
    }
    return arena_check(m, addr, n);
}

/* Permission/bounds pre-check performed under the domain lock BEFORE any
 * reservation invalidation or byte write. In Program mode this is the page
 * table check that makes a faulting store leave memory untouched. */
static AotMemStatus mem_precheck_locked(const AotMem *m, uint64_t addr,
                                        uint64_t n, int for_write) {
    if (m->as != NULL) {
        if (!for_write) return aot_as_check_locked(m->as, addr, n, 0);
#ifdef MN_AOT_MUTANT_PARTIAL_STORE
        /* TEST-ONLY wrong-implementation control: the write permission is left
         * to the per-page check inside the copy, which is exactly how a
         * partial store is produced. Read checks are unchanged. */
        return aot_as_range_locked(m->as, addr, n);
#else
        return aot_as_check_locked(m->as, addr, n, 1);
#endif
    }
    return arena_check(m, addr, n);
}

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
static void st16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
}
static void st32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
    p[2] = (uint8_t)((v >> 16) & 0xffu);
    p[3] = (uint8_t)((v >> 24) & 0xffu);
}
static void st64(uint8_t *p, uint64_t v) {
    st32(p, (uint32_t)(v & 0xffffffffu));
    st32(p + 4, (uint32_t)((v >> 32) & 0xffffffffu));
}

/* Unlocked little-endian access helpers (domain lock already held). In
 * Program mode they resolve through the address space instead of the single
 * arena; the G2 path is unchanged. */
static AotMemStatus ld_le(const AotMem *m, uint64_t addr, unsigned w,
                          uint64_t *out) {
    if (m->as != NULL) return aot_as_ld_locked(m->as, addr, w, out);
    AotMemStatus s = arena_check(m, addr, w);
    if (s != AOT_MEM_OK) return s;
    const uint8_t *p = m->base + (addr - m->guest_base);
    switch (w) {
    case 1: *out = p[0]; break;
    case 2: *out = le16(p); break;
    case 4: *out = le32(p); break;
    case 8: *out = le64(p); break;
    default: return AOT_MEM_ERR_WIDTH;
    }
    return AOT_MEM_OK;
}
static AotMemStatus st_le(AotMem *m, uint64_t addr, unsigned w, uint64_t v) {
    if (m->as != NULL) return aot_as_st_locked(m->as, addr, w, v);
    AotMemStatus s = arena_check(m, addr, w);
    if (s != AOT_MEM_OK) return s;
    uint8_t *p = m->base + (addr - m->guest_base);
    switch (w) {
    case 1: p[0] = (uint8_t)(v & 0xffu); break;
    case 2: st16(p, (uint16_t)v); break;
    case 4: st32(p, (uint32_t)v); break;
    case 8: st64(p, v); break;
    default: return AOT_MEM_ERR_WIDTH;
    }
    return AOT_MEM_OK;
}

AotMemStatus aot_mem_ld8(const AotMem *m, uint64_t addr, uint8_t *out) {
    uint64_t v = 0;
    AotMemStatus s;
    if (!mem_handle_ok(m)) return AOT_MEM_ERR_RANGE;
    AcquireSRWLockExclusive(&m->domain->lock);
    s = ld_le(m, addr, 1, &v);
    ReleaseSRWLockExclusive(&m->domain->lock);
    *out = (uint8_t)v;
    return s;
}
AotMemStatus aot_mem_ld16(const AotMem *m, uint64_t addr, uint16_t *out) {
    uint64_t v = 0;
    AotMemStatus s;
    if (!mem_handle_ok(m)) return AOT_MEM_ERR_RANGE;
    AcquireSRWLockExclusive(&m->domain->lock);
    s = ld_le(m, addr, 2, &v);
    ReleaseSRWLockExclusive(&m->domain->lock);
    *out = (uint16_t)v;
    return s;
}
AotMemStatus aot_mem_ld32(const AotMem *m, uint64_t addr, uint32_t *out) {
    uint64_t v = 0;
    AotMemStatus s;
    if (!mem_handle_ok(m)) return AOT_MEM_ERR_RANGE;
    AcquireSRWLockExclusive(&m->domain->lock);
    s = ld_le(m, addr, 4, &v);
    ReleaseSRWLockExclusive(&m->domain->lock);
    *out = (uint32_t)v;
    return s;
}
AotMemStatus aot_mem_ld64(const AotMem *m, uint64_t addr, uint64_t *out) {
    uint64_t v = 0;
    AotMemStatus s;
    if (!mem_handle_ok(m)) return AOT_MEM_ERR_RANGE;
    AcquireSRWLockExclusive(&m->domain->lock);
    s = ld_le(m, addr, 8, &v);
    ReleaseSRWLockExclusive(&m->domain->lock);
    *out = v;
    return s;
}
AotMemStatus aot_mem_ld128(const AotMem *m, uint64_t addr, uint64_t out[2]) {
    uint64_t a = 0, b = 0;
    AotMemStatus s;
    if (!mem_handle_ok(m)) return AOT_MEM_ERR_RANGE;
    AcquireSRWLockExclusive(&m->domain->lock);
    /* Check the WHOLE 16-byte range first: a partially in-range pair must not
     * read (or report) half the value. */
    s = mem_precheck_locked(m, addr, 16, 0);
    if (s == AOT_MEM_OK) s = ld_le(m, addr, 8, &a);
    if (s == AOT_MEM_OK) s = ld_le(m, addr + 8u, 8, &b);
    ReleaseSRWLockExclusive(&m->domain->lock);
    if (s == AOT_MEM_OK) { out[0] = a; out[1] = b; }
    return s;
}

AotMemStatus aot_mem_st8(AotMem *m, uint64_t addr, uint8_t v) {
    AotMemStatus s;
    if (!mem_handle_ok(m)) return AOT_MEM_ERR_RANGE;
    AcquireSRWLockExclusive(&m->domain->lock);
    s = mem_precheck_locked(m, addr, 1, 1);
    if (s == AOT_MEM_OK) {
        mon_invalidate_locked(m->domain, addr, 1);
        s = st_le(m, addr, 1, v);
    }
    ReleaseSRWLockExclusive(&m->domain->lock);
    return s;
}
AotMemStatus aot_mem_st16(AotMem *m, uint64_t addr, uint16_t v) {
    AotMemStatus s;
    if (!mem_handle_ok(m)) return AOT_MEM_ERR_RANGE;
    AcquireSRWLockExclusive(&m->domain->lock);
    s = mem_precheck_locked(m, addr, 2, 1);
    if (s == AOT_MEM_OK) {
        mon_invalidate_locked(m->domain, addr, 2);
        s = st_le(m, addr, 2, v);
    }
    ReleaseSRWLockExclusive(&m->domain->lock);
    return s;
}
AotMemStatus aot_mem_st32(AotMem *m, uint64_t addr, uint32_t v) {
    AotMemStatus s;
    if (!mem_handle_ok(m)) return AOT_MEM_ERR_RANGE;
    AcquireSRWLockExclusive(&m->domain->lock);
    s = mem_precheck_locked(m, addr, 4, 1);
    if (s == AOT_MEM_OK) {
        mon_invalidate_locked(m->domain, addr, 4);
        s = st_le(m, addr, 4, v);
    }
    ReleaseSRWLockExclusive(&m->domain->lock);
    return s;
}
AotMemStatus aot_mem_st64(AotMem *m, uint64_t addr, uint64_t v) {
    AotMemStatus s;
    if (!mem_handle_ok(m)) return AOT_MEM_ERR_RANGE;
    AcquireSRWLockExclusive(&m->domain->lock);
    s = mem_precheck_locked(m, addr, 8, 1);
    if (s == AOT_MEM_OK) {
        mon_invalidate_locked(m->domain, addr, 8);
        s = st_le(m, addr, 8, v);
    }
    ReleaseSRWLockExclusive(&m->domain->lock);
    return s;
}
AotMemStatus aot_mem_st128(AotMem *m, uint64_t addr, const uint64_t v[2]) {
    AotMemStatus s;
    if (!mem_handle_ok(m)) return AOT_MEM_ERR_RANGE;
    AcquireSRWLockExclusive(&m->domain->lock);
    s = mem_precheck_locked(m, addr, 16, 1);
    if (s == AOT_MEM_OK) {
        mon_invalidate_locked(m->domain, addr, 16);
        s = st_le(m, addr, 8, v[0]);
        if (s == AOT_MEM_OK) s = st_le(m, addr + 8u, 8, v[1]);
    }
    ReleaseSRWLockExclusive(&m->domain->lock);
    return s;
}

AotMemStatus aot_mem_lds8(const AotMem *m, uint64_t addr, int64_t *out) {
    uint8_t v;
    AotMemStatus s = aot_mem_ld8(m, addr, &v);
    if (s != AOT_MEM_OK) return s;
    *out = (int64_t)(int8_t)v;
    return AOT_MEM_OK;
}
AotMemStatus aot_mem_lds16(const AotMem *m, uint64_t addr, int64_t *out) {
    uint16_t v;
    AotMemStatus s = aot_mem_ld16(m, addr, &v);
    if (s != AOT_MEM_OK) return s;
    *out = (int64_t)(int16_t)v;
    return AOT_MEM_OK;
}
AotMemStatus aot_mem_lds32(const AotMem *m, uint64_t addr, int64_t *out) {
    uint32_t v;
    AotMemStatus s = aot_mem_ld32(m, addr, &v);
    if (s != AOT_MEM_OK) return s;
    *out = (int64_t)(int32_t)v;
    return AOT_MEM_OK;
}

/* --------------------------------------------- exclusive / ordered ------ */

AotMemStatus aot_mem_ldx(AotMem *m, uint32_t token, uint64_t addr,
                         unsigned width, uint64_t *out) {
    if (!mem_handle_ok(m)) return AOT_MEM_ERR_RANGE;
    if (width != 1u && width != 2u && width != 4u && width != 8u)
        return AOT_MEM_ERR_WIDTH;
    if (!aot_mem_is_aligned(addr, width)) return AOT_MEM_ERR_ALIGN;
    AotMemStatus s;
    uint64_t v = 0;
    AcquireSRWLockExclusive(&m->domain->lock);
    s = ld_le(m, addr, width, &v);
    if (s == AOT_MEM_OK) {
        int i = mon_find_locked(m->domain, token);
        if (i < 0) { s = AOT_MEM_ERR_RANGE; }
        else {
            m->domain->mon[i].addr = addr;
            m->domain->mon[i].size = width;
        }
    }
    ReleaseSRWLockExclusive(&m->domain->lock);
    if (s == AOT_MEM_OK) *out = v;
    return s;
}

AotMemStatus aot_mem_stx(AotMem *m, uint32_t token, uint64_t addr,
                         unsigned width, uint64_t val, uint32_t *status) {
    if (!mem_handle_ok(m)) return AOT_MEM_ERR_RANGE;
    if (width != 1u && width != 2u && width != 4u && width != 8u)
        return AOT_MEM_ERR_WIDTH;
    if (!aot_mem_is_aligned(addr, width)) return AOT_MEM_ERR_ALIGN;
    AotMemStatus s;
    uint32_t st = 1u;
    AcquireSRWLockExclusive(&m->domain->lock);
    s = mem_precheck_locked(m, addr, width, 1);
    {
        int i = mon_find_locked(m->domain, token);
        if (s == AOT_MEM_OK && i >= 0 && m->domain->mon[i].size == width &&
            m->domain->mon[i].addr == addr) {
            st = 0u;
            mon_invalidate_locked(m->domain, addr, width);
            s = st_le(m, addr, width, val);
        }
        /* STXR clears the reservation on success AND failure - including a
         * failure of the permission/bounds pre-check, which must still consume
         * the local exclusive monitor exactly like the architectural STXR -
         * but keeps the runtime's attached monitor token alive. */
#ifdef MN_AOT_MEM_MUT_KEEP_MONITOR_ON_PERM_FAIL
        /* WRONG (controlled mutant): keep the reservation after a failed
         * pre-check, so a later SC to the original address succeeds without
         * a new LDXR. */
        if (i >= 0 && s == AOT_MEM_OK) m->domain->mon[i].size = 0;
#else
        if (i >= 0) m->domain->mon[i].size = 0;
#endif
    }
    ReleaseSRWLockExclusive(&m->domain->lock);
    *status = st;
    return s;
}

AotMemStatus aot_mem_ldar(AotMem *m, uint64_t addr, unsigned width,
                          uint64_t *out) {
    if (!mem_handle_ok(m)) return AOT_MEM_ERR_RANGE;
    if (width != 1u && width != 2u && width != 4u && width != 8u)
        return AOT_MEM_ERR_WIDTH;
    if (!aot_mem_is_aligned(addr, width)) return AOT_MEM_ERR_ALIGN;
    AotMemStatus s;
    uint64_t v = 0;
    AcquireSRWLockExclusive(&m->domain->lock);
    s = ld_le(m, addr, width, &v);
    ReleaseSRWLockExclusive(&m->domain->lock);
    if (s == AOT_MEM_OK) *out = v;
    return s;
}

AotMemStatus aot_mem_stlr(AotMem *m, uint64_t addr, unsigned width,
                          uint64_t val) {
    if (!mem_handle_ok(m)) return AOT_MEM_ERR_RANGE;
    if (width != 1u && width != 2u && width != 4u && width != 8u)
        return AOT_MEM_ERR_WIDTH;
    if (!aot_mem_is_aligned(addr, width)) return AOT_MEM_ERR_ALIGN;
    AotMemStatus s;
    AcquireSRWLockExclusive(&m->domain->lock);
    s = mem_precheck_locked(m, addr, width, 1);
    if (s == AOT_MEM_OK) {
        mon_invalidate_locked(m->domain, addr, width);
        s = st_le(m, addr, width, val);
    }
    ReleaseSRWLockExclusive(&m->domain->lock);
    return s;
}

void aot_mem_clrex(AotMem *m, uint32_t token) {
    if (m == NULL || m->domain == NULL) return;
    AcquireSRWLockExclusive(&m->domain->lock);
    int i = mon_find_locked(m->domain, token);
    if (i >= 0) m->domain->mon[i].size = 0;
    ReleaseSRWLockExclusive(&m->domain->lock);
}

void aot_mem_fence(void) {
    MemoryBarrier();
}

uint64_t aot_mem_fnv1a(AotMem *m) {
    if (m == NULL || m->domain == NULL) return 0u;
    uint64_t h = 0xcbf29ce484222325ull;
    AcquireSRWLockExclusive(&m->domain->lock);
    /* The copied AotMem value is not trusted: a forged/enlarged size would
     * overread past the registered arena. Validate the owned identity first. */
    if (!arena_registered_locked(m->domain, m->base, m->size, m->guest_base)) {
        ReleaseSRWLockExclusive(&m->domain->lock);
        return 0u;
    }
    for (uint64_t i = 0; i < m->size; i++) {
        h ^= (uint64_t)m->base[i];
        h *= 0x100000001b3ull;
    }
    ReleaseSRWLockExclusive(&m->domain->lock);
    return h;
}
