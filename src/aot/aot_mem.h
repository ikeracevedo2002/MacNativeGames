/*
 * G2 AOT proof: bounds-checked guest memory arena with a shared, explicitly
 * owned access domain.
 *
 * Design (see docs/g2-aot-proof.md):
 *   - Every access (ordinary and exclusive) is performed under ONE
 *     domain-wide lock, so the proof's memory model is sequentially
 *     consistent. SC is stronger than the guest's weak model; that is a
 *     deliberate, documented choice and never a silently-weaker model.
 *   - Because all accesses are serialized, plain memcpy under the lock is
 *     data-race-free C: this is the UB-free shared-memory path.
 *   - An AotMem is a small value copied around (into AotRuntime by value); the
 *     AotMemDomain pointer it carries is shared and has EXPLICIT lifetime
 *     (aot_mem_domain_create/destroy) that must outlive every copy and every
 *     runtime.
 *   - The exclusive monitor is a per-runtime token registered in the domain;
 *     the reservation itself lives in the shared domain, never in guest state
 *     and never in AotGuestState.
 *   - Any store (ordinary, HLE, ordered or successful exclusive) invalidates
 *     reservations in the same 64-byte reservation granule, including a write
 *     of the SAME value (ABA) and a neighbouring address. STXR still requires
 *     an exact address+width match; invalidation is deliberately conservative.
 *
 * Supported limits: shared mutable access is defined only through this arena;
 * the token space is bounded (AOT_MEM_MAX_MONITORS). Exclusive accesses
 * require natural alignment and fail closed with AOT_MEM_ERR_ALIGN otherwise.
 * Bounds arithmetic rejects access/registration ranges whose host end address
 * would overflow the uint64 space (AOT_MEM_ERR_RANGE), so no range can wrap.
 *
 * Lifetime / ownership preconditions (part of the contract, not just advice):
 *   - aot_mem_init (arena registration) must COMPLETE before the domain is
 *     used concurrently; the arena table is frozen after initialization.
 *     Raw host initialization of the arena bytes is allowed BEFORE
 *     registration (the domain has not seen them yet), and a final read-only
 *     inspection is allowed when ALL execution is quiescent (no run in
 *     progress, no resumable reservations). During execution and inside HLE
 *     handlers every access MUST go through aot_mem_*; raw writes are
 *     forbidden while any reservation is live or resumable.
 *   - each host byte belongs to at most ONE live domain. Two domains over the
 *     same bytes have independent locks, so cross-domain aliasing is outside
 *     this proof (and is not detectable without a global registry).
 *   - an arena's host bytes must outlive every AotMem copy and the domain.
 *   - HLE handlers and other host code MUST NOT read/write arena bytes
 *     directly; all guest memory access goes through aot_mem_* so the shared
 *     lock, bounds checks and reservation invalidation always apply. The HLE
 *     `user` pointer may carry the AotMem/arena needed to do this. Reservations
 *     are also cleared at the SVC/HOSTCALL boundary (see aot_runtime.c), but
 *     that boundary clear is NOT permission to bypass aot_mem_* for memory.
 *   - one domain may register several DISJOINT arenas; exact re-init of the
 *     same (base,size,guest_base) is idempotent, but overlapping host or guest
 *     ranges (even with a different guest_base) are rejected.
 */
#ifndef AOT_MEM_H
#define AOT_MEM_H

#include <stddef.h>
#include <stdint.h>

typedef struct AotMemDomain AotMemDomain;

typedef enum {
    AOT_MEM_OK = 0,
    AOT_MEM_ERR_RANGE,   /* access outside every mapped range (legacy meaning
                          * unchanged). Heap host refusals use the appended
                          * AOT_MEM_ERR_HOST, never a renumbered value. */
    AOT_MEM_ERR_ALIGN,   /* caller demanded alignment and it was violated */
    AOT_MEM_ERR_WIDTH,   /* unsupported access width or invalid permission */
    /* The address is mapped but the page permission forbids the access
     * (a Program-mode guest address space only; the G2 arena never returns
     * it). Appended so every previous value is unchanged. */
    AOT_MEM_ERR_PERM,
    /* The host refused a completed guest-state operation (reserve/commit/
     * decommit/protect) and the guest-visible state is unchanged, or the
     * address space is fail-closed after an unrecoverable host rollback
     * failure. Appended so every previous value is unchanged. */
    AOT_MEM_ERR_HOST,
    /* The request is well-formed and inside the window but exceeds the
     * process resource pool (Mac APP_POOL LimitReached). Appended so every
     * previous value is unchanged. This is a GUEST-visible refusal, not a
     * host failure: the caller maps it to its own Result code (Mac
     * services.c alias_map: 0x10801) and the guest state stays coherent. */
    AOT_MEM_ERR_LIMIT
} AotMemStatus;

typedef struct AotAddressSpace AotAddressSpace;

/* A guest memory handle. Two mutually exclusive modes:
 *
 *   - G2 arena mode (`as == NULL`): one contiguous host allocation described
 *     by base/size/guest_base. Every G2 generated image uses this mode and its
 *     behaviour is UNCHANGED.
 *   - Program mode (`as != NULL`): the guest address space owns a sealed table
 *     of page-permission-checked regions (src/aot/aot_as.h). base/size/
 *     guest_base are then unused (0/NULL) and every access resolves through
 *     the address space.
 *
 * Both modes serialize every access under the SAME domain-wide lock, so the
 * proof's memory model stays sequentially consistent across modes. */
typedef struct AotMem {
    uint8_t *base;        /* host allocation (NULL => invalid arena) */
    uint64_t size;        /* bytes (> 0) */
    uint64_t guest_base;  /* guest address of base (evidence only) */
    AotMemDomain *domain; /* shared access domain; explicit lifetime */
    AotAddressSpace *as;  /* optional Program-mode address space */
} AotMem;

#define AOT_MEM_MAX_MONITORS 64u

/* Domain lifecycle. The returned domain must be destroyed after every AotMem
 * copy and every runtime that used it is finished. Returns NULL on failure. */
AotMemDomain *aot_mem_domain_create(void);
void aot_mem_domain_destroy(AotMemDomain *d);

/* Attach/detach a per-runtime exclusive-monitor token. Returns 0 on failure
 * (invalid domain or exhausted monitor table). */
uint32_t aot_mem_domain_attach(AotMemDomain *d);
void aot_mem_domain_detach(AotMemDomain *d, uint32_t token);

/* Disarm every reservation in the domain, keeping tokens attached. This is a
 * whole-domain operation for explicit teardown/diagnostics; the runtime's HLE
 * boundary clears only its LOCAL monitor token. HLE memory access must still
 * use aot_mem_* (see the ownership preconditions above). */
void aot_mem_domain_invalidate_all(AotMemDomain *d);

/* Initialize an arena inside `domain`. Returns AOT_MEM_OK only when:
 *   - `domain` is a live domain, `base` non-NULL and `size` non-zero;
 *   - `guest_base + size` does not overflow the guest address space.
 * On failure the fields are zeroed and every access is rejected. */
AotMemStatus aot_mem_init(AotMem *m, AotMemDomain *domain, uint8_t *base,
                          uint64_t size, uint64_t guest_base);

/* Initialize a Program-mode handle over a sealed-or-building address space.
 * The domain is taken from the address space (aot_as_domain). base/size/
 * guest_base are zero. Returns AOT_MEM_ERR_RANGE for NULL arguments. */
AotMemStatus aot_mem_init_aspace(AotMem *m, AotAddressSpace *as);

/* INTERNAL (Program mode): serialize an address-space operation with every
 * arena access in the same domain. The caller must NOT hold this lock while
 * running an HLE handler or a nested guest call, and must not re-enter any
 * other aot_mem_ / aot_as_ entry point that takes the lock. */
void aot_mem_domain_lock(AotMemDomain *d);
void aot_mem_domain_unlock(AotMemDomain *d);

/* INTERNAL: disarm every exclusive reservation whose granule overlaps
 * [addr, addr+n). The caller MUST already hold the domain lock (this primitive
 * does not take it). It is the locked half of the public
 * aot_mem_domain_invalidate_all() and is used by address-space transitions
 * (e.g. a successful heap shrink) that run inside one critical section. */
void aot_mem_domain_invalidate_range_locked(AotMemDomain *d, uint64_t addr,
                                            uint64_t n);

/* Bounds check only (no PERMISSION check). Arena mode: registered-arena
 * bounds, taken WITHOUT the domain lock (documented quiescent-use
 * precondition). Program mode: the address space's domain lock IS taken and the
 * range must lie inside one mapped region; page permissions are checked by the
 * access functions (or aot_as_check_locked) instead. The handle itself is
 * always validated: an AotMem whose m->domain is not aot_as_domain(m->as) fails
 * closed with AOT_MEM_ERR_RANGE. */
AotMemStatus aot_mem_check(const AotMem *m, uint64_t addr, uint64_t n);

/* Alignment predicate. */
int aot_mem_is_aligned(uint64_t addr, uint64_t align);

/* Little-endian loads/stores (locked). On failure *out is left undefined but
 * no memory outside the arena is touched. */
AotMemStatus aot_mem_ld8(const AotMem *m, uint64_t addr, uint8_t *out);
AotMemStatus aot_mem_ld16(const AotMem *m, uint64_t addr, uint16_t *out);
AotMemStatus aot_mem_ld32(const AotMem *m, uint64_t addr, uint32_t *out);
AotMemStatus aot_mem_ld64(const AotMem *m, uint64_t addr, uint64_t *out);
AotMemStatus aot_mem_ld128(const AotMem *m, uint64_t addr, uint64_t out[2]);
AotMemStatus aot_mem_st8(AotMem *m, uint64_t addr, uint8_t v);
AotMemStatus aot_mem_st16(AotMem *m, uint64_t addr, uint16_t v);
AotMemStatus aot_mem_st32(AotMem *m, uint64_t addr, uint32_t v);
AotMemStatus aot_mem_st64(AotMem *m, uint64_t addr, uint64_t v);
AotMemStatus aot_mem_st128(AotMem *m, uint64_t addr, const uint64_t v[2]);

/* Signed little-endian loads with sign extension. */
AotMemStatus aot_mem_lds8(const AotMem *m, uint64_t addr, int64_t *out);
AotMemStatus aot_mem_lds16(const AotMem *m, uint64_t addr, int64_t *out);
AotMemStatus aot_mem_lds32(const AotMem *m, uint64_t addr, int64_t *out);

/* Exclusive / ordered accesses. `width` is 1, 2, 4 or 8 bytes. Exclusive
 * accesses require natural alignment. The locked domain makes the pair
 * atomic. `token` is the runtime's attached monitor token. */
AotMemStatus aot_mem_ldx(AotMem *m, uint32_t token, uint64_t addr,
                         unsigned width, uint64_t *out);
AotMemStatus aot_mem_stx(AotMem *m, uint32_t token, uint64_t addr,
                         unsigned width, uint64_t val, uint32_t *status);
AotMemStatus aot_mem_ldar(AotMem *m, uint64_t addr, unsigned width,
                          uint64_t *out);
AotMemStatus aot_mem_stlr(AotMem *m, uint64_t addr, unsigned width,
                          uint64_t val);
void aot_mem_clrex(AotMem *m, uint32_t token);
void aot_mem_fence(void);

/* Deterministic FNV-1a of the arena (quick fixture checksum only). */
uint64_t aot_mem_fnv1a(AotMem *m);

#endif /* AOT_MEM_H */
