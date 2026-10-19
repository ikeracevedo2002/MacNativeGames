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
    AOT_MEM_ERR_RANGE,   /* access outside [base, base+size) */
    AOT_MEM_ERR_ALIGN,   /* caller demanded alignment and it was violated */
    AOT_MEM_ERR_WIDTH    /* unsupported access width */
} AotMemStatus;

typedef struct AotMem {
    uint8_t *base;        /* host allocation (NULL => invalid arena) */
    uint64_t size;        /* bytes (> 0) */
    uint64_t guest_base;  /* guest address of base (evidence only) */
    AotMemDomain *domain; /* shared access domain; explicit lifetime */
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

/* Bounds check only (no lock). */
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
