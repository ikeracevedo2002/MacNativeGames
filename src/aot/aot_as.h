/*
 * G3 increment 1: guest address space with per-page Horizon permissions.
 *
 * Scope: a 64-bit guest virtual-address table of sorted, disjoint, 4 KiB
 * aligned regions, each backed by page-aligned host memory reserved through
 * src/host_vm.h. It is NOT a general guest VM: no file/COW mapping, no
 * aliasing, no host-pointer escape, no page-fault path. Translated code never
 * receives a host pointer: host pointers returned by aot_as_add_region() are
 * for INIT-ONLY image population before aot_as_seal().
 *
 * Mac reference (behavioural only; games/ is unchanged):
 *   games/totk/runtime/loader.c maps a module RW, seals it with mprotect
 *   (text RX, rodata R, key page R, patch RX) and keeps a per-page permission
 *   byte table. runtime_module_permission() rewrites a 4 KiB-aligned range to
 *   permission {0,1,3} for data pages only, refuses to touch a page carrying
 *   the irreversible RELRO attribute 16, and refuses to overlap an executable
 *   page. runtime_module_lock_permission() ORs in attribute 16.
 *   runtime_module_query() reports {base, size, state, permission, attribute}
 *   for the maximal run of pages with an identical permission byte, with
 *   state 3 for text and 4 for data.
 *
 * Differences that are deliberate:
 *   - Windows has 4 KiB pages, so the Mac's union-of-four-16KiB-pages logic
 *     (needed because Darwin hands back 16 KiB pages) is absent.
 *   - The Mac derives the text/data split from module offsets; here the
 *     region's `state` carries it, and a query run never crosses a region.
 *   - Permission checks are enforced in software under the shared domain lock
 *     (the authoritative table); the host page protection is additionally
 *     applied so an out-of-band host write cannot silently succeed.
 *
 * Locking: after aot_as_seal() the region table is frozen and only page
 * permissions change; every operation that reads or writes the table is
 * serialized under the AotMemDomain lock shared with all guest memory
 * accesses (D013's sequentially-consistent model). No lock is ever held while
 * an HLE handler or a nested guest call runs.
 *
 * Address rules: guest addresses below 2^32 are never mappable (they collide
 * with the platform's own low-address space conventions in the Mac port) and
 * no region may reach 2^39. Overlapping, misaligned or overflowing regions
 * are rejected fail-closed.
 */
#ifndef AOT_AS_H
#define AOT_AS_H

#include "aot_mem.h"

/* Opaque host reservation handle (src/host_vm.h) so aot_as_host_page() can hand
 * one out without pulling the whole host wrapper header into every caller. */
typedef struct host_vm_region host_vm_region;

#include <stddef.h>
#include <stdint.h>

#define AOT_AS_PAGE_SHIFT 12u
#define AOT_AS_PAGE_BYTES (1ull << AOT_AS_PAGE_SHIFT)
#define AOT_AS_PAGE_MASK  (AOT_AS_PAGE_BYTES - 1ull)

/* Horizon-style permission bits (Mac: perm & 7).
 *
 * AOT_AS_PERM_X is GUEST-ONLY: it is bookkeeping for the query/protect contract
 * and a dispatch-side check, and it is NEVER forwarded to the host mapping. The
 * host protection a sealed page receives is
 *     R-X -> HOST_VM_PROT_READ   (PAGE_READONLY)
 *     RW- -> HOST_VM_PROT_READ|WRITE
 *     R-- -> HOST_VM_PROT_READ
 *     --- -> HOST_VM_PROT_NONE   (PAGE_NOACCESS)
 * because guest text holds ARM64 bytes the host CPU can never execute and the
 * design forbids dynamically created host-executable memory. Pinned by
 * tests/aot/aot_as_probe.c and tests/aot/aot_g3_link_probe.c after seal (they
 * ask the OS via host_vm_query and VirtualQuery), with the negative control
 * MN_AOT_MUTANT_HOST_EXEC (aot_as_mut_host_exec). */
#define AOT_AS_PERM_NONE 0u
#define AOT_AS_PERM_R    1u
#define AOT_AS_PERM_W    2u
#define AOT_AS_PERM_X    4u
#define AOT_AS_PERM_RW   (AOT_AS_PERM_R | AOT_AS_PERM_W)
#define AOT_AS_PERM_RX   (AOT_AS_PERM_R | AOT_AS_PERM_X)

/* RELRO-style irreversible attribute (Mac: perm & 16). */
#define AOT_AS_ATTR_LOCKED 16u

/* Module state values reported by aot_as_query (Mac: 3 text, 4 data). */
#define AOT_AS_STATE_TEXT 3u
#define AOT_AS_STATE_DATA 4u

/* Mapping bounds. */
#define AOT_AS_MIN_ADDR 0x100000000ull        /* 2^32: never mappable */
#define AOT_AS_MAX_ADDR 0x8000000000ull       /* 2^39: exclusive upper bound */
#define AOT_AS_MAX_REGIONS 64u

/* Result of aot_as_query. `base`/`size` describe the maximal run of pages
 * with an identical permission+attribute byte inside ONE region. */
typedef struct AotAsQuery {
    uint64_t base;
    uint64_t size;
    uint32_t perm;   /* AOT_AS_PERM_* bits (R|W|X) */
    uint32_t state;  /* AOT_AS_STATE_* or caller-defined */
    uint32_t attr;   /* AOT_AS_ATTR_LOCKED or 0 */
} AotAsQuery;

typedef struct AotAddressSpace AotAddressSpace;

/* Create/destroy. `domain` is borrowed and must outlive the address space;
 * destroy releases every host reservation. Returns NULL on failure. */
AotAddressSpace *aot_as_create(AotMemDomain *domain);
void aot_as_destroy(AotAddressSpace *as);

/* The domain this address space is serialized under. */
AotMemDomain *aot_as_domain(const AotAddressSpace *as);

/* 1 once aot_as_seal() has succeeded (the region table is frozen and every
 * host page carries its declared permission). A Program may only be finalized
 * over a sealed space and a runtime may only run over a sealed space. */
int aot_as_is_sealed(const AotAddressSpace *as);

/* Add one init-only region. `guest_base` and `size` must be non-zero multiples
 * of 4 KiB, `guest_base >= 2^32`, `guest_base + size <= 2^39`, the range must
 * not overlap an existing region, and `perm` must be one of {0,1,3,5}.
 *
 * The region's host pages are committed READ/WRITE so the caller can populate
 * them through *out_host_base (which is OPTIONAL and is a HOST pointer that
 * must never be stored in guest state or used as a guest code address).
 * aot_as_seal() applies the declared guest permissions to the host pages.
 *
 * Returns AOT_MEM_OK, AOT_MEM_ERR_RANGE (bad/overlapping range, table full,
 * sealed, host reservation failure) or AOT_MEM_ERR_WIDTH (bad permission). */
AotMemStatus aot_as_add_region(AotAddressSpace *as, uint64_t guest_base,
                               uint64_t size, uint32_t perm, uint32_t state,
                               void **out_host_base);

/* POISON the space (loader review fix 1): a load that failed after it had
 * already added regions must never be able to look loaded. After this call
 * aot_as_add_region() and aot_as_seal() both fail closed with
 * AOT_MEM_ERR_RANGE, so a partially populated space can neither grow nor be
 * sealed; the caller is expected to destroy it. Idempotent. */
void aot_as_poison(AotAddressSpace *as);

/* 1 once aot_as_poison() was called (diagnostics/mutant tests). */
int aot_as_is_poisoned(const AotAddressSpace *as);

/* Freeze the region table and apply the declared permissions to the host
 * pages. Idempotent, and RETRYABLE: `sealed` becomes 1 only when every host
 * page accepted its declared permission, so a failed call leaves the space
 * unsealed and a later call re-applies the same table. After this only
 * aot_as_protect()/aot_as_lock() may change page metadata. */
AotMemStatus aot_as_seal(AotAddressSpace *as);

/* Rewrite the permission of [addr, addr+size) with Mac runtime_module_permission
 * semantics: `addr`/`size` must be 4 KiB aligned and non-zero; `perm` must be
 * in {0,1,3} (data permissions only); a locked page, a currently executable
 * page, or ANY page of an AOT_AS_STATE_TEXT region in the range rejects the
 * whole call with AOT_MEM_ERR_PERM and changes nothing; a range not fully
 * inside one region is AOT_MEM_ERR_RANGE. The space must be SEALED: before
 * seal the call fails closed with AOT_MEM_ERR_RANGE (the table is not frozen
 * yet and a mid-init protect would race the seal's host-protection pass). */
AotMemStatus aot_as_protect(AotAddressSpace *as, uint64_t addr, uint64_t size,
                            uint32_t perm);

/* Irreversibly OR in AOT_AS_ATTR_LOCKED over [addr, addr+size) (Mac
 * runtime_module_lock_permission: attribute 16 only). Alignment and range
 * rules match aot_as_protect, including the requirement that the space is
 * already sealed (AOT_MEM_ERR_RANGE otherwise). */
AotMemStatus aot_as_lock(AotAddressSpace *as, uint64_t addr, uint64_t size);

/* Report the maximal run of identical pages containing `addr` (Mac
 * runtime_module_query). Returns 1 and fills `out`, or 0 when `addr` is not
 * mapped. */
int aot_as_query(AotAddressSpace *as, uint64_t addr, AotAsQuery *out);

/* Host identity of the guest page containing `addr`, for HOST-PROTECTION
 * checks (tests only). Fills the backing reservation handle (for
 * host_vm_query), a HOST pointer to the page start and its offset inside that
 * reservation; any out-pointer may be NULL. Returns 1 when mapped, 0 otherwise.
 * The returned pointer is a HOST address: it must never reach guest state, a
 * descriptor or a guest code path. It exists so a probe can ask the OS what
 * protection the page really carries, instead of trusting the software table. */
int aot_as_host_page(const AotAddressSpace *as, uint64_t addr,
                     host_vm_region **out_vm, const uint8_t **out_page,
                     size_t *out_offset);

/* Bulk host-side helpers for HLE: same permission checks as a guest load/store
 * (R for read, W for write), performed under the domain lock. A failing access
 * writes NOTHING for write and leaves `buf` untouched for read. n == 0 is a
 * no-op that succeeds. */
AotMemStatus aot_as_read(AotAddressSpace *as, uint64_t addr, void *buf,
                         uint64_t n);
AotMemStatus aot_as_write(AotAddressSpace *as, uint64_t addr, const void *buf,
                          uint64_t n);

/* INTERNAL: the following entry points require the domain lock to be held by
 * the caller (aot_mem_domain_lock). They are what the aot_mem_ load/store
 * helpers use when a handle carries an address space. */
AotMemStatus aot_as_range_locked(const AotAddressSpace *as, uint64_t addr,
                                 uint64_t n);
AotMemStatus aot_as_check_locked(const AotAddressSpace *as, uint64_t addr,
                                 uint64_t n, int for_write);
AotMemStatus aot_as_ld_locked(const AotAddressSpace *as, uint64_t addr,
                              unsigned width, uint64_t *out);
AotMemStatus aot_as_st_locked(AotAddressSpace *as, uint64_t addr,
                              unsigned width, uint64_t value);
/* 1 when ANY byte of [addr, addr+n) is mapped. Used by the Program link step
 * to prove thunks/sentinels are unmapped. Takes the lock itself. */
int aot_as_range_mapped(AotAddressSpace *as, uint64_t addr, uint64_t n);

#endif /* AOT_AS_H */
