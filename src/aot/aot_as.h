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
/* Horizon MemoryInfo state of a set-heap-size block (Mac memory.c: 5).
 * The AS never invents a state for uncommitted heap bytes: those are Free (0). */
#define AOT_AS_STATE_HEAP 5u
#define AOT_AS_STATE_FREE 0u
#define AOT_AS_STATE_INACCESSIBLE 0x10u

/* Horizon SetHeapSize requests a multiple of 2 MiB (Mac services.c:310). */
#define AOT_AS_HEAP_GRANULE 0x200000ull

/* Mac services.c:138 groups the alias decommit in 16 KiB (4 x 4 KiB) blocks. */
#define AOT_AS_ALIAS_GROUP_PAGES 4u

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

/* Authoritative guest VA bounds of a validated address-space instance:
 * [AOT_AS_MIN_ADDR, AOT_AS_MAX_ADDR) = [4 GiB, 512 GiB). These describe the
 * EXISTING D014 address-space extent (all module/heap/alias/stack/TLS/control
 * windows live inside it); they are not a new allocation or Mac numeric
 * identity. AOT_MEM_ERR_RANGE for NULL arguments. */
AotMemStatus aot_as_bounds(const AotAddressSpace *as, uint64_t *out_base,
                           uint64_t *out_size);

/* Closed reserved-window roles. Only the boot alias geometry exists in this
 * capability; unknown roles are AOT_MEM_ERR_WIDTH. */
typedef enum {
    AOT_AS_RESERVED_ROLE_ALIAS = 1u,
    /* Immutable global stack-mapping arena (NOT the current main-thread SP
     * region; QueryMemory special-cases that separately on Mac). Added only
     * after the actual original Start reached GetInfo(14). */
    AOT_AS_RESERVED_ROLE_STACK = 2u
} AotAsReservedRole;

/* Add the single immutable reserved window [guest_base, guest_base+size) for
 * `role`. Pre-seal only, at most one per role, no host pointer output,
 * RESERVE-only (64 GiB is a valid geometry on 64-bit hosts; nothing is
 * committed). Geometry/lifecycle errors return AOT_MEM_ERR_RANGE, an unknown
 * role AOT_MEM_ERR_WIDTH, and a host reservation failure AOT_MEM_ERR_HOST.
 * The window is claimed for range_mapped, has no per-page table, and is
 * refused by every access/protect/lock path (Free/NONE). */
AotMemStatus aot_as_add_reserved_window(AotAddressSpace *as,
                                        uint64_t guest_base, uint64_t size,
                                        uint32_t role);

/* Coherent immutable geometry for `role`, read under the domain lock. */
AotMemStatus aot_as_reserved_info(const AotAddressSpace *as, uint32_t role,
                                  uint64_t *out_base, uint64_t *out_size);

/* Add the single guest heap window [guest_base, guest_base+max_size). Pre-seal
 * only, at most one per address space, no host pointer output. The window is
 * RESERVED but not committed: every page starts host RESERVE/no-access and
 * guest NONE, so the existing permission checks reject any read/write before
 * aot_as_set_heap_size() commits it. `max_size` is a 4 KiB multiple and
 * `guest_base + max_size <= 2^39`; `commit_limit` bounds the logical size a
 * caller may request later (checked APP_POOL minus pinned images in the boot
 * profile, never computed here). The window counts as claimed, so
 * aot_as_range_mapped() keeps Program thunks/sentinels out of it.
 *
 * Returns AOT_MEM_OK, AOT_MEM_ERR_RANGE (bad/overlapping range, existing heap
 * window, sealed/poisoned space, table full) or AOT_MEM_ERR_HOST (host
 * reservation failure). */
AotMemStatus aot_as_add_heap_window(AotAddressSpace *as, uint64_t guest_base,
                                    uint64_t max_size, uint64_t commit_limit);

/* ---- Physical alias mapping (Mac services.c alias_map, SVC 0x2c/0x2d). ----
 *
 * The boot alias reserved window (AOT_AS_RESERVED_ROLE_ALIAS) is the only
 * place where individual pages can be committed: MapPhysicalMemory makes the
 * pages of [addr, addr+size) guest RW, UnmapPhysicalMemory releases them.
 * Every other reserved window stays RESERVE-only and refuses all access.
 *
 * Guest-visible contract (Mac services.c:118-150), per 4 KiB page:
 *   - a page that is already mapped keeps its CONTENTS (and is not counted as
 *     fresh, so a grow over an owned range is not charged twice);
 *   - a page that was never mapped, or was unmapped by an earlier call, reads
 *     ZERO when it is mapped (Mac zero-fills a stale page; a decommitted host
 *     page is zero by construction) -- a mapped page is never a view of
 *     retained bytes from before an unmap;
 *   - an unmapped page answers QueryMemory as Free/NONE and REFUSES guest
 *     access. (Divergence, documented in g3-alias-map-design.md: Mac leaves a
 *     released page of a still-partially-mapped 16 KiB group host-readable.
 *     Refusing is stricter and matches the QueryMemory answer this port gives;
 *     the guest never relies on reading an unmapped alias page.)
 *
 * `addr`/`size` must be non-zero 4 KiB multiples inside the window; `size` and
 * `addr` alignment are checked together like Mac's `(addr|size) & 4095`.
 * Returns:
 *   AOT_MEM_OK            success; *out_fresh/*out_released (optional) set.
 *   AOT_MEM_ERR_ALIGN     Mac 0xcc01 (zero/unaligned request).
 *   AOT_MEM_ERR_RANGE     Mac 0xdc01: the request leaves the alias window.
 *   AOT_MEM_ERR_PERM      lifecycle refusal: no alias window, unsealed or
 *                         poisoned space. Never a Mac Result code; the caller
 *                         must report it as a typed host fault, because Mac has
 *                         no such state and inventing a Metric answer would
 *                         hide a broken capability.
 *   AOT_MEM_ERR_LIMIT     Mac 0x10801: `fresh` bytes would make
 *                         alias+heap+`pinned_bytes` exceed `pool`. NOTHING was
 *                         mapped. Applies to map only (Mac checks no budget on
 *                         unmap).
 *   AOT_MEM_ERR_HOST      host commit/protect/decommit failure; the guest
 *                         table is unchanged unless the rollback itself
 *                         failed, in which case the space is sticky-desynced
 *                         and every later alias call fails with the same code
 *                         (Mac aborts the process instead).
 * `pinned_bytes` is the immutable image/pinned footprint the caller owns
 * (Mac runtime_image_bytes()); `pool` is the APP_POOL limit. The alias and
 * heap terms are the AS's own coherent state, read under the same lock, so the
 * budget decision cannot race a SetHeapSize or another alias call. */
AotMemStatus aot_as_alias_map(AotAddressSpace *as, uint64_t addr, uint64_t size,
                              uint64_t pinned_bytes, uint64_t pool,
                              uint64_t *out_fresh);

/* Release [addr, addr+size) (Mac UnmapPhysicalMemory). Validation matches
 * aot_as_alias_map without the budget check. Mapped pages become unmapped and
 * their host storage is decommitted in 16 KiB groups whose four pages are all
 * unmapped (Mac services.c:138-140); released pages read zero on a later map.
 * `*out_released` (optional) is the number of bytes that were mapped. Mac's
 * moved-stack overlap check has no counterpart here: SVC 0x04/0x05 are not
 * implemented, so no stack map can exist (the invariant is asserted, not
 * faked). */
AotMemStatus aot_as_alias_unmap(AotAddressSpace *as, uint64_t addr,
                                uint64_t size, uint64_t *out_released);

/* Coherent usage snapshot for GetInfo 7/22 (Mac: image + heap + alias), one
 * domain lock: the heap logical size and the currently mapped alias bytes. */
typedef struct AotAsUsage {
    uint64_t heap_size;
    uint64_t alias_bytes;
} AotAsUsage;

AotMemStatus aot_as_usage(const AotAddressSpace *as, AotAsUsage *out);

/* Coherent alias geometry + occupancy counter (diagnostics and tests). */
typedef struct AotAsAliasInfo {
    uint64_t base;
    uint64_t size;
    uint64_t mapped_bytes;
    uint64_t mapped_pages;
} AotAsAliasInfo;

AotMemStatus aot_as_alias_info(const AotAddressSpace *as, AotAsAliasInfo *out);

/* Coherent heap description, read under the domain lock. `size` is the
 * current logical SetHeapSize value; the committed high-water mark and host
 * page states stay PRIVATE (tests inspect them through host_vm_query via
 * aot_as_host_page). */
typedef struct AotAsHeapInfo {
    uint64_t base;
    uint64_t max_size; /* fixed reservation/window size */
    uint64_t size;     /* current guest heap size */
} AotAsHeapInfo;

/* Fill `out` with the heap window description. AOT_MEM_ERR_RANGE when the
 * space has no heap window or `out` is NULL. */
AotMemStatus aot_as_heap_info(const AotAddressSpace *as, AotAsHeapInfo *out);

/* Post-seal Horizon SetHeapSize for the registered heap window.
 *
 * `size` must be a 2 MiB multiple (0 is allowed and means an empty heap),
 * <= window max_size and <= the window's commit_limit; otherwise
 * AOT_MEM_ERR_ALIGN and NOTHING is written or changed. A poisoned space, an
 * unsealed space, or a space without a heap window fails with
 * AOT_MEM_ERR_RANGE before any host or guest mutation. On success *out_base (optional) receives the guest heap
 * base and the transition is:
 *   grow:   commit fresh [high_water, size) (never re-commits retained pages,
 *           because host_vm_commit rejects already-committed pages), then
 *           protect retained [old_size, min(size,high_water)) to RW;
 *   shrink: protect [size, old_size) to NONE FIRST, never decommit. Bytes of
 *           a shrunk block are retained and preserved by a later regrow (Mac
 *           mprotect NONE semantics); never-committed pages stay zero.
 * All under the domain lock, no guest/HLE callback while held. Host failure
 * returns AOT_MEM_ERR_HOST with the guest-visible map and `size` unchanged on
 * failure (a failed retained-protect rolls back only the fresh commit); an
 * unrecoverable rollback failure is sticky and later heap requests fail closed
 * with AOT_MEM_ERR_HOST. A successful shrink also invalidates exclusive
 * reservations overlapping the removed bytes in the same critical section. */
AotMemStatus aot_as_set_heap_size(AotAddressSpace *as, uint64_t size,
                                  uint64_t *out_base);

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
 * mapped. For the heap window this is truthful dynamic state: Horizon
 * state 5/RW for [base, base+size) and Free state 0/NONE for
 * [base+size, base+max). */
int aot_as_query(AotAddressSpace *as, uint64_t addr, AotAsQuery *out);

/* Whole data-address-space QueryMemory, one domain-locked snapshot.
 * [0,MIN) is Free (Mac's lower ASLR interval); unclaimed gaps in [MIN,MAX)
 * are Free, bounded by the nearest claimed region/window edges. Existing
 * region/window permission runs are unchanged. [MAX,2^64) is Inaccessible,
 * base MAX, size 0-MAX (its end deliberately wraps to zero), as Horizon's
 * QueryInfo specifies. No host address or committed high-water is exposed.
 * D015 opaque control PCs remain unmapped for data; this query does not grant
 * dispatchability or allocate memory. Adjacent Free extents across window/
 * profile boundaries need not merge (same as the Mac profile).
 * Returns 0 for NULL arguments or an unsealed/poisoned space (*out untouched);
 * otherwise 1 for EVERY uint64_t address. Does not change mapped-only query. */
int aot_as_query_domain(AotAddressSpace *as, uint64_t addr, AotAsQuery *out);

/* Host identity of the guest page containing `addr`, for HOST-PROTECTION
 * checks (tests only). Fills the backing reservation handle (for
 * host_vm_query), a HOST pointer to the page start and its offset inside that
 * reservation; any out-pointer may be NULL. Returns 1 when mapped, 0 otherwise.
 * For a heap-window page the reservation handle and offset are returned but
 * *out_page is ALWAYS NULL (the page may be reserve-only or retained NONE and
 * the committed high-water mark is private). CALLER CONTRACT: a subsequent
 * host_vm_query() on the returned handle MUST be serialized against ANY
 * address-space/region-table or heap mutation (add, seal, resize) on the same
 * domain; the AS does not lock the handle for that query. Pre-seal external
 * serialization or a quiescent probe is fine, a concurrent add is not. The
 * returned pointer is a HOST address: it
 * must never reach guest state, a descriptor or a guest code path. It exists
 * so a probe can ask the OS what protection the page really carries, instead
 * of trusting the software table. */
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
