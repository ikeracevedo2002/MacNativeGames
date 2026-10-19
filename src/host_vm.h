/* Host virtual-memory abstraction (G1 memory row).
 *
 * Scope: this is the HOST address-space primitive only. It reserves, commits,
 * decommits, protects and releases an anonymous, private, host-allocated
 * range and reports the true operating-system state. It is NOT the guest
 * virtual-address strategy: it makes no identity-mapping promise, chooses no
 * guest layout, and exposes no guest memory service. File-backed mapping,
 * copy-on-write remapping, aliasing and guest image layout are deliberately
 * left to the translated-image loader (G3).
 *
 * Mac reference (behavioural only; the Mac sources are unchanged):
 *
 *   games/totk/runtime/loader.c maps each rewritten module image with
 *   mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, ...) and
 *   later seals the pages with mprotect (text RX, rodata R, key page R,
 *   patch area RX) plus sys_icache_invalidate. games/totk/runtime/
 *   memory_probe.c validates RELRO-style protection changes and confirms
 *   the host page protection with an independent mach_vm_region query.
 *
 * What this module takes from that reference is the host-level shape:
 * reserve an anonymous private range, commit it, change protection, query the
 * real OS protection, and release it. What it deliberately does NOT create is
 * a guest address model, a module layout, a file/alias mapping or a guest
 * fault policy.
 *
 * Design: the reservation is owned by an opaque region handle, so every
 * offset/size argument is bounds-checked against the reservation BEFORE any
 * native call. A raw base pointer plus length would let a caller pass an
 * unrelated address to the backend; the handle prevents that.
 *
 * Granularity:
 *
 *   - host_vm_page_size() is the OS page size. Commit/decommit/protect offset
 *     and size must be whole multiples of it, and the reservation base is
 *     returned on an allocation-granularity boundary.
 *   - host_vm_allocation_granularity() is the OS reserve granularity (always
 *     >= page size and a multiple of it). A reservation is rounded up to the
 *     page size; the granularity is reported so a future loader can align a
 *     request without guessing the host value.
 *   - No relationship between host pages and any guest page size is claimed.
 *
 * Semantics:
 *
 *   - host_vm_reserve() reserves an anonymous private range. Pages start
 *     reserved, not committed, and without access.
 *   - host_vm_commit() commits a sub-range, which becomes zero-filled
 *     read/write. It requires EVERY page in the range to be currently
 *     reserved and is deliberately NOT idempotent: an already-committed or
 *     mixed reserved/committed range is rejected with nothing changed (see
 *     the commit() entry below for why).
 *   - host_vm_decommit() releases the physical storage of a committed
 *     sub-range (all pages must currently be committed); the pages stay
 *     reserved. A later commit returns zero-filled pages.
 *   - host_vm_protect() changes the protection of committed pages. WRITE
 *     implies READ (the platform has no write-without-read protection).
 *     EXEC selects an execute protection; an instruction-cache flush is
 *     available because the Windows contract places that responsibility on
 *     the caller even where the CPU is coherent.
 *   - host_vm_query() reports the OS's own view (base, size, state,
 *     protection, type) for an address inside the reservation. It is a
 *     query, not the wrapper's bookkeeping.
 *   - host_vm_release() releases the whole reservation and frees the region
 *     handle. After it returns the handle is invalid: using it again,
 *     including calling release() a second time, is undefined. A failed
 *     release leaves the handle usable.
 *
 * Concurrency:
 *
 *   - A region handle is owned by one caller at a time. The caller must
 *     externally serialise operations on it: in particular, no other thread
 *     may be inside a commit/decommit/protect/query/flush while release()
 *     runs, and no operation may use the handle after release(). The wrapper
 *     does not lock and does not track outstanding operations.
 *
 * Error handling is explicit: every entry point reports a host_vm_result. On
 * failure outputs are left unchanged and the region stays usable (except
 * after a successful release, which frees it).
 *
 * Backend: a narrow VirtualAlloc / VirtualFree / VirtualProtect /
 * VirtualQuery / FlushInstructionCache implementation in src/host_vm.c. This
 * header is deliberately free of <windows.h> and of any platform type.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum host_vm_result {
    /* Success; the documented output (if any) was written. */
    HOST_VM_OK = 0,
    /* A mandatory pointer argument was NULL, a size was zero, or the
     * requested size overflowed when rounded up to a page. Nothing changed. */
    HOST_VM_ERR_INVALID_ARGUMENT = 1,
    /* The handle or the OS state does not allow the requested operation:
     * an offset/size outside the reservation, a decommit/protect of reserved
     * (not committed) pages, or an alignment that is not a whole number of
     * pages. Nothing changed. (A handle already freed by release() is not a
     * detectable state; see the concurrency/ownership note above.) */
    HOST_VM_ERR_INVALID_STATE = 2,
    /* The OS refused the reservation for lack of address space or memory.
     * The handle is unchanged. */
    HOST_VM_ERR_ALLOCATION = 3,
    /* The OS rejected an otherwise well-formed request. Nothing changed. */
    HOST_VM_ERR_PLATFORM = 4
} host_vm_result;

/* Protection bits accepted by host_vm_protect(). WRITE implies READ because
 * the platform has no write-without-read protection; a bit outside this set
 * is rejected. HOST_VM_PROT_NONE means no access. */
typedef enum host_vm_prot {
    HOST_VM_PROT_NONE = 0x0,
    HOST_VM_PROT_READ = 0x1,
    HOST_VM_PROT_WRITE = 0x2,
    HOST_VM_PROT_EXEC = 0x4
} host_vm_prot;

/* OS page state reported by host_vm_query(). */
typedef enum host_vm_state {
    HOST_VM_STATE_FREE = 0,
    HOST_VM_STATE_RESERVE = 1,
    HOST_VM_STATE_COMMIT = 2
} host_vm_state;

/* OS region type reported by host_vm_query(). */
typedef enum host_vm_type {
    HOST_VM_TYPE_FREE = 0,
    HOST_VM_TYPE_PRIVATE = 1,
    HOST_VM_TYPE_MAPPED = 2,
    HOST_VM_TYPE_IMAGE = 3
} host_vm_type;

typedef struct host_vm_info {
    void   *base;        /* OS base of the region containing the address */
    size_t  size;        /* OS size of that region */
    unsigned state;      /* host_vm_state */
    unsigned protection; /* host_vm_prot bits (0 == no access) */
    unsigned type;       /* host_vm_type */
} host_vm_info;

/* Opaque owned reservation handle. */
typedef struct host_vm_region host_vm_region;

/* Host page size in bytes (always a power of two and >= 4096 on Windows). */
uint64_t host_vm_page_size(void);

/* Host reserve granularity in bytes (always >= page size). */
uint64_t host_vm_allocation_granularity(void);

/* Reserve an anonymous private range of at least `size` bytes.
 *
 * `size` must be non-zero and `out_region` non-NULL; the reservation is
 * rounded up to a whole number of pages. On success *out_region owns the
 * range and starts with no pages committed. On failure *out_region is
 * untouched. */
host_vm_result host_vm_reserve(size_t size, host_vm_region **out_region);

/* Release the whole reservation and free the handle.
 *
 * On success the handle is invalid and must not be used again. On failure the
 * reservation is unchanged and the handle stays usable. `region` must be
 * non-NULL. */
host_vm_result host_vm_release(host_vm_region *region);

/* Commit [offset, offset+size) inside the reservation.
 *
 * `offset` must be page-aligned; `size` must be page-aligned and non-zero;
 * the whole range must be inside the reservation. Every page in the range
 * must currently be RESERVED: commit() is deliberately NOT idempotent. A
 * range that contains an already-committed or mixed reserved/committed page
 * is rejected as HOST_VM_ERR_INVALID_STATE and NOTHING in the range changes.
 * Re-committing must not be used to change a page's state: VirtualAlloc with
 * MEM_COMMIT would reset an existing RX or read-only page to read/write, so
 * accepting such a range would silently weaken a protection. To obtain a
 * fresh zero-filled read/write page use decommit() then commit(). */
host_vm_result host_vm_commit(host_vm_region *region, size_t offset,
                              size_t size);

/* Decommit [offset, offset+size) inside the reservation.
 *
 * `offset` must be page-aligned; `size` must be page-aligned and non-zero;
 * the whole range must be inside the reservation, and every page in the
 * range must currently be committed. The pages become reserved; a later
 * commit yields zero-filled pages. */
host_vm_result host_vm_decommit(host_vm_region *region, size_t offset,
                                size_t size);

/* Change the protection of committed pages in [offset, offset+size).
 *
 * `protection` is a combination of host_vm_prot bits; unknown bits are
 * rejected and WRITE implies READ. Every page in the range must be committed.
 * `offset == 0` is a valid offset (the first page of the reservation).
 * If `out_old_protection` is non-NULL it receives the previous protection of
 * the FIRST page of the range (VirtualProtect reports a single old value for
 * the range, so the caller treats the range as homogeneous); on failure it is
 * left untouched. */
host_vm_result host_vm_protect(host_vm_region *region, size_t offset,
                               size_t size, unsigned protection,
                               unsigned *out_old_protection);

/* Query the OS's own view of the page at `offset`.
 *
 * `offset` must be inside the reservation. On success *out_info is written.
 * On failure *out_info is left untouched. Guard/cache attributes outside the
 * host_vm_prot model are not reported; the underlying access bits are. */
host_vm_result host_vm_query(const host_vm_region *region, size_t offset,
                             host_vm_info *out_info);

/* Make freshly written executable pages visible to instruction fetch.
 *
 * [offset, offset+size) must be inside the reservation. On x86-64 the data
 * and instruction caches are coherent, so this is not required for
 * correctness there, but the Windows contract places the flush on the caller
 * and this entry point keeps that responsibility explicit for translated
 * code and for any future non-coherent target. */
host_vm_result host_vm_flush_instruction_cache(host_vm_region *region,
                                               size_t offset, size_t size);

/* Report the reservation base and its page-rounded size.
 *
 * Both outputs must be non-NULL. On failure they are left untouched. */
host_vm_result host_vm_base(const host_vm_region *region, void **out_base,
                            size_t *out_size);

#ifdef __cplusplus
}
#endif
