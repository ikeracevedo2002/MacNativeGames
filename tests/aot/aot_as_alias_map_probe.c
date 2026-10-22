/* G3 alias physical mapping probe (Mac services.c alias_map, SVC 0x2c/0x2d).
 *
 * Covers the guest-visible contract of MapPhysicalMemory/UnmapPhysicalMemory on
 * the AS alias reserved window: first-map commit, contents preserved on a
 * re-map of an owned range, zero on a map after unmap, Free/NONE QueryMemory
 * runs for released pages, the APP_POOL budget, GetInfo 7/22 accounting, heap
 * independence, lifecycle refusals, the deterministic host-refusal seams and
 * the sticky-desync protocol.
 *
 * Exit protocol matches the other G3 probes: 0 = all checks passed,
 * 2 = at least one semantic FAIL, 1 (FATAL) = infrastructure failure.
 */
#include "aot_as.h"
#include "aot_mem.h"
#include "host_vm.h"

#include <stdio.h>
#include <string.h>

#define ALIAS_BASE 0x5000000000ull
#define ALIAS_SIZE 0x1000000000ull
#define HBASE      0x4000000000ull
#define HMAXSZ     0x800000ull
#define HCOMMIT    0x600000ull
#define STACK_BASE 0x2800000000ull
#define STACK_SIZE 0x10000000ull
#define IMG_BYTES  0x5ae8000ull
#define POOL       0xcd500000ull
#define PG         0x1000ull
#define GROUP      0x4000ull

#if defined(MN_AOT_ALIAS_FAULT_MODE) && MN_AOT_ALIAS_FAULT_MODE == 1
#define FAULT_MODE 1
#elif defined(MN_AOT_ALIAS_FAULT_MODE) && MN_AOT_ALIAS_FAULT_MODE == 2
#define FAULT_MODE 2
#elif defined(MN_AOT_ALIAS_FAULT_MODE) && MN_AOT_ALIAS_FAULT_MODE == 3
#define FAULT_MODE 3
#else
#define FAULT_MODE 0
#endif

static int g_fail;


static void check(int ok, const char *what) {
    if (!ok) {
        printf("FAIL: %s\n", what);
        g_fail++;
    }
}

static void fatal(const char *what) {
    printf("FATAL: %s\n", what);
    g_fail += 1000;
}

static AotAddressSpace *make_space(AotMemDomain *dom, int seal, int poison) {
    AotAddressSpace *as = aot_as_create(dom);
    if (as == NULL) {
        fatal("create space");
        return NULL;
    }
    if (aot_as_add_reserved_window(as, ALIAS_BASE, ALIAS_SIZE,
                                   AOT_AS_RESERVED_ROLE_ALIAS) != AOT_MEM_OK)
        fatal("alias window");
    if (aot_as_add_reserved_window(as, STACK_BASE, STACK_SIZE,
                                   AOT_AS_RESERVED_ROLE_STACK) != AOT_MEM_OK)
        fatal("stack window");
    if (aot_as_add_heap_window(as, HBASE, HMAXSZ, HCOMMIT) != AOT_MEM_OK)
        fatal("heap window");
    if (poison) aot_as_poison(as);
    if (seal && !poison && aot_as_seal(as) != AOT_MEM_OK) fatal("seal");
    return as;
}

/* OS-level witness of one alias page: the AS pointer handed out, the real host
 * state of the page and its real protection. `want_state` is the expected host
 * state of an unmapped page (RESERVE after a decommit, COMMIT when its 16 KiB
 * group is still partly mapped and the page is retained NONE). */
static void witness(AotAddressSpace *as, uint64_t addr, const char *what,
                    int want_page, unsigned want_state) {
    host_vm_region *vm = NULL;
    const uint8_t *page = NULL;
    size_t off = 0xdeadbeefu;
    host_vm_info info;
    if (!aot_as_host_page(as, addr, &vm, &page, &off)) {
        check(0, what);
        return;
    }
    if (vm == NULL || off != (size_t)(addr - ALIAS_BASE) ||
        host_vm_query(vm, off, &info) != HOST_VM_OK) {
        check(0, what);
        return;
    }
    if (want_page) {
        check(page != NULL, what);
        check(info.state == HOST_VM_STATE_COMMIT, what);
        check((info.protection & (HOST_VM_PROT_READ | HOST_VM_PROT_WRITE)) ==
                  (HOST_VM_PROT_READ | HOST_VM_PROT_WRITE),
              what);
    } else {
        check(page == NULL, what);
        check(info.state == want_state, what);
        check(info.protection == 0u, what);
    }
}

/* Request validation and the lifecycle refusals: no host state is created. */
static void lifecycle_rows(AotMemDomain *dom) {
    AotAddressSpace *as;
    AotAsQuery q;
    AotAsAliasInfo ai;
    uint64_t fresh = 0xdeadbeefdeadbeefull;
    uint64_t released = 0xdeadbeefdeadbeefull;

    as = make_space(dom, 1, 0);
    if (as == NULL) return;

    check(aot_as_alias_map(as, ALIAS_BASE, 0u, IMG_BYTES, POOL, &fresh) ==
              AOT_MEM_ERR_ALIGN,
          "map zero size is Mac 0xcc01 (ALIGN)");
    check(aot_as_alias_map(as, ALIAS_BASE + 1u, PG, IMG_BYTES, POOL, &fresh) ==
              AOT_MEM_ERR_ALIGN,
          "map misaligned address is Mac 0xcc01 (ALIGN)");
    check(aot_as_alias_map(as, ALIAS_BASE, PG + 1u, IMG_BYTES, POOL, &fresh) ==
              AOT_MEM_ERR_ALIGN,
          "map misaligned size is Mac 0xcc01 (ALIGN)");
    check(aot_as_alias_map(as, ALIAS_BASE - PG, PG, IMG_BYTES, POOL, &fresh) ==
              AOT_MEM_ERR_RANGE,
          "map below the window is Mac 0xdc01 (RANGE)");
    check(aot_as_alias_map(as, ALIAS_BASE + ALIAS_SIZE, PG, IMG_BYTES, POOL,
                           &fresh) == AOT_MEM_ERR_RANGE,
          "map at the window end is Mac 0xdc01 (RANGE)");
    check(aot_as_alias_map(as, ALIAS_BASE + ALIAS_SIZE - PG, PG * 2u, IMG_BYTES,
                           POOL, &fresh) == AOT_MEM_ERR_RANGE,
          "map crossing the window end is Mac 0xdc01 (RANGE)");
    check(aot_as_alias_map(as, 0xfffffffffffff000ull, PG, IMG_BYTES, POOL,
                           &fresh) == AOT_MEM_ERR_RANGE,
          "map wrapping address is RANGE, never accepted");
    check(aot_as_alias_unmap(as, ALIAS_BASE, 0u, &released) == AOT_MEM_ERR_ALIGN,
          "unmap zero size is ALIGN");
    check(aot_as_alias_unmap(as, ALIAS_BASE + 1u, PG, &released) ==
              AOT_MEM_ERR_ALIGN,
          "unmap misaligned address is ALIGN");
    check(aot_as_alias_unmap(as, ALIAS_BASE + ALIAS_SIZE - PG, PG * 2u,
                             &released) == AOT_MEM_ERR_RANGE,
          "unmap crossing the window end is RANGE");
    check(fresh == 0xdeadbeefdeadbeefull &&
              released == 0xdeadbeefdeadbeefull,
          "a refused request writes no output");

    check(aot_as_alias_info(as, &ai) == AOT_MEM_OK && ai.base == ALIAS_BASE &&
              ai.size == ALIAS_SIZE && ai.mapped_bytes == 0u &&
              ai.mapped_pages == 0u,
          "alias_info reports the AS geometry and an empty occupancy");
    check(aot_as_query(as, ALIAS_BASE, &q) == 1 && q.state == 0u &&
              q.perm == AOT_AS_PERM_NONE && q.base == ALIAS_BASE &&
              q.size == ALIAS_SIZE,
          "an entirely unmapped alias window is one Free run");
    aot_as_destroy(as);

    /* Unsealed space: no alias mapping may exist before the AS is sealed. */
    as = make_space(dom, 0, 0);
    if (as != NULL) {
        check(aot_as_alias_map(as, ALIAS_BASE, PG, IMG_BYTES, POOL, &fresh) ==
                  AOT_MEM_ERR_PERM,
              "map on an unsealed space is a typed PERM refusal");
        check(aot_as_alias_unmap(as, ALIAS_BASE, PG, &released) ==
                  AOT_MEM_ERR_PERM,
              "unmap on an unsealed space is a typed PERM refusal");
        aot_as_destroy(as);
    }

    /* Poisoned space (failed load residue) can never map alias pages. */
    as = make_space(dom, 0, 1);
    if (as != NULL) {
        check(aot_as_alias_map(as, ALIAS_BASE, PG, IMG_BYTES, POOL, &fresh) ==
                  AOT_MEM_ERR_PERM,
              "map on a poisoned space is a typed PERM refusal");
        aot_as_destroy(as);
    }

    /* A space without an alias window cannot serve the SVC at all. */
    as = aot_as_create(dom);
    if (as == NULL) {
        fatal("create alias-less space");
    } else {
        if (aot_as_add_heap_window(as, HBASE, HMAXSZ, HCOMMIT) != AOT_MEM_OK)
            fatal("alias-less heap");
        if (aot_as_seal(as) != AOT_MEM_OK) fatal("alias-less seal");
        check(aot_as_alias_map(as, ALIAS_BASE, PG, IMG_BYTES, POOL, &fresh) ==
                  AOT_MEM_ERR_PERM,
              "map without an alias window is a typed PERM refusal");
        check(aot_as_alias_info(as, &ai) == AOT_MEM_ERR_PERM,
              "alias_info without an alias window is PERM");
        aot_as_destroy(as);
    }
}

static void normal_rows(AotMemDomain *dom) {
    AotAddressSpace *as = make_space(dom, 1, 0);
    const uint64_t A = ALIAS_BASE + 0x40000ull;   /* 16 KiB aligned */
    const uint64_t B = ALIAS_BASE + 0x80000ull;
    const uint64_t C = ALIAS_BASE + 0xc0000ull;
    AotAsQuery q;
    AotAsAliasInfo ai;
    AotAsUsage u;
    uint64_t fresh = 0u, released = 0u, v = 0u, b = 0u;
    uint64_t pinned;
    int i;

    if (as == NULL) return;

    /* ---- first map: commit, occupancy, runs and guest access ---- */
    check(aot_as_alias_map(as, A, 2u * PG, IMG_BYTES, POOL, &fresh) ==
              AOT_MEM_OK && fresh == 2u * PG,
          "first map commits both pages and reports them fresh");
    witness(as, A, "mapped page is host COMMIT/RW with a real page pointer", 1,
            HOST_VM_STATE_RESERVE);
    witness(as, A + PG, "second mapped page is host COMMIT/RW", 1,
            HOST_VM_STATE_RESERVE);
    check(aot_as_query(as, A, &q) == 1 && q.base == A &&
              q.size == 2u * PG && q.state == AOT_AS_STATE_HEAP &&
              q.perm == AOT_AS_PERM_RW && q.attr == 0u,
          "a mapped block answers one RW/state-5 run");
    check(aot_as_query(as, A + PG, &q) == 1 && q.base == A &&
              q.size == 2u * PG,
          "the run is stable across the mapped block");
    check(aot_as_query(as, A - PG, &q) == 1 && q.base == ALIAS_BASE &&
              q.size == 0x40000ull && q.state == 0u &&
              q.perm == AOT_AS_PERM_NONE,
          "the Free run before the mapped block is reported exactly");
    check(aot_as_query(as, A + 2u * PG, &q) == 1 &&
              q.base == A + 2u * PG && q.size == ALIAS_SIZE - 0x42000ull &&
              q.state == 0u && q.perm == AOT_AS_PERM_NONE,
          "the Free run after the mapped block is reported exactly");
    check(aot_as_write(as, A, &(uint64_t){0x1122334455667788ull},
                       sizeof(uint64_t)) == AOT_MEM_OK,
          "a mapped alias page accepts a guest store");
    check(aot_as_write(as, A + PG, &(uint64_t){0x99aabbccddeeff00ull},
                       sizeof(uint64_t)) == AOT_MEM_OK,
          "the second mapped page accepts a guest store");
    check(aot_as_read(as, A, &v, sizeof v) == AOT_MEM_OK &&
              v == 0x1122334455667788ull,
          "a mapped alias page returns the stored bytes");
    check(aot_as_read(as, A + PG, &v, sizeof v) == AOT_MEM_OK &&
              v == 0x99aabbccddeeff00ull,
          "the second mapped page returns the stored bytes");
    check(aot_as_read(as, A + 2u * PG, &v, sizeof v) == AOT_MEM_ERR_PERM,
          "an unmapped alias page refuses a guest load");
    check(aot_as_write(as, A + 2u * PG, &v, sizeof v) == AOT_MEM_ERR_PERM,
          "an unmapped alias page refuses a guest store");
    witness(as, A + 2u * PG, "an unmapped page stays RESERVE/NONE", 0,
            HOST_VM_STATE_RESERVE);
    check(aot_as_usage(as, &u) == AOT_MEM_OK && u.heap_size == 0u &&
              u.alias_bytes == 2u * PG,
          "usage reports the mapped alias bytes and the heap size");

    /* ---- re-map of an owned range: contents preserved, not re-charged ---- */
    fresh = 1u;
    check(aot_as_alias_map(as, A, 2u * PG, IMG_BYTES, POOL, &fresh) ==
              AOT_MEM_OK && fresh == 0u,
          "re-mapping an owned range maps nothing fresh");
    check(aot_as_read(as, A, &v, sizeof v) == AOT_MEM_OK &&
              v == 0x1122334455667788ull,
          "re-mapping an owned range preserves its contents");

    /* ---- APP_POOL budget (Mac services.c:129) ---- */
    pinned = POOL - 2u * PG;   /* exactly full: pinned + alias == pool */
    fresh = 1u;
    check(aot_as_alias_map(as, A, 2u * PG, pinned, POOL, &fresh) ==
              AOT_MEM_OK && fresh == 0u,
          "a grow over an owned range is not charged twice");
    fresh = 1u;
    check(aot_as_alias_map(as, A + 2u * PG, PG, pinned, POOL, &fresh) ==
              AOT_MEM_ERR_LIMIT,
          "a fresh page over the pool is LimitReached");
    check(aot_as_alias_info(as, &ai) == AOT_MEM_OK &&
              ai.mapped_bytes == 2u * PG && ai.mapped_pages == 2u,
          "a refused map leaves the occupancy unchanged");

    /* ---- unmap: release, Free answer, retained host storage ---- */
    check(aot_as_alias_unmap(as, A, PG, &released) == AOT_MEM_OK &&
              released == PG,
          "unmap reports the released bytes");
    check(aot_as_query(as, A, &q) == 1 && q.state == 0u &&
              q.perm == AOT_AS_PERM_NONE && q.base == ALIAS_BASE &&
              q.size == 0x41000ull,
          "a released page joins the maximal Free run before it");
    check(aot_as_query(as, A + PG, &q) == 1 && q.base == A + PG &&
              q.size == PG && q.perm == AOT_AS_PERM_RW,
          "the still-mapped neighbour keeps its own mapped run");
    check(aot_as_read(as, A, &v, sizeof v) == AOT_MEM_ERR_PERM,
          "a released page refuses a guest load");
    witness(as, A, "a released page of a partly mapped group is retained NONE",
            0, HOST_VM_STATE_COMMIT);
    check(aot_as_usage(as, &u) == AOT_MEM_OK && u.alias_bytes == PG,
          "unmap subtracts the released bytes from the usage");

    /* ---- a later map of a released page reads zero, not old bytes ---- */
    fresh = 0u;
    check(aot_as_alias_map(as, A, PG, IMG_BYTES, POOL, &fresh) == AOT_MEM_OK &&
              fresh == PG,
          "re-mapping a released page is fresh again");
    check(aot_as_read(as, A, &v, sizeof v) == AOT_MEM_OK && v == 0u,
          "a re-mapped released page reads zero");

    /* ---- 16 KiB group stays committed while one page is still mapped ---- */
    check(aot_as_alias_map(as, B, GROUP, IMG_BYTES, POOL, &fresh) ==
              AOT_MEM_OK && fresh == GROUP,
          "map one full 16 KiB group");
    for (i = 0; i < 4; i++) {
        uint64_t pattern = 0xa000u + (uint64_t)i;
        check(aot_as_write(as, B + (uint64_t)i * PG, &pattern,
                           sizeof pattern) == AOT_MEM_OK,
              "group page accepts its pattern");
    }
    check(aot_as_alias_unmap(as, B + PG, PG, &released) == AOT_MEM_OK &&
              released == PG,
          "release the second page of the group");
    check(aot_as_alias_unmap(as, B + 3u * PG, PG, &released) == AOT_MEM_OK &&
              released == PG,
          "release the fourth page of the group");
    witness(as, B + PG, "a released page of a partly mapped group is COMMIT/NONE",
            0, HOST_VM_STATE_COMMIT);
    check(aot_as_read(as, B, &v, sizeof v) == AOT_MEM_OK && v == 0xa000u,
          "the first page of the group keeps its contents");
    check(aot_as_read(as, B + 2u * PG, &v, sizeof v) == AOT_MEM_OK &&
              v == 0xa002u,
          "the third page of the group keeps its contents");
    fresh = 0u;
    check(aot_as_alias_map(as, B + PG, PG, IMG_BYTES, POOL, &fresh) ==
              AOT_MEM_OK && fresh == PG,
          "re-map the released group page");
    check(aot_as_read(as, B + PG, &v, sizeof v) == AOT_MEM_OK && v == 0u,
          "the released group page comes back zero");

    /* ---- a fully released group is decommitted ---- */
    check(aot_as_alias_map(as, C, GROUP, IMG_BYTES, POOL, &fresh) ==
              AOT_MEM_OK && fresh == GROUP,
          "map a group for the decommit row");
    check(aot_as_alias_unmap(as, C, GROUP, &released) == AOT_MEM_OK &&
              released == GROUP,
          "release the whole group in one call");
    witness(as, C, "a fully released group page is host RESERVE/NONE", 0,
            HOST_VM_STATE_RESERVE);
    witness(as, C + 3u * PG, "every page of the released group is decommitted",
            0, HOST_VM_STATE_RESERVE);
    check(aot_as_query(as, C, &q) == 1 && q.state == 0u &&
              q.perm == AOT_AS_PERM_NONE && q.base <= C &&
              q.base + q.size >= C + GROUP,
          "the released group is inside a Free run");

    /* ---- accounting coherence and heap independence ---- */
    check(aot_as_alias_info(as, &ai) == AOT_MEM_OK &&
              ai.mapped_bytes == ai.mapped_pages * PG,
          "alias_info bytes and pages agree");
    check(aot_as_usage(as, &u) == AOT_MEM_OK &&
              u.alias_bytes == ai.mapped_bytes,
          "usage and alias_info agree");
    check(aot_as_set_heap_size(as, 0x200000ull, &b) == AOT_MEM_OK,
          "grow the heap");
    check(aot_as_alias_info(as, &ai) == AOT_MEM_OK &&
              ai.mapped_bytes == ai.mapped_pages * PG &&
              aot_as_usage(as, &u) == AOT_MEM_OK && u.heap_size == 0x200000ull,
          "heap growth leaves the alias occupancy and reporting alone");
    check(aot_as_query(as, B, &q) == 1 && q.perm == AOT_AS_PERM_RW,
          "alias mapping survives heap growth");
    check(aot_as_set_heap_size(as, 0u, &b) == AOT_MEM_OK, "shrink the heap");
    check(aot_as_read(as, B, &v, sizeof v) == AOT_MEM_OK && v == 0xa000u,
          "alias mapping survives heap shrink");

    /* ---- the stack reserved role is still refused ---- */
    check(aot_as_read(as, STACK_BASE, &v, sizeof v) == AOT_MEM_ERR_PERM,
          "the stack window keeps refusing guest access");

    aot_as_destroy(as);
}

/* Deterministic host-refusal seams (positive controls: the rollback and the
 * sticky-desync protocol must be exercised, and the probe must still pass). */
static void fault_rows(AotMemDomain *dom) {
    AotAddressSpace *as = make_space(dom, 1, 0);
    const uint64_t C = ALIAS_BASE + 0xc0000ull;
    AotAsQuery q;
    AotAsAliasInfo ai;
    uint64_t fresh = 0u, released = 0u;

    if (as == NULL) return;
#if FAULT_MODE == 1 || FAULT_MODE == 2
    const uint64_t A = ALIAS_BASE + 0x40000ull;
    (void)C;
    check(aot_as_alias_map(as, A, 2u * PG, IMG_BYTES, POOL, &fresh) ==
              AOT_MEM_ERR_HOST,
          "an injected host commit refusal is a typed HOST failure");
    check(aot_as_alias_info(as, &ai) == AOT_MEM_OK && ai.mapped_bytes == 0u &&
              ai.mapped_pages == 0u,
          "a failed map publishes no occupancy");
    check(aot_as_query(as, A, &q) == 1 && q.state == 0u &&
              q.base == ALIAS_BASE && q.size == ALIAS_SIZE,
          "a failed map publishes no mapped run");
    witness(as, A, "a rolled-back page is back to host RESERVE/NONE", 0,
            HOST_VM_STATE_RESERVE);
    /* A successful rollback must not leave the space sticky. */
    check(aot_as_alias_unmap(as, A, PG, &released) == AOT_MEM_OK &&
              released == 0u,
          "a successful rollback leaves the alias path usable");
#else
    check(aot_as_alias_map(as, C, GROUP, IMG_BYTES, POOL, &fresh) ==
              AOT_MEM_OK && fresh == GROUP,
          "map the group before the injected decommit failure");
    check(aot_as_alias_unmap(as, C, GROUP, &released) == AOT_MEM_ERR_HOST,
          "an injected host decommit refusal is a typed HOST failure");
    check(aot_as_alias_info(as, &ai) == AOT_MEM_OK && ai.mapped_bytes == 0u,
          "the release is published even when the decommit fails");
    check(aot_as_query(as, C, &q) == 1 && q.state == 0u,
          "the released group answers Free after the decommit failure");
    witness(as, C, "a refused decommit leaves the group committed", 0,
            HOST_VM_STATE_COMMIT);
    fresh = 0u;
    check(aot_as_alias_map(as, C, PG, IMG_BYTES, POOL, &fresh) ==
              AOT_MEM_ERR_HOST,
          "an unrecoverable alias failure makes later maps fail closed");
    check(aot_as_alias_unmap(as, C, PG, &released) == AOT_MEM_ERR_HOST,
          "an unrecoverable alias failure makes later unmaps fail closed");
#endif
    aot_as_destroy(as);
}


/* Batch-size and tail regression for the page-count reductions behind
 * MapPhysicalMemory/UnmapPhysicalMemory. The expectations are CLOSED FORM
 * (n pages => n * PG), not a second implementation of the counter, and every
 * batch size 1..12 is swept so all `count % 4` tails are exercised: the defect
 * pinned here only appeared for count >= 4 and only at /O2 (see
 * as_alias_mapped_pages in aot_as.c). */
static void batch_rows(AotMemDomain *dom) {
    uint64_t n;
    AotAddressSpace *as;
    AotAsAliasInfo ai;
    AotAsUsage u;
    const uint64_t B = ALIAS_BASE + 0x100000ull;   /* 16 KiB aligned */

    for (n = 1u; n <= 12u; n++) {
        uint64_t fresh = 0xdeadbeefdeadbeefull;
        uint64_t released = 0xdeadbeefdeadbeefull;
        as = make_space(dom, 1, 0);
        if (as == NULL) return;
        check(aot_as_alias_map(as, B, n * PG, IMG_BYTES, POOL, &fresh) ==
                  AOT_MEM_OK && fresh == n * PG,
              "a fresh batch reports every page as fresh");
        check(aot_as_alias_info(as, &ai) == AOT_MEM_OK &&
                  ai.mapped_pages == n && ai.mapped_bytes == n * PG,
              "a fresh batch reports its occupancy in pages and bytes");
        check(aot_as_usage(as, &u) == AOT_MEM_OK && u.alias_bytes == n * PG,
              "a fresh batch charges exactly its pages");
        check(aot_as_alias_map(as, B + n * PG, 3u * PG, IMG_BYTES, POOL,
                               &fresh) == AOT_MEM_OK && fresh == 3u * PG,
              "a grow charges only the pages beyond the owned batch");
        check(aot_as_alias_unmap(as, B + 3u * PG, n * PG, &released) ==
                  AOT_MEM_OK && released == n * PG,
              "a tail release reports exactly the released pages");
        check(aot_as_alias_info(as, &ai) == AOT_MEM_OK &&
                  ai.mapped_pages == 3u && ai.mapped_bytes == 3u * PG,
              "a tail release leaves the grow batch's accounting");
        check(aot_as_usage(as, &u) == AOT_MEM_OK && u.alias_bytes == 3u * PG,
              "a tail release subtracts exactly the released bytes");
        aot_as_destroy(as);
    }

    /* A release range that spans an already-released hole: 10 mapped pages,
     * release 2, release 6 past the hole, then 4 across it. */
    {
        uint64_t fresh = 0u;
        uint64_t released = 0xdeadbeefdeadbeefull;
        as = make_space(dom, 1, 0);
        if (as == NULL) return;
        check(aot_as_alias_map(as, B, 10u * PG, IMG_BYTES, POOL, &fresh) ==
                  AOT_MEM_OK && fresh == 10u * PG,
              "a ten-page batch reports every page as fresh");
        check(aot_as_alias_unmap(as, B + 2u * PG, 2u * PG, &released) ==
                  AOT_MEM_OK && released == 2u * PG,
              "releasing a two-page hole reports two pages");
        check(aot_as_alias_unmap(as, B + 4u * PG, 6u * PG, &released) ==
                  AOT_MEM_OK && released == 6u * PG,
              "a six-page release past the hole reports six pages");
        check(aot_as_alias_unmap(as, B, 4u * PG, &released) == AOT_MEM_OK &&
                  released == 2u * PG,
              "a release across a hole reports only the mapped pages");
        check(aot_as_alias_info(as, &ai) == AOT_MEM_OK &&
                  ai.mapped_pages == 0u && ai.mapped_bytes == 0u,
              "releasing every page returns the accounting to zero");
        aot_as_destroy(as);
    }
}

int main(void) {
    AotMemDomain *dom = aot_mem_domain_create();
    if (dom == NULL) {
        printf("FATAL: domain\n");
        return 1;
    }
    lifecycle_rows(dom);
#if FAULT_MODE == 0
    normal_rows(dom);
    batch_rows(dom);
#endif
#if FAULT_MODE != 0
    fault_rows(dom);
#endif
    aot_mem_domain_destroy(dom);
    if (g_fail != 0) {
        printf("alias map probe: %d failures\n", g_fail);
        return (g_fail >= 1000) ? 1 : 2;
    }
    printf("alias map probe: all checks passed\n");
    return 0;
}
