/* Owned G3 alias-reserved-window probe: immutable AS-owned geometry, Free
 * state, host RESERVE witness, no access/monitor/protect path, no dispatch. */
#include "aot_as.h"
#include "aot_mem.h"
#include "aot_runtime.h"
#include "host_vm.h"

#include <stdio.h>
#include <string.h>

#define ALIAS_BASE 0x5000000000ull
#define ALIAS_SIZE 0x1000000000ull          /* 64 GiB > 32-bit */
#define STACK_BASE 0x2800000000ull
#define STACK_SIZE 0x10000000ull
#define HMAXSZ     0x800000ull
#define HBASE      0x4000000000ull
#define MAXADDR    0x8000000000ull
#define ROLE       AOT_AS_RESERVED_ROLE_ALIAS
#define STACK_ROLE AOT_AS_RESERVED_ROLE_STACK
#define IMG_BASE   0x6100000000ull
#define IMG_SIZE   0x1000ull
#define THUNK_BASE 0x6200000000ull
#define SENTINEL_BASE 0x6300000000ull
#define SENTINEL_COUNT 32u

static int g_fail;
static void check(int ok, const char *what) {
    if (!ok) { printf("FAIL: %s\n", what); g_fail++; }
}
static void fatal(const char *what) { printf("FATAL: %s\n", what); g_fail++; }

static AotAddressSpace *make_space(AotMemDomain *dom) {
    AotAddressSpace *as = aot_as_create(dom);
    if (as == NULL) fatal("create space");
    return as;
}

static int all_bytes(const uint8_t *p, size_t n, uint8_t v) {
    for (size_t i = 0; i < n; i++) if (p[i] != v) return 0;
    return 1;
}

static void host_reserve(const AotAddressSpace *as, uint32_t role,
                         uint64_t addr, const char *what) {
    host_vm_region *vm = NULL;
    const uint8_t *page = (const uint8_t *)(uintptr_t)1;
    size_t off = 0xdeadbeefu;
    host_vm_info info;
    uint64_t ab = 0u, an = 0u;
    (void)an;
    if (aot_as_reserved_info(as, role, &ab, &an) != AOT_MEM_OK) {
        check(0, "host_reserve geometry");
        return;
    }
    check(aot_as_host_page(as, addr, &vm, &page, &off), what);
    check(vm != NULL && page == NULL && off == (size_t)(addr - ab),
          "host_page vm+offset+NULL page");
    check(host_vm_query(vm, off, &info) == HOST_VM_OK &&
              info.state == HOST_VM_STATE_RESERVE &&
              info.protection == 0u,
          "alias page is host RESERVE/NONE");
}

static AotExit dummy_block(AotGuestState *s, AotRuntime *rt) {
    (void)s;
    (void)rt;
    return AOT_EXIT_RET;
}

static void geometry(void) {
    AotMemDomain *dom = aot_mem_domain_create();
    AotAddressSpace *as;
    uint64_t b = 0u, n = 0u;
    if (dom == NULL) { fatal("domain"); return; }

    as = make_space(dom);
    check(aot_as_add_reserved_window(as, ALIAS_BASE, 0u, ROLE) ==
              AOT_MEM_ERR_RANGE, "zero size is RANGE");
    check(aot_as_add_reserved_window(as, ALIAS_BASE + 1u, 0x1000u, ROLE) ==
              AOT_MEM_ERR_RANGE, "misaligned base is RANGE");
    check(aot_as_add_reserved_window(as, ALIAS_BASE, 0x1001u, ROLE) ==
              AOT_MEM_ERR_RANGE, "misaligned size is RANGE");
    check(aot_as_add_reserved_window(as, 0x1000u, 0x1000u, ROLE) ==
              AOT_MEM_ERR_RANGE, "below MIN is RANGE");
    check(aot_as_add_reserved_window(as, MAXADDR - 0x1000u, 0x2000u, ROLE) ==
              AOT_MEM_ERR_RANGE, "past MAX is RANGE");
    check(aot_as_add_reserved_window(as, ALIAS_BASE, 0x1000u, UINT32_MAX) ==
              AOT_MEM_ERR_WIDTH, "unknown role is WIDTH");
    check(aot_as_add_reserved_window(as, ALIAS_BASE, 0x1000u, ROLE) ==
              AOT_MEM_OK, "alias add");
    check(aot_as_add_reserved_window(as, STACK_BASE, STACK_SIZE,
                                     STACK_ROLE) == AOT_MEM_OK,
          "stack add");
    check(aot_as_add_reserved_window(as, ALIAS_BASE + 0x1000u, 0x1000u,
                                     ROLE) == AOT_MEM_ERR_RANGE,
          "second alias role is RANGE");
    check(aot_as_add_reserved_window(as, STACK_BASE + STACK_SIZE, 0x1000u,
                                     STACK_ROLE) == AOT_MEM_ERR_RANGE,
          "second stack role is RANGE");
    check(aot_as_add_region(as, ALIAS_BASE, 0x1000u,
                            AOT_AS_PERM_RW, AOT_AS_STATE_DATA, NULL) ==
              AOT_MEM_ERR_RANGE, "region overlapping alias is RANGE");
    check(aot_as_add_region(as, STACK_BASE, 0x1000u,
                            AOT_AS_PERM_RW, AOT_AS_STATE_DATA, NULL) ==
              AOT_MEM_ERR_RANGE, "region overlapping stack is RANGE");
    check(aot_as_reserved_info(as, ROLE, &b, &n) == AOT_MEM_OK &&
              b == ALIAS_BASE && n == 0x1000u, "getter returns geometry");
    check(aot_as_reserved_info(as, STACK_ROLE, &b, &n) == AOT_MEM_OK &&
              b == STACK_BASE && n == STACK_SIZE, "stack getter geometry");
    check(aot_as_reserved_info(as, 3u, &b, &n) == AOT_MEM_ERR_WIDTH &&
              aot_as_reserved_info(as, UINT32_MAX, &b, &n) ==
                  AOT_MEM_ERR_WIDTH,
          "unknown reserved getter role is WIDTH");
    if (aot_as_seal(as) != AOT_MEM_OK) fatal("seal alias");
    check(aot_as_add_reserved_window(as, ALIAS_BASE + 0x1000u, 0x1000u,
                                     ROLE) == AOT_MEM_ERR_RANGE,
          "add after seal is RANGE");
    aot_as_destroy(as);

    as = make_space(dom);
    if (aot_as_add_region(as, ALIAS_BASE - 0x1000u, 0x1000u, AOT_AS_PERM_RW,
                          AOT_AS_STATE_DATA, NULL) != AOT_MEM_OK)
        fatal("region before alias");
    check(aot_as_add_reserved_window(as, ALIAS_BASE - 0x800u, 0x1000u, ROLE) ==
              AOT_MEM_ERR_RANGE, "alias overlapping region is RANGE");
    aot_as_destroy(as);

    as = make_space(dom);
    check(aot_as_add_reserved_window(as, MAXADDR - 0x100000000ull,
                                     0x100000000ull, ROLE) == AOT_MEM_OK,
          "window ending exactly at MAX is valid");
    check(aot_as_reserved_info(as, ROLE, &b, &n) == AOT_MEM_OK &&
              b + n == MAXADDR, "end==MAX geometry");
    aot_as_destroy(as);

    as = make_space(dom);
    aot_as_poison(as);
    check(aot_as_add_reserved_window(as, ALIAS_BASE, 0x1000u, ROLE) ==
              AOT_MEM_ERR_RANGE, "poisoned space is RANGE");
    aot_as_destroy(as);

    /* Overlap checks in BOTH insertion orders (heap first / alias-stack first). */
    as = make_space(dom);
    if (aot_as_add_heap_window(as, HBASE, 0x200000ull, 0x200000ull) !=
        AOT_MEM_OK)
        fatal("overlap heap first");
    check(aot_as_add_reserved_window(as, HBASE, 0x1000u, ROLE) ==
              AOT_MEM_ERR_RANGE, "alias overlapping heap (heap first) is RANGE");
    check(aot_as_add_reserved_window(as, HBASE, 0x1000u, STACK_ROLE) ==
              AOT_MEM_ERR_RANGE, "stack overlapping heap (heap first) is RANGE");
    aot_as_destroy(as);

    as = make_space(dom);
    if (aot_as_add_reserved_window(as, ALIAS_BASE, 0x1000u, ROLE) !=
            AOT_MEM_OK ||
        aot_as_add_reserved_window(as, STACK_BASE, STACK_SIZE, STACK_ROLE) !=
            AOT_MEM_OK)
        fatal("overlap alias-stack first");
    check(aot_as_add_heap_window(as, ALIAS_BASE, 0x200000ull, 0x200000ull) ==
              AOT_MEM_ERR_RANGE,
          "heap overlapping alias (alias first) is RANGE");
    check(aot_as_add_heap_window(as, STACK_BASE, 0x200000ull, 0x200000ull) ==
              AOT_MEM_ERR_RANGE,
          "heap overlapping stack (stack first) is RANGE");
    aot_as_destroy(as);

    /* A second AS with a DIFFERENT BASE AND SIZE for BOTH reserved roles. */
    as = make_space(dom);
    check(aot_as_add_reserved_window(as, 0x7000000000ull, 0x800000ull, ROLE) ==
              AOT_MEM_OK, "second distinct alias add");
    check(aot_as_add_reserved_window(as, 0x3000000000ull, 0x200000ull,
                                     STACK_ROLE) == AOT_MEM_OK,
          "second distinct stack add");
    check(aot_as_reserved_info(as, ROLE, &b, &n) == AOT_MEM_OK &&
              b == 0x7000000000ull && n == 0x800000ull,
          "second AS returns its own alias base and size");
    check(aot_as_reserved_info(as, STACK_ROLE, &b, &n) == AOT_MEM_OK &&
              b == 0x3000000000ull && n == 0x200000ull,
          "second AS returns its own stack base and size");
    if (aot_as_seal(as) != AOT_MEM_OK) fatal("seal second");
    host_reserve(as, ROLE, 0x7000000000ull, "second AS first page reserve");
    host_reserve(as, STACK_ROLE, 0x3000000000ull,
                 "second AS stack first page reserve");
    aot_as_destroy(as);

    aot_mem_domain_destroy(dom);
}

static void access_checks(AotMemDomain *dom) {
    AotAddressSpace *as = make_space(dom);
    AotAsQuery q;
    AotAsHeapInfo heap;
    AotMem mem;
    uint32_t token;
    uint32_t stx = 1u;
    uint64_t v = 0xdeadbeefdeadbeefull;
    uint64_t pair[2] = {0xdeadbeefdeadbeefull, 0xdeadbeefdeadbeefull};
    uint8_t buf[16];
    uint64_t b = 0u, n = 0u;

    if (aot_as_add_region(as, ALIAS_BASE - 0x2000ull, 0x2000ull,
                          AOT_AS_PERM_RW, AOT_AS_STATE_DATA, NULL) != AOT_MEM_OK)
        fatal("region below");
    if (aot_as_add_region(as, ALIAS_BASE + ALIAS_SIZE, 0x1000ull,
                          AOT_AS_PERM_RW, AOT_AS_STATE_DATA, NULL) != AOT_MEM_OK)
        fatal("region above");
    if (aot_as_add_heap_window(as, HBASE, HMAXSZ, 0x600000ull) != AOT_MEM_OK)
        fatal("heap add");
    if (aot_as_add_reserved_window(as, ALIAS_BASE, ALIAS_SIZE, ROLE) !=
        AOT_MEM_OK)
        fatal("alias add");
    if (aot_as_add_reserved_window(as, STACK_BASE, STACK_SIZE, STACK_ROLE) !=
        AOT_MEM_OK)
        fatal("stack add");
    if (aot_as_seal(as) != AOT_MEM_OK) fatal("seal");
    if (aot_mem_init_aspace(&mem, as) != AOT_MEM_OK) fatal("mem init");

    /* Heap getter must never select the alias reserved role. */
    check(aot_as_heap_info(as, &heap) == AOT_MEM_OK && heap.base == HBASE &&
              heap.max_size == HMAXSZ,
          "heap_info selects the heap window, not alias");
    check(aot_as_reserved_info(as, ROLE, &b, &n) == AOT_MEM_OK &&
              b == ALIAS_BASE && n == ALIAS_SIZE,
          "alias getter geometry");
    check(aot_as_query(as, ALIAS_BASE, &q) == 1 && q.state == 0u &&
              q.perm == AOT_AS_PERM_NONE && q.base == ALIAS_BASE &&
              q.size == ALIAS_SIZE && q.attr == 0u,
          "alias whole window queries Free/NONE/attr0");
    check(aot_as_query(as, ALIAS_BASE + ALIAS_SIZE - 0x1000ull, &q) == 1 &&
              q.state == 0u && q.perm == AOT_AS_PERM_NONE &&
              q.base == ALIAS_BASE && q.size == ALIAS_SIZE,
          "alias last-page query stays the whole Free window");
    check(aot_as_range_mapped(as, ALIAS_BASE, 16u) == 1,
          "alias first 16 bytes are claimed");
    check(aot_as_range_mapped(as, ALIAS_BASE + ALIAS_SIZE - 16ull, 16u) == 1,
          "alias last 16 bytes are claimed");
    check(aot_as_range_mapped(as, ALIAS_BASE - 16ull, 16u) == 1,
          "alias-adjacent region is claimed");
    check(aot_as_range_mapped(as, ALIAS_BASE + ALIAS_SIZE + 0x1000ull, 16u) == 0,
          "unmapped above alias is not claimed");
    check(aot_as_query(as, STACK_BASE, &q) == 1 && q.state == 0u &&
              q.perm == AOT_AS_PERM_NONE && q.base == STACK_BASE &&
              q.size == STACK_SIZE && q.attr == 0u,
          "stack whole window queries Free/NONE/attr0");
    check(aot_as_range_mapped(as, STACK_BASE, 16u) == 1,
          "stack first 16 bytes are claimed");
    check(aot_as_range_mapped(as, STACK_BASE + STACK_SIZE - 16ull, 16u) == 1,
          "stack last 16 bytes are claimed");

    host_reserve(as, ROLE, ALIAS_BASE, "alias first page reserve");
    host_reserve(as, ROLE, ALIAS_BASE + ALIAS_SIZE - 0x1000ull,
                 "alias last page reserve");
    host_reserve(as, STACK_ROLE, STACK_BASE, "stack first page reserve");
    host_reserve(as, STACK_ROLE, STACK_BASE + STACK_SIZE - 0x1000ull,
                 "stack last page reserve");

    /* Every access path refuses before any host dereference/output write. */
    memset(buf, 0xaa, sizeof buf);
    check(aot_as_read(as, ALIAS_BASE, buf, 16u) == AOT_MEM_ERR_PERM &&
              all_bytes(buf, sizeof buf, 0xaa),
          "read alias is PERM with output untouched");
    check(aot_as_write(as, ALIAS_BASE, buf, 16u) == AOT_MEM_ERR_PERM,
          "write alias is PERM");
    check(aot_as_ld_locked(as, ALIAS_BASE + 0x1000ull, 1u, &v) ==
              AOT_MEM_ERR_PERM && v == 0xdeadbeefdeadbeefull,
          "ld8 alias is PERM");
    check(aot_as_ld_locked(as, ALIAS_BASE + 0x2000ull, 2u, &v) ==
                  AOT_MEM_ERR_PERM && v == 0xdeadbeefdeadbeefull,
          "ld16 alias is PERM");
    check(aot_as_ld_locked(as, ALIAS_BASE + 0x3000ull, 4u, &v) ==
                  AOT_MEM_ERR_PERM && v == 0xdeadbeefdeadbeefull,
          "ld32 alias is PERM");
    check(aot_as_ld_locked(as, ALIAS_BASE + 0x4000ull, 8u, &v) ==
                  AOT_MEM_ERR_PERM && v == 0xdeadbeefdeadbeefull,
          "ld64 alias is PERM");
    check(aot_mem_ld128(&mem, ALIAS_BASE + 0x5000ull, pair) ==
                  AOT_MEM_ERR_PERM &&
              pair[0] == 0xdeadbeefdeadbeefull &&
              pair[1] == 0xdeadbeefdeadbeefull,
          "ld128 alias is PERM");
    pair[0] = pair[1] = 0x1122334455667788ull;
    check(aot_mem_st128(&mem, ALIAS_BASE + 0x6000ull, pair) ==
              AOT_MEM_ERR_PERM, "st128 alias is PERM");
    token = aot_mem_domain_attach(dom);
    if (token == 0u) fatal("monitor attach");
    /* STRONG monitor row: positive RW LDXR/SC, then a permission-failing SC
     * must still CONSUME the reservation, so an SC back to the original RW
     * address without a new LDXR reports status 1 (no store). */
    {
        const uint64_t rw = ALIAS_BASE - 0x1000ull;
        check(aot_mem_ldx(&mem, token, rw, 8u, &v) == AOT_MEM_OK &&
                  v == 0u,
              "positive RW LDXR succeeds");
        stx = 9u;
        check(aot_mem_stx(&mem, token, rw, 8u, 0x5a5a5a5a5a5a5a5aull,
                          &stx) == AOT_MEM_OK && stx == 0u,
              "positive RW SC succeeds");
        check(aot_mem_ldx(&mem, token, rw, 8u, &v) == AOT_MEM_OK,
              "positive RW LDXR re-arms the monitor");
        stx = 0u;
        check(aot_mem_stx(&mem, token, ALIAS_BASE + 0x7000ull, 8u,
                          0x1234u, &stx) == AOT_MEM_ERR_PERM &&
                  stx == 1u,
              "SC into denied alias is PERM with exclusive status 1");
        stx = 0u;
        check(aot_mem_stx(&mem, token, rw, 8u, 0x7777u, &stx) ==
                  AOT_MEM_OK && stx == 1u,
              "denied SC consumed the monitor");
        v = 0u;
        check(aot_as_ld_locked(as, rw, 8u, &v) == AOT_MEM_OK &&
                  v == 0x5a5a5a5a5a5a5a5aull,
              "consumed SC did not store");
    }
    check(aot_mem_ldx(&mem, token, ALIAS_BASE + 0x7000ull, 8u, &v) ==
              AOT_MEM_ERR_PERM, "ldxr alias is PERM");
    stx = 0u;
    check(aot_mem_stx(&mem, token, ALIAS_BASE + 0x7000ull, 8u,
                      0x1234u, &stx) == AOT_MEM_ERR_PERM && stx == 1u,
          "failed stxr alias is PERM and reports exclusive failure");
    check(aot_mem_ldar(&mem, ALIAS_BASE + 0x8000ull, 8u, &v) ==
              AOT_MEM_ERR_PERM, "ldar alias is PERM");
    check(aot_mem_stlr(&mem, ALIAS_BASE + 0x8000ull, 8u, 0x55u) ==
              AOT_MEM_ERR_PERM, "stlr alias is PERM");

    /* The STACK arena is the other immutable reserved role: every path is
     * denied before dereference, and the monitor is consumed the same way. */
    memset(buf, 0xaa, sizeof buf);
    check(aot_as_read(as, STACK_BASE, buf, 16u) == AOT_MEM_ERR_PERM &&
              all_bytes(buf, sizeof buf, 0xaa),
          "read stack is PERM with output untouched");
    check(aot_as_write(as, STACK_BASE, buf, 16u) == AOT_MEM_ERR_PERM,
          "write stack is PERM");
    /* Failed loads leave v untouched; reset before the stack row so the
     * expected sentinel does not depend on the earlier strong RW row. */
    v = 0xdeadbeefdeadbeefull;
    check(aot_as_ld_locked(as, STACK_BASE + 0x1000ull, 8u, &v) ==
              AOT_MEM_ERR_PERM && v == 0xdeadbeefdeadbeefull,
          "ld8 stack is PERM");
    check(aot_mem_ldx(&mem, token, STACK_BASE + 0x2000ull, 8u, &v) ==
              AOT_MEM_ERR_PERM, "ldxr stack is PERM");
    stx = 0u;
    check(aot_mem_stx(&mem, token, STACK_BASE + 0x2000ull, 8u,
                      0x1234u, &stx) == AOT_MEM_ERR_PERM && stx == 1u,
          "stxr stack is PERM");
    check(aot_mem_ldar(&mem, STACK_BASE + 0x3000ull, 8u, &v) ==
              AOT_MEM_ERR_PERM, "ldar stack is PERM");
    check(aot_mem_stlr(&mem, STACK_BASE + 0x3000ull, 8u, 0x55u) ==
              AOT_MEM_ERR_PERM, "stlr stack is PERM");
    aot_mem_domain_detach(dom, token);
    check(aot_as_protect(as, STACK_BASE, 0x1000u, AOT_AS_PERM_RW) ==
              AOT_MEM_ERR_PERM, "protect stack is PERM");
    check(aot_as_lock(as, STACK_BASE, 0x1000u) == AOT_MEM_ERR_PERM,
          "lock stack is PERM");

    check(aot_as_read(as, ALIAS_BASE - 8ull, buf, 16u) == AOT_MEM_ERR_RANGE,
          "read straddling region|alias is RANGE");
    check(aot_as_write(as, ALIAS_BASE - 8ull, buf, 16u) == AOT_MEM_ERR_RANGE,
          "write straddling region|alias is RANGE");
    check(aot_as_protect(as, ALIAS_BASE, 0x1000u, AOT_AS_PERM_RW) ==
              AOT_MEM_ERR_PERM, "protect alias is PERM");
    check(aot_as_lock(as, ALIAS_BASE, 0x1000u) == AOT_MEM_ERR_PERM,
          "lock alias is PERM");

    /* Heap grow/shrink leaves the immutable alias geometry and access alone. */
    check(aot_as_set_heap_size(as, 0x200000ull, &b) == AOT_MEM_OK,
          "heap grow");
    check(aot_as_reserved_info(as, ROLE, &b, &n) == AOT_MEM_OK &&
              b == ALIAS_BASE && n == ALIAS_SIZE,
          "alias unchanged by heap grow");
    host_reserve(as, ROLE, ALIAS_BASE,
                 "alias first page still reserve after grow");
    host_reserve(as, ROLE, ALIAS_BASE + ALIAS_SIZE - 0x1000ull,
                 "alias last page still reserve after grow");
    host_reserve(as, STACK_ROLE, STACK_BASE,
                 "stack first page still reserve after grow");
    host_reserve(as, STACK_ROLE, STACK_BASE + STACK_SIZE - 0x1000ull,
                 "stack last page still reserve after grow");
    check(aot_as_set_heap_size(as, 0u, &b) == AOT_MEM_OK, "heap shrink");
    check(aot_as_reserved_info(as, ROLE, &b, &n) == AOT_MEM_OK &&
              b == ALIAS_BASE && n == ALIAS_SIZE,
          "alias unchanged by heap shrink");
    host_reserve(as, ROLE, ALIAS_BASE,
                 "alias first page still reserve after shrink");
    host_reserve(as, ROLE, ALIAS_BASE + ALIAS_SIZE - 0x1000ull,
                 "alias last page still reserve after shrink");
    host_reserve(as, STACK_ROLE, STACK_BASE,
                 "stack first page still reserve after shrink");
    host_reserve(as, STACK_ROLE, STACK_BASE + STACK_SIZE - 0x1000ull,
                 "stack last page still reserve after shrink");
    check(aot_as_read(as, ALIAS_BASE, buf, 1u) == AOT_MEM_ERR_PERM,
          "alias still not guest-readable");

    /* A real ONE-IMAGE Program: a valid image entry resolves positively, while
     * alias and stack arena PCs are UNKNOWN_PC (the zero-image probe alone
     * could not distinguish a lookup that always returns NULL). */
    {
        static const AotCodeRange one_ranges[] = {
            { IMG_BASE, IMG_BASE + IMG_SIZE },
        };
        static const AotBlockEntry one_blocks[] = {
            { IMG_BASE, dummy_block },
        };
        static const AotProgImage one_img = {
            AOT_SUBSET_ID_MODULE, AOT_ABI_VERSION_PROGRAM, AOT_STATE_LAYOUT,
            "sha-alias-one-image", 0, one_blocks, 1, one_ranges, 1
        };
        AotProgram *p = aot_program_create(as);
        if (p == NULL) fatal("program create");
        if (aot_program_add_image(p, &one_img) != AOT_FAULT_NONE ||
            aot_program_set_host_regions(p, THUNK_BASE, 4u, SENTINEL_BASE,
                                         SENTINEL_COUNT) != AOT_FAULT_NONE ||
            aot_program_finalize(p) != AOT_FAULT_NONE)
            fatal("one-image program build");
        check(aot_program_image_at(p, IMG_BASE) == &one_img,
              "valid image entry resolves to the owned image");
        check(aot_program_lookup(p, IMG_BASE) == dummy_block,
              "valid image entry resolves to its block");
        check(aot_program_image_at(p, ALIAS_BASE) == NULL,
              "alias PC is not inside the one image");
        check(aot_program_lookup(p, ALIAS_BASE) == NULL,
              "alias PC has no dispatch block");
        check(aot_program_image_at(p, STACK_BASE) == NULL,
              "stack arena PC is not inside the one image");
        check(aot_program_lookup(p, STACK_BASE) == NULL,
              "stack arena PC has no dispatch block");
        aot_program_destroy(p);

        /* A reserved window must be UNMAPPED for thunk/sentinel slots: both
         * overlap orders/regions fail finalize. */
        p = aot_program_create(as);
        if (p == NULL) fatal("program create alias thunk");
        if (aot_program_add_image(p, &one_img) != AOT_FAULT_NONE ||
            aot_program_set_host_regions(p, ALIAS_BASE, 4u, SENTINEL_BASE,
                                         SENTINEL_COUNT) != AOT_FAULT_NONE)
            fatal("alias thunk setup");
        check(aot_program_finalize(p) == AOT_FAULT_BAD_STATE,
              "thunk region overlapping alias is rejected");
        aot_program_destroy(p);

        p = aot_program_create(as);
        if (p == NULL) fatal("program create stack thunk");
        if (aot_program_add_image(p, &one_img) != AOT_FAULT_NONE ||
            aot_program_set_host_regions(p, STACK_BASE, 4u, SENTINEL_BASE,
                                         SENTINEL_COUNT) != AOT_FAULT_NONE)
            fatal("stack thunk setup");
        check(aot_program_finalize(p) == AOT_FAULT_BAD_STATE,
              "thunk region overlapping stack arena is rejected");
        aot_program_destroy(p);

        p = aot_program_create(as);
        if (p == NULL) fatal("program create alias sentinel");
        if (aot_program_add_image(p, &one_img) != AOT_FAULT_NONE ||
            aot_program_set_host_regions(p, THUNK_BASE, 4u, ALIAS_BASE,
                                         SENTINEL_COUNT) != AOT_FAULT_NONE)
            fatal("alias sentinel setup");
        check(aot_program_finalize(p) == AOT_FAULT_BAD_STATE,
              "sentinel region overlapping alias is rejected");
        aot_program_destroy(p);

        p = aot_program_create(as);
        if (p == NULL) fatal("program create stack sentinel");
        if (aot_program_add_image(p, &one_img) != AOT_FAULT_NONE ||
            aot_program_set_host_regions(p, THUNK_BASE, 4u, STACK_BASE,
                                         SENTINEL_COUNT) != AOT_FAULT_NONE)
            fatal("stack sentinel setup");
        check(aot_program_finalize(p) == AOT_FAULT_BAD_STATE,
              "sentinel region overlapping stack arena is rejected");
        aot_program_destroy(p);
    }

    /* Poisoned sealed space: protect/lock must fail closed and change neither
     * the software ledger nor the host page protection (queries stay readable
     * for diagnostics). */
    {
        const uint64_t rw = ALIAS_BASE - 0x1000ull;
        AotAsQuery qb, qa;
        host_vm_region *pvm = NULL;
        const uint8_t *ppage = NULL;
        size_t poff = 0u;
        host_vm_info hb = {0}, ha = {0};
        check(aot_as_query(as, rw, &qb) == 1 && qb.perm == AOT_AS_PERM_RW &&
                  qb.attr == 0u,
              "pre-poison data page is RW/attr0");
        check(aot_as_host_page(as, rw, &pvm, &ppage, &poff) && pvm != NULL &&
                  ppage != NULL &&
                  host_vm_query(pvm, poff, &hb) == HOST_VM_OK,
              "pre-poison host page witness");
        aot_as_poison(as);
        check(aot_as_protect(as, rw, 0x1000u, AOT_AS_PERM_R) ==
                  AOT_MEM_ERR_RANGE,
              "poisoned sealed protect is RANGE");
        check(aot_as_lock(as, rw, 0x1000u) == AOT_MEM_ERR_RANGE,
              "poisoned sealed lock is RANGE");
        check(aot_as_query(as, rw, &qa) == 1 && qa.perm == qb.perm &&
                  qa.attr == 0u && qa.state == qb.state,
              "poisoned ledger unchanged by refused protect/lock");
        check(aot_as_host_page(as, rw, &pvm, &ppage, &poff) && pvm != NULL &&
                  host_vm_query(pvm, poff, &ha) == HOST_VM_OK &&
                  ha.state == hb.state && ha.protection == hb.protection,
              "poisoned host protection unchanged by refused protect/lock");
    }

    aot_as_destroy(as);
}

int main(void) {
    AotMemDomain *dom = aot_mem_domain_create();
    if (dom == NULL) { printf("FATAL: domain\n"); return 1; }
    geometry();
    access_checks(dom);
    aot_mem_domain_destroy(dom);
    if (g_fail) return 2;
    printf("aot_as_alias_probe: all alias AS checks passed\n");
    return 0;
}
