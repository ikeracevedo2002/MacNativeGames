/*
 * G3 boot-heap address-space contract probe (design: g3-heap-design-reviewed).
 *
 * Drives the REAL public AS interface (src/aot/aot_as.h) plus host_vm_query as
 * the independent OS witness. No game data, no ARM bytes, no translation.
 *
 * Exit protocol (the mutant driver depends on it):
 *   0 = every contract check passed
 *   2 = at least one semantic check failed (prints "FAIL: <check>")
 *   1 = infrastructure failure (prints "FATAL: <reason>")
 *
 * Private compile-time seams (never mutable production state):
 *   MN_AOT_HEAP_FAULT_MODE=1..4  deterministic host-refusal injection.
 *   MN_AOT_HEAP_MUT_*            wrong-implementation controls.
 */
#include "aot_as.h"
#include "aot_mem.h"
#include "host_vm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HBASE 0x4000000000ull       /* 256 GiB, probe-owned boot geometry */
#define MAXSZ 0x800000ull           /* 8 MiB window: small commits only */
#define LIMIT 0xA00000ull           /* 10 MiB > max: cap-alone branch */
#define MODBASE (HBASE - 0x2000ull) /* adjacent ordinary module region */

#ifdef MN_AOT_HEAP_FAULT_MODE
#define FAULT_MODE (MN_AOT_HEAP_FAULT_MODE)
#else
#define FAULT_MODE 0
#endif

static int g_fail;
static uint32_t g_second_token;

static void check(int cond, const char *msg) {
    if (!cond) {
        printf("FAIL: %s\n", msg);
        g_fail = 1;
    }
}

static void fatal(const char *msg) {
    printf("FATAL: %s\n", msg);
    exit(1);
}

/* OS witness for the heap page at guest offset `off`. Returns the queried
 * info; aborts on an infrastructure problem (no host heap page pointer is ever
 * handed out, per the AS contract). */
static host_vm_info heap_os(AotAddressSpace *as, uint64_t off) {
    host_vm_region *vm = NULL;
    const uint8_t *page = (const uint8_t *)(uintptr_t)1;
    size_t vm_off = 0;
    host_vm_info info;
    if (!aot_as_host_page(as, HBASE + off, &vm, &page, &vm_off))
        fatal("heap host_page unmapped");
    if (vm == NULL) fatal("heap host_page vm");
    if (page != NULL) fatal("heap host_page leaked a page pointer");
    if (vm_off != (size_t)off) fatal("heap host_page offset");
    memset(&info, 0, sizeof(info));
    if (host_vm_query(vm, vm_off, &info) != HOST_VM_OK)
        fatal("host_vm_query heap page");
    return info;
}

static void expect_os(AotAddressSpace *as, uint64_t off, unsigned state,
                      unsigned prot, const char *msg) {
    host_vm_info info = heap_os(as, off);
    check(info.state == state && info.protection == prot, msg);
}

static AotAddressSpace *make_space(AotMemDomain *dom) {
    AotAddressSpace *as = aot_as_create(dom);
    if (as == NULL) fatal("address space create");
    return as;
}

static void add_module(AotAddressSpace *as) {
    if (aot_as_add_region(as, MODBASE, 0x2000ull, AOT_AS_PERM_RW,
                          AOT_AS_STATE_DATA, NULL) != AOT_MEM_OK)
        fatal("module region add");
}

#if FAULT_MODE == 0
/* --------------------------------------------------------------- normal -- */

static void geometry_checks(AotMemDomain *dom) {
    AotAddressSpace *a = make_space(dom);
    AotAddressSpace *b;
    AotAsHeapInfo info;
    AotAsQuery q;
    uint64_t out;
    uint8_t buf[16];

    /* Invalid geometry is rejected before any reservation. */
    check(aot_as_add_heap_window(a, HBASE, 0u, LIMIT) == AOT_MEM_ERR_RANGE,
          "heap window rejects zero max");
    check(aot_as_add_heap_window(a, HBASE + 0x100ull, MAXSZ, LIMIT) ==
              AOT_MEM_ERR_RANGE,
          "heap window rejects misaligned base");
    check(aot_as_add_heap_window(a, HBASE, MAXSZ + 0x100ull, LIMIT) ==
              AOT_MEM_ERR_RANGE,
          "heap window rejects misaligned max");
    check(aot_as_add_heap_window(a, 0x1000ull, MAXSZ, LIMIT) ==
              AOT_MEM_ERR_RANGE,
          "heap window rejects base below 4 GiB");
    check(aot_as_add_heap_window(a, AOT_AS_MAX_ADDR - 0x2000ull, 0x4000ull,
                                 LIMIT) == AOT_MEM_ERR_RANGE,
          "heap window rejects end beyond 2^39");

    /* end == 2^39 is VALID when nothing overlaps. */
    check(aot_as_add_heap_window(a, AOT_AS_MAX_ADDR - MAXSZ, MAXSZ, 0u) ==
              AOT_MEM_OK,
          "heap window accepts end == 2^39");
    check(aot_as_add_heap_window(a, AOT_AS_MAX_ADDR - MAXSZ, MAXSZ, 0u) ==
              AOT_MEM_ERR_RANGE,
          "heap window rejects a second window");
    check(aot_as_add_region(a, AOT_AS_MAX_ADDR - MAXSZ + 0x1000ull, 0x1000ull,
                            AOT_AS_PERM_RW, 4u, NULL) == AOT_MEM_ERR_RANGE,
          "region overlapping the heap window is rejected");
    if (aot_as_seal(a) != AOT_MEM_OK) fatal("seal end-valid window");
    check(aot_as_set_heap_size(a, 0x100000ull, &out) == AOT_MEM_ERR_ALIGN,
          "set_heap_size rejects a non-2MiB size");
    check(aot_as_set_heap_size(a, MAXSZ, &out) == AOT_MEM_ERR_ALIGN,
          "set_heap_size rejects a size above commit_limit");
    check(aot_as_add_heap_window(a, 0x3000000000ull, MAXSZ, LIMIT) ==
              AOT_MEM_ERR_RANGE,
          "heap window add after seal is rejected");
    aot_as_destroy(a);

    /* Heap registered first, module added afterwards in BOTH orders. */
    b = make_space(dom);
    if (aot_as_add_heap_window(b, HBASE, MAXSZ, LIMIT) != AOT_MEM_OK)
        fatal("heap window add");
    check(aot_as_add_region(b, MODBASE, 0x2000ull, AOT_AS_PERM_RW, 4u, NULL) ==
              AOT_MEM_OK,
          "module region adjacent to heap is accepted");
    check(aot_as_add_region(b, HBASE - 0x1000ull, 0x2000ull, AOT_AS_PERM_RW,
                            4u, NULL) == AOT_MEM_ERR_RANGE,
          "module overlapping the heap window is rejected");
    {
        uint8_t span[16];
        memset(span, 0x5a, sizeof span);
        check(aot_as_write(b, HBASE - 8ull, span, 16u) ==
                  AOT_MEM_ERR_RANGE,
              "write straddling module|heap is RANGE");
    }
    check(aot_as_heap_info(b, &info) == AOT_MEM_OK && info.base == HBASE &&
              info.max_size == MAXSZ && info.size == 0u,
          "heap_info reports base/max/logical size");

    /* Pre-seal state: reserve-only, no guest access, window claimed. */
    expect_os(b, 0u, HOST_VM_STATE_RESERVE, 0u,
              "pre-seal heap page is host RESERVE/NONE");
    check(aot_as_write(b, HBASE + 0x1000ull, buf, sizeof(buf)) ==
              AOT_MEM_ERR_PERM,
          "pre-seal heap write is ERR_PERM (no host dereference)");
    check(aot_as_read(b, HBASE + 0x1000ull, buf, sizeof(buf)) ==
              AOT_MEM_ERR_PERM,
          "pre-seal heap read is ERR_PERM");
    check(aot_as_range_mapped(b, HBASE + MAXSZ - 16ull, 16u) == 1,
          "range_mapped claims the whole heap window");
    check(aot_as_range_mapped(b, HBASE + MAXSZ, 16u) == 0,
          "range_mapped does not claim bytes past the window");
    check(aot_as_set_heap_size(b, 0u, &out) == AOT_MEM_ERR_RANGE,
          "set_heap_size before seal is rejected");
    aot_as_poison(b);
    check(aot_as_add_heap_window(b, 0x3000000000ull, MAXSZ, LIMIT) ==
              AOT_MEM_ERR_RANGE,
          "poisoned space cannot add a heap window");
    out = 0xdeadbeefdeadbeefull;
    check(aot_as_set_heap_size(b, 0u, &out) == AOT_MEM_ERR_RANGE &&
              out == 0xdeadbeefdeadbeefull,
          "poisoned space rejects SetHeapSize like other lifecycle ops");
    aot_as_destroy(b);

    /* A sealed space with no heap window: invalid request (RANGE), not a
     * host/desync failure. */
    b = make_space(dom);
    add_module(b);
    if (aot_as_seal(b) != AOT_MEM_OK) fatal("seal no-heap space");
    out = 0xdeadbeefdeadbeefull;
    check(aot_as_set_heap_size(b, 0u, &out) == AOT_MEM_ERR_RANGE &&
              out == 0xdeadbeefdeadbeefull,
          "SetHeapSize without a heap window is RANGE");
    aot_as_destroy(b);

    /* 4 GiB window smoke: RESERVE-only, last page host RESERVE, guest Free. */
    b = make_space(dom);
    if (aot_as_add_heap_window(b, HBASE, 0x100000000ull, 0u) != AOT_MEM_OK)
        fatal("4GiB reserve window");
    if (aot_as_seal(b) != AOT_MEM_OK) fatal("seal 4GiB window");
    check(aot_as_heap_info(b, &info) == AOT_MEM_OK &&
              info.max_size == 0x100000000ull && info.size == 0u,
          "4 GiB window reports max 4 GiB and logical 0");
    expect_os(b, 0x100000000ull - 0x1000ull, HOST_VM_STATE_RESERVE, 0u,
              "4 GiB window last page is host RESERVE/NONE");
    check(aot_as_query(b, HBASE, &q) == 1 && q.state == 0u &&
              q.perm == AOT_AS_PERM_NONE && q.size == 0x100000000ull,
          "4 GiB window queries Free 4 GiB without committing it");
    {
        uint8_t byte = 0u;
        check(aot_as_read(b, HBASE, &byte, 1u) == AOT_MEM_ERR_PERM,
              "4 GiB reserve window denies reads");
    }
    aot_as_destroy(b);
}

static void transition_checks(AotMemDomain *dom) {
    AotAddressSpace *as = make_space(dom);
    AotMem mem;
    AotAsHeapInfo info;
    AotAsQuery q;
    uint32_t token;
    uint64_t out = 0xdeadbeefdeadbeefull;
    uint64_t v = 0;
    uint32_t stx = 1u;
    uint8_t zero[8];
    uint8_t pat[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};

    add_module(as);
    if (aot_as_add_heap_window(as, HBASE, MAXSZ, LIMIT) != AOT_MEM_OK)
        fatal("heap window add");
    if (aot_as_seal(as) != AOT_MEM_OK) fatal("seal");
    if (aot_mem_init_aspace(&mem, as) != AOT_MEM_OK) fatal("aspace mem init");
    if (aot_as_heap_info(as, &info) != AOT_MEM_OK)
        fatal("heap_info after seal");
    check(info.max_size == MAXSZ, "heap_info max after seal");
    check(info.size == 0u, "heap starts with logical size 0");
    check(aot_as_query(as, HBASE, &q) == 1 && q.state == 0u &&
              q.perm == AOT_AS_PERM_NONE && q.base == HBASE &&
              q.size == MAXSZ,
          "sealed heap window is truthfully Free/NONE with no invented state");

    /* protect/lock never touch the heap window, whole or mixed spans. */
    check(aot_as_protect(as, HBASE, 0x2000ull, AOT_AS_PERM_RW) ==
              AOT_MEM_ERR_PERM,
          "protect rejects a heap span");
    check(aot_as_protect(as, MODBASE, 0x2000ull, AOT_AS_PERM_RW) ==
              AOT_MEM_OK,
          "protect on the adjacent module still works");
    check(aot_as_protect(as, HBASE - 0x1000ull, 0x2000ull, AOT_AS_PERM_R) ==
              AOT_MEM_ERR_RANGE,
          "protect rejects a mixed module/heap span");
    check(aot_as_lock(as, HBASE, 0x1000ull) == AOT_MEM_ERR_PERM,
          "lock rejects a heap span");

    /* Invalid request: typed, no output, no mutation. */
    check(aot_as_set_heap_size(as, 0x100000ull, &out) == AOT_MEM_ERR_ALIGN &&
              out == 0xdeadbeefdeadbeefull,
          "invalid size is ALIGN and writes no base");
    check(aot_as_set_heap_size(as, 0u, &out) == AOT_MEM_OK && out == HBASE,
          "zero size succeeds and writes the heap base");

    /* Grow 2 MiB: fresh pages zero, guest RW/5, host COMMIT/RW. */
    out = 0xdeadbeefdeadbeefull;
    check(aot_as_set_heap_size(as, 0x200000ull, &out) == AOT_MEM_OK &&
              out == HBASE,
          "grow to 2 MiB succeeds and writes the base");
    memset(zero, 0xff, sizeof(zero));
    check(aot_as_read(as, HBASE + 0x1000ull, zero, 8u) == AOT_MEM_OK &&
              memcmp(zero, "\0\0\0\0\0\0\0\0", 8u) == 0,
          "fresh heap pages are zero");
    expect_os(as, 0u, HOST_VM_STATE_COMMIT, HOST_VM_PROT_READ | HOST_VM_PROT_WRITE,
              "grown heap page is host COMMIT/RW");
    check(aot_as_query(as, HBASE + 0x1000ull, &q) == 1 &&
              q.state == AOT_AS_STATE_HEAP && q.perm == AOT_AS_PERM_RW &&
              q.base == HBASE && q.size == 0x200000ull,
          "query reports the heap block as state 5/RW");
    check(aot_as_write(as, HBASE + 0x1000ull, pat, 8u) == AOT_MEM_OK,
          "guest can write a committed heap page");

    /* Boundary straddle [size-8, size+8): hw == size, tail is RESERVE.
     * Must fail before touching any host page (no AV) and leave outputs and
     * committed bytes unchanged. */
    {
        uint8_t guard[16];
        uint8_t strad[16];
        uint64_t ld128[2] = {0xdeadbeefdeadbeefull, 0xdeadbeefdeadbeefull};
        memset(guard, 0xaa, sizeof guard);
        memset(strad, 0x55, sizeof strad);
        check(aot_as_write(as, HBASE + 0x1ff000ull, pat, 8u) == AOT_MEM_OK,
              "write a marker in the last committed page");
        check(aot_as_read(as, HBASE + 0x200000ull - 8ull, guard, 16u) ==
                  AOT_MEM_ERR_PERM &&
                  guard[0] == 0xaa && guard[15] == 0xaa,
              "read straddling committed/reserved heap is PERM, untouched");
        check(aot_as_write(as, HBASE + 0x200000ull - 8ull, strad, 16u) ==
                  AOT_MEM_ERR_PERM,
              "write straddling committed/reserved heap is PERM");
        check(aot_as_read(as, HBASE + 0x1ff000ull, zero, 8u) == AOT_MEM_OK &&
                  memcmp(zero, pat, 8u) == 0,
              "straddling write changed no committed bytes");
        check(aot_mem_ld128(&mem, HBASE + 0x200000ull - 8ull, ld128) ==
                  AOT_MEM_ERR_PERM &&
                  ld128[0] == 0xdeadbeefdeadbeefull &&
                  ld128[1] == 0xdeadbeefdeadbeefull,
              "LD128 straddling committed/reserved heap is PERM");
    }

    /* Exclusive-monitor invalidation across a successful shrink/regrow.
     * TWO other tokens are armed so the claim is not single-token vacuous. */
    token = aot_mem_domain_attach(dom);
    if (token == 0u) fatal("monitor attach");
    g_second_token = aot_mem_domain_attach(dom);
    if (g_second_token == 0u) fatal("second monitor attach");
    if (aot_mem_st64(&mem, HBASE + 0x1000ull, 0xaaaabbbbccccddddu) !=
        AOT_MEM_OK)
        fatal("st64 heap");
    check(aot_mem_ldx(&mem, token, HBASE + 0x1000ull, 8u, &v) == AOT_MEM_OK,
          "LDXR arms on the heap");
    check(aot_mem_stx(&mem, token, HBASE + 0x1000ull, 8u, v, &stx) ==
                  AOT_MEM_OK &&
              stx == 0u,
          "control: STXR succeeds without a resize");
    check(aot_mem_ldx(&mem, token, HBASE + 0x1000ull, 8u, &v) == AOT_MEM_OK,
          "LDXR arms before shrink");
    check(aot_mem_ldx(&mem, g_second_token, HBASE + 0x1000ull, 8u, &v) ==
              AOT_MEM_OK,
          "second token LDXR arms before shrink");
    check(aot_as_set_heap_size(as, 0u, &out) == AOT_MEM_OK,
          "shrink to 0 succeeds");
    check(aot_as_set_heap_size(as, 0x200000ull, &out) == AOT_MEM_OK,
          "regrow to 2 MiB succeeds");
    stx = 1u;
    check(aot_mem_stx(&mem, token, HBASE + 0x1000ull, 8u, 0x1111111111111111ull,
                      &stx) == AOT_MEM_OK &&
              stx != 0u,
          "successful shrink/regrow invalidates another token reservation");
    stx = 1u;
    check(aot_mem_stx(&mem, g_second_token, HBASE + 0x1000ull, 8u,
                      0x2222222222222222ull, &stx) == AOT_MEM_OK &&
              stx != 0u,
          "both other-token reservations are invalidated");
    check(aot_mem_ld64(&mem, HBASE + 0x1000ull, &v) == AOT_MEM_OK &&
              v == 0xaaaabbbbccccddddu,
          "regrown retained bytes are unchanged");
    aot_mem_domain_detach(dom, g_second_token);
    aot_mem_domain_detach(dom, token);
    check(aot_as_write(as, HBASE + 0x1000ull, pat, 8u) == AOT_MEM_OK,
          "rewrite pattern after monitor test");

    /* Grow 4 MiB, write the new block, shrink, regrow: bytes preserved. */
    check(aot_as_set_heap_size(as, 0x400000ull, &out) == AOT_MEM_OK,
          "grow over retained pages to 4 MiB succeeds");
    check(aot_as_read(as, HBASE + 0x1000ull, zero, 8u) == AOT_MEM_OK &&
              memcmp(zero, pat, 8u) == 0,
          "growing retained pages preserves their bytes");
    check(aot_as_read(as, HBASE + 0x300000ull, zero, 8u) == AOT_MEM_OK &&
              memcmp(zero, "\0\0\0\0\0\0\0\0", 8u) == 0,
          "newly committed growth pages are zero");
    if (aot_as_write(as, HBASE + 0x300000ull, pat, 8u) != AOT_MEM_OK)
        check(0, "write new growth page");

    /* Shrink keeps host bytes committed with NONE (Mac mprotect semantics). */
    check(aot_as_set_heap_size(as, 0x200000ull, &out) == AOT_MEM_OK,
          "shrink to 2 MiB succeeds");
    expect_os(as, 0x200000ull, HOST_VM_STATE_COMMIT, HOST_VM_PROT_NONE,
              "shrink keeps host pages COMMIT/NONE (no decommit)");
    check(aot_as_query(as, HBASE + 0x200000ull, &q) == 1 && q.state == 0u &&
              q.perm == AOT_AS_PERM_NONE && q.base == HBASE + 0x200000ull &&
              q.size == MAXSZ - 0x200000ull,
          "shrunk heap tail is truthfully Free/NONE and clipped");
    check(aot_as_write(as, HBASE + 0x200000ull, pat, 8u) == AOT_MEM_ERR_PERM,
          "shrink denies guest writes to the removed bytes");
    check(aot_as_set_heap_size(as, 0x400000ull, &out) == AOT_MEM_OK,
          "regrow to 4 MiB re-protects retained pages");
    check(aot_as_read(as, HBASE + 0x300000ull, zero, 8u) == AOT_MEM_OK &&
              memcmp(zero, pat, 8u) == 0,
          "regrow preserves the shrunk block's bytes");

    /* Logical size, not high-water, drives the commit budget checks. With
     * commit_limit > max, the window cap alone must reject max+2 MiB. */
    check(aot_as_set_heap_size(as, 0u, &out) == AOT_MEM_OK, "shrink to 0");
    check(aot_as_set_heap_size(as, MAXSZ, &out) == AOT_MEM_OK,
          "grow to the window maximum succeeds");
    check(aot_as_set_heap_size(as, MAXSZ, &out) == AOT_MEM_OK && out == HBASE,
          "same-size request is a successful no-op");
    out = 0xdeadbeefdeadbeefull;
    check(aot_as_set_heap_size(as, MAXSZ + 0x200000ull, &out) ==
                  AOT_MEM_ERR_ALIGN &&
              out == 0xdeadbeefdeadbeefull,
          "aligned max+2MiB is rejected by the window cap");
    check(aot_as_heap_info(as, &info) == AOT_MEM_OK && info.size == MAXSZ &&
              info.max_size == MAXSZ,
          "cap rejection leaves the old heap map unchanged");

    aot_as_destroy(as);
}

int main(void) {
    AotMemDomain *dom = aot_mem_domain_create();
    if (dom == NULL) fatal("domain create");
    geometry_checks(dom);
    transition_checks(dom);
    aot_mem_domain_destroy(dom);
    if (g_fail) return 2;
    printf("aot_as_heap_probe: all heap AS checks passed\n");
    return 0;
}

#else /* FAULT_MODE != 0 */
/* --------------------------------------------------- failure injection -- */

static void fault_checks(AotMemDomain *dom) {
    AotAddressSpace *as = make_space(dom);
    AotAsHeapInfo info;
    uint64_t out = 0xdeadbeefdeadbeefull;

    if (aot_as_add_heap_window(as, HBASE, MAXSZ, LIMIT) != AOT_MEM_OK)
        fatal("heap window add");
    if (aot_as_seal(as) != AOT_MEM_OK) fatal("seal");

#if FAULT_MODE == 1
    /* Fresh commit fails: guest map, OS state and output unchanged. */
    check(aot_as_set_heap_size(as, 0x200000ull, &out) == AOT_MEM_ERR_HOST,
          "injected fresh-commit failure is ERR_HOST");
    check(out == 0xdeadbeefdeadbeefull,
          "failed grow writes no base output");
    check(aot_as_heap_info(as, &info) == AOT_MEM_OK && info.size == 0u,
          "failed fresh commit leaves logical size unchanged");
    expect_os(as, 0u, HOST_VM_STATE_RESERVE, 0u,
              "failed fresh commit leaves the host page RESERVE");
#elif FAULT_MODE == 2 || FAULT_MODE == 3
    /* Grow, shrink, then grow over retained pages with the retained-protect
     * failure injected after a successful fresh commit. */
    uint8_t pat[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t back[8];
    check(aot_as_set_heap_size(as, 0x400000ull, &out) == AOT_MEM_OK,
          "setup grow to 4 MiB succeeds");
    if (aot_as_write(as, HBASE + 0x200000ull, pat, 8u) != AOT_MEM_OK)
        fatal("write retained pattern");
    check(aot_as_set_heap_size(as, 0x200000ull, &out) == AOT_MEM_OK,
          "setup shrink to 2 MiB succeeds");
    out = 0xdeadbeefdeadbeefull;
    check(aot_as_set_heap_size(as, 0x600000ull, &out) == AOT_MEM_ERR_HOST,
          "injected retained-protect failure is ERR_HOST");
    check(out == 0xdeadbeefdeadbeefull,
          "failed retained protect writes no base output");
    check(aot_as_heap_info(as, &info) == AOT_MEM_OK && info.size == 0x200000ull,
          "failed retained protect leaves the logical size unchanged");
#if FAULT_MODE == 3
    /* The injected decommit rollback ALSO fails, so the fresh pages remain
     * committed while the guest map stays NONE: sticky fail-closed. */
    expect_os(as, 0x400000ull, HOST_VM_STATE_COMMIT,
              HOST_VM_PROT_READ | HOST_VM_PROT_WRITE,
              "unrolled-back fresh pages stay committed but unpublished");
    check(aot_as_read(as, HBASE + 0x400000ull, back, 8u) == AOT_MEM_ERR_PERM,
          "unpublished fresh bytes are not guest-readable");
#else
    expect_os(as, 0x400000ull, HOST_VM_STATE_RESERVE, 0u,
              "failed retained protect rolls the fresh commit back");
#endif
    expect_os(as, 0x200000ull, HOST_VM_STATE_COMMIT, HOST_VM_PROT_NONE,
              "failed retained protect leaves the retained pages NONE");
#if FAULT_MODE == 3
    /* Rollback itself failed: sticky fail-closed for every later request. */
    check(aot_as_set_heap_size(as, 0x200000ull, &out) == AOT_MEM_ERR_HOST,
          "rollback failure is sticky fail-closed");
    check(aot_as_set_heap_size(as, 0u, &out) == AOT_MEM_ERR_HOST,
          "sticky failure also refuses shrink");
#else
    check(aot_as_set_heap_size(as, 4u * 0x100000ull, &out) == AOT_MEM_OK,
          "recovered rollback does not poison later requests");
    check(aot_as_read(as, HBASE + 0x200000ull, back, 8u) == AOT_MEM_OK &&
              memcmp(back, pat, 8u) == 0,
          "retained bytes reread stable after the recovered failure");
    check(aot_as_set_heap_size(as, 2u * 0x100000ull, &out) == AOT_MEM_OK,
          "shrink back to the retained logical size succeeds");
#endif
#else /* FAULT_MODE == 4 */
    /* Shrink protect-to-NONE fails: old map, bytes and reservation unchanged,
     * and an exclusive reservation on those bytes stays valid. */
    AotMem mem;
    uint64_t v = 0;
    uint32_t stx = 1u;
    uint32_t token = 0u;
    uint8_t pat[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t back[8];
    check(aot_as_set_heap_size(as, 0x400000ull, &out) == AOT_MEM_OK,
          "setup grow to 4 MiB succeeds");
    if (aot_as_write(as, HBASE + 0x1000ull, pat, 8u) != AOT_MEM_OK)
        fatal("write pattern");
    token = aot_mem_domain_attach(dom);
    if (token == 0u) fatal("monitor attach");
    if (aot_mem_init_aspace(&mem, as) != AOT_MEM_OK) fatal("aspace mem init");
    check(aot_mem_ldx(&mem, token, HBASE + 0x1000ull, 8u, &v) == AOT_MEM_OK,
          "LDXR arms BEFORE the failed shrink");
    out = 0xdeadbeefdeadbeefull;
    check(aot_as_set_heap_size(as, 0x200000ull, &out) == AOT_MEM_ERR_HOST,
          "injected shrink-protect failure is ERR_HOST");
    check(out == 0xdeadbeefdeadbeefull,
          "failed shrink writes no base output");
    check(aot_as_heap_info(as, &info) == AOT_MEM_OK && info.size == 0x400000ull,
          "failed shrink leaves logical size unchanged");
    expect_os(as, 0x200000ull, HOST_VM_STATE_COMMIT,
              HOST_VM_PROT_READ | HOST_VM_PROT_WRITE,
              "failed shrink leaves host protection RW");
    check(aot_as_read(as, HBASE + 0x1000ull, back, 8u) == AOT_MEM_OK &&
              memcmp(back, pat, 8u) == 0,
          "failed shrink leaves bytes readable");
    check(aot_mem_stx(&mem, token, HBASE + 0x1000ull, 8u,
                      0x3333333333333333ull, &stx) == AOT_MEM_OK &&
              stx == 0u,
          "STXR succeeds 0 after the failed shrink (pre-armed token)");
    aot_mem_domain_detach(dom, token);
#endif
    aot_as_destroy(as);
}

int main(void) {
    AotMemDomain *dom = aot_mem_domain_create();
    if (dom == NULL) fatal("domain create");
    fault_checks(dom);
    aot_mem_domain_destroy(dom);
    if (g_fail) return 2;
    printf("aot_as_heap_probe: all heap AS checks passed\n");
    return 0;
}
#endif
