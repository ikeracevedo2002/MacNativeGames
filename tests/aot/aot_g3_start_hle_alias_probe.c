/* Game-data-free G3 Start MapPhysicalMemory/UnmapPhysicalMemory rows.
 *
 * Mac services.c:283: `case 0x2c: case 0x2d: { uint64_t a = r[0], n = r[1];
 * r[0] = alias_map(num == 0x2d, a, n); ... return r[0]; }`. The HLE handler
 * forwards exactly those two arguments and writes r0 with the Mac Result
 * code, so these rows pin: the exact Result codes, that no other guest
 * register is touched, that the page state really changed (guest read/write,
 * QueryMemory run, OS-level host witness), that GetInfo 7/22 charges the
 * mapped alias bytes, and that every refusal changes nothing.
 *
 * The wrong-implementation controls are separate executables built from this
 * same source with MN_G3_HLE_MUT_* (see tools/aot/g3_mutant_test.py); this
 * probe has to stay green for their rejections to mean anything.
 */
#include "aot_as.h"
#include "g3_start_hle.h"
#include "host_vm.h"

#include <stdio.h>
#include <string.h>

#define ABASE 0x5000000000ull
#define ASIZE 0x40000ull          /* four 16 KiB groups */
#define APG   0x1000ull
#define HBASE 0x4000000000ull
#define HMAX  0x100000000ull
#define HLIMIT 0x4000000ull
#define REC_BASE 0x7000000000ull   /* guest RW record slot */
#define IMG   0x1200000ull
#define POOL  0x8000000ull

static int g_fail;

static void check(int c, const char *m) {
    if (!c) { printf("FAIL: %s\n", m); g_fail++; }
}

static void init_state(AotGuestState *s) {
    unsigned i;
    memset(s, 0, sizeof *s);
    for (i = 0u; i < 31u; i++) s->x[i] = 0x1111000000000000ull + i;
    s->sp = 0x200003fe10ull; s->pc = 0x10201584b4ull;
    s->nzcv = 0x80000000ull; s->fpcr = 0x12345678ull; s->fpsr = 1u;
    s->tpidr = 0x3000000000ull; s->tpidrro = 0x3000002000ull;
    for (i = 0u; i < 32u; i++) {
        s->v[i][0] = 0x3333000000000000ull + i;
        s->v[i][1] = 0x4444000000000000ull + i;
    }
}

/* x0 is the Result and x1/x2 are the live arguments; nothing else may move. */
static int rest_ok(const AotGuestState *s, const AotGuestState *b) {
    unsigned i;
    if (s->sp != b->sp || s->pc != b->pc || s->nzcv != b->nzcv ||
        s->fpcr != b->fpcr || s->fpsr != b->fpsr || s->tpidr != b->tpidr ||
        s->tpidrro != b->tpidrro) return 0;
    if (memcmp(s->v, b->v, sizeof s->v) != 0) return 0;
    for (i = 3u; i < 31u; i++) if (s->x[i] != b->x[i]) return 0;
    return 1;
}

static int args_ok(const AotGuestState *s, const AotGuestState *b) {
    return rest_ok(s, b) && s->x[1] == b->x[1] && s->x[2] == b->x[2];
}

static void run_alias(G3StartHle *ctx, AotGuestState *s, AotRuntime *rt,
                      AotHleRequest *req, uint32_t id) {
    memset(rt, 0, sizeof *rt);
    req->kind = AOT_HLE_SVC;
    req->id = id;
    req->site_pc = 0x10201584b0ull;
    req->resume_pc = 0x10201584b4ull;
    g3_start_hle_svc_alias(rt, s, req, ctx);
}

/* One alias call: 1 iff the expected Result reached r0 and nothing else moved. */
static int expect_result(G3StartHle *ctx, uint64_t addr, uint64_t size,
                         uint32_t id, uint64_t want) {
    AotGuestState s, b;
    AotRuntime rt;
    AotHleRequest req;
    init_state(&s);
    s.x[0] = addr;
    s.x[1] = size;
    s.x[2] = 0x5252525252525252ull;   /* Mac never reads r2 */
    b = s;
    run_alias(ctx, &s, &rt, &req, id);
    return rt.fault == AOT_FAULT_NONE && s.x[0] == want && args_ok(&s, &b);
}

static int expect_alias_fault(G3StartHle *ctx, uint64_t addr, uint64_t size,
                              uint32_t id, int64_t want_status) {
    AotGuestState s, b;
    AotRuntime rt;
    AotHleRequest req;
    init_state(&s);
    s.x[0] = addr;
    s.x[1] = size;
    b = s;
    run_alias(ctx, &s, &rt, &req, id);
    return rt.fault == AOT_FAULT_BAD_HLE && rt.fault_status == want_status &&
           memcmp(&s, &b, sizeof s) == 0;
}

static int expect_getinfo(G3StartHle *ctx, uint64_t id, uint64_t want) {
    AotGuestState s, b;
    AotRuntime rt;
    AotHleRequest req;
    init_state(&s);
    s.x[0] = 0xdeadbeefull;   /* GetInfo never dereferences x0 */
    s.x[1] = id;
    s.x[3] = 0x5353535353535353ull;
    b = s;
    memset(&rt, 0, sizeof rt);
    req.kind = AOT_HLE_SVC;
    req.id = 0x29u;
    req.site_pc = 0x10201584b0ull;
    req.resume_pc = 0x10201584b4ull;
    g3_start_hle_svc(&rt, &s, &req, ctx);
    return rt.fault == AOT_FAULT_NONE && s.x[0] == 0u && s.x[1] == want &&
           s.x[2] == b.x[2] && s.x[3] == b.x[3] && rest_ok(&s, &b);
}

/* OS-level witness of one alias page: real host state and protection. */
static void witness(AotAddressSpace *as, uint64_t addr, int want_page,
                    unsigned want_state, const char *what) {
    host_vm_region *vm = NULL;
    const uint8_t *page = NULL;
    size_t off = 0xdeadbeefu;
    host_vm_info info;
    if (!aot_as_host_page(as, addr, &vm, &page, &off) || vm == NULL ||
        off != (size_t)(addr - ABASE) ||
        host_vm_query(vm, off, &info) != HOST_VM_OK) {
        check(0, what);
        return;
    }
    if (want_page) {
        check(page != NULL && info.state == HOST_VM_STATE_COMMIT &&
                  (info.protection & (HOST_VM_PROT_READ | HOST_VM_PROT_WRITE)) ==
                      (HOST_VM_PROT_READ | HOST_VM_PROT_WRITE),
              what);
    } else {
        check(page == NULL && info.state == want_state && info.protection == 0u,
              what);
    }
}

typedef struct QRec {
    uint64_t base;
    uint64_t size;
    uint32_t state;
    uint32_t attr;
    uint32_t perm;
} QRec;

/* QueryMemory through the SVC and decode the 40-byte little-endian record. */
static int query(AotAddressSpace *as, G3StartHle *ctx, uint64_t addr,
                 QRec *out) {
    AotGuestState s;
    AotRuntime rt;
    AotHleRequest req;
    uint8_t zero[40];
    uint8_t bytes[40];
    memset(zero, 0, sizeof zero);
    memset(bytes, 0, sizeof bytes);
    memset(&rt, 0, sizeof rt);
    init_state(&s);
    s.x[0] = REC_BASE;
    s.x[2] = addr;
    if (aot_as_write(as, s.x[0], zero, sizeof zero) != AOT_MEM_OK) return 0;
    req.kind = AOT_HLE_SVC;
    req.id = 0x06u;
    req.site_pc = 0x10201584b0ull;
    req.resume_pc = 0x10201584b4ull;
    g3_start_hle_svc6(&rt, &s, &req, ctx);
    if (rt.fault != AOT_FAULT_NONE || s.x[0] != 0u || s.x[1] != 0u) return 0;
    if (aot_as_read(as, REC_BASE, bytes, sizeof bytes) != AOT_MEM_OK) return 0;
    memcpy(&out->base, bytes + 0, 8);
    memcpy(&out->size, bytes + 8, 8);
    memcpy(&out->state, bytes + 16, 4);
    memcpy(&out->attr, bytes + 20, 4);
    memcpy(&out->perm, bytes + 24, 4);
    return 1;
}

static AotAddressSpace *make_space(AotMemDomain *dom, int with_alias) {
    AotAddressSpace *as = aot_as_create(dom);
    if (as == NULL) return NULL;
    if (with_alias &&
        aot_as_add_reserved_window(as, ABASE, ASIZE,
                                   AOT_AS_RESERVED_ROLE_ALIAS) != AOT_MEM_OK)
        return NULL;
    if (aot_as_add_region(as, REC_BASE, APG, AOT_AS_PERM_RW, 0xbu, NULL) !=
        AOT_MEM_OK)
        return NULL;
    if (aot_as_add_heap_window(as, HBASE, HMAX, HLIMIT) != AOT_MEM_OK)
        return NULL;
    if (aot_as_seal(as) != AOT_MEM_OK) return NULL;
    return as;
}

int main(void) {
    AotMemDomain *dom = aot_mem_domain_create();
    AotMemDomain *dom2 = aot_mem_domain_create();
    AotMemDomain *dom3 = aot_mem_domain_create();
    AotAddressSpace *as, *alt, *noalias, *poison;
    G3StartHle ctx, alt_ctx, ctx_na, ctx_pz, ctx_nb, ctx_nw;
    G3StartBudget budget = { POOL, IMG };
    G3StartBudget tight = { IMG + 2ull * APG, IMG };
    AotAsQuery q;
    AotAsAliasInfo ai;
    QRec rec;
    uint64_t v = 0u;
    int pattern_ok;
    const uint64_t pattern = 0xfeedfacecafebeefull;

    if (dom == 0 || dom2 == 0 || dom3 == 0) {
        printf("FATAL domain\n");
        return 1;
    }
    as = make_space(dom, 1);
    alt = make_space(dom, 1);
    noalias = make_space(dom2, 0);
    poison = make_space(dom3, 1);
    if (!as || !alt || !noalias || !poison) { printf("FATAL fixture\n"); return 1; }
    aot_as_poison(poison);
    g3_start_hle_init(&ctx, NULL, NULL);
    g3_start_hle_set_address_space(&ctx, as);
    g3_start_hle_set_budget(&ctx, &budget);

    /* ---- Mac Result codes, exact, with every other register preserved ---- */
    check(expect_result(&ctx, ABASE, 0u, 0x2cu,
                        G3_START_HLE_ALIAS_INVALID_ALIGN),
          "zero size is 0xcc01");
    check(expect_result(&ctx, ABASE + 1ull, APG, 0x2cu,
                        G3_START_HLE_ALIAS_INVALID_ALIGN),
          "unaligned address is 0xcc01");
    check(expect_result(&ctx, ABASE, APG + 1ull, 0x2cu,
                        G3_START_HLE_ALIAS_INVALID_ALIGN),
          "unaligned size is 0xcc01");
    check(expect_result(&ctx, ABASE - APG, APG, 0x2cu,
                        G3_START_HLE_ALIAS_INVALID_RANGE),
          "below the alias window is 0xdc01");
    check(expect_result(&ctx, ABASE, ASIZE + APG, 0x2cu,
                        G3_START_HLE_ALIAS_INVALID_RANGE),
          "past the alias window is 0xdc01");
    check(aot_as_alias_info(as, &ai) == AOT_MEM_OK && ai.mapped_pages == 0u &&
              ai.mapped_bytes == 0u,
          "a refused request maps nothing");
    check(expect_getinfo(&ctx, 7u, IMG), "id7 is image-only before any map");
    check(expect_getinfo(&ctx, 22u, IMG), "id22 is image-only before any map");

    /* ---- Map: Result 0, page usable, host really committed ---- */
    check(expect_result(&ctx, ABASE, 2ull * APG, 0x2cu, 0u),
          "map 2 pages returns 0 in r0");
    check(aot_as_alias_info(as, &ai) == AOT_MEM_OK &&
              ai.mapped_pages == 2u && ai.mapped_bytes == 2ull * APG,
          "map raises the mapped-page counter");
    check(expect_getinfo(&ctx, 7u, IMG + 2ull * APG),
          "id7 charges the mapped alias bytes");
    check(expect_getinfo(&ctx, 22u, IMG + 2ull * APG),
          "id22 charges the mapped alias bytes");
    check(aot_as_read(as, ABASE, &v, sizeof v) == AOT_MEM_OK && v == 0u,
          "a freshly mapped alias page reads zero");
    check(aot_as_write(as, ABASE, &pattern, sizeof pattern) == AOT_MEM_OK,
          "a mapped alias page accepts a guest store");
    check(aot_as_read(as, ABASE, &v, sizeof v) == AOT_MEM_OK && v == pattern,
          "a mapped alias page returns the stored bytes");
    check(aot_as_query(as, ABASE, &q) == 1 && q.base == ABASE &&
              q.size == 2ull * APG && q.state == AOT_AS_STATE_HEAP &&
              q.perm == AOT_AS_PERM_RW && q.attr == 0u,
          "mapped pages answer one RW/state-5 run");
    check(query(as, &ctx, ABASE, &rec) == 1 && rec.base == ABASE &&
              rec.size == 2ull * APG && rec.state == AOT_AS_STATE_HEAP &&
              rec.perm == AOT_AS_PERM_RW && rec.attr == 0u,
          "SVC 0x06 reports the mapped alias run");
    witness(as, ABASE, 1, HOST_VM_STATE_RESERVE,
            "a mapped alias page is host COMMIT/RW");

    /* A grow over an owned range keeps the bytes and is not charged twice. */
    check(expect_result(&ctx, ABASE, 4ull * APG, 0x2cu, 0u),
          "grow over an owned prefix succeeds");
    check(aot_as_read(as, ABASE, &v, sizeof v) == AOT_MEM_OK && v == pattern,
          "grow preserves the already-mapped bytes");
    check(expect_getinfo(&ctx, 22u, IMG + 4ull * APG),
          "grow charges only the fresh pages");
    check(aot_as_alias_info(as, &ai) == AOT_MEM_OK && ai.mapped_pages == 4u,
          "grow raises the counter by the fresh pages only");

    /* ---- Pool budget on a second space: LimitReached, never a host fault -- */
    g3_start_hle_init(&alt_ctx, NULL, NULL);
    g3_start_hle_set_address_space(&alt_ctx, alt);
    g3_start_hle_set_budget(&alt_ctx, &tight);
    check(expect_result(&alt_ctx, ABASE, 2ull * APG, 0x2cu, 0u),
          "fresh pages that exactly fit the pool succeed");
    check(expect_result(&alt_ctx, ABASE + 2ull * APG, APG, 0x2cu,
                        G3_START_HLE_ALIAS_LIMIT),
          "a fresh page over the pool is 0x10801");
    check(aot_as_alias_info(alt, &ai) == AOT_MEM_OK && ai.mapped_pages == 2u,
          "a refused map publishes no occupancy");
    check(expect_result(&alt_ctx, ABASE, APG, 0x2du, 0u),
          "unmap is never refused by the pool budget");

    /* ---- Unmap: Result 0, page released, Query Free, access refused ---- */
    check(expect_result(&ctx, ABASE, 2ull * APG, 0x2du, 0u),
          "unmap returns 0 in r0");
    check(aot_as_alias_info(as, &ai) == AOT_MEM_OK && ai.mapped_pages == 2u,
          "unmap reduces the mapped-page counter");
    check(aot_as_read(as, ABASE, &v, sizeof v) == AOT_MEM_ERR_PERM,
          "a released alias page refuses a guest load");
    check(aot_as_query(as, ABASE, &q) == 1 && q.base == ABASE &&
              q.size == 2ull * APG && q.state == 0u &&
              q.perm == AOT_AS_PERM_NONE,
          "released pages answer one Free run");
    check(expect_getinfo(&ctx, 22u, IMG + 2ull * APG),
          "unmap subtracts the released bytes from the budget");
    check(expect_result(&ctx, ABASE, 2ull * APG, 0x2cu, 0u),
          "re-mapping a released range succeeds");
    pattern_ok = aot_as_read(as, ABASE, &v, sizeof v) == AOT_MEM_OK && v == 0u;
    check(pattern_ok, "a re-mapped released page is zero, not the old bytes");
    check(expect_result(&ctx, ABASE, 2ull * APG, 0x2du, 0u),
          "second unmap returns 0");
    check(expect_result(&ctx, ABASE + 8ull * APG, APG, 0x2du, 0u),
          "unmapping a never-mapped page still returns 0");
    check(aot_as_alias_info(as, &ai) == AOT_MEM_OK && ai.mapped_pages == 2u,
          "unmapping an unmapped page releases nothing");

    /* Mac checks the pool on every map request, not only when fresh > 0
     * (services.c:129), and SetHeapSize ignores alias bytes (services.c:311).
     * So a heap grown after the fact can push the total over the pool and a
     * pure re-map of pages the alt space already owns must then be refused. */
    check(aot_as_set_heap_size(alt, 0x200000ull, NULL) == AOT_MEM_OK,
          "grow the alt heap past the alias headroom");
    check(expect_result(&alt_ctx, ABASE, APG, 0x2cu, G3_START_HLE_ALIAS_LIMIT),
          "a re-map over an already-exceeded pool is still 0x10801");
    check(aot_as_alias_info(alt, &ai) == AOT_MEM_OK && ai.mapped_pages == 1u,
          "the refused re-map changed no page");
    check(aot_as_set_heap_size(alt, 0ull, NULL) == AOT_MEM_OK,
          "shrink the alt heap back");

    /* ---- 16 KiB group decommit ---- */
    check(expect_result(&ctx, ABASE + 0x10000ull, 0x4000ull, 0x2cu, 0u),
          "map one whole 16 KiB group");
    check(expect_result(&ctx, ABASE + 0x10000ull, APG, 0x2du, 0u),
          "release one page of the group");
    witness(as, ABASE + 0x10000ull, 0, HOST_VM_STATE_COMMIT,
            "a partly mapped group page stays committed");
    check(expect_result(&ctx, ABASE + 0x11000ull, 0x3000ull, 0x2du, 0u),
          "release the remaining three pages");
    witness(as, ABASE + 0x10000ull, 0, HOST_VM_STATE_RESERVE,
            "a fully released group page is decommitted");
    witness(as, ABASE + 0x13000ull, 0, HOST_VM_STATE_RESERVE,
            "the last page of the released group is decommitted");
    check(aot_as_read(as, ABASE + 0x10000ull, &v, sizeof v) == AOT_MEM_ERR_PERM,
          "a released group page refuses a guest load");

    /* ---- Fail-closed: no AS / poisoned AS / no budget / wrong id ---- */
    g3_start_hle_init(&ctx_na, NULL, NULL);
    g3_start_hle_set_budget(&ctx_na, &budget);
    check(expect_alias_fault(&ctx_na, ABASE, APG, 0x2cu,
                             G3_START_HLE_FAULT_ALIAS_MAP), "missing AS");
    g3_start_hle_init(&ctx_pz, NULL, NULL);
    g3_start_hle_set_address_space(&ctx_pz, poison);
    g3_start_hle_set_budget(&ctx_pz, &budget);
    check(expect_alias_fault(&ctx_pz, ABASE, APG, 0x2du,
                             G3_START_HLE_FAULT_ALIAS_MAP), "poisoned AS");
    g3_start_hle_init(&ctx_nb, NULL, NULL);
    g3_start_hle_set_address_space(&ctx_nb, as);
    check(expect_alias_fault(&ctx_nb, ABASE, APG, 0x2cu,
                             G3_START_HLE_FAULT_ALIAS_MAP), "missing budget");
    check(expect_alias_fault(&ctx, ABASE, APG, 0x2eu, 0x2e),
          "wrong SVC id on the alias handler");
    g3_start_hle_init(&ctx_nw, NULL, NULL);
    g3_start_hle_set_address_space(&ctx_nw, noalias);
    g3_start_hle_set_budget(&ctx_nw, &budget);
    /* A space with no alias window is a lifecycle refusal, not a Mac Result:
     * the Mac code has no such state, so this must be a typed host fault. */
    check(expect_alias_fault(&ctx_nw, ABASE, APG, 0x2cu,
                             G3_START_HLE_FAULT_ALIAS_MAP),
          "a space without an alias window fails closed");

    /* Counter witness for the green paths above. */
    check(ctx.svc2c_calls == 9u && ctx.svc2d_calls == 5u,
          "alias call counters match the rows");
    check(ctx.svc2c_success == 4u && ctx.svc2d_success == 5u,
          "success counters match the rows");
    check(ctx.svc2c_invalid == 5u && ctx.alias_host_failures == 0u,
          "refusal counters match the rows");

    aot_as_destroy(noalias);
    aot_as_destroy(poison);
    aot_as_destroy(alt);
    aot_as_destroy(as);
    aot_mem_domain_destroy(dom3);
    aot_mem_domain_destroy(dom2);
    aot_mem_domain_destroy(dom);
    if (g_fail != 0) {
        printf("FAIL: %d check(s) failed\n", g_fail);
        return 2;
    }
    printf("PASS: g3_start_hle_alias\n");
    return 0;
}
