/*
 * Game-data-free rows for the minimal G3 Start SVC 0x06 (QueryMemory) HLE.
 *
 * Proves the whole data-address-space query against the REAL address space:
 *   - 40 little-endian bytes {u64 base,size; u32 state,attr,perm,ipc,device,
 *     pad} from aot_as_query_domain, never a host cast of a guest VA;
 *   - r0 NULL skips the copy, r1 is never dereferenced;
 *   - success is exactly r0=0/r1=0 with every other register unchanged;
 *   - holes are Free and the upper non-address-space extent is Inaccessible,
 *     never the Mac state-3/perm-5 fallback;
 *   - a read-only or cross-NONE output span is AOT_FAULT_MEMORY with the
 *     guest output pointer in fault_target and no partial byte write;
 *   - two AS geometries and locked/data/text/heap/alias/stack states are read
 *     from the AS, not from constants.
 * Deliberately wrong handlers (field swap, constant state, partial write,
 * page-info dereference) must be rejected by the same expectations.
 *
 * Exit: 0 all rows passed, 1 infrastructure, 2 semantic failure.
 */
#include "aot_as.h"
#include "g3_start_hle.h"

#include <stdio.h>
#include <string.h>

#define QBASE 0x2000000000ull      /* current main stack (state 0xb) */
#define QSIZE 0x40000ull
#define TXT_BASE 0x2100000000ull   /* module text: state 3, R|X */
#define TXT_SIZE 0x1000ull
#define DATA_BASE 0x2200000000ull  /* data: state 4, RW, second page locked */
#define DATA_SIZE 0x2000ull
#define HEAP_BASE 0x4000000000ull
#define HEAP_MAX 0x100000000ull
#define HEAP_LIMIT 0x600000ull
#define ALIAS_BASE 0x5000000000ull
#define ALIAS_SIZE 0x200000000ull
#define ARENA_BASE 0x2800000000ull
#define ARENA_SIZE 0x10000000ull
#define AS2_BASE 0x2400000000ull
#define AS2_SIZE 0x80000ull
#define OUT_PTR (QBASE + 0x1000ull)
#define X1_PTR (QBASE + 0x2000ull)
#define CANARY 0x5au
#define X1_CANARY 0x3cu

static int g_fail;
static int g_infra;
static int setup_failure(void) {
    printf("FATAL: query fixture canary/copy setup\n");
    g_infra = 1;
    return 0;
}
/* Positive baseline uses the real handler; negative controls point this at a
 * deliberately wrong handler with the same call shape. */
static AotProgHandler g_query_fn;

static void check(int cond, const char *msg) {
    if (!cond) {
        printf("FAIL: %s\n", msg);
        g_fail = 1;
    }
}

static int provider_zero(uint64_t *out, void *user) {
    (void)user;
    *out = 0u;
    return 0;
}

static void init_state(AotGuestState *s) {
    unsigned i;
    memset(s, 0, sizeof *s);
    for (i = 0u; i < 31u; i++) s->x[i] = 0x1111000000000000ull + i;
    s->sp = QBASE + QSIZE - 0x10ull;
    s->pc = 0x10201584b4ull;
    s->nzcv = 0x80000000ull;
    s->fpcr = 0x12345678ull;
    s->fpsr = 1u;
    s->tpidr = 0x3000000000ull;
    s->tpidrro = 0x3000002000ull;
    for (i = 0u; i < 32u; i++) {
        s->v[i][0] = 0x3333000000000000ull + i;
        s->v[i][1] = 0x4444000000000000ull + i;
    }
}

static void run(AotProgHandler fn, G3StartHle *ctx, uint32_t id,
                AotGuestState *s, AotRuntime *rt, AotHleRequest *req) {
    memset(rt, 0, sizeof *rt);
    req->kind = AOT_HLE_SVC;
    req->id = id;
    req->site_pc = 0x1030158318ull;
    req->resume_pc = 0x103015831cull;
    fn(rt, s, req, ctx);
}

static int rest_unchanged(const AotGuestState *s, const AotGuestState *b) {
    unsigned i;
    if (s->sp != b->sp || s->pc != b->pc || s->nzcv != b->nzcv ||
        s->fpcr != b->fpcr || s->fpsr != b->fpsr || s->tpidr != b->tpidr ||
        s->tpidrro != b->tpidrro)
        return 0;
    if (memcmp(s->v, b->v, sizeof s->v) != 0) return 0;
    for (i = 2u; i < 31u; i++)
        if (s->x[i] != b->x[i]) return 0;
    return 1;
}

static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint64_t rd64(const uint8_t *p) {
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

static int fill_bytes(AotAddressSpace *as, uint64_t addr, uint8_t value,
                      uint64_t n) {
    uint8_t buf[64];
    uint64_t i;
    if (n > sizeof buf) return 0;
    for (i = 0u; i < n; i++) buf[i] = value;
    return aot_as_write(as, addr, buf, n) == AOT_MEM_OK;
}

static int has_bytes(AotAddressSpace *as, uint64_t addr, uint8_t value,
                     uint64_t n) {
    uint8_t buf[64];
    uint64_t i;
    if (n > sizeof buf) return 0;
    if (aot_as_read(as, addr, buf, n) != AOT_MEM_OK) return 0;
    for (i = 0u; i < n; i++)
        if (buf[i] != value) return 0;
    return 1;
}

/*
 * Positive baseline. Returns 1 only when the full mapped-query contract and
 * the expected AS-derived record hold. `x1_canary` != 0 additionally requires
 * that a writable guest address placed in r1 is byte-unchanged.
 */
static int expect_ok(AotAddressSpace *as, G3StartHle *ctx, uint64_t qaddr,
                     uint64_t out_ptr, uint64_t x1, uint64_t x1_canary,
                     uint64_t exp_base, uint64_t exp_size, uint32_t exp_state,
                     uint32_t exp_attr, uint32_t exp_perm) {
    AotGuestState s, b;
    AotRuntime rt;
    AotHleRequest req;
    uint8_t rec[40];
    unsigned before_success;
    int ok;

    init_state(&s);
    s.x[0] = out_ptr;
    s.x[1] = x1;
    s.x[2] = qaddr;
    s.x[3] = 0x10000u;
    if (out_ptr != 0u) {
        if (!fill_bytes(as, out_ptr - 8u, CANARY, 8u) ||
            !fill_bytes(as, out_ptr + 40u, CANARY, 8u))
            return setup_failure();
    }
    if (x1_canary != 0u && !fill_bytes(as, x1_canary, X1_CANARY, 16u))
        return setup_failure();
    b = s;
    before_success = ctx->svc6_success;
    run(g_query_fn, ctx, 0x06u, &s, &rt, &req);
    ok = rt.fault == AOT_FAULT_NONE && s.x[0] == 0u && s.x[1] == 0u &&
         rest_unchanged(&s, &b) && ctx->svc6_success == before_success + 1u;
    if (!ok) return 0;
    if (x1_canary != 0u && !has_bytes(as, x1_canary, X1_CANARY, 16u))
        return 0;
    if (out_ptr == 0u) return 1;
    if (!has_bytes(as, out_ptr - 8u, CANARY, 8u) ||
        !has_bytes(as, out_ptr + 40u, CANARY, 8u))
        return 0;
    if (aot_as_read(as, out_ptr, rec, sizeof rec) != AOT_MEM_OK)
        return setup_failure();
    return rd64(rec + 0) == exp_base && rd64(rec + 8) == exp_size &&
           rd32(rec + 16) == exp_state && rd32(rec + 20) == exp_attr &&
           rd32(rec + 24) == exp_perm && rd32(rec + 28) == 0u &&
           rd32(rec + 32) == 0u && rd32(rec + 36) == 0u;
}

static int expect_write_fault(AotAddressSpace *as, G3StartHle *ctx,
                              uint64_t qaddr, uint64_t out_ptr,
                              int64_t exp_status, uint64_t keep_addr,
                              uint64_t keep_n) {
    AotGuestState s, b;
    AotRuntime rt;
    AotHleRequest req;
    unsigned before_faults;
    uint8_t keep[64];

    if (keep_n > sizeof keep) return 0;
    if (keep_n != 0u &&
        aot_as_read(as, keep_addr, keep, keep_n) != AOT_MEM_OK)
        return 0;
    init_state(&s);
    s.x[0] = out_ptr;
    s.x[1] = 0xdeadbeefdeadbeefull;
    s.x[2] = qaddr;
    s.x[3] = 0x10000u;
    b = s;
    before_faults = ctx->svc6_write_faults;
    run(g3_start_hle_svc6, ctx, 0x06u, &s, &rt, &req);
    if (rt.fault != AOT_FAULT_MEMORY || rt.fault_src != req.site_pc ||
        rt.fault_target != out_ptr || rt.fault_status != exp_status ||
        memcmp(&s, &b, sizeof s) != 0 ||
        ctx->svc6_write_faults != before_faults + 1u)
        return 0;
    if (keep_n != 0u) {
        uint8_t back[64];
        if (aot_as_read(as, keep_addr, back, keep_n) != AOT_MEM_OK ||
            memcmp(back, keep, (size_t)keep_n) != 0)
            return 0;
    }
    return 1;
}

/* Deliberately wrong handlers; each is rejected by the baseline above. */
static void mut_wrong_field(AotRuntime *rt, AotGuestState *s,
                            const AotHleRequest *req, void *user) {
    G3StartHle *ctx = (G3StartHle *)user;
    uint64_t out = s->x[0];
    uint8_t v[4] = { 0u, 0u, 0u, 0u };
    g3_start_hle_svc6(rt, s, req, user);
    if (rt->fault == AOT_FAULT_NONE && out != 0u)
        (void)aot_as_write(ctx->as, out + 16u, v, 4u); /* state=0 */
}

static void mut_state_const(AotRuntime *rt, AotGuestState *s,
                            const AotHleRequest *req, void *user) {
    G3StartHle *ctx = (G3StartHle *)user;
    uint64_t out = s->x[0];
    uint8_t v[4] = { (uint8_t)AOT_AS_STATE_TEXT, 0u, 0u, 0u };
    g3_start_hle_svc6(rt, s, req, user);
    if (rt->fault == AOT_FAULT_NONE && out != 0u)
        (void)aot_as_write(ctx->as, out + 16u, v, 4u);
}

static void mut_corrupt_tail(AotRuntime *rt, AotGuestState *s,
                              const AotHleRequest *req, void *user) {
    G3StartHle *ctx = (G3StartHle *)user;
    uint64_t out = s->x[0];
    g3_start_hle_svc6(rt, s, req, user);
    if (rt->fault == AOT_FAULT_NONE && out != 0u)
        (void)fill_bytes(ctx->as, out + 8u, CANARY, 32u);
}

static void mut_pageinfo_deref(AotRuntime *rt, AotGuestState *s,
                               const AotHleRequest *req, void *user) {
    G3StartHle *ctx = (G3StartHle *)user;
    uint64_t x1 = s->x[1];
    g3_start_hle_svc6(rt, s, req, user);
    if (rt->fault == AOT_FAULT_NONE && x1 != 0u)
        (void)fill_bytes(ctx->as, x1, 0u, 16u);
}

static void expect_host_failure(G3StartHle *ctx, uint64_t qaddr,
                                const char *msg) {
    AotGuestState s, b;
    AotRuntime rt;
    AotHleRequest req;

    init_state(&s);
    s.x[0] = OUT_PTR;
    s.x[1] = 0xdeadbeefdeadbeefull;
    s.x[2] = qaddr;
    s.x[3] = 0x10000u;
    b = s;
    run(g3_start_hle_svc6, ctx, 0x06u, &s, &rt, &req);
    check(rt.fault == AOT_FAULT_BAD_HLE &&
              rt.fault_status == G3_START_HLE_FAULT_QUERY &&
              memcmp(&s, &b, sizeof s) == 0,
          msg);
}

int main(void) {
    AotMemDomain *dom = aot_mem_domain_create();
    AotAddressSpace *as;
    AotAddressSpace *as2;
    G3StartHle ctx;
    G3StartHle ctx2;
    G3StartHle ctx_m;
    G3StartHle ctx_bad;
    uint64_t base = 0u;

    if (dom == 0) { printf("FATAL: domain\n"); return 1; }
    as = aot_as_create(dom);
    if (as == 0) { printf("FATAL: as\n"); return 1; }
    if (aot_as_add_region(as, QBASE, QSIZE, AOT_AS_PERM_RW, 0xbu, NULL) !=
            AOT_MEM_OK ||
        aot_as_add_region(as, TXT_BASE, TXT_SIZE, AOT_AS_PERM_RX,
                          AOT_AS_STATE_TEXT, NULL) != AOT_MEM_OK ||
        aot_as_add_region(as, DATA_BASE, DATA_SIZE, AOT_AS_PERM_RW,
                          AOT_AS_STATE_DATA, NULL) != AOT_MEM_OK) {
        printf("FATAL: region add\n");
        return 1;
    }
    if (aot_as_add_heap_window(as, HEAP_BASE, HEAP_MAX, HEAP_LIMIT) !=
            AOT_MEM_OK ||
        aot_as_add_reserved_window(as, ALIAS_BASE, ALIAS_SIZE,
                                   AOT_AS_RESERVED_ROLE_ALIAS) != AOT_MEM_OK ||
        aot_as_add_reserved_window(as, ARENA_BASE, ARENA_SIZE,
                                   AOT_AS_RESERVED_ROLE_STACK) != AOT_MEM_OK) {
        printf("FATAL: window add\n");
        return 1;
    }
    if (aot_as_seal(as) != AOT_MEM_OK) { printf("FATAL: seal\n"); return 1; }
    if (aot_as_lock(as, DATA_BASE + 0x1000ull, 0x1000ull) != AOT_MEM_OK) {
        printf("FATAL: lock\n");
        return 1;
    }
    g3_start_hle_init(&ctx, provider_zero, NULL);
    g3_start_hle_set_address_space(&ctx, as);
    g_query_fn = g3_start_hle_svc6;

    /* Current main stack: the actual SP inside the 0x40000 region. */
    check(expect_ok(as, &ctx, QBASE + 0x3fe60ull, OUT_PTR,
                    0xdeadbeefdeadbeefull, 0u, QBASE, QSIZE, 0xbu, 0u, 3u),
          "SP query reports base/size/state 11/attr 0/perm 3 from the AS");
    check(expect_ok(as, &ctx, QBASE + 0x3fe60ull, 0u,
                    0xdeadbeefdeadbeefull, 0u, 0u, 0u, 0u, 0u, 0u),
          "r0 NULL skips the copy and still succeeds");
    check(expect_ok(as, &ctx, TXT_BASE + 0x40ull, OUT_PTR,
                    0xdeadbeefdeadbeefull, 0u, TXT_BASE, TXT_SIZE, 3u, 0u,
                    5u),
          "text query reports state 3 / perm 5");
    check(expect_ok(as, &ctx, DATA_BASE + 0x40ull, OUT_PTR,
                    0xdeadbeefdeadbeefull, 0u, DATA_BASE, 0x1000ull, 4u, 0u,
                    3u),
          "data query reports state 4/RW for the first page");
    check(expect_ok(as, &ctx, DATA_BASE + 0x1040ull, OUT_PTR,
                    0xdeadbeefdeadbeefull, 0u, DATA_BASE + 0x1000ull,
                    0x1000ull, 4u, AOT_AS_ATTR_LOCKED, 3u),
          "locked data page reports attr 16");
    check(expect_ok(as, &ctx, HEAP_BASE + 0x1000ull, OUT_PTR,
                    0xdeadbeefdeadbeefull, 0u, HEAP_BASE, HEAP_MAX, 0u, 0u,
                    0u),
          "uncommitted heap window is Free/NONE");
    check(expect_ok(as, &ctx, ALIAS_BASE + 0x1000ull, OUT_PTR,
                    0xdeadbeefdeadbeefull, 0u, ALIAS_BASE, ALIAS_SIZE, 0u,
                    0u, 0u),
          "alias reserved window is Free/NONE");
    check(expect_ok(as, &ctx, ARENA_BASE + 0x1000ull, OUT_PTR,
                    0xdeadbeefdeadbeefull, 0u, ARENA_BASE, ARENA_SIZE, 0u,
                    0u, 0u),
          "global stack arena is Free/NONE, distinct from the current stack");
    check(expect_ok(as, &ctx, QBASE + 0x3fe60ull, OUT_PTR,
                    X1_PTR, X1_PTR, QBASE, QSIZE, 0xbu, 0u, 3u),
          "writable r1 is never dereferenced");

    /* Unmapped addresses are geometry, not made-up executable pages. */
    check(expect_ok(as, &ctx, 0u, OUT_PTR, 0u, 0u,
                    0u, AOT_AS_MIN_ADDR, 0u, 0u, 0u), "zero lower Free record");
    check(expect_ok(as, &ctx, AOT_AS_MIN_ADDR - 1u, OUT_PTR, 0u, 0u,
                    0u, AOT_AS_MIN_ADDR, 0u, 0u, 0u), "lower last-byte record");
    check(expect_ok(as, &ctx, 0x7000000000ull, OUT_PTR, 0u, 0u,
                    ALIAS_BASE + ALIAS_SIZE,
                    AOT_AS_MAX_ADDR - (ALIAS_BASE + ALIAS_SIZE), 0u, 0u, 0u),
          "last unclaimed gap is Free, not fake RX");
    check(expect_ok(as, &ctx, QBASE + QSIZE + 0x1000ull, OUT_PTR, 0u, 0u,
                    QBASE + QSIZE, TXT_BASE - (QBASE + QSIZE), 0u, 0u, 0u),
          "gap after stack is bounded by next region");
    check(expect_ok(as, &ctx, AOT_AS_MAX_ADDR, OUT_PTR, 0u, 0u,
                    AOT_AS_MAX_ADDR, 0ull - AOT_AS_MAX_ADDR, 16u, 0u, 0u),
          "upper endpoint is Inaccessible");
    check(expect_ok(as, &ctx, UINT64_MAX, OUT_PTR, 0u, 0u,
                    AOT_AS_MAX_ADDR, 0ull - AOT_AS_MAX_ADDR, 16u, 0u, 0u),
          "UINT64_MAX query returns wrapping Inaccessible extent");

    /* Output-span failures: whole-span precheck, no partial bytes. */
    check(expect_write_fault(as, &ctx, 0u, UINT64_MAX - 7u,
                            AOT_MEM_ERR_RANGE, 0u, 0u), "wrapping output rejected");
    check(expect_write_fault(as, &ctx, 0u, QBASE + QSIZE - 8u,
                            AOT_MEM_ERR_RANGE, QBASE + QSIZE - 8u, 8u),
          "region-end output straddle leaves prefix untouched");
    check(expect_write_fault(as, &ctx, TXT_BASE, TXT_BASE,
                             (int64_t)AOT_MEM_ERR_PERM, TXT_BASE, 40u),
          "read-only text output is AOT_FAULT_MEMORY and changes nothing");
    if (aot_as_set_heap_size(as, 0x200000ull, &base) != AOT_MEM_OK ||
        base != HEAP_BASE) {
        printf("FATAL: heap size\n");
        return 1;
    }
    check(fill_bytes(as, HEAP_BASE + 0x1ffff8ull, 0xa7u, 8u),
          "cross-NONE canary write");
    check(expect_write_fault(as, &ctx, HEAP_BASE + 0x1000ull,
                             HEAP_BASE + 0x1ffff8ull,
                             (int64_t)AOT_MEM_ERR_PERM,
                             HEAP_BASE + 0x1ffff8ull, 8u),
          "committed/free cross span fails whole and preserves the prefix");

    /* Second AS geometry proves the record is not a constant table. */
    as2 = aot_as_create(dom);
    if (as2 == 0) { printf("FATAL: as2\n"); return 1; }
    if (aot_as_add_region(as2, AS2_BASE, AS2_SIZE, AOT_AS_PERM_RW, 0xbu,
                          NULL) != AOT_MEM_OK ||
        aot_as_seal(as2) != AOT_MEM_OK) {
        printf("FATAL: as2 setup\n");
        return 1;
    }
    g3_start_hle_init(&ctx2, provider_zero, NULL);
    g3_start_hle_set_address_space(&ctx2, as2);
    check(expect_ok(as2, &ctx2, AS2_BASE + 0x1000ull, AS2_BASE + 0x3000ull,
                    0xdeadbeefdeadbeefull, 0u, AS2_BASE, AS2_SIZE, 0xbu, 0u,
                    3u),
          "second AS geometry is reported from that AS, not constants");
    check(ctx2.svc6_success == 1u && ctx2.svc6_unsupported == 0u,
          "second AS counters");
    aot_as_destroy(as2);

    /* Wrong-field / constant-state / partial-write controls. */
    g3_start_hle_init(&ctx_m, provider_zero, NULL);
    g3_start_hle_set_address_space(&ctx_m, as);
    g_query_fn = mut_wrong_field;
    check(!expect_ok(as, &ctx_m, QBASE + 0x3fe60ull, OUT_PTR,
                     0xdeadbeefdeadbeefull, 0u, QBASE, QSIZE, 0xbu, 0u, 3u),
          "wrong-field mutant rejected");
    g3_start_hle_init(&ctx_m, provider_zero, NULL);
    g3_start_hle_set_address_space(&ctx_m, as);
    g_query_fn = mut_state_const;
    check(!expect_ok(as, &ctx_m, QBASE + 0x3fe60ull, OUT_PTR,
                     0xdeadbeefdeadbeefull, 0u, QBASE, QSIZE, 0xbu, 0u, 3u),
          "constant-state mutant rejected");
    g3_start_hle_init(&ctx_m, provider_zero, NULL);
    g3_start_hle_set_address_space(&ctx_m, as);
    g_query_fn = mut_corrupt_tail;
    check(!expect_ok(as, &ctx_m, QBASE + 0x3fe60ull, OUT_PTR,
                     0xdeadbeefdeadbeefull, 0u, QBASE, QSIZE, 0xbu, 0u, 3u),
          "post-write field-corruption mutant rejected");
    g_query_fn = mut_pageinfo_deref;
    check(!expect_ok(as, &ctx_m, QBASE + 0x3fe60ull, OUT_PTR,
                     X1_PTR, X1_PTR, QBASE, QSIZE, 0xbu, 0u, 3u),
          "page-info-dereference mutant rejected by the baseline oracle");
    g_query_fn = g3_start_hle_svc6;

    /* Missing/poisoned AS: typed host failure, no zero-fake success. */
    g3_start_hle_init(&ctx_bad, provider_zero, NULL);
    expect_host_failure(&ctx_bad, QBASE + 0x3fe60ull,
                        "missing AS fails closed with a typed status");
    check(ctx_bad.svc6_host_failures == 1u, "missing AS counter");
    aot_as_poison(as);
    expect_host_failure(&ctx, QBASE + 0x3fe60ull,
                        "poisoned AS fails closed with a typed status");

    printf("G3QUERY calls=%u success=%u null_out=%u unsupported=%u "
           "write_faults=%u host_fail=%u\n",
           ctx.svc6_calls, ctx.svc6_success, ctx.svc6_null_out,
           ctx.svc6_unsupported, ctx.svc6_write_faults,
           ctx.svc6_host_failures);
    aot_as_destroy(as);
    aot_mem_domain_destroy(dom);
    if (g_infra) return 1;
    if (g_fail) return 2;
    printf("aot_g3_start_hle_query: all QueryMemory HLE rows passed\n");
    return 0;
}
