/* Game-data-free G3 Start GetInfo budget rows (Mac services.c:264).
 * ids 6/21 = APP_POOL; ids 7/22 = image_bytes + logical heap size + 0 alias.
 * Real address space + real heap grow/shrink/regrow; borrowed immutable
 * budget; typed fail-closed on unusable inputs; wrong handlers rejected. */
#include "aot_as.h"
#include "g3_start_hle.h"

#include <stdio.h>
#include <string.h>

#define HBASE 0x4000000000ull
#define HMAX  0x100000000ull
#define HLIMIT 0x4000000ull
#define HGROW 0x800000ull
#define HSHRINK 0x400000ull
#define HREGROW 0x600000ull
#define IMG1 0x12345000ull
#define POOL1 0xcd500000ull
#define IMG2 0x1000ull
#define POOL2 0x20000000ull
static int g_fail;
static G3StartHle *g_ctx;

static void check(int c, const char *m) {
    if (!c) { printf("FAIL: %s\n", m); g_fail = 1; }
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
static int rest_ok(const AotGuestState *s, const AotGuestState *b) {
    unsigned i;
    if (s->sp != b->sp || s->pc != b->pc || s->nzcv != b->nzcv ||
        s->fpcr != b->fpcr || s->fpsr != b->fpsr || s->tpidr != b->tpidr ||
        s->tpidrro != b->tpidrro) return 0;
    if (memcmp(s->v, b->v, sizeof s->v) != 0) return 0;
    for (i = 2u; i < 31u; i++) if (s->x[i] != b->x[i]) return 0;
    return 1;
}
static void run(AotProgHandler fn, AotGuestState *s, AotRuntime *rt,
                AotHleRequest *req, uint64_t id) {
    memset(rt, 0, sizeof *rt);
    req->kind = AOT_HLE_SVC; req->id = 0x29u;
    req->site_pc = 0x10201584b0ull; req->resume_pc = 0x10201584b4ull;
    s->x[1] = id;
    fn(rt, s, req, g_ctx);
}
static int expect_val(AotGuestState *s, AotRuntime *rt, AotHleRequest *req,
                      uint64_t id, uint64_t want) {
    AotGuestState b;
    init_state(s); b = *s;
    run(g3_start_hle_svc, s, rt, req, id);
    return rt->fault == AOT_FAULT_NONE && s->x[0] == 0u && s->x[1] == want &&
           rest_ok(s, &b);
}
static int expect_fault(G3StartHle *ctx, AotGuestState *s, AotRuntime *rt,
                        AotHleRequest *req, uint64_t id) {
    AotGuestState b;
    g_ctx = ctx; init_state(s); s->x[1] = id; b = *s;
    run(g3_start_hle_svc, s, rt, req, id);
    return rt->fault == AOT_FAULT_BAD_HLE &&
           rt->fault_status == G3_START_HLE_FAULT_BUDGET &&
           memcmp(s, &b, sizeof *s) == 0;
}
static void mut_const0(AotRuntime *rt, AotGuestState *s,
                       const AotHleRequest *req, void *u) {
    g3_start_hle_svc(rt, s, req, u);
    if (rt->fault == AOT_FAULT_NONE) s->x[1] = 0u;
}
static void mut_highwater(AotRuntime *rt, AotGuestState *s,
                          const AotHleRequest *req, void *u) {
    g3_start_hle_svc(rt, s, req, u);
    if (rt->fault == AOT_FAULT_NONE) s->x[1] = IMG1 + HGROW;
}
static void mut_omit_images(AotRuntime *rt, AotGuestState *s,
                            const AotHleRequest *req, void *u) {
    g3_start_hle_svc(rt, s, req, u);
    if (rt->fault == AOT_FAULT_NONE) s->x[1] -= IMG1;
}
static void mut_pool_wrong(AotRuntime *rt, AotGuestState *s,
                           const AotHleRequest *req, void *u) {
    g3_start_hle_svc(rt, s, req, u);
    if (rt->fault == AOT_FAULT_NONE) s->x[1] ^= 1u;
}

int main(void) {
    AotMemDomain *dom = aot_mem_domain_create();
    AotAddressSpace *as, *noheap, *poison;
    AotMemDomain *dom2 = aot_mem_domain_create();
    G3StartHle ctx, ctx2, ctx_nb, ctx_na, ctx_nh, ctx_pz;
    G3StartBudget b1 = { POOL1, IMG1 }, b2 = { POOL2, IMG2 };
    G3StartBudget b_bad = { 0x1000ull, 0x2000ull };
    G3StartBudget b_over = { 0x1000ull, 0x0ull };
    G3StartBudget b_wrap = { ~0ull, ~0ull - 8ull };
    AotGuestState s;
    AotRuntime rt;
    AotHleRequest req;
    uint64_t base = 0u;

    if (dom == 0 || dom2 == 0) { printf("FATAL domain\n"); return 1; }
    as = aot_as_create(dom); noheap = aot_as_create(dom2);
    poison = aot_as_create(dom2);
    if (!as || !noheap || !poison) { printf("FATAL as\n"); return 1; }
    if (aot_as_add_heap_window(as, HBASE, HMAX, HLIMIT) != AOT_MEM_OK ||
        aot_as_seal(as) != AOT_MEM_OK) {
        printf("FATAL heap\n"); return 1;
    }
    if (aot_as_add_heap_window(poison, HBASE, HMAX, HLIMIT) != AOT_MEM_OK ||
        aot_as_seal(poison) != AOT_MEM_OK) {
        printf("FATAL poison fixture\n"); return 1;
    }
    aot_as_poison(poison);
    g_ctx = &ctx;
    g3_start_hle_init(&ctx, NULL, NULL);
    g3_start_hle_set_address_space(&ctx, as);
    g3_start_hle_set_budget(&ctx, &b1);
    check(expect_val(&s, &rt, &req, 6u, POOL1), "id6 = pool");
    check(expect_val(&s, &rt, &req, 21u, POOL1), "id21 = pool");
    check(expect_val(&s, &rt, &req, 7u, IMG1), "id7 initial = image+0");
    check(expect_val(&s, &rt, &req, 22u, IMG1), "id22 initial = image+0");
    check(expect_val(&s, &rt, &req, 0x100000016ull, IMG1),
          "low32 id truncation (0x100000016 -> 22)");
    if (aot_as_set_heap_size(as, HGROW, &base) != AOT_MEM_OK) {
        printf("FATAL grow\n"); return 1;
    }
    check(expect_val(&s, &rt, &req, 7u, IMG1 + HGROW), "id7 grow");
    check(expect_val(&s, &rt, &req, 22u, IMG1 + HGROW), "id22 grow");
    if (aot_as_set_heap_size(as, HSHRINK, &base) != AOT_MEM_OK) {
        printf("FATAL shrink\n"); return 1;
    }
    check(expect_val(&s, &rt, &req, 7u, IMG1 + HSHRINK),
          "id7 shrink reduces used despite retained host pages");
    if (aot_as_set_heap_size(as, HREGROW, &base) != AOT_MEM_OK) {
        printf("FATAL regrow\n"); return 1;
    }
    check(expect_val(&s, &rt, &req, 7u, IMG1 + HREGROW), "id7 regrow");
    check(ctx.info6_calls == 1u && ctx.info21_calls == 1u &&
              ctx.info7_calls == 4u && ctx.info22_calls == 3u,
          "counter witness (6/21 once, 7 four, 22 three incl low32 row)");
    /* Different budget proves no constant return. */
    g_ctx = &ctx2;
    g3_start_hle_init(&ctx2, NULL, NULL);
    g3_start_hle_set_address_space(&ctx2, as);
    g3_start_hle_set_budget(&ctx2, &b2);
    check(expect_val(&s, &rt, &req, 6u, POOL2), "second pool from budget");
    check(expect_val(&s, &rt, &req, 7u, IMG2 + HREGROW),
          "second used from budget + AS");
    /* Fail-closed rows: missing/unconfigured/poisoned/overflow/malformed. */
    check(expect_fault(NULL, &s, &rt, &req, 22u), "missing context");
    g_ctx = &ctx_nb;
    g3_start_hle_init(&ctx_nb, NULL, NULL);
    g3_start_hle_set_address_space(&ctx_nb, as);
    check(expect_fault(&ctx_nb, &s, &rt, &req, 7u), "missing budget");
    check(expect_fault(&ctx_nb, &s, &rt, &req, 6u), "missing budget pool");
    g_ctx = &ctx_na;
    g3_start_hle_init(&ctx_na, NULL, NULL);
    g3_start_hle_set_budget(&ctx_na, &b1);
    check(expect_fault(&ctx_na, &s, &rt, &req, 7u), "missing AS");
    g_ctx = &ctx_nh;
    g3_start_hle_init(&ctx_nh, NULL, NULL);
    g3_start_hle_set_address_space(&ctx_nh, noheap);
    g3_start_hle_set_budget(&ctx_nh, &b1);
    check(expect_fault(&ctx_nh, &s, &rt, &req, 22u), "missing heap window");
    g_ctx = &ctx_pz;
    g3_start_hle_init(&ctx_pz, NULL, NULL);
    g3_start_hle_set_address_space(&ctx_pz, poison);
    g3_start_hle_set_budget(&ctx_pz, &b1);
    check(expect_fault(&ctx_pz, &s, &rt, &req, 7u), "poisoned AS");
    g_ctx = &ctx2;
    g3_start_hle_init(&ctx2, NULL, NULL);
    g3_start_hle_set_address_space(&ctx2, as);
    g3_start_hle_set_budget(&ctx2, &b_bad);
    check(expect_fault(&ctx2, &s, &rt, &req, 7u), "image > pool");
    g3_start_hle_set_budget(&ctx2, &b_over);
    if (aot_as_set_heap_size(as, 0x200000ull, &base) != AOT_MEM_OK) return 1;
    check(expect_fault(&ctx2, &s, &rt, &req, 7u), "used > pool");
    g3_start_hle_set_budget(&ctx2, &b_wrap);
    check(expect_fault(&ctx2, &s, &rt, &req, 22u), "checked overflow");
    check(ctx2.budget_failures >= 3u, "budget failure counter witness");
    /* Restore the logical fixture after the over-budget fault row. */
    if (aot_as_set_heap_size(as, HREGROW, &base) != AOT_MEM_OK) return 1;
    /* Wrong implementations: robust baseline green, named mutant red. */
    g_ctx = &ctx;
    check(expect_val(&s, &rt, &req, 7u, IMG1 + HREGROW),
          "baseline still green before mutants");
    g_ctx = &ctx2;
    g3_start_hle_set_budget(&ctx2, &b1);
    check(expect_val(&s, &rt, &req, 7u, IMG1 + HREGROW),
          "same mutant fixture baseline is green");
    {
        AotGuestState a, b;
        init_state(&a); b = a; memset(&rt, 0, sizeof rt);
        req.kind = AOT_HLE_SVC; req.id = 0x29u; req.site_pc = 1; req.resume_pc = 2;
        a.x[1] = 7u; mut_const0(&rt, &a, &req, &ctx2);
        check(rt.fault == AOT_FAULT_NONE && a.x[0] == 0u &&
                a.x[1] == 0u && a.x[1] != IMG1 + HREGROW && rest_ok(&a, &b),
              "const-0 wrapper rejected on value only");
        init_state(&a); b = a; memset(&rt, 0, sizeof rt);
        req.kind = AOT_HLE_SVC; req.id = 0x29u;
        a.x[1] = 7u; mut_highwater(&rt, &a, &req, &ctx2);
        check(rt.fault == AOT_FAULT_NONE && a.x[0] == 0u &&
                a.x[1] == IMG1 + HGROW && a.x[1] != IMG1 + HREGROW &&
                rest_ok(&a, &b), "retained high-water mutant rejected on value only");
        init_state(&a); b = a; memset(&rt, 0, sizeof rt);
        req.kind = AOT_HLE_SVC; req.id = 0x29u;
        a.x[1] = 7u; mut_omit_images(&rt, &a, &req, &ctx2);
        check(rt.fault == AOT_FAULT_NONE && a.x[0] == 0u &&
                a.x[1] == HREGROW && a.x[1] != IMG1 + HREGROW &&
                rest_ok(&a, &b), "omit-images mutant rejected on value only");
        init_state(&a); b = a; memset(&rt, 0, sizeof rt);
        req.kind = AOT_HLE_SVC; req.id = 0x29u;
        a.x[1] = 6u; mut_pool_wrong(&rt, &a, &req, &ctx2);
        check(rt.fault == AOT_FAULT_NONE && a.x[0] == 0u &&
                a.x[1] == (POOL1 ^ 1u) && a.x[1] != POOL1 &&
                rest_ok(&a, &b), "pool-wrong mutant rejected on value only");
    }
    printf("G3BUDGET pool=%llx image=%llx heap=%llx used=%llx "
           "info6=%u info21=%u info7=%u info22=%u fail=%u\n",
           (unsigned long long)b1.pool, (unsigned long long)b1.image_bytes,
           (unsigned long long)HREGROW,
           (unsigned long long)(IMG1 + HREGROW), ctx.info6_calls,
           ctx.info21_calls, ctx.info7_calls, ctx.info22_calls,
           ctx.budget_failures);
    aot_as_destroy(as); aot_as_destroy(noheap); aot_as_destroy(poison);
    aot_mem_domain_destroy(dom); aot_mem_domain_destroy(dom2);
    if (g_fail) return 2;
    printf("aot_g3_start_hle_budget: all GetInfo budget rows passed\n");
    return 0;
}
