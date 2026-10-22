/* Game-data-free native test for the minimal G3 Start SVC 0x29 HLE.
 *
 * Deterministic provider proves the register-only ABI, fresh provider calls,
 * success on zero entropy, typed failure with unchanged guest state, unknown
 * info-id fail-closed, and that x0 is never dereferenced. Three deliberately
 * wrong handlers must be rejected by the same expectations. The live CSPRNG
 * smoke records platform status and a probabilistic not-all-identical bit;
 * it never asserts mathematical non-equality or non-zero entropy.
 */

#include "g3_start_hle.h"
#include "host_random.h"

#include <stdio.h>
#include <string.h>

static int g_failures;

#define CHECK(cond, msg)                                                   \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("FAIL: %s (%s:%d)\n", (msg), __FILE__, __LINE__);       \
            g_failures++;                                                  \
        }                                                                  \
    } while (0)

typedef struct Provider {
    uint64_t value;
    int rc;
    unsigned calls;
} Provider;

static int provider(uint64_t *out, void *user)
{
    Provider *p = (Provider *)user;
    p->calls++;
    if (p->rc != 0) return p->rc;
    *out = p->value;
    return 0;
}

static void init_state(AotGuestState *s)
{
    unsigned i;
    memset(s, 0, sizeof *s);
    for (i = 0; i < 8u; i++) s->x[i] = 0x1111000000000000ull + i;
    for (i = 8u; i < 31u; i++) s->x[i] = 0x2222000000000000ull + i;
    s->sp = 0x2000040000ull;
    s->pc = 0x10201584b4ull;
    s->nzcv = 0x80000000ull;
    for (i = 0; i < 32u; i++) {
        s->v[i][0] = 0x3333000000000000ull + i;
        s->v[i][1] = 0x4444000000000000ull + i;
    }
    s->fpcr = 0x12345678ull;
    s->fpsr = 0x87654321ull;
    s->tpidr = 0x3000000000ull;
    s->tpidrro = 0x3000002000ull;
}

static int same_except_result(const AotGuestState *a, const AotGuestState *b)
{
    unsigned i;
    if (a->sp != b->sp || a->pc != b->pc || a->nzcv != b->nzcv)
        return 0;
    if (a->fpcr != b->fpcr || a->fpsr != b->fpsr ||
        a->tpidr != b->tpidr || a->tpidrro != b->tpidrro)
        return 0;
    if (memcmp(a->v, b->v, sizeof a->v) != 0) return 0;
    for (i = 2u; i < 31u; i++)
        if (a->x[i] != b->x[i]) return 0;
    return 1;
}

static void run_handler(AotProgHandler fn, AotGuestState *s, G3StartHle *ctx,
                        uint32_t svc_id,
                        AotRuntime *rt, AotHleRequest *req)
{
    memset(rt, 0, sizeof *rt);
    req->kind = AOT_HLE_SVC;
    req->id = svc_id;
    req->site_pc = 0x10201584b0ull;
    req->resume_pc = 0x10201584b4ull;
    fn(rt, s, req, ctx);
}

static int expect_success(AotProgHandler fn, uint64_t provider_value,
                          uint64_t expect, uint64_t bad_x0)
{
    AotGuestState s, before;
    AotRuntime rt;
    AotHleRequest req;
    Provider p;
    G3StartHle ctx;
    int ok;

    init_state(&s);
    s.x[0] = bad_x0;
    s.x[1] = 11u;
    s.x[2] = 0x5151515151515151ull;
    s.x[3] = 0x5252525252525252ull;
    before = s;
    p.value = provider_value;
    p.rc = 0;
    p.calls = 0u;
    g3_start_hle_init(&ctx, provider, &p);
    run_handler(fn, &s, &ctx, 0x29u, &rt, &req);
    ok = rt.fault == AOT_FAULT_NONE && s.x[0] == 0u &&
         s.x[1] == expect && s.x[2] == before.x[2] &&
         s.x[3] == before.x[3] && same_except_result(&s, &before);
    return ok;
}

static void mutant_wrong_return(AotRuntime *rt, AotGuestState *s,
                                const AotHleRequest *req, void *user)
{
    G3StartHle *ctx = (G3StartHle *)user;
    uint64_t value = 0;
    (void)rt; (void)req;
    if (ctx->entropy(&value, ctx->entropy_user) != 0) return;
    s->x[0] = 0u;
    s->x[2] = value;          /* WRONG destination register */
}

static void mutant_constant(AotRuntime *rt, AotGuestState *s,
                            const AotHleRequest *req, void *user)
{
    (void)rt; (void)req; (void)user;
    s->x[0] = 0u;
    s->x[1] = 0xC0FFEEu;      /* skips provider, constant */
}

static void mutant_failure_success(AotRuntime *rt, AotGuestState *s,
                                   const AotHleRequest *req, void *user)
{
    G3StartHle *ctx = (G3StartHle *)user;
    uint64_t value = 0;
    (void)rt; (void)req;
    if (ctx->entropy(&value, ctx->entropy_user) != 0) {
        s->x[0] = 0u;         /* fakes success on provider failure */
        s->x[1] = 0u;
    }
}

int main(void)
{
    AotGuestState s, before;
    AotRuntime rt;
    AotHleRequest req;
    Provider p;
    G3StartHle ctx;
    unsigned i;
    uint64_t draws[16];
    unsigned ok_draws = 0u;
    int all_same = 1;

    printf("g3_start_hle: deterministic provider ABI\n");
    CHECK(expect_success(g3_start_hle_svc, 0x1122334455667788ull,
                         0x1122334455667788ull, 0xdeadbeefull),
          "known-nonzero provider result");
    CHECK(expect_success(g3_start_hle_svc, 0u, 0u, 0xdeadbeefull),
          "ALL-ZERO is a valid success");
    CHECK(expect_success(g3_start_hle_svc, 0xFFFFFFFFFFFFFFFFull,
                         0xFFFFFFFFFFFFFFFFull, (uint64_t)1),
          "max64 result and invalid/unwritable x0 not dereferenced");

    /* Fresh provider invocation on two calls. */
    init_state(&s);
    s.x[1] = 11u;
    before = s;
    p.value = 0xAAAAAAAAAAAAAAAAull;
    p.rc = 0;
    p.calls = 0u;
    g3_start_hle_init(&ctx, provider, &p);
    run_handler(g3_start_hle_svc, &s, &ctx, 0x29u, &rt, &req);
    CHECK(rt.fault == AOT_FAULT_NONE && s.x[1] == p.value,
          "first random draw");
    p.value = 0xBBBBBBBBBBBBBBBBull;
    s.x[1] = 11u;
    run_handler(g3_start_hle_svc, &s, &ctx, 0x29u, &rt, &req);
    CHECK(rt.fault == AOT_FAULT_NONE && s.x[1] == p.value,
          "second random draw uses fresh provider value");
    CHECK(p.calls == 2u && ctx.entropy_calls == 2u,
          "provider invocation count is 2");

    /* Provider failure: typed BAD_HLE, all guest state unchanged. */
    init_state(&s);
    s.x[0] = (uint64_t)(uintptr_t)&s;   /* if dereferenced, visible/crash */
    s.x[1] = 11u;
    before = s;
    p.value = 0u;
    p.rc = 7;
    p.calls = 0u;
    g3_start_hle_init(&ctx, provider, &p);
    run_handler(g3_start_hle_svc, &s, &ctx, 0x29u, &rt, &req);
    CHECK(rt.fault == AOT_FAULT_BAD_HLE &&
          rt.fault_status == G3_START_HLE_FAULT_ENTROPY &&
          memcmp(&s, &before, sizeof s) == 0 && p.calls == 1u &&
          ctx.entropy_failures == 1u,
          "provider failure is typed and leaves guest state unchanged");

    /* Unknown GetInfo id: typed BAD_HLE, provider not called, regs unchanged. */
    init_state(&s);
    s.x[1] = 99u;
    before = s;
    p.value = 0u;
    p.rc = 0;
    p.calls = 0u;
    g3_start_hle_init(&ctx, provider, &p);
    run_handler(g3_start_hle_svc, &s, &ctx, 0x29u, &rt, &req);
    CHECK(rt.fault == AOT_FAULT_BAD_HLE && rt.fault_status == 99 &&
          memcmp(&s, &before, sizeof s) == 0 && p.calls == 0u &&
          ctx.unknown_info_calls == 1u,
          "unknown GetInfo id fails closed without provider");

    /* Negative controls: the same expectations reject wrong handlers. */
    CHECK(!expect_success(mutant_wrong_return, 0x1122334455667788ull,
                          0x1122334455667788ull, 0xdeadbeefull),
          "wrong return register mutant rejected");
    CHECK(!expect_success(mutant_constant, 0x1122334455667788ull,
                          0x1122334455667788ull, 0xdeadbeefull),
          "constant/skip-provider mutant rejected");
    init_state(&s);
    s.x[1] = 11u;
    before = s;
    p.rc = 9;
    p.calls = 0u;
    g3_start_hle_init(&ctx, provider, &p);
    run_handler(mutant_failure_success, &s, &ctx, 0x29u, &rt, &req);
    CHECK(rt.fault == AOT_FAULT_NONE &&
          memcmp(&s, &before, sizeof s) != 0,
          "failure-fakes-success mutant rejected");

    /* Live platform CSPRNG smoke: status evidence only. Zero is valid. */
    for (i = 0u; i < 16u; i++) {
        uint64_t value = 0u;
        host_random_result rr = host_random_u64(&value);
        CHECK(rr == HOST_RANDOM_OK, "live host_random_u64 status");
        if (rr == HOST_RANDOM_OK) draws[ok_draws++] = value;
    }
    for (i = 1u; i < ok_draws; i++)
        if (draws[i] != draws[0]) all_same = 0;
    printf("HOST_RANDOM live ok=%u/16 all_identical=%d (probabilistic, "
           "not an assertion)\n", ok_draws, all_same);

    /* Mac diagnostics startup is void, not a manufactured zero result. */
    {
        memset(&req, 0, sizeof req);
        init_state(&s); before = s;
        g3_start_hle_init(&ctx, NULL, NULL);
        memset(&rt, 0, sizeof rt);
        req.kind = AOT_HLE_HOSTCALL; req.id = 17u;
        req.site_pc = 0x1000u; req.resume_pc = 0x2000u;
        g3_start_hle_host_diag(&rt, &s, &req, &ctx);
        CHECK(rt.fault == AOT_FAULT_NONE && ctx.host_diag_calls == 1u &&
              memcmp(&s, &before, sizeof s) == 0,
              "void diagnostic hook preserves full guest state");
        memset(&rt, 0, sizeof rt); req.kind = AOT_HLE_SVC;
        g3_start_hle_host_diag(&rt, &s, &req, &ctx);
        CHECK(rt.fault == AOT_FAULT_BAD_HLE &&
              rt.fault_status == G3_START_HLE_FAULT_DIAG &&
              ctx.host_diag_calls == 1u && memcmp(&s, &before, sizeof s) == 0,
              "diagnostic wrong-kind fault preserves state");
        memset(&rt, 0, sizeof rt); req.kind = AOT_HLE_HOSTCALL;
        g3_start_hle_host_diag(&rt, &s, &req, NULL);
        CHECK(rt.fault == AOT_FAULT_BAD_HLE &&
              rt.fault_status == G3_START_HLE_FAULT_DIAG &&
              memcmp(&s, &before, sizeof s) == 0,
              "diagnostic missing-context fault preserves state");
    }
    {
        const uint64_t sys_limits[] = { 0x2000000ull, 0u, 0x123456789ull };
        for (unsigned sys_i = 0u; sys_i < 3u; sys_i++) {
            g3_start_hle_init(&ctx, provider, &p);
            g3_start_hle_set_system_resource_limit(&ctx, sys_limits[sys_i]);
            p.calls = 0u;
            init_state(&s); s.x[1] = 16u; before = s;
            run_handler(g3_start_hle_svc, &s, &ctx, 0x29u, &rt, &req);
            if (rt.fault != AOT_FAULT_NONE || s.x[0] != 0u ||
                s.x[1] != sys_limits[sys_i] || p.calls != 0u ||
                !same_except_result(&s, &before)) {
                printf("FAIL: configured system resource limit\n"); g_failures++;
            }
            init_state(&s); s.x[1] = 0x100000010ull; before = s;
            run_handler(g3_start_hle_svc, &s, &ctx, 0x29u, &rt, &req);
            CHECK(rt.fault == AOT_FAULT_NONE && s.x[1] == sys_limits[sys_i] &&
                  s.x[0] == 0u && ctx.info16_calls == 2u &&
                  same_except_result(&s, &before), "system resource id truncation");
        }
        g3_start_hle_init(&ctx, provider, &p);
        init_state(&s); s.x[1] = 16u; before = s;
        run_handler(g3_start_hle_svc, &s, &ctx, 0x29u, &rt, &req);
        CHECK(rt.fault == AOT_FAULT_BAD_HLE &&
              rt.fault_status == G3_START_HLE_FAULT_SYSRES &&
              ctx.sysres_failures == 1u && !memcmp(&s, &before, sizeof s),
              "missing system resource configuration preserves full state");
        run_handler(g3_start_hle_svc, &s, NULL, 0x29u, &rt, &req);
        CHECK(rt.fault == AOT_FAULT_BAD_HLE &&
              rt.fault_status == G3_START_HLE_FAULT_SYSRES &&
              !memcmp(&s, &before, sizeof s), "missing system resource context");
    }
    if (g_failures != 0) {
        printf("FAIL: %d check(s) failed\n", g_failures);
        /* Exit protocol shared with the rest of the G3 probes and required by
         * tools/aot/g3_mutant_test.py: 2 = semantic failure, 1 = infrastructure. */
        return 2;
    }
    printf("PASS: g3_start_hle\n");
    return 0;
}
