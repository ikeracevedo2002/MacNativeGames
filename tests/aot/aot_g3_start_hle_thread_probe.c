/*
 * Game-data-free rows for the minimal G3 Start thread HLE:
 * SVC 0x0c (GetThreadPriority) and SVC 0x25 (GetThreadId).
 *
 * Contract (Mac threads.c:378/389):
 *   - handle = (uint32_t)x1 (32-bit truncation like the Mac);
 *   - known THREAD -> r0=0, r1=priority / r1=GUEST thread id;
 *   - unknown handle -> r0=0xe401 (R_BAD_HANDLE), r1=0, no host fault;
 *   - missing registry/provider is a typed host fault, never a fake 0xe401;
 *   - 0xffff8000 (H_CUR_THREAD) aliases ONLY the is_main entry;
 *   - r0 is never dereferenced; only r0/r1 may change.
 *
 * Both the REAL borrowed-registry adapter and a deterministic lookup provider
 * are exercised. Deliberately wrong handlers (constant priority, host TID,
 * wrong result register, pseudo rejection) must be rejected by the rows.
 *
 * Exit: 0 all rows passed, 1 infrastructure, 2 semantic failure.
 */
#include "g3_start_hle.h"

#include <stdio.h>
#include <string.h>

static int g_fail;

static void check(int cond, const char *msg) {
    if (!cond) {
        printf("FAIL: %s\n", msg);
        g_fail = 1;
    }
}

static void init_state(AotGuestState *s) {
    unsigned i;
    memset(s, 0, sizeof *s);
    for (i = 0u; i < 31u; i++) s->x[i] = 0x1111000000000000ull + i;
    s->x[0] = 0xdeadbeefdeadbeefull; /* output pointer must never be read */
    s->sp = 0x200003fe10ull;
    s->pc = 0x1020158314ull;
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
    req->site_pc = 0x1020158368ull;
    req->resume_pc = 0x102015836cull;
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

#define RG 0x7fu
static const G3StartThreadInfo g_real_entries[] = {
    { 0x1001u, 1u, 0x2222u, 1u, 0x51ull, 44, 0, RG },
    { 0x1002u, 1u, 0x3333u, 0u, 0x123456789abcdef0ull, 59, 2, 3u },
    { 0x1003u, 2u, 0x4444u, 0u, 0x77ull, 30, 0, 1u }, /* not THREAD */
};
static const G3StartThreadRegistry g_real_reg = {
    g_real_entries, 3u
};

/* Deterministic provider: records the exact 32-bit handle it is given. */
typedef struct Fake {
    uint32_t seen[4];
    unsigned calls;
    int rc;
} Fake;

static int fake_lookup(uint32_t handle, G3StartThreadInfo *out, void *user) {
    Fake *f = (Fake *)user;
    f->seen[f->calls & 3u] = handle;
    f->calls++;
    if (f->rc != 0) return 0;
    out->handle = handle;
    out->type = 1u;
    out->owner_os_thread = 0x9999u;
    out->is_main = 1u;
    out->guest_id = 0x51ull;
    out->priority = 44;
    out->core = 0;
    out->affinity_mask = RG;
    return 1;
}

/* Wrong implementations used as negative controls. */
static void mut_const44(AotRuntime *rt, AotGuestState *s,
                        const AotHleRequest *req, void *user) {
    g3_start_hle_svc0c(rt, s, req, user);
    if (rt->fault == AOT_FAULT_NONE && s->x[0] != 0u) {
        s->x[0] = 0u;   /* lies: an unknown handle looks successful */
        s->x[1] = 44u;
    }
}

static void mut_wrong_reg(AotRuntime *rt, AotGuestState *s,
                          const AotHleRequest *req, void *user) {
    g3_start_hle_svc0c(rt, s, req, user);
    if (rt->fault == AOT_FAULT_NONE) {
        s->x[2] = s->x[1];
        s->x[1] = 0u;
    }
}

static void mut_host_tid(AotRuntime *rt, AotGuestState *s,
                         const AotHleRequest *req, void *user) {
    g3_start_hle_svc25(rt, s, req, user);
    if (rt->fault == AOT_FAULT_NONE && s->x[0] == 0u) s->x[1] = 0x3333u;
}

static void mut_pseudo_reject(AotRuntime *rt, AotGuestState *s,
                              const AotHleRequest *req, void *user) {
    if (s->x[1] == G3_START_HLE_CUR_THREAD) {
        s->x[0] = G3_START_HLE_BAD_HANDLE;
        s->x[1] = 0u;
        return;
    }
    g3_start_hle_svc0c(rt, s, req, user);
}

/* Positive row: known handle -> r0=0/r1=expected, rest byte-identical. */
static int expect_ok(G3StartHle *ctx, AotProgHandler fn, uint32_t id,
                     uint64_t in_x1, uint64_t exp_x1, unsigned *ok_calls) {
    AotGuestState s, b;
    AotRuntime rt;
    AotHleRequest req;
    unsigned before_ok = *ok_calls;

    init_state(&s);
    s.x[1] = in_x1;
    b = s;
    run(fn, ctx, id, &s, &rt, &req);
    return rt.fault == AOT_FAULT_NONE && s.x[0] == 0u && s.x[1] == exp_x1 &&
           rest_unchanged(&s, &b) && *ok_calls == before_ok + 1u;
}

/* Negative row: unknown handle -> 0xe401/0, no host fault, rest identical. */
static int expect_bad_handle(G3StartHle *ctx, AotProgHandler fn, uint32_t id,
                             uint64_t in_x1, unsigned *bad_calls) {
    AotGuestState s, b;
    AotRuntime rt;
    AotHleRequest req;
    unsigned before = *bad_calls;

    init_state(&s);
    s.x[1] = in_x1;
    b = s;
    run(fn, ctx, id, &s, &rt, &req);
    return rt.fault == AOT_FAULT_NONE &&
           s.x[0] == G3_START_HLE_BAD_HANDLE && s.x[1] == 0u &&
           rest_unchanged(&s, &b) && *bad_calls == before + 1u;
}

/* Missing registry -> typed host fault, state untouched, no fake 0xe401. */
static int expect_host_fault(G3StartHle *ctx, AotProgHandler fn, uint32_t id) {
    AotGuestState s, b;
    AotRuntime rt;
    AotHleRequest req;
    unsigned before = ctx->thread_host_failures;

    init_state(&s);
    s.x[1] = 0x1001u;
    b = s;
    run(fn, ctx, id, &s, &rt, &req);
    return rt.fault == AOT_FAULT_BAD_HLE &&
           rt.fault_status == G3_START_HLE_FAULT_THREAD &&
           memcmp(&s, &b, sizeof s) == 0 &&
           ctx->thread_host_failures == before + 1u;
}

int main(void) {
    G3StartHle ctx;
    G3StartHle ctx_bad;
    G3StartHle ctx_mut;
    G3StartHle ctx_fake;
    Fake fake;

    /* ---- Real borrowed registry adapter ---- */
    g3_start_hle_init(&ctx, NULL, NULL);
    g3_start_hle_set_thread_registry(&ctx, &g_real_reg);
    check(ctx.svc0c_calls == 0u && ctx.svc25_calls == 0u, "fresh counters");

    check(expect_ok(&ctx, g3_start_hle_svc0c, 0x0cu, 0x1001u, 44u,
                    &ctx.svc0c_success),
          "0x0c main handle -> r0=0/r1=44");
    check(expect_ok(&ctx, g3_start_hle_svc25, 0x25u, 0x1001u, 0x51u,
                    &ctx.svc25_success),
          "0x25 main handle -> guest id 0x51 (not host TID)");
    check(expect_ok(&ctx, g3_start_hle_svc0c, 0x0cu, G3_START_HLE_CUR_THREAD,
                    44u, &ctx.svc0c_success),
          "0x0c pseudo 0xffff8000 aliases the owned main entry");
    check(expect_ok(&ctx, g3_start_hle_svc25, 0x25u, G3_START_HLE_CUR_THREAD,
                    0x51u, &ctx.svc25_success),
          "0x25 pseudo 0xffff8000 aliases the owned main entry");
    check(expect_ok(&ctx, g3_start_hle_svc0c, 0x0cu,
                    0xdeadbeef00001001ull, 44u, &ctx.svc0c_success),
          "handle is the low 32 bits of x1 (Mac truncation)");
    check(expect_ok(&ctx, g3_start_hle_svc0c, 0x0cu, 0x1002u, 59u,
                    &ctx.svc0c_success),
          "second THREAD entry reports its own priority");
    check(expect_ok(&ctx, g3_start_hle_svc25, 0x25u, 0x1002u,
                    0x123456789abcdef0ull, &ctx.svc25_success),
          "guest id is the full 64-bit value (no host-TID/zero)");

    check(expect_bad_handle(&ctx, g3_start_hle_svc0c, 0x0cu, 0x1003u,
                            &ctx.svc0c_invalid),
          "non-THREAD handle -> 0xe401, not a priority");
    check(expect_bad_handle(&ctx, g3_start_hle_svc0c, 0x0cu, 0x9999u,
                            &ctx.svc0c_invalid),
          "unknown 0x0c handle -> 0xe401");
    check(expect_bad_handle(&ctx, g3_start_hle_svc25, 0x25u, 0x9999u,
                            &ctx.svc25_invalid),
          "unknown 0x25 handle -> 0xe401");
    check(ctx.svc0c_calls == 6u && ctx.svc25_calls == 4u &&
              ctx.svc0c_success == 4u && ctx.svc0c_invalid == 2u &&
              ctx.svc25_success == 3u && ctx.svc25_invalid == 1u,
          "real-adapter counters");

    /* Wrong kind/id is typed and does not touch the guest state. */
    {
        AotGuestState s, b;
        AotRuntime rt;
        AotHleRequest req;
        init_state(&s);
        b = s;
        memset(&rt, 0, sizeof rt);
        req.kind = AOT_HLE_HOSTCALL;
        req.id = 0x0cu;
        req.site_pc = 1u;
        req.resume_pc = 2u;
        g3_start_hle_svc0c(&rt, &s, &req, &ctx);
        check(rt.fault == AOT_FAULT_BAD_HLE && memcmp(&s, &b, sizeof s) == 0,
              "0x0c wrong request kind is a typed fault, state unchanged");
        memset(&rt, 0, sizeof rt);
        req.kind = AOT_HLE_SVC;
        req.id = 0x29u;
        g3_start_hle_svc25(&rt, &s, &req, &ctx);
        check(rt.fault == AOT_FAULT_BAD_HLE && memcmp(&s, &b, sizeof s) == 0,
              "0x25 wrong SVC id is a typed fault, state unchanged");
    }

    /* ---- Missing registry/provider: host fault, not guest 0xe401 ---- */
    g3_start_hle_init(&ctx_bad, NULL, NULL);
    check(expect_host_fault(&ctx_bad, g3_start_hle_svc0c, 0x0cu),
          "missing registry: 0x0c typed host fault");
    check(expect_host_fault(&ctx_bad, g3_start_hle_svc25, 0x25u),
          "missing registry: 0x25 typed host fault");

    /* ---- Deterministic provider: receives the real handle ---- */
    memset(&fake, 0, sizeof fake);
    g3_start_hle_init(&ctx_fake, NULL, NULL);
    g3_start_hle_set_thread_lookup(&ctx_fake, fake_lookup, &fake);
    check(expect_ok(&ctx_fake, g3_start_hle_svc0c, 0x0cu,
                    0xaaaa000000001001ull, 44u, &ctx_fake.svc0c_success),
          "provider: 0x0c success");
    check(expect_ok(&ctx_fake, g3_start_hle_svc25, 0x25u,
                    G3_START_HLE_CUR_THREAD, 0x51u, &ctx_fake.svc25_success),
          "provider: 0x25 pseudo success");
    check(fake.calls == 2u && fake.seen[0] == 0x1001u &&
              fake.seen[1] == G3_START_HLE_CUR_THREAD,
          "provider was called with the truncated handle, then pseudo");
    fake.rc = 1;
    check(expect_bad_handle(&ctx_fake, g3_start_hle_svc0c, 0x0cu, 0x1001u,
                            &ctx_fake.svc0c_invalid),
          "provider failure is 0xe401, never a 0/44 success");

    /* ---- Wrong implementations must fail the same rows ---- */
    g3_start_hle_init(&ctx_mut, NULL, NULL);
    g3_start_hle_set_thread_registry(&ctx_mut, &g_real_reg);
    check(!expect_bad_handle(&ctx_mut, mut_const44, 0x0cu, 0x9999u,
                             &ctx_mut.svc0c_invalid),
          "constant-priority mutant rejected");
    check(!expect_ok(&ctx_mut, mut_wrong_reg, 0x0cu, 0x1001u, 44u,
                     &ctx_mut.svc0c_success),
          "wrong-result-register mutant rejected");
    {
        AotGuestState s, b;
        AotRuntime rt;
        AotHleRequest req;
        init_state(&s);
        s.x[1] = 0x1002u;
        b = s;
        run(mut_host_tid, &ctx_mut, 0x25u, &s, &rt, &req);
        check(!(rt.fault == AOT_FAULT_NONE && s.x[0] == 0u &&
                s.x[1] == 0x123456789abcdef0ull && rest_unchanged(&s, &b)),
              "host-TID mutant rejected");
    }
    check(!expect_ok(&ctx_mut, mut_pseudo_reject, 0x0cu,
                     G3_START_HLE_CUR_THREAD, 44u, &ctx_mut.svc0c_success),
          "pseudo-rejection mutant rejected");
    check(expect_ok(&ctx_mut, g3_start_hle_svc0c, 0x0cu, 0x1001u, 44u,
                    &ctx_mut.svc0c_success),
          "positive control still passes");

    printf("G3THREAD svc0c_calls=%u ok=%u bad=%u svc25_calls=%u ok=%u "
           "bad=%u host_fail=%u\n",
           ctx.svc0c_calls, ctx.svc0c_success, ctx.svc0c_invalid,
           ctx.svc25_calls, ctx.svc25_success, ctx.svc25_invalid,
           ctx.thread_host_failures + ctx_bad.thread_host_failures);
    if (g_fail) return 2;
    printf("aot_g3_start_hle_thread: all thread HLE rows passed\n");
    return 0;
}
