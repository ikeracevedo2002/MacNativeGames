/*
 * G2 translated-memory concurrency probe.
 *
 * Uses the owned fixture_concurrency.s image (translated offline by
 * aot_translate.py) and persistent AotRuntime/AotGuestState pairs over ONE
 * shared AotMemDomain. No ARM64 bytes are decoded or executed at runtime.
 *
 * Deterministic two-runtime schedules cover reservation lifetime, invalidation
 * and STXR status/no-write semantics. Real-thread cases are POSITIVE stress
 * evidence only; negative controls below are deterministic semantic
 * mismatches, never timeouts or infrastructure faults.
 */
#include "aot_runtime.h"

#include <stdio.h>
#include <string.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

extern const AotImage aot_image_conc;
extern const AotImage aot_image_conc_mut;   /* test-only stxalwaysok image */

#define GB            0x100000ull
#define ARENA_SIZE    0x1000u
#define STOP_PC       0ull

static int g_fail = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", msg); g_fail = 1; } \
} while (0)

static AotMemDomain *g_dom;
static uint8_t g_arena[ARENA_SIZE];
static AotMem g_mem;

/* Infrastructure failures can never be counted as semantic evidence: a
 * missing thread/event or a wait timeout leaves workers alive that still
 * reference caller-stack state. Terminate BEFORE any cleanup or stack return. */
static void fatal_infra(const char *what) {
    printf("FATAL: %s (infrastructure, not semantic evidence)\n", what);
    fflush(stdout);
    ExitProcess(1);
}
static void need(int cond, const char *what) {
    if (!cond) fatal_infra(what);
}

typedef struct {
    AotRuntime rt;
    AotGuestState st;
} Ctx;

static uint64_t ga(uint64_t off) { return GB + off; }

static int scenario_open(void) {
    memset(g_arena, 0, sizeof(g_arena));
    g_dom = aot_mem_domain_create();
    if (g_dom == NULL) return 0;
    return aot_mem_init(&g_mem, g_dom, g_arena, sizeof(g_arena), GB) == AOT_MEM_OK;
}
static void scenario_close(void) { aot_mem_domain_destroy(g_dom); }

static int ctx_init(Ctx *c, const AotImage *img) {
    memset(c, 0, sizeof(*c));
    c->st.sp = GB + 0x800ull;
    c->st.x[30] = 0ull;
    return aot_rt_init(&c->rt, img, g_mem, &c->st, 1000000ull) == AOT_FAULT_NONE;
}

static AotExit run_raw(Ctx *c, uint64_t pc) {
    return aot_rt_run(&c->rt, pc, STOP_PC);
}

static int run_ok(Ctx *c, uint64_t pc, const char *label) {
    AotExit e = run_raw(c, pc);
    if (e != AOT_EXIT_STOP) {
        printf("FAIL: %s exit=%u fault=%u src=0x%llx target=0x%llx\n",
               label, (unsigned)e, c->rt.fault,
               (unsigned long long)c->rt.fault_src,
               (unsigned long long)c->rt.fault_target);
        g_fail = 1;
        return 0;
    }
    return 1;
}

static void mem64(uint64_t off, uint64_t *out) {
    if (aot_mem_ld64(&g_mem, ga(off), out) != AOT_MEM_OK) { *out = 0xFFFFFFFFFFFFFFFFull; }
}
static void set64(uint64_t off, uint64_t v) {
    CHECK(aot_mem_st64(&g_mem, ga(off), v) == AOT_MEM_OK, "set64");
}

/* HLE handler: explicit shared-arena access through its user pointer. */
typedef struct {
    AotMem mem;
    uint64_t addr;
    uint64_t value;
    unsigned width;
    int do_store;
    int calls;
    int status_ok;   /* every aot_mem_* call returned AOT_MEM_OK */
} HleCtx;

static void hle_shared(AotGuestState *s, const AotHleRequest *req, void *user) {
    HleCtx *h = (HleCtx *)user;
    h->calls++;
    h->status_ok = 1;
    if (h->do_store) {
        AotMemStatus st = AOT_MEM_ERR_RANGE;
        switch (h->width) {
        case 1: st = aot_mem_st8(&h->mem, h->addr, (uint8_t)h->value); break;
        case 2: st = aot_mem_st16(&h->mem, h->addr, (uint16_t)h->value); break;
        case 4: st = aot_mem_st32(&h->mem, h->addr, (uint32_t)h->value); break;
        default: st = aot_mem_st64(&h->mem, h->addr, h->value); break;
        }
        if (st != AOT_MEM_OK) h->status_ok = 0;
    } else {
        uint64_t v = 0;
        if (aot_mem_ld64(&h->mem, h->addr, &v) != AOT_MEM_OK) h->status_ok = 0;
    }
    (void)s;
    (void)req;
}
static void hle_noop(AotGuestState *s, const AotHleRequest *req, void *user) {
    (void)s; (void)req; (void)user;
}

/* ---- deterministic schedules ---- */
static void test_baseline_and_races(void) {
    need(scenario_open(), "baseline scenario open");
    Ctx a, b;
    need(ctx_init(&a, &aot_image_conc), "baseline init A");
    need(ctx_init(&b, &aot_image_conc), "baseline init B");

    /* Success baseline, split across two run sentinels: the monitor must
     * survive RET/STOP. */
    set64(0x100, 0x1111111111111111ull);
    a.st.x[0] = ga(0x100);
    run_ok(&a, 0x1000, "ldx baseline");
    CHECK(a.st.x[1] == 0x1111111111111111ull, "LDXR loaded baseline value");
    a.st.x[2] = 0xFFFFFFFFDEADBEEFull;   /* upper half must be zero-extended */
    a.st.x[1] = 0xAAAAAAAAAAAAAAAAull;
    run_ok(&a, 0x1010, "stx baseline");
    uint64_t v = 0;
    mem64(0x100, &v);
    CHECK(a.st.x[2] == 0ull, "STXR success status zero-extended");
    CHECK(v == 0xAAAAAAAAAAAAAAAAull, "STXR success wrote value");

    /* Reservation persists across a run boundary, then is consumed. */
    set64(0x108, 0x2222222222222222ull);
    a.st.x[0] = ga(0x108);
    run_ok(&a, 0x1000, "ldx sentinel persistence");
    a.st.x[1] = 0xBBBBBBBBBBBBBBBBull;
    a.st.x[2] = 0xFFFFFFFFFFFFFFFFull;
    run_ok(&a, 0x1010, "stx after sentinel");
    mem64(0x108, &v);
    CHECK(a.st.x[2] == 0ull && v == 0xBBBBBBBBBBBBBBBBull,
          "RET/STOP sentinel preserves reservation");

    /* Both runtimes reserve; first STXR wins, second fails with no write. */
    set64(0x110, 0x3333333333333333ull);
    a.st.x[0] = ga(0x110); b.st.x[0] = ga(0x110);
    run_ok(&a, 0x1000, "both reserve A");
    run_ok(&b, 0x1000, "both reserve B");
    a.st.x[1] = 0x4444444444444444ull; a.st.x[2] = 0xEE;
    run_ok(&a, 0x1010, "winner A");
    b.st.x[1] = 0x5555555555555555ull; b.st.x[2] = 0xFFFFFFFFFFFFFFFFull;
    run_ok(&b, 0x1010, "loser B");
    mem64(0x110, &v);
    CHECK(a.st.x[2] == 0ull && b.st.x[2] == 1ull, "one winner / one loser status");
    CHECK(v == 0x4444444444444444ull, "loser STXR wrote nothing");

    /* Missing reservation + failure/reuse. */
    run_ok(&a, 0x1050, "clrex before missing");
    a.st.x[0] = ga(0x118); a.st.x[1] = 0x6666; a.st.x[2] = 0xFFFFFFFFFFFFFFFFull;
    run_ok(&a, 0x1010, "stx without reservation");
    CHECK(a.st.x[2] == 1ull, "missing reservation fails, W status zero-extended to full 64");
    a.st.x[2] = 0xFFFFFFFFFFFFFFFFull;
    run_ok(&a, 0x1000, "re-arm");
    a.st.x[1] = 0x7777; run_ok(&a, 0x1010, "retry after failure");
    CHECK(a.st.x[2] == 0ull, "reservation can be reused after failure");

    /* Address mismatch: reserve 0x120, store at 0x128. */
    set64(0x120, 0x8888); set64(0x128, 0x9999);
    a.st.x[0] = ga(0x120); run_ok(&a, 0x1000, "arm addr mismatch");
    a.st.x[0] = ga(0x128); a.st.x[1] = 0xDEAD; a.st.x[2] = 0xFFFFFFFFFFFFFFFFull;
    run_ok(&a, 0x1010, "stx addr mismatch");
    mem64(0x128, &v);
    CHECK(a.st.x[2] == 1ull && v == 0x9999ull,
          "address mismatch fails without write, status zero-extended");

    /* Width mismatch: reserve X at 0x130, issue word STXR at same address. */
    set64(0x130, 0x12345678ABCDEF01ull);
    a.st.x[0] = ga(0x130); run_ok(&a, 0x1000, "arm width mismatch");
    a.st.x[1] = 0xFFFF0000FFFF0000ull; a.st.x[2] = 0xFFFFFFFFFFFFFFFFull;
    run_ok(&a, 0x10e0, "stx width mismatch");
    mem64(0x130, &v);
    CHECK(a.st.x[2] == 1ull && v == 0x12345678ABCDEF01ull,
          "width mismatch fails without write, status zero-extended");

    /* Same-value ordinary store from the OTHER runtime invalidates (ABA).
     * A value-based monitor would wrongly keep the reservation. */
    set64(0x138, 0xAABBCCDDEEFF0011ull);
    a.st.x[0] = ga(0x138); run_ok(&a, 0x1000, "arm same-value");
    b.st.x[0] = ga(0x138); b.st.x[1] = 0xAABBCCDDEEFF0011ull;
    run_ok(&b, 0x1020, "OTHER runtime str same value");
    a.st.x[1] = 0x1234; a.st.x[2] = 0xFFFFFFFFFFFFFFFFull; run_ok(&a, 0x1010, "stx after same-value");
    CHECK(a.st.x[2] == 1ull, "same-value ordinary store disarms");

    /* Changed-then-original ABA, both stores from the OTHER runtime. */
    set64(0x140, 0xAA00AA00AA00AA00ull);
    a.st.x[0] = ga(0x140); run_ok(&a, 0x1000, "arm ABA");
    b.st.x[0] = ga(0x140);
    b.st.x[1] = 0xBB00BB00BB00BB00ull; run_ok(&b, 0x1020, "OTHER runtime ABA changed");
    b.st.x[1] = 0xAA00AA00AA00AA00ull; run_ok(&b, 0x1020, "OTHER runtime ABA original");
    a.st.x[1] = 0x5555; a.st.x[2] = 0xFFFFFFFFFFFFFFFFull; run_ok(&a, 0x1010, "stx after ABA");
    CHECK(a.st.x[2] == 1ull, "changed-then-original store disarms");

    /* Ordered store invalidation (other runtime's STLR). */
    set64(0x148, 0x1111);
    a.st.x[0] = ga(0x148); run_ok(&a, 0x1000, "arm ordered");
    b.st.x[0] = ga(0x148); b.st.x[1] = 0x2222;
    run_ok(&b, 0x1040, "OTHER runtime stlr invalidation");
    a.st.x[1] = 0x3333; a.st.x[2] = 0xFFFFFFFFFFFFFFFFull; run_ok(&a, 0x1010, "stx after stlr");
    CHECK(a.st.x[2] == 1ull, "STLR invalidates reservation");

    /* Same 64-byte granule neighbour vs different granule. */
    set64(0x180, 0x1000); set64(0x188, 0x2000); set64(0x1C0, 0x3000);
    a.st.x[0] = ga(0x180); run_ok(&a, 0x1000, "arm same-granule neighbour");
    b.st.x[0] = ga(0x188); b.st.x[1] = 0xDEAD; run_ok(&b, 0x1020, "neighbour store");
    a.st.x[1] = 0x9999; a.st.x[2] = 0xFFFFFFFFFFFFFFFFull; run_ok(&a, 0x1010, "stx after neighbour");
    CHECK(a.st.x[2] == 1ull, "same-granule neighbour invalidates");

    a.st.x[0] = ga(0x180); run_ok(&a, 0x1000, "arm different-granule");
    b.st.x[0] = ga(0x1C0); b.st.x[1] = 0xBEEF; run_ok(&b, 0x1020, "different-granule store");
    a.st.x[1] = 0x7777; a.st.x[2] = 0xFFFFFFFFFFFFFFFFull; run_ok(&a, 0x1010, "stx after different granule");
    CHECK(a.st.x[2] == 0ull, "different granule preserves reservation");

    /* Local CLREX. */
    a.st.x[0] = ga(0x180); run_ok(&a, 0x1000, "arm before clrex");
    run_ok(&a, 0x1050, "translated clrex");
    a.st.x[2] = 0xEE; run_ok(&a, 0x1010, "stx after clrex");
    CHECK(a.st.x[2] == 1ull, "translated CLREX clears local monitor");

    aot_rt_release(&a.rt);
    aot_rt_release(&b.rt);
    scenario_close();
}

static void test_hle_and_ordered(void) {
    need(scenario_open(), "HLE scenario open");
    Ctx a, b;
    need(ctx_init(&a, &aot_image_conc), "HLE init A");
    need(ctx_init(&b, &aot_image_conc), "HLE init B");
    HleCtx h;
    memset(&h, 0, sizeof(h));
    h.mem = g_mem;

    uint64_t v = 0;
    set64(0x200, 0x1234);

    /* Read-only HLE on B must NOT invalidate A (B's boundary clear is local). */
    h.addr = ga(0x200); h.do_store = 0; h.calls = 0;
    CHECK(aot_rt_set_handler(&b.rt, AOT_HLE_SVC, 0x40, hle_shared, &h) == 0,
          "B read-only handler");
    a.st.x[0] = ga(0x200); run_ok(&a, 0x1000, "arm before read-only HLE");
    run_ok(&b, 0x1060, "B svc read-only");
    a.st.x[1] = 0x5555; a.st.x[2] = 0xEE; run_ok(&a, 0x1010, "stx after read HLE");
    CHECK(h.calls == 1 && h.status_ok && a.st.x[2] == 0ull,
          "read-only HLE on another runtime preserves A reservation");

    /* Store through B's handler user AotMem* invalidates A. */
    h.do_store = 1; h.width = 8; h.value = 0x9999; h.calls = 0;
    a.st.x[0] = ga(0x200); run_ok(&a, 0x1000, "arm before HLE store");
    run_ok(&b, 0x1060, "B svc store");
    a.st.x[1] = 0x6666; a.st.x[2] = 0xEE; run_ok(&a, 0x1010, "stx after HLE store");
    mem64(0x200, &v);
    CHECK(h.calls == 1 && h.status_ok && a.st.x[2] == 1ull && v == 0x9999ull,
          "HLE store through aot_mem_* invalidates A reservation");

    /* Local SVC boundary clear. */
    a.st.x[0] = ga(0x208); run_ok(&a, 0x1000, "arm before local svc");
    CHECK(aot_rt_set_handler(&a.rt, AOT_HLE_SVC, 0x40, hle_noop, NULL) == 0,
          "A noop handler");
    run_ok(&a, 0x1060, "A local svc");
    a.st.x[2] = 0xEE; run_ok(&a, 0x1010, "stx after local svc");
    CHECK(a.st.x[2] == 1ull, "translated SVC clears local monitor");

    /* Local HOSTCALL boundary clear. */
    a.st.x[0] = ga(0x210); run_ok(&a, 0x1000, "arm before hostcall");
    CHECK(aot_rt_set_handler(&a.rt, AOT_HLE_HOSTCALL, 0, hle_noop, NULL) == 0,
          "A hostcall handler");
    a.st.x[9] = 0x2000ull;   /* thunk base */
    run_ok(&a, 0x1070, "A blr hostcall");
    a.st.x[2] = 0xEE; run_ok(&a, 0x1010, "stx after hostcall");
    CHECK(a.st.x[2] == 1ull, "translated HOSTCALL clears local monitor");

    aot_rt_release(&a.rt);
    aot_rt_release(&b.rt);
    scenario_close();
}

static void test_shapes(void) {
    need(scenario_open(), "shape scenario open");
    Ctx a;
    need(ctx_init(&a, &aot_image_conc), "shape init");
    const uint64_t offs[4] = { 0x240, 0x248, 0x250, 0x258 };
    const unsigned widths[4] = { 1, 2, 4, 8 };
    const uint64_t ldx_pc[4] = { 0x1090, 0x10b0, 0x10d0, 0x1000 };
    const uint64_t stx_pc[4] = { 0x10A0, 0x10C0, 0x10E0, 0x1010 };
    const uint64_t values[4] = { 0xA5, 0xBEEF, 0xDEADBEEF, 0x1122334455667788ull };

    for (int i = 0; i < 4; i++) {
        set64(offs[i], 0);
        a.st.x[0] = ga(offs[i]);
        if (!run_ok(&a, ldx_pc[i], "shape ldx")) continue;
        a.st.x[1] = values[i]; a.st.x[2] = 0xFFFFFFFFFFFFFFFFull;
        if (!run_ok(&a, stx_pc[i], "shape stx")) continue;
        uint64_t got = 0;
        if (aot_mem_ld64(&g_mem, ga(offs[i]), &got) != AOT_MEM_OK) got = ~0ull;
        uint64_t mask = (widths[i] == 8) ? ~0ull : ((1ull << (8u * widths[i])) - 1ull);
        CHECK(a.st.x[2] == 0ull && got == (values[i] & mask),
              "translated byte/half/word/X exclusive success");
    }

    /* Cross-width failure: X reservation, word STXR. */
    a.st.x[0] = ga(0x260); run_ok(&a, 0x1000, "shape cross-width arm");
    a.st.x[1] = 0xFFFFFFFFFFFFFFFFull; a.st.x[2] = 0xFFFFFFFFFFFFFFFFull;
    run_ok(&a, 0x10E0, "shape cross-width stx");
    CHECK(a.st.x[2] == 1ull, "X reservation rejected by word STXR");

    /* LDAXR/STLXR acquire/release pair. */
    set64(0x268, 0);
    a.st.x[0] = ga(0x268); run_ok(&a, 0x1160, "ldaxr");
    a.st.x[1] = 0xCAFEBABEull; a.st.x[2] = 0xFFFFFFFFFFFFFFFFull;
    run_ok(&a, 0x1170, "stlxr");
    uint64_t v = 0; mem64(0x268, &v);
    CHECK(a.st.x[2] == 0ull && v == 0xCAFEBABEull, "LDAXR/STLXR pair succeeds");

    aot_rt_release(&a.rt);
    scenario_close();
}

/* ---- real-thread counter stress (positive only) ---- */
typedef struct {
    Ctx c;
    uint64_t iters;
    int ok;
    HANDLE start;   /* shared manual-reset event: all workers begin together */
} ThreadArg;

static DWORD WINAPI counter_thread(LPVOID p) {
    ThreadArg *t = (ThreadArg *)p;
    /* A wait failure here happens AFTER other workers may be running, so it
     * must terminate the process, never return through a shared stack frame. */
    if (WaitForSingleObject(t->start, 60000) != WAIT_OBJECT_0)
        fatal_infra("counter start event wait");
    t->ok = 1;
    for (uint64_t i = 0; i < t->iters; i++) {
        if (run_raw(&t->c, 0x1100) != AOT_EXIT_STOP) { t->ok = 0; break; }
    }
    return 0;
}

static int counter_stress(int nthreads, uint64_t iters) {
    ThreadArg args[4];
    HANDLE th[4];
    need(scenario_open(), "counter scenario open");
    set64(0x300, 0);
    HANDLE start = CreateEventW(NULL, TRUE, FALSE, NULL);
    need(start != NULL, "counter start event create");
    for (int i = 0; i < nthreads; i++) {
        memset(&args[i], 0, sizeof(args[i]));
        need(ctx_init(&args[i].c, &aot_image_conc), "counter ctx init");
        args[i].c.st.x[0] = ga(0x300);
        args[i].iters = iters;
        args[i].start = start;
        th[i] = CreateThread(NULL, 0, counter_thread, &args[i], 0, NULL);
        /* FATAL before returning: earlier workers are already live and point
         * at this stack frame. */
        need(th[i] != NULL, "counter thread create");
    }
    need(SetEvent(start) != 0, "counter start event set");
    need(WaitForMultipleObjects((DWORD)nthreads, th, TRUE, 60000) == WAIT_OBJECT_0,
         "counter worker join (timeout with live workers is not evidence)");
    for (int i = 0; i < nthreads; i++) {
        need(CloseHandle(th[i]) != 0, "counter thread handle close");
        /* All workers have joined, so no stack frame is live any more: a worker
         * run failure is a semantic FAIL, not an infrastructure termination. */
        CHECK(args[i].ok, "translated counter worker run failure");
    }
    need(CloseHandle(start) != 0, "counter start event close");
    uint64_t v = 0;
    mem64(0x300, &v);
    int ok = (v == (uint64_t)nthreads * iters);
    if (!ok) printf("FAIL: counter %d x %llu got %llu\n", nthreads,
                    (unsigned long long)iters, (unsigned long long)v);
    for (int i = 0; i < nthreads; i++) aot_rt_release(&args[i].c.rt);
    scenario_close();
    return ok;
}

/* Shared publication invariant: the flag announces exactly the payload that
 * must be visible to an acquire reader. Used by BOTH the positive reader and
 * the wrong-PROGRAM-order control so the negative test targets the same
 * invariant rather than an unrelated stale-value assertion. */
static int publication_valid(uint64_t flag, uint64_t payload, uint64_t announced) {
    return flag == 1ull && payload == announced;
}

/* One-way per-slot publication (NOT a handshake: the reader never acks).
 * ---- acquire/release publication ---- */
typedef struct {
    Ctx c;
    int rounds;
    int ok;
    int timeout;
    HANDLE start;
} PubArg;

static DWORD WINAPI pub_writer(LPVOID p) {
    PubArg *w = (PubArg *)p;
    if (WaitForSingleObject(w->start, 60000) != WAIT_OBJECT_0)
        fatal_infra("publication writer start event");
    w->ok = 1;
    for (int i = 0; i < w->rounds; i++) {
        w->c.st.x[0] = ga(0x400u + (uint64_t)i * 8u);
        w->c.st.x[1] = 0x1000ull + (uint64_t)i;
        if (run_raw(&w->c, 0x1120) != AOT_EXIT_STOP) { w->ok = 0; return 0; }
        w->c.st.x[0] = ga(0x800u + (uint64_t)i * 8u);
        w->c.st.x[1] = 1ull;
        if (run_raw(&w->c, 0x1130) != AOT_EXIT_STOP) { w->ok = 0; return 0; }
    }
    return 0;
}

static DWORD WINAPI pub_reader(LPVOID p) {
    PubArg *r = (PubArg *)p;
    if (WaitForSingleObject(r->start, 60000) != WAIT_OBJECT_0)
        fatal_infra("publication reader start event");
    r->ok = 1;
    for (int i = 0; i < r->rounds; i++) {
        uint64_t flag = 0, payload = 0;
        int waited = 0;
        do {
            r->c.st.x[0] = ga(0x800u + (uint64_t)i * 8u);
            if (run_raw(&r->c, 0x1140) != AOT_EXIT_STOP) { r->ok = 0; return 0; }
            flag = r->c.st.x[1];
            if (flag == 1ull) break;
            if (++waited > 200000) {
                /* Poll limit = infrastructure (no forward progress), never
                 * evidence of a rejected negative: terminate the process while
                 * the writer may still be live. */
                fatal_infra("publication reader poll limit exceeded");
            }
            SwitchToThread();
        } while (1);
        r->c.st.x[0] = ga(0x400u + (uint64_t)i * 8u);
        if (run_raw(&r->c, 0x1150) != AOT_EXIT_STOP) { r->ok = 0; return 0; }
        payload = r->c.st.x[1];
        if (!publication_valid(flag, payload, 0x1000ull + (uint64_t)i)) {
            r->ok = 0;
            return 0;
        }
    }
    return 0;
}

/* One-way per-slot publication is NOT a handshake: the reader never
 * acknowledges, so this is positive stress evidence only. Any infrastructure
 * failure is FATAL while workers can still reference these stack frames; the
 * domain/runtime teardown below only runs after a successful join. */
static void publication_per_slot_oneway(int rounds) {
    PubArg w, r;
    need(scenario_open(), "publication scenario open");
    memset(&w, 0, sizeof(w)); memset(&r, 0, sizeof(r));
    need(ctx_init(&w.c, &aot_image_conc), "publication writer init");
    need(ctx_init(&r.c, &aot_image_conc), "publication reader init");
    w.rounds = r.rounds = rounds;
    HANDLE start = CreateEventW(NULL, TRUE, FALSE, NULL);
    need(start != NULL, "publication start event create");
    w.start = r.start = start;
    HANDLE tw = CreateThread(NULL, 0, pub_writer, &w, 0, NULL);
    need(tw != NULL, "publication writer thread create");
    HANDLE tr = CreateThread(NULL, 0, pub_reader, &r, 0, NULL);
    need(tr != NULL, "publication reader thread create");
    need(SetEvent(start) != 0, "publication start event set");
    HANDLE hs[2] = { tw, tr };
    need(WaitForMultipleObjects(2, hs, TRUE, 60000) == WAIT_OBJECT_0,
         "publication worker join (timeout with live workers is not evidence)");
    need(CloseHandle(tw) != 0, "publication writer handle close");
    need(CloseHandle(tr) != 0, "publication reader handle close");
    need(CloseHandle(start) != 0, "publication start event close");
    if (!w.ok || !r.ok) {
        printf("FAIL: publication writer_ok=%d reader_ok=%d timeout=%d\n",
               w.ok, r.ok, r.timeout);
        g_fail = 1;
    }
    aot_rt_release(&w.c.rt); aot_rt_release(&r.c.rt);
    scenario_close();
}

/* Wrong PROGRAM order control: flag released before payload. At the controlled
 * split a reader observes flag=1 with the old payload. This is NOT evidence
 * that removing a barrier from a correct program must fail. */
static void test_wrong_program_order(void) {
    need(scenario_open(), "wrong-order scenario open");
    Ctx w, r;
    need(ctx_init(&w, &aot_image_conc), "wrong-order writer");
    need(ctx_init(&r, &aot_image_conc), "wrong-order reader");
    set64(0x400, 0xAAAAAAAAAAAAAAAAull);
    set64(0x800, 0);

    w.st.x[0] = ga(0x800); w.st.x[1] = 1; run_ok(&w, 0x1130, "flag first");
    r.st.x[0] = ga(0x800); run_ok(&r, 0x1140, "reader sees flag");
    uint64_t flag_seen = r.st.x[1];
    CHECK(flag_seen == 1ull, "wrong-order control flag visible");
    r.st.x[0] = ga(0x400); run_ok(&r, 0x1150, "reader stale payload");
    /* Same invariant as the positive case: announced value vs payload. */
    CHECK(!publication_valid(flag_seen, r.st.x[1], 0xBBBBBBBBBBBBBBBBull),
          "wrong-order control violates publication_valid at controlled split");
    w.st.x[0] = ga(0x400); w.st.x[1] = 0xBBBBBBBBBBBBBBBBull;
    run_ok(&w, 0x1120, "payload after flag");
    r.st.x[0] = ga(0x400); run_ok(&r, 0x1150, "reader fresh payload");
    CHECK(publication_valid(flag_seen, r.st.x[1], 0xBBBBBBBBBBBBBBBBull),
          "wrong-order control satisfies publication_valid after payload lands");

    aot_rt_release(&w.rt); aot_rt_release(&r.rt);
    scenario_close();
}

/* Deterministic negative control: the stxalwaysok image reports success after
 * a failed helper. Same schedule, no race/timeout; only the status differs. */
static void test_mutant_control(void) {
    need(scenario_open(), "mutant scenario open");
    Ctx n, m;
    need(ctx_init(&n, &aot_image_conc), "normal init for mutant control");
    need(ctx_init(&m, &aot_image_conc_mut), "mutant init");
    set64(0x500, 0x12345678);
    n.st.x[0] = ga(0x500); run_ok(&n, 0x1050, "normal clrex");
    m.st.x[0] = ga(0x500); run_ok(&m, 0x1050, "mutant clrex");
    n.st.x[1] = 0xAAAA; n.st.x[2] = 0xEE; run_ok(&n, 0x1010, "normal missing stx");
    m.st.x[1] = 0xBBBB; m.st.x[2] = 0xEE; run_ok(&m, 0x1010, "mutant missing stx");
    uint64_t vn = 0, vm = 0;
    mem64(0x500, &vn); mem64(0x500, &vm);
    CHECK(n.st.x[2] == 1ull && vn == 0x12345678ull, "normal no-reservation status/no-write");
    CHECK(m.st.x[2] == 0ull && vm == 0x12345678ull,
          "stxalwaysok control deterministically reaches wrong success status");
    aot_rt_release(&n.rt); aot_rt_release(&m.rt);
    scenario_close();
}

int main(void) {
    test_baseline_and_races();
    test_hle_and_ordered();
    test_shapes();
    test_wrong_program_order();
    test_mutant_control();
    CHECK(counter_stress(2, 2000), "2-thread translated counter exact");
    CHECK(counter_stress(4, 1000), "4-thread translated counter exact");
    publication_per_slot_oneway(64);
    if (g_fail) { printf("FAIL: aot_concurrency_probe\n"); return 1; }
    printf("PASS: aot_concurrency_probe\n");
    return 0;
}
