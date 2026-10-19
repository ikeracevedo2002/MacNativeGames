/*
 * TEST-ONLY wrong-backend control: "stores do not invalidate reservations".
 *
 * One source, two executables, IDENTICAL deterministic schedule and IDENTICAL
 * explicit expected constraints:
 *
 *   aot_conc_control_real   -- links the shipping aot_mem.c. Must OBSERVE the
 *                              constraint hold  (STXR fails, data unchanged).
 *   aot_conc_control_noinv  -- links aot_mem.c compiled with
 *                              AOT_MEM_TEST_NO_INVALIDATION. Must OBSERVE the
 *                              constraint violated (STXR succeeds and a value
 *                              is written), i.e. the wrong backend is rejected
 *                              semantically.
 *
 * There are NO threads, sleeps, retries or timeouts: the schedule is two
 * deterministic runtimes over one domain, each translated call required to
 * return STOP with fault == AOT_FAULT_NONE. Any fault/inconsistency is a
 * FATAL/FATAL-style failure of the test, never a "rejection".
 */
#include "aot_runtime.h"

#include <stdio.h>
#include <string.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

extern const AotImage aot_image_conc;

#define GB          0x100000ull
#define ARENA_SIZE  0x1000u

static int g_fail = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", msg); g_fail = 1; } \
} while (0)

static AotMemDomain *g_dom;
static uint8_t g_arena[ARENA_SIZE];
static AotMem g_mem;

static uint64_t ga(uint64_t off) { return GB + off; }

/* ---- THE shared explicit constraint (same one the positive suite asserts):
 * after another runtime performed an ordinary store to the reserved 64-byte
 * granule, a translated STXR at the reserved address must FAIL (status 1,
 * full 64-bit) and must NOT write. */
static int invalidation_constraint(uint64_t status, uint64_t memory, uint64_t original) {
    return status == 1ull && memory == original;
}

typedef struct { AotRuntime rt; AotGuestState st; } Ctx;

static void fatal(const char *what) {
    printf("FATAL: %s (infrastructure, not semantic rejection)\n", what);
    fflush(stdout);
    ExitProcess(1);
}

static void need(int cond, const char *what) {
    if (!cond) fatal(what);
}

static void scenario_open(void) {
    memset(g_arena, 0, sizeof(g_arena));
    g_dom = aot_mem_domain_create();
    need(g_dom != NULL, "domain create");
    need(aot_mem_init(&g_mem, g_dom, g_arena, sizeof(g_arena), GB) == AOT_MEM_OK,
         "arena init");
}

static void ctx_init(Ctx *c, const char *what) {
    memset(c, 0, sizeof(*c));
    c->st.sp = GB + 0x800ull;
    need(aot_rt_init(&c->rt, &aot_image_conc, g_mem, &c->st, 1000000ull)
         == AOT_FAULT_NONE, what);
}

/* Every translated call must be a clean STOP with no fault. */
static void run_stop(Ctx *c, uint64_t pc, const char *label) {
    AotExit e = aot_rt_run(&c->rt, pc, 0ull);
    if (e != AOT_EXIT_STOP || c->rt.fault != AOT_FAULT_NONE) {
        printf("FATAL: %s exit=%u fault=%u\n", label, (unsigned)e,
               (unsigned)c->rt.fault);
        fflush(stdout);
        ExitProcess(1);
    }
}

static void set64(uint64_t off, uint64_t v) {
    need(aot_mem_st64(&g_mem, ga(off), v) == AOT_MEM_OK, "set64");
}
static uint64_t get64(uint64_t off) {
    uint64_t v = 0;
    need(aot_mem_ld64(&g_mem, ga(off), &v) == AOT_MEM_OK, "get64");
    return v;
}

/* One deterministic case: A reserves at off, B (the OTHER runtime) performs an
 * ordinary same-granule store, A issues a translated STXR with high status
 * bits pre-seeded. Returns 1 if the explicit constraint holds. */
typedef struct {
    int hold_same_value;
    int hold_aba;
    int baseline_ok;
} Observed;

static Observed observe(void) {
    Observed r;
    Ctx a, b;
    ctx_init(&a, "control runtime A init");
    ctx_init(&b, "control runtime B init");

    /* Positive control: with NO intervening store the pair must succeed, in
     * BOTH backends. This keeps the control about invalidation specifically. */
    set64(0x100, 0ull);
    a.st.x[0] = ga(0x100);
    run_stop(&a, 0x1000, "baseline ldx");
    a.st.x[1] = 0x5A5A5A5A5A5A5A5Aull;
    a.st.x[2] = 0xFFFFFFFFFFFFFFFFull;
    run_stop(&a, 0x1010, "baseline stx");
    r.baseline_ok = (a.st.x[2] == 0ull) &&
                    (get64(0x100) == 0x5A5A5A5A5A5A5A5Aull);

    /* Same-value store from the OTHER runtime. */
    set64(0x108, 0x1111222233334444ull);
    a.st.x[0] = ga(0x108);
    run_stop(&a, 0x1000, "same-value ldx");
    b.st.x[0] = ga(0x108);
    b.st.x[1] = 0x1111222233334444ull;   /* identical value: value-based monitor
                                          * would wrongly keep the reservation */
    run_stop(&b, 0x1020, "other-runtime same-value str");
    a.st.x[1] = 0xDEADDEADDEADDEADull;
    a.st.x[2] = 0xFFFFFFFFFFFFFFFFull;
    run_stop(&a, 0x1010, "stx after same-value");
    r.hold_same_value = invalidation_constraint(a.st.x[2], get64(0x108),
                                               0x1111222233334444ull);

    /* Changed-then-original ABA, both stores from the OTHER runtime. */
    set64(0x110, 0xAB00AB00AB00AB00ull);
    a.st.x[0] = ga(0x110);
    run_stop(&a, 0x1000, "aba ldx");
    b.st.x[0] = ga(0x110);
    b.st.x[1] = 0xCD00CD00CD00CD00ull;
    run_stop(&b, 0x1020, "other-runtime ABA changed");
    b.st.x[1] = 0xAB00AB00AB00AB00ull;
    run_stop(&b, 0x1020, "other-runtime ABA original");
    a.st.x[1] = 0xBEEFBEEFBEEFBEEFull;
    a.st.x[2] = 0xFFFFFFFFFFFFFFFFull;
    run_stop(&a, 0x1010, "stx after ABA");
    r.hold_aba = invalidation_constraint(a.st.x[2], get64(0x110),
                                         0xAB00AB00AB00AB00ull);

    aot_rt_release(&a.rt);
    aot_rt_release(&b.rt);
    return r;
}

int main(int argc, char **argv) {
    int expect_reject = (argc > 1 && strcmp(argv[1], "--expect-reject") == 0);

    scenario_open();
    Observed o = observe();
    aot_mem_domain_destroy(g_dom);

    CHECK(o.baseline_ok, "baseline LDX/STX pair succeeds (control is about invalidation)");

    if (!expect_reject) {
        /* Shipping backend: the explicit constraint must hold. */
        CHECK(o.hold_same_value, "real backend: same-value store disarms reservation");
        CHECK(o.hold_aba, "real backend: changed-then-original store disarms reservation");
        if (g_fail) { printf("FAIL: aot_conc_control_real\n"); return 1; }
        printf("PASS: aot_conc_control_real\n");
        return 0;
    }

    /* Wrong backend: the SAME constraint must be VIOLATED, and the rejection
     * must come from status/data, not from any fault or infrastructure issue. */
    if (o.hold_same_value) {
        printf("FAIL: no-invalidation backend still satisfied the same-value constraint\n");
        g_fail = 1;
    }
    if (o.hold_aba) {
        printf("FAIL: no-invalidation backend still satisfied the ABA constraint\n");
        g_fail = 1;
    }
    if (g_fail) { printf("FAIL: aot_conc_control_noinv\n"); return 1; }
    printf("PASS: aot_conc_control_noinv (wrong backend rejected on status+data)\n");
    return 0;
}
