/*
 * G2 native-only translated FP contract probe.
 *
 * Links the REAL generated differential image (aot_image_diff) and drives the
 * runtime directly. No Unicorn: the pinned oracle masks unsupported FPCR bits
 * and cannot judge these, so the rows are counted separately.
 *
 *   A) 28 unsupported FPCR bits (enumerated from literals outside the
 *      independently specified supported mask 0x03c00000; never from
 *      aot_fp_supported) x 14 numeric sites = 392 fault rows. FPSR seed is
 *      QC-only (0x08000000) so an illicit sticky-flag OR is observable.
 *   B) Bitwise FMOV/FABS/FNEG under FPCR=FPSR=0xffffffff: bitwise results (no
 *      quieting), dirty upper lane zeroed, low-32 ABI fields preserved.
 *   C) Closed-form translated rows with raw-integer expectations, using
 *      full-64 S results (no 32-bit masking), dirty destination vectors and
 *      distinct compare/arithmetic assertions.
 *
 * The byte arena is poisoned before aot_mem_init (ownership precondition), and
 * all non-PC guest fields are seeded nonzero/patterned. Setup and
 * infrastructure failures are FATAL, never counted as semantic evidence.
 */
#include "aot_fp.h"
#include "aot_runtime.h"

#include <stdio.h>
#include <string.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

extern const AotImage aot_image_diff;

#define GB             0x100000ull
#define ARENA_SIZE     0x1000u
#define SUPPORTED_MASK 0x03c00000u   /* RMode(22-23) | FZ(24) | DN(25) */
#define FPSR_QC        0x08000000u

static const uint64_t NUM_SITES[14] = {
    0x1900ull, 0x1920ull, 0x1940ull, 0x1960ull,
    0x1980ull, 0x19A0ull, 0x19C0ull, 0x19E0ull,
    0x1A00ull, 0x1A20ull, 0x1A40ull, 0x1A60ull,
    0x1A80ull, 0x1AA0ull,
};

/* Compare sites never write a destination vector. */
static int is_compare_site(uint64_t pc) {
    return pc == 0x1A00ull || pc == 0x1A20ull || pc == 0x1A40ull ||
           pc == 0x1A60ull || pc == 0x1A80ull || pc == 0x1AA0ull;
}

static int g_fail = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", msg); g_fail = 1; } \
} while (0)

static AotMemDomain *g_dom;
static uint8_t g_arena[ARENA_SIZE];
static AotMem g_mem;
static AotGuestState g_state;

#define V0_LO 0xDEADBEEFCAFEBABEull
#define V0_HI 0xC0FFEEDEADBEEF01ull

static void fatal(const char *what) {
    printf("FATAL: %s (infrastructure; not semantic evidence)\n", what);
    fflush(stdout);
    ExitProcess(1);
}

/* Patterned seed: every field nonzero, operands overridden afterwards, x30=0
 * (RET/STOP sentinel), dirty destination v0 in BOTH 64-bit words. */
static void seed_state(uint32_t fpcr, uint32_t fpsr) {
    memset(&g_state, 0, sizeof(g_state));
    for (int i = 0; i < 31; i++)
        g_state.x[i] = 0x1111000000000000ull + (uint64_t)i * 0x0101010101010101ull;
    g_state.x[30] = 0ull;
    g_state.sp = 0x00007FFF00001230ull;
    g_state.nzcv = 0xA0000000ull;      /* N=1, C=1: valid and patterned */
    g_state.fpcr = fpcr;
    g_state.fpsr = fpsr;
    for (int i = 0; i < 32; i++) {
        g_state.v[i][0] = 0x0102030405060708ull + (uint64_t)i;
        g_state.v[i][1] = 0x8877665544332211ull + (uint64_t)i * 3u;
    }
    g_state.v[0][0] = V0_LO;
    g_state.v[0][1] = V0_HI;
    g_state.tpidr = 0x1234567890ABCDEFull;
    g_state.tpidrro = 0x0FEDCBA098765432ull;
}

/* Equality of every guest field except runtime-owned pc. */
static int state_equal_except_pc(const AotGuestState *a, const AotGuestState *b) {
    if (a->sp != b->sp || a->nzcv != b->nzcv) return 0;
    if (a->fpcr != b->fpcr || a->fpsr != b->fpsr) return 0;
    if (a->tpidr != b->tpidr || a->tpidrro != b->tpidrro) return 0;
    for (int i = 0; i < 31; i++)
        if (a->x[i] != b->x[i]) return 0;
    for (int i = 0; i < 32; i++)
        if (a->v[i][0] != b->v[i][0] || a->v[i][1] != b->v[i][1]) return 0;
    return 1;
}

static AotExit run_one(uint64_t pc, AotRuntime *rt) {
    memset(rt, 0, sizeof(*rt));
    if (aot_rt_init(rt, &aot_image_diff, g_mem, &g_state, 1000ull) != AOT_FAULT_NONE)
        fatal("runtime init");
    return aot_rt_run(rt, pc, 0ull);
}

/* ---- A) unsupported FPCR fault matrix (392) ---- */
static int g_unsupported_cases = 0;

static void test_unsupported_fpcr(void) {
    for (int bit = 0; bit < 32; bit++) {
        uint32_t fpcr = 1u << bit;
        if (fpcr & SUPPORTED_MASK) continue;   /* literal mask, not the helper */
        for (size_t s = 0; s < sizeof(NUM_SITES) / sizeof(NUM_SITES[0]); s++) {
            uint64_t pc = NUM_SITES[s];
            seed_state(fpcr, FPSR_QC);
            g_state.v[1][0] = 0x3F800000ull;
            g_state.v[2][0] = 0x40400000ull;
            AotGuestState before = g_state;

            AotRuntime rt;
            uint64_t arena_before = aot_mem_fnv1a(&g_mem);
            AotExit e = run_one(pc, &rt);
            uint64_t arena_after = aot_mem_fnv1a(&g_mem);

            if (e != AOT_EXIT_FAULT) {
                printf("FAIL: bit%u pc=0x%llx exit=%u (expected FAULT)\n",
                       (unsigned)bit, (unsigned long long)pc, (unsigned)e);
                g_fail = 1;
            } else if (rt.fault != AOT_FAULT_BAD_STATE ||
                       rt.fault_status != AOT_FP_ERR_UNSUPPORTED_FPCR ||
                       rt.fault_src != pc) {
                printf("FAIL: bit%u pc=0x%llx fault=%u status=%lld src=0x%llx\n",
                       (unsigned)bit, (unsigned long long)pc, (unsigned)rt.fault,
                       (long long)rt.fault_status,
                       (unsigned long long)rt.fault_src);
                g_fail = 1;
            } else if (g_state.pc != pc) {
                printf("FAIL: bit%u pc=0x%llx runtime pc=0x%llx\n", (unsigned)bit,
                       (unsigned long long)pc, (unsigned long long)g_state.pc);
                g_fail = 1;
            } else if (!state_equal_except_pc(&before, &g_state)) {
                printf("FAIL: bit%u pc=0x%llx guest state changed on unsupported fault\n",
                       (unsigned)bit, (unsigned long long)pc);
                g_fail = 1;
            } else if (arena_before != arena_after) {
                printf("FAIL: bit%u pc=0x%llx arena changed on unsupported fault\n",
                       (unsigned)bit, (unsigned long long)pc);
                g_fail = 1;
            } else {
                g_unsupported_cases++;
            }
            aot_rt_release(&rt);
        }
    }
    printf("native-only unsupported-FPCR fault rows: %d (expected 392)\n",
           g_unsupported_cases);
    CHECK(g_unsupported_cases == 392, "unsupported-FPCR fault row count");
}

/* ---- B) bitwise unrestricted under FPCR=FPSR=0xffffffff ---- */
static int g_bitwise_cases = 0;

static void run_bitwise(uint64_t pc, uint64_t v1, uint64_t want, const char *label) {
    seed_state(0xffffffffu, 0xffffffffu);
    g_state.v[1][0] = v1;
    AotRuntime rt;
    AotExit e = run_one(pc, &rt);
    if (e != AOT_EXIT_STOP || g_state.v[0][0] != want || g_state.v[0][1] != 0ull ||
        g_state.fpcr != 0xffffffffull || g_state.fpsr != 0xffffffffull) {
        printf("FAIL: %s: exit=%u v0=0x%016llx/0x%016llx (dirty hi was 0x%016llx) "
               "fpcr=0x%llx fpsr=0x%llx\n", label, (unsigned)e,
               (unsigned long long)g_state.v[0][0],
               (unsigned long long)g_state.v[0][1],
               (unsigned long long)V0_HI,
               (unsigned long long)g_state.fpcr, (unsigned long long)g_state.fpsr);
        g_fail = 1;
    } else {
        g_bitwise_cases++;
    }
    aot_rt_release(&rt);
}

static void test_bitwise_unrestricted(void) {
    const uint64_t neg_snan = 0xfff0000000000001ull;
    run_bitwise(0x1500ull, neg_snan, neg_snan, "FMOV_D bitwise, no quieting");
    run_bitwise(0x1520ull, neg_snan, 0x7ff0000000000001ull,
                "FABS_D clears sign without quieting");
    run_bitwise(0x1540ull, neg_snan, 0x7ff0000000000001ull,
                "FNEG_D flips sign without quieting");
    printf("native-only bitwise unrestricted rows: %d (expected 3)\n", g_bitwise_cases);
    CHECK(g_bitwise_cases == 3, "bitwise unrestricted row count");
}

/* ---- C) closed-form translated rows (raw integers, no host FP math) ---- */
static int g_closed_cases = 0;

/* Arithmetic: destination v0 must be written (from dirty), upper 64 zero.
 * S results are checked full 64 bits against a ZERO-EXTENDED 32-bit expected,
 * so bits 63:32 being nonzero would fail. NZCV must stay at the seed. */
static void run_arith(uint64_t pc, uint32_t fpcr, uint64_t v1, uint64_t v2,
                      uint64_t want_x, uint32_t want_fpsr, uint32_t fpsr_seed,
                      const char *label) {
    seed_state(fpcr, fpsr_seed);
    g_state.v[1][0] = v1;
    g_state.v[2][0] = v2;
    AotRuntime rt;
    AotExit e = run_one(pc, &rt);
    int ok = (e == AOT_EXIT_STOP) && g_state.v[0][0] == want_x &&
             g_state.v[0][1] == 0ull && g_state.fpsr == (uint64_t)want_fpsr &&
             g_state.fpcr == (uint64_t)fpcr && g_state.nzcv == 0xA0000000ull;
    if (!ok) {
        printf("FAIL: %s: exit=%u v0=0x%016llx/0x%016llx want 0x%016llx fpsr=0x%llx "
               "fpcr=0x%llx nzcv=0x%llx\n", label, (unsigned)e,
               (unsigned long long)g_state.v[0][0],
               (unsigned long long)g_state.v[0][1],
               (unsigned long long)want_x, (unsigned long long)g_state.fpsr,
               (unsigned long long)g_state.fpcr, (unsigned long long)g_state.nzcv);
        g_fail = 1;
    } else {
        g_closed_cases++;
    }
    aot_rt_release(&rt);
}

/* Compare: FP compare instructions must NOT write v0 (dirty stays intact). */
static void run_compare(uint64_t pc, uint32_t fpcr, uint64_t v1,
                        uint64_t want_nzcv, uint32_t want_fpsr, const char *label) {
    seed_state(fpcr, 0u);
    g_state.v[1][0] = v1;
    AotRuntime rt;
    AotExit e = run_one(pc, &rt);
    int ok = (e == AOT_EXIT_STOP) && g_state.v[0][0] == V0_LO &&
             g_state.v[0][1] == V0_HI && g_state.nzcv == want_nzcv &&
             g_state.fpsr == (uint64_t)want_fpsr &&
             g_state.fpcr == (uint64_t)fpcr;
    if (!ok) {
        printf("FAIL: %s: exit=%u v0=0x%016llx/0x%016llx nzcv=0x%llx want 0x%llx "
               "fpsr=0x%llx want 0x%x fpcr=0x%llx\n", label, (unsigned)e,
               (unsigned long long)g_state.v[0][0],
               (unsigned long long)g_state.v[0][1],
               (unsigned long long)g_state.nzcv, (unsigned long long)want_nzcv,
               (unsigned long long)g_state.fpsr, want_fpsr,
               (unsigned long long)g_state.fpcr);
        g_fail = 1;
    } else {
        g_closed_cases++;
    }
    aot_rt_release(&rt);
}

static void test_closed_form_translated(void) {
    /* S 1/3 RP/RM and -1/3 RM; IXC; full-64 compare vs zero-extended expected. */
    run_arith(0x19E0ull, 0x00400000u, 0x3F800000ull, 0x40400000ull,
              0x000000003EAAAAABull, 0x10u, 0u, "S 1/3 RP");
    run_arith(0x19E0ull, 0x00800000u, 0x3F800000ull, 0x40400000ull,
              0x000000003EAAAAAAull, 0x10u, 0u, "S 1/3 RM");
    run_arith(0x19E0ull, 0x00800000u, 0xBF800000ull, 0x40400000ull,
              0x00000000BEAAAAABull, 0x10u, 0u, "S -1/3 RM");
    /* Sticky seed QC|IOC must survive and the new IXC must OR in: 0x08000011. */
    run_arith(0x19E0ull, 0x00800000u, 0x3F800000ull, 0x40400000ull,
              0x000000003EAAAAAAull, 0x08000011u, 0x08000001u,
              "S 1/3 RM sticky QC|IOC");
    /* S minnormal*0.5 with FZ -> +0 with UFC only. */
    run_arith(0x19C0ull, 0x01000000u, 0x00800000ull, 0x3F000000ull,
              0x0000000000000000ull, 0x08u, 0u, "S minnorm*.5 FZ");
    /* D minnormal*(1-ulp): gradual -> minnormal, UFC|IXC; FZ -> zero, UFC. */
    run_arith(0x1940ull, 0x00000000u, 0x0010000000000000ull,
              0x3FEFFFFFFFFFFFFFull, 0x0010000000000000ull, 0x18u, 0u,
              "D minnorm*(1-ulp) RN");
    run_arith(0x1940ull, 0x01000000u, 0x0010000000000000ull,
              0x3FEFFFFFFFFFFFFFull, 0x0000000000000000ull, 0x08u, 0u,
              "D minnorm*(1-ulp) FZ");
    /* S qNaN + sNaN: quieted sNaN wins, IOC. */
    run_arith(0x1980ull, 0x00000000u, 0x7FC00002ull, 0x7F800001ull,
              0x000000007FC00001ull, 0x01u, 0u, "S qNaN+sNaN");
    /* S 1.0 - (-qNaN): NaN sign unchanged, no flags. */
    run_arith(0x19A0ull, 0x00000000u, 0x3F800000ull, 0xFFC00002ull,
              0x00000000FFC00002ull, 0x00u, 0u, "S sub negative qNaN sign");
    /* FCMPE S denormal vs 0 with FZ: EQ, IDC only, destination untouched. */
    run_compare(0x1AA0ull, 0x01000000u, 0x00000001ull,
                0x60000000ull, 0x80u, "FCMPE FZ denorm vs 0");
    printf("native-only closed-form translated rows: %d (expected 10)\n",
           g_closed_cases);
    CHECK(g_closed_cases == 10, "closed-form translated row count");
}

/* ---- D) guard-reject mode: observe the fpignoreguard mutant image ---- */
/*
 * --expect-guard-reject is only meaningful for the fpignoreguard mutant image:
 * the mutant replaces the unsupported-FPCR FAULT with `s->fpcr = 0` and runs
 * the helper. The normal image must still FAULT with the exact contract,
 * which this mode reports as a failure (it is a cross-check). Any other fault
 * code, crash or unexpected exit is infrastructure, never a pass.
 */
static int test_guard_reject_mode(void) {
    const uint32_t bad_fpcr = 1u << 13;      /* outside the supported mask */
    const uint64_t pc = 0x1980ull;           /* FADD_S */
    seed_state(bad_fpcr, FPSR_QC);
    g_state.v[1][0] = 0x7FC00002ull;
    g_state.v[2][0] = 0x7FC00003ull;
    AotGuestState before = g_state;
    AotRuntime rt;
    AotExit e = run_one(pc, &rt);
    int rc;
    if (e == AOT_EXIT_FAULT) {
        int proper = rt.fault == AOT_FAULT_BAD_STATE &&
                     rt.fault_status == AOT_FP_ERR_UNSUPPORTED_FPCR &&
                     rt.fault_src == pc && g_state.pc == pc &&
                     state_equal_except_pc(&before, &g_state);
        if (proper) {
            printf("FAIL: guard mode: image correctly rejected the unsupported "
                   "FPCR; this mode requires the fpignoreguard image\n");
        } else {
            printf("FAIL: guard mode: FAULT with wrong contract (fault=%u "
                   "status=%lld src=0x%llx)\n", (unsigned)rt.fault,
                   (long long)rt.fault_status,
                   (unsigned long long)rt.fault_src);
        }
        rc = 1;
    } else if (e != AOT_EXIT_STOP) {
        printf("FAIL: guard mode: unexpected exit=%u (infrastructure/other fault)\n",
               (unsigned)e);
        rc = 1;
    } else {
        int changed_fpcr = g_state.fpcr != before.fpcr;
        int wrote_dest = g_state.v[0][0] != before.v[0][0] ||
                         g_state.v[0][1] != before.v[0][1];
        if (rt.fault != AOT_FAULT_NONE || !(changed_fpcr && wrote_dest)) {
            printf("FAIL: guard mode: STOP but no guard-contract violation "
                   "(fault=%u fpcr 0x%llx->0x%llx v0 0x%llx->0x%llx)\n",
                   (unsigned)rt.fault, (unsigned long long)before.fpcr,
                   (unsigned long long)g_state.fpcr,
                   (unsigned long long)before.v[0][0],
                   (unsigned long long)g_state.v[0][0]);
            rc = 1;
        } else {
            printf("PASS(control): fpignoreguard mutant stopped without rejecting "
                   "(fpcr 0x%llx->0x%llx, dest 0x%llx->0x%llx)\n",
                   (unsigned long long)before.fpcr,
                   (unsigned long long)g_state.fpcr,
                   (unsigned long long)before.v[0][0],
                   (unsigned long long)g_state.v[0][0]);
            rc = 0;
        }
    }
    aot_rt_release(&rt);
    return rc;
}

int main(int argc, char **argv) {
    int guard_mode = 0;
    if (argc == 2 && strcmp(argv[1], "--expect-guard-reject") == 0) {
        guard_mode = 1;
    } else if (argc != 1) {
        printf("FAIL: usage: %s [--expect-guard-reject]\n", argv[0]);
        return 1;
    }
    /* Poison the arena bytes BEFORE registering them (ownership precondition:
     * the domain owns identity for the arena's whole lifetime). */
    memset(g_arena, 0x5A, sizeof(g_arena));
    g_dom = aot_mem_domain_create();
    if (g_dom == NULL) fatal("domain create");
    if (aot_mem_init(&g_mem, g_dom, g_arena, sizeof(g_arena), GB) != AOT_MEM_OK)
        fatal("arena init");
    if (aot_mem_st64(&g_mem, GB + 0x40ull, 0x0123456789ABCDEFull) != AOT_MEM_OK)
        fatal("arena seed store");

    if (guard_mode) {
        int rc = test_guard_reject_mode();
        aot_mem_domain_destroy(g_dom);
        return rc;
    }

    test_unsupported_fpcr();
    test_bitwise_unrestricted();
    test_closed_form_translated();

    aot_mem_domain_destroy(g_dom);
    if (g_fail) { printf("FAIL: aot_fp_translated_probe\n"); return 1; }
    printf("PASS: aot_fp_translated_probe (native-only: %d fault + %d bitwise + %d closed)\n",
           g_unsupported_cases, g_bitwise_cases, g_closed_cases);
    return 0;
}
