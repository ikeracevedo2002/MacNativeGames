/*
 * G2 AOT proof: scalar FP core contract probe.
 *
 * These are CORE unit vectors, not translation/differential evidence and not
 * an oracle claim beyond the values annotated below. They pin the bugs found
 * in review:
 *   - signed subtraction residual: 1 - tiny under RP/RZ must NOT round up;
 *   - fp_round shift == 64: the guard bit (bit 63) must be honoured;
 *   - FPCR.FZ must be read, not hardcoded, by comparisons;
 *   - +x and -x (and +inf/-inf) are not equal merely because |x| == |y|;
 *   - aot_fp_cmp64 returns NZCV as uint32_t (header signature).
 * Each expected value was cross-checked against the pinned A57/Unicorn oracle
 * by the lead unless marked "model". The closed-form boundary matrix below is
 * derived from the pinned A57 rules directly (raw integer bits), not from the
 * oracle process.
 */
#include "aot_fp.h"

#include <stdio.h>
#include <string.h>

static int g_fail = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", msg); g_fail = 1; } \
} while (0)

#define FZ  AOT_FPCR_FZ
#define RM_RN (AOT_FPCR_RN << AOT_FPCR_RMODE_SHIFT)
#define RM_RP (AOT_FPCR_RP << AOT_FPCR_RMODE_SHIFT)
#define RM_RM (AOT_FPCR_RM << AOT_FPCR_RMODE_SHIFT)
#define RM_RZ (AOT_FPCR_RZ << AOT_FPCR_RMODE_SHIFT)

static AotGuestState st;

static void reset(uint32_t fpcr) {
    memset(&st, 0, sizeof(st));
    st.fpcr = fpcr;
}

static void expect32(const char *msg, uint32_t got, uint32_t want,
                     uint32_t flags) {
    if (got != want || st.fpsr != flags) {
        printf("FAIL: %s: got 0x%08x flags 0x%llx want 0x%08x flags 0x%x\n",
               msg, got, (unsigned long long)st.fpsr, want, flags);
        g_fail = 1;
    }
}
static void expect64(const char *msg, uint64_t got, uint64_t want,
                     uint32_t flags) {
    if (got != want || st.fpsr != flags) {
        printf("FAIL: %s: got 0x%016llx flags 0x%llx want 0x%016llx flags 0x%x\n",
               msg, (unsigned long long)got, (unsigned long long)st.fpsr,
               (unsigned long long)want, flags);
        g_fail = 1;
    }
}
static void expect_cmp(const char *msg, uint32_t got, uint32_t want,
                       uint32_t flags) {
    if (got != want || st.fpsr != (uint64_t)flags) {
        printf("FAIL: %s: got NZCV 0x%08x flags 0x%llx want 0x%08x flags 0x%x\n",
               msg, got, (unsigned long long)st.fpsr, want, flags);
        g_fail = 1;
    }
}

/* ---- add/sub: signed residual must not turn a down-round into an up-round -- */
static void test_addsub_residual(void) {
    const uint32_t one = 0x3f800000u;
    const uint32_t tiny30 = 0x30800000u;   /* 2^-30 */
    const uint32_t neg_1_4 = 0xbd800001u;  /* -(1+2^-23)*2^-4 */
    const uint32_t neg_1_4p = 0xbd800005u; /* -(1+5*2^-23)*2^-4 */

    /* 1 - 2^-30: true value is just BELOW 1. RP must yield 1, not nextabove. */
    reset(RM_RP);
    expect32("sub RP 1-tiny", aot_fp_sub32(&st, one, tiny30), one, 0x10);
    reset(RM_RP);
    expect32("add RP 1+(-tiny)", aot_fp_add32(&st, one, 0x80800000u), one, 0x10);
    /* A value just BELOW 1 changes exponent: RZ/RM must keep 0x3f7fffff.
     * This is the canonical borrow case (sig is a power of two). */
    reset(RM_RZ);
    expect32("sub RZ 1-tiny", aot_fp_sub32(&st, one, tiny30), 0x3f7fffffu, 0x10);
    reset(RM_RM);
    expect32("sub RM 1-tiny", aot_fp_sub32(&st, one, tiny30), 0x3f7fffffu, 0x10);
    reset(RM_RN);
    expect32("sub RN 1-tiny (round up)", aot_fp_sub32(&st, one, tiny30), one, 0x10);
    reset(RM_RP);
    expect32("sub RP 1-tiny (stays 1)", aot_fp_sub32(&st, one, tiny30), one, 0x10);

    /* Lead audit vector: +1.0 + (-max subnormal), FPCR=0x02c00000 (DN|RZ).
     * Expected 0x3f7fffff, IXC only. The old signed-residual code returned
     * 0x3f800000 because it never borrowed the significand. */
    reset(0x02c00000u);
    expect32("add 1 + -maxsub RZ",
             aot_fp_add32(&st, 0x3f800000u, 0x807fffffu), 0x3f7fffffu, 0x10);

    /* 0.93749999... : RP rounds up to exactly 0.9375; RN/RZ choose the
     * representable neighbours below/above as annotated. */
    reset(RM_RP);
    expect32("add RP 1-0.0625+eps", aot_fp_add32(&st, one, neg_1_4),
             0x3f700000u, 0x10);
    reset(RM_RZ);
    expect32("add RZ 1-0.0625+eps", aot_fp_add32(&st, one, neg_1_4),
             0x3f6fffffu, 0x10);
    reset(RM_RN);
    expect32("add RN 1-0.0625+5eps", aot_fp_add32(&st, one, neg_1_4p),
             0x3f6fffffu, 0x10);

    /* Large + tiny-negative: large is exact in the guard, result just below. */
    reset(RM_RZ);
    expect32("add RZ 2^20-tiny", aot_fp_add32(&st, 0x49800000u, 0xa9800000u),
             0x497fffffu, 0x10);
    reset(RM_RP);
    expect32("add RP 2^20-tiny", aot_fp_add32(&st, 0x49800000u, 0xa9800000u),
             0x49800000u, 0x10);

    /* Exact cancellation must produce +0 except under RM (-0). */
    reset(RM_RN);
    expect32("RN x-x", aot_fp_sub32(&st, 0x40490fdbu, 0x40490fdbu),
             0x00000000u, 0x0);
    reset(RM_RM);
    expect32("RM x-x", aot_fp_sub32(&st, 0x40490fdbu, 0x40490fdbu),
             0x80000000u, 0x0);
}

/* ---- fp_round shift == 64: bit 63 must be the guard bit ------------------ */
static void test_underflow_guard64(void) {
    /* F64: (1+2^-52)*2^-1022 * 2^-53 = 2^-1075 + 2^-1127. In min-subnormal
     * ULPs this is 0.5 + 2^-52, so RN rounds UP to the smallest subnormal. */
    reset(RM_RN);
    expect64("mul64 RN min-subnormal",
             aot_fp_mul64(&st, 0x0010000000000001ull, 0x3ca0000000000000ull),
             0x0000000000000001ull, 0x18);   /* UFC|IXC */

    /* F32: (1+2^-23)*2^-126 / 2^24 = 0.5 + 2^-23 min-subnormal ULPs. */
    reset(RM_RN);
    expect32("div32 RN min-subnormal",
             aot_fp_div32(&st, 0x00800001u, 0x4b800000u),
             0x00000001u, 0x18);

    /* Directed modes: the same value is > 0 but < 1 ULP. */
    reset(RM_RP);
    expect32("div32 RP min-subnormal",
             aot_fp_div32(&st, 0x00800001u, 0x4b800000u),
             0x00000001u, 0x18);
    reset(RM_RZ);
    expect32("div32 RZ min-subnormal",
             aot_fp_div32(&st, 0x00800001u, 0x4b800000u),
             0x00000000u, 0x18);

    /* Regression for the old shift>=64 branch returning 0 under RN. */
    reset(RM_RN);
    expect32("div32 RN one-ulp-subnormal",
             aot_fp_div32(&st, 0x00800001u, 0x4b800000u),
             0x00000001u, 0x18);
}

/* ---- compare: FZ from FPCR, sign-aware equality ------------------------- */
static void test_compare(void) {
    reset(0);
    expect_cmp("+inf > -inf",
               aot_fp_cmp64(&st, 0x7ff0000000000000ull, 0xfff0000000000000ull,
                            0),
               0x20000000u, 0x0);
    reset(0);
    expect_cmp("-inf < +inf",
               aot_fp_cmp64(&st, 0xfff0000000000000ull, 0x7ff0000000000000ull,
                            0),
               0x80000000u, 0x0);
    reset(0);
    expect_cmp("+1 > -1",
               aot_fp_cmp32(&st, 0x3f800000u, 0xbf800000u, 0),
               0x20000000u, 0x0);
    reset(0);
    expect_cmp("-1 < +1",
               aot_fp_cmp32(&st, 0xbf800000u, 0x3f800000u, 0),
               0x80000000u, 0x0);
    reset(0);
    expect_cmp("+0 == -0",
               aot_fp_cmp32(&st, 0x00000000u, 0x80000000u, 0),
               0x60000000u, 0x0);
    reset(0);
    expect_cmp("1 == 1",
               aot_fp_cmp32(&st, 0x3f800000u, 0x3f800000u, 0),
               0x60000000u, 0x0);

    /* qNaN: FCMP is quiet, FCMPE raises IOC; both unordered. */
    reset(0);
    expect_cmp("FCMP qNaN quiet",
               aot_fp_cmp32(&st, 0x7fc00001u, 0x3f800000u, 0),
               0x30000000u, 0x0);
    reset(0);
    expect_cmp("FCMPE qNaN IOC",
               aot_fp_cmp32(&st, 0x7fc00001u, 0x3f800000u, 1),
               0x30000000u, 0x1);
    reset(0);
    expect_cmp("FCMP sNaN IOC",
               aot_fp_cmp32(&st, 0x7f800001u, 0x3f800000u, 0),
               0x30000000u, 0x1);

    /* Denormal vs zero: FZ=0 compares its value (GT), FZ=1 flushes to 0 (EQ).
     * ARM FPUnpack flushes the denormal input and sets IDC, so FZ=1 raising
     * IDC is the source-operand flush rule, not a model approximation. */
    reset(0);
    expect_cmp("FCMP denormal FZ=0",
               aot_fp_cmp32(&st, 0x00000001u, 0x00000000u, 0),
               0x20000000u, 0x0);
    reset(FZ);
    expect_cmp("FCMP denormal FZ=1",
               aot_fp_cmp32(&st, 0x00000001u, 0x00000000u, 0),
               0x60000000u, 0x80);   /* model: IDC on flushed input */
}

/* ---- unsupported FPCR modes: predicate gates generated-code faults ------- */
static void test_fpcr_guard(void) {
    CHECK(aot_fp_supported(0u), "FPCR=0 supported");
    CHECK(aot_fp_supported(AOT_FPCR_FZ | AOT_FPCR_DN | RM_RZ),
          "FZ/DN/RMode supported");
    CHECK(!aot_fp_supported(1u << 26), "AHP unsupported (must fault, not NaN)");
    CHECK(!aot_fp_supported(0x0000ff00u), "trap enables unsupported");
    CHECK(!aot_fp_supported(1u << 19), "FZ16 unsupported");

    /* fpsr upper 32 bits are always kept zero. */
    reset(0);
    st.fpsr = 0xffffffff00000000ull;
    (void)aot_fp_add32(&st, 0x3f800000u, 0x3f800000u);
    CHECK((st.fpsr >> 32) == 0u, "fpsr upper bits zero");
    CHECK(st.fpcr == 0u, "fpcr low-32 preserved");
}

/* ---- closed-form boundary matrix (independent of any oracle process) -----
 * Raw integer bits and exact FPSR sticky sets derived from the pinned A57
 * rules; no host floating-point arithmetic and no Unicorn. IXC=0x10 UFC=0x08
 * OFC=0x04 IOC=0x01. 1/3 F32 rounds UP under RN; F64 1/3 rounds DOWN. */
static void test_closed_form_matrix(void) {
    const uint32_t one = 0x3f800000u;
    const uint32_t three = 0x40400000u;
    const uint32_t mone = 0xbf800000u;

    reset(RM_RN); expect32("1/3 RN", aot_fp_div32(&st, one, three), 0x3eaaaaabu, 0x10);
    reset(RM_RP); expect32("1/3 RP", aot_fp_div32(&st, one, three), 0x3eaaaaabu, 0x10);
    reset(RM_RM); expect32("1/3 RM", aot_fp_div32(&st, one, three), 0x3eaaaaaau, 0x10);
    reset(RM_RZ); expect32("1/3 RZ", aot_fp_div32(&st, one, three), 0x3eaaaaaau, 0x10);
    reset(RM_RN); expect32("-1/3 RN", aot_fp_div32(&st, mone, three), 0xbeaaaaabu, 0x10);
    reset(RM_RM); expect32("-1/3 RM", aot_fp_div32(&st, mone, three), 0xbeaaaaabu, 0x10);
    reset(RM_RP); expect32("-1/3 RP", aot_fp_div32(&st, mone, three), 0xbeaaaaaau, 0x10);
    reset(RM_RZ); expect32("-1/3 RZ", aot_fp_div32(&st, mone, three), 0xbeaaaaaau, 0x10);

    const uint64_t d_one = 0x3ff0000000000000ull, d_three = 0x4008000000000000ull;
    const uint64_t d_mone = 0xbff0000000000000ull;
    reset(RM_RN); expect64("d 1/3 RN", aot_fp_div64(&st, d_one, d_three), 0x3fd5555555555555ull, 0x10);
    reset(RM_RP); expect64("d 1/3 RP", aot_fp_div64(&st, d_one, d_three), 0x3fd5555555555556ull, 0x10);
    reset(RM_RM); expect64("d 1/3 RM", aot_fp_div64(&st, d_one, d_three), 0x3fd5555555555555ull, 0x10);
    reset(RM_RZ); expect64("d 1/3 RZ", aot_fp_div64(&st, d_one, d_three), 0x3fd5555555555555ull, 0x10);
    reset(RM_RN); expect64("d -1/3 RN", aot_fp_div64(&st, d_mone, d_three), 0xbfd5555555555555ull, 0x10);
    reset(RM_RM); expect64("d -1/3 RM", aot_fp_div64(&st, d_mone, d_three), 0xbfd5555555555556ull, 0x10);
    reset(RM_RP); expect64("d -1/3 RP", aot_fp_div64(&st, d_mone, d_three), 0xbfd5555555555555ull, 0x10);
    reset(RM_RZ); expect64("d -1/3 RZ", aot_fp_div64(&st, d_mone, d_three), 0xbfd5555555555555ull, 0x10);

    reset(RM_RN); expect32("minnorm*.5 RN gradual", aot_fp_mul32(&st, 0x00800000u, 0x3f000000u), 0x00400000u, 0x0);
    reset(FZ);    expect32("minnorm*.5 FZ flush", aot_fp_mul32(&st, 0x00800000u, 0x3f000000u), 0x00000000u, 0x08);
    reset(RM_RN); expect64("d minnorm*.5 RN gradual", aot_fp_mul64(&st, 0x0010000000000000ull, 0x3fe0000000000000ull), 0x0008000000000000ull, 0x0);
    reset(FZ);    expect64("d minnorm*.5 FZ flush", aot_fp_mul64(&st, 0x0010000000000000ull, 0x3fe0000000000000ull), 0x0000000000000000ull, 0x08);

    reset(RM_RN); expect32("minnorm+1*.5 RN tie", aot_fp_mul32(&st, 0x00800001u, 0x3f000000u), 0x00400000u, 0x18);
    reset(RM_RP); expect32("minnorm+1*.5 RP tie", aot_fp_mul32(&st, 0x00800001u, 0x3f000000u), 0x00400001u, 0x18);
    reset(FZ);    expect32("minnorm+1*.5 FZ flush", aot_fp_mul32(&st, 0x00800001u, 0x3f000000u), 0x00000000u, 0x08);
    reset(RM_RN); expect64("d minnorm+1*.5 RN tie", aot_fp_mul64(&st, 0x0010000000000001ull, 0x3fe0000000000000ull), 0x0008000000000000ull, 0x18);
    reset(RM_RP); expect64("d minnorm+1*.5 RP tie", aot_fp_mul64(&st, 0x0010000000000001ull, 0x3fe0000000000000ull), 0x0008000000000001ull, 0x18);
    reset(FZ);    expect64("d minnorm+1*.5 FZ flush", aot_fp_mul64(&st, 0x0010000000000001ull, 0x3fe0000000000000ull), 0x0000000000000000ull, 0x08);

    reset(RM_RN); expect32("minnorm*(1-ulp) RN", aot_fp_mul32(&st, 0x00800000u, 0x3f7fffffu), 0x00800000u, 0x18);
    reset(FZ);    expect32("minnorm*(1-ulp) FZ", aot_fp_mul32(&st, 0x00800000u, 0x3f7fffffu), 0x00000000u, 0x08);
    reset(RM_RN); expect64("d minnorm*(1-ulp) RN", aot_fp_mul64(&st, 0x0010000000000000ull, 0x3fefffffffffffffull), 0x0010000000000000ull, 0x18);
    reset(FZ);    expect64("d minnorm*(1-ulp) FZ", aot_fp_mul64(&st, 0x0010000000000000ull, 0x3fefffffffffffffull), 0x0000000000000000ull, 0x08);

    reset(RM_RN); expect32("max*2 RN inf", aot_fp_mul32(&st, 0x7f7fffffu, 0x40000000u), 0x7f800000u, 0x14);
    reset(RM_RZ); expect32("max*2 RZ max", aot_fp_mul32(&st, 0x7f7fffffu, 0x40000000u), 0x7f7fffffu, 0x14);
    reset(RM_RN); expect64("d max*2 RN inf", aot_fp_mul64(&st, 0x7fefffffffffffffull, 0x4000000000000000ull), 0x7ff0000000000000ull, 0x14);

    reset(0);            expect32("qNaN+sNaN quiet op2", aot_fp_add32(&st, 0x7fc00002u, 0x7f800001u), 0x7fc00001u, 0x01);
    reset(AOT_FPCR_DN);  expect32("qNaN+sNaN DN default", aot_fp_add32(&st, 0x7fc00002u, 0x7f800001u), 0x7fc00000u, 0x01);
    reset(0);            expect32("qNaN op1 preferred", aot_fp_add32(&st, 0x7fc00002u, 0x7fc00003u), 0x7fc00002u, 0x0);
    reset(0);            expect32("FSUB NaN sign unchanged", aot_fp_sub32(&st, 0x7fc00002u, 0x3f800000u), 0x7fc00002u, 0x0);
    reset(0);            expect64("d qNaN+sNaN quiet op2", aot_fp_add64(&st, 0x7ff8000000000002ull, 0x7ff0000000000001ull), 0x7ff8000000000001ull, 0x01);
    reset(AOT_FPCR_DN);  expect64("d qNaN+sNaN DN default", aot_fp_add64(&st, 0x7ff8000000000002ull, 0x7ff0000000000001ull), 0x7ff8000000000000ull, 0x01);
    reset(0);            expect64("d FSUB NaN sign unchanged", aot_fp_sub64(&st, 0x7ff8000000000002ull, 0x3ff0000000000000ull), 0x7ff8000000000002ull, 0x0);

    reset(0);     expect32("+0 + -0 = +0", aot_fp_add32(&st, 0x00000000u, 0x80000000u), 0x00000000u, 0x0);
    reset(RM_RM); expect32("RM -0 + -0 = -0", aot_fp_add32(&st, 0x80000000u, 0x80000000u), 0x80000000u, 0x0);
    reset(RM_RN); expect32("+0/-0 equal", aot_fp_cmp32(&st, 0x00000000u, 0x80000000u, 0), 0x60000000u, 0x0);

    /* Sticky FPSR seeds accumulate only, never clear pre-existing bits. */
    reset(RM_RN); st.fpsr = 0x9fu;
    expect32("sticky seed | IXC", aot_fp_div32(&st, one, three), 0x3eaaaaabu, 0x9fu);
    reset(FZ); st.fpsr = 0x83u;
    expect32("sticky seed | UFC", aot_fp_mul32(&st, 0x00800000u, 0x3f000000u), 0x00000000u, 0x8bu);
}

int main(void) {
    test_addsub_residual();
    test_underflow_guard64();
    test_compare();
    test_fpcr_guard();
    test_closed_form_matrix();
    if (g_fail) { printf("FAIL: aot_fp_probe\n"); return 1; }
    printf("PASS: aot_fp_probe\n");
    return 0;
}
