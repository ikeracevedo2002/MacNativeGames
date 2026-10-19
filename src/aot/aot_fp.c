#include "aot_fp.h"

#include <stddef.h>

/* ---------------------------------------------------------------- formats */

typedef struct {
    int total_bits;      /* 32 or 64 */
    int exp_bits;        /* 8 or 11 */
    int frac_bits;       /* 23 or 52 */
    int bias;            /* 127 or 1023 */
    int64_t e_min;       /* 1 - bias */
    int64_t e_max;       /* bias */
    uint64_t frac_mask;
    uint64_t sign_mask;
    uint64_t quiet_bit;
    uint64_t implicit;
    uint64_t exp_ones;   /* value of the all-ones exponent field */
} FpFmt;

static const FpFmt FP32 = {
    32, 8, 23, 127, -126, 127,
    (1ull << 23) - 1u, 1ull << 31, 1ull << 22, 1ull << 23,
    ((1ull << 8) - 1u) << 23
};
static const FpFmt FP64 = {
    64, 11, 52, 1023, -1022, 1023,
    (1ull << 52) - 1u, 1ull << 63, 1ull << 51, 1ull << 52,
    ((1ull << 11) - 1u) << 52
};

enum { FP_ZERO = 0, FP_INF = 1, FP_QNAN = 2, FP_SNAN = 3, FP_FINITE = 4 };

typedef struct {
    int sign;
    int cls;
    int64_t E;        /* unbiased exponent of the value's ULP scale */
    uint64_t sig;     /* significand at scale 2^(E - frac_bits) */
    uint64_t bits;    /* post-unpack raw bits (input flush applied) */
} FpUnp;

/* ------------------------------------------------------------- primitives */

static unsigned clz64(uint64_t x) {
    unsigned n = 0;
    if (x == 0u) return 64u;
    while ((x & 0x8000000000000000ull) == 0u) { x <<= 1; n++; }
    return n;
}

static uint64_t fp_zero(const FpFmt *F, int sign) {
    return sign ? F->sign_mask : 0u;
}
static uint64_t fp_inf(const FpFmt *F, int sign) {
    return (sign ? F->sign_mask : 0u) | F->exp_ones;
}
static uint64_t fp_default_nan(const FpFmt *F) {
    return F->exp_ones | F->quiet_bit;
}
static uint64_t fp_bits_raw(const FpFmt *F, int sign, uint64_t expf,
                            uint64_t frac) {
    uint64_t b = (expf << F->frac_bits) | (frac & F->frac_mask);
    if (sign) b |= F->sign_mask;
    return b;
}
static int fp_is_nan_cls(int cls) {
    return cls == FP_QNAN || cls == FP_SNAN;
}

/* Unpack raw bits, applying the FZ input flush (and IDC) exactly once. */
static void fp_unpack(const FpFmt *F, uint64_t bits, int fz, uint32_t *fp,
                      FpUnp *o) {
    uint64_t u = (F->total_bits == 32) ? (bits & 0xffffffffull) : bits;
    uint64_t frac = u & F->frac_mask;
    uint64_t expf = (u >> F->frac_bits) & ((1ull << F->exp_bits) - 1ull);
    o->sign = (int)((u >> (F->total_bits - 1)) & 1u);
    o->cls = FP_ZERO;
    o->E = F->e_min;
    o->sig = 0;
    o->bits = u;
    if (expf == 0u) {
        if (frac == 0u) { o->cls = FP_ZERO; return; }
        if (fz) {
            *fp |= AOT_FPSR_IDC;
            o->cls = FP_ZERO;
            o->bits = fp_zero(F, o->sign);
            return;
        }
        o->cls = FP_FINITE;
        o->sig = frac;
        return;
    }
    if (expf == (1ull << F->exp_bits) - 1ull) {
        if (frac == 0u) { o->cls = FP_INF; return; }
        o->cls = (frac & F->quiet_bit) ? FP_QNAN : FP_SNAN;
        o->sig = frac;
        return;
    }
    o->cls = FP_FINITE;
    o->E = (int64_t)expf - F->bias;
    o->sig = frac | F->implicit;
}

/* Select and return the propagated NaN / default NaN. */
static uint64_t fp_nan_result(const FpFmt *F, const FpUnp *a, const FpUnp *b,
                              uint32_t fpcr, uint32_t *fp) {
    const FpUnp *n = NULL;
    if (a->cls == FP_SNAN) { *fp |= AOT_FPSR_IOC; n = a; }
    else if (b->cls == FP_SNAN) { *fp |= AOT_FPSR_IOC; n = b; }
    else if (a->cls == FP_QNAN) { n = a; }
    else if (b->cls == FP_QNAN) { n = b; }
    if (n == NULL) { *fp |= AOT_FPSR_IOC; return fp_default_nan(F); }
    if (fpcr & AOT_FPCR_DN) return fp_default_nan(F);
    return fp_bits_raw(F, n->sign, (1ull << F->exp_bits) - 1ull,
                       n->sig | F->quiet_bit);
}

/*
 * Round an exact value  (sig + resid * eps) * 2^e  to the format and pack it,
 * where 0 < eps < 1 LSB of sig and `resid` is -1, 0 or +1.
 *
 * `resid` is SIGNED on purpose: an addend such as 1 - tiny loses the tiny
 * operand's discarded bits, so the true result lies BELOW the truncated
 * significand. Treating that residual as "sticky high" (the pre-fix code) is
 * wrong for directed rounding: 1 - tiny under RP must stay 1, not become
 * nextabove(1).
 *
 * A negative residual is canonicalized at entry by borrowing one LSB from sig:
 *
 *     sig - eps  ==  (sig - 1) + (1 - eps),   0 < eps < 1  =>  0 < 1-eps < 1
 *
 * This is required (not just cosmetic): it lowers the leading-bit exponent when
 * sig is a power of two (a value just below 2^k has exponent k-1), and without
 * it RZ/RM keep the previous-above result and a boundary result can be
 * classified with the wrong tiny/overflow exponent.
 *
 * Callers guarantee !(sig == 0 && resid != 0) before canonicalization, because
 * a sub-ULP-only residual cannot arise from these operations (add/sub with 3
 * guard bits drops alignment bits only when the exponent difference is >= 4,
 * where cancellation to the guard is impossible).
 */
static uint64_t fp_round(const FpFmt *F, int sign, int64_t e, uint64_t sig,
                         int resid, uint32_t fpcr, uint32_t *fp) {
    const int p = F->frac_bits + 1;
    const int64_t min_lsb = F->e_min - F->frac_bits;   /* subnormal ULP */

    if (resid < 0) {   /* borrow: sig - eps == (sig-1) + (1-eps) */
        sig -= 1u;
        resid = 1;
    }
    if (sig == 0u) {
        if (resid == 0) return fp_zero(F, sign);
        /* Only a sub-ULP residual remains: unreachable for the operations
         * here; fail closed rather than compute an undefined exponent. */
        *fp |= AOT_FPSR_IXC;
        return fp_zero(F, sign);
    }

    unsigned k = 63u - clz64(sig);
    int64_t vexp = e + (int64_t)k;          /* exact leading-bit exponent */
    int64_t lsb = vexp - (p - 1);
    if (lsb < min_lsb) lsb = min_lsb;       /* subnormal: fixed ULP */
    int64_t shift = lsb - e;

    uint64_t q = 0;
    int g = 0;
    int low = 0;
    if (shift >= 64) {
        /* sig < 2^64, so for shift == 64 bit 63 IS the guard bit; ignoring it
         * silently returned zero for a result that rounds up (e.g. an
         * underflowed F64 product whose value is [0.5,1) min-subnormal ULPs). */
        if (shift == 64) {
            g = (int)((sig >> 63) & 1u);
            low = (sig & 0x7fffffffffffffffull) != 0u;
        } else {
            low = 1;   /* value is strictly below half an ULP */
        }
    } else if (shift > 0) {
        q = sig >> shift;
        g = (int)((sig >> (shift - 1)) & 1u);
        low = (sig & (((uint64_t)1u << (shift - 1)) - 1u)) != 0u;
    } else {
        q = sig << (unsigned)(-shift);
    }

    int inexact = (g || low || resid != 0);
    int tiny = (vexp < F->e_min);

    if ((fpcr & AOT_FPCR_FZ) && tiny) {
        /* AH=0 flush-to-zero before rounding: UFC only, no IXC. */
        *fp |= AOT_FPSR_UFC;
        return fp_zero(F, sign);
    }

    /* Directed modes increment when the discarded fraction is nonzero in the
     * direction being rounded; |resid| is strictly smaller than the "low"
     * bits' least significant unit, so a nonzero `low` dominates it. */
    const int frac_nonzero = g || low || resid > 0;
    unsigned rmode = (fpcr & AOT_FPCR_RMODE_MASK) >> AOT_FPCR_RMODE_SHIFT;
    int inc = 0;
    if (rmode == AOT_FPCR_RN)
        inc = g && (low || resid > 0 || (resid == 0 && (int)(q & 1u)));
    else if (rmode == AOT_FPCR_RP) inc = (sign == 0) && frac_nonzero;
    else if (rmode == AOT_FPCR_RM) inc = (sign == 1) && frac_nonzero;
    if (inc) q += 1u;
    if (q >= ((uint64_t)1u << p)) { q >>= 1; lsb += 1; }

    if (q != 0u) {
        unsigned m = 63u - clz64(q);
        if (lsb + (int64_t)m > F->e_max) {
            *fp |= AOT_FPSR_OFC | AOT_FPSR_IXC;
            int to_inf = (rmode == AOT_FPCR_RN) ||
                         (rmode == AOT_FPCR_RP && sign == 0) ||
                         (rmode == AOT_FPCR_RM && sign == 1);
            if (to_inf) return fp_inf(F, sign);
            /* max finite: exponent all ones minus 1, fraction all ones */
            return fp_bits_raw(F, sign, (1ull << F->exp_bits) - 2ull,
                               F->frac_mask);
        }
    }

    if (inexact) {
        if (tiny) *fp |= AOT_FPSR_UFC;
        *fp |= AOT_FPSR_IXC;
    }
    if (q == 0u) return fp_zero(F, sign);

    if (lsb == min_lsb && (63u - clz64(q)) < (unsigned)(p - 1)) {
        return fp_bits_raw(F, sign, 0, q);       /* subnormal */
    }
    /* Normal: place the implicit bit at p-1. */
    while ((63u - clz64(q)) < (unsigned)(p - 1)) { q <<= 1; lsb -= 1; }
    return fp_bits_raw(F, sign,
                       (uint64_t)(lsb + (int64_t)(p - 1) + F->bias),
                       q & F->frac_mask);
}

/* ------------------------------------------------------------- arithmetic */

/* The sub-LSB residual passed to fp_round is only a DIRECTION (-1/0/+1).
 * That is exact for these operations because a residual can only be produced by
 * discarding alignment (or product/quotient) bits below the guard region, and
 * a nonzero sticky implies shift >= 2: the residual is then strictly smaller
 * than the lowest retained "low" bit, so it can only break an exact RN tie or
 * decide a directed-mode tie. It is never large enough to need a second bit. */

static uint64_t fp_addsub(const FpFmt *F, uint64_t abits, uint64_t bbits,
                          int subtract, uint32_t fpcr, uint32_t *fp) {
    const int fz = (fpcr & AOT_FPCR_FZ) != 0u;
    FpUnp a, b;
    fp_unpack(F, abits, fz, fp, &a);
    fp_unpack(F, bbits, fz, fp, &b);

    /* NaN propagate first (uses original operand order/sign bits). */
    if (fp_is_nan_cls(a.cls) || fp_is_nan_cls(b.cls))
        return fp_nan_result(F, &a, &b, fpcr, fp);

    const int sa = a.sign;
    const int sb = b.sign ^ (subtract ? 1 : 0);

    if (a.cls == FP_INF || b.cls == FP_INF) {
        if (a.cls == FP_INF && b.cls == FP_INF) {
            if (sa != sb) { *fp |= AOT_FPSR_IOC; return fp_default_nan(F); }
            return fp_inf(F, sa);
        }
        return fp_inf(F, (a.cls == FP_INF) ? sa : sb);
    }
    if (a.cls == FP_ZERO && b.cls == FP_ZERO) {
        if (sa == sb) return fp_zero(F, sa);
        unsigned rmode = (fpcr & AOT_FPCR_RMODE_MASK) >> AOT_FPCR_RMODE_SHIFT;
        return fp_zero(F, (rmode == AOT_FPCR_RM) ? 1 : 0);
    }
    if (a.cls == FP_ZERO) {
        return (b.bits & ~F->sign_mask) | ((uint64_t)(sb & 1) << (F->total_bits - 1));
    }
    if (b.cls == FP_ZERO) {
        return (a.bits & ~F->sign_mask) | ((uint64_t)(sa & 1) << (F->total_bits - 1));
    }

    /* Finite nonzero. */
    int64_t Ea = a.E, Eb = b.E;
    uint64_t ma = a.sig, mb = b.sig;
    int sna = sa, snb = sb;
    if (Ea < Eb) {
        int64_t te = Ea; Ea = Eb; Eb = te;
        uint64_t tm = ma; ma = mb; mb = tm;
        int ts = sna; sna = snb; snb = ts;
    }
    const unsigned G = 3u;   /* guard bits */
    int64_t d = Ea - Eb;
    uint64_t xa = ma << G;
    uint64_t xb;
    int sticky = 0;
    if (d >= 64) {
        xb = 0u;
        sticky = (mb != 0u);
    } else if (d == 0) {
        xb = mb << G;
    } else {
        uint64_t s = mb << G;
        xb = s >> d;
        if ((s & (((uint64_t)1u << d) - 1u)) != 0u) sticky = 1;
    }
    int64_t e = Ea - F->frac_bits - (int64_t)G;

    uint64_t S;
    int sres;
    int resid_neg = 0;   /* is the sub-LSB residual subtracted from S? */
    if (sna == snb) {
        S = xa + xb;
        sres = sna;
    } else if (xa >= xb) {
        S = xa - xb;
        sres = sna;
        resid_neg = 1;   /* true = xa - (xb + eps) = S - eps */
    } else {
        S = xb - xa;
        sres = snb;
    }
    if (S == 0u) {
        if (sticky) {
            /* residual below the guard; round to signed zero conservatively */
            *fp |= AOT_FPSR_IXC;
            unsigned rmode = (fpcr & AOT_FPCR_RMODE_MASK) >> AOT_FPCR_RMODE_SHIFT;
            if (rmode == AOT_FPCR_RP && sres == 0) return fp_bits_raw(F, 0, 0, 1);
            if (rmode == AOT_FPCR_RM && sres == 1) return fp_bits_raw(F, 1, 0, 1);
            return fp_zero(F, 0);
        }
        unsigned rmode = (fpcr & AOT_FPCR_RMODE_MASK) >> AOT_FPCR_RMODE_SHIFT;
        return fp_zero(F, (rmode == AOT_FPCR_RM) ? 1 : 0);
    }
    return fp_round(F, sres, e, S,
                    sticky ? (resid_neg ? -1 : 1) : 0, fpcr, fp);
}

static void mul128(uint64_t a, uint64_t b, uint64_t *hi, uint64_t *lo) {
    uint64_t a0 = a & 0xffffffffull, a1 = a >> 32;
    uint64_t b0 = b & 0xffffffffull, b1 = b >> 32;
    uint64_t p0 = a0 * b0;
    uint64_t p1 = a0 * b1;
    uint64_t p2 = a1 * b0;
    uint64_t p3 = a1 * b1;
    uint64_t mid = p1 + (p0 >> 32);
    mid += p2;
    *lo = (mid << 32) | (p0 & 0xffffffffull);
    *hi = p3 + (mid >> 32) + (mid < p1 ? (1ull << 32) : 0ull);
}

static uint64_t fp_mul(const FpFmt *F, uint64_t abits, uint64_t bbits,
                       uint32_t fpcr, uint32_t *fp) {
    const int fz = (fpcr & AOT_FPCR_FZ) != 0u;
    FpUnp a, b;
    fp_unpack(F, abits, fz, fp, &a);
    fp_unpack(F, bbits, fz, fp, &b);
    if (fp_is_nan_cls(a.cls) || fp_is_nan_cls(b.cls))
        return fp_nan_result(F, &a, &b, fpcr, fp);
    const int sign = a.sign ^ b.sign;
    if (a.cls == FP_INF || b.cls == FP_INF) {
        if (a.cls == FP_ZERO || b.cls == FP_ZERO) {
            *fp |= AOT_FPSR_IOC;
            return fp_default_nan(F);
        }
        return fp_inf(F, sign);
    }
    if (a.cls == FP_ZERO || b.cls == FP_ZERO) return fp_zero(F, sign);

    int64_t e = a.E + b.E - 2 * F->frac_bits;
    uint64_t sig;
    int sticky = 0;
    if (F->total_bits == 32) {
        sig = a.sig * b.sig;
    } else {
        uint64_t hi, lo;
        mul128(a.sig, b.sig, &hi, &lo);
        while (hi != 0u) {
            sticky |= (int)(lo & 1u);
            lo = (hi << 63) | (lo >> 1);
            hi >>= 1;
            e += 1;
        }
        sig = lo;
    }
    return fp_round(F, sign, e, sig, sticky, fpcr, fp);
}

/* 128/64 division; requires hi < den. Returns quotient, sets *rem. */
static uint64_t div128by64(uint64_t hi, uint64_t lo, uint64_t den,
                           uint64_t *rem) {
    uint64_t q = 0, r = hi;
    for (int i = 63; i >= 0; i--) {
        int carry = (int)(r >> 63) & 1;
        r = (r << 1) | ((lo >> i) & 1u);
        if (carry || r >= den) { r -= den; q |= (uint64_t)1u << i; }
    }
    *rem = r;
    return q;
}

static uint64_t fp_div(const FpFmt *F, uint64_t abits, uint64_t bbits,
                       uint32_t fpcr, uint32_t *fp) {
    const int fz = (fpcr & AOT_FPCR_FZ) != 0u;
    FpUnp a, b;
    fp_unpack(F, abits, fz, fp, &a);
    fp_unpack(F, bbits, fz, fp, &b);
    if (fp_is_nan_cls(a.cls) || fp_is_nan_cls(b.cls))
        return fp_nan_result(F, &a, &b, fpcr, fp);
    const int sign = a.sign ^ b.sign;
    if (a.cls == FP_INF && b.cls == FP_INF) {
        *fp |= AOT_FPSR_IOC;
        return fp_default_nan(F);
    }
    if (a.cls == FP_INF) return fp_inf(F, sign);
    if (b.cls == FP_INF) return fp_zero(F, sign);
    if (b.cls == FP_ZERO) {
        if (a.cls == FP_ZERO) { *fp |= AOT_FPSR_IOC; return fp_default_nan(F); }
        *fp |= AOT_FPSR_DZC;
        return fp_inf(F, sign);
    }
    if (a.cls == FP_ZERO) return fp_zero(F, sign);

    uint64_t sa = a.sig, sb = b.sig;
    unsigned na = clz64(sa), nb = clz64(sb);
    uint64_t A = sa << na, B = sb << nb;
    int64_t e = a.E - b.E - (int64_t)na + (int64_t)nb;
    int sticky = 0;
    if (A >= B) {
        sticky |= (int)(A & 1u);
        A >>= 1;
        e += 1;
    }
    uint64_t rem;
    uint64_t Q = div128by64(A, 0u, B, &rem);
    if (rem != 0u) sticky = 1;
    e -= 64;
    return fp_round(F, sign, e, Q, sticky, fpcr, fp);
}

/* --------------------------------------------------------------- compare */

static uint32_t fp_cmp(const FpFmt *F, uint64_t abits, uint64_t bbits,
                       int signaling, uint32_t fpcr, uint32_t *fp) {
    FpUnp a, b;
    const int fz = (fpcr & AOT_FPCR_FZ) != 0u;
    /* Comparisons honour the SAME FPCR.FZ input flush as arithmetic. The
     * previous code hardcoded FZ=1, which diverged from FPCR.FZ=0. */
    fp_unpack(F, abits, fz, fp, &a);
    fp_unpack(F, bbits, fz, fp, &b);

    if (fp_is_nan_cls(a.cls) || fp_is_nan_cls(b.cls)) {
        if (a.cls == FP_SNAN || b.cls == FP_SNAN || signaling)
            *fp |= AOT_FPSR_IOC;
        /* unordered: N=0 Z=0 C=1 V=1 */
        return (1u << 29) | (1u << 28);
    }
    int mag;
    if (a.cls == FP_INF && b.cls == FP_INF) mag = 0;
    else if (a.cls == FP_INF) mag = 1;
    else if (b.cls == FP_INF) mag = -1;
    else if (a.cls == FP_ZERO && b.cls == FP_ZERO) mag = 0;
    else if (a.cls == FP_ZERO) mag = -1;
    else if (b.cls == FP_ZERO) mag = 1;
    else if (a.E != b.E) mag = (a.E > b.E) ? 1 : -1;
    else if (a.sig != b.sig) mag = (a.sig > b.sig) ? 1 : -1;
    else mag = 0;

    /* Equal magnitude only means equal VALUE for signed zero pairs: +x and -x
     * are not equal. The previous code equated |a| == |b| regardless of sign. */
    int eq = 0, lt = 0;
    if (a.sign != b.sign) {
        if (a.cls == FP_ZERO && b.cls == FP_ZERO) eq = 1;   /* +0 == -0 */
        else lt = a.sign;                /* negative < positive */
    } else if (mag == 0) {
        eq = 1;
    } else if (a.sign == 0) {
        lt = (mag < 0);
    } else {
        lt = (mag > 0);
    }
    if (eq) return (1u << 30) | (1u << 29);   /* N=0 Z=1 C=1 V=0 */
    if (lt) return (1u << 31);                /* N=1 Z=0 C=0 V=0 */
    return (1u << 29);                        /* N=0 Z=0 C=1 V=0 */
}

/* ------------------------------------------------------------ public API */

static void fp_accumulate(AotGuestState *s, uint32_t flags) {
    s->fpsr = (s->fpsr | (uint64_t)flags) & 0xffffffffull;
}

/* The FPCR subset this core can honour. Generated code MUST call
 * aot_fp_supported() BEFORE any arithmetic/compare and fault (BAD_STATE with
 * the source PC) when it is 0; there is no silent-NaN fallback because that
 * would be a wrong guest-visible result rather than a fail-closed fault.
 * The arithmetic helpers below are only called on supported modes. */
int aot_fp_supported(uint32_t fpcr) {
    return (fpcr & ~(uint32_t)(AOT_FPCR_FZ | AOT_FPCR_DN |
                               AOT_FPCR_RMODE_MASK)) == 0u;
}

uint32_t aot_fp_add32(AotGuestState *s, uint32_t a, uint32_t b) {
    uint32_t f = 0;
    uint64_t r = fp_addsub(&FP32, a, b, 0, (uint32_t)s->fpcr, &f);
    fp_accumulate(s, f);
    return (uint32_t)r;
}
uint32_t aot_fp_sub32(AotGuestState *s, uint32_t a, uint32_t b) {
    uint32_t f = 0;
    uint64_t r = fp_addsub(&FP32, a, b, 1, (uint32_t)s->fpcr, &f);
    fp_accumulate(s, f);
    return (uint32_t)r;
}
uint32_t aot_fp_mul32(AotGuestState *s, uint32_t a, uint32_t b) {
    uint32_t f = 0;
    uint64_t r = fp_mul(&FP32, a, b, (uint32_t)s->fpcr, &f);
    fp_accumulate(s, f);
    return (uint32_t)r;
}
uint32_t aot_fp_div32(AotGuestState *s, uint32_t a, uint32_t b) {
    uint32_t f = 0;
    uint64_t r = fp_div(&FP32, a, b, (uint32_t)s->fpcr, &f);
    fp_accumulate(s, f);
    return (uint32_t)r;
}
uint64_t aot_fp_add64(AotGuestState *s, uint64_t a, uint64_t b) {
    uint32_t f = 0;
    uint64_t r = fp_addsub(&FP64, a, b, 0, (uint32_t)s->fpcr, &f);
    fp_accumulate(s, f);
    return r;
}
uint64_t aot_fp_sub64(AotGuestState *s, uint64_t a, uint64_t b) {
    uint32_t f = 0;
    uint64_t r = fp_addsub(&FP64, a, b, 1, (uint32_t)s->fpcr, &f);
    fp_accumulate(s, f);
    return r;
}
uint64_t aot_fp_mul64(AotGuestState *s, uint64_t a, uint64_t b) {
    uint32_t f = 0;
    uint64_t r = fp_mul(&FP64, a, b, (uint32_t)s->fpcr, &f);
    fp_accumulate(s, f);
    return r;
}
uint64_t aot_fp_div64(AotGuestState *s, uint64_t a, uint64_t b) {
    uint32_t f = 0;
    uint64_t r = fp_div(&FP64, a, b, (uint32_t)s->fpcr, &f);
    fp_accumulate(s, f);
    return r;
}
uint32_t aot_fp_cmp32(AotGuestState *s, uint32_t a, uint32_t b, int signaling) {
    uint32_t f = 0;
    uint32_t nzcv = fp_cmp(&FP32, a, b, signaling, (uint32_t)s->fpcr, &f);
    fp_accumulate(s, f);
    return nzcv;
}
uint32_t aot_fp_cmp64(AotGuestState *s, uint64_t a, uint64_t b, int signaling) {
    uint32_t f = 0;
    uint32_t nzcv = fp_cmp(&FP64, a, b, signaling, (uint32_t)s->fpcr, &f);
    fp_accumulate(s, f);
    return nzcv;
}
