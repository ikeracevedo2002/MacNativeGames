/*
 * G2 AOT proof: exact-integer scalar FP core (F32/F64 add, sub, mul, div,
 * compare). This is deliberately NOT host C floating point: no host rounding
 * mode, NaN payload, denormal or exception behaviour is assumed. The only
 * arithmetic is unsigned integer arithmetic plus explicit shifts, so the
 * result and the FPSR flags are defined by this file and not by the MSVC
 * runtime or the x86-64 SSE unit.
 *
 * Model (documented in docs/g2-aot-proof.md):
 *   - input denormals are flushed to signed zero when FPCR.FZ=1, setting IDC
 *     (IDC is NOT set when FZ=0);
 *   - a finite exact result whose leading exponent is below the minimum normal
 *     exponent is "tiny before rounding"; with FZ=1 it is flushed to signed
 *     zero with UFC set and no IXC (AH=0 behaviour; the pinned A57 oracle has
 *     no AH feature);
 *   - with FZ=0, tininess is detected before rounding and UFC is set only when
 *     the result is also inexact, so a tiny value that rounds up to the
 *     minimum normal still raises UFC|IXC;
 *   - NaN precedence is sNaN(op1), sNaN(op2), qNaN(op1), qNaN(op2); FPCR.DN
 *     selects the default NaN; a propagated sNaN raises IOC;
 *   - rounding modes RN (nearest even), RP (+inf), RM (-inf), RZ are honoured.
 *
 * Only the FPCR bits FZ, DN and RMode are honoured for F32/F64 (matching the
 * pinned A57 ARMv8.0 reference). Any other FPCR bit (trap enables, AHP/FZ16,
 * reserved) makes the mode UNSUPPORTED: generated/translated code MUST call
 * aot_fp_supported() BEFORE the operation and fault with AOT_FAULT_BAD_STATE
 * and the source PC, without writing the destination or FPSR. Returning a
 * default NaN instead would be a silently wrong guest result, not fail-closed.
 * The helpers below are therefore only valid on supported modes, and the guest
 * FPCR value is never rewritten (low-32 ABI round-trip preserved).
 */
#ifndef AOT_FP_H
#define AOT_FP_H

#include "aot_abi.h"

#include <stdint.h>

/* Formats. */
#define AOT_FP_F32 0u
#define AOT_FP_F64 1u

/* FPCR fields interpreted by this module. */
#define AOT_FPCR_FZ          (1u << 24)
#define AOT_FPCR_DN          (1u << 25)
#define AOT_FPCR_RMODE_SHIFT 22u
#define AOT_FPCR_RMODE_MASK  (3u << AOT_FPCR_RMODE_SHIFT)
#define AOT_FPCR_RN          0u
#define AOT_FPCR_RP          1u
#define AOT_FPCR_RM          2u
#define AOT_FPCR_RZ          3u

/* FPSR cumulative exception bits (ARMV8.0 subset; QC is left untouched). */
#define AOT_FPSR_IOC (1u << 0)
#define AOT_FPSR_DZC (1u << 1)
#define AOT_FPSR_OFC (1u << 2)
#define AOT_FPSR_UFC (1u << 3)
#define AOT_FPSR_IXC (1u << 4)
#define AOT_FPSR_IDC (1u << 7)

/* Returns 1 iff every set FPCR bit is modelled (FZ/DN/RMode). Generated code
 * must check this first; the arithmetic/compare entry points below are
 * precondition: aot_fp_supported((uint32_t)s->fpcr) != 0. */
int aot_fp_supported(uint32_t fpcr);

/* fault_status value used by generated code when the FPCR mode is unsupported.
 * The fault code is AOT_FAULT_BAD_STATE and fault_src is the source PC. */
#define AOT_FP_ERR_UNSUPPORTED_FPCR 1

/* Each op returns the raw result bits of the given format and ORs the
 * cumulative exception bits into s->fpsr (upper 32 bits kept zero). */
uint32_t aot_fp_add32(AotGuestState *s, uint32_t a, uint32_t b);
uint32_t aot_fp_sub32(AotGuestState *s, uint32_t a, uint32_t b);
uint32_t aot_fp_mul32(AotGuestState *s, uint32_t a, uint32_t b);
uint32_t aot_fp_div32(AotGuestState *s, uint32_t a, uint32_t b);
uint64_t aot_fp_add64(AotGuestState *s, uint64_t a, uint64_t b);
uint64_t aot_fp_sub64(AotGuestState *s, uint64_t a, uint64_t b);
uint64_t aot_fp_mul64(AotGuestState *s, uint64_t a, uint64_t b);
uint64_t aot_fp_div64(AotGuestState *s, uint64_t a, uint64_t b);

/* Compare. Returns NZCV packed into bits 31..28. `signaling` selects FCMPE
 * (any NaN raises IOC) versus FCMP (only sNaN raises IOC). */
uint32_t aot_fp_cmp32(AotGuestState *s, uint32_t a, uint32_t b, int signaling);
uint32_t aot_fp_cmp64(AotGuestState *s, uint64_t a, uint64_t b, int signaling);

#endif /* AOT_FP_H */
