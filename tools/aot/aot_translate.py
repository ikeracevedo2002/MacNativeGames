#!/usr/bin/env python3
"""G2 stage-1 offline ARM64 -> native C translator (small, original subset).

This is a *small deliberate* translator, not a general A64 decoder. It:
  - decodes a fixed supported subset with exact raw ARM64 encoding masks and
    field validation, failing closed on every unsupported/reserved form;
  - recovers a control-flow graph from an explicit manifest (known text
    ranges, entries, indirect targets), validates direct branch targets and
    splits blocks at BL/SVC continuations;
  - emits straight-line native C basic-block functions plus native lookup
    image metadata (no generic opcode switch/interpreter).

Provenance: SHA-256 over fixture bytes + manifest bytes + this generator +
a config string. The runtime's FNV-1a arena checksum is a quick check only,
never provenance.

Subset (AOT_SUBSET_ID "g2-core-v2"):
  ADD/SUB (immediate, shifted register) with/without S
  MOVZ/MOVK
  B, B.cond, CBZ, CBNZ
  BL, BR, BLR, RET
  SVC
  LDR/STR/LDP/STP (immediate/offset/pre/post), LDXR/STXR family, LDAR
  FMOV/FABS/FNEG (64-bit bitwise), vector AND/ORR/EOR, byte add/sub
  F32/F64 FADD/FSUB/FMUL/FDIV/FCMP/FCMPE over the supported FPCR modes
Correct X/W zero-extension and SP vs XZR selection are enforced. BLR captures
its source register before x30 is updated (including BLR x30). Unsupported
numeric FPCR modes fault BEFORE any destination/FPSR write.
"""

import argparse
import hashlib
import json
import struct
import sys

# ---------------------------------------------------------------- semantics

AOT_SUBSET_ID = "g2-core-v2"
AOT_ABI_VERSION = 1
AOT_STATE_LAYOUT = 1
TOOL_CONFIG = "aot-translate-stage3/cfg-manifest/c-basicblock/v1"

# G3 module mode (--module): one image per loaded module. The image carries
# the Program ABI version, its own subset id (a Program accepts only this id)
# and the module flat SHA-256 as its source identity, so the loader binds an
# image to exactly one module descriptor.
AOT_MODULE_SUBSET_ID = "g3-module-v1"
AOT_ABI_VERSION_PROGRAM = 2
TOOL_CONFIG_MODULE = "aot-translate-stage3/module-flat/c-basicblock/g3-module-v1"

# Reserved, DISJOINT negative fault_status namespace for the local-switch
# runtime guard (D022).  Positive AOT_STATE_ERR_* values stay untouched; the
# status is (LOCAL_SWITCH_STATUS_BASE - (site_ordinal + 1)), where the ordinal
# follows sorted BR PCs, exactly as recorded in the metadata.
LOCAL_SWITCH_STATUS_BASE = -0x4C530000

# MRS sysreg16 fields accepted in module mode (see src/aot/aot_abi.h).
SYSREG_CNTPCT_EL0 = 0xDF01
SYSREG_CNTVCT_EL0 = 0xDF02
SYSREG_TPIDR_EL0 = 0xDE82
SYSREG_TPIDRRO_EL0 = 0xDE83
SYSREG_COUNTERS = (SYSREG_CNTPCT_EL0, SYSREG_CNTVCT_EL0)
SYSREG_TPIDR = {SYSREG_TPIDR_EL0: "tpidr", SYSREG_TPIDRRO_EL0: "tpidrro"}

# Test-only negative-control selector. None == the real (unmutated) image.
MUTANT = None
MUTANTS = ("wrongcarry", "lostwzeroext", "wrongcond", "blrorder",
           "msr_tpidr_noop", "msr_tpidr_tpidrro", "msr_tpidr_xzr_sp",
           "msr_tpidr_skip_xzr", "msr_tpidr_clobber_v",
           "msr_tpidr_clobber_fpcr", "msr_tpidr_clobber_fpsr",
           "strdrop", "scalarupper", "pair32trunc",
           "fpdropflags", "stxalwaysok",
           "fproundrn", "fpnanorder", "fpignoreguard",
           # G3 increment 3 MODULE-mode-only negative controls.
           "adrp_offset", "orr_noshift", "stp_split",
           # G3 DT_INIT new-family negative controls (module mode only).
           "tbz_bit", "csel_cond", "ldst_sign_zero", "imm9_wb_nooff",
           "smulh_unsigned",
           "msub_reverse", "madd_no_zeroext", "madd_ignore_ra",
           "div_zero_ones", "div_no_zeroext", "sdiv_overflow_clamp",
           "simd_upper_clear", "simd_v31_discard", "simd_offset_scale",
           "ccmp_ignore_cond", "ccmp_cond_invert", "ccmp_w64",
           # G3 inverted logical (BIC/ORN/EON/BICS) negative controls.
           "logic_inv_ignoren", "logic_inv_beforeshift",
           "logic_inv_bics_skipflags",
           # G3 one-source CLZ negative controls. Only --module accepts them.
           "clz_zero_wrong", "clz_W_uses64", "clz_clobber_flags",
           # G3 two-source variable shift negative controls.
           "varshift_oversize_zero", "varshift_asr_logical",
           "varshift_W_uses64",
           # G3 one-source RBIT negative controls (module mode only).
           "rbit_identity", "rbit_byteswap", "rbit_W_uses64",
           "rbit_clobber_flags",
           # G3 canonical DMB ISH negative controls (module mode only).
           "dmb_ish_clobber_flags", "dmb_ish_clearexclusive",
           "dmb_ish_clobber_gpr",
           # G3 UMULH-only negative controls (module mode only; each selects
           # its own wrong helper, never the shared aot_umulh).
           "umulh_signed", "umulh_lowprod", "umulh_midcarry")
# The two G3 module-mode mutants are only legal with --module; every other
# mutant belongs to the G2 single-image path and must stay there.
MODULE_MUTANTS = ("adrp_offset", "orr_noshift", "stp_split",
                  "tbz_bit", "csel_cond", "ldst_sign_zero", "imm9_wb_nooff",
           "smulh_unsigned",
           "msub_reverse", "madd_no_zeroext", "madd_ignore_ra",
           "div_zero_ones", "div_no_zeroext", "sdiv_overflow_clamp",
           "simd_upper_clear", "simd_v31_discard", "simd_offset_scale",
           "ccmp_ignore_cond", "ccmp_cond_invert", "ccmp_w64",
           "logic_inv_ignoren", "logic_inv_beforeshift",
           "logic_inv_bics_skipflags",
           "clz_zero_wrong", "clz_W_uses64", "clz_clobber_flags",
           "varshift_oversize_zero", "varshift_asr_logical",
           "varshift_W_uses64",
           "rbit_identity", "rbit_byteswap", "rbit_W_uses64",
           "rbit_clobber_flags",
           "dmb_ish_clobber_flags", "dmb_ish_clearexclusive",
           "dmb_ish_clobber_gpr",
           "umulh_signed", "umulh_lowprod", "umulh_midcarry",
           "msr_tpidr_noop", "msr_tpidr_tpidrro", "msr_tpidr_xzr_sp",
           "msr_tpidr_skip_xzr", "msr_tpidr_clobber_v",
           "msr_tpidr_clobber_fpcr", "msr_tpidr_clobber_fpsr")
MODULE_BASE = 0
# 1 while translating with --module (ABI-v2 Program image). Module-only
# lowerings (single-access pair stores) are gated on it so the G2 single-image
# output stays byte-identical.
MODULE_MODE = 0
# 1 while translating with --module --partial: a reachable word the module
# subset cannot decode stops its block with a typed fault instead of aborting
# the whole translation. The fault carries the guest PC and a stable status
# index into the offline --meta-out "unsupported" table (raw word + reason).
# No runtime decoding, no fabricated successor and no substitution.
PARTIAL = 0
PARTIAL_STATUS = {}

# Guest address-space rules the loader enforces (src/aot/aot_as.h): 4 KiB
# pages and the guest window [2^32, 2^39).
AOT_AS_PAGE_BYTES = 0x1000
AOT_AS_MIN_ADDR = 1 << 32
AOT_AS_MAX_ADDR = 1 << 39

# NZCV helpers are emitted by name; each marks itself used.
_HELPERS = {}
_USED = set()

# Provided by the linked aot_fp.c translation unit (declared by aot_fp.h);
# referenced by name but never emitted into the generated file.
_EXTERNAL = {"aot_fp_supported",
             "aot_fp_add32", "aot_fp_add64", "aot_fp_sub32", "aot_fp_sub64",
             "aot_fp_mul32", "aot_fp_mul64", "aot_fp_div32", "aot_fp_div64",
             "aot_fp_cmp32", "aot_fp_cmp64"}


def use(name):
    if name in _EXTERNAL:
        return name
    _USED.add(name)
    return name


_HELPERS["aot_gpr_sp"] = """
static uint64_t aot_gpr_sp(const AotGuestState *s, uint32_t n) {
    return (n == 31u) ? s->sp : s->x[n];
}
"""

_HELPERS["aot_gpr_zr"] = """
static uint64_t aot_gpr_zr(const AotGuestState *s, uint32_t n) {
    return (n == 31u) ? 0u : s->x[n];
}
"""

_HELPERS["aot_set_sp"] = """
static void aot_set_sp(AotGuestState *s, uint32_t n, uint64_t v) {
    if (n == 31u) s->sp = v; else s->x[n] = v;
}
"""

_HELPERS["aot_set_zr"] = """
static void aot_set_zr(AotGuestState *s, uint32_t n, uint64_t v) {
    if (n != 31u) s->x[n] = v;
}
"""

_HELPERS["aot_shift"] = """
/* Shift `val` (already masked to `w` bits) by `amount` using `type`
   (0=LSL,1=LSR,2=ASR). All arithmetic is on unsigned values; `amount` is
   validated < w by the translator, so no overshift or signed overflow. */
static uint64_t aot_shift(uint64_t val, unsigned w, unsigned type,
                          unsigned amount) {
    uint64_t mask = (w == 64u) ? UINT64_MAX : ((1ull << w) - 1ull);
    val &= mask;
    if (amount == 0u) return val;
    if (type == 0u) return (val << amount) & mask;          /* LSL */
    if (type == 1u) return (val >> amount) & mask;          /* LSR */
    /* ASR: for a negative value the vacated top `amount` bits must become
       ones. Build that fill explicitly (no shift by `w`, which would be UB
       for w == 64). `amount` is in 1..w-1 here. */
    if ((val >> (w - 1u)) & 1u) {
        uint64_t fill = (~(mask >> amount)) & mask;
        return ((val >> amount) | fill) & mask;
    }
    return (val >> amount) & mask;
}
"""

_HELPERS["aot_ror"] = """
/* Rotate right `val` (already masked to `w` bits) by `amount` < w.
   Separate from aot_shift on purpose: extending aot_shift with a fourth
   operator would change the emitted helper text of every existing image
   that uses it (G2 generated-output identity). */
static uint64_t aot_ror(uint64_t val, unsigned w, unsigned amount) {
    uint64_t mask = (w == 64u) ? UINT64_MAX : ((1ull << w) - 1ull);
    val &= mask;
    if (amount == 0u) return val;
    return ((val >> amount) | (val << (w - amount))) & mask;
}
"""

_HELPERS["aot_clz"] = """
/* A64 CLZ at the OPERAND width. `w` is 32 or 64 and only the low `w` bits of
   `val` are inspected, so a W form ignores the upper half entirely. The count
   is 0..w INCLUSIVE: an all-zero operand yields 32 (W) or 64 (X) leading
   zeros. Bounded loop on unsigned values only -- no host clz (whose zero
   input is undefined behaviour) and no compiler intrinsic. */
static uint64_t aot_clz(uint64_t val, unsigned w) {
    unsigned n = 0u;
    uint64_t bit = (w == 64u) ? 0x8000000000000000ull : 0x80000000ull;
    val &= (w == 64u) ? UINT64_MAX : 0xFFFFFFFFull;
    while (bit != 0u && (val & bit) == 0u) { n++; bit >>= 1; }
    return (uint64_t)n;
}
"""

_HELPERS["aot_rbit"] = """
/* A64 RBIT at the OPERAND width. Only the low `w` bits (32 or 64) are
   reversed and the result occupies exactly those low `w` bits, so a W form
   ignores the upper half of the source AND zero-extends its result. Bounded
   loop over unsigned values only: no host intrinsic, no byte-swap API and no
   dependence on the host's bit order. */
static uint64_t aot_rbit(uint64_t val, unsigned w) {
    uint64_t out = 0u;
    unsigned i;
    val &= (w == 64u) ? UINT64_MAX : 0xFFFFFFFFull;
    for (i = 0u; i < w; i++) {
        out = (out << 1) | (val & 1ull);
        val >>= 1;
    }
    return out;
}
"""

_HELPERS["aot_add64"] = """
static uint64_t aot_add64(AotGuestState *s, uint64_t a, uint64_t b, int set) {
    uint64_t r = a + b;
    if (set) {
        uint64_t n = (r >> 63) & 1ull;
        uint64_t z = (r == 0u) ? 1ull : 0ull;
        uint64_t c = (r < a) ? 1ull : 0ull;
        uint64_t v = (((a ^ r) & (b ^ r)) >> 63) & 1ull;
        s->nzcv = AOT_NZCV_PACK(n, z, c, v);
    }
    return r;
}
"""

_HELPERS["aot_sub64"] = """
static uint64_t aot_sub64(AotGuestState *s, uint64_t a, uint64_t b, int set) {
    uint64_t r = a - b;
    if (set) {
        uint64_t n = (r >> 63) & 1ull;
        uint64_t z = (r == 0u) ? 1ull : 0ull;
        uint64_t c = (a >= b) ? 1ull : 0ull;
        uint64_t v = (((a ^ b) & (a ^ r)) >> 63) & 1ull;
        s->nzcv = AOT_NZCV_PACK(n, z, c, v);
    }
    return r;
}
"""

_HELPERS["aot_add32"] = """
static uint64_t aot_add32(AotGuestState *s, uint32_t a, uint32_t b, int set) {
    uint32_t r = a + b;
    if (set) {
        uint64_t n = (r >> 31) & 1ull;
        uint64_t z = (r == 0u) ? 1ull : 0ull;
        uint64_t c = (r < a) ? 1ull : 0ull;
        uint64_t v = (((a ^ r) & (b ^ r)) >> 31) & 1ull;
        s->nzcv = AOT_NZCV_PACK(n, z, c, v);
    }
    return (uint64_t)r;
}
"""

_HELPERS["aot_sub32"] = """
static uint64_t aot_sub32(AotGuestState *s, uint32_t a, uint32_t b, int set) {
    uint32_t r = a - b;
    if (set) {
        uint64_t n = (r >> 31) & 1ull;
        uint64_t z = (r == 0u) ? 1ull : 0ull;
        uint64_t c = (a >= b) ? 1ull : 0ull;
        uint64_t v = (((a ^ b) & (a ^ r)) >> 31) & 1ull;
        s->nzcv = AOT_NZCV_PACK(n, z, c, v);
    }
    return (uint64_t)r;
}
"""

_HELPERS["aot_vadd_bytes"] = """
/* Per-byte (16-lane) wrapping add, no carry between lanes, no flags/QC. */
static uint64_t aot_vadd_bytes(uint64_t a, uint64_t b) {
    return ((a & 0x7f7f7f7f7f7f7f7full) + (b & 0x7f7f7f7f7f7f7f7full))
           ^ ((a ^ b) & 0x8080808080808080ull);
}
"""

_HELPERS["aot_umulh"] = """
/* Portable unsigned 64x64 -> high 64 (no __int128/MSVC intrinsic). */
static uint64_t aot_umulh(uint64_t a, uint64_t b) {
    uint64_t a0 = a & 0xffffffffull, a1 = a >> 32;
    uint64_t b0 = b & 0xffffffffull, b1 = b >> 32;
    uint64_t p00 = a0 * b0, p01 = a0 * b1, p10 = a1 * b0, p11 = a1 * b1;
    uint64_t mid = (p00 >> 32) + (p01 & 0xffffffffull) + (p10 & 0xffffffffull);
    return p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32);
}
"""

_HELPERS["aot_smulh"] = """
/* High 64 of the SIGNED 128-bit product, defined in unsigned C. */
static uint64_t aot_smulh(uint64_t a, uint64_t b) {
    uint64_t a0 = a & 0xffffffffull, a1 = a >> 32;
    uint64_t b0 = b & 0xffffffffull, b1 = b >> 32;
    uint64_t p00 = a0 * b0, p01 = a0 * b1, p10 = a1 * b0, p11 = a1 * b1;
    uint64_t mid = (p00 >> 32) + (p01 & 0xffffffffull) + (p10 & 0xffffffffull);
    uint64_t h = p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32);
    if ((int64_t)a < 0) h -= b;
    if ((int64_t)b < 0) h -= a;
    return h;
}
"""

_HELPERS["aot_umulh_low64"] = """
/* NEGATIVE CONTROL ONLY (mutant umulh_lowprod): returns the LOW 64 bits of
   the width-wide product instead of the high 64.  Selected only by the UMULH
   lowering; the shared aot_umulh above is never mutated. */
static uint64_t aot_umulh_low64(uint64_t a, uint64_t b) {
    return a * b;
}
"""

_HELPERS["aot_umulh_nomidcarry"] = """
/* NEGATIVE CONTROL ONLY (mutant umulh_midcarry): identical to aot_umulh except
   that the carry out of the 32-bit `mid` limb is dropped, so every operand
   pair whose three cross partials overflow 32 bits is wrong.  The `mid`
   computation itself is removed rather than left unused, so the negative
   image still compiles clean at /W4 /WX (C4189). */
static uint64_t aot_umulh_nomidcarry(uint64_t a, uint64_t b) {
    uint64_t a0 = a & 0xffffffffull, a1 = a >> 32;
    uint64_t b0 = b & 0xffffffffull, b1 = b >> 32;
    uint64_t p01 = a0 * b1, p10 = a1 * b0, p11 = a1 * b1;
    return p11 + (p01 >> 32) + (p10 >> 32);
}
"""

_HELPERS["aot_div"] = """
/* A64 UDIV/SDIV, exact instruction definitions. `w` is 32 or 64 and `sgn`
   non-zero selects SDIV. The two guards below keep every host signed
   division away from x/0 and INT_MIN / -1 (both C UB, both raising #DE on
   x86-64): A64 defines the first as 0 and the second as INT_MIN, i.e. the
   wrapped result, and neither traps. W forms read the low 32 bits of the
   operands and zero-extend the result; no flag is written either. */
static uint64_t aot_div(uint64_t a, uint64_t b, unsigned w, unsigned sgn) {
    uint64_t mask = (w == 64u) ? UINT64_MAX : 0xFFFFFFFFull;
    a &= mask;
    b &= mask;
    if (b == 0u) return 0u;                       /* x / 0 == 0 (both) */
    if (!sgn) return a / b;                       /* UDIV cannot overflow */
    if (w == 64u) {
        int64_t sa = (int64_t)a, sb = (int64_t)b;
        if (sa == INT64_MIN && sb == -1) return (uint64_t)INT64_MIN;
        return (uint64_t)(sa / sb);
    }
    {
        int32_t sa = (int32_t)(uint32_t)a, sb = (int32_t)(uint32_t)b;
        if (sa == INT32_MIN && sb == -1) return (uint64_t)(uint32_t)INT32_MIN;
        return (uint64_t)(uint32_t)(sa / sb);
    }
}
"""

_HELPERS["aot_vsub_bytes"] = """
/* Per-byte (16-lane) wrapping subtract, no borrow between lanes, no QC. */
static uint64_t aot_vsub_bytes(uint64_t a, uint64_t b) {
    return ((a | 0x8080808080808080ull) - (b & 0x7f7f7f7f7f7f7f7full))
           ^ ((a ^ ~b) & 0x8080808080808080ull);
}
"""

_HELPERS["aot_fault_mem"] = """
static AotExit aot_fault_mem(AotRuntime *rt, uint64_t addr, int64_t status) {
    rt->fault = AOT_FAULT_MEMORY;
    rt->fault_src = rt->site_pc;
    rt->fault_target = addr;
    rt->fault_status = status;
    rt->reason = AOT_EXIT_FAULT;
    rt->next_pc = addr;
    return AOT_EXIT_FAULT;
}
"""


_HELPERS["aot_fault_state"] = """
static AotExit aot_fault_state(AotRuntime *rt, uint64_t src, int64_t status) {
    rt->fault = AOT_FAULT_BAD_STATE;
    rt->fault_src = src;
    rt->fault_target = src;
    rt->fault_status = status;
    rt->reason = AOT_EXIT_FAULT;
    rt->next_pc = src;
    return AOT_EXIT_FAULT;
}
"""

_HELPERS["aot_fault_unsupported"] = """
/* Partial-AOT only: the block reached a guest word the module subset cannot
   decode. The code is AOT_FAULT_UNSUPPORTED_INSN (NOT BAD_STATE) and src is
   the exact instruction PC; status indexes the offline metadata table. */
static AotExit aot_fault_unsupported(AotRuntime *rt, uint64_t src,
                                     int64_t status) {
    rt->fault = AOT_FAULT_UNSUPPORTED_INSN;
    rt->fault_src = src;
    rt->fault_target = src;
    rt->fault_status = status;
    rt->reason = AOT_EXIT_FAULT;
    rt->next_pc = src;
    return AOT_EXIT_FAULT;
}
"""

_HELPERS["aot_ext"] = """
/* Extend the low bits of `v` per the A64 extended-register option field
   (0 UXTB, 1 UXTH, 2 UXTW, 3 UXTX, 4 SXTB, 5 SXTH, 6 SXTW, 7 SXTX) and then
   shift left by `shift` (0..4). */
static uint64_t aot_ext(uint64_t v, unsigned option, unsigned shift) {
    switch (option) {
    case 0u: v = (uint8_t)v; break;
    case 1u: v = (uint16_t)v; break;
    case 2u: v = (uint32_t)v; break;
    case 3u: break;
    case 4u: v = (uint64_t)(int64_t)(int8_t)v; break;
    case 5u: v = (uint64_t)(int64_t)(int16_t)v; break;
    case 6u: v = (uint64_t)(int64_t)(int32_t)v; break;
    default: break;
    }
    return v << shift;
}
"""

_HELPERS["aot_bfm"] = """
/* Bitfield move, op 0=SBFM (sign-extend), 1=BFM (insert), 2=UBFM.
   Mirrors the ARM bitfield geometry:
     imms >= immr: extract src[imms:immr] (width = imms-immr+1);
                   SBFM/UBFM put it in the low bits, BFM inserts it in place.
     imms <  immr: insert src[imms:0] at lsb = w-immr (SBFIZ/UBFIZ/BFI);
                   SBFM/UBFM zero the bits below lsb, BFM preserves them. */
static uint64_t aot_bfm(uint64_t src, uint64_t dst, unsigned w,
                        unsigned immr, unsigned imms, unsigned op) {
    uint64_t vm = (w == 64u) ? UINT64_MAX : ((1ull << w) - 1ull);
    if (imms >= immr) {
        unsigned n = imms - immr + 1u;
        uint64_t fm = (n >= 64u) ? UINT64_MAX : ((1ull << n) - 1ull);
        uint64_t field = (src >> immr) & fm;
        if (op == 2u) return field;
        if (op == 0u) {
            uint64_t ext = (uint64_t)((int64_t)(field << (64u - n)) >> (64u - n));
            return ext & vm;
        }
        /* BFXIL: insert the extracted field at the low end, preserving all
           destination bits above it. */
        return (dst & ~fm & vm) | field;
    } else {
        unsigned lsb = w - immr;
        unsigned n = imms + 1u;
        uint64_t fm = (n >= 64u) ? UINT64_MAX : ((1ull << n) - 1ull);
        uint64_t field = src & fm;
        if (op == 2u) return (field << lsb) & vm;
        if (op == 0u) {
            uint64_t ext = (uint64_t)((int64_t)(field << (64u - n)) >> (64u - n));
            return (ext << lsb) & vm;
        }
        return (dst & ~(fm << lsb) & vm) | ((field << lsb) & vm);
    }
}
"""


_HELPERS["aot_cond"] = """
static int aot_cond(const AotGuestState *s, unsigned cond) {
    uint64_t n = AOT_NZCV_N(s), z = AOT_NZCV_Z(s);
    uint64_t c = AOT_NZCV_C(s), v = AOT_NZCV_V(s);
    switch (cond) {
    case AOT_COND_EQ: return z == 1ull;
    case AOT_COND_NE: return z == 0ull;
    case AOT_COND_CS: return c == 1ull;
    case AOT_COND_CC: return c == 0ull;
    case AOT_COND_MI: return n == 1ull;
    case AOT_COND_PL: return n == 0ull;
    case AOT_COND_VS: return v == 1ull;
    case AOT_COND_VC: return v == 0ull;
    case AOT_COND_HI: return c == 1ull && z == 0ull;
    case AOT_COND_LS: return !(c == 1ull && z == 0ull);
    case AOT_COND_GE: return n == v;
    case AOT_COND_LT: return n != v;
    case AOT_COND_GT: return z == 0ull && n == v;
    case AOT_COND_LE: return !(z == 0ull && n == v);
    case AOT_COND_AL: return 1;
    default: return 1;   /* NV (0xF) is architecturally an always-true condition */
    }
}
"""


# ---------------------------------------------------------------- decoding

def sx(value, bits):
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


class DecodeError(Exception):
    pass


def _ror_bits(value, shift, width):
    shift %= width
    if shift == 0:
        return value & ((1 << width) - 1)
    mask = (1 << width) - 1
    return ((value >> shift) | (value << (width - shift))) & mask


def _invert_expr(width, expr):
    """C expression that bit-inverts `expr` AT the operand width.

    The 32-bit form inverts the low 32 bits and zero-extends, so no high half
    can leak into the W-result (the same discipline as every other 32-bit
    lowering). Callers guarantee the operand is already masked to `width`.
    """
    if width == 32:
        return "(uint64_t)(uint32_t)~(uint32_t)(%s)" % expr
    return "~(uint64_t)(%s)" % expr


def decode_bit_masks(n, imms, immr, width, immediate):
    """ARM ARM DecodeBitMasks; returns wmask (the logical-immediate value).

    `immediate=True` rejects the encoding where the low `len` bits of imms are
    all ones (S == levels).  That is the reserved case: it is NOT required,
    which is the direction some sketches get backwards.
    """
    combined = (n << 6) | ((~imms) & 0x3F)
    if combined == 0:
        raise DecodeError("DecodeBitMasks: highest set bit < 1")
    length = combined.bit_length() - 1
    if length < 1:
        raise DecodeError("DecodeBitMasks: len < 1")
    levels = (1 << length) - 1
    if immediate and (imms & levels) == levels:
        raise DecodeError("DecodeBitMasks: reserved immediate (S == levels)")
    sval = imms & levels
    rval = immr & levels
    diff = (sval - rval) & levels
    esize = 1 << length
    if esize > width:
        raise DecodeError("DecodeBitMasks: element larger than register")
    welem = (1 << (sval + 1)) - 1
    telem = (1 << (diff + 1)) - 1
    wmask = 0
    tmask = 0
    for pos in range(0, width, esize):
        wmask |= _ror_bits(welem, rval, esize) << pos
        tmask |= telem << pos
    return wmask & ((1 << width) - 1)


def decode(pc, word, module=False):
    """Decode one supported instruction. Returns a dict or raises
    DecodeError. Every branch is field-validated; unsupported forms fail.

    `module` (G3 module mode) enables the extra forms that real linked module
    text needs (PC-relative ADRP/ADR computed from the ABSOLUTE guest PC,
    logical shifted register, NOP, MRS of the four supported system
    registers). The legacy G2 subset is unchanged and its generated C output
    stays byte-identical."""
    sf = (word >> 31) & 1

    # ---- ADD/SUB (immediate): sf op S 100010 sh imm12 Rn Rd
    if ((word >> 23) & 0x3F) == 0x22:
        op = (word >> 30) & 1
        s = (word >> 29) & 1
        sh = (word >> 22) & 1
        imm12 = (word >> 10) & 0xFFF
        rn = (word >> 5) & 0x1F
        rd = word & 0x1F
        if sf == 0 and imm12 > 0xFFF:
            raise DecodeError("reserved imm12")
        return {"kind": "addsub_imm", "pc": pc, "op": op, "s": s,
                "imm": imm12 << (12 if sh else 0), "rn": rn, "rd": rd,
                "width": 64 if sf else 32}

    # ---- ADD/SUB (shifted register): sf op S 01011 shift 0 Rm imm6 Rn Rd
    if ((word >> 24) & 0x1F) == 0x0B and ((word >> 21) & 1) == 0:
        op = (word >> 30) & 1
        s = (word >> 29) & 1
        shift = (word >> 22) & 3
        rm = (word >> 16) & 0x1F
        imm6 = (word >> 10) & 0x3F
        rn = (word >> 5) & 0x1F
        rd = word & 0x1F
        if shift == 3:
            raise DecodeError("reserved shift type (ROR)")
        width = 64 if sf else 32
        if imm6 >= width:
            raise DecodeError("shift amount out of range for operand size")
        return {"kind": "addsub_shift", "pc": pc, "op": op, "s": s,
                "shift": shift, "imm6": imm6, "rm": rm, "rn": rn, "rd": rd,
                "width": width}

    # ---- ADD/SUB (extended register): sf op S 01011 1 opt 1 Rm option imm3 Rn Rd
    #      Rn and (non-S) Rd are SP-capable; Rm is XZR at 31.
    if ((word >> 24) & 0x1F) == 0x0B and ((word >> 21) & 1) == 1:
        if not module:
            raise DecodeError("ADD/SUB extended not in subset (G2)")
        op = (word >> 30) & 1
        sbit = (word >> 29) & 1
        opt = (word >> 22) & 3
        option = (word >> 13) & 7
        imm3 = (word >> 10) & 7
        width = 64 if sf else 32
        if opt != 0:
            raise DecodeError("ADD/SUB extended opt != 00 is reserved")
        # S=1, Rd=31 is the CMP/CMN alias: flags are set and the result is
        # discarded.  aot_set_zr(31, ...) already implements that.
        if width == 32 and imm3 > 4:
            raise DecodeError("ADD/SUB extended imm3 > 4 for 32-bit")
        if width == 64 and imm3 > 4:
            raise DecodeError("ADD/SUB extended imm3 > 4 for 64-bit")
        return {"kind": "addsub_ext", "pc": pc, "op": op, "s": sbit,
                "option": option, "imm3": imm3,
                "rm": (word >> 16) & 0x1F, "rn": (word >> 5) & 0x1F,
                "rd": word & 0x1F, "width": width}

    # ---- MOVZ/MOVK: sf opc 100101 hw imm16 Rd
    if ((word >> 23) & 0x3F) == 0x25 and sf == 1:
        opc = (word >> 29) & 3
        hw = (word >> 21) & 3
        imm16 = (word >> 5) & 0xFFFF
        rd = word & 0x1F
        if opc == 1:
            raise DecodeError("reserved move wide opc")
        if opc == 0:
            if not module:
                raise DecodeError("MOVN not in subset (G2)")
            return {"kind": "movn", "pc": pc, "rd": rd, "imm16": imm16,
                    "hw": hw, "width": 64}
        if opc == 2:
            return {"kind": "movz", "pc": pc, "rd": rd, "imm16": imm16,
                    "hw": hw, "width": 64}
        return {"kind": "movk", "pc": pc, "rd": rd, "imm16": imm16,
                "hw": hw, "width": 64}
    if ((word >> 23) & 0x3F) == 0x25 and sf == 0:
        opc = (word >> 29) & 3
        hw = (word >> 21) & 3
        imm16 = (word >> 5) & 0xFFFF
        rd = word & 0x1F
        if opc == 1:
            raise DecodeError("reserved move wide opc")
        if hw >= 2:
            raise DecodeError("reserved hw for 32-bit move wide")
        if opc == 0:
            if not module:
                raise DecodeError("MOVN not in subset (G2)")
            return {"kind": "movn", "pc": pc, "rd": rd, "imm16": imm16,
                    "hw": hw, "width": 32}
        if opc == 2:
            return {"kind": "movz", "pc": pc, "rd": rd, "imm16": imm16,
                    "hw": hw, "width": 32}
        return {"kind": "movk", "pc": pc, "rd": rd, "imm16": imm16,
                "hw": hw, "width": 32}

    # ---- B / BL: 000101/100101 imm26
    if ((word >> 26) & 0x3F) == 0x05:
        return {"kind": "b", "pc": pc,
                "target": (pc + (sx(word & 0x3FFFFFF, 26) << 2)) & 0xFFFFFFFFFFFFFFFF}
    if ((word >> 26) & 0x3F) == 0x25:
        return {"kind": "bl", "pc": pc,
                "target": (pc + (sx(word & 0x3FFFFFF, 26) << 2)) & 0xFFFFFFFFFFFFFFFF}

    # ---- B.cond: 01010100 imm19 0 cond
    if ((word >> 24) & 0xFF) == 0x54:
        if ((word >> 4) & 1) != 0:
            raise DecodeError("B.cond bit4 must be zero")
        imm19 = (word >> 5) & 0x7FFFF
        cond = word & 0xF
        return {"kind": "bcond", "pc": pc, "cond": cond,
                "target": (pc + (sx(imm19, 19) << 2)) & 0xFFFFFFFFFFFFFFFF}

    # ---- CBZ/CBNZ: sf 011010 op imm19 Rt
    if ((word >> 25) & 0x3F) == 0x1A:
        op = (word >> 24) & 1
        imm19 = (word >> 5) & 0x7FFFF
        rt = word & 0x1F
        return {"kind": "cbz" if op == 0 else "cbnz", "pc": pc, "rt": rt,
                "width": 64 if sf else 32,
                "target": (pc + (sx(imm19, 19) << 2)) & 0xFFFFFFFFFFFFFFFF}

    # ---- CSEL/CSINC/CSINV/CSNEG:
    #      sf op S 11010100 Rm cond o2 0 Rn Rd
    # S=0 and bit 11=0 are fixed; op (bit 30) and o2 (bit 10) independently
    # select the four operations.  Register 31 is XZR in every operand.
    if (word & 0x3FE00800) == 0x1A800000:
        if not module:
            raise DecodeError("CSEL family not in subset (G2)")
        op = (word >> 30) & 1
        o2 = (word >> 10) & 1
        kind = {(0, 0): "csel", (0, 1): "csinc",
                (1, 0): "csinv", (1, 1): "csneg"}[(op, o2)]
        return {"kind": kind, "pc": pc,
                "width": 64 if sf else 32,
                "rm": (word >> 16) & 0x1F, "cond": (word >> 12) & 0xF,
                "rn": (word >> 5) & 0x1F, "rd": word & 0x1F}

    # ---- TBZ/TBNZ: b5 011011 op b40 imm14 Rt
    # b5 (bit 31) is both the top bit of the tested bit number and the
    # register width selector: b5==0 is Wt (bits 0..31), b5==1 is Xt.
    if (word & 0x7E000000) == 0x36000000:
        if not module:
            raise DecodeError("TBZ/TBNZ not in subset (G2)")
        b5 = (word >> 31) & 1
        op = (word >> 24) & 1
        bit = (b5 << 5) | ((word >> 19) & 0x1F)
        imm14 = (word >> 5) & 0x3FFF
        rt = word & 0x1F
        return {"kind": "tbnz" if op else "tbz", "pc": pc, "rt": rt,
                "bit": bit, "width": 64 if b5 else 32,
                "target": (pc + (sx(imm14, 14) << 2)) & 0xFFFFFFFFFFFFFFFF}

    # ---- LDR/STR (immediate, unsigned offset): size 111 V 01 opc imm12 Rn Rt
    if ((word >> 27) & 0x7) == 0x7 and ((word >> 24) & 0x3) == 0x1 \
            and ((word >> 26) & 1) == 0:
        size = (word >> 30) & 3
        opc = (word >> 22) & 3
        if opc in (2, 3):
            if not module:
                raise DecodeError("signed loads not in subset (G2)")
            # opc=2: LDRSB/LDRSH/LDRSW sign-extended to 64 bits.
            # opc=3: LDRSB/LDRSH sign-extended to 32 bits (then zero-extended
            #        into the W destination).  size=3 opc=2 is PRFM; other
            #        size=3 / size=2,opc=3 combinations are unallocated.
            if size == 3:
                raise DecodeError("unsupported ldst opc (PRFM)")
            if size == 2 and opc == 3:
                raise DecodeError("reserved ldst opc (size=2 opc=3)")
            return {"kind": "ldst_signed", "pc": pc, "size": size,
                    "dest64": opc == 2,
                    "imm12": (word >> 10) & 0xFFF,
                    "rn": (word >> 5) & 0x1F, "rt": word & 0x1F}
        return {"kind": "ldst_imm", "pc": pc, "size": size, "load": opc == 1,
                "imm12": (word >> 10) & 0xFFF, "rn": (word >> 5) & 0x1F,
                "rt": word & 0x1F}

    # ---- LDP/STP: opc 101 V=0 (fixed bits 29..25 == 10100); exact base mask
    if (word & 0x3E000000) == 0x28000000:
        opc = (word >> 30) & 3
        op2 = (word >> 23) & 3
        l = (word >> 22) & 1
        if opc not in (0, 2):
            raise DecodeError("unsupported pair opc (LDPSW/other)")
        if op2 == 0:
            raise DecodeError("subset restriction: STNP/LDNP (op2=0) not supported")
        rt2 = (word >> 10) & 0x1F
        rt = word & 0x1F
        rn = (word >> 5) & 0x1F
        if l == 1 and rt == rt2:
            # LDP with the same destination twice is constrained-
            # unpredictable; the final register value is implementation
            # defined, so fail closed instead of choosing one.
            raise DecodeError("constrained-unpredictable LDP Rt == Rt2")
        # STP Rt == Rt2 is a real duplicate store. Rt2 == 31 is XZR: the
        # loaded value is discarded / the stored value is zero. Both are
        # ordinary architecture and are handled by the ordinary emitter.
        # The legacy G2 subset keeps its original restrictions byte for byte.
        if not module:
            if rt == rt2:
                raise DecodeError("subset restriction (G2): pair Rt == Rt2")
            if rt2 == 31:
                raise DecodeError("subset restriction (G2): pair Rt2 == 31")
        if op2 in (1, 3) and rn != 31 and (rn == rt or rn == rt2):
            raise DecodeError("unpredictable writeback base overlaps transferred "
                              "register (Rn == Rt/Rt2)")
        return {"kind": "ldstp", "pc": pc, "width": 64 if opc == 2 else 32,
                "load": l == 1, "op2": op2, "imm7": sx((word >> 15) & 0x7F, 7),
                "rn": rn, "rt": rt, "rt2": rt2}

    # ---- BR/BLR/RET: exact mask (bits 9:5 = Rn are the only free field)
    if (word & 0xFFFFFC1F) == 0xD61F0000:
        return {"kind": "br", "pc": pc, "rn": (word >> 5) & 0x1F}
    if (word & 0xFFFFFC1F) == 0xD63F0000:
        return {"kind": "blr", "pc": pc, "rn": (word >> 5) & 0x1F}
    if (word & 0xFFFFFC1F) == 0xD65F0000:
        return {"kind": "ret", "pc": pc, "rn": (word >> 5) & 0x1F}

    # ---- SVC: 11010100 000 imm16 000 01
    if (word & 0xFFE0001F) == 0xD4000001:
        return {"kind": "svc", "pc": pc, "imm16": (word >> 5) & 0xFFFF}

    # ---- Scalar FP 1-source double, BITWISE only (no FP arithmetic):
    #      FMOV/FABS/FNEG Dd,Dn. Exact mask 0xFFFFFC00 with only bits 9:5 (Rn)
    #      and 4:0 (Rd) free. S/half/other opcodes do not match and fail closed.
    if (word & 0xFFFFFC00) == 0x1E604000:
        return {"kind": "fmov_d", "pc": pc, "rn": (word >> 5) & 0x1F,
                "rd": word & 0x1F}
    if (word & 0xFFFFFC00) == 0x1E60C000:
        return {"kind": "fabs_d", "pc": pc, "rn": (word >> 5) & 0x1F,
                "rd": word & 0x1F}
    if (word & 0xFFFFFC00) == 0x1E614000:
        return {"kind": "fneg_d", "pc": pc, "rn": (word >> 5) & 0x1F,
                "rd": word & 0x1F}

    # ---- Vector three-same .16B integer: fixed bits except Rd(4:0), Rn(9:5),
    #      Rm(20:16); mask 0xFFE0FC00. .8B / other sizes / arrangements do not
    #      match. Only AND/ORR/EOR/ADD/SUB (no saturating/QC forms) are decoded.
    vec_pattern = word & 0xFFE0FC00
    if vec_pattern in (0x4E201C00, 0x4EA01C00, 0x6E201C00,
                       0x4E208400, 0x6E208400):
        kind = {0x4E201C00: "vand", 0x4EA01C00: "vorr", 0x6E201C00: "veor",
                0x4E208400: "vadd", 0x6E208400: "vsub"}[vec_pattern]
        return {"kind": kind, "pc": pc, "rm": (word >> 16) & 0x1F,
                "rn": (word >> 5) & 0x1F, "rd": word & 0x1F}

    # ---- Scalar FP two-source: FADD/FSUB/FMUL/FDIV, S and D -----------
    # Fixed bits 23..21 = 010; bits 15..10 encode the operation; Rm/Rn/Rd
    # are the only free fields. Other FP2 opcodes (FMAX/FMIN/FMADD/...) do
    # not match and fail closed.
    fp2 = word & 0xFFE0FC00
    fp2_map = {0x1E200800: ("fmul", 32), 0x1E600800: ("fmul", 64),
               0x1E201800: ("fdiv", 32), 0x1E601800: ("fdiv", 64),
               0x1E202800: ("fadd", 32), 0x1E602800: ("fadd", 64),
               0x1E203800: ("fsub", 32), 0x1E603800: ("fsub", 64)}
    if fp2 in fp2_map:
        op, width = fp2_map[fp2]
        return {"kind": op, "pc": pc, "width": width,
                "rm": (word >> 16) & 0x1F, "rn": (word >> 5) & 0x1F,
                "rd": word & 0x1F}

    # ---- FCMP/FCMPE (register and #0.0). Bit 4 selects signaling. ------
    fcmp = word & 0xFFE0FC0F
    if fcmp in (0x1E202000, 0x1E602000):
        return {"kind": "fcmp", "pc": pc,
                "width": 32 if fcmp == 0x1E202000 else 64,
                "rn": (word >> 5) & 0x1F, "rm": (word >> 16) & 0x1F,
                "signaling": (word >> 4) & 1}
    if fcmp in (0x1E202008, 0x1E602008):
        if ((word >> 16) & 0x1F) != 0:
            raise DecodeError("FCMP #0.0 Rm field must be zero")
        return {"kind": "fcmp_zero", "pc": pc,
                "width": 32 if fcmp == 0x1E202008 else 64,
                "rn": (word >> 5) & 0x1F,
                "signaling": (word >> 4) & 1}

    # ---- Exclusive / ordered scalar: LDXR/STXR/LDAXR/STLXR/LDAR/STLR
    #      (B/H/W/X) -------------------------------------------------- -
    # size(31:30) is the only operand-size field. Loads and ordered
    # accesses reserve bits 20:16 (Rs) as 11111; exclusive stores use Rs
    # as the status register. Separate exact masks keep LDXP/STXP and
    # reserved Rs field encodings out of the subset (fail closed).
    # LDAXR/STLXR differ from LDXR/STXR only by bit 15 (acquire/release),
    # so they share the exclusive-store/load lowering under the shared SC
    # domain.
    ex_ld = word & 0x3FFFFC00
    ex_ld_map = {0x085F7C00: "ldxr", 0x085FFC00: "ldaxr",
                 0x08DFFC00: "ldar", 0x089FFC00: "stlr"}
    if ex_ld in ex_ld_map:
        kind = ex_ld_map[ex_ld]
        return {"kind": kind, "pc": pc,
                "width": 8 << ((word >> 30) & 3),
                "rn": (word >> 5) & 0x1F, "rt": word & 0x1F}

    ex_st = word & 0x3FE0FC00
    ex_st_map = {0x08007C00: "stxr", 0x0800FC00: "stlxr"}
    if ex_st in ex_st_map:
        kind = ex_st_map[ex_st]
        rs = (word >> 16) & 0x1F
        rn = (word >> 5) & 0x1F
        rt = word & 0x1F
        # ARM STXR/STLXR constrained-unpredictable overlaps (verified
        # against the published pseudocode):
        #   s == t (including 31 == 31), or s == n && n != 31.
        # Rs=31 (WZR status) is fine with Rn=31 (SP) when Rt != 31.
        if rs == rt or (rs == rn and rn != 31):
            raise DecodeError("STXR constrained-unpredictable register overlap")
        return {"kind": kind, "pc": pc,
                "width": 8 << ((word >> 30) & 3),
                "rn": rn, "rt": rt, "rs": rs}

    # ---- CLREX and SY barriers (DSB/DMB/ISB); non-SY options fail closed -
    if word == 0xD5033F5F:
        return {"kind": "clrex", "pc": pc}
    if word in (0xD5033FBF, 0xD5033F9F, 0xD5033FDF):
        return {"kind": "barrier", "pc": pc}
    # DMB ISH (CRm=0b1011), the canonical zero-register form 0xD5033BBF.
    # MODULE ONLY, and ONLY this option: DMB ISHST/ISHLD/NSH*/OSH*/ST/LD, every
    # DSB/ISB option and every other opc stay typed refusals. This is the
    # existing D013 serialized domain's ordering, not a new memory model, so
    # it lowers to the SAME aot_mem_fence() as the SY forms. The new "option"
    # field exists only on this form, so the legacy G2 barrier IR text is
    # unchanged byte for byte.
    if word == 0xD5033BBF:
        if not module:
            raise DecodeError("DMB ISH not in subset (G2)")
        return {"kind": "barrier", "pc": pc, "option": "ish"}

    if module:
        # ---- ADRP: op=1 1 immlo 10000 immhi Rd (PC page in GUEST VAs) ----
        if (word & 0x9F000000) == 0x90000000:
            imm = ((word >> 5) & 0x7FFFF) << 2 | ((word >> 29) & 3)
            return {"kind": "adrp", "pc": pc, "imm": imm,
                    "value": ((pc & ~0xFFF) + (sx(imm, 21) << 12))
                             & 0xFFFFFFFFFFFFFFFF,
                    "rd": word & 0x1F}

        # ---- ADR: op=0 0 immlo 10000 immhi Rd -----------------------------
        if (word & 0x9F000000) == 0x10000000:
            imm = ((word >> 5) & 0x7FFFF) << 2 | ((word >> 29) & 3)
            return {"kind": "adr", "pc": pc,
                    "value": (pc + sx(imm, 21)) & 0xFFFFFFFFFFFFFFFF,
                    "rd": word & 0x1F}

        # ---- Logical (shifted register): sf opc 01010 shift N=0 imm6 ----
        # ---- LDR/STR (immediate, SIMD&FP) unsigned offset --------------
        #      size 111 V=1 01 opc imm12 Rn Rt. size 00 = Q(16 B),
        #      10 = S(4 B), 11 = D(8 B), 01 reserved. opc 0 store / 1 load.
        #      This is a raw BIT transfer: no numeric FP conversion, no
        #      FPCR/FPSR change, and V31 is a real vector register.
        if ((word >> 24) & 0x3F) == 0x3D:
            if not module:
                raise DecodeError("SIMD&FP load/store not in subset (G2)")
            szbits = (word >> 30) & 3
            opc = (word >> 22) & 3
            nbytes = {0: 16, 2: 4, 3: 8}.get(szbits)
            if nbytes is None:
                raise DecodeError("reserved SIMD&FP ldst size")
            # S/D use opc 0/1, Q uses opc 2/3; bit22 is the load flag.
            if nbytes == 16:
                if opc not in (2, 3):
                    raise DecodeError("reserved SIMD&FP ldst opc (Q)")
            elif opc not in (0, 1):
                raise DecodeError("reserved SIMD&FP ldst opc (S/D)")
            imm12 = (word >> 10) & 0xFFF
            return {"kind": "simd_ldst", "pc": pc, "nbytes": nbytes,
                    "load": opc & 1, "offset": imm12 * nbytes,
                    "rn": (word >> 5) & 0x1F, "rt": word & 0x1F}

        # ---- LDR/STR register offset: size 111 V 00 opc 1 Rm option S 10 Rn Rt
        if ((word >> 27) & 0x7) == 0x7 and ((word >> 24) & 0x3) == 0x0 \
                and ((word >> 26) & 1) == 0 and ((word >> 21) & 1) == 1 \
                and ((word >> 10) & 3) == 2:
            size = (word >> 30) & 3
            opc = (word >> 22) & 3
            option = (word >> 13) & 7
            scale = (word >> 12) & 1
            # Only UXTW(2)/LSL(3)/SXTW(6)/SXTX(7) are allocated for the
            # register-offset addressing mode; UXTB/UXTH/SXTB/SXTH are not.
            if option not in (2, 3, 6, 7):
                raise DecodeError("ldst register offset option reserved")
            if size == 3 and (opc == 2 or opc == 3):
                raise DecodeError("unsupported ldst opc (PRFM/unallocated)")
            if size == 2 and opc == 3:
                raise DecodeError("reserved ldst opc (size=2 opc=3)")
            shift = size if scale else 0
            dest64 = opc == 2
            return {"kind": "ldst_regoff", "pc": pc, "size": size,
                    "opc": opc, "dest64": dest64,
                    "rm": (word >> 16) & 0x1F, "option": option,
                    "shift": shift, "rn": (word >> 5) & 0x1F,
                    "rt": word & 0x1F}

        # ---- LDR/STR unscaled imm9 and pre/post-index:
        #      size 111 V 00 opc 0 imm9 mode Rn Rt, mode 00/01/11.
        if ((word >> 27) & 0x7) == 0x7 and ((word >> 24) & 0x3) == 0x0 \
                and ((word >> 26) & 1) == 0 and ((word >> 21) & 1) == 0:
            size = (word >> 30) & 3
            opc = (word >> 22) & 3
            mode = (word >> 10) & 3
            if mode == 2:
                raise DecodeError("ldst imm9 mode=10 is unallocated")
            if opc in (2, 3):
                if size == 3:
                    raise DecodeError("unsupported ldst opc (PRFM unscaled)")
                if size == 2 and opc == 3:
                    raise DecodeError("reserved ldst opc (size=2 opc=3)")
            rn = (word >> 5) & 0x1F
            rt = word & 0x1F
            if mode != 0 and rn == rt and rn != 31:
                raise DecodeError("ldst writeback base overlaps transferred "
                                  "register (Rn == Rt)")
            return {"kind": "ldst_imm9", "pc": pc, "size": size,
                    "opc": opc, "dest64": opc == 2,
                    "imm9": sx((word >> 12) & 0x1FF, 9), "mode": mode,
                    "rn": rn, "rt": rt}

        #      AND/ORR/EOR/ANDS shifted register (opc 3 == ANDS sets NZCV and
        #      is TST when Rd == 31), ROR excluded, imm6 must be in range for
        #      the operand size. ORR Rd,XZR,Rm is the MOV (register) alias:
        #      Rn == 31 is XZR in this form.
        #      N=1 (bit 21) selects the INVERTED forms with the same opc
        #      order: BIC/ORN/EON/BICS (ORN Rd,XZR,Rm is the MVN alias).
        #      Those are module-only, apply NOT to the SHIFTED Rm at the
        #      operand width, and need every legal shift type (ROR included),
        #      so architected ROR is accepted there while the N=0 subset keeps
        #      its original ROR refusal. Only the N=1 forms carry the "invert"
        #      field, so the N=0 IR shape (and the G2 output) is unchanged.
        if ((word >> 24) & 0x1F) == 0x0A:
            n = (word >> 21) & 1
            opc = (word >> 29) & 3
            shift = (word >> 22) & 3
            imm6 = (word >> 10) & 0x3F
            width = 64 if sf else 32
            if n and not module:
                raise DecodeError("inverted logical not in subset (G2)")
            # opc 3 (ANDS) sets NZCV and is TST when Rd=31.
            if not n and shift == 3:
                # ROR is architecturally LEGAL for the N=0 logical forms too;
                # it is merely unsupported by the current subset, in both
                # modes. It is NOT an architecture-reserved encoding, so do not
                # describe it as one (and do not implement it here).
                raise DecodeError("ROR shift unsupported in the current "
                                  "subset (both modes)")
            if imm6 >= width:
                raise DecodeError("shift amount out of range for operand size")
            ins = {"kind": "logic_shift", "pc": pc, "op": opc,
                   "s": 1 if opc == 3 else 0,
                   "shift": shift, "imm6": imm6,
                   "rm": (word >> 16) & 0x1F, "rn": (word >> 5) & 0x1F,
                   "rd": word & 0x1F, "width": width}
            if n:
                ins["invert"] = 1
            return ins

        # ---- NOP ---------------------------------------------------------
        # ---- Logical (immediate): sf opc 100100 N immr imms Rn Rd ----
        #      opc 0 AND, 1 ORR, 2 EOR, 3 ANDS; Rd=31 with ANDS is TST.
        if ((word >> 23) & 0x3F) == 0x24:
            opc = (word >> 29) & 3
            n = (word >> 22) & 1
            immr = (word >> 16) & 0x3F
            imms = (word >> 10) & 0x3F
            width = 64 if sf else 32
            if width == 32 and n != 0:
                raise DecodeError("logical immediate: N=1 in 32-bit form")
            imm = decode_bit_masks(n, imms, immr, width, True)
            return {"kind": "logic_imm", "pc": pc, "op": opc,
                    "imm": imm, "rn": (word >> 5) & 0x1F,
                    "rd": word & 0x1F, "width": width}

        # ---- Bitfield: sf opc 100110 N immr imms Rn Rd ----
        #      opc 0 SBFM, 1 BFM, 2 UBFM, 3 reserved.
        #      The operand geometry below follows the ARM extract/insert
        #      pseudocode; it is exercised by the exhaustive decoder tests.
        #        imms >= immr: extract src[imms:immr], lsb=immr
        #        imms <  immr: insert src[imms:0] at lsb=width-immr
        if ((word >> 23) & 0x3F) == 0x26:
            opc = (word >> 29) & 3
            n = (word >> 22) & 1
            immr = (word >> 16) & 0x3F
            imms = (word >> 10) & 0x3F
            width = 64 if sf else 32
            if opc == 3:
                raise DecodeError("reserved bitfield opc")
            if (width == 32 and n != 0) or (width == 64 and n != 1):
                raise DecodeError("bitfield N does not match register size")
            if width == 32 and (immr > 31 or imms > 31):
                raise DecodeError("bitfield imm outside 32-bit register")
            return {"kind": "bfm", "pc": pc, "op": opc,
                    "immr": immr, "imms": imms,
                    "rn": (word >> 5) & 0x1F,
                    "rd": word & 0x1F, "width": width}

        # ---- Data-processing (1 source): RBIT and CLZ ----------------------
        #      sf 1 0 11010110 opcode opcode2 Rn Rd  (bits 30..21 == 0x2D6)
        #      opcode (20:16) is 0 for the whole shared class; opcode2 (15:10)
        #      selects the operation. RBIT is opcode2 == 0b000000 and CLZ is
        #      opcode2 == 0b000100, so each has the COMPLETE fixed field set
        #          (word & 0x7FFFFC00) == 0x5AC00000   (RBIT)
        #          (word & 0x7FFFFC00) == 0x5AC01000   (CLZ)
        #      and only sf (31), Rn (9:5) and Rd (4:0) vary. Both widths are
        #      legal (sf=0 is the W form). Everything else in the group --
        #      REV16, REV32/REV, CLS (opcode2 1/2/3/5), the unallocated
        #      opcode2 values and any nonzero opcode -- stays a typed refusal
        #      instead of widening the class.
        #      MODULE-ONLY: the G2 single-image IR keeps refusing the group.
        if ((word >> 21) & 0x3FF) == 0x2D6:
            opcode = (word >> 16) & 0x1F
            opcode2 = (word >> 10) & 0x3F
            if opcode != 0 or opcode2 not in (0x00, 0x04):
                raise DecodeError(
                    "one-source opcode not in subset (RBIT/CLZ only)")
            if not module:
                raise DecodeError("one-source RBIT/CLZ not in subset (G2)")
            return {"kind": "rbit" if opcode2 == 0 else "clz", "pc": pc,
                    "width": 64 if sf else 32,
                    "rn": (word >> 5) & 0x1F, "rd": word & 0x1F}

        if word == 0xD503201F:
            return {"kind": "nop", "pc": pc}

        # ---- MRS Xt, <sysreg>: only the four registers below are modeled.
        #      MSR (0xD51...) does not match this mask and fails closed below.
        if (word & 0xFFF00000) == 0xD5300000:
            sysreg16 = (word >> 5) & 0xFFFF
            rt = word & 0x1F
            if sysreg16 in SYSREG_COUNTERS:
                return {"kind": "mrs_counter", "pc": pc,
                        "sysreg16": sysreg16, "rt": rt}
            if sysreg16 in SYSREG_TPIDR:
                return {"kind": "mrs_tpidr", "pc": pc,
                        "field": SYSREG_TPIDR[sysreg16], "rt": rt}
            raise DecodeError("unsupported MRS sysreg field 0x%04x" % sysreg16)

        # ---- MSR TPIDR_EL0, Xt: MODULE ONLY. Writes the canonical guest
        #      tpidr field (patch_nso.py site_tpidr_write); never host TLS,
        #      never TPIDRRO, never an HLE. Rt=31 is XZR, NOT SP.
        if module and (word & 0xFFFFFFE0) == 0xD51BD040:
            return {"kind": "msr_tpidr", "pc": pc, "rt": word & 0x1F}

    # ---- MADD/MSUB: sf 00 11011 000 Rm o0 Ra Rn Rd ----
    #      o0=0 MADD, o0=1 MSUB; Ra=31 with o0=0 is the MUL alias.
    #      Only modulo-width arithmetic is required: signed and unsigned
    #      products are identical modulo 2^N, and NZCV is NOT written.
    if (word & 0x7FE00000) == 0x1B000000:
        if not module:
            raise DecodeError("MADD/MSUB not in subset (G2)")
        sf = (word >> 31) & 1
        return {"kind": "maddsub", "pc": pc,
                "width": 64 if sf else 32,
                "sub": (word >> 15) & 1,
                "rm": (word >> 16) & 0x1F,
                "ra": (word >> 10) & 0x1F,
                "rn": (word >> 5) & 0x1F, "rd": word & 0x1F}

    # ---- SMULH: sf 00 11011 00 Rm 011111 Rn Rd (X only)
    if (word & 0xFFE0FC00) == 0x9B407C00:
        if not module:
            raise DecodeError("SMULH not in subset (G2)")
        return {"kind": "smulh", "pc": pc,
                "rm": (word >> 16) & 0x1F,
                "rn": (word >> 5) & 0x1F, "rd": word & 0x1F}

    # ---- UMULH X: exact fixed-bit mask; no defined W form.  Rn/Rm=31
    #      read XZR, Rd=31 discards, and NZCV is NOT written.
    if (word & 0xFFE0FC00) == 0x9BC07C00:
        if not module:
            raise DecodeError("UMULH not in subset (G2)")
        return {"kind": "umulh", "pc": pc,
                "rm": (word >> 16) & 0x1F,
                "rn": (word >> 5) & 0x1F, "rd": word & 0x1F}

    # ---- UDIV/SDIV: sf 00 11010110 Rm 00001 o1 Rn Rd (data-processing,
    #      two source). o1 (bit 10) selects SDIV; 000011 is unallocated and
    #      every other bit is fixed, so both exact words below are the whole
    #      allocated class (bare "11010" also covers the 1-source forms, so
    #      the mask keeps bits 15:10). Division is defined instruction-level:
    #      x / 0 == 0, SDIV(INT_MIN, -1) == INT_MIN, no trap and no UB. NZCV
    #      is NOT written. Rn/Rm read XZR for 31, Rd=31 discards.
    if (word & 0x7FE0FC00) in (0x1AC00800, 0x1AC00C00):
        if not module:
            raise DecodeError("UDIV/SDIV not in subset (G2)")
        return {"kind": "sdiv" if (word >> 10) & 1 else "udiv", "pc": pc,
                "width": 64 if (word >> 31) & 1 else 32,
                "rm": (word >> 16) & 0x1F,
                "rn": (word >> 5) & 0x1F, "rd": word & 0x1F}

    # ---- Variable shifts: LSLV/LSRV/ASRV/RORV (data-processing, two source)
    #      sf 0 0 11010110 Rm opcode Rn Rd.  The opcode field is bits 15:10:
    #          0b001000 LSLV   0b001001 LSRV
    #          0b001010 ASRV   0b001011 RORV
    #      and every other bit outside sf/Rm/Rn/Rd is fixed, so the mask below
    #      keeps bits 30:21 and 15:10 (the same mask shape UDIV/SDIV uses).
    #      UDIV/SDIV (0b000010/0b000011) keep their own earlier branch; every
    #      other opcode in this class -- including the reserved 0b00xx00 and
    #      0b00xx11 holes -- falls through to the generic refusal instead of
    #      widening the accepted set.
    #      Semantics: the shift amount is Rm modulo the OPERAND WIDTH (low 5
    #      bits for W, low 6 for X), i.e. modulo 32/64 for ANY value including
    #      2^64-1, so no host shift is ever undefined. Rn/Rm=31 read XZR (not
    #      SP); a W form reads only the low 32 bits and zero-extends its
    #      result; Rd=31 discards; NZCV, FP and memory are untouched.
    #      MODULE-ONLY: the G2 single-image IR keeps refusing the class.
    if (word & 0x7FE0FC00) in (0x1AC02000, 0x1AC02400,
                               0x1AC02800, 0x1AC02C00):
        if not module:
            raise DecodeError("variable shift not in subset (G2)")
        return {"kind": "varshift", "pc": pc,
                "shift": ((word >> 10) & 0x3F) - 8,
                "width": 64 if (word >> 31) & 1 else 32,
                "rm": (word >> 16) & 0x1F, "rn": (word >> 5) & 0x1F,
                "rd": word & 0x1F}

    # ---- CCMP/CCMN (immediate and register): data-processing class
    #      sf op 11 11010010 <Rm|imm5> cond i 0 Rn 0 nzcv, where i (bit 11)
    #      selects the immediate (1) or register (0) form, op (bit 30) selects
    #      CCMP (1, compare => subtract) or CCMN (0, compare => add), cond is
    #      bits 15:12 and nzcv bits 3:0 are N,Z,C,V. Checked against llvm-mc
    #      (ccmp w2,w3,#7,gt == 0x7A43C047, ccmn w2,w3,#7,gt == 0x3A43C047,
    #      ccmp w2,#7,#7,gt == 0x7A47C847): the CCMP/CCMN selector really is
    #      bit 30, NOT an "o2" bit 10, and bit 11 -- not bit 4 -- separates
    #      the immediate form. Bit 10 and bit 4 are fixed 0 in every allocated
    #      encoding (llvm-mc rejects both when set), so they stay in the mask
    #      and a set bit is an explicit unallocated rejection.
    #      Semantics: if `cond` holds, NZCV is written exactly as CMP (CCMP)
    #      or CMN (CCMN) of Rn with the operand at `width` would write it; if
    #      it does not hold, NZCV is the instruction's own nzcv field and no
    #      comparison happens. Rn/Rm=31 read XZR (never SP); no GPR, SP,
    #      FPSR, FPCR or memory is touched, and there is no Rd field.
    if (word & 0x3FE00400) == 0x3A400000:
        if not module:
            raise DecodeError("CCMP/CCMN not in subset (G2)")
        if (word >> 4) & 1:
            raise DecodeError("conditional compare o3 (bit 4) set: unallocated")
        ins = {"kind": "ccmp", "pc": pc,
               "width": 64 if (word >> 31) & 1 else 32,
               "sub": 1 if (word >> 30) & 1 else 0,
               "cond": (word >> 12) & 0x0F,
               "rn": (word >> 5) & 0x1F, "nzcv": word & 0x0F,
               "imm_form": (word >> 11) & 1}
        if ins["imm_form"]:
            ins["imm"] = (word >> 16) & 0x1F
        else:
            ins["rm"] = (word >> 16) & 0x1F
        return ins

    raise DecodeError("unsupported instruction encoding 0x%08x" % word)


TERMINATORS = {"b", "bcond", "bl", "cbz", "cbnz", "tbz", "tbnz", "br",
               "blr", "ret", "svc", "mrs_counter", "unsupported"}


def successors(ins):
    pc = ins["pc"]
    k = ins["kind"]
    if k == "unsupported":
        return []
    if k == "b":
        return [ins["target"]]
    if k in ("bcond", "cbz", "cbnz", "tbz", "tbnz"):
        return [ins["target"], pc + 4]
    if k == "bl":
        return [ins["target"], pc + 4]
    if k == "blr":
        return [pc + 4]
    if k == "svc":
        return [pc + 4]
    if k == "mrs_counter":
        # AOT_EXIT_SYSREG resumes at site_pc + 4 through the handler, so the
        # following instruction must be its own block entry: the block ends
        # at the MRS and pc + 4 is seeded as a CFG start.
        return [pc + 4]
    return []


def in_ranges(ranges, pc):
    for start, end in ranges:
        if start <= pc < end:
            return True
    return False


def validate_thunks(thunks, ranges):
    """Offline generator check consistent with the runtime contract:
    stride 16, count <= UINT32_MAX, safe span, code/thunk disjoint."""
    base, count, stride = thunks
    if count == 0:
        return
    if stride != 16:
        raise DecodeError("thunk stride must be 16")
    if count > 0xFFFFFFFF:
        raise DecodeError("thunk count exceeds UINT32_MAX")
    if base == 0 or (base % 4) != 0:
        raise DecodeError("invalid thunk base 0x%x" % base)
    span = count * stride
    if base > 0xFFFFFFFFFFFFFFFF - span:
        raise DecodeError("thunk span overflow")
    tend = base + span
    for start, end in ranges:
        if base < end and start < tend:
            raise DecodeError("code/thunk range overlap")


# ---------------------------------------------------------------- CFG

def build_cfg(raw, ranges, entries, indirect_targets, base=0, module=False,
              local_edges=None):
    """Recover the reachable CFG.

    `ranges` and the entry/target PCs are GUEST virtual addresses; `base` is
    the guest VA of flat offset 0 (0 for the legacy single-image G2 mode, where
    file offsets and guest PCs are the same thing). A word at guest PC `pc` is
    read from `raw[pc - base]`. Only code reachable from the entries/targets is
    decoded, so data words inside the text segment (the crt0 MOD0 offset, the
    MOD0 struct, ...) are never decoded.

    `local_edges` is a PRIVATE module-mode extension: a map from an
    already-walked `BR` PC to proven local targets. It never seeds the
    initial work list - those remain the original entries and the legacy
    indirect targets only. When the walk reaches a `BR` that has proven
    local edges, its targets are appended to that instruction's successors
    exactly like a direct branch, so a target that is already visited still
    becomes a new basic-block start (split). The default `None` leaves the
    legacy G2 path byte-identical.
    """
    for i, (s, e) in enumerate(ranges):
        if s >= e:
            raise DecodeError("range %d: start >= end" % i)
        if (s % 4) != 0 or (e % 4) != 0:
            raise DecodeError("range %d: not 4-byte aligned" % i)
        if s < base:
            raise DecodeError("range %d: start 0x%x below the image base 0x%x"
                              % (i, s, base))
        if e - base > len(raw):
            raise DecodeError("range %d: end 0x%x exceeds file size 0x%x"
                              % (i, e, len(raw) + base))
        if i and s < ranges[i - 1][1]:
            raise DecodeError("range %d: overlaps or unsorted" % i)

    starts = set(entries) | set(indirect_targets)
    for pc in starts:
        if pc % 4 != 0:
            raise DecodeError("entry/target not 4-aligned: 0x%x" % pc)
        if not in_ranges(ranges, pc):
            raise DecodeError("entry/target outside declared ranges: 0x%x" % pc)

    visited = {}
    work = list(starts)
    while work:
        pc = work.pop()
        cur = pc
        while True:
            if cur in visited:
                break
            if cur % 4 != 0:
                raise DecodeError("misaligned decode at 0x%x" % cur)
            if not in_ranges(ranges, cur):
                raise DecodeError("execution leaves declared ranges at 0x%x" % cur)
            word = struct.unpack_from("<I", raw, cur - base)[0]
            try:
                ins = decode(cur, word, module=module)
            except DecodeError as exc:
                if not PARTIAL:
                    raise
                ins = {"kind": "unsupported", "pc": cur, "word": word,
                       "reason": str(exc)}
                ins["word"] = word
                visited[cur] = ins
                break
            ins["word"] = word
            visited[cur] = ins
            if ins["kind"] in TERMINATORS:
                succ = list(successors(ins))
                if module and local_edges and ins["kind"] == "br":
                    succ = succ + list(local_edges.get(ins["pc"], ()))
                for t in succ:
                    if t % 4 != 0:
                        raise DecodeError("branch target not 4-aligned: 0x%x" % t)
                    if not in_ranges(ranges, t):
                        raise DecodeError("branch target outside ranges: 0x%x" % t)
                    if t not in starts:
                        starts.add(t)
                        work.append(t)
                break
            cur += 4

    blocks = []
    for pc in sorted(starts):
        insns = []
        cur = pc
        while True:
            if cur not in visited:
                raise DecodeError("unreachable block start 0x%x" % cur)
            ins = visited[cur]
            insns.append(ins)
            if ins["kind"] in TERMINATORS:
                break
            nxt = cur + 4
            if nxt in starts:
                break
            cur = nxt
        blocks.append({"pc": pc, "insns": insns})
    return blocks, visited


# ------------------------------------------------- local-switch pipeline

def module_cfg(raw, ranges, entries, base, layout):
    """Build the module CFG, then extend it only with proven local switch
    edges from already-reached BR sites.

    No Context is created unless a reached BR matches the strict raw shape.
    The only new block starts are targets proven by Context.discover over the
    current reached graph; entries/roots/metadata are never discovery inputs.
    Iteration continues until the proven site set and the resulting graph are
    stable. Any site that fails proof or final revalidation is a fatal
    DecodeError for the whole module (even PARTIAL); edges are never
    retracted. Proofs are marked `verified-final-graph` only after the final
    discover succeeded on the graph built from the final edge set.
    """
    import g3_local_switch
    blocks, visited = build_cfg(raw, ranges, entries, [], base=base,
                                module=True)
    if not any(ins.get("kind") == "br"
               and g3_local_switch.matches_shape(raw, base, pc)
               for pc, ins in visited.items()):
        return blocks, visited, {}
    try:
        ctx = g3_local_switch.Context(raw, layout, base, decode)
    except (g3_local_switch.InputError, g3_local_switch.ProofError) as e:
        raise DecodeError("local switch context refused: %s" % e)
    local = {}
    proofs = {}
    provisional = {}
    for _ in range(64):
        blocks, visited = build_cfg(raw, ranges, entries, [], base=base,
                                    module=True, local_edges=local)
        try:
            # Stage 1 (provisional): defer ONLY undecoded raw incoming-branch
            # threats, so the proven case paths can be decoded into the graph.
            provisional = ctx.discover(visited, entries, local or None,
                                       defer_threats=True)
        except (g3_local_switch.InputError, g3_local_switch.ProofError) as e:
            raise DecodeError("local switch site refused: %s" % e)
        new_local = {pc: tuple(sorted(set(p.targets)))
                     for pc, p in provisional.items()}
        # Monotonicity: an accepted site may never disappear or change its
        # proven target set.  Retraction is not allowed; it is a module fault.
        for pc, tg in local.items():
            if pc not in new_local:
                raise DecodeError("local switch site 0x%x disappeared after "
                                  "expansion" % pc)
            if new_local[pc] != tg:
                raise DecodeError("local switch target set changed for 0x%x "
                                  "after expansion" % pc)
        if new_local == local:
            break
        local = new_local
    else:
        raise DecodeError("local switch fixpoint did not converge")
    # Stage 2 (final, strict): re-prove every site against the FINAL graph.
    # All deferred threats must be resolved by decoded code; the site set and
    # every target set must be exactly the provisional ones.  Only these
    # proofs may be marked verified-final-graph or reach code emission.
    try:
        proofs = ctx.discover(visited, entries, local or None,
                              defer_threats=False)
    except (g3_local_switch.InputError, g3_local_switch.ProofError) as e:
        raise DecodeError("local switch final graph refused: %s" % e)
    if set(proofs) != set(provisional):
        raise DecodeError("local switch site set changed on the final graph "
                          "(provisional %s, final %s)"
                          % ([hex(pc) for pc in sorted(provisional)],
                             [hex(pc) for pc in sorted(proofs)]))
    for pc in sorted(proofs):
        if proofs[pc].targets != provisional[pc].targets:
            raise DecodeError("local switch targets changed on the final graph "
                              "for 0x%x" % pc)
        if proofs[pc].deferred_threats:
            raise DecodeError("local switch 0x%x still has an unresolved "
                              "incoming-branch threat on the final graph: %s"
                              % (pc, [(hex(s), hex(t))
                                     for s, t in proofs[pc].deferred_threats]))
    final = {pc: p.with_closure("verified-final-graph")
             for pc, p in proofs.items()}
    return blocks, visited, {pc: final[pc] for pc in sorted(final)}


# ---------------------------------------------------------------- codegen

def expr_operand(ins, width, sp_for_rn):
    """Return a C expression for the shifted second operand of a shifted-reg
    ADD/SUB. Rm uses XZR selection (SP is not encodable there)."""
    base = "%s(s, %uu)" % (use("aot_gpr_zr"), ins["rm"])
    if ins["imm6"] == 0 and ins["shift"] == 0:
        return base
    return "%s(%s, %uu, %uu, %uu)" % (
        use("aot_shift"), base, width, ins["shift"], ins["imm6"])


def emit_ldst_value(out, size, opc, addr_expr, rt, dest64, pc):
    """Emit one scalar load/store; addr_expr is a C expression (no side effects)."""
    width = 8 << size
    mk = use("aot_fault_mem")
    out.append("    rt->site_pc = 0x%xull;" % pc)
    out.append("    {")
    out.append("        uint64_t aot_addr = %s;" % addr_expr)
    if opc == 0:
        out.append("        AotMemStatus aot_ms = aot_mem_st%d(&rt->mem, aot_addr, (uint%d_t)%s(s, %uu));"
                   % (width, width, use("aot_gpr_zr"), rt))
        out.append("        if (aot_ms != AOT_MEM_OK) return %s(rt, aot_addr, (int64_t)aot_ms);" % mk)
    elif opc == 1:
        out.append("        uint%d_t aot_v;" % width)
        out.append("        AotMemStatus aot_ms = aot_mem_ld%d(&rt->mem, aot_addr, &aot_v);" % width)
        out.append("        if (aot_ms != AOT_MEM_OK) return %s(rt, aot_addr, (int64_t)aot_ms);" % mk)
        out.append("        %s(s, %uu, (uint64_t)aot_v);" % (use("aot_set_zr"), rt))
    else:
        out.append("        int64_t aot_v = 0;")
        out.append("        AotMemStatus aot_ms = aot_mem_lds%d(&rt->mem, aot_addr, &aot_v);" % width)
        out.append("        if (aot_ms != AOT_MEM_OK) return %s(rt, aot_addr, (int64_t)aot_ms);" % mk)
        if dest64:
            out.append("        %s(s, %uu, (uint64_t)aot_v);" % (use("aot_set_zr"), rt))
        else:
            out.append("        %s(s, %uu, (uint64_t)(uint32_t)(int32_t)aot_v);"
                       % (use("aot_set_zr"), rt))
    out.append("    }")


def emit_insn(ins, out, switch_sites=None, switch_status=None):
    k = ins["kind"]
    pc = ins["pc"]
    if k == "unsupported":
        # Partial mode only: this block stops here with a typed fault whose
        # source is exactly this guest PC. Nothing is written to guest state
        # and there is no successor, so the fault has zero effect by
        # construction. `status` indexes the offline metadata table.
        status = PARTIAL_STATUS[pc]
        out.append("    rt->site_pc = 0x%xull;" % pc)
        out.append("    return %s(rt, 0x%xull, (int64_t)%du);"
                   % (use("aot_fault_unsupported"), pc, status))
        return
    if k == "movn":
        sh = ins["hw"] * 16
        val = (~((ins["imm16"] << sh) & 0xFFFFFFFFFFFFFFFF)) & 0xFFFFFFFFFFFFFFFF
        if ins["width"] == 32:
            val &= 0xFFFFFFFF
        out.append("    %s(s, %uu, 0x%016xull);" % (use("aot_set_zr"), ins["rd"], val))
    elif k == "movz":
        sh = ins["hw"] * 16
        val = (ins["imm16"] << sh) & 0xFFFFFFFFFFFFFFFF
        if ins["width"] == 32:
            val &= 0xFFFFFFFF
        out.append("    %s(s, %uu, 0x%016xull);" % (use("aot_set_zr"), ins["rd"], val))
    elif k == "movk":
        sh = ins["hw"] * 16
        mask = ~((0xFFFF << sh) & 0xFFFFFFFFFFFFFFFF) & 0xFFFFFFFFFFFFFFFF
        if ins["width"] == 32:
            mask &= 0xFFFFFFFF
        val = (ins["imm16"] << sh) & 0xFFFFFFFFFFFFFFFF
        out.append("    %s(s, %uu, (%s(s, %uu) & 0x%016xull) | 0x%016xull);"
                   % (use("aot_set_zr"), ins["rd"], use("aot_gpr_zr"),
                      ins["rd"], mask, val))
    elif k == "addsub_imm":
        # ADD/SUB (immediate): reg31 is SP/WSP for BOTH Rn and non-S Rd,
        # regardless of operand width. WSP writes zero-extend into SP.
        width = ins["width"]
        rn_expr = "%s(s, %uu)" % (use("aot_gpr_sp"), ins["rn"])
        a = rn_expr if width == 64 else "((uint32_t)(%s))" % rn_expr
        b = "0x%xull" % ins["imm"] if width == 64 else "(uint32_t)0x%xull" % ins["imm"]
        if ins["s"]:
            fn = use("aot_add64" if (width == 64 and ins["op"] == 0) else
                     "aot_sub64" if width == 64 else
                     "aot_add32" if ins["op"] == 0 else "aot_sub32")
            call = "%s(s, %s, %s, 1)" % (fn, a, b)
            out.append("    %s(s, %uu, %s);" % (use("aot_set_zr"), ins["rd"], call))
        else:
            fn = ("aot_add64" if width == 64 else "aot_add32") if ins["op"] == 0 \
                else ("aot_sub64" if width == 64 else "aot_sub32")
            call = "%s(s, %s, %s, 0)" % (use(fn), a, b)
            out.append("    %s(s, %uu, %s);" % (use("aot_set_sp"), ins["rd"], call))
    elif k == "addsub_shift":
        width = ins["width"]
        a = "%s(s, %uu)" % (use("aot_gpr_zr"), ins["rn"])
        b = expr_operand(ins, width, False)
        if width == 32:
            a = "(uint32_t)(%s)" % a
            b = "(uint32_t)(%s)" % b
        if ins["s"]:
            fn = use("aot_add64" if (width == 64 and ins["op"] == 0) else
                     "aot_sub64" if width == 64 else
                     "aot_add32" if ins["op"] == 0 else "aot_sub32")
            call = "%s(s, %s, %s, 1)" % (fn, a, b)
            out.append("    %s(s, %uu, %s);" % (use("aot_set_zr"), ins["rd"], call))
        else:
            fn = ("aot_add64" if width == 64 else "aot_add32") if ins["op"] == 0 \
                else ("aot_sub64" if width == 64 else "aot_sub32")
            call = "%s(s, %s, %s, 0)" % (use(fn), a, b)
            out.append("    %s(s, %uu, %s);" % (use("aot_set_zr"), ins["rd"], call))
    elif k in ("adrp", "adr"):
        # Value is fully resolved at translation time from the ABSOLUTE guest
        # PC, so a page-base mistake in the module offset cannot survive.
        aot_val = ins["value"]
        if MUTANT == "adrp_offset" and k == "adrp":
            # TEST-ONLY wrong implementation: ADRP paged from the MODULE
            # OFFSET instead of the absolute guest VA.
            aot_val = (((ins["pc"] - MODULE_BASE) & ~0xFFF) +
                       (sx(ins["imm"], 21) << 12)) & 0xFFFFFFFFFFFFFFFF
        out.append("    %s(s, %uu, 0x%016xull);"
                   % (use("aot_set_zr"), ins["rd"], aot_val))
    elif k == "logic_shift":
        width = ins["width"]
        a = "%s(s, %uu)" % (use("aot_gpr_zr"), ins["rn"])
        b = "%s(s, %uu)" % (use("aot_gpr_zr"), ins["rm"])
        inv = 1 if ins.get("invert") else 0
        if MUTANT == "logic_inv_ignoren":
            # TEST-ONLY wrong implementation: the N=1 (BIC/ORN/EON/BICS)
            # forms lowered exactly like their N=0 counterparts.
            inv = 0
        if inv and MUTANT == "logic_inv_beforeshift":
            # TEST-ONLY wrong implementation: invert BEFORE the shift. NOT
            # commutes with ASR and ROR (and with any shift amount 0), but not
            # with a NONZERO LSL/LSR, so the LSL/LSR lanes are the only
            # discriminative ones -- the MVN LSL#0 word that stopped the real
            # boot cannot witness this mutant.
            b = _invert_expr(width, b)
        if not (ins["imm6"] == 0 and ins["shift"] == 0):
            if MUTANT == "orr_noshift" and ins["op"] == 1:
                # TEST-ONLY wrong implementation: ORR (shifted register)
                # silently drops the shift amount.
                pass
            elif ins["shift"] == 3:
                # ROR reaches this emitter only on the inverted (N=1) forms:
                # ROR is architecturally legal for N=0 as well, but the N=0
                # SUBSET refuses it, so it never reaches here from N=0. aot_shift
                # stays untouched so existing generated images keep their
                # helper text byte for byte.
                b = "%s(%s, %uu, %uu)" % (use("aot_ror"), b, width,
                                           ins["imm6"])
            else:
                b = "%s(%s, %uu, %uu, %uu)" % (use("aot_shift"), b, width,
                                               ins["shift"], ins["imm6"])
        if inv and MUTANT != "logic_inv_beforeshift":
            b = _invert_expr(width, b)
        op = {0: "&", 1: "|", 2: "^", 3: "&"}[ins["op"]]
        if width == 32:
            a = "(uint32_t)(%s)" % a
            b = "(uint32_t)(%s)" % b
        expr = "%s %s %s" % (a, op, b)
        if width == 32:
            # 32-bit form: both operands are truncated and the result is
            # zero-extended into the 64-bit register, exactly like the other
            # 32-bit lowerings (a plain `uint32_t` result would be
            # sign-extended by an int-promoting compiler if uint32_t were
            # narrower than int).
            expr = "(uint64_t)(uint32_t)(%s)" % expr
        if ins.get("s") and not (MUTANT == "logic_inv_bics_skipflags"
                                  and inv):
            out.append("    {")
            out.append("        uint64_t aot_r = %s;" % expr)
            out.append("        s->nzcv = AOT_NZCV_PACK((aot_r >> %du) & 1ull, "
                       "(aot_r == 0u) ? 1ull : 0ull, 0ull, 0ull);"
                       % (width - 1))
            out.append("        %s(s, %uu, aot_r);" % (use("aot_set_zr"), ins["rd"]))
            out.append("    }")
        else:
            out.append("    %s(s, %uu, %s);"
                       % (use("aot_set_zr"), ins["rd"], expr))
    elif k == "rbit":
        # RBIT (1 source): reg31 is the ZERO register for BOTH Rn and Rd
        # (never SP), the reversal happens at the operand width, the W form
        # reads only the low 32 bits and zero-extends its (<=32-bit) result,
        # Rd==31 discards, and neither NZCV nor FP nor memory changes.
        width = ins["width"]
        src = "%s(s, %uu)" % (use("aot_gpr_zr"), ins["rn"])
        warg = width
        if MUTANT == "rbit_W_uses64":
            # TEST-ONLY wrong implementation: the W form reverses all 64
            # register bits and the result is STILL truncated and
            # zero-extended to 32 bits below. The zero-extension is therefore
            # CORRECT; only the operand width is wrong, so the destination
            # holds reverse32(high half) instead of reverse32(low half). This
            # isolates the subtle operand-width bug from an output-width bug.
            warg = 64
        expr = "%s(%s, %uu)" % (use("aot_rbit"), src, warg)
        if MUTANT == "rbit_identity":
            # TEST-ONLY wrong implementation: the source is copied unchanged
            # (still width-truncated/zero-extended) instead of reversed.
            expr = src if width == 64 else "(uint64_t)(uint32_t)(%s)" % src
        elif MUTANT == "rbit_byteswap":
            # TEST-ONLY wrong implementation: BYTE reverse, not BIT reverse.
            nbytes = width // 8
            terms = ["(((%s) >> %du) & 0xFFull) << %du"
                     % (src, 8 * b, 8 * (nbytes - 1 - b))
                     for b in range(nbytes)]
            expr = "(" + " | ".join(terms) + ")"
        if width == 32:
            # The result is always truncated/zero-extended at the operand
            # width -- including under the rbit_W_uses64 control, so that
            # control cannot hide behind a missing W zero-extension.
            expr = "(uint64_t)(uint32_t)(%s)" % expr
        if MUTANT == "rbit_clobber_flags":
            # TEST-ONLY wrong implementation: RBIT clears NZCV, which the real
            # instruction must never touch.
            out.append("    {")
            out.append("        s->nzcv = 0u;")
            out.append("        %s(s, %uu, %s);"
                       % (use("aot_set_zr"), ins["rd"], expr))
            out.append("    }")
        else:
            out.append("    %s(s, %uu, %s);"
                       % (use("aot_set_zr"), ins["rd"], expr))
    elif k == "clz":
        # CLZ (1 source): reg31 is the ZERO register for BOTH Rn and Rd
        # (never SP), the count is at the operand width, the W form reads only
        # the low 32 bits and zero-extends its (<=32) result, Rd==31 discards,
        # and neither NZCV nor FP nor memory changes.
        width = ins["width"]
        src = "%s(s, %uu)" % (use("aot_gpr_zr"), ins["rn"])
        warg = width
        if MUTANT == "clz_W_uses64":
            # TEST-ONLY wrong implementation: the W form counts leading zeros
            # over all 64 register bits instead of the low 32.
            warg = 64
        expr = "%s(%s, %uu)" % (use("aot_clz"), src, warg)
        if MUTANT == "clz_zero_wrong":
            # TEST-ONLY wrong implementation: an all-zero operand yields 0
            # instead of the operand width. Only a ZERO (or zero low-half)
            # operand can witness this; a real nonzero boot word cannot.
            # The predicate is evaluated at the OPERAND WIDTH, so the W
            # "zero result" case is exactly low-32-bits-zero (high half
            # ignored), not the whole raw register being zero.
            if width == 64:
                zexpr = "(%s) == 0u" % src
            else:
                zexpr = "(uint32_t)(%s) == 0u" % src
            expr = "(%s ? 0ull : %s)" % (zexpr, expr)
        if MUTANT == "clz_clobber_flags":
            # TEST-ONLY wrong implementation: CLZ clears NZCV, which real CLZ
            # must never touch.
            out.append("    {")
            out.append("        s->nzcv = 0u;")
            out.append("        %s(s, %uu, %s);"
                       % (use("aot_set_zr"), ins["rd"], expr))
            out.append("    }")
        else:
            out.append("    %s(s, %uu, %s);"
                       % (use("aot_set_zr"), ins["rd"], expr))
    elif k == "varshift":
        # LSLV/LSRV/ASRV/RORV. The amount is masked HERE, before the helper,
        # so the emitted C can never shift by an unmasked value: masking is
        # exactly the architectural "modulo operand width" rule, and it also
        # keeps aot_shift/aot_ror's "amount < w" precondition true by
        # construction (that is why their text does not change).
        width = ins["width"]
        a = "%s(s, %uu)" % (use("aot_gpr_zr"), ins["rn"])
        b = "%s(s, %uu)" % (use("aot_gpr_zr"), ins["rm"])
        mask = 0x3F if width == 64 else 0x1F
        amt = "((unsigned)(%s) & 0x%xu)" % (b, mask)
        if MUTANT == "varshift_W_uses64":
            # TEST-ONLY wrong implementation: the W form behaves like the
            # 64-bit form (no low-32 source, amount masked to 6 bits).
            width = 64
            mask = 0x3F
            amt = "((unsigned)(%s) & 0x%xu)" % (b, mask)
        shift_type = ins["shift"]
        if MUTANT == "varshift_asr_logical":
            # TEST-ONLY wrong implementation: ASRV lowered as LSRV.
            if shift_type == 2:
                shift_type = 1
        if width == 32:
            a = "(uint32_t)(%s)" % a
        if shift_type == 3:
            expr = "%s(%s, %uu, %s)" % (use("aot_ror"), a, width, amt)
        else:
            expr = "%s(%s, %uu, %uu, %s)" % (use("aot_shift"), a, width,
                                             shift_type, amt)
        if MUTANT == "varshift_oversize_zero":
            # TEST-ONLY wrong implementation: an amount >= the operand width
            # yields 0 instead of being taken modulo the width. The predicate
            # uses the width-masked source (so a W form compares the low 32
            # bits), and the ternary keeps every SUBSETcompliant path masked --
            # no unmasked host shift, so the mutant stays defined C and can
            # never turn this suite into a crash instead of a mismatch.
            if ins["width"] == 64:
                raw = "(%s)" % b
            else:
                raw = "((uint64_t)(uint32_t)(%s))" % b
            expr = "((%s) >= %uu ? 0ull : %s)" % (raw, ins["width"], expr)
        if width == 32:
            expr = "(uint64_t)(uint32_t)(%s)" % expr
        out.append("    %s(s, %uu, %s);"
                   % (use("aot_set_zr"), ins["rd"], expr))
    elif k == "logic_imm":
        width = ins["width"]
        a = "%s(s, %uu)" % (use("aot_gpr_zr"), ins["rn"])
        if width == 32:
            a = "(uint32_t)(%s)" % a
        op = {0: "&", 1: "|", 2: "^", 3: "&"}[ins["op"]]
        imm = ins["imm"] & (0xFFFFFFFF if width == 32 else 0xFFFFFFFFFFFFFFFF)
        expr = "%s %s 0x%xull" % (a, op, imm)
        if width == 32:
            expr = "(uint64_t)(uint32_t)(%s)" % expr
        if ins["op"] == 3:
            # ANDS: Rd=31 discards the result (TST) but sets NZCV.
            out.append("    {")
            out.append("        uint64_t aot_r = %s;" % expr)
            out.append("        s->nzcv = AOT_NZCV_PACK((aot_r >> %du) & 1ull, "
                       "(aot_r == 0u) ? 1ull : 0ull, 0ull, 0ull);"
                       % (width - 1))
            out.append("        %s(s, %uu, aot_r);" % (use("aot_set_zr"), ins["rd"]))
            out.append("    }")
        else:
            # AND/ORR/EOR immediate name <Xd|SP>/<Wd|WSP>, unlike the shifted
            # register form where 31 is XZR: Rd=31 writes SP/WSP.
            out.append("    %s(s, %uu, %s);"
                       % (use("aot_set_sp"), ins["rd"], expr))
    elif k == "addsub_ext":
        width = ins["width"]
        a = "%s(s, %uu)" % (use("aot_gpr_sp"), ins["rn"])
        b = "%s(%s(s, %uu), %uu, %uu)" % (
            use("aot_ext"), use("aot_gpr_zr"), ins["rm"],
            ins["option"], ins["imm3"])
        if width == 32:
            a = "(uint32_t)(%s)" % a
            b = "(uint32_t)(%s)" % b
        fn = ("aot_add64" if width == 64 else "aot_add32") if ins["op"] == 0 \
            else ("aot_sub64" if width == 64 else "aot_sub32")
        call = "%s(s, %s, %s, %du)" % (use(fn), a, b, ins["s"])
        if ins["s"]:
            out.append("    %s(s, %uu, %s);" % (use("aot_set_zr"), ins["rd"], call))
        else:
            out.append("    %s(s, %uu, %s);" % (use("aot_set_sp"), ins["rd"], call))
    elif k == "maddsub":
        a = "%s(s, %uu)" % (use("aot_gpr_zr"), ins["rn"])
        b = "%s(s, %uu)" % (use("aot_gpr_zr"), ins["rm"])
        c = "%s(s, %uu)" % (use("aot_gpr_zr"), ins["ra"])
        sub = ins["sub"]
        if MUTANT == "msub_reverse" and sub:
            # Negative control: a*b - c instead of c - a*b.
            sub = 0
        if ins["width"] == 32:
            prod = "((uint32_t)%s * (uint32_t)%s)" % (a, b)
            if MUTANT == "madd_ignore_ra":
                expr = "(uint64_t)(uint32_t)(%s)" % prod
            elif sub:
                expr = "(uint64_t)(uint32_t)((uint32_t)%s - %s)" % (c, prod)
            else:
                expr = "(uint64_t)(uint32_t)(%s + (uint32_t)%s)" % (prod, c)
            if MUTANT == "madd_no_zeroext":
                # Negative control: keep the 64-bit product/accumulator.
                prod64 = "(uint64_t)%s * (uint64_t)%s" % (a, b)
                if sub:
                    expr = "(uint64_t)(%s - %s)" % (c, prod64)
                else:
                    expr = "(uint64_t)(%s + %s)" % (prod64, c)
        else:
            prod = "((uint64_t)%s * (uint64_t)%s)" % (a, b)
            if MUTANT == "madd_ignore_ra":
                expr = prod
            elif sub:
                expr = "(uint64_t)(%s - %s)" % (c, prod)
            else:
                expr = "(uint64_t)(%s + %s)" % (prod, c)
        out.append("    %s(s, %uu, %s);"
                   % (use("aot_set_zr"), ins["rd"], expr))
    elif k == "smulh":
        fn = "aot_umulh" if MUTANT == "smulh_unsigned" else "aot_smulh"
        use("aot_umulh")
        out.append("    %s(s, %uu, %s(%s(s, %uu), %s(s, %uu)));"
                   % (use("aot_set_zr"), ins["rd"], use(fn),
                      use("aot_gpr_zr"), ins["rn"],
                      use("aot_gpr_zr"), ins["rm"]))
    elif k == "umulh":
        # Unsigned high 64.  The portable 32-limb helper is shared with the
        # SMULH negative control and stays unmodified; each UMULH mutant
        # selects its OWN wrong helper so the old SMULH first-mismatch
        # contracts are untouched.
        fn = {"umulh_signed": "aot_smulh",
              "umulh_lowprod": "aot_umulh_low64",
              "umulh_midcarry": "aot_umulh_nomidcarry"}.get(
                  MUTANT, "aot_umulh")
        out.append("    %s(s, %uu, %s(%s(s, %uu), %s(s, %uu)));"
                   % (use("aot_set_zr"), ins["rd"], use(fn),
                      use("aot_gpr_zr"), ins["rn"],
                      use("aot_gpr_zr"), ins["rm"]))
    elif k in ("udiv", "sdiv"):
        # Rd=31 discards (XZR); Rn/Rm=31 read zero. Both widths share the
        # helper, which owns the x/0, INT_MIN/-1 and W zero-extension rules.
        width = ins["width"]
        if MUTANT == "div_no_zeroext":
            # Negative control: the W form neither truncates its operands nor
            # zero-extends its result, so it runs as a full 64-bit divide.
            width = 64
        out.append("    %s(s, %uu, %s(%s(s, %uu), %s(s, %uu), %uu, %du));"
                   % (use("aot_set_zr"), ins["rd"], use("aot_div"),
                      use("aot_gpr_zr"), ins["rn"],
                      use("aot_gpr_zr"), ins["rm"], width,
                      1 if k == "sdiv" else 0))
    elif k == "ccmp":
        # CCMP/CCMN: NZCV-only write, no GPR/SP/memory effect. The condition
        # is evaluated FIRST (into a local) because the comparison it guards
        # overwrites the very flags it tests -- a chained ccmp/ccmn/csel
        # depends on that order. CMP (CCMP) and CMN (CCMN) reuse the same
        # aot_sub{32,64}/aot_add{32,64} flag helpers as SUBS/ADDS/CMP/CMN so
        # the N/Z/C/V definitions cannot drift; Rd=31 semantics do not apply
        # here because bits 3:0 are the nzcv field, not a destination.
        width = ins["width"]
        if MUTANT == "ccmp_w64":
            # Negative control: the W form compares as a 64-bit operation.
            width = 64
        a = "%s(s, %uu)" % (use("aot_gpr_zr"), ins["rn"])
        if ins["imm_form"]:
            b = "0x%xull" % ins["imm"]
        else:
            b = "%s(s, %uu)" % (use("aot_gpr_zr"), ins["rm"])
        if width == 32:
            a = "(uint32_t)(%s)" % a
            b = "(uint32_t)(%s)" % b
        fn = ("aot_sub64" if width == 64 else "aot_sub32") if ins["sub"] \
            else ("aot_add64" if width == 64 else "aot_add32")
        cond = ins["cond"]
        if MUTANT == "ccmp_cond_invert":
            # Negative control: the condition is evaluated with inverted
            # polarity (EQ as "Z == 0"), so both guarded paths swap.
            cond ^= 1
        nz = ins["nzcv"]
        pack = "AOT_NZCV_PACK(%dull, %dull, %dull, %dull)" % (
            (nz >> 3) & 1, (nz >> 2) & 1, (nz >> 1) & 1, nz & 1)
        out.append("    {")
        if MUTANT == "ccmp_ignore_cond":
            # Negative control: the comparison always runs, so the "condition
            # false" path (NZCV := the instruction's nzcv field) is dead.
            out.append("        (void)%s(s, %s, %s, 1);" % (use(fn), a, b))
        else:
            out.append("        int aot_take = %s(s, %du);"
                       % (use("aot_cond"), cond))
            out.append("        if (aot_take) { (void)%s(s, %s, %s, 1); }"
                       % (use(fn), a, b))
            out.append("        else { s->nzcv = %s; }" % pack)
        out.append("    }")
    elif k == "bfm":
        src = "%s(s, %uu)" % (use("aot_gpr_zr"), ins["rn"])
        dst = "%s(s, %uu)" % (use("aot_gpr_zr"), ins["rd"])
        out.append("    %s(s, %uu, %s(%s, %s, %uu, %uu, %uu, %uu));"
                   % (use("aot_set_zr"), ins["rd"], use("aot_bfm"),
                      src, dst, ins["width"], ins["immr"], ins["imms"],
                      ins["op"]))
    elif k == "simd_ldst":
        rt = ins["rt"]
        nb = ins["nbytes"]
        off = ins["offset"]
        if MUTANT == "simd_offset_scale":
            off = off // nb
        mk = use("aot_fault_mem")
        out.append("    rt->site_pc = 0x%xull;" % pc)
        out.append("    {")
        out.append("        uint64_t aot_addr = %s(s, %uu) + %dull;"
                   % (use("aot_gpr_sp"), ins["rn"], off))
        if ins["load"] == 0:                    # store: raw V bits
            if MUTANT == "simd_v31_discard" and rt == 31:
                vals = ["0u", "0u"]
            else:
                vals = ["s->v[%du][0]" % rt, "s->v[%du][1]" % rt]
            if nb == 4:
                out.append("        AotMemStatus aot_ms = aot_mem_st32(&rt->mem, aot_addr, (uint32_t)%s);" % vals[0])
            elif nb == 8:
                out.append("        AotMemStatus aot_ms = aot_mem_st64(&rt->mem, aot_addr, %s);" % vals[0])
            else:
                out.append("        uint64_t aot_v[2] = { %s, %s };" % (vals[0], vals[1]))
                out.append("        AotMemStatus aot_ms = aot_mem_st128(&rt->mem, aot_addr, aot_v);")
            out.append("        if (aot_ms != AOT_MEM_OK) return %s(rt, aot_addr, (int64_t)aot_ms);" % mk)
        else:                                    # load: fault BEFORE V write
            if nb == 4:
                out.append("        uint32_t aot_v;")
                out.append("        AotMemStatus aot_ms = aot_mem_ld32(&rt->mem, aot_addr, &aot_v);")
            elif nb == 8:
                out.append("        uint64_t aot_v;")
                out.append("        AotMemStatus aot_ms = aot_mem_ld64(&rt->mem, aot_addr, &aot_v);")
            else:
                out.append("        uint64_t aot_v[2];")
                out.append("        AotMemStatus aot_ms = aot_mem_ld128(&rt->mem, aot_addr, aot_v);")
            out.append("        if (aot_ms != AOT_MEM_OK) return %s(rt, aot_addr, (int64_t)aot_ms);" % mk)
            if MUTANT == "simd_v31_discard" and rt == 31:
                out.append("        (void)aot_v;")
            elif nb == 4:
                # AArch64: an S load ZEROES the upper bits of the vector
                # register; a D load zeroes the upper 64 bits. This is not a
                # numeric conversion and never touches FPCR/FPSR.
                if MUTANT == "simd_upper_clear":
                    out.append("        s->v[%du][0] = (s->v[%du][0] & 0xFFFFFFFF00000000ull) | (uint64_t)aot_v;" % (rt, rt))
                else:
                    out.append("        s->v[%du][0] = (uint64_t)aot_v;" % rt)
                    out.append("        s->v[%du][1] = 0u;" % rt)
            elif nb == 8:
                out.append("        s->v[%du][0] = (uint64_t)aot_v;" % rt)
                if MUTANT != "simd_upper_clear":
                    out.append("        s->v[%du][1] = 0u;" % rt)
            else:
                out.append("        s->v[%du][0] = aot_v[0];" % rt)
                out.append("        s->v[%du][1] = aot_v[1];" % rt)
        out.append("    }")
    elif k == "ldst_regoff":
        addr = "%s(s, %uu) + %s(%s(s, %uu), %uu, %uu)" % (
            use("aot_gpr_sp"), ins["rn"], use("aot_ext"),
            use("aot_gpr_zr"), ins["rm"], ins["option"], ins["shift"])
        emit_ldst_value(out, ins["size"], ins["opc"], addr, ins["rt"],
                        ins["dest64"], pc)
    elif k == "ldst_imm9":
        base = "%s(s, %uu)" % (use("aot_gpr_sp"), ins["rn"])
        off = ins["imm9"]
        mk = use("aot_fault_mem")
        out.append("    rt->site_pc = 0x%xull;" % pc)
        out.append("    {")
        out.append("        uint64_t aot_base = %s;" % base)
        if ins["mode"] == 1:
            addr = "aot_base"
        else:
            addr = "aot_base + (uint64_t)(int64_t)(%d)" % off
        out.append("        uint64_t aot_addr = %s;" % addr)
        width = 8 << ins["size"]
        if ins["opc"] == 0:
            out.append("        AotMemStatus aot_ms = aot_mem_st%d(&rt->mem, aot_addr, (uint%d_t)%s(s, %uu));"
                       % (width, width, use("aot_gpr_zr"), ins["rt"]))
            out.append("        if (aot_ms != AOT_MEM_OK) return %s(rt, aot_addr, (int64_t)aot_ms);" % mk)
        elif ins["opc"] == 1:
            out.append("        uint%d_t aot_v;" % width)
            out.append("        AotMemStatus aot_ms = aot_mem_ld%d(&rt->mem, aot_addr, &aot_v);" % width)
            out.append("        if (aot_ms != AOT_MEM_OK) return %s(rt, aot_addr, (int64_t)aot_ms);" % mk)
            out.append("        %s(s, %uu, (uint64_t)aot_v);" % (use("aot_set_zr"), ins["rt"]))
        else:
            out.append("        int64_t aot_v = 0;")
            out.append("        AotMemStatus aot_ms = aot_mem_lds%d(&rt->mem, aot_addr, &aot_v);" % width)
            out.append("        if (aot_ms != AOT_MEM_OK) return %s(rt, aot_addr, (int64_t)aot_ms);" % mk)
            if ins["dest64"]:
                out.append("        %s(s, %uu, (uint64_t)aot_v);" % (use("aot_set_zr"), ins["rt"]))
            else:
                out.append("        %s(s, %uu, (uint64_t)(uint32_t)(int32_t)aot_v);"
                           % (use("aot_set_zr"), ins["rt"]))
        if ins["mode"] in (1, 3):
            if MUTANT == "imm9_wb_nooff":
                wb = "aot_base"
            elif ins["mode"] == 1:
                wb = "aot_base + (uint64_t)(int64_t)(%d)" % off
            else:
                wb = "aot_addr"
            out.append("        %s(s, %uu, %s);"
                       % (use("aot_set_sp"), ins["rn"], wb))
        out.append("    }")
    elif k == "nop":
        out.append("    /* nop */")
    elif k == "mrs_counter":
        # Program mode: the runtime delivers the value through a SYSREG HLE
        # request whose id folds the sysreg field and Rt (XZR discard is the
        # handler's aot_sysreg_write_dest rule).
        out.append("    rt->site_pc = 0x%xull;" % pc)
        out.append("    rt->hle_id = AOT_SYSREG_ID(0x%04xu, %uu);"
                   % (ins["sysreg16"], ins["rt"]))
        out.append("    return AOT_EXIT_SYSREG;")
    elif k == "mrs_tpidr":
        out.append("    %s(s, %uu, s->%s);"
                   % (use("aot_set_zr"), ins["rt"], ins["field"]))
    elif k == "msr_tpidr":
        src = "%s(s, %uu)" % (use("aot_gpr_zr"), ins["rt"])
        if MUTANT == "msr_tpidr_xzr_sp":
            src = "(31u == %uu ? s->sp : %s)" % (ins["rt"], src)
        if MUTANT == "msr_tpidr_skip_xzr" and ins["rt"] == 31:
            out.append("    /* mutant: incorrectly omit the XZR write of zero */")
        elif MUTANT != "msr_tpidr_noop":
            field = "tpidrro" if MUTANT == "msr_tpidr_tpidrro" else "tpidr"
            out.append("    s->%s = %s;" % (field, src))
        else:
            out.append("    /* mutant: MSR TPIDR_EL0 dropped */")
        if MUTANT == "msr_tpidr_clobber_v":
            out.append("    s->v[31][1] ^= 1ull;")
        if MUTANT == "msr_tpidr_clobber_fpcr":
            out.append("    s->fpcr ^= 0x1000000ull;")
        if MUTANT == "msr_tpidr_clobber_fpsr":
            out.append("    s->fpsr ^= 0x8000000ull;")
    elif k == "b":
        out.append("    rt->site_pc = 0x%xull;" % pc)
        out.append("    rt->next_pc = 0x%xull;" % ins["target"])
        out.append("    return AOT_EXIT_BRANCH;")
    elif k == "bcond":
        out.append("    rt->site_pc = 0x%xull;" % pc)
        out.append("    rt->next_pc = %s(s, 0x%xu) ? 0x%xull : 0x%xull;"
                   % (use("aot_cond"), ins["cond"], ins["target"], pc + 4))
        out.append("    return AOT_EXIT_COND;")
    elif k in ("csel", "csinc", "csinv", "csneg"):
        width = ins["width"]
        a = "%s(s, %uu)" % (use("aot_gpr_zr"), ins["rn"])
        b = "%s(s, %uu)" % (use("aot_gpr_zr"), ins["rm"])
        if width == 32:
            a = "(uint32_t)(%s)" % a
            b = "(uint32_t)(%s)" % b
        if k == "csinc":
            b = "(%s + 1u)" % b
        elif k == "csinv":
            b = "~(%s)" % b
        elif k == "csneg":
            b = "(0u - (%s))" % b
        cond = ins["cond"] ^ 1 if MUTANT == "csel_cond" else ins["cond"]
        expr = "%s(s, %du) ? %s : %s" % (use("aot_cond"), cond, a, b)
        if width == 32:
            expr = "(uint32_t)(%s)" % expr
        out.append("    %s(s, %uu, (uint64_t)(%s));"
                   % (use("aot_set_zr"), ins["rd"], expr))
    elif k in ("cbz", "cbnz"):
        reg = "%s(s, %uu)" % (use("aot_gpr_zr"), ins["rt"])
        if ins["width"] == 32:
            reg = "((uint32_t)(%s))" % reg
        test = "(%s == 0u)" % reg if k == "cbz" else "(%s != 0u)" % reg
        out.append("    rt->site_pc = 0x%xull;" % pc)
        out.append("    rt->next_pc = %s ? 0x%xull : 0x%xull;"
                   % (test, ins["target"], pc + 4))
        out.append("    return AOT_EXIT_COND;")
    elif k in ("tbz", "tbnz"):
        reg = "%s(s, %uu)" % (use("aot_gpr_zr"), ins["rt"])
        if ins["width"] == 32:
            reg = "((uint32_t)(%s))" % reg
        bit = ins["bit"] ^ 1 if MUTANT == "tbz_bit" else ins["bit"]
        test = "(((%s) >> %du) & 1u)" % (reg, bit)
        if k == "tbz":
            test = "(%s == 0u)" % test
        else:
            test = "(%s != 0u)" % test
        out.append("    rt->site_pc = 0x%xull;" % pc)
        out.append("    rt->next_pc = %s ? 0x%xull : 0x%xull;"
                   % (test, ins["target"], pc + 4))
        out.append("    return AOT_EXIT_COND;")
    elif k == "bl":
        out.append("    rt->site_pc = 0x%xull;" % pc)
        out.append("    s->x[30] = 0x%xull;" % (pc + 4))
        out.append("    rt->next_pc = 0x%xull;" % ins["target"])
        out.append("    return AOT_EXIT_CALL;")
    elif k == "blr":
        out.append("    rt->site_pc = 0x%xull;" % pc)
        out.append("    {")
        if MUTANT == "blrorder":
            # Mutant: write LR before capturing the target (BLR x30 skips callee).
            out.append("        s->x[30] = 0x%xull;" % (pc + 4))
            out.append("        uint64_t aot_tgt = %s;" % ("%s(s, %uu)" % (use("aot_gpr_zr"), ins["rn"])))
        else:
            out.append("        uint64_t aot_tgt = %s;" % ("%s(s, %uu)" % (use("aot_gpr_zr"), ins["rn"])))
            out.append("        s->x[30] = 0x%xull;" % (pc + 4))
        out.append("        rt->next_pc = aot_tgt;")
        out.append("    }")
        out.append("    return AOT_EXIT_CALL_INDIRECT;")
    elif k == "br":
        out.append("    rt->site_pc = 0x%xull;" % pc)
        out.append("    rt->next_pc = %s(s, %uu);" % (use("aot_gpr_zr"), ins["rn"]))
        targets = (switch_sites or {}).get(pc)
        if targets is not None:
            # Proven local switch: the runtime guard is an assertion over the
            # proved set, never a substitute for the proof.
            uniq = tuple(sorted(set(targets)))
            cond = " && ".join("rt->next_pc != 0x%xull" % t for t in uniq)
            out.append("    if (%s) {" % cond)
            out.append("        rt->fault = AOT_FAULT_BAD_STATE;")
            out.append("        rt->fault_src = 0x%xull;" % pc)
            out.append("        rt->fault_target = rt->next_pc;")
            out.append("        rt->fault_status = %d;"
                       % (switch_status or {}).get(pc, 0))
            out.append("        rt->reason = AOT_EXIT_FAULT;")
            out.append("        return AOT_EXIT_FAULT;")
            out.append("    }")
        out.append("    return AOT_EXIT_INDIRECT;")
    elif k == "ret":
        out.append("    rt->site_pc = 0x%xull;" % pc)
        out.append("    rt->next_pc = %s(s, %uu);" % (use("aot_gpr_zr"), ins["rn"]))
        out.append("    return AOT_EXIT_RET;")
    elif k == "svc":
        out.append("    rt->site_pc = 0x%xull;" % pc)
        out.append("    rt->hle_id = 0x%xu;" % ins["imm16"])
        out.append("    return AOT_EXIT_SVC;")
    elif k in ("fmov_d", "fabs_d", "fneg_d"):
        # Pure bit operations; no host FP/NaN semantics. High 64 bits zeroed.
        out.append("    {")
        out.append("        uint64_t aot_w = s->v[%uu][0];" % ins["rn"])
        if k == "fabs_d":
            out.append("        aot_w &= 0x7fffffffffffffffull;")
        elif k == "fneg_d":
            out.append("        aot_w ^= 0x8000000000000000ull;")
        out.append("        s->v[%uu][0] = aot_w;" % ins["rd"])
        if MUTANT != "scalarupper":
            out.append("        s->v[%uu][1] = 0u;" % ins["rd"])
        out.append("    }")
    elif k in ("vand", "vorr", "veor"):
        op = {"vand": "&", "vorr": "|", "veor": "^"}[k]
        out.append("    {")
        out.append("        uint64_t aot_a0 = s->v[%uu][0], aot_a1 = s->v[%uu][1];" % (ins["rn"], ins["rn"]))
        out.append("        uint64_t aot_b0 = s->v[%uu][0], aot_b1 = s->v[%uu][1];" % (ins["rm"], ins["rm"]))
        out.append("        s->v[%uu][0] = aot_a0 %s aot_b0;" % (ins["rd"], op))
        out.append("        s->v[%uu][1] = aot_a1 %s aot_b1;" % (ins["rd"], op))
        out.append("    }")
    elif k in ("vadd", "vsub"):
        fn = use("aot_vadd_bytes" if k == "vadd" else "aot_vsub_bytes")
        out.append("    {")
        out.append("        uint64_t aot_a0 = s->v[%uu][0], aot_a1 = s->v[%uu][1];" % (ins["rn"], ins["rn"]))
        out.append("        uint64_t aot_b0 = s->v[%uu][0], aot_b1 = s->v[%uu][1];" % (ins["rm"], ins["rm"]))
        out.append("        s->v[%uu][0] = %s(aot_a0, aot_b0);" % (ins["rd"], fn))
        out.append("        s->v[%uu][1] = %s(aot_a1, aot_b1);" % (ins["rd"], fn))
        out.append("    }")
    elif k == "ldst_imm":
        width = 8 << ins["size"]
        mk = use("aot_fault_mem")
        out.append("    rt->site_pc = 0x%xull;" % pc)
        out.append("    {")
        out.append("        uint64_t aot_addr = %s(s, %uu) + 0x%xull;"
                   % (use("aot_gpr_sp"), ins["rn"], ins["imm12"] * (width // 8)))
        if ins["load"]:
            out.append("        uint%d_t aot_v;" % width)
            out.append("        AotMemStatus aot_ms = aot_mem_ld%d(&rt->mem, aot_addr, &aot_v);" % width)
            out.append("        if (aot_ms != AOT_MEM_OK) return %s(rt, aot_addr, (int64_t)aot_ms);" % mk)
            out.append("        %s(s, %uu, (uint64_t)aot_v);" % (use("aot_set_zr"), ins["rt"]))
        else:
            if MUTANT == "strdrop":
                out.append("        (void)aot_addr;   /* mutant: store dropped */")
            else:
                out.append("        AotMemStatus aot_ms = aot_mem_st%d(&rt->mem, aot_addr, (uint%d_t)%s(s, %uu));"
                           % (width, width, use("aot_gpr_zr"), ins["rt"]))
                out.append("        if (aot_ms != AOT_MEM_OK) return %s(rt, aot_addr, (int64_t)aot_ms);" % mk)
        out.append("    }")
    elif k == "ldst_signed":
        width = 8 << ins["size"]
        mk = use("aot_fault_mem")
        out.append("    rt->site_pc = 0x%xull;" % pc)
        out.append("    {")
        out.append("        uint64_t aot_addr = %s(s, %uu) + 0x%xull;"
                   % (use("aot_gpr_sp"), ins["rn"],
                      ins["imm12"] * (width // 8)))
        out.append("        int64_t aot_v = 0;")
        out.append("        AotMemStatus aot_ms = aot_mem_lds%d(&rt->mem, aot_addr, &aot_v);" % width)
        out.append("        if (aot_ms != AOT_MEM_OK) return %s(rt, aot_addr, (int64_t)aot_ms);" % mk)
        if ins["dest64"]:
            if MUTANT == "ldst_sign_zero":
                out.append("        %s(s, %uu, (uint64_t)(uint32_t)aot_v);"
                           % (use("aot_set_zr"), ins["rt"]))
            else:
                out.append("        %s(s, %uu, (uint64_t)aot_v);" % (use("aot_set_zr"), ins["rt"]))
        else:
            out.append("        %s(s, %uu, (uint64_t)(uint32_t)(int32_t)aot_v);"
                       % (use("aot_set_zr"), ins["rt"]))
        out.append("    }")
    elif k == "ldstp":
        scale = 8 if ins["width"] == 64 else 4
        off = ins["imm7"] * scale
        mk = use("aot_fault_mem")
        out.append("    rt->site_pc = 0x%xull;" % pc)
        out.append("    {")
        out.append("        uint64_t aot_base = %s(s, %uu);" % (use("aot_gpr_sp"), ins["rn"]))
        if ins["op2"] == 1:
            # post-index: access at the unmodified base, then write back base+off
            out.append("        uint64_t aot_addr = aot_base;")
        else:
            out.append("        uint64_t aot_addr = aot_base + (uint64_t)(int64_t)(%d);" % off)
        if ins["load"]:
            out.append("        uint64_t aot_v0 = 0u, aot_v1 = 0u;")
            out.append("        AotMemStatus aot_ms;")
            if ins["width"] == 64:
                out.append("        aot_ms = aot_mem_ld64(&rt->mem, aot_addr, &aot_v0);")
                out.append("        if (aot_ms != AOT_MEM_OK) return %s(rt, aot_addr, (int64_t)aot_ms);" % mk)
                out.append("        aot_ms = aot_mem_ld64(&rt->mem, aot_addr + 8u, &aot_v1);")
                out.append("        if (aot_ms != AOT_MEM_OK) return %s(rt, aot_addr + 8u, (int64_t)aot_ms);" % mk)
            else:
                out.append("        { uint32_t aot_w0 = 0u, aot_w1 = 0u;")
                out.append("          aot_ms = aot_mem_ld32(&rt->mem, aot_addr, &aot_w0);")
                out.append("          if (aot_ms != AOT_MEM_OK) return %s(rt, aot_addr, (int64_t)aot_ms);" % mk)
                out.append("          aot_ms = aot_mem_ld32(&rt->mem, aot_addr + 4u, &aot_w1);")
                out.append("          if (aot_ms != AOT_MEM_OK) return %s(rt, aot_addr + 4u, (int64_t)aot_ms);" % mk)
                out.append("          aot_v0 = aot_w0; aot_v1 = aot_w1; }")
            out.append("        %s(s, %uu, aot_v0);" % (use("aot_set_zr"), ins["rt"]))
            out.append("        %s(s, %uu, aot_v1);" % (use("aot_set_zr"), ins["rt2"]))
        else:
            # Major 1: in MODULE mode a pair store is ONE access. The old
            # lowering emitted two independent stores, so a pair straddling a
            # RW->R page boundary wrote the first half and then faulted, leaving
            # 8 guest bytes modified by an instruction that must be all-or-
            # nothing (the hardware raises the fault before either half lands).
            #   STP x: one 16-byte store of {Rt, Rt2}      -> mem_st128
            #   STP w: one 8-byte store of  Rt | Rt2 << 32  -> mem_st64
            # The G2 single-image path keeps the original two-store text byte
            # for byte (aot_g2_gen_identity pins it).
            if MODULE_MODE and MUTANT != "stp_split":
                if ins["width"] == 64:
                    # aot_mem_st128 is an aot_mem.c symbol (like aot_mem_st64
                    # above), not a generated helper: never route it through use().
                    out.append("        AotMemStatus aot_ms = aot_mem_st128(&rt->mem, aot_addr, "
                               "(const uint64_t[2]){ (uint64_t)%s(s, %uu), "
                               "(uint64_t)%s(s, %uu) });"
                               % (use("aot_gpr_zr"), ins["rt"],
                                  use("aot_gpr_zr"), ins["rt2"]))
                    out.append("        if (aot_ms != AOT_MEM_OK) return %s(rt, aot_addr, (int64_t)aot_ms);" % mk)
                else:
                    out.append("        AotMemStatus aot_ms = aot_mem_st64(&rt->mem, aot_addr, "
                               "((uint64_t)(uint32_t)%s(s, %uu)) | "
                               "((uint64_t)(uint32_t)%s(s, %uu) << 32));"
                               % (use("aot_gpr_zr"), ins["rt"],
                                  use("aot_gpr_zr"), ins["rt2"]))
                    out.append("        if (aot_ms != AOT_MEM_OK) return %s(rt, aot_addr, (int64_t)aot_ms);" % mk)
            elif MUTANT == "stp_split" and MODULE_MODE and ins["width"] == 64:
                # TEST-ONLY wrong-implementation control: the pre-Major-1
                # two-store lowering, which partially writes a straddling pair.
                out.append("        AotMemStatus aot_ms = aot_mem_st64(&rt->mem, aot_addr, %s(s, %uu));" % (use("aot_gpr_zr"), ins["rt"]))
                out.append("        if (aot_ms != AOT_MEM_OK) return %s(rt, aot_addr, (int64_t)aot_ms);" % mk)
                out.append("        aot_ms = aot_mem_st64(&rt->mem, aot_addr + 8u, %s(s, %uu));" % (use("aot_gpr_zr"), ins["rt2"]))
                out.append("        if (aot_ms != AOT_MEM_OK) return %s(rt, aot_addr + 8u, (int64_t)aot_ms);" % mk)
            elif ins["width"] == 64:
                out.append("        AotMemStatus aot_ms = aot_mem_st64(&rt->mem, aot_addr, %s(s, %uu));" % (use("aot_gpr_zr"), ins["rt"]))
                out.append("        if (aot_ms != AOT_MEM_OK) return %s(rt, aot_addr, (int64_t)aot_ms);" % mk)
                out.append("        aot_ms = aot_mem_st64(&rt->mem, aot_addr + 8u, %s(s, %uu));" % (use("aot_gpr_zr"), ins["rt2"]))
                out.append("        if (aot_ms != AOT_MEM_OK) return %s(rt, aot_addr + 8u, (int64_t)aot_ms);" % mk)
            else:
                out.append("        AotMemStatus aot_ms = aot_mem_st32(&rt->mem, aot_addr, (uint32_t)%s(s, %uu));" % (use("aot_gpr_zr"), ins["rt"]))
                out.append("        if (aot_ms != AOT_MEM_OK) return %s(rt, aot_addr, (int64_t)aot_ms);" % mk)
                out.append("        aot_ms = aot_mem_st32(&rt->mem, aot_addr + 4u, (uint32_t)%s(s, %uu));" % (use("aot_gpr_zr"), ins["rt2"]))
                out.append("        if (aot_ms != AOT_MEM_OK) return %s(rt, aot_addr + 4u, (int64_t)aot_ms);" % mk)
        if ins["op2"] == 3:
            newb = "aot_addr"
        elif ins["op2"] == 1:
            newb = "aot_base + (uint64_t)(int64_t)(%d)" % off
        else:
            newb = None
        if newb is not None:
            # The writeback base is ALWAYS a 64-bit register, even for STP/LDP
            # with 32-bit data (WSP zero-extension applies only to arithmetic).
            if MUTANT == "pair32trunc" and ins["width"] == 32:
                newb = "(uint64_t)(uint32_t)(%s)" % newb   # reintroduced old bug
            out.append("        %s(s, %uu, %s);" % (use("aot_set_sp"), ins["rn"], newb))
        out.append("    }")
    elif k in ("fadd", "fsub", "fmul", "fdiv"):
        w = ins["width"]
        fn = use({"fadd": "aot_fp_add32" if w == 32 else "aot_fp_add64",
                  "fsub": "aot_fp_sub32" if w == 32 else "aot_fp_sub64",
                  "fmul": "aot_fp_mul32" if w == 32 else "aot_fp_mul64",
                  "fdiv": "aot_fp_div32" if w == 32 else "aot_fp_div64"}[k])
        out.append("    rt->site_pc = 0x%xull;" % pc)
        # Explicit fault BEFORE any destination/FPSR write. A default-NaN
        # result here would be a silently wrong guest result.
        out.append("    if (!aot_fp_supported((uint32_t)s->fpcr))")
        if MUTANT == "fpignoreguard":
            out.append("        s->fpcr = 0u;   /* mutant: sanitized instead of faulting */")
        else:
            out.append("        return %s(rt, 0x%xull, "
                       "(int64_t)AOT_FP_ERR_UNSUPPORTED_FPCR);"
                       % (use("aot_fault_state"), pc))
        out.append("    {")
        arg1 = "(uint32_t)s->v[%uu][0]" % ins["rn"]
        arg2 = "(uint32_t)s->v[%uu][0]" % ins["rm"]
        ctype = "uint32_t"
        if w == 64:
            arg1 = "s->v[%uu][0]" % ins["rn"]
            arg2 = "s->v[%uu][0]" % ins["rm"]
            ctype = "uint64_t"
        if MUTANT == "fpnanorder" and k == "fadd":
            arg1, arg2 = arg2, arg1   # mutant: FADD operand order swapped
        if MUTANT == "fproundrn":
            # Mutant: force RN around the helper, then restore the guest FPCR.
            out.append("        uint64_t aot_save_fpcr = s->fpcr;")
            out.append("        s->fpcr = aot_save_fpcr & ~0x00c00000ull;")
            out.append("        %s aot_r = %s(s, %s, %s);" % (ctype, fn, arg1, arg2))
            out.append("        s->fpcr = aot_save_fpcr;")
        else:
            out.append("        %s aot_r = %s(s, %s, %s);" % (ctype, fn, arg1, arg2))
        if MUTANT == "fpdropflags":
            out.append("        s->fpsr = 0u;   /* mutant: flags dropped */")
        out.append("        s->v[%uu][0] = (uint64_t)aot_r;" % ins["rd"])
        out.append("        s->v[%uu][1] = 0u;" % ins["rd"])
        out.append("    }")
    elif k in ("fcmp", "fcmp_zero"):
        w = ins["width"]
        fn = use("aot_fp_cmp32" if w == 32 else "aot_fp_cmp64")
        a = ("(uint32_t)s->v[%uu][0]" if w == 32 else "s->v[%uu][0]") % ins["rn"]
        if k == "fcmp":
            b = ("(uint32_t)s->v[%uu][0]" if w == 32 else "s->v[%uu][0]") % ins["rm"]
        else:
            b = "0u" if w == 32 else "0ull"
        out.append("    rt->site_pc = 0x%xull;" % pc)
        out.append("    if (!aot_fp_supported((uint32_t)s->fpcr))")
        if MUTANT == "fpignoreguard":
            out.append("        s->fpcr = 0u;   /* mutant: sanitized instead of faulting */")
        else:
            out.append("        return %s(rt, 0x%xull, "
                       "(int64_t)AOT_FP_ERR_UNSUPPORTED_FPCR);"
                       % (use("aot_fault_state"), pc))
        out.append("    s->nzcv = (uint64_t)%s(s, %s, %s, %du);"
                   % (fn, a, b, ins["signaling"]))
    elif k in ("ldxr", "ldaxr", "ldar"):
        w = ins["width"] // 8   # decode width is BITS; helpers take BYTES
        out.append("    rt->site_pc = 0x%xull;" % pc)
        out.append("    {")
        out.append("        uint64_t aot_v = 0u;")
        out.append("        uint64_t aot_addr = %s(s, %uu);"
                   % (use("aot_gpr_sp"), ins["rn"]))
        if k in ("ldxr", "ldaxr"):
            out.append("        if (rt->monitor_token == 0u) return %s(rt, "
                       "0x%xull, -1);" % (use("aot_fault_state"), pc))
            out.append("        AotMemStatus aot_ms = aot_mem_ldx(&rt->mem, "
                       "rt->monitor_token, aot_addr, %uu, &aot_v);" % w)
        else:
            out.append("        AotMemStatus aot_ms = aot_mem_ldar(&rt->mem, "
                       "aot_addr, %uu, &aot_v);" % w)
        out.append("        if (aot_ms != AOT_MEM_OK) return %s(rt, aot_addr, "
                   "(int64_t)aot_ms);" % use("aot_fault_mem"))
        out.append("        %s(s, %uu, aot_v);" % (use("aot_set_zr"), ins["rt"]))
        out.append("    }")
    elif k in ("stxr", "stlxr"):
        w = ins["width"] // 8   # decode width is BITS; helpers take BYTES
        out.append("    rt->site_pc = 0x%xull;" % pc)
        out.append("    {")
        out.append("        uint64_t aot_addr = %s(s, %uu);"
                   % (use("aot_gpr_sp"), ins["rn"]))
        out.append("        uint32_t aot_ok = 1u;")
        out.append("        if (rt->monitor_token == 0u) return %s(rt, 0x%xull, -1);"
                   % (use("aot_fault_state"), pc))
        out.append("        AotMemStatus aot_ms = aot_mem_stx(&rt->mem, "
                   "rt->monitor_token, aot_addr, %uu, %s(s, %uu), &aot_ok);"
                   % (w, use("aot_gpr_zr"), ins["rt"]))
        out.append("        if (aot_ms != AOT_MEM_OK) return %s(rt, aot_addr, "
                   "(int64_t)aot_ms);" % use("aot_fault_mem"))
        if MUTANT == "stxalwaysok":
            out.append("        aot_ok = 0u;   /* mutant: always success */")
        out.append("        %s(s, %uu, (uint64_t)aot_ok);"
                   % (use("aot_set_zr"), ins["rs"]))
        out.append("    }")
    elif k == "stlr":
        w = ins["width"] // 8   # decode width is BITS; helpers take BYTES
        out.append("    rt->site_pc = 0x%xull;" % pc)
        out.append("    {")
        out.append("        uint64_t aot_addr = %s(s, %uu);"
                   % (use("aot_gpr_sp"), ins["rn"]))
        out.append("        AotMemStatus aot_ms = aot_mem_stlr(&rt->mem, "
                   "aot_addr, %uu, %s(s, %uu));"
                   % (w, use("aot_gpr_zr"), ins["rt"]))
        out.append("        if (aot_ms != AOT_MEM_OK) return %s(rt, aot_addr, "
                   "(int64_t)aot_ms);" % use("aot_fault_mem"))
        out.append("    }")
    elif k == "clrex":
        out.append("    aot_mem_clrex(&rt->mem, rt->monitor_token);")
    elif k == "barrier":
        # SC domain: DMB/DSB/ISB ordering already holds. The canonical DMB ISH
        # form (module-only) uses exactly this same fence; the test-only
        # controls below mark themselves on that form only, never on the
        # legacy SY barriers, so the old IR/output stays identical.
        if ins.get("option") == "ish":
            if MUTANT == "dmb_ish_clobber_flags":
                out.append("    s->nzcv = 0u;   /* mutant: DMB ISH clears NZCV */")
            elif MUTANT == "dmb_ish_clearexclusive":
                out.append("    aot_mem_clrex(&rt->mem, rt->monitor_token);"
                           "   /* mutant: DMB treated as CLREX */")
            elif MUTANT == "dmb_ish_clobber_gpr":
                out.append("    %s(s, 5u, 0u);   /* mutant: DMB clobbers x5 */"
                           % use("aot_set_zr"))
        out.append("    aot_mem_fence();   /* barrier valid as no-op under SC */")
    else:
        raise DecodeError("codegen: unknown kind %s" % k)


def emit_c(name, blocks, ranges, sha, fnv, thunks, subset_id=AOT_SUBSET_ID,
           abi_expr="AOT_ABI_VERSION", provenance=None, switch_sites=None):
    """Emit one AotImage translation unit.

    Defaults reproduce the legacy G2 single-image ABI-v1 output byte for
    byte. G3 module mode passes its own subset id, the Program ABI version
    symbol, and the module flat SHA-256 as the image source identity.
    """
    head = []
    head.append("/* Generated by tools/aot/aot_translate.py -- DO NOT EDIT.")
    head.append(" * subset: %s" % subset_id)
    head.append(" * source sha256: %s" % sha)
    if provenance is not None:
        head.append(" * provenance: %s" % provenance)
    head.append(" * fixture fnv1a64: 0x%016x (quick check only)" % fnv)
    head.append(" */")
    head.append('#include "aot_runtime.h"')
    head.append('#include "aot_fp.h"')
    head.append("#include <stdint.h>")
    head.append("")
    # Blocks are emitted first so `use()` records every helper before the
    # helper section (which must precede its uses) is constructed.
    out = []
    switch_status = {}
    for i, pc in enumerate(sorted(switch_sites or {})):
        switch_status[pc] = LOCAL_SWITCH_STATUS_BASE - (i + 1)
    out.append("/* ---- straight-line native basic blocks ---- */")
    for blk in blocks:
        out.append("static AotExit aot_blk_%x(AotGuestState *s, AotRuntime *rt) {" % blk["pc"])
        out.append("    (void)s; (void)rt;")
        for ins in blk["insns"]:
            emit_insn(ins, out, switch_sites, switch_status)
        last = blk["insns"][-1]
        if last["kind"] not in TERMINATORS:
            # Straight-line block: explicit fallthrough to the next PC. The
            # site_pc is the last instruction (used as the fault source if the
            # successor turns out not to be a translated entry).
            out.append("    rt->site_pc = 0x%xull;" % last["pc"])
            out.append("    rt->next_pc = 0x%xull;" % (last["pc"] + 4))
            out.append("    return AOT_EXIT_FALLTHROUGH;")
        out.append("}")
        out.append("")
    out.append("static const AotBlockEntry aot_blocks_%s[] = {" % name)
    for blk in blocks:
        out.append("    { 0x%xull, aot_blk_%x }," % (blk["pc"], blk["pc"]))
    out.append("};")
    out.append("")
    out.append("static const AotCodeRange aot_ranges_%s[] = {" % name)
    for start, end in ranges:
        out.append("    { 0x%xull, 0x%xull }," % (start, end))
    out.append("};")
    out.append("")
    out.append("const AotImage aot_image_%s = {" % name)
    out.append('    "%s",' % subset_id)
    out.append("    %s, AOT_STATE_LAYOUT," % abi_expr)
    out.append('    "%s",' % sha)
    out.append("    0x%016xull," % fnv)
    out.append("    aot_blocks_%s, sizeof(aot_blocks_%s) / sizeof(aot_blocks_%s[0]),"
               % (name, name, name))
    out.append("    aot_ranges_%s, sizeof(aot_ranges_%s) / sizeof(aot_ranges_%s[0]),"
               % (name, name, name))
    out.append("    0x%xull, 0x%xull, 0x%xull" % (thunks[0], thunks[1], thunks[2]))
    out.append("};")
    out.append("")
    helpers = ["/* ---- generated semantic helpers ---- */"]
    for hname in sorted(_USED):
        src = _HELPERS[hname].strip("\n")
        # Real-lowering mutants (test-only; normal image is untouched).
        if MUTANT == "wrongcarry" and hname == "aot_add64":
            src = src.replace("uint64_t c = (r < a) ? 1ull : 0ull;",
                              "uint64_t c = 0ull;")
        if MUTANT == "wrongcarry" and hname == "aot_sub64":
            src = src.replace("uint64_t c = (a >= b) ? 1ull : 0ull;",
                              "uint64_t c = 0ull;")
        if MUTANT == "wrongcarry" and hname == "aot_add32":
            src = src.replace("uint64_t c = (r < a) ? 1ull : 0ull;",
                              "uint64_t c = 0ull;")
        if MUTANT == "wrongcarry" and hname == "aot_sub32":
            src = src.replace("uint64_t c = (a >= b) ? 1ull : 0ull;",
                              "uint64_t c = 0ull;")
        if MUTANT == "lostwzeroext" and hname in ("aot_add32", "aot_sub32"):
            src = src.replace("return (uint64_t)r;",
                              "return (uint64_t)(int64_t)(int32_t)r;")
        if MUTANT == "div_zero_ones" and hname == "aot_div":
            # Negative control: a zero divisor returns all-ones instead of 0.
            src = src.replace("if (b == 0u) return 0u;",
                              "if (b == 0u) return mask;")
        if MUTANT == "sdiv_overflow_clamp" and hname == "aot_div":
            # Negative control: SDIV(INT_MIN, -1) is clamped to INT_MAX
            # instead of wrapping to INT_MIN (no host #DE, so the divergence
            # stays a field-level failure rather than a process abort).
            src = src.replace("return (uint64_t)INT64_MIN;",
                              "return 0x7FFFFFFFFFFFFFFFull;")
            src = src.replace("return (uint64_t)(uint32_t)INT32_MIN;",
                              "return 0x7FFFFFFFull;")
        if MUTANT == "wrongcond" and hname == "aot_cond":
            src = src.replace("case AOT_COND_EQ: return z == 1ull;",
                              "case AOT_COND_EQ: return z == 0ull;")
            src = src.replace("case AOT_COND_NE: return z == 0ull;",
                              "case AOT_COND_NE: return z == 1ull;")
        helpers.append(src)
    helpers.append("")
    return "\n".join(head + helpers + out)


def module_layout_ranges(layout, guest_base):
    """The decoded code range(s) in GUEST virtual addresses: the text
    segment only, so rodata/data (including the crt0 MOD0 words that precede
    the text in a real image) are never decoded."""
    text_off, text_size = layout["text"]
    if text_size <= 0:
        raise DecodeError("layout text segment is empty")
    return [(guest_base + text_off, guest_base + text_off + text_size)]


def read_entries(path):
    with open(path, "rb") as f:
        data = json.loads(f.read().decode("utf-8"))
    if isinstance(data, dict):
        data = data.get("entries")
    if not isinstance(data, list):
        raise DecodeError("entries file must be a JSON array of guest VAs")
    entries = []
    for v in data:
        if isinstance(v, bool) or not isinstance(v, (int, str)):
            raise DecodeError("bad entry value %r" % (v,))
        pc = int(v, 0) if isinstance(v, str) else int(v)
        if pc < 0 or pc > 0xFFFFFFFFFFFFFFFF:
            raise DecodeError("entry 0x%x out of range" % pc)
        entries.append(pc)
    if not entries:
        raise DecodeError("module has no entries (nothing to translate)")
    return sorted(set(entries))


def run_module(args):
    """--module: translate one linked module flat into an ABI-v2 image."""
    global MODULE_BASE, MODULE_MODE, PARTIAL
    MODULE_BASE = 0
    MODULE_MODE = 1
    PARTIAL = 1 if getattr(args, "partial", False) else 0
    for opt, val in (("--flat", args.flat), ("--layout", args.layout),
                     ("--guest-base", args.guest_base),
                     ("--entries", args.entries)):
        if val is None:
            sys.stderr.write("aot_translate: FAIL-CLOSED: --module requires %s\n" % opt)
            return 1
    with open(args.flat, "rb") as f:
        raw = f.read()
    with open(args.layout, "rb") as f:
        layout_bytes = f.read()
    with open(__file__, "rb") as f:
        gen_bytes = f.read()
    try:
        layout = json.loads(layout_bytes.decode("utf-8"))
        guest_base = int(args.guest_base, 0)
        MODULE_BASE = guest_base
        # Minor 8: the module base is a PAGE base inside the guest window the
        # loader enforces ([2^32, 2^39)). A 4-byte-aligned or out-of-window base
        # would produce an image whose code ranges can never be mapped by
        # aot_as (page granularity) or bound by build_program, so it is rejected
        # here instead of at load time.
        if guest_base % AOT_AS_PAGE_BYTES != 0 or guest_base < AOT_AS_MIN_ADDR \
                or guest_base >= AOT_AS_MAX_ADDR:
            raise DecodeError("guest base 0x%x is not a 4 KiB aligned base "
                              "inside [0x%x, 0x%x)"
                              % (guest_base, AOT_AS_MIN_ADDR, AOT_AS_MAX_ADDR))
        if len(raw) != layout["image_size"] - layout.get("bss_size", 0):
            raise DecodeError("flat size 0x%x disagrees with layout image_size "
                              "0x%x - bss 0x%x"
                              % (len(raw), layout["image_size"],
                                 layout.get("bss_size", 0)))
        flat_sha = hashlib.sha256(raw).hexdigest()
        if layout.get("sha256") and layout["sha256"] != flat_sha:
            raise DecodeError("flat SHA-256 0x%s does not match layout.json"
                              % flat_sha[:16])
        ranges = module_layout_ranges(layout, guest_base)
        entries = read_entries(args.entries)
        for pc in entries:
            if not in_ranges(ranges, pc):
                raise DecodeError("entry 0x%x is outside the text segment" % pc)
        blocks, visited, switch_proofs = module_cfg(
            raw, ranges, entries, guest_base, layout)
        # Emission gate (D022): only the strict final-graph proof may drive
        # codegen.  A not-verified-final proof or any remaining deferred
        # threat is fatal; the runtime guard is never a substitute.
        for pc, p in switch_proofs.items():
            if p.closure != "verified-final-graph":
                raise DecodeError("local switch 0x%x is not "
                                  "verified-final-graph (closure %r)"
                                  % (pc, p.closure))
            if p.deferred_threats:
                raise DecodeError("local switch 0x%x still has deferred "
                                  "incoming-branch threats" % pc)
        unsup = sorted((pc for pc, ins in visited.items()
                        if ins["kind"] == "unsupported"))
        PARTIAL_STATUS.clear()
        PARTIAL_STATUS.update({pc: i for i, pc in enumerate(unsup)})
        # Provenance of the translation (evidence only); the image identity is
        # the module flat SHA-256 the loader binds the descriptor to.
        h = hashlib.sha256()
        h.update(raw)
        h.update(layout_bytes)
        h.update(gen_bytes)
        # The local-switch prover is part of the trusted code path, so its
        # exact source bytes and the Capstone build are provenance inputs.
        import g3_local_switch as _g3
        with open(_g3.__file__, "rb") as f:
            h.update(f.read())
        # aot_module.py supplies the loader metadata parsing the prover trusts.
        import aot_module as _m
        with open(_m.__file__, "rb") as f:
            h.update(f.read())
        try:
            import capstone as _cs
            h.update((";capstone=%s" % _cs.__version__).encode("ascii"))
        except ImportError:
            h.update(b";capstone=absent")
        h.update(TOOL_CONFIG_MODULE.encode("ascii"))
        # Config identity: entry root set, strict vs partial and the image
        # name are part of the provenance, so two images over the same flat
        # and layout cannot share a provenance SHA. The loader's identity is
        # still the flat SHA-256 (flat_sha); AOT_STATE_LAYOUT/ABI unchanged.
        h.update((";subset=%s;abi=%u;layout=%u;base=0x%x;mutant=%s"
                  ";partial=%u;name=%s;entries=%s"
                  % (AOT_MODULE_SUBSET_ID, AOT_ABI_VERSION_PROGRAM,
                     AOT_STATE_LAYOUT, guest_base,
                     MUTANT if MUTANT else "-", PARTIAL, args.name,
                     ",".join("0x%x" % e for e in entries))).encode("ascii"))
        provenance = h.hexdigest()
        fnv = 0xCBF29CE484222325
        for b in raw:
            fnv ^= b
            fnv = (fnv * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
        text = emit_c(args.name, blocks, ranges, flat_sha, fnv,
                      (0, 0, 0), subset_id=AOT_MODULE_SUBSET_ID,
                      abi_expr="AOT_ABI_VERSION_PROGRAM",
                      provenance="sha256 %s (translator+layout, flat %s)"
                                 % (provenance, flat_sha[:16]),
                      switch_sites={pc: p.targets
                                    for pc, p in switch_proofs.items()})
    except DecodeError as e:
        sys.stderr.write("aot_translate: FAIL-CLOSED: %s\n" % e)
        return 1
    except (KeyError, TypeError, ValueError) as e:
        sys.stderr.write("aot_translate: FAIL-CLOSED: malformed layout: %s\n" % e)
        return 1

    with open(args.out, "w", encoding="utf-8") as f:
        f.write(text)
    if args.meta_out:
        meta = {"name": args.name, "mode": "module",
                "subset_id": AOT_MODULE_SUBSET_ID,
                "abi_version": AOT_ABI_VERSION_PROGRAM,
                "state_layout": AOT_STATE_LAYOUT,
                "guest_base": "0x%x" % guest_base,
                "source_sha256": flat_sha,
                "provenance_sha256": provenance,
                "fnv1a64": "0x%016x" % fnv,
                "ranges": [list(r) for r in ranges],
                "entries": ["0x%x" % e for e in entries],
                "partial": bool(PARTIAL),
                "unsupported": [
                    {"status": PARTIAL_STATUS[pc], "pc": "0x%x" % pc,
                     "word": "0x%08x" % visited[pc]["word"],
                     "reason": visited[pc]["reason"]}
                    for pc in unsup],
                "thunks": {"base": 0, "count": 0, "stride": 0},
                "local_switch_sites": [
                    {"br_pc": "0x%x" % pc,
                     "owner": p.owner_name,
                     "owner_start": "0x%x" % p.owner_start,
                     "targets": ["0x%x" % t for t in p.targets],
                     "guard_bound": p.guard_bound,
                     "table": "0x%x" % p.table_va,
                     "table_sha256": p.table_sha256,
                     "status": LOCAL_SWITCH_STATUS_BASE - (i + 1),
                     "closure": p.closure}
                    for i, (pc, p) in
                    enumerate(sorted(switch_proofs.items()))],
                "blocks": []}
        for blk in blocks:
            last = blk["insns"][-1]
            succ = successors(last) if last["kind"] in TERMINATORS \
                else [last["pc"] + 4]
            meta["blocks"].append({"pc": "0x%x" % blk["pc"],
                                   "end_pc": "0x%x" % (last["pc"] + 4),
                                   "terminator": last["kind"],
                                   "next": ["0x%x" % t for t in succ]})
        with open(args.meta_out, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2, sort_keys=True)
            f.write("\n")
    sys.stderr.write("aot_translate: module %s: %d blocks, %d entries, "
                     "sha=%s\n" % (args.name, len(blocks), len(entries),
                                   flat_sha[:16]))
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", default=None)
    ap.add_argument("--bin", default=None, dest="binfile")
    ap.add_argument("--out", required=True)
    ap.add_argument("--name", required=True)
    ap.add_argument("--meta-out", dest="meta_out", default=None)
    ap.add_argument("--mutant", default=None, choices=list(MUTANTS))
    ap.add_argument("--module", action="store_true",
                    help="G3 module mode: one linked module flat -> ABI-v2 image")
    ap.add_argument("--flat", default=None)
    ap.add_argument("--layout", default=None)
    ap.add_argument("--guest-base", dest="guest_base", default=None)
    ap.add_argument("--entries", default=None)
    ap.add_argument("--partial", action="store_true",
                    help="--module only: stop an undecodable block with a "
                         "typed AOT_FAULT_UNSUPPORTED_INSN fault (offline "
                         "raw word/reason in --meta-out) instead of aborting")
    args = ap.parse_args()
    global MUTANT
    if args.module:
        if args.mutant is not None and args.mutant not in MODULE_MUTANTS:
            sys.stderr.write("aot_translate: FAIL-CLOSED: --mutant is G2-only\n")
            return 1
        globals()["MUTANT"] = args.mutant
        if args.partial:
            globals()["PARTIAL"] = 1
        return run_module(args)
    if args.mutant is not None and args.mutant in MODULE_MUTANTS:
        sys.stderr.write("aot_translate: FAIL-CLOSED: --mutant %s is module-mode "
                         "only (use --module)\n" % args.mutant)
        return 1
    if args.partial:
        sys.stderr.write("aot_translate: FAIL-CLOSED: --partial is module-mode "
                         "only (use --module)\n")
        return 1
    if args.manifest is None or args.binfile is None:
        sys.stderr.write("aot_translate: FAIL-CLOSED: --manifest and --bin are "
                         "required outside --module mode\n")
        return 1
    MUTANT = args.mutant

    with open(args.manifest, "rb") as f:
        manifest_bytes = f.read()
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        sys.stderr.write("aot_translate: FAIL-CLOSED: unparseable manifest JSON: %s\n" % e)
        return 1
    with open(args.binfile, "rb") as f:
        raw = f.read()
    with open(__file__, "rb") as f:
        gen_bytes = f.read()

    try:
        ranges = [tuple(int(x) for x in r) for r in manifest["ranges"]]
        entries = [int(x) for x in manifest["entries"]]
        indirect = [int(x) for x in manifest.get("indirect_targets", [])]
        th = manifest.get("thunks") or {}
        thunks = (int(th.get("base", 0)), int(th.get("count", 0)),
                  int(th.get("stride", 0)))
    except (KeyError, TypeError, ValueError) as e:
        sys.stderr.write("aot_translate: FAIL-CLOSED: malformed manifest: %s\n" % e)
        return 1

    h = hashlib.sha256()
    h.update(raw)
    h.update(manifest_bytes)
    h.update(gen_bytes)
    h.update(TOOL_CONFIG.encode("ascii"))
    h.update(("mutant=%s;subset=%s;abi=%u;layout=%u"
              % (MUTANT or "none", AOT_SUBSET_ID, AOT_ABI_VERSION,
                 AOT_STATE_LAYOUT)).encode("ascii"))
    sha = h.hexdigest()

    fnv = 0xCBF29CE484222325
    for b in raw:
        fnv ^= b
        fnv = (fnv * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF

    try:
        validate_thunks(thunks, ranges)
        blocks, _visited = build_cfg(raw, ranges, entries, indirect)
        text = emit_c(args.name, blocks, ranges, sha, fnv, thunks)
    except DecodeError as e:
        sys.stderr.write("aot_translate: FAIL-CLOSED: %s\n" % e)
        return 1

    with open(args.out, "w", encoding="utf-8") as f:
        f.write(text)

    if args.meta_out:
        meta = {"name": args.name, "subset_id": AOT_SUBSET_ID,
                "abi_version": AOT_ABI_VERSION, "state_layout": AOT_STATE_LAYOUT,
                "mutant": args.mutant or "none",
                "sha256": sha, "fnv1a64": "0x%016x" % fnv,
                "ranges": [list(r) for r in ranges],
                "thunks": {"base": thunks[0], "count": thunks[1],
                           "stride": thunks[2]},
                "blocks": []}
        for blk in blocks:
            last = blk["insns"][-1]
            succ = successors(last) if last["kind"] in TERMINATORS \
                else [last["pc"] + 4]
            meta["blocks"].append({"pc": blk["pc"],
                                   "end_pc": last["pc"] + 4,
                                   "terminator": last["kind"],
                                   "next": succ})
        with open(args.meta_out, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2, sort_keys=True)
            f.write("\n")

    sys.stderr.write("aot_translate: %d blocks, fnv=0x%016x, sha=%s\n"
                     % (len(blocks), fnv, sha[:16]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
