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
           "strdrop", "scalarupper", "pair32trunc",
           "fpdropflags", "stxalwaysok",
           "fproundrn", "fpnanorder", "fpignoreguard",
           # G3 increment 3 MODULE-mode-only negative controls.
           "adrp_offset", "orr_noshift", "stp_split")
# The two G3 module-mode mutants are only legal with --module; every other
# mutant belongs to the G2 single-image path and must stay there.
MODULE_MUTANTS = ("adrp_offset", "orr_noshift", "stp_split")
MODULE_BASE = 0
# 1 while translating with --module (ABI-v2 Program image). Module-only
# lowerings (single-access pair stores) are gated on it so the G2 single-image
# output stays byte-identical.
MODULE_MODE = 0

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

    # ---- MOVZ/MOVK: sf opc 100101 hw imm16 Rd
    if ((word >> 23) & 0x3F) == 0x25 and sf == 1:
        opc = (word >> 29) & 3
        hw = (word >> 21) & 3
        imm16 = (word >> 5) & 0xFFFF
        rd = word & 0x1F
        if opc == 0:
            raise DecodeError("MOVN not in subset")
        if opc == 1:
            raise DecodeError("reserved move wide opc")
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
        if opc == 0:
            raise DecodeError("MOVN not in subset")
        if opc == 1:
            raise DecodeError("reserved move wide opc")
        if hw >= 2:
            raise DecodeError("reserved hw for 32-bit move wide")
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

    # ---- LDR/STR (immediate, unsigned offset): size 111 V 01 opc imm12 Rn Rt
    if ((word >> 27) & 0x7) == 0x7 and ((word >> 24) & 0x3) == 0x1 \
            and ((word >> 26) & 1) == 0:
        size = (word >> 30) & 3
        opc = (word >> 22) & 3
        if opc == 2 or opc == 3:
            raise DecodeError("unsupported ldst opc (LDRSW/PRFM)")
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
        if rt == rt2:
            raise DecodeError("subset restriction: pair Rt == Rt2 excluded "
                              "(constrained-unpredictable for LDP; duplicate "
                              "store for STP)")
        if rt2 == 31:
            raise DecodeError("subset restriction: pair Rt2 == 31 (XZR operand) "
                              "not supported (valid architecture)")
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
        #      AND/ORR/EOR only (opc 3 == ANDS is excluded), ROR excluded,
        #      imm6 must be in range for the operand size. ORR Rd,XZR,Rm is
        #      the MOV (register) alias: Rn == 31 is XZR in this form.
        if ((word >> 24) & 0x1F) == 0x0A and ((word >> 21) & 1) == 0:
            opc = (word >> 29) & 3
            shift = (word >> 22) & 3
            imm6 = (word >> 10) & 0x3F
            width = 64 if sf else 32
            if opc not in (0, 1, 2):
                raise DecodeError("logical shifted register opc 3 (ANDS) not "
                                  "in subset")
            if shift == 3:
                raise DecodeError("reserved shift type (ROR)")
            if imm6 >= width:
                raise DecodeError("shift amount out of range for operand size")
            return {"kind": "logic_shift", "pc": pc, "op": opc,
                    "shift": shift, "imm6": imm6,
                    "rm": (word >> 16) & 0x1F, "rn": (word >> 5) & 0x1F,
                    "rd": word & 0x1F, "width": width}

        # ---- NOP ---------------------------------------------------------
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

    raise DecodeError("unsupported instruction encoding 0x%08x" % word)


TERMINATORS = {"b", "bcond", "bl", "cbz", "cbnz", "br", "blr", "ret",
               "svc", "mrs_counter"}


def successors(ins):
    pc = ins["pc"]
    k = ins["kind"]
    if k == "b":
        return [ins["target"]]
    if k in ("bcond", "cbz", "cbnz"):
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

def build_cfg(raw, ranges, entries, indirect_targets, base=0, module=False):
    """Recover the reachable CFG.

    `ranges` and the entry/target PCs are GUEST virtual addresses; `base` is
    the guest VA of flat offset 0 (0 for the legacy single-image G2 mode, where
    file offsets and guest PCs are the same thing). A word at guest PC `pc` is
    read from `raw[pc - base]`. Only code reachable from the entries/targets is
    decoded, so data words inside the text segment (the crt0 MOD0 offset, the
    MOD0 struct, ...) are never decoded.
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
            ins = decode(cur, word, module=module)
            ins["word"] = word
            visited[cur] = ins
            if ins["kind"] in TERMINATORS:
                for t in successors(ins):
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


# ---------------------------------------------------------------- codegen

def expr_operand(ins, width, sp_for_rn):
    """Return a C expression for the shifted second operand of a shifted-reg
    ADD/SUB. Rm uses XZR selection (SP is not encodable there)."""
    base = "%s(s, %uu)" % (use("aot_gpr_zr"), ins["rm"])
    if ins["imm6"] == 0 and ins["shift"] == 0:
        return base
    return "%s(%s, %uu, %uu, %uu)" % (
        use("aot_shift"), base, width, ins["shift"], ins["imm6"])


def emit_insn(ins, out):
    k = ins["kind"]
    pc = ins["pc"]
    if k == "movz":
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
        if not (ins["imm6"] == 0 and ins["shift"] == 0):
            if MUTANT == "orr_noshift" and ins["op"] == 1:
                # TEST-ONLY wrong implementation: ORR (shifted register)
                # silently drops the shift amount.
                pass
            else:
                b = "%s(%s, %uu, %uu, %uu)" % (use("aot_shift"), b, width,
                                               ins["shift"], ins["imm6"])
        op = {0: "&", 1: "|", 2: "^"}[ins["op"]]
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
        out.append("    %s(s, %uu, %s);"
                   % (use("aot_set_zr"), ins["rd"], expr))
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
    elif k == "b":
        out.append("    rt->site_pc = 0x%xull;" % pc)
        out.append("    rt->next_pc = 0x%xull;" % ins["target"])
        out.append("    return AOT_EXIT_BRANCH;")
    elif k == "bcond":
        out.append("    rt->site_pc = 0x%xull;" % pc)
        out.append("    rt->next_pc = %s(s, 0x%xu) ? 0x%xull : 0x%xull;"
                   % (use("aot_cond"), ins["cond"], ins["target"], pc + 4))
        out.append("    return AOT_EXIT_COND;")
    elif k in ("cbz", "cbnz"):
        reg = "%s(s, %uu)" % (use("aot_gpr_zr"), ins["rt"])
        if ins["width"] == 32:
            reg = "((uint32_t)(%s))" % reg
        test = "(%s == 0u)" % reg if k == "cbz" else "(%s != 0u)" % reg
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
        # SC domain: DMB/DSB/ISB ordering already holds.
        out.append("    aot_mem_fence();   /* barrier valid as no-op under SC */")
    else:
        raise DecodeError("codegen: unknown kind %s" % k)


def emit_c(name, blocks, ranges, sha, fnv, thunks, subset_id=AOT_SUBSET_ID,
           abi_expr="AOT_ABI_VERSION", provenance=None):
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
    out.append("/* ---- straight-line native basic blocks ---- */")
    for blk in blocks:
        out.append("static AotExit aot_blk_%x(AotGuestState *s, AotRuntime *rt) {" % blk["pc"])
        out.append("    (void)s; (void)rt;")
        for ins in blk["insns"]:
            emit_insn(ins, out)
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
    global MODULE_BASE, MODULE_MODE
    MODULE_BASE = 0
    MODULE_MODE = 1
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
        blocks, _visited = build_cfg(raw, ranges, entries, [],
                                     base=guest_base, module=True)
        # Provenance of the translation (evidence only); the image identity is
        # the module flat SHA-256 the loader binds the descriptor to.
        h = hashlib.sha256()
        h.update(raw)
        h.update(layout_bytes)
        h.update(gen_bytes)
        h.update(TOOL_CONFIG_MODULE.encode("ascii"))
        h.update((";subset=%s;abi=%u;layout=%u;base=0x%x;mutant=%s"
                  % (AOT_MODULE_SUBSET_ID, AOT_ABI_VERSION_PROGRAM,
                     AOT_STATE_LAYOUT, guest_base,
                     MUTANT if MUTANT else "-")).encode("ascii"))
        provenance = h.hexdigest()
        fnv = 0xCBF29CE484222325
        for b in raw:
            fnv ^= b
            fnv = (fnv * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
        text = emit_c(args.name, blocks, ranges, flat_sha, fnv,
                      (0, 0, 0), subset_id=AOT_MODULE_SUBSET_ID,
                      abi_expr="AOT_ABI_VERSION_PROGRAM",
                      provenance="sha256 %s (translator+layout, flat %s)"
                                 % (provenance, flat_sha[:16]))
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
                "thunks": {"base": 0, "count": 0, "stride": 0},
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
    args = ap.parse_args()
    global MUTANT
    if args.module:
        if args.mutant is not None and args.mutant not in MODULE_MUTANTS:
            sys.stderr.write("aot_translate: FAIL-CLOSED: --mutant is G2-only\n")
            return 1
        globals()["MUTANT"] = args.mutant
        return run_module(args)
    if args.mutant is not None and args.mutant in MODULE_MUTANTS:
        sys.stderr.write("aot_translate: FAIL-CLOSED: --mutant %s is module-mode "
                         "only (use --module)\n" % args.mutant)
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
