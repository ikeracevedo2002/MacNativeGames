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

Subset (AOT_SUBSET_ID "g2-core-v1"):
  ADD/SUB (immediate, shifted register) with/without S
  MOVZ/MOVK
  B, B.cond, CBZ, CBNZ
  BL, BR, BLR, RET
  SVC
Correct X/W zero-extension and SP vs XZR selection are enforced. BLR captures
its source register before x30 is updated (including BLR x30).
"""

import argparse
import hashlib
import json
import struct
import sys

# ---------------------------------------------------------------- semantics

AOT_SUBSET_ID = "g2-core-v1"
AOT_ABI_VERSION = 1
AOT_STATE_LAYOUT = 1
TOOL_CONFIG = "aot-translate-stage3/cfg-manifest/c-basicblock/v1"

# Test-only negative-control selector. None == the real (unmutated) image.
MUTANT = None
MUTANTS = ("wrongcarry", "lostwzeroext", "wrongcond", "blrorder",
           "strdrop", "scalarupper", "pair32trunc")

# NZCV helpers are emitted by name; each marks itself used.
_HELPERS = {}
_USED = set()


def use(name):
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


def decode(pc, word):
    """Decode one supported instruction. Returns a dict or raises
    DecodeError. Every branch is field-validated; unsupported forms fail."""
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

    raise DecodeError("unsupported instruction encoding 0x%08x" % word)


TERMINATORS = {"b", "bcond", "bl", "cbz", "cbnz", "br", "blr", "ret", "svc"}


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

def build_cfg(raw, ranges, entries, indirect_targets):
    for i, (s, e) in enumerate(ranges):
        if s >= e:
            raise DecodeError("range %d: start >= end" % i)
        if (s % 4) != 0 or (e % 4) != 0:
            raise DecodeError("range %d: not 4-byte aligned" % i)
        if e > len(raw):
            raise DecodeError("range %d: end 0x%x exceeds file size 0x%x" % (i, e, len(raw)))
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
            word = struct.unpack_from("<I", raw, cur)[0]
            ins = decode(cur, word)
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
            if ins["width"] == 64:
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
    else:
        raise DecodeError("codegen: unknown kind %s" % k)


def emit_c(name, blocks, ranges, sha, fnv, thunks):
    head = []
    head.append("/* Generated by tools/aot/aot_translate.py -- DO NOT EDIT.")
    head.append(" * subset: %s" % AOT_SUBSET_ID)
    head.append(" * source sha256: %s" % sha)
    head.append(" * fixture fnv1a64: 0x%016x (quick check only)" % fnv)
    head.append(" */")
    head.append('#include "aot_runtime.h"')
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
    out.append('    "%s",' % AOT_SUBSET_ID)
    out.append("    AOT_ABI_VERSION, AOT_STATE_LAYOUT,")
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--bin", required=True, dest="binfile")
    ap.add_argument("--out", required=True)
    ap.add_argument("--name", required=True)
    ap.add_argument("--meta-out", dest="meta_out", default=None)
    ap.add_argument("--mutant", default=None, choices=list(MUTANTS))
    args = ap.parse_args()
    global MUTANT
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
