#!/usr/bin/env python3
"""G2 stage-2 differential driver.

Runs each case twice:
  - the native AOT binary runner (tests/aot/aot_bin_runner.c), and
  - an independent Unicorn 2.1.4 A57 oracle that decodes the raw fixture
    binary itself and models the documented HLE/thunk contract,
and compares guest state, memory, HLE events and the block-entry PC trace.

The oracle does NOT import the translator's semantics. Infrastructure errors,
timeouts and nonzero process exits are failures, never silent skips.
"""

import argparse
import json
import os
import re
import random
import struct
import subprocess
import sys

import reference_cfg

try:
    import unicorn
    from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_INTR
    from unicorn import UC_HOOK_MEM_INVALID, UC_ERR_READ_UNMAPPED, UC_PROT_ALL
    from unicorn.arm64_const import (
        UC_ARM64_REG_X0, UC_ARM64_REG_X29, UC_ARM64_REG_SP, UC_ARM64_REG_PC,
        UC_ARM64_REG_NZCV, UC_ARM64_REG_X30, UC_ARM64_REG_V0, UC_ARM64_REG_FPCR,
        UC_ARM64_REG_FPSR, UC_ARM64_REG_TPIDR_EL0, UC_ARM64_REG_TPIDRRO_EL0,
        UC_ARM64_REG_CPACR_EL1, UC_CPU_ARM64_A57,
        UC_ARM64_REG_V8, UC_ARM64_REG_V31,
    )
except Exception as e:  # pragma: no cover - infrastructure
    sys.stderr.write("INFRA-ERROR: Unicorn unavailable: %r\n" % (e,))
    sys.exit(2)

UNICORN_VERSION = getattr(unicorn, "__version__", "unknown")
# X0..X28 are contiguous; X29/X30 are NOT adjacent to X28 in Unicorn's ID
# space (the next IDs are V0/V1).  Use explicit constants for X29/X30.
XREGS = [UC_ARM64_REG_X0 + i for i in range(29)] + \
        [UC_ARM64_REG_X29, UC_ARM64_REG_X30]

M64 = (1 << 64) - 1
M128 = (1 << 128) - 1


def apply_hle(u):
    """Independent oracle model of the native HLE mutation contract.

    This is derived from the documented contract, NOT from the translator and
    NOT by importing the native handler. The runtime owns the resume PC and
    ignores any handler attempt to redirect it, so this model never touches PC.
    """
    u.reg_write(XREGS[0], (u.reg_read(XREGS[0]) ^ u.reg_read(XREGS[1])) & M64)
    u.reg_write(XREGS[1], (u.reg_read(XREGS[1]) + 0x11) & M64)
    u.reg_write(XREGS[18], (u.reg_read(XREGS[18]) ^ 0xA5A5A5A5A5A5A5A5) & M64)
    u.reg_write(XREGS[19], (u.reg_read(XREGS[19]) + 1) & M64)
    u.reg_write(XREGS[20], (u.reg_read(XREGS[20]) - 2) & M64)
    v8 = u.reg_read(UC_ARM64_REG_V8)
    v31 = u.reg_read(UC_ARM64_REG_V31)
    u.reg_write(UC_ARM64_REG_V8, (v8 ^ v31) & M128)
    u.reg_write(UC_ARM64_REG_V31, (v31 + 1) & M128)
    u.reg_write(UC_ARM64_REG_SP, (u.reg_read(UC_ARM64_REG_SP) + 16) & M64)
    u.reg_write(UC_ARM64_REG_NZCV, 0xA0000000)
    u.reg_write(UC_ARM64_REG_FPCR, u.reg_read(UC_ARM64_REG_FPCR) ^ 0x00C00000)
    u.reg_write(UC_ARM64_REG_FPSR, u.reg_read(UC_ARM64_REG_FPSR) ^ 0x00000002)
    u.reg_write(UC_ARM64_REG_TPIDR_EL0,
                (u.reg_read(UC_ARM64_REG_TPIDR_EL0) ^ 0x123456789ABCDEF0) & M64)

IN_MAGIC = 0x414F5449
OUT_MAGIC = 0x414F544F
FORMAT_VERSION = 1
STOP_PC = 0
GUEST_BASE = 0x100000
HIGH_GUEST_BASE = 0x100000000   # above 4 GiB, exposes 32-bit writeback truncation
ARENA_SIZE = 0x1000
CODE_SIZE = 0x10000
BUDGET = 100000
HLE_SVC, HLE_HOSTCALL = 1, 2

X_OFF = 0
SP_OFF = 248
PC_OFF = 256
NZCV_OFF = 264
V_OFF = 272
FPCR_OFF = 784
FPSR_OFF = 792
TPIDR_OFF = 800
TPIDRRO_OFF = 808
STATE_SIZE = 816
# x[31], sp, pc, nzcv, v[32][2], fpcr, fpsr, tpidr, tpidrro
STATE_FMT = "<102Q"


def pack_state(st):
    vals = list(st["x"]) + [st["sp"], st["pc"], st["nzcv"]]
    for v in st["v"]:
        vals.append(v & 0xFFFFFFFFFFFFFFFF)
        vals.append((v >> 64) & 0xFFFFFFFFFFFFFFFF)
    vals += [st["fpcr"], st["fpsr"], st["tpidr"], st["tpidrro"]]
    return struct.pack(STATE_FMT, *vals)


def unpack_state(buf):
    vals = struct.unpack(STATE_FMT, buf[:STATE_SIZE])
    st = {"x": list(vals[0:31]), "sp": vals[31], "pc": vals[32], "nzcv": vals[33]}
    st["v"] = [(vals[34 + 2 * i + 1] << 64) | vals[34 + 2 * i] for i in range(32)]
    p = 34 + 64
    st["fpcr"], st["fpsr"], st["tpidr"], st["tpidrro"] = vals[p:p + 4]
    return st


def base_state(guest_base=None):
    gb = GUEST_BASE if guest_base is None else guest_base
    st = {"x": [0] * 31, "sp": gb + 0x800, "pc": 0, "nzcv": 0,
          "v": [0] * 32, "fpcr": 0x00400000, "fpsr": 0x08000001,
          "tpidr": 0x0123456789ABCDEF, "tpidrro": 0xFEDCBA9876543210}
    for i in range(31):
        st["x"][i] = (0x1000000000000000 + 0x1111 * i + 1) & M64
    for i in range(32):
        lo = (0x0102030405060708 + 0x1010101010101010 * i + i) & M64
        hi = (0xFEDCBA9876543210 + 0x0F0F0F0F0F0F0F0F * i + 7) & M64
        st["v"][i] = (hi << 64) | lo
    # Bit-pattern payloads (NOT arithmetic coverage): +0, -0, qNaN, sNaN,
    # subnormal, +/-inf. Both lanes seeded individually.
    st["v"][0] = 0x0000000000000000 | (0x0000000000000000 << 64)
    st["v"][1] = 0x8000000000000000 | (0x8000000000000000 << 64)
    st["v"][2] = 0x7FF8000000000000 | (0x7FF8000000000000 << 64)
    st["v"][3] = 0x7FF0000000000001 | (0x7FF0000000000001 << 64)
    st["v"][4] = 0x0000000000000001 | (0x000FFFFFFFFFFFFF << 64)
    st["v"][5] = 0x7FF0000000000000 | (0xFFF0000000000000 << 64)
    st["x"][18] = 0xDEADBEEF00C0FFEE
    st["x"][30] = 0   # LR = stop sentinel; a case ends by `ret` to PC 0
    return st


def arena_bytes():
    return bytes(((i * 7 + 3) & 0xFF) for i in range(ARENA_SIZE))


# ---- case table ---------------------------------------------------------

def make_cases():
    cases = []

    def add(name, pc, x=None, nzcv=0, handlers=((HLE_SVC, 0x40), (HLE_HOSTCALL, 0)),
            expected_fault=False, fault_addr=0, fault_src=0, fault_size=0,
            v=None, guest_base=None, fpcr=None, fpsr=None):
        cases.append({"name": name, "pc": pc, "x": x or {}, "nzcv": nzcv,
                      "handlers": handlers, "expected_fault": expected_fault,
                      "fault_addr": fault_addr, "fault_src": fault_src,
                      "fault_size": fault_size, "v": v or {},
                      "guest_base": GUEST_BASE if guest_base is None else guest_base,
                      "fpcr": fpcr, "fpsr": fpsr})

    # integer / flags
    add("adds_imm", 0x1000, {"x0": 0xFFFFFFFFFFFFFFFF}, 0)
    add("subs_imm", 0x1010, {"x0": 0x0000000080000000}, 0)
    add("add_shift_lsl", 0x1020, {"x0": 0x123456789ABCDEF0, "x2": 0x11}, 0)
    add("sub_shift_asr", 0x1030, {"x0": 0x8000000000000000, "x2": 0x80}, 0)
    add("adds32", 0x1040, {"x0": 0xFFFFFFFF00000001, "x2": 0xFFFFFFFF}, 0)
    add("subs32", 0x1050, {"x0": 0x10, "x2": 0x20}, 0)
    add("movz_movk", 0x1060, {}, 0)
    add("subs_wrap", 0x1070, {"x0": 0x0, "x2": 0x1}, 0)
    add("add_sp_imm", 0x1080, {}, 0)
    add("adds_xzr", 0x1090, {"x0": 0x8000000000000000, "x1": 0x8000000000000000}, 0)
    add("add_overlap", 0x10A0, {"x1": 0x7FFFFFFFFFFFFFFF}, 0)

    # all 16 conditions x 4 NZCV seeds (N,Z,C,V)
    conds = ["eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
             "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"]
    seeds = [(n, z, c, v) for n in (0, 1) for z in (0, 1)
             for c in (0, 1) for v in (0, 1)]
    for ci, cname in enumerate(conds):
        pc = 0x1200 + ci * 0x20
        for n, z, c, v in seeds:
            nz = (n << 31) | (z << 30) | (c << 29) | (v << 28)
            add("cond_%s_n%d%d%d%d" % (cname, n, z, c, v), pc, {}, nz)

    # memory (x1 -> arena + 0x100)
    mem = {"x1": GUEST_BASE + 0x100}
    add("str_ldr64", 0x1400, dict(mem, x0=0x1122334455667788), 0)
    add("strb_ldrb", 0x1420, dict(mem, x0=0xA5), 0)
    add("strh_ldrh", 0x1440, dict(mem, x0=0xBEEF), 0)
    add("str_ldr32", 0x1460, dict(mem, x0=0xCAFEBABE), 0)
    add("stp_pre_ldp_post", 0x1480, {"x0": 0x1111, "x2": 0x2222}, 0)
    add("stp_off_ldp_off", 0x14A0, {"x0": 0x3333, "x2": 0x4444}, 0)
    add("str_sp_ldr_sp", 0x14C0, {"x0": 0x5555}, 0)
    add("ldr_oob", 0x14E0, {"x1": 0x200000}, 0, expected_fault=True,
        fault_addr=0x200000, fault_src=0x14E0, fault_size=8)

    # calls / targets
    add("call_nested", 0x1600, {"x0": 5}, 0)
    add("br_dynamic", 0x1640, {"x9": 0x1800, "x0": 1}, 0)
    add("blr_dynamic", 0x1660, {"x9": 0x1800, "x0": 2}, 0)
    add("blr_x30_capture", 0x1680, {"x30": 0x1800, "x0": 3}, 0)
    add("ret_xN", 0x16A0, {"x9": 0x1800, "x0": 4}, 0)
    add("svc_case", 0x16C0, {"x0": 6}, 0)
    add("blr_hostthunk", 0x16E0, {"x9": 0x3000, "x0": 7}, 0)

    # ---- SIMD / vector integers (stage 3) ----
    v1 = (0x8123456789ABCDEF << 64) | 0xFEDCBA9876543210
    v2 = 0x0F0F0F0F0F0F0F0F_F0F0F0F0F0F0F0F0
    v0dirty = (0xDEADBEEFCAFEBABE << 64) | 0x0123456789ABCDEF
    add("fmov_d", 0x1500, {}, 0, v={0: v0dirty, 1: v1})
    add("fabs_d", 0x1520, {}, 0,
        v={0: v0dirty, 1: (0x8000000000000000 << 64) | 0x8000000000000001})
    add("fneg_d", 0x1540, {}, 0,
        v={0: v0dirty, 1: (0x7FFFFFFFFFFFFFFF << 64) | 0x0000000000000001})
    # Input bit-pattern payloads in SOURCE v1 (destination upper64 pre-dirtied so
    # the required high64-zeroing is actually exposed).
    for nm, pc in (("fmov", 0x1500), ("fabs", 0x1520), ("fneg", 0x1540)):
        for pl, val in (("pz", 0x0000000000000000), ("nz", 0x8000000000000000),
                        ("qnan", 0x7FF8000000000000), ("snan", 0x7FF0000000000001),
                        ("inf", 0x7FF0000000000000), ("sub", 0x0000000000000001)):
            add("%s_%s" % (nm, pl), pc, {}, 0,
                v={0: v0dirty, 1: (val << 64) | val})
    add("vand16b", 0x1560, {}, 0, v={0: 0, 1: v1, 2: v2})
    add("vorr16b", 0x1580, {}, 0, v={0: 0, 1: v1, 2: v2})
    add("veor16b", 0x15A0, {}, 0, v={0: 0, 1: v1, 2: v2})
    add("vadd16b", 0x15C0, {}, 0,
        v={0: 0, 1: (0xFFFFFFFFFFFFFFFF << 64) | 0xFFFFFFFFFFFFFFFF,
           2: (0x0101010101010101 << 64) | 0x0101010101010101})
    add("vsub16b", 0x15E0, {}, 0,
        v={0: 0, 1: 0, 2: (0x0101010101010101 << 64) | 0x0101010101010101})
    add("vadd16b_mixed", 0x15C0, {}, 0,
        v={0: 0, 1: (0x7F80FF00EE11DD22 << 64) | 0x33445566778899AA,
           2: (0x0180FF00EE11DD22 << 64) | 0x33445566778899AA})

    # ---- pair32 writeback above 4 GiB + WSP-only high-SP arithmetic ----
    add("pair32_wb_high", 0x1740,
        {"x1": HIGH_GUEST_BASE + 0x100, "x0": 0x11111111, "x2": 0x22222222}, 0,
        guest_base=HIGH_GUEST_BASE)
    add("wsp_high", 0x1760, {}, 0, guest_base=HIGH_GUEST_BASE)

    # ---- stage-4 coverage holes (existing decoded forms only) ----
    for nm, pc in (("cbz_x", 0x1780), ("cbz_w", 0x17A0),
                   ("cbnz_x", 0x17C0), ("cbnz_w", 0x17E0)):
        for val in (0x100000000, 0, 1, 0xFFFFFFFF00000000):
            add("%s_%x" % (nm, val), pc, {"x0": val}, 0)
    for val in (0x80000000, 0xFFFFFFFF, 0x7FFFFFFF, 0, 1):
        add("asr32_%x" % val, 0x1810, {"x0": val}, 0)
    for nm, pc in (("add_imm_lsl12", 0x1830), ("sub_imm_lsl12", 0x1850)):
        for val in (0, 1, 0xFFF, 0xFFFFFFFF, 0x7FFFFFFFFFFFFFFF,
                    0x8000000000000000, (1 << 64) - 1):
            add("%s_%x" % (nm, val), pc, {"x0": val}, 0)
    add("wsp_dest_high", 0x1870, {}, 0, guest_base=HIGH_GUEST_BASE)
    dirtyv = {0: ((0xDEADBEEFCAFEBABE << 64) | 0x0123456789ABCDEF),
              1: ((0x1122334455667788 << 64) | 0xFFEEDDCCBBAA0099),
              3: ((0xAA55AA55AA55AA55 << 64) | 0x00FF00FF00FF00FF)}
    add("fmov_d_same_dirty", 0x1890, {}, 0, v=dirtyv)
    add("vand_same_dirty", 0x18B0, {}, 0, v=dirtyv)
    add("veor_rd_eq_rn_dirty", 0x18D0, {}, 0, v=dirtyv)
    add("vorr_rd_eq_rm_dirty", 0x18F0, {}, 0, v=dirtyv)

    # ---- stage-5: scalar FP arithmetic/compare (oracle: Unicorn A57) ----
    D1_5 = 0x3FF8000000000000
    D2_25 = 0x4002000000000000
    D1_0 = 0x3FF0000000000000
    D3_0 = 0x4008000000000000
    DQNAN = 0x7FF8000000000001
    DSNAN = 0x7FF0000000000001
    F1_5 = 0x3FC00000
    F2_25 = 0x40100000
    F1_0 = 0x3F800000
    F3_0 = 0x40400000
    FQNAN = 0x7FC00001
    FSNAN = 0x7F800001

    def v2(lo, hi=0xDEADBEEFDEADBEEF):
        return (hi << 64) | lo

    add("fadd_d", 0x1900, {}, 0, v={1: v2(D1_5), 2: v2(D2_25)})
    add("fsub_d", 0x1920, {}, 0, v={1: v2(D1_5), 2: v2(D2_25)})
    add("fmul_d", 0x1940, {}, 0, v={1: v2(D1_5), 2: v2(D2_25)})
    add("fdiv_d", 0x1960, {}, 0, v={1: v2(D1_0), 2: v2(D3_0)}, fpcr=0x00000000)
    add("fdiv_d_rz", 0x1960, {}, 0, v={1: v2(D1_0), 2: v2(D3_0)},
        fpcr=0x00C00000)
    add("fadd_d_rn_tiny", 0x1900, {}, 0,
        v={1: v2(D1_0), 2: v2(0x3C30000000000000)}, fpcr=0x00000000)
    add("fadd_d_qnan", 0x1900, {}, 0, v={1: v2(DQNAN), 2: v2(D1_0)})
    add("fadd_d_snan", 0x1900, {}, 0, v={1: v2(DSNAN), 2: v2(D1_0)})
    add("fadd_d_fz_subnormal", 0x1900, {}, 0,
        v={1: v2(0x0000000000000001), 2: v2(0x0010000000000000)},
        fpcr=0x01000000)
    add("fadd_s", 0x1980, {}, 0, v={1: v2(F1_5), 2: v2(F2_25)})
    add("fsub_s", 0x19A0, {}, 0, v={1: v2(F1_5), 2: v2(F2_25)})
    add("fmul_s", 0x19C0, {}, 0, v={1: v2(F1_5), 2: v2(F2_25)})
    add("fdiv_s", 0x19E0, {}, 0, v={1: v2(F1_0), 2: v2(F3_0)},
        fpcr=0x00000000)
    add("fdiv_s_rm", 0x19E0, {}, 0, v={1: v2(F1_0), 2: v2(F3_0)},
        fpcr=0x00800000)
    add("fadd_s_qnan", 0x1980, {}, 0, v={1: v2(FQNAN), 2: v2(F1_0)})
    add("fcmp_d_lt", 0x1A00, {}, 0, v={1: v2(D1_0), 2: v2(D3_0)})
    add("fcmp_d_nan", 0x1A00, {}, 0, v={1: v2(DQNAN), 2: v2(D1_0)}, fpsr=0)
    add("fcmpe_d_qnan", 0x1A20, {}, 0, v={1: v2(DQNAN), 2: v2(D1_0)}, fpsr=0)
    add("fcmpe_d_snan", 0x1A20, {}, 0, v={1: v2(DSNAN), 2: v2(D1_0)}, fpsr=0)
    add("fcmp_s_gt", 0x1A40, {}, 0, v={1: v2(F3_0), 2: v2(F1_0)})
    add("fcmpe_s_qnan", 0x1A60, {}, 0, v={1: v2(FQNAN), 2: v2(F1_0)}, fpsr=0)
    add("fcmp_zero_d_gt", 0x1A80, {}, 0, v={1: v2(D1_0)})
    add("fcmpe_zero_s_nan", 0x1AA0, {}, 0, v={1: v2(FQNAN)}, fpsr=0)

    # ---- stage-5: exclusive / ordered scalar + barriers ----
    A0 = GUEST_BASE + 0x40
    add("ldxr_x", 0x1B00, {"x1": A0}, 0)
    add("ldxr_w", 0x1B10, {"x1": A0}, 0)
    add("ldxrb", 0x1B20, {"x1": A0}, 0)
    add("ldxrh", 0x1B30, {"x1": A0}, 0)
    add("stxr_x", 0x1B40, {"x1": A0, "x0": 0x1122334455667788,
                           "x3": 0xDEAD}, 0)
    add("stxr_w", 0x1B50, {"x1": A0, "x0": 0xFFFFFFFF99887766, "x3": 0xDEAD}, 0)
    add("stxrb", 0x1B60, {"x1": A0, "x0": 0xFFFFFFFFFFFFFFAA, "x3": 0xDEAD}, 0)
    add("stxrh", 0x1B70, {"x1": A0, "x0": 0xFFFFFFFFFFFFBBAA, "x3": 0xDEAD}, 0)
    add("ldar_x", 0x1B80, {"x1": A0}, 0)
    add("ldar_w", 0x1B90, {"x1": A0}, 0)
    add("ldarb", 0x1BA0, {"x1": A0}, 0)
    add("ldarh", 0x1BB0, {"x1": A0}, 0)
    add("stlr_x", 0x1BC0, {"x1": A0, "x0": 0x1122334455667788}, 0)
    add("stlr_w", 0x1BD0, {"x1": A0, "x0": 0xFFFFFFFF99887766}, 0)
    add("stlrb", 0x1BE0, {"x1": A0, "x0": 0xFFFFFFFFFFFFFFAA}, 0)
    add("stlrh", 0x1BF0, {"x1": A0, "x0": 0xFFFFFFFFFFFFBBAA}, 0)
    add("ldxr_stxr_ok", 0x1C00, {"x1": A0, "x3": 0xDEAD}, 0)
    add("ldxr_stxr_other", 0x1C20, {"x1": A0, "x3": 0xDEAD}, 0)
    add("ldxr_str_stxr", 0x1C40, {"x1": A0, "x2": 0xAABBCCDDEEFF0011,
                                  "x3": 0xDEAD}, 0)
    add("ldxr_stlr_stxr", 0x1C60, {"x1": A0, "x2": 0xAABBCCDDEEFF0011,
                                   "x3": 0xDEAD}, 0)
    add("clrex", 0x1C80, {}, 0)
    add("barriers_noop_under_sc", 0x1CA0, {}, 0)

    # ---- stage-FP-matrix: generated differential coverage -----------------
    # 2 widths x 6 ops x 16 FPCR modes x 12 operand pairs = 2304 cases.
    # Sticky FPSR seeds rotate 0 / QC / all-sticky. Expected values come ONLY
    # from the pinned Unicorn A57 oracle; no expected vector is hardcoded here.
    fp_ops = [("add", 0x1900, 0x1980), ("sub", 0x1920, 0x19A0),
              ("mul", 0x1940, 0x19C0), ("div", 0x1960, 0x19E0),
              ("cmp", 0x1A00, 0x1A40), ("cmpe", 0x1A20, 0x1A60)]
    fp_seeds = [0, 0x08000000, 0x9F]      # 0 / QC / sticky IOC..IDC
    pairs32 = [(0x00000000, 0x00000000), (0x80000000, 0x00000000),
               (0x3F800000, 0x40400000), (0x7F800000, 0xFF800000),
               (0x7FC00002, 0x3F800000), (0x7F800001, 0x3F800000),
               (0x7FC00002, 0x7F800001), (0x00000001, 0x00000002),
               (0x00800000, 0x3F000000), (0x7F7FFFFF, 0x40000000),
               (0x00800001, 0x3F000000), (0x7F7FFFFF, 0x7FC00003)]
    pairs64 = [(0x0000000000000000, 0x0000000000000000),
               (0x8000000000000000, 0x0000000000000000),
               (0x3FF0000000000000, 0x4008000000000000),
               (0x7FF0000000000000, 0xFFF0000000000000),
               (0x7FF8000000000002, 0x3FF0000000000000),
               (0x7FF0000000000001, 0x3FF0000000000000),
               (0x7FF8000000000002, 0x7FF0000000000001),
               (0x0000000000000001, 0x0000000000000002),
               (0x0010000000000000, 0x3FE0000000000000),
               (0x7FEFFFFFFFFFFFFF, 0x4000000000000000),
               (0x0010000000000001, 0x3FE0000000000000),
               (0x7FEFFFFFFFFFFFFF, 0x7FF8000000000003)]
    idx = 0
    for wname, pairs in (("s", pairs32), ("d", pairs64)):
        for oname, pc_d, pc_s in fp_ops:   # tuples are (op, D, S)
            pc = pc_s if wname == "s" else pc_d
            for rmode in range(4):
                for fz in (0, 1):
                    for dn in (0, 1):
                        fpcr = (rmode << 22) | (fz << 24) | (dn << 25)
                        for pa, pb in pairs:
                            add("mat_%s_%s_r%d_fz%d_dn%d_%x_%x"
                                % (wname, oname, rmode, fz, dn, pa, pb),
                                pc, {}, 0, v={1: v2(pa), 2: v2(pb)},
                                fpcr=fpcr, fpsr=fp_seeds[idx % 3])
                            idx += 1

    # Named, stable-address cases for future rounding/NaN mutants.
    add("fadd_s_qnan_op1_preferred", 0x1980, {}, 0,
        v={1: v2(0x7FC00002), 2: v2(0x7FC00003)}, fpsr=0)
    add("fadd_d_qnan_op1_preferred", 0x1900, {}, 0,
        v={1: v2(0x7FF8000000000002), 2: v2(0x7FF8000000000003)}, fpsr=0)
    for rmode, nm in ((0x00000000, "rn"), (0x00400000, "rp"),
                      (0x00800000, "rm"), (0x00C00000, "rz")):
        add("fdiv_s_one_third_%s" % nm, 0x19E0, {}, 0,
            v={1: v2(F1_0), 2: v2(F3_0)}, fpcr=rmode, fpsr=0)
        add("fdiv_d_one_third_%s" % nm, 0x1960, {}, 0,
            v={1: v2(D1_0), 2: v2(D3_0)}, fpcr=rmode, fpsr=0)

    # ---- post-HLE numeric rounding: the HLE callback XORs FPCR 0xC00000, so a
    # guest RP (0x400000) becomes RM (0x800000) BEFORE the translated FDIV
    # executes. 1/3 must then be 0x3eaaaaaa, not the pre-call RP 0x3eaaaaab.
    add("post_svc_fdiv_s", 0x1CC0, {}, 0,
        v={1: v2(F1_0), 2: v2(F3_0)}, fpcr=0x00400000, fpsr=0)
    add("post_svc_fdiv_s_sticky", 0x1CC0, {}, 0,
        v={1: v2(F1_0), 2: v2(F3_0)}, fpcr=0x00400000, fpsr=0x9F)
    add("post_svc_fdiv_d", 0x1D00, {}, 0,
        v={1: v2(D1_0), 2: v2(D3_0)}, fpcr=0x00400000, fpsr=0)
    add("post_hostcall_fdiv_s", 0x1CE0, {"x9": 0x3000}, 0,
        v={1: v2(F1_0), 2: v2(F3_0)}, fpcr=0x00400000, fpsr=0)
    add("post_hostcall_fdiv_s_sticky", 0x1CE0, {"x9": 0x3000}, 0,
        v={1: v2(F1_0), 2: v2(F3_0)}, fpcr=0x00400000, fpsr=0x9F)
    add("post_hostcall_fdiv_d", 0x1D20, {"x9": 0x3000}, 0,
        v={1: v2(D1_0), 2: v2(D3_0)}, fpcr=0x00400000, fpsr=0)

    # ---- deterministic edge values + seeded random GPR cases ----
    rng = random.Random(0x5EED)
    m64 = (1 << 64) - 1
    edge = [0, 1, 2, 0x7F, 0x80, 0xFF, 0x1000, 0xFFFFFFFF, 0x80000000,
            0x7FFFFFFFFFFFFFFF, 0x8000000000000000, m64, m64 - 1]
    int_entries = [(0x1000, "adds_imm"), (0x1010, "subs_imm"),
                   (0x1020, "add_shift_lsl"), (0x1030, "sub_shift_asr"),
                   (0x1040, "adds32"), (0x1050, "subs32"),
                   (0x1070, "subs_wrap"), (0x1090, "adds_xzr"),
                   (0x10A0, "add_overlap")]
    for pc, nm in int_entries:
        for e in edge:
            add("%s_e%x" % (nm, e), pc, {"x0": e, "x1": e, "x2": e}, 0)
        for k in range(24):
            add("%s_r%d" % (nm, k), pc,
                {"x0": rng.getrandbits(64), "x1": rng.getrandbits(64),
                 "x2": rng.getrandbits(64)}, rng.getrandbits(4) << 28)
    return cases


# ---- native side --------------------------------------------------------

def native_run(exe, case, in_path, out_path):
    gb = case.get("guest_base", GUEST_BASE)
    st = base_state(gb)
    st["nzcv"] = case["nzcv"]
    for k, v in case["x"].items():
        st["x"][int(k[1:])] = v
    for i, val in case.get("v", {}).items():
        st["v"][i] = val
    if case.get("fpcr") is not None:
        st["fpcr"] = case["fpcr"]
    if case.get("fpsr") is not None:
        st["fpsr"] = case["fpsr"]
    with open(in_path, "wb") as f:
        f.write(struct.pack("<II", IN_MAGIC, 1))
        f.write(struct.pack("<QQQQQ", case["pc"], STOP_PC, BUDGET,
                            gb, ARENA_SIZE))
        f.write(struct.pack("<II", 1, len(case["handlers"])))
        for k, i in case["handlers"]:
            f.write(struct.pack("<II", k, i))
        f.write(pack_state(st))
        f.write(arena_bytes())
    try:
        r = subprocess.run([exe, in_path, out_path], capture_output=True,
                           timeout=10)
    except subprocess.TimeoutExpired:
        raise RuntimeError("native runner TIMEOUT after 10s")
    if r.returncode != 0:
        raise RuntimeError("native runner exit %d: %s" %
                           (r.returncode, r.stdout.decode(errors="replace")))
    with open(out_path, "rb") as f:
        data = f.read()
    off = 0

    def take(fmt):
        nonlocal off
        n = struct.calcsize(fmt)
        vals = struct.unpack_from(fmt, data, off)
        off += n
        return vals
    magic, ver = take("<II")
    if magic != OUT_MAGIC or ver != FORMAT_VERSION:
        raise RuntimeError("bad native output magic")
    exit_reason, fault = take("<II")
    fault_src, fault_target, fault_status, steps = take("<QQqQ")
    state = unpack_state(data[off:off + STATE_SIZE]); off += STATE_SIZE
    (nev,) = take("<I")
    events = []
    for _ in range(nev):
        k, i, s, r = take("<IIQQ")
        events.append({"kind": k, "id": i, "site_pc": s, "resume_pc": r})
    (ntr,) = take("<I")
    trace = [take("<Q")[0] for _ in range(ntr)]
    eof1, eof2 = take("<II")
    (asz,) = take("<Q")
    arena = data[off:off + asz]
    off += asz
    # Structural integrity: these are INFRA failures, never semantic negatives.
    if eof1 != 0 or eof2 != 0:
        raise RuntimeError("native output overflow flags set (events=%d trace=%d)" % (eof1, eof2))
    if asz != ARENA_SIZE or len(arena) != ARENA_SIZE:
        raise RuntimeError("native output arena size %d != %d" % (asz, ARENA_SIZE))
    if off != len(data):
        raise RuntimeError("native output has %d trailing byte(s)" % (len(data) - off))
    return {"exit": exit_reason, "fault": fault, "fault_src": fault_src,
            "fault_target": fault_target, "fault_status": fault_status,
            "steps": steps, "state": state, "events": events, "trace": trace,
            "arena": arena, "events_overflow": eof1, "trace_overflow": eof2}


# ---- oracle side --------------------------------------------------------

def oracle_run(case, bin_bytes, block_starts, thunk_base, thunk_count, thunk_stride,
               guest_base=None):
    gb = GUEST_BASE if guest_base is None else guest_base
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.ctl_set_cpu_model(UC_CPU_ARM64_A57)
    uc.mem_map(0, CODE_SIZE, UC_PROT_ALL)
    padded = bin_bytes + b"\x00" * (CODE_SIZE - len(bin_bytes))
    uc.mem_write(0, padded)
    if thunk_count:
        nop = b"\x1f\x20\x03\xd5"
        for i in range(thunk_count):
            uc.mem_write(thunk_base + i * thunk_stride, nop * (thunk_stride // 4))
    uc.mem_map(gb, ARENA_SIZE, UC_PROT_ALL)
    uc.mem_write(gb, arena_bytes())
    uc.reg_write(UC_ARM64_REG_CPACR_EL1, 3 << 20)

    st = base_state(gb)
    st["nzcv"] = case["nzcv"]
    for k, v in case["x"].items():
        st["x"][int(k[1:])] = v
    for i, val in case.get("v", {}).items():
        st["v"][i] = val
    if case.get("fpcr") is not None:
        st["fpcr"] = case["fpcr"]
    if case.get("fpsr") is not None:
        st["fpsr"] = case["fpsr"]
    for i in range(31):
        uc.reg_write(XREGS[i], st["x"][i])
    uc.reg_write(UC_ARM64_REG_SP, st["sp"])
    uc.reg_write(UC_ARM64_REG_NZCV, st["nzcv"] & 0xF0000000)
    for i in range(32):
        uc.reg_write(UC_ARM64_REG_V0 + i, st["v"][i])
    uc.reg_write(UC_ARM64_REG_FPCR, st["fpcr"])
    uc.reg_write(UC_ARM64_REG_FPSR, st["fpsr"])
    uc.reg_write(UC_ARM64_REG_TPIDR_EL0, st["tpidr"])
    uc.reg_write(UC_ARM64_REG_TPIDRRO_EL0, st["tpidrro"])

    events = []
    trace = []
    fault = {"code": 0}
    memi = {}

    def hook_mem_invalid(u, access, addr, size, value, ud):
        memi["access"] = access
        memi["addr"] = addr
        memi["size"] = size
        memi["pc"] = u.reg_read(UC_ARM64_REG_PC)
        return False    # let Unicorn raise the UcError

    def hook_code(u, addr, size, ud):
        if addr == STOP_PC:
            u.emu_stop()
            return
        if thunk_count and thunk_base <= addr < thunk_base + thunk_count * thunk_stride:
            idx = (addr - thunk_base) // thunk_stride
            lr = u.reg_read(UC_ARM64_REG_X30)
            events.append({"kind": HLE_HOSTCALL, "id": idx,
                           "site_pc": lr - 4, "resume_pc": lr})
            apply_hle(u)
            u.reg_write(UC_ARM64_REG_PC, lr)
            return
        if addr in block_starts:
            trace.append(addr)

    def hook_intr(u, intno, ud):
        pc = u.reg_read(UC_ARM64_REG_PC)

        def word_at(a):
            return int.from_bytes(u.mem_read(a, 4), "little")

        # Unicorn may deliver PC at the SVC site or already advanced to
        # site+4; accept either, but only if the exact SVC mask matches.
        site = resume = None
        if (word_at(pc) & 0xFFE0001F) == 0xD4000001:
            site, resume = pc, pc + 4
        elif pc >= 4 and (word_at(pc - 4) & 0xFFE0001F) == 0xD4000001:
            site, resume = pc - 4, pc
        if site is None:
            fault["code"] = "unexpected-trap-pc=0x%x" % pc
            u.emu_stop()
            return
        events.append({"kind": HLE_SVC, "id": (word_at(site) >> 5) & 0xFFFF,
                       "site_pc": site, "resume_pc": resume})
        apply_hle(u)
        u.reg_write(UC_ARM64_REG_PC, resume)

    uc.hook_add(UC_HOOK_CODE, hook_code)
    uc.hook_add(UC_HOOK_INTR, hook_intr)
    uc.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid)

    try:
        uc.emu_start(case["pc"], STOP_PC, timeout=5 * 1000000, count=BUDGET)
    except UcError as e:
        fault["code"] = str(e)
        fault["errno"] = e.errno
        fault["memi"] = dict(memi)

    out = base_state(gb)
    for i in range(31):
        out["x"][i] = uc.reg_read(XREGS[i])
    out["sp"] = uc.reg_read(UC_ARM64_REG_SP)
    out["pc"] = uc.reg_read(UC_ARM64_REG_PC)
    out["nzcv"] = uc.reg_read(UC_ARM64_REG_NZCV) & 0xF0000000
    for i in range(32):
        out["v"][i] = uc.reg_read(UC_ARM64_REG_V0 + i)
    out["fpcr"] = uc.reg_read(UC_ARM64_REG_FPCR)
    out["fpsr"] = uc.reg_read(UC_ARM64_REG_FPSR)
    out["tpidr"] = uc.reg_read(UC_ARM64_REG_TPIDR_EL0)
    out["tpidrro"] = uc.reg_read(UC_ARM64_REG_TPIDRRO_EL0)
    arena = bytes(uc.mem_read(gb, ARENA_SIZE))
    return {"state": out, "events": events, "trace": trace,
            "arena": arena, "fault": fault}


# ---- compare ------------------------------------------------------------

def cmp_case(case, nat, orc):
    errs = []
    if case.get("expected_fault"):
        # Only cases explicitly named as expected faults may be compared as
        # faults; the fault must be the specific memory fault at the seeded
        # address, matched by both the oracle and native sides.
        if not orc["fault"]["code"]:
            errs.append("expected oracle fault, got none (native exit=%d)" % nat["exit"])
        else:
            mi = orc["fault"].get("memi") or {}
            if orc["fault"].get("errno") != UC_ERR_READ_UNMAPPED:
                errs.append("oracle fault errno=%r (expected UC_ERR_READ_UNMAPPED=%d)"
                            % (orc["fault"].get("errno"), UC_ERR_READ_UNMAPPED))
            if mi.get("addr") != case.get("fault_addr", 0):
                errs.append("oracle fault addr=0x%x expected=0x%x"
                            % (mi.get("addr", 0), case.get("fault_addr", 0)))
            if mi.get("size") != case.get("fault_size", 0):
                errs.append("oracle fault size=%r expected=%d"
                            % (mi.get("size"), case.get("fault_size", 0)))
            if mi.get("pc") != case.get("fault_src", 0):
                errs.append("oracle fault source pc=0x%x expected=0x%x"
                            % (mi.get("pc", 0), case.get("fault_src", 0)))
        if nat["exit"] != 11:   # AOT_EXIT_FAULT
            errs.append("expected native FAULT (exit=11), got exit=%d" % nat["exit"])
        else:
            if nat["fault"] != 3:   # AOT_FAULT_MEMORY
                errs.append("expected AOT_FAULT_MEMORY(3), got fault=%d" % nat["fault"])
            if nat["fault_target"] != case.get("fault_addr", 0):
                errs.append("fault_target native=0x%x expected=0x%x" %
                            (nat["fault_target"], case.get("fault_addr", 0)))
            if nat["fault_src"] != case.get("fault_src", 0):
                errs.append("fault_src native=0x%x expected=0x%x" %
                            (nat["fault_src"], case.get("fault_src", 0)))
        return errs, "fault"
    # Normal differential case: the oracle must NOT fault, and the native
    # side must reach a clean STOP at the sentinel PC.  An oracle trap here
    # is an unexpected oracle/infra failure, never a passing 'fault_exact'.
    if orc["fault"]["code"]:
        errs.append("oracle unexpectedly faulted (%r) for a non-fault case" %
                    (orc["fault"]["code"],))
        return errs, "oracle-fault"
    if nat["exit"] != 10:       # AOT_EXIT_STOP
        errs.append("native exit=%d fault=%d (expected STOP)" %
                    (nat["exit"], nat["fault"]))
        return errs, "fault"
    if nat["state"]["pc"] != STOP_PC:
        errs.append("native final pc=0x%x (expected STOP sentinel %d)" %
                    (nat["state"]["pc"], STOP_PC))
    ns, os_ = nat["state"], orc["state"]
    for i in range(31):
        if ns["x"][i] != os_["x"][i]:
            errs.append("x%d native=0x%x oracle=0x%x" % (i, ns["x"][i], os_["x"][i]))
    for f in ("sp", "pc", "nzcv", "fpcr", "fpsr", "tpidr", "tpidrro"):
        if ns[f] != os_[f]:
            errs.append("%s native=0x%x oracle=0x%x" % (f, ns[f], os_[f]))
    for i in range(32):
        if ns["v"][i] != os_["v"][i]:
            errs.append("v%d native=0x%x oracle=0x%x" % (i, ns["v"][i], os_["v"][i]))
    if nat["arena"] != orc["arena"]:
        errs.append("arena mismatch")
    if nat["events"] != orc["events"]:
        errs.append("events native=%r oracle=%r" % (nat["events"], orc["events"]))
    if nat["trace"] != orc["trace"]:
        errs.append("trace native=%r oracle=%r" % (nat["trace"], orc["trace"]))
    if not errs:
        return errs, "exact"
    return errs, "mismatch"



# ---- structural guards (independent of native/oracle agreement) -----------
_FP_MAT_RE = re.compile(r"^mat_([sd])_(add|sub|mul|div|cmp|cmpe)_")
_FP_MN = {"add": "fadd", "sub": "fsub", "mul": "fmul", "div": "fdiv",
          "cmp": "fcmp", "cmpe": "fcmpe"}


def check_fp_widths(bin_bytes, cases):
    """Verify the CASE->INSTRUCTION width mapping by decoding raw words.

    Both native and oracle agreeing proves nothing if the matrix points an
    "s" case at a D instruction (or the reverse): both then execute the same
    wrong width. This check decodes the actual fixture word with Capstone and
    requires the register class to match the case name.
    """
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    errs = []
    seen = {}
    covered = set()
    for c in cases:
        m = _FP_MAT_RE.match(c["name"])
        if not m:
            continue
        w, op = m.group(1), m.group(2)
        # Deduplicate by (width, op, PC): a later matrix case for the same
        # (width, op) but a DIFFERENT PC must still be decoded. Deduplicating
        # by (width, op) alone silently ignored such a case, so a mis-pointed
        # duplicate was invisible (lead-found false positive).
        key = (w, op, c["pc"])
        covered.add((w, op))
        if key in seen:
            continue
        seen[key] = c["pc"]
        ins = next(md.disasm(bin_bytes[c["pc"]:c["pc"] + 4], c["pc"]), None)
        if ins is None:
            errs.append("%s: no instruction at 0x%x" % (c["name"], c["pc"]))
            continue
        if ins.mnemonic != _FP_MN[op]:
            errs.append("%s: 0x%x decodes %s, expected %s"
                        % (c["name"], c["pc"], ins.mnemonic, _FP_MN[op]))
            continue
        regs = [r for r in ins.op_str.replace(" ", "").split(",") if r]
        if not regs or not all(r.startswith(w) for r in regs):
            errs.append("%s: 0x%x decodes '%s' but width %s was requested"
                        % (c["name"], c["pc"], ins.op_str, w))
    if len(covered) != 12:
        errs.append("fp matrix width check saw %d/12 (width,op) pairs" % len(covered))

    for c in cases:
        if not c["name"].startswith("post_"):
            continue
        w = "d" if c["name"].endswith("_fdiv_d") else "s"
        off = 8 if c["name"].startswith("post_hostcall") else 4
        pc = c["pc"] + off
        ins = next(md.disasm(bin_bytes[pc:pc + 4], pc), None)
        if ins is None or ins.mnemonic != "fdiv":
            errs.append("%s: expected fdiv at 0x%x" % (c["name"], pc))
            continue
        regs = [r for r in ins.op_str.replace(" ", "").split(",") if r]
        if not regs or not all(r.startswith(w) for r in regs):
            errs.append("%s: 0x%x decodes '%s' but width %s was requested"
                        % (c["name"], pc, ins.op_str, w))
    return errs


def check_post_hle_expected(case, nat):
    """Independent expected FPCR/FPSR/result for the post-HLE rows.

    The oracle applies its own HLE model, so blind native/oracle agreement did
    NOT catch a case pointing at the wrong-width fixture. These expectations
    are closed form: FPCR RP(0x400000) ^ HLE XOR 0xC00000 = RM(0x800000);
    FPSR = (seed ^ 0x2) | IXC; 1/3 in RM is 0x3eaaaaaa (S) / 0x3fd5555555555555 (D).
    """
    if not case["name"].startswith("post_"):
        return []
    errs = []
    if nat.get("exit") != 10:   # AOT_EXIT_STOP
        return ["post-HLE: native exit=%r (expected STOP)" % (nat.get("exit"),)]
    st = nat["state"]
    is_d = case["name"].endswith("_fdiv_d")
    want_v0 = 0x3FD5555555555555 if is_d else 0x3EAAAAAA
    # Full 128-bit lane: the expectation is the zero-extended 32/64-bit value,
    # so nonzero upper bits also fail here (independent of the comparator).
    got = st["v"][0]
    if got != want_v0:
        errs.append("post-HLE: v0=0x%x expected 0x%x (full 128-bit lane)"
                    % (got, want_v0))
    if st["fpcr"] != 0x00800000:
        errs.append("post-HLE: fpcr=0x%x expected RM 0x800000" % st["fpcr"])
    want_fpsr = ((case.get("fpsr") or 0) ^ 0x2) | 0x10
    if st["fpsr"] != want_fpsr:
        errs.append("post-HLE: fpsr=0x%x expected 0x%x" % (st["fpsr"], want_fpsr))
    return errs

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", required=True)
    ap.add_argument("--bin", required=True)
    ap.add_argument("--meta", required=True)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    print("oracle: Unicorn %s (CPU model A57 pinned)" % UNICORN_VERSION)
    with open(args.bin, "rb") as f:
        bin_bytes = f.read()
    with open(args.meta) as f:
        meta = json.load(f)
    meta_starts = set(b["pc"] for b in meta["blocks"])
    with open(args.manifest) as f:
        man = json.load(f)
    ref_starts = reference_cfg.derive_starts(
        bin_bytes, [tuple(r) for r in man["ranges"]],
        list(man["entries"]), list(man.get("indirect_targets", [])))
    if ref_starts != meta_starts:
        only_ref = sorted(ref_starts - meta_starts)
        only_meta = sorted(meta_starts - ref_starts)
        print("FAIL: independent Capstone CFG != meta blocks; ref-only=%r meta-only=%r"
              % ([hex(x) for x in only_ref], [hex(x) for x in only_meta]))
        return 2
    block_starts = ref_starts
    if "thunks" not in man:
        print("FAIL: manifest missing required thunks")
        return 2
    mth = man["thunks"]
    th = {"base": int(mth["base"]), "count": int(mth["count"]),
          "stride": int(mth["stride"])}
    mmeta = meta.get("thunks", {})
    if (th["base"], th["count"], th["stride"]) != (
            mmeta.get("base"), mmeta.get("count"), mmeta.get("stride")):
        print("FAIL: manifest thunks %r != meta thunks %r" % (th, mmeta))
        return 2
    os.makedirs(args.work, exist_ok=True)

    cases = make_cases()
    width_errs = check_fp_widths(bin_bytes, cases)
    if width_errs:
        print("FAIL: case/instruction width structure:")
        for e in width_errs[:10]:
            print("  " + e)
        return 2
    if args.limit:
        cases = cases[:args.limit]

    exact = fault_cases = mismatch = 0
    failures = []
    # Unique scratch names per process: even if another test (or a stale
    # run) touches this directory, this run can never collide with its files.
    scratch = "d%d" % os.getpid()
    for idx, case in enumerate(cases):
        in_path = os.path.join(args.work, "%s_in_%d.bin" % (scratch, idx))
        out_path = os.path.join(args.work, "%s_out_%d.bin" % (scratch, idx))
        try:
            nat = native_run(args.exe, case, in_path, out_path)
        except Exception as e:
            failures.append("%s: native infra: %r (work=%s)"
                            % (case["name"], e, in_path))
            mismatch += 1
            continue
        try:
            orc = oracle_run(case, bin_bytes, block_starts,
                             th.get("base", 0), th.get("count", 0), th.get("stride", 0),
                             case.get("guest_base", GUEST_BASE))
        except Exception as e:
            failures.append("%s: oracle infra: %r" % (case["name"], e))
            mismatch += 1
            continue
        exp_errs = check_post_hle_expected(case, nat)
        if exp_errs:
            mismatch += 1
            failures.append("%s: %s" % (case["name"], "; ".join(exp_errs)))
            continue
        errs, kind = cmp_case(case, nat, orc)
        if errs:
            mismatch += 1
            failures.append("%s: %s" % (case["name"], "; ".join(errs[:4])))
        elif kind == "fault":
            fault_cases += 1
        else:
            exact += 1

    print("aot differential: cases=%d exact=%d fault_exact=%d mismatch=%d"
          % (len(cases), exact, fault_cases, mismatch))
    for f in failures[:20]:
        print("  FAIL " + f)
    if mismatch:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
