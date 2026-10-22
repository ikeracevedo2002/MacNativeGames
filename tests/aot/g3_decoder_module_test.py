#!/usr/bin/env python3
"""G3 module-mode decoder cross-check against Capstone 5.0.7 (review fix 2).

Everything the module-mode decoder ACCEPTS must be a real A64 instruction that
Capstone decodes to the same class with the same operands (including the
PC-relative ADRP/ADR targets computed from the absolute guest PC).  Everything
it refuses for subset reasons must still be a REAL instruction (Capstone
decodes it) -- otherwise a "refusal" would only mean the word was garbage.

Also asserted:
  * the fixed fail-closed list (ANDS, ROR on the N=0 forms, W imm6 >= 32, MSR,
    SYS, other MRS sysregs, MRS op0=2) raises DecodeError in module mode;
  * G2 gating: with module=False NONE of the module-mode forms is accepted;
  * a fixed-seed random sweep (default 200k words) where every accepted word is
    Capstone-valid and of the expected class.

Exit: 0 = pass, 2 = semantic FAIL, 1 = infrastructure (Capstone/decoder import).
"""

import argparse
import os
import random
import struct
import sys

FAILS = []


def fail(msg):
    FAILS.append(msg)
    print("FAIL: " + msg)


# ---- encoders (independent of the decoder under test) --------------------
def enc_adrp(rd, imm21):
    imm21 &= (1 << 21) - 1
    return (0x90000000 | (((imm21 & 3) << 29)) |
            (((imm21 >> 2) & 0x7FFFF) << 5) | rd)


def enc_adr(rd, imm21):
    imm21 &= (1 << 21) - 1
    return (0x10000000 | (((imm21 & 3) << 29)) |
            (((imm21 >> 2) & 0x7FFFF) << 5) | rd)


def enc_logic(sf, opc, shift, imm6, rm, rn, rd, n=0):
    return ((sf << 31) | (opc << 29) | (0x0A << 24) | (shift << 22) |
            (n << 21) | ((imm6 & 0x3F) << 10) | (rm << 16) | (rn << 5) | rd)


def enc_mrs(sysreg16, rt):
    return 0xD5300000 | ((sysreg16 & 0xFFFF) << 5) | rt


def enc_msr(sysreg16, rt):
    return 0xD5100000 | ((sysreg16 & 0xFFFF) << 5) | rt


def enc_sys(op1, crn, crm, op2, rt=31):
    return (0xD5080000 | ((op1 & 7) << 16) | ((crn & 15) << 12) |
            ((crm & 15) << 8) | ((op2 & 7) << 5) | rt)


def enc_sysreg16(op0, op1, crn, crm, op2):
    """Same encoding as AOT_SYSREG16 in src/aot/aot_abi.h (bit 15 is the fixed
    opcode bit, NOT part of op0; op0 = 2 + o0 where o0 is bit 14)."""
    return (0x8000 | (((op0 - 2) & 1) << 14) | ((op1 & 7) << 11) |
            ((crn & 15) << 7) | ((crm & 15) << 3) | (op2 & 7))


def sx(value, bits):
    if value & (1 << (bits - 1)):
        value -= 1 << bits
    return value


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--tools", required=True, help="tools/aot directory")
    ap.add_argument("--sweep", type=int, default=200000)
    ap.add_argument("--perturb", action="store_true",
                    help="negative control: expect every PC-relative target "
                         "off by one page, which MUST make this test fail")
    ap.add_argument("--seed", type=int, default=0x3C3)
    args = ap.parse_args(argv)

    sys.path.insert(0, os.path.abspath(args.tools))
    try:
        import aot_translate as T
    except Exception as e:                                    # noqa: BLE001
        sys.stderr.write("INFRA: cannot import aot_translate: %r\n" % (e,))
        return 1
    try:
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
        from capstone import CS_GRP_INVALID  # noqa: F401  (import probe)
        import capstone
    except Exception as e:                                    # noqa: BLE001
        sys.stderr.write("INFRA: cannot import capstone: %r\n" % (e,))
        return 1
    print("capstone %s" % capstone.__version__ if hasattr(capstone, "__version__")
          else "capstone (version unknown)")

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    def capstone_one(word, pc):
        code = struct.pack("<I", word & 0xFFFFFFFF)
        for ins in md.disasm(code, pc):
            return ins
        return None

    # Capstone prints the ABI aliases for R29/R30; compare canonical names.
    alias = {"lr": "x30", "fp": "x29", "ip0": "x16", "ip1": "x17"}

    def cname(cs, reg):
        n = cs.reg_name(reg)
        return alias.get(n, n)

    def reg_name(width, num):
        if num == 31:
            return "xzr" if width == 64 else "wzr"
        return ("x%d" if width == 64 else "w%d") % num

    stripped = 0
    corpus = []       # (pc, word, why)

    # ---------------- ADRP / ADR: positive, negative, page boundaries -----
    adr_pcs = [0x1000000000, 0x1000000FFC, 0x1001000000, 0x1FFFFFF000,
               0x10000FFFF8, 0x7FFFE000]
    imms = [0, 1, 3, 4, 0x1FFFFF, (1 << 21) - 1, 0x7FFFF, -1, -4, -0x1000,
            -0x200000, 0x12345, -0x12345]
    for rd in (0, 1, 8, 30, 31):
        for pc in adr_pcs:
            for imm in imms:
                corpus.append((pc, enc_adrp(rd, imm), "adrp rd=%d imm=%d"
                               % (rd, imm)))
                corpus.append((pc, enc_adr(rd, imm), "adr rd=%d imm=%d"
                               % (rd, imm)))

    # ---------------- logical shifted register (W and X) ------------------
    for sf, width in ((1, 64), (0, 32)):
        for opc, name in ((0, "and"), (1, "orr"), (2, "eor")):
            for shift, sname in ((0, "lsl"), (1, "lsr"), (2, "asr")):
                edges = [0, 1, 31] if width == 32 else [0, 1, 31, 32, 63]
                for imm6 in edges:
                    for rn, rm, rd in ((0, 1, 2), (31, 1, 2), (5, 31, 31),
                                       (31, 31, 31), (10, 10, 10)):
                        corpus.append((0x1000002000,
                                       enc_logic(sf, opc, shift, imm6, rm, rn, rd),
                                       "%s %s imm6=%d rn=%d rm=%d rd=%d"
                                       % (name, sname, imm6, rn, rm, rd)))
    # MOV (register) alias: ORR Rd, XZR, Rm with no shift.
    for rd, rm in ((0, 1), (8, 9), (31, 5), (5, 31), (31, 31)):
        corpus.append((0x1000002000, enc_logic(1, 1, 0, 0, rm, 31, rd),
                       "mov x%d, x%d alias" % (rd, rm)))

    # ---------------- NOP --------------------------------------------------
    corpus.append((0x1000000000, 0xD503201F, "nop"))

    # ---------------- MRS (all four registers, incl. Rt=31) ---------------
    sysregs = [("cntpct_el0", T.SYSREG_CNTPCT_EL0),
               ("cntvct_el0", T.SYSREG_CNTVCT_EL0),
               ("tpidr_el0", T.SYSREG_TPIDR_EL0),
               ("tpidrro_el0", T.SYSREG_TPIDRRO_EL0)]
    for nm, field in sysregs:
        for rt in (0, 1, 8, 30, 31):
            corpus.append((0x1000000000, enc_mrs(field, rt),
                           "mrs x%d, %s" % (rt, nm)))

    # ---------------- new module-only families ---------------------------
    # Each word must be a real instruction, accepted in module mode with the
    # expected Capstone mnemonic, and refused by the legacy G2 subset.
    new_forms = [
        (0x92824680, "movn x0,#0x1234", {"mov"}),
        (0x12A24680, "movn w0,#0x1234,lsl#16", {"mov"}),
        (0xB9800820, "ldrsw x0,[x1,#8]", {"ldrsw"}),
        (0x39C00020, "ldrsb w0,[x1]", {"ldrsb"}),
        (0x39800020, "ldrsb x0,[x1]", {"ldrsb"}),
        (0x79C00020, "ldrsh w0,[x1]", {"ldrsh"}),
        (0x36180000, "tbz w0,#3", {"tbz"}),
        (0xB7400000, "tbnz x0,#40", {"tbnz"}),
        (0x9A820020, "csel x0,x1,x2,eq", {"csel"}),
        (0x1A821420, "csinc w0,w1,w2,ne", {"csinc"}),
        (0xDA822020, "csinv x0,x1,x2,hs", {"csinv"}),
        (0x5A824420, "csneg w0,w1,w2,mi", {"csneg"}),
        (0x9A9F17E0, "cset x0,eq", {"csinc", "cset"}),
        (0x8B224020, "add x0,x1,w2,uxtw", {"add"}),
        (0xCB226C20, "sub x0,x1,x2,uxtx#3", {"sub"}),
        (0xF85F8020, "ldur x0,[x1,#-8]", {"ldur"}),
        (0xB800C020, "stur w0,[x1,#12]", {"stur"}),
        (0xF8408C20, "ldr x0,[x1,#8]!", {"ldr"}),
        (0xF8408420, "ldr x0,[x1],#8", {"ldr"}),
        (0x38401420, "ldrb w0,[x1],#1", {"ldrb"}),
        (0xF8626820, "ldr x0,[x1,x2]", {"ldr"}),
        (0xB8625820, "ldr w0,[x1,w2,uxtw#2]", {"ldr"}),
        (0xF862D820, "ldr x0,[x1,w2,sxtw#3]", {"ldr"}),
        (0xB8A27820, "ldrsw x0,[x1,x2,lsl#2]", {"ldrsw"}),
        (0x92089C20, "and x0,x1,#0xff00ff00ff00ff00", {"and"}),
        (0xB2607C20, "orr x0,x1,#0xffffffff00000000", {"orr"}),
        (0xD200CC20, "eor x0,x1,#0x0f0f...", {"eor"}),
        (0xF2401C20, "ands x0,x1,#0xff", {"ands"}),
        (0xF2401C1F, "tst x0,#0xff", {"tst"}),
        (0x93435020, "sbfx x0,x1,#3,#18", {"sbfx"}),
        (0xD3435020, "ubfx x0,x1,#3,#18", {"ubfx"}),
        (0xB3435020, "bfxil x0,x1,#3,#18", {"bfxil"}),
        (0x9343FC20, "asr x0,x1,#3", {"asr"}),
        (0x53057C20, "lsr w0,w1,#5", {"lsr"}),
        (0xD379E020, "lsl x0,x1,#7", {"lsl"}),
        (0x93407C20, "sxtw x0,w1", {"sxtw"}),
        (0xB3781C20, "bfi x0,x1,#8,#8", {"bfi"}),
        (0xA9017E68, "stp x8,xzr,[x19,#16]", {"stp"}),
        (0xA900FD1F, "stp xzr,xzr,[x8,#8]", {"stp"}),
        (0xA9000020, "stp x0,x0,[x1]", {"stp"}),
        (0xA9407C20, "ldp x0,xzr,[x1]", {"ldp"}),
        (0xD51BD048, "msr tpidr_el0,x8", {"msr"}),
        (0xD51BD05F, "msr tpidr_el0,xzr", {"msr"}),
        # ---- inverted logical shifted register (N=1): BIC/ORN/EON/BICS ----
        # Words below come from llvm-mc for the mnemonics named here; the
        # 0xaa2c03e8 row is the exact word that stopped the real G3 boot
        # (mvn x8,x12 == orn x8,xzr,x12, lsl #0).
        (0x8A220020, "bic x0,x1,x2", {"bic"}),
        (0x0A250083, "bic w3,w4,w5", {"bic"}),
        (0x8A281CE6, "bic x6,x7,x8,lsl#7", {"bic"}),
        (0x8A6B8549, "bic x9,x10,x11,lsr#33", {"bic"}),
        (0x8AAEFDAC, "bic x12,x13,x14,asr#63", {"bic"}),
        (0x0AF12E0F, "bic w15,w16,w17,ror#11", {"bic"}),
        (0xAA220020, "orn x0,x1,x2", {"orn"}),
        (0x2A251483, "orn w3,w4,w5,lsl#5", {"orn"}),
        (0xAA6804E6, "orn x6,x7,x8,lsr#1", {"orn"}),
        (0x2AAB7D49, "orn w9,w10,w11,asr#31", {"orn"}),
        (0xAAEE81AC, "orn x12,x13,x14,ror#32", {"orn"}),
        (0xCA220020, "eon x0,x1,x2", {"eon"}),
        (0x4A651C83, "eon w3,w4,w5,lsr#7", {"eon"}),
        (0xCAA808E6, "eon x6,x7,x8,asr#2", {"eon"}),
        (0xEA220020, "bics x0,x1,x2", {"bics"}),
        (0x6A250083, "bics w3,w4,w5", {"bics"}),
        (0xEAE810E6, "bics x6,x7,x8,ror#4", {"bics"}),
        (0xEA22003F, "bics xzr,x1,x2", {"bics"}),
        (0xAA2C03E8, "mvn x8,x12 (real boot word)", {"mvn", "orn"}),
        (0xAA2A03E9, "mvn x9,x10", {"mvn", "orn"}),
        (0x2A2C03EB, "mvn w11,w12", {"mvn", "orn"}),
        (0xAA2E27ED, "mvn x13,x14,lsl#9", {"mvn", "orn"}),
        (0x8A3003EF, "bic x15,xzr,x16", {"bic"}),
        (0x8A3F0251, "bic x17,x18,xzr", {"bic"}),
        # ---- canonical DMB ISH (module-only; the exact boot word) ----
        # 0xd5033bbf stopped the real G3 boot at 0x102011c4f8.
        (0xD5033BBF, "dmb ish (real boot word)", {"dmb"}),
        # ---- one-source RBIT (module-only, both widths) ----
        # 0xdac00129 is the exact word that stopped the real G3 boot
        # (rbit x9, x9), so the encoder under test is pinned to a real one.
        (0xDAC00129, "rbit x9,x9 (real boot word)", {"rbit"}),
        (0x5AC00000, "rbit w0,w0", {"rbit"}),
        (0xDAC003FF, "rbit xzr,xzr", {"rbit"}),
        (0xDAC001FF, "rbit xzr,x15 (Rd=31, Rn=15)", {"rbit"}),
        (0xDAC0010B, "rbit x11,x8", {"rbit"}),
        (0x5AC00028, "rbit w8,w1", {"rbit"}),
        (0x5AC003FF, "rbit wzr,wzr", {"rbit"}),
        # ---- one-source CLZ (module-only, both widths) ----
        # 0xdac0110b is the exact word that stopped the real G3 boot
        # (clz x11, x8), so the encoder under test is pinned to a real one.
        (0xDAC0110B, "clz x11,x8 (real boot word)", {"clz"}),
        (0x5AC01000, "clz w0,w0", {"clz"}),
        (0xDAC013FF, "clz xzr,xzr", {"clz"}),
        (0xDAC01269, "clz x9,x19", {"clz"}),
        (0x5AC01251, "clz w17,w18", {"clz"}),
        # ---- two-source variable shifts (module-only, both widths) ----
        # 0x9acb254e is the exact word that stopped the real Start prefix
        # right after the CLZ fix (lsr x14, x10, x11).
        (0x9ACB254E, "lsr x14,x10,x11 (real boot word)", {"lsr"}),
        (0x1ACE254E, "lsr w14,w10,w14", {"lsr"}),
        (0x9ACB214E, "lsl x14,x10,x11", {"lsl"}),
        (0x1ACE214E, "lsl w14,w10,w14", {"lsl"}),
        (0x9ACB294E, "asr x14,x10,x11", {"asr"}),
        (0x1ACE294E, "asr w14,w10,w14", {"asr"}),
        (0x9ACB2D4E, "ror x14,x10,x11", {"ror"}),
        (0x1ACE2D4E, "ror w14,w10,w14", {"ror"}),
        (0x9ACB23FF, "lsl xzr,xzr,x11", {"lsl"}),
        (0x1ACB255F, "lsr wzr,w10,w11", {"lsr"}),
        # ---- UMULH (module-only, X only; the exact boot word) ----
        # 0x9bc97d49 is the exact word that stopped the real G3 boot
        # (umulh x9, x10, x9), so the encoder under test is pinned to a real
        # one.  The words below come from llvm-mc for the mnemonics named.
        (0x9BC97D49, "umulh x9,x10,x9 (real boot word)", {"umulh"}),
        (0x9BC07C00, "umulh x0,x0,x0", {"umulh"}),
        (0x9BC07FFF, "umulh xzr,xzr,x0", {"umulh"}),
        (0x9BC97C24, "umulh x4,x1,x9 (Rn=1)", {"umulh"}),
        (0x9BC57C29, "umulh x9,x1,x5", {"umulh"}),
    ]
    new_ok = 0
    for word, why, want in new_forms:
        cs = capstone_one(word, 0x1000000000)
        if cs is None:
            fail("%s: fixture word 0x%08x is not a real instruction"
                 % (why, word))
            continue
        try:
            T.decode(0x1000000000, word, module=True)
        except T.DecodeError as exc:
            fail("module mode REFUSED new family %s: %s" % (why, exc))
            continue
        if cs.mnemonic not in want:
            fail("%s: Capstone says %r, wanted %r"
                 % (why, cs.mnemonic, sorted(want)))
            continue
        try:
            T.decode(0x1000000000, word, module=False)
        except T.DecodeError:
            new_ok += 1
        else:
            fail("%s: new family leaked into the legacy G2 subset" % why)
    print("new module-only families: %d/%d checked"
          % (new_ok, len(new_forms)))
    # MSR TPIDR_EL0 metadata: module accepts canonical tpidr with exact Rt;
    # legacy G2 and unrelated MSR encodings stay typed rejections.
    for word, rt in ((0xD51BD040, 0), (0xD51BD048, 8),
                     (0xD51BD05E, 30), (0xD51BD05F, 31)):
        try:
            d = T.decode(0x1000000000, word, module=True)
        except T.DecodeError as exc:
            fail("msr tpidr_el0 Rt=%d refused in module mode: %s" % (rt, exc))
            continue
        if d.get("kind") != "msr_tpidr" or d.get("rt") != rt:
            fail("msr tpidr_el0 Rt=%d metadata %r" % (rt, d))
        try:
            T.decode(0x1000000000, word, module=False)
        except T.DecodeError:
            pass
        else:
            fail("msr tpidr_el0 Rt=%d leaked into legacy G2" % rt)
    for word, why in ((0xD51BD060, "msr tpidrro_el0,x0"),
                      (0xD51BE320, "msr cntv_ctl_el0,x0"),
                      (0xD5184000, "msr unrelated sysreg")):
        try:
            T.decode(0x1000000000, word, module=True)
        except T.DecodeError:
            pass
        else:
            fail("%s was accepted (must stay rejected)" % why)

    # ---------------- one-source RBIT: exhaustive field sweep --------------
    #     sf 1 0 11010110 opcode opcode2 Rn Rd
    # with opcode == 0 and opcode2 == 0b000000, i.e. only bits 31 (sf), 9:5
    # (Rn) and 4:0 (Rd) vary and every other bit is fixed by
    #     (word & 0x7FFFFC00) == 0x5AC00000.
    # All 2 * 32 * 32 = 2048 encodings are checked against Capstone (mnemonic
    # plus BOTH registers, with reg31 named as the zero register, never SP),
    # the decoded set is proven EQUAL to the masked set -- so no other word in
    # the class is silently accepted -- and each one must stay refused by the
    # G2 single-image subset.
    def enc_rbit(sf, rn, rd):
        return ((sf << 31) | (0x2D6 << 21) |
                ((rn & 0x1F) << 5) | (rd & 0x1F))

    rbit_seen = set()
    for sf in (0, 1):
        for rn in range(32):
            for rd in range(32):
                word = enc_rbit(sf, rn, rd)
                width = 64 if sf else 32
                if word & 0x7FFFFC00 != 0x5AC00000:
                    fail("enc_rbit(%d,%d,%d) breaks the fixed mask"
                         % (sf, rn, rd))
                    continue
                try:
                    ins = T.decode(0x1000000000, word, module=True)
                except T.DecodeError as exc:
                    fail("module mode refused rbit %s,%s: %s"
                         % (reg_name(width, rd), reg_name(width, rn), exc))
                    continue
                want = ("rbit", width, rn, rd)
                got = (ins["kind"], ins["width"], ins["rn"], ins["rd"])
                if got != want:
                    fail("rbit 0x%08x metadata %r != %r" % (word, got, want))
                    continue
                cs = capstone_one(word, 0x1000000000)
                if cs is None or cs.mnemonic != "rbit":
                    fail("rbit 0x%08x: Capstone says %r"
                         % (word, None if cs is None else cs.mnemonic))
                    continue
                got_regs = tuple(cname(cs, o.reg) for o in cs.operands)
                want_regs = (reg_name(width, rd), reg_name(width, rn))
                if got_regs != want_regs:
                    fail("rbit 0x%08x: Capstone operands %r != %r"
                         % (word, got_regs, want_regs))
                    continue
                try:
                    T.decode(0x1000000000, word, module=False)
                except T.DecodeError:
                    pass
                else:
                    fail("rbit 0x%08x leaked into the G2 subset" % word)
                    continue
                rbit_seen.add(word)
    stray = sum(1 for w in rbit_seen if w & 0x7FFFFC00 != 0x5AC00000)
    if stray:
        fail("%d accepted RBIT words escape the fixed mask" % stray)
    if len(rbit_seen) != 2048:
        fail("RBIT sweep covered %d/2048 encodings" % len(rbit_seen))
    print("rbit sweep: %d/%d encodings module-only with exact fields, "
          "Capstone-agreed, G2-refused" % (len(rbit_seen), 2048))

    # ---------------- UMULH: exhaustive field sweep ------------------------
    #     mask 0xFFE0FC00 == 0x9BC07C00, i.e. bits 15:10 are the fixed
    #     "011111" field (UMULH is a three-source FORMAT with Ra/p-bit 15
    #     reserved, not an aliased Ra operand); the mask fixes the opcode.
    #     Only Rm(20:16), Rn(9:5) and Rd(4:0) vary, so all 32**3 = 32768
    #     encodings are enumerated with Capstone agreeing on the mnemonic AND
    #     all three registers (31 named as the ZERO register, never SP).  The
    #     sf=0 class 0x1BC07C00 is NOT this instruction: Capstone rejects it
    #     and module mode must refuse it, so no W form exists.
    def enc_umulh(rm, rn, rd):
        return (0x9BC07C00 | ((rm & 0x1F) << 16) |
                ((rn & 0x1F) << 5) | (rd & 0x1F))

    umulh_seen = set()
    for rm in range(32):
        for rn in range(32):
            for rd in range(32):
                word = enc_umulh(rm, rn, rd)
                if word & 0xFFE0FC00 != 0x9BC07C00:
                    fail("enc_umulh(%d,%d,%d) breaks the fixed mask"
                         % (rm, rn, rd))
                    continue
                if (word >> 10) & 0x3F != 0x1F:
                    fail("enc_umulh(%d,%d,%d) breaks the reserved field"
                         % (rm, rn, rd))
                    continue
                try:
                    ins = T.decode(0x1000000000, word, module=True)
                except T.DecodeError as exc:
                    fail("module mode refused umulh x%d,x%d,x%d: %s"
                         % (rd, rn, rm, exc))
                    continue
                want = ("umulh", rm, rn, rd)
                got = (ins["kind"], ins["rm"], ins["rn"], ins["rd"])
                if got != want:
                    fail("umulh 0x%08x metadata %r != %r" % (word, got, want))
                    continue
                cs = capstone_one(word, 0x1000000000)
                if cs is None or cs.mnemonic != "umulh":
                    fail("umulh 0x%08x: Capstone says %r"
                         % (word, None if cs is None else cs.mnemonic))
                    continue
                got_regs = tuple(cname(cs, o.reg) for o in cs.operands)
                want_regs = (reg_name(64, rd), reg_name(64, rn),
                             reg_name(64, rm))
                if got_regs != want_regs:
                    fail("umulh 0x%08x: Capstone operands %r != %r"
                         % (word, got_regs, want_regs))
                    continue
                try:
                    T.decode(0x1000000000, word, module=False)
                except T.DecodeError:
                    pass
                else:
                    fail("umulh 0x%08x leaked into the G2 subset" % word)
                    continue
                umulh_seen.add(word)
    stray = sum(1 for w in umulh_seen if w & 0xFFE0FC00 != 0x9BC07C00)
    if stray:
        fail("%d accepted UMULH words escape the fixed mask" % stray)
    if len(umulh_seen) != 32768:
        fail("UMULH sweep covered %d/32768 encodings" % len(umulh_seen))
    print("umulh sweep: %d/%d encodings module-only with exact fields, "
          "Capstone-agreed, G2-refused" % (len(umulh_seen), 32768))

    # ---------------- DMB/DSB/ISB option grid ------------------------------
    # Encoding: 11010101 00000011 0011 CRm(4) opc(3) 11111, i.e. bits 15:12 are
    # fixed 0x3 and bits 4:0 fixed 0x1F; CRm selects the option and opc the
    # operation (2 CLREX at CRm=0xF, 4 DSB, 5 DMB, 6 ISB). ALL 8*16 = 128
    # combinations are enumerated so the new acceptance cannot widen the
    # class: module mode may accept ONLY the three pre-existing SY words plus
    # the canonical DMB ISH, and G2 only the three legacy SY words. Capstone
    # must agree on the mnemonic AND the barrier option of every word it
    # decodes.
    opc_names = {4: "dsb", 5: "dmb", 6: "isb"}
    old_sy = {0xD5033FBF, 0xD5033F9F, 0xD5033FDF}
    grid_ok = grid_refused = 0
    for opc3 in range(8):
        for crm in range(16):
            word = 0xD5033000 | (crm << 8) | (opc3 << 5) | 0x1F
            if (word & 0xFFFF3000) != 0xD5033000:
                fail("grid word 0x%08x escapes the barrier mask" % word)
                continue
            want_new = word == 0xD5033BBF
            want_old = word in old_sy
            if word == 0xD5033F5F:
                # CLREX lives in the same grid slice (opc=2, CRm=0xF) and was
                # already accepted by the legacy subset: it must keep decoding
                # as CLREX in BOTH modes, never as a barrier.
                if T.decode(0x1000000000, word, module=True)["kind"] != "clrex":
                    fail("0x%08x no longer decodes as clrex" % word)
                    continue
                if T.decode(0x1000000000, word, module=False)["kind"] != "clrex":
                    fail("0x%08x: G2 no longer accepts clrex" % word)
                    continue
                grid_ok += 1
                continue
            cs = capstone_one(word, 0x1000000000)
            if opc3 in opc_names:
                # Three CRm values in the DSB slice are separate named
                # barriers (SSBB/PSSBB/DFB), not DSB options; they must stay
                # refused like every other non-canonical form.
                special = {0xD503309F: "ssbb", 0xD503349F: "pssbb",
                           0xD5033C9F: "dfb"}
                want_m = special.get(word, opc_names[opc3])
                if cs is None:
                    fail("Capstone cannot decode the %s grid word 0x%08x"
                         % (want_m, word))
                    continue
                if cs.mnemonic != want_m:
                    fail("grid 0x%08x: Capstone mnemonic %r != %r"
                         % (word, cs.mnemonic, want_m))
                    continue
                if want_m in ("dsb", "dmb"):
                    if len(cs.operands) != 1 or \
                            getattr(cs.operands[0], "barrier", None) != crm:
                        fail("grid 0x%08x: Capstone option %r != %d"
                             % (word, [getattr(o, "barrier", None)
                                      for o in cs.operands], crm))
                        continue
            try:
                ins = T.decode(0x1000000000, word, module=True)
            except T.DecodeError:
                if want_new or want_old:
                    fail("module mode refused the accepted barrier 0x%08x"
                         % word)
                    continue
                grid_refused += 1
            else:
                if not (want_new or want_old):
                    fail("module mode accepted the unexpected barrier 0x%08x "
                         "(opc=%d CRm=%d)" % (word, opc3, crm))
                    continue
                if ins["kind"] != "barrier":
                    fail("0x%08x decoded as %r" % (word, ins["kind"]))
                    continue
                if want_new:
                    if ins.get("option") != "ish":
                        fail("dmb ish 0x%08x metadata %r lacks option ish"
                             % (word, ins))
                        continue
                elif "option" in ins:
                    fail("0x%08x: legacy SY barrier gained an option field"
                         % word)
                    continue
                grid_ok += 1
            try:
                T.decode(0x1000000000, word, module=False)
            except T.DecodeError:
                if want_old:
                    fail("G2 refused the legacy SY barrier 0x%08x" % word)
                    continue
                if want_new:
                    continue
            else:
                if not want_old:
                    fail("0x%08x leaked into the G2 single-image subset"
                         % word)
    if (grid_ok, grid_refused) != (5, 123):
        fail("barrier grid covered %d accepted / %d refused, wanted 5 / 123 "
             "(3 legacy SY + dmb ish + clrex)" % (grid_ok, grid_refused))
    print("barrier grid: 128 CRm/opc combinations; module accepts only the 3 "
          "legacy SY words + canonical dmb ish (+clrex), G2 rejects dmb ish, "
          "Capstone mnemonic+option agreed")

    # ---------------- one-source CLZ: exhaustive field sweep -------------
    # The complete encoding is
    #     sf 1 0 11010110 opcode opcode2 Rn Rd
    # with opcode == 0 and opcode2 == 0b000100, i.e. only bits 31 (sf), 9:5
    # (Rn) and 4:0 (Rd) vary and every other bit is fixed by
    #     (word & 0x7FFFFC00) == 0x5AC01000.
    # All 2 * 32 * 32 = 2048 encodings are checked against Capstone (mnemonic
    # plus BOTH registers, with reg31 named as the zero register, never SP),
    # the decoded set is proven EQUAL to the masked set -- so no other word
    # in the class is silently accepted -- and each one must stay refused by
    # the G2 single-image subset.
    def enc_clz(sf, rn, rd):
        return ((sf << 31) | (0x2D6 << 21) | (0x04 << 10) |
                ((rn & 0x1F) << 5) | (rd & 0x1F))

    clz_seen = set()
    clz_bad = 0
    for sf in (0, 1):
        for rn in range(32):
            for rd in range(32):
                word = enc_clz(sf, rn, rd)
                width = 64 if sf else 32
                if word & 0x7FFFFC00 != 0x5AC01000:
                    fail("enc_clz(%d,%d,%d) breaks the fixed mask"
                         % (sf, rn, rd))
                    clz_bad += 1
                    continue
                try:
                    ins = T.decode(0x1000000000, word, module=True)
                except T.DecodeError as exc:
                    fail("module mode refused clz %s,%s: %s"
                         % (reg_name(width, rd), reg_name(width, rn), exc))
                    clz_bad += 1
                    continue
                want = ("clz", width, rn, rd)
                got = (ins["kind"], ins["width"], ins["rn"], ins["rd"])
                if got != want:
                    fail("clz 0x%08x metadata %r != %r" % (word, got, want))
                    clz_bad += 1
                    continue
                cs = capstone_one(word, 0x1000000000)
                if cs is None or cs.mnemonic != "clz":
                    fail("clz 0x%08x: Capstone says %r"
                         % (word, None if cs is None else cs.mnemonic))
                    clz_bad += 1
                    continue
                got_regs = tuple(cname(cs, o.reg) for o in cs.operands)
                want_regs = (reg_name(width, rd), reg_name(width, rn))
                if got_regs != want_regs:
                    fail("clz 0x%08x: Capstone operands %r != %r"
                         % (word, got_regs, want_regs))
                    clz_bad += 1
                    continue
                try:
                    T.decode(0x1000000000, word, module=False)
                except T.DecodeError:
                    pass
                else:
                    fail("clz 0x%08x leaked into the G2 subset" % word)
                    clz_bad += 1
                    continue
                clz_seen.add(word)
    sweep_domain = set()
    stray = sum(1 for w in clz_seen if w & 0x7FFFFC00 != 0x5AC01000)
    if stray:
        fail("%d accepted CLZ words escape the fixed mask" % stray)
    if stray:
        fail("%d accepted CLZ words escape the fixed mask" % stray)
    if len(clz_seen) != 2048:
        fail("CLZ sweep covered %d/2048 encodings" % len(clz_seen))
    print("clz sweep: %d/%d encodings module-only with exact fields, "
          "Capstone-agreed, G2-refused" % (len(clz_seen), 2048))

    # ---- two-source variable shifts: exhaustive register-field sweep -----
    #     sf 0 0 11010110 Rm opcode Rn Rd  with opcode (15:10) in
    #     0b001000..0b001011 (LSLV/LSRV/ASRV/RORV). The fixed field set is
    #     bits 30:21 and 15:10, so the mask below is exact and only
    #     sf/Rm/Rn/Rd vary: 2 * 4 * 32 * 32 * 32 = 262144 encodings.
    def enc_vshift(sf, op, rm, rn, rd):
        return ((sf << 31) | (0x0D6 << 21) | ((rm & 0x1F) << 16) |
                ((8 + op) << 10) | ((rn & 0x1F) << 5) | (rd & 0x1F))

    vs_mnem = {0: "lsl", 1: "lsr", 2: "asr", 3: "ror"}
    vs_seen = set()
    vs_bad = 0
    for sf in (0, 1):
        for op in range(4):
            for rm in range(32):
                for rn in range(32):
                    for rd in range(32):
                        word = enc_vshift(sf, op, rm, rn, rd)
                        if (word & 0x7FE0FC00) not in (
                                0x1AC02000, 0x1AC02400,
                                0x1AC02800, 0x1AC02C00):
                            fail("enc_vshift(0x%08x) escapes the class mask"
                                 % word)
                            vs_bad += 1
                            continue
                        try:
                            ins = T.decode(0x1000000000, word, module=True)
                        except T.DecodeError as exc:
                            fail("module refused %s %s 0x%08x: %s"
                                 % (vs_mnem[op], "x" if sf else "w",
                                    word, exc))
                            vs_bad += 1
                            continue
                        got = (ins["kind"], ins["shift"], ins["width"],
                               ins["rm"], ins["rn"], ins["rd"])
                        want = ("varshift", op, 64 if sf else 32, rm, rn, rd)
                        if got != want:
                            fail("0x%08x metadata %r != %r"
                                 % (word, got, want))
                            vs_bad += 1
                            continue
                        cs = capstone_one(word, 0x1000000000)
                        if cs is None or cs.mnemonic != vs_mnem[op]:
                            fail("0x%08x: Capstone says %r, wanted %r"
                                 % (word, None if cs is None else cs.mnemonic,
                                    vs_mnem[op]))
                            vs_bad += 1
                            continue
                        wd = 64 if sf else 32
                        want_regs = (reg_name(wd, rd), reg_name(wd, rn),
                                     reg_name(wd, rm))
                        got_regs = tuple(cname(cs, o.reg) for o in cs.operands)
                        if got_regs != want_regs:
                            fail("0x%08x: Capstone operands %r != %r"
                                 % (word, got_regs, want_regs))
                            vs_bad += 1
                            continue
                        try:
                            T.decode(0x1000000000, word, module=False)
                        except T.DecodeError:
                            pass
                        else:
                            fail("0x%08x leaked into the G2 subset" % word)
                            vs_bad += 1
                            continue
                        vs_seen.add(word)
    stray = sum(1 for w in vs_seen if w & 0x7FE0FC00 not in
                (0x1AC02000, 0x1AC02400, 0x1AC02800, 0x1AC02C00))
    if stray:
        fail("%d accepted variable-shift words escape the class mask" % stray)
    if len(vs_seen) != 262144:
        fail("variable-shift sweep covered %d/262144 encodings" % len(vs_seen))
    if vs_bad:
        fail("%d variable-shift sweep failures" % vs_bad)
    print("varshift sweep: %d/%d encodings (2 widths x 4 opcodes x 32^3 "
          "registers) module-only with exact fields, Capstone-agreed, "
          "G2-refused" % (len(vs_seen), 262144))

    # Reserved / adjacent two-source words must stay refused: the opcode
    # holes 0b000100/0b000101/0b000110/0b000111, 0b0011xx, the S-bit (29)
    # set, and UDIV/SDIV are NOT variable shifts.
    for why, word in (("opcode=0b000100", 0x1AC01000),
                      ("opcode=0b000101", 0x1AC01400),
                      ("opcode=0b000110", 0x1AC01800),
                      ("opcode=0b000111", 0x1AC01C00),
                      ("opcode=0b001100", 0x1AC03000),
                      ("opcode=0b001111 X", 0x9AC03400),
                      ("bit29 (S) set on LSLV", 0x3AC02000),
                      ("bit30 set on LSRV", 0x5AC02400),
                      ("bit21 (part of fixed group) set", 0x1AE02400)):
        try:
            T.decode(0x1000000000, word, module=True)
        except T.DecodeError:
            continue
        fail("%s (0x%08x) decoded instead of failing closed" % (why, word))
    # UDIV/SDIV must keep decoding as their own kind (the new branch must not
    # swallow them), and must still be module-only.
    for word, kind in ((0x9AD70918, "udiv"), (0x1AC20820, "udiv"),
                       (0x9AC50C83, "sdiv"), (0x1AC80CE6, "sdiv")):
        ins = T.decode(0x1000000000, word, module=True)
        if ins["kind"] != kind:
            fail("0x%08x decoded as %r, wanted %r"
                 % (word, ins["kind"], kind))
    print("varshift negatives: 9 reserved/adjacent words refused, "
          "UDIV/SDIV still their own kind")

    # Adjacent one-source forms MUST stay refused (no class widening) and the
    # reserved/opcode bit combinations must never decode as RBIT or CLZ. All
    # of these words were produced by llvm-mc or are the exact RBIT/CLZ word
    # with ONE field folded to its nearest neighbour.
    for why, word in (
            ("rev16 w0,w0", 0x5AC00400),
            ("rev16 x0,x0", 0xDAC00400),
            ("rev32/REV x0,x0 (opcode2=2)", 0x5AC00800),
            ("rev x0,x0 (opcode2=3)", 0xDAC00C00),
            ("cls x0,x0 (opcode2=5)", 0x5AC01400),
            ("opcode2=6", 0x5AC01800),
            ("opcode2=7", 0x5AC01C00),
            ("opcode=1 opcode2=4 (PAC-ish hole)", 0x5AC11000),
            ("opcode=2 opcode2=4", 0x5AC21000),
            ("rbit with S bit set (bit 29)", 0x7AC00000),
            ("rbit with bit 30 clear", 0x1AC00029),
            ("rbit with Rm field nonzero (opcode=8)", 0x5AC80029),
            ("clz with S bit set (bit 29)", 0x7AC01000),
            ("clz with bit 30 clear", 0x1AC0100B),
            ("clz with Rm field nonzero (opcode=8)", 0x5AC8100B),
            ("opcode2=0b100100 (bit15+bit12, unallocated)", 0x5AC0900B)):
        try:
            T.decode(0x1000000000, word, module=True)
        except T.DecodeError:
            continue
        fail("%s (0x%08x) decoded instead of failing closed" % (why, word))

    def logic_mnem(ins):
        """EXACT Capstone mnemonic for a logic_shift decode, aliases included.

        N=0: AND / ORR / EOR / ANDS, with ORR Rd,XZR,Rm (no shift) -> MOV and
             ANDS with Rd==31 -> TST.
        N=1: BIC / ORN / EON / BICS, with ORN Rd,XZR,Rm -> MVN for ANY shift
             (mvn x13,x14,lsl #9 is a real encoding). BICS with Rd==31 is NOT
             a TST alias -- there is no inverted TST -- so it stays "bics".
        Nothing here is a membership SET: one field tuple maps to one mnemonic,
        which is what makes the sweep check non-vacuous.
        """
        op = ins["op"]
        if ins.get("invert"):
            if op == 1 and ins["rn"] == 31:
                return "mvn"
            return {0: "bic", 1: "orn", 2: "eon", 3: "bics"}[op]
        if op == 1 and ins["rn"] == 31 and ins["shift"] == 0 and ins["imm6"] == 0:
            return "mov"
        if op == 3 and ins["rd"] == 31:
            return "tst"
        return {0: "and", 1: "orr", 2: "eor", 3: "ands"}[op]

    # ---- N1 (inverted logical) exact-mnemonic fixtures -------------------
    # These words come from llvm-mc (they are the same fixtures as new_forms
    # above) and are pushed through the SAME logic_mnem() mapping the accepted
    # corpus uses, with the expected mnemonic spelled out per word. This is
    # what makes the N1 lanes non-vacuous: ORN Rn==31 is MVN for ANY shift,
    # and BICS with Rd==31 must stay "bics" -- never the N=0 TST alias.
    n1_exact = [(0x8A220020, "bic"),
                (0x0A250083, "bic"),
                (0x8A281CE6, "bic"),
                (0x0AF12E0F, "bic"),            # ror #11 is legal for N=1
                (0xAA220020, "orn"),
                (0x2AAB7D49, "orn"),
                (0xAAEE81AC, "orn"),            # ror #32
                (0xCA220020, "eon"),
                (0xEA220020, "bics"),
                (0xEA22003F, "bics"),           # Rd == 31: NOT tst
                (0x6A250083, "bics"),
                (0xEAE810E6, "bics"),           # ror #4
                (0xAA2C03E8, "mvn"),            # real boot word, rn == 31
                (0x2A2C03EB, "mvn"),            # w11, w12
                (0xAA2E27ED, "mvn"),            # lsl #9: still MVN
                ]
    for word, want_mnem in n1_exact:
        try:
            ins = T.decode(0x1000000000, word, module=True)
        except T.DecodeError as exc:
            fail("module refused N1 fixture 0x%08x (%s): %s"
                 % (word, want_mnem, exc))
            continue
        if ins["kind"] != "logic_shift" or not ins.get("invert"):
            fail("N1 fixture 0x%08x decoded as %r (invert=%r)"
                 % (word, ins["kind"], ins.get("invert")))
            continue
        got = logic_mnem(ins)
        if got != want_mnem:
            fail("N1 fixture 0x%08x: exact mapping says %r, wanted %r"
                 % (word, got, want_mnem))
            continue
        cs = capstone_one(word, 0x1000000000)
        if cs is None or cs.mnemonic != want_mnem:
            fail("N1 fixture 0x%08x: Capstone says %r, exact mapping %r"
                 % (word, None if cs is None else cs.mnemonic, want_mnem))
            continue
        if want_mnem == "bics" and int(ins["rd"]) == 31 and                 cs.mnemonic == "tst":
            fail("BICS Rd==31 was reported as TST on 0x%08x" % word)
    print("N1 exact mapping: %d inverted-logical words matched one-to-one "
          "with Capstone (MVN for rn==31, BICS Rd==31 never TST)"
          % len(n1_exact))

    # ---------------- accepted corpus: cross-check against Capstone -------
    accepted = 0
    per_kind = {}
    for pc, word, why in corpus:
        try:
            ins = T.decode(pc, word, module=True)
        except T.DecodeError as e:
            fail("module mode REFUSED %s: %s" % (why, e))
            continue
        accepted += 1
        per_kind[ins["kind"]] = per_kind.get(ins["kind"], 0) + 1
        cs = capstone_one(word, pc)
        if cs is None:
            fail("accepted %s but Capstone cannot decode 0x%08x" % (why, word))
            continue
        k = ins["kind"]
        if k in ("adrp", "adr"):
            if cs.mnemonic != k:
                fail("%s: Capstone says %r" % (why, cs.mnemonic))
                continue
            want_reg = reg_name(64, ins["rd"])
            got_reg = cname(cs, cs.operands[0].reg)
            if got_reg != want_reg:
                fail("%s: Capstone Rd %r != %r" % (why, got_reg, want_reg))
            want_val = (ins["value"] + 0x1000) if args.perturb else ins["value"]
            if cs.operands[-1].imm != want_val:
                fail("%s: Capstone target 0x%x != decoder 0x%x"
                     % (why, cs.operands[-1].imm & 0xFFFFFFFFFFFFFFFF,
                        want_val))
        elif k == "logic_shift":
            width = ins["width"]
            want_mnem = logic_mnem(ins)      # ONE mnemonic, invert included
            # Aliases that drop an operand: MOV/MVN (Rn == 31) and TST (Rd).
            no_rd = want_mnem in ("mov", "tst", "mvn")
            if cs.mnemonic != want_mnem:
                fail("%s: Capstone says %r, decoder expects %r "
                     "(op=%d invert=%d rn=%d rd=%d shift=%d imm6=%d)"
                     % (why, cs.mnemonic, want_mnem, ins["op"],
                        1 if ins.get("invert") else 0, ins["rn"], ins["rd"],
                        ins["shift"], ins["imm6"]))
            if not no_rd:
                want_rd = reg_name(width, ins["rd"])
                if cname(cs, cs.operands[0].reg) != want_rd:
                    fail("%s: Capstone Rd %r != %r"
                         % (why, cname(cs, cs.operands[0].reg), want_rd))
            # Rn (XZR: 31 in this form is XZR) -- not printed by MOV/MVN/TST.
            if want_mnem not in ("mov", "mvn"):
                want_rn = reg_name(width, ins["rn"])
                rn_op = 0 if want_mnem == "tst" else 1
                if cname(cs, cs.operands[rn_op].reg) != want_rn:
                    fail("%s: Capstone Rn %r != %r"
                         % (why, cname(cs, cs.operands[rn_op].reg), want_rn))
            want_rm = reg_name(width, ins["rm"])
            last = cs.operands[-1]
            if cname(cs, last.reg) != want_rm:
                fail("%s: Capstone Rm %r != %r"
                     % (why, cname(cs, last.reg), want_rm))
            names = {0: "lsl", 1: "lsr", 2: "asr"}
            # Capstone reports LSL #0 as "no shift" or "lsl #0".
            got_amt = last.shift.value if last.shift.type != 0 else 0
            if got_amt != ins["imm6"]:
                fail("%s: Capstone shift amount %s != imm6 %d"
                     % (why, got_amt, ins["imm6"]))
            if ins["imm6"] != 0:
                print_shift = getattr(last.shift, "type", 0)
                if print_shift == 0:
                    fail("%s: Capstone sees no shift, decoder has %s #%d"
                         % (why, names[ins["shift"]], ins["imm6"]))
        elif k == "nop":
            if cs.mnemonic != "nop":
                fail("%s: Capstone says %r" % (why, cs.mnemonic))
        elif k in ("mrs_counter", "mrs_tpidr"):
            if cs.mnemonic != "mrs":
                fail("%s: Capstone says %r" % (why, cs.mnemonic))
                continue
            want = reg_name(64, ins["rt"]) if ins["rt"] != 31 else "xzr"
            if cname(cs, cs.operands[0].reg) != want:
                fail("%s: Capstone Rt %r != %r"
                     % (why, cname(cs, cs.operands[0].reg), want))
            sysname = cs.op_str.split(",")[-1].strip()
            fields = {T.SYSREG_CNTPCT_EL0: "cntpct_el0",
                      T.SYSREG_CNTVCT_EL0: "cntvct_el0"}
            if k == "mrs_tpidr":
                key = ins["field"]
            else:
                key = ins["sysreg16"]
            want_sys = fields.get(key) if k == "mrs_counter" else                 {"tpidr": "tpidr_el0", "tpidrro": "tpidrro_el0"}[key]
            if sysname != want_sys:
                fail("%s: Capstone system register %r != %r"
                     % (why, sysname, want_sys))
        else:
            fail("%s: unexpected kind %r from module mode" % (why, k))
    print("accepted corpus: %d words, kinds %s"
          % (accepted, dict(sorted(per_kind.items()))))
    for kind in ("adrp", "adr", "logic_shift", "nop", "mrs_counter",
                 "mrs_tpidr"):
        if per_kind.get(kind, 0) == 0:
            fail("corpus never exercised kind %r" % kind)
    if accepted != len(corpus):
        fail("corpus is not fully accepted (%d/%d)" % (accepted, len(corpus)))

    # ---------------- negative control for the comparison itself ----------
    ctl_word = enc_adrp(1, 0x10)
    ctl_pc = 0x1000000000
    ctl_ins = T.decode(ctl_pc, ctl_word, module=True)
    ctl_cs = capstone_one(ctl_word, ctl_pc)
    if ctl_cs is None or ctl_cs.operands[-1].imm != ctl_ins["value"]:
        fail("negative control: Capstone and the decoder disagree on a plain "
             "ADRP target, so the comparison is not measuring anything")
    elif ctl_cs.operands[-1].imm == (ctl_ins["value"] + 0x1000):
        fail("negative control: an off-by-one-page target cannot be detected")
    else:
        print("negative control: an off-by-one-page ADRP target is "
              "distinguishable (decoder 0x%x vs +0x1000)"
              % ctl_ins["value"])

    # ---------------- G2 gating: none of these is a G2 instruction --------
    g2_accepted = []
    for pc, word, why in corpus:
        try:
            T.decode(pc, word, module=False)
        except T.DecodeError:
            continue
        g2_accepted.append(why)
    if g2_accepted:
        fail("module-only forms leaked into the G2 subset: %r"
             % (g2_accepted[:5],))
    else:
        print("G2 gating: none of the %d module forms is accepted with "
              "module=False" % len(corpus))

    # ---------------- explicit fail-closed list ---------------------------
    # Each word must be a REAL instruction (Capstone decodes it) that the
    # module subset refuses; a refusal of garbage would prove nothing.
    refusals = [
        ("ROR shift (N=0)", enc_logic(1, 1, 3, 5, 1, 0, 0)),
        ("W LSL #32", enc_logic(0, 1, 0, 32, 1, 0, 0)),
        ("W LSR #40", enc_logic(0, 0, 1, 40, 1, 0, 0)),
        ("W ASR #63", enc_logic(0, 2, 2, 63, 1, 0, 0)),
        # The inverted (N=1) forms keep the same reserved-W rule: imm6 bit 5
        # is UNPREDICTABLE for 32-bit operands, for every shift type.
        ("BIC W LSL #32", enc_logic(0, 0, 0, 32, 1, 0, 0, n=1)),
        ("BIC W ROR #32", enc_logic(0, 0, 3, 32, 1, 0, 0, n=1)),
        ("ORN W LSR #40", enc_logic(0, 1, 1, 40, 1, 0, 0, n=1)),
        ("EON W ASR #63", enc_logic(0, 2, 2, 63, 1, 0, 0, n=1)),
        ("BICS W LSL #32", enc_logic(0, 3, 0, 32, 1, 0, 0, n=1)),
        ("SYS #0,c7,c5,#0", enc_sys(0, 7, 5, 0)),
        ("MRS midr_el1", enc_mrs(0xC000, 0)),
        ("MRS op0=2 (0xC0xx)", enc_mrs(0xC000, 0)),
        ("MRS op0=2 ctr-like", enc_mrs(enc_sysreg16(2, 3, 0, 0, 1), 0)),
        ("MRS ctr_el0", enc_mrs(enc_sysreg16(3, 3, 0, 0, 1), 0)),
        # UMULH has no defined W form: sf=0 (the whole 0x1BC07C00 class) is
        # unallocated, so both Capstone and this subset must reject it.  A
        # neighbouring fixed-field corruption must be rejected as well, even
        # though Capstone decodes neither of them either.
        ("UMULH W form (sf=0)", 0x1BC97D49),
        ("UMULH with Ra/reserved field", 0x9BC0FC00),
    ]
    # imm6 >= width in the W form is UNPREDICTABLE, not an instruction that
    # Capstone will disassemble: our refusal must agree with Capstone's.
    unpredictable = {"W LSL #32", "W LSR #40", "W ASR #63",
                     "BIC W LSL #32", "BIC W ROR #32",
                     "ORN W LSR #40", "EON W ASR #63",
                     "BICS W LSL #32",
                     "UMULH W form (sf=0)",
                     "UMULH with Ra/reserved field"}
    for why, word in refusals:
        cs = capstone_one(word, 0x1000000000)
        if why in unpredictable:
            if cs is not None:
                fail("%s: Capstone accepted the UNPREDICTABLE 0x%08x as %r"
                     % (why, word, cs.mnemonic))
                continue
        elif cs is None:
            fail("%s: fixture word 0x%08x is not a real instruction"
                 % (why, word))
            continue
        try:
            T.decode(0x1000000000, word, module=True)
        except T.DecodeError:
            continue
        fail("module mode ACCEPTED %s (0x%08x) but it is outside the subset"
             % (why, word))
    print("fail-closed list: %d forms checked" % len(refusals))

    # ---------------- fixed-seed random sweep -----------------------------
    rng = random.Random(args.seed)
    MODULE_ONLY = {"adrp", "adr", "logic_shift", "nop", "mrs_counter",
                   "mrs_tpidr", "movn", "ldst_signed", "tbz", "tbnz",
                   "csel", "csinc", "csinv", "csneg", "addsub_ext",
                   "ldst_imm9", "ldst_regoff", "bfm", "logic_imm", "clz",
                   "varshift", "umulh"}
    MNEMONIC_SETS = {
        "movn": {"mov"},
        "ldst_signed": {"ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrsw"},
        "tbz": {"tbz"}, "tbnz": {"tbnz"},
        "csel": {"csel"},
        "csinc": {"csinc", "cset", "cinc"},
        "csinv": {"csinv", "csetm", "cinv"},
        "csneg": {"csneg", "cneg"},
        "addsub_ext": {"add", "adds", "sub", "subs", "cmp", "cmn"},
        "ldst_imm9": {"ldr", "str", "ldrb", "strb", "ldrh", "strh",
                      "ldrsb", "ldrsh", "ldrsw", "ldur", "stur", "ldurb",
                      "sturb", "ldurh", "sturh", "ldursb", "ldursh",
                      "ldursw"},
        "ldst_regoff": {"ldr", "str", "ldrb", "strb", "ldrh", "strh",
                        "ldrsb", "ldrsh", "ldrsw"},
        "bfm": {"sbfm", "ubfm", "bfm", "sbfx", "ubfx", "bfxil", "bfi", "bfc",
                "asr", "lsr", "lsl", "sxtb", "sxth", "sxtw", "uxtb",
                "uxth", "ubfiz", "sbfiz"},
        "logic_imm": {"and", "orr", "eor", "ands", "tst", "mov"},
    }
    sweep_accepted = 0
    sweep_kinds = {}
    sweep_shared = {}
    for _ in range(args.sweep):
        word = rng.getrandbits(32)
        pc = 0x1000000000 | (rng.getrandbits(12) & ~3)
        try:
            ins = T.decode(pc, word, module=True)
        except T.DecodeError:
            continue
        sweep_accepted += 1
        sweep_kinds[ins["kind"]] = sweep_kinds.get(ins["kind"], 0) + 1
        cs = capstone_one(word, pc)
        if cs is None:
            fail("sweep accepted 0x%08x (%s) which Capstone rejects"
                 % (word, ins["kind"]))
            continue
        if ins["kind"] in MODULE_ONLY:
            switch_kind = ins["kind"]
            if switch_kind == "varshift":
                # EXACT mapping: the shift code selects ONE mnemonic.
                want = {{0: "lsl", 1: "lsr", 2: "asr", 3: "ror"}[ins["shift"]]}
            elif switch_kind == "logic_shift":
                # EXACT mapping (invert and aliases included), never a
                # union-of-names membership test that anything passes.
                want = {logic_mnem(ins)}
            elif switch_kind in ("mrs_counter", "mrs_tpidr"):
                want = {"mrs"}
            else:
                want = MNEMONIC_SETS.get(switch_kind, {switch_kind})
            if cs.mnemonic not in want:
                fail("sweep: 0x%08x decoded %r, Capstone says %r"
                     % (word, ins["kind"], cs.mnemonic))
            # G2 must never accept a MODULE-ONLY form.
            try:
                T.decode(pc, word, module=False)
            except T.DecodeError:
                pass
            else:
                fail("sweep: 0x%08x is accepted with module=False " % word)
        else:
            # A G2 form: module mode accepts it, Capstone must decode it. Its
            # instruction class is the G2 decoder test's business.
            sweep_shared[ins["kind"]] = sweep_shared.get(ins["kind"], 0) + 1
    print("random sweep: %d words (seed %#x), %d accepted by module mode, "
          "kinds %s, shared G2 forms %s"
          % (args.sweep, args.seed, sweep_accepted,
             dict(sorted(sweep_kinds.items())),
             dict(sorted(sweep_shared.items()))))
    if sweep_accepted == 0:
        fail("random sweep accepted nothing: the cross-check is vacuous")

    if FAILS:
        print("g3_decoder_module_test: %d failure(s)" % len(FAILS))
        return 2
    print("g3_decoder_module_test: module-mode decode agrees with Capstone "
          "and refuses the documented out-of-subset forms")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
