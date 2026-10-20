#!/usr/bin/env python3
"""G3 module-mode decoder cross-check against Capstone 5.0.7 (review fix 2).

Everything the module-mode decoder ACCEPTS must be a real A64 instruction that
Capstone decodes to the same class with the same operands (including the
PC-relative ADRP/ADR targets computed from the absolute guest PC).  Everything
it refuses for subset reasons must still be a REAL instruction (Capstone
decodes it) -- otherwise a "refusal" would only mean the word was garbage.

Also asserted:
  * the fixed fail-closed list (ANDS, BIC/ORN/EON, ROR, W imm6 >= 32, MSR, SYS,
    other MRS sysregs, MRS op0=2) raises DecodeError in module mode;
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
            want_mov = (ins["op"] == 1 and ins["rn"] == 31 and
                        ins["shift"] == 0 and ins["imm6"] == 0)
            want = {0: "and", 1: "orr", 2: "eor"}[ins["op"]]
            if want_mov:
                if cs.mnemonic != "mov":
                    fail("%s: expected the MOV alias, Capstone says %r"
                         % (why, cs.mnemonic))
            elif cs.mnemonic != want:
                fail("%s: Capstone says %r, decoder class %r"
                     % (why, cs.mnemonic, want))
            want_rd = reg_name(width, ins["rd"])
            if cname(cs, cs.operands[0].reg) != want_rd:
                fail("%s: Capstone Rd %r != %r"
                     % (why, cname(cs, cs.operands[0].reg), want_rd))
            # Rn (XZR/SP: 31 in this form is XZR) -- not printed by MOV.
            if not want_mov:
                want_rn = reg_name(width, ins["rn"])
                if cname(cs, cs.operands[1].reg) != want_rn:
                    fail("%s: Capstone Rn %r != %r"
                         % (why, cname(cs, cs.operands[1].reg), want_rn))
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
        ("ANDS (opc=3)", enc_logic(1, 3, 0, 0, 1, 0, 0)),
        ("ANDS W (opc=3)", enc_logic(0, 3, 0, 0, 1, 0, 0)),
        ("BIC (N=1, opc=0)", enc_logic(1, 0, 0, 0, 1, 0, 0, n=1)),
        ("ORN (N=1, opc=1)", enc_logic(1, 1, 0, 0, 1, 0, 0, n=1)),
        ("EON (N=1, opc=2)", enc_logic(1, 2, 0, 0, 1, 0, 0, n=1)),
        ("ROR shift", enc_logic(1, 1, 3, 5, 1, 0, 0)),
        ("W LSL #32", enc_logic(0, 1, 0, 32, 1, 0, 0)),
        ("W LSR #40", enc_logic(0, 0, 1, 40, 1, 0, 0)),
        ("W ASR #63", enc_logic(0, 2, 2, 63, 1, 0, 0)),
        ("MSR tpidr_el0", enc_msr(T.SYSREG_TPIDR_EL0, 0)),
        ("SYS #0,c7,c5,#0", enc_sys(0, 7, 5, 0)),
        ("MRS midr_el1", enc_mrs(0xC000, 0)),
        ("MRS op0=2 (0xC0xx)", enc_mrs(0xC000, 0)),
        ("MRS op0=2 ctr-like", enc_mrs(enc_sysreg16(2, 3, 0, 0, 1), 0)),
        ("MRS ctr_el0", enc_mrs(enc_sysreg16(3, 3, 0, 0, 1), 0)),
    ]
    # imm6 >= width in the W form is UNPREDICTABLE, not an instruction that
    # Capstone will disassemble: our refusal must agree with Capstone's.
    unpredictable = {"W LSL #32", "W LSR #40", "W ASR #63"}
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
                   "mrs_tpidr"}
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
            if switch_kind == "logic_shift":
                want = {"and", "orr", "eor", "mov"}
            elif switch_kind in ("mrs_counter", "mrs_tpidr"):
                want = {"mrs"}
            else:
                want = {switch_kind}
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
