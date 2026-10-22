#!/usr/bin/env python3
"""Synthetic tests for tools/aot/g3_init_reach.py (w4 review follow-up).

These build two-word-sized fake NSO images in memory and exercise the CFG
scanner without any game data:

  * function entries are pinned roots + BL/indirect callees, never conditional
    blocks or fallthrough-only labels;
  * an instruction rejected by the module subset is counted once per unique
    site even when the block is re-scanned under a different constant state;
  * a BL into a second image is recorded as a call entry and its code is
    attributed to that image (cross-module provenance);
  * a BR/BLR with an unknown or out-of-image register is fail-closed (no
    invented target, an explicit ambiguous record);
  * an undecodable reachable word is a data-in-code stop that blocks callers;
  * a negative control asserts the scanner does not silently invent the value
    of an unresolved register.

Exit: 0 pass, 2 semantic failure, 1 import/usage failure.
"""

import argparse
import os
import sys

FAILS = []


def fail(msg):
    FAILS.append(msg)
    print("FAIL: " + msg)


def expect(cond, msg):
    if not cond:
        fail(msg)


class FakeImage:
    """Minimal Image interface used by scan_world()."""

    def __init__(self, name, base, words):
        self.name = name
        self.base = base
        self.words = list(words)
        self.text = (base, base + 4 * len(self.words))
        self.limit = self.text[1]

    def contains(self, va):
        return self.base <= va < self.limit

    def kind(self, va):
        return "text" if self.contains(va) else None

    def read(self, va, size):
        if size != 4 or va % 4 or not self.contains(va):
            return None
        return self.words[(va - self.base) // 4]

    def read_u32(self, va):
        return self.read(va, 4)


def enc_b(off):
    return 0x14000000 | ((off >> 2) & 0x03FFFFFF)


def enc_bl(off):
    return 0x94000000 | ((off >> 2) & 0x03FFFFFF)


def enc_cbz_x0(off):
    return 0xB4000000 | (((off >> 2) & 0x7FFFF) << 5)


def enc_mov_x0_imm(v):
    return 0xD2800000 | ((v & 0xFFFF) << 5)


RET = 0xD65F03C0
BR_X0 = 0xD61F0000
MOV_X0_1 = enc_mov_x0_imm(1)
MOV_X0_2 = enc_mov_x0_imm(2)
MOV_X0_0x40 = enc_mov_x0_imm(0x40)
# add x1, x1, #1: the decoder stub below rejects exactly this PC.
ADD_X1_1 = 0x91000421
DATA_WORD = 0xFFFFFFFF


def check_encodings(cs):
    samples = [
        (RET, "ret"),
        (BR_X0, "br"),
        (MOV_X0_1, "mov"),
        (MOV_X0_2, "mov"),
        (ADD_X1_1, "add"),
        (enc_cbz_x0(8), "cbz"),
        (enc_b(8), "b"),
        (enc_bl(8), "bl"),
    ]
    for word, mn in samples:
        ins = list(cs.disasm(word.to_bytes(4, "little"), 0x1000))
        expect(bool(ins) and ins[0].mnemonic == mn,
               "test encoder self-check: 0x%08x is %r, wanted %s"
               % (word, [i.mnemonic for i in ins], mn))


def run(tools, capstone):
    sys.path.insert(0, tools)
    import aot_translate as T
    import g3_init_reach as R

    cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    check_encodings(cs)

    def dec_ok(pc, word, module=True):
        return True

    def make_world(images):
        return R.World(images)

    # ---- 1. blocks are not functions ----------------------------------
    words = [enc_cbz_x0(8), RET, RET]
    w = make_world([FakeImage("m", 0x1000, words)])
    s = R.scan_world(w, [(0x1000, "dt_init")], subset_decoder=dec_ok)
    expect(set(s.entries) == {0x1000},
           "conditional target was recorded as a function entry: %r"
           % sorted(hex(x) for x in s.entries))

    words = [enc_bl(8), RET, RET]
    w = make_world([FakeImage("m", 0x1000, words)])
    s = R.scan_world(w, [(0x1000, "dt_init")], subset_decoder=dec_ok)
    expect(s.entries.get(0x1008) == "bl",
           "BL target not recorded as a call entry: %r"
           % {hex(k): v for k, v in s.entries.items()})

    # ---- 2. unique-site counting under two incoming states -------------
    words = [MOV_X0_1, enc_b(8), MOV_X0_2, ADD_X1_1, RET]
    rejected = {0x100C}

    def dec_one(pc, word, module=True):
        if pc in rejected:
            raise T.DecodeError("synthetic unsupported")
        return True

    w = make_world([FakeImage("m", 0x1000, words)])
    s = R.scan_world(w, [(0x1000, "dt_init"), (0x1008, "dt_init")],
                     subset_decoder=dec_one)
    expect(s.insns["m"] == 5,
           "unique instructions counted %d, wanted 5 (vmap)"
           % s.insns["m"])
    reason_counts = [n for (_mn, _reason), n in s.unsupported.items()]
    expect(reason_counts == [1],
           "unsupported site counted per state visit: %r" % reason_counts)
    expect(s.unsupported_sites == {("m", 0x100C)},
           "unsupported_sites %r" % s.unsupported_sites)

    # ---- 3. cross-image BL provenance ---------------------------------
    a = FakeImage("a", 0x1000, [enc_bl(0x1000)])
    b = FakeImage("b", 0x2000, [RET])
    w = make_world([a, b])
    s = R.scan_world(w, [(0x1000, "dt_init")], subset_decoder=dec_ok)
    expect(s.insns["a"] == 1 and s.insns["b"] == 1,
           "cross-image BL did not reach b: %r" % s.insns)
    expect(s.entries.get(0x2000) == "bl",
           "cross-image BL entry kind %r" % s.entries.get(0x2000))
    pm, totals = R.summarize(s, w)
    expect(pm["b"]["entries"] == 1,
           "cross-image call entry not attributed to b: %r" % pm["b"])

    # ---- 4. fail-closed indirects -------------------------------------
    w = make_world([FakeImage("m", 0x1000, [BR_X0])])
    s = R.scan_world(w, [(0x1000, "dt_init")], subset_decoder=dec_ok)
    expect(s.ambiguous_by_kind["register-unknown"] == 1,
           "unknown br not fail-closed: %r" % s.ambiguous_by_kind)
    expect(set(s.entries) == {0x1000},
           "unknown br invented a target: %r" % sorted(s.entries))

    # negative control: the register is known but points outside every image
    w = make_world([FakeImage("m", 0x1000, [MOV_X0_0x40, BR_X0])])
    s = R.scan_world(w, [(0x1000, "dt_init")], subset_decoder=dec_ok)
    expect(s.ambiguous_by_kind["outside-image"] == 1,
           "out-of-image br not fail-closed: %r" % s.ambiguous_by_kind)
    expect(len(s.entries) == 1,
           "out-of-image br added a code entry: %r" % sorted(s.entries))

    # ---- 4b. 4-insn GOT stub pointing at DATA (uniform 5-tuples) ------
    # adrp x16,#0x1000; ldr w17,[x16,#16]; add x16,x16,#0; br x17
    # The loaded slot holds 0x40 (outside every image): the scanner must
    # record a uniform 5-tuple indirect, stay fail-closed, and summarize()
    # must not crash on it (_candidate_functions previously indexed rec[4]).
    GOT = [0x90000010, 0xB9401211, 0x91000210, 0xD61F0220, 0x40]
    w = make_world([FakeImage("m", 0x1000, GOT)])
    s = R.scan_world(w, [(0x1000, "dt_init")], subset_decoder=dec_ok)
    blk = s.blocks[0x1000]
    expect(len(blk.indirects) == 1 and len(blk.indirects[0]) == 5,
           "GOT stub indirect record is not a uniform 5-tuple: %r"
           % (blk.indirects,))
    expect(blk.indirects[0][3] == 0x40 and blk.indirects[0][4] ==
           "outside-image",
           "GOT stub data target not recorded as outside-image: %r"
           % (blk.indirects,))
    expect(s.ambiguous_by_kind["outside-image"] == 1,
           "GOT data target not ambiguous: %r" % s.ambiguous_by_kind)
    expect(len(s.entries) == 1,
           "GOT data target invented a code entry: %r"
           % sorted(hex(x) for x in s.entries))
    try:
        pm, _t = R.summarize(s, w)
        expect(pm["m"]["callable_complete"] == 0,
               "GOT data target reported callable-complete")
    except Exception as exc:
        fail("summarize() crashed on a 4-insn data GOT stub: %r" % (exc,))

    # ---- 5. data-in-code poisons its callers ---------------------------
    words = [enc_bl(8), RET, DATA_WORD]
    w = make_world([FakeImage("m", 0x1000, words)])
    s = R.scan_world(w, [(0x1000, "dt_init")], subset_decoder=dec_ok)
    expect(len(s.data_in_code) == 1 and s.data_in_code[0][2] == DATA_WORD,
           "data-in-code word not recorded: %r" % s.data_in_code)
    pm, _ = R.summarize(s, w)
    expect(pm["m"]["subset_complete"] == 0,
           "caller of data-in-code block reported subset-complete")
    expect(pm["m"]["blocked"] >= 1,
           "data-in-code block did not block any function")

    print("%d synthetic checks, %d failure(s)" %
          (17, len(FAILS)))
    return 0 if not FAILS else 2


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--tools", default="tools/aot")
    args = ap.parse_args(argv)
    try:
        import capstone
    except Exception as exc:                                # pragma: no cover
        print("infrastructure: capstone import failed: %s" % exc)
        return 1
    try:
        return run(args.tools, capstone)
    except Exception as exc:
        import traceback
        traceback.print_exc()
        print("infrastructure: %s" % exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
