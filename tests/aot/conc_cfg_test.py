#!/usr/bin/env python3
"""Independent Capstone CFG check for the concurrency fixture.

Structural only: it never trusts the translator's `meta` as the source of
truth.  It derives the block-start set from the declared manifest ranges with
an independent Capstone 5.0.7 walk (tools/aot/reference_cfg.py), then compares
that set with the translator's emitted metadata and with a few hand-checked
micro edges of the fixture (including the BLR chunk whose LR sentinel handling
must not self-loop and the LDXR/STXR retry loop).

It also fails closed if any declared range covers padding/gap bytes or extends
past the raw image, which is what makes "one range covers the whole .org span"
manifest mistakes visible.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile

import capstone
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64_const import ARM64_REG_X9

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.normpath(os.path.join(HERE, "..", "..", "tools", "aot"))
sys.path.insert(0, TOOLS)
import reference_cfg  # noqa: E402


def fail(msg):
    print("FAIL: conc_cfg: " + msg)
    return 1


# fixture micro-edges: pc -> (mnemonic, direct target or None, falls through)
EDGES = {
    0x1060: ("svc", None, True),
    0x1070: ("add", None, False),
    0x1074: ("blr", None, False),   # indirect: no immediate target
    0x1078: ("add", None, False),
    0x107C: ("ret", None, False),
    0x1100: ("ldxr", None, False),
    0x1108: ("stxr", None, False),
    0x110C: ("cbnz", 0x1100, True),
    0x1170: ("stlxr", None, False),
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--python", required=True)
    ap.add_argument("--translator", required=True)
    args = ap.parse_args()

    with open(args.bin, "rb") as f:
        raw = f.read()
    with open(args.manifest) as f:
        man = json.load(f)
    ranges = [tuple(r) for r in man["ranges"]]
    entries = list(man["entries"])
    indirect = list(man.get("indirect_targets", []))

    # 1. Ranges must be exact: no overlap, no gap bytes, no past-EOF padding.
    ordered = sorted(ranges)
    if ordered != ranges:
        return fail("ranges not sorted ascending")
    for i in range(1, len(ordered)):
        if ordered[i][0] < ordered[i - 1][1]:
            return fail("ranges overlap")
    covered = 0
    for s, e in ranges:
        if e > len(raw):
            return fail("range 0x%x..0x%x beyond raw size 0x%x"
                        % (s, e, len(raw)))
        if (s % 4) or (e % 4):
            return fail("range not 4-byte aligned")
        covered += e - s
    # Every declared byte must be a real instruction in the fixture, and the
    # declared ranges must not include alignment gaps between chunks.
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    total_ins = 0
    for s, e in ranges:
        words = list(md.disasm(raw[s:e], s))
        if not words:
            return fail("undecodable range 0x%x..0x%x" % (s, e))
        for ins in words:
            if ins.address < s or ins.address + ins.size > e:
                return fail("instruction straddles range end at 0x%x" % ins.address)
        total_ins += len(words)
    if total_ins * 4 != covered:
        return fail("ranges contain non-instruction/padding bytes")

    # 2. Independent CFG block starts.
    try:
        starts = set(reference_cfg.derive_starts(raw, ranges, entries, indirect))
    except ValueError as e:
        return fail("reference_cfg: %s" % e)
    if starts != set(entries):
        return fail("independent CFG starts %r != manifest entries %r"
                    % (sorted(hex(x) for x in starts - set(entries)),
                       sorted(hex(x) for x in set(entries) - starts)))

    # 3. Translator metadata must agree with the independent set.
    with tempfile.TemporaryDirectory() as td:
        out_c = os.path.join(td, "conc.c")
        meta_p = os.path.join(td, "conc.meta.json")
        r = subprocess.run([args.python, args.translator,
                            "--manifest", args.manifest, "--bin", args.bin,
                            "--out", out_c, "--name", "cfgdummy",
                            "--meta-out", meta_p],
                           capture_output=True, text=True)
        if r.returncode != 0:
            return fail("translator failed: %s%s" % (r.stdout, r.stderr))
        with open(meta_p) as f:
            meta = json.load(f)
    meta_pcs = set(int(b["pc"]) for b in meta["blocks"])
    if meta_pcs != starts:
        return fail("translator blocks differ from independent CFG; "
                    "capstone-only=%r meta-only=%r"
                    % (sorted(hex(x) for x in starts - meta_pcs),
                       sorted(hex(x) for x in meta_pcs - starts)))

    # 4. Micro edges, decoded independently.
    words = {}
    for s, e in ranges:
        for ins in md.disasm(raw[s:e], s):
            words[ins.address] = ins
    for pc, (mn, tgt, cont) in sorted(EDGES.items()):
        ins = words.get(pc)
        if ins is None:
            return fail("no instruction at 0x%x" % pc)
        if ins.mnemonic != mn:
            return fail("0x%x is %s, expected %s" % (pc, ins.mnemonic, mn))
        imm = None
        for op in ins.operands:
            if op.type == capstone.CS_OP_IMM:
                imm = op.imm
        if tgt is not None and imm != tgt:
            return fail("0x%x target %r, expected 0x%x" % (pc, imm, tgt))
        # Indirect/return forms carry NO immediate target (BLR goes through
        # x9, the manifest-declared host-thunk register; RET carries nothing).
        if mn in ("blr", "ret") and imm is not None:
            return fail("0x%x %s must not carry an immediate target" % (pc, mn))
        if cont and (pc + ins.size) not in starts:
            return fail("0x%x falls through to 0x%x which is not a block start"
                        % (pc, pc + ins.size))

    # The BLR chunk must publish through x9, the host-thunk register declared by
    # the manifest thunks block (base 8192 = 0x2000, one 16-byte thunk).
    th = man.get("thunks") or {}
    if int(th.get("base", 0)) != 8192 or int(th.get("count", 0)) != 1:
        return fail("unexpected thunks declaration %r" % (th,))
    bin_ins = words.get(0x1074)
    if (bin_ins is None or bin_ins.mnemonic != "blr" or not bin_ins.operands
            or bin_ins.operands[0].type != capstone.CS_OP_REG
            or bin_ins.operands[0].reg != ARM64_REG_X9):
        return fail("0x1074 is not 'blr x9' (host-thunk register)")

    print("PASS: conc_cfg (%d ranges, %d entries, %d instructions)"
          % (len(ranges), len(entries), total_ins))
    return 0


if __name__ == "__main__":
    sys.exit(main())
