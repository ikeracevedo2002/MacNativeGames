#!/usr/bin/env python3
"""Decoder + CFG structural tests (independent of the differential oracle).

These are STRUCTURAL checks of the offline translator's decode masks, manifest
validation and CFG block set.  They are not new ARM coverage.  The CFG block
set is derived INDEPENDENTLY with Capstone 5.0.7 from the declared manifest
ranges; the CFG oracle itself does NOT use translator semantics (the decoder
unit section does call `aot_translate.decode` to test its masks).
"""
import argparse
import importlib.util
import json
import os
import subprocess
import sys
import tempfile

import capstone
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.normpath(os.path.join(HERE, "..", "..", "tools", "aot"))
sys.path.insert(0, TOOLS)
import reference_cfg  # noqa: E402  (independent Capstone CFG)


def load_ast():
    spec = importlib.util.spec_from_file_location(
        "ast_translate", os.path.join(TOOLS, "aot_translate.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def expect_decode_error(a, word, label):
    try:
        a.decode(0x1000, word)
    except a.DecodeError:
        return True
    print("FAIL: expected DecodeError for %s (0x%08x)" % (label, word))
    return False


def expect_decode_ok(a, word, kind, label):
    try:
        ins = a.decode(0x1000, word)
    except a.DecodeError as e:
        print("FAIL: unexpected DecodeError for %s (0x%08x): %s" % (label, word, e))
        return False
    if ins["kind"] != kind:
        print("FAIL: %s decoded as %s, expected %s" % (label, ins["kind"], kind))
        return False
    return True


def decoder_tests(a):
    global_fail = 0
    cases = [
        (0x2B6FABFF, "reserved pair word 0x2b6fabff"),
        (0xD61F0010, "BR reserved bits"),
        (0xC85F7C00, "LDXR/atomic (unsupported)"),
        (0x1E602820, "unsupported numeric FP (FADD D)"),
        (0x0B008020, "32-bit addsub overshift imm6=32"),
        (0xA9BF0400, "pair writeback base overlaps transferred reg"),
        (0x1E204020, "unsupported FP scalar S (FMOV S)"),
    ]
    for word, label in cases:
        if not expect_decode_error(a, word, label):
            global_fail = 1
    ok = [
        (0x1E604020, "fmov_d", "FMOV D0,D1"),
        (0x1E60C020, "fabs_d", "FABS D0,D1"),
        (0x1E614020, "fneg_d", "FNEG D0,D1"),
        (0x4E221C20, "vand", "AND V0.16B,V1.16B,V2.16B"),
        (0x4EA21C20, "vorr", "ORR V0.16B"),
        (0x6E221C20, "veor", "EOR V0.16B"),
        (0x4E228420, "vadd", "ADD V0.16B"),
        (0x6E228420, "vsub", "SUB V0.16B"),
    ]
    for word, kind, label in ok:
        if not expect_decode_ok(a, word, kind, label):
            global_fail = 1
    return global_fail


def load_driver():
    spec = importlib.util.spec_from_file_location(
        "dd_cmp", os.path.join(TOOLS, "diff_driver.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def comparator_fault_unit():
    """A wrong-cause oracle fault must be rejected (separate from the 8
    codegen mutants)."""
    dd = load_driver()
    rerr = getattr(dd, "UC_ERR_READ_UNMAPPED", 8)
    case = {"expected_fault": True, "fault_addr": 0x2000,
            "fault_src": 0x14E0, "fault_size": 8}
    nat = {"exit": 11, "fault": 3, "fault_target": 0x2000, "fault_src": 0x14E0}

    def orc(errno, addr, size, pc):
        return {"fault": {"code": "x", "errno": errno,
                          "memi": {"addr": addr, "size": size, "pc": pc}}}

    fails = 0
    if dd.cmp_case(case, nat, orc(rerr, 0x2000, 8, 0x14E0))[0]:
        print("FAIL: comparator rejected a correct memory fault")
        fails = 1
    bad = [("errno", orc(rerr + 1, 0x2000, 8, 0x14E0)),
           ("addr", orc(rerr, 0x3000, 8, 0x14E0)),
           ("size", orc(rerr, 0x2000, 4, 0x14E0)),
           ("pc", orc(rerr, 0x2000, 8, 0x14E4)),
           ("none", {"fault": {"code": 0}})]
    for label, o in bad:
        if not dd.cmp_case(case, nat, o)[0]:
            print("FAIL: comparator accepted wrong-cause fault (%s)" % label)
            fails = 1
    return fails


def reference_strict_unit(raw, ranges):
    """derive_starts must fail closed on malformed/overlapping declarations."""
    fails = 0
    negatives = [
        (((-4, 16),), [0], [], "negative range"),
        ([(16, 16)], [0], [], "zero-length range"),
        ([(0, 16), (8, 24)], [0], [], "overlapping ranges"),
        ([(0, 16)], [32], [], "entry outside"),
    ]
    for ranges_, entries_, indirect_, label in negatives:
        try:
            reference_cfg.derive_starts(raw, ranges_, entries_, indirect_)
        except ValueError:
            continue
        print("FAIL: derive_starts accepted %s" % label)
        fails = 1
    return fails


def manifest_tests(a):
    # Valid RET fill so a structural failure cannot be attributed to an
    # undecodable instruction if the validation order ever changes.
    raw = (0xD65F03C0).to_bytes(4, "little") * 16
    fails = 0

    def expect_cfg_error(ranges, entries, indirect, label):
        try:
            a.build_cfg(raw, ranges, entries, indirect)
        except a.DecodeError:
            return True
        print("FAIL: expected CFG DecodeError for %s" % label)
        return False

    checks = [
        ([(4, 4)], [0], [], "range start>=end"),
        ([(2, 8)], [0], [], "range misaligned"),
        ([(0, 128)], [0], [], "range end beyond file"),
        ([(0, 16), (8, 24)], [0], [], "ranges overlap/unsorted"),
        ([(0, 16)], [32], [], "entry outside ranges"),
        ([(0, 16)], [2], [], "entry misaligned"),
    ]
    for ranges, entries, indirect, label in checks:
        if not expect_cfg_error(ranges, entries, indirect, label):
            fails = 1

    def expect_thunk_error(thunks, ranges, label):
        try:
            a.validate_thunks(thunks, ranges)
        except a.DecodeError:
            return True
        print("FAIL: expected thunk DecodeError for %s" % label)
        return False

    tchecks = [
        ((0x2000, 1, 8), [(0, 16)], "thunk stride != 16"),
        ((0x2000, 0x100000000, 16), [(0, 16)], "thunk count > UINT32_MAX"),
        ((0, 1, 16), [(0, 16)], "thunk base zero"),
        ((0xFFFFFFFFFFFFFFF0, 4, 16), [(0, 16)], "thunk span overflow"),
        ((0x4, 1, 16), [(0, 16)], "code/thunk overlap"),
    ]
    for thunks, ranges, label in tchecks:
        if not expect_thunk_error(thunks, ranges, label):
            fails = 1
    # valid thunk shape accepted
    a.validate_thunks((0x2000, 1, 16), [(0, 16)])
    return fails


def capstone_starts(raw, ranges, entries, indirect):
    return reference_cfg.derive_starts(raw, ranges, entries, indirect)


def decode_completeness(raw, ranges):
    """Every 4-byte slot of every declared range must decode; Capstone must
    not silently stop mid-range."""
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    for s, e in ranges:
        seen = 0
        for ins in md.disasm(raw[s:e], s):
            seen += 1
        want = (e - s) // 4
        if seen != want:
            print("FAIL: Capstone decoded %d/%d words in range 0x%x-0x%x"
                  % (seen, want, s, e))
            return 1
    return 0


def cfg_test(raw, meta, ranges, entries, indirect, expected_edges):
    starts = capstone_starts(raw, ranges, entries, indirect)
    meta_pcs = set(b["pc"] for b in meta["blocks"])
    if starts != meta_pcs:
        only_cs = sorted(starts - meta_pcs)
        only_meta = sorted(meta_pcs - starts)
        print("FAIL: independent CFG block set differs; capstone-only=%r meta-only=%r"
              % ([hex(x) for x in only_cs], [hex(x) for x in only_meta]))
        return 1
    # independent disassembly of the explicitly required micro edges
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    words = {}
    for s, e in ranges:
        for ins in md.disasm(raw[s:e], s):
            words[ins.address] = ins
    for site, want in expected_edges.items():
        ins = words.get(site)
        if ins is None:
            print("FAIL: no instruction at 0x%x" % site)
            return 1
        tgt = None
        for op in ins.operands:
            if op.type == capstone.CS_OP_IMM:
                tgt = op.imm
        if want["mnemonic"] != ins.mnemonic:
            print("FAIL: 0x%x is '%s', expected '%s'" % (site, ins.mnemonic, want["mnemonic"]))
            return 1
        if want.get("target") is not None and tgt != want["target"]:
            print("FAIL: 0x%x target 0x%x != 0x%x" % (site, tgt, want["target"]))
            return 1
        if want.get("cont") is not None and (site + 4) not in meta_pcs:
            print("FAIL: 0x%x continuation 0x%x missing" % (site, site + 4))
            return 1
        if want.get("target") is not None and want["target"] not in meta_pcs:
            print("FAIL: 0x%x target 0x%x missing" % (site, want["target"]))
            return 1
    return 0


def sha_identity_test(a, bin_path, manifest_path):
    """Normal vs mutant native image fingerprints must differ (SHA includes the
    canonical config identity, not just the sidecar mutant field)."""
    fails = 0
    with tempfile.TemporaryDirectory() as td:
        shas = {}
        for mode in (None, "wrongcarry"):
            cmd = [sys.executable, os.path.join(TOOLS, "aot_translate.py"),
                   "--manifest", manifest_path, "--bin", bin_path,
                   "--out", os.path.join(td, "m_%s.c" % (mode or "none")),
                   "--meta-out", os.path.join(td, "m_%s.json" % (mode or "none")),
                   "--name", "diff"]
            if mode:
                cmd += ["--mutant", mode]
            r = subprocess.run(cmd, capture_output=True)
            if r.returncode != 0:
                print("FAIL: translator failed for mode=%s: %s" % (mode, r.stderr.decode()))
                return 1
            with open(os.path.join(td, "m_%s.json" % (mode or "none"))) as f:
                shas[mode or "none"] = json.load(f)["sha256"]
        if shas["none"] == shas["wrongcarry"]:
            print("FAIL: normal and mutant image SHA256 are identical")
            fails = 1
    return fails


def translator_failclosed_unit(a, bin_path, manifest_path):
    """A malformed thunk field must produce a named FAIL-CLOSED error, not a
    traceback."""
    with open(manifest_path) as f:
        man = json.load(f)
    man["thunks"] = {"base": 0x2000, "count": "not-a-number", "stride": 16}
    fails = 0
    with tempfile.TemporaryDirectory() as td:
        mpath = os.path.join(td, "bad.manifest.json")
        with open(mpath, "w") as f:
            json.dump(man, f)
        r = subprocess.run(
            [sys.executable, os.path.join(TOOLS, "aot_translate.py"),
             "--manifest", mpath, "--bin", bin_path,
             "--out", os.path.join(td, "o.c"),
             "--meta-out", os.path.join(td, "o.json"), "--name", "d"],
            capture_output=True)
        err = r.stderr.decode()
        if r.returncode == 0 or "FAIL-CLOSED: malformed manifest" not in err:
            print("FAIL: malformed thunk not named FAIL-CLOSED: rc=%d err=%s"
                  % (r.returncode, err.strip()[:200]))
            fails = 1
    return fails


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True)
    ap.add_argument("--meta", required=True)
    ap.add_argument("--manifest", required=True)
    args = ap.parse_args()

    with open(args.bin, "rb") as f:
        raw = f.read()
    with open(args.meta) as f:
        meta = json.load(f)
    with open(args.manifest) as f:
        man = json.load(f)
    ranges = [tuple(r) for r in man["ranges"]]
    entries = list(man["entries"])
    indirect = list(man.get("indirect_targets", []))

    a = load_ast()
    fails = decoder_tests(a) + manifest_tests(a)
    fails += comparator_fault_unit()
    fails += reference_strict_unit(raw, ranges)
    fails += decode_completeness(raw, ranges)
    fails += cfg_test(raw, meta, ranges, entries, indirect, {
        0x1604: {"mnemonic": "bl", "target": 0x1700, "cont": True},
        0x16C0: {"mnemonic": "svc", "cont": True},
        0x1200: {"mnemonic": "b.eq", "target": None, "cont": True},
    })
    fails += sha_identity_test(a, args.bin, args.manifest)
    fails += translator_failclosed_unit(a, args.bin, args.manifest)

    if fails:
        print("FAIL: aot_decoder_cfg")
        return 1
    print("PASS: aot_decoder_cfg")
    return 0


if __name__ == "__main__":
    sys.exit(main())
