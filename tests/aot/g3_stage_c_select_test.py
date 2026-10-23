#!/usr/bin/env python3
"""Hermetic synthetic tests for tools/aot/g3_stage_c_select.py (D024 Stage C).

Everything is generated in memory or in a fresh temp directory: no game data,
no title constants.  The scanner encodings were checked with
`llvm-mc -triple=aarch64 [-mattr=+lse] -show-encoding` (LLVM 18); the words
below are copied from that output (little-endian in the flat, shown as 32-bit
values here):

    bl #8        94000002     bl #-8        97fffffe     bl #-256     97ffffc0
    bl #256      94000040     udf #0        00000000
    blr x30      d63f03c0     br x17        d61f0220
    ldxr x0,[x1] c85f7c20     stlxr w2,w0,[x1] 8802fc20
    fadd d0,d1,d2 1e622820    ldr q0,[x1]   3dc00020
    add x0,x1,x2 8b020020     ldr x0,[x1]   f9400020
    ldadd x0,x1,[x2] (+lse) f8200041

Covered:
  * next_ctors order, the admitted cut (FIRST not-admitted slot; a duplicate or
    later admitted target never moves it), the no-admitted case;
  * no_fde targets go to no_fde_targets, never to windows;
  * BFS depth bound (a chain of six callees adds four levels), max_windows cap,
    and a max_windows smaller than the next constructors is refused;
  * stratum fill adds measurement windows from LATER slots, capped by
    extra_per_stratum; a stratum with no later window stays in missing_strata;
    local_switch is searched only when a caller hint exists;
  * authority none, no entries/roots keys, deterministic sorted windows;
  * scan_window BL forward/backward target math, BLR/BR, exclusives, FP/SIMD,
    plain integer ALU/load (no stratum), UDF -> unsupported, alignment refusal;
  * a NEGATIVE CONTROL: a selector that ignores `admitted` must FAIL the
    next_ctors check (the check must detect it, else the check is vacuous);
  * CLI round trip (manifest/flat SHA binding, JSON output, the source-tree
    refusal and the bad-SHA refusal).

Exit: 0 pass, 1 a check failed.
"""

import hashlib
import json
import os
import shutil
import struct
import sys
import tempfile

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO, "tools", "aot"))

import aot_translate as T          # noqa: E402
import g3_fde_frontend as F        # noqa: E402
import g3_stage_c_select as S      # noqa: E402

FAILS = []
OKS = [0]


def fail(msg):
    FAILS.append(msg)
    print("FAIL: " + msg)


def check(cond, msg):
    if cond:
        OKS[0] += 1
        return True
    fail(msg)
    return False


def W(k):
    """Synthetic window k: [0x1000*k, 0x1000*k + 0x100)."""
    return 0x1000 * k


def manifest_for(starts):
    return {
        "schema_version": F.SCHEMA_VERSION,
        "kind": F.KIND,
        "authority": F.AUTHORITY,
        "module": {"sha256": "00" * 32},
        "boundaries": [{"start": "0x%x" % s, "end": "0x%x" % (s + 0x100),
                        "provenance": ["fde"]} for s in starts],
    }


MANIFEST = manifest_for([W(k) for k in range(1, 41)])


def info(bl=(), strata=()):
    return {"bl_targets": list(bl), "strata": set(strata)}


def table(overrides=None):
    out = dict((W(k), info()) for k in range(1, 41))
    out.update(overrides or {})
    return out


def starts_of(selection):
    return [w["start"] for w in selection["windows"]]


def walk_keys(obj, out):
    if isinstance(obj, dict):
        for key, value in obj.items():
            out.add(key)
            walk_keys(value, out)
    elif isinstance(obj, list):
        for value in obj:
            walk_keys(value, out)
    return out


def next_ok(selection, expected):
    return selection["next_ctors"] == expected


# ------------------------------------------------------------- selector cases

def cases_next_ctors():
    # Admitted cut: an admitted prefix, duplicates after it.  Expected next
    # ctors are [W4,W5,W6] from slot indices 4, 6, 7.
    slots = [W(1), W(2), W(2), W(3), W(4), W(4), W(5), W(6), W(7), W(8)]
    sel = S.select_catalog_windows(MANIFEST, slots, [W(1), W(2), W(3)],
                                   table(), n=3, depth=0, extra_per_stratum=0)
    check(next_ok(sel, [W(4), W(5), W(6)]),
          "next_ctors follow the admitted cut in array order: %r"
          % sel["next_ctors"])
    check([w["ctor_slot"] for w in sel["windows"]] == [4, 6, 7],
          "next-ctor ctor_slot is the first slot index after the cut: %r"
          % [w["ctor_slot"] for w in sel["windows"]])
    check(all(w["purpose"] == "next-ctor" for w in sel["windows"]),
          "every window in that run is a next-ctor window")

    # A target admitted out of order (W3, e.g. by an STT_FUNC follow) must not
    # move the cut: the loop still has to reach W1 and W2 first.
    sel1 = S.select_catalog_windows(MANIFEST, slots, [W(3)], table(), n=3,
                                    depth=0, extra_per_stratum=0)
    check(next_ok(sel1, [W(1), W(2), W(4)]),
          "an out-of-order admitted target does not skip earlier slots: %r"
          % sel1["next_ctors"])

    # A duplicate of an admitted target later in the array: the cut is at the
    # FIRST not-admitted slot, so W2 is kept (a last-admitted-slot cut would
    # skip it and give only [W4]).
    slots2 = [W(1), W(3), W(2), W(3), W(4)]
    sel2 = S.select_catalog_windows(MANIFEST, slots2, [W(1), W(3)], table(),
                                    n=3, depth=0, extra_per_stratum=0)
    check(next_ok(sel2, [W(2), W(4)]),
          "a later duplicate of an admitted target does not move the cut: %r"
          % sel2["next_ctors"])

    # No admitted root: from the beginning, duplicates collapsed.
    sel3 = S.select_catalog_windows(MANIFEST, slots, [], table(), n=3,
                                    depth=0, extra_per_stratum=0)
    check(next_ok(sel3, [W(1), W(2), W(3)]),
          "without admitted roots next ctors start at the array head: %r"
          % sel3["next_ctors"])


def cases_no_fde():
    stray = 0x500                       # not an FDE start
    slots = [W(1), stray, W(2)]
    sel = S.select_catalog_windows(MANIFEST, slots, [], table(), n=3, depth=0,
                                   extra_per_stratum=0)
    check(sel["no_fde_targets"] == [stray],
          "a non-FDE constructor is reported in no_fde_targets: %r"
          % sel["no_fde_targets"])
    check(stray not in starts_of(sel) and next_ok(sel, [W(1), stray, W(2)]),
          "a non-FDE constructor never becomes a window")
    check("no_fde" not in sel["missing_strata"],
          "the no_fde stratum is covered by a non-FDE next ctor")


def chain_table():
    # W10 -> W11 -> ... -> W16: six callees below the next constructor W10.
    over = {}
    for k in range(10, 16):
        over[W(k)] = info(bl=[W(k + 1)])
    return table(over)


def cases_bfs_and_cap():
    tab = chain_table()
    sel = S.select_catalog_windows(MANIFEST, [W(10)], [], tab, n=1, depth=4,
                                   extra_per_stratum=0)
    check(starts_of(sel) == [W(k) for k in range(10, 15)],
          "BFS depth 4 adds exactly four callee levels (W11..W14): %r"
          % [hex(s) for s in starts_of(sel)])
    check(sorted(w["purpose"] for w in sel["windows"]) ==
          ["callee"] * 4 + ["next-ctor"],
          "BFS windows carry the callee purpose, the ctor keeps next-ctor")

    deep = S.select_catalog_windows(MANIFEST, [W(10)], [], tab, n=1, depth=6,
                                    extra_per_stratum=0)
    check(len(deep["windows"]) == 7,
          "uncapped depth 6 reaches all six callees (7 windows), got %d"
          % len(deep["windows"]))

    capped = S.select_catalog_windows(MANIFEST, [W(10)], [], tab, n=1, depth=6,
                                      max_windows=3, extra_per_stratum=0)
    check(starts_of(capped) == [W(10), W(11), W(12)],
          "max_windows=3 caps the BFS in insertion order: %r"
          % [hex(s) for s in starts_of(capped)])

    refused = False
    try:
        S.select_catalog_windows(MANIFEST, [W(1), W(2), W(3)], [], table(),
                                 n=3, max_windows=2)
    except ValueError:
        refused = True
    check(refused, "max_windows smaller than the next constructors is refused")


def cases_fill():
    overrides = {
        W(1): info(strata=["bl"]),
        W(2): info(strata=["bl"]),
        W(5): info(strata=["fp_simd"]),
        W(6): info(strata=["fp_simd"]),
        W(7): info(strata=["fp_simd"]),
        W(8): info(strata=["fp_simd"]),
        W(9): info(strata=["indirect"]),
    }
    slots = [W(k) for k in range(1, 10)]
    sel = S.select_catalog_windows(MANIFEST, slots, [], table(overrides), n=2,
                                   depth=4, extra_per_stratum=2)
    meas = [w for w in sel["windows"] if w["purpose"] == "measurement"]
    check(next_ok(sel, [W(1), W(2)]), "fill test: next ctors are W1,W2")
    check([w["start"] for w in meas if "fp_simd" in w["strata"]] == [W(5), W(6)],
          "fp_simd fill takes the first two later windows (cap 2): %r"
          % [hex(w["start"]) for w in meas])
    check(W(9) in [w["start"] for w in meas] and
          [w["ctor_slot"] for w in meas if w["start"] == W(9)] == [8],
          "indirect fill adds the later window W9 from its slot index 8")
    check(sorted(w["start"] for w in sel["windows"]) == starts_of(sel),
          "windows are sorted by start with no duplicates")
    check(len(set(starts_of(sel))) == len(starts_of(sel)),
          "no duplicate window starts")
    check(sel["missing_strata"] == ["exclusive", "local_switch", "no_fde",
                                    "unsupported"],
          "strata with no later window are reported missing (local_switch "
          "unknown, no hint): %r" % sel["missing_strata"])
    check(S.select_arg(sel) == "0x1000,0x2000,0x5000,0x6000,0x9000",
          "select_arg is the comma-separated hex starts: %r"
          % S.select_arg(sel))

    # A caller hint makes local_switch searchable: W7 carries it.
    hinted = dict(overrides)
    hinted[W(7)] = info(strata=["fp_simd", "local_switch"])
    sel2 = S.select_catalog_windows(MANIFEST, slots, [], table(hinted), n=2,
                                    depth=4, extra_per_stratum=2)
    check("local_switch" not in sel2["missing_strata"] and
          any(w["start"] == W(7) and w["purpose"] == "measurement"
              for w in sel2["windows"]),
          "a caller local_switch hint is searched and filled from later slots")

    # Pure-function check: the input table is not mutated by the selection.
    before = table(overrides)
    S.select_catalog_windows(MANIFEST, slots, [], before, n=2, depth=4,
                             extra_per_stratum=2)
    check(before == table(overrides), "the selector does not mutate window_info")


def cases_authority_and_keys():
    sel = S.select_catalog_windows(MANIFEST, [W(1), 0x500], [], table(), n=2,
                                   depth=4, extra_per_stratum=1)
    keys = walk_keys(sel, set())
    check(sel["authority"] == "none" and sel["kind"] == "catalog-selection",
          "the selection is authority none, kind catalog-selection")
    check("entries" not in keys and "roots" not in keys,
          "the selection has no entries/roots key anywhere: %r"
          % sorted(keys))
    check(sel["schema_version"] == 1, "schema_version is 1")


def cases_negative_control():
    """The next_ctors check must FAIL for a selector that ignores `admitted`."""
    slots = [W(1), W(2), W(2), W(3), W(4), W(4), W(5), W(6), W(7), W(8)]
    expected = [W(4), W(5), W(6)]
    original = S._pick_next

    def ignores_admitted(slots_, admitted_, n_):
        return original(slots_, set(), n_)

    S._pick_next = ignores_admitted
    try:
        mutant = S.select_catalog_windows(MANIFEST, slots,
                                          [W(1), W(2), W(3)], table(),
                                          n=3, depth=0, extra_per_stratum=0)
    finally:
        S._pick_next = original
    detected = not next_ok(mutant, expected)
    check(detected, "NEGATIVE CONTROL: the ignores-admitted selector was NOT "
                    "detected by the next_ctors check (got %r)"
          % mutant["next_ctors"])
    check(next_ok(S.select_catalog_windows(MANIFEST, slots,
                                           [W(1), W(2), W(3)], table(),
                                           n=3, depth=0, extra_per_stratum=0),
                  expected),
          "the restored selector passes the same next_ctors check")

    # A last-admitted-slot cut (the reviewed bug) skips W2 when a duplicate of
    # an admitted target follows it; the duplicate case must catch it.
    original_cut = S._cut_index

    def last_admitted_cut(slots_, admitted_):
        cut = 0
        for index, target in enumerate(slots_):
            if target in admitted_:
                cut = index + 1
        return cut

    S._cut_index = last_admitted_cut
    try:
        mutant2 = S.select_catalog_windows(
            MANIFEST, [W(1), W(3), W(2), W(3), W(4)], [W(1), W(3)], table(),
            n=3, depth=0, extra_per_stratum=0)
    finally:
        S._cut_index = original_cut
    check(not next_ok(mutant2, [W(2), W(4)]),
          "NEGATIVE CONTROL: a last-admitted-slot cut was NOT detected (got %r)"
          % mutant2["next_ctors"])


# ------------------------------------------------------------------- scanner

def word_at(flat, off, word):
    flat[off:off + 4] = struct.pack("<I", word)


def cases_scan():
    flat = bytearray(0x400)
    rows = [
        # (name, offset, word, expected bl_targets, expected strata)
        ("bl forward #8", 0x100, 0x94000002, [0x108], {"bl"}),
        ("bl backward #-256", 0x300, 0x97FFFFC0, [0x200], {"bl"}),
        ("bl backward #-8", 0x200, 0x97FFFFFE, [0x1F8], {"bl"}),
        ("bl forward #256", 0x100, 0x94000040, [0x200], {"bl"}),
        ("blr x30", 0x000, 0xD63F03C0, [], {"indirect"}),
        ("br x17", 0x010, 0xD61F0220, [], {"indirect"}),
        ("ldxr x0,[x1]", 0x020, 0xC85F7C20, [], {"exclusive"}),
        ("stlxr w2,w0,[x1]", 0x030, 0x8802FC20, [], {"exclusive"}),
        ("fadd d0,d1,d2", 0x040, 0x1E622820, [], {"fp_simd"}),
        ("ldr q0,[x1] (SIMD&FP ls)", 0x050, 0x3DC00020, [], {"fp_simd"}),
        ("add x0,x1,x2 (negative)", 0x060, 0x8B020020, [], set()),
        ("ldr x0,[x1] (negative)", 0x070, 0xF9400020, [], set()),
        ("udf #0 refused by decode", 0x080, 0x00000000, [], {"unsupported"}),
        ("ldadd (LSE, decode refuses)", 0x090, 0xF8200041, [],
         {"exclusive", "unsupported"}),
    ]
    for name, off, word, targets, strata in rows:
        word_at(flat, off, word)
        got = S.scan_window(bytes(flat), off, off + 4, guest_base=0x100000000)
        check(got["bl_targets"] == targets and got["strata"] == strata,
              "scan %s: got %r %r, want %r %r"
              % (name, got["bl_targets"], sorted(got["strata"]), targets,
                 sorted(strata)))

    # Decoder agreement for the two refusal rows (the test's oracle).
    refused = False
    try:
        T.decode(0x100000080, 0x00000000, module=True)
    except T.DecodeError:
        refused = True
    check(refused, "T.decode refuses UDF #0 (the unsupported oracle)")

    # A backward BL from pc 0 has no image-offset target: kept out of the
    # targets, the bl stratum is still recorded.
    flat2 = bytearray(0x100)
    word_at(flat2, 0, 0x97FFFFFE)
    got = S.scan_window(bytes(flat2), 0, 4)
    check(got["bl_targets"] == [] and got["strata"] == {"bl"},
          "a BL that lands before the image is not a target: %r" % got)

    # Mixed window: strata accumulate and BL targets are sorted, unique.
    mixed = bytearray(0x100)
    word_at(mixed, 0x00, 0x94000010)     # bl -> 0x40
    word_at(mixed, 0x04, 0x94000004)     # bl -> 0x14
    word_at(mixed, 0x08, 0x9400000E)     # bl -> 0x40 again (imm 14 words)
    word_at(mixed, 0x0C, 0xD63F0000)     # blr x0
    got = S.scan_window(bytes(mixed), 0, 0x10)
    check(got["bl_targets"] == [0x14, 0x40] and
          got["strata"] == {"bl", "indirect"},
          "targets are sorted and unique across a window: %r" % got)

    refused_align = False
    try:
        S.scan_window(bytes(flat), 0x2, 0x10)
    except ValueError:
        refused_align = True
    check(refused_align, "a misaligned window is refused")
    refused_end = False
    try:
        S.scan_window(bytes(flat), 0x3F0, 0x800)
    except ValueError:
        refused_end = True
    check(refused_end, "a window past the flat is refused")


# ----------------------------------------------------------------------- CLI

def cases_cli():
    work = tempfile.mkdtemp(prefix="g3_stage_c_select_")
    try:
        flat = bytearray(0x400)
        word_at(flat, 0x100, 0x94000040)    # bl -> 0x200
        flat = bytes(flat)
        sha = hashlib.sha256(flat).hexdigest()
        manifest = manifest_for([0x100, 0x200])
        manifest["module"]["sha256"] = sha
        man_path = os.path.join(work, "manifest.json")
        flat_path = os.path.join(work, "module.flat")
        out_path = os.path.join(work, "selection.json")
        with open(man_path, "w", encoding="utf-8") as handle:
            json.dump(manifest, handle)
        with open(flat_path, "wb") as handle:
            handle.write(flat)
        argv = ["--manifest", man_path, "--slots", '["0x100","0x200"]',
                "--flat", flat_path, "--guest-base", "0x100000000",
                "--n", "1", "--out", out_path]
        rc = S.main(argv)
        check(rc == 0, "CLI round trip returns 0 (got %d)" % rc)
        if rc == 0:
            with open(out_path, "r", encoding="utf-8") as handle:
                sel = json.load(handle)
            check(starts_of(sel) == [0x100, 0x200] and
                  sel["next_ctors"] == [0x100] and
                  S.select_arg(sel) == "0x100,0x200",
                  "CLI selection: callee 0x200 reached by BL from next ctor "
                  "0x100 (%r)" % starts_of(sel))

        bad = dict(manifest)
        bad["module"] = {"sha256": "11" * 32}
        bad_path = os.path.join(work, "bad.json")
        with open(bad_path, "w", encoding="utf-8") as handle:
            json.dump(bad, handle)
        rc_bad = S.main(["--manifest", bad_path, "--slots", '["0x100"]',
                         "--flat", flat_path, "--guest-base", "0x100000000",
                         "--out", os.path.join(work, "x.json")])
        check(rc_bad == 1 and not os.path.exists(os.path.join(work, "x.json")),
              "a manifest whose SHA does not match the flat is refused (%r)"
              % rc_bad)

        in_tree = os.path.join(REPO, "tests", "aot", "g3_stage_c_select_NOWRITE.json")
        refused = False
        try:
            S.main(["--manifest", man_path, "--slots", '["0x100"]',
                    "--flat", flat_path, "--guest-base", "0x100000000",
                    "--out", in_tree])
        except SystemExit as exc:
            refused = exc.code == 2
        check(refused and not os.path.exists(in_tree),
              "an --out inside the source tree is refused (exit 2)")
        check(not F.inside_tree(out_path, REPO),
              "the temp output directory is outside the source tree")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main(argv=None):
    cases_next_ctors()
    cases_no_fde()
    cases_bfs_and_cap()
    cases_fill()
    cases_authority_and_keys()
    cases_negative_control()
    cases_scan()
    cases_cli()
    if FAILS:
        print("FAIL: %d g3_stage_c_select check(s)" % len(FAILS))
        return 1
    print("PASS: g3_stage_c_select (%d checks)" % OKS[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
