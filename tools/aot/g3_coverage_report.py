#!/usr/bin/env python3
"""G3 increment 4, work item E (REPORT ONLY): how much of the real modules'
text does the current module-mode decoder accept?

Two measurements, both over the flats produced by `aot_module.py nso2flat`
(they live OUTSIDE the repository; this script contains no game data):

  (a) LINEAR SWEEP of every 4-byte word of the text segment through
      `aot_translate.decode(pc, word, module=True)`. This is a lower bound on
      translatability: text also holds non-code (the crt0 MOD0 offset, the MOD0
      struct, literal pools), so rejected words are grouped by the Capstone
      mnemonic of the word to show WHAT is rejected, and words Capstone cannot
      disassemble at all are reported separately as "data in text".

  (b) PER-FUNCTION: for every DEFINED STT_FUNC dynsym symbol whose value lands
      in the text segment, walk the reachable CFG exactly the way
      `aot_translate.build_cfg(..., module=True)` does (fallthrough, direct
      branch/call targets inside the shipped ranges, stop at `ret`/`br`) and
      report whether the whole reachable function decodes. The first word that
      blocks a function is grouped by its Capstone mnemonic too.

Usage:
  g3_coverage_report.py --v0-dir <dir> [--out <markdown>] [--json <json>]

  <dir> must hold flat/<name>.flat + flat/<name>.layout.json for
  main, subsdk0, sdk (the nso2flat outputs). Nothing is written inside the
  repository unless --out points there (it must not).

Exit status is 0 in all cases: this is a REPORT, not a gate.
"""

import argparse
import collections
import json
import os
import struct
import sys

import capstone

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import aot_module as M          # noqa: E402  (local, same directory)
import aot_translate as T       # noqa: E402

MODULES = ("main", "subsdk0", "sdk")
TOP_REJECTED = 40
TOP_BLOCKING = 10

_MD = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
_MD.detail = False


def capstone_mnemonic(pc, word):
    """Mnemonic Capstone gives this word, or None when it cannot decode it."""
    for ins in _MD.disasm(struct.pack("<I", word), pc):
        return ins.mnemonic
    return None


def text_ranges(layout):
    off, size = layout["text"]
    return [(off, off + size)]


def load(name, v0_dir):
    flat_path = os.path.join(v0_dir, "flat", name + ".flat")
    layout_path = os.path.join(v0_dir, "flat", name + ".layout.json")
    # guest_base 0: PCs are image offsets, which is what decode() needs for the
    # PC-relative forms (ADRP/ADR) - only the DELTA matters here.
    return M.load_module(flat_path, layout_path, name, 0)


def sweep(mod, mnem_cache):
    """(a) every text word through decode(module=True)."""
    flat = mod["flat"]
    ranges = text_ranges(mod["layout"])
    accepted = 0
    rejected = 0
    invalid_words = 0            # Capstone cannot disassemble them at all
    by_mnemonic = collections.Counter()
    examples = {}

    for start, end in ranges:
        for pc in range(start, end, 4):
            word = struct.unpack_from("<I", flat, pc)[0]
            try:
                T.decode(pc, word, module=True)
                accepted += 1
                continue
            except T.DecodeError:
                rejected += 1
            key = (pc, word)
            mnem = mnem_cache.get(word)
            if mnem is None:
                mnem = capstone_mnemonic(pc, word)
                mnem_cache[word] = mnem
            if mnem is None:
                invalid_words += 1
                by_mnemonic["<capstone-invalid>"] += 1
            else:
                by_mnemonic[mnem] += 1
                examples.setdefault(mnem, (pc, word))
    return dict(accepted=accepted, rejected=rejected,
                invalid_words=invalid_words, by_mnemonic=by_mnemonic,
                examples=examples, words=accepted + rejected)


def walk_function(flat, ranges, entry, limit=200000):
    """Reachable-CFG walk with aot_translate's own decode/successors rules.

    Returns (ok, reason, pc, word). Mirrors build_cfg(module=True): decode the
    block, follow the successors of the terminator that stay inside `ranges`,
    stop at a terminator with no successor (`ret`, indirect `br`).
    """
    seen = set()
    work = [entry]

    while work:
        pc = work.pop()
        if pc in seen:
            continue
        cur = pc
        while True:
            if cur in seen:
                break
            if not T.in_ranges(ranges, cur):
                return (False, "leaves-declared-ranges", cur, None)
            if cur % 4 != 0:
                return (False, "misaligned", cur, None)
            word = struct.unpack_from("<I", flat, cur)[0]
            try:
                ins = T.decode(cur, word, module=True)
            except T.DecodeError as exc:
                return (False, "decode: %s" % exc, cur, word)
            ins["word"] = word
            seen.add(cur)
            if len(seen) > limit:
                return (False, "size-limit", cur, word)
            if ins["kind"] in T.TERMINATORS:
                for target in T.successors(ins):
                    if not T.in_ranges(ranges, target) or target % 4 != 0:
                        return (False, "branch-out-of-range", target, None)
                    if target not in seen:
                        work.append(target)
                break
            cur += 4
    return (True, None, None, None)


def functions(mod, mnem_cache):
    """(b) is each defined STT_FUNC symbol's reachable CFG fully decodable?"""
    flat = mod["flat"]
    ranges = text_ranges(mod["layout"])
    image_size = mod["image_size"]
    full = 0
    blocked = 0
    blocking = collections.Counter()
    examples = {}
    in_text = 0
    aligned = 0

    for sym in mod["syms"]:
        if sym["type"] != M.STT_FUNC or not sym["name"]:
            continue
        if not M.sym_defined(sym, image_size):
            continue
        value = sym["value"]
        if not any(s <= value < e for s, e in ranges):
            continue
        in_text += 1
        if value % 4 != 0:
            blocked += 1
            blocking["<misaligned-entry>"] += 1
            continue
        aligned += 1
        ok, reason, pc, word = walk_function(flat, ranges, value)
        if ok:
            full += 1
            continue
        blocked += 1
        if word is not None:
            if word not in mnem_cache:
                mnem_cache[word] = capstone_mnemonic(pc, word)
            mnem = mnem_cache[word] or "<capstone-invalid>"
            examples.setdefault(mnem, (sym["name"], pc, word, reason))
        else:
            mnem = "<%s>" % reason.split(":")[0]
        blocking[mnem] += 1
    return dict(functions_in_text=in_text, aligned=aligned, full=full,
                blocked=blocked, blocking=blocking, examples=examples)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--v0-dir", required=True,
                    help="dir holding flat/<name>.flat + .layout.json")
    ap.add_argument("--out", default=None, help="markdown output path")
    ap.add_argument("--json", default=None, help="optional JSON summary path")
    args = ap.parse_args(argv)

    mnem_cache = {}
    per_module = {}
    for name in MODULES:
        mod = load(name, args.v0_dir)
        s = sweep(mod, mnem_cache)
        f = functions(mod, mnem_cache)
        per_module[name] = dict(sweep=s, functions=f,
                               image=len(mod["flat"]),
                               text=text_ranges(mod["layout"]))
        print("%-8s text words %9d  accepted %8d (%.1f%%)  rejected %8d  "
              "capstone-invalid %7d | funcs in text %5d  full %5d  blocked %5d"
              % (name, s["words"], s["accepted"],
                 100.0 * s["accepted"] / max(1, s["words"]), s["rejected"],
                 s["invalid_words"], f["functions_in_text"], f["full"],
                 f["blocked"]))
        sys.stdout.flush()

    lines = []
    add = lines.append
    add("# G3 increment 4 (work item E): module-mode decoder coverage on the "
        "real TotK 1.0.0 modules")
    add("")
    add("REPORT ONLY. Generated by `tools/aot/g3_coverage_report.py` from the "
        "flats under a local `MN_TOTK_V0_DIR`; it contains no game data.")
    add("")
    add("## (a) Linear sweep of every text word "
        "(`decode(pc, word, module=True)`)")
    add("")
    add("| module | text words | accepted | accepted % | rejected | "
        "capstone-invalid (data in text) |")
    add("|---|---|---|---|---|---|")
    tot = collections.Counter()
    for name in MODULES:
        s = per_module[name]["sweep"]
        tot["words"] += s["words"]
        tot["accepted"] += s["accepted"]
        tot["rejected"] += s["rejected"]
        tot["invalid"] += s["invalid_words"]
        add("| %s | %d | %d | %.2f%% | %d | %d |"
            % (name, s["words"], s["accepted"],
               100.0 * s["accepted"] / max(1, s["words"]), s["rejected"],
               s["invalid_words"]))
    add("| **total** | **%d** | **%d** | **%.2f%%** | **%d** | **%d** |"
        % (tot["words"], tot["accepted"],
           100.0 * tot["accepted"] / max(1, tot["words"]), tot["rejected"],
           tot["invalid"]))
    add("")
    add("## (a') Rejected text words grouped by Capstone mnemonic (top %d)"
        % TOP_REJECTED)
    add("")
    agg = collections.Counter()
    for name in MODULES:
        agg.update(per_module[name]["sweep"]["by_mnemonic"])
    add("| # | mnemonic | main | subsdk0 | sdk | total | example PC | word |")
    add("|---|---|---|---|---|---|---|---|")
    row = 0
    for mnem, total in agg.most_common(TOP_REJECTED):
        row += 1
        cells = []
        example = None
        for name in MODULES:
            s = per_module[name]["sweep"]
            cells.append(s["by_mnemonic"].get(mnem, 0))
            if example is None and mnem in s["examples"]:
                example = s["examples"][mnem]
        add("| %d | `%s` | %d | %d | %d | %d | %s | %s |"
            % (row, mnem, cells[0], cells[1], cells[2], total,
               ("0x%x" % example[0]) if example else "-",
               ("0x%08x" % example[1]) if example else "-"))
    add("")
    add("## (b) Defined STT_FUNC symbols: is the whole reachable CFG decodable?")
    add("")
    add("A function counts as fully translatable when every word reachable from "
        "its entry (fallthrough + direct branch/call targets inside the shipped "
        "text range, stopping at `ret`/indirect `br`) decodes in module mode - "
        "the same walk `aot_translate.build_cfg(module=True)` performs.")
    add("")
    add("| module | defined STT_FUNC in text | 4-byte aligned | fully "
        "translatable | blocked | full % |")
    add("|---|---|---|---|---|---|")
    tf = collections.Counter()
    for name in MODULES:
        f = per_module[name]["functions"]
        tf["in_text"] += f["functions_in_text"]
        tf["aligned"] += f["aligned"]
        tf["full"] += f["full"]
        tf["blocked"] += f["blocked"]
        add("| %s | %d | %d | %d | %d | %.2f%% |"
            % (name, f["functions_in_text"], f["aligned"], f["full"],
               f["blocked"], 100.0 * f["full"] / max(1, f["aligned"])))
    add("| **total** | **%d** | **%d** | **%d** | **%d** | **%.2f%%** |"
        % (tf["in_text"], tf["aligned"], tf["full"], tf["blocked"],
           100.0 * tf["full"] / max(1, tf["aligned"])))
    add("")
    add("## (b') First blocking mnemonic for the blocked functions (top %d)"
        % TOP_BLOCKING)
    add("")
    fagg = collections.Counter()
    for name in MODULES:
        fagg.update(per_module[name]["functions"]["blocking"])
    add("| # | first blocking mnemonic | main | subsdk0 | sdk | total | "
        "example symbol | PC | word |")
    add("|---|---|---|---|---|---|---|---|---|")
    row = 0
    for mnem, total in fagg.most_common(TOP_BLOCKING):
        row += 1
        cells = [per_module[n]["functions"]["blocking"].get(mnem, 0)
                 for n in MODULES]
        example = None
        for name in MODULES:
            if mnem in per_module[name]["functions"]["examples"]:
                example = per_module[name]["functions"]["examples"][mnem]
                break
        add("| %d | `%s` | %d | %d | %d | %d | %s | %s | %s |"
            % (row, mnem, cells[0], cells[1], cells[2], total,
               ("`%s`" % example[0]) if example else "-",
               ("0x%x" % example[1]) if example else "-",
               ("0x%08x" % example[2]) if example else "-"))
    add("")
    add("Note: the linear sweep (a) counts DATA inside the text segment as "
        "rejected, so it understates code coverage; (b) is the meaningful "
        "number because it only follows reachable instructions from real "
        "function entries.")
    text = "\n".join(lines) + "\n"

    if args.out:
        out_dir = os.path.dirname(os.path.abspath(args.out))
        if out_dir and not os.path.isdir(out_dir):
            os.makedirs(out_dir)
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
        print("wrote %s" % args.out)
    if args.json:
        summary = {
            "modules": {
                name: {
                    "sweep": {
                        "words": per_module[name]["sweep"]["words"],
                        "accepted": per_module[name]["sweep"]["accepted"],
                        "rejected": per_module[name]["sweep"]["rejected"],
                        "invalid_words":
                            per_module[name]["sweep"]["invalid_words"],
                        "by_mnemonic": dict(
                            per_module[name]["sweep"]["by_mnemonic"]),
                    },
                    "functions": {
                        "in_text":
                            per_module[name]["functions"]["functions_in_text"],
                        "aligned": per_module[name]["functions"]["aligned"],
                        "full": per_module[name]["functions"]["full"],
                        "blocked": per_module[name]["functions"]["blocked"],
                        "blocking": dict(
                            per_module[name]["functions"]["blocking"]),
                    },
                } for name in MODULES
            },
            "totals": {"sweep": dict(tot),
                       "functions": dict(tf)},
        }
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=1, sort_keys=True)
        print("wrote %s" % args.json)
    if not args.out:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
