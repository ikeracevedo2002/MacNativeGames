#!/usr/bin/env python3
"""G3 increment 4: real-module link configuration and pre-link report.

Two subcommands, both usable without touching the repository's tests:

  config  Turn the Mac observer/override lists (tools/aot/extract_mac_bindings.py
          output) into a link_config.json for the REAL TotK modules, including
          the thunk binding table.

  report  Load the real flats and report, WITHOUT linking: every unresolved
          strong import (name, module, site count), how many sites resolve to
          host thunks, and how many symbolic sites would resolve to a different
          value under a Horizon-style global-first search order.

Thunk index rule (documented because both the reference linker and the C loader
must agree on it byte for byte):

    index = position in  observers (in the Mac source order of the JSON file)
                        followed by  overrides (sorted by name)

Observer names keep their source order so a human diff against
services.c::runtime_observer stays readable; overrides are sorted so the table
does not depend on the order files were parsed in. Indices are 0-based and
contiguous; the guest VA of thunk i is thunk_base + 16*i.

Usage:
  aot_real_link.py config --bindings B.json --out DIR [--base main=0x...]...
  aot_real_link.py report --config real_link_config.json --dir FLATDIR
"""

import argparse
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import aot_module as am  # noqa: E402

DEFAULT_BASES = [("main", "0x1000000000"),     # 0x10_0000_0000
                 ("subsdk0", "0x1010000000"),  # 0x10_1000_0000
                 ("sdk", "0x1020000000")]      # 0x10_2000_0000
THUNK_BASE = "0x7f00000000"
SENTINEL = "0x7f00100000"


def repo_root():
    return os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))))


def refuse_inside_repo(path):
    root = os.path.realpath(repo_root())
    target = os.path.realpath(os.path.abspath(path))
    if target == root or target.startswith(root + os.sep):
        raise SystemExit("aot_real_link: refusing to write real-module data "
                         "inside the repository: %s" % path)


def thunk_table(bindings):
    """(observers, overrides) as name -> index under the documented rule."""
    observers = {name: i for i, name in enumerate(bindings["observers"])}
    base = len(observers)
    overrides = {name: base + i
                 for i, name in enumerate(sorted(bindings["overrides"]))}
    clash = set(observers) & set(overrides)
    if clash:
        raise SystemExit("aot_real_link: names in both tables: %s"
                         % sorted(clash))
    if len(observers) != 6:
        raise SystemExit("aot_real_link: expected 6 observers, got %d"
                         % len(observers))
    return observers, overrides


def cmd_config(args):
    bindings = json.loads(open(args.bindings, encoding="utf-8").read())
    observers, overrides = thunk_table(bindings)
    bases = dict(DEFAULT_BASES)
    for spec in args.base or []:
        name, _, value = spec.partition("=")
        if not name or not value:
            raise SystemExit("aot_real_link: --base wants name=0xADDR")
        bases[name] = value
    names = [b for b, _ in DEFAULT_BASES]
    config = {
        "_comment": [
            "G3 increment 4 real-module link configuration (TotK 1.0.0).",
            "Module order IS the loader's global symbol search order.",
            "guest_base values are the fixed AOT-time bases.",
            "Thunk VA = thunk_base + 16*index. Indexes: observers in Mac",
            "source order first, then overrides sorted by name (rule",
            "documented in tools/aot/aot_real_link.py).",
            "Generated from the Mac sources by tools/aot/extract_mac_bindings.py;",
            "contains no game data.",
        ],
        "thunk_base": THUNK_BASE,
        "sentinel": SENTINEL,
        "modules": [{"name": n, "guest_base": bases[n]} for n in names],
        "overrides": overrides,
        "observers": observers,
    }
    os.makedirs(args.out, exist_ok=True)
    refuse_inside_repo(args.out)
    path = os.path.join(args.out, "real_link_config.json")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(config, f, indent=2, sort_keys=True)
        f.write("\n")
    print("wrote %s: %d observers, %d overrides, %d thunks, thunk_base %s"
          % (path, len(observers), len(overrides),
             max(overrides.values()) + 1, THUNK_BASE))
    return 0


def collect_sites(mod):
    """Every relocation entry of one module as (kind, sym_index, where)."""
    out = []
    tags = mod["tags"]
    image_size = mod["image_size"]
    if am.DT_RELA in tags:
        for e in am.parse_rela_table(mod["flat"], tags[am.DT_RELA],
                                     tags.get(am.DT_RELASZ, 0), image_size,
                                     ".rela.dyn"):
            out.append(e)
    if am.DT_JMPREL in tags:
        for e in am.parse_rela_table(mod["flat"], tags[am.DT_JMPREL],
                                     tags.get(am.DT_PLTRELSZ, 0), image_size,
                                     ".rela.plt"):
            out.append(e)
    if am.DT_RELR in tags:
        for where in am.decode_relr(mod["flat"], tags[am.DT_RELR],
                                    tags.get(am.DT_RELRSZ, 0), image_size):
            out.append(dict(where=where, sym=0, kind=am.R_AARCH64_RELATIVE,
                            addend=0, table=".relr", idx=0))
    return out


def cmd_report(args):
    cfg = json.loads(open(args.config, encoding="utf-8").read())
    overrides = cfg.get("overrides", {})
    observers = cfg.get("observers", {})
    mods = []
    for spec in cfg["modules"]:
        name = spec["name"]
        mods.append(am.load_module(
            os.path.join(args.dir, name + ".flat"),
            os.path.join(args.dir, name + ".layout.json"), name,
            am.parse_hex(spec["guest_base"])))

    def defined_in(mod, name):
        sym = mod["sym_by_name"].get(name)
        if sym is not None and am.sym_defined(sym, mod["image_size"]):
            return mod["base"] + sym["value"]
        return None

    unresolved = {}
    thunk_sites = 0
    weak_zero = 0
    order_diff = 0
    order_diff_names = {}
    per_kind = {m["name"]: {k: 0 for k in ("RELATIVE", "ABS64", "GLOB_DAT",
                                           "JUMP_SLOT")} for m in mods}
    symbolic_sites = 0
    for mod in mods:
        for e in collect_sites(mod):
            kind = e["kind"]
            per_kind[mod["name"]][am.KIND_NAMES[kind]] += 1
            if kind == am.R_AARCH64_RELATIVE:
                continue
            symbolic_sites += 1
            sym = mod["syms"][e["sym"]]
            name = sym["name"]
            if kind == am.R_AARCH64_JUMP_SLOT and name in observers:
                thunk_sites += 1
                continue
            if name in overrides:
                thunk_sites += 1
                continue
            own = defined_in(mod, name)
            if own is not None:
                # Global-first would take the first module in order defining it.
                gfirst = None
                for other in mods:
                    gfirst = defined_in(other, name)
                    if gfirst is not None:
                        break
                if gfirst != own:
                    order_diff += 1
                    order_diff_names[name] = order_diff_names.get(name, 0) + 1
                continue
            gfirst = None
            for other in mods:
                gfirst = defined_in(other, name)
                if gfirst is not None:
                    break
            if gfirst is not None:
                continue
            if sym["bind"] == am.STB_WEAK:
                weak_zero += 1
                continue
            key = (mod["name"], name)
            unresolved[key] = unresolved.get(key, 0) + 1

    print("modules:")
    for mod in mods:
        k = per_kind[mod["name"]]
        print("  %-8s base=%#x image=%#x symbols=%d reloc: relative=%d "
              "ABS64=%d GLOB_DAT=%d JUMP_SLOT=%d"
              % (mod["name"], mod["base"], mod["image_size"],
                 len(mod["syms"]), k["RELATIVE"], k["ABS64"], k["GLOB_DAT"],
                 k["JUMP_SLOT"]))
    print("symbolic sites: %d, resolved to host thunks: %d"
          % (symbolic_sites, thunk_sites))
    print("weak imports resolving to 0: %d" % weak_zero)
    print("own-first vs global-first differing symbolic sites: %d (%d names)"
          % (order_diff, len(order_diff_names)))
    print("unresolved strong imports: %d distinct (module, name) pairs"
          % len(unresolved))
    for (module, name), count in sorted(unresolved.items(),
                                        key=lambda kv: (-kv[1], kv[0])):
        print("  %-8s %-70s %d site%s" % (module, name, count,
                                          "" if count == 1 else "s"))
    return 0 if not unresolved else 3


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("config")
    p.add_argument("--bindings", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--base", action="append", metavar="NAME=0xADDR")
    p = sub.add_parser("report")
    p.add_argument("--config", required=True)
    p.add_argument("--dir", required=True)
    args = ap.parse_args(argv[1:])
    if args.cmd == "config":
        return cmd_config(args)
    return cmd_report(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
