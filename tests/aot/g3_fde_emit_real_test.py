#!/usr/bin/env python3
"""D024 Stage B: opt-in REAL-module catalog + authority step (local data only).

Registered as CTest `aot_g3_fde_emit_real` ONLY when MN_TOTK_V0_DIR is set,
like `aot_g3_real_link`.  Inputs under <v0> are only read; every output (Stage
A manifests, catalog/table C units, metadata, partition reports, today's X
emission) is written under --work, a BUILD directory, never the source tree.

Targets (bases from <v0>/link/real_link_config.json, as aot_g3_real_link and
aot_g3_fde_frontend_real derive them):

  main  constructor at image offset 0x1520, FDE [0x1520, 0x1584)
  sdk   DEFINED STT_FUNC `__nnmusl_init_dso` (its FDE range), which holds the
        D022 local switch BR 0x102008db10 (validated target 0x102008db18)

For each module: Stage A manifest -> catalog of the selected FDE -> authority
step over the ADMITTED roots -> partition matches/mismatches per kind,
unsupported instructions, D022 sites.  When the authority step accepts, today's
emission X (`aot_translate.py --module --partial`, same roots) is generated and
every admitted catalog body must equal X's body for that block modulo the
status namespace, and the AotImage must list exactly X's block starts.

Roots: by default the registered real slice roots (<v0>/img/entries_<m>.json);
`--roots-dir DIR` reads DIR/entries_<m>_real.json instead (e.g. a Start-prefix
work dir whose admitted set reaches the targets).  Roots are never derived
from FDEs.  A partition mismatch is REPORTED measurement data (Stage C), not a
test failure; any other refusal or contract violation fails.

Execution: not performed.  The existing real-exec harnesses either link the
prebuilt <v0>/img/real_*.c slice (aot_g3_real_exec) or translate their own
images (tools/aot/g3_start_prefix.py); neither accepts a catalog + table pair.

Exit: 0 = every step ran and every contract held, 1 = semantic failure,
2 = infrastructure problem.
"""

import argparse
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
TOOLS = os.path.join(REPO, "tools", "aot")
for path in (TOOLS, HERE):
    if path not in sys.path:
        sys.path.insert(0, path)

import aot_translate as T          # noqa: E402
import g3_fde_emit as E            # noqa: E402
import g3_fde_frontend as F        # noqa: E402
import g3_fde_emit_test as H       # noqa: E402  (static body comparison)

MAIN_CTOR = 0x1520
MAIN_CTOR_RANGE = (0x1520, 0x1584)
SDK_FUNC = "__nnmusl_init_dso"
SDK_FUNC_VA = 0x102008d880
SDK_FUNC_SIZE = 2648
SDK_SWITCH_BR = 0x102008db10
SDK_SWITCH_TARGET = 0x102008db18

FAILS = []


def fail(msg):
    FAILS.append(msg)
    print("FAIL: %s" % msg)


def read_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def write_bytes(path, data):
    with open(path, "wb") as handle:
        handle.write(data)


def roots_for(args, module):
    if args.roots_dir:
        path = os.path.join(args.roots_dir, "entries_%s_real.json" % module)
    else:
        path = os.path.join(args.v0_dir, "img", "entries_%s.json" % module)
    return path, T.read_entries(path)


def select(module, flat, layout, base, manifest):
    """-> (start offset, FDE end) for this module's Stage B target."""
    bounds = dict((int(b["start"], 16), int(b["end"], 16))
                  for b in manifest["boundaries"])
    if module == "main":
        got = (MAIN_CTOR, bounds.get(MAIN_CTOR))
        if got != MAIN_CTOR_RANGE:
            fail("main: FDE at 0x%x is %r, expected [0x%x,0x%x)"
                 % ((MAIN_CTOR, got[1]) + MAIN_CTOR_RANGE))
        return got
    syms = F.func_symbols(F.read_module(flat, layout, module))
    offs = [off for off, names in syms.items() if SDK_FUNC in names]
    if len(offs) != 1 or base + offs[0] != SDK_FUNC_VA:
        raise SystemExit("INFRA: %s: defined STT_FUNC %s at %s, expected "
                         "VA 0x%x" % (module, SDK_FUNC,
                                      [hex(base + o) for o in offs],
                                      SDK_FUNC_VA))
    start = offs[0]
    if start not in bounds:
        fail("sdk: %s 0x%x is not an FDE start" % (SDK_FUNC, start))
        return None
    end = bounds[start]
    print("  sdk: %s VA 0x%x, FDE [0x%x,0x%x) (%d bytes; dynsym size %d)"
          % (SDK_FUNC, base + start, start, end, end - start, SDK_FUNC_SIZE))
    if not start <= SDK_SWITCH_BR - base < end:
        fail("sdk: the D022 BR 0x%x is outside the FDE" % SDK_SWITCH_BR)
    return start, end


def run_x(args, work, module, flat_path, layout_path, base, entries_path):
    out_c = os.path.join(work, "x_%s.c" % module)
    out_j = os.path.join(work, "x_%s.json" % module)
    proc = subprocess.run(
        [sys.executable, os.path.join(TOOLS, "aot_translate.py"), "--module",
         "--partial", "--flat", flat_path, "--layout", layout_path,
         "--guest-base", "0x%x" % base, "--entries", entries_path,
         "--name", module, "--out", out_c, "--meta-out", out_j],
        capture_output=True, text=True)
    if proc.returncode:
        fail("%s: today's emission refused: %s" % (module, proc.stderr[-800:]))
        return None
    with open(out_c, "r", encoding="utf-8") as handle:
        text = handle.read()
    return {"text": text, "meta": read_json(out_j)}


def compare_bodies(module, x, table_c, table_meta, catalog_c):
    y_tab = H.table_pcs(table_c.replace("aot_blocks_%s[]" % module,
                                        "aot_blocks_fx[]"))
    x_tab = H.table_pcs(x["text"].replace("aot_blocks_%s[]" % module,
                                          "aot_blocks_fx[]"))
    if [p for p, _ in x_tab] != [p for p, _ in y_tab]:
        fail("%s: AotImage entries differ from today's closure (%d vs %d)"
             % (module, len(y_tab), len(x_tab)))
        return
    xb = H.bodies(x["text"])
    yb = H.bodies(catalog_c.replace("aot_cand_%s_" % module, "aot_cand_fx_"))
    bad = [pc for pc, sym in y_tab if sym.startswith("aot_cand_")
           and H.normalize(xb[pc][1], x["meta"])
           != H.normalize(yb[pc][1], table_meta)]
    n_cat = sum(1 for _p, sym in y_tab if sym.startswith("aot_cand_"))
    if bad:
        fail("%s: %d admitted catalog bodies differ from today's (first 0x%x)"
             % (module, len(bad), bad[0]))
    else:
        print("  %s: AotImage == today's %d closure starts; %d admitted "
              "catalog bodies == today's bodies modulo status namespace"
              % (module, len(x_tab), n_cat))


def run_module(args, work, module, base, report):
    flat_path = os.path.join(args.v0_dir, "flat", module + ".flat")
    layout_path = os.path.join(args.v0_dir, "flat", module + ".layout.json")
    with open(flat_path, "rb") as handle:
        flat = handle.read()
    layout = read_json(layout_path)
    rec = {"module": module, "guest_base": "0x%x" % base}
    report[module] = rec

    t0 = time.perf_counter()
    manifest = F.manifest_for(flat, layout, name=module)
    man_path = os.path.join(work, "%s.fde_candidates.json" % module)
    F.write_manifest(manifest, man_path)
    rec["t_manifest_s"] = round(time.perf_counter() - t0, 3)
    sel = select(module, flat, layout, base, manifest)
    if sel is None:
        return
    rec["window"] = ["0x%x" % sel[0], "0x%x" % sel[1]]

    t0 = time.perf_counter()
    try:
        cat_c, cat_meta = E.build_catalog(flat, layout, manifest, base, module,
                                          [sel[0]])
    except E.EmitError as exc:
        fail("%s: catalog refused %s (%s)" % (module, exc.reason, exc.detail))
        return
    rec["t_catalog_s"] = round(time.perf_counter() - t0, 3)
    write_bytes(os.path.join(work, "cat_%s.c" % module), cat_c.encode("utf-8"))
    write_bytes(os.path.join(work, "cat_%s.json" % module),
                E._json_bytes(cat_meta))
    rec["catalog_blocks"] = len(cat_meta["blocks"])
    rec["catalog_unsupported"] = cat_meta["unsupported"]
    rec["catalog_switches"] = cat_meta["local_switch_sites"]
    print("%s: window [0x%x,0x%x) VA [0x%x,0x%x): catalog %d blocks, %d "
          "unsupported, %d local switch(es), identity %s"
          % (module, sel[0], sel[1], base + sel[0], base + sel[1],
             len(cat_meta["blocks"]), len(cat_meta["unsupported"]),
             len(cat_meta["local_switch_sites"]), cat_meta["identity"][:16]))
    for u in cat_meta["unsupported"]:
        print("  unsupported %s word %s: %s" % (u["pc"], u["word"], u["reason"]))
    for s in cat_meta["local_switch_sites"]:
        print("  candidate switch %s -> %d targets %s"
              % (s["br_pc"], len(s["targets"]), s["targets"]))
    if module == "sdk":
        sw = [s for s in cat_meta["local_switch_sites"]
              if int(s["br_pc"], 16) == SDK_SWITCH_BR]
        if not sw or "0x%x" % SDK_SWITCH_TARGET not in sw[0]["targets"]:
            fail("sdk: the function-local proof does not reproduce the "
                 "validated D022 site 0x%x -> 0x%x"
                 % (SDK_SWITCH_BR, SDK_SWITCH_TARGET))

    entries_path, entries = roots_for(args, module)
    rec["roots"] = {"path": entries_path, "count": len(entries)}
    t0 = time.perf_counter()
    try:
        tab_c, tab_meta, part = E.build_table(flat, layout, base, module,
                                              entries, cat_meta, cat_c)
        rec["authority"] = "accepted"
    except E.PartitionMismatch as exc:
        part = exc.report
        tab_c = tab_meta = None
        rec["authority"] = "partition-mismatch"
    except E.EmitError as exc:
        fail("%s: authority step refused %s (%s)"
             % (module, exc.reason, exc.detail))
        return
    rec["t_authority_s"] = round(time.perf_counter() - t0, 3)
    rec["partition"] = part
    write_bytes(os.path.join(work, "partition_%s.json" % module),
                E._json_bytes(part))
    print("  authority over %d root(s) from %s: %s; closure %d blocks, %d "
          "matched catalog, %d outside the window, %d catalog block(s) "
          "compiled but not admitted, mismatches %s"
          % (len(entries), entries_path, rec["authority"],
             part["closure_blocks"], part["covered_matches"],
             part["outside_candidates"], part["unadmitted_catalog_blocks"],
             part["mismatch_counts"] or "none"))
    for item in part["mismatches"][:8]:
        print("    mismatch %s %s: %s" % (item["kind"], item["pc"],
                                         item["detail"]))
    if tab_c is None:
        # Both targets are claimed to partition exactly; a mismatch here is a
        # regression, not just Stage C measurement data.
        fail("%s: authority step refused with a partition mismatch %s"
             % (module, part["mismatch_counts"]))
        return
    write_bytes(os.path.join(work, "tab_%s.c" % module), tab_c.encode("utf-8"))
    write_bytes(os.path.join(work, "tab_%s.json" % module),
                E._json_bytes(tab_meta))
    sites = [s for s in tab_meta["local_switch_sites"] if s["body"] == "catalog"]
    for s in sites:
        print("  admitted switch %s (catalog body): %d targets, status %d"
              % (s["br_pc"], len(s["targets"]), s["status"]))
    x = run_x(args, work, module, flat_path, layout_path, base, entries_path)
    if x is not None:
        compare_bodies(module, x, tab_c, tab_meta, cat_c)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--v0-dir", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--roots-dir", default=None,
                    help="dir with entries_<module>_real.json (admitted sets)")
    args = ap.parse_args(argv)
    work = os.path.abspath(args.work)
    if F.inside_tree(work, REPO):
        print("FAIL: --work %r is inside the source tree (D006)" % work)
        return 2
    os.makedirs(work, exist_ok=True)
    cfg = read_json(os.path.join(args.v0_dir, "link", "real_link_config.json"))
    bases = dict((m["name"], int(m["guest_base"], 0)) for m in cfg["modules"])
    report = {}
    for module in ("main", "sdk"):
        run_module(args, work, module, bases[module], report)
    report["executed"] = False
    report["executed_reason"] = (
        "no existing real-exec harness accepts a catalog + table pair: "
        "aot_g3_real_exec links the prebuilt <v0>/img/real_*.c slice and "
        "g3_start_prefix.py translates its own images")
    write_bytes(os.path.join(work, "stageB_real_report.json"),
                E._json_bytes(report))
    print("not executed: %s" % report["executed_reason"])
    if FAILS:
        print("FAIL: g3_fde_emit_real (%d)" % len(FAILS))
        return 1
    print("PASS: g3_fde_emit_real (outputs under %s)" % work)
    return 0


if __name__ == "__main__":
    sys.exit(main())
