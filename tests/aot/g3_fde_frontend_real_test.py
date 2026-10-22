#!/usr/bin/env python3
"""D024 Stage A: opt-in REAL-module FDE frontend driver (local data only).

Registered as CTest `aot_g3_fde_frontend_real` ONLY when MN_TOTK_V0_DIR is
set, exactly like `aot_g3_real_link`, so the repository's test suite never
depends on game data.  Everything this driver produces is written under
--work (a BUILD directory), never into the source tree, and the inputs under
<v0>/flat and <v0>/link are only ever read.

For each module in <v0>/flat/*.flat:

  1. read the flat + layout pair (identity, not a copy);
  2. rebuild the reference link's relocated image from <v0>/link/real_sites.tsv
     so `g3_ctor_roots.derive()` sees the same post-relocation bytes the loader
     seals;
  3. derive and fully validate the declared DT_INIT_ARRAY (D023 authority);
  4. parse .eh_frame_hdr through the module's own MOD0, walk .eh_frame and
     cross-check both, then build the CANDIDATE manifest;
  5. write the manifest under --work and assert that EVERY derived constructor
     target is an FDE start.

The audit numbers below come from an EXTERNAL audit of the same modules and are
NOT ground truth: they are printed side by side with what this parser found. A
difference is reported with its size, never "fixed" by loosening a check.

Exit: 0 = every constructor target is an FDE start, 1 = a semantic check
failed or a module was refused, 2 = infrastructure problem.
"""

import argparse
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
TOOLS = os.path.join(REPO, "tools", "aot")
if TOOLS not in sys.path:
    sys.path.insert(0, TOOLS)

import aot_translate as T          # noqa: E402
import g3_ctor_roots as G          # noqa: E402
import g3_fde_frontend as F        # noqa: E402
import g3_init_reach as R          # noqa: E402
import g3_local_switch as LS       # noqa: E402

MODULES = ("main", "subsdk0", "sdk")
# External audit (see docs/research/savagewind-audit.md section 1). Evidence,
# not ground truth.
REFERENCE = {
    "main": {"fdes": 242860, "ctors": 10539},
    "subsdk0": {"fdes": 10061, "ctors": 45},
    "sdk": {"fdes": 31238, "ctors": 116},
}
REFERENCE_CTORS_TOTAL = 10700
REFERENCE_MAIN_CTOR = 0x1520
REFERENCE_MAIN_CTOR_RANGE = (0x1520, 0x1584)


def parse_hex(value, default=0):
    if value is None:
        return default
    if isinstance(value, int):
        return value
    return int(str(value), 0)


def read_link_config(v0_dir):
    path = os.path.join(v0_dir, "link", "real_link_config.json")
    if not os.path.isfile(path):
        raise SystemExit("g3_fde_frontend_real_test: missing %s (run the "
                         "reference link first)" % path)
    with open(path, "r", encoding="utf-8") as handle:
        cfg = json.load(handle)
    bases = {}
    for spec in cfg.get("modules", []):
        bases[spec["name"]] = parse_hex(spec["guest_base"])
    return bases, parse_hex(cfg.get("sentinel"), 0)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--v0-dir", required=True,
                        help="local TotK v1.0.0 work dir (flat/, link/)")
    parser.add_argument("--work", required=True,
                        help="build directory for the manifests (never the tree)")
    parser.add_argument("--modules", default=",".join(MODULES))
    args = parser.parse_args(argv)
    modules = [name for name in args.modules.split(",") if name]

    work = os.path.abspath(args.work)
    if F.inside_tree(work, REPO):
        print("FAIL: --work %r is inside the source tree; game-derived "
              "manifests must stay outside it (D006)" % work)
        return 2
    os.makedirs(work, exist_ok=True)

    bases, sentinel = read_link_config(args.v0_dir)
    tsv = os.path.join(args.v0_dir, "link", "real_sites.tsv")
    if not os.path.isfile(tsv):
        print("FAIL: missing %s" % tsv)
        return 2
    sites = R.read_sites(tsv)

    failures = []
    totals = {"fdes": 0, "ctors": 0, "covered": 0}
    for name in modules:
        flat_path = os.path.join(args.v0_dir, "flat", name + ".flat")
        layout_path = os.path.join(args.v0_dir, "flat", name + ".layout.json")
        if not (os.path.isfile(flat_path) and os.path.isfile(layout_path)):
            print("FAIL: missing %s or %s" % (flat_path, layout_path))
            return 2
        with open(flat_path, "rb") as handle:
            flat = handle.read()
        with open(layout_path, "r", encoding="utf-8") as handle:
            layout = json.load(handle)
        base = bases.get(name)
        if base is None:
            print("FAIL: %s has no guest_base in real_link_config.json" % name)
            return 2

        try:
            meta = F.read_module(flat, layout, name)
            context = F._conflict_context(meta, None, base)
            image = R.Image(name, base, flat, layout, sites.get(name, {}))
            ctor_targets, ctor_info = F.derive_ctor_targets(image, context,
                                                           sentinel)
            header, fdes, terminator_end = F.parse_fdes(meta)
            manifest = F.build_manifest(meta, header, terminator_end, fdes,
                                        context, ctor_targets, ctor_info)
        except F.NoEhFrameHdr as exc:
            print("FAIL: %s: no .eh_frame_hdr (%s)" % (name, exc))
            failures.append("%s: no .eh_frame_hdr" % name)
            continue
        except F.FdeError as exc:
            print("FAIL: %s: refused %s (%s)" % (name, exc.reason, exc.detail))
            failures.append("%s: %s" % (name, exc.reason))
            continue
        except (G.CtorRefusal, G.CtorInputError) as exc:
            print("FAIL: %s: constructor table refused: %s"
                  % (name, exc))
            failures.append("%s: ctor-table %s"
                            % (name, getattr(exc, "reason", "input-error")))
            continue
        except LS.InputError as exc:
            print("FAIL: %s: metadata context error: %s" % (name, exc))
            failures.append("%s: metadata-invalid" % name)
            continue

        out = os.path.join(work, name + ".fde_candidates.json")
        F.write_manifest(manifest, out)
        counts = manifest["counts"]
        starts = set(int(item["start"], 16) for item in manifest["boundaries"])
        missing = sorted(ctor_targets - starts)
        script = os.path.relpath(out, work)
        print("%s: FDEs=%d boundaries=%d gaps=%d conflicts=%d "
              "ctor_entries=%d ctor_on_fde_start=%d dynsym_func=%d -> %s"
              % (name, counts["fde"], counts["boundaries"],
                 counts["text_gaps"], counts["conflicts"],
                 counts["ctor_targets"], counts["ctor_targets_on_fde_start"],
                 counts["dynsym_func"], script))
        if manifest["kind"] != "candidates" or manifest["authority"] != "none":
            print("FAIL: %s: manifest lost the candidate/authority contract"
                  % name)
            failures.append("%s: candidate-contract" % name)
        if missing:
            print("FAIL: %s: %d constructor target(s) is not an FDE start: %s"
                  % (name, len(missing),
                     ", ".join("0x%x" % value for value in missing[:8])))
            failures.append("%s: ctor-not-an-fde-start" % name)
        reference = REFERENCE.get(name)
        if reference is not None:
            for key, value in (("fdes", counts["fde"]),
                               ("ctors", counts["ctor_targets"])):
                want = reference[key]
                if value == want:
                    print("  reference %s: %d == audit %d (match)"
                          % (key, value, want))
                else:
                    print("  reference %s: %d != audit %d (difference %+d: the "
                          "audit is evidence, not ground truth; no check was "
                          "relaxed to match it)" % (key, value, want,
                                                    value - want))
        totals["fdes"] += counts["fde"]
        totals["ctors"] += counts["ctor_targets"]
        totals["covered"] += counts["ctor_targets_on_fde_start"]

        if name == "main":
            row = next((item for item in manifest["boundaries"]
                        if int(item["start"], 16) == REFERENCE_MAIN_CTOR), None)
            if row is None:
                print("FAIL: main: constructor 0x%x is not an FDE start"
                      % REFERENCE_MAIN_CTOR)
                failures.append("main: 0x%x-not-an-fde-start"
                                % REFERENCE_MAIN_CTOR)
            else:
                got = (int(row["start"], 16), int(row["end"], 16))
                if got == REFERENCE_MAIN_CTOR_RANGE:
                    print("  reference main ctor 0x%x: FDE range [0x%x,0x%x) "
                          "== audit" % (got[0], got[0], got[1]))
                else:
                    print("  reference main ctor 0x%x: FDE range "
                          "[0x%x,0x%x) != audit [0x%x,0x%x) (reported, not "
                          "tuned)" % (REFERENCE_MAIN_CTOR, got[0], got[1],
                                      REFERENCE_MAIN_CTOR_RANGE[0],
                                      REFERENCE_MAIN_CTOR_RANGE[1]))
                if "dt_init_array" not in row["provenance"]:
                    print("FAIL: main: constructor 0x%x lost its "
                          "dt_init_array provenance (%r)"
                          % (REFERENCE_MAIN_CTOR, row["provenance"]))
                    failures.append("main: 0x%x-provenance"
                                    % REFERENCE_MAIN_CTOR)

    print("totals: FDEs=%d ctor_entries=%d ctor_on_fde_start=%d"
          % (totals["fdes"], totals["ctors"], totals["covered"]))
    audit_fdes = sum(item["fdes"] for item in REFERENCE.values())
    if totals["fdes"] == audit_fdes:
        print("  reference FDE total: %d == audit %d (match)"
              % (totals["fdes"], audit_fdes))
    else:
        print("  reference FDE total: %d != audit %d (difference %+d)"
              % (totals["fdes"], audit_fdes, totals["fdes"] - audit_fdes))
    if totals["ctors"] == REFERENCE_CTORS_TOTAL:
        print("  reference ctor total: %d == audit %d (match)"
              % (totals["ctors"], REFERENCE_CTORS_TOTAL))
    else:
        print("  reference ctor total: %d != audit %d (difference %+d; the "
              "audit is evidence, not ground truth)"
              % (totals["ctors"], REFERENCE_CTORS_TOTAL,
                 totals["ctors"] - REFERENCE_CTORS_TOTAL))
    if failures:
        print("FAIL: g3_fde_frontend_real (%s)" % "; ".join(failures))
        return 1
    print("PASS: g3_fde_frontend_real (manifests under %s)" % work)
    return 0


if __name__ == "__main__":
    sys.exit(main())
