#!/usr/bin/env python3
"""G3 increment 4: local-only driver for the real-module link test.

Registered as CTest `aot_g3_real_link` ONLY when MN_TOTK_V0_DIR is set, so the
repository's test suite never depends on game data.  Everything it produces
lives in the build tree or under MN_TOTK_V0_DIR -- never in the source tree.

Steps:
  1. stage <v0>/flat/{main,subsdk0,sdk}.{flat,layout.json} as <work>/<name>_real.*
     (the reference linker names images "<module>_<variant>");
  2. rebuild the thunk/binding config from <v0>/bindings-mac.json and run the
     Python reference link over the staged flats -> reference TSV;
  3. run the C probe (compiled against the generated descriptor from step 2's
     inputs) over the same flats -> its own TSV dump;
  4. compare the two files byte for byte, which covers all ~560K sites, their
     kinds, symbols and resolved values.

Exit: 0 = identical, 1 = infrastructure problem, 2 = the dumps differ.
"""

import argparse
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.join(os.path.dirname(os.path.dirname(HERE)), "tools", "aot")


def run(cmd, what):
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.stdout:
        sys.stdout.write(proc.stdout)
    if proc.stderr:
        sys.stderr.write(proc.stderr)
    if proc.returncode != 0:
        raise SystemExit("aot_real_link_test: %s failed (exit %d)"
                         % (what, proc.returncode))
    return proc.stdout


def stage(v0_dir, work, modules):
    os.makedirs(work, exist_ok=True)
    for name in modules:
        for suffix in (".flat", ".layout.json"):
            src = os.path.join(v0_dir, "flat", name + suffix)
            dst = os.path.join(work, "%s_real%s" % (name, suffix))
            if not os.path.isfile(src):
                raise SystemExit("aot_real_link_test: missing %s" % src)
            if os.path.exists(dst):
                os.remove(dst)
            try:
                os.link(src, dst)
            except OSError:
                shutil.copyfile(src, dst)


def first_difference(ref, dump, limit=5):
    with open(ref, "rb") as f:
        want = f.read().split(b"\n")
    with open(dump, "rb") as f:
        got = f.read().split(b"\n")
    diffs = []
    for i in range(max(len(want), len(got))):
        a = want[i] if i < len(want) else b"<missing>"
        b = got[i] if i < len(got) else b"<missing>"
        if a != b:
            diffs.append((i + 1, a, b))
            if len(diffs) >= limit:
                break
    return len(want) - 1, len(got) - 1, diffs


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe", required=True)
    ap.add_argument("--python", required=True)
    ap.add_argument("--v0-dir", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--modules", default="main,subsdk0,sdk")
    args = ap.parse_args(argv[1:])
    modules = [m for m in args.modules.split(",") if m]

    if not os.path.isfile(os.path.join(args.v0_dir, "bindings-mac.json")):
        raise SystemExit("aot_real_link_test: %s/bindings-mac.json is missing; "
                         "run tools/aot/extract_mac_bindings.py first"
                         % args.v0_dir)

    work = os.path.abspath(args.work)
    stage(args.v0_dir, work, modules)

    run([args.python, os.path.join(TOOLS, "aot_real_link.py"), "config",
         "--bindings", os.path.join(args.v0_dir, "bindings-mac.json"),
         "--out", work], "thunk/binding config")
    ref_tsv = os.path.join(work, "real_sites.tsv")
    run([args.python, os.path.join(TOOLS, "aot_module.py"), "link",
         "--config", os.path.join(work, "real_link_config.json"),
         "--dir", work, "--variant", "real", "--out-tsv", ref_tsv,
         "--out-counters", os.path.join(work, "real_counters.json")],
        "reference link")

    dump = os.path.join(work, "c_dump.tsv")
    run([args.probe, work, dump], "C loader probe")

    want_rows, got_rows, diffs = first_difference(ref_tsv, dump)
    print("aot_real_link_test: reference %d sites, C loader %d sites"
          % (want_rows, got_rows))
    if diffs or want_rows != got_rows:
        for line, a, b in diffs:
            print("  line %d\n    reference: %s\n    C loader : %s"
                  % (line, a.decode("utf-8", "replace"),
                     b.decode("utf-8", "replace")))
        print("aot_real_link_test: FAILED (site dumps differ)")
        return 2
    print("aot_real_link_test: OK -- C loader dump is byte-identical to the "
          "reference TSV")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
