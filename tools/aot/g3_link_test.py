#!/usr/bin/env python3
"""G3 increment 2 (T3): driver for the C module loader.

The C loader probe (tests/aot/aot_g3_link_probe.c) is the implementation under
test; everything this script compares it against is INDEPENDENT of it:

  1. the reference linker's per-site TSV   (tools/aot/aot_module.py link)
  2. tools/aot/g3_link_check.py, which recomputes every expected site and the
     link digest from `llvm-readelf` output of the ELFs, and
  3. the reference counters (fx_<variant>.counters.json).

Per variant the probe is run in its own process, so a crash in one variant
cannot hide another. Infrastructure problems (missing binary/fixture, non-zero
exit, timeout, unreadable dump) are FAILURES, never skips: a silently skipped
loader is exactly the failure mode this driver exists to prevent.

Exit: 0 = every variant agreed, 1 = at least one failure.
"""
import argparse
import json
import os
import subprocess
import sys

VARIANTS = ("v0", "relr", "gnuonly", "shadow")
COUNTER_KEYS = ("relative", "symbolic", "cross", "weak")


class Fail(Exception):
    pass


def run(cmd, timeout):
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
    except FileNotFoundError as exc:
        raise Fail("cannot execute %r: %s" % (cmd[0], exc))
    except subprocess.TimeoutExpired:
        raise Fail("timeout after %ss executing %r" % (timeout, cmd))
    except OSError as exc:
        raise Fail("cannot execute %r: %s" % (cmd[0], exc))


def read_text(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError as exc:
        raise Fail("cannot read %s: %s" % (path, exc))


def probe_variant(args, variant):
    """Run the probe for one variant and return its counter lines."""
    proc = run([args.probe, args.dir, variant], timeout=args.timeout)
    if proc.returncode != 0:
        raise Fail("probe failed for %s (exit %d)\n--- stdout ---\n%s"
                   "--- stderr ---\n%s"
                   % (variant, proc.returncode, proc.stdout, proc.stderr))
    counters = {}
    for line in proc.stdout.splitlines():
        fields = line.split()
        if not fields or fields[0] != "counters":
            continue
        if len(fields) != 6:
            raise Fail("unparsable counter line %r" % line)
        name = fields[1]
        values = {}
        for field in fields[2:]:
            key, _, raw = field.partition("=")
            if key not in COUNTER_KEYS:
                raise Fail("unknown counter %r in %r" % (key, line))
            values[key] = int(raw)
        counters[name] = values
    if not counters:
        raise Fail("probe printed no counter lines for %s" % variant)
    return counters


def compare_sites(args, variant):
    """C dump must be byte-identical to the reference linker's TSV."""
    dump_path = os.path.join(args.dir, "fx_%s.c_dump.tsv" % variant)
    ref_path = os.path.join(args.dir, "fx_%s.sites.tsv" % variant)
    dump = read_text(dump_path)
    ref = read_text(ref_path)
    dump_lines = dump.splitlines()
    ref_lines = ref.splitlines()
    if not ref_lines:
        raise Fail("reference TSV %s is empty" % ref_path)
    if dump_lines[:1] != ["module\twhere\tkind\tsymbol\tvalue"]:
        raise Fail("%s: missing/incorrect header" % dump_path)
    if dump_lines != ref_lines:
        for index, (got, want) in enumerate(zip(dump_lines, ref_lines)):
            if got != want:
                raise Fail("%s: row %d differs from the reference linker\n"
                           "  C dump    : %r\n  reference : %r"
                           % (dump_path, index + 1, got, want))
        raise Fail("%s: %d rows, reference has %d"
                   % (dump_path, len(dump_lines), len(ref_lines)))
    return len(dump_lines) - 1


def compare_counters(args, variant, got):
    counters_path = os.path.join(args.dir, "fx_%s.counters.json" % variant)
    try:
        ref = json.loads(read_text(counters_path))
    except ValueError as exc:
        raise Fail("%s: not valid JSON: %s" % (counters_path, exc))
    ref_counters = ref.get("counters")
    if not isinstance(ref_counters, dict):
        raise Fail("%s: no counters object" % counters_path)
    if set(got) != set(ref_counters):
        raise Fail("%s: module set mismatch (C=%r reference=%r)"
                   % (variant, sorted(got), sorted(ref_counters)))
    for name, want in ref_counters.items():
        if got[name] != want:
            raise Fail("%s: counters for %s differ (C=%r reference=%r)"
                       % (variant, name, got[name], want))
    return ref_counters


def independent_check(args, variant):
    """Re-run g3_link_check.py against the C dump instead of the reference."""
    proc = run([args.python, args.check,
                "--dir", args.dir,
                "--config", args.config,
                "--readelf", args.readelf,
                "--variants", variant,
                "--tsv", "fx_{variant}.c_dump.tsv"], timeout=args.timeout)
    if proc.returncode != 0:
        raise Fail("g3_link_check.py rejected the C dump for %s\n"
                   "--- stdout ---\n%s--- stderr ---\n%s"
                   % (variant, proc.stdout, proc.stderr))
    return proc.stdout.strip()


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dir", required=True, help="fixture output directory")
    ap.add_argument("--probe", required=True, help="path to aot_g3_link_probe")
    ap.add_argument("--check", required=True, help="tools/aot/g3_link_check.py")
    ap.add_argument("--python", required=True)
    ap.add_argument("--config", required=True, help="tests/aot/g3/link_config.json")
    ap.add_argument("--readelf", required=True)
    ap.add_argument("--timeout", type=int, default=180)
    args = ap.parse_args(argv)

    failures = 0
    for variant in VARIANTS:
        try:
            counters = probe_variant(args, variant)
            sites = compare_sites(args, variant)
            compare_counters(args, variant, counters)
            independent_check(args, variant)
            print("%s: OK %d sites, counters and independent check agree"
                  % (variant, sites))
        except Fail as exc:
            failures += 1
            print("%s: FAIL: %s" % (variant, exc), file=sys.stderr)

    if failures:
        print("g3_link_test: %d of %d variants failed"
              % (failures, len(VARIANTS)), file=sys.stderr)
        return 1
    print("g3_link_test: C loader agrees with the reference linker and the "
          "independent checker for all %d variants" % len(VARIANTS))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
