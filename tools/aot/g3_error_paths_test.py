#!/usr/bin/env python3
"""G3: typed-error and negative-control checks for the offline toolchain.

Every case is a DELIBERATELY bad invocation of a tool that must fail cleanly:
a single-line typed message on stderr, a non-zero exit status, and NO Python
traceback. Infra failures (missing tool, missing fixture) are failures, never
skips. The last group is a NEGATIVE CONTROL for the G2 identity guard: a
generated file with one semantic byte changed must be rejected, which proves the
guard is not vacuously passing.

Usage:
  g3_error_paths_test.py --g3-dir <aot_gen/g3> --aot-gen <aot_gen>
                         --tools <tools/aot dir> --python <python.exe>
                         [--baseline <tests/aot/g2_gen_identity.txt>]
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

FAILS = []


def fail(msg):
    FAILS.append(msg)
    print("FAIL: %s" % msg)


def run(args):
    return subprocess.run(args, capture_output=True, text=True)


def expect_clean_error(args, tag, expect_fragment):
    proc = run(args)
    if proc.returncode == 0:
        fail("%s: expected a non-zero exit, got success" % tag)
        return
    if "Traceback (most recent call last)" in proc.stderr:
        fail("%s: produced a Python traceback" % tag)
        return
    if expect_fragment not in proc.stderr:
        fail("%s: stderr does not mention %r (got %r)"
             % (tag, expect_fragment, proc.stderr.strip()[:200]))
        return
    print("error-path %-26s -> rc=%d: %s"
          % (tag, proc.returncode, proc.stderr.strip().splitlines()[0][:110]))


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--g3-dir", required=True)
    ap.add_argument("--aot-gen", required=True)
    ap.add_argument("--tools", required=True)
    ap.add_argument("--python", required=True)
    ap.add_argument("--config", required=True,
                    help="tests/aot/g3/link_config.json")
    ap.add_argument("--readelf", default="llvm-readelf")
    ap.add_argument("--baseline", default=None)
    args = ap.parse_args(argv)

    aot_module = os.path.join(args.tools, "aot_module.py")
    checker = os.path.join(args.tools, "g3_link_check.py")
    guard = os.path.join(args.tools, "g2_gen_identity_check.py")
    config = args.config
    for path in (aot_module, checker, guard):
        if not os.path.exists(path):
            fail("missing tool %s" % path)
    if not os.path.exists(config):
        fail("missing fixture link config %s" % config)
    if FAILS:
        return 1

    tmp = tempfile.mkdtemp(prefix="mn_g3_errpaths_")
    try:
        # --- 1. truncated flat: the reference linker must report it cleanly.
        flats = os.path.join(tmp, "flats")
        os.makedirs(flats)
        for name in ("fx_main_v0", "fx_sub_v0", "fx_sdk_v0"):
            src = os.path.join(args.g3_dir, name + ".flat")
            dst = os.path.join(flats, name + ".flat")
            shutil.copyfile(src, dst)
            shutil.copyfile(os.path.join(args.g3_dir, name + ".layout.json"),
                            os.path.join(flats, name + ".layout.json"))
        trunc = os.path.join(flats, "fx_sdk_v0.flat")
        with open(trunc, "r+b") as f:
            f.truncate(os.path.getsize(trunc) // 2)
        expect_clean_error(
            [args.python, aot_module, "link", "--config", config,
             "--dir", flats, "--variant", "v0",
             "--out-tsv", os.path.join(tmp, "x.tsv"),
             "--out-counters", os.path.join(tmp, "x.json")],
            "truncated-flat", "aot_module.py")

        # --- 2. truncated ELF into elf2flat.
        elf = os.path.join(args.g3_dir, "libfx_sdk_v0.so")
        bad_elf = os.path.join(tmp, "bad.so")
        with open(elf, "rb") as f:
            head = f.read(64)
        with open(bad_elf, "wb") as f:
            f.write(head)
        expect_clean_error(
            [args.python, aot_module, "elf2flat", "--elf", bad_elf,
             "--name", "bad", "--out-dir", tmp],
            "truncated-elf", "aot_module.py")

        # --- 3. malformed link config JSON for the independent checker.
        bad_cfg = os.path.join(tmp, "bad_config.json")
        with open(bad_cfg, "w", encoding="utf-8") as f:
            f.write('{"modules": [ this is not json')
        expect_clean_error(
            [args.python, checker, "--dir", args.g3_dir, "--config", bad_cfg,
             "--readelf", args.readelf],
            "bad-config-json", "g3_link_check.py")

        # --- 4. checker notices a tampered layout.json (review fix 7).
        lay_dir = os.path.join(tmp, "lay")
        os.makedirs(lay_dir)
        for name in ("fx_main_v0", "fx_sub_v0", "fx_sdk_v0"):
            for suffix in (".flat", ".layout.json"):
                shutil.copyfile(os.path.join(args.g3_dir, name + suffix),
                                os.path.join(lay_dir, name + suffix))
            shutil.copyfile(os.path.join(args.g3_dir, "lib" + name + ".so"),
                            os.path.join(lay_dir, "lib" + name + ".so"))
        lay_path = os.path.join(lay_dir, "fx_sdk_v0.layout.json")
        layout = json.load(open(lay_path, encoding="utf-8"))
        layout["bss_size"] += 8
        json.dump(layout, open(lay_path, "w", encoding="utf-8"), indent=2)
        expect_clean_error(
            [args.python, checker, "--dir", lay_dir, "--config", config,
             "--variants", "v0", "--readelf", args.readelf],
            "tampered-layout", "layout.bss_size")

        # --- 4b. translator --guest-base must be 4 KiB aligned and inside the
        #         guest window [2^32, 2^39) (Minor 8): an image translated for
        #         a 4-byte-aligned or out-of-window base can never be mapped or
        #         bound, so it is refused at translate time.
        translate = os.path.join(args.tools, "aot_translate.py")
        main_flat = os.path.join(args.g3_dir, "fx_main_v0.flat")
        main_layout = os.path.join(args.g3_dir, "fx_main_v0.layout.json")
        main_entries = os.path.join(args.g3_dir, "fx_main_v0.entries.json")
        if not os.path.exists(translate):
            fail("missing tool %s" % translate)
        for tag, value in (("guest-base-misaligned", "0x1000000004"),
                           ("guest-base-below-window", "0x1000"),
                           ("guest-base-above-window", "0x8000000000")):
            expect_clean_error(
                [args.python, translate, "--module",
                 "--flat", main_flat, "--layout", main_layout,
                 "--entries", main_entries, "--guest-base", value,
                 "--name", "bad", "--out", os.path.join(tmp, "bad_blocks.c")],
                tag, "guest base")

        # --- 5. NEGATIVE CONTROL: the G2 identity guard must catch a
        #        non-provenance change (a semantic edit to generated code).
        if args.baseline:
            # Copy EXACTLY the files the identity guard checks: the G2
            # generated *.c listed in the baseline manifest. A tree walk of
            # aot_gen would read sibling tests' live scratch (e.g.
            # aot_differential_stage2 writes diff_cases/*.bin concurrently),
            # which is both unnecessary and a Windows sharing hazard.
            gen = os.path.join(tmp, "gen")
            os.makedirs(gen)
            with open(args.baseline, encoding="utf-8") as bf:
                listed = [ln.split()[-1] for ln in bf
                          if ln.strip() and not ln.lstrip().startswith("#")]
            if not listed:
                fail("guard negative control: empty baseline manifest")
            for name in listed:
                shutil.copyfile(os.path.join(args.aot_gen, name),
                                os.path.join(gen, name))
            # Rewrite one REAL code line; the two provenance lines stay.
            with open(os.path.join(gen, "mut_wrongcond.c"), "rb") as f:
                text = f.read()
            mutated = text.replace(b"case AOT_COND_EQ: return z == 0ull;",
                                   b"case AOT_COND_EQ: return z == 1ull;")
            if mutated == text:
                fail("guard negative control: the mutation did not land")
            with open(os.path.join(gen, "mut_wrongcond.c"), "wb") as f:
                f.write(mutated)
            proc = run([args.python, guard, "--dir", gen,
                        "--baseline", args.baseline])
            if proc.returncode == 0:
                fail("guard negative control: a semantic change was ACCEPTED")
            elif (proc.stdout.count("FAIL ") != 1 or
                  "FAIL mut_wrongcond.c" not in proc.stdout):
                fail("guard negative control: wrong failure message %r"
                     % proc.stdout.strip()[:160])
            else:
                print("guard-negative-control   -> rejected: %s"
                      % proc.stdout.strip().splitlines()[0][:100])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if FAILS:
        print("g3_error_paths_test: %d failure(s)" % len(FAILS))
        return 1
    print("g3_error_paths_test: all error paths typed and the identity guard "
          "rejects a semantic change")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
