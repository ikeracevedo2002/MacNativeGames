#!/usr/bin/env python3
"""G3 increment 3 brief F driver: EXEC negative controls.

Every mutant executable below is the SAME execution probe built with ONE
deliberately wrong implementation (a MODULE-mode translator mutant, or a
loader/program compile define). Each must be REJECTED by its SPECIFIC check:

    - exit code 2 (the probe's "a semantic check failed" code), and
    - the exact failing-check text that the wrong implementation must trip.

A mutant that exits 0 is a SURVIVOR: the check it targets is vacuous.
Anything else (missing binary, crash, exit 1 = infrastructure, timeout) is
counted as an INFRA failure, never as a pass.

The unmutated probe is also run as a control: if it does not pass, the whole
driver is meaningless.

Usage: g3_exec_mutant_test.py --exe-dir <dir with the probe binaries>
                             --fixtures <aot_gen/g3 dir>
Exit: 0 = all mutants rejected + control passes, 1 = survivor/control
failure, 2 = infrastructure failure.
"""

import argparse
import os
import subprocess
import sys

CASES = [
    dict(
        exe="aot_g3_exec_probe_mut_adrp_offset",
        what="translator mutant adrp_offset (ADRP paged from the module "
             "offset, not the guest VA)",
        must=("FAIL: main_scn_calls returns cleanly",),
    ),
    dict(
        exe="aot_g3_exec_probe_mut_orr_noshift",
        what="translator mutant orr_noshift (ORR shifted register drops the "
             "shift amount)",
        must=("FAIL: ORR shifted register honours the shift amount",),
    ),
    dict(
        exe="aot_g3_exec_probe_mut_stp_split",
        what="translator mutant stp_split (the pre-Major-1 two-store STP "
             "lowering, which partially writes a page-straddling pair)",
        must=("FAIL: the fault reports the PAIR's base address, not base+8",
              "FAIL: a faulting straddling STP wrote ZERO bytes of the RW "
              "page"),
    ),
    dict(
        exe="aot_g3_exec_probe_mut_init_array_walk",
        what="program mutant INIT_ARRAY_WALK (the loader ALSO walks "
             "DT_INIT_ARRAY on top of the guest DT_INIT)",
        must=("FAIL: the ctor log holds exactly five markers",
              "FAIL: global ctor order[2] == 2"),
    ),
    dict(
        exe="aot_g3_exec_probe_mut_image_unbound",
        what="program mutant IMAGE_UNBOUND (build_program skips the "
             "image<->descriptor flat SHA-256 binding)",
        must=("FAIL: a mismatched image/descriptor pairing is refused "
              "(SHA256)",),
    ),
]


def run(exe, fixtures):
    try:
        p = subprocess.run([exe, fixtures], capture_output=True, text=True,
                           timeout=300)
    except subprocess.TimeoutExpired:
        return None, "timeout"
    except OSError as e:
        return None, "cannot run %s: %r" % (exe, e)
    return p, ""


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe-dir", required=True)
    ap.add_argument("--fixtures", required=True)
    args = ap.parse_args(argv)

    exe_dir = args.exe_dir
    control = os.path.join(exe_dir, "aot_g3_exec_probe.exe")
    if not os.path.exists(control):
        sys.stderr.write("INFRA-ERROR: missing control probe %s\n" % control)
        return 2

    # Control: the unmutated probe must PASS, otherwise every "rejection"
    # below could be meaningless.
    proc, err = run(control, args.fixtures)
    if proc is None:
        sys.stderr.write("INFRA-ERROR: %s\n" % err)
        return 2
    if proc.returncode != 0:
        sys.stdout.write(proc.stdout)
        sys.stdout.write(proc.stderr)
        sys.stdout.write("FAIL: the UNMUTATED control probe did not pass "
                         "(exit %d)\n" % proc.returncode)
        return 1
    sys.stdout.write("control: unmutated aot_g3_exec_probe passes\n")

    rejected = 0
    survivors = []
    infra = 0
    for case in CASES:
        exe = os.path.join(exe_dir, case["exe"] + ".exe")
        if not os.path.exists(exe):
            sys.stderr.write("INFRA-ERROR: missing mutant binary %s\n" % exe)
            infra += 1
            continue
        proc, err = run(exe, args.fixtures)
        if proc is None:
            if err == "timeout":
                sys.stdout.write("INFRA: %s timed out (not a rejection)\n"
                                 % case["exe"])
            else:
                sys.stdout.write("INFRA: %s\n" % err)
            infra += 1
            continue
        out = proc.stdout + proc.stderr
        # Any "FAIL:" line other than the expected ones, or exit 1 (FATAL),
        # means the mutant was caught by the WRONG check or by an
        # infrastructure failure: not evidence for the target check.
        hits = [m for m in case["must"] if m in out]
        if proc.returncode == 1:
            sys.stdout.write(proc.stdout)
            sys.stdout.write("INFRA: %s exited 1 (infrastructure/FATAL)\n"
                             % case["exe"])
            infra += 1
            continue
        if proc.returncode == 0:
            survivors.append(case)
            sys.stdout.write(proc.stdout)
            sys.stdout.write("SURVIVOR: %s\n" % case["what"])
            continue
        if proc.returncode != 2 or not hits:
            sys.stdout.write(proc.stdout)
            sys.stdout.write("FAIL: %s was rejected by the WRONG check "
                             "(exit %d, expected text %r)\n"
                             % (case["what"], proc.returncode,
                                case["must"]))
            survivors.append(case)
            continue
        rejected += 1
        sys.stdout.write("REJECTED (%s, exit 2) by: %s\n"
                         % (case["what"], ", ".join(case["must"])))

    sys.stdout.write("g3 exec mutants: %d rejected, %d survivor(s), "
                     "%d infra failure(s)\n"
                     % (rejected, len(survivors), infra))
    if infra:
        return 2
    if survivors:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
