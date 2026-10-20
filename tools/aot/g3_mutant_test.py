#!/usr/bin/env python3
"""G3 increment 1 negative controls: runtime/address-space mutants must be
REJECTED by the same probes that the real build passes.

Each mutant is a separate executable built from the SAME shipping sources with
one test-only compile define (MN_AOT_MUTANT_*) that suppresses exactly one
behaviour (see the comments at each define in src/aot/). The probes use an exit
protocol that distinguishes the two failure classes:

    0 = every contract check passed
    2 = at least one SEMANTIC check failed, and every failure printed
        "FAIL: <check name>"
    1 = INFRASTRUCTURE failure ("FATAL: <reason>")

This driver is deliberately strict:

  * the real probe executable must exit 0 first, otherwise the mutants prove
    nothing and every mutant is reported as an infrastructure failure;
  * a mutant must exit with EXACTLY the semantic-failure code (2) and print the
    SPECIFIC failing check it is supposed to break;
  * a crash (negative exit status), a timeout, exit 1, a FATAL line, or a
    different first failure is an INFRASTRUCTURE failure, never a rejection.

Modelled on tools/aot/mutant_test.py (G2), which makes the same
infrastructure-vs-rejection distinction. No game data, no ARM bytes, no
translation: these are runtime contract probes only.
"""

import argparse
import os
import subprocess
import sys

# mutant executable stem -> (probe stem, the specific check it must break)
#
# The expected check is the FIRST semantic failure the mutant produces, so a
# mutant that breaks something unrelated is not silently accepted.
MUTANTS = {
    # ---- address space (tests/aot/aot_as_probe.c) ----
    "aot_as_mut_partial_store": (
        "aot_as_probe",
        "store across a RW->R page boundary writes zero bytes (first page)",
    ),
    "aot_as_mut_no_perm": (
        "aot_as_probe",
        "store to an R-only page is rejected",
    ),
    # Lead finding: the guest X bit must never be forwarded to the host mapping.
    # The mutant restores HOST_VM_PROT_EXEC for R-X pages, so the first semantic
    # check that breaks is the text page's host protection.
    "aot_as_mut_host_exec": (
        "aot_as_probe",
        "R-X text page has no HOST_VM_PROT_EXEC bit",
    ),
    # ---- Program runtime (tests/aot/aot_program_probe.c) ----
    "aot_prog_mut_thunk_site4": (
        "aot_program_probe",
        "thunk entered by BR (PLT stub) returns cleanly",
    ),
    "aot_prog_mut_resume_after": (
        "aot_program_probe",
        "handler x30 clobber does not affect control flow",
    ),
    "aot_prog_mut_no_depth_check": (
        "aot_program_probe",
        "sentinel reached at the wrong depth is BAD_RETURN",
    ),
    "aot_prog_mut_no_scratch_save": (
        "aot_program_probe",
        "nested call preserves outer dispatch scratch",
    ),
    "aot_prog_mut_reset_steps": (
        "aot_program_probe",
        "steps are shared and not reset by a nested call",
    ),
    # ---- Turn B mutant batch: each suppresses exactly one shipped guard ----
    "aot_prog_mut_handler_before_resume_check": (
        "aot_program_probe",
        "thunk with an invalid x30 is BAD_RESUME",
    ),
    "aot_prog_mut_drop_sticky": (
        "aot_program_probe",
        # The sticky test now runs BEFORE the depth probe and checks the guest
        # marker slot first, so the mutant's own intent fails first: with the
        # fault swallowed the outer resume block runs and writes the marker.
        "sticky inner fault left the outer marker slot alone",
    ),
    "aot_prog_mut_no_abi_check": (
        "aot_program_probe",
        "callee that clobbers x19 is ABI_VIOLATION",
    ),
    "aot_prog_mut_sysreg_xzr": (
        "aot_program_probe",
        "SYSREG Rt=31 write is discarded (XZR)",
    ),
    "aot_prog_mut_recall_after_fault": (
        "aot_program_probe",
        # With the guard removed the second nested call actually RUNS, so the
        # discriminating assertion is the step count (the return value still
        # reports the sticky fault, because rt->fault is never cleared).
        "second nested call after a sticky fault runs no block",
    ),
}

EXIT_OK = 0
EXIT_INFRA = 1
EXIT_SEMANTIC = 2


def run_exe(path, timeout):
    """Run one probe. Returns (exit_code, stdout, error_or_None)."""
    if not os.path.isfile(path):
        return None, "", "missing executable %s" % path
    try:
        proc = subprocess.run(
            [path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"),
        )
    except subprocess.TimeoutExpired:
        return None, "", "TIMEOUT after %ss" % timeout
    except OSError as exc:
        return None, "", "could not run %s: %r" % (path, exc)
    out = proc.stdout.decode("utf-8", "replace")
    return proc.returncode, out, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exedir", required=True,
                    help="directory containing the probe executables")
    ap.add_argument("--timeout", type=int, default=120,
                    help="per-executable timeout in seconds")
    args = ap.parse_args()

    failures = []
    results = []

    # ---- 1. the real probes must pass (otherwise nothing is proven) ----
    real_ok = {}
    for probe in sorted(set(p for p, _ in MUTANTS.values())):
        exe = os.path.join(args.exedir, probe + ".exe")
        code, out, err = run_exe(exe, args.timeout)
        if err is not None:
            failures.append("%s: INFRA %s" % (probe, err))
            continue
        if code != EXIT_OK:
            failures.append("%s: real build exited %r (expected 0)" % (probe, code))
            for line in out.splitlines():
                if line.startswith("FAIL:") or line.startswith("FATAL:"):
                    failures.append("%s:   %s" % (probe, line))
            continue
        if "all " not in out or "passed" not in out:
            failures.append("%s: real build printed no success summary" % probe)
            continue
        real_ok[probe] = True

    # ---- 2. every mutant must be rejected for the intended reason ----
    if not failures:
        for stem in sorted(MUTANTS):
            probe, expected = MUTANTS[stem]
            if probe not in real_ok:
                failures.append("%s: INFRA real %s not verified" % (stem, probe))
                continue
            exe = os.path.join(args.exedir, stem + ".exe")
            code, out, err = run_exe(exe, args.timeout)
            if err is not None:
                failures.append("%s: INFRA %s" % (stem, err))
                continue
            if code != EXIT_SEMANTIC:
                # 0 = mutant not detected; 1 = the probe itself broke;
                # anything else = crash. All are infrastructure failures.
                failures.append(
                    "%s: INFRA exit=%r (expected semantic failure %d)"
                    % (stem, code, EXIT_SEMANTIC))
                continue
            lines = out.splitlines()
            if any(line.startswith("FATAL:") for line in lines):
                failures.append("%s: INFRA probe reported FATAL" % stem)
                continue
            fails = [line[len("FAIL: "):] for line in lines
                     if line.startswith("FAIL: ")]
            if not fails:
                failures.append("%s: INFRA exit 2 without a FAIL line" % stem)
                continue
            if fails[0] != expected:
                failures.append(
                    "%s: rejected for the wrong reason: first=%r expected=%r"
                    % (stem, fails[0], expected))
                continue
            results.append((stem, probe, fails[0], len(fails)))

    for stem, probe, check, total in results:
        print("REJECTED %-28s probe=%-18s checks_failed=%d" % (stem, probe, total))
        print("         first: %s" % check)

    expected_count = len(MUTANTS)
    if len(results) != expected_count:
        failures.append("expected exactly %d rejections, got %d"
                        % (expected_count, len(results)))
    for f in failures:
        print("  FAIL " + f)
    print("aot g3 mutants: rejected=%d infra_failures=%d"
          % (len(results), len(failures)))
    return EXIT_INFRA if failures else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
