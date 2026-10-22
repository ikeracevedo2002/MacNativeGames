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
    # ---- boot heap window (tests/aot/aot_as_heap_probe.c) ----
    # Each expected string is the FIRST semantic failure the control produces.
    "aot_as_heap_mut_info5_size": (
        "aot_as_heap_probe",
        "heap_info reports base/max/logical size",
    ),
    "aot_as_heap_mut_shrink_decommit": (
        "aot_as_heap_probe",
        # Decommitting [0,2MiB) discards the retained bytes, so the immediate
        # regrow cannot re-protect them (host_vm_protect rejects RESERVE pages).
        "regrow to 2 MiB succeeds",
    ),
    "aot_as_heap_mut_no_monitor_invalidate": (
        "aot_as_heap_probe",
        "successful shrink/regrow invalidates another token reservation",
    ),
    "aot_as_heap_mut_recommit_retained": (
        "aot_as_heap_probe",
        # The monitor scenario regrows from 0 while high-water is 2 MiB, so the
        # retained prefix is committed and the recommit is rejected there first.
        "regrow to 2 MiB succeeds",
    ),
    "aot_as_heap_mut_hw_as_used": (
        "aot_as_heap_probe",
        "grow to the window maximum succeeds",
    ),
    # This control is only observable with an injected host failure, so its
    # positive baseline is the SAME fault mode (fault_4), not the normal probe.
    "aot_as_heap_mut_publish_before_host": (
        "aot_as_heap_fault_4",
        "failed shrink leaves logical size unchanged",
    ),
    "aot_as_heap_mut_no_desync": (
        "aot_as_heap_fault_3",
        "rollback failure is sticky fail-closed",
    ),
    "aot_as_heap_mut_publish_on_commit_fail": (
        "aot_as_heap_fault_1",
        "failed fresh commit leaves logical size unchanged",
    ),
    # ---- Immutable alias reserved window ----
    "aot_as_alias_mut_query_state5": (
        "aot_as_alias_probe",
        "alias whole window queries Free/NONE/attr0",
    ),
    "aot_as_alias_mut_range_omit": (
        "aot_as_alias_probe",
        "alias first 16 bytes are claimed",
    ),
    "aot_as_alias_mut_heap_selects": (
        "aot_as_alias_probe",
        "heap_info selects the heap window, not alias",
    ),
    # A failed permission pre-check must still consume the reservation, so a
    # later SC to the original RW address must report status 1 without LDXR.
    "aot_as_alias_mut_keep_monitor_on_perm_fail": (
        "aot_as_alias_probe",
        "denied SC consumed the monitor",
    ),
    # ---- physical alias map/unmap (tests/aot/aot_as_alias_map_probe.c) ----
    # Each expected string is the FIRST semantic failure the control produces,
    # which is also why the baseline for a fault-seam control is its own fault
    # build: the normal probe never reaches the injected refusal.
    "aot_as_alias_map_mut_charge_all": (
        "aot_as_alias_map_probe",
        "a grow over an owned range is not charged twice",
    ),
    "aot_as_alias_map_mut_keep_stale": (
        "aot_as_alias_map_probe",
        "a re-mapped released page reads zero",
    ),
    "aot_as_alias_map_mut_keep_mapped": (
        "aot_as_alias_map_probe",
        "a released page joins the maximal Free run before it",
    ),
    "aot_as_alias_map_mut_query_no_run": (
        "aot_as_alias_map_probe",
        "an entirely unmapped alias window is one Free run",
    ),
    "aot_as_alias_map_mut_no_budget": (
        "aot_as_alias_map_probe",
        "a fresh page over the pool is LimitReached",
    ),
    "aot_as_alias_map_mut_omit_usage": (
        "aot_as_alias_map_probe",
        "usage reports the mapped alias bytes and the heap size",
    ),
    "aot_g3_start_hle_mut_info_const": (
        "aot_g3_start_hle_heap_probe",
        "Info2 returns the AS alias base, not a constant",
    ),
    # Positive baseline expects the real STACK role; returning ALIAS is wrong.
    "aot_g3_start_hle_mut_info14_alias": (
        "aot_g3_start_hle_heap_probe",
        "Info14 returns the AS stack arena base, not a constant",
    ),
    # Whole-domain QueryMemory: exact semantic failures, not arbitrary nonzero.
    "aot_as_domain_mut_low_from_addr": (
        "aot_as_query_domain_probe", "domain low interval",
    ),
    "aot_as_domain_mut_gap_page": (
        "aot_as_query_domain_probe", "domain interval",
    ),
    "aot_as_domain_mut_above_free": (
        "aot_as_query_domain_probe", "domain upper interval",
    ),
    "aot_g3_query_mut_partial_store": (
        "aot_g3_start_hle_query_probe",
        "committed/free cross span fails whole and preserves the prefix",
    ),
    "aot_g3_query_mut_mapped_only": (
        "aot_g3_start_hle_query_probe", "zero lower Free record",
    ),
    "aot_g3_start_hle_mut_sysres_const": (
        "aot_g3_start_hle_probe", "configured system resource limit",
    ),
    # ---- alias SVC 0x2c/0x2d (tests/aot/aot_g3_start_hle_alias_probe.c) ----
    "aot_g3_start_hle_mut_alias_limit_code": (
        "aot_g3_start_hle_alias_probe",
        "a fresh page over the pool is 0x10801",
    ),
    "aot_g3_start_hle_mut_alias_clobber": (
        "aot_g3_start_hle_alias_probe",
        "grow over an owned prefix succeeds",
    ),
    "aot_g3_start_hle_mut_alias_no_unmap": (
        "aot_g3_start_hle_alias_probe",
        "unmap reduces the mapped-page counter",
    ),
    "aot_g3_start_hle_mut_budget_omit_alias": (
        "aot_g3_start_hle_alias_probe",
        "id7 charges the mapped alias bytes",
    ),
    # ---- Mac host overrides (tests/aot/aot_g3_start_hle_override_probe.c) ----
    # A void override must write NO guest register: fabricating x0=0 breaks the
    # first void row (oe Initialize). CountAddOnContent must return 0.
    "aot_g3_start_hle_mut_override_x0": (
        "aot_g3_start_hle_override_probe",
        "oe Initialize leaves every guest register, flag and byte unchanged",
    ),
    "aot_g3_start_hle_mut_override_count": (
        "aot_g3_start_hle_override_probe",
        "CountAddOnContent returns 0 in x0 and changes nothing else",
    ),
    # The byte witness must be non-vacuous: the same production write path
    # (aot_as_write at the caller's x0) is exercised by this control.
    "aot_g3_start_hle_mut_override_write": (
        "aot_g3_start_hle_override_probe",
        "oe Initialize writes no guest byte",
    ),
    # SetCpuBoostMode's Mac body is void for modes 0/1/2, so a control that only
    # drops the runtime_fail range check still passes every VALID row; it must be
    # caught by the first out-of-range mode row instead.
    "aot_g3_start_hle_mut_skip_boost_range": (
        "aot_g3_start_hle_override_probe",
        "CPU boost rejects mode -1",
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
            # The probe suite has two documented success spellings: the
            # "<probe>: all checks passed" summary and a final "PASS: <name>"
            # line (e.g. tests/aot/g3_start_hle_probe.c). Exit 0 plus one of
            # them is a real pass; a FAIL/FATAL line always disqualifies it.
            passed_line = any(line.startswith("PASS: ")
                              for line in out.splitlines())
            bad = any(line.startswith("FAIL:") or line.startswith("FATAL:")
                      for line in out.splitlines())
            if not (passed_line and not bad):
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
