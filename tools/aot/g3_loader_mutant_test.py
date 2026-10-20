#!/usr/bin/env python3
"""G3 increment 2 (T4): loader mutant driver.

Each executable here is the SAME probe over a loader compiled with one
deliberately wrong rule (MN_AOT_MUTANT_* in src/aot/aot_loader.c). A mutant that
is NOT rejected means the corresponding probe check is vacuous, so every entry
must

  * exit with the semantic-failure code 2 (not 0, not a crash, not a timeout),
  * print a FAIL line containing the specific text of the check that owns that
    rule, and
  * never exit 1 (infrastructure) - that would mean the probe did not run.

Infrastructure problems (missing executable, timeout, unparsable output) are
counted separately from "mutant survived", because they mean the test did not
run at all. (The increment-1 runtime/address-space mutants have their own driver,
tools/aot/g3_mutant_test.py.)

Exit: 0 = every mutant was rejected by its expected check, 2 = at least one
mutant survived or failed with the wrong message, 1 = infrastructure failure.
"""
import argparse
import os
import subprocess
import sys

# (mutant, executable, expected substring of the first FAIL line, why)
MUTANTS = [
    ("symbol_first_any", "aot_g3_link_mut_SYMBOL_FIRST_ANY",
     "link-digest-mismatch",
     "a name lookup takes the FIRST match whatever its definition state, so the "
     "shadow variant's UNDEFINED STB_WEAK 'main_vtable' entry (index 6) wins "
     "over the definition at index 54 and the three sites that reference it "
     "resolve to 0 instead of the module VA"),
    ("relative_no_base", "aot_g3_link_mut_relative_no_base",
     "link-digest-mismatch",
     "RELATIVE sites lose the module base, so the sealed data segment differs "
     "from the offline digest"),
    ("abs64_no_addend", "aot_g3_link_mut_abs64_no_addend",
     "link-digest-mismatch",
     "ABS64/GLOB_DAT sites drop S+A, so the data segment digest differs"),
    ("global_first", "aot_g3_link_mut_global_first",
     "link-digest-mismatch",
     "sdk's own reference to shared_impl resolves to sub's definition, so the "
     "digest differs"),
    ("observer_all_kinds", "aot_g3_link_mut_observer_all_kinds",
     "link-digest-mismatch",
     "the nnMain address-taken slot receives the thunk VA instead of the real "
     "module VA"),
    ("trunc32", "aot_g3_link_mut_trunc32",
     "link-digest-mismatch",
     "every guest VA above 4 GiB is truncated, so the data segment differs"),
    ("thunk_per_module", "aot_g3_link_mut_thunk_per_module",
     "link-digest-mismatch",
     "host_hook resolves to a different thunk VA in main and sub, breaking "
     "thunk identity"),
    ("weak_strong_swap", "aot_g3_link_mut_weak_strong_swap",
     "unresolved-symbol",
     "the weak fx_missing_sym import becomes a hard error, so loading fails"),
    ("jumpslot_addend_accept", "aot_g3_neg_mut_jumpslot_addend_accept",
     "expected bad-relocation",
     "the negative JUMP_SLOT-with-addend fixture is accepted instead of "
     "rejected"),
    ("no_dup_check", "aot_g3_neg_mut_no_dup_check",
     "expected bad-relocation",
     "the duplicate RELR/RELA site is written twice instead of being "
     "rejected"),
    ("allow_table_overlap", "aot_g3_neg_mut_ALLOW_TABLE_OVERLAP",
     "reloc_into_dynamic: expected bad-relocation",
     "the negative fixture that relocates a RELATIVE site into .dynamic is "
     "accepted (the site/consumed-table overlap rule is skipped), so the "
     "loader writes a guest VA over a table it has already parsed"),
]


def first_fail(output):
    for line in output.splitlines():
        if line.startswith("FAIL:"):
            return line
    return ""


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--exedir", required=True)
    ap.add_argument("--dir", required=True,
                    help="fixture directory the link probe mutants need")
    ap.add_argument("--only", nargs="+", default=None)
    ap.add_argument("--timeout", type=int, default=180)
    args = ap.parse_args(argv)

    rejected = 0
    survived = 0
    wrong_check = 0
    infra = 0
    for name, exe, expected, why in MUTANTS:
        if args.only is not None and name not in args.only:
            continue
        path = os.path.join(args.exedir,
                            exe + (".exe" if os.name == "nt" else ""))
        if not os.path.isfile(path):
            infra += 1
            print("%-24s INFRA: missing executable %s" % (name, path))
            continue
        cmd = [path]
        if "neg" not in exe:
            cmd.append(args.dir)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=args.timeout)
        except subprocess.TimeoutExpired:
            infra += 1
            print("%-24s INFRA: timeout" % name)
            continue
        except OSError as exc:
            infra += 1
            print("%-24s INFRA: %s" % (name, exc))
            continue

        line = first_fail(proc.stdout)
        if proc.returncode == 1 or "FATAL:" in proc.stdout:
            infra += 1
            print("%-24s INFRA: infrastructure failure (%r)" % (name, line))
        elif proc.returncode == 0:
            survived += 1
            print("%-24s SURVIVED: mutant accepted (%s)" % (name, why))
        elif proc.returncode != 2:
            infra += 1
            print("%-24s INFRA: unexpected exit %d" % (name, proc.returncode))
        elif expected not in line:
            wrong_check += 1
            print("%-24s WRONG CHECK: %r (expected %r)"
                  % (name, line, expected))
        else:
            rejected += 1
            print("%-24s rejected: %s" % (name, line))

    total = rejected + survived + wrong_check
    print("\naot loader mutants: rejected=%d survived=%d wrong_check=%d "
          "infra=%d" % (rejected, survived, wrong_check, infra))
    if infra:
        return 1
    if survived or wrong_check:
        return 2
    if total == 0:
        print("aot loader mutants: nothing selected", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
