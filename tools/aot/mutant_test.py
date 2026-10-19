#!/usr/bin/env python3
"""G2 negative controls: real-lowering mutants must be REJECTED by the same
differential comparator used by the normal suite.

For every mutant image we run the real native runner (must exit 0 with a
parseable, well-formed output) and the independent Unicorn oracle, then use
diff_driver.cmp_case.  A compiler failure, native nonzero exit/crash, timeout,
malformed output, or an oracle trap is an INFRASTRUCTURE FAILURE and the test
fails; it is never counted as a successful rejection.  Only the specific,
intended mismatch (or, for the pair32 truncation, the specific bad-translation
guest FAULT) counts as a rejection.
"""

import argparse
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def load_driver():
    spec = importlib.util.spec_from_file_location(
        "dd", os.path.join(HERE, "diff_driver.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# mutant exe stem -> (case name, intended mismatch token)
MUTANTS = {
    "wrongcarry": ("adds_imm", "nzcv"),
    "lostwzeroext": ("subs32", "x1"),
    "wrongcond": ("cond_eq_n0100", "x1"),
    "blrorder": ("blr_x30_capture", "x0"),
    "strdrop": ("str_ldr64", "x2"),
    "scalarupper": ("fmov_d", "v0"),
    "hlex18": ("svc_case", "x18"),
    "fpdropflags": ("fdiv_d", "fpsr"),
    "stxalwaysok": ("stxr_x", "x3"),
    "fproundrn": ("fdiv_s_one_third_rm", "v0"),
    "fpnanorder": ("fadd_s_qnan_op1_preferred", "v0"),
}


def run_one(dd, exe, case, bin_bytes, blocks, th, work, idx):
    in_path = os.path.join(work, "in_%d.bin" % idx)
    out_path = os.path.join(work, "out_%d.bin" % idx)
    nat = dd.native_run(exe, case, in_path, out_path)
    orc = dd.oracle_run(case, bin_bytes, blocks, th.get("base", 0),
                        th.get("count", 0), th.get("stride", 0),
                        case.get("guest_base", dd.GUEST_BASE))
    return nat, orc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exedir", required=True)
    ap.add_argument("--bin", required=True)
    ap.add_argument("--meta", required=True)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--work", required=True)
    args = ap.parse_args()
    os.makedirs(args.work, exist_ok=True)

    dd = load_driver()
    with open(args.bin, "rb") as f:
        bin_bytes = f.read()
    with open(args.meta) as f:
        meta = json.load(f)
    meta_starts = set(b["pc"] for b in meta["blocks"])
    import reference_cfg
    with open(args.manifest) as f:
        man = json.load(f)
    blocks = reference_cfg.derive_starts(
        bin_bytes, [tuple(r) for r in man["ranges"]],
        list(man["entries"]), list(man.get("indirect_targets", [])))
    if blocks != meta_starts:
        print("FAIL: independent Capstone CFG != meta blocks")
        return 2
    if "thunks" not in man:
        print("FAIL: manifest missing required thunks")
        return 2
    mth = man["thunks"]
    th = {"base": int(mth["base"]), "count": int(mth["count"]),
          "stride": int(mth["stride"])}
    mmeta = meta.get("thunks", {})
    if (th["base"], th["count"], th["stride"]) != (
            mmeta.get("base"), mmeta.get("count"), mmeta.get("stride")):
        print("FAIL: manifest thunks %r != meta thunks %r" % (th, mmeta))
        return 2

    cases = {c["name"]: c for c in dd.make_cases()}
    failures = []
    results = []
    idx = 0
    for name, (case_name, token) in MUTANTS.items():
        exe = os.path.join(args.exedir, "aot_mut_%s.exe" % name)
        case = cases[case_name]
        try:
            nat, orc = run_one(dd, exe, case, bin_bytes, blocks, th, args.work, idx)
        except Exception as e:   # infra: crash/timeout/nonzero/bad output/oracle trap
            failures.append("%s: INFRA %r" % (name, e))
            continue
        idx += 1
        if orc["fault"]["code"]:
            failures.append("%s: oracle trap %r (infra)" % (name, orc["fault"]["code"]))
            continue
        if nat["exit"] != 10:    # AOT_EXIT_STOP
            failures.append("%s: native exit=%d (expected STOP)" % (name, nat["exit"]))
            continue
        errs, kind = dd.cmp_case(case, nat, orc)
        if not errs:
            failures.append("%s: NO mismatch (mutant not rejected)" % name)
            continue
        if not any(e.startswith(token + " ") for e in errs):
            failures.append("%s: mismatch not the intended %r: %s"
                            % (name, token, "; ".join(errs[:3])))
            continue
        results.append((name, case_name, errs[0]))

    # pair32 truncation: bad translation must FAULT (MEMORY) at the guest
    # address, not STOP; explicitly assert the exact fault fields.
    name = "pair32trunc"
    exe = os.path.join(args.exedir, "aot_mut_%s.exe" % name)
    case = cases["pair32_wb_high"]
    try:
        nat, orc = run_one(dd, exe, case, bin_bytes, blocks, th, args.work, idx)
    except Exception as e:
        failures.append("%s: INFRA %r" % (name, e))
    else:
        if orc["fault"]["code"]:
            failures.append("%s: oracle trap %r (infra)" % (name, orc["fault"]["code"]))
        elif nat["exit"] != 11 or nat["fault"] != 3:   # FAULT / AOT_FAULT_MEMORY
            failures.append("%s: expected guest FAULT(11)/MEMORY(3), got exit=%d fault=%d"
                            % (name, nat["exit"], nat["fault"]))
        elif nat["fault_target"] != 0xF8 or nat["fault_src"] != 0x1744:
            failures.append("%s: expected fault_src=0x1744 target=0xf8, got src=0x%x target=0x%x"
                            % (name, nat["fault_src"], nat["fault_target"]))
        elif not dd.cmp_case(case, nat, orc)[0]:
            # Same comparator as the other mutants: the normal case expects a
            # clean STOP, so a fault MUST be reported as a mismatch.
            failures.append("%s: cmp_case reported no mismatch" % name)
        else:
            results.append((name, "pair32_wb_high",
                            "FAULT mem src=0x%x target=0x%x"
                            % (nat["fault_src"], nat["fault_target"])))

    for name, cname, msg in results:
        print("REJECTED %-13s case=%-18s %s" % (name, cname, msg))
    expected = len(MUTANTS) + 1   # + pair32trunc (separate fault-path control)
    if len(results) != expected:
        failures.append("expected exactly %d rejections, got %d"
                        % (expected, len(results)))
    for f in failures:
        print("  FAIL " + f)
    print("aot mutants: rejected=%d infra_failures=%d" % (len(results), len(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
