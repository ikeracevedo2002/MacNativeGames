#!/usr/bin/env python3
"""D024 Stage C prerequisite (plan 1.2.6): hash-bound catalog verification.

Hermetic (no game data, no MSVC).  The fixture is the one used by
`g3_fde_emit_test.py` (`build_fixture`): llvm-mc + ld.lld, flattened by
`aot_module.elf2flat`.  Every step runs through the real CLI entry point
`g3_fde_emit.main([...])`, in-process, with stdout/stderr captured.

Checks:
  * catalog build; `table --verify-mode regenerate --write-receipt` -> C/JSON A;
  * `table --verify-mode bound --receipt` -> C/JSON byte-identical to A;
  * the bound run never regenerates: `_catalog_from_bounds` is replaced by a
    tripwire for that run only (the same tripwire MUST fire on a regenerate
    run, which proves it is wired in);
  * plain regenerate (no new flags) -> byte-identical to A (regression);
  * negatives, each exactly `REFUSED <reason>` with exit 2:
      a catalog .c with one byte flipped         -> catalog-c-mismatch
      receipt with `tools` altered               -> catalog-receipt-mismatch
      receipt with `meta_sha256` altered         -> catalog-receipt-mismatch
      receipt file missing                       -> catalog-receipt-missing
      receipt file not JSON                      -> catalog-receipt-missing
      receipt with verified_by "bound"           -> catalog-receipt-mismatch
      receipt of a DIFFERENT valid catalog       -> catalog-receipt-mismatch
  * argparse errors (SystemExit 2): bound without --receipt, bound with
    --write-receipt, regenerate with --receipt, in-tree --write-receipt;
  * build_table with an unknown verify mode -> EmitError verify-mode-invalid.

Exit: 0 pass, 1 semantic failure, 2 infrastructure.
"""

import argparse
import contextlib
import io
import json
import os
import shutil
import sys
import tempfile

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
TOOLS = os.path.join(REPO, "tools", "aot")
if TOOLS not in sys.path:
    sys.path.insert(0, TOOLS)
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import aot_module as M                   # noqa: E402
import g3_fde_frontend as F              # noqa: E402
import g3_fde_emit as E                  # noqa: E402
import g3_fde_emit_test as GT            # noqa: E402

NAME = "fx"
ALL_WINDOWS = ("fx_entry", "fx_ctor", "fx_switch", "fx_unadmitted")
MIXED_WINDOWS = ("fx_ctor", "fx_switch", "fx_unadmitted")

FAILS = []
OKS = [0]


def check(cond, msg):
    if cond:
        OKS[0] += 1
        print("OK: %s" % msg)
    else:
        FAILS.append(msg)
        print("FAIL: %s" % msg)


class Infra(Exception):
    pass


def run_cli(argv):
    """-> (exit code, stdout, stderr) of one real `g3_fde_emit.main` call."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = E.main(argv)
        except SystemExit as exc:          # argparse errors
            rc = exc.code
    return rc, out.getvalue(), err.getvalue()


def read_bytes(path):
    with open(path, "rb") as handle:
        return handle.read()


def read_json(path):
    return json.loads(read_bytes(path).decode("utf-8"))


def write_json(path, obj):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(obj, handle, indent=1, sort_keys=True)


def catalog_argv(fx, names, out_c, out_j):
    starts = ",".join("0x%x" % fx["window"][n][0] for n in names)
    return ["catalog", "--flat", fx["flat_path"],
            "--layout", fx["layout_path"],
            "--guest-base", "0x%x" % GT.BASE, "--name", NAME,
            "--manifest", fx["manifest_path"], "--select", starts,
            "--out-c", out_c, "--out-json", out_j]


def table_argv(fx, cat_j, cat_c, out_c, out_j, extra=()):
    return ["table", "--flat", fx["flat_path"],
            "--layout", fx["layout_path"],
            "--guest-base", "0x%x" % GT.BASE, "--name", NAME,
            "--entries", fx["entries_path"],
            "--catalog-json", cat_j, "--catalog-c", cat_c,
            "--out-c", out_c, "--out-json", out_j] + list(extra)


def expect_refused(label, argv, reason, detail=None):
    rc, out, err = run_cli(argv)
    check(rc == 2 and out == "REFUSED %s\n" % reason,
          "%s: exit 2 and stdout 'REFUSED %s' (got rc=%r stdout=%r)"
          % (label, reason, rc, out))
    if detail is not None:
        check(detail in err,
              "%s: stderr names the differing part %r" % (label, detail))


def expect_argparse_error(label, argv):
    rc, out, err = run_cli(argv)
    check(rc == 2 and out == "" and "error:" in err,
          "%s: argparse error, exit 2 (got rc=%r)" % (label, rc))


def run(work, llvm):
    fx = GT.build_fixture(work, llvm, M, F)
    d = lambda *p: os.path.join(work, *p)   # noqa: E731

    # --- catalog A (all four windows) and catalog B (a different selection).
    cat_a_c, cat_a_j = d("a_cat.c"), d("a_cat.json")
    rc, _o, err = run_cli(catalog_argv(fx, ALL_WINDOWS, cat_a_c, cat_a_j))
    check(rc == 0, "catalog A (all four windows) builds (rc=%r %s)"
          % (rc, err.strip()))
    cat_b_c, cat_b_j = d("b_cat.c"), d("b_cat.json")
    rc, _o, err = run_cli(catalog_argv(fx, MIXED_WINDOWS, cat_b_c, cat_b_j))
    check(rc == 0, "catalog B (mixed selection) builds (rc=%r %s)"
          % (rc, err.strip()))
    if FAILS:
        return

    # --- regenerate + --write-receipt -> A, receipt R_A.
    rec_a = d("a_receipt.json")
    tab_a_c, tab_a_j = d("a_tab.c"), d("a_tab.json")
    rc, out_regen, err = run_cli(table_argv(
        fx, cat_a_j, cat_a_c, tab_a_c, tab_a_j,
        ["--verify-mode", "regenerate", "--write-receipt", rec_a]))
    check(rc == 0, "table regenerate + --write-receipt OK (rc=%r %s)"
          % (rc, err.strip()))
    if rc != 0:
        return
    receipt_a = read_json(rec_a)
    check(receipt_a.get("kind") == "catalog-receipt"
          and receipt_a.get("schema_version") == 1
          and receipt_a.get("verified_by") == "regenerate",
          "receipt A has kind/schema/verified_by of a regenerate receipt")
    golden_c = read_bytes(tab_a_c)
    golden_j = read_bytes(tab_a_j)

    # --- regression: plain regenerate, no new flags, same bytes as A.
    tab_r_c, tab_r_j = d("r_tab.c"), d("r_tab.json")
    rc, out_plain, err = run_cli(table_argv(fx, cat_a_j, cat_a_c,
                                            tab_r_c, tab_r_j))
    check(rc == 0 and read_bytes(tab_r_c) == golden_c
          and read_bytes(tab_r_j) == golden_j and out_plain == out_regen,
          "plain regenerate (no new flags) is byte-identical to A")

    # --- bound + --receipt -> byte-identical to A.
    tab_b_c, tab_b_j = d("b_tab.c"), d("b_tab.json")
    rc, out_bound, err = run_cli(table_argv(
        fx, cat_a_j, cat_a_c, tab_b_c, tab_b_j,
        ["--verify-mode", "bound", "--receipt", rec_a]))
    check(rc == 0, "table bound + --receipt OK (rc=%r %s)"
          % (rc, err.strip()))
    check(rc == 0 and read_bytes(tab_b_c) == golden_c,
          "bound table C is byte-identical to A")
    check(rc == 0 and read_bytes(tab_b_j) == golden_j,
          "bound table JSON is byte-identical to A")
    check(out_bound == out_regen, "bound stdout equals regenerate stdout")

    # --- the bound run never regenerates; the tripwire must fire on regenerate.
    real_cfb = E._catalog_from_bounds
    calls = []

    def tripwire(*args, **kwargs):
        calls.append(1)
        raise AssertionError("catalog regenerated")

    E._catalog_from_bounds = tripwire
    try:
        tab_t_c, tab_t_j = d("t_tab.c"), d("t_tab.json")
        rc, _o, err = run_cli(table_argv(
            fx, cat_a_j, cat_a_c, tab_t_c, tab_t_j,
            ["--verify-mode", "bound", "--receipt", rec_a]))
        check(rc == 0 and not calls,
              "bound verification does not regenerate the catalog "
              "(tripwire silent, rc=%r)" % rc)
        fired = False
        try:
            E.main(table_argv(fx, cat_a_j, cat_a_c, d("t2_tab.c"),
                              d("t2_tab.json")))
        except AssertionError:
            fired = True
        check(fired and bool(calls),
              "negative control: the tripwire fires on a regenerate run")
    finally:
        E._catalog_from_bounds = real_cfb

    # --- negatives.  Each receipt is a fresh copy of R_A, altered in one way.
    def bound_argv(catalog_c_path, receipt_path, tag):
        return table_argv(fx, cat_a_j, catalog_c_path, d("n_%s_tab.c" % tag),
                          d("n_%s_tab.json" % tag),
                          ["--verify-mode", "bound", "--receipt",
                           receipt_path])

    def altered(tag, mutate):
        path = d("n_%s_receipt.json" % tag)
        obj = json.loads(json.dumps(receipt_a))
        mutate(obj)
        write_json(path, obj)
        return path

    # a) one byte of the catalog C flipped, metadata unchanged.
    flipped_c = d("n_flip_cat.c")
    data = bytearray(read_bytes(cat_a_c))
    pos = data.index(b"aot_cand_identity_%s[]" % NAME.encode("ascii"))
    data[pos] ^= 0x20        # 'a' -> 'A': still ASCII, still valid UTF-8
    with open(flipped_c, "wb") as handle:
        handle.write(bytes(data))
    expect_refused("a) flipped catalog byte", bound_argv(flipped_c, rec_a,
                                                         "a"),
                   "catalog-c-mismatch")

    def set_tools(obj):
        obj["tools"]["emitter"] = "0" * 64

    expect_refused("b) receipt tools altered",
                   bound_argv(cat_a_c, altered("b", set_tools), "b"),
                   "catalog-receipt-mismatch", detail="tools")

    def set_meta(obj):
        obj["meta_sha256"] = "1" * 64

    expect_refused("c) receipt meta_sha256 altered",
                   bound_argv(cat_a_c, altered("c", set_meta), "c"),
                   "catalog-receipt-mismatch", detail="meta_sha256")

    expect_refused("d) receipt file missing",
                   bound_argv(cat_a_c, d("does_not_exist.json"), "d"),
                   "catalog-receipt-missing")

    bad_json = d("n_e_receipt.json")
    with open(bad_json, "w", encoding="utf-8") as handle:
        handle.write("{not json")
    expect_refused("e) receipt file not JSON",
                   bound_argv(cat_a_c, bad_json, "e"),
                   "catalog-receipt-missing")

    def set_bound(obj):
        obj["verified_by"] = "bound"

    expect_refused("f) receipt verified_by 'bound'",
                   bound_argv(cat_a_c, altered("f", set_bound), "f"),
                   "catalog-receipt-mismatch", detail="verified_by")

    # g) receipt of a DIFFERENT valid catalog, used with catalog A.
    rec_b = d("b_receipt.json")
    tab_bb_c, tab_bb_j = d("bb_tab.c"), d("bb_tab.json")
    rc, _o, err = run_cli(table_argv(
        fx, cat_b_j, cat_b_c, tab_bb_c, tab_bb_j,
        ["--verify-mode", "regenerate", "--write-receipt", rec_b]))
    check(rc == 0 and os.path.exists(rec_b),
          "receipt B produced by a regenerate table build of catalog B "
          "(rc=%r %s)" % (rc, err.strip()))
    expect_refused("g) receipt from a different catalog",
                   bound_argv(cat_a_c, rec_b, "g"),
                   "catalog-receipt-mismatch", detail="catalog_identity")

    # --- argparse errors.
    expect_argparse_error("h) bound without --receipt", table_argv(
        fx, cat_a_j, cat_a_c, d("h_tab.c"), d("h_tab.json"),
        ["--verify-mode", "bound"]))
    expect_argparse_error("i) bound with --write-receipt", table_argv(
        fx, cat_a_j, cat_a_c, d("i_tab.c"), d("i_tab.json"),
        ["--verify-mode", "bound", "--receipt", rec_a,
         "--write-receipt", d("i_receipt.json")]))
    expect_argparse_error("j) regenerate with --receipt", table_argv(
        fx, cat_a_j, cat_a_c, d("j_tab.c"), d("j_tab.json"),
        ["--receipt", rec_a]))
    in_tree = os.path.join(REPO, "tests", "aot", "_g3_receipt_should_not_exist")
    expect_argparse_error("k) in-tree --write-receipt refused", table_argv(
        fx, cat_a_j, cat_a_c, d("k_tab.c"), d("k_tab.json"),
        ["--write-receipt", in_tree]))
    check(not os.path.exists(in_tree),
          "k) no file was created inside the source tree")

    # --- build_table rejects an unknown verify mode (not reachable via CLI).
    try:
        E.build_table(fx["flat"], fx["layout"], GT.BASE, NAME,
                      [fx["fx_entry"]], read_json(cat_a_j),
                      read_bytes(cat_a_c).decode("utf-8"), True,
                      verify_mode="bogus")
        check(False, "unknown verify mode is refused")
    except E.EmitError as exc:
        check(exc.reason == "verify-mode-invalid",
              "unknown verify mode -> EmitError verify-mode-invalid")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--llvm", default=os.environ.get("AOT_LLVM_BIN", ""),
                        help="directory holding llvm-mc.exe and ld.lld.exe")
    args = parser.parse_args(argv)
    if not args.llvm:
        sys.stderr.write("g3_fde_emit_receipt_test: --llvm is required\n")
        return 2
    work = tempfile.mkdtemp(prefix="g3_emit_receipt_")
    try:
        run(work, args.llvm)
    except (GT.Infra, RuntimeError, OSError) as exc:
        sys.stderr.write("g3_fde_emit_receipt_test: infrastructure: %s\n"
                         % exc)
        return 2
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if FAILS:
        print("FAIL: %d g3_fde_emit_receipt check(s)" % len(FAILS))
        return 1
    print("PASS: g3_fde_emit_receipt (%d checks)" % OKS[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
