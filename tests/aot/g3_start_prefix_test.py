#!/usr/bin/env python3
"""Game-data-free deterministic tests for g3_start_prefix STOP classification."""

import sys

sys.dont_write_bytecode = True

import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import struct
import tempfile
import types

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO, "tools", "aot"))

import g3_start_prefix as G  # noqa: E402

THUNK_BASE = 0x7f00000000
THUNK_COUNT = 180


def stop(code, src=0x10201584b0, target=0x10201584b4, status=0):
    return {"code": code, "src": src, "target": target, "status": status}


def check(name, got, want):
    if got != want:
        print("FAIL: %s: got %r want %r" % (name, got, want))
        return 1
    return 0


class Proof:
    def __init__(self, ok=True, reason=None, detail=None, evidence=None):
        self.ok = ok
        self.reason = reason
        self.detail = detail
        self.evidence = evidence


class Prover:
    """Minimal stand-in for g3_veneer_roots.Prover (no game data needed)."""

    def __init__(self, verdict):
        self.verdict = verdict
        self.calls = []

    def prove(self, target):
        self.calls.append(target)
        return self.verdict


# Arbitrary well-formed digest strings: this test only checks that the binding
# compares `source_sha256` (never `provenance_sha256`). No allowlist exists in
# production code.
FLAT_SHA = "a095f9114edad2f9e77a6a217143eaccf7a4b25ab8273792d327774b4652d230"
PROVENANCE_SHA = "c" * 64
PRODUCER_SHA = "e" * 64


def materialization(module="main_real", sha=FLAT_SHA, value=0x1020002000,
                    pc=0x102113f90):
    return {"pc": pc, "word": 0x90000000, "add_pc": pc + 4,
            "add_word": 0x91000000, "value": value, "reg": 0,
            "module": module, "sourceModuleSHA": sha}


def evidence(value=0x1020002000, owner="main_real",
             tail_sym="aligned_alloc", tail=0x1002000000, flat=FLAT_SHA,
             mats=None):
    return {"kind": "veneer", "owner": owner, "value": value, "size": 16,
            "flat_sha256": flat, "veneer_sha256": "b" * 64,
            "materialization": (list(mats) if mats is not None
                                else [materialization(owner, flat)]),
            "movs": [], "prior": {},
            "tail": {"pc": tail - 4, "word": 0x14000000, "target": tail,
                     "symbol": {"name": tail_sym, "bind": 1, "size": 76,
                                "type": 2}},
            "eh": {"offset": 0x37dd510}}


def must_not_construct(label):
    def factory():
        raise AssertionError(label)
    return factory


def expect_driver_error(label, fn):
    try:
        fn()
    except G.DriverError as exc:
        print("OK: %s -> DriverError: %s" % (label, exc))
        return 0
    except Exception as exc:                                # noqa: BLE001
        print("FAIL: %s: raised %s, expected G.DriverError"
              % (label, type(exc).__name__))
        return 1
    print("FAIL: %s: no DriverError" % label)
    return 1


def expect_driver_error_containing(label, fn, needle):
    try:
        fn()
    except G.DriverError as exc:
        if needle not in str(exc):
            print("FAIL: %s: DriverError %r lacks %r"
                  % (label, str(exc), needle))
            return 1
        print("OK: %s -> DriverError contains %r" % (label, needle))
        return 0
    except Exception as exc:                                # noqa: BLE001
        print("FAIL: %s: raised %s, expected G.DriverError"
              % (label, type(exc).__name__))
        return 1
    print("FAIL: %s: no DriverError" % label)
    return 1


def timing_passes(rec):
    try:
        return G.validate_timing_record(rec) is rec
    except G.DriverError:
        return False


def _write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def _unwin(path):
    return path.replace("\\", "/")


def _key_tracks_headers(key_fn, src, flags, cid, d_before, d_after):
    """True when a key function changes across a header digest change."""
    return (key_fn(src, flags, cid, d_before)
            != key_fn(src, flags, cid, d_after))


def _wrong_key_ignores_headers(source_bytes, flags, compiler_id,
                               headers_sha):
    # Deliberately wrong: the header digest is dropped from the key.
    return G.cache_key(source_bytes, flags, compiler_id, "")


class FakeToolchain:
    """Stands in for G._run_bat: 'compiles' and 'links' by writing files."""

    def __init__(self):
        self.events = []
        self.fail_source = None
        self.link_objs = None

    def __call__(self, bat_path):
        with open(bat_path, encoding="ascii") as f:
            lines = [ln for ln in f.read().splitlines() if ln]
        if any("/Fo:" in ln for ln in lines):
            return self._compile(lines)
        return self._link(lines)

    def _compile(self, lines):
        for ln in lines:
            if "/Fo:" not in ln:
                continue
            obj = _unwin(re.search(r'/Fo:"([^"]+)"', ln).group(1))
            src = _unwin(re.findall(r'"([^"]+\.c)"', ln)[-1])
            name = os.path.basename(src)
            self.events.append("compile:" + name)
            if name == self.fail_source:
                return 2, "fake cl\n", "fake cl error C2061 in %s\n" % name
            with open(src, "rb") as f:
                body = f.read()
            _write(obj, b"OBJ\0" + body)
        return 0, "fake cl ok\n", ""

    def _link(self, lines):
        ln = [x for x in lines if "/OUT:" in x][0]
        exe = _unwin(re.search(r'/OUT:"([^"]+)"', ln).group(1))
        objs = [_unwin(o) for o in re.findall(r'"([^"]+\.obj)"', ln)]
        self.events.append("link")
        self.link_objs = [os.path.basename(o) for o in objs]
        blob = b"EXE\0"
        for o in objs:
            with open(o, "rb") as f:
                blob += f.read()
        _write(exe, blob)
        return 0, "fake link ok\n", ""


MOD_BASE = 0x7100000000
SDK_BASE = 0x7200000000


def _arg(cmd, flag):
    return cmd[cmd.index(flag) + 1]


class FakeTool:
    """Stands in for G.run: writes the outputs the real D024 tools write.

    Records every argv.  `refuse` names modules whose table build fails the
    way g3_fde_emit does (stdout REFUSED line, DriverError with .stdout).
    """

    def __init__(self):
        self.calls = []
        self.refuse = set()
        self.boundaries = []

    def __call__(self, cmd, **_kw):
        self.calls.append(list(cmd))
        tool = os.path.basename(cmd[1])
        if tool == "g3_fde_frontend.py":
            doc = {"schema_version": G.SEL.F.SCHEMA_VERSION,
                   "kind": G.SEL.F.KIND, "authority": G.SEL.F.AUTHORITY,
                   "module": {"sha256": "0" * 64},
                   "boundaries": [{"start": "0x%x" % s, "end": "0x%x" % e}
                                  for s, e in self.boundaries]}
            _write(_arg(cmd, "--out"),
                   json.dumps(doc).encode("utf-8"))
            return None
        if cmd[2] == "catalog":
            _write(_arg(cmd, "--out-c"), b"/* catalog */\n")
            _write(_arg(cmd, "--out-json"), b'{"identity": "x"}')
            return None
        name = _arg(cmd, "--name")
        if name in self.refuse:
            err = G.DriverError("command failed: %s" % (cmd,))
            err.stdout = "REFUSED partition-mismatch\n"
            raise err
        _write(_arg(cmd, "--out-c"), b"/* table %s */\n" % name.encode())
        meta = {"name": name, "source_sha256": hashlib.sha256(
            name.encode("utf-8")).hexdigest(), "unsupported": [],
            "local_switch_sites": []}
        _write(_arg(cmd, "--out-json"),
               json.dumps(meta).encode("utf-8"))
        _write(_arg(cmd, "--report"), b"{}")
        if "--write-receipt" in cmd:
            _write(_arg(cmd, "--write-receipt"), b'{"kind": "receipt"}')
        return None


def _catalog_stop(status, src=MOD_BASE + 0x200):
    return {"code": 16, "src": src, "target": src + 4, "status": status,
            "steps": 9}


def _catalog_meta(status, pc=MOD_BASE + 0x200):
    return {"unsupported": [{"status": status, "pc": "0x%x" % pc,
                             "word": "0x00000000", "reason": "x"}],
            "local_switch_sites": []}


def catalog_backend_checks():
    failures = 0
    tmpdirs = []
    saved_run = G.run
    try:
        # resolve_status: one place that maps a status to its metadata.
        leg = {"unsupported": [{"status": 0, "pc": "0x%x" % (MOD_BASE + 0x200),
                                "word": "0x1", "reason": "r"}],
               "local_switch_sites": [{"br_pc": "0x%x" % (MOD_BASE + 0x300),
                                       "status": -5}]}
        hit = G.resolve_status(leg, 0, MOD_BASE + 0x200)
        failures += check("resolve_status unique unsupported hit kind",
                          hit[0], "unsupported")
        failures += check("resolve_status unique unsupported hit entry",
                          hit[1], leg["unsupported"][0])
        hit = G.resolve_status(leg, -5, MOD_BASE + 0x300)
        failures += check("resolve_status unique switch hit",
                          (hit[0], hit[1]), ("switch",
                                             leg["local_switch_sites"][0]))
        failures += check("resolve_status zero hits is None",
                          G.resolve_status(leg, 7, MOD_BASE + 0x200), None)
        failures += check("resolve_status unsupported with another pc is None",
                          G.resolve_status(leg, 0, MOD_BASE + 0x204), None)
        dup = dict(leg, unsupported=leg["unsupported"] * 2)
        failures += expect_driver_error(
            "resolve_status duplicate unsupported status is ambiguous",
            lambda: G.resolve_status(dup, 0, MOD_BASE + 0x200))
        dup_sw = dict(leg, local_switch_sites=leg["local_switch_sites"] * 2)
        failures += expect_driver_error(
            "resolve_status duplicate switch status is ambiguous",
            lambda: G.resolve_status(dup_sw, -5, MOD_BASE + 0x300))

        # normalize_stop: namespaces do not matter, pc and raw fields do.
        metas_leg = {"main_real": _catalog_meta(0)}
        metas_cat = {"main_real": _catalog_meta(0x43500000)}
        norm_leg = G.normalize_stop(_catalog_stop(0), metas_leg, "main_real")
        norm_cat = G.normalize_stop(_catalog_stop(0x43500000), metas_cat,
                                    "main_real")
        failures += check("catalog and legacy statuses of one pc are equal",
                          norm_leg == norm_cat, True)
        failures += check("normalized status is the unsupported pc",
                          norm_cat["status"], ("unsupported",
                                               MOD_BASE + 0x200))
        failures += check("raw catalog and legacy statuses differ",
                          _catalog_stop(0)["status"] ==
                          _catalog_stop(0x43500000)["status"], False)
        failures += check("raw statuses that differ compare unequal",
                          G.normalize_stop(_catalog_stop(1), {}, None) ==
                          G.normalize_stop(_catalog_stop(2), {}, None), False)
        # Same raw status and target; only src differs (no metadata hit).
        src_a = _catalog_stop(5, MOD_BASE + 0x200)
        src_b = dict(src_a, src=MOD_BASE + 0x204)
        failures += check("NEGATIVE: stops differing only in src are unequal",
                          G.normalize_stop(src_a, metas_leg, "main_real") ==
                          G.normalize_stop(src_b, metas_leg, "main_real"),
                          False)
        failures += check("normalize_stop of no stop is None",
                          G.normalize_stop(None, {}, None), None)

        modules = [{"name": "main_real", "base": MOD_BASE,
                    "image_size": 0x1000, "init_va": MOD_BASE + 0x100}]
        out_cat = "STARTFAULTGPR code=10 reg=0 value=0x8 read_va=0x0 " \
                  "read_status=-1 live=0x0\n"
        view_cat = G.equivalence_view(_catalog_stop(0x43500000), out_cat,
                                      metas_cat, modules)
        view_leg = G.equivalence_view(_catalog_stop(0), out_cat, metas_leg,
                                      modules)
        failures += check("equivalence views equal across namespaces",
                          view_cat == view_leg, True)
        failures += check("equivalence view keeps GPR lines",
                          view_leg["gprs"], [out_cat.rstrip("\n")])
        failures += check("NEGATIVE: differing GPR line is unequal",
                          G.equivalence_view(_catalog_stop(0), "", metas_leg,
                                             modules) == view_leg, False)

        # catalog_exhausted: refresh only when EVERY next ctor is admitted.
        cat = {"next_ctors": {0x200, 0x300}}
        failures += check("catalog partly admitted is not exhausted",
                          G.catalog_exhausted(cat, {0x200}), False)
        failures += check("catalog fully admitted is exhausted",
                          G.catalog_exhausted(cat, {0x200, 0x300, 0x400}),
                          True)
        failures += check("catalog with no next ctors is not exhausted",
                          G.catalog_exhausted({"next_ctors": set()}, {0x1}),
                          False)

        # translate_catalog: reuse, per-module regenerate/bound, REFUSED.
        tmp = tempfile.mkdtemp(prefix="g3tc_")
        tmpdirs.append(tmp)
        work = os.path.join(tmp, "work")
        os.makedirs(os.path.join(work, "img"))
        v0 = os.path.join(tmp, "v0")
        cats = {}
        for name in ("main_real", "sdk_real"):
            cat_c = os.path.join(tmp, "cat", name + ".cat.c")
            cat_js = os.path.join(tmp, "cat", name + ".cat.json")
            _write(cat_c, ("/* catalog %s */\n" % name).encode("ascii"))
            _write(cat_js, b'{"identity": "%s"}' % name.encode("ascii"))
            cats[name] = {"cat_c": cat_c, "cat_json": cat_js,
                          "receipt": os.path.join(tmp, "cat",
                                                  name + ".receipt.json"),
                          "receipt_ok": False, "next_ctors": set(),
                          "t_prepare": 0.0}
        modules = [{"name": "main_real", "base": MOD_BASE,
                    "image_size": 0x1000, "init_va": MOD_BASE + 0x100},
                   {"name": "sdk_real", "base": SDK_BASE,
                    "image_size": 0x1000, "init_va": SDK_BASE + 0x100}]
        entries = {"main_real": {MOD_BASE + 0x100, MOD_BASE + 0x200},
                   "sdk_real": {SDK_BASE + 0x100}}
        targs = types.SimpleNamespace(python=sys.executable)
        fake = FakeTool()
        G.run = fake
        prev = {}

        def tcat():
            return G.translate_catalog(REPO, targs, work, v0, modules,
                                       entries, cats, prev)

        imgs, metas, secs = tcat()
        failures += check("first call: two table builds", len(fake.calls), 2)
        failures += check("first call: each is a regenerate with a receipt",
                          [("--verify-mode" in c and
                            _arg(c, "--verify-mode") == "regenerate"
                            and "--write-receipt" in c) for c in fake.calls],
                          [True, True])
        failures += check("imgs values are [cat_c, tab_c]",
                          imgs["main_real"],
                          [cats["main_real"]["cat_c"],
                           os.path.join(work, "img", "main_real.tab.c")])
        failures += check("first call: receipts recorded",
                          (cats["main_real"]["receipt_ok"],
                           cats["sdk_real"]["receipt_ok"],
                           os.path.isfile(cats["main_real"]["receipt"])),
                          (True, True, True))
        failures += check("table metadata is returned per module",
                          metas["sdk_real"]["name"], "sdk_real")
        with open(os.path.join(work, "entries_main_real.json"),
                  encoding="utf-8") as f:
            failures += check("entries file is the sorted root list",
                              json.load(f), sorted(entries["main_real"]))
        fake.calls = []
        imgs2, _metas2, secs2 = tcat()
        failures += check("unchanged entries reuse the tables",
                          (fake.calls, secs2),
                          ([], {"main_real": 0.0, "sdk_real": 0.0}))
        failures += check("reused imgs are the same paths",
                          imgs2, imgs)
        entries["sdk_real"].add(SDK_BASE + 0x200)
        fake.calls = []
        tcat()
        failures += check("one changed module: only that table rebuilt",
                          [_arg(c, "--name") for c in fake.calls],
                          ["sdk_real"])
        failures += check("rebuild after receipt is bound, not regenerated",
                          (_arg(fake.calls[0], "--verify-mode"),
                           "--receipt" in fake.calls[0],
                           "--write-receipt" in fake.calls[0]),
                          ("bound", True, False))
        # A refreshed catalog (new bytes, receipt reset) must rebuild its
        # table even though the entries did not change.
        # The table is also bound to the catalog BYTES: changed bytes rebuild
        # it even while the receipt still claims a valid regenerate.
        _write(cats["main_real"]["cat_c"], b"/* catalog changed */\n")
        fake.calls = []
        tcat()
        failures += check("changed catalog bytes: table rebuilt, bound",
                          [(_arg(c, "--name"), _arg(c, "--verify-mode"))
                           for c in fake.calls],
                          [("main_real", "bound")])
        _write(cats["main_real"]["cat_c"], b"/* catalog refreshed */\n")
        cats["main_real"]["receipt_ok"] = False
        fake.calls = []
        tcat()
        failures += check("refreshed catalog: table rebuilt, unchanged roots",
                          [(_arg(c, "--name"), _arg(c, "--verify-mode"))
                           for c in fake.calls],
                          [("main_real", "regenerate")])
        entries["main_real"].add(MOD_BASE + 0x400)
        fake.refuse = {"main_real"}
        fake.calls = []
        failures += expect_driver_error_containing(
            "table REFUSED is a DriverError with the REFUSED line",
            tcat, "REFUSED partition-mismatch")
        failures += check("table REFUSED never falls back to legacy",
                          [_arg(c, "--name") for c in fake.calls],
                          ["main_real"])
        fake.refuse = set()

        # The real run(): a non-zero exit keeps its stdout on the exception.
        G.run = saved_run
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            try:
                G.run([sys.executable, "-c",
                       "print('REFUSED probe'); raise SystemExit(2)"])
                refused = None
            except G.DriverError as exc:
                refused = getattr(exc, "stdout", None)
        failures += check("run() keeps the child's stdout on failure",
                          refused, "REFUSED probe\n")

        # prepare_catalog: frontend + selection + catalog, all faked.
        G.run = fake
        ptmp = tempfile.mkdtemp(prefix="g3pc_")
        tmpdirs.append(ptmp)
        pv0 = os.path.join(ptmp, "v0")
        _write(os.path.join(pv0, "link", "main_real.flat"), b"\0" * 0x400)
        _write(os.path.join(pv0, "link", "main_real.layout.json"), b"{}")
        pwork = os.path.join(ptmp, "work")
        pargs = types.SimpleNamespace(python=sys.executable, catalog_n=32)
        pm = modules[0]
        # FDE starts 0x100, 0x200, 0x300; slot order 0x100, 0x200.
        fake.boundaries = [(0x100, 0x110), (0x200, 0x220), (0x300, 0x320)]
        slots = [0x100, 0x200]
        admitted_va = {MOD_BASE + 0x100, MOD_BASE + 0x104,
                       MOD_BASE + 0x300}
        fake.calls = []
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cat = G.prepare_catalog(REPO, pargs, pwork, pv0, pm, admitted_va,
                                    slots)
        starts = [w["start"] for w in cat["selection"]["windows"]]
        failures += check("prepare: next ctor + admitted FDE roots",
                          starts, [0x100, 0x200, 0x300])
        failures += check("prepare: next_ctors is the first unadmitted slot",
                          cat["next_ctors"], {0x200})
        failures += check("prepare: non-FDE admitted offset adds no window",
                          0x104 in starts, False)
        failures += check("prepare: selection is fed to the catalog tool",
                          _arg(fake.calls[-1], "--select"),
                          "0x100,0x200,0x300")
        failures += check("prepare: receipt starts unbound",
                          (cat["receipt_ok"], cat["receipt"]),
                          (False, os.path.join(pwork, "cat",
                                               "main_real.cat.receipt.json")))
        failures += check("prepare: prints the CATALOG line",
                          buf.getvalue().count("CATALOG module=main_real "
                                               "windows=3 next_ctors=1 "),
                          1)
        failures += check("prepare: selection written under work",
                          os.path.isfile(os.path.join(
                              pwork, "cat", "main_real.selection.json")),
                          True)
        fake.boundaries = [(0x100, 0x110)]
        failures += expect_driver_error_containing(
            "prepare: empty selection is refused",
            lambda: G.prepare_catalog(REPO, pargs, pwork, pv0, pm, set(),
                                      []),
            "catalog selection is empty for main_real")
    finally:
        G.run = saved_run
        for path in tmpdirs:
            shutil.rmtree(path, ignore_errors=True)

    # CLI guard: equivalence needs the catalog backend, before v0 is read.
    gtmp = tempfile.mkdtemp(prefix="g3guard_")
    try:
        gwork = os.path.join(gtmp, "work")
        gv0 = os.path.join(gtmp, "v0")
        base_argv = ["--repo", REPO, "--work", gwork, "--v0-dir", gv0,
                     "--vcvars", "x.bat"]
        def guard_rc(extra):
            # An escaped exception is a failed guard, not a pass.
            try:
                with contextlib.redirect_stdout(buf):
                    return G.main(base_argv + extra)
            except Exception as exc:                        # noqa: BLE001
                return "raised %s" % type(exc).__name__

        buf = io.StringIO()
        rc = guard_rc(["--backend", "legacy", "--equivalence-check"])
        failures += check("--equivalence-check with legacy returns 1", rc, 1)
        failures += check("guard names the backend requirement",
                          "requires --backend catalog" in buf.getvalue(),
                          True)
        failures += check("guard touches neither work nor v0",
                          (os.path.exists(gwork), os.path.exists(gv0)),
                          (False, False))
        rc2 = guard_rc(["--equivalence-every", "2"])
        rc3 = guard_rc(["--backend", "catalog", "--equivalence-check",
                        "--equivalence-every", "3"])
        failures += check("--equivalence-every with default backend is 1",
                          rc2, 1)
        failures += check("--equivalence-check conflicts with every 3",
                          rc3, 1)
        failures += check("guards never create the work tree",
                          os.path.exists(gwork), False)
    finally:
        shutil.rmtree(gtmp, ignore_errors=True)

    # Timing: the two new keys and the catalog backend name.
    timing = {
        "iteration": 3, "backend": "catalog", "roots": {"main_real": 2},
        "t_translate": {"main_real": 0.0}, "t_bind": 0.0,
        "t_emit_desc": 0.0, "t_compile": 0.0, "t_link": 0.0, "t_run": 0.0,
        "t_classify": 0.0, "t_total": 1.0, "t_prepare": 0.5,
        "t_equivalence": 0.25, "c_bytes": {"main_real": 10},
        "obj_bytes": None, "exe_bytes": None, "steps": None, "stop": None,
        "admitted": None,
    }
    failures += check("catalog timing record with new keys passes",
                      timing_passes(timing), True)
    failures += expect_driver_error(
        "timing rejects a negative t_equivalence",
        lambda: G.validate_timing_record(dict(timing, t_equivalence=-0.1)))
    failures += expect_driver_error(
        "timing rejects a negative t_prepare",
        lambda: G.validate_timing_record(dict(timing, t_prepare=-1)))
    no_prepare = dict(timing)
    del no_prepare["t_prepare"]
    failures += expect_driver_error(
        "timing record missing t_prepare",
        lambda: G.validate_timing_record(no_prepare))
    failures += expect_driver_error(
        "timing rejects an unknown backend",
        lambda: G.validate_timing_record(dict(timing, backend="fast")))
    return failures


def main():
    failures = 0
    failures += check("clean return",
                      G.classify_stop(stop(0), "", THUNK_BASE,
                                      THUNK_COUNT)["kind"],
                      "clean_return")
    failures += check("untranslated",
                      G.classify_stop(stop(10, target=0x1020001234), "",
                                      THUNK_BASE, THUNK_COUNT)["kind"],
                      "untranslated")
    failures += check("unsupported",
                      G.classify_stop(stop(16), "", THUNK_BASE,
                                      THUNK_COUNT)["kind"],
                      "unsupported")

    svc = G.classify_stop(stop(7, status=4),
                          "word=0xd4000521 svc #0x29", THUNK_BASE,
                          THUNK_COUNT)
    failures += check("svc kind", svc["kind"], "svc")
    failures += check("svc immediate", svc["svc_imm"], 0x29)
    failures += check("GetInfo id only for SVC 0x29", svc["getinfo_status"], 4)

    other = G.classify_stop(stop(7, status=99), "svc #0x25", THUNK_BASE,
                            THUNK_COUNT)
    failures += check("other SVC kind", other["kind"], "svc")
    failures += check("other SVC immediate", other["svc_imm"], 0x25)
    failures += check("no GetInfo claim for other SVC",
                      other["getinfo_status"], None)

    host = G.classify_stop(stop(7, src=THUNK_BASE + 16 * 177),
                           "word=0xd63f0000 blr x0", THUNK_BASE,
                           THUNK_COUNT)
    failures += check("hostcall kind", host["kind"], "hostcall")
    failures += check("hostcall has no GetInfo id", host["getinfo_status"],
                      None)

    host_site = G.classify_stop(stop(7, status=177), "word=0xd63f0100 blr x8",
                                THUNK_BASE, THUNK_COUNT)
    failures += check("missing-hostcall call-site kind", host_site["kind"],
                      "hostcall")

    unknown = G.classify_stop(stop(7, src=0x10201584b0),
                              "word=0xf9400000 ldr x0,[x0]", THUNK_BASE,
                              THUNK_COUNT)
    failures += check("unknown BAD_HLE kind", unknown["kind"],
                      "bad_hle_unknown")

    typed = G.classify_stop(stop(2), "word=0x00000000 udf #0", THUNK_BASE,
                            THUNK_COUNT)
    failures += check("other typed kind", typed["kind"], "typed")

    failures += check("clean return exit 2",
                      G.result_exit_code("clean_return"), 2)
    failures += check("pre-G4 boundary exit 2, no pass claim",
                      G.result_exit_code("pre_g4_boundary"), 2)
    nnmain = 0x1000e99570
    failures += check("exact nnMain target is boundary",
                      G.is_pre_g4_boundary_target(nnmain, nnmain), 1)
    failures += check("different target is not boundary",
                      G.is_pre_g4_boundary_target(nnmain + 4, nnmain), 0)
    kept, excluded = G.filter_pre_g4_batch(
        [(0x1020001000, ("sdk", "fn", 1, 8)),
         (nnmain, ("main", "nnMain", 1, 4))], nnmain)
    failures += check("batch keeps non-nnMain", [v for v, _ in kept],
                      [0x1020001000])
    failures += check("batch excludes real nnMain",
                      [v for v, _ in excluded], [nnmain])
    failures += check("blocker exit 0",
                      G.result_exit_code("svc"), 0)
    with contextlib.redirect_stdout(io.StringIO()):
        failure_rc = G.fail("synthetic justification failure")
    failures += check("unjustified/justification failure exit 1",
                      failure_rc, 1)

    # --- Phase 2 narrow veneer follow-selection seam ----------------------
    nnmain_va = 0x1002146110
    target = 0x1020002000

    # Positive: old strict symbol lookup misses -> compound proof decides.
    prover = Prover(Proof(ok=True, evidence=evidence(target)))
    decides = []

    def accept_all():
        decides.append("prover constructed")
        return prover

    dec = G.select_follow(target, nnmain_va, lambda va: None, "blr",
                          accept_all)
    failures += check("veneer follow kind", dec["kind"], "veneer")
    failures += check("veneer follow label is veneer:+tail name",
                      dec["label"], "veneer:aligned_alloc")
    failures += check("veneer follow keeps proof evidence",
                      dec["evidence"]["flat_sha256"], FLAT_SHA)
    failures += check("veneer follow proves the exact observed target",
                      prover.calls, [target])
    failures += check("veneer follow constructed the prover once",
                      len(decides), 1)
    failures += check("veneer follow does not fabricate a symbol hit",
                      dec["hit"], None)
    failures += check("BR fault site is also accepted",
                      G.select_follow(target, nnmain_va, lambda va: None,
                                      "br",
                                      accept_all)["kind"], "veneer")

    # Old exact-DEFINED-STT_FUNC path is unchanged and never proves.
    dec = G.select_follow(target, nnmain_va,
                          lambda va: ("main_real", "aligned_alloc", 1, 76),
                          "blr", must_not_construct("prover constructed"))
    failures += check("old symbol path unchanged", dec["kind"], "old")
    failures += check("old symbol path keeps its hit", dec["hit"],
                      ("main_real", "aligned_alloc", 1, 76))
    dec = G.select_follow(target, nnmain_va,
                          lambda va: ("main_real", "aligned_alloc", 1, 76),
                          None, lambda: None)
    failures += check("old symbol path needs no indirect site",
                      dec["kind"], "old")

    # Rejection: no fallback, reason/detail surface unchanged.
    rejected = Prover(Proof(ok=False, reason="eh-not-exact",
                            detail="0x1020002000 is not an exact initial "
                                   "location"))
    dec = G.select_follow(target, nnmain_va, lambda va: None, "blr",
                          lambda: rejected)
    failures += check("proof rejection is a refusal", dec["kind"], "refused")
    failures += check("proof rejection reason survives", dec["reason"],
                      "eh-not-exact")
    failures += check("proof rejection detail survives", dec["detail"],
                      "0x1020002000 is not an exact initial location")
    failures += check("proof rejection yields no hit/label",
                      (dec["hit"], dec["label"]), (None, None))
    failures += check("proof rejection proves only the observed target",
                      rejected.calls, [target])

    # Wrong ORIGINAL source kind: never even consult the proof.  These call the
    # SAME public seam with non-None, non-'br'/'blr' strings, so a seam that
    # only gated on `is None` would construct the prover and fail here.
    for why, kind in (("no original site", None), ("no indirect site", None),
                      ("RET site", "ret"), ("direct B site", "b"),
                      ("unknown site kind", "unknown"),
                      ("empty site kind", "")):
        dec = G.select_follow(target, nnmain_va, lambda va: None, kind,
                              must_not_construct("prover constructed"))
        failures += check("%s is a refusal" % why, dec["kind"], "refused")
        failures += check("%s reason is specific" % why, dec["reason"],
                          "fault-site-not-indirect")

    def site_flat():
        buf = bytearray(site_va - base + 4)
        struct.pack_into("<I", buf, site_va - base, 0xD61F0000)
        return bytes(buf)

    base, text = 0x100000000, (0x100000000, 0x100100000)
    site_va = base + 0x1000

    def site(word, va=site_va, flat=None):
        if flat is None:
            buf = bytearray(va - base + 4)
            struct.pack_into("<I", buf, va - base, word)
            flat = bytes(buf)
        return G.indirect_site_kind(flat, base, text, va)

    failures += check("BR site recognised", site(0xD61F0000), "br")
    failures += check("BLR site recognised", site(0xD63F0000), "blr")
    failures += check("RET site rejected", site(0xD65F03C0), None)
    failures += check("direct B site rejected", site(0x14000000), None)
    failures += check("SVC site rejected", site(0xD4000001), None)
    failures += check("site outside known TEXT rejected",
                      site(0xD63F0000, va=text[1]), None)
    failures += check("unaligned site rejected",
                      site(0xD63F0000, va=site_va + 2), None)
    failures += check("unreadable site rejected", site(0, flat=b""), None)
    # A readable word whose 4 bytes only PARTLY overlap TEXT must be refused:
    # the whole original word has to sit inside the known text extent.
    truncated = (base, site_va + 2)
    failures += check(
        "word straddling the TEXT end rejected",
        G.indirect_site_kind(site_flat(), base, truncated, site_va), None)
    failures += check(
        "same word accepted when whole word is inside TEXT",
        G.indirect_site_kind(site_flat(), base, (base, site_va + 4),
                             site_va), "br")

    # A proof whose TAIL is exactly nnMain must be rejected after prove().
    tail_nn = 0x1000e99570
    prover = Prover(Proof(ok=True, evidence=evidence(target, tail=tail_nn)))
    dec = G.select_follow(target, tail_nn, lambda va: None, "blr",
                          lambda: prover)
    failures += check("tail==nnMain refusal kind", dec["kind"], "refused")
    failures += check("tail==nnMain refusal reason", dec["reason"],
                      "tail-is-nnmain")
    failures += check("tail==nnMain refuses label/hit",
                      (dec["label"], dec["hit"]), (None, None))
    failures += check("tail==nnMain proof was consulted for the target",
                      prover.calls, [target])

    # nnMain pre-G4 guard wins BEFORE any proof, even an accept-all prover.
    guard = Prover(Proof(ok=True, evidence=evidence(nnmain_va)))
    constructed = []

    def guard_factory():
        constructed.append("prover constructed")
        return guard

    dec = G.select_follow(nnmain_va, nnmain_va, lambda va: None, "blr",
                          guard_factory)
    failures += check("nnMain guard wins over accept-all prover",
                      dec["kind"], "pre_g4_boundary")
    failures += check("nnMain guard never constructs a prover", constructed,
                      [])
    failures += check("nnMain guard never proves", guard.calls, [])

    # Already-root refusal and the label actually recorded for a new root.
    mods = [{"name": "main_real", "base": 0x1020000000,
             "image_size": 0x03000000}]
    by_mod = {"main_real": {}}
    ok, why = G.record_follow(by_mod, mods, target, "veneer:aligned_alloc")
    failures += check("new veneer root is recorded", (ok, why), (True, None))
    failures += check("recorded label is veneer:+tail",
                      by_mod["main_real"][target], "veneer:aligned_alloc")
    ok, why = G.record_follow(by_mod, mods, target, "veneer:aligned_alloc")
    failures += check("already-root still refuses", ok, False)
    failures += check("already-root refusal explains itself",
                      why.endswith("is already a root"), True)
    ok, why = G.record_follow(by_mod, mods, 0x200000000, "veneer:x")
    failures += check("owner-less follow refuses", (ok, why[0:6]),
                      (False, "target"))

    # Documented proof InputError -> host DriverError (never a root/negative).
    world = types.SimpleNamespace(images=[])
    scan = types.SimpleNamespace(visited={})
    factory = G.make_prover_factory({"broken": {"name": "broken"}}, scan,
                                    world)
    failures += expect_driver_error("proof InputError becomes DriverError",
                                    factory)

    # flat SHA binding uses compiled `source_sha256`, never provenance.
    ev = evidence(target)
    metas = {"main_real": {"source_sha256": FLAT_SHA,
                           "provenance_sha256": PROVENANCE_SHA}}
    ok = G.bind_veneer_flat_sha(metas, [{"evidence": ev}])
    failures += check("matching source_sha256 binds", ok, True)
    metas_bad = {"main_real": {"source_sha256": "d" * 64,
                                "provenance_sha256": PROVENANCE_SHA}}
    failures += expect_driver_error(
        "source_sha256 mismatch refuses the rebuilt image",
        lambda: G.bind_veneer_flat_sha(metas_bad, [{"evidence": ev}]))
    metas_prov = {"main_real": {"source_sha256": FLAT_SHA,
                                 "provenance_sha256": "d" * 64}}
    failures += check("provenance_sha256 is NOT the binding",
                      G.bind_veneer_flat_sha(metas_prov,
                                             [{"evidence": ev}]), True)
    failures += expect_driver_error(
        "missing compiled metadata refuses",
        lambda: G.bind_veneer_flat_sha({}, [{"evidence": ev}]))

    # Compound proofs may cite ADRP+ADD producers in OTHER modules: the binding
    # must check the owner AND every cited producer, using each module's own
    # internal immutable snapshot SHA.  Owner matching alone must not suffice.
    multi = evidence(target, mats=[
        materialization("main_real", FLAT_SHA),
        materialization("sdk_real", PRODUCER_SHA, pc=0x102a00000)])
    metas_ok = {"main_real": {"source_sha256": FLAT_SHA,
                               "provenance_sha256": PROVENANCE_SHA},
                "sdk_real": {"source_sha256": PRODUCER_SHA,
                              "provenance_sha256": PROVENANCE_SHA}}
    failures += check("matching multi-module producer hashes bind",
                      G.bind_veneer_flat_sha(metas_ok,
                                             [{"evidence": multi}]), True)
    metas_cross_bad = {"main_real": {"source_sha256": FLAT_SHA},
                       "sdk_real": {"source_sha256": "d" * 64}}
    failures += expect_driver_error(
        "cross-module producer hash mismatch refuses (owner matches)",
        lambda: G.bind_veneer_flat_sha(metas_cross_bad,
                                        [{"evidence": multi}]))
    failures += expect_driver_error(
        "missing producer module metadata refuses",
        lambda: G.bind_veneer_flat_sha({"main_real": {
            "source_sha256": FLAT_SHA}}, [{"evidence": multi}]))
    no_hash = evidence(target, mats=[
        {"pc": 0x102113f90, "value": target, "module": "main_real"}])
    failures += expect_driver_error(
        "materialization record without sourceModuleSHA refuses",
        lambda: G.bind_veneer_flat_sha(metas_ok, [{"evidence": no_hash}]))
    producer_prov_only = {"main_real": {"source_sha256": FLAT_SHA},
                          "sdk_real": {"source_sha256": "d" * 64,
                                        "provenance_sha256": PRODUCER_SHA}}
    failures += expect_driver_error(
        "producer provenance_sha256 is NOT the binding",
        lambda: G.bind_veneer_flat_sha(producer_prov_only,
                                        [{"evidence": multi}]))
    # Owner-only evidence must never bind: the compound proof always cites at
    # least one reached materialization producer, so absent provenance is a
    # contract violation, not a weaker-but-acceptable claim.
    owner_only = evidence(target)
    del owner_only["materialization"]
    failures += expect_driver_error(
        "missing materialization list refuses (owner-only evidence)",
        lambda: G.bind_veneer_flat_sha(metas_ok, [{"evidence": owner_only}]))
    empty = evidence(target, mats=[])
    failures += expect_driver_error(
        "empty materialization list refuses",
        lambda: G.bind_veneer_flat_sha(metas_ok, [{"evidence": empty}]))
    nonlist = evidence(target)
    nonlist["materialization"] = {"module": "main_real",
                                  "sourceModuleSHA": FLAT_SHA}
    failures += expect_driver_error(
        "non-list materialization refuses",
        lambda: G.bind_veneer_flat_sha(metas_ok, [{"evidence": nonlist}]))
    notdict = evidence(target, mats=["main_real"])
    failures += expect_driver_error(
        "non-dict materialization record refuses",
        lambda: G.bind_veneer_flat_sha(metas_ok, [{"evidence": notdict}]))

    # --- REAL factory integration: world "m" vs runtime image "m_real" -----
    # R.load_world names images after the base flat ("m"), while by_module uses
    # the expected-linked runtime name ("m_real").  The factory must re-key by
    # UNIQUE guest base + TEXT extent + byte-identical TEXT, not by stripping
    # "_real", and the resulting evidence must bind to the runtime metas keys.
    import hashlib
    import shutil
    import tempfile

    if HERE not in sys.path:
        sys.path.insert(0, HERE)
    import g3_veneer_roots_test as RT

    def world_image(name="m", base=RT.BASE, flat=None, layout=None):
        layout = layout or mod["layout"]
        toff, tsize = layout["text"]
        return types.SimpleNamespace(
            name=name, base=base,
            flat=bytes(mod["flat"] if flat is None else flat),
            layout=layout,
            text=(base + toff, base + toff + tsize))

    tmpdir = tempfile.mkdtemp(prefix="g3prefix_factory_")
    try:
        mod = RT.make_module(tmpdir, "m_real", RT.BASE)
        toff, tsize = mod["layout"]["text"]
        bitmap = [0] * (tsize // 4)
        for off in RT.REACHED:
            bitmap[(off - toff) // 4] = 1
        scan = types.SimpleNamespace(visited={"m": bitmap})
        by_module = {"m_real": mod}
        world = types.SimpleNamespace(images=[world_image()])
        factory = G.make_prover_factory(by_module, scan, world)
        verdict = factory().prove(RT.BASE + RT.V1)
        failures += check("real factory proves via base/TEXT identity",
                          verdict.ok, True)
        failures += check("real factory evidence owner is runtime name",
                          (verdict.evidence or {}).get("owner"), "m_real")
        meta = {"m_real": {"source_sha256":
                           hashlib.sha256(mod["flat"]).hexdigest()}}
        failures += check(
            "real factory evidence binds to runtime metas",
            G.bind_veneer_flat_sha(meta,
                                   [{"evidence": verdict.evidence}]), True)
        # every materialization must also be cited under the runtime name
        failures += check(
            "producer records use runtime module names",
            all(r["module"] == "m_real"
                for r in verdict.evidence["materialization"]), True)

        assert tsize > 0x104, "fixture TEXT must contain offset 0x100"
        badflat = bytearray(mod["flat"])
        assert toff + 0x100 + 4 <= len(badflat), "flip stays inside TEXT"
        badflat[toff + 0x100] ^= 0xFF
        failures += expect_driver_error_containing(
            "factory refuses byte-different TEXT (wrong text)",
            lambda: G.make_prover_factory(
                by_module, scan,
                types.SimpleNamespace(images=[
                    world_image(flat=bytes(badflat))]))(),
            "TEXT bytes differ")
        # a SEPARATE world layout (not the shared module dict) with a
        # different extent must be refused as an extent mismatch
        short_layout = dict(mod["layout"])
        short_layout["text"] = [toff, tsize - 4]
        failures += expect_driver_error_containing(
            "factory refuses TEXT extent mismatch (separate world layout)",
            lambda: G.make_prover_factory(
                by_module, scan,
                types.SimpleNamespace(images=[
                    types.SimpleNamespace(
                        name="m", base=RT.BASE, flat=bytes(mod["flat"]),
                        layout=short_layout,
                        text=(RT.BASE + toff,
                              RT.BASE + toff + tsize - 4))]))(),
            "TEXT extent differs")
        bad_extent = dict(mod["layout"])
        bad_extent["text"] = ["not-a-number", tsize]
        failures += expect_driver_error_containing(
            "factory refuses a non-numeric TEXT extent",
            lambda: G.make_prover_factory(
                by_module, scan,
                types.SimpleNamespace(images=[
                    types.SimpleNamespace(
                        name="m", base=RT.BASE, flat=bytes(mod["flat"]),
                        layout=bad_extent,
                        text=(RT.BASE + toff, RT.BASE + toff + tsize))]))(),
            "TEXT extent is not numeric")
        failures += expect_driver_error(
            "factory refuses an extra unmatched world image",
            lambda: G.make_prover_factory(
                by_module, scan,
                types.SimpleNamespace(images=[
                    world_image(),
                    world_image(name="extra",
                                base=RT.BASE + 0x20000000)]))())
        failures += expect_driver_error(
            "factory refuses a world image with no base match (missing)",
            lambda: G.make_prover_factory(
                by_module, scan,
                types.SimpleNamespace(images=[
                    world_image(base=RT.BASE + 0x10000000)]))())
        failures += expect_driver_error(
            "factory refuses two images on the same base (ambiguous)",
            lambda: G.make_prover_factory(
                by_module, scan,
                types.SimpleNamespace(images=[world_image("m", RT.BASE),
                                              world_image("m2", RT.BASE)]))())
        # REAL proof whose tail is a DEFINED STT_FUNC named nnMain: the proof
        # itself is valid, so only the seam guard can reject seeding it.
        nn_mod = RT.make_module(
            tmpdir, "m_nn", RT.BASE,
            syms=[("nnMain", RT.T1, 76, 0x2, 1)])
        nn_prover = RT.G.Prover(
            [nn_mod], {"m_nn": {RT.BASE + o for o in RT.REACHED}})
        nn_verdict = nn_prover.prove(RT.BASE + RT.V1)
        failures += check("real proof with nnMain tail is structurally valid",
                          nn_verdict.ok, True)
        failures += check("real proof nnMain tail target is the tail",
                          nn_verdict.evidence["tail"]["target"],
                          RT.BASE + RT.T1)
        dec = G.select_follow(
            RT.BASE + RT.V1, RT.BASE + RT.T1, lambda va: None, "blr",
            lambda: nn_prover)
        failures += check("real nnMain-tail proof refused by the seam",
                          (dec["kind"], dec["reason"]),
                          ("refused", "tail-is-nnmain"))
    finally:
        shutil.rmtree(tmpdir)

    # Per-iteration --timing-out records (plan step 1.1).
    timing_rec = {
        "iteration": 0, "backend": "legacy", "roots": {"main_real": 3},
        "t_translate": {"main_real": 0.25, "sdk_real": 1},
        "t_bind": 0.0, "t_emit_desc": 0.01, "t_compile": 1.5,
        "t_link": 0.0, "t_run": 0.5, "t_classify": 0.001, "t_total": 2.3,
        "t_prepare": 0.0, "t_equivalence": 0.0,
        "c_bytes": {"main_real": 1024}, "obj_bytes": 4096, "exe_bytes": None,
        "steps": 12,
        "stop": {"code": 10, "src": 0x10201584B0, "target": 0x10200FA060,
                 "status": 0},
        "admitted": {"kind": "old", "va": 0x10200FA060},
    }
    timing_last = {
        "iteration": 1, "backend": "legacy", "roots": {},
        "t_translate": {}, "t_bind": 0.0, "t_emit_desc": 0.0,
        "t_compile": 0.0, "t_link": 0.0, "t_run": 0.0, "t_classify": 0.0,
        "t_total": 0.0, "t_prepare": 0.0, "t_equivalence": 0.0,
        "c_bytes": {}, "obj_bytes": None, "exe_bytes": 8192,
        "steps": None, "stop": None, "admitted": None,
    }
    failures += check("valid timing record passes",
                      timing_passes(timing_rec), True)
    failures += check("valid timing record with None fields passes",
                      timing_passes(timing_last), True)
    no_run = dict(timing_rec)
    del no_run["t_run"]
    failures += expect_driver_error(
        "timing record missing t_run",
        lambda: G.validate_timing_record(no_run))
    failures += expect_driver_error(
        "timing record extra key",
        lambda: G.validate_timing_record(dict(timing_rec, surprise=1)))
    failures += expect_driver_error(
        "timing record negative t_total",
        lambda: G.validate_timing_record(dict(timing_rec, t_total=-0.1)))
    failures += expect_driver_error(
        "timing stop missing status",
        lambda: G.validate_timing_record(dict(
            timing_rec, stop={"code": 10, "src": 1, "target": 2})))
    failures += expect_driver_error(
        "timing admitted va as string",
        lambda: G.validate_timing_record(dict(
            timing_rec, admitted={"kind": "old", "va": "0x10200FA060"})))
    failures += expect_driver_error(
        "timing roots value as float",
        lambda: G.validate_timing_record(dict(
            timing_rec, roots={"main_real": 3.0})))

    import json
    import shutil
    import tempfile
    tdir = tempfile.mkdtemp(prefix="g3timing_")
    try:
        out = os.path.join(tdir, "timing.json")
        G.write_timing(out, [timing_rec, timing_last])
        with open(out, encoding="utf-8") as f:
            back = json.load(f)
        failures += check("write_timing round-trips records", back,
                          [timing_rec, timing_last])
        bad_out = os.path.join(tdir, "bad.json")
        failures += expect_driver_error(
            "write_timing rejects an invalid record",
            lambda: G.write_timing(bad_out, [timing_rec, no_run]))
        failures += check("invalid write creates no target or tmp file",
                          os.path.exists(bad_out)
                          or os.path.exists(bad_out + ".tmp"), False)
        failures += check("_inside: path in repo is inside",
                          G._inside(REPO, os.path.join(REPO, "tests",
                                                       "timing.json")),
                          True)
        failures += check("_inside: temp dir outside repo is not inside",
                          G._inside(REPO, tdir), False)
    finally:
        shutil.rmtree(tdir)

    # --- content-addressed object cache (plan step 1.3) -------------------
    base_src = b"int x;\n"
    flags0 = list(G.COMPILE_FLAGS)
    k0 = G.cache_key(base_src, flags0, "cl-19.44", "h0")
    failures += check("cache_key separates identical bytes at two paths",
                      G.cache_key(base_src, flags0, "cl-19.44", "h0",
                                  "/a/x.c")
                      != G.cache_key(base_src, flags0, "cl-19.44", "h0",
                                     "/b/x.c"), True)
    failures += check("cache_key is stable for identical inputs",
                      G.cache_key(base_src, list(flags0), "cl-19.44", "h0"),
                      k0)
    failures += check("cache_key changes with one source byte",
                      G.cache_key(bytes([base_src[0] ^ 1]) + base_src[1:],
                                  flags0, "cl-19.44", "h0") != k0, True)
    failures += check("cache_key changes with one flag",
                      G.cache_key(base_src, flags0 + ["/Zi"], "cl-19.44",
                                  "h0") != k0, True)
    failures += check("cache_key is sensitive to flag order",
                      G.cache_key(base_src, list(reversed(flags0)),
                                  "cl-19.44", "h0") != k0, True)
    failures += check("cache_key changes with the compiler id",
                      G.cache_key(base_src, flags0, "cl-19.45", "h0") != k0,
                      True)
    failures += check("cache_key changes with headers_sha",
                      G.cache_key(base_src, flags0, "cl-19.44", "h1") != k0,
                      True)

    hdr_tmp = tempfile.mkdtemp(prefix="g3hdr_")
    try:
        tree = os.path.join(hdr_tmp, "repo")

        def tpath(rel):
            return os.path.join(tree, *rel.split("/"))

        hdr_files = {"src/aot/a.h": b"#define A 1\n",
                     "src/b.h": b"#define B 2\n",
                     "tests/aot/t.h": b"#define T 3\n"}
        for rel, data in sorted(hdr_files.items()):
            _write(tpath(rel), data)
        _write(tpath("src/x.c"), b"int x;\n")
        d0 = G.header_digest(tree)
        failures += check("header_digest is stable for an unchanged tree",
                          G.header_digest(tree), d0)
        for rel, data in sorted(hdr_files.items()):
            _write(tpath(rel), data + b"/* edit */\n")
            failures += check("header_digest changes with %s" % rel,
                              G.header_digest(tree) != d0, True)
            _write(tpath(rel), data)
        failures += check("restoring headers restores the digest",
                          G.header_digest(tree), d0)
        _write(tpath("src/x.c"), b"int y;\n")
        failures += check("a non-header edit leaves header_digest alone",
                          G.header_digest(tree), d0)
        _write(tpath("src/aot/a.h"), hdr_files["src/aot/a.h"] + b"/*e*/\n")
        d1 = G.header_digest(tree)
        failures += check("real key passes the header-change check",
                          _key_tracks_headers(G.cache_key, base_src, flags0,
                                              "cl-19.44", d0, d1), True)
        failures += check("NEGATIVE: header-blind key fails the header check",
                          _key_tracks_headers(_wrong_key_ignores_headers,
                                              base_src, flags0, "cl-19.44",
                                              d0, d1), False)
    finally:
        shutil.rmtree(hdr_tmp, ignore_errors=True)

    failures += check("_flatten_images: module order, list order kept",
                      G._flatten_images({"sdk_real": "s.c",
                                         "main_real": ["m2.c", "m1.c"],
                                         "aa": ["x.c"]}),
                      ["x.c", "m2.c", "m1.c", "s.c"])
    failures += check("_flatten_images: plain str value",
                      G._flatten_images({"a": "one.c"}), ["one.c"])

    build_tmp = tempfile.mkdtemp(prefix="g3objbuild_")
    saved_run, saved_id = G._run_bat, G.compiler_id
    try:
        banner = ("Microsoft (R) C/C++ Optimizing Compiler Version "
                  "19.44.35207 for x64")
        id_calls = []

        def fake_id_bat(bat):
            id_calls.append(bat)
            return 2, "", banner + "\nCopyright (C) Microsoft\n"

        G._run_bat = fake_id_bat
        G._COMPILER_IDS.clear()
        id_args = types.SimpleNamespace(vcvars="C:\\fake\\vcvars64.bat",
                                        cl="C:\\fake\\cl.exe")
        first_id = G.compiler_id(id_args)
        second_id = G.compiler_id(id_args)
        failures += check("compiler_id runs cl once per process",
                          len(id_calls), 1)
        failures += check("compiler_id is SHA-256 of the banner line",
                          first_id == second_id and first_id ==
                          hashlib.sha256(banner.encode("utf-8")).hexdigest(),
                          True)

        fake = FakeToolchain()
        G._run_bat = fake
        G.compiler_id = lambda _args: "fake-cl-19.44"

        repo = os.path.join(build_tmp, "repo")

        def rpath(rel):
            return os.path.join(repo, *rel.split("/"))

        rel_fixed = ["tests/aot/aot_g3_start_probe.c",
                   "tests/aot/g3_start_hle.c",
                   "tests/aot/g4_romfs_start_hle.c",
                   "src/romfs_provider.c", "src/romfs_file_win.c",
                   "src/host_random.c", "src/host_sha256.c"]
        for rel in rel_fixed + list(G.CORE):
            _write(rpath(rel), ("/* %s */\n" % rel).encode("ascii"))
        desc = os.path.join(build_tmp, "gen", "real_desc.c")
        config_c = os.path.join(build_tmp, "gen", "romfs_config.c")
        _write(desc, b"/* desc */\n")
        _write(config_c, b"/* config */\n")

        def img(name):
            return os.path.join(build_tmp, "img", name)

        images = {"sdk_real": img("sdk.c"),
                  "main_real": [img("main_a.c"), img("main_b.c")]}
        for p in G._flatten_images(images):
            _write(p, ("/* %s */\n" % os.path.basename(p)).encode("ascii"))
        sources = ([rpath(r) for r in rel_fixed] + [desc, config_c]
                   + [img("main_a.c"), img("main_b.c"), img("sdk.c")]
                   + [rpath(c) for c in G.CORE])
        n = len(sources)

        work = os.path.join(build_tmp, "work")
        os.makedirs(work)
        exe = os.path.join(work, "probe.exe")
        objdir = os.path.join(work, "obj")
        index_path = os.path.join(objdir, "cache.json")
        bargs = types.SimpleNamespace(vcvars="C:\\fake\\vcvars64.bat",
                                      cl="cl.exe")

        def run_build():
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out):
                with contextlib.redirect_stderr(err):
                    res = G.build(repo, work, bargs, desc, images, exe,
                                  config_c)
            return res, out.getvalue()

        def counters():
            return (G.LAST_BUILD["compiled"], G.LAST_BUILD["reused"])

        def read_index():
            with open(index_path, encoding="utf-8") as f:
                return json.load(f)

        def obj_of(key):
            return os.path.join(objdir, key + ".obj")

        # 1. cold build: every source compiled, one link, index complete.
        fake.events = []
        (ok, tc, tl), out = run_build()
        failures += check("cold build succeeds", ok, True)
        failures += check("cold build compiles every source",
                          counters(), (n, 0))
        failures += check("cold build prints the BUILD line", out,
                          "BUILD compiled=%d reused=0\n" % n)
        failures += check("cold build: compile each source, then link",
                          fake.events,
                          ["compile:" + os.path.basename(s) for s in sources]
                          + ["link"])
        failures += check("timings are non-negative floats",
                          all(isinstance(x, float) and x >= 0
                              for x in (tc, tl)), True)
        with open(os.path.join(work, "build_start.log"),
                  encoding="utf-8") as lf:
            log_text = lf.read()
        failures += check("build log holds the compiler output",
                          "fake cl ok" in log_text
                          and "fake link ok" in log_text, True)
        idx = read_index()
        key_of = {v["source"]: k for k, v in idx.items()}
        failures += check("index records every source once", len(idx), n)
        failures += check("index sources are the build sources",
                          sorted(v["source"] for v in idx.values()),
                          sorted(sources))
        failures += check("link takes objects in source order",
                          fake.link_objs,
                          [key_of[s] + ".obj" for s in sources])
        failures += check("index hashes match the object files",
                          all(G.sha256_file(obj_of(k)) == v["obj_sha256"]
                              for k, v in idx.items()), True)

        # 2. identical rebuild: nothing compiled, everything reused.
        fake.events = []
        (ok, tc, tl), out = run_build()
        failures += check("identical rebuild succeeds", ok, True)
        failures += check("identical rebuild compiles nothing",
                          counters(), (0, n))
        failures += check("identical rebuild prints the BUILD line", out,
                          "BUILD compiled=0 reused=%d\n" % n)
        failures += check("identical rebuild only links", fake.events,
                          ["link"])
        failures += check("obj_bytes counts only this build's objects",
                          G.LAST_BUILD["obj_bytes"],
                          sum(os.path.getsize(obj_of(k)) for k in idx))

        # 3. one source byte changed: exactly that source recompiled.
        _write(rpath("src/host_random.c"),
               b"/* host_random changed */\n")
        fake.events = []
        (ok, tc, tl), out = run_build()
        failures += check("one changed source: build succeeds", ok, True)
        failures += check("one changed source: compiled == 1, reused == n-1",
                          counters(), (1, n - 1))
        failures += check("one changed source: only it is compiled",
                          fake.events,
                          ["compile:host_random.c", "link"])

        # 4. a cached object whose bytes were corrupted is recompiled.
        idx = read_index()
        key_of = {v["source"]: k for k, v in idx.items()}
        probe_key = key_of[rpath(rel_fixed[0])]
        _write(obj_of(probe_key), b"CORRUPT")
        fake.events = []
        (ok, tc, tl), out = run_build()
        failures += check("corrupt cached object: build succeeds", ok, True)
        failures += check("corrupt cached object: compiled == 1",
                          counters(), (1, n - 1))
        failures += check("corrupt cached object: that source recompiled",
                          fake.events,
                          ["compile:aot_g3_start_probe.c", "link"])
        failures += check("corrupt cached object: rebuilt hash is indexed",
                          G.sha256_file(obj_of(probe_key)),
                          read_index()[probe_key]["obj_sha256"])

        # 5. a failed compile returns False and records nothing.
        _write(img("sdk.c"), b"/* sdk v2 */\n")
        with open(index_path, "rb") as f:
            before = f.read()
        fake.fail_source = "sdk.c"
        fake.events = []
        (ok, tc, tl), out = run_build()
        failures += check("failed compile returns ok False", ok, False)
        failures += check("failed compile: compiled == 0, reused == n-1",
                          counters(), (0, n - 1))
        # Failure echoes the compiler stdout first (as before), then BUILD.
        failures += check("failed compile prints the BUILD line last",
                          out.endswith("BUILD compiled=0 reused=%d\n"
                                       % (n - 1)), True)
        failures += check("failed compile never links", fake.events,
                          ["compile:sdk.c"])
        with open(index_path, "rb") as f:
            after = f.read()
        failures += check("failed compile leaves cache.json unchanged",
                          after, before)
        failures += check("failed compile leaves no tmp objects",
                          [f for f in os.listdir(objdir)
                           if f.startswith("tmp_")], [])

        # 6. after the failure is fixed, only the failed source compiles.
        fake.fail_source = None
        fake.events = []
        (ok, tc, tl), out = run_build()
        failures += check("retry after failure succeeds", ok, True)
        failures += check("retry after failure: compiled == 1",
                          counters(), (1, n - 1))
        failures += check("retry after failure: only sdk.c compiled",
                          fake.events, ["compile:sdk.c", "link"])
    finally:
        G._run_bat, G.compiler_id = saved_run, saved_id
        G._COMPILER_IDS.clear()
        shutil.rmtree(build_tmp, ignore_errors=True)

    failures += catalog_backend_checks()
    if failures:
        print("FAIL: %d classification check(s)" % failures)
        return 1
    print("PASS: g3_start_prefix classification + veneer follow selection")
    return 0


if __name__ == "__main__":
    sys.exit(main())
