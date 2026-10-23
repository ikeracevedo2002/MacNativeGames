#!/usr/bin/env python3
"""Game-data-free deterministic tests for g3_start_prefix STOP classification."""

import sys

sys.dont_write_bytecode = True

import contextlib
import io
import os
import struct
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
        "t_total": 0.0, "c_bytes": {}, "obj_bytes": None, "exe_bytes": 8192,
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

    if failures:
        print("FAIL: %d classification check(s)" % failures)
        return 1
    print("PASS: g3_start_prefix classification + veneer follow selection")
    return 0


if __name__ == "__main__":
    sys.exit(main())
