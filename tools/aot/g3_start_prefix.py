#!/usr/bin/env python3
"""Reusable ORIGINAL nn::init::Start-prefix partial-AOT driver (local only).

This is the focused Start driver, not the all-init-array batch:
  * roots are the REAL Start symbol, the five transparent observer functions
    the start probe delegates to, each module's DT_INIT, and a statically
    extracted batch of indirect targets already reachable from those roots;
  * an indirect target is added only when it is a DEFINED STT_FUNC in the
    module's own dynsym (WEAK included). A relocation value alone is a
    candidate, never proof, so an unknown target is reported fail-closed;
  * partial images are translated, compiled with /W4 /WX and run through
    tests/aot/aot_g3_start_probe.c;
  * the loop continues while the runtime reaches AOT_FAULT_UNTRANSLATED and
    the target is statically justified. It stops at the first real typed
    blocker: AOT_FAULT_UNSUPPORTED_INSN (16), an unregistered SVC
    (AOT_FAULT_BAD_HLE, 7), or any other non-transfer fault.

No game data is written to the repository. The external v0/link and v0/flat
inputs are read-only; every generated image/object/log goes under --work.
The probe never fabricates SVC success: an unhandled SVC is the typed BAD_HLE
with its site and immediate. Exit 0 = real typed blocker, 2 = no blocker
(clean return or follow limit), 1 = infrastructure/justification failure.
"""

import sys

sys.dont_write_bytecode = True

import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import tempfile
import time
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import aot_module as M          # noqa: E402
import aot_translate as T       # noqa: E402
import g3_ctor_roots as CR      # noqa: E402
import g3_init_reach as R       # noqa: E402
import g3_local_switch as LS    # noqa: E402
import g3_veneer_roots as VR    # noqa: E402
import g4_romfs_config as RC    # noqa: E402

CORE = [
    "src/aot/aot_prog_assembly.c",
    "src/aot/aot_program.c",
    "src/aot/aot_runtime.c",
    "src/aot/aot_mem.c",
    "src/aot/aot_as.c",
    "src/aot/aot_loader.c",
    "src/aot/aot_sha256.c",
    "src/aot/aot_fp.c",
    "src/host_vm.c",
    "src/host_thread.c",
    "src/host_time.c",
    "src/host_time_convert.c",
]

START_SYM = "_ZN2nn4init5StartEmmPFvvES2_S2_"
# The probe pins this exact VA; resolve it from dynsym instead of trusting it.
START_VA = 0x10200FA060
# Required keys of every --timing-out record (one per completed iteration).
TIMING_KEYS = ("iteration", "backend", "roots", "t_translate", "t_bind",
               "t_emit_desc", "t_compile", "t_link", "t_run", "t_classify",
               "t_total", "c_bytes", "obj_bytes", "exe_bytes", "steps",
               "stop", "admitted")


class DriverError(Exception):
    pass


def fail(msg):
    print("FAIL: " + msg)
    return 1


def _inside(repo, path):
    try:
        common = os.path.commonpath([os.path.normcase(repo),
                                     os.path.normcase(path)])
    except ValueError:
        common = ""
    return os.path.normcase(common) == os.path.normcase(repo)


def sha256_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def load_meta(v0):
    with open(os.path.join(v0, "link", "real_counters.json"),
              encoding="utf-8") as f:
        counters = json.load(f)
    modules = []
    for spec in counters["modules"]:
        name = spec["name"]
        base = int(spec["guest_base"])
        modules.append(dict(name=name, base=base,
                            init_va=int(spec["init_va"]),
                            image_size=int(spec["image_size"]),
                            sha256=spec["sha256"]))
    modules.sort(key=lambda m: m["base"])
    return modules


def crosscheck_inputs(v0, modules):
    """Canonical v0/link vs v0/flat must be the same bytes and bases."""
    for m in modules:
        rel = m["name"].rsplit("_real", 1)[0]
        link_flat = os.path.join(v0, "link", m["name"] + ".flat")
        flat_flat = os.path.join(v0, "flat", rel + ".flat")
        a, b = sha256_file(link_flat), sha256_file(flat_flat)
        if a != b or a != m["sha256"]:
            raise DriverError("flat hash mismatch for %s: link=%s flat=%s "
                              "counter=%s" % (m["name"], a[:16], b[:16],
                                              m["sha256"][:16]))
        with open(os.path.join(v0, "flat", rel + ".layout.json"),
                  encoding="utf-8") as f:
            lay = json.load(f)
        if int(lay.get("image_size", -1)) != m["image_size"]:
            raise DriverError("layout image_size mismatch for %s" % m["name"])
        if lay.get("sha256") and lay["sha256"] != a:
            raise DriverError("layout sha mismatch for %s" % m["name"])
    print("CROSSCHECK link==flat sha256 image_size bases OK (%d modules)"
          % len(modules))


def symbol_index(v0, modules):
    """guest VA -> list of DEFINED STT_FUNC dynsym entries (weak included)."""
    index = {}
    by_module = {}
    for m in modules:
        mod = M.load_module(os.path.join(v0, "link", m["name"] + ".flat"),
                            os.path.join(v0, "link",
                                         m["name"] + ".layout.json"),
                            m["name"], m["base"])
        by_module[m["name"]] = mod
        for sym in mod["syms"]:
            if (sym["type"] == M.STT_FUNC and sym["name"]
                    and M.sym_defined(sym, mod["image_size"])):
                index.setdefault(m["base"] + sym["value"], []).append(
                    (m["name"], sym["name"], sym["bind"], sym["size"]))
    return index, by_module


def resolve_unique(by_module, modules, index, name, want_module=None):
    hits = []
    for modname, mod in by_module.items():
        if want_module is not None and modname != want_module:
            continue
        for sym in mod["syms"]:
            if (sym["name"] == name and sym["type"] == M.STT_FUNC
                    and M.sym_defined(sym, mod["image_size"])):
                base = next(m["base"] for m in modules
                            if m["name"] == modname)
                hits.append((modname, base + sym["value"], sym))
    if len(hits) != 1:
        raise DriverError("symbol %r must resolve to exactly one DEFINED "
                          "STT_FUNC, got %d" % (name, len(hits)))
    return hits[0]


def module_of(va, modules):
    for m in modules:
        if m["base"] <= va < m["base"] + m["image_size"]:
            return m
    return None


def text_range(v0, m):
    rel = m["name"].rsplit("_real", 1)[0]
    with open(os.path.join(v0, "link", m["name"] + ".layout.json"),
              encoding="utf-8") as f:
        lay = json.load(f)
    off, size = lay["text"]
    return m["base"] + off, m["base"] + off + size


def justified(index, va, modules):
    """Return (module, symbol, bind, size) iff va is a DEFINED STT_FUNC."""
    if module_of(va, modules) is None:
        return None
    hits = index.get(va)
    if not hits:
        return None
    # Prefer the unique symbol that owns the exact VA; multiple aliases are
    # still code evidence but must not disagree on the owning module.
    mods = {h[0] for h in hits}
    if len(mods) != 1:
        return None
    return hits[0]


def indirect_site_kind(flat, base, text, va):
    """'br'/'blr' iff the ORIGINAL word at va is an indirect branch in TEXT.

    Anything else (RET, direct B, a host-callback site, an address outside the
    known TEXT extent, or an undecodable/unreadable word) returns None, which
    keeps the narrow veneer category out of that case entirely.
    """
    lo, hi = text
    if not (lo <= va < hi) or va + 4 > hi or va % 4:
        # The WHOLE 4-byte original word must lie inside TEXT: a readable word
        # that merely STARTS inside the text extent is not evidence.
        return None
    off = va - base
    if off < 0 or off + 4 > len(flat):
        return None
    word = struct.unpack_from("<I", flat, off)[0]
    try:
        ins = T.decode(va, word, module=True)
    except T.DecodeError:
        return None
    kind = ins["kind"]
    return kind if kind in ("br", "blr") else None


def select_follow(target, nnmain_va, old_justify, site_kind, prover_factory,
                  ctor_decide=None):
    """The Start-prefix follow-selection seam (real driver AND hermetic tests).

    Order is the policy, and it is deterministic:
      1. the pre-G4 nnMain guard wins and NEVER constructs/proves anything;
      2. the UNCHANGED old exact-DEFINED-STT_FUNC rule decides first;
      3. only when the old lookup fails AND the ORIGINAL fault-site instruction
         is an indirect BR/BLR inside TEXT is the frozen compound veneer proof
         consulted once for this exact target;
      4. a refusal is final: no nearest match, no second category, no retry.

    D023: after the nnMain guard and BEFORE step 2, `ctor_decide(target)` may
    claim the site.  It returns None when the fault site is not the proven
    DT_INIT array-walk call (steps 2-3 then run unchanged), otherwise a final
    verdict: the site IS the class, so a refusal is final (no D021/old fallback)
    and an admission is `kind='ctor'` (label 'ctor:<module>#<index>').

    Returns {'kind': 'pre_g4_boundary'|'old'|'veneer'|'refused', ...}.  For
    'veneer' the label is 'veneer:'+tail symbol name; no STT symbol is ever
    fabricated for the observed value.
    """
    if is_pre_g4_boundary_target(target, nnmain_va):
        return {"kind": "pre_g4_boundary", "hit": None, "label": None}
    if ctor_decide is not None:
        verdict = ctor_decide(target)
        if verdict is not None:
            if not verdict.ok:
                return {"kind": "refused", "hit": None, "label": None,
                        "reason": verdict.reason, "detail": verdict.detail}
            return {"kind": "ctor", "hit": None, "label": verdict.label,
                    "evidence": verdict.evidence}
    hit = old_justify(target)
    if hit is not None:
        return {"kind": "old", "hit": hit, "label": None}
    if site_kind not in ("br", "blr"):
        return {"kind": "refused", "hit": None, "label": None,
                "reason": "fault-site-not-indirect",
                "detail": "the original fault-site word is not an indirect "
                          "BR/BLR inside known TEXT"}
    proof = prover_factory().prove(target)
    if not proof.ok:
        return {"kind": "refused", "hit": None, "label": None,
                "reason": proof.reason, "detail": proof.detail}
    evidence = proof.evidence
    if (evidence.get("tail") or {}).get("target") == nnmain_va:
        return {"kind": "refused", "hit": None, "label": None,
                "reason": "tail-is-nnmain",
                "detail": "the proven veneer tail is the pre-G4 nnMain 0x%x; "
                          "refusing to seed/translate it" % nnmain_va}
    return {"kind": "veneer", "hit": None,
            "label": "veneer:" + evidence["tail"]["symbol"]["name"],
            "evidence": evidence}


def record_follow(by_mod, modules, target, label):
    """Add one followed root; refuse an owner-less or already-present one."""
    owner = module_of(target, modules)
    if owner is None:
        return False, "target 0x%x is outside every module" % target
    entries = by_mod.setdefault(owner["name"], {})
    if target in entries:
        return False, "target 0x%x is already a root" % target
    entries[target] = label
    return True, None


def reached_for_modules(by_module, world, reached):
    """Re-key the world's reached-word map onto the RUNTIME module names.

    `R.load_world` names images after the base flat file (`v0/flat/main.flat`
    -> "main"), while the runtime modules in `by_module` are named after the
    expected-linked image (`v0/link/main_real.flat` -> "main_real").  Identity
    is UNIQUE guest base + identical TEXT extent, plus byte-identical TEXT
    words: `R.load_world` deliberately reads the ORIGINAL flat (relocations in
    DATA make the full flat SHA differ), so only TEXT may be compared, and no
    name rewriting, title mapping or versioned alias is involved.
    """
    images = list(world.images)
    used = set()
    out = {}
    for mod in by_module.values():
        name = mod["name"]
        base = mod["base"]
        cands = [im for im in images if im.base == base]
        if not cands:
            raise DriverError(
                "veneer proof input: no world image shares module %s guest "
                "base 0x%x (reached map cannot be bound)" % (name, base))
        if len(cands) > 1:
            raise DriverError(
                "veneer proof input: %d world images share module %s guest "
                "base 0x%x (ambiguous identity)" % (len(cands), name, base))
        im = cands[0]
        if im.name in used:
            raise DriverError(
                "veneer proof input: world image %s matched more than one "
                "runtime module" % im.name)
        used.add(im.name)
        try:
            mtext = [int(x) for x in mod["layout"]["text"]]
            wtext = [int(x) for x in im.layout["text"]]
        except (TypeError, ValueError, KeyError, IndexError) as exc:
            raise DriverError(
                "veneer proof input: TEXT extent is not numeric for module %s "
                "or world image %s (%r / %r)"
                % (name, im.name, mod["layout"].get("text"),
                   im.layout.get("text"))) from exc
        if mtext != wtext:
            raise DriverError(
                "veneer proof input: TEXT extent differs for module %s "
                "(runtime %r vs world %r at base 0x%x)"
                % (name, mtext, wtext, base))
        off, size = mtext
        mbytes = bytes(mod["flat"][off:off + size])
        wbytes = bytes(im.flat[off:off + size])
        if len(mbytes) != size or len(wbytes) != size:
            raise DriverError(
                "veneer proof input: TEXT extent [0x%x,0x%x) is outside the "
                "flat of module %s or world image %s"
                % (off, off + size, name, im.name))
        if mbytes != wbytes:
            raise DriverError(
                "veneer proof input: TEXT bytes differ between module %s and "
                "world image %s at base 0x%x (reached map describes different "
                "code; refusing to prove)" % (name, im.name, base))
        out[name] = set(reached.get(im.name, ()))
    missing = sorted(im.name for im in images if im.name not in used)
    if missing:
        raise DriverError(
            "veneer proof input: world image(s) %s have no matching runtime "
            "module (unbound reached words)" % ", ".join(missing))
    return out


def make_prover_factory(by_module, scan, world):
    """Lazy frozen `Prover` factory built from the existing full snapshots.

    The constructor takes NO observed target: it freezes every module and
    derives ALL reached materializations, so it is independent of whatever
    target later triggers it.  A documented proof-input failure is a host
    DriverError, never a successful root and never a semantic negative result.
    """
    state = {}

    def factory():
        if "prover" not in state:
            try:
                reached = VR.reached_from_scan(scan, world)
                state["prover"] = VR.Prover(
                    list(by_module.values()),
                    reached_for_modules(by_module, world, reached))
            except (VR.InputError, KeyError, TypeError, IndexError) as exc:
                # Incomplete/malformed descriptors are documented input
                # errors: never a successful root, never a semantic negative.
                raise DriverError("veneer proof input: %s" % exc) from exc
        return state["prover"]

    return factory


def write_veneer_audit(work, audits):
    """Write the JSON audit under --work only (never into the source tree)."""
    path = os.path.join(work, "veneer_audit.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"schema": 1, "kind": "veneer", "count": len(audits),
                   "entries": audits}, f, indent=2, sort_keys=True)
        f.write("\n")
    return path


def bind_veneer_flat_sha(metas, audits):
    """Bind each proof's frozen flat SHA to the COMPILED module metadata.

    A compound proof is only as strong as EVERY module it cites: the OWNER of
    the veneer AND every module that produced a reached ADRP+ADD
    materialization must be bound to the exact bytes the compiled image came
    from.  The proof deep-copies each materialization record with its internal
    immutable `sourceModuleSHA`, so a producer in ANOTHER module cannot slip
    past an owner-only check.

    `source_sha256` is the generated image's actual flat SHA (`provenance_sha256`
    is a different translator+layout digest and must not be used here).  A
    missing module, missing metadata or missing/corrupt hash is a DriverError:
    there is no silent fallback to a weaker binding.
    """
    for audit in audits:
        evidence = audit["evidence"]
        owner = evidence["owner"]
        mats = evidence.get("materialization")
        if not isinstance(mats, list) or not mats:
            # The frozen compound prover ALWAYS cites >= 1 reached ADRP+ADD
            # producer.  Missing/empty/non-list provenance is owner-only
            # evidence, i.e. not a compound proof at all.
            raise DriverError(
                "veneer audit: compound proof must cite at least one reached "
                "materialization producer (missing/empty/non-list "
                "materialization is owner-only evidence)")
        cited = {owner: evidence["flat_sha256"]}
        for rec in mats:
            if not isinstance(rec, dict):
                raise DriverError("veneer audit: materialization record is "
                                  "not a dict: %r" % (rec,))
            producer = rec.get("module")
            producer_sha = rec.get("sourceModuleSHA")
            if not isinstance(producer, str) or not producer:
                raise DriverError("veneer audit: materialization record has "
                                  "no producer module name")
            if not isinstance(producer_sha, str) or not producer_sha:
                raise DriverError("veneer audit: producer %s materialization "
                                  "record has no sourceModuleSHA"
                                  % producer)
            prev = cited.get(producer)
            if prev is not None and prev != producer_sha:
                raise DriverError(
                    "veneer audit: producer %s is cited with conflicting "
                    "flat SHAs %s != %s" % (producer, prev, producer_sha))
            cited[producer] = producer_sha
        for name in sorted(cited):
            want = cited[name]
            meta = metas.get(name)
            if meta is None:
                raise DriverError("veneer audit: module %s has no compiled "
                                  "metadata" % name)
            got = meta.get("source_sha256")
            if got != want:
                raise DriverError(
                    "veneer audit: proof flat SHA %s for %s != compiled "
                    "metadata source_sha256 %s (proof and generated code "
                    "disagree; refusing to execute the rebuilt image)"
                    % (want, name, got))
    return True


def batch_indirect_targets(world, roots, index, modules, stop_entries=None):
    """Static over-approximation: every reachable indirect text target that is
    independently a DEFINED STT_FUNC. Relocation values alone are excluded.

    `stop_entries` is forwarded to the scan as a hard boundary, so code that is
    only reachable through an out-of-scope entry (the pre-G4 `nnMain`) neither
    becomes a batch root nor donates reached producer words to the prover.
    """
    scan = R.scan_world(world, roots, subset_decoder=None,
                        stop_entries=stop_entries)
    out = []
    rejected = []
    for mod, pc, mn, reg, value, kind in scan.indirects:
        if not kind.startswith("text"):
            continue
        hit = justified(index, value, modules)
        if hit is None:
            rejected.append((mod, pc, mn, value, kind))
            continue
        out.append((value, hit))
    return out, rejected, scan


def translate(repo, args, work, v0, modules, entries):
    imgs = {}
    metas = {}
    secs = {}
    for m in modules:
        name = m["name"]
        es = sorted(entries.get(name, set()))
        if m["init_va"] not in es:
            raise DriverError("%s: DT_INIT 0x%x missing from roots"
                              % (name, m["init_va"]))
        ep = os.path.join(work, "entries_%s.json" % name)
        with open(ep, "w", encoding="utf-8") as f:
            json.dump(es, f)
        img = os.path.join(work, "img", name + ".c")
        meta = os.path.join(work, "img", name + ".meta.json")
        t0 = time.perf_counter()
        run([args.python, os.path.join(repo, "tools", "aot",
                                       "aot_translate.py"),
             "--module", "--partial",
             "--flat", os.path.join(v0, "link", name + ".flat"),
             "--layout", os.path.join(v0, "link", name + ".layout.json"),
             "--guest-base", hex(m["base"]), "--entries", ep,
             "--name", name, "--out", img, "--meta-out", meta])
        secs[name] = time.perf_counter() - t0
        imgs[name] = img
        with open(meta, encoding="utf-8") as f:
            metas[name] = json.load(f)
    return imgs, metas, secs


def emit_desc(repo, args, work, v0, modules):
    desc = os.path.join(work, "real_desc_partial.c")
    image_map = {m["name"]: "aot_image_%s" % m["name"] for m in modules}
    images_json = os.path.join(work, "images.json")
    with open(images_json, "w", encoding="utf-8") as f:
        json.dump(image_map, f)
    run([args.python, os.path.join(repo, "tools", "aot", "aot_module.py"),
         "emit-desc",
         "--config", os.path.join(v0, "link", "real_link_config.json"),
         "--dir", os.path.join(v0, "link"), "--variant", "real",
         "--out-c", desc, "--images", images_json])
    return desc


def run(cmd, **kw):
    p = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if p.returncode != 0:
        sys.stdout.write(p.stdout)
        sys.stderr.write(p.stderr)
        raise DriverError("command failed: %s" % (cmd,))
    return p


# Per-TU compile flags, in the order the single-cl build used them. The /I
# paths are repo-relative: the compile bat runs with cwd = repo, so the list
# is a constant and the cache key does not depend on where the checkout is.
COMPILE_FLAGS = ["/nologo", "/W4", "/WX", "/O2", "/std:c11", "/bigobj",
                 "/D_CRT_SECURE_NO_WARNINGS",
                 "/Isrc\\aot", "/Isrc", "/Itests\\aot"]
HEADER_DIRS = ("src", "src/aot", "tests/aot")

# Counters of the most recent build() (tests read them).
LAST_BUILD = {"compiled": 0, "reused": 0}
_COMPILER_IDS = {}


def _win(path):
    return path.replace("/", "\\")


def header_digest(repo):
    """SHA-256 over every *.h (non-recursive) in HEADER_DIRS that exists."""
    found = []
    for rel_dir in HEADER_DIRS:
        d = os.path.join(repo, *rel_dir.split("/"))
        if not os.path.isdir(d):
            continue
        for name in sorted(os.listdir(d)):
            full = os.path.join(d, name)
            if name.endswith(".h") and os.path.isfile(full):
                with open(full, "rb") as f:
                    found.append((rel_dir + "/" + name, f.read()))
    h = hashlib.sha256()
    for rel, data in sorted(found):
        h.update(rel.encode("utf-8") + b"\0")
        h.update(str(len(data)).encode("ascii") + b"\0")
        h.update(data)
    return h.hexdigest()


def cache_key(source_bytes, flags, compiler_id, headers_sha):
    doc = {"src": hashlib.sha256(source_bytes).hexdigest(),
           "flags": list(flags), "compiler": compiler_id,
           "headers": headers_sha}
    canon = json.dumps(doc, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def _run_bat(bat_path):
    p = subprocess.run([bat_path], capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def compiler_id(args):
    """SHA-256 of cl's first non-blank banner line; one cl run per process."""
    key = (args.vcvars, args.cl)
    if key not in _COMPILER_IDS:
        tdir = tempfile.mkdtemp(prefix="g3clid_")
        try:
            bat = os.path.join(tdir, "cl_id.bat")
            with open(bat, "w", encoding="ascii") as f:
                f.write('@call "%s" >nul\r\n' % _win(args.vcvars))
                f.write('"%s"\r\n' % _win(args.cl))
            _rc, out, err = _run_bat(bat)
        finally:
            shutil.rmtree(tdir, ignore_errors=True)
        lines = [ln for ln in (out + err).splitlines() if ln.strip()]
        if not lines:
            raise DriverError("cl printed no banner; cannot key the cache")
        _COMPILER_IDS[key] = hashlib.sha256(
            lines[0].encode("utf-8")).hexdigest()
    return _COMPILER_IDS[key]


def _flatten_images(images):
    """Image paths: modules by name, list order kept within a module."""
    out = []
    for name in sorted(images):
        value = images[name]
        if isinstance(value, str):
            out.append(value)
        else:
            out.extend(value)
    return out


def _obj_path(objdir, key):
    return os.path.join(objdir, key + ".obj")


def _tmp_obj(objdir, key):
    return os.path.join(objdir, "tmp_%s.obj" % key)


def _load_index(path):
    try:
        with open(path, encoding="utf-8") as f:
            idx = json.load(f)
    except (OSError, ValueError):
        return {}
    return idx if isinstance(idx, dict) else {}


def _save_index(path, idx):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(idx, f, indent=1, sort_keys=True)
    os.replace(tmp, path)


def _reusable(ent, obj):
    return (isinstance(ent, dict) and os.path.isfile(obj)
            and sha256_file(obj) == ent.get("obj_sha256"))


def _append_log(log_path, out, err):
    with open(log_path, "a", encoding="utf-8") as lf:
        lf.write(out)
        lf.write(err)


def _echo_failure(out, err):
    sys.stdout.write(out)
    sys.stderr.write(err)


def _compile_missing(repo, work, args, index, index_path, todo, log_path):
    """Compile (src, key) pairs to tmp objects, then publish them.

    Any failure returns False and records nothing in the index.
    """
    objdir = os.path.join(work, "obj")
    lines = ['@call "%s" >nul' % _win(args.vcvars),
             'cd /d "%s" || exit /b 1' % _win(repo)]
    for src, key in todo:
        cmd = (['"%s"' % _win(args.cl), "/c"] + COMPILE_FLAGS
               + ["/MP", '/Fo:"%s"' % _win(_tmp_obj(objdir, key)),
                  '"%s"' % _win(src), "|| exit /b 1"])
        lines.append(" ".join(cmd))
    bat = os.path.join(work, "build_compile.bat")
    with open(bat, "w", encoding="ascii") as f:
        f.write("\r\n".join(lines) + "\r\n")
    rc, out, err = _run_bat(bat)
    _append_log(log_path, out, err)
    produced = all(os.path.isfile(_tmp_obj(objdir, key))
                   for _src, key in todo)
    if rc != 0 or not produced:
        _echo_failure(out, err)
        for _src, key in todo:
            if os.path.exists(_tmp_obj(objdir, key)):
                os.remove(_tmp_obj(objdir, key))
        return False
    recorded = dict(index)
    for src, key in todo:
        final = _obj_path(objdir, key)
        os.replace(_tmp_obj(objdir, key), final)
        recorded[key] = {"source": src, "obj_sha256": sha256_file(final)}
    _save_index(index_path, recorded)
    LAST_BUILD["compiled"] = len(todo)
    return True


def _link(work, args, exe, objs, log_path):
    if args.cl != "cl.exe":
        linker = '"%s"' % _win(os.path.join(os.path.dirname(args.cl),
                                            "link.exe"))
    else:
        linker = "link"
    cmd = ([linker, "/nologo", '/OUT:"%s"' % _win(exe)]
           + ['"%s"' % _win(o) for o in objs]
           + ["bcrypt.lib", "|| exit /b 1"])
    bat = os.path.join(work, "build_link.bat")
    with open(bat, "w", encoding="ascii") as f:
        f.write('@call "%s" >nul\r\n' % _win(args.vcvars))
        f.write(" ".join(cmd) + "\r\n")
    rc, out, err = _run_bat(bat)
    _append_log(log_path, out, err)
    if rc != 0:
        _echo_failure(out, err)
        return False
    return True


def _build_result(ok, t_compile, t_link):
    print("BUILD compiled=%d reused=%d"
          % (LAST_BUILD["compiled"], LAST_BUILD["reused"]))
    return ok, t_compile, t_link


def build(repo, work, args, desc, images, exe, config_c):
    """Compile stale per-TU objects, then link.

    Returns (ok, t_compile, t_link). Objects are cached as
    work/obj/<cache_key>.obj with an index in work/obj/cache.json; the
    compiler output of this build is in work/build_start.log.
    """
    repo = os.path.abspath(repo)
    LAST_BUILD["compiled"] = 0
    LAST_BUILD["reused"] = 0
    objdir = os.path.join(work, "obj")
    index_path = os.path.join(objdir, "cache.json")
    log_path = os.path.join(work, "build_start.log")
    open(log_path, "w", encoding="utf-8").close()
    sources = ([os.path.join(repo, "tests", "aot", "aot_g3_start_probe.c"),
                os.path.join(repo, "tests", "aot", "g3_start_hle.c"),
                os.path.join(repo, "tests", "aot", "g4_romfs_start_hle.c"),
                os.path.join(repo, "src", "romfs_provider.c"),
                os.path.join(repo, "src", "romfs_file_win.c"),
                os.path.join(repo, "src", "host_random.c"), desc, config_c]
               + _flatten_images(images)
               + [os.path.join(repo, s) for s in CORE])
    try:
        cid = compiler_id(args)
    except DriverError as exc:
        print("FAIL: " + str(exc))
        return _build_result(False, 0.0, 0.0)
    headers = header_digest(repo)
    index = _load_index(index_path)
    os.makedirs(objdir, exist_ok=True)
    t0 = time.perf_counter()
    plan = []
    todo = []
    seen = set()
    reused = 0
    for src in sources:
        try:
            with open(src, "rb") as f:
                data = f.read()
        except OSError as exc:
            print("FAIL: cannot read build source: %s" % exc)
            return _build_result(False, 0.0, 0.0)
        key = cache_key(data, COMPILE_FLAGS, cid, headers)
        obj = _obj_path(objdir, key)
        plan.append(obj)
        if key in seen:
            continue
        seen.add(key)
        if _reusable(index.get(key), obj):
            reused += 1
        else:
            if os.path.exists(obj):
                os.remove(obj)
            todo.append((src, key))
    LAST_BUILD["reused"] = reused
    ok = True
    if todo:
        ok = _compile_missing(repo, work, args, index, index_path, todo,
                              log_path)
    t_compile = time.perf_counter() - t0
    t0 = time.perf_counter()
    if ok:
        ok = _link(work, args, exe, plan, log_path)
    return _build_result(ok, t_compile, time.perf_counter() - t0)


def classify_stop(st, decode, thunk_base, thunk_count):
    """Classify a terminal STOP without overclaiming what caused it."""
    code = st["code"]
    if code == 0:
        return {"kind": "clean_return", "svc_imm": None,
                "getinfo_status": None}
    if code == 10:
        return {"kind": "untranslated", "svc_imm": None,
                "getinfo_status": None}
    if code == 16:
        return {"kind": "unsupported", "svc_imm": None,
                "getinfo_status": None}
    if code != 7:
        return {"kind": "typed", "svc_imm": None, "getinfo_status": None}
    m = re.search(r"\bsvc\s+#(0x[0-9a-f]+|\d+)", decode or "", re.I)
    if m:
        imm = int(m.group(1), 0)
        # Only the registered 0x29 handler maps a nonnegative BAD_HLE
        # status to the unhandled GetInfo id. Never generalize this.
        status = st["status"]
        gi = status if imm == 0x29 and status >= 0 else None
        return {"kind": "svc", "svc_imm": imm, "getinfo_status": gi}
    lo = thunk_base
    hi = thunk_base + 16 * thunk_count
    in_window = thunk_count > 0 and lo <= st["src"] < hi
    # A missing HOSTCALL handler faults at the call site with status=thunk id;
    # the thunk VA itself is not in fault_src. Require both thunk metadata and
    # a branch-register decode before calling it a HOSTCALL.
    branch = re.search(r"\b(?:blr|br|bl)\b", decode or "", re.I)
    thunk_id = st["status"]
    if in_window or (thunk_count > 0 and branch is not None and
                     0 <= thunk_id < thunk_count):
        return {"kind": "hostcall", "svc_imm": None,
                "getinfo_status": None}
    return {"kind": "bad_hle_unknown", "svc_imm": None,
            "getinfo_status": None}


def is_pre_g4_boundary_target(target, nnmain_va):
    """nnMain is a deliberate pre-G4 stop, never a follow/seed candidate."""
    return target == nnmain_va


def filter_pre_g4_batch(batch, nnmain_va):
    """Split supplemental STT_FUNC roots, excluding the real nnMain VA."""
    kept = []
    excluded = []
    for va, hit in batch:
        if is_pre_g4_boundary_target(va, nnmain_va):
            excluded.append((va, hit))
        else:
            kept.append((va, hit))
    return kept, excluded


def result_exit_code(kind):
    """Exit 2 means no G3 pass claim: clean return or explicit pre-G4 stop."""
    return 2 if kind in ("clean_return", "pre_g4_boundary") else 0


def parse_gprs(out, stop):
    """Strict parse of the probe STARTFAULTGPR lines for ONE fault.

    Exactly 31 lines (x0..x30, each once, code=10), each internally
    consistent (read_va == value-8, status/live coherent).  Anything else is a
    host DriverError: a partial capture is never evidence.  Returns None when
    the stop is not an UNTRANSLATED fault and no line exists.
    """
    rows = re.findall(
        r"^STARTFAULTGPR code=(\d+) reg=(\d+) value=0x([0-9a-f]+) "
        r"read_va=0x([0-9a-f]+) read_status=(-?\d+) live=0x([0-9a-f]+)$",
        out, re.M)
    if stop["code"] != 10:
        if rows:
            raise DriverError("STARTFAULTGPR lines on a non-UNTRANSLATED stop")
        return None
    if len(rows) != 31:
        raise DriverError("expected 31 STARTFAULTGPR lines, got %d"
                          % len(rows))
    gprs = {}
    for code, reg, value, rva, rstat, live in rows:
        reg, value, rva = int(reg), int(value, 16), int(rva, 16)
        rstat, live = int(rstat), int(live, 16)
        if int(code) != 10 or reg in gprs or not 0 <= reg <= 30:
            raise DriverError("bad/duplicate STARTFAULTGPR reg %d" % reg)
        if rva != (value - 8 if value >= 8 else 0):
            raise DriverError("STARTFAULTGPR x%d read_va != value-8" % reg)
        if (rstat != 0 and live != 0) or (value < 8 and rstat == 0):
            raise DriverError("STARTFAULTGPR x%d status/live incoherent"
                              % reg)
        gprs[reg] = {"value": value, "read_va": rva, "status": rstat,
                     "live": live}
    return gprs


def make_ctor_decide(v0, modules, world, nnmain_va, sentinel, st, gprs, mm,
                     auths=None):
    """Per-fault D023 decision callable (authority built lazily per owner).

    Returns target -> None (not the pinned loop) | CR.Verdict.  The owner
    authority is derived from that module's ORIGINAL world image only; other
    modules are never touched (SAME-MODULE class).
    """
    def decide(target):
        if mm is None or gprs is None:
            return None
        cands = [im for im in world.images if im.base == mm["base"]]
        if len(cands) != 1:
            return None
        image = cands[0]
        text = text_range(v0, mm)
        # CLASS = the pinned DT_INIT array-walk of the owner's DECLARED array
        # (loop shape AND DT_INIT-local CFG reach with GOT-bound provenance,
        # independent of slot contents).  Anything else - an ordinary callback
        # loop of the same shape, a module with no array, a loop DT_INIT does
        # not reach - is NOT the class and keeps the old STT_FUNC/D021 rules.
        # Once the class is established a malformed table / bad capture is a
        # FINAL typed refusal (never swallowed into the old rules).
        proof, refusal = CR.classify_site(image, text, st["src"])
        if refusal is not None:
            return CR.refuse(*refusal)       # declared array, bad entry
        if proof is None:
            return None                      # not class: old rules apply
        try:
            auth = None if auths is None else auths.get(image.name)
            if auth is None:
                sha = hashlib.sha256(image.flat).hexdigest()
                ctx = LS.Context(image.flat, image.layout, image.base,
                                 T.decode)
                auth = CR.Authority.build([image], {image.name: sha},
                                          {image.name: ctx},
                                          nnmain_va=nnmain_va,
                                          sentinel=sentinel)
                if auths is not None:
                    auths[image.name] = auth
        except CR.CtorRefusal as exc:
            return CR.refuse(exc.reason, exc.detail)
        except LS.InputError as exc:
            # The module declares the array but its metadata is malformed:
            # a typed FINAL refusal (class membership already established).
            return CR.refuse("ctor-metadata-invalid", str(exc))
        except CR.CtorInputError as exc:
            raise DriverError("ctor authority input: %s" % exc) from exc
        cur, bnd = gprs[proof["cursor_reg"]], gprs[proof["bound_reg"]]
        cursor = {"reg": proof["cursor_reg"], "value": cur["value"],
                  "slot_bytes": cur["live"] if cur["status"] == 0 else None,
                  "bound_reg": proof["bound_reg"],
                  "bound_value": bnd["value"]}
        return auth.prove(target, st["src"], "blr", cursor,
                          {image.name: (image.flat, image.base, text)})
    return decide


def parse_stop(out):
    m = re.search(r"^STARTSTOP code=(-?\d+) src=0x([0-9a-f]+) "
                  r"target=0x([0-9a-f]+) status=(-?\d+) "
                  r"steps=(\d+)(?: x0=0x([0-9a-f]+) x1=0x([0-9a-f]+) "
                  r"x2=0x([0-9a-f]+) x3=0x([0-9a-f]+) "
                  r"x4=0x([0-9a-f]+) x5=0x([0-9a-f]+) "
                  r"x6=0x([0-9a-f]+) x7=0x([0-9a-f]+) sp=0x([0-9a-f]+) "
                  r"return_out_valid=(\d+) return_out_x0=0x([0-9a-f]+))?",
                  out, re.M)
    if not m:
        return None
    regs = [int(m.group(i), 16) if m.group(i) else None
            for i in range(6, 14)]
    return dict(code=int(m.group(1)), src=int(m.group(2), 16),
                target=int(m.group(3), 16), status=int(m.group(4)),
                steps=int(m.group(5)), regs=regs[:8],
                sp=int(m.group(14), 16) if m.group(14) else None,
                return_out_valid=int(m.group(15)) if m.group(15) else None,
                return_out_x0=int(m.group(16), 16) if m.group(16) else None)


def capstone_one(flat, base, va):
    try:
        import capstone
    except ImportError:
        return None
    off = va - base
    if off < 0 or off + 4 > len(flat):
        return None
    word = struct.unpack_from("<I", flat, off)[0]
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    ins = list(md.disasm(struct.pack("<I", word), va, count=1))
    if not ins:
        return "word=0x%08x (Capstone cannot decode)" % word
    return "word=0x%08x %s %s" % (word, ins[0].mnemonic, ins[0].op_str)


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _is_nonneg_int(v):
    return _is_int(v) and v >= 0


def _is_secs(v):
    return (isinstance(v, (int, float)) and not isinstance(v, bool)
            and v >= 0)


def validate_timing_record(rec):
    if not isinstance(rec, dict):
        raise DriverError("timing record is not a dict: %r" % (rec,))
    missing = [k for k in TIMING_KEYS if k not in rec]
    if missing:
        raise DriverError("timing record missing keys %s" % missing)
    extra = sorted(set(rec) - set(TIMING_KEYS))
    if extra:
        raise DriverError("timing record has unexpected keys %s" % extra)
    if not _is_int(rec["iteration"]):
        raise DriverError("timing iteration must be int")
    if not isinstance(rec["backend"], str):
        raise DriverError("timing backend must be str")
    if rec["steps"] is not None and not _is_int(rec["steps"]):
        raise DriverError("timing steps must be int or None")
    for key, check, what in (("roots", _is_nonneg_int, "int"),
                             ("t_translate", _is_secs, "seconds"),
                             ("c_bytes", _is_nonneg_int, "int")):
        val = rec[key]
        if not isinstance(val, dict) or not all(
                isinstance(k, str) and check(v) for k, v in val.items()):
            raise DriverError("timing %s must be a dict of str -> %s"
                              % (key, what))
    for key in ("t_bind", "t_emit_desc", "t_compile", "t_link", "t_run",
                "t_classify", "t_total"):
        if not _is_secs(rec[key]):
            raise DriverError("timing %s must be a non-negative number"
                              % key)
    for key in ("obj_bytes", "exe_bytes"):
        if rec[key] is not None and not _is_nonneg_int(rec[key]):
            raise DriverError("timing %s must be int or None" % key)
    stop = rec["stop"]
    if stop is not None:
        if not isinstance(stop, dict) or set(stop) != {"code", "src",
                                                       "target", "status"}:
            raise DriverError("timing stop must be None or exactly "
                              "code,src,target,status")
        if not all(_is_int(v) for v in stop.values()):
            raise DriverError("timing stop fields must be int")
    adm = rec["admitted"]
    if adm is not None:
        if not isinstance(adm, dict) or set(adm) != {"kind", "va"}:
            raise DriverError("timing admitted must be None or exactly "
                              "kind,va")
        if not isinstance(adm["kind"], str) or not _is_int(adm["va"]):
            raise DriverError("timing admitted needs str kind and int va")
    return rec


def write_timing(path, records):
    for rec in records:
        validate_timing_record(rec)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=1, sort_keys=True)
    os.replace(tmp, path)


def iteration_record(work, iteration, entries, imgs, exe, st, t, admitted):
    """One TIMING_KEYS record from main()'s per-phase clocks (seconds)."""
    obj_sizes = [os.path.getsize(os.path.join(d, f))
                 for d, _dirs, files in os.walk(os.path.join(work, "obj"))
                 for f in files]
    stop = None
    if st is not None:
        stop = {k: st[k] for k in ("code", "src", "target", "status")}
    return validate_timing_record(dict(
        iteration=iteration, backend="legacy",
        roots={n: len(v) for n, v in entries.items()},
        t_translate=t["translate"], t_bind=t["bind"],
        t_emit_desc=t["emit_desc"], t_compile=t["compile"],
        t_link=t["link"], t_run=t["run"], t_classify=t["classify"],
        t_total=t["total"],
        c_bytes={n: os.path.getsize(p) for n, p in imgs.items()},
        obj_bytes=sum(obj_sizes) if obj_sizes else None,
        exe_bytes=os.path.getsize(exe) if os.path.exists(exe) else None,
        steps=st["steps"] if st is not None else None,
        stop=stop, admitted=admitted))


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=".")
    ap.add_argument("--work", required=True)
    ap.add_argument("--v0-dir", required=True)
    ap.add_argument("--python", default=sys.executable)
    ap.add_argument("--vcvars", required=True)
    ap.add_argument("--cl", default="cl.exe")
    ap.add_argument("--max-iterations", type=int, default=24)
    # Early-G4 RomFS is DISABLED unless an explicit external config is given.
    ap.add_argument("--romfs-config")
    ap.add_argument("--romfs-dir")
    ap.add_argument("--romfs-overlay-dir")
    ap.add_argument("--romfs-required-overlay-dir")
    ap.add_argument("--romfs-no-overlays", action="store_true")
    ap.add_argument("--timing-out")
    args = ap.parse_args(argv)
    repo = str(Path(args.repo).resolve())
    work = str(Path(args.work).resolve())
    v0 = str(Path(args.v0_dir).resolve())
    if _inside(repo, work):
        return fail("--work must be outside the repository")
    timing_out = None
    if args.timing_out:
        timing_out = str(Path(args.timing_out).resolve())
        if _inside(repo, timing_out):
            return fail("--timing-out must be outside the repository")
        os.makedirs(os.path.dirname(timing_out), exist_ok=True)
    os.makedirs(os.path.join(work, "img"), exist_ok=True)
    os.makedirs(os.path.join(work, "obj"), exist_ok=True)

    config_c = os.path.join(work, "romfs_start_config.c")
    try:
        start_cfg = RC.resolve_start_config(
            args.romfs_config,
            os.path.join(repo, "games", "totk", "assets",
                         "expected-v1.0.0.json"),
            resource_dir=args.romfs_dir,
            overlay_dir=args.romfs_overlay_dir,
            required_overlay_dir=args.romfs_required_overlay_dir,
            no_overlays=args.romfs_no_overlays,
        )
        RC.emit_config_c(start_cfg, config_c)
    except RC.ConfigError as exc:
        return fail("G4 RomFS config: %s" % exc)
    if start_cfg is None:
        print("G4CONFIG enabled=0 profile=headless-native output_res=0 "
              "(no --romfs-config; fs stays the pre-G4 BAD_HLE boundary; "
              "no resolution-overlay auto-selection)")
    else:
        print("G4CONFIG enabled=1 profile=%s output_res=%s resource=%s "
              "image_size=%d index_sha256=%s overlays=%s"
              % ("explicit-required-overlay"
                 if any(o["required"] for o in start_cfg["overlays"])
                 else "headless-native",
                 start_cfg["output_res"], start_cfg["resource_dir"],
                 start_cfg["image_size"], start_cfg["index_sha256"],
                 [o["dir"] for o in start_cfg["overlays"]]))

    timing = []     # one validated record per completed iteration
    try:
        modules = load_meta(v0)
        crosscheck_inputs(v0, modules)
        index, by_module = symbol_index(v0, modules)
        world = R.load_world(v0)
        start_mod, start_va, _start_sym = resolve_unique(
            by_module, modules, index, START_SYM, want_module="sdk_real")
        if start_va != START_VA:
            raise DriverError("Start resolves to 0x%x, probe pins 0x%x"
                              % (start_va, START_VA))
        nnmain_mod, nnmain_va, _nnmain_sym = resolve_unique(
            by_module, modules, index, "nnMain")
        if world.find(nnmain_va) is None or not world.in_text(nnmain_va):
            raise DriverError("nnMain 0x%x is not defined in main text"
                              % nnmain_va)
        print("PRE_G4_GUARD nnMain=%s 0x%x (never auto-follow/seed/execute)"
              % (nnmain_mod, nnmain_va))
        with open(os.path.join(v0, "link", "real_link_config.json"),
                  encoding="utf-8") as f:
            cfg = json.load(f)
        thunk_base = int(cfg["thunk_base"], 0) \
            if isinstance(cfg["thunk_base"], str) else int(cfg["thunk_base"])
        thunk_count = len(cfg.get("observers", {})) + \
            len(cfg.get("overrides", {}))
        roots = [(start_va, "start")]
        names = {start_va: START_SYM}
        # Five transparent observers are the REAL functions the probe
        # delegates to. nnMain stays unregistered (explicit pre-G4 boundary).
        for name in sorted(cfg["observers"]):
            if name == "nnMain":
                continue
            modname, va, sym = resolve_unique(by_module, modules, index, name)
            if world.find(va) is None or not world.in_text(va):
                raise DriverError("observer %s 0x%x is not in module text"
                                  % (name, va))
            roots.append((va, "observer:" + name))
            names[va] = name
            print("OBSERVER %s %s 0x%x size=%d bind=%d"
                  % (name, modname, va, sym["size"], sym["bind"]))
        for m in modules:
            roots.append((m["init_va"], "dt_init:" + m["name"]))
            names[m["init_va"]] = "DT_INIT:" + m["name"]
        by_mod = {}
        for va, kind in roots:
            mm = module_of(va, modules)
            if mm is None or not (text_range(v0, mm)[0] <= va
                                  < text_range(v0, mm)[1]):
                raise DriverError("root 0x%x (%s) is not in module text"
                                  % (va, kind))
            by_mod.setdefault(mm["name"], {})[va] = kind
        # Batch-known-callee extraction: all statically reachable indirect
        # text targets that are DEFINED STT_FUNC. This replaces one-callee-
        # per-run discovery; later runtime UNTRANSLATED targets still go
        # through the same static justification before they are added.
        batch, rejected, scan = batch_indirect_targets(
            world, roots, index, modules, stop_entries={nnmain_va})
        veneer_prover = make_prover_factory(by_module, scan, world)
        veneer_audit = []
        ctor_audit = []
        ctor_auths = {}            # lazy per-owner frozen D023 authorities
        added = 0
        batch, excluded_nnmain = filter_pre_g4_batch(batch, nnmain_va)
        for va, hit in excluded_nnmain:
            print("EXCLUDE_NNMAIN_BATCH 0x%x %s (pre-G4 boundary)"
                  % (va, hit[1]))
        for va, hit in batch:
            mm = module_of(va, modules)
            if va in by_mod[mm["name"]]:
                continue
            by_mod[mm["name"]][va] = "batch:" + hit[1]
            print("BATCH 0x%x %s (%s bind=%d size=%d)"
                  % (va, hit[1], hit[0], hit[2], hit[3]))
            added += 1
        print("ROOTS static_scan_entries=%d indirects=%d batch_added=%d "
              "unjustified_indirects=%d"
              % (len(scan.entries), len(scan.indirects), added,
                 len(rejected)))

        # Capstone evidence that the blocker site really is an SVC and what
        # immediate it carries (never guess a mnemonic from the fault code).
        blocker = None

        def done(admitted):
            """Close this iteration's clocks; record it when timing is on."""
            now = time.perf_counter()
            t["classify"] = now - t["cls0"]
            t["total"] = now - t["iter"]
            if timing_out:
                timing.append(iteration_record(work, iteration, entries, imgs,
                                               exe, st, t, admitted))
                write_timing(timing_out, timing)

        for iteration in range(args.max_iterations):
            print("== iteration %d" % iteration)
            t = {"iter": time.perf_counter()}
            entries = {}
            for name, vals in by_mod.items():
                entries[name] = set(vals)
            imgs, metas, t["translate"] = translate(repo, args, work, v0,
                                                    modules, entries)
            t0 = time.perf_counter()
            if veneer_audit:
                # Bind every proved flat SHA to the compiled image metadata
                # BEFORE the rebuilt image is executed.
                bind_veneer_flat_sha(metas, veneer_audit)
            if ctor_audit:
                # Bind the proved owner flat SHA to compiled metadata BEFORE
                # the rebuilt image executes (hard error, no weaker fallback).
                for a in ctor_audit:
                    owner = a["evidence"]["module"]
                    try:
                        CR.bind_flat_sha(ctor_auths.get(owner), metas, [a],
                                         {owner: a["runtime_module"]})
                    except CR.CtorInputError as exc:
                        raise DriverError("ctor audit binding: %s"
                                          % exc) from exc
            t["bind"] = time.perf_counter() - t0
            t0 = time.perf_counter()
            desc = emit_desc(repo, args, work, v0, modules)
            t["emit_desc"] = time.perf_counter() - t0
            exe = os.path.join(work, "aot_g3_start_probe.exe")
            built, t["compile"], t["link"] = build(
                repo, work, args, desc, imgs, exe, config_c)
            if not built:
                return fail("build failed")
            t0 = time.perf_counter()
            p = subprocess.run([exe, os.path.join(v0, "link")],
                               capture_output=True, text=True)
            t["run"] = time.perf_counter() - t0
            log = os.path.join(work, "run_start.log")
            with open(log, "w", encoding="utf-8") as lf:
                lf.write(p.stdout)
                lf.write(p.stderr)
            if p.returncode != 0:
                sys.stderr.write(p.stderr)
                return fail("probe exited %d" % p.returncode)
            t["cls0"] = time.perf_counter()
            st = parse_stop(p.stdout)
            if st is None:
                return fail("no STARTSTOP line")
            mm = module_of(st["src"], modules)
            if mm is not None:
                with open(os.path.join(v0, "link", mm["name"] + ".flat"),
                          "rb") as f:
                    flat = f.read()
                dec = capstone_one(flat, mm["base"], st["src"])
            else:
                dec = None
            cls = classify_stop(st, dec, thunk_base, thunk_count)
            print("STOP code=%d src=0x%x target=0x%x status=%d steps=%d "
                  "image=%s class=%s %s regs=%s"
                  % (st["code"], st["src"], st["target"], st["status"],
                     st["steps"], mm["name"] if mm else "?", cls["kind"],
                     dec or "capstone-unavailable",
                     ["0x%x" % r if r is not None else "?"
                      for r in st["regs"]]))
            if (st["code"] == 10 and
                    is_pre_g4_boundary_target(st["target"], nnmain_va)):
                blocker = dict(stop=st, image=mm["name"] if mm else None,
                               decode=dec, kind="pre_g4_boundary",
                               classification={"kind": "pre_g4_boundary",
                                               "svc_imm": None,
                                               "getinfo_status": None})
                print("PRE_G4_BOUNDARY kind=nnMain target=0x%x module=%s "
                      "(not seeded, not followed, not executed)"
                      % (st["target"], nnmain_mod))
                done(None)
                break
            if st["code"] == 10:
                site_kind = None
                if mm is not None:
                    site_kind = indirect_site_kind(flat, mm["base"],
                                                   text_range(v0, mm),
                                                   st["src"])
                gprs = parse_gprs(p.stdout, st)
                ctor_decide = make_ctor_decide(
                    v0, modules, world, nnmain_va, world.sentinel, st, gprs,
                    mm, ctor_auths)
                decision = select_follow(
                    st["target"], nnmain_va,
                    lambda va: justified(index, va, modules),
                    site_kind, veneer_prover, ctor_decide)
                if decision["kind"] == "ctor":
                    ok, why = record_follow(by_mod, modules, st["target"],
                                            decision["label"])
                    if not ok:
                        return fail(why)
                    ev = dict(decision["evidence"])
                    ctor_audit.append({
                        "target": "0x%x" % st["target"],
                        "label": decision["label"],
                        "fault_site": "0x%x" % st["src"],
                        "evidence": ev, "runtime_module": mm["name"]})
                    CR.write_audit(work, ctor_audit)
                    print("FOLLOW_CTOR 0x%x %s module=%s slot=%s (D023 "
                          "same-module DT_INIT_ARRAY walk; no STT symbol "
                          "fabricated)" % (st["target"], decision["label"],
                                           ev["module"], ev["slot"]))
                    done({"kind": decision["kind"], "va": st["target"]})
                    continue
                if decision["kind"] == "veneer":
                    ok, why = record_follow(by_mod, modules, st["target"],
                                            decision["label"])
                    if not ok:
                        return fail(why)
                    evidence = decision["evidence"]
                    veneer_audit.append({
                        "target": "0x%x" % st["target"],
                        "label": decision["label"],
                        "fault_site": "0x%x" % st["src"],
                        "fault_site_kind": site_kind,
                        "evidence": evidence})
                    write_veneer_audit(work, veneer_audit)
                    print("FOLLOW_VENEER 0x%x %s size=%d owner=%s "
                          "tail=0x%x tail_symbol=%s eh=0x%x (compound proof "
                          "passed; no STT symbol fabricated for the value)"
                          % (st["target"], decision["label"],
                             evidence["size"], evidence["owner"],
                             evidence["tail"]["target"],
                             evidence["tail"]["symbol"]["name"],
                             evidence["eh"]["offset"]))
                    done({"kind": decision["kind"], "va": st["target"]})
                    continue
                if decision["kind"] == "refused":
                    print("UNJUSTIFIED target 0x%x is not a DEFINED STT_FUNC "
                          "in module text; relocation evidence is ambiguous, "
                          "so it is not followed" % st["target"])
                    print("VENEER_REFUSED target=0x%x reason=%s detail=%s "
                          "(no fallback)"
                          % (st["target"], decision["reason"],
                             decision["detail"]))
                    return fail("UNTRANSLATED target 0x%x cannot be "
                                "statically justified" % st["target"])
                if decision["kind"] != "old":
                    return fail("follow selection returned %r for 0x%x"
                                % (decision["kind"], st["target"]))
                hit = decision["hit"]
                ok, why = record_follow(by_mod, modules, st["target"],
                                        "follow:" + hit[1])
                if not ok:
                    return fail(why)
                print("FOLLOW 0x%x %s (%s bind=%d size=%d)"
                      % (st["target"], hit[1], hit[0], hit[2], hit[3]))
                done({"kind": decision["kind"], "va": st["target"]})
                continue
            blocker = dict(stop=st, image=mm["name"] if mm else None,
                           decode=dec, kind=cls["kind"],
                           classification=cls)
            if st["code"] == 0:
                print("CLEAN_RETURN image=%s pc=0x%x status=0 steps=%d "
                      "(Start returned cleanly; this is NOT a G3 closure "
                      "or pass claim)"
                      % (mm["name"] if mm else "?", st["src"], st["steps"]))
            elif st["code"] == 16:
                if mm is None:
                    return fail("UNSUPPORTED src outside every image")
                table = metas[mm["name"]]["unsupported"]
                hit = [u for u in table if u["status"] == st["status"]]
                if not hit or int(hit[0]["pc"], 16) != st["src"]:
                    return fail("UNSUPPORTED status %d does not match offline "
                                "metadata at 0x%x" % (st["status"], st["src"]))
                u = hit[0]
                print("FIRST BLOCKER unsupported image=%s pc=%s word=%s "
                      "reason=%s" % (mm["name"], u["pc"], u["word"],
                                     u["reason"]))
            elif cls["kind"] == "svc":
                print("FIRST BLOCKER svc image=%s pc=0x%x svc_imm=0x%x "
                      "fault_status=%d resume=0x%x (typed "
                      "AOT_FAULT_BAD_HLE from the registered SVC handler)"
                      % (mm["name"] if mm else "?", st["src"],
                         cls["svc_imm"], st["status"], st["target"]))
                if cls["getinfo_status"] is not None:
                    print("SVC29_GETINFO_STATUS id=%d (only the known 0x29 "
                          "handler maps nonnegative status this way)"
                          % cls["getinfo_status"])
            elif cls["kind"] == "hostcall":
                print("FIRST BLOCKER hostcall image=%s src=0x%x target=0x%x "
                      "status=%d (typed AOT_FAULT_BAD_HLE at a thunk "
                      "site, not an SVC)"
                      % (mm["name"] if mm else "?", st["src"],
                         st["target"], st["status"]))
            elif cls["kind"] == "bad_hle_unknown":
                print("FIRST BLOCKER bad_hle_unknown image=%s src=0x%x "
                      "target=0x%x status=%d (no SVC decode and source is "
                      "outside the thunk window)"
                      % (mm["name"] if mm else "?", st["src"],
                         st["target"], st["status"]))
            else:
                print("FIRST BLOCKER typed code=%d image=%s src=0x%x "
                      "target=0x%x status=%d"
                      % (st["code"], mm["name"] if mm else "?", st["src"],
                         st["target"], st["status"]))
            done(None)
            break
        if blocker is None:
            return 2
        result = {
            "kind": blocker["kind"],
            "classification": blocker["classification"],
            "code": blocker["stop"]["code"],
            "src": "0x%x" % blocker["stop"]["src"],
            "target": "0x%x" % blocker["stop"]["target"],
            "status": blocker["stop"]["status"],
            "steps": blocker["stop"]["steps"],
            "image": blocker["image"],
            "decode": blocker["decode"],
            "regs": ["0x%x" % r if r is not None else None
                     for r in blocker["stop"]["regs"]],
            "sp": ("0x%x" % blocker["stop"]["sp"]
                   if blocker["stop"]["sp"] is not None else None),
            "return_out_valid": blocker["stop"]["return_out_valid"],
            "return_out_x0": ("0x%x" % blocker["stop"]["return_out_x0"]
                              if blocker["stop"]["return_out_x0"] is not None
                              else None),
            "files": {},
        }
        for rel in (["aot_g3_start_probe.exe", "real_desc_partial.c"]
                    + ["img/%s.c" % m["name"] for m in modules]
                    + ["img/%s.meta.json" % m["name"] for m in modules]):
            path = os.path.join(work, rel)
            if os.path.exists(path):
                result["files"][rel] = sha256_file(path)
        if ctor_audit:
            result["ctor_audit"] = {
                "file": "ctor_audit.json",
                "sha256": sha256_file(CR.write_audit(work, ctor_audit)),
                "count": len(ctor_audit),
                "targets": [e["target"] for e in ctor_audit]}
        if veneer_audit:
            audit_path = write_veneer_audit(work, veneer_audit)
            audit_sha = sha256_file(audit_path)
            result["files"]["veneer_audit.json"] = audit_sha
            result["veneer_audit"] = {
                "file": "veneer_audit.json",
                "sha256": audit_sha,
                "count": len(veneer_audit),
                "targets": [e["target"] for e in veneer_audit],
                "flat_sha256": [e["evidence"]["flat_sha256"]
                                for e in veneer_audit],
            }
        with open(os.path.join(work, "result.json"), "w",
                  encoding="utf-8") as f:
            json.dump(result, f, indent=2, sort_keys=True)
        print("START_PREFIX_RESULT kind=%s code=%d src=%s target=%s "
              "status=%d image=%s"
              % (result["kind"], result["code"], result["src"],
                 result["target"], result["status"], result["image"]))
        if result["kind"] == "clean_return":
            print("CLEAN_RETURN_RESULT (not a G3 pass/closure)")
        return result_exit_code(result["kind"])
    except DriverError as exc:
        return fail(str(exc))
    finally:
        # Early fail() returns still keep the iterations already completed.
        if timing_out and timing:
            write_timing(timing_out, timing)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
