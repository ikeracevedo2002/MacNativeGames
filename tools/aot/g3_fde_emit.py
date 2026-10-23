#!/usr/bin/env python3
"""D024 Stage B - candidate catalog and authority table (G3).

"Compiled is not authorized" made representable OFFLINE, with no runtime,
loader, Program or AotImage/AotProgImage change.  Two independent steps:

1. CATALOG (`build_catalog`, CLI `catalog`).  Input: one flat module, a Stage
   A candidate manifest (`tools/aot/g3_fde_frontend.py`, kind=candidates,
   authority=none) and a selection of boundaries by EXACT start.  For every
   selected boundary a function-local CFG is built from its start and
   restricted to its FDE window `[start, end)` (`aot_translate.module_cfg(...,
   restrict=...)`: a target outside the window ends the block and is not
   followed).  Every block becomes an EXTERNALLY named body
   `aot_cand_<mod>_<pc>` lowered by the existing `aot_translate.emit_insn`
   (no SavageWind code), plus a catalog array {pc, end_pc, words sha256, fn}
   and an identity string.  The catalog TU contains NO AotImage: nothing in it
   is dispatchable.

2. AUTHORITY (`build_table`, CLI `table`).  The catalog is first re-verified
   from the flat: every window must be the exact range of a re-derived FDE and
   regenerating the catalog with the current tools must reproduce the supplied
   C unit and metadata (`verify_catalog`).  The executable entry set is still
   the closure that the UNCHANGED `aot_translate.module_cfg` computes from the
   admitted roots.  Every closure block whose start lies inside a selected
   candidate window must have a catalog block with the identical start, end
   and instruction words (and, for a D022 switch, the identical proven target
   set), and no closure block may start outside a window and run into it;
   otherwise the step fails closed with `PartitionMismatch` (the per-kind
   counts are the report; the CLI writes only the report) and writes nothing
   else.  The emitted AotImage lists ONLY closure starts: covered ones point
   at catalog bodies, the others at bodies emitted exactly like today's
   `emit_c`.  Catalog bodies outside the closure are linked into the binary but
   are NOT in the table, so a transfer to them is `AOT_FAULT_UNTRANSLATED`,
   exactly as before.

D022 (local switches).  A catalog body may only contain a switch guard whose
target set was proved over the function-local candidate graph; that proof is a
CANDIDATE.  The authority step accepts the body only if the strict proof over
the ADMITTED graph (the one `module_cfg` performs for today's emission) yields
exactly the same target set for that BR, and refuses otherwise.

Status numbering.  The existing formulas are untouched for every body emitted
on the current path (`PARTIAL_STATUS` = ordinal over the closure's sorted
unsupported PCs, switch status = LOCAL_SWITCH_STATUS_BASE - (ordinal + 1) over
the closure's sorted BR PCs).  Candidate bodies use a stable per-catalog
numbering in DISJOINT namespaces (`CAND_PARTIAL_STATUS_BASE + ordinal`,
`CAND_SWITCH_STATUS_BASE - (ordinal + 1)`, ordinals over the catalog's sorted
PCs), recorded in the catalog and table metadata.  Equivalence with today's
image is therefore (fault kind, source PC, metadata-resolved PC), never the
raw status integer.

Everything here runs offline; no ARM64 is decoded at runtime.
"""

import argparse
import bisect
import contextlib
import hashlib
import json
import os
import re
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import aot_module as M          # noqa: E402
import aot_translate as T       # noqa: E402
import g3_fde_frontend as F     # noqa: E402
import g3_local_switch as LS    # noqa: E402

SCHEMA_VERSION = 1
KIND = "candidate-catalog"
AUTHORITY = "none"
# Receipt written only after a successful REGENERATE verification (plan 1.2.6).
RECEIPT_KIND = "catalog-receipt"
RECEIPT_SCHEMA = 1
VERIFY_MODES = ("regenerate", "bound")
# Disjoint fault_status namespaces used ONLY inside candidate bodies.  The
# positive one sits far above any per-module unsupported ordinal of today's
# path; the negative one is disjoint from LOCAL_SWITCH_STATUS_BASE's range,
# from AOT_STATE_ERR_* and from AotMemStatus.
CAND_PARTIAL_STATUS_BASE = 0x43500000
CAND_SWITCH_STATUS_BASE = -0x43530000
_MAX_ORDINAL = 0x00FFFFFF

_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class EmitError(Exception):
    """Typed fail-closed refusal.  `reason` is stable and machine-readable."""

    def __init__(self, reason, detail=""):
        self.reason = reason
        self.detail = detail or reason
        Exception.__init__(self, "%s: %s" % (reason, self.detail))


class PartitionMismatch(EmitError):
    """Catalog and admitted closure disagree; `report` is measurement data."""

    def __init__(self, report):
        self.report = report
        counts = report["mismatch_counts"]
        first = report["mismatches"][0]
        EmitError.__init__(
            self, "partition-mismatch",
            "%d closure block(s) inside candidate windows disagree with the "
            "catalog (%s); first: %s at 0x%x (%s)"
            % (len(report["mismatches"]),
               ", ".join("%s=%d" % kv for kv in sorted(counts.items())),
               first["kind"], int(first["pc"], 16), first["detail"]))


# ------------------------------------------------------------------ helpers

def _hex(value):
    return "0x%x" % value


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _file_sha(path):
    with open(path, "rb") as handle:
        return _sha(handle.read())


def tool_hashes():
    """Exact source identity of every component that shapes a body."""
    try:
        import capstone as _cs
        capstone = _cs.__version__
    except ImportError:
        capstone = "absent"
    return {"translator": _file_sha(T.__file__),
            "frontend": _file_sha(F.__file__),
            "emitter": _file_sha(os.path.abspath(__file__)),
            "local_switch": _file_sha(LS.__file__),
            "aot_module": _file_sha(M.__file__),
            "capstone": capstone,
            "tool_config": T.TOOL_CONFIG_MODULE}


def manifest_sha256(manifest):
    """SHA-256 of the manifest exactly as Stage A writes it."""
    text = json.dumps(manifest, indent=1, sort_keys=True) + "\n"
    return _sha(text.encode("utf-8"))


def words_sha256(insns):
    return _sha(b"".join(struct.pack("<I", ins["word"]) for ins in insns))


def _check_name(name):
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise EmitError("bad-name", "module/image name %r is not a C "
                        "identifier" % (name,))


def _check_base(guest_base):
    if guest_base % T.AOT_AS_PAGE_BYTES or guest_base < T.AOT_AS_MIN_ADDR \
            or guest_base >= T.AOT_AS_MAX_ADDR:
        raise EmitError("bad-guest-base",
                        "guest base 0x%x is not a 4 KiB aligned base inside "
                        "[0x%x, 0x%x)" % (guest_base, T.AOT_AS_MIN_ADDR,
                                          T.AOT_AS_MAX_ADDR))


@contextlib.contextmanager
def _translator(partial, guest_base):
    """Module-mode translator globals for one emission; restored afterwards.

    The helper set (`_USED`) is emptied for the duration so a TU carries only
    the helpers its own bodies use, and restored so no caller of `emit_c` in
    the same process observes a difference.
    """
    if T.MUTANT is not None:
        raise EmitError("translator-mutant-active",
                        "aot_translate.MUTANT=%r; candidate emission is only "
                        "defined for the unmutated translator" % (T.MUTANT,))
    saved = (T.MODULE_MODE, T.MODULE_BASE, T.PARTIAL,
             dict(T.PARTIAL_STATUS), set(T._USED))
    T.MODULE_MODE, T.MODULE_BASE, T.PARTIAL = 1, guest_base, 1 if partial else 0
    T.PARTIAL_STATUS.clear()
    T._USED.clear()
    try:
        yield
    finally:
        T.MODULE_MODE, T.MODULE_BASE, T.PARTIAL = saved[:3]
        T.PARTIAL_STATUS.clear()
        T.PARTIAL_STATUS.update(saved[3])
        T._USED.clear()
        T._USED.update(saved[4])


def _helpers():
    out = ["/* ---- generated semantic helpers ---- */"]
    for hname in sorted(T._USED):
        out.append(T._HELPERS[hname].strip("\n"))
    out.append("")
    return out


def _gate_proofs(proofs, what):
    """The emission gate of `aot_translate.run_module` (D022)."""
    for pc, p in proofs.items():
        if p.closure != "verified-final-graph":
            raise EmitError("switch-not-final",
                            "%s: local switch 0x%x is not verified-final-graph "
                            "(closure %r)" % (what, pc, p.closure))
        if p.deferred_threats:
            raise EmitError("switch-deferred-threats",
                            "%s: local switch 0x%x still has deferred "
                            "incoming-branch threats" % (what, pc))


def _block_record(blk):
    last = blk["insns"][-1]
    return {"pc": blk["pc"], "end_pc": last["pc"] + 4,
            "terminator": last["kind"], "words_sha256": words_sha256(blk["insns"])}


# ------------------------------------------------------------------ manifest

def select_boundaries(manifest, meta, starts):
    """Validate the Stage A manifest against the flat; -> sorted (start, end).

    The manifest is an untrusted file: beyond its contract fields, its
    boundary set must equal the FDE set re-derived from the flat by the same
    frontend, so a forged start/end is a typed refusal, not a new window.
    """
    if not isinstance(manifest, dict):
        raise EmitError("manifest-invalid", "manifest is not a JSON object")
    if manifest.get("schema_version") != F.SCHEMA_VERSION:
        raise EmitError("manifest-schema",
                        "manifest schema_version %r (expected %d)"
                        % (manifest.get("schema_version"), F.SCHEMA_VERSION))
    if manifest.get("kind") != F.KIND:
        raise EmitError("manifest-kind", "manifest kind %r (expected %r)"
                        % (manifest.get("kind"), F.KIND))
    if manifest.get("authority") != F.AUTHORITY:
        raise EmitError("manifest-authority",
                        "manifest authority %r (expected %r): a candidate "
                        "manifest never carries authority"
                        % (manifest.get("authority"), F.AUTHORITY))
    module = manifest.get("module")
    if not isinstance(module, dict) or module.get("sha256") != meta.sha256:
        raise EmitError("manifest-module-mismatch",
                        "manifest module sha256 %r != flat SHA-256 %s"
                        % (module.get("sha256") if isinstance(module, dict)
                           else None, meta.sha256))
    try:
        listed = [(int(b["start"], 16), int(b["end"], 16))
                  for b in manifest["boundaries"]]
        conflicts = set(int(c["start"], 16)
                        for c in manifest.get("conflicts", []))
    except (KeyError, TypeError, ValueError) as exc:
        raise EmitError("manifest-invalid", "boundary list: %s" % exc)
    _header, fdes, _end = F.parse_fdes(meta)
    derived = sorted((fde.start, fde.end) for fde in fdes)
    if sorted(listed) != derived:
        only_m = sorted(set(listed) - set(derived))
        only_f = sorted(set(derived) - set(listed))
        raise EmitError("manifest-boundaries-mismatch",
                        "manifest boundaries differ from the FDEs re-derived "
                        "from the flat (%d only in the manifest, first %s; %d "
                        "only in the flat, first %s)"
                        % (len(only_m), only_m[:1], len(only_f), only_f[:1]))
    if not starts:
        raise EmitError("selection-empty", "no boundary was selected")
    if len(set(starts)) != len(starts):
        raise EmitError("selection-duplicate", "a boundary start is selected "
                        "more than once")
    by_start = dict(listed)
    out = []
    for start in sorted(starts):
        if start not in by_start:
            raise EmitError("boundary-not-in-manifest",
                            "0x%x is not the exact start of any candidate "
                            "boundary" % start)
        if start in conflicts:
            raise EmitError("boundary-conflict",
                            "boundary 0x%x is listed as a known-DATA/metadata "
                            "conflict in the manifest" % start)
        out.append((start, by_start[start]))
    # Stage A already refuses overlapping FDEs and the windows equal the
    # re-derived FDE set; check_partition's bisect relies on disjoint windows,
    # so that precondition is enforced here rather than assumed.
    for (lo_a, hi_a), (lo_b, _hi_b) in zip(out, out[1:]):
        if lo_b < hi_a:
            raise EmitError("selection-overlap",
                            "windows [0x%x,0x%x) and 0x%x overlap"
                            % (lo_a, hi_a, lo_b))
    return out


# ------------------------------------------------------------------ catalog

def _catalog_from_bounds(flat, layout, guest_base, name, bounds, partial,
                         manifest_sha):
    """Build the catalog for explicit (start, end) image-offset windows.

    Internal: the public entry point `build_catalog` only passes windows that
    `select_boundaries` validated against the flat.  Tests call this directly
    to exercise the authority step with windows a manifest would never hold.
    """
    ranges = T.module_layout_ranges(layout, guest_base)
    blocks = []
    switches = {}
    unsupported = {}
    seen = set()
    with _translator(partial, guest_base):
        for start, end in bounds:
            lo, hi = guest_base + start, guest_base + end
            try:
                cfg_blocks, visited, proofs = T.module_cfg(
                    flat, ranges, [lo], guest_base, layout, restrict=(lo, hi))
            except T.DecodeError as exc:
                raise EmitError("boundary-cfg-refused",
                                "boundary [0x%x,0x%x): %s" % (start, end, exc))
            _gate_proofs(proofs, "boundary 0x%x" % start)
            for blk in cfg_blocks:
                if blk["pc"] in seen:
                    raise EmitError("catalog-overlap",
                                    "block 0x%x appears in two windows"
                                    % blk["pc"])
                seen.add(blk["pc"])
                blocks.append((start, blk))
            for pc, p in proofs.items():
                switches[pc] = tuple(sorted(set(p.targets)))
            for pc, ins in visited.items():
                if ins["kind"] == "unsupported":
                    unsupported[pc] = ins
        if len(switches) > _MAX_ORDINAL or len(unsupported) > _MAX_ORDINAL:
            raise EmitError("catalog-too-large", "status namespace exhausted")
        switch_status = {pc: CAND_SWITCH_STATUS_BASE - (i + 1)
                         for i, pc in enumerate(sorted(switches))}
        T.PARTIAL_STATUS.update({pc: CAND_PARTIAL_STATUS_BASE + i
                                 for i, pc in enumerate(sorted(unsupported))})
        blocks.sort(key=lambda item: item[1]["pc"])
        records = []
        bodies = ["/* ---- candidate bodies (external linkage; NOT in any "
                  "AotImage) ---- */"]
        for start, blk in blocks:
            fn = "aot_cand_%s_%x" % (name, blk["pc"])
            rec = _block_record(blk)
            last = blk["insns"][-1]
            rec["boundary"] = start
            rec["fn"] = fn
            rec["switch_targets"] = (list(switches[last["pc"]])
                                     if last["pc"] in switches else None)
            records.append(rec)
            bodies.append("AotExit %s(AotGuestState *s, AotRuntime *rt);" % fn)
            bodies.append("AotExit %s(AotGuestState *s, AotRuntime *rt) {" % fn)
            bodies.append("    (void)s; (void)rt;")
            for ins in blk["insns"]:
                T.emit_insn(ins, bodies, switches, switch_status)
            if last["kind"] not in T.TERMINATORS:
                bodies.append("    rt->site_pc = 0x%xull;" % last["pc"])
                bodies.append("    rt->next_pc = 0x%xull;" % (last["pc"] + 4))
                bodies.append("    return AOT_EXIT_FALLTHROUGH;")
            bodies.append("}")
            bodies.append("")
        helpers = _helpers()
        partial_status = dict(T.PARTIAL_STATUS)

    ident = {
        "schema_version": SCHEMA_VERSION, "kind": KIND, "authority": AUTHORITY,
        "module": name, "guest_base": _hex(guest_base),
        "flat_sha256": _sha(flat), "layout_sha256": _sha(_canonical(layout)),
        "manifest_sha256": manifest_sha, "tools": tool_hashes(),
        "partial": bool(partial), "subset_id": T.AOT_MODULE_SUBSET_ID,
        "selection": [[_hex(s), _hex(e)] for s, e in bounds],
        "status_namespaces": {
            "unsupported": "%s + ordinal" % _hex(CAND_PARTIAL_STATUS_BASE),
            "local_switch": "%d - (ordinal + 1)" % CAND_SWITCH_STATUS_BASE},
        "blocks": [{"pc": _hex(r["pc"]), "end_pc": _hex(r["end_pc"]),
                    "terminator": r["terminator"],
                    "words_sha256": r["words_sha256"],
                    "boundary": _hex(r["boundary"]), "fn": r["fn"],
                    "switch_targets": (None if r["switch_targets"] is None
                                       else [_hex(t) for t in
                                             r["switch_targets"]])}
                   for r in records],
        "local_switch_sites": [{"br_pc": _hex(pc), "status": switch_status[pc],
                                "targets": [_hex(t) for t in switches[pc]],
                                "closure": "candidate-function-local"}
                               for pc in sorted(switches)],
        "unsupported": [{"status": partial_status[pc], "pc": _hex(pc),
                         "word": "0x%08x" % unsupported[pc]["word"],
                         "reason": unsupported[pc]["reason"]}
                        for pc in sorted(unsupported)],
    }
    identity = _sha(_canonical(ident))
    head = ["/* Generated by tools/aot/g3_fde_emit.py -- DO NOT EDIT.",
            " * D024 Stage B CANDIDATE CATALOG (authority: none).  Nothing in",
            " * this unit is dispatchable: a body runs only if an authority",
            " * table emitted from the admitted CFG closure lists its PC.",
            " * module: %s  guest base: 0x%x" % (name, guest_base),
            " * flat sha256: %s" % ident["flat_sha256"],
            " * manifest sha256: %s" % manifest_sha,
            " * translator sha256: %s" % ident["tools"]["translator"],
            " * frontend sha256: %s" % ident["tools"]["frontend"],
            " * catalog identity: %s" % identity,
            " */",
            '#include "aot_runtime.h"',
            '#include "aot_fp.h"',
            "#include <stdint.h>",
            "",
            "typedef struct AotCandBlock {",
            "    uint64_t pc;",
            "    uint64_t end_pc;",
            "    const char *words_sha256;",
            "    AotBlockFn fn;",
            "} AotCandBlock;",
            ""]
    tail = ["const AotCandBlock aot_cand_catalog_%s[] = {" % name]
    for r in records:
        tail.append('    { 0x%xull, 0x%xull, "%s", %s },'
                    % (r["pc"], r["end_pc"], r["words_sha256"], r["fn"]))
    tail.append("};")
    tail.append("const uint32_t aot_cand_catalog_%s_count = %du;"
                % (name, len(records)))
    tail.append('const char aot_cand_identity_%s[] = "%s";' % (name, identity))
    tail.append("")
    text = "\n".join(head + helpers + bodies + tail)
    meta = dict(ident)
    meta["identity"] = identity
    meta["c_sha256"] = _sha(text.encode("utf-8"))
    return text, meta


def build_catalog(flat, layout, manifest, guest_base, name, starts,
                  partial=True):
    """Manifest + selected starts -> (catalog C text, catalog metadata)."""
    _check_name(name)
    _check_base(guest_base)
    try:
        meta = F.read_module(flat, layout, layout.get("name") or name)
    except F.FdeError as exc:
        raise EmitError("module-invalid:%s" % exc.reason, exc.detail)
    try:
        bounds = select_boundaries(manifest, meta, list(starts))
    except F.FdeError as exc:
        raise EmitError("manifest-rederive:%s" % exc.reason, exc.detail)
    return _catalog_from_bounds(bytes(flat), layout, guest_base, name, bounds,
                                partial, manifest_sha256(manifest))


def seal_catalog(meta, c_text):
    """Recompute `identity`/`c_sha256` of a catalog dict (producer side)."""
    ident = {k: v for k, v in meta.items() if k not in ("identity", "c_sha256")}
    out = dict(ident)
    out["identity"] = _sha(_canonical(ident))
    out["c_sha256"] = _sha(c_text.encode("utf-8"))
    return out


def _verify_catalog_static(meta, c_text, flat, guest_base, name, partial):
    """Fail closed unless the catalog is self-consistent, current and bound to
    the caller's flat, guest base, partial flag and module name.

    No FDE is re-derived and nothing is regenerated here.  -> the selected
    (start, end) windows, sorted.
    """
    if not isinstance(meta, dict):
        raise EmitError("catalog-invalid", "catalog metadata is not an object")
    if meta.get("schema_version") != SCHEMA_VERSION or meta.get("kind") != KIND \
            or meta.get("authority") != AUTHORITY:
        raise EmitError("catalog-contract",
                        "catalog schema/kind/authority %r/%r/%r"
                        % (meta.get("schema_version"), meta.get("kind"),
                           meta.get("authority")))
    ident = {k: v for k, v in meta.items() if k not in ("identity", "c_sha256")}
    if meta.get("identity") != _sha(_canonical(ident)):
        raise EmitError("catalog-identity-mismatch",
                        "catalog identity does not match its own content")
    if meta.get("c_sha256") != _sha(c_text.encode("utf-8")):
        raise EmitError("catalog-c-mismatch",
                        "catalog C unit is not the one the metadata pins")
    if ('aot_cand_identity_%s[] = "%s";' % (meta.get("module"),
                                             meta.get("identity"))) \
            not in c_text:
        raise EmitError("catalog-c-mismatch",
                        "catalog C unit does not embed the identity string")
    current = tool_hashes()
    if meta.get("tools") != current:
        stale = sorted(k for k in current
                       if (meta.get("tools") or {}).get(k) != current[k])
        raise EmitError("catalog-tool-mismatch",
                        "catalog was produced by a different tool version "
                        "(%s)" % ", ".join(stale))
    if meta.get("flat_sha256") != _sha(flat):
        raise EmitError("catalog-module-mismatch",
                        "catalog flat SHA-256 %r != %s"
                        % (meta.get("flat_sha256"), _sha(flat)))
    if meta.get("guest_base") != _hex(guest_base):
        raise EmitError("catalog-base-mismatch",
                        "catalog guest base %r != 0x%x"
                        % (meta.get("guest_base"), guest_base))
    if meta.get("partial") != bool(partial):
        raise EmitError("catalog-partial-mismatch",
                        "catalog partial=%r, authority partial=%r"
                        % (meta.get("partial"), bool(partial)))
    if meta.get("module") != name:
        raise EmitError("catalog-name-mismatch",
                        "catalog module %r != image name %r"
                        % (meta.get("module"), name))
    try:
        bounds = sorted((int(s, 16), int(e, 16)) for s, e in meta["selection"])
    except (KeyError, TypeError, ValueError) as exc:
        raise EmitError("catalog-invalid", "selection: %s" % exc)
    return bounds


def verify_catalog(meta, c_text, flat, layout, guest_base, name, partial):
    """Fail closed unless the catalog is self-consistent and current.

    Beyond the pinned identity strings, the authority step trusts nothing the
    catalog says about itself: every selected window must be the exact range
    of an FDE re-derived from the flat, and the catalog is regenerated from
    (flat, layout, windows) with the current tools; the regenerated C unit and
    metadata must be identical to the supplied ones.
    """
    bounds = _verify_catalog_static(meta, c_text, flat, guest_base, name,
                                    partial)
    try:
        fmeta = F.read_module(flat, layout, layout.get("name") or name)
        _header, fdes, _end = F.parse_fdes(fmeta)
    except F.FdeError as exc:
        raise EmitError("module-invalid:%s" % exc.reason, exc.detail)
    fde_ranges = set((fde.start, fde.end) for fde in fdes)
    for start, end in bounds:
        if (start, end) not in fde_ranges:
            raise EmitError("catalog-window-not-fde",
                            "catalog window [0x%x,0x%x) is not the exact range "
                            "of an FDE of this module" % (start, end))
    regen_c, regen_meta = _catalog_from_bounds(
        flat, layout, guest_base, name, bounds, partial,
        meta.get("manifest_sha256"))
    if regen_c != c_text or regen_meta != meta:
        raise EmitError("catalog-not-reproducible",
                        "regenerating the catalog from the flat and its "
                        "windows does not reproduce the supplied unit")


def make_receipt(meta, c_text, flat, guest_base, name, partial):
    """Receipt of a successful REGENERATE verification of this catalog.

    A pure function of its inputs and the current tools.  It is evidence of a
    regenerate verification only when the caller has just performed one (the
    CLI writes it with `--write-receipt` after a successful table build).
    """
    return {"schema_version": RECEIPT_SCHEMA, "kind": RECEIPT_KIND,
            "catalog_identity": meta["identity"],
            "c_sha256": _sha(c_text.encode("utf-8")),
            "meta_sha256": _sha(_canonical(meta)),
            "flat_sha256": _sha(flat),
            "guest_base": _hex(guest_base),
            "module": name,
            "partial": bool(partial),
            "tools": tool_hashes(),
            "selection": meta["selection"],
            "verified_by": "regenerate"}


def verify_catalog_bound(meta, c_text, flat, guest_base, name, partial,
                         receipt):
    """Hash-bound verification: the static checks, then the receipt.

    NOT a regeneration: no FDE is re-derived and the catalog is not rebuilt.
    The receipt must be exactly the receipt `make_receipt` computes now for
    these inputs and the current tools, and must record a regenerate
    verification.
    """
    _verify_catalog_static(meta, c_text, flat, guest_base, name, partial)
    if not isinstance(receipt, dict):
        raise EmitError("catalog-receipt-missing",
                        "no catalog receipt object was supplied")
    if receipt.get("schema_version") != RECEIPT_SCHEMA \
            or receipt.get("kind") != RECEIPT_KIND:
        raise EmitError("catalog-receipt-mismatch",
                        "receipt schema/kind %r/%r (expected %d/%r)"
                        % (receipt.get("schema_version"), receipt.get("kind"),
                           RECEIPT_SCHEMA, RECEIPT_KIND))
    if receipt.get("verified_by") != "regenerate":
        raise EmitError("catalog-receipt-mismatch",
                        "receipt verified_by %r; only a regenerate "
                        "verification can be bound"
                        % (receipt.get("verified_by"),))
    expected = make_receipt(meta, c_text, flat, guest_base, name, partial)
    if _canonical(receipt) != _canonical(expected):
        differ = [k for k in sorted(set(receipt) | set(expected))
                  if k not in receipt or k not in expected
                  or _canonical(receipt[k]) != _canonical(expected[k])]
        raise EmitError("catalog-receipt-mismatch",
                        "receipt does not match this catalog and the current "
                        "tools; differing field(s): %s" % ", ".join(differ))


# ---------------------------------------------------------------- authority

def closure(flat, layout, guest_base, entries, partial):
    """Today's admitted closure: the UNCHANGED module_cfg + emission gate."""
    if len(flat) != layout["image_size"] - layout.get("bss_size", 0):
        raise EmitError("layout-invalid", "flat size disagrees with layout")
    if layout.get("sha256") and layout["sha256"] != _sha(flat):
        raise EmitError("layout-invalid", "flat SHA-256 != layout sha256")
    ranges = T.module_layout_ranges(layout, guest_base)
    for pc in entries:
        if not T.in_ranges(ranges, pc):
            raise EmitError("entry-outside-text",
                            "entry 0x%x is outside the text segment" % pc)
    with _translator(partial, guest_base):
        try:
            blocks, visited, proofs = T.module_cfg(flat, ranges, entries,
                                                   guest_base, layout)
        except T.DecodeError as exc:
            raise EmitError("closure-refused", str(exc))
    _gate_proofs(proofs, "closure")
    return ranges, blocks, visited, proofs


def _windows(meta):
    base = int(meta["guest_base"], 16)
    return sorted((base + int(s, 16), base + int(e, 16))
                  for s, e in meta["selection"])


def check_partition(blocks, proofs, meta):
    """-> (covered {pc: catalog block}, report).  Never raises.

    Mismatch kinds: `missing` (no catalog block starts at a closure block
    inside a window), `end`, `words`, `switch` (D022 target sets differ) and
    `straddle` (a closure block that starts outside every window but runs
    into one: the catalog partition and the closure disagree about where the
    window's code starts).
    """
    windows = _windows(meta)
    lows = [lo for lo, _hi in windows]
    catalog = {int(b["pc"], 16): b for b in meta["blocks"]}
    covered = {}
    mismatches = []
    outside = 0
    for blk in blocks:
        pc = blk["pc"]
        rec = _block_record(blk)
        i = bisect.bisect_right(lows, pc) - 1
        if i < 0 or not windows[i][0] <= pc < windows[i][1]:
            j = bisect.bisect_left(lows, rec["end_pc"]) - 1
            if j >= 0 and windows[j][1] > pc:
                mismatches.append({
                    "pc": _hex(pc), "kind": "straddle",
                    "detail": "closure block [0x%x,0x%x) starts outside the "
                              "window and runs into it" % (pc, rec["end_pc"]),
                    "window": [_hex(windows[j][0]), _hex(windows[j][1])]})
                continue
            outside += 1
            continue
        cand = catalog.get(pc)
        last = blk["insns"][-1]
        want_sw = (sorted(set(proofs[last["pc"]].targets))
                   if last["kind"] == "br" and last["pc"] in proofs else None)
        if cand is None:
            kind, detail = "missing", ("no catalog block starts at this "
                                       "closure block")
        elif int(cand["end_pc"], 16) != rec["end_pc"]:
            kind, detail = "end", ("closure ends at 0x%x, catalog at %s"
                                   % (rec["end_pc"], cand["end_pc"]))
        elif cand["words_sha256"] != rec["words_sha256"]:
            kind, detail = "words", "instruction words differ"
        elif (None if cand["switch_targets"] is None
              else sorted(int(t, 16) for t in cand["switch_targets"])) \
                != want_sw:
            kind, detail = "switch", (
                "admitted-graph proof %s != catalog claim %s"
                % (None if want_sw is None else [_hex(t) for t in want_sw],
                   cand["switch_targets"]))
        else:
            covered[pc] = cand
            continue
        mismatches.append({"pc": _hex(pc), "kind": kind, "detail": detail,
                           "window": [_hex(windows[i][0]),
                                      _hex(windows[i][1])]})
    counts = {}
    for item in mismatches:
        counts[item["kind"]] = counts.get(item["kind"], 0) + 1
    report = {"closure_blocks": len(blocks),
              "catalog_blocks": len(catalog),
              "covered_matches": len(covered),
              "outside_candidates": outside,
              "unadmitted_catalog_blocks": len(set(catalog) - set(covered)),
              "mismatch_counts": counts,
              "mismatches": mismatches}
    return covered, report


def _table_entries(blocks, covered, catalog_meta):
    """(pc, C symbol, from_catalog) for EXACTLY the closure starts.

    `catalog_meta` is deliberately NOT consulted: the catalog contributes
    bodies, never entries.  (The parameter exists so a wrong authority step
    that also lists out-of-closure catalog bodies is expressible in a test.)
    """
    return [(blk["pc"], covered[blk["pc"]]["fn"], True)
            if blk["pc"] in covered
            else (blk["pc"], "aot_blk_%x" % blk["pc"], False)
            for blk in blocks]


def build_table(flat, layout, guest_base, name, entries, catalog_meta,
                catalog_c, partial=True, verify_mode="regenerate",
                receipt=None):
    """Authority step -> (table C text, image metadata, partition report).

    `verify_mode="regenerate"` (default) re-derives and regenerates the catalog;
    `verify_mode="bound"` checks `receipt` instead (see verify_catalog_bound).
    """
    _check_name(name)
    _check_base(guest_base)
    flat = bytes(flat)
    if verify_mode not in VERIFY_MODES:
        raise EmitError("verify-mode-invalid",
                        "verify mode %r (expected one of %s)"
                        % (verify_mode, ", ".join(VERIFY_MODES)))
    if verify_mode == "bound":
        verify_catalog_bound(catalog_meta, catalog_c, flat, guest_base, name,
                             partial, receipt)
    else:
        verify_catalog(catalog_meta, catalog_c, flat, layout, guest_base, name,
                       partial)
    entries = sorted(set(entries))
    if not entries:
        raise EmitError("no-entries", "the admitted root set is empty")
    ranges, blocks, visited, proofs = closure(flat, layout, guest_base,
                                              entries, partial)
    covered, report = check_partition(blocks, proofs, catalog_meta)
    if report["mismatches"]:
        raise PartitionMismatch(report)

    unsup = sorted(pc for pc, ins in visited.items()
                   if ins["kind"] == "unsupported")
    # Today's partial statuses are ordinals 0..len-1; they must stay below
    # the candidate namespace or the two would no longer be disjoint.
    if len(unsup) >= CAND_PARTIAL_STATUS_BASE:
        raise EmitError("status-namespace-overlap",
                        "%d unsupported closure PCs reach the candidate "
                        "status namespace 0x%x"
                        % (len(unsup), CAND_PARTIAL_STATUS_BASE))
    switch_sites = {pc: p.targets for pc, p in proofs.items()}
    switch_status = {pc: T.LOCAL_SWITCH_STATUS_BASE - (i + 1)
                     for i, pc in enumerate(sorted(switch_sites))}
    cand_unsup = {int(u["pc"], 16): u["status"]
                  for u in catalog_meta["unsupported"]}
    cand_switch = {int(s["br_pc"], 16): s["status"]
                   for s in catalog_meta["local_switch_sites"]}
    table = _table_entries(blocks, covered, catalog_meta)
    by_pc = {blk["pc"]: blk for blk in blocks}

    with _translator(partial, guest_base):
        T.PARTIAL_STATUS.update({pc: i for i, pc in enumerate(unsup)})
        out = ["/* ---- straight-line native basic blocks (outside every "
               "candidate window) ---- */"]
        externs = []
        for pc, sym, from_catalog in table:
            if from_catalog:
                externs.append("AotExit %s(AotGuestState *s, AotRuntime *rt);"
                               % sym)
                continue
            blk = by_pc[pc]
            out.append("static AotExit %s(AotGuestState *s, AotRuntime *rt) {"
                       % sym)
            out.append("    (void)s; (void)rt;")
            for ins in blk["insns"]:
                T.emit_insn(ins, out, switch_sites, switch_status)
            last = blk["insns"][-1]
            if last["kind"] not in T.TERMINATORS:
                out.append("    rt->site_pc = 0x%xull;" % last["pc"])
                out.append("    rt->next_pc = 0x%xull;" % (last["pc"] + 4))
                out.append("    return AOT_EXIT_FALLTHROUGH;")
            out.append("}")
            out.append("")
        helpers = _helpers()

    fnv = 0xCBF29CE484222325
    for b in flat:
        fnv ^= b
        fnv = (fnv * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    flat_sha = _sha(flat)
    provenance = _sha(_canonical({
        "catalog_identity": catalog_meta["identity"],
        "layout_sha256": _sha(_canonical(layout)),
        "tools": tool_hashes(), "name": name, "base": _hex(guest_base),
        "partial": bool(partial), "entries": [_hex(e) for e in entries]}))
    head = ["/* Generated by tools/aot/g3_fde_emit.py -- DO NOT EDIT.",
            " * D024 Stage B AUTHORITY TABLE: the dispatchable set is exactly",
            " * the CFG closure of the admitted roots (aot_translate.module_cfg).",
            " * subset: %s" % T.AOT_MODULE_SUBSET_ID,
            " * source sha256: %s" % flat_sha,
            " * provenance: sha256 %s (catalog %s)"
            % (provenance, catalog_meta["identity"]),
            " * fixture fnv1a64: 0x%016x (quick check only)" % fnv,
            " */",
            '#include "aot_runtime.h"',
            '#include "aot_fp.h"',
            "#include <stdint.h>",
            ""]
    if externs:
        externs = ["/* ---- admitted catalog bodies (defined in the catalog "
                   "unit) ---- */"] + externs + [""]
    tail = ["static const AotBlockEntry aot_blocks_%s[] = {" % name]
    for pc, sym, _from_catalog in table:
        tail.append("    { 0x%xull, %s }," % (pc, sym))
    tail.append("};")
    tail.append("")
    tail.append("static const AotCodeRange aot_ranges_%s[] = {" % name)
    for start, end in ranges:
        tail.append("    { 0x%xull, 0x%xull }," % (start, end))
    tail.append("};")
    tail.append("")
    tail.append("const AotImage aot_image_%s = {" % name)
    tail.append('    "%s",' % T.AOT_MODULE_SUBSET_ID)
    tail.append("    AOT_ABI_VERSION_PROGRAM, AOT_STATE_LAYOUT,")
    tail.append('    "%s",' % flat_sha)
    tail.append("    0x%016xull," % fnv)
    tail.append("    aot_blocks_%s, sizeof(aot_blocks_%s) / sizeof(aot_blocks_%s[0]),"
                % (name, name, name))
    tail.append("    aot_ranges_%s, sizeof(aot_ranges_%s) / sizeof(aot_ranges_%s[0]),"
                % (name, name, name))
    tail.append("    0x0ull, 0x0ull, 0x0ull")
    tail.append("};")
    tail.append("")
    text = "\n".join(head + helpers + externs + out + tail)

    unsup_index = {pc: i for i, pc in enumerate(unsup)}
    body_of = {}
    for blk in blocks:
        for ins in blk["insns"]:
            body_of[ins["pc"]] = blk["pc"] in covered
    meta = {"name": name, "mode": "module-authority",
            "subset_id": T.AOT_MODULE_SUBSET_ID,
            "abi_version": T.AOT_ABI_VERSION_PROGRAM,
            "state_layout": T.AOT_STATE_LAYOUT,
            "guest_base": _hex(guest_base), "source_sha256": flat_sha,
            "provenance_sha256": provenance,
            "catalog_identity": catalog_meta["identity"],
            "fnv1a64": "0x%016x" % fnv,
            "ranges": [list(r) for r in ranges],
            "entries": [_hex(e) for e in entries],
            "partial": bool(partial),
            "unsupported": [
                {"status": (cand_unsup[pc] if body_of.get(pc)
                                       else unsup_index[pc]),
                 "pc": _hex(pc), "word": "0x%08x" % visited[pc]["word"],
                 "reason": visited[pc]["reason"],
                 "body": "catalog" if body_of.get(pc) else "emitted"}
                for pc in unsup],
            "local_switch_sites": [
                {"br_pc": _hex(pc), "targets": [_hex(t) for t in p.targets],
                 "status": (cand_switch[pc] if body_of.get(pc)
                            else switch_status[pc]),
                 "body": "catalog" if body_of.get(pc) else "emitted",
                 "closure": p.closure}
                for pc, p in sorted(proofs.items())],
            "blocks": [{"pc": _hex(pc), "fn": sym,
                        "body": "catalog" if from_catalog else "emitted"}
                       for pc, sym, from_catalog in table],
            "partition": {k: v for k, v in report.items()
                          if k != "mismatches"}}
    return text, meta, report


# ----------------------------------------------------------------------- CLI

def _write(path, data):
    directory = os.path.dirname(os.path.abspath(path))
    if directory and not os.path.isdir(directory):
        os.makedirs(directory)
    tmp = path + ".tmp"
    with open(tmp, "wb") as handle:
        handle.write(data)
    os.replace(tmp, path)


def _json_bytes(obj):
    return (json.dumps(obj, indent=1, sort_keys=True) + "\n").encode("utf-8")


def _read_json(path):
    with open(path, "rb") as handle:
        return json.loads(handle.read().decode("utf-8"))


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="D024 Stage B: candidate catalog / authority table")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for cmd in ("catalog", "table"):
        p = sub.add_parser(cmd)
        p.add_argument("--flat", required=True)
        p.add_argument("--layout", required=True)
        p.add_argument("--guest-base", dest="guest_base", required=True)
        p.add_argument("--name", required=True)
        p.add_argument("--strict", action="store_true",
                       help="abort on an undecodable word instead of the "
                            "typed partial fault (default: partial)")
        p.add_argument("--out-c", dest="out_c", required=True)
        p.add_argument("--out-json", dest="out_json", required=True)
    cat = sub.choices["catalog"]
    cat.add_argument("--manifest", required=True)
    cat.add_argument("--select", required=True,
                     help="comma-separated exact boundary starts (image "
                          "offsets)")
    tab = sub.choices["table"]
    tab.add_argument("--entries", required=True)
    tab.add_argument("--catalog-json", dest="catalog_json", required=True)
    tab.add_argument("--catalog-c", dest="catalog_c", required=True)
    tab.add_argument("--report", default=None,
                     help="partition report JSON (also written on refusal)")
    tab.add_argument("--verify-mode", dest="verify_mode", default="regenerate",
                     choices=VERIFY_MODES,
                     help="regenerate (default): re-derive and regenerate the "
                          "catalog; bound: check --receipt only")
    tab.add_argument("--receipt", default=None,
                     help="catalog receipt JSON (required with --verify-mode "
                          "bound)")
    tab.add_argument("--write-receipt", dest="write_receipt", default=None,
                     help="after a successful regenerate table build, write "
                          "the catalog receipt here")
    args = ap.parse_args(argv)
    if args.cmd == "table":
        if args.verify_mode == "bound" and not args.receipt:
            ap.error("--verify-mode bound requires --receipt")
        if args.verify_mode == "bound" and args.write_receipt:
            ap.error("--write-receipt is only valid with --verify-mode "
                     "regenerate")
        if args.verify_mode == "regenerate" and args.receipt:
            ap.error("--receipt is only valid with --verify-mode bound")

    repo = os.path.dirname(os.path.dirname(_HERE))
    is_table = args.cmd == "table"
    outs = [args.out_c, args.out_json] + (
        [args.report] if is_table and args.report else []) + (
        [args.write_receipt] if is_table and args.write_receipt else [])
    for path in outs:
        if F.inside_tree(path, repo):
            ap.error("%r is inside the source tree; generated module code "
                     "must stay outside it (D006)" % path)
        if os.path.exists(path):
            os.remove(path)
    # The receipt is an INPUT in bound mode: refuse an in-tree path, but never
    # delete it.
    if is_table and args.receipt and F.inside_tree(args.receipt, repo):
        ap.error("%r is inside the source tree; a catalog receipt must stay "
                 "outside it (D006)" % args.receipt)
    try:
        with open(args.flat, "rb") as handle:
            flat = handle.read()
        layout = _read_json(args.layout)
        guest_base = int(args.guest_base, 0)
        if args.cmd == "catalog":
            manifest = _read_json(args.manifest)
            starts = [int(x, 0) for x in args.select.split(",") if x]
        else:
            entries = T.read_entries(args.entries)
            catalog_meta = _read_json(args.catalog_json)
            with open(args.catalog_c, "rb") as handle:
                catalog_c = handle.read().decode("utf-8")
    except (OSError, ValueError, T.DecodeError) as exc:
        sys.stderr.write("g3_fde_emit: input error: %s\n" % exc)
        return 1
    receipt = None
    if is_table and args.verify_mode == "bound":
        try:
            receipt = _read_json(args.receipt)
        except (OSError, ValueError) as exc:
            sys.stdout.write("REFUSED catalog-receipt-missing\n")
            sys.stderr.write("g3_fde_emit: receipt %s is unreadable: %s\n"
                             % (args.receipt, exc))
            return 2
    partial = not args.strict
    try:
        if args.cmd == "catalog":
            text, meta = build_catalog(flat, layout, manifest, guest_base,
                                       args.name, starts, partial)
            report = None
        else:
            text, meta, report = build_table(flat, layout, guest_base,
                                             args.name, entries, catalog_meta,
                                             catalog_c, partial,
                                             verify_mode=args.verify_mode,
                                             receipt=receipt)
    except PartitionMismatch as exc:
        if args.report:
            _write(args.report, _json_bytes(exc.report))
        sys.stdout.write("REFUSED %s\n" % exc.reason)
        sys.stderr.write("g3_fde_emit: %s\n" % exc)
        return 2
    except EmitError as exc:
        sys.stdout.write("REFUSED %s\n" % exc.reason)
        sys.stderr.write("g3_fde_emit: %s\n" % exc)
        return 2
    _write(args.out_c, text.encode("utf-8"))
    _write(args.out_json, _json_bytes(meta))
    if args.cmd == "table":
        if args.report:
            _write(args.report, _json_bytes(report))
        if args.write_receipt:
            # Only reached after a successful regenerate verification.
            _write(args.write_receipt, _json_bytes(make_receipt(
                catalog_meta, catalog_c, flat, guest_base, args.name, partial)))
        print("%s: %d closure blocks, %d from the catalog, %d emitted, %d "
              "catalog block(s) compiled but not admitted"
              % (args.name, report["closure_blocks"],
                 report["covered_matches"], report["outside_candidates"],
                 report["unadmitted_catalog_blocks"]))
    else:
        print("%s: catalog of %d block(s) over %d boundar%s, identity %s"
              % (args.name, len(meta["blocks"]), len(meta["selection"]),
                 "y" if len(meta["selection"]) == 1 else "ies",
                 meta["identity"][:16]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
