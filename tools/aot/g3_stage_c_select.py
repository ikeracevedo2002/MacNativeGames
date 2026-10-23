#!/usr/bin/env python3
"""D024 Stage C - stratified catalog-window selection (plan step 1.4; PORTING_PLAN Phase 2).

WHAT THIS IS
------------
A PURE selector of FDE windows that the Stage C candidate catalog should
precompile next, so that constructors admitted later are usually already
compiled.  Its output is a SELECTION for `g3_fde_emit.py catalog --select`
(comma-separated image-offset window starts).  It is never roots, entries or
an authority table.

    authority: none.  Compiled is not authorized (D024): this module reads a
    candidate manifest and plain inputs and returns advice.  Nothing here adds
    an executable entry, changes the root policy, the runtime, the loader or
    the translator.  `g3_fde_emit.py catalog` re-derives every window from the
    flat before it accepts one, so a wrong selection is a typed refusal there.

INPUTS (plain data, all image offsets)
--------------------------------------
    manifest      dict from g3_fde_frontend.build_manifest (schema 1,
                  kind "candidates", authority "none"); boundaries are
                  {"start": "0x..", "end": "0x..", "provenance": [...]}.
    ctor_slots    DT_INIT_ARRAY targets in ARRAY ORDER (duplicates possible).
    admitted      set of targets already admitted as roots.
    window_info   start -> {"bl_targets": [...], "strata": set(...)}.  A lazy
                  mapping (LazyWindowInfo) is accepted and scans on demand.

STRATA AND THE SCANNER
----------------------
`scan_window` classifies the 4-byte words of one window.  Every mask below was
checked with `llvm-mc -triple=aarch64 [-mattr=+lse] -show-encoding` (LLVM 18),
positives and negatives; the exact words are in
tests/aot/g3_stage_c_select_test.py.

    bl           (w & 0xFC000000) == 0x94000000           target = pc + imm26*4
    indirect     (w & 0xFFFFFC1F) == 0xD63F0000  (BLR)
                 (w & 0xFFFFFC1F) == 0xD61F0000  (BR; PLT tails too)
    exclusive    (w & 0x3F000000) == 0x08000000  (LDXR/LDAXR/STXR/STLXR, all
                 sizes; this class also contains LDXP/CAS/LDAR/STLR)
                 plus LSE atomics (w & 0x3F200C00) == 0x38200000 (LDADD, SWP,
                 STADD).  The LSE extension is NOT in the brief; it is added
                 because atomics must not be reported as missing.
    fp_simd      (w & 0x0E000000) == 0x0E000000  (scalar/vector FP & SIMD DP)
                 or ((w & 0x0A000000) == 0x08000000 and bit 26 (V) set)
                 (SIMD&FP loads/stores)
    unsupported  T.decode(guest_base + pc, w, module=True) raises DecodeError
    no_fde       not a per-window stratum; a constructor target that is not an
                 FDE start (selector-level, see select_catalog_windows)
    local_switch cannot be known from bytes; a caller hint in window_info only.
                 scan_window never sets it.
"""

import argparse
import collections
import hashlib
import json
import os
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import aot_translate as T       # noqa: E402
import g3_fde_frontend as F     # noqa: E402

SCHEMA_VERSION = 1
KIND = "catalog-selection"
AUTHORITY = "none"
STRATA = ("bl", "indirect", "local_switch", "fp_simd", "exclusive",
          "unsupported", "no_fde")

MASK_BL = (0xFC000000, 0x94000000)
MASK_BLR = (0xFFFFFC1F, 0xD63F0000)
MASK_BR = (0xFFFFFC1F, 0xD61F0000)
MASK_EXCL = (0x3F000000, 0x08000000)
MASK_LSE = (0x3F200C00, 0x38200000)
MASK_FP_DP = (0x0E000000, 0x0E000000)
MASK_FP_LS = (0x0A000000, 0x08000000)
BIT_V = 26


def _hit(word, mask):
    return (word & mask[0]) == mask[1]


def _signed(value, bits):
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def scan_window(flat, start, end, guest_base=0):
    """Classify the words of image window [start, end) -> {bl_targets, strata}.

    `start`/`end` and the BL targets are image offsets; the decoder sees the
    guest VA `guest_base + offset`.  Windows must be 4-aligned and inside flat.
    """
    if start < 0 or end < start or (start & 3) or (end & 3):
        raise ValueError("window [0x%x,0x%x) is not a 4-aligned forward range"
                         % (start, end))
    if end > len(flat):
        raise ValueError("window end 0x%x is past the flat (0x%x bytes)"
                         % (end, len(flat)))
    targets = set()
    strata = set()
    for pc in range(start, end, 4):
        word = struct.unpack_from("<I", flat, pc)[0]
        if _hit(word, MASK_BL):
            target = pc + _signed(word & 0x3FFFFFF, 26) * 4
            if target >= 0:
                targets.add(target)
            strata.add("bl")
        if _hit(word, MASK_BLR) or _hit(word, MASK_BR):
            strata.add("indirect")
        if _hit(word, MASK_EXCL) or _hit(word, MASK_LSE):
            strata.add("exclusive")
        if _hit(word, MASK_FP_DP) or (_hit(word, MASK_FP_LS)
                                      and ((word >> BIT_V) & 1)):
            strata.add("fp_simd")
        try:
            T.decode(guest_base + pc, word, module=True)
        except T.DecodeError:
            strata.add("unsupported")
    return {"bl_targets": sorted(targets), "strata": strata}


class LazyWindowInfo(object):
    """start -> scan_window(...) computed on first use and cached.

    It carries no caller hints, so `local_switch` is never known through it;
    the selector then reports that stratum as missing instead of inventing it.
    """

    def __init__(self, flat, boundaries, guest_base=0):
        self._flat = flat
        self._ends = boundaries
        self._base = guest_base
        self._cache = {}

    def __getitem__(self, start):
        if start not in self._cache:
            self._cache[start] = scan_window(self._flat, start,
                                             self._ends[start], self._base)
        return self._cache[start]


def _as_offset(value):
    if isinstance(value, bool):
        raise ValueError("offset %r is a boolean" % (value,))
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise ValueError("offset %r is not an int or hex string" % (value,))


def _check_manifest(manifest):
    if not isinstance(manifest, dict):
        raise ValueError("manifest is not a JSON object")
    if manifest.get("schema_version") != F.SCHEMA_VERSION:
        raise ValueError("manifest schema_version %r (expected %d)"
                         % (manifest.get("schema_version"), F.SCHEMA_VERSION))
    if manifest.get("kind") != F.KIND or manifest.get("authority") != F.AUTHORITY:
        raise ValueError("manifest is not a candidate manifest with authority "
                         "none (kind %r, authority %r)"
                         % (manifest.get("kind"), manifest.get("authority")))


def _boundary_map(manifest):
    """manifest boundaries -> {start: end}; typed refusal on malformed windows."""
    ends = {}
    for item in manifest.get("boundaries", []):
        start = _as_offset(item["start"])
        end = _as_offset(item["end"])
        if end <= start or (start & 3) or (end & 3):
            raise ValueError("boundary [0x%x,0x%x) is not a 4-aligned range"
                             % (start, end))
        if ends.get(start, end) != end:
            raise ValueError("boundary start 0x%x has two ends" % start)
        ends[start] = end
    return ends


def _cut_index(slots, admitted):
    """Index just after the LAST slot whose target is admitted; 0 if none."""
    cut = 0
    for index, target in enumerate(slots):
        if target in admitted:
            cut = index + 1
    return cut


def _pick_next(slots, admitted, n):
    """First n distinct not-admitted targets after the admitted cut.

    -> list of (target, first slot index after the cut).  Negative control
    `g3_stage_c_select_test.py` replaces this helper with one that ignores
    `admitted`, and the next-ctor check must then fail.
    """
    picked = []
    seen = set()
    for index in range(_cut_index(slots, admitted), len(slots)):
        target = slots[index]
        if target in admitted or target in seen:
            continue
        seen.add(target)
        picked.append((target, index))
        if len(picked) == n:
            break
    return picked


def _hinted_anywhere(window_info, stratum):
    """True only when a caller-supplied mapping already carries the stratum.

    A lazy mapping never has hints, so a hint-less run cannot search for it.
    """
    if not isinstance(window_info, dict):
        return False
    return any(stratum in set(info["strata"]) for info in window_info.values())


def select_catalog_windows(manifest, ctor_slots, admitted, window_info, n=32,
                           depth=4, max_windows=512, extra_per_stratum=8):
    """Pure selection; see the module docstring.  Returns a plain dict."""
    _check_manifest(manifest)
    if n < 1 or depth < 0 or max_windows < 1 or extra_per_stratum < 0:
        raise ValueError("n >= 1, depth >= 0, max_windows >= 1 and "
                         "extra_per_stratum >= 0 are required")
    bounds = _boundary_map(manifest)
    slots = [_as_offset(s) for s in ctor_slots]
    adm = set(_as_offset(a) for a in admitted)

    picked = _pick_next(slots, adm, n)
    windows = collections.OrderedDict()       # start -> record, insertion order
    no_fde = []

    def add(start, purpose, slot):
        info = window_info[start]
        windows[start] = {"start": start, "end": bounds[start],
                          "purpose": purpose, "ctor_slot": slot,
                          "strata": set(info["strata"])}

    next_ctors = []
    for target, slot in picked:
        next_ctors.append(target)
        if target in bounds:
            add(target, "next-ctor", slot)
        else:
            no_fde.append(target)
    if len(windows) > max_windows:
        raise ValueError("max_windows %d cannot hold %d next-ctor windows"
                         % (max_windows, len(windows)))

    # Callee BFS.  Level 0 is the next-ctor set; `depth` bounds the BL hops.
    queue = collections.deque((start, 0) for start in list(windows))
    full = False
    while queue and not full:
        start, level = queue.popleft()
        if level >= depth:
            continue
        for target in sorted(window_info[start]["bl_targets"]):
            if target not in bounds or target in windows:
                continue
            if len(windows) >= max_windows:
                full = True
                break
            add(target, "callee", None)
            queue.append((target, level + 1))

    # Stratum fill from LATER constructor slots (after the chosen n).
    later_from = picked[-1][1] + 1 if picked else _cut_index(slots, adm)
    later = []
    seen_later = set(target for target, _slot in picked)
    for index in range(later_from, len(slots)):
        target = slots[index]
        if target in adm or target in seen_later:
            continue
        seen_later.add(target)
        later.append((target, index))

    def coverage():
        cov = set()
        for record in windows.values():
            cov |= record["strata"]
        if no_fde:
            cov.add("no_fde")
        return cov

    cov = coverage()
    hinted = _hinted_anywhere(window_info, "local_switch")
    to_fill = [s for s in STRATA
               if s not in cov and (s != "local_switch" or hinted)]
    for stratum in to_fill:
        added = 0
        for target, index in later:
            if added >= extra_per_stratum:
                break
            if stratum == "no_fde":
                if target not in bounds:
                    no_fde.append(target)
                    added += 1
                continue
            if len(windows) >= max_windows:
                break
            if target not in bounds or target in windows:
                continue
            if stratum not in window_info[target]["strata"]:
                continue
            add(target, "measurement", index)
            added += 1

    cov = coverage()
    windows_out = []
    for start in sorted(windows):
        record = windows[start]
        windows_out.append({"start": start, "end": record["end"],
                            "purpose": record["purpose"],
                            "ctor_slot": record["ctor_slot"],
                            "strata": sorted(record["strata"])})
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "authority": AUTHORITY,
        "windows": windows_out,
        "next_ctors": next_ctors,
        "missing_strata": sorted(s for s in STRATA if s not in cov),
        "no_fde_targets": no_fde,
    }


def select_arg(selection):
    """Comma-separated hex window starts for `g3_fde_emit.py catalog --select`."""
    return ",".join("0x%x" % window["start"] for window in selection["windows"])


# ---------------------------------------------------------------------- CLI

def _read_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _json_list(text, what):
    """A JSON list given inline (starts with '[') or as a file path."""
    if text.lstrip().startswith("["):
        data = json.loads(text)
    else:
        data = _read_json(text)
    if not isinstance(data, list):
        raise ValueError("%s is not a JSON list" % what)
    return data


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="D024 Stage C: stratified catalog-window selection "
                    "(authority none; output feeds g3_fde_emit.py catalog)")
    ap.add_argument("--manifest", required=True,
                    help="Stage A candidate manifest JSON")
    ap.add_argument("--slots", required=True,
                    help="DT_INIT_ARRAY targets in array order: a JSON list "
                         "(inline or a file path); hex strings or ints")
    ap.add_argument("--admitted", default="[]",
                    help="admitted root targets: a JSON list (inline or a "
                         "file path)")
    ap.add_argument("--flat", required=True, help="the module's flat image")
    ap.add_argument("--guest-base", dest="guest_base", required=True)
    ap.add_argument("--n", type=int, default=32,
                    help="number of next constructors (default 32)")
    ap.add_argument("--out", required=True,
                    help="selection JSON to write (outside the source tree)")
    args = ap.parse_args(argv)

    repo = os.path.dirname(os.path.dirname(_HERE))
    if F.inside_tree(args.out, repo):
        ap.error("%r is inside the source tree; generated selections must "
                 "stay outside it (D006)" % args.out)
    try:
        manifest = _read_json(args.manifest)
        _check_manifest(manifest)
        with open(args.flat, "rb") as handle:
            flat = handle.read()
        module = manifest.get("module")
        if not isinstance(module, dict) or module.get("sha256") != \
                hashlib.sha256(flat).hexdigest():
            raise ValueError("manifest module sha256 does not match the flat")
        guest_base = int(args.guest_base, 0)
        slots = _json_list(args.slots, "slots")
        admitted = _json_list(args.admitted, "admitted")
        if args.n < 1:
            raise ValueError("--n must be at least 1")
        bounds = _boundary_map(manifest)
        info = LazyWindowInfo(flat, bounds, guest_base)
        selection = select_catalog_windows(manifest, slots, admitted, info,
                                           n=args.n)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        sys.stderr.write("g3_stage_c_select: input error: %s\n" % exc)
        return 1
    with open(args.out, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(selection, indent=2, sort_keys=True) + "\n")
    print("SELECT %d windows missing_strata=%s"
          % (len(selection["windows"]),
             ",".join(selection["missing_strata"]) or "none"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
