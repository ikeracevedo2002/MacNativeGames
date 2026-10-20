#!/usr/bin/env python3
"""Derive the Mac runtime binding tables (observers + overrides) for the Windows AOT link.

The Mac port decides which guest symbols the host takes over by string comparison, in
`runtime_observer()` / `runtime_override()` (games/totk/runtime/services.c) and in the
tables/functions those two delegate to.  The Windows AOT loader needs the same two name
lists up front (they define the whole linker binding set), so this script reads the Mac
sources and emits them as JSON.

Nothing here is game data: the names are C string literals in this repository's own
source tree, so the script and its output may be committed.

Only the *shape* of each source is described below, never the names themselves:

  shape          how names are recognised
  -----          ---------------------------
  table          initializer groups that start with a string literal: {"name", fn, ...}
                 (covers `entries[]`, `map[]`, and the GfxEntry records that
                 gfx_bridge.c puts in the __DATA,totkgfx section)
  strcmp         `strcmp(name, "name")` probes (single-name overrides)
  strlist        a `NAMES[]` array of string literals, indexed alongside `ENTRIES[]`
                 (movie_host.c)
  hle_force      the first argument of `HLE_FORCE("name", ...)` (hle_nvn.c)

Everything else in those files -- notably `runtime_symbol("...")` lookups inside the
implementations, which are *not* bindings -- is deliberately ignored.

Configuration: the tables are conditional.  Mac desktop defaults are used (rumble and
gyro on, libvpx present).  The conditions are read from the sources where they are
preprocessor macros; the two TOTK_RUMBLE/TOTK_GYRO runtime flags are honoured per entry
because hid_feedback.c records the flag in the table record and in the strcmp probes.

Usage:
  extract_mac_bindings.py --out bindings.json [--repo-root DIR] [--quiet]

Exit status is non-zero if a self-check fails (observer count != 6, duplicate names,
missing anchor names), so the JSON can be trusted by the link step.
"""

import argparse
import json
import os
import re
import sys

# --- default Mac desktop configuration ---------------------------------------------
# Preprocessor macros as the Mac desktop build sees them.
MACROS = {
    "TARGET_OS_OSX": 1,
    "TARGET_OS_IPHONE": 0,
    "TOTK_MOVIE_HOST": 1,
}
# `__has_include(<vpx/...>)` is true when the macOS build has libvpx; the game's movie
# decoder is then taken over (the brief calls this the "libvpx/TOTK_MOVIE_HOST" gate).
HAS_INCLUDE = {"vpx": "TOTK_MOVIE_HOST"}
# TOTK_RUMBLE / TOTK_GYRO runtime flags of hid_feedback.c (on in the default desktop run).
RUNTIME_FLAGS = {"rumble": True, "gyro": True}

# --- what to read ------------------------------------------------------------------
RUNTIME = "games/totk/runtime"
SOURCES = [
    # (path, shape, region)
    # `region` is either None (whole file) or a list of C function names whose bodies are
    # scanned separately, which is how services.c keeps its observers and overrides apart.
    (f"{RUNTIME}/services.c", "services", ["runtime_observer", "runtime_override"]),
    (f"{RUNTIME}/input.c", "table", None),
    (f"{RUNTIME}/hid_feedback.c", "hid", ["runtime_hid_feedback_override"]),
    (f"{RUNTIME}/shared_font.c", "table", None),
    (f"{RUNTIME}/opus_codec.c", "table", None),
    (f"{RUNTIME}/movie_host.c", "table+strlist", None),
    (f"{RUNTIME}/time_host.c", "table", None),
    (f"{RUNTIME}/applet_host.c", "table", None),
    (f"{RUNTIME}/swkbd_host.c", "strcmp", None),
    (f"{RUNTIME}/account.c", "table", None),
    (f"{RUNTIME}/romfs.c", "table", None),
    (f"{RUNTIME}/fs_host.c", "table", None),
    (f"{RUNTIME}/frontend.m", "table", None),
    (f"{RUNTIME}/gfx_bridge.c", "gfx", None),
    ("games/totk/third_party/d2r_gfx/gfx/nvn/hle_nvn.c", "hle_force", None),
]

# A guest symbol name: an Itanium-mangled C++ name, or a C name such as nnMain,
# nnosInitialize, nninitStartup, nvnBootstrapLoader (lowercase prefix + a capital).
NAME_RE = re.compile(r"^(?:_Z[A-Za-z0-9_.$]+|[a-z][a-z0-9]*[A-Z][A-Za-z0-9_]*)$")

TABLE_RE = re.compile(r'\{\s*"([^"]+)"\s*,')
STRCMP_RE = re.compile(r'\bstrcmp\s*\(\s*name\s*,\s*"([^"]+)"\s*\)')
STRLIST_RE = re.compile(r'NAMES\s*\[[^\]]*\]\s*=\s*\{(.*?)\};', re.S)
STRLIST_ITEM_RE = re.compile(r'"([^"]+)"')
HLE_FORCE_RE = re.compile(r'HLE_FORCE\s*\(\s*"([^"]+)"')
# hid_feedback.c table records: {"name", (void *)fn, <gyro?>}
HID_RECORD_RE = re.compile(r'\{\s*"([^"]+)"\s*,\s*\(void\s*\*\)\s*\w+\s*,\s*(true|false)\s*\}')
# hid_feedback.c probes: strcmp(name, "X")) return <flag> ? NULL : (void *)no_handles;
HID_PROBE_RE = re.compile(
    r'\bstrcmp\s*\(\s*name\s*,\s*"([^"]+)"\s*\)\s*\)\s*\n?\s*return\s+(rumble|gyro)\s*\?\s*NULL')


def fail(msg):
    print(f"extract_mac_bindings: {msg}", file=sys.stderr)
    raise SystemExit(1)


def strip_comments(text):
    """Remove C comments while keeping string literals intact (and line numbering)."""
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == '"' or c == "'":
            q = c
            out.append(c)
            i += 1
            while i < n:
                if text[i] == "\\":
                    out.append(text[i:i + 2])
                    i += 2
                    continue
                out.append(text[i])
                if text[i] == q:
                    i += 1
                    break
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
            i = min(i + 2, n)
            continue
        out.append(c)
        i += 1
    return "".join(out)


def eval_cond(expr):
    """Evaluate the small subset of preprocessor conditions these sources use."""
    t = expr.strip()
    m = re.fullmatch(r"!\s*__has_include\s*\(\s*<([^>]+)>\s*\)", t)
    if m:
        top = m.group(1).split("/")[0]
        return not bool(MACROS.get(HAS_INCLUDE.get(top, f"__has_include:{top}"), 0))
    m = re.fullmatch(r"__has_include\s*\(\s*<([^>]+)>\s*\)", t)
    if m:
        top = m.group(1).split("/")[0]
        return bool(MACROS.get(HAS_INCLUDE.get(top, f"__has_include:{top}"), 0))
    m = re.fullmatch(r"!?\s*defined\s*\(\s*(\w+)\s*\)|!?\s*defined\s+(\w+)", t)
    if m:
        name = m.group(1) or m.group(2)
        defined = MACROS.get(name, 0) != 0
        return (not defined) if t.startswith("!") else defined
    m = re.fullmatch(r"!?\s*(\w+)", t)
    if m:
        value = MACROS.get(m.group(1), 0) != 0
        return (not value) if t.startswith("!") else value
    raise SystemExit(f"extract_mac_bindings: unsupported preprocessor condition: {expr!r}")


def apply_gates(text, origin):
    """Drop preprocessor-inactive lines for the configured build."""
    out = []
    stack = []  # (parent_active, this_branch_active, any_branch_taken)
    active = True
    for lineno, line in enumerate(text.splitlines(True), 1):
        s = line.lstrip()
        if s.startswith("#"):
            body = s[1:].strip()
            directive = body.split(None, 1)[0] if body else ""
            rest = body[len(directive):].strip()
            if directive in ("ifdef", "ifndef"):
                cond = (rest.split()[0] in MACROS and MACROS[rest.split()[0]] != 0)
                if directive == "ifndef":
                    cond = not cond
                stack.append([active, active and cond, cond])
                active = active and cond
            elif directive == "if":
                cond = eval_cond(rest)
                stack.append([active, active and cond, cond])
                active = active and cond
            elif directive == "elif":
                if not stack:
                    raise SystemExit(f"{origin}:{lineno}: stray #elif")
                parent, _, taken = stack[-1]
                cond = (not taken) and eval_cond(rest)
                stack[-1][1] = parent and cond
                stack[-1][2] = taken or cond
                active = parent and cond
            elif directive == "else":
                if not stack:
                    raise SystemExit(f"{origin}:{lineno}: stray #else")
                parent, _, taken = stack[-1]
                stack[-1][1] = parent and not taken
                stack[-1][2] = True
                active = parent and not taken
            elif directive == "endif":
                if not stack:
                    raise SystemExit(f"{origin}:{lineno}: stray #endif")
                parent, _, _ = stack.pop()
                active = parent
            continue
        out.append(line if active else ("\n" if line.endswith("\n") else ""))
    if stack:
        raise SystemExit(f"extract_mac_bindings: unbalanced #if in {origin}")
    return "".join(out)


def function_body(text, name):
    """Slice out `... name(...) { ... }` (brace matched) or fail."""
    m = re.search(r"\b" + re.escape(name) + r"\s*\([^;{]*\)\s*\{", text)
    if not m:
        raise SystemExit(f"extract_mac_bindings: function {name} not found")
    start = m.end() - 1
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    raise SystemExit(f"extract_mac_bindings: unbalanced braces in {name}")


def table_names(region):
    return [m.group(1) for m in TABLE_RE.finditer(region)]


def strcmp_names(region):
    return [m.group(1) for m in STRCMP_RE.finditer(region)]


def strlist_names(region):
    names = []
    for m in STRLIST_RE.finditer(region):
        names.extend(STRLIST_ITEM_RE.findall(m.group(1)))
    return names


def hid_names(region, reasons):
    """hid_feedback.c: table records carry their flag; probes carry an inverted flag."""
    names = []
    records = {m.group(1): (m.group(2) == "true") for m in HID_RECORD_RE.finditer(region)}
    inverted = {m.group(1): m.group(2) for m in HID_PROBE_RE.finditer(region)}
    for name in strcmp_names(region):
        if name in inverted:
            flag = inverted[name]
            if RUNTIME_FLAGS[flag]:
                reasons[name] = f"inverted {flag} probe: not an override while {flag} is on"
                continue
        names.append(name)
    for name in table_names(region):
        if name in records and records[name]:
            if not RUNTIME_FLAGS["gyro"]:
                reasons[name] = "gyro-flagged record: no override while gyro is off"
                continue
        elif name in records and not records[name]:
            if not RUNTIME_FLAGS["rumble"]:
                reasons[name] = "rumble-flagged record: no override while rumble is off"
                continue
        names.append(name)
    # Names that only appear in a record/inverted probe (not matched by the shapes above).
    for name in records:
        if name not in names:
            names.append(name) if records[name] and RUNTIME_FLAGS["gyro"] else None
    return names


def extract(repo_root):
    observers, overrides, skipped = [], [], {}
    per_source = {}
    for rel, shape, region_names in SOURCES:
        path = os.path.join(repo_root, rel)
        if not os.path.isfile(path):
            raise SystemExit(f"extract_mac_bindings: missing source {rel}")
        text = apply_gates(strip_comments(open(path, encoding="utf-8", errors="replace").read()), rel)
        raw = []
        if shape == "services":
            raw = table_names(function_body(text, region_names[0]))
            names_obs = [n for n in raw if NAME_RE.match(n)]
            body = function_body(text, region_names[1])
            raw_ovr = table_names(body) + strcmp_names(body)
            names_ovr = [n for n in raw_ovr if NAME_RE.match(n)]
            observers.extend(names_obs)
            overrides.extend(names_ovr)
            per_source[rel] = {"observers": len(names_obs), "overrides": len(names_ovr)}
            continue
        if region_names:
            region = "\n".join(function_body(text, fn) for fn in region_names)
        else:
            region = text
        if shape in ("table", "table+strlist", "gfx", "services"):
            raw += table_names(region)
            raw += strcmp_names(region)
        if shape == "table+strlist":
            raw += strlist_names(region)
        if shape == "strcmp":
            raw += strcmp_names(region)
        if shape == "hid":
            raw += hid_names(region, skipped)
        if shape == "hle_force":
            raw += HLE_FORCE_RE.findall(region)
        names = [n for n in raw if NAME_RE.match(n)]
        overrides.extend(names)
        per_source[rel] = {"observers": 0, "overrides": len(names)}
    return observers, overrides, skipped, per_source


def main(argv):
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    ap = argparse.ArgumentParser(description="Derive Mac observer/override name lists.")
    ap.add_argument("--out", required=True, help="JSON output path")
    ap.add_argument("--repo-root", default=root, help="repository root (default: this tree)")
    ap.add_argument("--config", default=None,
                    help="JSON with optional \"macros\" and \"runtime_flags\" "
                         "overrides (testing/diagnostic use: the default is "
                         "the Mac desktop configuration)")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv[1:])

    if args.config:
        over = json.loads(open(args.config, encoding="utf-8").read())
        for key, value in over.get("macros", {}).items():
            if key not in MACROS:
                raise SystemExit("extract_mac_bindings: unknown macro %r" % key)
            MACROS[key] = value
        for key, value in over.get("runtime_flags", {}).items():
            if key not in RUNTIME_FLAGS:
                raise SystemExit("extract_mac_bindings: unknown runtime flag "
                                 "%r" % key)
            RUNTIME_FLAGS[key] = bool(value)

    observers, overrides, reasons, per_source = extract(args.repo_root)

    def dedup(seq, label):
        seen, out, dups = set(), [], []
        for s in seq:
            if s in seen:
                dups.append(s)
            else:
                seen.add(s)
                out.append(s)
        return out, dups

    observers, obs_dups = dedup(observers, "observers")
    overrides, ovr_dups = dedup(overrides, "overrides")

    # --- self-checks -----------------------------------------------------------------
    if len(observers) != 6:
        fail(f"expected 6 observers, derived {len(observers)}: {observers}")
    if obs_dups:
        fail(f"duplicate observer names: {sorted(set(obs_dups))}")
    both = sorted(set(observers) & set(overrides))
    if both:
        fail(f"names in both tables: {both}")
    for anchor in ("nnMain", "nnosInitialize"):
        if anchor not in observers:
            fail(f"anchor observer {anchor} missing")
    override_anchors = ["nvnBootstrapLoader", "_ZN2nn2oe18GetDesiredLanguageEv"]
    if MACROS.get("TOTK_MOVIE_HOST"):
        override_anchors.append("_ZN5movie7DecoderC1ENS_11DecoderTypeENS_19"
                                "DecoderOutputFormatENS_11DecoderModeEi")
    for anchor in override_anchors:
        if anchor not in overrides:
            fail(f"anchor override {anchor} missing")
    if not overrides:
        fail("no overrides derived")

    doc = {
        "generated_by": "tools/aot/extract_mac_bindings.py",
        "configuration": {
            "name": "mac-desktop-default",
            "macros": {k: v for k, v in sorted(MACROS.items())},
            "runtime_flags": dict(sorted(RUNTIME_FLAGS.items())),
            "notes": [
                "hid_feedback.c detail records are gyro-flagged; with gyro on they are overrides",
                "hid_feedback.c GetVibrationDeviceHandles/GetSixAxisSensorHandles return NULL while the flag is on",
                "movie_host.c Decoder names are compiled in only when libvpx is available",
            ],
        },
        "observers": observers,
        "overrides": overrides,
        "counts": {"observers": len(observers), "overrides": len(overrides)},
        "per_source": per_source,
        "excluded": dict(sorted(reasons.items())),
        "duplicates": {"observers": sorted(set(obs_dups)), "overrides": sorted(set(ovr_dups))},
    }
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(doc, f, indent=2, sort_keys=False)
        f.write("\n")

    if not args.quiet:
        print(f"observers: {len(observers)}")
        print(f"overrides: {len(overrides)}")
        if ovr_dups:
            print(f"duplicate override names: {len(ovr_dups)} (kept once)")
        for rel, c in per_source.items():
            print(f"  {c['observers']:3d} obs {c['overrides']:3d} ovr  {rel}")
        for name, why in sorted(reasons.items()):
            print(f"  excluded {name}: {why}")
        print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
