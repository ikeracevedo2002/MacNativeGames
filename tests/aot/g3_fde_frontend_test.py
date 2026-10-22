#!/usr/bin/env python3
"""Hermetic synthetic tests for tools/aot/g3_fde_frontend.py (D024 Stage A).

Everything is generated: a tiny AArch64 module assembled with llvm-mc from
`tests/aot/g3/fde_fixture.s` (real `.cfi_*` directives), linked with ld.lld
`--eh-frame-hdr` against `tests/aot/g3/fde.ld`, and flattened to an NSO byte
image by `aot_module.elf2flat`.  No game data, no title constants, no hash
allowlist.

The expectations are NOT read from the frontend: the boundary starts/ends come
from the linked ELF's own `.symtab` (the fixture declares an explicit `.size`
per function) and the `.eh_frame`/`.eh_frame_hdr` extents come from the ELF's
own section headers, which is an oracle the flat image cannot forge.

Covered:
  * positive: exact boundary set and per-boundary provenance
    (fde+dynsym_func, fde only, fde+dt_init_array), exact TEXT gaps, the
    candidate/authority contract, deterministic output, CLI round trip;
  * negatives, each asserting its SPECIFIC typed reason code: truncated hdr,
    bad hdr version, unsupported encoding, fde_count mismatch, unsorted table,
    table/walk disagreement, FDE outside TEXT, overlapping FDEs, bad CIE
    pointer, record length past the extent, unknown augmentation, missing MOD0
    hdr extent, augmentation data shorter than its fields, absolute FDE pointer
    encoding, forged layout dynsym_count; a DT_INIT_ARRAY target that is not an
    FDE start is a reported conflict; the D006 guard against a case-changed
    path and a junction into the tree;
  * a NEGATIVE CONTROL: the same assertions run in a child process against a
    deliberately lax frontend (monkeypatched in that child only; the tool
    itself has no mutant switch) must FAIL.  A mutant
    that passes is a SURVIVOR, i.e. the checks it targets are vacuous.

Exit: 0 pass, 1 a check failed, 2 the negative control survived.
"""

import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO, "tools", "aot"))

import aot_module as M            # noqa: E402
import aot_translate as T         # noqa: E402
import g3_ctor_roots as G         # noqa: E402
import g3_fde_frontend as F       # noqa: E402
import g3_init_reach as R         # noqa: E402
import g3_local_switch as LS      # noqa: E402

FIXTURE_ASM = os.path.join(REPO, "tests", "aot", "g3", "fde_fixture.s")
FIXTURE_LD = os.path.join(REPO, "tests", "aot", "g3", "fde.ld")
TOOL = os.path.join(REPO, "tools", "aot", "g3_fde_frontend.py")
FUNCTIONS = ("fx_entry", "fx_local", "fx_hidden", "fx_ctor")

FAILS = []
OKS = [0]
SURVIVORS = []


def fail(msg):
    FAILS.append(msg)
    print("FAIL: " + msg)


def okk(msg):
    OKS[0] += 1
    print("OK: " + msg)


def check(cond, msg):
    if not cond:
        fail(msg)
    return cond


def checked(cmd):
    proc = subprocess.run([str(x) for x in cmd], capture_output=True, text=True)
    if proc.returncode:
        raise RuntimeError("command failed (%d): %s\n%s\n%s"
                           % (proc.returncode, cmd, proc.stdout[-4000:],
                              proc.stderr[-4000:]))
    return proc.stdout


def enc_sdata4(value):
    return struct.pack("<i", value)


def enc_udata4(value):
    return struct.pack("<I", value)


# --------------------------------------------------------------- fixture build

def symbols(elf):
    """{name: {value, size, type, bind}} from the ELF's own .symtab."""
    symtab = elf.section(".symtab")
    strtab = elf.section(".strtab")
    if symtab is None or strtab is None:
        raise RuntimeError("fixture ELF has no .symtab/.strtab")
    strings = elf.section_bytes(strtab)
    out = {}
    for index in range(symtab["size"] // 24):
        off = symtab["offset"] + index * 24
        name_off, info, _other, _shndx, value, size = \
            struct.unpack_from("<IBBHQQ", elf.data, off)
        end = strings.find(b"\x00", name_off)
        name = strings[name_off:end].decode("utf-8", "replace")
        if name:
            out[name] = {"value": value, "size": size,
                         "type": info & 0xF, "bind": info >> 4}
    return out


def build_fixture(work, llvm):
    if not os.path.isdir(work):
        os.makedirs(work)
    for tool in ("llvm-mc.exe", "ld.lld.exe"):
        path = os.path.join(llvm, tool)
        if not os.path.isfile(path):
            raise RuntimeError("missing %s (pass --llvm)" % path)
    obj = os.path.join(work, "fx.o")
    shared = os.path.join(work, "libfx.so")
    checked([os.path.join(llvm, "llvm-mc.exe"), "-triple=aarch64-none-elf",
             "-filetype=obj", "-o", obj, FIXTURE_ASM])
    checked([os.path.join(llvm, "ld.lld.exe"), "-shared",
             "-z", "max-page-size=4096", "-soname", "libfx.so",
             "--hash-style=both", "-T", FIXTURE_LD, "--eh-frame-hdr",
             "-o", shared, obj])
    layout = M.elf2flat(shared, "fx_fde", work)
    flat_path = os.path.join(work, "fx_fde.flat")
    with open(flat_path, "rb") as handle:
        flat = handle.read()
    elf = M.Elf64(open(shared, "rb").read(), shared)
    syms = symbols(elf)
    hdr = elf.section(".eh_frame_hdr")
    eh = elf.section(".eh_frame")
    if hdr is None or eh is None:
        raise RuntimeError("fixture ELF has no .eh_frame_hdr/.eh_frame")
    return {
        "flat": flat,
        "layout": layout,
        "path": flat_path,
        "layout_path": os.path.join(work, "fx_fde.layout.json"),
        "syms": syms,
        "elf_hdr": (hdr["addr"], hdr["addr"] + hdr["size"]),
        "elf_eh_frame": (eh["addr"], eh["addr"] + eh["size"]),
        "eh_frame_ptr": syms.get("__eh_frame_start", {}).get("value"),
    }


def relative_sites(flat, layout):
    """The module's own R_AARCH64_RELATIVE sym-0 records applied (base 0)."""
    tags = M.read_dynamic(flat, layout["mod0_off"], layout["image_size"],
                          layout["data"][0], layout["data"][1])
    sites = {}
    for name, addr_tag, size_tag in ((".rela", M.DT_RELA, M.DT_RELASZ),
                                     (".jmprel", M.DT_JMPREL,
                                      getattr(M, "DT_PLTRELSZ", 2))):
        if addr_tag not in tags:
            continue
        for rec in M.parse_rela_table(flat, tags[addr_tag], tags[size_tag],
                                      layout["image_size"], name):
            if rec["kind"] == G.R_AARCH64_RELATIVE and rec["sym"] == 0:
                sites[rec["where"]] = rec["addend"]
    return sites


def fixture_view(fx):
    """Everything the positive assertions and the mutations need."""
    flat, layout = fx["flat"], fx["layout"]
    meta = F.read_module(flat, layout, "fx_fde")
    header, fdes, terminator_end = F.parse_fdes(meta)
    return {"meta": meta, "header": header, "fdes": fdes,
            "terminator_end": terminator_end,
            "context": LS.Context(flat, layout, 0, T.decode)}


def build_manifest(fx, view):
    """The REAL pipeline: derive() the ctor table, then build the manifest."""
    image = R.Image("fx_fde", 0, fx["flat"], fx["layout"],
                    relative_sites(fx["flat"], fx["layout"]))
    ctor_targets, ctor_info = F.derive_ctor_targets(image, view["context"])
    return F.build_manifest(view["meta"], view["header"],
                            view["terminator_end"], view["fdes"],
                            view["context"], ctor_targets, ctor_info)


# ------------------------------------------------------------------ mutations

def mutated(fx, edits):
    flat = bytearray(fx["flat"])
    for off, data in edits:
        flat[off:off + len(data)] = data
    layout = dict(fx["layout"])
    layout["sha256"] = hashlib.sha256(bytes(flat)).hexdigest()
    return bytes(flat), layout


def hdr_edit(fx, view, offset, data):
    start = view["header"].start
    return (start + offset, data)


def table_pc_edit(fx, view, index, value):
    """Patch one binary-search table initial_location (datarel|sdata4)."""
    start = view["header"].start
    off = start + 12 + 8 * index
    return (off, enc_sdata4(value - start))


def table_fde_edit(fx, view, index, value):
    start = view["header"].start
    off = start + 16 + 8 * index
    return (off, enc_sdata4(value - start))


def fde_pc_edit(fde, value):
    """Patch an FDE's pc_begin (pcrel|sdata4 from the field's own address)."""
    field = fde.address + 8
    return (field, enc_sdata4(value - field))


def fde_range_edit(fde, value):
    return (fde.address + 12, enc_sdata4(value))


def expect_refusal(label, fx, edits, reason):
    flat, layout = mutated(fx, edits)
    try:
        F.manifest_for(flat, layout, context=None, name="fx_fde")
    except F.FdeError as exc:
        if exc.reason != reason:
            fail("%s: refused %r (%s), expected %r"
                 % (label, exc.reason, exc.detail, reason))
            return False
        okk("%s -> refused %s" % (label, exc.reason))
        return True
    fail("%s: no refusal (expected %r)" % (label, reason))
    return False


# ------------------------------------------------------------------ assertions

def expected_boundaries(fx):
    out = []
    for name in FUNCTIONS:
        sym = fx["syms"][name]
        start, size = sym["value"], sym["size"]
        if size <= 0:
            raise RuntimeError("fixture %s has no explicit .size" % name)
        provenance = ["fde"]
        if name == "fx_entry":                 # only this one is in .dynsym
            provenance.append("dynsym_func")
        if name == "fx_ctor":                  # the .init_array member
            provenance.append("dt_init_array")
        out.append({"start": "0x%x" % start, "end": "0x%x" % (start + size),
                    "provenance": provenance})
    return out


def expected_gaps(fx, boundaries):
    text_lo, text_hi = fx["layout"]["text"][0], \
        fx["layout"]["text"][0] + fx["layout"]["text"][1]
    gaps = []
    cursor = text_lo
    for item in sorted(boundaries, key=lambda b: int(b["start"], 16)):
        start, end = int(item["start"], 16), int(item["end"], 16)
        if start > cursor:
            gaps.append({"start": "0x%x" % cursor, "end": "0x%x" % start,
                         "size": start - cursor})
        cursor = max(cursor, end)
    if cursor < text_hi:
        gaps.append({"start": "0x%x" % cursor, "end": "0x%x" % text_hi,
                     "size": text_hi - cursor})
    return gaps


def verify_positive(fx, view, manifest):
    """Every positive assertion.  Returns the number of checks that ran."""
    before = OKS[0]
    expect = expected_boundaries(fx)

    check(manifest["schema_version"] == F.SCHEMA_VERSION,
          "schema_version is %r" % (manifest["schema_version"],))
    check(manifest["kind"] == "candidates",
          "kind is %r (must be 'candidates', never 'roots')"
          % (manifest["kind"],))
    check(manifest["authority"] == "none",
          "authority is %r (FDE starts are evidence, not authority)"
          % (manifest["authority"],))
    check("never roots" in manifest["authority_note"],
          "the manifest does not state that its entries are never roots")
    check(manifest["module"]["sha256"] == fx["layout"]["sha256"],
          "the manifest does not bind the flat SHA-256")
    okk("schema/kind/authority/flat-SHA contract")

    if not check(manifest["boundaries"] == expect,
                 "boundaries %r != expected %r"
                 % (manifest["boundaries"], expect)):
        return OKS[0] - before
    okk("exact boundary set and provenance (fde, fde+dynsym_func, "
        "fde+dt_init_array)")

    gaps = expected_gaps(fx, expect)
    if check(manifest["text_gaps"] == gaps,
             "text gaps %r != expected %r"
             % (manifest["text_gaps"], gaps)):
        okk("exact TEXT gaps not covered by any FDE (%d)" % len(gaps))

    counts = manifest["counts"]
    check(counts["boundaries"] == len(expect),
          "boundary count %r" % (counts["boundaries"],))
    check(counts["dynsym_func"] == 1, "dynsym_func count %r"
          % (counts["dynsym_func"],))
    check(counts["dt_init_array"] == 1, "dt_init_array count %r"
          % (counts["dt_init_array"],))
    check(counts["ctor_targets"] == 1 and counts["ctor_targets_on_fde_start"]
          == 1, "constructor targets are not all FDE starts: %r" % (counts,))
    check(counts["conflicts"] == 0, "unexpected conflicts %r"
          % (manifest["conflicts"],))
    okk("counts")

    # The extents must be the ELF's OWN .eh_frame_hdr/.eh_frame geometry, which
    # the flat image cannot forge: MOD0 is the only thing the frontend may use.
    hdr = (int(manifest["eh_frame_hdr"]["start"], 16),
           int(manifest["eh_frame_hdr"]["end"], 16))
    if check(hdr == fx["elf_hdr"],
             ".eh_frame_hdr extent %r != ELF section %r"
             % (hdr, fx["elf_hdr"])):
        okk(".eh_frame_hdr extent comes from MOD0 (matches the ELF section)")
    check(int(manifest["eh_frame_hdr"]["table_entries"]) == len(expect),
          "table entry count %r" % (manifest["eh_frame_hdr"]["table_entries"],))
    eh = (int(manifest["eh_frame"]["start"], 16),
          int(manifest["eh_frame"]["end"], 16))
    if check(eh == fx["elf_eh_frame"],
             ".eh_frame walk %r != ELF section %r (start/terminator)"
             % (eh, fx["elf_eh_frame"])):
        okk(".eh_frame walk spans exactly the section, terminator included")
    check(int(manifest["eh_frame"]["start"], 16) == fx["eh_frame_ptr"],
          ".eh_frame_ptr %r is not the ELF's __eh_frame_start"
          % (manifest["eh_frame"]["start"],))
    okk("eh_frame_ptr is the linker's own symbol")

    ctor = manifest["ctor_table"]
    check(ctor.get("status") == "derived",
          "ctor table status %r (derive() must have been used)" % (ctor,))
    check(ctor.get("entries") == 1, "ctor table entries %r" % (ctor,))
    okk("dt_init_array provenance reuses g3_ctor_roots.derive()")

    # Determinism: the same input must produce byte-identical JSON.
    first = json.dumps(manifest, sort_keys=True)
    second = json.dumps(build_manifest(fx, view), sort_keys=True)
    check(first == second, "the manifest is not deterministic")
    okk("deterministic manifest")
    return OKS[0] - before


# ------------------------------------------------------------------ negatives

def run_negatives(fx, view):
    hdr = view["header"]
    fdes = view["fdes"]
    first_fde = fdes[0]
    last_fde = max(fdes, key=lambda fde: fde.address)
    cie = first_fde.cie_offset
    mod0 = fx["layout"]["mod0_off"]
    hdr_start_rel = struct.unpack_from("<i", fx["flat"], mod0 + 16)[0]

    # 1. truncated header: the MOD0 extent stops 3 bytes into the header.
    expect_refusal("truncated .eh_frame_hdr",
                   fx, [(mod0 + 20, enc_sdata4(hdr_start_rel + 3))],
                   "eh-frame-hdr-truncated")
    # 2. bad version.
    expect_refusal("bad header version", fx,
                   [hdr_edit(fx, view, 0, bytes([0x02]))], "bad-hdr-version")
    # 3. unsupported table encoding (datarel|sdata2 instead of datarel|sdata4).
    expect_refusal("unsupported table encoding", fx,
                   [hdr_edit(fx, view, 3, bytes([0x3A]))],
                   "unsupported-encoding:table")
    # 4. fde_count smaller than the number of FDEs the walk finds (the freed
    #    table slot is zeroed so the extent is still consumed exactly).
    shrunk = len(fdes) - 1
    expect_refusal("fde_count mismatch", fx,
                   [hdr_edit(fx, view, 8, enc_udata4(shrunk)),
                    (view["header"].start + 12 + 8 * shrunk,
                     b"\x00" * 8)],
                   "fde-count-mismatch")
    # 5. unsorted table: swap the first two initial_location values.
    table = [pc for pc, _fde in hdr.table]
    expect_refusal("unsorted table", fx,
                   [table_pc_edit(fx, view, 0, table[1]),
                    table_pc_edit(fx, view, 1, table[0])],
                   "table-not-sorted")
    # 6. table/walk disagreement: one table FDE address is off by 4.
    expect_refusal("table/walk disagreement", fx,
                   [table_fde_edit(fx, view, 1, hdr.table[1][1] + 4)],
                   "table-walk-disagreement")
    # 7. an FDE outside TEXT: move the last function past the TEXT end.
    text_hi = fx["layout"]["text"][1]
    expect_refusal("FDE outside TEXT", fx,
                   [fde_pc_edit(last_fde, text_hi),
                    table_pc_edit(fx, view, len(hdr.table) - 1, text_hi)],
                   "fde-outside-text")
    # 8. overlapping FDEs: stretch one range over its successor.
    lo = first_fde.start
    nxt = [fde for fde in fdes if fde.start > lo]
    span = (nxt[0].end - lo) if nxt else 4
    expect_refusal("overlapping FDEs", fx,
                   [fde_range_edit(first_fde, (span // 4 + 1) * 4)],
                   "overlapping-fde")
    # 9. bad CIE pointer: point the second FDE at a non-CIE record.
    second = fdes[1]
    expect_refusal("bad CIE pointer", fx,
                   [(second.address + 4, enc_udata4(0x1000))],
                   "bad-cie-pointer")
    # 10. record length past the extent: the last record claims 8 KiB.
    expect_refusal("record length past the extent", fx,
                   [(last_fde.address, enc_udata4(0x2000))],
                   "record-length-past-extent")
    # 11. unknown augmentation: "zR" -> "zQ".
    expect_refusal("unknown augmentation", fx,
                   [(cie + 10, b"Q")], "unknown-augmentation:Q")
    # 12. missing MOD0 extent: this is a DISTINCT outcome, not an empty list.
    expect_refusal("missing MOD0 .eh_frame_hdr extent", fx,
                   [(mod0 + 16, enc_udata4(0)), (mod0 + 20, enc_udata4(0))],
                   "no-eh-frame-hdr")

    # The fixture CIE is v1 "zR": code/data/return-register are one byte
    # each, so aug_len sits at +15 and the R encoding at +16.  Check that
    # first so a toolchain change cannot turn the next two into no-ops.
    flat = fx["flat"]
    if check(flat[cie + 8] == 1 and flat[cie + 9:cie + 12] == b"zR\x00"
             and flat[cie + 15] == 1 and flat[cie + 16] == 0x1B,
             "fixture CIE layout changed: %s" % flat[cie:cie + 17].hex()):
        # 13. aug_len 0: the R byte would be read from the initial
        #     instructions; it must be refused inside the augmentation data.
        expect_refusal("augmentation data shorter than its fields", fx,
                       [(cie + 15, b"\x00")],
                       "cie-augmentation-data-truncated")
        # 14. absolute pc_begin: an unrelocated raw word, never an offset.
        expect_refusal("absolute FDE pointer encoding", fx,
                       [(cie + 16, b"\x00")],
                       "unsupported-encoding:pc_begin")

    # 15. a forged layout dynsym_count can neither hide nor truncate symbols.
    for forged in (fx["layout"]["dynsym_count"] - 1, -1):
        layout = dict(fx["layout"], dynsym_count=forged)
        try:
            F.manifest_for(fx["flat"], layout, context=None, name="fx_fde")
        except F.FdeError as exc:
            if check(exc.reason in ("dynsym-invalid", "layout-invalid"),
                     "forged dynsym_count %d refused as %r" % (forged,
                                                              exc.reason)):
                okk("forged dynsym_count %d -> refused %s"
                    % (forged, exc.reason))
        else:
            fail("forged dynsym_count %d was accepted" % forged)

    # 16. a constructor target with no FDE is a reported conflict.
    gap = F.text_gaps(view["meta"], fdes)[0]
    manifest = F.build_manifest(view["meta"], view["header"],
                                view["terminator_end"], fdes, view["context"],
                                ctor_targets=[gap[0]])
    hits = [c for c in manifest["conflicts"]
            if c["reasons"] == ["dt-init-array-not-fde-start"]]
    if check(len(hits) == 1 and int(hits[0]["start"], 16) == gap[0]
             and manifest["counts"]["conflicts"] == len(manifest["conflicts"]),
             "ctor target 0x%x off any FDE start was not reported: %r"
             % (gap[0], manifest["conflicts"])):
        okk("DT_INIT_ARRAY target off an FDE start -> conflict reported")


def run_cli(fx, work):
    out = os.path.join(work, "cli_manifest.json")
    stdout = checked([sys.executable, TOOL, fx["path"], fx["layout_path"],
                      "--out", out])
    if not check(os.path.isfile(out), "the CLI wrote no manifest"):
        return
    with open(out, "r", encoding="utf-8") as handle:
        again = json.load(handle)
    with open(out, "r", encoding="utf-8") as handle:
        raw_first = handle.read()
    checked([sys.executable, TOOL, fx["path"], fx["layout_path"],
             "--out", out])
    with open(out, "r", encoding="utf-8") as handle:
        raw_second = handle.read()
    check(raw_first == raw_second, "the CLI output is not deterministic")
    check(again["kind"] == "candidates" and again["authority"] == "none",
          "the CLI manifest lost the candidate/authority contract")
    check(len(again["boundaries"]) == len(FUNCTIONS),
          "the CLI manifest has %d boundaries" % len(again["boundaries"]))
    okk("CLI: %s" % stdout.strip().splitlines()[-1])

    # Fail closed: a disagreeing table must exit 2 with the typed reason and
    # must not write a manifest.
    flat, layout = mutated(fx, [table_fde_edit(fx, fixture_view(fx),
                                              1, 0x2000)])
    bad_flat = os.path.join(work, "bad.flat")
    bad_layout = os.path.join(work, "bad.layout.json")
    bad_out = os.path.join(work, "bad.manifest.json")
    with open(bad_flat, "wb") as handle:
        handle.write(flat)
    with open(bad_layout, "w", encoding="utf-8") as handle:
        json.dump(layout, handle)
    proc = subprocess.run([sys.executable, TOOL, bad_flat, bad_layout,
                           "--out", bad_out], capture_output=True, text=True)
    check(proc.returncode == 2,
          "a disagreeing table must exit 2, got %d" % proc.returncode)
    check("REFUSED table-walk-disagreement" in proc.stdout,
          "the refusal reason is not on stdout: %r" % proc.stdout)
    check(not os.path.exists(bad_out),
          "the CLI wrote a manifest for a refused image")
    okk("CLI fails closed on a table/walk disagreement")

    # D006: a real module manifest must never land inside the source tree.
    inside = os.path.join(REPO, "fde_manifest_must_not_exist.json")
    proc = subprocess.run([sys.executable, TOOL, fx["path"], fx["layout_path"],
                           "--out", inside], capture_output=True, text=True)
    check(proc.returncode == 2,
          "--out inside the tree must be rejected, got %d" % proc.returncode)
    check(not os.path.exists(inside),
          "the CLI wrote a manifest inside the source tree")
    okk("CLI refuses an --out path inside the source tree")

    # Windows paths are case-insensitive: a case-changed spelling of the tree
    # is still the tree.
    if os.name == "nt":
        swapped = os.path.join(REPO.swapcase(), "fde_manifest_must_not_exist.json")
        proc = subprocess.run([sys.executable, TOOL, fx["path"],
                               fx["layout_path"], "--out", swapped],
                              capture_output=True, text=True)
        check(proc.returncode == 2 and not os.path.exists(inside),
              "a case-changed --out inside the tree was accepted (%d)"
              % proc.returncode)
        okk("CLI refuses a case-changed --out inside the source tree")

    # A junction/symlink outside the tree that resolves inside it.
    link = os.path.join(work, "tree_link")
    if os.name == "nt":
        made = subprocess.run(["cmd", "/c", "mklink", "/J", link, REPO],
                              capture_output=True, text=True).returncode == 0
    else:
        try:
            os.symlink(REPO, link)
            made = True
        except OSError:
            made = False
    if not check(made, "could not create a junction/symlink to the tree"):
        return
    try:
        via = os.path.join(link, "fde_manifest_must_not_exist.json")
        proc = subprocess.run([sys.executable, TOOL, fx["path"],
                               fx["layout_path"], "--out", via],
                              capture_output=True, text=True)
        check(proc.returncode == 2 and not os.path.exists(inside),
              "an --out through a junction into the tree was accepted (%d)"
              % proc.returncode)
        okk("CLI refuses an --out through a junction into the source tree")
    finally:
        if os.name == "nt":
            os.rmdir(link)              # removes the junction, not its target
        else:
            os.unlink(link)


# ----------------------------------------------------------- negative control

MUTANTS = ("empty", "skip_crosscheck")


def apply_mutant(name):
    """Monkeypatch a deliberately lax frontend into THIS (child) process."""
    if name == "empty":
        parse = F.parse_fdes
        F.parse_fdes = lambda meta: (lambda r: (r[0], [], r[2]))(parse(meta))
    elif name == "skip_crosscheck":
        F._crosscheck = lambda *args, **kwargs: None
    elif name:
        raise SystemExit("unknown mutant %r" % name)


def child_mode(args):
    """Run the SAME assertions; used to prove a lax mutant makes them fail."""
    apply_mutant(args.child_mutant)
    with open(args.child_flat, "rb") as handle:
        flat = handle.read()
    with open(args.child_layout, "r", encoding="utf-8") as handle:
        layout = json.load(handle)
    fx = {"flat": flat, "layout": layout}
    if args.child_variant == "disagreement":
        view = fixture_view(fx)
        flat, layout = mutated(fx, [table_fde_edit(fx, view, 1, 0x2000)])
        try:
            F.manifest_for(flat, layout, context=None, name="fx_fde")
        except F.FdeError as exc:
            if exc.reason == "table-walk-disagreement":
                print("OK: the disagreeing table was refused")
                return 0
            fail("the disagreement was refused as %r" % exc.reason)
            return 1
        fail("SURVIVOR: the table/walk disagreement was ACCEPTED")
        return 1    # "clean": the full positive suite over the pristine fixture.
    with open(args.child_symbols, "r", encoding="utf-8") as handle:
        export = json.load(handle)
    fx["syms"] = export["syms"]
    fx["elf_hdr"] = tuple(export["__hdr"])
    fx["elf_eh_frame"] = tuple(export["__eh"])
    fx["eh_frame_ptr"] = fx["syms"]["__eh_frame_start"]["value"]
    view = fixture_view(fx)
    manifest = build_manifest(fx, view)
    verify_positive(fx, view, manifest)
    return 1 if FAILS else 0


def run_mutant_control(fx, work):
    export = {"syms": fx["syms"],
              "__hdr": list(fx["elf_hdr"]),
              "__eh": list(fx["elf_eh_frame"])}
    symbols_path = os.path.join(work, "symbols.json")
    with open(symbols_path, "w", encoding="utf-8") as handle:
        json.dump(export, handle)

    def run(variant, mutant):
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        proc = subprocess.run(
            [sys.executable, os.path.abspath(__file__), "--child",
             "--child-variant", variant, "--child-mutant", mutant or "",
             "--child-flat", fx["path"],
             "--child-layout", fx["layout_path"],
             "--child-symbols", symbols_path],
            capture_output=True, text=True, env=env)
        return proc

    control = run("clean", None)
    if control.returncode != 0:
        fail("negative control: the UNMUTATED suite did not pass (%d)\n%s"
             % (control.returncode, control.stdout[-3000:]))
    else:
        okk("negative control: the unmutated suite passes in a child process")

    cases = (("empty", "clean", "boundaries ",
              "returns no boundaries at all (a lax 'no FDEs found' parser)"),
             ("skip_crosscheck", "disagreement", "was ACCEPTED",
              "skips the header-table/walk cross-check"))
    for mutant, variant, needle, what in cases:
        proc = run(variant, mutant)
        if proc.returncode == 0:
            SURVIVORS.append(mutant)
            fail("SURVIVOR: the mutant %r (%s) still passes the suite"
                 % (mutant, what))
            continue
        if needle not in proc.stdout:
            fail("the mutant %r was not caught by its own check (%r missing)\n%s"
                 % (mutant, needle, proc.stdout[-2000:]))
            continue
        caught = [line for line in proc.stdout.splitlines()
                  if line.startswith("FAIL")][0]
        okk("negative control: mutant %r is caught (%s)"
            % (mutant, caught[:96]))


# ---------------------------------------------------------------------- main

def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--llvm", default=os.environ.get("AOT_LLVM_BIN", ""),
                        help="directory holding llvm-mc.exe and ld.lld.exe")
    parser.add_argument("--keep", default=None,
                        help="keep the generated fixture in this directory")
    parser.add_argument("--child", action="store_true",
                        help=argparse.SUPPRESS)
    parser.add_argument("--child-variant", default="clean",
                        choices=("clean", "disagreement"))
    parser.add_argument("--child-mutant", default="",
                        choices=("",) + MUTANTS)
    parser.add_argument("--child-flat", default=None)
    parser.add_argument("--child-layout", default=None)
    parser.add_argument("--child-symbols", default=None)
    args = parser.parse_args(argv)
    if args.child:
        return child_mode(args)
    if not args.llvm:
        sys.stderr.write("g3_fde_frontend_test: --llvm is required\n")
        return 2
    work = args.keep or tempfile.mkdtemp(prefix="g3fde_")
    try:
        fx = build_fixture(work, args.llvm)
        view = fixture_view(fx)
        manifest = build_manifest(fx, view)
        verify_positive(fx, view, manifest)
        run_negatives(fx, view)
        run_cli(fx, work)
        run_mutant_control(fx, work)
    finally:
        if args.keep is None:
            import shutil
            shutil.rmtree(work, ignore_errors=True)
    if SURVIVORS:
        print("FAIL: %d surviving mutant(s): %s"
              % (len(SURVIVORS), ", ".join(SURVIVORS)))
        return 2
    if FAILS:
        print("FAIL: %d fde-frontend check(s)" % len(FAILS))
        return 1
    print("PASS: g3_fde_frontend (%d checks)" % OKS[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
