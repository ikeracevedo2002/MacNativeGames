#!/usr/bin/env python3
"""G3 increment 2: INDEPENDENT reference check for the module linker.

Shares no code with tools/aot/aot_module.py. It takes the fixture ELFs and
asks llvm-readelf for the program headers, dynamic symbols and relocations,
then applies the link rules from the design brief itself:

  * JUMP_SLOT -> observer table; override table; own module definition;
    global search in module order; undefined weak -> 0; else error.
  * ABS64 / GLOB_DAT: no observer, otherwise the same order (S + A).
  * JUMP_SLOT: value S, addend must be 0.
  * RELATIVE: B + A, 0 <= A < image size.
  * RELR: RELATIVE with the implicit addend stored at the site.

The expected (module, where, kind, value) set is compared with the TSV the
reference linker produced for the same variant, and the link digest is
recomputed from scratch (flats + expected values) and compared with the
reference counters JSON.

Usage:
  g3_link_check.py --dir <g3 build dir> --config <link_config.json>
                   [--variants v0 relr gnuonly]
"""

import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys

ABS64 = 257
GLOB_DAT = 1025
JUMP_SLOT = 1026
RELATIVE = 1027

KIND_NAMES = {ABS64: "ABS64", GLOB_DAT: "GLOB_DAT",
              JUMP_SLOT: "JUMP_SLOT", RELATIVE: "RELATIVE"}
KIND_BY_NAME = {v: k for k, v in KIND_NAMES.items()}


class CheckError(Exception):
    pass


def need(cond, msg):
    if not cond:
        raise CheckError(msg)


def run(args):
    proc = subprocess.run(args, capture_output=True, text=True)
    need(proc.returncode == 0,
         "%s failed (%d): %s" % (" ".join(args), proc.returncode,
                                 proc.stderr.strip()))
    return proc.stdout


def parse_program_headers(text, path):
    loads = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 7 and parts[0] == "LOAD":
            loads.append(dict(offset=int(parts[1], 16),
                              vaddr=int(parts[2], 16),
                              filesz=int(parts[4], 16),
                              memsz=int(parts[5], 16)))
    loads.sort(key=lambda p: p["vaddr"])
    need(len(loads) == 3, "%s: expected 3 PT_LOAD, got %d"
         % (path, len(loads)))
    need(loads[0]["vaddr"] == 0, "%s: first PT_LOAD not at vaddr 0" % path)
    return loads


PAGE = 0x1000


def rebuild_flat(elf_path, loads):
    """Rebuild the NSO-shaped flat image from the ELF PT_LOADs (review fix 7).

    Independent of tools/aot/aot_module.py elf2flat: it walks the program
    headers llvm-readelf printed, copies each LOAD's file-backed bytes to its
    vaddr, and leaves bss out. The result is compared byte-for-byte with the
    .flat the fixture build produced."""
    with open(elf_path, "rb") as f:
        data = f.read()
    flat_size = loads[2]["vaddr"] + loads[2]["filesz"]
    flat = bytearray(flat_size)
    prev_end = None
    for p in loads:
        need(p["vaddr"] % PAGE == 0,
             "%s: PT_LOAD vaddr 0x%x is not page aligned" % (elf_path,
                                                             p["vaddr"]))
        need(p["filesz"] <= p["memsz"],
             "%s: PT_LOAD 0x%x has filesz > memsz" % (elf_path, p["vaddr"]))
        need(p["offset"] + p["filesz"] <= len(data),
             "%s: PT_LOAD 0x%x runs past the end of the file"
             % (elf_path, p["vaddr"]))
        if prev_end is not None:
            need(p["vaddr"] >= prev_end,
                 "%s: PT_LOAD 0x%x overlaps the previous segment"
                 % (elf_path, p["vaddr"]))
        prev_end = p["vaddr"] + p["memsz"]
        flat[p["vaddr"]:p["vaddr"] + p["filesz"]] = \
            data[p["offset"]:p["offset"] + p["filesz"]]
    return flat


def check_layout(g3dir, base_name, loads, flat, dynsym_count):
    """Recompute the layout + digest independently and compare with the
    layout.json that elf2flat wrote (review fix 7). No golden values are pinned:
    a different LLVM version may change the bytes, and both sides are derived
    from the same ELF, so the check stays meaningful without being brittle."""
    text, ro, data = loads
    image_size = data["vaddr"] + data["memsz"]
    want = dict(
        name=base_name,
        text=[0, text["filesz"]],
        ro=[ro["vaddr"], ro["filesz"]],
        data=[data["vaddr"], data["filesz"]],
        bss_size=data["memsz"] - data["filesz"],
        image_size=image_size,
        dynsym_count=dynsym_count,
        sha256=hashlib.sha256(bytes(flat)).hexdigest(),
    )
    layout_path = os.path.join(g3dir, base_name + ".layout.json")
    need(os.path.exists(layout_path), "missing layout %s" % layout_path)
    layout = json.load(open(layout_path, encoding="utf-8"))
    for key, value in want.items():
        need(layout.get(key) == value,
             "%s: layout.%s is %r, independently recomputed %r"
             % (base_name, key, layout.get(key), value))
    flat_path = os.path.join(g3dir, base_name + ".flat")
    need(os.path.exists(flat_path), "missing flat %s" % flat_path)
    with open(flat_path, "rb") as f:
        disk = f.read()
    need(disk == bytes(flat),
         "%s: %s (%d bytes) is not the PT_LOAD rebuild (%d bytes)"
         % (base_name, flat_path, len(disk), len(flat)))
    return layout


def parse_dynsyms(text, path, image_size):
    """Parse `readelf --dyn-syms` independently of the reference linker.

    Review fix 4: fail closed on TLS symbols, reserved section indices
    (SHN_ABS/SHN_COMMON/SHN_LORESERVE..) and DEFINED values past the image end;
    value == image_size is VALID (the real modules' `end` symbol).
    Review fix 8: the FIRST DEFINED symbol with a name wins, so an earlier
    undefined duplicate cannot shadow a later definition."""
    out = {}
    by_index = {}
    count = 0
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 7 or not parts[0].endswith(":"):
            continue
        try:
            value = int(parts[1], 16)
            index = int(parts[0][:-1])
        except ValueError:
            continue
        stype = parts[3]
        bind = parts[4]
        shndx = parts[6]
        name = " ".join(parts[7:])
        count += 1   # every printed entry counts, including the empty one
        if not name:
            continue
        if stype == "TLS":
            raise CheckError("%s: %r is STT_TLS (no TLS model)" % (path, name))
        if shndx in ("ABS", "COM", "LOPROC", "HIPROC"):
            raise CheckError("%s: %r uses reserved st_shndx %s"
                             % (path, name, shndx))
        defined = shndx != "UND"
        if defined:
            try:
                sect = int(shndx)
            except ValueError:
                raise CheckError("%s: %r has an unparsable st_shndx %r"
                                 % (path, name, shndx))
            if sect >= 0xff00:
                raise CheckError("%s: %r uses reserved st_shndx %d"
                                 % (path, name, sect))
            if value > image_size:
                raise CheckError("%s: %r value 0x%x is past the image end 0x%x"
                                 % (path, name, value, image_size))
        sym = dict(value=value, shndx=shndx, bind=bind, type=stype,
                   defined=defined, index=index, name=name)
        need(index not in by_index, "%s: dynsym index %d printed twice"
             % (path, index))
        by_index[index] = sym
        have = out.get(name)
        if have is None or (not have["defined"] and defined):
            out[name] = sym
    return out, count, by_index


def split_name_addend(rest):
    if " + " in rest:
        name, addend = rest.rsplit(" + ", 1)
        return name.strip(), int(addend, 16)
    return rest.strip(), 0


def parse_reloc_sections(text, path):
    """Return (rela_entries, relr_addrs) from llvm-readelf --relocs -W."""
    rela = []
    relr = []
    section = None
    for line in text.splitlines():
        if line.startswith("Relocation section"):
            section = line.split("'")[1] if "'" in line else ""
            continue
        if section is None or not line.strip():
            continue
        parts = line.split()
        if section == ".relr.dyn":
            # Format A (this LLVM): "Index: Entry Address Symbolic Address"
            # rows: "0000:  <raw> <decoded>  <name>" / continuation
            # Format B (some LLVM): real R_AARCH64_RELATIVE rows.
            if len(parts) >= 3 and parts[1].startswith("R_AARCH64_"):
                need(parts[1] == "R_AARCH64_RELATIVE",
                     "%s: unexpected %s in .relr.dyn" % (path, parts[1]))
                rela.append(dict(where=int(parts[0], 16), kind=RELATIVE,
                                 name=None, addend=None, table=".relr.dyn"))
                continue
            if parts[0].startswith("Index:") or parts[0] == "Entry":
                continue
            if parts[0].endswith(":"):
                need(len(parts) >= 3, "%s: bad RELR row %r" % (path, line))
                relr.append(int(parts[2], 16))
            elif len(parts) >= 2:
                relr.append(int(parts[0], 16))
            continue
        if parts[0].startswith("Offset") or parts[0] == "Index:":
            continue
        if len(parts) < 3 or not parts[2].startswith("R_AARCH64_"):
            continue
        where = int(parts[0], 16)
        kind = KIND_BY_NAME.get(parts[2].replace("R_AARCH64_", ""))
        need(kind is not None, "%s: unexpected relocation %s"
             % (path, parts[2]))
        if kind == RELATIVE:
            need(len(parts) == 4, "%s: unexpected RELATIVE row %r"
                 % (path, line))
            rela.append(dict(where=where, kind=kind, name=None,
                             addend=int(parts[3], 16), table=section,
                             sym_index=None))
        else:
            name, addend = split_name_addend(" ".join(parts[4:]))
            need(name, "%s: relocation at 0x%x has no symbol name"
                 % (path, where))
            # The `Info` column carries the referencing .dynsym INDEX in its high
            # 32 bits. Attribution must use that index, not the name: a name can
            # appear twice in .dynsym (an UNDEFINED duplicate before the
            # definition), and the reference linker counts `cross` from the
            # REFERENCING entry's st_shndx.
            try:
                info = int(parts[1], 16)
            except ValueError:
                raise CheckError("%s: relocation at 0x%x has no parsable Info "
                                 "column (%r); cannot attribute it to a dynsym "
                                 "entry" % (path, where, parts[1]))
            rela.append(dict(where=where, kind=kind, name=name,
                             addend=addend, table=section,
                             sym_index=info >> 32))
    need(not (rela and any(e["table"] == ".relr.dyn" for e in rela)) or
         not relr, "%s: RELR reported twice" % path)
    return rela, relr


def thunk_va(cfg, index):
    return int(cfg["thunk_base"], 0) + 16 * index


def resolve(cfg, mod, name, kind, mods, syms):
    if kind == JUMP_SLOT and name in cfg.get("observers", {}):
        return thunk_va(cfg, cfg["observers"][name]), "observer"
    if name in cfg.get("overrides", {}):
        return thunk_va(cfg, cfg["overrides"][name]), "override"
    # `parse_dynsyms` already applied review fix 8 (first DEFINED wins) and
    # review fix 4 (no TLS/reserved/out-of-image definitions), so a DEFINED
    # entry here is a valid definition and value == image_size is accepted.
    own = syms[mod].get(name)
    if own is not None and own["defined"]:
        return mods[mod]["base"] + own["value"], "own"
    for other in mods:   # insertion order == configured module order
        sym = syms[other].get(name)
        if sym is not None and sym["defined"]:
            return mods[other]["base"] + sym["value"], "global"
    if own is not None and own["bind"] == "WEAK":
        return 0, "weak"
    raise CheckError("%s: unresolved strong import %r" % (mod, name))


def check_variant(cfg, g3dir, variant, readelf,
                  tsv_name="fx_{variant}.sites.tsv"):
    mods = {}
    syms = {}
    syms_by_index = {}
    flats = {}
    for spec in cfg["modules"]:
        base_name = "%s_%s" % (spec["name"], variant)
        short = spec["name"][3:] if spec["name"].startswith("fx_")             else spec["name"]
        elf = os.path.join(g3dir, "libfx_%s_%s.so" % (short, variant))
        need(os.path.exists(elf), "missing fixture ELF %s" % elf)
        ph = run([readelf, "--program-headers", "-W", elf])
        loads = parse_program_headers(ph, elf)
        mods[base_name] = dict(
            base=int(spec["guest_base"], 0), loads=loads,
            image_size=loads[2]["vaddr"] + loads[2]["memsz"])
        syms[base_name], dynsym_count, by_index = parse_dynsyms(
            run([readelf, "--dyn-syms", "-W", elf]), elf,
            mods[base_name]["image_size"])
        syms_by_index[base_name] = by_index
        # Review fix 7: rebuild the flat from the PT_LOADs and recompute the
        # layout/digest, instead of trusting elf2flat's output.
        rebuilt = rebuild_flat(elf, loads)
        check_layout(g3dir, base_name, loads, rebuilt, dynsym_count)
        flats[base_name] = rebuilt
        rela, relr = parse_reloc_sections(
            run([readelf, "--relocs", "-W", elf]), elf)
        mods[base_name]["rela"] = rela
        mods[base_name]["relr"] = relr

    expected = {}   # (module, where) -> (kind, value)
    counters = {name: dict(relative=0, symbolic=0, cross=0, weak=0)
                for name in mods}
    for name, mod in mods.items():
        data_lo, data_hi = mod["loads"][2]["vaddr"], \
            mod["loads"][2]["vaddr"] + mod["loads"][2]["filesz"]

        def ref_of(entry):
            """The .dynsym entry the relocation REFERENCES (by index, not name).
            Attribution is exact because the Info column carries the index; fail
            closed when it cannot be resolved or disagrees with the printed
            name."""
            if entry["sym_index"] is None:
                return None
            ref = syms_by_index[name].get(entry["sym_index"])
            need(ref is not None,
                 "%s: relocation at 0x%x references dynsym[%d], which is not in "
                 "the parsed symbol table"
                 % (name, entry["where"], entry["sym_index"]))
            need(ref["name"] == entry["name"],
                 "%s: relocation at 0x%x names %r but dynsym[%d] is %r"
                 % (name, entry["where"], entry["name"], entry["sym_index"],
                    ref["name"]))
            return ref

        def put(where, kind, value, how, s_value=None, ref=None):
            need(data_lo <= where <= data_hi - 8,
                 "%s: site 0x%x outside data segment" % (name, where))
            need((name, where) not in expected,
                 "%s: site 0x%x reported twice" % (name, where))
            expected[(name, where)] = (kind, value)
            if kind == RELATIVE:
                counters[name]["relative"] += 1
            else:
                counters[name]["symbolic"] += 1
            # Review fix 16: `cross` counts every relocation whose SYMBOL IS
            # UNDEFINED in the referencing module and whose resolved value S is
            # non-zero. It is decided from the REFERENCING .dynsym entry, not
            # from how the value was found: with a duplicate name (an UNDEFINED
            # entry earlier than the definition) a name-based rule would call the
            # site "own" and lose the cross count that the reference linker
            # reports. Only RELATIVE/RELR sites have no symbol.
            if ref is not None:
                cross = (not ref["defined"]) and s_value != 0
            else:
                cross = how in ("global", "override", "observer")
            if cross:
                counters[name]["cross"] += 1
            elif how == "weak":
                counters[name]["weak"] += 1

        for where in mod["relr"]:
            need(where + 8 <= len(flats[name]),
                 "%s: RELR site 0x%x outside flat" % (name, where))
            addend = struct.unpack_from("<Q", flats[name], where)[0]
            need(0 <= addend < mod["image_size"],
                 "%s: RELR addend 0x%x out of image" % (name, addend))
            put(where, RELATIVE, mod["base"] + addend, None)

        for entry in mod["rela"]:
            kind = entry["kind"]
            if kind == RELATIVE:
                addend = entry["addend"]
                need(0 <= addend < mod["image_size"],
                     "%s: RELATIVE addend 0x%x out of image"
                     % (name, addend))
                put(entry["where"], kind, mod["base"] + addend, None)
            elif kind == JUMP_SLOT:
                need(entry["addend"] == 0,
                     "%s: JUMP_SLOT %r addend %d != 0"
                     % (name, entry["name"], entry["addend"]))
                ref = ref_of(entry)
                value, how = resolve(cfg, name, entry["name"], kind, mods, syms)
                put(entry["where"], kind, value, how, value, ref)
            else:
                ref = ref_of(entry)
                value, how = resolve(cfg, name, entry["name"], kind, mods, syms)
                put(entry["where"], kind, value + entry["addend"], how, value, ref)

    # ---- compare with the reference linker TSV ------------------------
    tsv_path = os.path.join(g3dir, tsv_name.format(variant=variant))
    need(os.path.exists(tsv_path), "missing reference TSV %s" % tsv_path)
    lines = open(tsv_path, encoding="utf-8").read().splitlines()
    need(lines and lines[0].split("\t") ==
         ["module", "where", "kind", "symbol", "value"],
         "%s: bad header" % tsv_path)
    got = {}
    for line in lines[1:]:
        cols = line.split("\t")
        need(len(cols) == 5, "%s: bad row %r" % (tsv_path, line))
        got[(cols[0], int(cols[1], 16))] = (int(cols[2]), int(cols[4], 16))
    if set(got) != set(expected):
        missing = sorted(set(expected) - set(got))[:5]
        extra = sorted(set(got) - set(expected))[:5]
        raise CheckError("%s: site set mismatch (missing=%r extra=%r)"
                         % (variant, missing, extra))
    bad = [(k, expected[k], got[k]) for k in expected if expected[k] != got[k]]
    if bad:
        raise CheckError("%s: %d site mismatches, first: %r"
                         % (variant, len(bad), bad[0]))

    # ---- independent link digest --------------------------------------
    digest = hashlib.sha256()
    for spec in cfg["modules"]:
        name = "%s_%s" % (spec["name"], variant)
        data = mods[name]["loads"][2]
        image = bytearray(flats[name])
        for (mname, where), (kind, value) in expected.items():
            if mname == name:
                struct.pack_into("<Q", image, where, value)
        digest.update(bytes(image[data["vaddr"]:
                                  data["vaddr"] + data["filesz"]]))
    digest_hex = digest.hexdigest()

    counters_path = os.path.join(g3dir, "fx_%s.counters.json" % variant)
    ref = json.load(open(counters_path, encoding="utf-8"))
    if ref["link_digest"] != digest_hex:
        raise CheckError("%s: link digest mismatch: reference %s, "
                         "independent %s" % (variant, ref["link_digest"],
                                             digest_hex))
    for name, counted in counters.items():
        if ref["counters"].get(name) != counted:
            raise CheckError("%s: counters mismatch for %s: reference %r, "
                             "independent %r"
                             % (variant, name, ref["counters"].get(name),
                                counted))
    return len(expected), counters, digest_hex


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dir", required=True, help="directory with fixture output")
    ap.add_argument("--config", required=True)
    ap.add_argument("--variants", nargs="+",
                    default=["v0", "relr", "gnuonly", "shadow"])
    ap.add_argument("--readelf", default="llvm-readelf")
    # Which site table to validate. The default is the reference linker's own
    # TSV; the C loader probe's dump can be substituted so the SAME independent
    # checker judges both (tools/aot/g3_link_test.py does exactly that).
    ap.add_argument("--tsv", default="fx_{variant}.sites.tsv")
    args = ap.parse_args(argv)
    try:
        cfg = json.load(open(args.config, encoding="utf-8"))
        for variant in args.variants:
            count, counters, digest = check_variant(
                cfg, args.dir, variant, args.readelf, args.tsv)
            total = {k: sum(c[k] for c in counters.values()) for k in
                     ("relative", "symbolic", "cross", "weak")}
            print("%s: OK %d sites relative=%d symbolic=%d cross=%d weak=%d "
                  "digest=%s"
                  % (variant, count, total["relative"], total["symbolic"],
                     total["cross"], total["weak"], digest[:16]))
    except CheckError as exc:
        print("g3_link_check.py: %s" % exc, file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, struct.error,
            json.JSONDecodeError) as exc:
        # Review fix 15: malformed input is a typed error, never a traceback.
        print("g3_link_check.py: %s: %s" % (type(exc).__name__, exc),
              file=sys.stderr)
        return 1
    print("g3_link_check: all variants agree with the reference linker")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
