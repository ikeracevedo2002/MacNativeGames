#!/usr/bin/env python3
"""G3 AOT module tooling: NSO-like flat images from fixture/shared ELFs.

This file deliberately contains its own minimal ELF64 reader (no pyelftools
dependency). It is the OFFLINE half of the module loader work: the C loader in
src/aot/aot_loader.c never parses ELF, it consumes the flat images and the
descriptors produced here.

Subcommands:
  elf2flat   ELF (3 PT_LOAD, text at vaddr 0) -> <name>.flat + <name>.layout.json
  nso2flat   (increment 4) real NSO0 -> <name>.flat + <name>.layout.json, with the
             NSO SHA-256 checked against games/totk/assets/expected-v1.0.0.json,
             every segment LZ4-decompressed and re-hashed, bss/image_size from
             MOD0 and dynsym_count from the NSO header's dynsym extent

The flat image is the NSO byte image: a memory image of every file-backed byte
of the three loadable segments, with bss excluded. The crt0 header
(word0 = entry branch, word1 = MOD0 offset) is the first 8 bytes, and the MOD0
struct carries the dynamic/bss offsets -- exactly the shape the Mac reference
loader (games/totk/runtime/loader.c) and prepare_runtime.py expect.

Every conversion re-verifies the MOD0 round-trip so a broken fixture or a
broken linker script fails loudly at build time instead of at load time.
"""

import argparse
import hashlib
import json
import os
import struct
import sys

PAGE = 0x1000

PT_LOAD = 1
PT_DYNAMIC = 2
SHT_DYNSYM = 11
EM_AARCH64 = 183
ET_DYN = 3

# d_tag values we care about while validating the flat image.
DT_NAMES = {
    0: "NULL", 1: "NEEDED", 2: "PLTRELSZ", 3: "PLTGOT", 4: "HASH",
    5: "STRTAB", 6: "SYMTAB", 7: "RELA", 8: "RELASZ", 9: "RELAENT",
    10: "STRSZ", 11: "SYMENT", 12: "INIT", 13: "FINI", 14: "SONAME",
    16: "SYMBOLIC", 17: "REL", 18: "RELSZ", 19: "RELENT", 20: "PLTREL",
    21: "DEBUG", 22: "TEXTREL", 23: "JMPREL", 24: "BIND_NOW",
    25: "INIT_ARRAY", 27: "INIT_ARRAYSZ", 26: "FINI_ARRAY",
    28: "FINI_ARRAYSZ", 30: "FLAGS", 32: "PREINIT_ARRAY",
    33: "PREINIT_ARRAYSZ", 0x6FFFFFF9: "RELACOUNT", 0x6FFFFFFA: "RELCOUNT",
    0x6FFFFFFB: "FLAGS_1", 0x6FFFFFFE: "VERNEED", 0x6FFFFFFF: "VERNEEDNUM",
    0x6FFFFFF0: "VERSYM", 0x6FFFFEF5: "GNU_HASH", 0x6FFFFFFC: "VERDEF",
    0x6FFFFFFD: "VERDEFNUM", 35: "RELRSZ", 36: "RELR", 37: "RELRENT",
    34: "SYMTAB_SHNDX",
}


class ElfError(Exception):
    pass


def need(cond, msg):
    if not cond:
        raise ElfError(msg)


def read_file(path):
    with open(path, "rb") as f:
        return f.read()


class Elf64:
    """Minimal, strict ELF64 little-endian reader (headers + sections only)."""

    def __init__(self, data, path="<mem>"):
        self.data = data
        self.path = path
        need(len(data) >= 64, "file shorter than an ELF64 header")
        need(data[0:4] == b"\x7fELF", "not an ELF file")
        need(data[4] == 2, "not ELFCLASS64")
        need(data[5] == 1, "not little-endian")
        (e_type, e_machine) = struct.unpack_from("<HH", data, 16)
        need(e_type == ET_DYN, "not ET_DYN (shared object): got %d" % e_type)
        need(e_machine == EM_AARCH64, "not EM_AARCH64: got %d" % e_machine)
        (e_phoff, e_shoff) = struct.unpack_from("<QQ", data, 32)
        (e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = \
            struct.unpack_from("<HHHHH", data, 54)
        need(e_phentsize == 56, "unexpected e_phentsize %d" % e_phentsize)
        need(e_shentsize == 64, "unexpected e_shentsize %d" % e_shentsize)
        self.phdrs = []
        for i in range(e_phnum):
            off = e_phoff + i * 56
            need(off + 56 <= len(data), "program header %d out of file" % i)
            (p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz,
             p_align) = struct.unpack_from("<IIQQQQQQ", data, off)
            self.phdrs.append(dict(type=p_type, flags=p_flags, offset=p_offset,
                                   vaddr=p_vaddr, paddr=p_paddr,
                                   filesz=p_filesz, memsz=p_memsz,
                                   align=p_align))
        self.sections = []
        self.shstrtab = b""
        if e_shnum:
            for i in range(e_shnum):
                off = e_shoff + i * 64
                need(off + 64 <= len(data), "section header %d out of file" % i)
                (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
                 sh_link, sh_info, sh_addralign, sh_entsize) = \
                    struct.unpack_from("<IIQQQQIIQQ", data, off)
                self.sections.append(dict(
                    name_off=sh_name, type=sh_type, flags=sh_flags,
                    addr=sh_addr, offset=sh_offset, size=sh_size,
                    link=sh_link, info=sh_info, align=sh_addralign,
                    entsize=sh_entsize))
            if 0 <= e_shstrndx < len(self.sections):
                sh = self.sections[e_shstrndx]
                self.shstrtab = data[sh["offset"]:sh["offset"] + sh["size"]]
            for s in self.sections:
                n = s["name_off"]
                end = self.shstrtab.find(b"\x00", n)
                s["name"] = self.shstrtab[n:end if end >= 0 else None].decode(
                    "utf-8", "replace")

    def section(self, name):
        for s in self.sections:
            if s.get("name") == name:
                return s
        return None

    def section_bytes(self, s):
        need(s["type"] != 8, "section %s is NOBITS" % s["name"])
        need(s["offset"] + s["size"] <= len(self.data), "section out of file")
        return self.data[s["offset"]:s["offset"] + s["size"]]

    def loads(self):
        return [p for p in self.phdrs if p["type"] == PT_LOAD]

    def dynamic(self):
        return [p for p in self.phdrs if p["type"] == PT_DYNAMIC]


def parse_dynamic(flat, off, end):
    """Return [(tag, value)] for the DT_ array at flat[off:end]."""
    out = []
    while off + 16 <= end:
        tag, val = struct.unpack_from("<QQ", flat, off)
        out.append((tag, val))
        off += 16
        if tag == 0:
            break
    return out


def dt_lookup(dyn, tag):
    for t, v in dyn:
        if t == tag:
            return v
    return None


def elf2flat(elf_path, name, out_dir, verbose=False):
    data = read_file(elf_path)
    elf = Elf64(data, elf_path)

    loads = sorted(elf.loads(), key=lambda p: p["vaddr"])
    need(len(loads) == 3,
         "%s: expected exactly 3 PT_LOAD segments, found %d"
         % (elf_path, len(loads)))
    text, ro, data_seg = loads

    # Segment shape: text at vaddr 0 (R-X), then R, then RW; each page aligned.
    need(text["vaddr"] == 0, "text PT_LOAD must start at vaddr 0 (got 0x%x)"
         % text["vaddr"])
    need(text["flags"] == 5, "text PT_LOAD must be R-X (flags 5), got %d"
         % text["flags"])
    need(ro["flags"] == 4, "second PT_LOAD must be R (flags 4), got %d"
         % ro["flags"])
    need(data_seg["flags"] == 6, "third PT_LOAD must be RW (flags 6), got %d"
         % data_seg["flags"])
    prev_end = None
    for p in loads:
        need(p["vaddr"] % PAGE == 0,
             "PT_LOAD vaddr 0x%x is not %d-byte aligned" % (p["vaddr"], PAGE))
        need(p["filesz"] <= p["memsz"],
             "PT_LOAD at 0x%x has filesz > memsz" % p["vaddr"])
        need(p["offset"] + p["filesz"] <= len(data),
             "PT_LOAD at 0x%x runs past end of file" % p["vaddr"])
        if prev_end is not None:
            need(p["vaddr"] > prev_end,
                 "PT_LOAD at 0x%x overlaps the previous segment" % p["vaddr"])
        prev_end = p["vaddr"] + p["memsz"]

    dyns = elf.dynamic()
    need(len(dyns) == 1, "expected exactly 1 PT_DYNAMIC, found %d" % len(dyns))
    dyn_ph = dyns[0]
    need(data_seg["vaddr"] <= dyn_ph["vaddr"] <
         data_seg["vaddr"] + data_seg["memsz"],
         "PT_DYNAMIC is not inside the RW segment")
    dyn_sec = elf.section(".dynamic")
    need(dyn_sec is not None, "no .dynamic section")
    need(dyn_sec["addr"] == dyn_ph["vaddr"],
         "PT_DYNAMIC vaddr 0x%x != .dynamic addr 0x%x"
         % (dyn_ph["vaddr"], dyn_sec["addr"]))
    need(dyn_sec["addr"] == data_seg["vaddr"],
         ".dynamic must be the FIRST thing in the RW segment "
         "(.dynamic 0x%x, RW segment 0x%x)" % (dyn_sec["addr"],
                                               data_seg["vaddr"]))

    # Flat image = file-backed bytes of the three segments (bss excluded).
    flat_size = data_seg["vaddr"] + data_seg["filesz"]
    flat = bytearray(flat_size)
    for p in loads:
        chunk = data[p["offset"]:p["offset"] + p["filesz"]]
        flat[p["vaddr"]:p["vaddr"] + p["filesz"]] = chunk

    # ---- crt0 header + MOD0 round-trip -------------------------------
    word0 = struct.unpack_from("<I", flat, 0)[0]
    need(word0 == 0 or (word0 >> 26) == 0x05,
         "crt0 word0 0x%08x is neither 0 nor a B/BL branch" % word0)
    mod0_off = struct.unpack_from("<I", flat, 4)[0]
    need(mod0_off % 4 == 0 and mod0_off + 32 <= len(flat),
         "MOD0 offset 0x%x out of range" % mod0_off)
    need(bytes(flat[mod0_off:mod0_off + 4]) == b"MOD0",
         "word at +4 (0x%x) does not point at a MOD0 magic" % mod0_off)
    (dyn_rel, bss_start_rel, bss_end_rel, eh_start, eh_end,
     module_object) = struct.unpack_from("<iiiiii", flat, mod0_off + 4)
    need(dyn_rel >= 0, "MOD0 dynamic_off is negative")
    need(mod0_off + dyn_rel == dyn_ph["vaddr"],
         "MOD0 dynamic_off -> 0x%x, PT_DYNAMIC is at 0x%x"
         % (mod0_off + dyn_rel, dyn_ph["vaddr"]))
    dyn = parse_dynamic(flat, mod0_off + dyn_rel,
                        mod0_off + dyn_rel + dyn_ph["filesz"])
    need(len(dyn) >= 2 and dyn[0][0] != 0, "empty/malformed .dynamic")
    need(dt_lookup(dyn, 6) is not None, "DT_SYMTAB missing")
    need(dt_lookup(dyn, 5) is not None, "DT_STRTAB missing")

    bss_start = mod0_off + bss_start_rel
    bss_end = mod0_off + bss_end_rel
    data_end_off = data_seg["vaddr"] + data_seg["filesz"]
    need(bss_start == data_end_off,
         "MOD0 bss_start 0x%x != end of file-backed data 0x%x"
         % (bss_start, data_end_off))
    need(bss_end == data_seg["vaddr"] + data_seg["memsz"],
         "MOD0 bss_end 0x%x != RW segment end 0x%x"
         % (bss_end, data_seg["vaddr"] + data_seg["memsz"]))
    for label, v in (("eh_frame_hdr_start", eh_start),
                     ("eh_frame_hdr_end", eh_end),
                     ("module_object_off", module_object)):
        if v:
            pos = mod0_off + v
            need(0 <= pos <= flat_size,
                 "MOD0 %s 0x%x out of image" % (label, v))

    # ---- dynsym count / hash tables ----------------------------------
    dynsym_sec = elf.section(".dynsym")
    need(dynsym_sec is not None, "no .dynsym section")
    need(dynsym_sec["entsize"] == 24,
         ".dynsym entsize %d != 24" % dynsym_sec["entsize"])
    need(dynsym_sec["size"] % 24 == 0, ".dynsym size not a multiple of 24")
    dynsym_count = dynsym_sec["size"] // 24
    dynsym_addr = dt_lookup(dyn, 6)
    need(dynsym_addr == dynsym_sec["addr"],
         "DT_SYMTAB 0x%x != .dynsym addr 0x%x" % (dynsym_addr,
                                                 dynsym_sec["addr"]))
    need(dynsym_sec["addr"] + dynsym_sec["size"] <= flat_size,
         ".dynsym is not inside the flat image (dynamic tables must be in a "
         "file-backed segment)")

    hash_addr = dt_lookup(dyn, 4)      # DT_HASH
    gnu_hash_addr = dt_lookup(dyn, 0x6FFFFEF5)
    if hash_addr is not None:
        need(hash_addr + 8 <= flat_size, "DT_HASH outside the image")
        nbucket, nchain = struct.unpack_from("<II", flat, hash_addr)
        need(nchain == dynsym_count,
             "DT_HASH nchain %d != .dynsym count %d" % (nchain, dynsym_count))
    need(hash_addr is not None or gnu_hash_addr is not None,
         "module has neither DT_HASH nor DT_GNU_HASH")

    relr_info = None
    relr_addr = dt_lookup(dyn, 36)     # DT_RELR
    relr_sz = dt_lookup(dyn, 35)       # DT_RELSZ... note: DT_RELRSZ = 35
    if relr_addr is not None:
        relr_info = dict(addr=relr_addr, size=relr_sz or 0)

    layout = {
        "name": name,
        "text": [0, text["filesz"]],        "ro": [ro["vaddr"], ro["filesz"]],
        "data": [data_seg["vaddr"], data_seg["filesz"]],
        "bss_size": data_seg["vaddr"] + data_seg["memsz"] - flat_size,
        "dynsym_count": dynsym_count,
        "mod0_off": mod0_off,
        "dynamic_off": mod0_off + dyn_rel,
        "dynamic_size": dyn_ph["filesz"],
        # Increment 4 decision: image_size is the MOD0 bss_end rounded up to a
        # page (real modules) or exactly bss_end (fixtures, which predate the
        # rule); the loader accepts both and maps page_up(image_size) either
        # way.
        "image_size": data_seg["vaddr"] + data_seg["memsz"],
        "init_array": [dt_lookup(dyn, 25) or 0, dt_lookup(dyn, 27) or 0],
        "fini_array": [dt_lookup(dyn, 26) or 0, dt_lookup(dyn, 28) or 0],
        "dt_tags": sorted({DT_NAMES.get(t, "0x%x" % t) for t, _ in dyn}),
        "sha256": hashlib.sha256(bytes(flat)).hexdigest(),
    }
    if relr_info is not None:
        layout["relr"] = relr_info

    os.makedirs(out_dir, exist_ok=True)
    flat_path = os.path.join(out_dir, name + ".flat")
    with open(flat_path, "wb") as f:
        f.write(flat)
    layout_path = os.path.join(out_dir, name + ".layout.json")
    with open(layout_path, "w", encoding="utf-8") as f:
        json.dump(layout, f, indent=2, sort_keys=True)
        f.write("\n")

    if verbose:
        print("%s: flat=%s size=%d" % (name, flat_path, flat_size))
    print("%s text=[0,0x%x] ro=[0x%x,0x%x] data=[0x%x,0x%x] bss=0x%x "
          "dynsym=%d sha256=%s"
          % (name, text["filesz"], ro["vaddr"], ro["filesz"],
             data_seg["vaddr"], data_seg["filesz"], layout["bss_size"],
             dynsym_count, layout["sha256"][:16]))
    return layout


def shadow_undefined(elf_path, undef_name, target_name, verbose=False):
    """TEST-FIXTURE MUTATION (link-only): give a module an UNDEFINED STB_WEAK
    dynamic symbol whose name equals an existing DEFINED symbol's name, with a
    SMALLER dynsym index.

    It renames `undef_name` (an UNDEFINED symbol) in place inside the ELF's
    .dynstr and forces its binding to STB_WEAK; the DEFINED symbol
    `target_name` keeps its index and value. Only used to build the `shadow`
    link variant, which pins the Mac rule "the first DEFINED symbol with a name
    wins - an earlier UNDEFINED duplicate must not shadow a later definition"
    (negative control MN_AOT_MUTANT_SYMBOL_FIRST_ANY).

    The new name MUST fit the old name's .dynstr slot: every other string offset
    in the table then stays valid, so elf2flat's flat agrees byte for byte with
    the ELF and llvm-readelf (g3_link_check) sees exactly what the loader sees.
    """
    data = bytearray(read_file(elf_path))
    elf = Elf64(bytes(data), elf_path)
    dynsym = elf.section(".dynsym")
    dynstr = elf.section(".dynstr")
    need(dynsym is not None, "%s: no .dynsym" % elf_path)
    need(dynstr is not None, "%s: no .dynstr" % elf_path)
    count = dynsym["size"] // 24
    undef = None
    target = None
    for i in range(count):
        off = dynsym["offset"] + i * 24
        (st_name, st_info, _other, st_shndx, st_value,
         _st_size) = struct.unpack_from("<IBBHQQ", data, off)
        name_off = dynstr["offset"] + st_name
        end = data.index(b"\0", name_off)
        name = bytes(data[name_off:end]).decode("utf-8", "replace")
        if name == undef_name and st_shndx == 0:
            if undef is not None:
                raise ElfError("duplicate UNDEFINED %r" % undef_name)
            undef = (i, off, name_off, end, st_info)
        if name == target_name and st_shndx != 0:
            if target is not None:
                raise ElfError("duplicate DEFINED %r" % target_name)
            target = (i, st_value, st_shndx)
    need(undef is not None, "%s: no UNDEFINED dynamic symbol %r"
         % (elf_path, undef_name))
    need(target is not None, "%s: no DEFINED dynamic symbol %r"
         % (elf_path, target_name))
    need(undef[0] < target[0],
         "%s: the shadow entry (index %d) must come BEFORE the definition "
         "(index %d)" % (elf_path, undef[0], target[0]))
    slot = undef[3] - undef[2]          # old name length, excluding the NUL
    need(len(target_name) <= slot,
         "%s: %r (len %d) does not fit the %r slot (len %d) - every other "
         "dynstr offset would have to move"
         % (elf_path, target_name, len(target_name), undef_name, slot))
    # Write the new name PLUS its NUL over the OLD name plus its NUL: the
    # replaced range must keep the exact same length, or every byte after the
    # .dynstr slot (including the section header table) would move.
    data[undef[2]:undef[3] + 1] = (target_name.encode() +
                                   b"\0" * (slot + 1 - len(target_name)))
    data[undef[1] + 4] = (STB_WEAK << 4) | (undef[4] & 0xF)
    # Verify by re-reading through the same parser the flat will be built from.
    check = Elf64(bytes(data), elf_path)
    sec = check.section(".dynsym")
    strsec = check.section(".dynstr")
    got = []
    for i in range(sec["size"] // 24):
        off = sec["offset"] + i * 24
        st_name, st_info, _o, st_shndx, _v, _s = struct.unpack_from(
            "<IBBHQQ", data, off)
        name_off = strsec["offset"] + st_name
        end = data.index(b"\0", name_off)
        name = bytes(data[name_off:end]).decode("utf-8", "replace")
        if name == target_name:
            got.append((i, st_shndx, st_info >> 4))
    need(any(g[0] == undef[0] and g[1] == 0 and g[2] == STB_WEAK
             for g in got),
         "%s: the shadow entry did not become an UNDEFINED WEAK %r"
         % (elf_path, target_name))
    need(any(g[0] == target[0] and g[1] != 0 for g in got),
         "%s: the definition %r disappeared" % (elf_path, target_name))
    with open(elf_path, "wb") as f:
        f.write(bytes(data))
    if verbose:
        print("%s: shadow undefined %r (index %d) -> %r; definition at %d"
              % (elf_path, undef_name, undef[0], target_name, target[0]))
    print("shadow-undefined: %s undef[%d] %r -> %r (STB_WEAK, shndx 0), "
          "defined at [%d] value 0x%x"
          % (os.path.basename(elf_path), undef[0], undef_name, target_name,
             target[0], target[1]))
    return dict(undef_index=undef[0], target_index=target[0],
                target_value=target[1])


# ---------------------------------------------------------------------------
# Increment 4, work item B: real NSO0 -> flat image + layout.json.
#
# Header of the ExeFS NSO0s the game ships (little endian).  This is NOT the
# short 3x(file,mem,size) layout some references document: the repo's own
# reader for these exact files (games/totk/scripts/prepare_modules.py) uses
# this shape, and nso2flat re-verifies it against the real modules:
#
#   0x00  "NSO0"   0x04 version   0x08 reserved
#   0x0c  flags: bit i = segment i is LZ4-compressed, bit 3+i = segment i hash present
#   0x10 + 16*i  segment i:  file offset, memory offset, size (uncompressed), extra
#                 (extra is only used for data, where it is the bss size)
#   0x60 +  4*i  compressed size of segment i (when its flag bit is set)
#   0xa0 + 32*i  SHA-256 of the DECOMPRESSED segment i
#   0x90/0x94, 0x98/0x9c  two (offset,size) pairs relative to rodata; the
#                 .dynsym one is recognised by matching DT_SYMTAB (see below)
#
# The segment bodies are raw (frameless) LZ4 blocks.
#
# The flat image mirrors elf2flat: every file-backed byte of the three
# segments at its memory offset, with bss excluded.  The bss bounds come from
# MOD0 (as on the Mac), so image_size is page_up(bss_end) and len(flat) is the
# data segment's file end.
# ---------------------------------------------------------------------------

NSO_MAGIC = b"NSO0"
NSO_HEADER_SIZE = 0x100
NSO_FLAGS_OFF = 0x0C
NSO_SEG_OFF = 0x10
NSO_SEG_STRIDE = 16
NSO_COMP_OFF = 0x60
NSO_HASH_OFF = 0xA0
NSO_LABELS = ("text", "ro", "data")
DYN_SIZE = 24  # sizeof(Elf64_Sym)
# The two (offset,size) metadata pairs of the header, relative to rodata.
NSO_META_PAIRS = ((0x90, 0x94), (0x98, 0x9C))


def page_up(value, page=PAGE):
    return (value + page - 1) // page * page


def default_expected_path():
    root = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))
    return os.path.join(root, "games", "totk", "assets", "expected-v1.0.0.json")


def _repo_root():
    return os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))


def _check_outside_repo(path):
    root = os.path.realpath(_repo_root())
    target = os.path.realpath(os.path.abspath(path))
    need(not (target == root or target.startswith(root + os.sep)),
         "refusing to write real-module output inside the repository: %s"
         % path)


def lz4_decompress_block(blob, size, what):
    try:
        import lz4.block as lz4block
    except ImportError as exc:  # pragma: no cover - environment problem
        raise ElfError("python lz4 module is required for nso2flat (%s)" % exc)
    out = lz4block.decompress(bytes(blob), uncompressed_size=size)
    need(len(out) == size, "%s: LZ4 produced %d bytes, header says %d"
         % (what, len(out), size))
    return out


def parse_nso_header(data, path):
    need(len(data) >= NSO_HEADER_SIZE, "%s: shorter than an NSO0 header" % path)
    need(data[0:4] == NSO_MAGIC,
         "%s: not an NSO0 image (magic %r)" % (path, bytes(data[0:4])))
    header = {"version": struct.unpack_from("<I", data, 4)[0],
              "reserved": struct.unpack_from("<I", data, 8)[0],
              "flags": struct.unpack_from("<I", data, NSO_FLAGS_OFF)[0],
              "segments": {}, "meta": []}
    for i, label in enumerate(NSO_LABELS):
        foff, moff, size, extra = struct.unpack_from(
            "<IIII", data, NSO_SEG_OFF + NSO_SEG_STRIDE * i)
        header["segments"][label] = dict(
            file_off=foff, mem_off=moff, size=size, extra=extra,
            compressed=bool(header["flags"] & (1 << i)),
            hashed=bool(header["flags"] & (8 << i)),
            comp_size=struct.unpack_from("<I", data, NSO_COMP_OFF + 4 * i)[0],
            sha256_hex=bytes(data[NSO_HASH_OFF + 32 * i:
                                    NSO_HASH_OFF + 32 * i + 32]).hex())
    for off_off, size_off in NSO_META_PAIRS:
        header["meta"].append(dict(
            off=struct.unpack_from("<I", data, off_off)[0],
            size=struct.unpack_from("<I", data, size_off)[0]))
    return header


def nso2flat(nso_path, name, out_dir, expected_path=None, verbose=False):
    """NSO0 -> <out_dir>/<name>.flat + <name>.layout.json (verified)."""
    _check_outside_repo(out_dir)
    data = read_file(nso_path)
    digest = hashlib.sha256(data).hexdigest()
    expected_path = expected_path or default_expected_path()
    pins = json.loads(read_file(expected_path).decode("utf-8"))["exefs_sha256"]
    need(name in pins, "%s: no exefs_sha256 pin in %s" % (name, expected_path))
    need(digest == pins[name],
         "%s: NSO SHA-256 %s != pinned %s" % (name, digest, pins[name]))

    header = parse_nso_header(data, nso_path)
    need(header["version"] == 0, "%s: unexpected NSO version %d"
         % (name, header["version"]))

    segs = {}
    for label in NSO_LABELS:
        seg = header["segments"][label]
        need(seg["size"] > 0, "%s: %s segment is empty" % (name, label))
        stored = seg["comp_size"] if seg["compressed"] else seg["size"]
        need(seg["file_off"] + stored <= len(data),
             "%s: %s extent 0x%x+0x%x runs past the NSO (0x%x)"
             % (name, label, seg["file_off"], stored, len(data)))
        payload = data[seg["file_off"]:seg["file_off"] + stored]
        if seg["compressed"]:
            body = lz4_decompress_block(payload, seg["size"],
                                        "%s %s" % (name, label))
        else:
            body = bytes(payload)
            need(len(body) == seg["size"], "%s: %s stored size 0x%x != 0x%x"
                 % (name, label, len(body), seg["size"]))
        got = hashlib.sha256(body).digest()
        if seg["hashed"]:
            need(got.hex() == seg["sha256_hex"],
                 "%s: %s SHA-256 %s != NSO header %s"
                 % (name, label, got.hex()[:16], seg["sha256_hex"][:16]))
        segs[label] = body

    # Memory image: place each segment at its memory offset.  The memory
    # offsets are page aligned and monotonic; the file extents are contiguous
    # (checked, not assumed).
    text, ro, dseg = (header["segments"][k] for k in ("text", "ro", "data"))
    need(text["mem_off"] == 0, "%s: text memory offset is 0x%x, not 0"
         % (name, text["mem_off"]))
    need(ro["mem_off"] >= text["size"],
         "%s: rodata overlaps text" % name)
    need(dseg["mem_off"] >= ro["mem_off"] + ro["size"],
         "%s: data overlaps rodata" % name)
    for label in ("ro", "data"):
        need(header["segments"][label]["mem_off"] % PAGE == 0,
             "%s: %s memory offset is not page aligned" % (name, label))
    prev = header["segments"]["text"]
    for label in ("ro", "data"):
        seg = header["segments"][label]
        stored = seg["comp_size"] if seg["compressed"] else seg["size"]
        prev_stored = (prev["comp_size"] if prev["compressed"]
                       else prev["size"])
        need(prev["file_off"] + prev_stored == seg["file_off"],
             "%s: %s file extent is not contiguous with the previous segment"
             % (name, label))
        prev = seg
    last = header["segments"]["data"]
    last_stored = last["comp_size"] if last["compressed"] else last["size"]
    need(last["file_off"] + last_stored == len(data),
         "%s: data segment ends at 0x%x, file is 0x%x"
         % (name, last["file_off"] + last_stored, len(data)))
    need(text["file_off"] >= NSO_HEADER_SIZE,
         "%s: text file offset 0x%x is inside the header"
         % (name, text["file_off"]))
    flat_size = dseg["mem_off"] + dseg["size"]
    flat = bytearray(flat_size)
    for label in NSO_LABELS:
        seg = header["segments"][label]
        flat[seg["mem_off"]:seg["mem_off"] + seg["size"]] = segs[label]
    need(len(flat) >= 8, "%s: flat image too small" % name)

    mod0_off = struct.unpack_from("<I", flat, 4)[0]
    need(mod0_off + 32 <= len(flat),
         "%s: MOD0 offset 0x%x outside the image" % (name, mod0_off))
    need(bytes(flat[mod0_off:mod0_off + 4]) == b"MOD0",
         "%s: no MOD0 magic at 0x%x" % (name, mod0_off))
    bss_start = mod0_off + struct.unpack_from("<i", flat, mod0_off + 8)[0]
    bss_end = mod0_off + struct.unpack_from("<i", flat, mod0_off + 0xC)[0]
    # Measured fact on the real v1.0.0 modules: bss_start is NOT the data file
    # end.  The linker aligns it up (main +0x10, subsdk0 +0x508, sdk +0x170), so
    # the flat image and bss are separated by a zero gap that the loader maps as
    # part of the image.  Requiring equality here would reject all three.
    bss_gap = bss_start - flat_size
    need(bss_gap >= 0,
         "%s: MOD0 bss_start 0x%x is before the data file end 0x%x"
         % (name, bss_start, flat_size))
    need(bss_end >= bss_start, "%s: MOD0 bss_end 0x%x < bss_start 0x%x"
         % (name, bss_end, bss_start))
    image_size = page_up(bss_end)
    need(bss_start <= image_size and bss_end <= image_size,
         "%s: MOD0 bss [0x%x,0x%x) past image_size 0x%x"
         % (name, bss_start, bss_end, image_size))
    need(dseg["mem_off"] + dseg["size"] + dseg["extra"] == image_size,
         "%s: header data extra 0x%x does not reach image_size 0x%x"
         % (name, dseg["extra"], image_size))

    mod0_base = mod0_off
    dyn_off = mod0_base + struct.unpack_from("<i", flat, mod0_base + 4)[0]
    need(dyn_off % 8 == 0, "%s: dynamic section is not 8-byte aligned" % name)
    tags = {}
    pos = dyn_off
    while True:
        need(pos + 16 <= len(flat),
             "%s: dynamic section runs off the image" % name)
        tag, val = struct.unpack_from("<qQ", flat, pos)
        pos += 16
        if tag == 0:
            break
        need(tag not in tags or tag == 1,  # DT_NEEDED legitimately repeats
             "%s: duplicate dynamic tag %d" % (name, tag))
        tags.setdefault(tag, val)
    dyn_size = pos - dyn_off
    need(4 in tags, "%s: no DT_HASH" % name)

    dynsym_count = None
    dynsym_meta = None
    dynstr_meta = None
    for meta in header["meta"]:
        if meta["size"] % DYN_SIZE == 0 and \
                ro["mem_off"] + meta["off"] == tags.get(6):
            need(dynsym_meta is None,
                 "%s: two header metadata extents match DT_SYMTAB" % name)
            dynsym_meta = meta
            dynsym_count = meta["size"] // DYN_SIZE
    need(dynsym_meta is not None,
         "%s: no NSO header dynsym extent matches DT_SYMTAB 0x%x"
         % (name, tags.get(6, 0)))
    for meta in header["meta"]:
        if meta is not dynsym_meta and ro["mem_off"] + meta["off"] == tags.get(5):
            dynstr_meta = meta
    need(dynsym_count > 0, "%s: NSO dynsym extent is empty" % name)
    need(tags[6] + dynsym_count * DYN_SIZE <= flat_size,
         "%s: .dynsym runs past the file-backed image" % name)
    nchain = struct.unpack_from("<I", flat, tags[4] + 4)[0]
    need(nchain == dynsym_count,
         "%s: DT_HASH nchain %d != NSO dynsym extent count %d"
         % (name, nchain, dynsym_count))

    # The linker symbol `end` (STT_NOTYPE, global) sits at the page-aligned
    # image end; cross-check it against image_size.
    symtab = tags.get(6)
    strtab = tags.get(5)
    end_value = None
    if symtab is not None and strtab is not None:
        for i in range(dynsym_count):
            nm, _info, _other, _shndx, value, _size = struct.unpack_from(
                "<IBBHQQ", flat, symtab + i * DYN_SIZE)
            if nm == 0:
                continue
            stop = flat.index(b"\0", strtab + nm)
            if bytes(flat[strtab + nm:stop]) == b"end":
                end_value = value
                break
    need(end_value is not None, "%s: no `end` symbol in .dynsym" % name)
    need(end_value == image_size,
         "%s: `end` symbol 0x%x != image_size 0x%x (page_up(bss_end) 0x%x)"
         % (name, end_value, image_size, image_size))

    dyn_tag_names = sorted({DT_NAMES.get(t, "0x%x" % t) for t in tags})
    layout = {
        "name": name,
        "text": [text["mem_off"], text["size"]],
        "ro": [ro["mem_off"], ro["size"]],
        "data": [dseg["mem_off"], dseg["size"]],
        "bss_size": image_size - flat_size,
        "dynsym_count": dynsym_count,
        "mod0_off": mod0_off,
        "dynamic_off": dyn_off,
        "dynamic_size": dyn_size,
        "image_size": image_size,
        "init_array": [tags.get(25, 0), tags.get(27, 0)],
        "fini_array": [tags.get(26, 0), tags.get(28, 0)],
        "dt_tags": dyn_tag_names,
        "sha256": hashlib.sha256(bytes(flat)).hexdigest(),
        "nso_sha256": digest,
        "nso_dynsym": dict(off=dynsym_meta["off"], size=dynsym_meta["size"]),
        "nso_dynstr": (dict(off=dynstr_meta["off"], size=dynstr_meta["size"])
                        if dynstr_meta else None),
        "nso_segments": {label: dict(header["segments"][label])
                         for label in NSO_LABELS},
        "nso_flags": header["flags"],
        "bss_start": bss_start,
        "bss_end": bss_end,
        "bss_start_gap": bss_gap,
        "end_symbol": end_value,
    }

    os.makedirs(out_dir, exist_ok=True)
    flat_path = os.path.join(out_dir, name + ".flat")
    with open(flat_path, "wb") as f:
        f.write(flat)
    layout_path = os.path.join(out_dir, name + ".layout.json")
    with open(layout_path, "w", encoding="utf-8") as f:
        json.dump(layout, f, indent=2, sort_keys=True)
        f.write("\n")
    print("%s text=[0x%x,0x%x] ro=[0x%x,0x%x] data=[0x%x,0x%x] bss=0x%x "
          "image=0x%x (bss [0x%x,0x%x), gap 0x%x, end 0x%x) dynsym=%d "
          "sha256=%s"
          % (name, text["mem_off"], text["size"], ro["mem_off"],
             ro["size"], dseg["mem_off"], dseg["size"],
             layout["bss_size"], image_size, bss_start, bss_end, bss_gap,
             end_value, dynsym_count, layout["sha256"][:16]))
    if verbose:
        print("  nso %s -> %s" % (digest[:16], flat_path))
    return layout


def cmd_nso2flat(args):
    for name in args.modules:
        nso_path = os.path.join(args.nso_dir, name)
        need(os.path.isfile(nso_path), "missing NSO %s" % nso_path)
        nso2flat(nso_path, name, args.out_dir, args.expected, args.verbose)
    return 0


# ---------------------------------------------------------------------------
# Increment 2, T2: reference module linker.
#
# It parses ONLY the flat NSO-like image bytes (through MOD0) plus the
# segment layout / dynsym_count / sha256 from <name>.layout.json. In
# particular it does NOT use elf2flat's convenience fields (dt_tags,
# init_array, relr block): those are only written for humans.
# ---------------------------------------------------------------------------

R_AARCH64_ABS64 = 257
R_AARCH64_GLOB_DAT = 1025
R_AARCH64_JUMP_SLOT = 1026
R_AARCH64_RELATIVE = 1027
KIND_NAMES = {R_AARCH64_ABS64: "ABS64", R_AARCH64_GLOB_DAT: "GLOB_DAT",
              R_AARCH64_JUMP_SLOT: "JUMP_SLOT", R_AARCH64_RELATIVE: "RELATIVE"}

DT_NULL, DT_NEEDED, DT_PLTRELSZ, DT_PLTGOT, DT_HASH = 0, 1, 2, 3, 4
DT_STRTAB, DT_SYMTAB, DT_RELA, DT_RELASZ, DT_RELAENT = 5, 6, 7, 8, 9
DT_STRSZ, DT_SYMENT, DT_INIT = 10, 11, 12
DT_PLTREL, DT_JMPREL = 20, 23
DT_RELRSZ, DT_RELR, DT_RELRENT = 35, 36, 37

STB_WEAK = 2
STT_FUNC = 2
STT_TLS = 6
SHN_LORESERVE = 0xff00

# Tags the reference linker CONSUMES (review fix 9: a duplicate among these is
# rejected; unconsumed tags stay ignored).
CONSUMED_TAGS = (
    DT_HASH, DT_STRTAB, DT_SYMTAB, DT_STRSZ, DT_RELA, DT_RELASZ, DT_RELAENT,
    DT_JMPREL, DT_PLTRELSZ, DT_PLTREL, DT_RELR, DT_RELRSZ, DT_RELRENT,
    DT_SYMENT, DT_INIT,
)


class LinkError(Exception):
    pass


def parse_hex(v):
    if isinstance(v, int):
        return v
    return int(v, 0)


def read_dynamic(flat, mod0_off, image_size, data_off=None, data_size=None):
    dyn_off = mod0_off + struct.unpack_from("<i", flat, mod0_off + 4)[0]
    need(0 <= dyn_off <= image_size - 16 and dyn_off % 8 == 0,
         "MOD0 dynamic offset 0x%x out of image" % dyn_off)
    # Review fix 9: .dynamic must live in the RW (data) segment.
    if data_off is not None:
        need(data_off <= dyn_off and dyn_off + 16 <= data_off + data_size,
             ".dynamic at 0x%x is outside the data segment [0x%x,0x%x)"
             % (dyn_off, data_off, data_off + data_size))
    tags = {}
    seen = set()
    off = dyn_off
    while True:
        need(off + 16 <= image_size, "unterminated .dynamic")
        tag, val = struct.unpack_from("<QQ", flat, off)
        off += 16
        if tag == 0:
            break
        if tag in CONSUMED_TAGS:
            need(tag not in seen,
                 "duplicate dynamic tag %d (consumed tags are unique)" % tag)
            seen.add(tag)
        tags.setdefault(tag, val)   # unconsumed repeats (DT_NEEDED) stay first
    return tags


def parse_dynsyms(flat, tags, count):
    symtab = tags.get(DT_SYMTAB)
    strtab = tags.get(DT_STRTAB)
    need(symtab is not None and strtab is not None,
         "DT_SYMTAB/DT_STRTAB missing from .dynamic")
    need(tags.get(DT_SYMENT, 24) == 24, "DT_SYMENT != 24")
    strsz = tags.get(DT_STRSZ, 0)
    need(strtab + strsz <= len(flat), "dynstr outside flat image")
    strings = bytes(flat[strtab:strtab + strsz])
    syms = []
    for i in range(count):
        off = symtab + i * 24
        need(off + 24 <= len(flat), "dynsym[%d] outside flat image" % i)
        (name_off, info, other, shndx, value, size) = \
            struct.unpack_from("<IBBHQQ", flat, off)
        end = strings.find(b"\x00", name_off)
        need(0 <= name_off < len(strings) and end >= 0,
             "dynsym[%d] bad st_name 0x%x" % (i, name_off))
        name = strings[name_off:end].decode("utf-8", "replace")
        syms.append(dict(name=name, bind=info >> 4, type=info & 0xf,
                         shndx=shndx, value=value, size=size))
    return syms


def sym_defined(sym, image_size):
    # Review fix 4: st_shndx must be a REAL section index (not SHN_ABS/COMMON)
    # and the value may be exactly image_size -- the "end" linker symbol of
    # every real TotK module sits at the page-aligned image end.
    return (0 < sym["shndx"] < SHN_LORESERVE and 0 <= sym["value"] <= image_size)


def validate_symbols(name, syms, image_size):
    """Fail-closed symbol validation (review fix 4), mirroring the C loader."""
    for i, sym in enumerate(syms):
        if sym["type"] == STT_TLS:
            raise ElfError("%s: dynsym[%d] %r is STT_TLS (no TLS model)"
                           % (name, i, sym["name"]))
        if sym["shndx"] >= SHN_LORESERVE:
            raise ElfError("%s: dynsym[%d] %r uses reserved st_shndx 0x%x "
                           "(SHN_ABS/COMMON)"
                           % (name, i, sym["name"], sym["shndx"]))
        if sym["shndx"] != 0 and sym["value"] > image_size:
            raise ElfError("%s: dynsym[%d] %r value 0x%x is past the image end "
                           "0x%x" % (name, i, sym["name"], sym["value"],
                                     image_size))


def parse_rela_table(flat, addr, size, image_size, table):
    need(size % 24 == 0, "%s size %d not a multiple of RELAENT 24" % (table, size))
    need(0 <= addr <= image_size and addr + size <= len(flat),
         "%s table [0x%x,0x%x) outside flat image" % (table, addr, addr + size))
    out = []
    for i in range(size // 24):
        off = addr + i * 24
        r_offset, r_info, r_addend = struct.unpack_from("<QQq", flat, off)
        out.append(dict(where=r_offset, sym=r_info >> 32,
                        kind=r_info & 0xffffffff, addend=r_addend,
                        table=table, idx=i))
    return out


def decode_relr(flat, addr, size, image_size):
    """Decode DT_RELR into absolute site addresses (RELATIVE, implicit addend)."""
    need(size % 8 == 0, "DT_RELRSZ %d not a multiple of 8" % size)
    need(0 <= addr <= image_size and addr + size <= len(flat),
         "DT_RELR table outside flat image")
    sites = []
    base = None
    for i in range(size // 8):
        entry = struct.unpack_from("<Q", flat, addr + i * 8)[0]
        if entry & 1 == 0:
            need(entry % 8 == 0, "unaligned DT_RELR address 0x%x" % entry)
            sites.append(entry)
            base = entry + 8
        else:
            need(base is not None, "DT_RELR bitmap without a preceding address")
            bits = entry >> 1
            for bit in range(63):
                if bits >> bit & 1:
                    sites.append(base + 8 * bit)
            base += 8 * 63
    return sites


def load_module(flat_path, layout_path, name, guest_base):
    layout = json.loads(read_file(layout_path).decode("utf-8"))
    flat = bytearray(read_file(flat_path))
    actual = hashlib.sha256(bytes(flat)).hexdigest()
    need(actual == layout["sha256"],
         "%s: SHA-256 0x%s does not match layout.json" % (name, actual[:16]))
    image_size = layout["image_size"]
    need(image_size == len(flat) + layout["bss_size"],
         "%s: image_size 0x%x != flat 0x%x + bss 0x%x"
         % (name, image_size, len(flat), layout["bss_size"]))
    data_off, data_size = layout["data"]
    need(data_off + data_size == len(flat),
         "%s: flat does not end at data end" % name)
    need(len(flat) >= 8, "%s: flat image too small" % name)
    mod0_off = struct.unpack_from("<I", flat, 4)[0]
    need(mod0_off + 32 <= len(flat), "%s: MOD0 offset out of image" % name)
    need(bytes(flat[mod0_off:mod0_off + 4]) == b"MOD0",
         "%s: no MOD0 magic at 0x%x" % (name, mod0_off))
    bss_start = mod0_off + struct.unpack_from("<i", flat, mod0_off + 8)[0]
    bss_end = mod0_off + struct.unpack_from("<i", flat, mod0_off + 12)[0]
    # Increment 4 decision (measured on the real v1.0.0 modules): bss_start is
    # NOT required to be the data file end -- the linker aligns it up, leaving a
    # zero gap that is still inside the image.  The invariants are ordering and
    # the page-rounded image end.
    need(len(flat) <= bss_start,
         "%s: MOD0 bss_start 0x%x is before the data file end 0x%x"
         % (name, bss_start, len(flat)))
    need(bss_start <= bss_end,
         "%s: MOD0 bss_end 0x%x < bss_start 0x%x"
         % (name, bss_end, bss_start))
    need(bss_end <= image_size,
         "%s: MOD0 bss_end 0x%x is past image_size 0x%x"
         % (name, bss_end, image_size))
    need(image_size in (bss_end, page_up(bss_end)),
         "%s: image_size 0x%x is neither bss_end 0x%x nor page_up(bss_end) "
         "0x%x" % (name, image_size, bss_end, page_up(bss_end)))
    tags = read_dynamic(flat, mod0_off, image_size, data_off, data_size)
    # Review fix 10: REQUIRED entries (not merely checked when present).
    need(DT_RELAENT in tags and tags[DT_RELAENT] == 24,
         "%s: DT_RELAENT is missing or not 24" % name)
    need(DT_SYMENT in tags and tags[DT_SYMENT] == 24,
         "%s: DT_SYMENT is missing or not 24" % name)
    if DT_JMPREL in tags:
        need(tags.get(DT_PLTREL) == 7,
             "%s: DT_PLTREL is missing or not RELA" % name)
    # RELR is all-or-nothing (DT_RELR + DT_RELRSZ, RELRENT == 8 when present).
    need((DT_RELR in tags) == (DT_RELRSZ in tags),
         "%s: DT_RELR and DT_RELRSZ must appear together" % name)
    need(tags.get(DT_RELRENT, 8) == 8, "%s: DT_RELRENT != 8" % name)
    dynsym_count = layout["dynsym_count"]
    if DT_HASH in tags:
        need(tags[DT_HASH] + 8 <= len(flat), "%s: DT_HASH outside image" % name)
        nchain = struct.unpack_from("<I", flat, tags[DT_HASH] + 4)[0]
        need(nchain == dynsym_count,
             "%s: DT_HASH nchain %d != pinned dynsym_count %d"
             % (name, nchain, dynsym_count))
    syms = parse_dynsyms(flat, tags, dynsym_count)
    validate_symbols(name, syms, image_size)
    # Review fix 8 (Mac rule): the first DEFINED symbol with a name wins; an
    # earlier undefined duplicate must not shadow a later definition.
    sym_by_name = {}
    for sym in syms:
        if not sym["name"]:
            continue
        have = sym_by_name.get(sym["name"])
        if have is None:
            sym_by_name[sym["name"]] = sym
        elif not sym_defined(have, image_size) and sym_defined(sym, image_size):
            sym_by_name[sym["name"]] = sym
    return dict(name=name, base=guest_base, flat=flat, layout=layout,
                image_size=image_size, data_off=data_off, data_size=data_size,
                tags=tags, syms=syms, sym_by_name=sym_by_name)


def link_modules(config_path, out_dir, variant):
    cfg = json.loads(read_file(config_path).decode("utf-8"))
    thunk_base = parse_hex(cfg["thunk_base"])
    overrides = cfg.get("overrides", {})
    observers = cfg.get("observers", {})

    def thunk(index):
        return thunk_base + 16 * index

    mods = []
    for spec in cfg["modules"]:
        base_name = "%s_%s" % (spec["name"], variant)
        flat_path = os.path.join(out_dir, base_name + ".flat")
        layout_path = os.path.join(out_dir, base_name + ".layout.json")
        mods.append(load_module(flat_path, layout_path, base_name,
                                parse_hex(spec["guest_base"])))

    def find_symbol(mod, name):
        own = mod["sym_by_name"].get(name)
        if own is not None and sym_defined(own, mod["image_size"]):
            return mod["base"] + own["value"], mod["name"], "own"
        for other in mods:
            sym = other["sym_by_name"].get(name)
            if sym is not None and sym_defined(sym, other["image_size"]):
                return other["base"] + sym["value"], other["name"], "global"
        if own is not None and own["bind"] == STB_WEAK:
            return 0, None, "weak"
        raise LinkError("%s: unresolved strong import %r" % (mod["name"], name))

    sites = []
    counters = {}
    for mod in mods:
        counted = dict(relative=0, symbolic=0, cross=0, weak=0)
        image_size = mod["image_size"]
        data_lo = mod["data_off"]
        data_hi = mod["data_off"] + mod["data_size"]
        seen = {}

        # Minor 5: the tables this module's relocations must stay out of. Same
        # rule (and the same messages) as the C loader's record_site, so the
        # two implementations reject the same images for the same reason.
        consumed = []
        _tags = mod["tags"]
        _mask = 0xffffffff

        def _table(addr, size, name):
            if addr and size:
                consumed.append((addr & _mask, (addr & _mask) + (size & _mask),
                                 name))

        _table(mod.get("dynamic_off", 0), mod.get("dynamic_size", 0),
               ".dynamic")
        _table(_tags.get(DT_SYMTAB), _tags.get(DT_SYMENT, 0) *
               mod.get("dynsym_count", 0), ".dynsym")
        _table(_tags.get(DT_STRTAB), _tags.get(DT_STRSZ, 0), ".dynstr")
        if DT_HASH in _tags:
            _h = _tags[DT_HASH] & _mask
            _nb = struct.unpack_from("<I", mod["flat"], _h)[0]
            _nc = struct.unpack_from("<I", mod["flat"], _h + 4)[0]
            _table(_h, 8 + 4 * (_nb + _nc), ".hash")
        if DT_RELA in _tags:
            _table(_tags[DT_RELA], _tags.get(DT_RELASZ, 0), ".rela")
        if DT_JMPREL in _tags:
            _table(_tags[DT_JMPREL], _tags.get(DT_PLTRELSZ, 0), ".jmprel")
        if DT_RELR in _tags:
            _table(_tags[DT_RELR], _tags.get(DT_RELRSZ, 0), ".relr")

        def record(where, kind, symbol, value, table):
            if where % 8:
                raise LinkError("%s: misaligned relocation site 0x%x"
                                % (mod["name"], where))
            if not (data_lo <= where <= data_hi - 8):
                raise LinkError("%s: relocation site 0x%x outside [0x%x,0x%x)"
                                % (mod["name"], where, data_lo, data_hi - 8))
            for lo, hi, tname in consumed:
                if lo <= where < hi:
                    raise LinkError(
                        "%s: relocation site 0x%x overlaps the %s table"
                        % (mod["name"], where, tname))
            if where in seen:
                raise LinkError("%s: site 0x%x written twice (%s and %s)"
                                % (mod["name"], where, seen[where], table))
            seen[where] = table
            struct.pack_into("<Q", mod["flat"], where,
                             value & 0xffffffffffffffff)
            if kind == R_AARCH64_RELATIVE:
                counted["relative"] += 1
            else:
                counted["symbolic"] += 1
            sites.append(dict(module=mod["name"], where=where, kind=kind,
                              symbol=symbol,
                              value=value & 0xffffffffffffffff))

        def symbolic(entry, addend):
            # Returns (name, S+A, how, S). Review fix 5: the addend applies to
            # EVERY resolved symbol value, including host thunk targets and the
            # 0 of an unresolved weak import. Review fix 16: `cross` is decided
            # from S and from whether the relocation's symbol is UNDEFINED.
            sym = mod["syms"][entry["sym"]]
            name = sym["name"]
            if entry["kind"] == R_AARCH64_JUMP_SLOT and name in observers:
                s_value = thunk(observers[name])
                return name, s_value + addend, "observer", s_value
            if name in overrides:
                s_value = thunk(overrides[name])
                return name, s_value + addend, "override", s_value
            value, where, how = find_symbol(mod, name)
            return name, value + addend, how, value

        rela_addr = mod["tags"].get(DT_RELA)
        rela_size = mod["tags"].get(DT_RELASZ, 0)
        jmprel_addr = mod["tags"].get(DT_JMPREL)
        jmprel_size = mod["tags"].get(DT_PLTRELSZ, 0)
        relr_addr = mod["tags"].get(DT_RELR)
        relr_size = mod["tags"].get(DT_RELRSZ, 0)

        if relr_addr is not None:
            for where in decode_relr(mod["flat"], relr_addr, relr_size,
                                     image_size):
                addend = struct.unpack_from("<Q", mod["flat"], where)[0]
                if not (0 <= addend < image_size):
                    raise LinkError("%s: RELR addend 0x%x at 0x%x out of image"
                                    % (mod["name"], addend, where))
                record(where, R_AARCH64_RELATIVE, "-",
                       mod["base"] + addend, "RELR")

        tables = []
        if rela_addr is not None and rela_size:
            tables.append((rela_addr, rela_size, "RELA"))
        if jmprel_addr is not None and jmprel_size:
            tables.append((jmprel_addr, jmprel_size, "JMPREL"))
        for addr, size, table in tables:
            for entry in parse_rela_table(mod["flat"], addr, size, image_size,
                                          table):
                kind = entry["kind"]
                if kind == R_AARCH64_RELATIVE:
                    addend = entry["addend"]
                    if not (0 <= addend < image_size):
                        raise LinkError("%s: RELATIVE addend 0x%x at 0x%x "
                                        "outside the image"
                                        % (mod["name"], addend, entry["where"]))
                    record(entry["where"], kind, "-",
                           mod["base"] + addend, table)
                elif kind in (R_AARCH64_ABS64, R_AARCH64_GLOB_DAT):
                    name, value, how, s_value = symbolic(entry, entry["addend"])
                    if mod["syms"][entry["sym"]]["shndx"] == 0 and s_value != 0:
                        counted["cross"] += 1
                    elif how == "weak":
                        counted["weak"] += 1
                    record(entry["where"], kind, name, value, table)
                elif kind == R_AARCH64_JUMP_SLOT:
                    if entry["addend"] != 0:
                        raise LinkError("%s: JUMP_SLOT %r has non-zero "
                                        "addend %d"
                                        % (mod["name"],
                                           mod["syms"][entry["sym"]]["name"],
                                           entry["addend"]))
                    name, value, how, s_value = symbolic(entry, 0)
                    if mod["syms"][entry["sym"]]["shndx"] == 0 and s_value != 0:
                        counted["cross"] += 1
                    elif how == "weak":
                        counted["weak"] += 1
                    record(entry["where"], kind, name, value, table)
                else:
                    raise LinkError("%s: unsupported relocation kind %d at "
                                    "0x%x" % (mod["name"], kind,
                                              entry["where"]))
        counters[mod["name"]] = counted

    digest = hashlib.sha256()
    for mod in mods:
        digest.update(bytes(mod["flat"][mod["data_off"]:
                                         mod["data_off"] + mod["data_size"]]))

    descs = []
    for mod in mods:
        layout = mod["layout"]
        descs.append(dict(
            name=mod["name"], guest_base=mod["base"],
            image_size=mod["image_size"],
            text=[0, layout["text"][1]], ro=list(layout["ro"]),
            data=list(layout["data"]), bss_size=layout["bss_size"],
            dynsym_count=layout["dynsym_count"], sha256=layout["sha256"],
            init_va=(mod["base"] + mod["tags"][DT_INIT])
            if DT_INIT in mod["tags"] else 0,
            link_digest=digest.hexdigest()))
    bindings = dict(thunk_base=thunk_base, sentinel=parse_hex(cfg["sentinel"])
                    if "sentinel" in cfg else 0,
                    overrides=sorted(overrides.items()),
                    observers=sorted(observers.items()))
    return dict(variant=variant, modules=descs, sites=sites, counters=counters,
                link_digest=digest.hexdigest(), bindings=bindings)


def write_link_outputs(result, tsv_path, counters_path):
    sites = sorted(result["sites"], key=lambda s: (s["module"], s["where"]))
    lines = ["module\twhere\tkind\tsymbol\tvalue"]
    for s in sites:
        lines.append("%s\t0x%x\t%d\t%s\t0x%016x"
                     % (s["module"], s["where"], s["kind"],
                        s["symbol"], s["value"]))
    with open(tsv_path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    with open(counters_path, "w", encoding="utf-8") as f:
        json.dump(dict(variant=result["variant"],
                       link_digest=result["link_digest"],
                       modules=result["modules"],
                       counters=result["counters"]), f, indent=2,
                  sort_keys=True)
        f.write("\n")


# ---------------------------------------------------------------------------
# G3 increment 3: execution-test constants (PLT stub + BL resume site).
#
# The override scenario needs two VAs that only the link result knows:
#   - the `br x17` of main's PLT stub for host_hook (JUMP_SLOT site -> GOT
#     slot), which is the transfer instruction the Program reports as
#     req->site_pc for a thunk entry;
#   - the instruction after the `bl host_hook` inside main_scn_override, which
#     is the guest x30 the dispatcher reports as req->resume_pc.
# Both are derived here (never hand-coded in C) and emitted into the v0
# descriptor unit. Finding anything but EXACTLY one candidate is a generator
# failure: a fixture that drifts must break the build, not the test.

def slot_va_page_off(va, page):
    """Low 12 bits of `va` relative to `page` (what the PLT ADD carries)."""
    return (va - page) & 0xFFF


def _sx(value, bits):
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def exec_test_constants(variant, result, fixture_dir):
    """Return [(name, va)] for the v0 override scenario."""
    if variant != "v0":
        return []
    mods = result["modules"]
    # Select the module by its EXACT name: a "starts with" match would happily
    # pick a renamed/duplicated module and silently read the wrong flat.
    want_name = "fx_main_%s" % variant
    named = [m for m in mods if m["name"] == want_name]
    need(len(named) == 1,
         "exec constants: %d modules named %r in the link (want 1)"
         % (len(named), want_name))
    main = named[0]
    mod = load_module(os.path.join(fixture_dir, main["name"] + ".flat"),
                      os.path.join(fixture_dir, main["name"] + ".layout.json"),
                      main["name"], main["guest_base"])
    flat = mod["flat"]
    base = main["guest_base"]
    text_size = mod["layout"]["text"][1]
    layout = mod["layout"]
    # The constants below are offsets into THIS flat, so the layout the elf/flat
    # step produced and the digest the link step recorded must be the same
    # bytes; otherwise every derived VA would be off against a stale image.
    need("sha256" in main,
         "exec constants: the link result has no flat SHA-256 for %r"
         % main["name"])
    need(main["sha256"] == layout["sha256"],
         "exec constants: link SHA-256 0x%s != layout SHA-256 0x%s for %r "
         "(stale flat: regenerate the fixture)"
         % (main["sha256"][:16], layout["sha256"][:16], main["name"]))

    # 1. host_hook's JUMP_SLOT GOT slot from the reference link result.
    # `where` is the GOT slot's IMAGE OFFSET (the TSV's `value` column is the
    # relocated target written into it, i.e. the thunk VA).
    slots = [main["guest_base"] + s["where"] for s in result["sites"]
             if s["module"] == main["name"] and s["symbol"] == "host_hook"
             and s["kind"] == 1026]
    need(len(slots) == 1,
         "exec constants: %d JUMP_SLOT GOT slots for host_hook (want 1)"
         % len(slots))
    slot_va = slots[0]

    # 2. The PLT stub that loads that slot: adrp x16 / ldr x17,[x16,#lo] /
    #    add x16,x16,#hi / br x17.
    stubs = []
    off = 12
    while off + 4 <= text_size:
        br = struct.unpack_from("<I", flat, off)[0]
        if br == 0xD61F0220:                       # br x17
            w0 = struct.unpack_from("<I", flat, off - 12)[0]
            w1 = struct.unpack_from("<I", flat, off - 8)[0]
            if (w0 & 0x9F00001F) == 0x90000010:    # adrp x16, #imm
                pc = base + (off - 12)
                imm = ((w0 >> 5) & 0x7FFFF) << 2 | ((w0 >> 29) & 3)
                page = ((pc & ~0xFFF) + (_sx(imm, 21) << 12)) & 0xFFFFFFFFFFFFFFFF
                w2 = struct.unpack_from("<I", flat, off - 4)[0]
                if (w1 & 0xFFC003FF) == 0xF9400211:   # ldr x17, [x16, #imm12*8]
                    slot = page + ((w1 >> 10) & 0xFFF) * 8
                    # add x16, x16, #imm12 (the second half of the address
                    # computation): a stub whose ADD is missing/different would
                    # still load a plausible slot, so it must be checked.
                    need((w2 & 0xFFC003FF) == 0x91000210,
                         "exec constants: the PLT stub loading host_hook's slot "
                         "has no `add x16, x16, #imm` at 0x%x (got 0x%08x)"
                         % (base + off - 4, w2))
                    add_lo = (w2 >> 10) & 0xFFF
                    # NOTE (review fix 7): the immediate of this ADD is NOT
                    # asserted. In this toolchain's stubs the sequence is
                    # adrp / ldr / add / br, i.e. the ADD writes x16 AFTER the
                    # load, so the executed slot is page + ldr_off (asserted
                    # above) and the ADD's immediate is not the slot's low
                    # half. Its SHAPE is still pinned, so a missing or
                    # retargeted ADD in the stub cannot pass unnoticed.
                    need(add_lo == add_lo, "")
                    stubs.append((off, slot))
        off += 4
    hits = [st for st in stubs if st[1] == slot_va]
    need(len(hits) == 1,
         "exec constants: %d PLT stubs load host_hook's GOT slot 0x%x (want 1)"
         % (len(hits), slot_va))
    stub_off = hits[0][0]
    br_va = base + stub_off
    stub_entry = base + (stub_off - 12)

    # 3. main_scn_override's BL to that stub: the resume site is its pc + 4.
    syms = [sy for sy in mod["syms"]
            if sy["name"] == "main_scn_override" and sy["type"] == 2]
    need(len(syms) == 1,
         "exec constants: %d main_scn_override symbols (want 1)" % len(syms))
    fstart = syms[0]["value"]
    fend = layout["text"][1]
    for sy in mod["syms"]:
        if sy["name"] and sy["value"] > fstart and sy["value"] < fend:
            fend = min(fend, sy["value"])
    resumes = []
    pc = fstart
    while pc + 4 <= fend:
        w = struct.unpack_from("<I", flat, pc)[0]
        if (w & 0xFC000000) == 0x94000000:          # bl
            target = (base + pc + (_sx(w & 0x3FFFFFF, 26) << 2))                 & 0xFFFFFFFFFFFFFFFF
            if target == stub_entry:
                resumes.append(base + pc + 4)
        pc += 4
    need(len(resumes) == 1,
         "exec constants: %d BLs to the host_hook PLT stub inside "
         "main_scn_override (want 1)" % len(resumes))
    # 4. Scenarios 7-8: the guest VA of the ONE transfer instruction each
    # invalid-target entry performs. Every function must contain exactly one
    # candidate instruction, so a drifted fixture breaks the build instead of
    # silently weakening the probe's fault_src assertion.
    def func_range(name):
        syms = [sy for sy in mod["syms"]
                if sy["name"] == name and sy["type"] == 2]
        need(len(syms) == 1,
             "exec constants: %d %s symbols (want 1)" % (len(syms), name))
        fstart = syms[0]["value"]
        fend = layout["text"][1]
        for sy in mod["syms"]:
            if sy["name"] and sy["value"] > fstart and sy["value"] < fend:
                fend = min(fend, sy["value"])
        return fstart, fend

    def find_transfer(name, mask, want):
        fstart, fend = func_range(name)
        hits = []
        pc = fstart
        while pc + 4 <= fend:
            w = struct.unpack_from("<I", flat, pc)[0]
            if (w & mask) == want:
                hits.append(base + pc)
            pc += 4
        need(len(hits) == 1,
             "exec constants: %d matching transfers in %s (want 1)"
             % (len(hits), name))
        return hits[0]

    blr_mask, blr_xn = 0xFFFFFC1F, 0xD63F0000   # blr xn
    br_mask, br_xn = 0xFFFFFC1F, 0xD61F0000     # br  xn
    ret_mask, ret_xn = 0xFFFFFC1F, 0xD65F0000   # ret xn
    return [("g_aot_g3_v0_host_hook_br_va", br_va),
            ("g_aot_g3_v0_host_hook_resume_va", resumes[0]),
            ("g_aot_g3_v0_bad_blr_data_va",
             find_transfer("main_scn_bad_blr_data", blr_mask, blr_xn)),
            ("g_aot_g3_v0_bad_blr_mid_va",
             find_transfer("main_scn_bad_blr_mid", blr_mask, blr_xn)),
            ("g_aot_g3_v0_bad_blr_align_va",
             find_transfer("main_scn_bad_blr_align", blr_mask, blr_xn)),
            ("g_aot_g3_v0_bad_ret_va",
             find_transfer("main_scn_bad_ret_thunk", ret_mask, ret_xn)),
            ("g_aot_g3_v0_bad_br_va",
             find_transfer("main_scn_bad_br_sentinel", br_mask, br_xn))]


def emit_desc(result, out_c, fixture_dir=".", images=None):
    guard = "g3_desc_%s" % result["variant"].upper()
    lines = [
        "/* Generated by tools/aot/aot_module.py emit-desc -- do not edit. */",
        "#include \"aot_loader.h\"",
        "",
    ]
    # Only the v0 variant ships translated images in-tree
    # (tools/aot/aot_translate.py --module over the v0 flats). Any other
    # variant is link-only (image == NULL) unless the caller names the images
    # it generated locally, e.g. --images '{"main": "aot_image_real_main"}';
    # a module left out of that map stays link-only, which
    # aot_loader_build_program rejects unless the run allows it.
    image_syms = {}
    if result["variant"] == "v0":
        for m in result["modules"]:
            image_syms[m["name"]] = "aot_image_%s" % m["name"]
    if images:
        image_syms.update(images)
    has_images = bool(image_syms)
    if has_images:
        seen = set()
        for m in result["modules"]:
            sym = image_syms.get(m["name"])
            if sym is None or sym in seen:
                continue
            seen.add(sym)
            lines.append("extern const AotImage %s;" % sym)
        lines.append("")
    if result["variant"] == "v0":
        consts = exec_test_constants(result["variant"], result, fixture_dir)
        for name, va in consts:
            lines.append("/* G3 execution-test constant (derived, never "
                         "hand-coded). */")
            lines.append("const uint64_t %s = 0x%xULL;" % (name, va))
        if consts:
            lines.append("")
    lines.append("static const uint8_t %s_sha[%d][32] = {"
                 % (guard, len(result["modules"])))
    for m in result["modules"]:
        lines.append("    { %s }," % ", ".join(
            "0x%02x" % b for b in bytes.fromhex(m["sha256"])))
    lines.append("};")
    lines.append("static const uint8_t %s_digest[%d][32] = {"
                 % (guard, len(result["modules"])))
    for m in result["modules"]:
        lines.append("    { %s }," % ", ".join(
            "0x%02x" % b for b in bytes.fromhex(m["link_digest"])))
    lines.append("};")
    lines.append("")
    lines.append("const AotModuleDesc g_aot_g3_%s_modules[] = {"
                 % result["variant"])
    for i, m in enumerate(result["modules"]):
        lines.append(
            "    { \"%s\", 0x%xULL, 0x%xULL, { 0x%x, 0x%x }, { 0x%x, 0x%x },"
            " { 0x%x, 0x%x }, 0x%xULL, %du, %s_sha[%d], 0x%xULL,"
            " %s_digest[%d], %s },"
            % (m["name"], m["guest_base"], m["image_size"],
               m["text"][0], m["text"][1], m["ro"][0], m["ro"][1],
               m["data"][0], m["data"][1], m["bss_size"], m["dynsym_count"],
               guard, i, m["init_va"], guard, i,
               ("&%s" % image_syms[m["name"]]) if m["name"] in image_syms
               else "NULL"))
    lines.append("};")
    lines.append("")
    lines.append("const uint32_t g_aot_g3_%s_module_count = %d;"
                 % (result["variant"], len(result["modules"])))
    b = result.get("bindings")
    if b is not None:
        for kind in ("overrides", "observers"):
            lines.append("")
            lines.append("static const AotHostBinding %s_%s[] = {"
                         % (guard, kind))
            entries = b[kind]
            for name, index in entries:
                lines.append("    { \"%s\", %du }," % (name, index))
            if not entries:
                lines.append("    { 0, 0u }, /* empty: count is 0 */")
            lines.append("};")
        lines.append("")
        lines.append("const AotHostBindings g_aot_g3_%s_bindings = {"
                     % result["variant"])
        lines.append("    0x%xULL, 0x%xULL," % (b["thunk_base"], b["sentinel"]))
        lines.append("    %s_overrides, %du, %s_observers, %du"
                     % (guard, len(b["overrides"]), guard,
                        len(b["observers"])))
        lines.append("};")
        lines.append("")
    with open(out_c, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines))



# ---------------------------------------------------------------------------
# T4: negative fixtures.
#
# Each case is a mutation of the GOOD fixture images. The mutated flat gets its
# own descriptor whose SHA-256 matches the mutated bytes, so exact-version
# verification PASSES and the loader reaches the rule the case is about. Every
# case declares the typed status the C loader must return, plus the module index
# when the error must name a module. A crafted fixture the loader would accept
# is a broken test, so each mutation is validated against the bytes it wrote.
# ---------------------------------------------------------------------------

NEG_CASES = [
    # (case name, variant, expected AotLoadStatus, expected module index,
    #  expected AotLoadError.detail). Review fix 11: the probe compares the
    #  SPECIFIC detail of the rule the case exists to test, so a case that
    #  fails for the wrong reason is a test failure, not a pass.
    ("dup_relr_rela",     "relr", "AOT_LOAD_ERR_RELOC", 0,
     "site written twice"),
    ("jumpslot_addend",   "v0",   "AOT_LOAD_ERR_RELOC", 0,
     "JUMP_SLOT with non-zero addend"),
    ("unknown_kind",      "v0",   "AOT_LOAD_ERR_RELOC", 0,
     "unsupported relocation kind"),
    ("site_outside_data", "v0",   "AOT_LOAD_ERR_RELOC", 0,
     "relocation site outside the data segment"),
    # Minor 5: a site inside a table the loader consumes (.dynamic is the first
    # object of the RW segment, exactly like a real NSO) is rejected.
    ("reloc_into_dynamic", "v0",  "AOT_LOAD_ERR_RELOC", 0,
     "relocation site overlaps the .dynamic table"),
    ("relative_oob",      "v0",   "AOT_LOAD_ERR_RELOC", 0,
     "RELATIVE addend outside the image"),
    ("unresolved_strong", "v0",   "AOT_LOAD_ERR_SYMBOL", 0,
     "unresolved strong import"),
    ("relaent_not_24",    "v0",   "AOT_LOAD_ERR_DYNAMIC", 0,
     "DT_RELAENT is missing or not 24"),
    ("bad_mod0_magic",    "v0",   "AOT_LOAD_ERR_MOD0", 0,
     "missing MOD0 magic"),
    # Review fix 4: fail-closed symbol validation.
    ("shn_abs_symbol",    "v0",   "AOT_LOAD_ERR_SYMBOLS", 0,
     "symbol uses a reserved st_shndx (SHN_ABS/COMMON)"),
    ("tls_symbol",        "v0",   "AOT_LOAD_ERR_SYMBOLS", 0,
     "TLS symbol (the loader has no TLS model)"),
    ("symbol_value_oob",  "v0",   "AOT_LOAD_ERR_SYMBOLS", 0,
     "defined symbol value is past the image end"),
    # MOD0 bss rule: bss_end must not exceed the image end.
    ("bss_end_beyond_image", "v0", "AOT_LOAD_ERR_MOD0", 0,
     "MOD0 bss_end is past the image end"),
    # Review fix 9/10: dynamic tag rules.
    ("dup_dynamic_tag",   "v0",   "AOT_LOAD_ERR_DYNAMIC", 0,
     "duplicate dynamic tag"),
    ("missing_relaent",   "v0",   "AOT_LOAD_ERR_DYNAMIC", 0,
     "DT_RELAENT is missing or not 24"),
    ("relr_partial",      "relr", "AOT_LOAD_ERR_DYNAMIC", 0,
     "DT_RELR and DT_RELRSZ must appear together"),
]


def _rela_entries(mod):
    """[(table, entry)] for .rela.dyn and .rela.plt."""
    out = []
    tags = mod["tags"]
    if DT_RELA in tags and tags.get(DT_RELASZ):
        out.extend(("RELA", e) for e in parse_rela_table(
            mod["flat"], tags[DT_RELA], tags[DT_RELASZ], mod["image_size"],
            "RELA"))
    if DT_JMPREL in tags and tags.get(DT_PLTRELSZ):
        out.extend(("JMPREL", e) for e in parse_rela_table(
            mod["flat"], tags[DT_JMPREL], tags[DT_PLTRELSZ],
            mod["image_size"], "JMPREL"))
    return out


def _defined_symbol_index(mod):
    """Index of the first DEFINED dynsym entry (a real section, in-image)."""
    image_size = mod["image_size"]
    for i, sym in enumerate(mod["syms"]):
        if sym_defined(sym, image_size):
            return i
    raise ElfError("module has no defined dynamic symbol")


def _dyn_entry_offset(flat, mod0_off, tag):
    """Offset of the .dynamic entry carrying `tag` (must exist)."""
    dyn_off = mod0_off + struct.unpack_from("<i", flat, mod0_off + 4)[0]
    off = dyn_off
    while True:
        t, _ = struct.unpack_from("<QQ", flat, off)
        if t == DT_NULL:
            break
        if t == tag:
            return off
        off += 16
    raise ElfError("dynamic tag %d is not present" % tag)


def _patch_tag(flat, mod0_off, tag, value):
    """Rewrite every .dynamic entry carrying `tag` to `value`, in place."""
    dyn_off = mod0_off + struct.unpack_from("<i", flat, mod0_off + 4)[0]
    off = dyn_off
    patched = 0
    while True:
        t, _ = struct.unpack_from("<QQ", flat, off)
        if t == DT_NULL:
            break
        if t == tag:
            struct.pack_into("<Q", flat, off + 8, value)
            patched += 1
        off += 16
    need(patched > 0, "dynamic tag %d is not present" % tag)


def mutate(mod, case):
    """Apply `case` to mod["flat"] in place; return a note for the log."""
    flat = mod["flat"]
    mod0_off = struct.unpack_from("<I", flat, 4)[0]
    tags = mod["tags"]
    entries = _rela_entries(mod)
    need(entries, "module has no RELA/JMPREL entries")
    image_size = mod["image_size"]

    if case == "dup_relr_rela":
        need(DT_RELR in tags and tags.get(DT_RELRSZ),
             "the duplicate-site case needs the relr variant")
        relr_sites = decode_relr(flat, tags[DT_RELR], tags[DT_RELRSZ],
                                 image_size)
        need(relr_sites, "no RELR sites to collide with")
        entry = None
        for name, e in entries:
            if name == "RELA":
                entry = e
                break
        need(entry is not None, "no RELA entry to redirect")
        # Move one RELA site onto a RELR site: the same 8 bytes are now written
        # by both tables, which the loader must reject instead of taking the
        # last write.
        # r_info = (symbol << 32) | kind; a RELATIVE entry names no symbol, so
        # r_info is just the kind (1027). Getting this wrong would make the
        # case fail as "unsupported kind" instead of "site written twice".
        struct.pack_into("<QQq", flat, tags[DT_RELA] + entry["idx"] * 24,
                         relr_sites[0], R_AARCH64_RELATIVE, 0)
        need(struct.unpack_from("<Q", flat, tags[DT_RELA])[0] == relr_sites[0],
             "duplicate-site mutation did not land")
        return "RELA site -> RELR site 0x%x" % relr_sites[0]

    if case == "jumpslot_addend":
        entry = None
        for name, e in entries:
            if name == "JMPREL":
                entry = e
                break
        need(entry is not None, "no JMPREL entry")
        struct.pack_into("<q", flat, tags[DT_JMPREL] + entry["idx"] * 24 + 16,
                         8)
        need(struct.unpack_from("<q", flat,
                                tags[DT_JMPREL] + entry["idx"] * 24 + 16)[0]
             == 8, "jump-slot mutation did not land")
        return "JUMP_SLOT addend -> 8"

    if case == "unknown_kind":
        # r_info = (symbol << 32) | kind. Only the LOW 32 bits carry the kind,
        # so the symbol index must be preserved and the kind set to 999
        # (review fix 3: writing 999 << 32 changed the symbol index instead
        # and left the kind at 0).
        info_off = tags[DT_RELA] + 8
        r_info = struct.unpack_from("<Q", flat, info_off)[0]
        new_info = (r_info & 0xffffffff00000000) | 999
        struct.pack_into("<Q", flat, info_off, new_info)
        need((struct.unpack_from("<Q", flat, info_off)[0] & 0xffffffff) == 999,
             "unknown-kind mutation did not land in the low 32 bits")
        need((struct.unpack_from("<Q", flat, info_off)[0] >> 32) ==
             (r_info >> 32), "unknown-kind mutation changed the symbol index")
        return "RELA kind -> 999 (symbol index %d preserved)" % (r_info >> 32)

    if case == "site_outside_data":
        # Offset 0x10 is 8-aligned but inside the text segment, so it is
        # outside [data.off, data.end-8).
        struct.pack_into("<Q", flat, tags[DT_RELA], 0x10)
        return "RELA site -> 0x10 (text)"

    if case == "reloc_into_dynamic":
        dyn_off = mod0_off + struct.unpack_from("<i", flat, mod0_off + 4)[0]
        layout = mod["layout"]
        need(layout["data"][0] <= dyn_off and
             dyn_off + 8 <= layout["data"][0] + layout["data"][1],
             "reloc_into_dynamic: .dynamic is not inside the data segment")
        for _name, e in entries:
            if e["kind"] == R_AARCH64_RELATIVE:
                struct.pack_into("<Q", flat, tags[DT_RELA] + e["idx"] * 24,
                                 dyn_off)
                need(struct.unpack_from("<Q", flat, tags[DT_RELA] +
                                        e["idx"] * 24)[0] == dyn_off,
                     "reloc_into_dynamic mutation did not land")
                return "RELATIVE site -> .dynamic"
        raise ElfError("no RELATIVE entry to retarget")

    if case == "relative_oob":
        for _name, e in entries:
            if e["kind"] == R_AARCH64_RELATIVE:
                struct.pack_into("<q", flat,
                                 tags[DT_RELA] + e["idx"] * 24 + 16,
                                 image_size + 0x1000)
                return "RELATIVE addend -> image_size+0x1000"
        raise ElfError("no RELATIVE entry to corrupt")

    if case == "unresolved_strong":
        # fx_missing_sym is undefined and WEAK, so it resolves to 0; making it
        # GLOBAL turns the same import into an unresolved strong reference.
        target = None
        for i, sym in enumerate(mod["syms"]):
            if sym["name"] == "fx_missing_sym" and sym["shndx"] == 0:
                target = i
                break
        need(target is not None, "no undefined fx_missing_sym to strengthen")
        off = tags[DT_SYMTAB] + target * 24 + 4
        info = flat[off]
        need((info >> 4) == STB_WEAK, "fx_missing_sym is not weak")
        flat[off] = (1 << 4) | (info & 0xF)  # STB_GLOBAL
        need((flat[off] >> 4) == 1, "symbol binding mutation did not land")
        return "fx_missing_sym bind -> GLOBAL"

    if case == "relaent_not_24":
        _patch_tag(flat, mod0_off, DT_RELAENT, 8)
        return "DT_RELAENT -> 8"

    if case == "bss_end_beyond_image":
        # MOD0 fields are offsets relative to the MOD0 header: bss_end_rel sits
        # at hdr+12. Push bss_end 0x1000 past the descriptor's image end; the
        # loader's ordering rule (flat_size <= bss_start <= bss_end <=
        # image_size) must reject it instead of mapping past the image.
        old_rel = struct.unpack_from("<i", flat, mod0_off + 12)[0]
        old_end = mod0_off + old_rel
        need(old_end <= image_size,
             "bss_end_beyond_image: the fixture's bss_end is already past end")
        new_rel = (image_size - mod0_off) + 0x1000
        need(new_rel < 0x7fffffff, "bss_end_beyond_image: offset overflows")
        struct.pack_into("<i", flat, mod0_off + 12, new_rel)
        need(mod0_off + struct.unpack_from("<i", flat, mod0_off + 12)[0] >
             image_size,
             "bss_end_beyond_image mutation did not land")
        return "MOD0 bss_end -> 0x%x (image_size 0x%x)" % (old_end + 0x1000,
                                                            image_size)

    if case in ("shn_abs_symbol", "tls_symbol", "symbol_value_oob"):
        idx = _defined_symbol_index(mod)
        sym_off = tags[DT_SYMTAB] + idx * 24
        if case == "shn_abs_symbol":
            # st_shndx = SHN_ABS (0xfff1): an "absolute" definition the loader
            # does not model, so it must be rejected, not resolved to base+v.
            struct.pack_into("<H", flat, sym_off + 6, 0xfff1)
            need(struct.unpack_from("<H", flat, sym_off + 6)[0] == 0xfff1,
                 "SHN_ABS mutation did not land")
            return "dynsym[%d] st_shndx -> SHN_ABS" % idx
        if case == "tls_symbol":
            # st_info type = STT_TLS (6), binding untouched.
            info = flat[sym_off + 4]
            flat[sym_off + 4] = (info & 0xf0) | 6
            need((flat[sym_off + 4] & 0xf) == 6,
                 "STT_TLS mutation did not land")
            return "dynsym[%d] st_info type -> STT_TLS" % idx
        # st_value one past the end of what an image can contain.
        struct.pack_into("<Q", flat, sym_off + 8, image_size + 8)
        need(struct.unpack_from("<Q", flat, sym_off + 8)[0] == image_size + 8,
             "out-of-image value mutation did not land")
        return "dynsym[%d] st_value -> image_size+8" % idx

    if case == "dup_dynamic_tag":
        # A tag the loader CONSUMES may not appear twice: turn the DT_RELASZ
        # entry into a second DT_RELAENT (review fix 9).
        src = _dyn_entry_offset(flat, mod0_off, DT_RELAENT)
        dst = _dyn_entry_offset(flat, mod0_off, DT_RELASZ)
        need(src != dst, "the duplicate-tag case needs two distinct entries")
        struct.pack_into("<Q", flat, dst, DT_RELAENT)
        need(struct.unpack_from("<Q", flat, dst)[0] == DT_RELAENT,
             "duplicate-tag mutation did not land")
        return "DT_RELASZ entry -> second DT_RELAENT"

    if case == "missing_relaent":
        # DT_RELAENT becomes an unconsumed tag, so a required tag is missing.
        dst = _dyn_entry_offset(flat, mod0_off, DT_RELAENT)
        struct.pack_into("<Q", flat, dst, 0x6ffffffb)   # DT_FLAGS_1, ignored
        need(struct.unpack_from("<Q", flat, dst)[0] == 0x6ffffffb,
             "missing-RELAENT mutation did not land")
        return "DT_RELAENT -> unconsumed tag"

    if case == "relr_partial":
        # DT_RELRSZ disappears while DT_RELR stays: a partial RELR set.
        need(DT_RELR in tags and DT_RELRSZ in tags,
             "the relr-partial case needs the relr variant")
        dst = _dyn_entry_offset(flat, mod0_off, DT_RELRSZ)
        struct.pack_into("<Q", flat, dst, 0x6ffffffb)   # unconsumed
        need(struct.unpack_from("<Q", flat, dst)[0] == 0x6ffffffb,
             "relr-partial mutation did not land")
        return "DT_RELRSZ -> unconsumed tag (DT_RELR stays)"

    if case == "bad_mod0_magic":
        need(bytes(flat[mod0_off:mod0_off + 4]) == b"MOD0",
             "no MOD0 magic at the header offset")
        flat[mod0_off] = ord("X")
        need(bytes(flat[mod0_off:mod0_off + 4]) == b"XOD0",
             "MOD0 mutation did not land")
        return "MOD0 magic -> XOD0"

    raise ElfError("unknown negative case %r" % case)


def craft_negative(config_path, out_dir, neg_dir, out_c):
    """Write mutated flats + a generated case table + their descriptors."""
    cfg = json.loads(read_file(config_path).decode("utf-8"))
    thunk_base = parse_hex(cfg["thunk_base"])
    sentinel = parse_hex(cfg.get("sentinel", 0))
    overrides = sorted(cfg.get("overrides", {}).items())
    observers = sorted(cfg.get("observers", {}).items())

    out = [
        "/* Generated by tools/aot/aot_module.py craft-negative -- do not edit.",
        " *",
        " * Each descriptor carries the SHA-256 of its MUTATED image, so the",
        " * loader's exact-version check passes and the case reaches the rule it",
        " * exists to test. expected_status is the AotLoadStatus the C loader",
        " * must return (see src/aot/aot_loader.h). The pinned link digests are",
        " * zero: every case fails before the digest is compared, so a digest",
        " * match would be a false signal, not a pass.",
        " */",
        '#include "aot_g3_neg_cases.h"',
        "",
    ]
    entries = []
    for case, variant, expected, module, detail in NEG_CASES:
        mods = []
        for spec in cfg["modules"]:
            base_name = "%s_%s" % (spec["name"], variant)
            mods.append(load_module(
                os.path.join(out_dir, base_name + ".flat"),
                os.path.join(out_dir, base_name + ".layout.json"),
                base_name, parse_hex(spec["guest_base"])))
        note = mutate(mods[0], case)
        case_dir = os.path.join(neg_dir, case)
        os.makedirs(case_dir, exist_ok=True)
        shas = []
        for mod in mods:
            with open(os.path.join(case_dir, mod["name"] + ".flat"), "wb") as f:
                f.write(bytes(mod["flat"]))
            shas.append(hashlib.sha256(bytes(mod["flat"])).hexdigest())

        guard = "neg_%s" % case
        out.append("static const uint8_t %s_sha[%d][32] = {"
                   % (guard, len(mods)))
        for hexdigest in shas:
            out.append("    { %s }," % ", ".join(
                "0x%02x" % b for b in bytes.fromhex(hexdigest)))
        out.append("};")
        out.append("static const uint8_t %s_digest[%d][32] = { /* unused */"
                   % (guard, len(mods)))
        for _mod in mods:
            out.append("    { %s }," % ", ".join("0x00" for _ in range(32)))
        out.append("};")
        out.append("static const AotModuleDesc %s_modules[] = {" % guard)
        for i, mod in enumerate(mods):
            layout = mod["layout"]
            init_va = ((mod["base"] + mod["tags"][DT_INIT])
                       if DT_INIT in mod["tags"] else 0)
            out.append(
                '    { "%s", 0x%xULL, 0x%xULL, { 0x%x, 0x%x }, { 0x%x, 0x%x },'
                ' { 0x%x, 0x%x }, 0x%xULL, %du, %s_sha[%d], 0x%xULL,'
                ' %s_digest[%d] },'
                % (mod["name"], mod["base"], layout["image_size"],
                   layout["text"][0], layout["text"][1],
                   layout["ro"][0], layout["ro"][1],
                   layout["data"][0], layout["data"][1],
                   layout["bss_size"], layout["dynsym_count"],
                   guard, i, init_va, guard, i))
        out.append("};")
        for kind, table in (("overrides", overrides),
                            ("observers", observers)):
            out.append("static const AotHostBinding %s_%s[] = {"
                       % (guard, kind))
            for name, index in table:
                out.append('    { "%s", %du },' % (name, index))
            if not table:
                out.append("    { 0, 0u }, /* count is 0 */")
            out.append("};")
        out.append("static const AotHostBindings %s_bindings = {" % guard)
        out.append("    0x%xULL, 0x%xULL, %s_overrides, %du, %s_observers, %du"
                   % (thunk_base, sentinel, guard, len(overrides), guard,
                      len(observers)))
        out.append("};")
        out.append("")
        entries.append((case, case_dir, guard, len(mods), expected, module,
                        detail))
        print("craft-negative %s: %s (%s, expects %s)"
              % (case, note, variant, expected))

    out.append("const AotNegCase g_aot_g3_neg_cases[] = {")
    for case, case_dir, guard, count, expected, module, detail in entries:
        out.append('    { "%s", "%s", %s_modules, %du, &%s_bindings, %s, %du,'
                   ' "%s" },'
                   % (case, case_dir.replace(os.sep, "/"),
                      guard, count, guard, expected, module, detail))
    out.append("};")
    out.append("")
    out.append("const uint32_t g_aot_g3_neg_case_count = %du;" % len(entries))
    out.append("")
    with open(out_c, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(out))


def cmd_craft_negative(args):
    craft_negative(args.config, args.dir, args.neg_dir, args.out_c)
    return 0


def read_link_rows(path):
    """Read the reference linker's sites TSV (module/where/kind/symbol/value)."""
    text = read_file(path).decode("utf-8")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    need(lines, "%s: empty link TSV" % path)
    header = lines[0].split("\t")
    need(header[:5] == ["module", "where", "kind", "symbol", "value"],
         "%s: unexpected link TSV header %r" % (path, header))
    rows = []
    for ln in lines[1:]:
        f = ln.split("\t")
        need(len(f) == 5, "%s: malformed link TSV row %r" % (path, ln))
        rows.append(dict(module=f[0], where=int(f[1], 0), kind=int(f[2], 0),
                         symbol=f[3], value=int(f[4], 0)))
    return rows


def module_entries(flat_path, layout_path, name, guest_base, link_tsv,
                   link_module):
    """Entry set for the AOT translator, from the flat + reference link TSV.

    Exactly three sources (nothing else -- BL/BLR return sites and direct
    branch targets come from the CFG):
      1. DT_INIT;
      2. DEFINED STT_FUNC dynsym symbols whose value lands inside this
         module's text segment;
      3. relocation results (RELATIVE/ABS64/GLOB_DAT/JUMP_SLOT) whose LINK
         VALUE lands inside this module's text.
    Values are guest VAs. A VM-range value can only be an entry if the code
    behind it is reachable, so every candidate is checked against the text
    segment before it is accepted.
    """
    mod = load_module(flat_path, layout_path, name, guest_base)
    layout = mod["layout"]
    image_size = mod["image_size"]
    text_off, text_size = layout["text"]
    need(text_size > 0, "%s: empty text segment" % name)
    lo = guest_base + text_off
    hi = guest_base + text_off + text_size

    def in_text(va):
        return lo <= va < hi

    sources = {}

    def add(va, why):
        need(va % 4 == 0, "%s: entry 0x%x (%s) is not 4-byte aligned"
             % (name, va, why))
        sources.setdefault(va, []).append(why)

    dt_init = mod["tags"].get(DT_INIT)
    if dt_init is not None:
        va = guest_base + dt_init
        need(in_text(va), "%s: DT_INIT 0x%x is outside the text segment "
             "[0x%x,0x%x)" % (name, va, lo, hi))
        add(va, "DT_INIT")

    for sym in mod["syms"]:
        if sym["type"] != STT_FUNC or not sym["name"]:
            continue
        if not sym_defined(sym, image_size):
            continue
        va = guest_base + sym["value"]
        if in_text(va):
            add(va, "sym:%s" % sym["name"])

    link_rows = 0
    for row in read_link_rows(link_tsv):
        if row["module"] != link_module:
            continue
        link_rows += 1
        need(row["kind"] in KIND_NAMES,
             "%s: relocation kind %d is not a G3 module relocation"
             % (link_tsv, row["kind"]))
        if in_text(row["value"]):
            add(row["value"], "link:%s(%s)" % (row["symbol"],
                                                KIND_NAMES[row["kind"]]))

    # A typo in --link-module used to yield "no entries" (or, worse, entries
    # derived only from symbols); require the TSV to actually cover it.
    need(link_rows > 0,
         "%s: the link TSV %s has no relocation row for module %r "
         "(typo in --link-module?)" % (name, link_tsv, link_module))
    entries = sorted(sources)
    return dict(name=name, guest_base="0x%x" % guest_base,
                module=link_module,
                text=["0x%x" % lo, "0x%x" % hi],
                entries=["0x%x" % va for va in entries],
                sources={"0x%x" % va: sources[va] for va in entries})


def cmd_entries(args):
    result = module_entries(args.flat, args.layout, args.name,
                            parse_hex(args.guest_base), args.link,
                            args.link_module)
    need(result["entries"], "%s: no entries found (nothing to translate)"
         % args.name)
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(result, f, indent=2, sort_keys=True)
        f.write("\n")
    print("%s: %d entries in text [%s,%s)"
          % (args.name, len(result["entries"]), result["text"][0],
             result["text"][1]))
    return 0


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_nso = sub.add_parser(
        "nso2flat",
        help="real NSO0 -> flat image + layout.json (pinned, hash-verified)")
    p_nso.add_argument("--nso-dir", dest="nso_dir", required=True,
                       help="directory containing main/subsdk0/sdk NSOs")
    p_nso.add_argument("--out-dir", dest="out_dir", required=True,
                       help="output directory (must be outside the repository)")
    p_nso.add_argument("--modules", nargs="+",
                       default=["main", "subsdk0", "sdk"])
    p_nso.add_argument("--expected", default=None,
                       help="expected-v1.0.0.json (default: this tree's)")
    p_nso.add_argument("--verbose", action="store_true")

    p_flat = sub.add_parser("elf2flat", help="ELF -> NSO-like flat image")
    p_flat.add_argument("--elf", required=True)
    p_flat.add_argument("--name", required=True)
    p_flat.add_argument("--out-dir", required=True)
    p_flat.add_argument("--verbose", action="store_true")

    p_shadow = sub.add_parser(
        "shadow-undefined",
        help="TEST FIXTURE: rename an UNDEFINED dynsym entry to a DEFINED "
             "symbol's name (builds the `shadow` link variant)")
    p_shadow.add_argument("--elf", required=True)
    p_shadow.add_argument("--undef", required=True,
                          help="existing UNDEFINED symbol to repurpose")
    p_shadow.add_argument("--with", required=True, dest="with_name",
                          help="DEFINED symbol whose name it takes")
    p_shadow.add_argument("--verbose", action="store_true")

    p_link = sub.add_parser(
        "link", help="reference linker: flat images -> sites TSV + counters")
    p_link.add_argument("--config", required=True,
                        help="link_config.json (module order, bases, tables)")
    p_link.add_argument("--dir", required=True, help="directory with flats")
    p_link.add_argument("--variant", required=True)
    p_link.add_argument("--out-tsv", required=True)
    p_link.add_argument("--out-counters", required=True)

    p_desc = sub.add_parser(
        "emit-desc", help="reference linker -> generated AotModuleDesc C")
    p_desc.add_argument("--config", required=True)
    p_desc.add_argument("--dir", required=True)
    p_desc.add_argument("--variant", required=True)
    p_desc.add_argument("--out-c", required=True)
    p_desc.add_argument("--images", default=None,
                        help='JSON {"<module>": "<image symbol>"} for modules '
                             'with a locally generated AotImage; the rest stay '
                             'link-only (image == NULL)')

    p_neg = sub.add_parser(
        "craft-negative",
        help="mutated flats + descriptors for the loader's error paths")
    p_neg.add_argument("--config", required=True)
    p_neg.add_argument("--dir", required=True,
                       help="directory with the GOOD flats (link output)")
    p_neg.add_argument("--neg-dir", required=True,
                       help="directory to write the mutated flats into")
    p_neg.add_argument("--out-c", required=True)

    p_ent = sub.add_parser(
        "entries",
        help="AOT entry set for one module (DT_INIT, STT_FUNC, link values)")
    p_ent.add_argument("--flat", required=True)
    p_ent.add_argument("--layout", required=True)
    p_ent.add_argument("--name", required=True)
    p_ent.add_argument("--guest-base", dest="guest_base", required=True)
    p_ent.add_argument("--link", required=True,
                       help="reference linker sites TSV")
    p_ent.add_argument("--link-module", dest="link_module", required=True,
                       help="module column value of THIS module in the TSV")
    p_ent.add_argument("--out", required=True)

    args = ap.parse_args(argv)
    try:
        if args.cmd == "elf2flat":
            elf2flat(args.elf, args.name, args.out_dir, args.verbose)
            return 0
        if args.cmd == "shadow-undefined":
            shadow_undefined(args.elf, args.undef, args.with_name, args.verbose)
            return 0
        if args.cmd == "nso2flat":
            return cmd_nso2flat(args)
        if args.cmd == "link":
            result = link_modules(args.config, args.dir, args.variant)
            write_link_outputs(result, args.out_tsv, args.out_counters)
            total = dict.fromkeys(("relative", "symbolic", "cross", "weak"), 0)
            for c in result["counters"].values():
                for k in total:
                    total[k] += c[k]
            print("%s: %d sites (relative=%d symbolic=%d cross=%d weak=%d) "
                  "link_digest=%s"
                  % (args.variant, len(result["sites"]), total["relative"],
                     total["symbolic"], total["cross"], total["weak"],
                     result["link_digest"][:16]))
            return 0
        if args.cmd == "craft-negative":
            return cmd_craft_negative(args)
        if args.cmd == "entries":
            return cmd_entries(args)
        if args.cmd == "emit-desc":
            result = link_modules(args.config, args.dir, args.variant)
            images = None
            if args.images:
                with open(args.images, encoding="utf-8") as f:
                    images = json.load(f)
                if not isinstance(images, dict) or not all(
                        isinstance(k, str) and isinstance(v, str)
                        for k, v in images.items()):
                    raise ValueError("--images must be a JSON object of "
                                     "module name -> image symbol")
            emit_desc(result, args.out_c, args.dir, images)
            print("%s: wrote %s" % (args.variant, args.out_c))
            return 0
    except (ElfError, LinkError) as exc:
        print("aot_module.py: %s: %s"
              % (getattr(args, "variant", args.cmd), exc), file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, struct.error,
            json.JSONDecodeError) as exc:
        # Review fix 15: malformed input (truncated/garbled image, missing file,
        # bad JSON) is a typed, single-line error with a non-zero exit -- never
        # a Python traceback, which would look like a tool crash.
        print("aot_module.py: %s: %s: %s"
              % (getattr(args, "variant", args.cmd),
                 type(exc).__name__, exc), file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
