#!/usr/bin/env python3
"""Bounded, MODULE-ONLY local jump-table CFG edge proof.

This module recovers *intra-function* successors for one exact, guarded
byte-table switch form observed in module text:

    cmp  Xidx, #N              ; SUBS XZR, Xidx, #N  (64-bit, unshifted imm)
    b.hi DEFAULT               ; the only admitted guard
    adr  Xlabel, L             ; 4-byte aligned label inside the owner function
    ldrb Woff, [Xtab, Xidx]    ; unsigned register offset, LSL #0, unextended
    add  Xtarget, Xlabel, Xoff, LSL #2
    br   Xtarget

The recovered entries are CFG EDGES, never function roots, never a new entry
class.  The caller supplies the already-reached branch sites plus the current
root set and known edge graph; this module never discovers a new module entry
of its own and refuses (typed) rather than falling back.

Trust boundary (deliberate):
  * `Context` snapshots the raw flat bytes, the layout, the guest base and the
    injected decoder at construction; later mutation of the caller's objects
    cannot change a proof.
  * Symbols, relocation sites/tables and loader-consumed metadata extents are
    re-derived from that snapshot, and the snapshot's SHA-256 must equal the
    layout SHA-256.
  * The table base is proven by static dataflow inside the owner function
    (an adjacent ADRP+ADD pair that dominates the load and has no alternative
    entry).  The runtime value observed by a reboot is NOT an input.
  * The table bytes must live wholly inside the immutable read-only segment,
    outside every defined sized symbol, relocation slot and loader-consumed
    metadata extent, and no selector outside `cmp #N` is admitted.
  * Every byte of the N+1 table is used to derive the COMPLETE target set; the
    observed runtime selector is not consulted.

Not claimed: full code/data separation.  An unannotated literal word inside a
declared STT_FUNC extent cannot be distinguished from code in general; the
proof relies on the declared function extent and the pinned immutable module.

Called only offline.  No ARM64 is decoded at runtime by this module.
"""

import copy
import hashlib
import struct

import aot_module as M

__all__ = ["Context", "Proof", "InputError", "ProofError", "Refusal"]

# ---------------------------------------------------------------- errors


class InputError(Exception):
    """Bad context / layout / ELF metadata (construction or inputs)."""


class ProofError(Exception):
    """A recognised switch site failed its proof (whole module must fail)."""


class Refusal(ProofError):
    """Recognised shape, insufficient evidence for a bounded local edge."""


# ---------------------------------------------------------------- helpers

_PAGE = 0x1000
_U64 = (1 << 64) - 1


def _chk(cond, msg, cls=InputError):
    if not cond:
        raise cls(msg)


def _sx(value, bits):
    sign = 1 << (bits - 1)
    return ((value & (sign - 1)) - (value & sign))


def _raw_branch_target(word, pc):
    """Direct PC-relative branch target from raw bits, or None.

    Detects B/BL, B.cond, CBZ/CBNZ and TBZ/TBNZ. Used only for the
    conservative incoming-threat scan.
    """
    if (word & 0x7C000000) == 0x14000000:          # B / BL
        return pc + _sx((word & 0x03FFFFFF) << 2, 28)
    if (word & 0xFF000010) == 0x54000000:          # B.cond
        return pc + _sx(((word >> 5) & 0x7FFFF) << 2, 21)
    if (word & 0x7E000000) in (0x34000000, 0x36000000):
        # CBZ/CBNZ (imm19) and TBZ/TBNZ (imm14)
        if (word & 0x7E000000) == 0x34000000:
            return pc + _sx(((word >> 5) & 0x7FFFF) << 2, 21)
        return pc + _sx(((word >> 5) & 0x3FFF) << 2, 16)
    return None


def _sha(data):
    return hashlib.sha256(bytes(data)).hexdigest()


def _overlap(a_lo, a_hi, b_lo, b_hi):
    return a_lo < b_hi and b_lo < a_hi


def _sat_add(a, b):
    """Checked 64-bit add; None on wrap."""
    out = a + b
    return None if out > _U64 else out


# Decoded field descriptions of the six-word window, cross-checked against the
# injected decoder.  Raw fixed bits are independent of the decoder.
_CMP_MASK = 0xFFC0001F      # sf op S 100010 sh, Rd
_CMP_VAL = 0xF100001F       # 64-bit SUBS, unshifted, Rd=31 (XZR)
_BCOND_MASK = 0xFF000010
_BCOND_VAL = 0x54000000     # B.cond, bit4 zero; cond checked separately (8=HI)
_ADR_MASK = 0x9F000000
_ADR_VAL = 0x10000000
_LDRB_MASK = 0xFFE0FC00
_LDRB_VAL = 0x38606800      # size=00 opc=01 option=011 (LSL) S=0
_ADD_MASK = 0xFFE0FC00
_ADD_VAL = 0x8B000800       # 64-bit ADD shifted, shift=00, imm6=2
_BR_MASK = 0xFFFFFC1F
_BR_VAL = 0xD61F0000


def _adr_value(pc, word):
    imm = (((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 3)
    return (pc + _sx(imm, 21)) & _U64


class _Window(object):
    """Fully decoded, raw-bit-verified switch window."""

    __slots__ = ("pc", "n", "idx", "default", "label", "tab", "off", "target",
                 "br_reg", "words", "pcs")


def matches_shape(raw, base, br_pc):
    """Cheap raw-bit match of the exact six-word form (no metadata parse).

    Used by the module pipeline to decide whether a Context must be created at
    all.  It is only a filter: a match never admits a site without the full
    Context proof.
    """
    pcs = [br_pc - 20, br_pc - 16, br_pc - 12, br_pc - 8, br_pc - 4, br_pc]
    if any((pc - base) % 4 or pc - base < 0 or pc - base + 4 > len(raw)
           for pc in pcs):
        return False
    words = [struct.unpack_from("<I", raw, pc - base)[0] for pc in pcs]
    return ((words[5] & _BR_MASK) == _BR_VAL
            and (words[4] & _ADD_MASK) == _ADD_VAL
            and (words[3] & _LDRB_MASK) == _LDRB_VAL
            and (words[2] & _ADR_MASK) == _ADR_VAL
            and (words[1] & _BCOND_MASK) == _BCOND_VAL
            and (words[1] & 0xF) == 8
            and (words[0] & _CMP_MASK) == _CMP_VAL)


def _decode_window(raw, base, br_pc, decode):
    """Match the exact six-word form at `br_pc`.

    Returns a `_Window` or None when the raw bits are a different BR idiom
    (other BRs stay unhandled).  Raises ProofError when the raw form matches
    but the injected decoder disagrees -- a recognised site must not fall back.
    """
    pcs = [br_pc - 20, br_pc - 16, br_pc - 12, br_pc - 8, br_pc - 4, br_pc]
    if any((pc - base) % 4 or pc - base < 0 or pc - base + 4 > len(raw)
           for pc in pcs):
        return None
    words = [struct.unpack_from("<I", raw, pc - base)[0] for pc in pcs]
    if (words[5] & _BR_MASK) != _BR_VAL:
        return None
    if (words[4] & _ADD_MASK) != _ADD_VAL:
        return None
    if (words[3] & _LDRB_MASK) != _LDRB_VAL:
        return None
    if (words[2] & _ADR_MASK) != _ADR_VAL:
        return None
    if (words[1] & _BCOND_MASK) != _BCOND_VAL or (words[1] & 0xF) != 8:
        return None
    if (words[0] & _CMP_MASK) != _CMP_VAL:
        return None

    cmp_pc, bc_pc, adr_pc, ldr_pc, add_pc = pcs[:5]
    idx = (words[0] >> 5) & 0x1F
    n = (words[0] >> 10) & 0xFFF
    label_reg = (words[2] & 0x1F)
    label = _adr_value(adr_pc, words[2])
    ld_rm = (words[3] >> 16) & 0x1F
    ld_tab = (words[3] >> 5) & 0x1F
    ld_rt = words[3] & 0x1F
    add_rm = (words[4] >> 16) & 0x1F
    add_rn = (words[4] >> 5) & 0x1F
    add_rd = words[4] & 0x1F
    br_rn = (words[5] >> 5) & 0x1F

    # Cross-check decoder semantics field by field.  Every trip is a refusal,
    # never a fallback to a different idiom.
    def _dec(pc, word, kind):
        try:
            ins = decode(pc, word, module=True)
        except Exception as exc:  # noqa: BLE001 - typed refusal below
            raise Refusal("decoder refused 0x%x at 0x%x (%s)" % (word, pc, exc))
        if not isinstance(ins, dict) or ins.get("kind") != kind:
            raise Refusal("decoder kind %r != %s at 0x%x"
                          % (ins.get("kind") if isinstance(ins, dict) else ins,
                             kind, pc))
        return ins

    c = _dec(cmp_pc, words[0], "addsub_imm")
    if not (c.get("op") == 1 and c.get("s") == 1 and c.get("width") == 64
            and c.get("rd") == 31 and c.get("rn") == idx
            and c.get("imm") == n):
        raise Refusal("CMP shape mismatch at 0x%x" % cmp_pc)
    b = _dec(bc_pc, words[1], "bcond")
    if b.get("cond") != 8:
        raise Refusal("guard is not B.HI at 0x%x" % bc_pc)
    a = _dec(adr_pc, words[2], "adr")
    if a.get("rd") != label_reg or a.get("value") != label:
        raise Refusal("ADR shape mismatch at 0x%x" % adr_pc)
    l = _dec(ldr_pc, words[3], "ldst_regoff")
    if not (l.get("size") == 0 and l.get("opc") == 1
            and l.get("option") == 3 and l.get("shift") == 0
            and l.get("rm") == idx and l.get("rn") == ld_tab
            and l.get("rt") == ld_rt):
        raise Refusal("LDRB shape mismatch at 0x%x" % ldr_pc)
    ad = _dec(add_pc, words[4], "addsub_shift")
    if not (ad.get("op") == 0 and ad.get("s") == 0
            and ad.get("shift") == 0 and ad.get("imm6") == 2
            and ad.get("width") == 64 and ad.get("rm") == ld_rt
            and ad.get("rn") == label_reg and ad.get("rd") == add_rd):
        raise Refusal("shifted ADD shape mismatch at 0x%x" % add_pc)
    br = _dec(br_pc, words[5], "br")
    if br.get("rn") != add_rd:
        raise Refusal("BR does not consume the ADD result at 0x%x" % br_pc)
    # Register-31 is ZR, never SP, in every one of these operand positions.
    if 31 in (label_reg, idx, ld_tab, ld_rt, add_rd, br_rn):
        raise Refusal("ZR used as a switch operand")
    # The label register may not also carry the index or the table base, the
    # LDRB destination may not overwrite the label, and the ADD destination
    # may not consume the index/table base positions.
    if label_reg in (idx, ld_tab) or ld_rt == label_reg:
        raise Refusal("switch operand registers alias (label w%d)"
                      % label_reg)
    if add_rd in (idx, ld_tab):
        raise Refusal("ADD destination aliases an index/table register")

    w = _Window()
    w.pc = br_pc
    w.n = n
    w.idx = idx
    w.default = b.get("target")
    w.label = label
    w.tab = ld_tab
    w.off = ld_rt
    w.target = add_rd
    w.br_reg = br_rn
    w.words = tuple(words)
    w.pcs = tuple(pcs)
    return w


# Write sets for the conservative intra-function dataflow.  Anything not in
# this table kills every register (the Opus-approved conservative profile);
# calls/SVC/host boundaries kill all explicitly because they may clobber the
# whole guest argument/scratch range.
_KILL_ALL = frozenset(range(31))
_STT_OBJECT = getattr(M, "STT_OBJECT", 1)

# Capstone is an existing pinned AOT dependency (used by the independent CFG
# and oracle tools).  It is used here ONLY offline, on the ORIGINAL instruction
# words, to derive the conservative write-kill set.  No ARM64 is decoded at
# runtime and the G2 translator never imports this module.
try:
    from capstone import Cs as _Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    import capstone.arm64 as _A64
except Exception as _exc:  # pragma: no cover - environment failure
    _Cs = None
    _CAPSTONE_ERROR = _exc
else:
    _CAPSTONE_ERROR = None


def _new_analyzer():
    if _Cs is None:
        raise InputError("Capstone is required for the local switch prover: %s"
                         % _CAPSTONE_ERROR)
    md = _Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    return md


def _reg_number(reg):
    """Map a Capstone ARM64 register id to guest GPR 0..30 (or None).

    A write to Wn kills Xn (the 32-bit write zero-extends into the 64-bit
    register), so both halves map to the same number.  SP/WSP, XZR/WZR and
    non-GPR (vector/system) registers are not tracked.
    """
    if _A64.ARM64_REG_X0 <= reg <= _A64.ARM64_REG_X28:
        return reg - _A64.ARM64_REG_X0
    if reg == _A64.ARM64_REG_X29:
        return 29
    if reg == _A64.ARM64_REG_X30:
        return 30
    if _A64.ARM64_REG_W0 <= reg <= _A64.ARM64_REG_W30:
        return reg - _A64.ARM64_REG_W0
    return None


def _capstone_writes(md, pc, word):
    """Registers written by the original word, or _KILL_ALL if unknown."""
    try:
        insns = list(md.disasm(struct.pack("<I", word), pc))
    except Exception:
        return _KILL_ALL
    if len(insns) != 1:
        return _KILL_ALL
    try:
        _read, written = insns[0].regs_access()
    except Exception:
        return _KILL_ALL
    out = set()
    for reg in written:
        num = _reg_number(reg)
        if num is not None:
            out.add(num)
    return frozenset(out)


def _succ(ins):
    """Intra-function successors for the decoded subset; unknown => []."""
    k = ins.get("kind")
    pc = ins.get("pc")
    if k == "b":
        t = ins.get("target")
        return [t] if isinstance(t, int) else []
    if k in ("bcond", "cbz", "cbnz", "tbz", "tbnz", "bl"):
        t = ins.get("target")
        return [t, pc + 4] if isinstance(t, int) else [pc + 4]
    if k in ("blr", "svc", "mrs_counter"):
        return [pc + 4]
    if k in ("br", "ret", "unsupported", "barrier", "nop"):
        return [pc + 4] if k in ("barrier", "nop") else []
    return [pc + 4]


class Proof(object):
    """Immutable, deep-copyable site-local edge proof."""

    __slots__ = ("_f")

    def __init__(self, **fields):
        for k, v in sorted(fields.items()):
            if isinstance(v, (list, set)):
                v = tuple(sorted(v) if isinstance(v, set) else v)
            elif isinstance(v, dict):
                v = tuple(sorted((kk, v[kk]) for kk in v))
            fields[k] = v
        object.__setattr__(self, "_f", tuple(sorted(fields.items())))

    def __setattr__(self, name, value):
        raise Refusal("Proof is frozen")

    def __getattr__(self, name):
        for k, v in object.__getattribute__(self, "_f"):
            if k == name:
                return v
        raise AttributeError(name)

    def keys(self):
        return [k for k, _ in object.__getattribute__(self, "_f")]

    def with_closure(self, value):
        """Return a copy with a different audit-only closure marker.

        Only the module pipeline may promote a proof to
        `verified-final-graph`, and only after the final revalidation ran on
        the complete graph. The proven fields are unchanged.
        """
        fields = dict(object.__getattribute__(self, "_f"))
        fields["closure"] = value
        return Proof(**fields)

    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self                 # frozen: fields are tuples / scalars

    def to_dict(self):
        return copy.deepcopy(dict(object.__getattribute__(self, "_f")))

    def __repr__(self):
        return "Proof(%s)" % ", ".join(
            "%s=%r" % (k, v) for k, v in object.__getattribute__(self, "_f"))


class Context(object):
    """Immutable snapshot of one module's bytes, layout, base and decoder."""

    def __setattr__(self, name, value):
        if getattr(self, "_frozen", False):
            raise InputError("Context is immutable after construction")
        object.__setattr__(self, name, value)

    @property
    def layout(self):
        return copy.deepcopy(self._layout)

    @property
    def tags(self):
        return copy.deepcopy(self._tags)

    @property
    def syms(self):
        return copy.deepcopy(self._syms)

    def __init__(self, raw, layout, base, decode):
        _chk(isinstance(raw, (bytes, bytearray, memoryview)),
             "raw must be bytes-like")
        _chk(isinstance(layout, dict), "layout must be a dict")
        _chk(isinstance(base, int) and not isinstance(base, bool),
             "base must be an int")
        _chk(callable(decode), "decode must be callable")
        _chk(base >= 0 and base % _PAGE == 0, "base is not 4 KiB aligned")
        self.raw = bytes(raw)
        self._layout = copy.deepcopy(layout)
        self.base = base
        self.decode = decode
        self.sha256 = _sha(self.raw)
        self._md = _new_analyzer()
        lay = self._layout
        d = hashlib.sha256(self.raw).hexdigest()
        _chk(lay.get("sha256") == d,
             "raw SHA-256 0x%s != layout sha256 %r" % (d[:16], lay.get("sha256")))
        for key in ("image_size", "bss_size", "dynsym_count", "mod0_off",
                    "text", "ro", "data"):
            _chk(key in lay, "layout is missing %r" % key)
        image = lay["image_size"]
        _chk(isinstance(image, int) and not isinstance(image, bool)
             and image > 0, "bad image_size")
        _chk(isinstance(lay["bss_size"], int)
             and not isinstance(lay["bss_size"], bool)
             and lay["bss_size"] >= 0, "bad bss_size")
        _chk(isinstance(lay["mod0_off"], int)
             and not isinstance(lay["mod0_off"], bool)
             and lay["mod0_off"] >= 0, "bad mod0_off")
        _chk(isinstance(lay["dynsym_count"], int)
             and not isinstance(lay["dynsym_count"], bool)
             and lay["dynsym_count"] >= 1, "bad dynsym_count")
        _chk(len(self.raw) == image - lay["bss_size"],
             "raw size 0x%x != image_size - bss 0x%x"
             % (len(self.raw), image - lay["bss_size"]))
        _chk(8 <= len(self.raw), "raw image too small")
        for seg in ("text", "ro", "data"):
            v = lay[seg]
            _chk(isinstance(v, (list, tuple)) and len(v) == 2
                 and all(isinstance(x, int) and not isinstance(x, bool)
                         for x in v),
                 "layout %s must be [offset, size]" % seg)
            _chk(v[0] % _PAGE == 0,
                 "layout %s does not start on a page boundary" % seg)
            _chk(v[0] >= 0 and v[1] >= 0 and v[0] + v[1] <= image,
                 "layout %s outside the image" % seg)
        _chk(lay["text"][1] > 0, "empty text")
        segs = [(name, lay[name][0], lay[name][0] + lay[name][1])
                for name in ("text", "ro", "data")]
        for i in range(len(segs)):
            for j in range(i + 1, len(segs)):
                a, b = segs[i], segs[j]
                _chk(not _overlap(a[1], a[2], b[1], b[2]),
                     "layout %s and %s overlap" % (a[0], b[0]))
        _chk(segs[0][2] <= segs[1][1] and segs[1][2] <= segs[2][1],
             "layout segments are not ordered text < ro < data")
        self._text = (base + lay["text"][0], base + lay["text"][0] + lay["text"][1])
        self._ro = (base + lay["ro"][0], base + lay["ro"][0] + lay["ro"][1])
        self._data = (base + lay["data"][0],
                      base + lay["data"][0] + lay["data"][1])
        self._snapshot_symbols_and_metadata()
        object.__setattr__(self, "_br_cache", None)
        object.__setattr__(self, "_frozen", True)

    # -- construction-time metadata snapshot ------------------------------
    def _snapshot_symbols_and_metadata(self):
        raw, lay, image = self.raw, self._layout, self._layout["image_size"]
        mod0 = lay["mod0_off"]
        _chk(0 <= mod0 <= len(raw) - 32, "MOD0 offset out of image")
        _chk(bytes(raw[mod0:mod0 + 4]) == b"MOD0", "no MOD0 magic")
        bss_start = mod0 + struct.unpack_from("<i", raw, mod0 + 8)[0]
        bss_end = mod0 + struct.unpack_from("<i", raw, mod0 + 12)[0]
        _chk(len(raw) <= bss_start <= bss_end <= image,
             "MOD0 bss range is not ordered inside the image")
        data_off, data_size = lay["data"]
        try:
            tags = M.read_dynamic(raw, mod0, image, data_off, data_size)
            syms = M.parse_dynsyms(raw, tags, lay["dynsym_count"])
            M.validate_symbols(lay.get("name", "<module>"), syms, image)
        except (M.ElfError, struct.error, ValueError, TypeError,
                KeyError, IndexError) as exc:  # typed metadata failures
            raise InputError("ELF metadata: %s" % exc)
        self._tags = dict(tags)
        self._syms = [dict(x) for x in syms]
        unsupported = {17: "DT_REL", 18: "DT_RELSZ", 19: "DT_RELENT",
                       0x6ffffff0: "DT_VERSYM", 0x6ffffffc: "DT_VERDEF",
                       0x6ffffffd: "DT_VERDEFNUM", 0x6ffffffe: "DT_VERNEED",
                       0x6fffffff: "DT_VERNEEDNUM"}
        for tag, name in unsupported.items():
            _chk(tag not in tags, "unsupported consumed dynamic tag %s" % name)
        if M.DT_JMPREL in tags:
            _chk(tags.get(M.DT_PLTREL) == 7,
                 "DT_PLTREL must be RELA (7) when DT_JMPREL is present")
        self._text_off = lay["text"][0]
        self._defined = []
        for s in self._syms:
            if M.sym_defined(s, image) and s["size"] > 0:
                self._defined.append(s)
        # Loader-consumed metadata extents (image offsets).
        ext = [("mod0", mod0, mod0 + 32)]
        dyn_end = self._dynamic_end(mod0, image)
        ext.append((".dynamic", mod0 + struct.unpack_from("<i", raw, mod0 + 4)[0],
                    dyn_end))
        symtab = tags.get(M.DT_SYMTAB)
        strtab = tags.get(M.DT_STRTAB)
        strsz = tags.get(M.DT_STRSZ, 0)
        if symtab is not None:
            ext.append((".dynsym", symtab, symtab + 24 * lay["dynsym_count"]))
        if strtab is not None:
            ext.append((".dynstr", strtab, strtab + strsz))
        if M.DT_HASH in tags:
            h = tags[M.DT_HASH]
            _chk(isinstance(h, int) and not isinstance(h, bool) and h >= 0,
                 "DT_HASH address is not a non-negative int")
            _chk(h + 8 <= len(raw), "DT_HASH outside image")
            # DT_HASH layout is {nbucket, nchain, bucket[nbucket],
            # chain[nchain]}.  The CONSUMED extent therefore covers BOTH arrays;
            # an nbuckets-omitting extent would leave the bucket words
            # (non-zero hashes, i.e. known DATA) outside every exclusion.
            nbucket = struct.unpack_from("<I", raw, h)[0]
            nchain = struct.unpack_from("<I", raw, h + 4)[0]
            hash_end = h + 8 + 4 * (nbucket + nchain)
            _chk(hash_end <= len(raw),
                 "DT_HASH extent [0x%x,0x%x) outside image (nbucket=%d "
                 "nchain=%d)" % (h, hash_end, nbucket, nchain))
            ext.append((".hash", h, hash_end))
        if getattr(M, "DT_GNU_HASH", None) in tags:
            ext.append((".gnu.hash",) + self._gnu_hash_extent(tags[M.DT_GNU_HASH]))
        for label, addr_tag, size_tag in (
                (".rela", M.DT_RELA, M.DT_RELASZ),
                (".jmprel", M.DT_JMPREL, M.DT_PLTRELSZ),
                (".relr", M.DT_RELR, M.DT_RELRSZ)):
            if addr_tag in tags or size_tag in tags:
                _chk(addr_tag in tags and size_tag in tags,
                     "%s address/size tags are unpaired" % label)
                lo, sz = tags[addr_tag], tags[size_tag]
                _chk(lo + sz <= image, "%s extent outside the image" % label)
                ext.append((label, lo, lo + sz))
        # MOD0+16/+20 are SIGNED OFFSETS RELATIVE TO MOD0 (not absolute image
        # offsets); the consumed EH-frame-header interval is [mod0+start,
        # mod0+end).
        eh_rel_start = struct.unpack_from("<i", raw, mod0 + 16)[0]
        eh_rel_end = struct.unpack_from("<i", raw, mod0 + 20)[0]
        if eh_rel_start or eh_rel_end:
            _chk((eh_rel_start > 0) == (eh_rel_end > 0),
                 "MOD0 EH-frame-header offset/size are unpaired")
            eh_start = mod0 + eh_rel_start
            eh_end = mod0 + eh_rel_end
            _chk(0 <= eh_start <= eh_end <= image,
                 "MOD0 EH-frame-header interval is invalid")
            ext.append(("eh_frame_hdr", eh_start, eh_end))
            # M1: a PRESENT EH-frame header must be completely inside the
            # module's own RO segment.  Silently skipping the frame exclusion
            # when it is not would be fail-open; it is a typed context error.
            ro_start, ro_end = lay["ro"][0], lay["ro"][0] + lay["ro"][1]
            _chk(ro_start <= eh_start and eh_end <= ro_end,
                 "MOD0 EH-frame-header interval [0x%x,0x%x) is not fully "
                 "inside the module RO segment [0x%x,0x%x)"
                 % (eh_start, eh_end, ro_start, ro_end))
            # The consumed .eh_frame section extent is not guessed: the whole
            # read-only suffix from the header is excluded as an explicit
            # over-approximation (recorded, not claimed exact) and covers the
            # complete parsed interval.
            ext.append(("eh_frame_ro_suffix_overapprox", eh_start, ro_end))
        # DT_PREINIT_ARRAY/SZ are consumed by the loader exactly like the
        # init/fini arrays: a present pair is a consumed interval; an
        # unpaired appearance is a context error (32 = PREINIT_ARRAY,
        # 33 = PREINIT_ARRAYSZ).
        for name, addr_tag, size_tag in (
                ("init_array", 25, 27), ("fini_array", 26, 28),
                ("preinit_array", 32, 33)):
            if addr_tag in tags or size_tag in tags:
                _chk(addr_tag in tags and size_tag in tags,
                     "DT_%s address/size tags are unpaired"
                     % name.upper())
                lo, sz = tags[addr_tag], tags[size_tag]
                _chk(isinstance(lo, int) and isinstance(sz, int)
                     and lo >= 0 and sz >= 0 and lo + sz <= image,
                     "DT_%s interval is invalid" % name.upper())
                ext.append((".%s" % name, lo, lo + sz))
        for label, lo, hi in ext:
            _chk(0 <= lo <= hi <= image,
                 "metadata extent %s [0x%x,0x%x) is invalid" % (label, lo, hi))
        self._extents = tuple(ext)

        sites = []
        try:
            for addr_tag, size_tag, name in (
                    (M.DT_RELA, M.DT_RELASZ, "RELA"),
                    (M.DT_JMPREL, M.DT_PLTRELSZ, "JMPREL")):
                if addr_tag in tags:
                    for e in M.parse_rela_table(raw, tags[addr_tag],
                                                tags[size_tag], image, name):
                        _chk(e["where"] % 8 == 0,
                             "%s site 0x%x is not 8-byte aligned"
                             % (name, e["where"]))
                        sites.append((e["where"], name))
            if M.DT_RELR in tags:
                for where in M.decode_relr(raw, tags[M.DT_RELR],
                                           tags[M.DT_RELRSZ], image):
                    sites.append((where, "RELR"))
        except Exception as exc:  # noqa: BLE001
            raise InputError("relocation metadata: %s" % exc)
        self._reloc_sites = tuple(sorted(sites))

    def _dynamic_end(self, mod0, image):
        off = mod0 + struct.unpack_from("<i", self.raw, mod0 + 4)[0]
        _chk(0 <= off <= image - 16 and off % 8 == 0,
             "MOD0 dynamic offset 0x%x out of image" % off)
        while True:
            _chk(off + 16 <= image, "unterminated .dynamic")
            tag = struct.unpack_from("<Q", self.raw, off)[0]
            off += 16
            if tag == 0:
                return off

    def _gnu_hash_extent(self, addr):
        raw = self.raw
        _chk(addr + 16 <= len(raw), "DT_GNU_HASH outside image")
        nbuckets, symoff, bloom_size, _shift = struct.unpack_from("<IIII", raw, addr)
        _chk(symoff <= self._layout["dynsym_count"],
             "DT_GNU_HASH symoffset past dynsym_count")
        end = addr + 16 + bloom_size * 8 + nbuckets * 4
        end += (self._layout["dynsym_count"] - symoff) * 4
        _chk(end <= len(raw), "DT_GNU_HASH chains outside image")
        return addr, end

    # -- lookup helpers ----------------------------------------------------
    def _owner(self, br_pc):
        """Unique owning DEFINED sized STT_FUNC containing the BR."""
        syms = self._defined
        cands = [s for s in syms if s["type"] == M.STT_FUNC
                 and self.base + s["value"] <= br_pc
                 < self.base + s["value"] + s["size"]]
        spans = {(s["value"], s["size"]) for s in cands}
        _chk(len(spans) == 1,
             "BR at 0x%x has %d distinct owning FUNC spans"
             % (br_pc, len(spans)), Refusal)
        value, size = spans.pop()
        lo, hi = self.base + value, self.base + value + size
        _chk(lo % 4 == 0 and hi % 4 == 0, "owner FUNC span is not 4-aligned")
        t_lo, t_hi = self._text
        _chk(t_lo <= lo and hi <= t_hi,
             "owner FUNC span is not fully inside module TEXT")
        name = sorted(s["name"] for s in cands)[0]
        return dict(name=name, start=lo, end=hi, size=size, value=value)

    def _reject_symbol_overlaps(self, owner, ranges):
        """Table/proof/target words must not be declared symbol storage."""
        for lo, hi, what in ranges:
            if not _overlap(lo, hi, owner["start"], owner["end"]):
                continue
            for s in self._defined:
                s_lo = self.base + s["value"]
                s_hi = s_lo + s["size"]
                if not _overlap(lo, hi, s_lo, s_hi):
                    continue
                alias = (s["type"] == M.STT_FUNC
                         and s["value"] == owner["value"]
                         and s["size"] == owner["size"])
                if alias:
                    continue
                _chk(False,
                     "%s [0x%x,0x%x) overlaps defined symbol %r (type %d, "
                     "[0x%x,0x%x))" % (what, lo, hi, s["name"], s["type"],
                                       s_lo, s_hi), Refusal)

    # -- narrow read-only metadata API -------------------------------------
    # Root-selection policy (e.g. tools/aot/g3_ctor_roots.py) needs the SAME
    # consumed-metadata extents and symbol storage this context already
    # validated.  These accessors expose copies; they add no policy and
    # mutate nothing.
    def metadata_extents(self):
        """((label, image_off_lo, image_off_hi), ...) consumed metadata."""
        return tuple((label, lo, hi) for label, lo, hi in self._extents)

    def relocation_sites(self):
        """((image_off, table_label), ...) every relocation site."""
        return tuple(self._reloc_sites)

    def defined_symbols(self):
        """Every DEFINED dynsym (size 0 included) as a dict copy."""
        image = self._layout["image_size"]
        return tuple(dict(s) for s in self._syms
                     if M.sym_defined(s, image))

    def mod0_offset(self):
        """Image offset of the MOD0 structure."""
        return self._layout["mod0_off"]

    def _check_table_bytes(self, owner, tab_lo, tab_hi):
        ro_lo, ro_hi = self._ro
        _chk(ro_lo < ro_hi, "module has no read-only segment")
        _chk(tab_lo >= ro_lo and tab_hi <= ro_hi,
             "table [0x%x,0x%x) is outside the immutable RO segment "
             "[0x%x,0x%x)" % (tab_lo, tab_hi, ro_lo, ro_hi), Refusal)
        # Metadata extents and relocation sites compare in image offsets.
        b = self.base
        lo_off, hi_off = tab_lo - b, tab_hi - b
        for label, lo, hi in self._extents:
            _chk(not _overlap(lo_off, hi_off, lo, hi),
                 "table overlaps loader-consumed extent %s [0x%x,0x%x)"
                 % (label, lo, hi), Refusal)
        for where, label in self._reloc_sites:
            _chk(not _overlap(lo_off, hi_off, where, where + 8),
                 "table overlaps a %s relocation site at 0x%x"
                 % (label, where), Refusal)
        for s in self._defined:
            s_lo = self.base + s["value"]
            s_hi = s_lo + s["size"]
            _chk(not _overlap(tab_lo, tab_hi, s_lo, s_hi),
                 "table overlaps defined symbol %r (type %d, [0x%x,0x%x))"
                 % (s["name"], s["type"], s_lo, s_hi), Refusal)

    def _raw_branches(self):
        """Index every 4-byte TEXT word that could be a direct PC-relative
        branch, from raw bits only. Memoised; this is a threat index, never a
        code or worklist source."""
        if self._br_cache is not None:
            return self._br_cache
        lo, hi = self._text
        out = []
        raw = self.raw
        base = self.base
        for pc in range(lo, hi - 3, 4):
            word = struct.unpack_from("<I", raw, pc - base)[0]
            tgt = _raw_branch_target(word, pc)
            if tgt is not None:
                out.append((pc, tgt))
        object.__setattr__(self, "_br_cache", tuple(out))
        return self._br_cache

    def _raw_owner_threats(self, decoded, owner):
        """Negative-only index: (undecoded raw branch source, decoded owner
        node it can enter).  Never decodes a word or adds a block/root."""
        threats = []
        if owner is None:
            return ()
        for src, tgt in self._raw_branches():
            if src in decoded:
                continue
            if tgt in decoded and owner["start"] <= tgt < owner["end"]:
                threats.append((src, tgt))
        return tuple(sorted(set(threats)))

    def _refuse_known_bypass(self, w, add_pc, decoded):
        """A DECODED instruction must not branch into the post-CMP guard
        window (B.HI..BR): that would bypass the selector bound.  Ordinary
        pre-window nodes and the pair ADD are left to the graph dataflow
        (UNKNOWN entry seeds + the explicit ADD jump-in check), so a decoded
        case body with a proven base may loop back."""
        protected = set(w.pcs[1:])
        for src, tgt in self._raw_branches():
            if src in decoded and tgt in protected:
                raise Refusal(
                    "decoded instruction 0x%x branches into the protected "
                    "switch range at 0x%x" % (src, tgt))

    def _target_in_text(self, target, owner):
        lo, hi = self._text
        _chk(lo <= target and target + 4 <= hi,
             "target 0x%x is outside module TEXT" % target, Refusal)
        _chk(owner["start"] <= target and target + 4 <= owner["end"],
             "target 0x%x is outside the owning FUNC" % target, Refusal)
        off = target - self.base
        for s in self._defined:
            if s["type"] == M.STT_FUNC:
                continue
            s_lo = self.base + s["value"]
            if _overlap(target, target + 4, s_lo, s_lo + s["size"]):
                _chk(False,
                     "target 0x%x overlaps %s symbol %r"
                     % (target, "object" if s["type"] == _STT_OBJECT else "data",
                        s["name"]), Refusal)
        _chk(0 <= off and off + 4 <= len(self.raw), "target outside the flat")
        word = struct.unpack_from("<I", self.raw, off)[0]
        try:
            ins = self.decode(target, word, module=True)
        except Exception as exc:  # noqa: BLE001
            raise Refusal("target 0x%x does not decode (%s)" % (target, exc))
        _chk(isinstance(ins, dict) and ins.get("kind") not in
             (None, "unsupported"),
             "target 0x%x is not strictly decodable code" % target, Refusal)

    # -- dataflow ---------------------------------------------------------
    def _written(self, ins):
        """Conservative write-kill set from Capstone on the original word."""
        kind = ins.get("kind")
        if kind in ("bl", "blr", "svc"):
            return _KILL_ALL           # call/HLE boundary clobbers the range
        if kind in ("unsupported", None):
            return _KILL_ALL
        if kind == "br":
            # A BR writes no GPR.  Opaque destinations are not traversed by
            # this analysis; only caller-supplied same-owner edges bind it.
            return frozenset()
        return _capstone_writes(self._md, ins["pc"], ins["word"])

    def _must_const(self, owner, decoded, window, pair, edges, roots,
                    unknown_entries=()):
        """Prove the table base is the dominating ADRP+ADD constant.

        Lattice per register: BOTTOM = no path reaches the node yet; UNKNOWN =
        value not proven (all None).  UNKNOWN is seeded at the original roots,
        the owner entry and every node without an in-graph predecessor, so an
        external/mid-function entry can never be silently ignored.  Preds are
        taken from the decoded instruction semantics AND the caller's current
        edge graph (including local BR edges).  Merges intersect; a clobber on
        any path (loop back edge, disagreement) yields UNKNOWN and refuses.
        """
        reg = window.tab
        adrp_pc, add_pc, _table, add_imm = pair
        pair_id = ("pair", adrp_pc)
        adrp_mark = ("adrp", adrp_pc)
        nodes = decoded
        preds = {pc: set() for pc in nodes}
        for pc, ins in nodes.items():
            for t in list(_succ(ins)) + list(edges.get(pc, ())):
                if t in nodes:
                    preds[t].add(pc)
        entries = set(roots)
        entries.add(owner["start"])
        # H1: every decoded owner node reachable from an UNDECODED raw branch
        # (negative-only index) enters the dataflow with an UNKNOWN table-base
        # register.  A later ADRP regenerates it; any other path fails.
        entries.update(t for t in unknown_entries if t in nodes)
        for pc in nodes:
            if not preds[pc]:
                entries.add(pc)
        state = {pc: None for pc in nodes}          # None == BOTTOM
        for pc in entries:
            state[pc] = [None] * 31                 # UNKNOWN
        changed = True
        while changed:
            changed = False
            for pc in sorted(nodes):
                inc = None
                if pc in entries:
                    inc = [None] * 31
                for p in preds[pc]:
                    st = state[p]
                    if st is None:
                        continue
                    if inc is None:
                        inc = list(st)
                    else:
                        inc = [a if a == b else None
                               for a, b in zip(inc, st)]
                if inc is None:
                    continue
                out = list(inc)
                for r in self._written(nodes[pc]):
                    out[r] = None
                if pc == adrp_pc:
                    out[reg] = adrp_mark
                elif pc == add_pc:
                    # GENERATION requires the adjacent ADRP on EVERY path.
                    out[reg] = pair_id if inc[reg] == adrp_mark else None
                if out != state[pc]:
                    state[pc] = out
                    changed = True
        at_load = state.get(window.pcs[3])
        _chk(at_load is not None and at_load[reg] == pair_id,
             "table base register w%d is not the proven ADRP+ADD constant at "
             "0x%x (ADD fed by 0x%x)" % (reg, window.pcs[3], adrp_pc), Refusal)
        return state

    def _edges_into_window(self, window, roots, site_edges):
        """Refuse any alternative entry/edge into the ADR..BR window.

        Normal CMP -> B.HI -> ADR fall-through is allowed (B.HI splits the
        block); roots, other branch edges, table targets and direct edges into
        instructions pc1..pc5 are not.
        """
        win = set(window.pcs)
        pcs = window.pcs
        forbidden = set(pcs[1:])
        for pc in roots:
            _chk(pc not in forbidden,
                 "root 0x%x enters the ADR..BR window at 0x%x"
                 % (pc, pc), Refusal)
        for src, targets in site_edges.items():
            for t in targets:
                if t not in win:
                    continue
                if t == pcs[0]:
                    continue          # the guard's own entry is the normal path
                allowed = {pcs[1]: pcs[0], pcs[2]: pcs[1],
                           pcs[3]: pcs[2], pcs[4]: pcs[3], pcs[5]: pcs[4]}
                if t in allowed and src == allowed[t]:
                    continue
                _chk(False,
                     "edge 0x%x -> 0x%x enters the switch window"
                     % (src, t), Refusal)
        return True

    def _find_pair(self, owner, decoded, window):
        """Find the adjacent ADRP+ADD whose result is the LDRB base."""
        reg = window.tab
        found = []
        for pc in sorted(decoded):
            ins = decoded[pc]
            if ins.get("kind") != "addsub_imm":
                continue
            if not (ins.get("op") == 0 and ins.get("s") == 0
                    and ins.get("width") == 64
                    and ins.get("rn") == ins.get("rd") == reg):
                continue
            if (ins.get("word", 0) >> 22) & 1:
                continue                       # ADD (immediate) with sh=1
            prev = decoded.get(pc - 4)
            if not isinstance(prev, dict) or prev.get("kind") != "adrp" \
                    or prev.get("rd") != reg:
                continue
            if not (owner["start"] <= prev["pc"] and pc + 4 <= owner["end"]):
                continue
            table = _sat_add(prev.get("value"), ins.get("imm"))
            if table is None:
                continue
            found.append((prev["pc"], pc, table, ins.get("imm")))
        return found

    # -- public interface -------------------------------------------------
    def discover(self, visited_instructions, original_root_entries=None,
                 site_edges=None, defer_threats=False):
        """Return {already-reached BR pc: Proof} for this exact switch form.

        `visited_instructions`: pc -> decoded instruction from the CURRENT
        CFG (roots already reached).  `original_root_entries`: the root set the
        graph was seeded with.  `site_edges`: current known edge graph
        (pc -> iterable of target pcs).  No runtime address is accepted and no
        function root is produced.
        """
        if isinstance(visited_instructions, dict):
            vals = list(visited_instructions.values())
        else:
            _chk(hasattr(visited_instructions, "__iter__"),
                 "visited_instructions must be a mapping or iterable")
            try:
                vals = list(visited_instructions)
            except TypeError:
                raise InputError("visited_instructions is not iterable")
        # NEVER trust the caller's instruction IR.  Every visited PC is
        # re-decoded from the immutable raw snapshot; a caller word/field that
        # disagrees is rejected.  This also removes the last-wins duplicate bug.
        text_lo, text_hi = self._text
        decoded = {}
        for ins in vals:
            _chk(isinstance(ins, dict), "visited entries must be dicts")
            pc = ins.get("pc")
            _chk(isinstance(pc, int) and not isinstance(pc, bool),
                 "visited pc must be an int")
            _chk(pc % 4 == 0 and text_lo <= pc and pc + 4 <= text_hi,
                 "visited pc 0x%x is not a full word inside module TEXT" % pc)
            _chk(pc not in decoded, "duplicate visited pc 0x%x" % pc)
            off = pc - self.base
            _chk(0 <= off and off + 4 <= len(self.raw),
                 "visited pc 0x%x is outside the raw snapshot" % pc)
            word = struct.unpack_from("<I", self.raw, off)[0]
            try:
                snap = dict(self.decode(pc, word, module=True))
            except Exception:
                # A PARTIAL module graph legitimately carries an authoritative
                # unsupported placeholder for an unrelated op.  Accept it ONLY
                # when the caller's word matches the snapshot and the caller
                # also marked it unsupported; it is terminal and kills all.
                _chk(ins.get("kind") == "unsupported"
                     and ins.get("word") == word,
                     "visited pc 0x%x is unsupported in the raw snapshot but "
                     "the caller did not present the authoritative "
                     "placeholder" % pc)
                snap = {"kind": "unsupported", "pc": pc, "word": word}
            _chk(ins.get("kind") != "unsupported" or
                 snap.get("kind") == "unsupported",
                 "caller claims an unsupported op at 0x%x but the raw word "
                 "strictly decodes" % pc)
            for f in ("kind", "target", "value", "imm", "rn", "rd", "rt",
                      "rt2", "rm", "cond", "op", "s", "shift", "imm6",
                      "width", "size", "opc", "option", "load"):
                if f in ins and f in snap:
                    _chk(ins[f] == snap[f],
                         "caller field %s at 0x%x disagrees with the raw "
                         "snapshot" % (f, pc))
                elif f in ins and f in ("target", "value", "imm"):
                    _chk(ins[f] == snap.get(f),
                         "caller field %s at 0x%x disagrees with the raw "
                         "snapshot" % (f, pc))
            if "word" in ins:
                _chk(ins["word"] == word,
                     "caller word at 0x%x disagrees with the raw snapshot"
                     % pc)
            snap["word"] = word
            decoded[pc] = snap
        _chk(original_root_entries is not None,
             "the original root entries are required")
        try:
            roots = set(original_root_entries)
        except TypeError:
            raise InputError("original_root_entries is not iterable")
        _chk(bool(roots), "the original root entry set is empty")
        _chk(all(isinstance(r, int) and not isinstance(r, bool) for r in roots),
             "original_root_entries must be ints")
        _chk(roots <= set(decoded),
             "a root entry is not present in the reached instruction set")
        # Natural intra-graph edges: decoded instruction semantics ONLY.
        natural = {}
        for pc, ins in decoded.items():
            tg = tuple(sorted(t for t in _succ(ins) if t in decoded))
            if tg:
                natural[pc] = tg
        # Additional edges are a CLAIM, never an input: each source must be a
        # raw BR and its target set must exactly equal a proof produced below
        # over the current reached graph.  A fake root/fall-through edge from a
        # non-BR can therefore never introduce an unreachable site.
        claimed = {}
        if site_edges is not None:
            _chk(hasattr(site_edges, "items"), "site_edges must be a mapping")
            for src, tgts in site_edges.items():
                _chk(isinstance(src, int) and not isinstance(src, bool),
                     "site_edges key must be an int pc")
                if isinstance(tgts, int) and not isinstance(tgts, bool):
                    tgts = [tgts]
                try:
                    tgts = list(tgts)
                except TypeError:
                    raise InputError("site_edges target list is not iterable")
                _chk(all(isinstance(t, int) and not isinstance(t, bool)
                         for t in tgts),
                     "site_edges targets must be ints")
                _chk(src in decoded,
                     "site_edges source 0x%x is not a reached instruction"
                     % src)
                _chk(all(t in decoded for t in tgts),
                     "site_edges targets must all be reached instructions")
                claimed[src] = tuple(sorted(set(tgts)))
        # A claim is only honoured provisionally when its source is itself a
        # strict-shape BR window in the raw snapshot and every target is a
        # decoded node.  Even then it cannot admit a site: the final proof for
        # that source must reproduce the claimed set exactly.
        provisional = {}
        for src, tgts in claimed.items():
            _chk(decoded[src].get("kind") == "br",
                 "caller site edge source 0x%x is not a BR instruction" % src,
                 InputError)
            if _decode_window(self.raw, self.base, src, self.decode) is None:
                continue        # ordinary BR idiom: unhandled, no local edges
            provisional[src] = tgts

        def reach_of(local):
            full = {}
            for pc in set(natural) | set(local):
                full[pc] = tuple(sorted(set(natural.get(pc, ()))
                                      | set(local.get(pc, ()))))
            reach = set(roots)
            stack = list(roots)
            while stack:
                pc = stack.pop()
                for t in full.get(pc, ()):
                    if t not in reach:
                        reach.add(t)
                        stack.append(t)
            return reach, full

        local = {}
        out = {}
        for _ in range(64):
            work_edges = dict(provisional)
            for pc, tg in local.items():
                work_edges[pc] = tuple(sorted(set(work_edges.get(pc, ()))
                                             | set(tg)))
            reach, full = reach_of(work_edges)
            out = {}
            for pc in sorted(pc for pc in reach
                             if pc in decoded
                             and decoded[pc].get("kind") == "br"):
                w = _decode_window(self.raw, self.base, pc, self.decode)
                if w is None:
                    continue                  # other BR idiom: unhandled
                _chk(all(p in reach for p in w.pcs),
                     "switch window at 0x%x is not fully reachable from the "
                     "roots" % pc, Refusal)
                out[pc] = self._prove(w, decoded, roots, full,
                                      defer_threats=defer_threats)
            new_local = {pc: tuple(sorted(set(p.targets)))
                         for pc, p in out.items()}
            if new_local == local:
                break
            local = new_local
        else:
            raise Refusal("local switch closure did not converge")
        for src, tgts in provisional.items():
            _chk(src in out,
                 "site edge source 0x%x is not a proven BR site" % src,
                 InputError)
            _chk(tgts == tuple(sorted(set(out[src].targets))),
                 "site edge targets at 0x%x disagree with the proof "
                 "(caller %s, proven %s)"
                 % (src, [hex(t) for t in tgts],
                    [hex(t) for t in sorted(set(out[src].targets))]),
                 InputError)
        return out

    def _prove(self, w, decoded, roots, edges, defer_threats=False):
        """Full proof for one recognised window; raises typed ProofError.

        `defer_threats` is the module pipeline's expansion phase ONLY: raw,
        not-yet-decoded incoming-branch threats are recorded as
        `deferred_threats` (closure `pending-expansion`) so the derived case
        paths can be decoded.  Every other check is immediate, and the strict
        default refuses any remaining threat.
        """
        for pc in w.pcs:
            ins = decoded.get(pc)
            _chk(ins is not None,
                 "switch window at 0x%x is not part of the reached CFG "
                 "(pc 0x%x)" % (w.pc, pc), Refusal)
            _chk(ins.get("word") == w.words[w.pcs.index(pc)],
                 "reached word at 0x%x disagrees with the raw snapshot" % pc)
        _chk(w.n >= 1, "selector bound N=%d is degenerate" % w.n, Refusal)
        _chk(w.label % 4 == 0, "ADR label 0x%x is not 4-aligned" % w.label,
             Refusal)
        _chk(w.pc not in roots, "the BR site itself is a root", Refusal)
        owner = self._owner(w.pc)
        # ANY other defined sized symbol overlapping the owner span is an
        # ambiguity, even if it does not contain the BR (nested/partial FUNC).
        for s in self._defined:
            s_lo = self.base + s["value"]
            s_hi = s_lo + s["size"]
            if not _overlap(owner["start"], owner["end"], s_lo, s_hi):
                continue
            if (s["type"] == M.STT_FUNC and s_lo == owner["start"]
                    and s_hi == owner["end"]):
                continue
            raise Refusal("owner FUNC %r overlaps another defined symbol %r "
                          "(type %d, [0x%x,0x%x))"
                          % (owner["name"], s["name"], s["type"], s_lo, s_hi))
        _chk(isinstance(w.default, int) and w.default % 4 == 0
             and owner["start"] <= w.default
             and w.default + 4 <= owner["end"]
             and self._text[0] <= w.default
             and w.default + 4 <= self._text[1],
             "the B.HI default target is not a full word inside the owner "
             "FUNC in module TEXT", Refusal)
        for pc in w.pcs:
            _chk(owner["start"] <= pc and pc + 4 <= owner["end"],
                 "guard window 0x%x is outside its owning FUNC" % pc, Refusal)
            _chk(w.label != pc and not _overlap(w.label, w.label + 4, pc, pc + 4),
                 "ADR label points into the guard window", Refusal)

        self._edges_into_window(w, roots, edges)

        decoded_owner = {pc: ins for pc, ins in decoded.items()
                         if owner["start"] <= pc < owner["end"]}
        # H1: every decoded owner node that an UNDECODED raw branch could
        # enter is an UNKNOWN dataflow entry.  Stage 1 records the threats and
        # omits the seeds; strict stage merges them.
        threats = self._raw_owner_threats(decoded, owner)
        if not defer_threats:
            # H1-R: an UNKNOWN seed at/after LDR (ADD/BR) can never propagate
            # back to at_load, so the static guarantee needs an explicit refusal
            # for any undecoded raw branch into the post-CMP window.
            post_cmp = set(w.pcs[1:])
            for src, tgt in threats:
                if tgt in post_cmp:
                    raise Refusal(
                        "undecoded raw word 0x%x could branch into the "
                        "post-CMP switch window at 0x%x (static refusal)"
                        % (src, tgt))
        seeds = () if defer_threats else tuple(sorted({t for _s, t in threats}))
        pairs = self._find_pair(owner, decoded_owner, w)
        _chk(bool(pairs),
             "no ADRP+ADD table base candidate inside the owner FUNC", Refusal)
        proven = []
        for cand in pairs:
            try:
                self._must_const(owner, decoded, w, cand, edges, roots,
                                 unknown_entries=seeds)
            except ProofError:
                continue
            proven.append(cand)
        if not proven and len(pairs) == 1:
            # Re-raise the specific dataflow refusal for the only candidate.
            self._must_const(owner, decoded, w, pairs[0], edges, roots,
                             unknown_entries=seeds)
        _chk(len(proven) == 1,
             "no ADRP+ADD pair proves the table base"
             if not proven else
             "%d ADRP+ADD pairs both prove as the dominating table base"
             % len(proven), Refusal)
        adrp_pc, add_pc, table, add_imm = proven[0]
        _chk(not _overlap(adrp_pc, add_pc + 4, w.pcs[2], w.pc + 4),
             "table base pair lies inside the switch window", Refusal)
        _chk(add_pc not in roots,
             "the ADD of the table base pair is a root entry", Refusal)
        for src, tgts in edges.items():
            if src == adrp_pc:
                continue                  # the normal ADRP fall-through
            _chk(add_pc not in tgts,
                 "the ADD of the table base pair is a jump-in target from "
                 "0x%x" % src, Refusal)
        count = w.n + 1
        tab_hi = _sat_add(table, count)
        _chk(tab_hi is not None, "table extent overflows 64 bits", Refusal)
        self._check_table_bytes(owner, table, tab_hi)
        self._reject_symbol_overlaps(owner, [(table, tab_hi, "table")])

        off = table - self.base
        table_bytes = self.raw[off:off + count]
        _chk(len(table_bytes) == count, "table is not fully inside the flat")
        targets = []
        for value in table_bytes:
            target = _sat_add(w.label, value << 2)
            _chk(target is not None, "target arithmetic overflows", Refusal)
            _chk(target % 4 == 0, "target 0x%x is misaligned" % target, Refusal)
            _chk(target not in w.pcs and target not in (adrp_pc, add_pc)
                 and not any(_overlap(target, target + 4, pc, pc + 4)
                             for pc in w.pcs),
                 "table target 0x%x lands inside the guard window or the "
                 "table-base pair" % target, Refusal)
            self._target_in_text(target, owner)
            targets.append(target)
        # Every observed selector maps inside the proven set (N+1 entries) --
        # this is checked only as a consistency guard for the caller, never as
        # a source of edges.
        _chk(len(targets) == count, "incomplete target set", Refusal)
        self._refuse_known_bypass(w, add_pc, decoded)
        deferred = threats if defer_threats else ()

        return Proof(
            br_pc=w.pc,
            owner_name=owner["name"],
            owner_start=owner["start"],
            owner_size=owner["size"],
            source_sha256=self.sha256,
            table_sha256=_sha(table_bytes),
            table_va=table,
            table_off=off,
            table_size=count,
            guard_pc=w.pcs[0],
            guard_bound=w.n,
            label_va=w.label,
            index_reg=w.idx,
            table_reg=w.tab,
            adrp_pc=adrp_pc,
            add_pc=add_pc,
            window_pcs=w.pcs,
            targets=tuple(targets),
            default_target=w.default,
            deferred_threats=deferred,
            raw_entry_seeds=seeds,
            closure=("pending-expansion" if deferred
                     else "pending-final-graph"),
        )
