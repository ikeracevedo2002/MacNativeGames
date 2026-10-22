#!/usr/bin/env python3
"""D024 Stage A - NSO/FDE metadata frontend producing a CANDIDATE manifest (G3).

WHAT THIS IS (and what it is NOT)
---------------------------------
One flat module image (`.flat` + `.layout.json`) is turned into a manifest of
CANDIDATE function boundaries with explicit per-boundary provenance:

    * `.eh_frame_hdr` is located ONLY through the module's own MOD0
      (`eh_frame_hdr_start` / `eh_frame_hdr_end`, both signed offsets RELATIVE
      to MOD0).  There is no side-car, no section header and no guess.
    * the header is parsed (version, encodings, binary-search table) and
      `.eh_frame` is walked INDEPENDENTLY (CIE/FDE records, extended lengths,
      terminator, augmentation strings, pointer encodings).
    * the HDR table and the linear walk must agree EXACTLY: same
      (pc_begin, fde_address) set, strictly sorted table, same count.
    * every FDE range is non-empty, 4-aligned and inside the module TEXT;
      FDE ranges may not overlap.
    * provenance is `fde` for every boundary, plus `dynsym_func` when a DEFINED
      STT_FUNC dynamic symbol has exactly that value and `dt_init_array` when
      the start is a member of the constructor table derived by
      `g3_ctor_roots.derive()` (the derivation is REUSED, never reimplemented).

D024 is explicit that "compiled is not authorized": an FDE start is EVIDENCE
for a boundary, never a root.  This module therefore emits
`"kind": "candidates"` and `"authority": "none"`, it never feeds a root set,
and nothing in the translator, the root policies (D021/D022/D023), the runtime
or the existing tests consumes it.  Execution behaviour is unchanged.

FAIL CLOSED
-----------
Every malformed input raises `FdeError` with a stable `reason` code and a
detail string.  There is no "empty list" and no partial result: an empty
boundary list can only be the honest result of a module whose TEXT really has
no FDE.  A module whose MOD0 declares no `.eh_frame_hdr` raises the dedicated
`NoEhFrameHdr` (reason `no-eh-frame-hdr`), which is a DISTINCT outcome, not an
empty success: "the module has no unwind metadata" must never be indistinguishable
from "the parser gave up".

The parser is written from the DWARF/LSB `.eh_frame` specification; no code is
copied from SavageWindRecomp or any other GPL source.

Limitations (recorded, not hidden):
    * only the three encodings real NSOs use are accepted
      (eh_frame_ptr `pcrel|sdata4`, fde_count `udata4`, table `datarel|sdata4`);
      every other encoding is a typed refusal instead of a best effort;
    * the linear walk is bounded by the module's RO segment end (the only
      extent the image itself declares); the terminator is mandatory;
    * the FDE instruction program is bounded by the record length but is not
      interpreted - this frontend claims boundaries, never unwind semantics.
"""

import argparse
import hashlib
import json
import os
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import aot_module as M          # noqa: E402
import aot_translate as T       # noqa: E402
import g3_ctor_roots as G       # noqa: E402
import g3_local_switch as LS    # noqa: E402

SCHEMA_VERSION = 1
KIND = "candidates"
AUTHORITY = "none"

MOD0_MAGIC = b"MOD0"
MOD0_SIZE = 32
MOD0_EH_FRAME_HDR_START = 16
MOD0_EH_FRAME_HDR_END = 20

HDR_VERSION = 1
DW_EH_PE_PCREL_SDATA4 = 0x1B        # eh_frame_ptr (real NSOs, llvm/gcc)
DW_EH_PE_UDATA4 = 0x03              # fde_count
DW_EH_PE_DATAREL_SDATA4 = 0x3B      # binary-search table
HDR_ENC_EH_FRAME_PTR = DW_EH_PE_PCREL_SDATA4
HDR_ENC_FDE_COUNT = DW_EH_PE_UDATA4
HDR_ENC_TABLE = DW_EH_PE_DATAREL_SDATA4

# DW_EH_PE encoding bytes: low nibble = value format, high nibble = application.
DW_EH_PE_ABSPTR = 0x00
DW_EH_PE_ULEB128 = 0x01
DW_EH_PE_UDATA2 = 0x02
DW_EH_PE_UDATA4 = 0x03
DW_EH_PE_UDATA8 = 0x04
DW_EH_PE_SLEB128 = 0x09
DW_EH_PE_SDATA2 = 0x0A
DW_EH_PE_SDATA4 = 0x0B
DW_EH_PE_SDATA8 = 0x0C
DW_EH_PE_OMIT = 0xFF
DW_EH_PE_FORMATS = {
    DW_EH_PE_ABSPTR: ("absptr", 8, False),
    DW_EH_PE_ULEB128: ("uleb128", None, True),
    DW_EH_PE_UDATA2: ("udata2", 2, False),
    DW_EH_PE_UDATA4: ("udata4", 4, False),
    DW_EH_PE_UDATA8: ("udata8", 8, False),
    DW_EH_PE_SLEB128: ("sleb128", None, True),
    DW_EH_PE_SDATA2: ("sdata2", 2, True),
    DW_EH_PE_SDATA4: ("sdata4", 4, True),
    DW_EH_PE_SDATA8: ("sdata8", 8, True),
}
DW_EH_PE_APP_MASK = 0x70
DW_EH_PE_APP_ABS = 0x00
DW_EH_PE_APP_PCREL = 0x10
DW_EH_PE_APP_DATAREL = 0x30
DW_EH_PE_INDIRECT = 0x80

CIE_VERSION_MIN = 1
SUPPORTED_CIE_VERSIONS = (1, 3)
CIE_ID_32 = 0x00000000          # in .eh_frame a CIE id is 0
EXTENDED_LENGTH = 0xFFFFFFFF    # 64-bit length follows
SUPPORTED_AUGMENTATIONS = frozenset("RPLS")
# Only pcrel|sdata4: an absolute pc_begin would be an unrelocated raw word in
# the flat image (RELATIVE records are not applied here), so it is refused
# rather than read as an image offset.
FDE_PC_ENCODINGS = frozenset([DW_EH_PE_SDATA4 | DW_EH_PE_APP_PCREL])


class FdeError(Exception):
    """Typed fail-closed refusal.  `reason` is stable and machine-readable."""

    def __init__(self, reason, detail=""):
        self.reason = reason
        self.detail = detail or reason
        super().__init__("%s: %s" % (reason, self.detail))


class NoEhFrameHdr(FdeError):
    """Distinct outcome: the module's own MOD0 declares no `.eh_frame_hdr`."""

    def __init__(self, detail=""):
        FdeError.__init__(self, "no-eh-frame-hdr", detail)


def _hex(value):
    return "0x%x" % value


def _sx(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def _overlap(a_lo, a_hi, b_lo, b_hi):
    return a_lo < b_hi and b_lo < a_hi


# ------------------------------------------------------------- bounded reader

class _Reader(object):
    """Every read is bounded by [pos, end); `what` keeps the reason typed."""

    __slots__ = ("flat", "pos", "end", "what", "image_size")

    def __init__(self, flat, start, end, what, image_size):
        if not 0 <= start <= end <= len(flat):
            raise FdeError(
                "%s-not-file-backed" % what,
                "extent [0x%x,0x%x) is not inside the flat file [0x0,0x%x)"
                % (start, end, len(flat)))
        self.flat = flat
        self.pos = start
        self.end = end
        self.what = what
        self.image_size = image_size

    def _need(self, count):
        if count < 0 or self.pos + count > self.end:
            raise FdeError(
                "%s-truncated" % self.what,
                "read of %d byte(s) at 0x%x runs past the extent end 0x%x"
                % (count, self.pos, self.end))

    def u8(self):
        self._need(1)
        value = self.flat[self.pos]
        self.pos += 1
        return value

    def u16(self):
        self._need(2)
        value = struct.unpack_from("<H", self.flat, self.pos)[0]
        self.pos += 2
        return value

    def u32(self):
        self._need(4)
        value = struct.unpack_from("<I", self.flat, self.pos)[0]
        self.pos += 4
        return value

    def u64(self):
        self._need(8)
        value = struct.unpack_from("<Q", self.flat, self.pos)[0]
        self.pos += 8
        return value

    def uleb(self):
        result, shift = 0, 0
        while True:
            byte = self.u8()
            result |= (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                return result
            if shift > 64:
                raise FdeError("%s-leb-overflow" % self.what,
                               "ULEB128 at 0x%x is longer than 64 bits"
                               % (self.pos - 1))

    def sleb(self):
        result, shift = 0, 0
        while True:
            byte = self.u8()
            result |= (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                if byte & 0x40:
                    result -= 1 << shift
                return result
            if shift > 64:
                raise FdeError("%s-leb-overflow" % self.what,
                               "SLEB128 at 0x%x is longer than 64 bits"
                               % (self.pos - 1))

    def cstring(self):
        start = self.pos
        while True:
            self._need(1)
            byte = self.flat[self.pos]
            self.pos += 1
            if byte == 0:
                break
            if not 0x20 <= byte <= 0x7E:
                raise FdeError(
                    "%s-bad-augmentation-string" % self.what,
                    "augmentation byte 0x%02x at 0x%x is not printable ASCII"
                    % (byte, self.pos - 1))
        return self.flat[start:self.pos - 1].decode("ascii")

    def fixed(self, fmt):
        name, size, signed = DW_EH_PE_FORMATS[fmt]
        if size == 2:
            raw = self.u16()
            value = _sx(raw, 16) if signed else raw
        elif size == 4:
            raw = self.u32()
            value = _sx(raw, 32) if signed else raw
        elif size == 8:
            raw = self.u64()
            value = _sx(raw, 64) if signed else raw
        elif fmt == DW_EH_PE_ULEB128:
            value = self.uleb()
        elif fmt == DW_EH_PE_SLEB128:
            value = self.sleb()
        else:                                    # pragma: no cover - table
            raise FdeError("%s-unsupported-format" % self.what,
                           "value format 0x%02x" % fmt)
        return value

    def encoded(self, enc, apps, what, datarel_base=0):
        """Read ONE DW_EH_PE value and resolve its application modifier."""
        if enc == DW_EH_PE_OMIT:
            raise FdeError("unsupported-encoding:%s" % what,
                           "DW_EH_PE_omit (0x%02x) has no value" % enc)
        if enc & DW_EH_PE_INDIRECT:
            raise FdeError("unsupported-encoding:%s" % what,
                           "indirect (0x%02x) encodings are not resolved"
                           % enc)
        fmt = enc & 0x0F
        app = enc & DW_EH_PE_APP_MASK
        if fmt not in DW_EH_PE_FORMATS:
            raise FdeError("unsupported-encoding:%s" % what,
                           "value format 0x%x of encoding 0x%02x" % (fmt, enc))
        if app not in apps:
            raise FdeError("unsupported-encoding:%s" % what,
                           "application 0x%x of encoding 0x%02x" % (app, enc))
        field = self.pos
        value = self.fixed(fmt)
        if app == DW_EH_PE_APP_PCREL:
            value += field
        elif app == DW_EH_PE_APP_DATAREL:
            value += datarel_base
        if value < 0 or value > self.image_size:
            raise FdeError("%s-outside-image" % what,
                           "value 0x%x resolves outside the image "
                           "[0x0,0x%x)" % (value, self.image_size))
        return value

    def skip_encoded(self, enc, what):
        """Bounds-check ONE DW_EH_PE field without resolving it.

        Only the FDE's personality routine uses this: the frontend claims
        boundaries and never needs the handler address, so a
        `DW_EH_PE_indirect` personality pointer is READ (and bounded) but never
        dereferenced.  The value format still has to be a known one.
        """
        if enc == DW_EH_PE_OMIT:
            raise FdeError("unsupported-encoding:%s" % what,
                           "DW_EH_PE_omit (0x%02x) has no value" % enc)
        fmt = enc & 0x0F
        if fmt not in DW_EH_PE_FORMATS:
            raise FdeError("unsupported-encoding:%s" % what,
                           "value format 0x%x of encoding 0x%02x" % (fmt, enc))
        self.fixed(fmt)
        return enc


# -------------------------------------------------------------- module extents

class ModuleMeta(object):
    """Validated MOD0 geometry of ONE flat image (image offsets, not VAs)."""

    __slots__ = ("flat", "layout", "name", "sha256", "image_size", "bss_size",
                 "mod0", "text", "ro", "data", "hdr")

    def __init__(self, flat, layout, name):
        self.flat = flat
        self.layout = layout
        self.name = name
        self.sha256 = hashlib.sha256(flat).hexdigest()
        self.image_size = 0
        self.bss_size = 0
        self.mod0 = 0
        self.text = (0, 0)
        self.ro = (0, 0)
        self.data = (0, 0)
        self.hdr = None

    def json(self):
        return {"name": self.name, "sha256": self.sha256,
                "image_size": self.image_size, "bss_size": self.bss_size,
                "mod0_offset": self.mod0,
                "text": [_hex(self.text[0]), _hex(self.text[1])],
                "ro": [_hex(self.ro[0]), _hex(self.ro[1])],
                "data": [_hex(self.data[0]), _hex(self.data[1])]}


def _need(cond, msg):
    if not cond:
        raise FdeError("layout-invalid", msg)


def read_module(flat, layout, name=None):
    """Validate the flat/layout pair and read the MOD0 extents.

    Raises `NoEhFrameHdr` when the module's own MOD0 declares no
    `.eh_frame_hdr` at all; every other problem is a typed `FdeError`.
    """
    _need(isinstance(flat, (bytes, bytearray)), "flat image is not bytes")
    _need(isinstance(layout, dict), "layout is not a JSON object")
    flat = bytes(flat)
    for key in ("sha256", "image_size", "bss_size", "mod0_off", "text", "ro",
                "data", "dynsym_count"):
        _need(key in layout, "layout is missing %r" % key)
    name = name or layout.get("name")
    _need(isinstance(name, str) and name, "module name is missing")
    dynsym_count = layout["dynsym_count"]
    _need(isinstance(dynsym_count, int) and not isinstance(dynsym_count, bool)
          and dynsym_count >= 0, "bad dynsym_count %r" % (dynsym_count,))
    meta = ModuleMeta(flat, layout, name)
    _need(meta.sha256 == layout["sha256"],
          "%s: flat SHA-256 %s != layout sha256 %r"
          % (meta.name, meta.sha256, layout["sha256"]))
    image_size = layout["image_size"]
    bss_size = layout["bss_size"]
    _need(isinstance(image_size, int) and not isinstance(image_size, bool)
          and image_size > 0, "bad image_size %r" % (image_size,))
    _need(isinstance(bss_size, int) and not isinstance(bss_size, bool)
          and bss_size >= 0, "bad bss_size %r" % (bss_size,))
    _need(image_size == len(flat) + bss_size,
          "%s: image_size 0x%x != flat 0x%x + bss 0x%x"
          % (meta.name, image_size, len(flat), bss_size))
    meta.image_size, meta.bss_size = image_size, bss_size
    _need(len(flat) >= 8, "%s: flat image too small" % meta.name)

    mod0 = layout["mod0_off"]
    _need(isinstance(mod0, int) and not isinstance(mod0, bool) and mod0 >= 0,
          "bad mod0_off %r" % (mod0,))
    _need(mod0 + MOD0_SIZE <= len(flat),
          "%s: MOD0 offset 0x%x out of image" % (meta.name, mod0))
    _need(flat[mod0:mod0 + 4] == MOD0_MAGIC,
          "%s: no MOD0 magic at 0x%x" % (meta.name, mod0))
    meta.mod0 = mod0
    bss_start = mod0 + struct.unpack_from("<i", flat, mod0 + 8)[0]
    bss_end = mod0 + struct.unpack_from("<i", flat, mod0 + 12)[0]
    _need(len(flat) <= bss_start,
          "%s: MOD0 bss_start 0x%x is before the data file end 0x%x"
          % (meta.name, bss_start, len(flat)))
    _need(bss_start <= bss_end,
          "%s: MOD0 bss_end 0x%x < bss_start 0x%x"
          % (meta.name, bss_end, bss_start))
    _need(bss_end <= image_size,
          "%s: MOD0 bss_end 0x%x is past image_size 0x%x"
          % (meta.name, bss_end, image_size))

    segs = []
    for seg in ("text", "ro", "data"):
        value = layout[seg]
        _need(isinstance(value, (list, tuple)) and len(value) == 2
              and all(isinstance(x, int) and not isinstance(x, bool)
                      for x in value),
              "layout %s must be [offset, size]" % seg)
        lo, size = int(value[0]), int(value[1])
        _need(lo >= 0 and size >= 0 and lo + size <= image_size,
              "layout %s [0x%x,0x%x) is outside the image"
              % (seg, lo, lo + size))
        segs.append((seg, lo, lo + size))
    _need(segs[0][1] == 0, "layout text does not start at image offset 0")
    _need(layout["text"][1] > 0, "empty text")
    for i in range(len(segs)):
        for j in range(i + 1, len(segs)):
            _need(not _overlap(segs[i][1], segs[i][2], segs[j][1], segs[j][2]),
                  "layout %s and %s overlap" % (segs[i][0], segs[j][0]))
    _need(segs[0][2] <= segs[1][1] and segs[1][2] <= segs[2][1],
          "layout segments are not ordered text < ro < data")
    _need(segs[1][2] <= len(flat),
          "%s: layout ro [0x%x,0x%x) is not file backed (flat ends at 0x%x)"
          % (meta.name, segs[1][1], segs[1][2], len(flat)))
    meta.text = (segs[0][1], segs[0][2])
    meta.ro = (segs[1][1], segs[1][2])
    meta.data = (segs[2][1], segs[2][2])

    # The ONLY source of the .eh_frame_hdr extent is the module's own MOD0.
    start_rel = struct.unpack_from("<i", flat, mod0 + MOD0_EH_FRAME_HDR_START)[0]
    end_rel = struct.unpack_from("<i", flat, mod0 + MOD0_EH_FRAME_HDR_END)[0]
    if start_rel == 0 and end_rel == 0:
        raise NoEhFrameHdr(
            "%s: MOD0 declares no .eh_frame_hdr (both offsets are zero); "
            "this is 'no unwind metadata', not an empty boundary list"
            % meta.name)
    _need(start_rel != 0 and end_rel != 0,
          "%s: MOD0 .eh_frame_hdr offsets %d/%d are unpaired"
          % (meta.name, start_rel, end_rel))
    hdr_start = mod0 + start_rel
    hdr_end = mod0 + end_rel
    _need(0 <= hdr_start < hdr_end <= image_size,
          "%s: MOD0 .eh_frame_hdr extent [0x%x,0x%x) is invalid"
          % (meta.name, hdr_start, hdr_end))
    _need(hdr_end <= len(flat),
          "%s: MOD0 .eh_frame_hdr extent [0x%x,0x%x) is not file backed "
          "(flat ends at 0x%x)" % (meta.name, hdr_start, hdr_end, len(flat)))
    ro_lo, ro_hi = meta.ro
    _need(ro_lo <= hdr_start and hdr_end <= ro_hi,
          "%s: MOD0 .eh_frame_hdr extent [0x%x,0x%x) is not fully inside the "
          "RO segment [0x%x,0x%x)" % (meta.name, hdr_start, hdr_end,
                                      ro_lo, ro_hi))
    meta.hdr = (hdr_start, hdr_end)
    return meta


# ------------------------------------------------------------- .eh_frame_hdr

class Header(object):
    """Parsed `.eh_frame_hdr` plus the extent it was bound to."""

    __slots__ = ("start", "end", "padding", "eh_frame_ptr", "fde_count",
                 "table", "table_bytes")

    def __init__(self):
        self.start = 0
        self.end = 0
        self.padding = 0
        self.eh_frame_ptr = 0
        self.fde_count = 0
        self.table = []
        self.table_bytes = 0


def parse_header(meta):
    hdr_start, hdr_end = meta.hdr
    rd = _Reader(meta.flat, hdr_start, hdr_end, "eh-frame-hdr",
                 meta.image_size)
    version = rd.u8()
    if version != HDR_VERSION:
        raise FdeError("bad-hdr-version",
                       "%s: .eh_frame_hdr version %d (only %d is defined)"
                       % (meta.name, version, HDR_VERSION))
    eh_enc, count_enc, table_enc = rd.u8(), rd.u8(), rd.u8()
    for got, want, what in (
            (eh_enc, HDR_ENC_EH_FRAME_PTR, "eh_frame_ptr"),
            (count_enc, HDR_ENC_FDE_COUNT, "fde_count"),
            (table_enc, HDR_ENC_TABLE, "table")):
        if got != want:
            raise FdeError(
                "unsupported-encoding:%s" % what,
                "%s: .eh_frame_hdr %s encoding 0x%02x (only 0x%02x is "
                "supported)" % (meta.name, what, got, want))
    header = Header()
    header.start, header.end = hdr_start, hdr_end
    header.eh_frame_ptr = rd.encoded(eh_enc, (DW_EH_PE_APP_PCREL,),
                                     "eh-frame-ptr", datarel_base=hdr_start)
    header.fde_count = rd.encoded(count_enc, (DW_EH_PE_APP_ABS,),
                                  "fde-count", datarel_base=hdr_start)
    if header.fde_count < 0:
        raise FdeError("fde-count-negative",
                       "%s: .eh_frame_hdr fde_count %d"
                       % (meta.name, header.fde_count))
    # Bound the count by the remaining extent BEFORE looping: a forged count
    # must not turn into a huge allocation or a long loop.
    fmt = table_enc & 0x0F
    entry_bytes = 2 * (DW_EH_PE_FORMATS.get(fmt, (None, None, None))[1] or 0)
    if not entry_bytes:
        raise FdeError("unsupported-encoding:table",
                       "%s: .eh_frame_hdr table uses the variable-length "
                       "format 0x%x" % (meta.name, fmt))
    if header.fde_count * entry_bytes > hdr_end - rd.pos:
        raise FdeError(
            "fde-count-exceeds-extent",
            "%s: .eh_frame_hdr fde_count %d needs 0x%x bytes but only 0x%x "
            "remain in [0x%x,0x%x)"
            % (meta.name, header.fde_count,
               header.fde_count * entry_bytes, hdr_end - rd.pos,
               hdr_start, hdr_end))
    table = []
    for index in range(header.fde_count):
        pc_begin = rd.encoded(table_enc, (DW_EH_PE_APP_DATAREL,),
                              "table-entry", datarel_base=hdr_start)
        fde = rd.encoded(table_enc, (DW_EH_PE_APP_DATAREL,),
                         "table-entry", datarel_base=hdr_start)
        table.append((pc_begin, fde))
    header.table = table
    header.table_bytes = header.fde_count * entry_bytes
    padding = hdr_end - rd.pos
    if padding:
        if any(meta.flat[rd.pos:hdr_end]):
            raise FdeError(
                "hdr-trailing-bytes",
                "%s: .eh_frame_hdr has %d non-zero byte(s) after the "
                "binary-search table at 0x%x (extent ends at 0x%x)"
                % (meta.name, padding, rd.pos, hdr_end))
        header.padding = padding
    return header


# ---------------------------------------------------------------- .eh_frame

class Cie(object):
    __slots__ = ("offset", "length", "version", "augmentation", "code_align",
                 "data_align", "return_reg", "fde_enc", "lsda_enc")

    def __init__(self):
        self.offset = 0
        self.length = 0
        self.version = 0
        self.augmentation = ""
        self.code_align = 0
        self.data_align = 0
        self.return_reg = 0
        self.fde_enc = DW_EH_PE_ABSPTR
        self.lsda_enc = None


class Fde(object):
    __slots__ = ("start", "end", "address", "length", "cie_offset")

    def __init__(self, start, end, address, length, cie_offset):
        self.start = start
        self.end = end
        self.address = address
        self.length = length
        self.cie_offset = cie_offset


def _record_extent(rd, limit, what):
    """Read one record header; returns (record_start, body_start, record_end)."""
    if rd.pos + 4 > limit:
        raise FdeError("eh-frame-unterminated",
                       "%s: .eh_frame ends at 0x%x without a zero terminator "
                       "(next record header at 0x%x)" % (what, limit, rd.pos))
    start = rd.pos
    length = rd.u32()
    if length == 0:
        return start, None, start + 4
    if length == EXTENDED_LENGTH:
        if rd.pos + 8 > limit:
            raise FdeError("record-length-past-extent",
                           "%s: extended record length at 0x%x runs past the "
                           "extent end 0x%x" % (what, start, limit))
        length = rd.u64()
        id_size = 8
    else:
        id_size = 4
    if length < id_size:
        raise FdeError("record-length-too-small",
                       "%s: record at 0x%x declares length 0x%x (smaller than "
                       "its %d-byte CIE id/pointer)"
                       % (what, start, length, id_size))
    end = rd.pos + length
    if end > limit:
        raise FdeError("record-length-past-extent",
                       "%s: record at 0x%x declares length 0x%x, ending at "
                       "0x%x past the extent end 0x%x"
                       % (what, start, length, end, limit))
    return start, (rd.pos, id_size), end


def _parse_cie(meta, start, body, limit, cache):
    body_pos, id_size = body
    record_end = limit
    rd = _Reader(meta.flat, body_pos + id_size, record_end, "eh-frame",
                 meta.image_size)
    cie = Cie()
    cie.offset = start
    cie.length = record_end - start
    version = rd.u8()
    if version not in SUPPORTED_CIE_VERSIONS:
        raise FdeError("unsupported-cie-version",
                       "%s: CIE at 0x%x has version %d (supported: %s)"
                       % (meta.name, start, version,
                          ",".join(str(v) for v in SUPPORTED_CIE_VERSIONS)))
    cie.version = version
    cie.augmentation = rd.cstring()
    aug = cie.augmentation
    if not aug:
        raise FdeError(
            "unknown-augmentation",
            "%s: CIE at 0x%x has the empty augmentation string; only 'z' "
            "based augmentations are understood" % (meta.name, start))
    if not aug.startswith("z"):
        raise FdeError(
            "unknown-augmentation",
            "%s: CIE at 0x%x augmentation %r does not start with 'z'"
            % (meta.name, start, aug))
    for char in aug[1:]:
        if char not in SUPPORTED_AUGMENTATIONS:
            raise FdeError(
                "unknown-augmentation:%s" % char,
                "%s: CIE at 0x%x augmentation %r uses the unsupported 'z%s' "
                "data" % (meta.name, start, aug, char))
    cie.code_align = rd.uleb()
    cie.data_align = rd.sleb()
    cie.return_reg = rd.u8() if version == 1 else rd.uleb()
    aug_len = rd.uleb()
    aug_end = rd.pos + aug_len
    if aug_end > record_end:
        raise FdeError("record-length-past-extent",
                       "%s: CIE at 0x%x augmentation data (0x%x bytes) runs "
                       "past the record end 0x%x"
                       % (meta.name, start, aug_len, record_end))
    # The augmentation fields are read through a reader bounded by the
    # declared augmentation data length, so a short aug_len can never make
    # them consume the initial instructions.  Trailing bytes are allowed.
    aug_rd = _Reader(meta.flat, rd.pos, aug_end, "cie-augmentation-data",
                     meta.image_size)
    for char in aug[1:]:
        if char == "R":
            cie.fde_enc = aug_rd.u8()
        elif char == "P":
            personality_enc = aug_rd.u8()
            aug_rd.skip_encoded(personality_enc, "personality")
        elif char == "L":
            cie.lsda_enc = aug_rd.u8()
            if (cie.lsda_enc != DW_EH_PE_OMIT
                    and (cie.lsda_enc & 0x0F) not in DW_EH_PE_FORMATS):
                raise FdeError("unsupported-encoding:lsda",
                               "%s: CIE at 0x%x LSDA encoding 0x%02x"
                               % (meta.name, start, cie.lsda_enc))
        elif char == "S":
            pass                                   # signal frame, no data
    if cie.fde_enc not in FDE_PC_ENCODINGS:
        raise FdeError(
            "unsupported-encoding:pc_begin",
            "%s: CIE at 0x%x declares the FDE pointer encoding 0x%02x"
            % (meta.name, start, cie.fde_enc))
    rd.pos = aug_end
    if cie.code_align == 0:
        raise FdeError("bad-cie-code-alignment",
                       "%s: CIE at 0x%x has code alignment factor 0"
                       % (meta.name, start))
    cache[start] = cie
    return cie


def _parse_fde(meta, start, body, record_end, walk_start):
    body_pos, id_size = body
    rd = _Reader(meta.flat, body_pos, record_end, "eh-frame", meta.image_size)
    cie_pointer = rd.u64() if id_size == 8 else rd.u32()
    if cie_pointer == 0:
        raise FdeError("bad-cie-pointer",
                       "%s: record at 0x%x has CIE id 0 inside an FDE branch"
                       % (meta.name, start))
    cie_offset = body_pos - cie_pointer
    if cie_offset < walk_start or cie_offset >= body_pos:
        raise FdeError(
            "bad-cie-pointer",
            "%s: FDE at 0x%x points back 0x%x bytes to 0x%x, outside the "
            ".eh_frame walk [0x%x,0x%x)"
            % (meta.name, start, cie_pointer, cie_offset, walk_start,
               body_pos))
    return cie_offset, rd


def walk_eh_frame(meta, header):
    """Independent linear walk of .eh_frame; returns Fde list in walk order."""
    eh_start = header.eh_frame_ptr
    ro_lo, ro_hi = meta.ro
    if not (ro_lo <= eh_start < ro_hi):
        raise FdeError("eh-frame-outside-ro",
                       "%s: .eh_frame_ptr 0x%x is not inside the RO segment "
                       "[0x%x,0x%x)" % (meta.name, eh_start, ro_lo, ro_hi))
    if eh_start % 4:
        raise FdeError("eh-frame-misaligned",
                       "%s: .eh_frame_ptr 0x%x is not 4-byte aligned"
                       % (meta.name, eh_start))
    if eh_start > header.start and header.end > eh_start:
        raise FdeError("eh-frame-overlaps-hdr",
                       "%s: .eh_frame at 0x%x overlaps .eh_frame_hdr "
                       "[0x%x,0x%x)" % (meta.name, eh_start, header.start,
                                        header.end))
    limit = ro_hi
    rd = _Reader(meta.flat, eh_start, limit, "eh-frame", meta.image_size)
    cies = {}
    fdes = []
    while True:
        start, body, record_end = _record_extent(rd, limit, meta.name)
        if body is None:                            # zero terminator
            rd.pos = record_end
            break
        body_pos, id_size = body
        first = rd.u64() if id_size == 8 else rd.u32()
        if first == CIE_ID_32:
            body = (body_pos, id_size)
            rd.pos = body_pos + id_size
            _parse_cie(meta, start, body, record_end, cies)
            rd.pos = record_end
            continue
        cie_offset, fde_rd = _parse_fde(meta, start, body, record_end,
                                        eh_start)
        cie = cies.get(cie_offset)
        if cie is None:
            raise FdeError(
                "bad-cie-pointer",
                "%s: FDE at 0x%x points to 0x%x, which is not a CIE parsed "
                "by this walk" % (meta.name, start, cie_offset))
        enc = cie.fde_enc
        if enc not in FDE_PC_ENCODINGS:
            raise FdeError(
                "unsupported-encoding:pc_begin",
                "%s: CIE at 0x%x declares the FDE pointer encoding 0x%02x"
                % (meta.name, cie_offset, enc))
        pc_begin = fde_rd.encoded(enc, (DW_EH_PE_APP_ABS,
                                        DW_EH_PE_APP_PCREL), "fde-pc-begin",
                                  datarel_base=cie_offset)
        fmt = enc & 0x0F
        if DW_EH_PE_FORMATS[fmt][1] is None:
            raise FdeError("unsupported-encoding:pc_range",
                           "%s: FDE at 0x%x uses the variable-length format "
                           "0x%x for pc_range" % (meta.name, start, fmt))
        pc_range = fde_rd.fixed(fmt)
        if pc_range == 0:
            raise FdeError("fde-empty-range",
                           "%s: FDE at 0x%x covers the empty range at 0x%x"
                           % (meta.name, start, pc_begin))
        if pc_range < 0:
            raise FdeError("fde-negative-range",
                           "%s: FDE at 0x%x has pc_range %d at 0x%x"
                           % (meta.name, start, pc_range, pc_begin))
        fdes.append(Fde(pc_begin, pc_begin + pc_range, start, record_end - start,
                        cie_offset))
        rd.pos = record_end
    return fdes, rd.pos


def parse_fdes(meta):
    """Parse the header and walk .eh_frame; cross-check both, then bounds."""
    header = parse_header(meta)
    fdes, terminator_end = walk_eh_frame(meta, header)
    _crosscheck(meta, header, fdes)
    _validate_ranges(meta, fdes)
    return header, sorted(fdes, key=lambda fde: fde.start), terminator_end


def _crosscheck(meta, header, fdes):
    table = header.table
    for index in range(1, len(table)):
        if table[index][0] <= table[index - 1][0]:
            raise FdeError(
                "table-not-sorted",
                "%s: .eh_frame_hdr table entry %d has initial_location 0x%x "
                "after 0x%x (the table must be strictly sorted)"
                % (meta.name, index, table[index][0], table[index - 1][0]))
    if header.fde_count != len(fdes):
        raise FdeError(
            "fde-count-mismatch",
            "%s: .eh_frame_hdr declares %d FDE(s) but the .eh_frame walk "
            "found %d" % (meta.name, header.fde_count, len(fdes)))
    walked = [(fde.start, fde.address) for fde in fdes]
    if len(set(walked)) != len(walked):
        raise FdeError("duplicate-fde-record",
                       "%s: the .eh_frame walk produced duplicate "
                       "(pc_begin, address) pairs" % meta.name)
    only_table = sorted(set(table) - set(walked))
    only_walk = sorted(set(walked) - set(table))
    if only_table or only_walk:
        raise FdeError(
            "table-walk-disagreement",
            "%s: .eh_frame_hdr and the .eh_frame walk disagree "
            "(%d entr(y|ies) only in the table, %d only in the walk; "
            "first table-only %r, first walk-only %r)"
            % (meta.name, len(only_table), len(only_walk),
               only_table[0] if only_table else None,
               only_walk[0] if only_walk else None))


def _validate_ranges(meta, fdes):
    text_lo, text_hi = meta.text
    for fde in fdes:
        if fde.start % 4:
            raise FdeError(
                "fde-start-misaligned",
                "%s: FDE at 0x%x starts at 0x%x (not 4-byte aligned)"
                % (meta.name, fde.address, fde.start))
        if fde.end % 4:
            raise FdeError(
                "fde-end-misaligned",
                "%s: FDE at 0x%x ends at 0x%x (not 4-byte aligned)"
                % (meta.name, fde.address, fde.end))
        if not (text_lo <= fde.start and fde.end <= text_hi):
            raise FdeError(
                "fde-outside-text",
                "%s: FDE at 0x%x covers [0x%x,0x%x), outside the module TEXT "
                "[0x%x,0x%x)" % (meta.name, fde.address, fde.start, fde.end,
                                 text_lo, text_hi))
    ordered = sorted(fdes, key=lambda fde: (fde.start, fde.end))
    for index in range(1, len(ordered)):
        prev, cur = ordered[index - 1], ordered[index]
        if cur.start < prev.end:
            raise FdeError(
                "overlapping-fde",
                "%s: FDE at 0x%x covers [0x%x,0x%x) and FDE at 0x%x covers "
                "[0x%x,0x%x); they overlap"
                % (meta.name, prev.address, prev.start, prev.end,
                   cur.address, cur.start, cur.end))


# ---------------------------------------------------------------- provenance

def func_symbols(meta):
    """{image_offset: [name, ...]} for DEFINED STT_FUNC dynamic symbols."""
    count = meta.layout["dynsym_count"]
    try:
        tags = M.read_dynamic(meta.flat, meta.mod0, meta.image_size,
                              meta.data[0], meta.data[1] - meta.data[0])
        # Same cross-check g3_ctor_roots applies: with DT_HASH present the
        # layout's dynsym_count must equal nchain, so a forged count can
        # neither hide nor truncate STT_FUNC provenance.
        if M.DT_HASH in tags:
            h = tags[M.DT_HASH]
            if h < 0 or h + 8 > len(meta.flat):
                raise FdeError("dynsym-invalid",
                               "%s: DT_HASH 0x%x outside the flat image"
                               % (meta.name, h))
            nchain = struct.unpack_from("<I", meta.flat, h + 4)[0]
            if nchain != count:
                raise FdeError("dynsym-invalid",
                               "%s: DT_HASH nchain %d != layout dynsym_count %d"
                               % (meta.name, nchain, count))
        syms = M.parse_dynsyms(meta.flat, tags, count)
        M.validate_symbols(meta.name, syms, meta.image_size)
    except (M.ElfError, struct.error, ValueError, TypeError, KeyError) as exc:
        raise FdeError("dynsym-invalid", "%s: %s" % (meta.name, exc))
    out = {}
    for sym in syms:
        if sym["type"] != M.STT_FUNC or not M.sym_defined(sym, meta.image_size):
            continue
        out.setdefault(sym["value"], []).append(sym["name"])
    return out


def derive_ctor_targets(image, context, sentinel=0):
    """Reuse g3_ctor_roots.derive(): -> (frozenset(target offsets), info dict).

    `image` is a g3_init_reach.Image (the reference link's relocated buffer).
    No table derivation is reimplemented here; a refusal propagates as the
    existing typed `g3_ctor_roots.CtorRefusal` / `CtorInputError`.
    """
    array = G.derive(image, image_sha256(image), context, sentinel)
    if array is None:
        return frozenset(), {"status": "absent",
                             "detail": "the module declares no DT_INIT_ARRAY"}
    targets = frozenset(int(slot.target) - image.base for slot in array.slots)
    info = {"status": "derived", "entries": array.count,
            "array": [_hex(array.start_va), _hex(array.array_end)],
            "table_sha256": G.table_digest(array)}
    return targets, info


def image_sha256(image):
    return hashlib.sha256(bytes(image.flat)).hexdigest()


# ------------------------------------------------------------------ conflicts

def _conflict_context(meta, context, base=0):
    if context is not None:
        return context
    try:
        return LS.Context(meta.flat, meta.layout, base, T.decode)
    except LS.InputError as exc:
        raise FdeError("metadata-invalid",
                       "%s: exclusion context: %s" % (meta.name, exc))


def boundary_conflicts(meta, boundaries, context):
    """Boundaries that touch known-DATA / loader-consumed extents.

    The exclusion indexes are the SAME ones `g3_ctor_roots` uses
    (`build_exclusions`); only the queried window differs: the WHOLE boundary
    range instead of the 4-byte point `_target_refusal` inspects, because a
    candidate function that swallows a metadata blob is a conflict even when
    its first word happens to be clean.
    """
    mod0 = meta.mod0
    exclusions = G.build_exclusions(context, mod0)
    base = getattr(context, "base", 0)
    header_end = exclusions["header_end"]
    out = []
    for fde in boundaries:
        lo, hi = fde.start - base, fde.end - base
        reasons = []
        details = []
        if _overlap(lo, hi, 0, header_end):
            reasons.append("boundary-overlaps-image-header")
            details.append("overlaps the NSO header/MOD0 [0x0,0x%x)"
                           % header_end)
        for key, label in (("meta", "loader-consumed"),
                           ("reloc", "relocation-site"),
                           ("ranges", "defined-storage")):
            hit = exclusions[key].find(lo, hi)
            if hit is not None:
                reasons.append("boundary-overlaps-%s:%s" % (label, hit[2]))
                details.append("[0x%x,0x%x) intersects %s %r [0x%x,0x%x)"
                               % (lo, hi, label, hit[2],
                                  base + hit[0], base + hit[1]))
        hit = exclusions["points"].find(lo, hi)
        if hit is not None:
            sym = hit[2]
            reasons.append("boundary-overlaps-storage-point")
            details.append("[0x%x,0x%x) contains the zero-sized %r address "
                           "0x%x (type %d)" % (lo, hi, sym.get("name"),
                                               base + hit[0], sym["type"]))
        # The exact 4-byte verdict `g3_ctor_roots` itself would produce for the
        # candidate START is recorded too: these reason codes are the ones the
        # root policy already knows.
        bad = G._target_refusal(fde.start, context, mod0, exclusions)
        if bad is not None and bad[0] not in reasons:
            reasons.append(bad[0])
            details.append(bad[1])
        if reasons:
            out.append({"start": fde.start, "end": fde.end,
                        "reasons": sorted(set(reasons)),
                        "detail": "; ".join(details)})
    return out


# ------------------------------------------------------------------ manifest

def text_gaps(meta, boundaries):
    """Sorted TEXT gaps not covered by any FDE (image offsets)."""
    text_lo, text_hi = meta.text
    gaps = []
    cursor = text_lo
    for fde in sorted(boundaries, key=lambda fde: fde.start):
        if fde.start > cursor:
            gaps.append((cursor, fde.start))
        cursor = max(cursor, fde.end)
    if cursor < text_hi:
        gaps.append((cursor, text_hi))
    return gaps


def build_manifest(meta, header, terminator_end, fdes, context=None,
                   ctor_targets=(), ctor_info=None):
    """Deterministic candidate manifest for one module."""
    context = _conflict_context(meta, context)
    symbols = func_symbols(meta)
    ctor_targets = frozenset(int(t) for t in ctor_targets)
    boundaries = []
    counts = {"fde": 0, "dynsym_func": 0, "dt_init_array": 0}
    for fde in sorted(fdes, key=lambda fde: fde.start):
        provenance = ["fde"]
        counts["fde"] += 1
        if fde.start in symbols:
            provenance.append("dynsym_func")
            counts["dynsym_func"] += 1
        if fde.start in ctor_targets:
            provenance.append("dt_init_array")
            counts["dt_init_array"] += 1
        boundaries.append({"start": _hex(fde.start), "end": _hex(fde.end),
                           "provenance": provenance})
    covered = set(fde.start for fde in fdes)
    conflicts = boundary_conflicts(meta, fdes, context)
    # A derived constructor that is not an FDE start is reported, never
    # dropped: the frontend has no candidate boundary for it.
    for target in sorted(ctor_targets - covered):
        conflicts.append({"start": target, "end": target,
                          "reasons": ["dt-init-array-not-fde-start"],
                          "detail": "DT_INIT_ARRAY target 0x%x is not the "
                                    "start of any FDE" % target})
    conflicts.sort(key=lambda item: (item["start"], item["end"]))
    gaps = text_gaps(meta, fdes)
    if ctor_info is None:
        ctor_info = {"status": "not-evaluated",
                     "detail": "no DT_INIT_ARRAY derivation was supplied"}
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "authority": AUTHORITY,
        "authority_note": (
            "FDE starts are EVIDENCE for candidate boundaries, never roots "
            "(D024: compiled is not authorized). Nothing in this manifest "
            "authorizes execution; the executable entry set stays the CFG "
            "closure of the roots admitted by the current root policy."),
        "address_space": ("image offsets: guest VA = guest_base + offset "
                          "(the manifest never depends on the load base)"),
        "module": meta.json(),
        "text": {"start": _hex(meta.text[0]), "end": _hex(meta.text[1]),
                 "size": meta.text[1] - meta.text[0]},
        "eh_frame_hdr": {"start": _hex(header.start),
                         "end": _hex(header.end),
                         "size": header.end - header.start,
                         "fhdr_version": HDR_VERSION,
                         "eh_frame_ptr_encoding": _hex(HDR_ENC_EH_FRAME_PTR),
                         "fde_count_encoding": _hex(HDR_ENC_FDE_COUNT),
                         "table_encoding": _hex(HDR_ENC_TABLE),
                         "table_entries": len(header.table),
                         "padding_bytes": header.padding},
        "eh_frame": {"start": _hex(header.eh_frame_ptr),
                     "end": _hex(terminator_end),
                     "bound": _hex(meta.ro[1]),
                     "bound_note": ("the linear walk is bounded by the RO "
                                    "segment end; the zero terminator was "
                                    "required and found")},
        "ctor_table": dict(ctor_info),
        "exclusions": {"status": "evaluated",
                       "note": ("g3_ctor_roots.build_exclusions over the same "
                                "metadata; conflicts are reported, never "
                                "dropped or promoted")},
        "counts": {"boundaries": len(boundaries),
                   "fde": counts["fde"],
                   "dynsym_func": counts["dynsym_func"],
                   "dt_init_array": counts["dt_init_array"],
                   "ctor_targets": len(ctor_targets),
                   "ctor_targets_on_fde_start": len(covered & ctor_targets),
                   "text_gaps": len(gaps),
                   "conflicts": len(conflicts)},
        "boundaries": boundaries,
        "text_gaps": [{"start": _hex(lo), "end": _hex(hi),
                       "size": hi - lo} for lo, hi in gaps],
        "conflicts": [{"start": _hex(item["start"]),
                       "end": _hex(item["end"]),
                       "reasons": item["reasons"],
                       "detail": item["detail"]} for item in conflicts],
    }
    return manifest


def manifest_for(flat, layout, context=None, name=None, ctor_targets=(),
                 ctor_info=None):
    """One-shot: flat + layout -> candidate manifest (fail closed)."""
    meta = read_module(flat, layout, name)
    header, fdes, terminator_end = parse_fdes(meta)
    return build_manifest(meta, header, terminator_end, fdes, context,
                          ctor_targets, ctor_info)


def write_manifest(manifest, path):
    directory = os.path.dirname(os.path.abspath(path))
    if directory and not os.path.isdir(directory):
        os.makedirs(directory)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=1, sort_keys=True)
        handle.write("\n")
    os.replace(tmp, path)


# ----------------------------------------------------------------------- CLI

def _repo_root():
    return os.path.dirname(os.path.dirname(_HERE))


def _canonical(path):
    """Resolved, case-normalized path (junctions/symlinks followed)."""
    return os.path.normcase(os.path.realpath(os.path.abspath(path)))


def inside_tree(path, root=None):
    """True when `path` resolves inside the source tree `root`."""
    path = _canonical(path)
    root = _canonical(root or _repo_root())
    try:
        common = os.path.commonpath([path, root])
    except ValueError:                              # different drives
        return False
    return common == root


def _parse_hex(text):
    return int(text, 0)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="D024 Stage A: flat module -> CANDIDATE boundary manifest")
    parser.add_argument("flat", help="flat module image (.flat)")
    parser.add_argument("layout", help="its layout JSON (.layout.json)")
    parser.add_argument("--out", required=True, help="manifest JSON to write")
    parser.add_argument("--name", default=None,
                        help="module name (default: the layout's name)")
    parser.add_argument("--base", default="0x0",
                        help="guest base for the exclusion context (default 0)")
    parser.add_argument("--sites", default=None,
                        help="reference-link sites TSV; enables the "
                             "dt_init_array provenance through "
                             "g3_ctor_roots.derive()")
    parser.add_argument("--sentinel", default="0x0",
                        help="constructor sentinel used by derive()")
    args = parser.parse_args(argv)

    repo = _repo_root()
    if inside_tree(args.out, repo):
        parser.error("--out %r is inside the source tree (%r); game-derived "
                     "manifests must stay outside it (D006)"
                     % (args.out, repo))
    try:
        base = _parse_hex(args.base)
        sentinel = _parse_hex(args.sentinel)
    except ValueError as exc:
        parser.error("bad --base/--sentinel: %s" % exc)
    # A stale manifest from an earlier run must never survive a refusal.
    if os.path.exists(args.out):
        os.remove(args.out)

    try:
        with open(args.flat, "rb") as handle:
            flat = handle.read()
        with open(args.layout, "r", encoding="utf-8") as handle:
            layout = json.load(handle)
    except (OSError, ValueError) as exc:
        sys.stderr.write("g3_fde_frontend: input error: %s\n" % exc)
        return 1
    if not isinstance(layout, dict):
        sys.stdout.write("REFUSED layout-invalid\n")
        sys.stderr.write("g3_fde_frontend: %s: layout is not a JSON object\n"
                         % args.layout)
        return 2

    name = args.name or layout.get("name")
    try:
        meta = read_module(flat, layout, name)
        context = _conflict_context(meta, None, base)
        ctor_targets, ctor_info = frozenset(), None
        if args.sites:
            import g3_init_reach as R
            try:
                sites = R.read_sites(args.sites)
            except (OSError, ValueError, KeyError, IndexError) as exc:
                raise FdeError("sites-invalid", "%s: %s" % (args.sites, exc))
            module_key = meta.name
            image = R.Image(module_key, base, flat, layout,
                            sites.get(module_key, {}))
            ctor_targets, ctor_info = derive_ctor_targets(image, context,
                                                          sentinel)
        header, fdes, terminator_end = parse_fdes(meta)
        manifest = build_manifest(meta, header, terminator_end, fdes, context,
                                 ctor_targets, ctor_info)
    except NoEhFrameHdr as exc:
        sys.stdout.write("NO_EH_FRAME_HDR %s\n" % exc)
        return 3
    except FdeError as exc:
        sys.stdout.write("REFUSED %s\n" % exc.reason)
        sys.stderr.write("g3_fde_frontend: %s: %s\n"
                         % (meta_name(args, layout), exc))
        return 2
    except (G.CtorRefusal, G.CtorInputError) as exc:
        sys.stdout.write("REFUSED ctor-table %s\n"
                         % getattr(exc, "reason", "input-error"))
        sys.stderr.write("g3_fde_frontend: %s: %s\n"
                         % (meta_name(args, layout), exc))
        return 2
    except LS.InputError as exc:
        sys.stdout.write("REFUSED metadata-invalid\n")
        sys.stderr.write("g3_fde_frontend: %s: %s\n"
                         % (meta_name(args, layout), exc))
        return 2

    write_manifest(manifest, args.out)
    counts = manifest["counts"]
    print("%s: %d candidate boundaries (%d dynsym_func, %d dt_init_array), "
          "%d text gap(s), %d conflict(s) -> %s"
          % (manifest["module"]["name"], counts["boundaries"],
             counts["dynsym_func"], counts["dt_init_array"],
             counts["text_gaps"], counts["conflicts"], args.out))
    return 0


def meta_name(args, layout):
    return args.name or layout.get("name") or args.flat


if __name__ == "__main__":
    sys.exit(main())
