#!/usr/bin/env python3
"""Offline veneer-root proof for G3 (D021 candidate, PHASE 1, no driver).

The boot stops on an *indirect* target that the old rule cannot justify.  This
module answers exactly one question, offline and deterministically:

    given an observed indirect target V, is the ORIGINAL code at V a small
    translation veneer whose existence is INDEPENDENTLY proved by static
    evidence, so it may be treated as a code root?

It is a proof, not a heuristic.  ALL of the following must hold; anything else
is a refusal with a specific reason (never a fallback, never a nearest match,
never a fabricated symbol):

1. Static materialization.  Some adjacent ADRP+ADD pair *already present in the
   reached instruction map* materializes exactly V (same Xd in x0..x15, ADD64
   no-flags lo12 with the ACTUAL sh bit 22 clear: `ADD Xd,Xn,#imm12` only, so
   `ADD #0, LSL #12` -- same value, different shape -- is refused).  The set of
   materialized values is derived from the reached code alone; the observed
   target is only ever compared against it.
2. Shape.  V is 4-aligned, in the same module TEXT, and the full span is
   in-text: 0..3 exact `MOV Xd, Xm` (ORR Xd, XZR, Xm, LSL #0) with d/m in
   x0..x15, then exactly one unconditional B imm26 to T.
3. Tail.  T is in the SAME TEXT and is justified by the UNCHANGED old rule: a
   DEFINED STT_FUNC dynsym entry at exactly T.  No STT binding/symbol is ever
   fabricated for V, no sized DEFINED symbol of ANY type (FUNC/OBJECT/NOTYPE/
   ...) at an earlier or equal VA may cover V -- a veneer cannot hide inside a
   data object the linker also describes -- the prior
   word must be a terminator (B/BR/RET/UDF) so nothing falls through into V,
   and no relocation SITE may overlap the span.  T must not itself be a veneer
   (no chains).
4. eh_frame_hdr.  As an ADDITIONAL guard (not a general FDE-root category),
   V must be an EXACT initial location in the module's `.eh_frame_hdr`, found
   only through the MOD0 signed relative offsets (never through raw NSO header
   guesses).  The header must be the single supported encoding
   `01 1b 03 3b`, the table bounded by MOD0's end, strictly ascending, inside
   the image, with an aligned FDE pointer inside file-backed RO.  Missing,
   unsupported or malformed tables refuse the NEW category; the old symbol
   rules are untouched.

The caller applies the nnMain pre-G4 guard BEFORE this category.  The observed
target must equal the prederived V exactly (never V+4, never an interior
address); a refusal here has no fallback.

Immutable proof input.  `Prover` snapshots, at construction, the ORIGINAL
flat bytes of every module (after checking them against the descriptor's
`layout["sha256"]`) together with the metadata it depends on (symbols, dynamic
tags, text/RO extents).  Every later `prove()` call -- including the audit
hashes -- reads only that snapshot, so a caller mutating its own `flat`
bytearray or symbol/tag lists afterwards cannot change a verdict or evidence.
Bytes mutated BEFORE construction are refused.  Each returned `Verdict` owns
deep-copied audit primitives, so mutating a returned evidence dict cannot
change a later `prove()` either.

Documented input errors (fail closed, never a silent default): a module
descriptor that is incomplete, whose flat bytes do not match its
`layout["sha256"]`, or whose relocation tags are unpaired (DT_RELA without
DT_RELASZ, DT_JMPREL without DT_PLTRELSZ, DT_RELR without DT_RELRSZ) or whose
tables cannot be decoded raise `InputError` from the constructor.  There is no
"size 0" fallback that would silently drop relocation sites.

Interface (one object, one call)::

    prover = Prover(modules, reached)      # immutable descriptors + reached map
    verdict = prover.prove(target)         # -> Verdict(ok, reason, detail,
                                           #            evidence)  [JSON-safe]

`modules` are the dicts produced by `aot_module.load_module` (strict NSO/
symbol validation already done there), `reached` is a `{module: {VA, ...}}`
map from the approved root scan (or a `va -> bool` callable;
`reached_from_scan()` adapts an `g3_init_reach.Scan`).  Metadata/EH/shape
parsing, the old strict symbol lookup and relocation-site decoding stay inside
this module; the caller does not learn any of them.

No game data, no host pointers, no title VA and no hash allowlist appear here;
every derived fact is recomputed from the supplied original bytes.
"""

import copy
import hashlib
import struct

import aot_module as M
import aot_translate as T

MASK64 = (1 << 64) - 1

# Symbol types the COVER guard considers (tail justification stays STT_FUNC).
STT_NOTYPE = 0
STT_OBJECT = 1

# The only supported .eh_frame_hdr prefix: version 1, eh_frame_ptr_enc 0x1b
# (pcrel sdata4), fde_count_enc 0x03 (udata4), table_enc 0x3b (datarel sdata4).
EH_HDR_PREFIX = b"\x01\x1b\x03\x3b"
EH_HDR_MIN = 12            # prefix(4) + eh_frame_ptr(4) + fde_count(4)
EH_ROW = 8                 # signed32 datarel + signed32 fde pointer
MAX_MOVS = 3
# Registers a veneer may touch: x0..x15 (no callee-saved, no x16/x17/x18,
# no SP/ZR in any operand).
R_LIMIT = 16

MOV = "mov"
TERMINATORS = ("b", "br", "ret")


class InputError(ValueError):
    """Documented fail-closed PROOF-INPUT error (see module docstring).

    Raised by `Prover.__init__` only, never by `prove()`: a refused candidate
    is a `Verdict`, but an unusable set of input descriptors is an error, so
    nothing can be silently proved against a partial/mutated description.
    """


def sha256(data):
    return hashlib.sha256(bytes(data)).hexdigest()


def _sx32(value):
    return value - (1 << 32) if value & 0x80000000 else value


class Verdict:
    """Deterministic decision: evidence (ok) or a specific refusal reason."""

    __slots__ = ("ok", "reason", "detail", "evidence")

    def __init__(self, ok, reason, detail, evidence=None):
        self.ok = ok
        self.reason = reason
        self.detail = detail
        self.evidence = evidence

    def to_json(self):
        return {"ok": self.ok, "reason": self.reason, "detail": self.detail,
                "evidence": self.evidence}

    def __repr__(self):
        return "Verdict(ok=%r, reason=%r)" % (self.ok, self.reason)


def _refuse(reason, detail, evidence=None):
    return Verdict(False, reason, detail, evidence)


# ------------------------------------------------------------------ inputs

def reached_from_scan(scan, world):
    """Adapter: an approved root scan -> {module: {reached VA, ...}}.

    Both the ADRP and the ADD of a materialization are ordinary reached
    instructions; the scan's per-word bitmap is the whole authority here.
    """
    out = {}
    for im in world.images:
        bitmap = scan.visited.get(im.name)
        if bitmap is None:
            continue
        base = im.text[0]
        out[im.name] = {base + 4 * i for i, flag in enumerate(bitmap) if flag}
    return out


class Prover:
    """Deep, immutable veneer-root prover.  Construct once, call prove() many."""

    def __init__(self, modules, reached):
        if not modules:
            raise InputError("Prover needs at least one module")
        self._mods = sorted((self._snapshot(m) for m in modules),
                            key=lambda m: m["base"])
        self._by_name = {m["name"]: m for m in self._mods}
        names = [m["name"] for m in self._mods]
        if len(set(names)) != len(names):
            raise InputError("duplicate module name")
        start = 0
        for m in self._mods:
            if m["base"] < start:
                raise InputError("modules overlap at 0x%x" % m["base"])
            start = m["base"] + m["image_size"]
        self._frozen = None
        self._callable = None
        if callable(reached):
            self._callable = reached
        else:
            self._frozen = {
                name: frozenset(int(v) for v in reached.get(name, ()))
                for name in names}
        self._relocs = {m["name"]: self._reloc_sites(m) for m in self._mods}
        self._func_at = {}
        self._sized = {}
        for m in self._mods:
            base = m["base"]
            sized = []
            for sym in m["syms"]:
                if not M.sym_defined(sym, m["image_size"]):
                    continue
                # COVER guard: ANY defined sized symbol (STT_FUNC, OBJECT,
                # NOTYPE, ...), not only STT_FUNC -- this is what keeps a
                # literal data word from masquerading as a veneer.
                if sym["size"] > 0:
                    sized.append((base + sym["value"],
                                  base + sym["value"] + sym["size"], sym))
                # TAIL justification stays the UNCHANGED old rule.
                if sym["type"] == M.STT_FUNC:
                    self._func_at.setdefault(base + sym["value"], []).append(
                        (m["name"], sym))
            self._sized[m["name"]] = sized
        self._materializations = self._build_materializations()
        self._eh_cache = {}

    # -- immutable input snapshot -------------------------------------------

    @staticmethod
    def _snapshot(mod):
        """Freeze the original bytes plus every dependent field we read."""
        try:
            flat = bytes(mod["flat"])
            layout = mod["layout"]
            name = str(mod["name"])
            base = int(mod["base"])
            image_size = int(mod["image_size"])
            tags = dict(mod["tags"])
            syms = tuple(dict(sym) for sym in mod["syms"])
            text = (int(layout["text"][0]), int(layout["text"][1]))
            ro = (int(layout["ro"][0]), int(layout["ro"][1]))
            want = layout["sha256"]
        except (KeyError, TypeError, IndexError) as exc:
            raise InputError(
                "module descriptor is incomplete (%r); the prover needs the "
                "fields produced by aot_module.load_module plus "
                "layout[text/ro/sha256]" % (exc,)) from exc
        actual = sha256(flat)
        if not isinstance(want, str) or actual != want:
            raise InputError(
                "%s: original flat SHA-256 %s does not match layout sha256 "
                "%r (bytes changed before proof construction)"
                % (name, actual, want))
        if image_size < len(flat):
            raise InputError("%s: image_size 0x%x < flat 0x%x"
                             % (name, image_size, len(flat)))
        return {"name": name, "base": base, "image_size": image_size,
                "flat": flat, "tags": tags, "syms": syms,
                "text": text, "ro": ro, "sha256": actual}

    # -- derived static facts ------------------------------------------------

    def _reloc_sites(self, mod):
        """Absolute 8-byte relocation SITE addresses (DT_RELA/JMPREL + RELR).

        The address tag and its size tag are a PAIR: both or neither.  A
        partial pair is a documented input error, never a silent size 0 that
        would drop every site.
        """
        tags = mod["tags"]
        flat = mod["flat"]
        base = mod["base"]
        size = mod["image_size"]
        pairs = ((M.DT_RELA, M.DT_RELASZ, "DT_RELA", "DT_RELASZ"),
                 (M.DT_JMPREL, M.DT_PLTRELSZ, "DT_JMPREL", "DT_PLTRELSZ"),
                 (M.DT_RELR, M.DT_RELRSZ, "DT_RELR", "DT_RELRSZ"))
        for addr_tag, sz_tag, addr_name, sz_name in pairs:
            if (addr_tag in tags) != (sz_tag in tags):
                raise InputError(
                    "%s: %s and %s must appear together (found %s only)"
                    % (mod["name"], addr_name, sz_name,
                       addr_name if addr_tag in tags else sz_name))
        sites = []
        try:
            if M.DT_RELA in tags:
                for e in M.parse_rela_table(flat, tags[M.DT_RELA],
                                            tags[M.DT_RELASZ], size,
                                            "DT_RELA"):
                    sites.append(base + e["where"])
            if M.DT_JMPREL in tags:
                for e in M.parse_rela_table(flat, tags[M.DT_JMPREL],
                                            tags[M.DT_PLTRELSZ], size,
                                            "DT_JMPREL"):
                    sites.append(base + e["where"])
            if M.DT_RELR in tags:
                for where in M.decode_relr(flat, tags[M.DT_RELR],
                                           tags[M.DT_RELRSZ], size):
                    sites.append(base + where)
        except (M.ElfError, struct.error, ValueError) as exc:
            raise InputError("%s: relocation table cannot be decoded: %s"
                             % (mod["name"], exc)) from exc
        return sorted(sites)

    def _word(self, mod, va):
        off = va - mod["base"]
        if off < 0 or off + 4 > len(mod["flat"]):
            return None
        return struct.unpack_from("<I", mod["flat"], off)[0]

    def _materialize(self, pc, word):
        """ADRP+ADD at (pc, pc+4) -> (value, record) or None.

        ADRP is prefiltered on its opcode bits, then decoded by the project
        decoder with module semantics (PC-relative in guest VAs).
        """
        if (word & 0x9F000000) != 0x90000000:
            return None
        mod = self._module_of(pc)
        if mod is None:
            return None
        add_pc = pc + 4
        add_word = self._word(mod, add_pc)
        if add_word is None:
            return None
        if (add_word >> 22) & 1:
            # Actual ADD sh bit: `ADD #0, LSL #12` materializes the same value
            # as `ADD #0` but is a DIFFERENT literal shape.  The decoder folds
            # sh into imm, so bit 22 must be checked on the raw word.
            return None
        try:
            a = T.decode(pc, word, module=True)
            b = T.decode(add_pc, add_word, module=True)
        except T.DecodeError:
            return None
        if a["kind"] != "adrp" or a["rd"] >= R_LIMIT:
            return None
        if b["kind"] != "addsub_imm":
            return None
        if (b["op"] != 0 or b["s"] != 0 or b["width"] != 64
                or b["imm"] >= 0x1000              # plain lo12 only
                or b["rn"] != a["rd"] or b["rd"] != a["rd"]):
            return None
        value = (a["value"] + b["imm"]) & MASK64
        return value, {"pc": pc, "word": word, "add_pc": add_pc,
                       "add_word": add_word, "value": value, "reg": a["rd"]}

    def _build_materializations(self):
        """Every ADRP+ADD value materialized by REACHED original bytes.

        Independent of any observed target: the map is a function of the
        reached code only, and prove() merely looks its argument up.
        """
        out = {}
        for mod in self._mods:
            text_lo, text_hi = self._text(mod)
            lo = max(mod["base"], text_lo)
            hi = min(mod["base"] + len(mod["flat"]), text_hi)
            for off in range(lo - mod["base"], hi - mod["base"], 4):
                pc = mod["base"] + off
                if not (self._is_reached(pc)
                        and self._is_reached(pc + 4)):
                    continue
                word = struct.unpack_from("<I", mod["flat"], off)[0]
                got = self._materialize(pc, word)
                if got is None:
                    continue
                value, rec = got
                out.setdefault(value, []).append(
                    (mod["name"],
                     dict(rec, module=mod["name"],
                          sourceModuleSHA=mod["sha256"])))
        for rows in out.values():
            rows.sort(key=lambda r: r[1]["pc"])
        return out

    # -- small lookups -------------------------------------------------------

    def _module_of(self, va):
        for mod in self._mods:
            if mod["base"] <= va < mod["base"] + mod["image_size"]:
                return mod
        return None

    def _is_reached(self, va):
        """Is this exact word in the approved reached-instruction map?"""
        if self._callable is not None:
            return bool(self._callable(va))
        mod = self._module_of(va)
        return mod is not None and va in self._frozen[mod["name"]]

    @staticmethod
    def _text(mod):
        off, size = mod["text"]
        return mod["base"] + off, mod["base"] + off + size

    @staticmethod
    def _ro(mod):
        off, size = mod["ro"]
        return mod["base"] + off, mod["base"] + off + size

    # -- shape ---------------------------------------------------------------

    def _mov(self, pc, word):
        """Exact `MOV Xd, Xm` = ORR Xd, XZR, Xm, LSL #0 with d/m in x0..x15."""
        try:
            ins = T.decode(pc, word, module=True)
        except T.DecodeError:
            return None
        if ins["kind"] != "logic_shift":
            return None
        if (ins["op"] != 1 or ins["s"] != 0 or ins["width"] != 64
                or ins["rn"] != 31 or ins["shift"] != 0 or ins["imm6"] != 0
                or ins.get("invert")):
            # N=1 (MVN/ORN/BIC/EON/BICS) is a DIFFERENT instruction: it must be
            # rejected explicitly, otherwise `MVN Xd,Xm` (which decodes as
            # op=1,rn=31,shift=0,imm6=0 PLUS invert) would falsely pass as the
            # MOV Xd,Xm alias.
            return None
        if ins["rd"] >= R_LIMIT or ins["rm"] >= R_LIMIT:
            return None
        return {"pc": pc, "word": word, "rd": ins["rd"], "rm": ins["rm"]}

    def _shape(self, mod, va):
        """(movs, tail_pc, tail_ins, span) or a Refusal reason/detail pair."""
        text_lo, text_hi = self._text(mod)
        movs = []
        pc = va
        while True:
            if pc + 4 > text_hi:
                return None, "span-out-of-text", \
                    "span leaves text at 0x%x" % pc
            word = self._word(mod, pc)
            if word is None:
                return None, "not-file-backed", "word 0x%x is not in flat" % pc
            mov = self._mov(pc, word)
            if mov is not None:
                if len(movs) >= MAX_MOVS:
                    return None, "shape-too-many-movs", \
                        "more than %d MOV Xd,Xm before the tail" % MAX_MOVS
                movs.append(mov)
                pc += 4
                continue
            try:
                ins = T.decode(pc, word, module=True)
            except T.DecodeError as exc:
                return None, "shape-undecodable", \
                    "0x%x: %s" % (pc, exc)
            if ins["kind"] != "b":
                return None, "shape-not-mov-or-b", \
                    "0x%x: %s is not MOV Xd,Xm or B" % (pc, ins["kind"])
            return (movs, pc, ins), None, None

    def _is_veneer_at(self, mod, va):
        """Structural (bounded) veneer shape test, used to forbid chains."""
        got = self._shape(mod, va)
        if got[1] is not None:
            return False
        shape, _r, _d = got
        return True

    # -- eh_frame_hdr --------------------------------------------------------

    def _eh(self, mod, target):
        """Strict .eh_frame_hdr parse via MOD0 relative offsets (cached)."""
        key = (mod["name"], target)
        if key not in self._eh_cache:
            self._eh_cache[key] = self._parse_eh(mod, target)
        return self._eh_cache[key]

    def _parse_eh(self, mod, target):
        """Strict .eh_frame_hdr parse; every address below is a flat OFFSET."""
        flat = mod["flat"]
        base = mod["base"]
        size = mod["image_size"]
        ro_lo, ro_hi = self._ro(mod)
        ro_lo -= base
        ro_hi -= base
        if len(flat) < 8:
            return None, "eh-missing", "image too small for a MOD0 header"
        mod0 = struct.unpack_from("<I", flat, 4)[0]
        if mod0 + 0x18 > len(flat):
            return None, "eh-missing", "MOD0 at 0x%x is not in the flat" % mod0
        if bytes(flat[mod0:mod0 + 4]) != b"MOD0":
            return None, "eh-missing", "no MOD0 magic at 0x%x" % mod0
        # MOD0 +0x10/+0x14 are SIGNED offsets RELATIVE TO MOD0 (not to the
        # image, not raw).  h = mod0 + start, end = mod0 + end_off.
        start = _sx32(struct.unpack_from("<I", flat, mod0 + 0x10)[0])
        end_rel = _sx32(struct.unpack_from("<I", flat, mod0 + 0x14)[0])
        if start == 0 and end_rel == 0:
            return None, "eh-missing", "MOD0 has no .eh_frame_hdr extent"
        h = mod0 + start
        end_off = mod0 + end_rel
        if not (0 <= h <= end_off <= size):
            return None, "eh-malformed", \
                "MOD0 extent 0x%x..0x%x is outside the image" % (h, end_off)
        if h % 4 or end_off % 4:
            return None, "eh-alignment", \
                "MOD0 extent 0x%x..0x%x is not 4-aligned" % (h, end_off)
        if not (ro_lo <= h and end_off <= ro_hi and end_off <= len(flat)):
            return None, "eh-not-ro", \
                "extent 0x%x..0x%x is not inside file-backed RO [0x%x,0x%x)" \
                % (h, end_off, ro_lo, ro_hi)
        # Bound the fixed header (prefix + eh_frame_ptr + fde_count) BEFORE the
        # count is read: a truncated extent must not read past MOD0's end.
        if h + EH_HDR_MIN > end_off:
            return None, "eh-malformed", \
                "header extent 0x%x..0x%x is shorter than %d bytes" \
                % (h, end_off, EH_HDR_MIN)
        if bytes(flat[h:h + 4]) != EH_HDR_PREFIX:
            return None, "eh-unsupported", \
                "header 0x%x is %s, not the supported 011b033b" % (
                    h, bytes(flat[h:h + 4]).hex())
        # prefix(4) | eh_frame_ptr u32 | fde_count u32 | table
        count = struct.unpack_from("<I", flat, h + 8)[0]
        if count == 0:
            return None, "eh-empty", "fde_count is zero"
        table = h + EH_HDR_MIN
        table_end = table + count * EH_ROW
        if table_end > end_off:
            return None, "eh-malformed", \
                "table 0x%x..0x%x exceeds MOD0 end 0x%x" % (
                    table, table_end, end_off)
        raw = bytes(flat[table:table_end])
        prev = None
        match = None
        for i in range(count):
            datarel, fde = struct.unpack_from("<ii", raw, i * EH_ROW)
            loc = h + datarel
            if not (0 <= loc < size):
                return None, "eh-initial-outside", \
                    "row %d initial location 0x%x is outside the image" % (
                        i, loc)
            if prev is not None and loc <= prev:
                kind = "eh-duplicate" if loc == prev else "eh-unsorted"
                return None, kind, \
                    "row %d initial location 0x%x after 0x%x" % (i, loc, prev)
            prev = loc
            if base + loc == target:
                match = (i, loc, h + fde)
        if match is None:
            return None, "eh-not-exact", \
                "0x%x is not an exact .eh_frame_hdr initial location" % target
        index, loc, fde_off = match
        if fde_off % 4 or not (ro_lo <= fde_off < ro_hi):
            return None, "eh-fde", \
                "FDE pointer 0x%x (row %d) is not aligned in RO" % (
                    base + fde_off, index)
        return {
            "offset": base + h,
            "module_offset": h,
            "end": base + end_off,
            "bytes": EH_HDR_PREFIX.hex(),
            "count": count,
            "table_sha256": sha256(raw),
            "match_index": index,
            "initial_location": base + loc,
            "fde_pointer": base + fde_off,
        }, None, None

    # -- proof ---------------------------------------------------------------

    def prove(self, target):
        """Prove `target` is a veneer root; return evidence or a refusal."""
        if not isinstance(target, int) or target < 0 or target > MASK64:
            return _refuse("bad-target", "target is not a guest VA")
        mod = self._module_of(target)
        text_lo, text_hi = (0, 0) if mod is None else self._text(mod)
        if mod is None or not (text_lo <= target < text_hi):
            return _refuse("not-text",
                           "0x%x is not in a module TEXT segment" % target)
        if target % 4:
            return _refuse("unaligned", "0x%x is not 4-aligned" % target)

        # 1. independent static materialization
        rows = self._materializations.get(target)
        if not rows:
            return _refuse("not-materialized",
                           "no reached ADRP+ADD pair materializes 0x%x"
                           % target)

        # 2. shape
        got, reason, detail = self._shape(mod, target)
        if got is None:
            return _refuse(reason, detail)
        movs, tail_pc, tail_ins = got
        tail = tail_ins["target"]
        span = 4 * (len(movs) + 1)

        # 3. tail + symbol/cover/prior/relocation guards
        tail_mod = self._module_of(tail)
        if tail_mod is None or tail_mod["name"] != mod["name"]:
            return _refuse("tail-other-module",
                           "tail 0x%x is not in module %s"
                           % (tail, mod["name"]))
        t_lo, t_hi = self._text(tail_mod)
        if not (t_lo <= tail < t_hi):
            return _refuse("tail-not-text",
                           "tail 0x%x is not TEXT" % tail)
        hits = self._func_at.get(tail) or []
        hits = [h for h in hits if h[0] == mod["name"]]
        if not hits:
            return _refuse("tail-undefined",
                           "tail 0x%x has no exact DEFINED STT_FUNC" % tail)
        if self._is_veneer_at(tail_mod, tail):
            return _refuse("tail-recursive-veneer",
                           "tail 0x%x is itself a veneer (chain)" % tail)
        for lo, hi, sym in self._sized[mod["name"]]:
            # The WHOLE veneer span must be uncovered, not just its entry:
            # a sized symbol starting at target+4 is still an overlap.
            if lo < target + span and hi > target:
                why = "exact" if lo == target else "earlier"
                return _refuse(
                    "veneer-covered-by-symbol",
                    "%s sized symbol %r (type %d) [0x%x,0x%x) covers 0x%x"
                    % (why, sym["name"], sym["type"], lo, hi, target))
        prior_pc = target - 4
        prior_word = None if prior_pc < text_lo else self._word(mod, prior_pc)
        if prior_word is None:
            return _refuse("prior-out-of-text",
                           "no word before 0x%x" % target)
        prior_kind = self._terminator(prior_pc, prior_word)
        if prior_kind is None:
            return _refuse("fallthrough-prior",
                           "word 0x%x is not a terminator (0x%08x)"
                           % (prior_pc, prior_word))
        for site in self._relocs[mod["name"]]:
            if site < target + span and site + 8 > target:
                return _refuse("relocation-overlap",
                               "relocation site 0x%x overlaps [0x%x,0x%x)"
                               % (site, target, target + span))

        # 4. exact .eh_frame_hdr initial location (new-category guard only)
        eh, reason, detail = self._eh(mod, target)
        if eh is None:
            return _refuse(reason, detail)

        _owner, sym = hits[0]
        # Every audit value is a FRESH deep copy: the cached materialization
        # records and the cached EH dict are internal, so a caller annotating
        # a returned evidence dict must not be able to change a later prove().
        return Verdict(True, None, None, {
            "kind": "veneer",
            "owner": mod["name"],
            "value": target,
            "size": span,
            "flat_sha256": sha256(mod["flat"]),
            "veneer_sha256": sha256(
                mod["flat"][target - mod["base"]:
                            target - mod["base"] + span]),
            "materialization": copy.deepcopy([rec for _n, rec in rows]),
            "movs": copy.deepcopy(movs),
            "tail": {"pc": tail_pc,
                     "word": self._word(mod, tail_pc),
                     "target": tail,
                     "symbol": {"name": sym["name"], "bind": sym["bind"],
                                "size": sym["size"], "type": sym["type"]}},
            "prior": {"pc": prior_pc, "word": prior_word, "kind": prior_kind},
            "eh": copy.deepcopy(eh),
        })

    def _terminator(self, pc, word):
        """'b'/'br'/'ret'/'udf' if the word cannot fall through, else None."""
        try:
            ins = T.decode(pc, word, module=True)
        except T.DecodeError:
            return "udf" if (word & 0xFFFF0000) == 0 else None
        return ins["kind"] if ins["kind"] in TERMINATORS else None
