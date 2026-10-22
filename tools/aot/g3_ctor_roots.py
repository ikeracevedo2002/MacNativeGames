#!/usr/bin/env python3
"""D023 - pinned SAME-MODULE DT_INIT_ARRAY constructor-root authority (G3).

The G3 Start driver may seed the translated graph with the constructor that an
ORIGINAL module's own DT_INIT array-walk loop is about to call.  Nothing else
changes: the original guest `LDR x8,[x20],#8; BLR x8; CMP x20,x19; B.LO` loop
stays in translated control and walks its own array in its own order (D017).
There is no host constructor loop, no host function pointer and no synthetic
guest return.

WHY THIS IS A SEPARATE CLASS (it is not a D021/D022 relaxation)
--------------------------------------------------------------
D021's veneer class needs a tail the exact-DEFINED-STT_FUNC rule already
justifies; D022 only adds switch edges inside an already-rooted FUNC.  Real
DT_INIT_ARRAY constructors frequently have NO dynamic symbol at all (1.0.0
main's first entry is stripped), so a root category whose evidence is
"this exact proven loop site demanded a member of the module's own validated
constructor table" is strictly different from both, and strictly narrower than
"a relocated value" or "any BLR target".

TWO CONJUNCTS, BOTH MANDATORY
-----------------------------
1. PROVEN SITE.  The fault site must be the original array-walk call, proven
   from raw words around it (no address hardcode, no title constant):

       LDR  Xr,  [Xc], #8      ; post-indexed load of the next slot
       BLR  Xr                 ; <= the fault site
       CMP  Xc,  Xb            ; SUBS XZR, Xc, Xb
       B.LO  <the LDR>         ; exact back-edge to the load (imm19 == -3)

   Every operand is cross-bound: the BLR source register is the LDR target
   register, the CMP's first operand is the LDR's base (cursor) register, and
   all four words must lie inside the owner module's TEXT.  A non-loop BLR to a
   perfectly valid constructor is therefore REFUSED - table membership alone is
   never authority.

2. LIVE SLOT PROVENANCE.  The probe must report, for the cursor register the
   site proof identified, the post-index cursor value, the 8 bytes it read at
   `cursor-8` through the checked address space, the CMP bound register and its
   value.  The policy then requires

       cursor_reg     == proven LDR base register
       cursor_value-8 == the demanded slot address (cursor may be the END bound
                         after the last slot - the loop's terminating case)
       slot_bytes     == the demanded target
       snapshot[slot] == the demanded target
       bound_value    == the declared array end VA

   The runtime target alone is NEVER a pointer: a captured value with no
   cursor, no slot bytes or a bound that does not equal the declared end is a
   typed refusal.  `prove()` cannot be called without a cursor record.

THE TABLE IS DERIVED, NEVER TRUSTED
-----------------------------------
* DT_INIT_ARRAY/DT_INIT_ARRAYSZ come from the ORIGINAL module `.dynamic`
  (reached through the module's own MOD0), never from a layout field, side-car
  or the fault report.  A forged layout field has no effect.
* The span must be inside the module's own RW data segment, 8-byte aligned, a
  positive multiple of 8, bounded (`MAX_ARRAY_BYTES`) and must not overlap any
  loader-consumed metadata extent.
* EVERY slot must carry EXACTLY ONE site, labelled RELA (DT_RELA) by the
  validated metadata context, and that site must be an R_AARCH64_RELATIVE
  (1027) / sym 0 record of the ORIGINAL ELF.  A missing, duplicate, symbolic,
  non-relative, RELR-derived or JMPREL-derived slot record invalidates the WHOLE
  table (fail closed; no partial admission).
* The post-relocation value is read from the reference link's relocated image
  (`g3_init_reach.Image.buf`, the same per-site values the C loader writes) and
  must equal `base + addend`; the per-site dump must agree too.  Raw zeros are a
  refusal, never a value.
* The declared bounds are CORROBORATED: two DISTINCT original RELA sites must
  relocate exactly `array_off` and exactly `array_off + arraysz` (the GOT bound
  words the loop's CMP compares against), both outside the array span.
* Each target must be 4-byte aligned, inside the OWNING module's TEXT with all
  4 bytes present, non-zero, not the configured sentinel, and its whole 4 bytes
  must avoid the image header/MOD0, every loader-consumed metadata extent, every
  relocation slot and every DEFINED non-FUNC symbol's storage (a zero-sized
  storage symbol still rejects its exact point).  A DEFINED STT_FUNC that
  contains the target neither grants nor denies authority.
* The metadata context must describe the SAME bytes: context SHA, base and
  segment extents are compared with the image, so a context built from a forged
  layout cannot donate weakened exclusions.

No STT_FUNC, FDE/.eh_frame, "nearest symbol" or prologue heuristic participates.

Enumeration is static and complete for AUDIT only (`Authority.targets()`); the
Start driver adds exactly the target the guest demanded, one per
AOT_FAULT_UNTRANSLATED miss.  Structural/code/data validation covers the whole
array; ISA coverage does not - a demanded constructor may still produce the
existing typed `unsupported` metadata, which is a separate blocker.

Nothing game-derived is written to the repository (D006).
"""

import hashlib
import bisect
import json
import os
import struct
import sys
import types

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import aot_module as M          # noqa: E402
import aot_translate as T       # noqa: E402

R_AARCH64_RELATIVE = 1027
DT_INIT = 12
DT_INIT_ARRAY = 25
DT_INIT_ARRAYSZ = 27
SLOT_SIZE = 8
MAX_ARRAY_BYTES = 1 << 20     # 131072 slots; real 1.0.0 main is 84312 B
HEADER_BYTES = 32             # MOD0 structure size; header starts at offset 0
RELA_LABEL = "RELA"           # Context.relocation_sites() label for DT_RELA


class CtorInputError(Exception):
    """Malformed / inconsistent frozen INPUT (a host-side DriverError)."""


class CtorRefusal(Exception):
    """Typed fail-closed refusal.  `reason` is stable and machine-readable."""

    def __init__(self, reason, detail=""):
        self.reason = reason
        self.detail = detail or reason
        super().__init__("%s: %s" % (reason, self.detail))


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _overlap(a_lo, a_hi, b_lo, b_hi):
    return a_lo < b_hi and b_lo < a_hi


# ------------------------------------------------------- raw A64 site shapes

BLR_MASK, BLR_WORD = 0xFFFFFC1F, 0xD63F0000
# LDR Xt,[Xn],#imm9 : size=11 V=0 opc=01, post-index, imm9 signed.
POST_LDR_X_MASK, POST_LDR_X_WORD = 0xFFE00C00, 0xF8400400
POST_LDR_W_MASK, POST_LDR_W_WORD = 0xFFE00C00, 0xB8400400
# SUBS XZR,Xn,Xm (LSL #0) == CMP Xn,Xm
SUBS_MASK, SUBS_WORD = 0xFFE0FC1F, 0xEB00001F
BCOND_MASK, BCOND_WORD = 0xFF000010, 0x54000000
COND_LO = 0x3                # unsigned-lower only (first profile; no B.LT)


def _sx9(value):
    return value - 0x200 if value & 0x100 else value


def loop_site_proof(flat, base, text, site):
    """Prove ONE original word sequence is the DT_INIT array-walk call.

    Returns (proof, refusal_reason).  Never guesses: every operand is
    cross-bound to the others and all four words must be inside TEXT.
    """
    lo, hi = text
    if not _is_int(site) or site % 4 or not (lo <= site and site + 4 <= hi):
        return None, "site-outside-owner-text"
    if not (lo <= site - 4 and site + 12 <= hi):
        return None, "loop-window-outside-text"

    def word(va):
        off = va - base
        if off < 0 or off + 4 > len(flat):
            return None
        return struct.unpack_from("<I", flat, off)[0]

    blr, ldr, cmp_, br = word(site), word(site - 4), word(site + 4), \
        word(site + 8)
    if None in (blr, ldr, cmp_, br):
        return None, "loop-window-unreadable"
    if blr & BLR_MASK != BLR_WORD:
        return None, "site-not-blr"
    blr_reg = (blr >> 5) & 0x1F        # BLR Xn: Rn is bits 9-5
    if blr_reg == 31:
        return None, "blr-register-is-xzr"
    if (ldr & POST_LDR_X_MASK) != POST_LDR_X_WORD:
        if (ldr & POST_LDR_W_MASK) == POST_LDR_W_WORD:
            return None, "loop-load-not-64-bit"
        return None, "loop-load-not-postindexed-ldr"
    if _sx9((ldr >> 12) & 0x1FF) != SLOT_SIZE:
        return None, "loop-load-scale-not-slot"
    if (ldr & 0x1F) != blr_reg:
        return None, "loop-load-register-not-blr-source"
    cursor_reg = (ldr >> 5) & 0x1F
    if cursor_reg == 31:
        return None, "loop-cursor-is-xzr"
    if cursor_reg == blr_reg:
        # LDR Xt,[Xt],#8 is CONSTRAINED UNPREDICTABLE (writeback == Rt).
        return None, "loop-cursor-overlaps-load-target"
    if (cmp_ & SUBS_MASK) != SUBS_WORD:
        return None, "loop-not-followed-by-cmp"
    if ((cmp_ >> 5) & 0x1F) != cursor_reg:
        return None, "cmp-does-not-compare-the-cursor"
    bound_reg = (cmp_ >> 16) & 0x1F
    if bound_reg in (31, cursor_reg, blr_reg):
        return None, "cmp-bound-register-invalid"
    if (br & BCOND_MASK) != BCOND_WORD:
        return None, "loop-branch-not-conditional"
    if (br & 0xF) != COND_LO:
        return None, "loop-branch-not-unsigned-lower"
    imm19 = (br >> 5) & 0x7FFFF
    if imm19 & 0x40000:
        imm19 -= 0x80000
    # B.cond is at site+8; its target must be exactly the LDR at site-4.
    if (site + 8) + imm19 * 4 != site - 4:
        return None, "loop-branch-target-not-the-load"
    return {"site": site, "cursor_reg": cursor_reg, "bound_reg": bound_reg,
            "slot_reg": blr_reg,
            "words": {"ldr": "0x%08x" % ldr, "blr": "0x%08x" % blr,
                      "cmp": "0x%08x" % cmp_, "bcond": "0x%08x" % br},
            "post_index": SLOT_SIZE}, None


DT_INIT_BUDGET_WORDS = 4096   # bounded DT_INIT-local CFG region (words)
DT_INIT_WINDOW = DT_INIT_BUDGET_WORDS * 4
ADRP_MASK, ADRP_WORD = 0x9F000000, 0x90000000
LDR_X_UIMM_MASK, LDR_X_UIMM_WORD = 0xFFC00000, 0xF9400000
MOV_REG_MASK, MOV_REG_WORD = 0xFFE0FFE0, 0xAA0003E0      # ORR Xd,XZR,Xm
CALLER_SAVED = tuple(range(19)) + (30,)


def _sx(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


class _Undecodable(Exception):
    def __init__(self, va, word, why):
        super().__init__("0x%x: word 0x%08x not decodable: %s" % (va, word,
                                                                   why))


def _step(w, va, st):
    """One instruction of the DT_INIT-local CFG.

    Returns (successor VAs, new register state).  Calls (BL/BLR) fall through
    ONLY: the callee is never entered, and per the AAPCS64 x0..x18/x30 are
    treated as clobbered.  RET/BR end the path.  The state maps a register
    to ("page", image_off) after ADRP or ("got", image_off) after an ADRP+LDR;
    any write this tracker does not model KILLS the register (a refusal can only
    come from lost information, never from a guessed value).
    """
    st = dict(st)

    def kill(r):
        if r != 31:
            st.pop(r, None)

    nxt = va + 4
    rd, rn = w & 0x1F, (w >> 5) & 0x1F
    # Control flow comes from the project's own decoder (module mode); a word
    # it cannot decode is a typed refusal, never silently fallen through.
    try:
        ins = T.decode(va, w, module=True)
    except T.DecodeError as exc:
        raise _Undecodable(va, w, str(exc))
    kind = ins["kind"]
    if kind in ("br", "ret"):
        return [], st                         # path ends
    if kind in ("blr", "bl"):                 # call: fall through ONLY
        for r in CALLER_SAVED:
            kill(r)
        return [nxt], st
    if kind == "b":
        return [ins["target"]], st
    if kind in ("bcond", "cbz", "cbnz", "tbz", "tbnz"):
        return [ins["target"], nxt], st
    if w & ADRP_MASK == ADRP_WORD:
        imm = _sx((((w >> 5) & 0x7FFFF) << 2) | ((w >> 29) & 3), 21)
        kill(rd)
        if rd != 31:
            st[rd] = ("page", ((va & ~0xFFF) + (imm << 12)))
        return [nxt], st
    if w & LDR_X_UIMM_MASK == LDR_X_UIMM_WORD:
        held = st.get(rn)
        kill(rd)
        if rd != 31 and held is not None and held[0] == "page":
            st[rd] = ("got", held[1] + ((w >> 10) & 0xFFF) * 8)
        return [nxt], st
    if w & MOV_REG_MASK == MOV_REG_WORD:
        held = st.get((w >> 16) & 0x1F)
        kill(rd)
        if rd != 31 and held is not None:
            st[rd] = held
        return [nxt], st
    if (w >> 25) & 5 == 4:                    # load/store group
        v = (w >> 26) & 1
        top = (w >> 27) & 7
        opc = (w >> 22) & 3
        if top == 5:                          # pairs
            if (w >> 22) & 1 and not v:
                kill(rd)
                kill((w >> 10) & 0x1F)
            if (w >> 23) & 3 in (1, 3):
                kill(rn)
        elif top == 7:
            if (w >> 24) & 1:
                if opc and not v:
                    kill(rd)
            elif (w >> 21) & 1:
                if (w >> 10) & 3 == 0:        # atomics: Rs/Rt may be written
                    kill(rd)
                    kill((w >> 16) & 0x1F)
                else:
                    if opc and not v:
                        kill(rd)
                    kill(rn)                  # PAC-load writeback forms
            else:
                if opc and not v:
                    kill(rd)
                if (w >> 10) & 3 in (1, 3):
                    kill(rn)
        elif top == 3:                        # literal
            if not v:
                kill(rd)
        elif top == 1 and not v and (w >> 24) & 0x3F == 0x08:
            kill(rd)                          # exclusive / ordered
            kill((w >> 16) & 0x1F)
            kill((w >> 10) & 0x1F)
        else:                                 # SIMD structures, unknown
            kill(rd)
            kill(rn)
        return [nxt], st
    kill(rd)                                  # every other class: Rd
    return [nxt], st


def dt_init_cfg_proof(flat, base, text, dt_init, proof, start_sites=None,
                      end_sites=None, require_bounds=True):
    """Prove the proven loop is reached from the module's OWN DT_INIT and that
    its bound/cursor registers hold the GOT words relocating the array end /
    start.

    Local forward dataflow over the DT_INIT-local CFG (calls fall through,
    callees are never entered; paths leaving the bounded region simply end).
    The walk stops AT the proven loop LDR, so the back-edge never feeds the
    entry state, and any path entering the loop body anywhere but the LDR is a
    refusal.  Returns (reason, detail) on refusal or (None, evidence).

    `require_bounds=False` is the CLASSIFIER mode only: reachability from the
    module's own DT_INIT without the GOT-bound provenance.  Every admission
    (`Authority.prove`) uses the default strict mode.
    """
    lo, hi = text
    ldr_va = proof["site"] - 4
    body = {proof["site"], proof["site"] + 4, proof["site"] + 8}
    region_hi = min(hi, dt_init + DT_INIT_WINDOW) if _is_int(dt_init) else 0
    if not _is_int(dt_init) or dt_init % 4 or dt_init < lo \
            or not (dt_init <= ldr_va < region_hi):
        return ("loop-not-reached-from-dt-init",
                "DT_INIT %r is not a TEXT address within 0x%x bytes before "
                "the loop LDR 0x%x" % (dt_init, DT_INIT_WINDOW, ldr_va))
    states = {dt_init: {}}
    work = [dt_init]
    while work:
        if len(states) > DT_INIT_BUDGET_WORDS:
            return ("dt-init-cfg-budget",
                    "more than %d words reachable" % DT_INIT_BUDGET_WORDS)
        va = work.pop()
        if va == ldr_va:
            continue
        off = va - base
        if off < 0 or off + 4 > len(flat):
            return "dt-init-window-unreadable", "0x%x" % va
        try:
            succs, new = _step(struct.unpack_from("<I", flat, off)[0], va,
                               states[va])
        except _Undecodable as exc:
            return "dt-init-undecodable", str(exc)
        for t in succs:
            if t % 4 or not (dt_init <= t < region_hi):
                continue                     # leaves the region: path ends
            if t in body:
                return ("loop-entered-mid-body",
                        "0x%x is reached from DT_INIT without passing the "
                        "loop LDR 0x%x" % (t, ldr_va))
            old = states.get(t)
            if old is None:
                states[t] = dict(new)
                work.append(t)
                continue
            merged = {r: v for r, v in old.items() if new.get(r) == v}
            if merged != old:
                states[t] = merged
                work.append(t)
    if ldr_va not in states:
        return ("loop-not-reached-from-dt-init",
                "no DT_INIT-local path reaches the loop LDR 0x%x" % ldr_va)
    if not require_bounds:
        return None, {"cfg_nodes": len(states)}
    held = states[ldr_va]
    end = held.get(proof["bound_reg"])
    if end is None or end[0] != "got" or end[1] - base not in end_sites:
        return ("dt-init-bound-not-got-end",
                "x%d holds %r at the loop entry; expected a GOT word "
                "relocating the declared array end" % (proof["bound_reg"],
                                                       end))
    start = held.get(proof["cursor_reg"])
    if start is None or start[0] != "got" or start[1] - base not in start_sites:
        return ("dt-init-cursor-not-got-start",
                "x%d holds %r at the loop entry; expected a GOT word "
                "relocating the declared array start" % (proof["cursor_reg"],
                                                         start))
    # The four loop words are sequential non-branching words after the LDR
    # (LDR, BLR [call falls through], CMP, B.LO), so reaching the LDR reaches
    # all of them; recorded for the audit.
    return None, {"cfg_nodes": len(states),
                  "loop_pcs": ["0x%x" % (ldr_va + 4 * i) for i in range(4)],
                  "end_slot": "0x%x" % (end[1] - base),
                  "start_slot": "0x%x" % (start[1] - base)}


# --------------------------------------------------------------- table model

class _Frozen(object):
    """Attribute writes after construction fail closed."""

    __slots__ = ()

    def __setattr__(self, name, value):
        raise AttributeError("%s is frozen" % type(self).__name__)

    def __delattr__(self, name):
        raise AttributeError("%s is frozen" % type(self).__name__)


def _init(obj, **fields):
    for k, v in fields.items():
        object.__setattr__(obj, k, v)


class Slot(_Frozen):
    """One validated constructor slot (frozen)."""

    __slots__ = ("index", "slot_va", "off", "addend", "target")

    def __init__(self, index, slot_va, off, addend, target):
        _init(self, index=index, slot_va=slot_va, off=off, addend=addend,
              target=target)

    def json(self):
        return {"index": self.index, "slot": "0x%x" % self.slot_va,
                "offset": "0x%x" % self.off, "addend": "0x%x" % self.addend,
                "target": "0x%x" % self.target}


class PinnedArray(_Frozen):
    """One module's COMPLETE, validated DT_INIT_ARRAY (frozen).

    Attributes cannot be rebound and the containers are tuples / read-only
    mappings.  `table_digest` is recomputed by `Authority.prove`, so a bypass
    through `object.__setattr__` fails closed as `authority-mutated`.
    """

    __slots__ = ("module", "base", "flat_sha256", "image_size", "text", "data",
                 "array_va", "array_size", "slots", "mod0", "bounds",
                 "dt_init", "digest")

    def __init__(self, module, base, flat_sha256, image_size, text, data,
                 array_va, array_size, slots, mod0, bounds, dt_init=None):
        _init(self, module=module, base=base, flat_sha256=flat_sha256,
              image_size=image_size, text=tuple(text), data=tuple(data),
              array_va=array_va, array_size=array_size,
              slots=tuple(slots), mod0=mod0,
              bounds=types.MappingProxyType({
                  "start_sites": tuple(sorted(bounds["start_sites"])),
                  "end_sites": tuple(sorted(bounds["end_sites"]))}),
              dt_init=dt_init)
        _init(self, digest=table_digest(self))

    @property
    def count(self):
        return len(self.slots)

    @property
    def array_end(self):
        return self.array_va + self.array_size

    @property
    def start_va(self):
        return self.array_va

    def contains_va(self, va):
        return self.array_va <= va < self.array_end

    def evidence(self):
        return {"module": self.module, "base": "0x%x" % self.base,
                "flat_sha256": self.flat_sha256,
                "image_size": "0x%x" % self.image_size,
                "text": ["0x%x" % self.text[0], "0x%x" % self.text[1]],
                "data": ["0x%x" % self.data[0], "0x%x" % self.data[1]],
                "dt_init": (None if self.dt_init is None
                            else "0x%x" % self.dt_init),
                "dt_init_array": "0x%x" % self.array_va,
                "dt_init_arraysz": self.array_size,
                "slots": self.count,
                "bounds": {k: ["0x%x" % v for v in vals]
                           for k, vals in sorted(self.bounds.items())},
                "table_sha256": self.digest}


def table_digest(array):
    """Digest of the DERIVED table (module, layout, span, bounds, every slot)."""
    h = hashlib.sha256()
    h.update(("d023-ctor-array|%s|%s|%d|%d|%d|%d|%d|%d|%d|%d|%r|%r|%r\n"
              % (array.module, array.flat_sha256, array.base,
                 array.image_size, array.text[0], array.text[1],
                 array.data[0], array.data[1], array.array_va,
                 array.array_size, array.dt_init,
                 tuple(array.bounds["start_sites"]),
                 tuple(array.bounds["end_sites"]))).encode("ascii"))
    for slot in array.slots:
        h.update(("%d:%d:%d:%d:%d\n" % (slot.index, slot.off, slot.addend,
                                        slot.target,
                                        slot.slot_va)).encode("ascii"))
    return h.hexdigest()


def array_consistent(array):
    """Re-derive every slot's identity from the array geometry.

    Independent of the stored digest: index == position, slot VA/offset follow
    the array span, and target == base + addend.  A mutated slot fails here
    even if a caller also rewrote the digest."""
    if table_digest(array) != array.digest:
        return False
    if len(array.slots) * SLOT_SIZE != array.array_size:
        return False
    for i, slot in enumerate(array.slots):
        if slot.index != i or slot.slot_va != array.array_va + i * SLOT_SIZE \
                or slot.off != slot.slot_va - array.base \
                or slot.target != array.base + slot.addend:
            return False
    return True


# --------------------------------------------------------------- derivation

def classify_site(image, text, site):
    """Is `site` the DT_INIT array-walk loop of a module that DECLARES an array?

    Returns (proof, refusal):
      (None, None)      NOT the class - older rules (STT_FUNC / D021) apply;
      (proof, None)     the class: the final strict derive + CFG/GOT + cursor
                        proof decides, and any refusal there is final;
      (None, (reason, detail))  the class, refused outright (a declared array
                        whose loop is entered mid-body).
    The class is deliberately LOOSE (it must never let a bad table escape to
    the old rules): loop shape, EITHER DT_INIT_ARRAY or DT_INIT_ARRAYSZ
    declared (even unpaired/malformed), a valid DT_INIT, and the module's OWN
    DT_INIT-local CFG reaching the loop LDR.  No bound RELA, slot or table
    validity is required here; those stay strict in the final proof.
    """
    proof, _why = loop_site_proof(image.flat, image.base, text, site)
    if proof is None:
        return None, None
    try:
        tags, _mod0 = _read_tags(image)
    except CtorInputError:
        return None, None
    if tags.get(DT_INIT_ARRAY) is None and tags.get(DT_INIT_ARRAYSZ) is None:
        return None, None                    # no array declared: not ours
    dt_init = tags.get(DT_INIT)
    if not _is_int(dt_init):
        return None, None
    why, detail = dt_init_cfg_proof(image.flat, image.base, text,
                                    image.base + dt_init, proof,
                                    require_bounds=False)
    if why is None:
        return proof, None
    if why == "loop-entered-mid-body":
        return None, (why, detail)
    return None, None                        # unreachable/budget/undecodable


def _read_tags(image):
    lay = image.layout
    data_off, data_size = int(lay["data"][0]), int(lay["data"][1])
    mod0 = struct.unpack_from("<I", image.flat, 4)[0]
    try:
        return M.read_dynamic(image.flat, mod0, image.image_size, data_off,
                              data_size), mod0
    except (M.ElfError, struct.error, ValueError, TypeError, KeyError) as exc:
        raise CtorInputError("%s: .dynamic: %s" % (image.name, exc))


def _all_rela_records(image, tags):
    """Every DT_RELA record of the ORIGINAL ELF, in file order."""
    if M.DT_RELA not in tags:
        return []
    try:
        return M.parse_rela_table(image.flat, tags[M.DT_RELA],
                                  tags.get(M.DT_RELASZ, 0),
                                  image.image_size, ".rela.dyn")
    except (M.ElfError, struct.error, ValueError, TypeError) as exc:
        raise CtorInputError("%s: .rela.dyn: %s" % (image.name, exc))


def _check_context_identity(image, flat_sha256, context):
    """The exclusion context must describe the SAME image, not a forged one."""
    if getattr(context, "base", None) != image.base:
        raise CtorInputError("%s: context base 0x%r != image base 0x%x"
                             % (image.name, getattr(context, "base", None),
                                image.base))
    if getattr(context, "sha256", None) != flat_sha256:
        raise CtorInputError(
            "%s: context SHA %s != frozen flat SHA %s (exclusions would come "
            "from different bytes)" % (image.name,
                                       getattr(context, "sha256", None),
                                       flat_sha256))
    if bytes(getattr(context, "raw", b"")) != bytes(image.flat):
        raise CtorInputError("%s: context raw bytes != image flat bytes"
                             % image.name)
    want = json.dumps(image.layout, sort_keys=True, separators=(",", ":"))
    got = json.dumps(context.layout, sort_keys=True, separators=(",", ":"))
    if want != got:
        raise CtorInputError(
            "%s: context layout (digest %s) != image layout (digest %s); the "
            "exclusions would describe a different dynsym_count/image_size/"
            "MOD0 geometry" % (image.name,
                               hashlib.sha256(got.encode()).hexdigest(),
                               hashlib.sha256(want.encode()).hexdigest()))


def _check_header_identity(image, context, tags, mod0):
    """MOD0 offset, magic, dynamic tags and DT_HASH must agree between the
    raw image, the declared layout and the validated metadata context."""
    name = image.name
    lay = image.layout.get("mod0_off")
    if not _is_int(lay) or lay != mod0:
        raise CtorInputError("%s: layout mod0_off %r != raw MOD0 pointer 0x%x"
                             % (name, lay, mod0))
    if context.mod0_offset() != mod0:
        raise CtorInputError("%s: context MOD0 offset 0x%x != raw 0x%x"
                             % (name, context.mod0_offset(), mod0))
    if bytes(image.flat[mod0:mod0 + 4]) != b"MOD0":
        raise CtorInputError("%s: no MOD0 magic at 0x%x" % (name, mod0))
    if dict(context.tags) != dict(tags):
        raise CtorInputError("%s: context .dynamic tags differ from the raw "
                             "image's" % name)
    if M.DT_HASH in tags:
        h = tags[M.DT_HASH]
        if not _is_int(h) or h < 0 or h + 8 > len(image.flat):
            raise CtorInputError("%s: DT_HASH 0x%r outside the image"
                                 % (name, h))
        nchain = struct.unpack_from("<I", image.flat, h + 4)[0]
        if nchain != image.layout.get("dynsym_count"):
            raise CtorInputError(
                "%s: DT_HASH nchain %d != layout dynsym_count %r"
                % (name, nchain, image.layout.get("dynsym_count")))


class _Index(object):
    """Interval-overlap index: built ONCE per module, O(log n) per query."""

    def __init__(self, items):
        self.items = sorted(items, key=lambda it: (it[0], it[1]))
        self.los = [it[0] for it in self.items]
        self.pmax = []
        best = -1
        for it in self.items:
            best = max(best, it[1])
            self.pmax.append(best)

    def find(self, lo, hi):
        i = bisect.bisect_left(self.los, hi)
        if i == 0 or self.pmax[i - 1] <= lo:
            return None
        for j in range(i - 1, -1, -1):
            it = self.items[j]
            if it[1] > lo and it[0] < hi:
                return it
        return None


def build_exclusions(context, mod0):
    """Exclusion indexes for one module (header, metadata, relocation sites,
    defined non-FUNC storage ranges, zero-sized storage points)."""
    reloc, ranges, points = [], [], []
    t_lo = int(context.layout["text"][0])
    t_hi = t_lo + int(context.layout["text"][1])
    # Every queried 4-byte extent is already inside the owner TEXT, so only
    # exclusions overlapping TEXT can ever matter: the (large) relocation
    # table and symbol table are filtered to that window once, up front.
    for sym in context.defined_symbols():
        if sym.get("type") == M.STT_FUNC:
            continue
        value, size = sym["value"], sym.get("size", 0)
        if size > 0:
            if _overlap(value, value + size, t_lo, t_hi):
                ranges.append((value, value + size, sym))
        elif t_lo <= value < t_hi:
            points.append((value, value + 1, sym))
    for where, label in context.relocation_sites():
        if _overlap(where, where + 8, t_lo, t_hi):
            reloc.append((where, where + 8, label))
    return {"header_end": mod0 + HEADER_BYTES,
            "meta": _Index([(a, b, label) for label, a, b in
                            context.metadata_extents()]),
            "reloc": _Index(reloc), "ranges": _Index(ranges),
            "points": _Index(points)}


def _target_refusal(target, context, mod0, index=None):
    """4-byte-extent exclusion of known non-code metadata / symbol storage.

    All comparisons are in IMAGE OFFSETS (symbol values are offsets)."""
    if index is None:
        index = build_exclusions(context, mod0)
    base = context.base
    lo, hi = target - base, target - base + 4
    if _overlap(lo, hi, 0, index["header_end"]):
        return ("target-in-image-header",
                "0x%x..0x%x overlaps the NSO header/MOD0 [0,0x%x)"
                % (target, target + 4, index["header_end"]))
    hit = index["meta"].find(lo, hi)
    if hit is not None:
        return ("target-in-metadata:%s" % hit[2],
                "0x%x..0x%x overlaps loader-consumed %s [0x%x,0x%x)"
                % (target, target + 4, hit[2], base + hit[0], base + hit[1]))
    hit = index["reloc"].find(lo, hi)
    if hit is not None:
        return ("target-in-relocation-slot:%s" % hit[2],
                "0x%x..0x%x overlaps the %s site at 0x%x"
                % (target, target + 4, hit[2], base + hit[0]))
    hit = index["ranges"].find(lo, hi)
    if hit is not None:
        sym = hit[2]
        return ("target-in-storage-symbol",
                "0x%x..0x%x overlaps defined %r (type %d) [0x%x,0x%x)"
                % (target, target + 4, sym.get("name"), sym["type"],
                   base + hit[0], base + hit[1]))
    hit = index["points"].find(lo, hi)
    if hit is not None:
        sym = hit[2]
        return ("target-at-storage-point",
                "0x%x is the defined address of zero-sized %r (type %d)"
                % (base + hit[0], sym.get("name"), sym["type"]))
    return None


def derive(image, flat_sha256, context, sentinel=0):
    """Derive and fully validate ONE module's declared DT_INIT_ARRAY.

    Returns a `PinnedArray`, or None when the module declares no array at all.
    Any malformed/forged/incomplete declaration raises a typed `CtorRefusal`;
    an internally inconsistent input raises `CtorInputError`.  No partial
    success exists.
    """
    name = image.name
    actual = hashlib.sha256(image.flat).hexdigest()
    if flat_sha256 != actual:
        raise CtorInputError("%s: frozen flat SHA %s != actual %s (stale pin)"
                             % (name, flat_sha256, actual))
    _check_context_identity(image, flat_sha256, context)
    tags, mod0 = _read_tags(image)
    _check_header_identity(image, context, tags, mod0)
    dt_init = tags.get(DT_INIT)
    declared = tags.get(DT_INIT_ARRAY)
    declared_size = tags.get(DT_INIT_ARRAYSZ)
    if declared is None and declared_size is None:
        return None
    if declared is None or declared_size is None:
        raise CtorRefusal(
            "array-tags-unpaired",
            "%s: DT_INIT_ARRAY=%r DT_INIT_ARRAYSZ=%r (both are required)"
            % (name, declared, declared_size))
    if not _is_int(declared) or not _is_int(declared_size):
        raise CtorRefusal("array-tags-not-integers",
                          "%s: declared array %r size %r"
                          % (name, declared, declared_size))
    if declared_size <= 0:
        raise CtorRefusal("array-empty",
                          "%s: DT_INIT_ARRAYSZ is %d" % (name, declared_size))
    if declared_size % SLOT_SIZE:
        raise CtorRefusal(
            "array-size-not-slot-multiple",
            "%s: DT_INIT_ARRAYSZ 0x%x is not a multiple of %d"
            % (name, declared_size, SLOT_SIZE))
    if declared_size > MAX_ARRAY_BYTES:
        raise CtorRefusal(
            "array-too-large",
            "%s: DT_INIT_ARRAYSZ 0x%x exceeds the bounded complete-table "
            "limit 0x%x" % (name, declared_size, MAX_ARRAY_BYTES))
    data_lo = int(image.layout["data"][0])
    data_hi = data_lo + int(image.layout["data"][1])
    if declared % SLOT_SIZE:
        raise CtorRefusal("array-misaligned",
                          "%s: DT_INIT_ARRAY 0x%x is not 8-byte aligned"
                          % (name, declared))
    if declared < data_lo or declared + declared_size > data_hi:
        raise CtorRefusal(
            "array-outside-data-segment",
            "%s: declared array [0x%x,0x%x) is not inside the RW data "
            "segment [0x%x,0x%x)" % (name, declared,
                                     declared + declared_size, data_lo,
                                     data_hi))
    span_lo, span_hi = declared, declared + declared_size
    own = None
    for label, a, b in context.metadata_extents():
        if label == ".init_array":
            own = (a, b)
            continue
        if _overlap(span_lo, span_hi, a, b):
            raise CtorRefusal(
                "array-overlaps-metadata:%s" % label,
                "%s: array [0x%x,0x%x) overlaps loader-consumed %s "
                "[0x%x,0x%x)" % (name, span_lo, span_hi, label, a, b))
    if own is None:
        raise CtorInputError(
            "%s: metadata context has no consumed .init_array interval "
            "although .dynamic declares one" % name)
    if own != (span_lo, span_hi):
        raise CtorRefusal(
            "array-extent-inconsistent",
            "%s: .dynamic declares [0x%x,0x%x) but the parsed metadata says "
            "[0x%x,0x%x)" % (name, span_lo, span_hi, own[0], own[1]))

    # --- every slot: exactly one RELA (DT_RELA) site, nothing else --------
    labels = {}
    for where, label in context.relocation_sites():
        if span_lo <= where < span_hi:
            labels.setdefault(where, []).append(label)
    records = _all_rela_records(image, tags)
    by_where = {}
    for rec in records:
        where = rec["where"]
        if not (span_lo <= where < span_hi):
            continue
        if where in by_where:
            raise CtorRefusal(
                "slot-relocation-duplicate",
                "%s: two DT_RELA records for slot 0x%x" % (name, where))
        by_where[where] = rec
    text_lo, text_hi = image.text
    exclusions = build_exclusions(context, mod0)
    slots = []
    for index in range(declared_size // SLOT_SIZE):
        off = span_lo + index * SLOT_SIZE
        got_labels = labels.get(off, [])
        if not got_labels:
            raise CtorRefusal(
                "slot-relocation-missing",
                "%s: slot %d at 0x%x has no relocation site (the complete "
                "declared table must be relocated)" % (name, index, off))
        if len(got_labels) > 1:
            raise CtorRefusal(
                "slot-relocation-overlap",
                "%s: slot %d at 0x%x is covered by %d relocation tables (%s)"
                % (name, index, off, len(got_labels),
                   ", ".join(sorted(got_labels))))
        if got_labels[0] != RELA_LABEL:
            raise CtorRefusal(
                "slot-relocation-not-rela",
                "%s: slot %d at 0x%x is a %s site; constructor slots must be "
                "DT_RELA RELATIVE records" % (name, index, off,
                                              got_labels[0]))
        rec = by_where.get(off)
        if rec is None:
            raise CtorRefusal(
                "slot-relocation-missing",
                "%s: slot %d at 0x%x has a site but no DT_RELA record"
                % (name, index, off))
        if rec["kind"] != R_AARCH64_RELATIVE:
            raise CtorRefusal(
                "slot-relocation-not-relative",
                "%s: slot %d at 0x%x has relocation kind %d (only %d)"
                % (name, index, off, rec["kind"], R_AARCH64_RELATIVE))
        if rec["sym"] != 0:
            raise CtorRefusal(
                "slot-relocation-symbolic",
                "%s: slot %d at 0x%x names dynsym %d (constructor tables are "
                "RELATIVE, sym 0)" % (name, index, off, rec["sym"]))
        addend = rec["addend"]
        if not _is_int(addend) or addend < 0:
            raise CtorRefusal("slot-negative-addend",
                              "%s: slot %d at 0x%x addend %r"
                              % (name, index, off, addend))
        if addend == 0:
            raise CtorRefusal("slot-null-target",
                              "%s: slot %d at 0x%x relocates to NULL"
                              % (name, index, off))
        target = image.base + addend
        if target == sentinel:
            raise CtorRefusal("slot-sentinel-target",
                              "%s: slot %d at 0x%x relocates to the sentinel "
                              "0x%x" % (name, index, off, sentinel))
        if addend % 4:
            raise CtorRefusal(
                "slot-target-misaligned",
                "%s: slot %d at 0x%x targets 0x%x (not 4-byte aligned)"
                % (name, index, off, target))
        if not (text_lo <= target and target + 4 <= text_hi):
            raise CtorRefusal(
                "slot-target-not-same-module-text",
                "%s: slot %d at 0x%x targets 0x%x, outside the owner TEXT "
                "extent [0x%x,0x%x) with 4 bytes present"
                % (name, index, off, target, text_lo, text_hi))
        observed = image.read(image.base + off, SLOT_SIZE)
        if observed != target:
            raise CtorRefusal(
                "slot-value-mismatch",
                "%s: slot %d at 0x%x holds %r after the reference link, "
                "expected 0x%x (base+addend)" % (name, index, off, observed,
                                                 target))
        pinned = image.sites.get(off)
        if pinned is not None and pinned != target:
            raise CtorRefusal(
                "slot-site-value-mismatch",
                "%s: slot %d at 0x%x: link site dump says 0x%x, RELA says "
                "0x%x" % (name, index, off, pinned, target))
        bad = _target_refusal(target, context, mod0, exclusions)
        if bad is not None:
            raise CtorRefusal(bad[0], "%s: slot %d %s"
                              % (name, index, bad[1]))
        slots.append(Slot(index, image.base + off, off, addend, target))

    # --- declared bounds: EVERY original RELA site that relocates them -----
    # Which of these words the loop really loads is decided by the DT_INIT
    # CFG proof in `Authority.prove`; here we only collect the complete set of
    # candidate GOT words, each of which must be a unique, relocated, RELATIVE
    # sym-0 DT_RELA site holding base+span in the reference image.
    bound_labels = {}
    for where, label in context.relocation_sites():
        bound_labels.setdefault(where, []).append(label)
    counts = {}
    for rec in records:
        counts[rec["where"]] = counts.get(rec["where"], 0) + 1
    cands = {"start_sites": [], "end_sites": []}
    for rec in records:
        if rec["kind"] != R_AARCH64_RELATIVE or rec["sym"] != 0:
            continue
        where = rec["where"]
        if span_lo <= where < span_hi:
            continue
        if not (data_lo <= where and where + 8 <= data_hi):
            continue
        if rec["addend"] == span_lo:
            key = "start_sites"
        elif rec["addend"] == span_hi:
            key = "end_sites"
        else:
            continue
        pinned_site = image.sites.get(where)
        if counts[where] != 1 or image.read(image.base + where, 8) != \
                image.base + rec["addend"] or \
                (pinned_site is not None
                 and pinned_site != image.base + rec["addend"]) or \
                bound_labels.get(where) != [RELA_LABEL]:
            raise CtorRefusal(
                "array-bounds-not-corroborated",
                "%s: bound site 0x%x is duplicated or not relocated to "
                "base+0x%x" % (name, where, rec["addend"]))
        cands[key].append(where)
    if not cands["start_sites"] or not cands["end_sites"]:
        raise CtorRefusal(
            "array-bounds-not-corroborated",
            "%s: no original RELA site relocates the declared bounds "
            "[0x%x,0x%x) (start sites=%r end sites=%r); the declaration "
            "cannot be tied to the loop's own bound words"
            % (name, span_lo, span_hi, cands["start_sites"],
               cands["end_sites"]))
    return PinnedArray(name, image.base, flat_sha256, image.image_size,
                       image.text, (image.base + data_lo,
                                    image.base + data_hi),
                       image.base + declared, declared_size, slots, mod0,
                       cands, dt_init=(image.base + dt_init
                                       if _is_int(dt_init) else None))


# ------------------------------------------------------------------ verdict

class Verdict(object):
    __slots__ = ("ok", "reason", "detail", "label", "evidence")

    def __init__(self, ok, reason=None, detail=None, label=None,
                 evidence=None):
        self.ok = ok
        self.reason = reason
        self.detail = detail
        self.label = label
        self.evidence = evidence

    def to_json(self):
        return {"ok": self.ok, "reason": self.reason, "detail": self.detail,
                "label": self.label, "evidence": self.evidence}


def refuse(reason, detail):
    return Verdict(False, reason, detail)


class Authority(_Frozen):
    """The pinned constructor-root authority for one boot world (frozen)."""

    __slots__ = ("arrays", "nnmain_va", "sentinel", "_by_target")

    def __init__(self, arrays, nnmain_va=None, sentinel=0):
        by_target = {}
        for array in arrays:
            for slot in array.slots:
                by_target.setdefault(slot.target, []).append(
                    (array.module, slot.index))
        _init(self, arrays=types.MappingProxyType(
            {a.module: a for a in arrays}),
            nnmain_va=nnmain_va, sentinel=sentinel,
            _by_target=types.MappingProxyType(
                {k: tuple(v) for k, v in by_target.items()}))

    @classmethod
    def build(cls, images, flat_shas, contexts, nnmain_va=None, sentinel=0):
        arrays = []
        for image in images:
            sha = flat_shas.get(image.name)
            if sha is None:
                raise CtorInputError("%s: no pinned flat SHA" % image.name)
            ctx = contexts.get(image.name)
            if ctx is None:
                raise CtorInputError("%s: no validated metadata context"
                                     % image.name)
            arr = derive(image, sha, ctx, sentinel=sentinel)
            if arr is not None:
                arrays.append(arr)
        return cls(arrays, nnmain_va=nnmain_va, sentinel=sentinel)

    # -- audit only -------------------------------------------------------
    def targets(self):
        return sorted(self._by_target)

    def counts(self):
        return {name: arr.count for name, arr in sorted(self.arrays.items())}

    # -- site ownership ---------------------------------------------------
    def _owner(self, fault_site, raw_by_module):
        """The pinned array whose TEXT contains the fault site AND for which
        the caller supplied raw bytes.  Raw bytes of any other module (or of a
        module without a validated array) never participate."""
        if not isinstance(raw_by_module, dict):
            return None
        for name, array in self.arrays.items():
            if name in raw_by_module and \
                    array.text[0] <= fault_site < array.text[1]:
                return array
        return None

    # -- admission --------------------------------------------------------
    def prove(self, target, fault_site, site_kind, cursor, raw_by_module):
        """Admit ONE observed target.  `fault_site`, `site_kind`, `cursor` and
        the owner's raw bytes are REQUIRED: there is no target-only path."""
        if not _is_int(target):
            return refuse("target-not-an-address", repr(target))
        if self.nnmain_va is not None and target == self.nnmain_va:
            return refuse("target-is-nnmain",
                          "0x%x is the pre-G4 nnMain boundary" % target)
        if not _is_int(fault_site):
            return refuse("fault-site-missing", repr(fault_site))
        array = self._owner(fault_site, raw_by_module)
        if array is None:
            return refuse(
                "fault-site-not-array-walk",
                "0x%x is not inside the TEXT of a module with a validated "
                "DT_INIT_ARRAY and supplied bytes; table membership alone is "
                "not authority" % fault_site)
        module = array.module
        raw = raw_by_module[module]
        try:
            flat, base, text = raw
            text = tuple(text)
            pinned = (isinstance(flat, (bytes, bytearray)) and
                      base == array.base and text == array.text and
                      hashlib.sha256(flat).hexdigest() == array.flat_sha256)
        except (TypeError, ValueError):
            pinned = False
        if not pinned:
            return refuse(
                "live-bytes-not-pinned",
                "the supplied %s bytes/base/TEXT do not match the pinned flat "
                "SHA %s" % (module, array.flat_sha256))
        if not array_consistent(array):
            return refuse("authority-mutated",
                          "%s table no longer matches its derived digest"
                          % module)
        proof, why = loop_site_proof(flat, base, text, fault_site)
        if proof is None:
            return refuse(
                "fault-site-not-array-walk",
                "0x%x is not a proven LDR->BLR/CMP/B.LO constructor-walk "
                "site (%s); table membership alone is not authority"
                % (fault_site, why))
        if site_kind != "blr":
            return refuse("fault-site-not-blr",
                          "the original loop site word is %r" % (site_kind,))
        hits = self._by_target.get(target, ())
        if not any(m == module for m, _i in hits):
            if hits:
                return refuse(
                    "cross-module-target",
                    "0x%x belongs to another module's array while the proven "
                    "site is in %s" % (target, module))
            return refuse(
                "not-in-init-array",
                "0x%x is not a member of %s's validated DT_INIT_ARRAY"
                % (target, module))
        why, cfg = dt_init_cfg_proof(flat, base, text, array.dt_init, proof,
                                     array.bounds["start_sites"],
                                     array.bounds["end_sites"])
        if why is not None:
            return refuse(why, cfg)
        bad, slot = self._check_cursor(array, target, proof, cursor)
        if bad is not None:
            return bad
        evidence = {
            "kind": "ctor-array-root",
            "module": array.module,
            "index": slot.index,
            "slot": "0x%x" % slot.slot_va,
            "addend": "0x%x" % slot.addend,
            "target": "0x%x" % target,
            "flat_sha256": array.flat_sha256,
            "array": array.evidence(),
            "site": proof,
            "dt_init_cfg": cfg,
            "fault_site": "0x%x" % fault_site,
            "fault_site_kind": site_kind,
            "runtime": dict(cursor),
        }
        return Verdict(True, label="ctor:%s#%d" % (array.module, slot.index),
                       evidence=evidence)

    def _check_cursor(self, array, target, proof, cursor):
        """Exact live slot provenance.  Returns (refusal, None) or
        (None, slot) where the slot is chosen by the CURSOR INDEX - never by
        'the first slot holding this value' (duplicate constructors exist)."""
        if not isinstance(cursor, dict):
            return refuse("cursor-not-observed",
                          "no live cursor/slot capture was supplied; a runtime "
                          "target alone is not a pointer"), None
        for key in ("reg", "value", "slot_bytes", "bound_reg", "bound_value"):
            if not _is_int(cursor.get(key)):
                return refuse("cursor-field-missing",
                              "cursor record lacks an integer %r: %r"
                              % (key, cursor)), None
        if cursor["reg"] != proof["cursor_reg"]:
            return refuse(
                "cursor-register-not-proven",
                "the capture reports x%d but the proven loop cursor is x%d"
                % (cursor["reg"], proof["cursor_reg"])), None
        if cursor["bound_reg"] != proof["bound_reg"]:
            return refuse(
                "cursor-bound-register-not-proven",
                "the capture reports x%d as the bound but the proven CMP uses "
                "x%d" % (cursor["bound_reg"], proof["bound_reg"])), None
        value = cursor["value"]
        # Post-index only: the LDR wrote the cursor AFTER the load, so the slot
        # that produced the target is exactly `cursor - 8` (cursor == array_end
        # is the last slot).  No "value or value-8" guessing.
        slot_va = value - SLOT_SIZE
        if slot_va < array.array_va or slot_va % SLOT_SIZE:
            return refuse(
                "cursor-outside-array",
                "post-index cursor 0x%x -> slot 0x%x is outside %s array "
                "[0x%x,0x%x)" % (value, slot_va, array.module,
                                 array.array_va, array.array_end)), None
        index = (slot_va - array.array_va) // SLOT_SIZE
        if index >= array.count:
            return refuse(
                "cursor-beyond-array-end",
                "post-index cursor 0x%x is past the last slot (array end "
                "0x%x)" % (value, array.array_end)), None
        if cursor["slot_bytes"] != target:
            return refuse(
                "cursor-slot-bytes-mismatch",
                "the live 8 bytes at slot 0x%x are 0x%x, not the demanded "
                "0x%x" % (slot_va, cursor["slot_bytes"], target)), None
        want = array.slots[index]
        if want.target != target:
            return refuse(
                "cursor-slot-mismatch",
                "live slot %d (0x%x) holds 0x%x per the snapshot, not the "
                "demanded 0x%x" % (index, slot_va, want.target, target)), None
        if cursor["bound_value"] != array.array_end:
            return refuse(
                "cursor-bound-mismatch",
                "the live bound register holds 0x%x, but the declared array "
                "end is 0x%x" % (cursor["bound_value"], array.array_end)), None
        if cursor.get("slot") is not None and cursor["slot"] != slot_va:
            return refuse("cursor-slot-field-mismatch", repr(cursor)), None
        return None, want


# -------------------------------------------------------------------- audit

def write_audit(work, audits):
    path = os.path.join(work, "ctor_audit.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"schema": 1, "kind": "ctor-array-root",
                   "count": len(audits), "entries": audits},
                  f, indent=2, sort_keys=True)
        f.write("\n")
    return path


def _need(ev, *path):
    cur = ev
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            raise CtorInputError("ctor audit: evidence lacks %s"
                                 % ".".join(path))
        cur = cur[key]
    return cur


def bind_flat_sha(authority, metas, audits, meta_name=None):
    """Bind every admitted constructor to the AUTHORITY and compiled metadata.

    The audit dicts are never trusted: each entry is re-checked against the
    live frozen `Authority` (module array present, derived table digest
    re-computed and equal, flat SHA equal, slot index/VA/target equal to the
    authority's own slot).  The owning module's compiled `source_sha256` (the
    generated image's actual flat SHA) must equal the pinned flat SHA exactly.
    A missing module/metadata/key is a typed `CtorInputError`; there is no
    optional published-digest path and no weaker fallback.  `meta_name` maps
    the proof's module name to the runtime metadata key when they differ.
    """
    if not isinstance(authority, Authority):
        raise CtorInputError("ctor audit: no Authority to bind against")
    for audit in audits:
        if not isinstance(audit, dict) or "evidence" not in audit:
            raise CtorInputError("ctor audit: entry has no evidence")
        ev = audit["evidence"]
        module = _need(ev, "module")
        array = authority.arrays.get(module)
        if array is None:
            raise CtorInputError("ctor audit: module %r has no validated "
                                 "array in the authority" % (module,))
        if not array_consistent(array):
            raise CtorInputError("ctor audit: %s array no longer matches its "
                                 "derived digest" % module)
        if _need(ev, "array", "table_sha256") != array.digest:
            raise CtorInputError("ctor audit: %s table digest %s != "
                                 "re-derived %s" % (
                                     module, ev["array"]["table_sha256"],
                                     array.digest))
        if _need(ev, "flat_sha256") != array.flat_sha256:
            raise CtorInputError("ctor audit: proof flat SHA != pinned SHA "
                                 "for %s" % module)
        index = _need(ev, "index")
        if not _is_int(index) or not 0 <= index < array.count:
            raise CtorInputError("ctor audit: slot index %r outside %s's "
                                 "array" % (index, module))
        slot = array.slots[index]
        if _need(ev, "slot") != "0x%x" % slot.slot_va or \
                _need(ev, "target") != "0x%x" % slot.target or \
                _need(ev, "addend") != "0x%x" % slot.addend:
            raise CtorInputError("ctor audit: slot %d record != the "
                                 "authority's slot" % index)
        key = (meta_name or {}).get(module, module)
        meta = metas.get(key)
        if not isinstance(meta, dict):
            raise CtorInputError("ctor audit: module %s has no compiled "
                                 "metadata" % key)
        got = meta.get("source_sha256")
        if got != array.flat_sha256:
            raise CtorInputError(
                "ctor audit: pinned flat SHA %s for %s != compiled metadata "
                "source_sha256 %r (proof and generated code disagree)"
                % (array.flat_sha256, key, got))
        # Layout binding: the generated image must be linked at the pinned
        # guest base and must actually seed the admitted root.
        try:
            meta_base = int(str(meta.get("guest_base")), 0)
        except (TypeError, ValueError):
            raise CtorInputError("ctor audit: %s metadata guest_base %r is "
                                 "not an address" % (key,
                                                     meta.get("guest_base")))
        if meta_base != array.base:
            raise CtorInputError(
                "ctor audit: %s metadata guest_base 0x%x != pinned 0x%x"
                % (key, meta_base, array.base))
        entries = meta.get("entries")
        if not isinstance(entries, list):
            raise CtorInputError("ctor audit: %s metadata has no entries list"
                                 % key)
        try:
            seeded = {int(e, 0) for e in entries}
        except (TypeError, ValueError):
            raise CtorInputError("ctor audit: %s metadata entries malformed"
                                 % key)
        if slot.target not in seeded:
            raise CtorInputError(
                "ctor audit: admitted root 0x%x is not an entry of the "
                "compiled %s image (the generated code does not seed it)"
                % (slot.target, key))
    return True
