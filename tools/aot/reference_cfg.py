#!/usr/bin/env python3
"""Independent reference CFG derived with Capstone 5.0.7.

This module deliberately does NOT import or use any translator semantics. It
disassembles the declared manifest code ranges with Capstone and recovers the
block-start set by reachability from entries + indirect targets:
  - an immediate operand is a target ONLY for jump/call group instructions
    (conditional B included); SVC/ADD/MOVZ immediates are not targets;
  - a continuation (pc+4) is added only after jump/call/int/ret that fall
    through (unconditional `b`/`br`/`ret` do not);
  - straight-line code ends at a terminator or an existing block start.
"""

import capstone
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

_EXPECTED_CAPSTONE = "5.0.7"


def _capstone_version():
    v = getattr(capstone, "__version__", None)
    if v:
        return str(v)
    try:
        cv = capstone.cs_version()
        return ".".join(str(x) for x in cv[:2])
    except Exception:
        return "unknown"


def _assert_capstone():
    got = _capstone_version()
    if not got.startswith(_EXPECTED_CAPSTONE):
        raise RuntimeError("reference_cfg requires capstone %s, found %s"
                           % (_EXPECTED_CAPSTONE, got))


_assert_capstone()


def _md():
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    return md


def derive_starts(raw, ranges, entries, indirect_targets):
    """Return the set of block-start PCs implied by the declared code ranges.

    Raises ValueError on malformed ranges/entries so callers fail closed.
    """
    for s, e in ranges:
        if s < 0 or e < 0:
            raise ValueError("negative range bound")
        if s >= e:
            raise ValueError("range start >= end")
        if (s % 4) != 0 or (e % 4) != 0:
            raise ValueError("range not 4-byte aligned")
        if e > len(raw):
            raise ValueError("range end beyond raw bytes")
    ordered = sorted(ranges)
    if ordered != list(ranges):
        raise ValueError("ranges not sorted ascending")
    for i in range(1, len(ordered)):
        if ordered[i][0] < ordered[i - 1][1]:
            raise ValueError("ranges overlap")

    def in_range(a):
        return any(s <= a < e for s, e in ranges)

    md = _md()

    def disasm_at(a):
        for ins in md.disasm(raw[a:a + 4], a):
            return ins
        return None

    starts = set(entries) | set(indirect_targets)
    for pc in starts:
        if (pc % 4) != 0:
            raise ValueError("entry/target not 4-aligned")
        if not in_range(pc):
            raise ValueError("entry/target outside declared ranges")

    work = list(starts)
    while work:
        cur = work.pop()
        while True:
            if not in_range(cur):
                break
            ins = disasm_at(cur)
            if ins is None:
                raise ValueError("undecodable word at 0x%x" % cur)
            g = ins.groups
            is_jump = capstone.CS_GRP_JUMP in g
            is_call = capstone.CS_GRP_CALL in g
            is_ret = capstone.CS_GRP_RET in g
            is_int = capstone.CS_GRP_INT in g
            tgt = None
            if is_jump or is_call:
                for op in ins.operands:
                    if op.type == capstone.CS_OP_IMM:
                        tgt = op.imm
            if tgt is not None:
                if (tgt % 4) != 0:
                    raise ValueError("direct target 0x%x not 4-aligned" % tgt)
                if not in_range(tgt):
                    raise ValueError("direct target 0x%x outside declared ranges" % tgt)
                if tgt not in starts:
                    starts.add(tgt)
                    work.append(tgt)
            if is_jump or is_call or is_ret or is_int:
                mn = ins.mnemonic
                fallthrough = not (mn == "b" or mn == "br" or mn.startswith("ret"))
                if fallthrough and (cur + 4) not in starts:
                    starts.add(cur + 4)
                    work.append(cur + 4)
                break
            if (cur + 4) in starts:
                break
            cur += 4
    return starts
