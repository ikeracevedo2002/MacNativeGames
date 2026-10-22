#!/usr/bin/env python3
"""Hermetic synthetic tests for tools/aot/g3_veneer_roots.py (PHASE 1).

Everything here is generated: a tiny A64 image with a MOD0 header, a strict
.eh_frame_hdr table in RO, a small dynsym, DT_RELA/DT_RELR tables and a few
dozen instructions.  No game data, no title VA, no hash allowlist.

The tests cross the SAME public interface a driver will use:
    Prover(modules, reached).prove(target) -> Verdict
and the modules are loaded through the real `aot_module.load_module` parser
(so the synthetic image must satisfy the same NSO/MOD0/symbol invariants).

Every mandatory compound criterion has a positive case and at least one
single-guard negative case, plus a MEANINGFUL bypass control: for the static
reach, exact-EH and shape/tail guards, the same fixture is shown to pass once
the one offending fact is repaired - so a refusal is semantic, not collateral.

Exit: 0 pass, 2 semantic failure, 1 import/usage failure.
"""

import hashlib
import json
import os
import re
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
TOOLS = os.path.join(REPO, "tools", "aot")
sys.path.insert(0, TOOLS)

import aot_module as M          # noqa: E402
import g3_init_reach as R       # noqa: E402
import g3_veneer_roots as G     # noqa: E402

BASE = 0x100000000
IMG = 0x4000
MOD0 = 0x100
DYN = 0x3F00
SYMTAB = 0x3400
STRTAB = 0x3600
RELA = 0x3000
JMPREL = 0x3100
RELR = 0x3200
HDR = 0x2000
TEXT_OFF, TEXT_SIZE = 0x1000, 0x1000
RO_OFF, RO_SIZE = 0x2000, 0x1000
DATA_OFF, DATA_SIZE = 0x3000, 0x1000

V1 = 0x1810                      # 3 MOVs + B (mirrors the real Stop site shape)
V2 = 0x1820                      # 0 MOVs + B (mirrors the second real site)
T1 = 0x1F00
T2 = 0x1F80

NOP = 0xD503201F
RET = 0xD65F03C0
MOV_X0_X1 = 0xAA0103E0
HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")


# ------------------------------------------------------------------ encoders

def enc_adrp(pc, target_page, rd):
    imm = ((target_page - (pc & ~0xFFF)) >> 12) & 0x1FFFFF
    return (0x90000000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7FFFF) << 5)
            | rd)


def enc_add_lo12(rd, rn, imm12):
    return 0x91000000 | (imm12 << 10) | (rn << 5) | rd


def enc_mov(rd, rm):
    return 0xAA0003E0 | (rm << 16) | rd


def enc_mov_w(rd, rm):
    return 0x2A0003E0 | (rm << 16) | rd


def enc_mvn(rd, rm):
    """MVN Xd,Xm = ORN Xd,XZR,Xm (N=1, rn=31, shift 0, imm6 0)."""
    return 0xAA2003E0 | (rm << 16) | rd


def enc_orr(rn, rm, rd, imm6=0):
    """ORR Xd,Xn,Xm,LSL #imm6 (rn != 31: NOT the MOV alias)."""
    return 0xAA000000 | (rm << 16) | (imm6 << 10) | (rn << 5) | rd


def enc_add_shift12(rd, rn, imm12=0):
    """ADD Xd,Xn,#imm12,LSL #12 (sh bit 22 set)."""
    return 0x91400000 | (imm12 << 10) | (rn << 5) | rd


def enc_b(pc, target):
    return 0x14000000 | (((target - pc) >> 2) & 0x3FFFFFF)


def enc_bl(pc, target):
    return 0x94000000 | (((target - pc) >> 2) & 0x3FFFFFF)


def enc_bcond(pc, target, cond=0):
    return (0x54000000 | ((((target - pc) >> 2) & 0x7FFFF) << 5) | cond)


def enc_br(rn):
    return 0xD61F0000 | (rn << 5)


def enc_pair(off, target, reg=0, extra=0):
    """ADRP Xreg, page(target) ; ADD Xreg, Xreg, #lo12(target)."""
    return {off: enc_adrp(off, target & ~0xFFF, reg),
            off + 4: enc_add_lo12(reg, reg, (target & 0xFFF) + extra)}


DEFAULT_WORDS = {
    0x1000: enc_adrp(0x1000, 0x1000, 0), 0x1004: enc_add_lo12(0, 0, 0x810),
    0x1008: enc_adrp(0x1008, 0x1000, 1), 0x100C: enc_add_lo12(1, 1, 0x820),
    0x1010: enc_b(0x1010, 0x1800),
    0x1800: NOP, 0x1804: NOP, 0x1808: NOP,
    0x180C: enc_b(0x180C, V1),
    V1: enc_mov(8, 0), V1 + 4: enc_mov(0, 1), V1 + 8: enc_mov(1, 8),
    V1 + 12: enc_b(V1 + 12, T1),
    V2: enc_b(V2, T2),
    T1: RET, T2: RET,
}

DEFAULT_SYMS = [
    ("aligned_alloc", T1, 76, M.STT_FUNC, 1),
    ("free", T2, 24, M.STT_FUNC, 1),
]

DEFAULT_ROWS = [(0x1400, 0x2100), (V1, 0x2108), (V2, 0x2110)]

REACHED = {0x1000, 0x1004, 0x1008, 0x100C}


# ------------------------------------------------------------------- fixture

def build_flat(words=None, syms=None, rows=None, prefix=G.EH_HDR_PREFIX,
               datarel_bias=0, fde_override=None, count=None, extent=None,
               rela=(), jmprel=(), relr=(), hdr_at=HDR, tags_drop=(),
               tags_override=None):
    w = dict(DEFAULT_WORDS)
    if words:
        w.update(words)
    syms = list(DEFAULT_SYMS if syms is None else syms)
    rows = list(DEFAULT_ROWS if rows is None else rows)
    buf = bytearray(IMG)
    buf[0:4] = b"NSO0"
    struct.pack_into("<I", buf, 4, MOD0)
    buf[MOD0:MOD0 + 4] = b"MOD0"
    struct.pack_into("<i", buf, MOD0 + 4, DYN - MOD0)
    struct.pack_into("<i", buf, MOD0 + 8, IMG - MOD0)    # bss_start (rel MOD0)
    struct.pack_into("<i", buf, MOD0 + 12, IMG - MOD0)   # bss_end (rel MOD0)
    end = hdr_at + 12 + 8 * len(rows)
    start_off, end_off = extent if extent is not None else (hdr_at, end)
    struct.pack_into("<i", buf, MOD0 + 0x10, start_off - MOD0)
    struct.pack_into("<i", buf, MOD0 + 0x14, end_off - MOD0)
    for off, word in w.items():
        struct.pack_into("<I", buf, off, word)
    h = hdr_at
    buf[h:h + 4] = prefix
    struct.pack_into("<I", buf, h + 4, 0)            # eh_frame_ptr (unused)
    struct.pack_into("<I", buf, h + 8, len(rows) if count is None else count)
    for i, (loc, fde) in enumerate(rows):
        d = loc - h + datarel_bias
        f = (fde - h) if fde_override is None else fde_override
        struct.pack_into("<ii", buf, h + 12 + 8 * i, d, f)
    # dynstr + dynsym
    strings = bytearray(b"\x00")
    name_off = {}
    for name, _v, _s, _t, _sh in syms:
        name_off[name] = len(strings)
        strings += name.encode() + b"\x00"
    for i, (name, value, size, typ, shndx) in enumerate(syms):
        info = (1 << 4) | typ
        struct.pack_into("<IBBHQQ", buf, SYMTAB + i * 24, name_off[name],
                         info, 0, shndx, value, size)
    buf[STRTAB:STRTAB + len(strings)] = strings
    for i, site in enumerate(rela):
        struct.pack_into("<QQq", buf, RELA + i * 24, site, 0, 0)
    for i, site in enumerate(jmprel):
        struct.pack_into("<QQq", buf, JMPREL + i * 24, site, 0, 0)
    for i, site in enumerate(relr):
        struct.pack_into("<Q", buf, RELR + i * 8, site)
    tags = [(M.DT_RELA, RELA), (M.DT_RELASZ, len(rela) * 24),
            (M.DT_RELAENT, 24),
            (M.DT_RELR, RELR),
            (M.DT_RELRSZ, len(relr) * 8), (M.DT_RELRENT, 8),
            (M.DT_SYMTAB, SYMTAB), (M.DT_SYMENT, 24),
            (M.DT_STRTAB, STRTAB), (M.DT_STRSZ, len(strings)), (0, 0)]
    if jmprel:
        tags[1:1] = [(M.DT_JMPREL, JMPREL),
                     (M.DT_PLTRELSZ, len(jmprel) * 24), (M.DT_PLTREL, 7)]
    tags = [(tag, (tags_override or {}).get(tag, value))
            for tag, value in tags if tag not in tags_drop
            or tag == 0]
    for i, (tag, value) in enumerate(tags):
        struct.pack_into("<QQ", buf, DYN + i * 16, tag, value)
    return bytes(buf)


def make_module(tmp, name, base, **kw):
    flat = build_flat(**kw)
    layout = {
        "sha256": hashlib.sha256(flat).hexdigest(),
        "image_size": IMG, "bss_size": 0,
        "text": [TEXT_OFF, TEXT_SIZE], "ro": [RO_OFF, RO_SIZE],
        "data": [DATA_OFF, DATA_SIZE],
        "dynsym_count": len(kw.get("syms") or DEFAULT_SYMS),
    }
    fp = os.path.join(tmp, name + ".flat")
    lp = os.path.join(tmp, name + ".layout.json")
    with open(fp, "wb") as f:
        f.write(flat)
    with open(lp, "w", encoding="utf-8") as f:
        json.dump(layout, f)
    return M.load_module(fp, lp, name, base)


CAT = 0


def case(tmp, label, target_off, expect_ok, expect_reason=None, reached=None,
         modules=None, base=BASE, **kw):
    """One independent fixture -> one prove() call at the public interface."""
    global CAT
    CAT += 1
    if modules is None:
        mod = make_module(tmp, "main", base, **kw)
        modules = [mod]
    if reached is None:
        reach = {"main": {base + off for off in REACHED}}
    elif callable(reached) or isinstance(reached, dict):
        reach = reached
    else:
        reach = {"main": {base + off for off in reached}}
    prover = G.Prover(modules, reach)
    verdict = prover.prove(base + target_off if target_off is not None
                           else None)
    tag = "case %02d %s" % (CAT, label)
    if verdict.ok != expect_ok:
        fail("%s: ok=%r expected %r (%s)" % (tag, verdict.ok, expect_ok,
                                             verdict.reason))
        return verdict, prover
    if expect_ok:
        okk("%s -> evidence" % tag)
    else:
        if verdict.reason != expect_reason:
            fail("%s: reason %r expected %r" % (tag, verdict.reason,
                                                expect_reason))
            return verdict, prover
        json.dumps(verdict.to_json())
        okk("%s -> refused %s" % (tag, verdict.reason))
    return verdict, prover


FAILS = []
OKS = [0]


def fail(msg):
    FAILS.append(msg)
    print("FAIL: " + msg)


def okk(msg):
    OKS[0] += 1
    print("ok   " + msg)


def note(msg):
    print("     " + msg)


def main():
    assert os.path.isdir(TOOLS)
    tmp = tempfile.mkdtemp(prefix="g3veneer_")
    try:
        run(tmp)
    finally:
        for name in os.listdir(tmp):
            os.unlink(os.path.join(tmp, name))
        os.rmdir(tmp)
    print("-" * 70)
    print("%d checks passed, %d failed" % (OKS[0], len(FAILS)))
    if FAILS:
        return 2
    return 0


def run(tmp):
    # ---- 1. the two real shape classes, full audit ------------------------
    v, prover = case(tmp, "3MOV+B veneer (full audit)", V1, True)
    ev = v.evidence or {}
    want = {"kind", "owner", "value", "size", "flat_sha256",
            "veneer_sha256", "materialization", "movs", "tail", "prior",
            "eh"}
    check = sorted(want - set(ev))
    expect(not check, "audit keys missing: %r" % check)
    expect(ev.get("kind") == "veneer", "kind")
    expect(ev.get("owner") == "main", "owner")
    expect(ev.get("value") == BASE + V1, "value")
    expect(ev.get("size") == 4 * (3 + 1), "size")
    expect(len(ev.get("movs") or []) == 3, "three MOV Xd,Xm")
    expect([m["rd"] for m in ev.get("movs") or []] == [8, 0, 1], "mov rd order")
    expect([m["rm"] for m in ev.get("movs") or []] == [0, 1, 8], "mov rm order")
    expect(ev["tail"]["target"] == BASE + T1, "tail target")
    expect(ev["tail"]["symbol"]["name"] == "aligned_alloc", "tail symbol")
    expect(ev["tail"]["symbol"]["size"] == 76, "tail symbol size")
    expect(ev["prior"]["kind"] == "b", "prior is a B terminator")
    expect(ev["materialization"][0]["value"] == BASE + V1, "materialized V")
    expect(ev["materialization"][0]["pc"] == BASE + 0x1000, "materializing PC")
    expect(ev["eh"]["count"] == 3 and ev["eh"]["match_index"] == 1, "EH row")
    expect(ev["eh"]["initial_location"] == BASE + V1, "EH initial location")
    expect(ev["eh"]["bytes"] == "011b033b", "EH header bytes")
    expect(ev["eh"]["offset"] == BASE + HDR, "EH hdr offset (h = MOD0+start)")
    expect(all(isinstance(x, (int, str)) for x in
               [ev["flat_sha256"], ev["veneer_sha256"]]), "hashes are strings")
    for label, digest in (("flat_sha256", ev["flat_sha256"]),
                          ("veneer_sha256", ev["veneer_sha256"]),
                          ("eh.table_sha256", ev["eh"]["table_sha256"])):
        expect(isinstance(digest, str) and HEX64.match(digest) is not None,
               "%s is 64 lowercase hex" % label)
    # Every materialization record carries its PRODUCER module's immutable
    # source SHA, so a compound proof citing another module can be bound too.
    expect(all(isinstance(m.get("sourceModuleSHA"), str)
               and HEX64.match(m["sourceModuleSHA"]) is not None
               for m in ev["materialization"]),
           "materialization sourceModuleSHA is 64 lowercase hex")
    expect(json.dumps(v.to_json()) == json.dumps(
        prover.prove(BASE + V1).to_json()), "deterministic decision")

    flat = make_module(tmp, "main", BASE).get("flat")
    expect(ev["flat_sha256"] == hashlib.sha256(flat).hexdigest(),
           "flat hash is the original flat")
    expect(ev["veneer_sha256"] ==
           hashlib.sha256(flat[V1:V1 + 16]).hexdigest(), "veneer hash")
    expect(ev["eh"]["table_sha256"] ==
           hashlib.sha256(flat[HDR + 12:HDR + 36]).hexdigest(), "table hash")

    v2, _ = case(tmp, "0MOV+B veneer", V2, True)
    expect((v2.evidence or {}).get("size") == 4, "0-MOV span is just the B")
    expect((v2.evidence or {}).get("movs") == [], "0-MOV list is empty")
    expect((v2.evidence or {}).get("tail", {}).get("symbol", {}).get("name")
           == "free", "0-MOV tail symbol")

    # ALL reached materializations are reported, never just the first.
    extra = enc_pair(0x1060, V1, reg=5)
    v, _ = case(tmp, "two independent materializations", V1, True,
                words=extra, reached=REACHED | {0x1060, 0x1064})
    pcs = [m["pc"] for m in (v.evidence or {}).get("materialization") or []]
    expect(pcs == [BASE + 0x1000, BASE + 0x1060], "both materializing PCs")
    expect(all(m.get("module") == "main" for m in
               v.evidence["materialization"]), "materialization owner")
    expect(all(m.get("sourceModuleSHA") == v.evidence["flat_sha256"]
               for m in v.evidence["materialization"]),
           "materialization sourceModuleSHA is the producer snapshot")

    # ---- 2. reached map comes from the real approved scan machinery --------
    mod = make_module(tmp, "main", BASE)
    world = R.World([R.Image("main", BASE, mod["flat"], mod["layout"], {})])
    scan = R.scan_world(world, [(BASE + 0x1000, "start")])
    reached = G.reached_from_scan(scan, world)
    prover = G.Prover([mod], reached)
    for label, off in (("scan-reached 3MOV+B", V1), ("scan-reached 0MOV+B", V2)):
        global CAT
        CAT += 1
        got = prover.prove(BASE + off)
        expect(got.ok, "case %02d %s -> evidence" % (CAT, label))
    expect(BASE + 0x1004 in reached["main"] and BASE + 0x1008 in reached["main"],
           "scan bitmap really contains the ADRP/ADD words")
    # callable form of the same interface
    got = G.Prover([mod], lambda va: va in reached["main"]).prove(BASE + V1)
    expect(got.ok, "callable reached map accepted")

    # ---- 3. static-reach guard (+ semantic bypass control) ----------------
    case(tmp, "materialization words not reached", V1, False,
         "not-materialized", reached=set())
    case(tmp, "only the ADD word reached", V1, False, "not-materialized",
         reached={0x1004})
    case(tmp, "relocation value/site only (no materialization)", V1, False,
         "not-materialized", reached=set(), rela=[V1])
    case(tmp, "trace-only target word reached", V1, False, "not-materialized",
         reached={V1})
    # control: put the two words back into the reached map -> same fixture ok
    case(tmp, "control: reached map repaired", V1, True, reached=REACHED)

    # ---- 4. exact target, never +-4 / interior ----------------------------
    case(tmp, "target V+4", V1 + 4, False, "not-materialized")
    case(tmp, "target V-4", V1 - 4, False, "not-materialized")
    case(tmp, "target V+0x100 without materialization", V1 + 0x100, False,
         "not-materialized")

    # ---- 5. shape: MOV list ----------------------------------------------
    for label, word, why in (
            ("W-register MOV", enc_mov_w(8, 0), "width 32"),
            ("callee-saved rm x19", enc_mov(8, 19), "rm=19"),
            ("callee-saved rd x19", enc_mov(19, 0), "rd=19"),
            ("x16 gadget register", enc_mov(16, 0), "rd=16"),
            ("x17 gadget register", enc_mov(0, 17), "rm=17"),
            ("x18 platform register", enc_mov(0, 18), "rm=18"),
            ("SP/ZR destination", enc_mov(31, 0), "rd=31"),
            ("LR source", enc_mov(0, 30), "rm=30"),
            ("ANDS (flags)", 0xEA0003E8, "logic_shift op=3"),
            ("LDR (memory)", 0xF9400008, "ldst_imm"),
            ("MOVZ literal", 0xD2800020, "movz")):
        note(label + " -> " + why)
        case(tmp, "shape rejects " + label, V2, False, "shape-not-mov-or-b",
             words={V2: word})
    case(tmp, "shape rejects 4 MOVs", V2, False, "shape-too-many-movs",
         words={V2: enc_mov(8, 0), V2 + 4: enc_mov(8, 1),
                V2 + 8: enc_mov(8, 2), V2 + 12: enc_mov(8, 3),
                V2 + 16: enc_b(V2 + 16, T2)})
    # MVN is NOT the MOV alias: N=1 must be rejected explicitly.
    note("MVN X8,X0 (0xAA2003E8) is inverted, not a MOV")
    case(tmp, "shape rejects MVN X8,X0 (0xAA2003E8)", V2, False,
         "shape-not-mov-or-b",
         words={V2: 0xAA2003E8, V2 + 4: enc_b(V2 + 4, T2)})
    case(tmp, "shape rejects MVN in a 3-MOV veneer", V1, False,
         "shape-not-mov-or-b", words={V1 + 4: enc_mvn(0, 1)})
    case(tmp, "shape rejects ORN with rn != ZR", V2, False,
         "shape-not-mov-or-b",
         words={V2: 0xAA200000 | (2 << 16) | (1 << 5) | 0})
    case(tmp, "shape rejects ORR rn != ZR", V2, False,
         "shape-not-mov-or-b", words={V2: enc_orr(0, 1, 0)})
    case(tmp, "shape rejects ORR with LSL #1", V2, False,
         "shape-not-mov-or-b", words={V2: enc_orr(31, 1, 0, imm6=1)})
    # semantic bypass control: MVN -> the real MOV alias of the same regs
    case(tmp, "control: MVN repaired to MOV X8,X0", V1, True,
         words={V1 + 4: enc_mov(0, 1)})
    # shape/tail bypass control: the 0-MOV veneer with an unconditional B
    case(tmp, "control: tail repaired to B", V2, True)

    # ---- 5b. ADRP+ADD literal shape: bits, not just the folded value -----
    case(tmp, "literal ADDS (S=1) is refused", V1, False,
         "not-materialized", reached={0x1060, 0x1064},
         words={0x1060: enc_adrp(0x1060, V1 & ~0xFFF, 2),
                0x1064: enc_add_lo12(2, 2, V1 & 0xFFF) | (1 << 29)})
    case(tmp, "literal WADD is refused", V1, False, "not-materialized",
         reached={0x1060, 0x1064},
         words={0x1060: enc_adrp(0x1060, V1 & ~0xFFF, 2),
                0x1064: 0x11000000 | ((V1 & 0xFFF) << 10) | (2 << 5) | 2})
    case(tmp, "literal ADD #lo12,LSL #12 is refused", V1, False,
         "not-materialized", reached={0x1060, 0x1064},
         words={0x1060: enc_adrp(0x1060, V1 & ~0xFFF, 2),
                0x1064: enc_add_shift12(2, 2, (V1 & 0xFFF) >> 12)})
    case(tmp, "literal ADRP rd=16 is refused", V1, False, "not-materialized",
         reached={0x1060, 0x1064},
         words={0x1060: enc_adrp(0x1060, V1 & ~0xFFF, 16),
                0x1064: enc_add_lo12(16, 16, V1 & 0xFFF)})
    case(tmp, "literal ADD rd differs is refused", V1, False,
         "not-materialized", reached={0x1060, 0x1064},
         words={0x1060: enc_adrp(0x1060, V1 & ~0xFFF, 2),
                0x1064: enc_add_lo12(3, 2, V1 & 0xFFF)})
    case(tmp, "literal ADD rn differs is refused", V1, False,
         "not-materialized", reached={0x1060, 0x1064},
         words={0x1060: enc_adrp(0x1060, V1 & ~0xFFF, 2),
                0x1064: enc_add_lo12(2, 3, V1 & 0xFFF)})
    case(tmp, "literal ADD not adjacent is refused", V1, False,
         "not-materialized", reached={0x1060, 0x1068},
         words={0x1060: enc_adrp(0x1060, V1 & ~0xFFF, 2),
                0x1068: enc_add_lo12(2, 2, V1 & 0xFFF)})
    case(tmp, "literal ADD word not reached is refused", V1, False,
         "not-materialized", reached={0x1060},
         words=enc_pair(0x1060, V1, reg=2))
    case(tmp, "control: literal pair repaired", V1, True,
         reached={0x1060, 0x1064}, words=enc_pair(0x1060, V1, reg=2))
    # DISCRIMINATING: `ADD #0, LSL #12` materializes the very same value as
    # `ADD #0`; with a non-page-aligned base the target is page-aligned and the
    # whole proof would pass if only the folded imm were checked.  Fixed code
    # must refuse the literal SHAPE (bit 22), not the value.
    B2 = BASE + 0x800
    page_target = 0x100002000          # == B2 + 0x1800, page aligned
    case(tmp, "literal shift1 imm0 same value is refused", 0x1800, False,
         "not-materialized", base=B2, reached={0x1060, 0x1064},
         rows=[(0x1400, 0x2100), (0x1800, 0x2110)],
         words={0x1060: enc_adrp(B2 + 0x1060, page_target, 2),
                0x1064: enc_add_shift12(2, 2, 0),
                0x17FC: enc_b(0x17FC, 0x1000),
                0x1800: enc_b(0x1800, T2)})
    case(tmp, "control: same fixture with ADD #0 (sh clear)", 0x1800, True,
         base=B2, reached={0x1060, 0x1064},
         rows=[(0x1400, 0x2100), (0x1800, 0x2110)],
         words={0x1060: enc_adrp(B2 + 0x1060, page_target, 2),
                0x1064: enc_add_lo12(2, 2, 0),
                0x17FC: enc_b(0x17FC, 0x1000),
                0x1800: enc_b(0x1800, T2)})

    # ---- 6. tail: exactly one unconditional B ----------------------------
    case(tmp, "tail BL (call, not tail)", V2, False, "shape-not-mov-or-b",
         words={V2: enc_bl(V2, T2)})
    case(tmp, "tail BR (indirect)", V2, False, "shape-not-mov-or-b",
         words={V2: enc_br(2)})
    case(tmp, "tail B.cond", V2, False, "shape-not-mov-or-b",
         words={V2: enc_bcond(V2, T2)})
    case(tmp, "tail has no symbol", V2, False, "tail-undefined",
         words={V2: enc_b(V2, 0x1F40)})
    case(tmp, "tail symbol undefined", V2, False, "tail-undefined",
         syms=DEFAULT_SYMS + [("undef_tail", 0x1F40, 8, M.STT_FUNC, 0)],
         words={V2: enc_b(V2, 0x1F40)})
    case(tmp, "tail itself a veneer (chain)", V2, False,
         "tail-recursive-veneer",
         words={T2: enc_mov(0, 1), T2 + 4: enc_b(T2 + 4, T1)})
    # different module tail
    sdk = make_module(tmp, "sdk", BASE + 0x200000,
                      words={T1: RET}, syms=[("sdk_fn", T1, 4, M.STT_FUNC, 1)],
                      rows=[], extent=(0, 0))
    case(tmp, "tail in a different module", V2, False, "tail-other-module",
         modules=[make_module(tmp, "main", BASE,
                              words={V2: enc_b(V2, 0x200000 + T1)}), sdk])
    case(tmp, "control: same-module tail", V2, True)

    # ---- 7. symbol / prior / relocation guards ---------------------------
    case(tmp, "sized STT_FUNC covers V", V1, False,
         "veneer-covered-by-symbol",
         syms=DEFAULT_SYMS + [("covers", 0x1800, 0x30, M.STT_FUNC, 1)])
    # The COVER guard is type-agnostic: a literal data object (or an untyped
    # symbol) that covers V must also stop the veneer claim.
    case(tmp, "sized STT_OBJECT covers V", V1, False,
         "veneer-covered-by-symbol",
         syms=DEFAULT_SYMS + [("data_obj", 0x1800, 0x30, G.STT_OBJECT, 1)])
    case(tmp, "exact sized STT_OBJECT at V", V1, False,
         "veneer-covered-by-symbol",
         syms=DEFAULT_SYMS + [("obj_here", V1, 8, G.STT_OBJECT, 1)])
    case(tmp, "sized STT_NOTYPE covers V", V1, False,
         "veneer-covered-by-symbol",
         syms=DEFAULT_SYMS + [("untyped", 0x1800, 0x30, G.STT_NOTYPE, 1)])
    case(tmp, "single-guard control: STT_OBJECT covers elsewhere", V1, True,
         syms=DEFAULT_SYMS + [("other_obj", 0x1400, 0x10, G.STT_OBJECT, 1)])
    case(tmp, "exact sized STT_FUNC at V", V1, False,
         "veneer-covered-by-symbol",
         syms=DEFAULT_SYMS + [("veneer_here", V1, 8, M.STT_FUNC, 1)])
    # WHOLE-span cover: a symbol that STARTS at V+4 leaves the entry itself
    # uncovered but still overlaps the veneer bytes, so it must refuse.
    case(tmp, "OBJECT starts at V+4 (entry uncovered)", V1, False,
         "veneer-covered-by-symbol",
         syms=DEFAULT_SYMS + [("obj_after", V1 + 4, 12, G.STT_OBJECT, 1)])
    case(tmp, "FUNC starts at V+4 (entry uncovered)", V1, False,
         "veneer-covered-by-symbol",
         syms=DEFAULT_SYMS + [("fn_after", V1 + 4, 12, M.STT_FUNC, 1)])
    # Touching endpoints do not overlap and must stay positive.
    case(tmp, "symbol ends exactly at V", V1, True,
         syms=DEFAULT_SYMS + [("before", V1 - 8, 8, G.STT_OBJECT, 1)])
    case(tmp, "symbol starts exactly at V+span", V1, True,
         syms=DEFAULT_SYMS + [("after", V1 + 16, 8, G.STT_OBJECT, 1)])
    case(tmp, "prior word falls through", V1, False, "fallthrough-prior",
         words={0x180C: MOV_X0_X1})
    case(tmp, "prior word BL falls through", V1, False, "fallthrough-prior",
         words={0x180C: enc_bl(0x180C, 0x1000)})
    case(tmp, "relocation site at V", V1, False, "relocation-overlap",
         rela=[V1])
    case(tmp, "relocation site inside span", V1, False, "relocation-overlap",
         rela=[V1 + 8])
    case(tmp, "DT_RELR site at V (0-MOV)", V2, False, "relocation-overlap",
         relr=[V2])
    case(tmp, "control: site just past the span", V1, True, rela=[V2])
    # JMPREL sites are real relocation sites too (paired tags only).
    case(tmp, "JMPREL site at V", V1, False, "relocation-overlap",
         jmprel=[V1])
    case(tmp, "JMPREL site inside span", V1, False, "relocation-overlap",
         jmprel=[V1 + 8])
    case(tmp, "control: JMPREL site past the span", V1, True,
         jmprel=[V2])
    case(tmp, "control: RELA and JMPREL sites", V1, True,
         rela=[V2], jmprel=[V2 + 4])
    for label, prior, kind in (("B", enc_b(0x180C, 0x1000), "b"),
                               ("BR", enc_br(2), "br"),
                               ("RET", RET, "ret"),
                               ("UDF padding", 0x00000000, "udf")):
        v, _ = case(tmp, "prior terminator " + label, V1, True,
                    words={0x180C: prior})
        expect((v.evidence or {}).get("prior", {}).get("kind") == kind,
               "prior kind %s" % kind)

    # ---- 7b. relocation tag PAIRS: no silent size 0 ----------------------
    for label, kw in (
            ("DT_RELA without DT_RELASZ", dict(tags_drop=(M.DT_RELASZ,))),
            ("DT_RELASZ without DT_RELA", dict(tags_drop=(M.DT_RELA,))),
            ("DT_JMPREL without DT_PLTRELSZ",
             dict(jmprel=[V2], tags_drop=(M.DT_PLTRELSZ,))),
            ("DT_PLTRELSZ without DT_JMPREL",
             dict(jmprel=[V2], tags_drop=(M.DT_JMPREL,))),
            ("malformed DT_RELASZ", dict(tags_override={M.DT_RELASZ: 12}))):
        expect_input_error(
            label,
            lambda tmp=tmp, kw=kw: G.Prover(
                [make_module(tmp, "main", BASE, **kw)],
                {"main": {BASE + o for o in REACHED}}))
    # RELR half-pair cannot even be loaded, so exercise it on a descriptor copy
    mod = make_module(tmp, "main", BASE)
    half = dict(mod, tags={k: v for k, v in mod["tags"].items()
                           if k != M.DT_RELRSZ})
    expect_input_error("DT_RELR without DT_RELRSZ",
                       lambda: G.Prover([half], {"main": set()}))
    # control: the FULL pair still constructs and proves
    v, _ = case(tmp, "control: paired relocation tags", V1, True, rela=[V2])

    # ---- 8. span / alignment / module bounds -----------------------------
    case(tmp, "unaligned candidate", 0x1812, False, "unaligned",
         words=enc_pair(0x1030, 0x1812, reg=2),
         reached=REACHED | {0x1030, 0x1034})
    case(tmp, "materialized value outside TEXT", 0x2010, False, "not-text",
         words=enc_pair(0x1040, 0x2010, reg=3),
         reached=REACHED | {0x1040, 0x1044})
    span_words = enc_pair(0x1050, 0x1FFC, reg=4)
    span_words[0x1FFC] = enc_mov(0, 1)
    case(tmp, "span leaves TEXT", 0x1FFC, False, "span-out-of-text",
         words=span_words, reached=REACHED | {0x1050, 0x1054})
    case(tmp, "title-VA style target is not a root", 0x0200FA060, False,
         "not-text")
    case(tmp, "target outside every module", 0x1810, False, "not-text",
         modules=[make_module(tmp, "main", BASE + 0x200000)])

    # ---- 9. exact .eh_frame_hdr guard ------------------------------------
    case(tmp, "EH missing (MOD0 extent 0)", V1, False, "eh-missing",
         extent=(MOD0, MOD0))
    case(tmp, "EH empty table", V1, False, "eh-empty", count=0)
    case(tmp, "EH bad version", V1, False, "eh-unsupported",
         prefix=b"\x02\x1b\x03\x3b")
    case(tmp, "EH bad table encoding", V1, False, "eh-unsupported",
         prefix=b"\x01\x1b\x03\x3c")
    case(tmp, "EH oversized count", V1, False, "eh-malformed", count=0x100000)
    case(tmp, "EH table past MOD0 end", V1, False, "eh-malformed",
         extent=(HDR, HDR + 20))
    case(tmp, "EH rows unsorted", V1, False, "eh-unsorted",
         rows=[(V1, 0x2100), (0x1400, 0x2108)])
    case(tmp, "EH duplicate rows", V1, False, "eh-duplicate",
         rows=[(0x1400, 0x2100), (0x1400, 0x2108), (V1, 0x2110)])
    case(tmp, "EH nearest V-4 is not exact", V1, False, "eh-not-exact",
         rows=[(0x1400, 0x2100), (V1 - 4, 0x2108), (V2, 0x2110)])
    # control: move that row onto V exactly -> same fixture passes
    case(tmp, "control: EH row repaired to V", V1, True,
         rows=[(0x1400, 0x2100), (V1, 0x2108), (V2, 0x2110)])
    case(tmp, "EH table relative to h+8", V1, False, "eh-not-exact",
         datarel_bias=-8)
    case(tmp, "control: h base repaired", V1, True, datarel_bias=0)
    case(tmp, "EH table relative to MOD0", V1, False, "eh-not-exact",
         datarel_bias=HDR - MOD0)
    case(tmp, "EH FDE pointer unaligned", V1, False, "eh-fde",
         fde_override=0x2102)
    case(tmp, "EH FDE pointer outside RO", V1, False, "eh-fde",
         fde_override=-0x1800)
    case(tmp, "EH extent in TEXT", V1, False, "eh-not-ro",
         extent=(0x1000, 0x1010))
    case(tmp, "EH extent unaligned", V1, False, "eh-alignment",
         extent=(HDR + 2, HDR + 12 + 8 * 3 + 2))
    # the fixed header must be bounded BEFORE fde_count is read
    case(tmp, "EH header shorter than 12 bytes", V1, False, "eh-malformed",
         extent=(HDR, HDR + 8))
    case(tmp, "EH header shorter than the prefix", V1, False,
         "eh-malformed", extent=(HDR, HDR + 4))

    # ---- 10. immutable snapshot + returned-audit lifetime ----------------
    mod = make_module(tmp, "main", BASE)
    original = bytes(mod["flat"])
    prover = G.Prover([mod], {"main": {BASE + o for o in REACHED}})
    baseline = prover.prove(BASE + V1).to_json()
    expect(baseline["ok"], "snapshot fixture baseline proves")
    # mutate the CALLER's own objects AFTER construction: the proof must not
    # move, and the audit must still describe the ORIGINAL bytes.
    mod["flat"][V1:V1 + 4] = b"\x00\x00\x00\x00"
    mod["flat"][HDR + 12:HDR + 16] = b"\x00\x00\x00\x00"
    mod["syms"][0].update(value=0, size=0)
    mod["tags"][M.DT_RELA] = 0
    after = prover.prove(BASE + V1)
    expect(after.ok, "verdict unchanged after caller mutation")
    expect(after.to_json() == baseline,
           "evidence unchanged after caller mutation")
    expect(after.evidence["flat_sha256"] == hashlib.sha256(original).hexdigest(),
           "audit hashes the ORIGINAL flat bytes")
    expect(after.evidence["veneer_sha256"] ==
           hashlib.sha256(original[V1:V1 + 16]).hexdigest(),
           "audit veneer hash is the original bytes")
    expect(all(m["sourceModuleSHA"] == hashlib.sha256(original).hexdigest()
               for m in after.evidence["materialization"]),
           "materialization sourceModuleSHA is the original snapshot")
    # bytes changed BEFORE construction are a documented input error
    mod = make_module(tmp, "main", BASE)
    mod["flat"][V1] ^= 0xFF
    expect_input_error("flat mutated before construction",
                       lambda: G.Prover([mod],
                                        {"main": {BASE + o for o in REACHED}}))
    # mutating a RETURNED evidence dict (incl. nested audit records) must not
    # reach the cached materialization/EH/symbol state seen by a later prove()
    mod = make_module(tmp, "main", BASE)
    prover = G.Prover([mod], {"main": {BASE + o for o in REACHED}})
    first = prover.prove(BASE + V1).to_json()
    ev = prover.prove(BASE + V1).evidence
    ev["materialization"][0]["pc"] = 0
    ev["materialization"][0]["value"] = 0
    ev["materialization"].append({"pc": 1})
    ev["movs"][0]["rd"] = 99
    ev["eh"]["count"] = 999
    ev["eh"]["offset"] = 0
    ev["eh"]["table_sha256"] = "0" * 64
    ev["tail"]["symbol"]["name"] = "tampered"
    ev["materialization"][0]["sourceModuleSHA"] = "0" * 64
    ev["kind"] = "data"
    again = prover.prove(BASE + V1)
    expect(again.to_json() == first,
           "mutating a returned audit cannot change a later prove()")
    expect(again.evidence is not ev and
           again.evidence["eh"] is not ev["eh"] and
           again.evidence["materialization"] is not ev["materialization"],
           "each prove() returns fresh audit objects")

    # ---- 12. scan-level pre-G4 stop boundary (FIX1) ----------------------
    N = 0x1A00        # stand-in out-of-scope entry (e.g. nnMain)
    OBS = 0x1060      # approved observer that independently materializes V1
    scan_words = dict(DEFAULT_WORDS)
    scan_words.update(enc_pair(0x1000, N, reg=0))
    scan_words[0x1008] = enc_br(0)
    scan_words.update(enc_pair(N, V1, reg=0))
    scan_words[N + 8] = RET
    scan_words.update(enc_pair(OBS, V1, reg=5))
    scan_words[OBS + 8] = RET
    expect(0x180C in scan_words, "prior terminator before V1 retained")
    scan_mod = make_module(tmp, "main", BASE, words=scan_words)
    world = R.World([R.Image("main", BASE, scan_mod["flat"],
                             scan_mod["layout"], {})])

    s_all = R.scan_world(world, [(BASE + 0x1000, "start")],
                         subset_decoder=None)
    r_all = G.reached_from_scan(s_all, world)
    v_all = G.Prover([scan_mod], r_all).prove(BASE + V1)
    expect(v_all.ok, "default scan (no stop) admits V via N-only producer")

    s_stop = R.scan_world(world, [(BASE + 0x1000, "start")],
                          subset_decoder=None, stop_entries={BASE + N})
    r_stop = G.reached_from_scan(s_stop, world)
    bm = s_stop.visited["main"]
    expect(not bm[(N - TEXT_OFF) // 4], "stop entry word is not visited")
    expect(not bm[(0x1800 - TEXT_OFF) // 4]
           and not bm[(0x1804 - TEXT_OFF) // 4],
           "N-only producer words are not visited with the stop")
    v_stop = G.Prover([scan_mod], r_stop).prove(BASE + V1)
    expect(not v_stop.ok and v_stop.reason == "not-materialized",
           "pruned scan refuses V (producer not reached)")
    # The SAME pruned scan still admits V when an approved observer reaches
    # the producer independently: the stop must not disable other paths.
    s_stop2 = R.scan_world(world, [(BASE + 0x1000, "start"),
                                   (BASE + OBS, "observer")],
                           subset_decoder=None, stop_entries={BASE + N})
    v_stop2 = G.Prover([scan_mod],
                       G.reached_from_scan(s_stop2, world)).prove(BASE + V1)
    expect(v_stop2.ok,
           "pruned scan admits V when an observer reaches the producer")

    # ---- 12b. producer AFTER a known call/BL to the stopped entry --------
    after_words = dict(DEFAULT_WORDS)
    after_words.update({
        0x1000: enc_bl(0x1000, N), 0x1004: enc_adrp(0x1004, V1 & ~0xFFF, 0),
        0x1008: enc_add_lo12(0, 0, V1 & 0xFFF), 0x100C: enc_b(0x100C, V1),
        N: RET})
    after_mod = make_module(tmp, "main", BASE, words=after_words)
    after_world = R.World([R.Image("main", BASE, after_mod["flat"],
                                   after_mod["layout"], {})])
    a_all = R.scan_world(after_world, [(BASE + 0x1000, "start")],
                         subset_decoder=None)
    a_all_v = G.Prover([after_mod],
                       G.reached_from_scan(a_all, after_world)).prove(BASE + V1)
    expect(a_all_v.ok, "default scan admits a producer after bl <entry>")
    a_stop = R.scan_world(after_world, [(BASE + 0x1000, "start")],
                          subset_decoder=None, stop_entries={BASE + N})
    bm2 = a_stop.visited["main"]
    expect(not bm2[(0x1004 - TEXT_OFF) // 4],
           "bl <stopped> suppresses the return continuation")
    a_stop_v = G.Prover([after_mod],
                        G.reached_from_scan(a_stop, after_world)).prove(BASE + V1)
    expect(not a_stop_v.ok and a_stop_v.reason == "not-materialized",
           "pruned scan refuses V from a post-call-only producer")

    # A CONDITIONAL branch into the stopped entry keeps the other arm alive.
    cond_words = dict(DEFAULT_WORDS)
    cond_words.update({
        0x1000: enc_bcond(0x1000, N), 0x1004: enc_adrp(0x1004, V1 & ~0xFFF, 0),
        0x1008: enc_add_lo12(0, 0, V1 & 0xFFF), 0x100C: enc_b(0x100C, V1),
        N: RET})
    cond_mod = make_module(tmp, "main", BASE, words=cond_words)
    cond_world = R.World([R.Image("main", BASE, cond_mod["flat"],
                                  cond_mod["layout"], {})])
    c_stop = R.scan_world(cond_world, [(BASE + 0x1000, "start")],
                          subset_decoder=None, stop_entries={BASE + N})
    expect(c_stop.visited["main"][(0x1000 - TEXT_OFF) // 4],
           "conditional site itself stays visited")
    c_stop_v = G.Prover([cond_mod],
                        G.reached_from_scan(c_stop, cond_world)).prove(BASE + V1)
    expect(c_stop_v.ok,
           "conditional other-arm producer still admitted with the stop")

    # ---- 11. interface-level sanity --------------------------------------
    mod = make_module(tmp, "main", BASE)
    prover = G.Prover([mod], {"main": {BASE + o for o in REACHED}})
    expect(prover.prove(BASE + V1).ok, "positive still ok after refusals")
    expect(prover.prove(-1).reason == "bad-target", "negative VA refused")
    expect(prover.prove(BASE + V1 + 0x200000).reason == "not-text",
           "address past the image refused")
    try:
        G.Prover([mod, mod], REACHED)
        fail("duplicate module names accepted")
    except ValueError:
        okk("duplicate module names rejected")
    okk("verdicts are JSON serializable")


def expect(cond, msg):
    if cond:
        okk(msg)
    else:
        fail(msg)


def expect_input_error(label, fn):
    """Documented fail-closed INPUT error (not a Verdict, not a silent pass)."""
    global CAT
    CAT += 1
    try:
        fn()
    except G.InputError as exc:
        okk("case %02d %s -> InputError: %s" % (CAT, label, exc))
        return
    except Exception as exc:                               # noqa: BLE001
        fail("case %02d %s: raised %s, expected G.InputError"
             % (CAT, label, type(exc).__name__))
        return
    fail("case %02d %s: constructed without an InputError" % (CAT, label))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:                                   # noqa: BLE001
        import traceback
        traceback.print_exc()
        print("FAIL: infrastructure: %s" % exc)
        sys.exit(1)
