#!/usr/bin/env python3
"""Hermetic tests for tools/aot/g3_local_switch.py (bounded local switch edges).

Builds a synthetic, fully valid flat module (MOD0 + .dynamic + .dynsym +
.dynstr [+ .rela]) and drives the PUBLIC Context.discover interface with the
real aot_translate.decode callback.  Every negative is otherwise valid and is
asserted to fail for its own specific typed reason, not a broad one.

Exit: 0 pass, 2 semantic fail, 1 infrastructure.
"""

import copy
import hashlib
import json
import os
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "tools", "aot"))

import aot_module as M            # noqa: E402
import aot_translate as T         # noqa: E402

from g3_local_switch import (     # noqa: E402
    Context, InputError, ProofError, Refusal)

FAILS = []


def fail(msg):
    FAILS.append(msg)
    print("FAIL: " + msg)


def check(cond, msg):
    if not cond:
        fail(msg)


# ---------------------------------------------------------------- encoders
def enc_adrp(rd, imm21):
    imm21 &= (1 << 21) - 1
    return (0x90000000 | ((imm21 & 3) << 29) |
            (((imm21 >> 2) & 0x7FFFF) << 5) | rd)


def enc_adr(rd, imm21):
    imm21 &= (1 << 21) - 1
    return (0x10000000 | ((imm21 & 3) << 29) |
            (((imm21 >> 2) & 0x7FFFF) << 5) | rd)


def enc_add_imm(rd, rn, imm12):
    return 0x91000000 | ((imm12 & 0xFFF) << 10) | (rn << 5) | rd


def enc_cmp_imm(rn, imm12):
    return 0xF100001F | ((imm12 & 0xFFF) << 10) | (rn << 5)


def enc_bcond(cond, delta_words):
    return 0x54000000 | (((delta_words & 0x7FFFF) << 5)) | cond


def enc_ldrb_regoff(rt, rn, rm):
    return 0x38606800 | (rm << 16) | (rn << 5) | rt


def enc_add_lsl2(rd, rn, rm):
    return 0x8B000800 | (rm << 16) | (rn << 5) | rd


def enc_movz_w(rd, imm16):
    return 0x52800000 | ((imm16 & 0xFFFF) << 5) | rd


def enc_ldr_imm(rt, rn, imm12):
    return 0xF9400000 | ((imm12 & 0xFFF) << 10) | (rn << 5) | rt


def enc_b(delta_words):
    return 0x14000000 | (delta_words & 0x3FFFFFF)


def enc_bl(delta_words):
    return 0x94000000 | (delta_words & 0x3FFFFFF)


NOP = 0xD503201F
RET = 0xD65F03C0


def enc_umulh(rd, rn, rm):
    return (0x9BC07C00 | ((rm & 0x1F) << 16) |
            ((rn & 0x1F) << 5) | (rd & 0x1F))

TEXT_OFF = 0x1000
TEXT_SIZE = 0xC00
RO_OFF = 0x2000
RO_SIZE = 0x1000
DATA_OFF = 0x3000
FN_OFF = 0x1000
FN_SIZE = 0x800
TARGETS_OFF = 0x1600


def build(switch_n=5, values=None, table_off=0x40, table_seg="ro",
          label_off=None, fn_size=FN_SIZE, pre_window=(), extra_syms=(),
          extra_layout=None, rela_at_table=None, unpaired_rela=False,
          second=None, write_targets=True, loop_mode=None, fns=None,
          extra_words=(), eh_hdr=None, regs=None, extra_tags=None):
    """Build one valid flat module. `second` optionally adds a second switch."""
    if values is None:
        values = list(range(switch_n + 1))
    specs = [dict(n=switch_n, values=values, table_off=table_off,
                  table_seg=table_seg, label_off=label_off,
                  pre_window=list(pre_window))]
    if second:
        specs.append(second)

    text = bytearray(TEXT_SIZE)
    ro = bytearray(RO_SIZE)
    data = bytearray(0x400)
    table_vas = {}
    targets = {}
    windows = {}
    for i, sp in enumerate(specs):
        win = sp.get("win_off", TEXT_OFF + i * 0x80)
        tab_img = (RO_OFF if sp["table_seg"] == "ro" else DATA_OFF + 0x200)
        tab_img += sp["table_off"]
        lab = sp["label_off"] if sp["label_off"] is not None else TARGETS_OFF + i * 0x80
        # ADRP x9, page(tab); ADD x9, x9, #low12
        r = dict(idx=0, label=10, tab=9, off=11, add=10, br=10)
        if regs:
            r.update(regs)
        page_delta = (tab_img & ~0xFFF) - (win & ~0xFFF)
        k = page_delta >> 12
        word = enc_adrp(r["tab"], k)
        struct.pack_into("<I", text, win - TEXT_OFF, word)
        struct.pack_into("<I", text, win - TEXT_OFF + 4,
                         enc_add_imm(r["tab"], r["tab"], tab_img & 0xFFF))
        cur = win + 8
        for w in sp["pre_window"]:
            struct.pack_into("<I", text, cur - TEXT_OFF, w)
            cur += 4
        # window
        struct.pack_into("<I", text, cur - TEXT_OFF, enc_cmp_imm(r["idx"], sp["n"]))
        struct.pack_into("<I", text, cur - TEXT_OFF + 4,
                         enc_bcond(8, 5))          # -> +24 = default ret
        struct.pack_into("<I", text, cur - TEXT_OFF + 8,
                         enc_adr(r["label"], lab - (cur + 8)))
        struct.pack_into("<I", text, cur - TEXT_OFF + 12,
                         enc_ldrb_regoff(r["off"], r["tab"], r["idx"]))
        struct.pack_into("<I", text, cur - TEXT_OFF + 16,
                         enc_add_lsl2(r["add"], r["label"], r["off"]))
        struct.pack_into("<I", text, cur - TEXT_OFF + 20,
                         0xD61F0000 | (r["br"] << 5))
        struct.pack_into("<I", text, cur - TEXT_OFF + 24, RET)
        windows[i] = (cur, tab_img, lab)
        table_vas[i] = tab_img
        tg_img = tuple(lab + 4 * v for v in sp["values"])
        targets[i] = tuple(0x100000000 + t for t in tg_img)
        if write_targets:
            end = lab + 4 * (max(sp["values"]) + 1)
            for t in range(lab, end, 4):
                if 0 <= t - TEXT_OFF <= TEXT_SIZE - 4:
                    struct.pack_into("<I", text, t - TEXT_OFF, NOP)
            if 0 <= end - TEXT_OFF <= TEXT_SIZE - 4:
                struct.pack_into("<I", text, end - TEXT_OFF, RET)
        if loop_mode and i == 0:
            src = lab
            if loop_mode == "clobber":
                struct.pack_into("<I", text, src - TEXT_OFF,
                                 enc_add_imm(9, 9, 4))
                struct.pack_into("<I", text, src - TEXT_OFF + 4,
                                 enc_b((cur - (src + 4)) >> 2))
            else:
                tgt = cur - 4 if loop_mode == "prewindow" else cur
                struct.pack_into("<I", text, src - TEXT_OFF,
                                 enc_b((tgt - src) >> 2))
        blob = bytes(sp["values"])
        if sp["table_seg"] == "ro":
            lo = tab_img - RO_OFF
            ro[lo:min(lo + len(blob), RO_SIZE)] = blob[:max(0, RO_SIZE - lo)]
        else:
            lo = tab_img - DATA_OFF
            data[lo:min(lo + len(blob), len(data))] =                 blob[:max(0, len(data) - lo)]

    for off, word in extra_words:
        struct.pack_into("<I", text, off - TEXT_OFF, word)

    # symbols: null, declared FUNC set, extras
    if fns is None:
        fns = [("fn", FN_OFF, fn_size)]
    names = [b""]
    syms = [(0, 0, 0, 0, 0)]
    for nm, value, size in fns:
        names.append(nm.encode())
        syms.append((len(names) - 1, (1 << 4) | 2, 0, 1, value, size))
    for nm, typ, value, size in extra_syms:
        names.append(nm.encode())
        syms.append((len(names) - 1, (1 << 4) | typ, 0, 1, value, size))
    sym_bytes = bytearray()
    sym_bytes += b"\x00" * 24
    strt = bytearray(b"\x00")
    for nm in names[1:]:
        off = len(strt)
        strt += nm + b"\x00"
    for idx, (si, info_or_zero, _o, _s, val, size) in enumerate(syms[1:], 1):
        name_off = 1 + sum(len(n) + 1 for n in names[1:idx])
        sym_bytes += struct.pack("<IBBHQQ", name_off, info_or_zero, 0, 1,
                                 val, size)
    n_syms = len(syms)

    # data layout
    mod0 = 0
    dyn_rel = 0x20
    tags = {}
    if extra_tags:
        tags.update(extra_tags)
    tags[M.DT_SYMTAB] = None
    tags[M.DT_STRTAB] = None
    tags[M.DT_STRSZ] = len(strt)
    tags[M.DT_SYMENT] = 24
    if unpaired_rela:
        tags[M.DT_RELA] = 0
    if rela_at_table is not None:
        tags[M.DT_RELA] = None
        tags[M.DT_RELASZ] = 24
    n_dyn = len(tags) + 1
    dyn_size = n_dyn * 16
    symtab_rel = dyn_rel + dyn_size
    strtab_rel = symtab_rel + 24 * n_syms
    rela_rel = (strtab_rel + len(strt) + 7) & ~7
    need = rela_rel + (24 if rela_at_table is not None else 0)
    assert need <= len(data)
    tags[M.DT_SYMTAB] = DATA_OFF + symtab_rel
    tags[M.DT_STRTAB] = DATA_OFF + strtab_rel
    if rela_at_table is not None and rela_at_table >= 0:
        tags[M.DT_RELA] = DATA_OFF + rela_rel
        struct.pack_into("<QQq", data, rela_rel, rela_at_table, 1027 << 32, 0)
    struct.pack_into("<16s", data, mod0, b"MOD0")
    struct.pack_into("<i", data, mod0 + 4, dyn_rel)
    # bss_start/bss_end filled after we know the flat length
    off = dyn_rel
    for tag, val in tags.items():
        struct.pack_into("<QQ", data, off, tag, val)
        off += 16
    struct.pack_into("<QQ", data, off, 0, 0)
    data[symtab_rel:symtab_rel + len(sym_bytes)] = sym_bytes
    data[strtab_rel:strtab_rel + len(strt)] = strt

    raw = (bytes(TEXT_OFF) + bytes(text) +
           bytes(RO_OFF - TEXT_OFF - TEXT_SIZE) + bytes(ro) +
           bytes(DATA_OFF - RO_OFF - RO_SIZE) + bytes(data))
    flat_len = len(raw)
    struct.pack_into("<i", raw_buf := bytearray(raw), DATA_OFF + 8,
                     flat_len - DATA_OFF)
    struct.pack_into("<i", raw_buf, DATA_OFF + 12, flat_len - DATA_OFF)
    if eh_hdr is not None:
        struct.pack_into("<ii", raw_buf, DATA_OFF + 16, eh_hdr[0], eh_hdr[1])
    raw = bytes(raw_buf)
    layout = {
        "name": "fixture",
        "text": [TEXT_OFF, TEXT_SIZE],
        "ro": [RO_OFF, RO_SIZE],
        "data": [DATA_OFF, len(data)],
        "bss_size": 0,
        "dynsym_count": n_syms,
        "mod0_off": DATA_OFF,
        "image_size": flat_len,
        "init_array": [0, 0],
        "fini_array": [0, 0],
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    if extra_layout:
        layout.update(extra_layout)
    return dict(raw=raw, layout=layout, base=0x100000000,
                windows=windows, targets=targets, table_vas=table_vas,
                specs=specs)


def reach_graph(fx, roots, indirect=(), local=()):
    """REAL reached CFG: aot_translate.build_cfg from the ORIGINAL roots.

    `indirect` is used ONLY by the test harness to emulate the Phase-B
    post-expansion decode of already-discovered local targets; `local` adds the
    site-local edges the caller knows after that expansion.  No linear TEXT
    sweep is ever treated as "reached".
    """
    T.PARTIAL = 0
    base = fx["base"]
    ranges = [(base + TEXT_OFF, base + TEXT_OFF + TEXT_SIZE)]
    entries = sorted(set(roots))
    _blocks, visited = T.build_cfg(fx["raw"], ranges, entries,
                                   sorted(set(indirect)), base=base,
                                   module=True)
    # Only BR-site edges are a caller CLAIM; every other edge is derived by
    # discover from the raw-decoded semantics itself.
    edges = {}
    for pc, ins in visited.items():
        if ins.get("kind") != "br":
            continue
        tg = [t for t in T.successors(ins) if t in visited]
        if tg:
            edges[pc] = tuple(sorted(set(tg)))
    for src, tgt in local:
        cur = set(edges.get(src, ()))
        cur.add(tgt)
        edges[src] = tuple(sorted(cur))
    return visited, edges


def context(fx):
    return Context(fx["raw"], fx["layout"], fx["base"], T.decode)


def discover(fx, ctx=None, visited=None, roots=None, edges=None,
             indirect=(), local=(), defer=False):
    if roots is None:
        roots = {fx["base"] + FN_OFF}
    if visited is None or edges is None:
        visited, edges = reach_graph(fx, roots, indirect, local)
    ctx = ctx or context(fx)
    return ctx.discover(visited, roots, edges, defer_threats=defer)


# ---------------------------------------------------------------- positives
def test_positive():
    for n in (5, 7):
        values = [(i * 2) % (n + 1) for i in range(n + 1)] if n == 7             else list(range(n + 1))
        # N=7 also loops one case target back to the guard, so the expanded
        # graph revalidation exercises a real BR back edge.
        fx = build(switch_n=n, values=values,
                   loop_mode="back" if n == 7 else None)
        roots = {fx["base"] + FN_OFF}
        br_pc = fx["base"] + fx["windows"][0][0] + 20
        visited, edges = reach_graph(fx, roots)
        check(br_pc in visited, "N=%d: BR must be reached by build_cfg" % n)
        res = discover(fx, visited=visited, roots=roots, edges=edges,
                       defer=True)
        check(set(res) == {br_pc}, "N=%d: expected exactly the BR site" % n)
        p = res[br_pc]
        check(p.targets == fx["targets"][0], "N=%d: target set mismatch" % n)
        check(p.guard_bound == n, "N=%d: N is not the count authority" % n)
        check(len(p.targets) == n + 1, "N=%d: incomplete target set" % n)
        check(p.table_size == n + 1, "table size must be N+1")
        check(p.table_off == fx["table_vas"][0], "table VA mismatch")
        check(p.source_sha256 == fx["layout"]["sha256"], "source SHA binding")
        check(p.table_sha256 == hashlib.sha256(bytes(values)).hexdigest(),
              "table SHA binding")
        check(p.owner_name == "fn" and p.owner_size == FN_SIZE, "owner")
        check(p.window_pcs[0] + 20 == br_pc, "window PCs")
        d = p.to_dict()
        d["targets"] = ()
        check(p.targets == fx["targets"][0], "to_dict must be a deep copy")
        try:
            p.frozen_probe = 1
            fail("Proof must be frozen")
        except ProofError:
            pass
        check("root" not in p.keys(), "no root field may be produced")
        dflt = fx["base"] + fx["windows"][0][0] + 24
        check(p.default_target == dflt,
              "N=%d: B.HI default target audit field" % n)
        check(p.closure in ("pending-final-graph", "pending-expansion"),
              "a standalone phase-A proof must not claim closure")
        if p.deferred_threats:
            check(p.closure == "pending-expansion",
                  "deferred threats must be marked pending-expansion")
            check(any(s not in visited for s, _t in p.deferred_threats),
                  "only undecoded sources may be deferred")
        lo, hi = fx["base"] + TEXT_OFF, fx["base"] + TEXT_OFF + TEXT_SIZE
        check(lo <= p.default_target and p.default_target + 4 <= hi,
              "the default target must be a full word in TEXT")

        # Phase-B-shaped revalidation: the caller decodes the local targets and
        # adds the site-local BR edges, then re-proves on the expanded graph.
        tg = list(p.targets)
        v2, e2 = reach_graph(fx, roots, indirect=tg,
                             local=[(br_pc, t) for t in tg])
        res2 = discover(fx, visited=v2, roots=roots, edges=e2)
        check(br_pc in res2, "N=%d: final revalidation lost the proof" % n)
        check(res2[br_pc].targets == p.targets,
              "N=%d: final revalidation changed the target set" % n)
        check(not res2[br_pc].deferred_threats,
              "N=%d: strict revalidation must resolve every threat" % n)

    # two independent switches in two declared FUNC roots, both reached.
    second = dict(n=4, values=[0, 1, 2, 3, 4], table_off=0x80,
                  table_seg="ro", label_off=0x1680, win_off=0x1400,
                  pre_window=[])
    fx = build(switch_n=3, values=[0, 1, 2, 3], label_off=0x1200,
               fns=[("fn1", 0x1000, 0x400), ("fn2", 0x1400, 0x400)],
               second=second)
    roots = {fx["base"] + 0x1000, fx["base"] + 0x1400}
    res = discover(fx, roots=roots)
    check(len(res) == 2, "two rooted switches must both be recovered")
    for i in (0, 1):
        br_pc = fx["base"] + fx["windows"][i][0] + 20
        check(br_pc in res, "missing proof for switch %d" % i)
        check(res[br_pc].targets == fx["targets"][i],
              "switch %d target set" % i)


def test_alias_owner_counts_one():
    fx = build(extra_syms=[("fn_alias", 2, FN_OFF, FN_SIZE)])
    p = discover(fx)[fx["base"] + fx["windows"][0][0] + 20]
    check(p.owner_size == FN_SIZE, "identical alias must count as one owner")


def test_table_is_authority_not_observed_value():
    # Two fixtures with identical windows and different table bytes must yield
    # different target sets: no observed runtime selector is consulted.
    a = build(values=[0, 1, 2, 3, 4, 5])
    b = build(values=[0, 2, 4, 1, 3, 5])
    pa = discover(a)[a["base"] + a["windows"][0][0] + 20]
    pb = discover(b)[b["base"] + b["windows"][0][0] + 20]
    check(pa.targets != pb.targets, "target set must follow the table bytes")
    check(pa.targets == a["targets"][0] and pb.targets == b["targets"][0],
          "each proof must equal its own complete table mapping")


def test_unreachable_switch_not_recovered():
    # A matching, otherwise-valid switch window is DECODED into the candidate
    # pool but has no path from the original roots.  Context must filter it by
    # reach, not because the caller omitted it.
    extra = dict(n=3, values=[0, 1, 2, 3], table_off=0x2C0,
                 table_seg="ro", label_off=0x1B00, win_off=0x1A00,
                 pre_window=[])
    fx = build(fns=[("fn", FN_OFF, 0x800), ("fn_extra", 0x1A00, 0x200)],
               second=extra)
    roots = {fx["base"] + FN_OFF}
    visited, edges = reach_graph(fx, roots)
    extra_br = fx["base"] + fx["windows"][1][0] + 20
    check(extra_br not in visited, "the disconnected window is not reached")
    # Auxiliary decode of that window block (test-only candidate pool entry).
    aux, _aux_edges = reach_graph(fx, {fx["base"] + 0x1A00})
    merged = dict(visited)
    merged.update(aux)
    check(extra_br in merged, "the matching BR must be in the candidate pool")
    res = discover(fx, visited=merged, roots=roots, edges=edges)
    check(set(res) == {fx["base"] + fx["windows"][0][0] + 20},
          "an unreached matching BR must never be recovered")
    # Same bytes are provable when that window is genuinely rooted.
    rooted = discover(fx, roots={fx["base"] + 0x1A00})
    check(extra_br in rooted,
          "the fixture window itself must be a valid proof when rooted")


def test_other_br_idiom_unhandled():
    fx = build(extra_words=[(0x1A00, 0xD61F0000 | (3 << 5))])
    roots = {fx["base"] + FN_OFF}
    visited, edges = reach_graph(fx, roots)
    extra_pc = fx["base"] + 0x1A00
    w = struct.unpack_from("<I", fx["raw"], extra_pc - fx["base"])[0]
    ins = T.decode(extra_pc, w, module=True)
    ins["word"] = w
    visited[extra_pc] = ins
    res = discover(fx, visited=visited, roots=roots, edges=edges)
    check(set(res) == {fx["base"] + fx["windows"][0][0] + 20},
          "non-matching BR must stay unhandled (no fallback)")
    check(extra_pc not in res, "a different BR idiom is never admitted")


def test_mutation_after_context():
    fx = build()
    roots = {fx["base"] + FN_OFF}
    visited, edges = reach_graph(fx, roots)
    raw = bytearray(fx["raw"])
    layout = copy.deepcopy(fx["layout"])
    ctx = Context(bytes(raw), layout, fx["base"], T.decode)
    br_pc = fx["base"] + fx["windows"][0][0] + 20
    before = ctx.discover(visited, roots, edges)
    table_va = fx["table_vas"][0]
    raw[table_va] = 0xFE
    layout["ro"] = [RO_OFF, 0]
    layout["sha256"] = "0" * 64
    after = ctx.discover(visited, roots, edges)
    check(before[br_pc].targets == after[br_pc].targets,
          "mutating caller objects after construction must have no effect")
    check(after[br_pc].table_sha256 == before[br_pc].table_sha256,
          "snapshot table SHA must be stable")


# ---------------------------------------------------------------- negatives
def expect(message, fn, cls=Refusal):
    try:
        fn()
    except cls as exc:
        if message and message not in str(exc):
            fail("wrong reason: expected %r in %r" % (message, str(exc)))
        return
    except ProofError as exc:
        fail("wrong typed failure (%s): %r" % (cls.__name__, str(exc)))
        return
    fail("expected %s for %r" % (cls.__name__, message))


def test_negative_table_placement():
    # writable (data) table
    fx = build(table_seg="data")
    expect("immutable RO segment", lambda: discover(fx))
    # table crossing the RO end
    fx = build(table_off=RO_SIZE - 3)
    expect("immutable RO segment", lambda: discover(fx))
    # bad count: N+1 bytes do not fit the RO extent
    fx = build(switch_n=0xFFF, values=[0] * 0x1000,
               label_off=TARGETS_OFF)
    expect("immutable RO segment", lambda: discover(fx))


def test_negative_label_and_targets():
    fx = build(label_off=TARGETS_OFF + 2)
    expect("not 4-aligned", lambda: discover(fx))
    # target past the owning FUNC end
    fx = build(switch_n=1, values=[0, 1], label_off=FN_OFF + FN_SIZE - 4)
    expect("outside the owning FUNC", lambda: discover(fx))
    # target past TEXT (owner extended over text end for this control)
    fx = build(switch_n=1, values=[0, 1], label_off=TEXT_OFF + TEXT_SIZE - 4,
               fn_size=TEXT_SIZE)
    expect("outside module TEXT", lambda: discover(fx))
    # target inside a declared OBJECT (caught as owner-span ambiguity)
    fx = build(extra_syms=[("tabobj", 1, TARGETS_OFF, 8)],
               label_off=TARGETS_OFF)
    expect("overlaps another defined symbol", lambda: discover(fx), Refusal)
    # label pointing into the guard window
    fx = build(label_off=TEXT_OFF + 12, write_targets=False)
    expect("label points into the guard window", lambda: discover(fx))


def test_negative_metadata_and_relocs():
    # MOD0+16/+20 are SIGNED OFFSETS RELATIVE TO MOD0 (DATA_OFF here), not
    # absolute image offsets.
    fx = build(eh_hdr=(RO_OFF + 0x40 - DATA_OFF, RO_OFF + 0x80 - DATA_OFF))
    expect("loader-consumed extent", lambda: discover(fx))
    # Absolute-interpretation geometry must NOT hide the header: the same
    # bytes read as absolute would land inside the raw data segment, so the
    # corrected interval is what refuses the table.  A bogus relative interval
    # outside the image is a typed context error.
    fx2 = build(eh_hdr=(RO_OFF + 0x4000, RO_OFF + 0x4004))
    expect("EH-frame-header interval is invalid",
           lambda: Context(fx2["raw"], fx2["layout"], fx2["base"], T.decode),
           InputError)
    # M1: a present EH header outside the module RO is a typed refusal, never
    # a silent skip of the frame exclusion (fail-open).
    fx3 = build(eh_hdr=(0x40, 0x44))       # -> DATA_OFF+0x40, in DATA
    expect("not fully inside the module RO segment",
           lambda: Context(fx3["raw"], fx3["layout"], fx3["base"], T.decode),
           InputError)
    # DT_PREINIT_ARRAY/SZ are consumed intervals; unpaired is an error.
    fx = build(extra_tags={32: RO_OFF + 0x40, 33: 8})
    expect("loader-consumed extent", lambda: discover(fx))
    fx = build(extra_tags={32: RO_OFF + 0x40})
    expect("unpaired", lambda: Context(fx["raw"], fx["layout"],
                                       fx["base"], T.decode), InputError)
    # MOD0 is the authority: an old layout eh_frame_hdr key alone is ignored.
    fx = build(extra_layout={"eh_frame_hdr": [RO_OFF + 0x40, 0x40]})
    check(bool(discover(fx)), "a layout-only eh_frame_hdr key must not be "
          "treated as metadata")
    fx = build(rela_at_table=RO_OFF + 0x40)
    expect("relocation site", lambda: discover(fx))
    fx = build(unpaired_rela=True)
    expect("unpaired", lambda: Context(fx["raw"], fx["layout"],
                                       fx["base"], T.decode), InputError)


def test_negative_owner_ambiguity():
    fx = build(extra_syms=[("fn_partial", 2, FN_OFF, 0x40)])
    expect("distinct owning FUNC spans", lambda: discover(fx))


def test_positive_br_backedge_preserves_base():
    # A case target branches back to the guard.  The BR writes no GPR, so the
    # proven table base must survive the loop merge on the REAL expanded graph.
    fx = build(switch_n=7, values=[0, 1, 2, 3, 4, 5, 6, 7], loop_mode="back")
    roots = {fx["base"] + FN_OFF}
    br_pc = fx["base"] + fx["windows"][0][0] + 20
    first = discover(fx, roots=roots, defer=True)
    tg = list(first[br_pc].targets)
    v2, e2 = reach_graph(fx, roots, indirect=tg,
                         local=[(br_pc, t) for t in tg])
    p = discover(fx, visited=v2, roots=roots, edges=e2)[br_pc]
    check(p.targets == fx["targets"][0],
          "loop back edge must not destroy the table-base proof")


def test_negative_table_base():
    # overwrite the proven base register before the window
    fx = build(pre_window=[enc_add_imm(9, 9, 4)])
    expect("not the proven ADRP+ADD constant", lambda: discover(fx))
    # W-form alias write kills the X register
    fx = build(pre_window=[enc_movz_w(9, 0)])
    expect("not the proven ADRP+ADD constant", lambda: discover(fx))
    # a call boundary clobbers conservatively
    fx = build(pre_window=[enc_bl(0)])
    expect("not the proven ADRP+ADD constant", lambda: discover(fx))
    # actual T-decoded loads into the base register kill the constant
    for word, label in ((enc_ldr_imm(9, 1, 0), "LDR X9"),
                        (0x39400029, "LDRB W9"),
                        (0x39800029, "LDRSB X9"),
                        (0xD53BE029, "MRS X9, CNTPCT"),
                        (enc_umulh(9, 1, 2), "UMULH X9")):
        fx = build(pre_window=[word])
        expect("not the proven ADRP+ADD constant",
               lambda fx=fx: discover(fx))
        check(label, label)
    # UMULH kills ONLY its Rd: the identical form writing another register
    # must leave the proven base intact.
    fx = build(pre_window=[enc_umulh(4, 9, 1)])
    check(len(discover(fx)) == 1,
          "umulh x4,x9,x1 must not clobber the proven table base")


def test_umulh_write_set():
    """UMULH is a NEW decoded kind, so its write-kill set must come from the
    ACTUAL decoded word (Capstone defs), not from a relaxed unknown rule.
    Exactly Rd is killed, Rd=31 (the ZERO register) kills nothing, and Rn/Rm
    are reads only."""
    fx = build()
    ctx = context(fx)
    pc = fx["base"]

    def ins_for(word):
        # The prover consumes the raw-snapshot shape: the decoded fields plus
        # the ORIGINAL word that Capstone is asked about.
        d = dict(T.decode(pc, word, module=True))
        d["word"] = word
        return d

    for rd, rn, rm in ((2, 0, 1), (9, 31, 31), (18, 10, 9), (0, 0, 0),
                       (30, 1, 2)):
        ins = ins_for(enc_umulh(rd, rn, rm))
        check(ins["kind"] == "umulh",
              "fixture 0x%08x must decode as umulh" % enc_umulh(rd, rn, rm))
        check(ctx._written(ins) == frozenset({rd}),
              "umulh x%d,x%d,x%d must kill exactly Rd=%d, got %r"
              % (rd, rn, rm, rd, sorted(ctx._written(ins))))
    ins = ins_for(enc_umulh(31, 1, 2))
    check(ctx._written(ins) == frozenset(),
          "umulh with Rd=31 discards and must kill no GPR, got %r"
          % sorted(ctx._written(ins)))


def test_negative_guard_entry():
    fx = build()
    win = fx["base"] + fx["windows"][0][0]
    # a root entering the ADR..BR window bypasses the guard
    roots = {fx["base"] + FN_OFF, win + 16}
    v, e = reach_graph(fx, roots)
    expect("enters the ADR..BR window",
           lambda: discover(fx, visited=v, roots=roots, edges=e))
    # a direct edge into the LDRB window from a reached RET
    roots = {fx["base"] + FN_OFF}
    v, e = reach_graph(fx, roots)
    src = fx["base"] + 0x1020
    e = dict(e)
    e[src] = tuple(sorted(set(e.get(src, ())) | {win + 12}))
    expect("not a BR instruction",
           lambda: discover(fx, visited=v, roots=roots, edges=e), InputError)


def test_b1_unknown_raw_incoming_branch():
    """A raw B word outside the decoded graph that targets the window or the
    ADD pair is an UNKNOWN dataflow entry; it is never decoded or promoted and
    the base proof fails unless a later ADRP regenerates the base."""
    def b_word(pc, tgt):
        return 0x14000000 | (((tgt - pc) >> 2) & 0x03FFFFFF)
    win = TEXT_OFF
    src = 0x1400
    fx = build(extra_words=[(src, b_word(src, win + 12))])
    roots = {fx["base"] + FN_OFF}
    v, e = reach_graph(fx, roots)
    check(src + fx["base"] not in v,
          "the threat word must stay outside the decoded graph")
    expect("post-CMP switch window",
           lambda: discover(fx, visited=v, roots=roots, edges=e))
    # the ADD of the table base pair is never an admissible incoming target
    fx2 = build(extra_words=[(src, b_word(src, win + 4))])
    v2, e2 = reach_graph(fx2, roots)
    expect("not the proven ADRP+ADD constant",
           lambda: discover(fx2, visited=v2, roots=roots, edges=e2))
    # B1 owner: an unvisited B into an ORDINARY instruction between the ADD
    # and the load (not the window, not the pair) still bypasses the base.
    fx3 = build(pre_window=(NOP, NOP), extra_words=[(src, b_word(src, win + 8))])
    v3, e3 = reach_graph(fx3, roots)
    expect("not the proven ADRP+ADD constant",
           lambda: discover(fx3, visited=v3, roots=roots, edges=e3))


def test_negative_mid_function_root():
    # An injected original root mid-function bypasses the materialization.
    fx = build()
    roots = {fx["base"] + FN_OFF, fx["base"] + fx["windows"][0][0]}
    v, e = reach_graph(fx, roots)
    expect("not the proven ADRP+ADD constant",
           lambda: discover(fx, visited=v, roots=roots, edges=e))


def test_negative_loop_clobber_after_revalidation():
    # Initial proof on the unexpanded graph, then a NEW local edge exposes a
    # case block that CLOBBERS the base before branching back: the final
    # revalidation must refuse rather than keep the stale proof.
    fx = build(switch_n=3, values=[0, 1, 2, 3], loop_mode="clobber")
    roots = {fx["base"] + FN_OFF}
    br_pc = fx["base"] + fx["windows"][0][0] + 20
    first = discover(fx, roots=roots, defer=True)
    check(br_pc in first, "the initial proof must succeed before expansion")
    tg = list(first[br_pc].targets)
    v2, e2 = reach_graph(fx, roots, indirect=tg,
                         local=[(br_pc, t) for t in tg])
    expect("not the proven ADRP+ADD constant",
           lambda: discover(fx, visited=v2, roots=roots, edges=e2))


def test_c2_stage_positive_cmp_and_prewindow_entries():
    # A decoded case body may branch back to the CMP or into the pre-window
    # (after the ADRP+ADD ADD): the guard re-checks and the table base is
    # proven along the B edge.  An UNDECODED raw B into the CMP cannot
    # re-establish the table base, so the strict pass must refuse it (H1).
    win = TEXT_OFF
    src = 0x1400
    b_word = lambda pc, tgt: 0x14000000 | (((tgt - pc) >> 2) & 0x03FFFFFF)
    # case body B -> CMP (the guard re-establishes itself: not a threat)
    fx = build(switch_n=3, values=[0, 1, 2, 3], loop_mode="back")
    roots = {fx["base"] + FN_OFF}
    br_pc = fx["base"] + fx["windows"][0][0] + 20
    p0 = discover(fx, roots=roots, defer=True)
    check(p0[br_pc].deferred_threats,
          "stage 1 defers the undecoded case-body B into the CMP")
    check(p0[br_pc].closure == "pending-expansion", "stage-1 closure")
    tg0 = list(p0[br_pc].targets)
    v0, e0 = reach_graph(fx, roots, indirect=tg0,
                         local=[(br_pc, t) for t in tg0])
    f0 = discover(fx, visited=v0, roots=roots, edges=e0)[br_pc]
    check(not f0.deferred_threats,
          "the decoded case body resolves the CMP entry threat")
    check(f0.raw_entry_seeds == (), "no UNKNOWN seed remains on the final graph")
    # case body B -> the pre-window NOP after the ADRP+ADD ADD: protected, so
    # stage 1 defers it and stage 2 resolves it via the decoded case body.
    fx = build(switch_n=3, values=[0, 1, 2, 3], pre_window=(NOP,),
               loop_mode="prewindow")
    roots = {fx["base"] + FN_OFF}
    br_pc = fx["base"] + fx["windows"][0][0] + 20
    prov = discover(fx, roots=roots, defer=True)
    check(br_pc in prov, "the provisional proof must admit the case path")
    check(prov[br_pc].deferred_threats,
          "the undecoded case-body B into the pre-window must be deferred")
    check(prov[br_pc].closure == "pending-expansion", "stage-1 closure")
    tg = list(prov[br_pc].targets)
    v2, e2 = reach_graph(fx, roots, indirect=tg,
                         local=[(br_pc, t) for t in tg])
    final = discover(fx, visited=v2, roots=roots, edges=e2)
    check(not final[br_pc].deferred_threats,
          "the decoded case body must resolve the deferred threat")
    check(final[br_pc].targets == prov[br_pc].targets, "targets unchanged")


def test_c2_stage_negative_dead_external_source():
    # A raw external B into the window that is NEVER decoded (directly after
    # the CMP, not a case target) may be deferred by stage 1, but the strict
    # final pass must merge an UNKNOWN entry and refuse (no later ADRP).
    win = TEXT_OFF
    src = 0x1400
    b_word = lambda pc, tgt: 0x14000000 | (((tgt - pc) >> 2) & 0x03FFFFFF)
    dead = build(extra_words=[(src, b_word(src, win + 12))])
    roots = {dead["base"] + FN_OFF}
    v, e = reach_graph(dead, roots)
    prov = discover(dead, visited=v, edges=e, defer=True)
    br_pc = dead["base"] + dead["windows"][0][0] + 20
    check(prov[br_pc].deferred_threats ==
          ((dead["base"] + src, dead["base"] + win + 12),),
          "the dead external source must be recorded, not ignored")
    expect("post-CMP switch window",
           lambda: discover(dead, visited=v, edges=e))
    # an UNDECODED raw B into the ADRP does NOT refuse: the ADRP regenerates
    # the table base before the ADD/load (H1).
    fx = build(extra_words=[(src, b_word(src, win))])
    v2, e2 = reach_graph(fx, {fx["base"] + FN_OFF})
    check(discover(fx, visited=v2, edges=e2),
          "an ADRP re-entry must be allowed to regenerate the base")
    T.PARTIAL = 0
    ranges = [(dead["base"] + TEXT_OFF,
               dead["base"] + TEXT_OFF + TEXT_SIZE)]
    expect("final graph refused",
           lambda: T.module_cfg(dead["raw"], ranges,
                                [dead["base"] + FN_OFF],
                                dead["base"], dead["layout"]), T.DecodeError)


def test_h1_out_of_numeric_range_guard_path():
    """H1: the UNKNOWN-entry index follows the owner GRAPH, not the numeric
    [ADD, load) interval.  A valid switch whose pair->B goes to a block far
    after the BR and back to the guard still proves; an undecoded external B
    into that out-of-range block seeds UNKNOWN and the final pass refuses."""
    block = 0x1700
    ext = 0x17C0
    guard = TEXT_OFF + 8 + 4               # one pre-window word
    pre = [enc_b((block - (TEXT_OFF + 8)) >> 2)]
    block_b = enc_b((guard - block) >> 2)
    roots = {0x100000000 + FN_OFF}
    T.PARTIAL = 0
    ranges = [(0x100000000 + TEXT_OFF, 0x100000000 + TEXT_OFF + TEXT_SIZE)]
    fx = build(switch_n=3, values=[0, 1, 2, 3], pre_window=pre,
               extra_words=[(block, block_b)])
    br_pc = fx["base"] + fx["windows"][0][0] + 20
    _b, vis, proofs = T.module_cfg(fx["raw"], ranges, sorted(roots),
                                   fx["base"], fx["layout"])
    check(proofs[br_pc].closure == "verified-final-graph",
          "a B out of the numeric range and back to the guard is valid")
    check(fx["base"] + block in vis,
          "the out-of-range block is decoded through the real B edge")
    # add an UNDECODED external B into the out-of-range block
    bad = build(switch_n=3, values=[0, 1, 2, 3], pre_window=pre,
                extra_words=[(block, block_b),
                             (ext, enc_b((block - ext) >> 2))])
    v, e = reach_graph(bad, roots)
    check(bad["base"] + ext not in v, "the external source stays undecoded")
    expect("not the proven ADRP+ADD constant",
           lambda: discover(bad, visited=v, roots=roots, edges=e))
    expect("final graph refused",
           lambda: T.module_cfg(bad["raw"], ranges, sorted(roots),
                                bad["base"], bad["layout"]), T.DecodeError)


def test_h1r_undecoded_raw_into_add_and_br():
    """H1-R: an UNKNOWN seed at ADD/BR can never reach at_load, so the strict
    proof must refuse an undecoded raw branch into the post-CMP window."""
    w0 = TEXT_OFF + 8                 # window start (empty pre-window)
    for off in (16, 20):              # ADD (pcs[4]) and BR (pcs[5])
        fx = build(extra_words=[(0x1400, 0x14000000 |
                                 ((((w0 + off) - 0x1400) >> 2) & 0x03FFFFFF))])
        roots = {fx["base"] + FN_OFF}
        v, e = reach_graph(fx, roots)
        br_pc = fx["base"] + fx["windows"][0][0] + 20
        prov = discover(fx, visited=v, roots=roots, edges=e, defer=True)
        check(prov[br_pc].deferred_threats ==
              ((fx["base"] + 0x1400, fx["base"] + w0 + off),),
              "provisional must RECORD the ADD/BR threat, not drop it")
        expect("post-CMP switch window",
               lambda: discover(fx, visited=v, roots=roots, edges=e))
        T.PARTIAL = 0
        ranges = [(fx["base"] + TEXT_OFF,
                   fx["base"] + TEXT_OFF + TEXT_SIZE)]
        expect("final graph refused",
               lambda: T.module_cfg(fx["raw"], ranges,
                                    [fx["base"] + FN_OFF],
                                    fx["base"], fx["layout"]), T.DecodeError)


def test_forged_or_duplicate_caller_ir():
    fx = build()
    roots = {fx["base"] + FN_OFF}
    v, e = reach_graph(fx, roots)
    br_pc = fx["base"] + fx["windows"][0][0] + 20
    adr_pc = br_pc - 12
    # forged word
    bad = dict(v)
    bad[br_pc] = dict(v[br_pc])
    bad[br_pc]["word"] ^= 1
    expect("caller word", lambda: discover(fx, visited=bad, roots=roots,
                                           edges=e), InputError)
    # forged PC-relative ADR value (would select an arbitrary RO table)
    bad = dict(v)
    bad[adr_pc] = dict(v[adr_pc])
    bad[adr_pc]["value"] = fx["base"] + RO_OFF
    expect("caller field value", lambda: discover(fx, visited=bad, roots=roots,
                                                  edges=e), InputError)
    # duplicate PCs in list form must not last-wins
    dup = list(v.values()) + [dict(v[adr_pc])]
    expect("duplicate visited pc",
           lambda: discover(fx, visited=dup, roots=roots, edges=e), InputError)
    # forged "unsupported" for a strictly decodable word
    bad = dict(v)
    bad[br_pc] = {"pc": br_pc, "kind": "unsupported",
                  "word": v[br_pc]["word"]}
    expect("strictly decodes", lambda: discover(fx, visited=bad, roots=roots,
                                               edges=e), InputError)
    # forged known IR for an unsupported raw word
    extra_pc = fx["base"] + 0x1A00
    bad = dict(v)
    bad[extra_pc] = {"pc": extra_pc, "kind": "nop", "word": 0}
    expect("authoritative placeholder",
           lambda: discover(fx, visited=bad, roots=roots, edges=e),
           InputError)
    # authoritative unsupported placeholder for an unrelated op is tolerated
    # in a PARTIAL graph and does not invalidate the reachable proof.
    ok = dict(v)
    ok[extra_pc] = {"pc": extra_pc, "kind": "unsupported", "word": 0}
    res = discover(fx, visited=ok, roots=roots, edges=e)
    check(br_pc in res, "an unrelated unsupported node must not reject the "
          "whole partial module")


def test_shape_register_aliases():
    cases = [
        (dict(idx=31), "ZR"),
        (dict(tab=31), "ZR"),
        (dict(label=31), "ZR"),
        (dict(off=31), "ZR"),
        (dict(add=31, br=31), "ZR"),
        (dict(label=0), "alias"),        # label == idx
        (dict(label=9), "alias"),        # label == tab
        (dict(off=10), "alias"),         # LDRB dest == label
        (dict(add=0, br=0), "aliases"),  # ADD dest == idx
        (dict(add=9, br=9), "aliases"),  # ADD dest == tab
    ]
    for regs, why in cases:
        fx = build(regs=regs)
        expect(why, lambda fx=fx: discover(fx))


def test_target_into_table_pair():
    fx = build(label_off=TEXT_OFF, values=[0, 1, 2, 3], write_targets=False)
    expect("table-base pair", lambda: discover(fx))


def test_owner_span_ambiguity():
    # a nested FUNC that does NOT contain the BR still makes the owner span
    # ambiguous
    fx = build(extra_syms=[("nested", 2, 0x1400, 0x100)])
    expect("overlaps another defined symbol", lambda: discover(fx))
    # a partial FUNC that DOES contain the BR is also ambiguous
    fx = build(extra_syms=[("fn_partial", 2, FN_OFF, 0x40)])
    expect("distinct owning FUNC spans", lambda: discover(fx))


def test_segment_geometry_and_freeze():
    fx = build()
    bad = copy.deepcopy(fx["layout"])
    bad["ro"] = [0x3000, 0x100]          # page-aligned, overlaps data
    expect("overlap", lambda: Context(fx["raw"], bad, fx["base"], T.decode),
           InputError)
    bad = copy.deepcopy(fx["layout"])
    bad["ro"] = [0x2010, 0x100]          # not page-aligned
    expect("page boundary",
           lambda: Context(fx["raw"], bad, fx["base"], T.decode), InputError)
    ctx = context(fx)
    expect("immutable", lambda: setattr(ctx, "base", 1), InputError)
    expect("immutable", lambda: setattr(ctx, "layout", {}), InputError)
    lay = ctx.layout
    lay["ro"] = [0, 0]
    check(ctx.layout["ro"] == [RO_OFF, RO_SIZE],
          "the exposed layout must be a copy")
    tags = ctx.tags
    tags[1234] = 1
    check(1234 not in ctx.tags, "the exposed tags must be a copy")
    # Proof deepcopy must work (and stay frozen).
    p = discover(fx)[fx["base"] + fx["windows"][0][0] + 20]
    q = copy.deepcopy(p)
    check(q is p and q.targets == p.targets,
          "deepcopy of a frozen Proof must return the frozen object")


def test_unsupported_consumed_tags():
    fx = build(extra_tags={17: 0})
    expect("DT_REL", lambda: context(fx), InputError)
    fx = build(extra_tags={M.DT_JMPREL: DATA_OFF, M.DT_PLTRELSZ: 0,
                           M.DT_PLTREL: 17})
    expect("DT_PLTREL", lambda: context(fx), InputError)


def test_phase_b_module_pipeline():
    """Phase-B wiring: real build_cfg + public module_cfg + codegen guard."""
    fx = build(switch_n=12, values=[0, 1, 2, 3, 4, 5] * 2)
    base = fx["base"]
    roots = {base + FN_OFF}
    ranges = [(base + TEXT_OFF, base + TEXT_OFF + TEXT_SIZE)]
    T.PARTIAL = 0
    _b0, v0 = T.build_cfg(fx["raw"], ranges, sorted(roots), [], base=base,
                          module=True)
    want = {base + TARGETS_OFF + 4 * i for i in range(6)}
    check(not (want & set(v0)),
          "table targets must not be decoded as initial roots")
    blocks, vis, proofs = T.module_cfg(fx["raw"], ranges, sorted(roots), base,
                                       fx["layout"])
    check(len(proofs) == 1, "one reached BR site is proven")
    p = next(iter(proofs.values()))
    check(set(p.targets) == want,
          "the graph must include ALL table targets, not metadata entries")
    check(len(set(p.targets)) == 6, "12 values must dedupe to 6 targets")
    check(want <= set(vis), "new blocks come from site targets only")
    check(set(roots) <= set(vis)
          and p.closure == "verified-final-graph",
          "only the pipeline may mark verified closure")
    check(not (want & set(v0)),
          "the initial graph must still not contain the targets")
    text = T.emit_c("t", blocks, ranges, "00" * 32, 0,
                    (0, 0, 0),
                    subset_id="test", abi_expr="AOT_ABI_VERSION_PROGRAM",
                    switch_sites={pc: q.targets for pc, q in proofs.items()})
    for t in want:
        check("0x%xull" % t in text, "guard must list every proven target")
    check("AOT_FAULT_BAD_STATE" in text
          and "rt->fault_target = rt->next_pc" in text,
          "a non-member target must fault with the exact target")
    # D022 C3: reserved DISJOINT negative status namespace (never 1..3).
    check("rt->fault_status = %d;" % (T.LOCAL_SWITCH_STATUS_BASE - 1) in text,
          "the guard must use the reserved negative local-switch status")
    check("rt->fault_status = 0;\n        rt->reason" not in text,
          "the guard must not borrow an unrelated status value")
    check("AOT_EXIT_INDIRECT" in text, "the valid path keeps INDIRECT")
    # a matching but unreachable switch is not recovered by the pipeline
    fx2 = build(switch_n=7, values=list(range(8)), second=dict(
        n=13, values=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0],
        table_off=0x80, table_seg="ro", pre_window=[],
        win_off=TEXT_OFF + 0xA00, label_off=TARGETS_OFF + 0x200))
    _b2, v2, pr2 = T.module_cfg(fx2["raw"], ranges, sorted(roots), base,
                                fx2["layout"])
    check(len(pr2) == 1, "an unreached switch must not be recovered")
    # final closure: a clobber introduced by a new case must fail the module
    fx3 = build(switch_n=3, values=[0, 1, 2, 3], loop_mode="clobber")
    try:
        T.module_cfg(fx3["raw"], ranges, sorted(roots), base, fx3["layout"])
    except T.DecodeError as e:
        check("closure" in str(e) or "refused" in str(e),
              "a failed final revalidation is a typed module error")
    else:
        raise AssertionError("a post-expansion base clobber must fail closure")


def test_phase_b_interior_target_splits_blocks():
    """A proven target already visited as an INTERIOR word must become a new
    BB start; a global indirect seed or a 'not in visited' filter misses it."""
    fx = build(switch_n=1, values=[0, 1], pre_window=(NOP, NOP),
               label_off=TEXT_OFF + 8, write_targets=False)
    base = fx["base"]
    roots = {base + FN_OFF}
    ranges = [(base + TEXT_OFF, base + TEXT_OFF + TEXT_SIZE)]
    tg = {base + TEXT_OFF + 8, base + TEXT_OFF + 12}
    T.PARTIAL = 0
    b0, v0 = T.build_cfg(fx["raw"], ranges, sorted(roots), [], base=base,
                         module=True)
    check(tg <= set(v0), "the interior words must already be decoded")
    check(not (tg & {b["pc"] for b in b0}),
          "they must not be block starts without a proven local edge")
    blocks, _vis, proofs = T.module_cfg(fx["raw"], ranges, sorted(roots), base,
                                        fx["layout"])
    starts = {b["pc"] for b in blocks}
    check(tg <= starts, "proven interior targets must split new blocks")
    check(len(proofs) == 1 and set(proofs[next(iter(proofs))].targets) == tg,
          "the proof must carry both interior targets")
    for pc in tg:
        blk = [b for b in blocks if b["pc"] == pc][0]
        check(blk["insns"][0]["pc"] == pc, "new block must start at the target")
    check(set(roots) <= {b["pc"] for b in b0},
          "entries remain the only initial work-list source")
    # no-global-seeding control: build_cfg without local_edges must not
    # produce those starts, and the legacy G2 path is byte-identical.
    b1, v1 = T.build_cfg(fx["raw"], ranges, sorted(roots), [], base=base,
                         module=True, local_edges=None)
    check(b1 == b0 and set(v1) == set(v0),
          "local_edges=None must be identical to the legacy call")


def test_g2_default_path_unchanged():
    fx = build()
    blocks, visited = T.build_cfg(fx["raw"], [(fx["base"] + TEXT_OFF,
                                               fx["base"] + TEXT_OFF + TEXT_SIZE)],
                                  [fx["base"] + FN_OFF], [], base=fx["base"],
                                  module=True)
    a = T.emit_c("t", blocks, [(fx["base"] + TEXT_OFF,
                                fx["base"] + TEXT_OFF + TEXT_SIZE)],
                 "00" * 32, 0, (0, 0, 0), subset_id="test",
                 abi_expr="AOT_ABI_VERSION")
    b = T.emit_c("t", blocks, [(fx["base"] + TEXT_OFF,
                                fx["base"] + TEXT_OFF + TEXT_SIZE)],
                 "00" * 32, 0, (0, 0, 0), subset_id="test",
                 abi_expr="AOT_ABI_VERSION", switch_sites=None)
    check(a == b, "an unproven BR must keep the legacy INDIRECT codegen")


def test_b2_caller_edges_are_claims_only():
    """A caller-provided edge must be a strict-shape BR source and its target
    set must equal the proof. Nothing is admitted from the caller graph."""
    fx = build()
    base = fx["base"]
    roots = {base + FN_OFF}
    br_pc = base + fx["windows"][0][0] + 20
    v, e = reach_graph(fx, roots)
    real = v[br_pc]
    # fake root: a NOP source cannot introduce the unreached window
    fx2 = build(switch_n=3, values=[0, 1, 2, 3], second=dict(
        n=4, values=[0, 1, 2, 3, 4], table_off=0x80, table_seg="ro",
        pre_window=[], win_off=TEXT_OFF + 0xA00,
        label_off=TARGETS_OFF + 0x200), extra_words=[(0x1400, NOP)])
    v2, e2 = reach_graph(fx2, roots)
    fake_src = base + 0x1400
    if fake_src not in v2:
        v2 = dict(v2)
        v2[fake_src] = dict(T.decode(fake_src,
                                     struct.unpack_from("<I", fx2["raw"],
                                                        fake_src - base)[0],
                                     module=True), word=struct.unpack_from(
                                         "<I", fx2["raw"], fake_src - base)[0])
    bad = dict(e2)
    bad[fake_src] = (base + TEXT_OFF,)
    expect("not a BR instruction",
           lambda: discover(fx2, visited=v2, roots=roots, edges=bad),
           InputError)
    # a real BR with an incomplete/wrong target set is rejected
    tg = list(real_targets(fx, v))
    v, e = reach_graph(fx, roots, indirect=tg)
    bad = dict(e)
    bad[br_pc] = tuple(tg[:-1])
    expect("disagree with the proof", lambda: discover(fx, visited=v, roots=roots,
                                                       edges=bad), InputError)
    # a BR word at a decoded-but-unreachable PC is not a shape site: the
    # claim is ignored and no ghost proof appears.
    fxx = build(extra_words=[(0x1500, 0xD61F0060)])
    ghost = base + 0x1500
    v3, e3 = reach_graph(fxx, roots)
    gw = struct.unpack_from("<I", fxx["raw"], ghost - base)[0]
    v3 = dict(v3)
    v3[ghost] = dict(T.decode(ghost, gw, module=True), word=gw)
    bad = dict(e3)
    bad[ghost] = (base + TEXT_OFF,)
    res = discover(fxx, visited=v3, roots=roots, edges=bad)
    check(ghost not in res, "an unreachable BR claim cannot be promoted")


def real_targets(fx, visited):
    return fx["targets"][0]


def test_input_errors():
    fx = build()
    expect("SHA-256", lambda: Context(fx["raw"], fx["layout"],
                                      fx["base"], T.decode), InputError) \
        if False else None
    bad = copy.deepcopy(fx["layout"])
    bad["sha256"] = "1" * 64
    expect("SHA-256", lambda: Context(fx["raw"], bad, fx["base"], T.decode),
           InputError)
    expect("aligned", lambda: Context(fx["raw"], fx["layout"],
                                      fx["base"] + 1, T.decode), InputError)
    expect("layout must be a dict",
           lambda: Context(fx["raw"], [], fx["base"], T.decode), InputError)
    roots = {fx["base"] + FN_OFF}
    v, e = reach_graph(fx, roots)
    ctx = context(fx)
    expect("root entry set is empty",
           lambda: ctx.discover(v, set(), e), InputError)
    expect("not present in the reached instruction set",
           lambda: ctx.discover(v, {fx["base"] + 0x1500}, e), InputError)
    bad_e = dict(e)
    bad_e[fx["base"] + 0x1020] = (fx["base"] + 0x1500,)
    expect("targets must all be reached instructions",
           lambda: ctx.discover(v, roots, bad_e), InputError)
    bad_e = dict(e)
    bad_e[fx["base"] + 0x1020] = (fx["base"] + 0x1018,)
    expect("not a BR instruction",
           lambda: ctx.discover(v, roots, bad_e), InputError)
    expect("not iterable",
           lambda: ctx.discover(v, 5, e), InputError)
    bad_pc = dict(v)
    bad_pc[fx["base"] + FN_OFF] = dict(v[fx["base"] + FN_OFF], pc=True)
    expect("pc must be an int",
           lambda: ctx.discover(list(bad_pc.values()), roots, e), InputError)
    expect("bytes-like", lambda: Context("raw", fx["layout"], fx["base"],
                                         T.decode), InputError)


def main():
    test_positive()
    test_alias_owner_counts_one()
    test_table_is_authority_not_observed_value()
    test_unreachable_switch_not_recovered()
    test_other_br_idiom_unhandled()
    test_mutation_after_context()
    test_negative_table_placement()
    test_negative_label_and_targets()
    test_negative_metadata_and_relocs()
    test_negative_owner_ambiguity()
    test_positive_br_backedge_preserves_base()
    test_negative_table_base()
    test_umulh_write_set()
    test_negative_guard_entry()
    test_b1_unknown_raw_incoming_branch()
    test_negative_mid_function_root()
    test_forged_or_duplicate_caller_ir()
    test_shape_register_aliases()
    test_target_into_table_pair()
    test_owner_span_ambiguity()
    test_segment_geometry_and_freeze()
    test_unsupported_consumed_tags()
    test_phase_b_module_pipeline()
    test_phase_b_interior_target_splits_blocks()
    test_g2_default_path_unchanged()
    test_b2_caller_edges_are_claims_only()
    test_c2_stage_positive_cmp_and_prewindow_entries()
    test_c2_stage_negative_dead_external_source()
    test_h1_out_of_numeric_range_guard_path()
    test_h1r_undecoded_raw_into_add_and_br()
    test_negative_loop_clobber_after_revalidation()
    test_input_errors()
    if FAILS:
        print("\n%d FAILURE(S)" % len(FAILS))
        return 2
    print("OK: g3_local_switch hermetic checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
