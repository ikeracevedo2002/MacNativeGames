#!/usr/bin/env python3
"""Hermetic synthetic tests for tools/aot/g3_ctor_roots.py (D023).

Everything is generated: tiny NSO images with a MOD0 header, a `.dynamic`
declaring DT_INIT_ARRAY/DT_INIT_ARRAYSZ, an original ELF RELA table with real
ADDENDS, a dynsym, and a handful of instructions.  No game data, no title VA,
no hash allowlist.

The fixtures cross the SAME interfaces the real driver uses:
  R.Image          (reference link: original flat + per-site relocated values)
  LS.Context       (validated metadata extents / symbols, reused read-only)
  G.derive(...)    (complete declared-table derivation)
  G.Authority(...).prove(target, fault_site, site_kind, cursor)

Every mandatory criterion has a positive case and at least one single-guard
negative case, and the negative cases are typed by `reason`, so a refusal that
fires for the wrong cause fails the test.

Exit: 0 pass, 1 failure.
"""

import hashlib
import os
import struct
import sys
import tempfile

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO, "tools", "aot"))

import aot_module as M            # noqa: E402
import aot_translate as T         # noqa: E402
import g3_ctor_roots as G         # noqa: E402
import g3_init_reach as R         # noqa: E402
import g3_local_switch as LS      # noqa: E402

BASE = 0x100000000
IMG = 0x4000
MOD0 = 0x100
DYN = 0x3F00
SYMTAB = 0x3D00
STRTAB = 0x3E00
RELA = 0x3000
JMPREL = 0x3100
HASH = 0x3C80
ARRAY_OFF = 0x3800
TEXT_OFF, TEXT_SIZE = 0x1000, 0x1000
RO_OFF, RO_SIZE = 0x2000, 0x1000
DATA_OFF, DATA_SIZE = 0x3000, 0x1000

GOT_END, GOT_START = 0x3A00, 0x3A08
DT_INIT_OFF = 0x1100
SITE_OFF = 0x1114                      # the original BLR
# ADRP x9,#page(0x3000); LDR x19,[x9,#end]; LDR x20,[x9,#start]; then
# LDR x8,[x20],#8 ; BLR x8 ; CMP x20,x19 ; B.LO back  (the real generic shape)
LOOP_WORDS = {
    DT_INIT_OFF: 0xD0000009,
    DT_INIT_OFF + 4: 0xF9400000 | ((GOT_END & 0xFFF) // 8 << 10) | (9 << 5) | 19,
    DT_INIT_OFF + 8: 0xF9400000 | ((GOT_START & 0xFFF) // 8 << 10) | (9 << 5) | 20,
    DT_INIT_OFF + 12: 0xD503201F,         # NOP (decodable straight line)
    SITE_OFF - 4: 0xF8400400 | (8 << 12) | (20 << 5) | 8,
    SITE_OFF: 0xD63F0100,
    SITE_OFF + 4: 0xEB00001F | (19 << 16) | (20 << 5),
    SITE_OFF + 8: 0x54000000 | ((-3 & 0x7FFFF) << 5) | 3,
}
STT_OBJECT = 1
NOP = 0xD503201F
RET = 0xD65F03C0
BLR_X8 = 0xD63F0100
R_REL = G.R_AARCH64_RELATIVE

FAILS = []
OKS = [0]


def fail(msg):
    FAILS.append(msg)
    print("FAIL: " + msg)


def okk(msg):
    OKS[0] += 1
    print("OK: " + msg)


# --------------------------------------------------------------- fixture flat

def build_flat(slots=None, words=None, syms=None, array_off=ARRAY_OFF,
               arraysz=None, rela_extra=(), jmprel=(), drop_slots=(),
               duplicate_slot=None, hash_buckets=(), tags_extra=(),
               tags_drop=(), raw_slot_zero=False, image_size=IMG):
    """One synthetic NSO image.  `slots` is [(addend, kind, sym), ...]."""
    slots = list([(0x1010, R_REL, 0), (0x1020, R_REL, 0)]
                 if slots is None else slots)
    syms = list(syms or [])
    buf = bytearray(image_size)
    buf[0:4] = b"NSO0"
    struct.pack_into("<I", buf, 4, MOD0)
    buf[MOD0:MOD0 + 4] = b"MOD0"
    struct.pack_into("<i", buf, MOD0 + 4, DYN - MOD0)
    struct.pack_into("<i", buf, MOD0 + 8, image_size - MOD0)   # bss_start
    struct.pack_into("<i", buf, MOD0 + 12, image_size - MOD0)  # bss_end
    struct.pack_into("<i", buf, MOD0 + 16, 0)                  # no eh_frame
    struct.pack_into("<i", buf, MOD0 + 20, 0)
    for off, word in {**LOOP_WORDS, **(words or {})}.items():
        struct.pack_into("<I", buf, off, word)
    # dynstr + dynsym
    strings = bytearray(b"\x00")
    name_off = {}
    for name, _v, _s, _t, _sh in syms:
        name_off[name] = len(strings)
        strings += name.encode() + b"\x00"
    for i, (name, value, size, typ, shndx) in enumerate(syms):
        struct.pack_into("<IBBHQQ", buf, SYMTAB + i * 24, name_off[name],
                         (1 << 4) | typ, 0, shndx, value, size)
    buf[STRTAB:STRTAB + len(strings)] = strings
    # RELA: one record per declared slot (unless dropped), plus extras.
    records = []
    for i, (addend, kind, sym) in enumerate(slots):
        where = array_off + i * 8
        if where in drop_slots:
            continue
        records.append((where, kind, sym, addend))
    if duplicate_slot is not None:
        i = duplicate_slot
        records.append((array_off + i * 8, R_REL, 0, slots[i][0]))
    asz = len(slots) * 8 if arraysz is None else arraysz
    records.append((GOT_END, R_REL, 0, array_off + asz))
    records.append((GOT_START, R_REL, 0, array_off))
    records.extend(rela_extra)
    for i, (where, kind, sym, addend) in enumerate(records):
        struct.pack_into("<QQq", buf, RELA + i * 24, where,
                         (sym << 32) | kind, addend)
    for i, (where, kind, sym, addend) in enumerate(jmprel):
        struct.pack_into("<QQq", buf, JMPREL + i * 24, where,
                         (sym << 32) | kind, addend)
    tags = [(M.DT_RELA, RELA), (M.DT_RELASZ, len(records) * 24),
            (M.DT_RELAENT, 24),
            (M.DT_SYMTAB, SYMTAB), (M.DT_SYMENT, 24),
            (M.DT_STRTAB, STRTAB), (M.DT_STRSZ, len(strings)),
            (G.DT_INIT, DT_INIT_OFF), (G.DT_INIT_ARRAY, array_off),
            (G.DT_INIT_ARRAYSZ, (len(slots) * 8 if arraysz is None
                                 else arraysz))]
    if jmprel:
        tags.append((M.DT_JMPREL, JMPREL))
        tags.append((M.DT_PLTRELSZ, len(jmprel) * 24))
        tags.append((M.DT_PLTREL, 7))
    if hash_buckets:
        nbucket, nchain = len(hash_buckets), 2
        struct.pack_into("<II", buf, HASH, nbucket, nchain)
        for i, v in enumerate(hash_buckets):
            struct.pack_into("<I", buf, HASH + 8 + 4 * i, v)
        tags.append((M.DT_HASH, HASH))
    if raw_slot_zero:
        pass
    tags = [t for t in tags if t[0] not in tags_drop]
    tags.extend(tags_extra)
    tags.append((0, 0))
    for i, (tag, value) in enumerate(tags):
        struct.pack_into("<QQ", buf, DYN + i * 16, tag, value)
    return bytes(buf)


def make(tmp, name, base, **kw):
    """Build flat + layout + R.Image + LS.Context for one synthetic module."""
    flat = build_flat(**{k: v for k, v in kw.items() if k not in (
        "text_layout", "layout_size", "sites_override")})
    text = kw.get("text_layout") or [TEXT_OFF, TEXT_SIZE]
    size = kw.get("layout_size") or IMG
    layout = {
        "sha256": hashlib.sha256(flat).hexdigest(),
        "name": name, "image_size": size, "bss_size": 0, "mod0_off": MOD0,
        "text": list(text), "ro": [RO_OFF, RO_SIZE],
        "data": [DATA_OFF, DATA_SIZE],
        "dynsym_count": max(1, len(kw.get("syms") or [])),
    }
    fp = os.path.join(tmp, name + ".flat")
    lp = os.path.join(tmp, name + ".layout.json")
    with open(fp, "wb") as f:
        f.write(flat)
    with open(lp, "w", encoding="utf-8") as f:
        f.write(__import__("json").dumps(layout))
    ctx = LS.Context(flat, layout, base, T.decode)
    # The reference link's per-site values: pass them so Image.buf really holds
    # the post-relocation bytes (a raw-zero slot simply omits its own site).
    slots = list([(0x1010, R_REL, 0), (0x1020, R_REL, 0)]
                 if kw.get("slots") is None else kw["slots"])
    array_off = kw.get("array_off", ARRAY_OFF)
    sites = {}
    if not kw.get("raw_slot_zero"):
        for i, (addend, _kind, _sym) in enumerate(slots):
            sites[array_off + i * 8] = (base + addend) & 0xFFFFFFFFFFFFFFFF
    asz = len(slots) * 8 if kw.get("arraysz") is None else kw["arraysz"]
    sites[GOT_END] = base + array_off + asz
    sites[GOT_START] = base + array_off
    sites.update(kw.get("sites_override") or {})
    image = R.Image(name, base, flat, layout, sites)
    return {"name": name, "base": base, "flat": flat, "layout": layout,
            "image": image, "ctx": ctx,
            "sha": layout["sha256"]}


def world(mods):
    return R.World([m["image"] for m in mods])


def authority(mods, **kw):
    return G.Authority.build([m["image"] for m in mods],
                             {m["name"]: m["sha"] for m in mods},
                             {m["name"]: m["ctx"] for m in mods}, **kw)


def raw_of(mods):
    return {m["name"]: (m["flat"], m["base"], (
        m["base"] + m["layout"]["text"][0],
        m["base"] + m["layout"]["text"][0] + m["layout"]["text"][1]))
        for m in mods}


def P(auth, mods, target, site=None, kind="blr", cursor="auto", raw=None):
    """Drive the REAL prove() signature with a fully populated live capture."""
    site = BASE + SITE_OFF if site is None else site
    raw = raw_of(mods) if raw is None else raw
    if cursor == "auto":
        arr = next(iter(auth.arrays.values()))
        idx = [sl.target for sl in arr.slots].index(target)
        cursor = {"reg": 20, "value": arr.array_va + 8 * (idx + 1),
                  "slot_bytes": target, "bound_reg": 19,
                  "bound_value": arr.array_end}
    return auth.prove(target, site, kind, cursor, raw)


def expect_derive_refusal(label, mods, reason, **kw):
    try:
        authority(mods, **kw)
    except G.CtorRefusal as exc:
        if exc.reason != reason:
            fail("%s: refusal %r expected %r (%s)"
                 % (label, exc.reason, reason, exc.detail))
            return
        okk("%s -> refused %s" % (label, exc.reason))
        return
    except G.CtorInputError as exc:
        fail("%s: CtorInputError %s expected refusal %r"
             % (label, exc, reason))
        return
    fail("%s: no refusal (expected %r)" % (label, reason))


def expect_input_error(label, fn, needle=None):
    try:
        fn()
    except (G.CtorInputError, LS.InputError, M.ElfError) as exc:
        if needle is not None and needle not in str(exc):
            fail("%s: %s lacks %r" % (label, exc, needle))
            return
        okk("%s -> CtorInputError" % label)
        return
    fail("%s: no CtorInputError" % label)


def expect_refuse(label, verdict, reason):
    if verdict.ok:
        fail("%s: accepted, expected refusal %r" % (label, reason))
        return
    if verdict.reason != reason:
        fail("%s: refused %r expected %r (%s)"
             % (label, verdict.reason, reason, verdict.detail))
        return
    okk("%s -> refused %s" % (label, verdict.reason))


def expect_accept(label, verdict):
    if not verdict.ok:
        fail("%s: refused %r (%s)" % (label, verdict.reason, verdict.detail))
        return False
    okk("%s -> %s" % (label, verdict.label))
    return True


# ---------------------------------------------------------------------- tests

def main():
    tmp = tempfile.mkdtemp(prefix="g3ctor_")
    try:
        run(tmp)
    finally:
        import shutil
        shutil.rmtree(tmp)
    if FAILS:
        print("FAIL: %d ctor-root check(s)" % len(FAILS))
        return 1
    print("PASS: g3_ctor_roots (%d checks)" % OKS[0])
    return 0


def run(tmp):
    TARGET_A = BASE + 0x1010
    TARGET_B = BASE + 0x1020

    # ---- 1. positive: valid stripped constructor (no dynsym for it) -------
    mod = make(tmp, "main", BASE)
    auth = authority(mods := [mod])
    verdict = P(auth, [mod], TARGET_A)
    if expect_accept("valid stripped constructor", verdict):
        ev = verdict.evidence
        if ev["index"] != 0 or ev["module"] != "main":
            fail("positive evidence slot/module %r" % ev)
        else:
            okk("positive evidence names slot 0 of main")
        if ev["array"]["slots"] != 2:
            fail("positive evidence should cite the complete 2-slot table")
        else:
            okk("positive evidence cites the complete declared table")
        if ev["flat_sha256"] != mod["sha"]:
            fail("evidence flat SHA is not the pinned module SHA")
        else:
            okk("evidence binds the pinned flat SHA")
        if not (len(ev["array"]["table_sha256"]) == 64):
            fail("table digest is not a hex SHA-256")
    expect_accept("second slot / end-bound cursor (last slot)",
                  P(auth, [mod], TARGET_B))
    expect_refuse("BR fault site kind is not the proven BLR loop", P(
        auth, [mod], TARGET_A, kind="br"), "fault-site-not-blr")

    # ---- 2. complete declared table, not the layout field ----------------
    forged = make(tmp, "main2", BASE)
    forged["layout"] = dict(forged["layout"])
    forged["layout"]["dt_init_array"] = 0x1010       # a forged LAYOUT field
    forged["layout"]["dt_init_arraysz"] = 0xDEAD
    auth = authority([forged])
    if auth.counts() != {"main2": 2}:
        fail("forged layout dt_init_array/arraysz influenced derivation: %r"
             % auth.counts())
    else:
        okk("forged layout field is ignored (declaration read from .dynamic)")

    # ---- 3. every slot must be a RELATIVE, sym-0 record ------------------
    expect_derive_refusal("slot relocation kind 257", [make(
        tmp, "m", BASE, slots=[(0x1010, 257, 0)])],
        "slot-relocation-not-relative")
    expect_derive_refusal("slot relocation symbolic", [make(
        tmp, "m", BASE, slots=[(0x1010, R_REL, 0),
                               (0x1020, R_REL, 1)])],
        "slot-relocation-symbolic")
    expect_derive_refusal(
        "slot relocation missing (incomplete table)", [make(
            tmp, "m", BASE, drop_slots={ARRAY_OFF + 8})],
        "slot-relocation-missing")
    expect_derive_refusal("slot relocation duplicate", [make(
        tmp, "m", BASE, duplicate_slot=1)], "slot-relocation-duplicate")
    # An unaligned RELA site cannot survive the metadata context, so
    # `slot-relocation-extra` stays a DEFENSIVE check in the policy (the
    # upstream guard fires first).  Both are pinned here.
    expect_input_error(
        "unaligned RELA site refused by the metadata context",
        lambda: make(tmp, "m", BASE,
                     rela_extra=[(ARRAY_OFF + 4, R_REL, 0, 0x1010)]))
    # a symbolic JMPREL record in the span is equally fatal
    expect_derive_refusal(
        "JMPREL record inside the array span", [make(
            tmp, "m", BASE, jmprel=[(ARRAY_OFF + 8, 1026, 1, 0)],
            drop_slots={ARRAY_OFF + 8})], "slot-relocation-not-rela")

    # ---- 4. declared-range / metadata sanity ----------------------------
    expect_derive_refusal("array size not a slot multiple", [make(
        tmp, "m", BASE, arraysz=12)], "array-size-not-slot-multiple")
    expect_derive_refusal("empty array", [make(
        tmp, "m", BASE, arraysz=0)], "array-empty")
    big = 0x3800 + G.MAX_ARRAY_BYTES + 0x4000
    expect_derive_refusal("array too large for the bounded complete scan", [make(
        tmp, "m", BASE, arraysz=G.MAX_ARRAY_BYTES + 8,
        image_size=big, layout_size=big)], "array-too-large")
    expect_derive_refusal(
        "array declared inside TEXT (forged .dynamic)", [make(
            tmp, "m", BASE, array_off=0x1100)], "array-outside-data-segment")
    expect_input_error(
        "array misaligned (refused by the metadata context first)",
        lambda: make(tmp, "m", BASE, array_off=ARRAY_OFF + 4), "8-byte")
    expect_derive_refusal(
        "array overlaps loader-consumed metadata", [make(
            tmp, "m", BASE, array_off=DYN - 8, words={})],
        "array-overlaps-metadata:.dynamic")
    expect_input_error(
        "unpaired init-array tags (refused by the metadata context first)",
        lambda: make(tmp, "m", BASE, tags_drop=(G.DT_INIT_ARRAYSZ,)),
        "unpaired")
    # no declaration at all is NOT an error: the module simply has no array
    silent = make(tmp, "m", BASE, tags_drop=(G.DT_INIT_ARRAY,
                                             G.DT_INIT_ARRAYSZ))
    if G.derive(silent["image"], silent["sha"], silent["ctx"]) is not None:
        fail("a module without DT_INIT_ARRAY produced an array")
    else:
        okk("absent DT_INIT_ARRAY pair derives nothing (no implicit array)")

    # ---- 5. per-target exclusions ---------------------------------------
    expect_derive_refusal("null constructor slot", [make(
        tmp, "m", BASE, slots=[(0, R_REL, 0)])], "slot-null-target")
    expect_derive_refusal(
        "sentinel constructor slot", [make(
            tmp, "m", BASE, slots=[(0x1000, R_REL, 0)])],
        "slot-sentinel-target", sentinel=BASE + 0x1000)
    expect_derive_refusal("misaligned constructor target", [make(
        tmp, "m", BASE, slots=[(0x1002, R_REL, 0)])],
        "slot-target-misaligned")
    expect_derive_refusal("target outside owner TEXT (non-exec RO)", [make(
        tmp, "m", BASE, slots=[(RO_OFF + 0x40, R_REL, 0)])],
        "slot-target-not-same-module-text")
    expect_derive_refusal("target inside the array itself", [make(
        tmp, "m", BASE, slots=[(ARRAY_OFF + 8, R_REL, 0)])],
        "slot-target-not-same-module-text")
    expect_derive_refusal(
        "target truncated at the TEXT end", [make(
            tmp, "m", BASE, slots=[(TEXT_OFF + TEXT_SIZE, R_REL, 0)])],
        "slot-target-not-same-module-text")
    # cross-module: a second module's TEXT is a valid code VA, not this module
    a = make(tmp, "mainA", BASE, slots=[(0x1010, R_REL, 0)])
    other_base = BASE + 0x10000
    b = make(tmp, "mainB", other_base)
    cross = make(tmp, "mainC", BASE,
                 slots=[(0x1010, R_REL, 0),
                        (other_base + 0x1010 - BASE, R_REL, 0)])
    expect_derive_refusal("cross-module constructor target", [cross, b],
                          "slot-target-not-same-module-text")
    if authority([a]).counts() != {"mainA": 1}:
        fail("cross-module control module did not derive 1 slot")
    else:
        okk("cross-module control module still derives its own slot")

    # known DATA / storage symbols inside TEXT
    obj = (("stored_table", 0x1040, 0x20, STT_OBJECT, 1),
           ("zero_obj", 0x1080, 0, STT_OBJECT, 1))
    expect_derive_refusal(
        "target inside a known OBJECT's storage", [make(
            tmp, "m", BASE, syms=[obj[0]], slots=[(0x1050, R_REL, 0)])],
        "target-in-storage-symbol")
    expect_derive_refusal(
        "target AT a zero-sized OBJECT point", [make(
            tmp, "m", BASE, syms=[obj[1]], slots=[(0x1080, R_REL, 0)])],
        "target-at-storage-point")
    # ... but a DEFINED STT_FUNC containing the target is NOT a refusal
    fn = (("named_ctor", 0x1000, 0x80, M.STT_FUNC, 1),)
    fm = make(tmp, "m", BASE, syms=list(fn), slots=[(0x1010, R_REL, 0)])
    verdict = P(authority([fm]), [fm], TARGET_A)
    expect_accept("valid constructor that IS a defined STT_FUNC (stripped "
                  "and named both admitted)", verdict)

    # ---- 6. post-relocation value cross-check ---------------------------
    expect_derive_refusal("raw-zero slot (no link value applied)", [make(
        tmp, "m", BASE, raw_slot_zero=True)], "slot-value-mismatch")
    expect_derive_refusal(
        "link site dump disagrees with RELA addend", [make(
            tmp, "m", BASE, sites_override={ARRAY_OFF: BASE + 0x1030})],
        "slot-value-mismatch")
    expect_input_error("stale flat SHA pin", lambda: G.derive(
        make(tmp, "m", BASE)["image"], "0" * 64, make(tmp, "m2", BASE)["ctx"]),
        "stale pin")

    # ---- 7. authority-level refusals ------------------------------------
    auth = authority([mod])
    ms = [mod]
    arr = auth.arrays["main"]
    expect_refuse("arbitrary BLR target not in the array",
                  auth.prove(BASE + 0x1030, BASE + SITE_OFF, "blr",
                             {"reg": 20, "value": arr.array_va + 8,
                              "slot_bytes": BASE + 0x1030, "bound_reg": 19,
                              "bound_value": arr.array_end}, raw_of(ms)),
                  "not-in-init-array")
    expect_refuse("ANY non-loop BLR to a valid constructor is refused",
                  P(auth, ms, TARGET_A, site=BASE + 0x1200),
                  "fault-site-not-array-walk")
    expect_refuse("RET fault site kind", P(auth, ms, TARGET_A, kind="ret"),
                  "fault-site-not-blr")
    expect_refuse("fault site outside the owner TEXT",
                  P(auth, ms, TARGET_A, site=BASE + RO_OFF),
                  "fault-site-not-array-walk")
    expect_refuse("misaligned fault site",
                  P(auth, ms, TARGET_A, site=BASE + SITE_OFF + 2),
                  "fault-site-not-array-walk")
    nn = BASE + 0x1050
    nn_auth = authority([make(tmp, "m", BASE, slots=[(0x1050, R_REL, 0)])],
                        nnmain_va=nn)
    expect_refuse("constructor target that is nnMain (pre-G4 guard)",
                  nn_auth.prove(nn, BASE + SITE_OFF, "blr", {}, {}),
                  "target-is-nnmain")
    expect_refuse("non-address target",
                  auth.prove(None, BASE + SITE_OFF, "blr", {}, {}),
                  "target-not-an-address")
    expect_refuse("no raw bytes supplied -> not a proven site",
                  auth.prove(TARGET_A, BASE + SITE_OFF, "blr", {}, None),
                  "fault-site-not-array-walk")
    zeros = {"main": (bytes(len(mod["flat"])), BASE,
                      (BASE + 0x1000, BASE + 0x2000))}
    expect_refuse("raw bytes that are zeros (unbound flat)",
                  P(auth, ms, TARGET_A, raw=zeros),
                  "live-bytes-not-pinned")
    tampered = bytearray(mod["flat"])
    struct.pack_into("<I", tampered, 0x1F00, NOP)       # same loop, other byte
    expect_refuse("loop intact but flat SHA differs from the pin",
                  P(auth, ms, TARGET_A, raw={"main": (
                      bytes(tampered), BASE, (BASE + 0x1000, BASE + 0x2000))}),
                  "live-bytes-not-pinned")
    for label, words, reason in (
            ("LDR is pre-index not post-index",
             {SITE_OFF - 4: 0xF8400C00 | (8 << 12) | (20 << 5) | 8},
             "fault-site-not-array-walk"),
            ("CMP does not use the cursor",
             {SITE_OFF + 4: 0xEB00001F | (19 << 16) | (21 << 5)},
             "fault-site-not-array-walk"),
            ("loop branch is unconditional",
             {SITE_OFF + 8: 0x17FFFFFD}, "fault-site-not-array-walk")):
        m = make(tmp, "mv", BASE, words=words)
        expect_refuse(label, P(authority([m]), [m], TARGET_A), reason)
    m = make(tmp, "mg", BASE, words={DT_INIT_OFF + 4: NOP})
    expect_refuse("DT_INIT never loads the GOT end bound", P(
        authority([m]), [m], TARGET_A), "dt-init-bound-not-got-end")
    m = make(tmp, "mg2", BASE, words={DT_INIT_OFF + 8: NOP})
    expect_refuse("DT_INIT never loads the GOT start bound", P(
        authority([m]), [m], TARGET_A), "dt-init-cursor-not-got-start")
    m = make(tmp, "mg3", BASE, tags_drop=(G.DT_INIT,))
    expect_refuse("module has no DT_INIT root", P(
        authority([m]), [m], TARGET_A), "loop-not-reached-from-dt-init")

    # ---- 8. mandatory live cursor capture -------------------------------
    good = {"reg": 20, "value": arr.array_va + 8, "slot_bytes": TARGET_A,
            "bound_reg": 19, "bound_value": arr.array_end}
    for label, over, reason in (
            ("missing cursor record", None, "cursor-not-observed"),
            ("cursor register not the proven one", {"reg": 3},
             "cursor-register-not-proven"),
            ("bound register not the proven one", {"bound_reg": 3},
             "cursor-bound-register-not-proven"),
            ("cursor at a different slot", {"value": arr.array_va + 16},
             "cursor-slot-mismatch"),
            ("cursor before the array", {"value": arr.array_va},
             "cursor-outside-array"),
            ("cursor past the end", {"value": arr.array_end + 16},
             "cursor-beyond-array-end"),
            ("live slot bytes differ", {"slot_bytes": TARGET_B},
             "cursor-slot-bytes-mismatch"),
            ("bound value is not array_end", {"bound_value": 0x1234},
             "cursor-bound-mismatch"),
            ("cursor field missing", {"slot_bytes": None},
             "cursor-field-missing"),
            ("misaligned cursor", {"value": arr.array_va + 12},
             "cursor-outside-array")):
        cur = None if over is None else dict(good, **over)
        expect_refuse(label, P(auth, ms, TARGET_A, cursor=cur), reason)
    expect_accept("good capture (post-index slot+8)",
                  P(auth, ms, TARGET_A, cursor=good))

    # ---- 9. DT_HASH buckets are consumed metadata (narrow context fix) --
    hashed = make(tmp, "m", BASE, hash_buckets=(0xAABBCCDD, 0x11223344))
    ext = {label: (lo, hi) for label, lo, hi in hashed["ctx"]
           .metadata_extents()}
    if ".hash" not in ext:
        fail("DT_HASH extent missing from Context.metadata_extents()")
    else:
        lo, hi = ext[".hash"]
        want = HASH + 8 + 4 * (2 + 2)      # nbucket + nchain arrays
        if (lo, hi) != (HASH, want):
            fail("DT_HASH extent is [0x%x,0x%x), expected [0x%x,0x%x) "
                 "(buckets must be covered)" % (lo, hi, HASH, want))
        else:
            okk("DT_HASH extent covers nbucket+nchain (%d words)" % (4,))
    # a constructor cannot point at a bucket word even if it were in TEXT:
    # prove the exclusion directly at the unit level.
    bad = G._target_refusal(BASE + HASH + 8, hashed["ctx"], MOD0)
    if bad is None or not bad[0].startswith("target-in-metadata:.hash"):
        fail("target inside DT_HASH buckets was not refused: %r" % (bad,))
    else:
        okk("target inside DT_HASH buckets -> %s" % bad[0])
    bad = G._target_refusal(BASE + MOD0, hashed["ctx"], MOD0)
    if bad is None or bad[0] != "target-in-image-header":
        fail("target inside the MOD0 header was not refused: %r" % (bad,))
    else:
        okk("target inside the MOD0 header -> %s" % bad[0])
    zero = G._target_refusal(BASE + 0x1080, make(
        tmp, "mz", BASE, syms=[("zero_obj", 0x1080, 0, STT_OBJECT, 1)])
        ["ctx"], MOD0)
    if zero is None or zero[0] != "target-at-storage-point":
        fail("zero-sized OBJECT point was not refused: %r" % (zero,))
    else:
        okk("zero-sized OBJECT point -> %s" % zero[0])

    # ---- 10. binding + enumeration are audit-only -----------------------
    verdict = P(auth, ms, TARGET_A)
    audit = {"evidence": verdict.evidence}
    GM = {"source_sha256": mod["sha"], "guest_base": "0x%x" % BASE,
          "entries": ["0x%x" % TARGET_A]}
    metas = {"main": dict(GM)}
    if G.bind_flat_sha(auth, metas, [audit]):
        okk("owner flat SHA binds to compiled metadata via the authority")
    expect_input_error("binding refuses a mismatching flat SHA", lambda:
                       G.bind_flat_sha(auth, {"main": {
                           **GM, "source_sha256": "d" * 64}}, [audit]))
    expect_input_error("binding refuses missing metadata", lambda:
                       G.bind_flat_sha(auth, {}, [audit]))
    expect_input_error("binding refuses missing source_sha256", lambda:
                       G.bind_flat_sha(auth, {"main": {}}, [audit]))
    expect_input_error("binding refuses a non-Authority", lambda:
                       G.bind_flat_sha(None, metas, [audit]))
    expect_input_error("binding refuses an audit without evidence", lambda:
                       G.bind_flat_sha(auth, metas, [{}]))
    expect_input_error("binding refuses a missing evidence key (typed)",
                       lambda: G.bind_flat_sha(auth, metas, [{"evidence": {
                           "module": "main"}}]), "lacks")
    import copy
    for label, path, value in (
            ("forged table digest", ("array", "table_sha256"), "e" * 64),
            ("forged flat SHA", ("flat_sha256",), "f" * 64),
            ("forged slot index", ("index",), 1),
            ("forged slot VA", ("slot",), "0x1"),
            ("forged target", ("target",), "0x1"),
            ("unknown module", ("module",), "ghost")):
        forged = copy.deepcopy(audit)
        tgt = forged["evidence"]
        for key in path[:-1]:
            tgt = tgt[key]
        tgt[path[-1]] = value
        expect_input_error("binding refuses " + label, lambda f=forged:
                           G.bind_flat_sha(auth, metas, [f]))
    for label, bad in (
            ("wrong guest_base", dict(GM, guest_base="0x200000000")),
            ("non-numeric guest_base", dict(GM, guest_base="nope")),
            ("missing entries", {k: v for k, v in GM.items()
                                 if k != "entries"}),
            ("root not seeded in entries", dict(GM, entries=["0x1"])),
            ("malformed entries", dict(GM, entries=["zz"]))):
        expect_input_error("binding refuses " + label, lambda b=bad:
                           G.bind_flat_sha(auth, {"main": b}, [audit]))
    # a ctor_arrays metadata entry is NOT an optional bypass any more
    okk("ctor_arrays presence does not weaken the exact source SHA check") \
        if G.bind_flat_sha(auth, {"main": {**GM,
                                           "ctor_arrays": {"main": "e" * 64}}},
                           [audit]) else None
    remap = G.bind_flat_sha(auth, {"main_real": dict(GM)},
                            [audit], {"main": "main_real"})
    okk("binding maps the proof module to the runtime metadata name") \
        if remap else fail("meta_name mapping")
    mut = authority([make(tmp, "bm", BASE)])
    mut_a = {"evidence": P(mut, [make(tmp, "bm", BASE)], TARGET_A).evidence}
    object.__setattr__(mut.arrays["bm"], "array_size", 8)
    expect_input_error("binding refuses a mutated authority", lambda:
                       G.bind_flat_sha(mut, {"bm": dict(GM)}, [mut_a]))
    # enumeration reports the finite set; it never seeds anything by itself
    if auth.targets() != [TARGET_A, TARGET_B]:
        fail("targets() enumeration is %r" % (auth.targets(),))
    else:
        okk("targets() enumerates the eligible set (AUDIT only)")

    # ---- 11. no eager roots: prove() is per-target ----------------------
    only = P(auth, ms, TARGET_A)
    if not only.ok or only.evidence["index"] != 0:
        fail("per-target admission did not name one slot")
    else:
        okk("admitting one target names exactly one slot (no eager table)")

    # ---- 12. driver seam: class sites are final, non-class sites unchanged
    import g3_start_prefix as SP
    nonce = []

    def old(va):
        nonce.append(va)
        return ("FUNC", "named", 1, 4)
    ok_v = P(auth, ms, TARGET_A)
    d = SP.select_follow(TARGET_A, None, old, "blr", lambda: None,
                         lambda t: ok_v)
    if d["kind"] != "ctor" or nonce or d["label"] != "ctor:main#0":
        fail("class site must be admitted by D023 only: %r" % d)
    else:
        okk("class site -> ctor decision, old/veneer rules not consulted")
    bad_v = P(auth, ms, TARGET_A, cursor=None)
    d = SP.select_follow(TARGET_A, None, old, "blr", lambda: None,
                         lambda t: bad_v)
    if d["kind"] != "refused" or nonce:
        fail("class refusal must be final (no old/D021 fallback): %r" % d)
    else:
        okk("class refusal is final (no old STT_FUNC / D021 fallback)")
    d = SP.select_follow(TARGET_A, None, old, "blr", lambda: None,
                         lambda t: None)
    if d["kind"] != "old" or not nonce:
        fail("non-class site must keep the old rule: %r" % d)
    else:
        okk("non-class site keeps the original old STT_FUNC rule")
    d = SP.select_follow(TARGET_A, TARGET_A, old, "blr", lambda: None,
                         lambda t: ok_v)
    if d["kind"] != "pre_g4_boundary":
        fail("nnMain filter must run first: %r" % d)
    else:
        okk("pre-G4 nnMain filter runs before D023")
    rows = "".join(
        "STARTFAULTGPR code=10 reg=%d value=0x%x read_va=0x%x "
        "read_status=0 live=0x%x\n" % (r, 0x100 + 8 * r, 0xF8 + 8 * r, r)
        for r in range(31))
    g = SP.parse_gprs(rows, {"code": 10})
    if g is None or len(g) != 31 or g[3]["live"] != 3:
        fail("parse_gprs good capture")
    else:
        okk("parse_gprs accepts the strict 31-GPR capture")
    for label, text in (("30 lines", "".join(rows.splitlines(True)[:30])),
                        ("dup reg", rows + rows.splitlines(True)[0]),
                        ("bad read_va", rows.replace("read_va=0xf8",
                                                    "read_va=0xf0", 1))):
        try:
            SP.parse_gprs(text, {"code": 10})
            fail("parse_gprs accepted %s" % label)
        except SP.DriverError:
            okk("parse_gprs refuses %s" % label)


    # ---- 13. loop_site_proof single-fault shapes (exact reasons) ---------
    base_flat = make(tmp, "lp", BASE)["flat"]
    text = (BASE + 0x1000, BASE + 0x2000)
    proof, why = G.loop_site_proof(base_flat, BASE, text, BASE + SITE_OFF)
    if proof is None or proof["slot_reg"] != 8 or proof["cursor_reg"] != 20             or proof["bound_reg"] != 19:
        fail("BLR x8 (0xd63f0100) must decode slot_reg 8: %r %r" % (proof, why))
    else:
        okk("real BLR x8 word decodes Rn from bits 9:5 (slot_reg 8)")
    for label, words, reason in (
            ("B.LT is not the first profile",
             {SITE_OFF + 8: 0x54000000 | ((-3 & 0x7FFFF) << 5) | 0xB},
             "loop-branch-not-unsigned-lower"),
            ("B.LO to the wrong target",
             {SITE_OFF + 8: 0x54000000 | ((-4 & 0x7FFFF) << 5) | 3},
             "loop-branch-target-not-the-load"),
            ("B.LO forward",
             {SITE_OFF + 8: 0x54000000 | (3 << 5) | 3},
             "loop-branch-target-not-the-load"),
            ("BLR xzr-style register 31",
             {SITE_OFF: 0xD63F03E0}, "blr-register-is-xzr"),
            ("LDR/BLR register differ",
             {SITE_OFF: 0xD63F0120}, "loop-load-register-not-blr-source"),
            ("cursor register == load target (unpredictable)",
             {SITE_OFF - 4: 0xF8400400 | (8 << 12) | (20 << 5) | 20,
              SITE_OFF: 0xD63F0280}, "loop-cursor-overlaps-load-target"),
            ("bound register == load target",
             {SITE_OFF + 4: 0xEB00001F | (8 << 16) | (20 << 5)},
             "cmp-bound-register-invalid")):
        fl = bytearray(base_flat)
        for off, word in words.items():
            struct.pack_into("<I", fl, off, word)
        _p, got = G.loop_site_proof(bytes(fl), BASE, text, BASE + SITE_OFF)
        if _p is not None or got != reason:
            fail("%s: got %r expected %r" % (label, got, reason))
        else:
            okk("%s -> %s" % (label, got))


    # ---- 14. DT_INIT-local CFG reachability + GOT provenance -------------
    LDR_X19 = LOOP_WORDS[DT_INIT_OFF + 4]
    LDR_X20 = LOOP_WORDS[DT_INIT_OFF + 8]

    def variant(label, name, reason, words=None, **kw):
        m = make(tmp, name, BASE, words=words, **kw)
        a = authority([m])
        v = P(a, [m], TARGET_A, site=BASE + (kw.pop("site_off", SITE_OFF)))
        if reason is None:
            expect_accept(label, v)
        else:
            expect_refuse(label, v, reason)

    variant("BL falls through (callee never entered, x19/x20 kept)", "c1",
            None, words={DT_INIT_OFF + 12: 0x94000040})
    variant("BLR clobber of caller-saved only keeps callee-saved bounds", "c1b",
            None, words={DT_INIT_OFF + 12: 0xD63F0120})
    variant("path jumps into the middle of the loop body", "c2",
            "loop-entered-mid-body", words={DT_INIT_OFF + 12: 0x34000040})
    variant("a branch path skips the GOT loads (join loses the bounds)",
            "c3", "dt-init-bound-not-got-end",
            words={DT_INIT_OFF + 4: 0x34000060, DT_INIT_OFF + 8: LDR_X19,
                   DT_INIT_OFF + 12: LDR_X20})
    variant("unmodelled write to x19 between load and loop kills it", "c4",
            "dt-init-bound-not-got-end", words={DT_INIT_OFF + 12: 0x91000273})
    m = make(tmp, "c5", BASE, words={
        DT_INIT_OFF + 12: RET,
        0x1310: LOOP_WORDS[SITE_OFF - 4], 0x1314: 0xD63F0100,
        0x1318: LOOP_WORDS[SITE_OFF + 4],
        0x131C: 0x54000000 | ((-3 & 0x7FFFF) << 5) | 3})
    expect_refuse("loop copy elsewhere in TEXT not reachable from DT_INIT",
                  P(authority([m]), [m], TARGET_A, site=BASE + 0x1314),
                  "loop-not-reached-from-dt-init")
    m = make(tmp, "c6", BASE,
             words={DT_INIT_OFF + 4: 0xF9400000 | (0xA10 // 8 << 10)
                    | (9 << 5) | 19},
             rela_extra=[(0x3A10, R_REL, 0, 0x2000)])
    expect_refuse("loop loads a different GOT word than the bounds",
                  P(authority([m]), [m], TARGET_A),
                  "dt-init-bound-not-got-end")
    expect_derive_refusal("duplicate RELA for a bound site", [make(
        tmp, "m", BASE, rela_extra=[(GOT_END, R_REL, 0, ARRAY_OFF + 16)])],
        "array-bounds-not-corroborated")

    # duplicate constructor values: the CURSOR INDEX picks the slot
    dm = make(tmp, "dup", BASE, slots=[(0x1010, R_REL, 0),
                                       (0x1010, R_REL, 0)])
    da = authority([dm])
    darr = da.arrays["dup"]
    ev = P(da, [dm], TARGET_A, cursor={
        "reg": 20, "value": darr.array_va + 16, "slot_bytes": TARGET_A,
        "bound_reg": 19, "bound_value": darr.array_end})
    if expect_accept("duplicate ctor value, cursor at slot 1", ev):
        if ev.evidence["index"] != 1 or ev.label != "ctor:dup#1" or                 ev.evidence["slot"] != "0x%x" % (darr.array_va + 8):
            fail("evidence names the first duplicate, not the cursor slot: %r"
                 % (ev.evidence["index"],))
        else:
            okk("evidence index follows the cursor (slot 1), not hits[0]")

    # full layout identity: a context from different geometry is refused
    lm = make(tmp, "lay", BASE)
    other = dict(lm["layout"])
    other["mod0_off_shadow"] = 4
    try:
        octx = LS.Context(lm["flat"], other, BASE, T.decode)
    except Exception as exc:                       # noqa: BLE001
        octx = None
        okk("context with altered layout is refused upstream (%s)"
            % type(exc).__name__)
    if octx is not None:
        expect_input_error("context layout != image layout (full digest)",
                           lambda: G.derive(lm["image"], lm["sha"], octx),
                           "context layout")

    # mutation: frozen attributes, read-only containers, digest backstop
    fm = make(tmp, "frz", BASE)
    fa = authority([fm])
    farr = fa.arrays["frz"]
    for label, fn in (
            ("array attribute rebind", lambda: setattr(farr, "array_va", 1)),
            ("slot attribute rebind", lambda: setattr(farr.slots[0],
                                                     "target", 1)),
            ("authority attribute rebind", lambda: setattr(fa, "arrays", {})),
            ("arrays mapping item set", lambda: fa.arrays.__setitem__("x", 1)),
            ("bounds mapping item set", lambda: farr.bounds.__setitem__(
                "end_sites", ())),
            ("slots tuple item set", lambda: farr.slots.__setitem__(0, 1))):
        try:
            fn()
            fail("%s succeeded on a frozen object" % label)
        except (AttributeError, TypeError):
            okk("%s is refused" % label)
    object.__setattr__(farr, "array_size", farr.array_size + 8)
    expect_refuse("bypass mutation of the pinned array fails closed",
                  P(fa, [fm], TARGET_A), "authority-mutated")


    # ---- 15. second-round review items ------------------------------------
    # C1: storage symbols are compared in IMAGE OFFSETS at a NONZERO base.
    so = make(tmp, "so", BASE + 0x40000,
              syms=[("tbl", 0x1040, 0x20, STT_OBJECT, 1)],
              slots=[(0x1050, R_REL, 0)])
    expect_derive_refusal("storage symbol exclusion at a nonzero base", [so],
                          "target-in-storage-symbol")
    # C2: raw MOD0 pointer / layout / magic / tags / DT_HASH identity
    lm2 = make(tmp, "mh", BASE)
    badlay = dict(lm2["layout"])
    badlay["mod0_off"] = MOD0 + 0x10
    try:
        bl_ctx = LS.Context(lm2["flat"], badlay, BASE, T.decode)
    except Exception:                                  # noqa: BLE001
        bl_ctx = None
        okk("layout mod0_off != raw MOD0 pointer refused upstream")
    if bl_ctx is not None:
        expect_input_error("layout mod0_off != raw MOD0 pointer", lambda:
                           G.derive(R.Image("mh", BASE, lm2["flat"], badlay,
                                            lm2["image"].sites),
                                    lm2["sha"], bl_ctx), "mod0_off")
    nomagic = bytearray(lm2["flat"])
    nomagic[MOD0:MOD0 + 4] = b"XXXX"
    nm_flat = bytes(nomagic)
    nm_layout = dict(lm2["layout"], sha256=hashlib.sha256(nm_flat).hexdigest())
    try:
        nm_ctx = LS.Context(nm_flat, nm_layout, BASE, T.decode)
    except Exception:                                  # noqa: BLE001
        nm_ctx = None
        okk("a missing MOD0 magic is refused upstream by the context")
    if nm_ctx is not None:
        expect_input_error("missing MOD0 magic", lambda: G.derive(
            R.Image("nm", BASE, nm_flat, nm_layout, {}),
            nm_layout["sha256"], nm_ctx), "MOD0")
    hm = make(tmp, "hm", BASE, hash_buckets=(1, 2))
    hl = dict(hm["layout"], dynsym_count=7)
    try:
        h_ctx = LS.Context(hm["flat"], hl, BASE, T.decode)
    except Exception:                                  # noqa: BLE001
        h_ctx = None
        okk("DT_HASH nchain != dynsym_count refused upstream by the context")
    if h_ctx is not None:
        expect_input_error("DT_HASH nchain != dynsym_count", lambda: G.derive(
            R.Image("hm", BASE, hm["flat"], hl, hm["image"].sites),
            hm["sha"], h_ctx), "nchain")
    # C5: the exclusion index is built once and answers like the old scans
    ix = G.build_exclusions(so["ctx"], MOD0)
    if G._target_refusal(BASE + 0x40000 + 0x1044, so["ctx"], MOD0,
                         ix) is None:
        fail("indexed exclusion missed a storage symbol")
    else:
        okk("indexed exclusion hits a storage symbol (nonzero base)")
    if G._target_refusal(BASE + 0x40000 + 0x1100, so["ctx"], MOD0,
                         ix) is not None:
        fail("indexed exclusion false positive")
    else:
        okk("indexed exclusion has no false positive on plain code")
    import time
    t0 = time.time()
    for i in range(20000):
        G._target_refusal(BASE + 0x40000 + 0x1100 + 4 * (i % 64), so["ctx"],
                          MOD0, ix)
    if time.time() - t0 > 3.0:
        fail("indexed exclusion is too slow: %.1fs" % (time.time() - t0))
    else:
        okk("20000 indexed target queries run in %.2fs" % (time.time() - t0))
    # N3: bound sites carry complete checks (link dump agrees with the RELA)
    expect_derive_refusal(
        "bound GOT word disagrees with the link site dump", [make(
            tmp, "m", BASE, sites_override={GOT_END: BASE + 0x1234})],
        "array-bounds-not-corroborated")
    # N4: typed errors for malformed inputs instead of KeyError
    expect_input_error("missing pinned SHA is typed", lambda:
                       G.Authority.build([mod["image"]], {}, {}))
    expect_input_error("missing context is typed", lambda:
                       G.Authority.build([mod["image"]],
                                         {"main": mod["sha"]}, {}))
    expect_refuse("cursor record missing keys is typed (no KeyError)",
                  P(auth, ms, TARGET_A, cursor={"reg": 20}),
                  "cursor-field-missing")
    expect_refuse("malformed raw record is typed (no unpack error)",
                  auth.prove(TARGET_A, BASE + SITE_OFF, "blr",
                             {"reg": 20}, {"main": (1, 2)}),
                  "live-bytes-not-pinned")


    # ---- 16. control-flow reach (not a linear interval) -------------------
    LDR_X19 = LOOP_WORDS[DT_INIT_OFF + 4]
    LDR_X20 = LOOP_WORDS[DT_INIT_OFF + 8]
    m = make(tmp, "d1", BASE, words={
        DT_INIT_OFF: 0x14000004,            # B +16 -> the loop LDR directly
        DT_INIT_OFF + 4: 0xD0000009,        # dead ADRP + fake GOT loads
        DT_INIT_OFF + 8: LDR_X19, DT_INIT_OFF + 12: LDR_X20})
    expect_refuse("B over dead fake GOT loads into the loop",
                  P(authority([m]), [m], TARGET_A),
                  "dt-init-bound-not-got-end")
    m = make(tmp, "d2", BASE, words={DT_INIT_OFF + 12: 0x00000000})
    expect_refuse("undecodable word on the DT_INIT path is typed",
                  P(authority([m]), [m], TARGET_A), "dt-init-undecodable")
    m = make(tmp, "d3", BASE, words={
        DT_INIT_OFF + 8: 0xF9400000 | ((0xA10 // 8) << 10) | (9 << 5) | 20},
        rela_extra=[(0x3A10, R_REL, 0, ARRAY_OFF)],
        sites_override={0x3A10: BASE + ARRAY_OFF})
    d3 = authority([m])
    if len(d3.arrays["d3"].bounds["start_sites"]) != 2:
        fail("expected two validated start bound sites: %r"
             % (d3.arrays["d3"].bounds["start_sites"],))
    v3 = P(d3, [m], TARGET_A)
    if expect_accept("two start GOT sites: loop loads the SECOND", v3):
        if v3.evidence["dt_init_cfg"]["start_slot"] != "0x3a10":
            fail("pinned start slot is %r" % (v3.evidence["dt_init_cfg"],))
        else:
            okk("the actually loaded start GOT word is pinned in the evidence")
    m = make(tmp, "d4", BASE, words={
        DT_INIT_OFF + 8: 0xF9400000 | ((0xA18 // 8) << 10) | (9 << 5) | 20},
        rela_extra=[(0x3A18, R_REL, 0, 0x2000)],
        sites_override={0x3A18: BASE + 0x2000})
    expect_refuse("loop loads a RELA word that is not a validated bound",
                  P(authority([m]), [m], TARGET_A),
                  "dt-init-cursor-not-got-start")
    ev16 = P(auth, ms, TARGET_A).evidence["dt_init_cfg"]
    if ev16["loop_pcs"] != ["0x%x" % (BASE + SITE_OFF - 4 + 4 * i)
                            for i in range(4)]:
        fail("loop pcs evidence %r" % (ev16["loop_pcs"],))
    else:
        okk("evidence records all four loop PCs as reached")


    # ---- 17. fast-smoke scale, stale context, TEXT-only exclusion --------
    import time
    t0 = time.time()
    far = [(0x400000 + 8 * i, 0x400008 + 8 * i, "RELA") for i in range(500000)]
    big_ix = G._Index(far + [(0x1040, 0x1060, "tbl")])
    for i in range(20000):
        if big_ix.find(0x1100 + 4 * (i % 64), 0x1104 + 4 * (i % 64)):
            fail("large index false positive")
            break
    if big_ix.find(0x1044, 0x1048) is None:
        fail("large index missed an in-TEXT interval")
    elif time.time() - t0 > 20.0:
        fail("large-index smoke too slow: %.1fs" % (time.time() - t0))
    else:
        okk("500k-interval index: build+20000 bisect queries in %.2fs"
            % (time.time() - t0))
    sm = make(tmp, "stale", BASE)
    sm2 = make(tmp, "stale2", BASE, slots=[(0x1010, R_REL, 0)])
    expect_input_error("stale/forged context from other bytes", lambda:
                       G.derive(sm["image"], sm["sha"], sm2["ctx"]),
                       "context SHA")
    # TEXT-only filtering keeps the same semantics: an OBJECT symbol OUTSIDE
    # TEXT never excludes a TEXT target, one inside TEXT always does.
    far_sym = make(tmp, "fs", BASE,
                   syms=[("far", 0x3F00, 0x20, STT_OBJECT, 1)])
    if G._target_refusal(BASE + 0x1010, far_sym["ctx"], MOD0) is not None:
        fail("symbol outside TEXT excluded a TEXT target")
    else:
        okk("symbols outside TEXT are filtered from the exclusion index")

    # ---- 18. final three: C2 direct, C5 call counts, C6 audit keys --------
    # C2: the header identity check, driven DIRECTLY with a context that has
    # been forged to agree with a forged layout (the upstream Context would
    # normally refuse these; the check must not depend on that).
    class _Ctx(object):
        def __init__(self, real, mod0, tags):
            self._m, self._t, self._real = mod0, tags, real

        def mod0_offset(self):
            return self._m

        @property
        def tags(self):
            return self._t

    hdr = make(tmp, "hdr", BASE, hash_buckets=(1, 2),
               syms=[("sa", 0x1500, 0x10, STT_OBJECT, 1),
                     ("sb", 0x1600, 0x10, STT_OBJECT, 1)])
    raw_tags, raw_mod0 = G._read_tags(hdr["image"])
    G._check_header_identity(hdr["image"], _Ctx(None, raw_mod0, raw_tags),
                             raw_tags, raw_mod0)
    okk("header identity passes for consistent raw/layout/context")
    forged_lay = dict(hdr["layout"], mod0_off=MOD0 + 0x20)
    forged_img = R.Image("hdr", BASE, hdr["flat"], forged_lay, {})
    expect_input_error(
        "raw MOD0 pointer != forged layout AND forged context agree",
        lambda: G._check_header_identity(
            forged_img, _Ctx(None, MOD0 + 0x20, raw_tags), raw_tags,
            MOD0 + 0x20), "MOD0")
    expect_input_error(
        "context MOD0 offset != raw pointer (layout agrees with raw)",
        lambda: G._check_header_identity(
            hdr["image"], _Ctx(None, MOD0 + 0x20, raw_tags), raw_tags,
            raw_mod0), "context MOD0")
    expect_input_error(
        "context tags != raw tags",
        lambda: G._check_header_identity(
            hdr["image"], _Ctx(None, raw_mod0, {**raw_tags, 99: 1}),
            raw_tags, raw_mod0), "tags differ")
    magicless = bytearray(hdr["flat"])
    magicless[MOD0:MOD0 + 4] = b"NOPE"
    expect_input_error(
        "no MOD0 magic at the pointed offset",
        lambda: G._check_header_identity(
            R.Image("hdr", BASE, bytes(magicless), hdr["layout"], {}),
            _Ctx(None, raw_mod0, raw_tags), raw_tags, raw_mod0), "magic")
    expect_input_error(
        "DT_HASH nchain != layout dynsym_count (both layouts forged)",
        lambda: G._check_header_identity(
            R.Image("hdr", BASE, hdr["flat"],
                    dict(hdr["layout"], dynsym_count=9), {}),
            _Ctx(None, raw_mod0, raw_tags), raw_tags, raw_mod0), "nchain")

    # C5: derive reads the (large) relocation/symbol tables a CONSTANT number
    # of times, never once per slot.
    class _Counting(object):
        def __init__(self, real):
            object.__setattr__(self, "_real", real)
            object.__setattr__(self, "calls", {})

        def __getattr__(self, name):
            attr = getattr(self._real, name)
            if callable(attr):
                def wrapped(*a, **kw):
                    self.calls[name] = self.calls.get(name, 0) + 1
                    return attr(*a, **kw)
                return wrapped
            return attr

    many = [(0x1010 + 4 * i, R_REL, 0) for i in range(60)]
    cm = make(tmp, "cnt", BASE, slots=many,
              syms=[("tbl", 0x1500, 0x20, STT_OBJECT, 1)])
    counting = _Counting(cm["ctx"])
    arr60 = G.derive(cm["image"], cm["sha"], counting)
    c = counting.calls
    if arr60 is None or arr60.count != 60:
        fail("60-slot array did not derive")
    elif c.get("defined_symbols", 0) > 1 or c.get("relocation_sites", 0) > 3 \
            or c.get("metadata_extents", 0) > 2:
        fail("table scans scale with slots: %r" % (c,))
    else:
        okk("60 slots -> constant table scans %r (not per slot)"
            % (sorted(c.items()),))

    # C6: every evidence key is required; absent -> typed error, not KeyError
    gm = {"source_sha256": mod["sha"], "guest_base": "0x%x" % BASE,
          "entries": ["0x%x" % TARGET_A]}
    base_audit = {"evidence": P(auth, ms, TARGET_A).evidence}
    for path in (("module",), ("flat_sha256",), ("index",), ("slot",),
                 ("target",), ("addend",), ("array",),
                 ("array", "table_sha256")):
        cut = copy.deepcopy(base_audit)
        tgt = cut["evidence"]
        for key in path[:-1]:
            tgt = tgt[key]
        del tgt[path[-1]]
        try:
            G.bind_flat_sha(auth, {"main": dict(gm)}, [cut])
            fail("bind accepted evidence without %s" % ".".join(path))
        except G.CtorInputError:
            okk("bind: missing evidence %s -> CtorInputError"
                % ".".join(path))
        except Exception as exc:                        # noqa: BLE001
            fail("bind: missing %s raised %s" % (".".join(path),
                                                 type(exc).__name__))
    expect_input_error("bind refuses a serialized-only audit (no Authority)",
                       lambda: G.bind_flat_sha(
                           {"arrays": {}}, {"main": dict(gm)}, [base_audit]))
    stale = authority([make(tmp, "stale3", BASE,
                            slots=[(0x1010, R_REL, 0)])])
    expect_input_error("audit from another authority/table is refused",
                       lambda: G.bind_flat_sha(stale, {"stale3": dict(gm)},
                                               [base_audit]))

    # ---- 19. class gate: ordinary callback loops keep the OLD rules -------
    # N2: tampering a Slot (even with the digest rewritten) fails closed.
    tm = make(tmp, "tam", BASE)
    ta = authority([tm])
    tarr = ta.arrays["tam"]
    object.__setattr__(tarr.slots[0], "target", BASE + 0x1030)
    expect_refuse("tampered Slot.target fails closed",
                  P(ta, [tm], TARGET_A, cursor={"reg": 20, "value": tarr.array_va + 8,
                                                "slot_bytes": TARGET_A, "bound_reg": 19,
                                                "bound_value": tarr.array_end}),
                  "authority-mutated")
    object.__setattr__(tarr, "digest", G.table_digest(tarr))   # digest redone
    if G.array_consistent(tarr):
        fail("per-slot consistency accepted target != base+addend")
    else:
        okk("per-slot consistency rejects target != base+addend even with a "
            "recomputed digest")
    expect_input_error("bind refuses a tampered slot", lambda:
                       G.bind_flat_sha(ta, {"tam": {
                           "source_sha256": tm["sha"],
                           "guest_base": "0x%x" % BASE,
                           "entries": ["0x%x" % TARGET_A]}},
                           [{"evidence": {"module": "tam"}}]))
    tm2 = make(tmp, "tam2", BASE)
    ta2 = authority([tm2])
    object.__setattr__(ta2.arrays["tam2"].slots[1], "slot_va", 0x1234)
    expect_refuse("tampered Slot.slot_va fails closed",
                  P(ta2, [tm2], TARGET_A), "authority-mutated")

    import json as _json
    v0 = os.path.join(tmp, "v0")
    os.makedirs(os.path.join(v0, "link"), exist_ok=True)

    class _World(object):
        def __init__(self, image):
            self.images = [image]
            self.sentinel = 0

    def seam(mod_, target, label, expect, gprs_over=None, old_hit=True,
             site_off=SITE_OFF):
        """Drive the REAL make_ctor_decide + select_follow."""
        with open(os.path.join(v0, "link", mod_["name"] + ".layout.json"), "w",
                  encoding="utf-8") as f:
            f.write(_json.dumps(mod_["layout"]))
        mm = {"name": mod_["name"], "base": BASE}
        a_ = None
        gp = {r: {"value": 0, "read_va": 0, "status": -1, "live": 0}
              for r in range(31)}
        try:
            a_ = authority([mod_])
            arr_ = next(iter(a_.arrays.values()))
            idx_ = [sl.target for sl in arr_.slots].index(target)
            gp[20] = {"value": arr_.array_va + 8 * (idx_ + 1), "read_va": 0,
                      "status": 0, "live": target}
            gp[19] = {"value": arr_.array_end, "read_va": 0, "status": 0,
                      "live": 0}
        except Exception:                                # noqa: BLE001
            gp[20] = {"value": BASE + ARRAY_OFF + 8, "read_va": 0,
                      "status": 0, "live": target}
            gp[19] = {"value": BASE + ARRAY_OFF + 8 * 2, "read_va": 0,
                      "status": 0, "live": 0}
        for k, v in (gprs_over or {}).items():
            gp[k] = dict(gp[k], **v)
        st = {"src": BASE + site_off}
        decide = SP.make_ctor_decide(v0, [], _World(mod_["image"]), None, 0,
                                     st, gp, mm, {})
        old_calls = []

        def old(va):
            old_calls.append(va)
            return ("FUNC", "named", 1, 4) if old_hit else None
        class _Veneer(object):
            def prove(self, t):
                return G.refuse("veneer-stub-refusal", "stub")
        d_ = SP.select_follow(target, None, old, "blr", lambda: _Veneer(),
                              decide)
        if d_["kind"] != expect:
            fail("%s: kind %r expected %r (%r)" % (label, d_["kind"], expect,
                                                  d_.get("reason")))
            return d_, old_calls
        okk("%s -> %s%s" % (label, d_["kind"],
                            " (%s)" % d_.get("reason") if d_.get("reason")
                            else ""))
        return d_, old_calls

    # genuine constructor loop: D023 admits, old rule is NOT consulted
    g_mod = make(tmp, "main", BASE)
    d_, oc = seam(g_mod, TARGET_A, "genuine ctor loop", "ctor")
    if oc:
        fail("old rule consulted for a genuine ctor loop")
    # ordinary callback loop (same shape) in a module with NO init array:
    # STT_FUNC target keeps the OLD follow
    na = make(tmp, "noarr", BASE, tags_drop=(G.DT_INIT_ARRAY,
                                             G.DT_INIT_ARRAYSZ))
    d_, oc = seam(na, BASE + 0x1030, "loop-shaped site, module has no "
                  "init array, STT_FUNC target", "old")
    if oc != [BASE + 0x1030]:
        fail("old STT_FUNC rule was not the decider: %r" % (oc,))
    # loop-shaped site NOT reached from DT_INIT (RET before it): old rules
    ur = make(tmp, "unreach", BASE, words={DT_INIT_OFF + 12: RET})
    seam(ur, BASE + 0x1030, "loop-shaped site outside the DT_INIT CFG, "
         "STT_FUNC target", "old")
    # same, with no old hit: ordinary refusal path, NOT a D023 verdict
    d_, oc = seam(ur, BASE + 0x1030, "unreached loop, unjustified target",
                  "refused", old_hit=False)
    if d_.get("reason") != "veneer-stub-refusal":
        fail("unreached loop did not take the old veneer path: %r" % d_)
    # genuine declared loop + MALFORMED table: FINAL typed refusal, no
    # fallback to the old STT_FUNC rule
    bad = make(tmp, "badtbl", BASE, slots=[(0, R_REL, 0), (0x1020, R_REL, 0)])
    d_, oc = seam(bad, BASE + 0x1030, "genuine loop, null-slot table",
                  "refused")
    if d_.get("reason") != "slot-null-target" or oc:
        fail("malformed table was swallowed: %r old=%r" % (d_, oc))
    # genuine loop + bad live capture: final
    d_, oc = seam(g_mod, TARGET_A, "genuine loop, wrong live slot bytes",
                  "refused", gprs_over={20: {"live": TARGET_B}})
    if oc:
        fail("old rule consulted after a class refusal")
    # genuine loop + target not a member: final refusal, no STT fallback
    d_, oc = seam(g_mod, BASE + 0x1030, "genuine loop, non-member target",
                  "refused")
    if oc or d_.get("reason") != "not-in-init-array":
        fail("non-member target in a genuine loop fell back: %r" % (d_,))

    # ---- 20. loose class gate / strict final proof (non-vacuous) ----------
    NAMED = BASE + 0x1030          # exact target the old STT_FUNC spy admits

    def final_refusal(label, mod_, reason, **kw):
        d_, oc = seam(mod_, NAMED if kw.pop("named", True) else TARGET_A,
                      label, "refused", **kw)
        if oc:
            fail("%s: old_justify was consulted (%r)" % (label, oc))
        if reason is not None and d_.get("reason") != reason:
            fail("%s: reason %r expected %r" % (label, d_.get("reason"),
                                                reason))
        return d_

    # not the class -> the SPY old rule is consulted and admits the target
    for label, mod_ in (
            ("no array declared", make(tmp, "g1", BASE, tags_drop=(
                G.DT_INIT_ARRAY, G.DT_INIT_ARRAYSZ))),
            ("array declared but no DT_INIT", make(tmp, "g2", BASE,
                                                   tags_drop=(G.DT_INIT,))),
            ("loop unreachable from DT_INIT", make(
                tmp, "g3", BASE, words={DT_INIT_OFF + 12: RET}))):
        d_, oc = seam(mod_, NAMED, label + " -> old STT_FUNC admits", "old")
        if oc != [NAMED]:
            fail("%s: spy old rule not the decider: %r" % (label, oc))
    # the class -> typed FINAL refusal, spy NEVER called, STT_FUNC ignored
    final_refusal("declared array, slot relocation kind 257",
                  make(tmp, "f1", BASE,
                       slots=[(0x1010, 257, 0), (0x1020, R_REL, 0)]),
                  "slot-relocation-not-relative")
    final_refusal("declared array, duplicate bound RELA",
                  make(tmp, "f2", BASE, rela_extra=[
                      (GOT_END, R_REL, 0, ARRAY_OFF + 16)]),
                  "array-bounds-not-corroborated")
    final_refusal("declared array, loop entered mid-body",
                  make(tmp, "f3", BASE, words={DT_INIT_OFF + 12: 0x34000040}),
                  "loop-entered-mid-body")
    final_refusal("declared array, dead fake GOT loads before the loop",
                  make(tmp, "f4", BASE, words={
                      DT_INIT_OFF: 0x14000004, DT_INIT_OFF + 4: 0xD0000009,
                      DT_INIT_OFF + 8: LOOP_WORDS[DT_INIT_OFF + 4],
                      DT_INIT_OFF + 12: LOOP_WORDS[DT_INIT_OFF + 8]}),
                  "dt-init-bound-not-got-end", named=False)
    # UNPAIRED declared array (metadata invalid) is still the class
    up_flat = build_flat(tags_drop=(G.DT_INIT_ARRAYSZ,))
    up_layout = dict(make(tmp, "up0", BASE)["layout"],
                     sha256=hashlib.sha256(up_flat).hexdigest(), name="up")
    up_img = R.Image("up", BASE, up_flat, up_layout, {})
    pr, rf = G.classify_site(up_img, (BASE + 0x1000, BASE + 0x2000),
                             BASE + SITE_OFF)
    if pr is None or rf is not None:
        fail("unpaired declared array must still classify: %r %r" % (pr, rf))
    else:
        okk("unpaired DT_INIT_ARRAY tags still classify (bad table cannot "
            "escape to the old rules)")
    final_refusal("declared UNPAIRED array metadata", {
        "name": "up", "layout": up_layout, "image": up_img},
        "ctor-metadata-invalid")
    # loop shape alone (no declared array) never intercepts
    pr, rf = G.classify_site(make(tmp, "g1b", BASE, tags_drop=(
        G.DT_INIT_ARRAY, G.DT_INIT_ARRAYSZ))["image"],
        (BASE + 0x1000, BASE + 0x2000), BASE + SITE_OFF)
    if pr is not None or rf is not None:
        fail("shape-only module was classified")
    else:
        okk("loop shape alone never classifies")


if __name__ == "__main__":
    sys.exit(main())
