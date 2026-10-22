#!/usr/bin/env python3
"""Partial-AOT unsupported-instruction trap + provenance fingerprint tests.

Synthetic module flats only (no game data, no Capstone/Unicorn needed):

  1. PARTIAL: a reachable undecodable word ends its block with the typed
     AOT_FAULT_UNSUPPORTED_INSN fault at exactly that PC and status; the block
     has NO successor and performs no destination/SP/memory write before the
     fault (the generated block body is checked line by line).
  2. STRICT (no --partial): the same image fails closed at translation time.
  3. The emitted fault helper sets AOT_FAULT_UNSUPPORTED_INSN, NOT BAD_STATE.
  4. NEGATIVE CONTROL: a text mutation that replaces the fault with a
     fallthrough (or that reports BAD_STATE) is rejected by the same checker.
  5. Provenance: same flat+layout with a different entry set, or strict vs
     partial, must produce a different provenance SHA; identical inputs must
     reproduce it. The flat SHA-256 (loader identity) is unchanged.

Exit: 0 pass, 2 semantic failure, 1 infrastructure/usage.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile

FAILS = []

MOV_X0_1 = 0xD2800020
RET = 0xD65F03C0
UNDECODABLE = 0xFFFFFFFF          # `udf`-shaped word: outside the module subset


def fail(msg):
    FAILS.append(msg)
    print("FAIL: " + msg)


def make_image(words, entries, partial, work, name, tag, sha_index=0):
    raw = b"".join(w.to_bytes(4, "little") for w in words)
    base = 0x1000000000
    lay = {
        "name": name,
        "image_size": len(raw),
        "bss_size": 0,
        "bss_start": len(raw),
        "bss_end": len(raw),
        "text": [0, len(raw)],
        "ro": [len(raw), len(raw)],
        "data": [len(raw), len(raw)],
        "sha256": hashlib.sha256(raw).hexdigest(),
        "dynsym_count": 0,
    }
    flat = os.path.join(work, "%s_flat_%d.bin" % (tag, sha_index))
    with open(flat, "wb") as f:
        f.write(raw)
    lp = os.path.join(work, "%s_layout_%d.json" % (tag, sha_index))
    with open(lp, "w", encoding="utf-8") as f:
        json.dump(lay, f)
    ep = os.path.join(work, "%s_entries_%s.json" % (tag, partial))
    with open(ep, "w", encoding="utf-8") as f:
        json.dump([base + e for e in entries], f)
    return flat, lp, ep, base


def translate(args, flat, lp, ep, base, partial, out, meta):
    cmd = [sys.executable, os.path.join(args.tools, "aot_translate.py"),
           "--module", "--flat", flat, "--layout", lp,
           "--guest-base", "0x%x" % base, "--entries", ep,
           "--name", "synthetic", "--out", out, "--meta-out", meta]
    if partial:
        cmd.insert(2, "--partial")
    return subprocess.run(cmd, capture_output=True, text=True)


def block_body(text, pc, status):
    """The emitted block containing the fault for (pc, status), plus its start."""
    fault = "return aot_fault_unsupported(rt, 0x%xull, (int64_t)%du);" % (pc,
                                                                         status)
    idx = text.find(fault)
    if idx < 0:
        return None, None
    start = text.rfind("static AotExit aot_blk_", 0, idx)
    if start < 0:
        return None, None
    end = text.find("\n}", idx)
    return text[start:end + 2], start


def check_partial(text, meta, pc, status):
    bad = []
    body, start = block_body(text, pc, status)
    if body is None:
        return ["no generated block contains the unsupported fault at 0x%x"
                % pc]
    blk_pc = int(text[start:text.find("(", start)].split("_")[-1], 16)
    fault = "return aot_fault_unsupported(rt, 0x%xull, (int64_t)%du);" % (pc,
                                                                         status)
    tail = ("    rt->site_pc = 0x%xull;\n    %s" % (pc, fault))
    if not body.endswith(tail + "\n}"):
        bad.append("block does not END with site_pc + the exact fault")
    for forbidden in ("aot_fault_state(", "AOT_FAULT_BAD_STATE",
                      "rt->next_pc", "AOT_EXIT_FALLTHROUGH",
                      "aot_mem_st", "aot_mem_ld"):
        if forbidden in body:
            bad.append("fault block contains %r (fabricated effect/successor)"
                       % forbidden)
    if blk_pc > pc:
        bad.append("fault block starts after the faulting PC")
    if '"partial": true' not in open(meta, encoding="utf-8").read().lower():
        bad.append("metadata does not mark the image partial")
    doc = json.load(open(meta, encoding="utf-8"))
    table = doc.get("unsupported", [])
    hit = [u for u in table if int(u["status"]) == status]
    if len(hit) != 1:
        bad.append("metadata has %d rows for status %d" % (len(hit), status))
    else:
        u = hit[0]
        if int(u["pc"], 16) != pc:
            bad.append("metadata pc %s != fault pc 0x%x" % (u["pc"], pc))
        if int(u["word"], 16) != UNDECODABLE:
            bad.append("metadata word %s != 0x%08x" % (u["word"],
                                                       UNDECODABLE))
        if not u.get("reason"):
            bad.append("metadata reason is empty")
    # the helper must use the specific code, never BAD_STATE
    helper = text[text.find("static AotExit aot_fault_unsupported"):
                  text.find("static AotExit aot_fault_unsupported") + 600]
    if "rt->fault = AOT_FAULT_UNSUPPORTED_INSN;" not in helper:
        bad.append("unsupported helper does not set "
                   "AOT_FAULT_UNSUPPORTED_INSN")
    if "AOT_FAULT_BAD_STATE" in helper:
        bad.append("unsupported helper uses AOT_FAULT_BAD_STATE")
    # no successor in the metadata block table
    for blk in doc["blocks"]:
        if int(blk["pc"], 16) == blk_pc:
            if blk["terminator"] != "unsupported":
                bad.append("block terminator is %r, not unsupported"
                           % blk["terminator"])
            if blk["next"]:
                bad.append("unsupported block has successors %r"
                           % blk["next"])
    return bad


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--tools", default="tools/aot")
    args = ap.parse_args(argv)
    tools = os.path.abspath(args.tools)

    work = tempfile.mkdtemp(prefix="aot_partial_")
    base_words = [MOV_X0_1, UNDECODABLE, RET]

    # ---- 1. partial image: typed fault at the exact site ---------------
    flat, lp, ep, base = make_image(base_words, [0], "partial", work,
                                   "synthetic", "trap")
    out = os.path.join(work, "trap_partial.c")
    meta = os.path.join(work, "trap_partial.meta.json")
    args.tools = tools
    p = translate(args, flat, lp, ep, base, True, out, meta)
    if p.returncode != 0:
        fail("partial translation failed: %s" % p.stderr.strip())
    else:
        text = open(out, encoding="utf-8").read()
        for msg in check_partial(text, meta, base + 4, 0):
            fail(msg)

    # ---- 2. strict translation of the same image fails closed ----------
    p = translate(args, flat, lp, ep, base, False,
                  os.path.join(work, "trap_strict.c"),
                  os.path.join(work, "trap_strict.meta.json"))
    if p.returncode == 0:
        fail("strict translation accepted an undecodable reachable word")
    elif "unsupported instruction encoding 0xffffffff" not in p.stderr:
        fail("strict failure does not name the word: %s" % p.stderr.strip())

    # ---- 3. negative control on the checker itself ---------------------
    text = open(out, encoding="utf-8").read()
    mutated = text.replace(
        "return aot_fault_unsupported(rt, 0x%xull, (int64_t)0u);"
        % (base + 4),
        "rt->next_pc = 0x%xull; return AOT_EXIT_FALLTHROUGH;" % (base + 8))
    if mutated == text:
        fail("negative control could not construct the fallthrough mutation")
    else:
        if not check_partial(mutated, meta, base + 4, 0):
            fail("checker accepted a fabricated fallthrough after the "
                 "unsupported word (vacuous check)")
    bad_state = text.replace(
        "rt->fault = AOT_FAULT_UNSUPPORTED_INSN;",
        "rt->fault = AOT_FAULT_BAD_STATE;")
    if bad_state == text:
        fail("negative control could not construct the BAD_STATE mutation")
    else:
        if not check_partial(bad_state, meta, base + 4, 0):
            fail("checker accepted BAD_STATE in the unsupported helper")

    # ---- 4. provenance fingerprint ------------------------------------
    # valid two-entry image so the entry set can differ
    ok_words = [MOV_X0_1, RET, RET]
    f2, l2, e_single, b2 = make_image(ok_words, [0], "strict", work,
                                     "prov", "prov", 0)
    _f3, _l3, e_single2, _b3 = make_image(ok_words, [0], "strict", work,
                                         "prov", "prov", 1)
    _f4, _l4, e_two, _b4 = make_image(ok_words, [0, 4], "strict", work,
                                     "prov", "prov2", 2)
    outs = {}
    for tag, epx, partial in (("single", e_single, False),
                              ("single_again", e_single2, False),
                              ("two", e_two, False),
                              ("single_partial", e_single, True)):
        o = os.path.join(work, "prov_%s.c" % tag)
        m = os.path.join(work, "prov_%s.meta.json" % tag)
        p = translate(args, f2, l2, epx, b2, partial, o, m)
        if p.returncode != 0:
            fail("provenance translation %s failed: %s" % (tag, p.stderr))
            continue
        doc = json.load(open(m, encoding="utf-8"))
        outs[tag] = doc["provenance_sha256"]
        outs[tag + "_flat"] = doc["source_sha256"]
    if len(outs) == 8:
        if outs["single"] != outs["single_again"]:
            fail("identical inputs produced different provenance")
        if outs["single"] == outs["two"]:
            fail("a different entry root set shares the provenance SHA")
        if outs["single"] == outs["single_partial"]:
            fail("strict and partial share the provenance SHA")
        if outs["single_flat"] != outs["two_flat"] or \
                outs["single_flat"] != outs["single_partial_flat"]:
            fail("the loader flat SHA-256 changed with the config")

    print("partial-trap checks: %d failure(s)" % len(FAILS))
    return 0 if not FAILS else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
