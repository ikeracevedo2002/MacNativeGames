#!/usr/bin/env python3
"""Batch real DT_INIT run over ALL offline-justified init_array roots.

Reads the relocated init_array values with g3_init_reach.load_world (so the
values are relocation-resolved, never raw flat pointers), puts DT_INIT plus
every root of the module into ONE partial image, compiles it once and runs a
fresh process per module. No per-function follow loop: the DT_INIT loop's
`blr` dispatches every ctor entry inside the image until a real typed stop.

D008 measurements are printed here (translate/compile wall time, C bytes,
block and unsupported counts). v0/img and v0/link are read-only.

Exit: 0 a typed stop other than UNTRANSLATED, 2 no such stop, 1 infra.
"""

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))


def load_mod(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=".")
    ap.add_argument("--work", required=True)
    ap.add_argument("--v0-dir", required=True)
    ap.add_argument("--python", default=sys.executable)
    ap.add_argument("--vcvars", required=True)
    ap.add_argument("--cl", default="cl.exe")
    args = ap.parse_args(argv)
    repo = str(Path(args.repo).resolve())
    work = str(Path(args.work).resolve())
    v0 = str(Path(args.v0_dir).resolve())
    common = os.path.commonpath([os.path.normcase(repo), os.path.normcase(work)])
    if os.path.normcase(common) == os.path.normcase(repo):
        print("FAIL: --work must be outside the repository")
        return 1
    os.makedirs(os.path.join(work, "img"), exist_ok=True)
    os.makedirs(os.path.join(work, "obj"), exist_ok=True)

    drv = load_mod(os.path.join(HERE, "g3_dtinit_run.py"), "g3_dtinit_run")
    reach = load_mod(os.path.join(HERE, "g3_init_reach.py"), "g3_init_reach")
    world = reach.load_world(v0)
    roots, counts = reach.boot_roots(world)
    print("roots: %s total=%d" % (counts, len(roots)))

    base_of = {name: name.rsplit("_real", 1)[0]
               for name, _b, _i in drv.MODULES}
    link = os.path.join(v0, "link")
    ranges = {name: drv.text_range(
        os.path.join(link, name + ".layout.json"), int(base, 0))
        for name, base, _init in drv.MODULES}

    def owner_of(va):
        for name, (lo, hi) in ranges.items():
            if lo <= va < hi:
                return name
        return None

    link_values = drv.load_link_values(os.path.join(v0, "link",
                                                    "real_sites.tsv"))
    by_module = {}
    seeds = {k: list(v) for k, v in drv.START_EXTRA.items()}
    seeds.setdefault("sdk_real", []).extend(
        [0x102012C870, 0x1020587580, 0x102056F610])

    # Statically justified CODE entries: DEFINED STT_FUNC dynsym symbols in
    # sdk's text (lead-confirmed names; re-verified against this image's own
    # dynsym+layout, never guessed from an address alone).
    import aot_module as M
    # 0xfa260/0x1282f4 are lead-confirmed callees of __nnmusl_init_dso.
    # 0x127dc0/0xfb3f0/0x13186c are the CALL_INDIRECT targets OBSERVED by the
    # previous all-roots run (batch-w1-4-mul) after MUL/MADD/MSUB landed; each
    # is re-verified here as a DEFINED STT_FUNC in this image, so the seed set
    # is batched from evidence instead of one callee per checkpoint.
    # 0x131724/0xfb2d0 are the CALL_INDIRECT targets observed by the second
    # all-roots run (batch-w1-4-mul2); both re-verified as DEFINED STT_FUNC.
    # subsdk0 0x620 is a DEFINED STT_FUNC (nn::mmnv::Request C1/C2) observed
    # as an indirect constructor target; static dynsym justification only.
    static_entries = {"subsdk0_real": [0x1010000620],
                      "sdk_real": [0x10200FA060, 0x102056F470, 0x10200FA260, 0x10201282F4,
                                   0x1020127DC0, 0x10200FB3F0,
                                   0x102013186C, 0x1020131724,
                                   0x10200FB2D0]}
    static_names = {}
    for mname, vals in static_entries.items():
        base = dict((n, int(b, 0)) for n, b, _i in drv.MODULES)[mname]
        mod = M.load_module(os.path.join(link, mname + ".flat"),
                            os.path.join(link, mname + ".layout.json"),
                            mname, base)
        lo, hi = ranges[mname]
        for v in vals:
            if not (lo <= v < hi):
                print("FAIL: static entry 0x%x outside %s text" % (v, mname))
                return 1
            hit = [sym["name"] for sym in mod["syms"]
                   if sym["type"] == M.STT_FUNC and sym["name"]
                   and M.sym_defined(sym, mod["image_size"])
                   and base + sym["value"] == v]
            if not hit:
                print("FAIL: static entry 0x%x is not a defined STT_FUNC in "
                      "%s" % (v, mname))
                return 1
            static_names[v] = hit[0]
            seeds.setdefault(mname, []).append(v)
            print("static STT_FUNC entry 0x%x %s" % (v, hit[0]))
    for mname, vals in seeds.items():
        for v in vals:
            if v not in link_values and v not in static_names:
                print("FAIL: seed 0x%x neither link-resolved nor a defined "
                      "STT_FUNC" % v)
                return 1
            by_module.setdefault(mname, set()).add(v)
    for value, kind in roots:
        if kind != "constructor":
            continue
        own = owner_of(value)
        if own is None:
            print("FAIL: root 0x%x outside module text" % value)
            return 1
        by_module.setdefault(own, set()).add(value)

    entries = {}
    t0 = time.time()
    csize = blocks = unsup = 0
    for name, base, init in drv.MODULES:
        es = sorted(set([int(init, 0)]) | by_module.get(name, set()))
        entries[name] = es
        ep = os.path.join(work, "entries_%s.json" % name)
        json.dump(es, open(ep, "w"))
        img = os.path.join(work, "img", name + ".c")
        meta = os.path.join(work, "img", name + ".meta.json")
        drv.run([args.python, os.path.join(HERE, "aot_translate.py"),
                 "--module", "--partial",
                 "--flat", os.path.join(link, name + ".flat"),
                 "--layout", os.path.join(link, name + ".layout.json"),
                 "--guest-base", base, "--entries", ep,
                 "--name", name, "--out", img, "--meta-out", meta])
        csize += os.path.getsize(img)
        doc = json.load(open(meta))
        blocks += len(doc.get("blocks", []))
        unsup += len(doc.get("unsupported", []))
    t_translate = time.time() - t0
    print("D008 translate_s=%.1f c_bytes=%d blocks=%d unsupported=%d"
          % (t_translate, csize, blocks, unsup))

    desc = os.path.join(work, "real_desc_partial.c")
    image_map = {name: "aot_image_%s" % name for name, _b, _i in drv.MODULES}
    images_json = os.path.join(work, "images.json")
    json.dump(image_map, open(images_json, "w"))
    drv.run([args.python, os.path.join(HERE, "aot_module.py"), "emit-desc",
             "--config", os.path.join(link, "real_link_config.json"),
             "--dir", link, "--variant", "real", "--out-c", desc,
             "--images", images_json])
    exe = os.path.join(work, "aot_g3_dtinit_batch_probe.exe")
    t0 = time.time()
    if not drv.build(repo, work, args, desc, [os.path.join(work, "img", n + ".c")
                                              for n, _b, _i in drv.MODULES],
                     exe):
        return 1
    t_build = time.time() - t0
    print("D008 build_s=%.1f exe=%s" % (t_build, exe))

    ok = False
    for name, _base, init in drv.MODULES:
        p = subprocess.run([exe, link, "--module", name],
                           capture_output=True, text=True)
        log = os.path.join(work, "batch_%s.log" % name)
        open(log, "w", encoding="utf-8").write(p.stdout + p.stderr)
        if p.returncode != 0:
            print("infra: probe exited %d for %s" % (p.returncode, name))
            return 1
        m = re.search(r"^STOP (\S+) code=(-?\d+) src=0x([0-9a-f]+) "
                      r"target=0x([0-9a-f]+) status=(-?\d+) steps=(\d+)",
                      p.stdout, re.M)
        x = re.search(r"^STOPX \S+ nzcv=0x([0-9a-f]+) sp=0x([0-9a-f]+) "
                      r"trace=(\d+) over=(\d+)", p.stdout, re.M)
        t = re.search(r"^TRACE((?: [0-9a-f]+)*)$", p.stdout, re.M)
        if not (m and x and t):
            print("infra: malformed probe output for %s" % name)
            return 1
        trace = [int(v, 16) for v in t.group(1).split()] if t.group(1) else []
        # Module-local DT_INIT loop witnesses (prefix-only when trace is
        # bounded): block entry of the blr at stub+0x144 (attempt) and the
        # block after the loop's return at stub+0x14c (return). Do NOT count
        # PLT/helper seeds as constructors.
        base_init = int(init, 0)
        attempts = sum(1 for pc in trace if pc == base_init + 0x114)
        loop_ret = sum(1 for pc in trace if pc == base_init + 0x11C)
        pre = re.search(r"^ENTRY \S+ init=0x[0-9a-f]+ nzcv_before=0x([0-9a-f]+)",
                        p.stdout, re.M)
        print("%s: code=%s src=0x%s target=0x%s status=%s steps=%s "
              "nzcv %s->%s loop_attempts(prefix)=%d loop_returns(prefix)=%d "
              "trace=%s over=%s" %
              (name, m.group(2), m.group(3), m.group(4), m.group(5),
               m.group(6), pre.group(1) if pre else "?",
               x.group(1), attempts, loop_ret, x.group(3), x.group(4)))
        print("  first_trace: %s" %
              " ".join("0x%x" % v for v in trace[:14]))
        if m.group(2) != "10":
            ok = True
        if m.group(2) == "16":
            um = re.search(r'"unsupported": \[(.*?)\]', open(
                os.path.join(work, "img", name + ".meta.json")).read(), re.S)
            print("  unsupported sites: %s" % (um.group(1)[:400] if um else "?"))
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
