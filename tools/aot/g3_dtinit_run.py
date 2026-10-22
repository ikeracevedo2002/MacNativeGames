#!/usr/bin/env python3
"""DT_INIT partial-AOT first-fault harness (real modules, local only).

Builds external artifacts OUTSIDE the repository:
  * entries JSON files: each module's DT_INIT VA plus explicitly listed roots,
  * partial translated images (aot_translate.py --module --partial),
  * a descriptor for the same three flats via aot_module.py emit-desc,
  * one MSVC x64 executable (probe + images + loader/runtime sources),
runs it on the host CPU and follows AOT_FAULT_UNTRANSLATED targets only when
they are independently justified by the OFFLINE reference link (real_sites.tsv:
the target is a link-resolved symbol value), never from the runtime observation
alone.

No game data is written into the repository; v0/img and v0/link are only READ.

Exit codes: 0 a non-transfer typed stop was observed, 2 no such stop.
"""

import argparse
import json
import os
import re
import subprocess
import sys

MODULES = [
    ("main_real", "0x1000000000", "0x1000000030"),
    ("subsdk0_real", "0x1010000000", "0x1010000030"),
    ("sdk_real", "0x1020000000", "0x1020000030"),
]
# The ONE root added from the first run: the shared helper all three DT_INIT
# prologues call through their PLT (sdk+0x8d880, __nnmusl_init_dso). The value
# is cross-checked against the offline reference link below.
START_EXTRA = {"sdk_real": [0x102008D880]}
MAX_FOLLOW = 10

CORE = [
    "src/aot/aot_prog_assembly.c",
    "src/aot/aot_program.c",
    "src/aot/aot_runtime.c",
    "src/aot/aot_mem.c",
    "src/aot/aot_as.c",
    "src/aot/aot_loader.c",
    "src/aot/aot_sha256.c",
    "src/aot/aot_fp.c",
    "src/host_vm.c",
    "src/host_thread.c",
    "src/host_time.c",
    "src/host_time_convert.c",
]


def run(cmd, **kw):
    p = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if p.returncode != 0:
        sys.stdout.write(p.stdout)
        sys.stderr.write(p.stderr)
        raise SystemExit("infrastructure: command failed: %s" % (cmd,))
    return p


def load_link_values(tsv):
    """value -> (module, symbol) from the independent reference link dump."""
    out = {}
    with open(tsv, encoding="utf-8") as f:
        next(f)
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) != 5:
                continue
            mod, _where, _kind, sym, value = parts
            v = int(value, 0)
            if sym != "-" and v:
                out.setdefault(v, (mod, sym))
    return out


def text_range(layout_path, base):
    with open(layout_path, encoding="utf-8") as f:
        lay = json.load(f)
    off, end = lay["text"]
    return base + off, base + end


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=".")
    ap.add_argument("--work", required=True)
    ap.add_argument("--v0-dir", required=True)
    ap.add_argument("--python", default=sys.executable)
    ap.add_argument("--vcvars", required=True)
    ap.add_argument("--cl", default="cl.exe")
    args = ap.parse_args(argv)

    from pathlib import Path
    repo = str(Path(args.repo).resolve())
    work = str(Path(args.work).resolve())
    v0 = str(Path(args.v0_dir).resolve())
    try:
        common = os.path.commonpath([os.path.normcase(repo),
                                     os.path.normcase(work)])
    except ValueError:
        common = ""
    if os.path.normcase(common) == os.path.normcase(repo):
        return fail("--work must not be the repository or inside it "
                    "(resolved path %s)" % work)
    os.makedirs(os.path.join(work, "img"), exist_ok=True)
    os.makedirs(os.path.join(work, "obj"), exist_ok=True)

    tools = os.path.join(repo, "tools", "aot")
    translate = os.path.join(tools, "aot_translate.py")
    module_tool = os.path.join(tools, "aot_module.py")
    link_values = load_link_values(os.path.join(v0, "real_sites.tsv"))
    ranges = {name: text_range(os.path.join(v0, name + ".layout.json"),
                               int(base, 0))
              for name, base, _init in MODULES}

    extra = {k: list(v) for k, v in START_EXTRA.items()}
    justified = {}
    for name, vals in extra.items():
        for v in vals:
            hit = link_values.get(v)
            justified[v] = hit
            if hit is None:
                return fail("seed root 0x%x is not a link-resolved value" % v)

    for iteration in range(MAX_FOLLOW + 1):
        print("== iteration %d: extra roots %s" %
              (iteration, {k: [hex(x) for x in v] for k, v in extra.items() if v}))
        images, metas = [], {}
        for name, base, init in MODULES:
            entries = os.path.join(work, "entries_%s.json" % name)
            with open(entries, "w", encoding="utf-8") as f:
                json.dump(sorted(set([int(init, 0)] + extra.get(name, []))), f)
            img = os.path.join(work, "img", name + ".c")
            meta = os.path.join(work, "img", name + ".meta.json")
            run([args.python, translate, "--module", "--partial",
                 "--flat", os.path.join(v0, name + ".flat"),
                 "--layout", os.path.join(v0, name + ".layout.json"),
                 "--guest-base", base, "--entries", entries,
                 "--name", name, "--out", img, "--meta-out", meta])
            images.append(img)
            with open(meta, encoding="utf-8") as f:
                metas[name] = json.load(f)

        desc = os.path.join(work, "real_desc_partial.c")
        image_map = {name: "aot_image_%s" % name for name, _b, _i in MODULES}
        images_json = os.path.join(work, "images.json")
        with open(images_json, "w", encoding="utf-8") as f:
            json.dump(image_map, f)
        run([args.python, module_tool, "emit-desc",
             "--config", os.path.join(v0, "real_link_config.json"),
             "--dir", v0, "--variant", "real", "--out-c", desc,
             "--images", images_json])
        exe = os.path.join(work, "aot_g3_dtinit_probe.exe")
        if not build(repo, work, args, desc, images, exe):
            return 1

        stops = {}
        for name, _base, _init in MODULES:
            p = subprocess.run([exe, v0, "--module", name],
                               capture_output=True, text=True)
            with open(os.path.join(work, "run_%s_it%d.log" % (name, iteration)),
                      "w", encoding="utf-8") as lf:
                lf.write(p.stdout)
                lf.write(p.stderr)
            sys.stdout.write(p.stdout)
            if p.returncode != 0:
                sys.stderr.write(p.stderr)
                return fail("probe exited %d for %s" % (p.returncode, name))
            m = re.search(r"^STOP (\S+) code=(-?\d+) src=0x([0-9a-f]+) "
                          r"target=0x([0-9a-f]+) status=(-?\d+) "
                          r"steps=(\d+)", p.stdout, re.M)
            if not m:
                return fail("no STOP line for %s" % name)
            stops[name] = m.groups()

        grew = False
        for name, code, src, target, status, steps in stops.values():
            code_i = int(code)
            tgt = int(target, 16)
            if code_i != 10:
                continue
            hit = link_values.get(tgt)
            owner = None
            for mod, (lo, hi) in ranges.items():
                if lo <= tgt < hi:
                    owner = mod
            if hit is None or owner is None:
                print("  target 0x%x has NO offline link/symbol justification; "
                      "not followed" % tgt)
                continue
            if tgt in extra.get(owner, []):
                continue
            extra.setdefault(owner, []).append(tgt)
            justified[tgt] = hit
            grew = True
            print("  follow 0x%x in %s: link %s (%s) justified at site 0x%s"
                  % (tgt, owner, hit[1], hit[0], src))
        if not grew:
            return summarize(stops, metas, justified, ranges, work)
    return fail("root-follow limit reached")


def build(repo, work, args, desc, images, exe):
    sources = [os.path.join(repo, "tests", "aot", "aot_g3_dtinit_probe.c"),
               desc] + images + [os.path.join(repo, s) for s in CORE]
    bat = os.path.join(work, "build.bat")
    with open(bat, "w", encoding="ascii") as f:
        f.write('@call "%s" >nul\r\n' % args.vcvars.replace("/", "\\"))
        cmd = ['"%s"' % args.cl.replace("/", "\\"), "/nologo", "/W4", "/O2",
               "/std:c11", "/bigobj", "/D_CRT_SECURE_NO_WARNINGS",
               "/Fo:%s\\\\" % os.path.join(work, "obj").replace("/", "\\"),
               "/I%s" % os.path.join(repo, "src", "aot").replace("/", "\\"),
               "/I%s" % os.path.join(repo, "src").replace("/", "\\"),
               "/Fe:%s" % exe.replace("/", "\\")]
        cmd += ['"%s"' % s.replace("/", "\\") for s in sources]
        f.write(" ".join(cmd) + "\r\n")
    p = subprocess.run([bat], capture_output=True, text=True)
    log = os.path.join(work, "build.log")
    with open(log, "w", encoding="utf-8") as lf:
        lf.write(p.stdout)
        lf.write(p.stderr)
    if p.returncode != 0:
        sys.stdout.write(p.stdout)
        sys.stderr.write(p.stderr)
        return False
    return True


def summarize(stops, metas, justified, ranges=None, work=None):
    print()
    typed = 0
    for name in sorted(stops):
        _n, code, src, target, status, steps = stops[name]
        code_i, src_i, status_i = int(code), int(src, 16), int(status)
        if code_i == 0:
            print("NO TYPED STOP %s: returned cleanly (NOT a pass: no "
                  "per-constructor witness)" % name)
            continue
        if code_i == 10:
            print("DISCOVERY GAP %s: AOT_FAULT_UNTRANSLATED pc=0x%x "
                  "target=0x%s (no offline link justification / no new root)"
                  % (name, src_i, target))
            continue
        # Typed non-transfer fault. Image-local diagnostics: the faulting PC
        # may belong to ANOTHER image than the entry module, and unsupported
        # status indices are per-image. Resolve the image from fault_src.
        img = image_of(src_i, ranges)
        if code_i == 16:
            if img is None:
                return fail("%s: UNSUPPORTED_INSN src 0x%x is outside every "
                            "image text range" % (name, src_i))
            table = metas[img]["unsupported"]
            hit = [u for u in table if u["status"] == status_i]
            if not hit:
                return fail("%s: status %d is not in %s offline metadata"
                            % (name, status_i, img))
            u = hit[0]
            if int(u["pc"], 16) != src_i:
                return fail("%s: fault_src 0x%x != offline metadata pc %s "
                            "(%s status %d)" % (name, src_i, u["pc"], img,
                                                status_i))
            typed += 1
            print("FIRST BLOCKER %s: AOT_FAULT_UNSUPPORTED_INSN image=%s "
                  "pc=%s word=%s reason=%s steps=%s"
                  % (name, img, u["pc"], u["word"], u["reason"], steps))
        else:
            typed += 1
            print("FIRST BLOCKER %s: fault code=%d image=%s src=0x%x "
                  "target=0x%s status=%d steps=%s"
                  % (name, code_i, img or "?", src_i, target, status_i,
                     steps))
    print()
    for tgt, (mod, sym) in sorted(justified.items()):
        print("followed root 0x%x = %s (%s)" % (tgt, sym, mod))
    if work is not None:
        import hashlib
        man = {"stops": {k: list(v) for k, v in stops.items()},
               "files": {}}
        for rel in ["aot_g3_dtinit_probe.exe", "real_desc_partial.c"] +                    ["img/%s.c" % m for m, _b, _i in MODULES] +                    ["img/%s.meta.json" % m for m, _b, _i in MODULES]:
            path = os.path.join(work, rel)
            with open(path, "rb") as f:
                man["files"][rel] = hashlib.sha256(f.read()).hexdigest()
        with open(os.path.join(work, "manifest.json"), "w",
                  encoding="utf-8") as f:
            json.dump(man, f, indent=2, sort_keys=True)
    return 0 if typed else 2


def image_of(va, ranges):
    if not ranges:
        return None
    for mod, (lo, hi) in ranges.items():
        if lo <= va < hi:
            return mod
    return None


def fail(msg):
    print("FAIL: " + msg)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
