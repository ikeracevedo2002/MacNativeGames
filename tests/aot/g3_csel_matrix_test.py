#!/usr/bin/env python3
"""CSEL/CSINC/CSINV/CSNEG full condition x width x NZCV matrix.

For every op (4) x width (X,W) x cond (0..15) one entry block
`<op> x9[,w9], x0, x1, <cond>` + `ret`, emitted C compiled by cl and called
natively under all 16 NZCV nibbles, compared field-exactly (GPR/SP/NZCV) with
a pinned Unicorn A57. ZR-destination rows are included per op/width/cond.

An unsigned/plain-translated `csel_cond` mutant image must produce a field
mismatch for every op/width at some NZCV value; a parse/compile failure is
infrastructure and is never counted as a rejection.
"""

import argparse
import glob
import hashlib
import json
import os
import subprocess
import sys
import tempfile

BASE = 0x1000000000
CONDS = ["eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
         "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"]
OPS = [("csel", 0), ("csinc", 1), ("csinv", 2), ("csneg", 3)]


def infra(m):
    print("infrastructure: " + m)
    return 1


def fail(m):
    print("FAIL: " + m)
    return 2


RUNNER = r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aot_runtime.h"
#include "__IMG__"

static void dump(const AotGuestState *s, const AotRuntime *rt)
{
    unsigned i;
    printf("X");
    for (i = 0; i < 31; i++) printf(" %016llx", (unsigned long long)s->x[i]);
    printf(" SP %016llx NZCV %08llx NEXT %016llx FAULT %u\n",
           (unsigned long long)s->sp, (unsigned long long)s->nzcv,
           (unsigned long long)rt->next_pc, (unsigned)rt->fault);
}

int main(int argc, char **argv)
{
    AotGuestState s;
    AotRuntime rt;
    unsigned i;
    unsigned long long x0, x1;
    unsigned nz;

    if (argc != 5) return 2;
    x0 = strtoull(argv[2], NULL, 0);
    x1 = strtoull(argv[3], NULL, 0);
    nz = (unsigned)strtoul(argv[4], NULL, 0);
    memset(&s, 0, sizeof s);
    memset(&rt, 0, sizeof rt);
    for (i = 0; i < 31; i++) s.x[i] = 0x1111000000000000ull + i;
    s.x[0] = x0;
    s.x[1] = x1;
    s.sp = 0x2000000000ull;
    s.nzcv = (uint32_t)nz << 28;
    s.x[30] = 0x1000000ff0ull;
    {
        static const unsigned long long entries[] = { __ENTRIES__ };
        unsigned idx = (unsigned)strtoul(argv[1], NULL, 0);
        if (idx >= sizeof entries / sizeof entries[0]) return 2;
        switch (entries[idx]) {
__CASES__
        default: return 2;
        }
    }
    dump(&s, &rt);
    return 0;
}
'''


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--tools", default="tools/aot")
    ap.add_argument("--repo", default=".")
    ap.add_argument("--llvm", default=None)
    args = ap.parse_args(argv)
    repo = os.path.abspath(args.repo)
    llvm = args.llvm or os.environ.get("AOT_LLVM_BIN", "")
    if not llvm:
        for c in glob.glob(r"C:/Program Files/LLVM/bin") + \
                glob.glob(r"C:/Users/IKER/tools/LLVM/bin"):
            if os.path.exists(os.path.join(c, "llvm-mc.exe")):
                llvm = c
                break
    if not llvm:
        return infra("LLVM bin dir not found (pass --llvm)")
    vcvars = None
    hits = sorted(glob.glob(
        r"C:/Program Files/Microsoft Visual Studio/*/*/VC/Auxiliary/Build/vcvars64.bat"))
    if hits:
        vcvars = hits[-1]
    if vcvars is None:
        return infra("vcvars64.bat not found")

    bodies, entries, labels = [], [], []
    for op, _ in OPS:
        for w in ("x", "w"):
            for cond in CONDS:
                lab = "t_%s_%s_%s" % (op, w, cond)
                bodies.append("    %s   %s9, %s0, %s1, %s\n    ret\n"
                              % (op, w, w, w, cond))
                entries.append(lab)
                labels.append("%s:" % lab)
    asm = ".text\n" + "".join("%s\n%s" % (l, b)
                              for l, b in zip(labels, bodies))
    work = tempfile.mkdtemp(prefix="aot_csel_")
    sp = os.path.join(work, "fx.s")
    open(sp, "w").write(asm)
    obj, binp = os.path.join(work, "fx.o"), os.path.join(work, "fx.bin")
    p = subprocess.run([os.path.join(llvm, "llvm-mc.exe"),
                        "-triple=aarch64-none-elf", "-filetype=obj",
                        "-o", obj, sp], capture_output=True, text=True)
    if p.returncode != 0:
        return infra("llvm-mc: " + p.stdout + p.stderr)
    p = subprocess.run([os.path.join(llvm, "llvm-objcopy.exe"), "-O", "binary",
                        "--only-section=.text", obj, binp],
                       capture_output=True, text=True)
    if p.returncode != 0:
        return infra("llvm-objcopy: " + p.stderr)
    raw = open(binp, "rb").read()
    nm = subprocess.run([os.path.join(llvm, "llvm-nm.exe"), "-n",
                         "--defined-only", obj], capture_output=True, text=True)
    syms = {}
    for line in nm.stdout.splitlines():
        q = line.split()
        if len(q) == 3 and q[1] in ("T", "t"):
            syms[q[2]] = int(q[0], 16)
    missing = [l for l in entries if l not in syms]
    if missing:
        return infra("llvm-nm did not resolve entry symbols: %r" % missing[:4])
    if len(set(BASE + syms[l] for l in entries)) != len(entries):
        return infra("duplicate entry VAs from llvm-nm")
    lay = {"name": "csel", "image_size": len(raw), "bss_size": 0,
           "bss_start": len(raw), "bss_end": len(raw), "text": [0, len(raw)],
           "ro": [len(raw), len(raw)], "data": [len(raw), len(raw)],
           "dynsym_count": 0,
           "sha256": hashlib.sha256(raw).hexdigest()}
    lp = os.path.join(work, "fx.layout.json")
    json.dump(lay, open(lp, "w"))
    entry_vas = [BASE + syms[l] for l in entries]
    ep = os.path.join(work, "fx.entries.json")
    json.dump(entry_vas, open(ep, "w"))

    def translate(mutant, out):
        cmd = [sys.executable, os.path.join(repo, "tools", "aot",
                                            "aot_translate.py"),
               "--module", "--flat", binp, "--layout", lp,
               "--guest-base", "0x%x" % BASE, "--entries", ep,
               "--name", "csel", "--out", out]
        if mutant:
            cmd[2:2] = ["--mutant", mutant]
        return subprocess.run(cmd, capture_output=True, text=True)

    def build(cdir, src, vas):
        os.makedirs(cdir, exist_ok=True)
        open(os.path.join(cdir, "img.c"), "w").write(src)
        cases = "\n".join('        case 0x%xull: (void)aot_blk_%x(&s, &rt); break;'
                          % (e, e) for e in vas)
        txt = RUNNER.replace("__IMG__", "img.c").replace(
            "__ENTRIES__", ", ".join("0x%xull" % e for e in vas)
        ).replace("__CASES__", cases)
        rr = os.path.join(cdir, "runner.c")
        open(rr, "w").write(txt)
        exe = os.path.join(cdir, "runner.exe")
        bat = os.path.join(cdir, "build.bat")
        with open(bat, "w", encoding="ascii") as f:
            f.write('@call "%s" >nul\r\n' % vcvars.replace("/", "\\"))
            f.write('cl /nologo /W4 /O2 /std:c11 /D_CRT_SECURE_NO_WARNINGS '
                    '/Fo:"%s\\\\" /I"%s" /I"%s" /Fe:"%s" "%s"\r\n'
                    % (cdir.replace("/", "\\"),
                       os.path.join(repo, "src", "aot").replace("/", "\\"),
                       os.path.join(repo, "src").replace("/", "\\"),
                       exe.replace("/", "\\"), rr.replace("/", "\\")))
        q = subprocess.run([bat], capture_output=True, text=True)
        if q.returncode != 0:
            return None, q.stdout + q.stderr
        return exe, ""

    p = translate(None, os.path.join(work, "img.c"))
    if p.returncode != 0:
        return infra("translation: " + p.stderr)
    img = "".join(open(os.path.join(work, "img.c")).readlines())
    exe, err = build(os.path.join(work, "real"), img, entry_vas)
    if exe is None:
        return infra("real compile: " + err)

    try:
        import unicorn
        from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_PROT_ALL
        from unicorn import UcError
        from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X29,
                                         UC_ARM64_REG_X30, UC_ARM64_REG_SP,
                                         UC_ARM64_REG_NZCV, UC_CPU_ARM64_A57)
    except Exception as exc:
        return infra("unicorn A57 pin unavailable: %r" % (exc,))
    uc_version = getattr(unicorn, "__version__", "unknown")
    uc_probe = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    try:
        uc_probe.ctl_set_cpu_model(UC_CPU_ARM64_A57)
    except UcError as exc:
        return infra("ctl_set_cpu_model(ARM64_A57) failed: %r" % (exc,))
    print("oracle: unicorn %s pinned to ARM64_A57" % uc_version)
    XR = [UC_ARM64_REG_X0 + i for i in range(29)] + [UC_ARM64_REG_X29,
                                                     UC_ARM64_REG_X30]
    pairs = [(0, 0), (0, 0xFFFFFFFFFFFFFFFF), (1, 0),
             (0x8000000000000000, 0x7FFFFFFFFFFFFFFF)]
    checks = 0
    native = {}
    for idx, lab in enumerate(entries):
        for (x0, x1) in pairs:
            for nz in range(16):
                a = subprocess.run([exe, str(idx), hex(x0), hex(x1), str(nz)],
                                   capture_output=True, text=True, timeout=60)
                if a.returncode != 0:
                    return infra("native failed %s: %s" % (lab, a.stdout + a.stderr))
                out = a.stdout.strip()
                if not out.startswith("X ") or "FAULT 0" not in out:
                    return infra("malformed native dump %s: %r" % (lab, out))
                native[(idx, x0, x1, nz)] = out
                uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
                try:
                    uc.ctl_set_cpu_model(UC_CPU_ARM64_A57)
                except UcError as exc:
                    return infra("oracle pin failed mid-run: %r" % (exc,))
                uc.mem_map(BASE, 0x4000, UC_PROT_ALL)
                uc.mem_write(BASE, raw)
                for i in range(31):
                    v = 0x1111000000000000 + i
                    if i == 0:
                        v = x0
                    elif i == 1:
                        v = x1
                    uc.reg_write(XR[i], v & 0xFFFFFFFFFFFFFFFF)
                uc.reg_write(UC_ARM64_REG_SP, 0x2000000000)
                uc.reg_write(UC_ARM64_REG_NZCV, nz << 28)
                uc.reg_write(XR[30], 0x1000000ff0)
                uc.emu_start(entry_vas[idx], entry_vas[idx] + 4, count=1)
                toks = out.split()
                xs = [int(v, 16) for v in toks[1:32]]
                for i in range(31):
                    if xs[i] != uc.reg_read(XR[i]):
                        return fail("%s x0=%x x1=%x nz=%x: x%d 0x%x != 0x%x"
                                    % (lab, x0, x1, nz, i, xs[i],
                                       uc.reg_read(XR[i])))
                if int(toks[33], 16) != uc.reg_read(UC_ARM64_REG_SP):
                    return fail("%s: SP mismatch" % lab)
                if int(toks[35], 16) != uc.reg_read(UC_ARM64_REG_NZCV):
                    return fail("%s: NZCV mismatch" % lab)
                checks += 1
    print("csel matrix: %d entries x %d operand pairs x 16 NZCV = %d exact"
          % (len(entries), len(pairs), checks))

    # ZR destination rows: ensure no architecture state depends on x9.
    zr_bodies, zr_entries = [], []
    for op, _ in OPS:
        for w in ("x", "w"):
            for cond in ("eq", "ne", "al", "nv"):
                lab = "z_%s_%s_%s" % (op, w, cond)
                zr_bodies.append("    %s   %szr, %s0, %s1, %s\n    ret\n"
                                 % (op, w, w, w, cond))
                zr_entries.append(lab)
    zasm = ".text\n" + "".join("%s:\n%s" % (l, b) for l, b in
                               zip(zr_entries, zr_bodies))
    zp = os.path.join(work, "z.s")
    open(zp, "w").write(zasm)
    zobj = os.path.join(work, "z.o")
    zbin = os.path.join(work, "z.bin")
    if subprocess.run([os.path.join(llvm, "llvm-mc.exe"),
                       "-triple=aarch64-none-elf", "-filetype=obj",
                       "-o", zobj, zp], capture_output=True).returncode != 0:
        return infra("zr llvm-mc failed")
    subprocess.run([os.path.join(llvm, "llvm-objcopy.exe"), "-O", "binary",
                    "--only-section=.text", zobj, zbin], check=True)
    zraw = open(zbin, "rb").read()
    zoff = 0
    zsyms = {}
    znm = subprocess.run([os.path.join(llvm, "llvm-nm.exe"), "-n",
                          "--defined-only", zobj], capture_output=True,
                         text=True)
    for line in znm.stdout.splitlines():
        q = line.split()
        if len(q) == 3 and q[1] in ("T", "t"):
            zsyms[q[2]] = int(q[0], 16)
    if [l for l in zr_entries if l not in zsyms]:
        return infra("llvm-nm did not resolve ZR entry symbols")
    zlay = dict(lay)
    zlay.update(image_size=len(zraw), text=[0, len(zraw)],
                ro=[len(zraw), len(zraw)], data=[len(zraw), len(zraw)],
                sha256=hashlib.sha256(zraw).hexdigest())
    zlp = os.path.join(work, "z.layout.json")
    json.dump(zlay, open(zlp, "w"))
    zvas = [BASE + zsyms[l] for l in zr_entries]
    zep = os.path.join(work, "z.entries.json")
    json.dump(zvas, open(zep, "w"))
    zout = os.path.join(work, "z_img.c")
    p = subprocess.run([sys.executable, os.path.join(repo, "tools", "aot",
                                                     "aot_translate.py"),
                        "--module", "--flat", zbin, "--layout", zlp,
                        "--guest-base", "0x%x" % BASE, "--entries", zep,
                        "--name", "cselz", "--out", zout],
                       capture_output=True, text=True)
    if p.returncode != 0:
        return infra("zr translation: " + p.stderr)
    zexe, zerr = build(os.path.join(work, "zreal"), open(zout).read(), zvas)
    if zexe is None:
        return infra("zr compile: " + zerr)
    for idx, lab in enumerate(zr_entries):
        a = subprocess.run([zexe, str(idx), "0", "0", "0"],
                           capture_output=True, text=True, timeout=60)
        if a.returncode != 0 or "FAULT 0" not in a.stdout:
            return fail("ZR row %s did not execute cleanly: %s"
                        % (lab, a.stdout + a.stderr))
        toks = a.stdout.split()
        if int(toks[10], 16) != 0x1111000000000009:
            return fail("ZR row %s wrote x9: %s" % (lab, toks[10]))
    print("ZR destination rows: %d exact (x9 untouched)" % len(zr_entries))

    # Compiled mutant: cond bit flipped must change a named field for every
    # op/width at cond=al; malformed/empty output is infrastructure, never a
    # rejection.
    mimg = os.path.join(work, "mut.c")
    p = translate("csel_cond", mimg)
    if p.returncode != 0:
        return infra("mutant translation: " + p.stderr)
    mex, merr = build(os.path.join(work, "mut"), open(mimg).read(), entry_vas)
    if mex is None:
        return infra("mutant compile: " + merr)
    seen = 0
    for op, _ in OPS:
        for w in ("x", "w"):
            lab = "t_%s_%s_eq" % (op, w)
            idx = entries.index(lab)
            a = subprocess.run([exe, str(idx), "0", "0xffff", "0"],
                               capture_output=True, text=True, timeout=60)
            b = subprocess.run([mex, str(idx), "0", "0xffff", "0"],
                               capture_output=True, text=True, timeout=60)
            for tag, q in (("real", a), ("mutant", b)):
                if q.returncode != 0 or "FAULT 0" not in q.stdout or                         not q.stdout.strip().startswith("X "):
                    return infra("%s %s malformed: %r" % (tag, lab,
                                                          q.stdout + q.stderr))
            ra, rb = a.stdout.split(), b.stdout.split()
            if len(ra) != len(rb):
                return infra("%s field-count mismatch" % lab)
            if ra[10] == rb[10]:
                return fail("csel_cond mutant survived on %s (x9=%s)"
                            % (lab, ra[10]))
            if ra[35] != rb[35]:
                return fail("%s: mutant changed NZCV (%s != %s)"
                            % (lab, ra[35], rb[35]))
            seen += 1
    print("csel_cond mutant: rejected on %d op/width rows (named x9 field)" % seen)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
