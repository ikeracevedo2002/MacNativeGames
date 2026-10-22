#!/usr/bin/env python3
"""Bitfield differential: generated C helper vs Unicorn A57.

Covers every valid (immr, imms) geometry for SBFM/UBFM/BFM in both register
widths, with random source/destination values.  The C text is taken from the
translator's helper table, so this tests the code that generated images use,
not a re-implementation.

Exit 0 pass, 2 semantic mismatch, 1 infrastructure.
"""

import argparse
import glob
import os
import random
import subprocess
import sys
import tempfile

FAILS = []


def fail(msg):
    FAILS.append(msg)
    print("FAIL: " + msg)


def find_cl():
    pats = [
        r"C:/Program Files/Microsoft Visual Studio/*/*/VC/Tools/MSVC/*/bin/Hostx64/x64/cl.exe",
        r"C:/Program Files (x86)/Microsoft Visual Studio/*/*/VC/Tools/MSVC/*/bin/Hostx64/x64/cl.exe",
    ]
    for pat in pats:
        hits = sorted(glob.glob(pat))
        if hits:
            return hits[-1]
    return None


def enc_bfm(sf, opc, immr, imms, rn, rd):
    n = 1 if sf else 0
    return ((sf << 31) | (opc << 29) | (0x26 << 23) | (n << 22) |
            (immr << 16) | (imms << 10) | (rn << 5) | rd)


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--tools", default="tools/aot")
    ap.add_argument("--seed", default="0xB17F1E1D")
    ap.add_argument("--per-geometry", type=int, default=1)
    args = ap.parse_args(argv)

    sys.path.insert(0, args.tools)
    import aot_translate as T
    try:
        from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_PROT_ALL
        from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                                         UC_ARM64_REG_X2)
    except Exception as exc:                                # pragma: no cover
        print("infrastructure: unicorn unavailable: %r" % exc)
        return 1
    cl = find_cl()
    if cl is None:                                          # pragma: no cover
        print("infrastructure: cl.exe not found")
        return 1
    vhits = sorted(glob.glob(
        r"C:/Program Files/Microsoft Visual Studio/*/*/VC/Auxiliary/Build/vcvars64.bat"))
    if not vhits:
        print("infrastructure: vcvars64.bat not found")
        return 1
    vcvars = vhits[-1]

    rng = random.Random(int(args.seed, 0))
    cases = []
    for sf, width in ((0, 32), (1, 64)):
        for immr in range(width):
            for imms in range(width):
                for opc in (0, 1, 2):
                    for _ in range(args.per_geometry):
                        src = rng.getrandbits(width)
                        dst = rng.getrandbits(width)
                        cases.append((width, immr, imms, opc, src, dst))

    csrc = ['#include <stdio.h>', '#include <stdint.h>',
            T._HELPERS["aot_bfm"],
            'int main(void) {',
            '    unsigned w, immr, imms, op;',
            '    unsigned long long src, dst;',
            '    while (scanf("%u %u %u %u %llu %llu", &w, &immr, &imms, &op,',
            '                 &src, &dst) == 6) {',
            '        printf("%llu\\n", (unsigned long long)aot_bfm(',
            '            (uint64_t)src, (uint64_t)dst, w, immr, imms, op));',
            '    }',
            '    return 0;',
            '}']
    work = tempfile.mkdtemp(prefix="aot_bfm_")
    cpath = os.path.join(work, "bfm.c")
    exe = os.path.join(work, "bfm.exe")
    with open(cpath, "w", encoding="utf-8") as f:
        f.write("\n".join(csrc) + "\n")
    bat = os.path.join(work, "build.bat")
    with open(bat, "w", encoding="ascii") as f:
        f.write('@call "' + vcvars.replace("/", chr(92)) + '" >nul' + chr(13) + chr(10))
        f.write('"' + cl.replace("/", chr(92)) + '" /nologo /O2 /W3 /Fo:"'
                + os.path.join(work, "bfm.obj").replace("/", chr(92))
                + '" /Fe:"' + exe.replace("/", chr(92)) + '" "'
                + cpath.replace("/", chr(92)) + '"' + chr(13) + chr(10))
    sub = subprocess.run([bat], capture_output=True, text=True)
    if sub.returncode != 0:
        print(sub.stdout)
        print(sub.stderr)
        print("infrastructure: cl failed")
        return 1

    inp = "".join("%u %u %u %u %u %u\n" % c for c in cases)
    sub = subprocess.run([exe], input=inp, capture_output=True, text=True)
    if sub.returncode != 0:
        print("infrastructure: helper program failed")
        return 1
    got = [int(x) for x in sub.stdout.split()]
    if len(got) != len(cases):
        print("infrastructure: %d results for %d cases" % (len(got), len(cases)))
        return 1

    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    base = 0x1000
    uc.mem_map(base & ~0xFFF, 0x2000, UC_PROT_ALL)
    bad = 0
    for idx, (width, immr, imms, opc, src, dst) in enumerate(cases):
        word = enc_bfm(1 if width == 64 else 0, opc, immr, imms, 0, 2)
        uc.mem_write(base, word.to_bytes(4, "little"))
        uc.reg_write(UC_ARM64_REG_X0, src)
        uc.reg_write(UC_ARM64_REG_X1, dst)
        uc.reg_write(UC_ARM64_REG_X2, dst)
        uc.emu_start(base, base + 4, count=1)
        want = uc.reg_read(UC_ARM64_REG_X2)
        if width == 32:
            want &= 0xFFFFFFFF
        if want != got[idx]:
            bad += 1
            if bad <= 10:
                fail("w=%d immr=%d imms=%d op=%d src=0x%x dst=0x%x: "
                     "unicorn 0x%x != C helper 0x%x"
                     % (width, immr, imms, opc, src, dst, want, got[idx]))
    print("bitfield differential: %d cases, %d mismatch(es)" % (len(cases), bad))
    return 0 if not FAILS else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
