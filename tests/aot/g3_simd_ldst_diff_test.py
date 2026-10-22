#!/usr/bin/env python3
"""Module-only SIMD&FP MEMORY bit transfers (LDR/STR S/D/Q, unsigned offset).

Emitted C blocks are compiled by cl and called natively. The full raw vector
file V0..V31 (2 x 64-bit lanes), FPCR, FPSR, SP, NZCV, NEXT and the 4096-byte
data page are compared field-exactly with a pinned Unicorn A57. This is a
BIT-transfer test: FPCR is deliberately set to an unsupported numeric mode
and must not be read, masked or changed; V31 is a real vector register.

The fault row pins a straddling Q load: typed MEMORY fault with exact
src/target/status BEFORE any V write, full state and page bytes unchanged.

Compiled mutants (simd_upper_clear, simd_v31_discard, simd_offset_scale) must
mismatch their expected named fields; malformed/empty output is infrastructure,
never a rejected mutant.
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
DATA = 0x3000000000
STACK = 0x2000000000
PAGE = 0x1000
LR = 0x1000000FF0

ASM = r'''
.text
.global t_s
t_s:    ldr  s0, [x20]
        str  s1, [x20, #4]
        ldr  s2, [x20, #8]
        ldr  s31, [x20, #12]
        str  s31, [x20, #16]
        ret
.global t_d
t_d:    ldr  d0, [x20]
        str  d1, [x20, #8]
        ldr  d31, [x20, #16]
        str  d31, [x20, #24]
        ret
.global t_q
t_q:    ldr  q0, [x20]
        str  q1, [x20, #16]
        ldr  q31, [x20, #32]
        str  q31, [x20, #48]
        ret
.global t_fault
t_fault: ldr q0, [x20]
        ret
'''

RUNNER = r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "aot_runtime.h"
#include "__IMG__"

#define DATA_BASE 0x3000000000ull
#define STACK_BASE 0x2000000000ull
static uint8_t g_page[0x1000];
#define GUARD(a,n) ((a) >= DATA_BASE && (a) + (n) <= DATA_BASE + sizeof g_page)

AotMemStatus aot_mem_ld32(const AotMem *m, uint64_t a, uint32_t *o)
{ (void)m; if (!GUARD(a,4)) return AOT_MEM_ERR_RANGE; memcpy(o,g_page+(a-DATA_BASE),4); return AOT_MEM_OK; }
AotMemStatus aot_mem_ld64(const AotMem *m, uint64_t a, uint64_t *o)
{ (void)m; if (!GUARD(a,8)) return AOT_MEM_ERR_RANGE; memcpy(o,g_page+(a-DATA_BASE),8); return AOT_MEM_OK; }
AotMemStatus aot_mem_ld128(const AotMem *m, uint64_t a, uint64_t o[2])
{ (void)m; if (!GUARD(a,16)) return AOT_MEM_ERR_RANGE; memcpy(o,g_page+(a-DATA_BASE),16); return AOT_MEM_OK; }
AotMemStatus aot_mem_st32(AotMem *m, uint64_t a, uint32_t v)
{ (void)m; if (!GUARD(a,4)) return AOT_MEM_ERR_RANGE; memcpy(g_page+(a-DATA_BASE),&v,4); return AOT_MEM_OK; }
AotMemStatus aot_mem_st64(AotMem *m, uint64_t a, uint64_t v)
{ (void)m; if (!GUARD(a,8)) return AOT_MEM_ERR_RANGE; memcpy(g_page+(a-DATA_BASE),&v,8); return AOT_MEM_OK; }
AotMemStatus aot_mem_st128(AotMem *m, uint64_t a, const uint64_t v[2])
{ (void)m; if (!GUARD(a,16)) return AOT_MEM_ERR_RANGE; memcpy(g_page+(a-DATA_BASE),v,16); return AOT_MEM_OK; }

static void dump(const AotGuestState *s, const AotRuntime *rt)
{
    unsigned i;
    printf("V");
    for (i = 0; i < 32; i++)
        printf(" %016llx %016llx", (unsigned long long)s->v[i][0],
               (unsigned long long)s->v[i][1]);
    printf(" FPCR %08x FPSR %08x X", (unsigned)s->fpcr, (unsigned)s->fpsr);
    for (i = 0; i < 31; i++) printf(" %016llx", (unsigned long long)s->x[i]);
    printf(" SP %016llx NZCV %08llx NEXT %016llx FAULT %u SRC %016llx "
           "TARGET %016llx STATUS %lld BYTES ",
           (unsigned long long)s->sp, (unsigned long long)s->nzcv,
           (unsigned long long)rt->next_pc, (unsigned)rt->fault,
           (unsigned long long)rt->fault_src,
           (unsigned long long)rt->fault_target,
           (long long)rt->fault_status);
    for (i = 0; i < sizeof g_page; i++) printf("%02x", g_page[i]);
    printf("\n");
}

int main(int argc, char **argv)
{
    AotGuestState s;
    AotRuntime rt;
    unsigned i, idx;
    unsigned long long seed;
    if (argc != 3 && argc != 4) return 2;
    idx = (unsigned)strtoul(argv[1], NULL, 0);
    seed = strtoull(argv[2], NULL, 0);
    memset(&s, 0, sizeof s);
    memset(&rt, 0, sizeof rt);
    for (i = 0; i < 32; i++) {
        s.v[i][0] = 0x0101010101010101ull * (i + 1) ^ seed;
        s.v[i][1] = 0x1111000000000000ull + i ^ (seed << 1);
    }
    /* D012-legal numeric mode: DN+FZ set, RN rounding, FPSR=0x10. Bit
     * transfers must neither read nor change either register. */
    s.fpcr = 0x03000000u;
    s.fpsr = 0x00000010u;
    if (argc == 4) {           /* NATIVE-only all-ones FPCR/FPSR row */
        s.fpcr = (uint32_t)strtoul(argv[3], NULL, 0);
        s.fpsr = (uint32_t)strtoul(argv[3], NULL, 0);
    }
    for (i = 0; i < 31; i++)
        s.x[i] = 0x0101010101010101ull * (i + 1) ^ seed;
    s.x[30] = 0x1000000ff0ull;
    s.sp = STACK_BASE + 0x800;
    s.nzcv = (uint32_t)((0xA0000000u ^ (unsigned)seed) & 0xF0000000u);
    for (i = 0; i < sizeof g_page; i++) g_page[i] = (uint8_t)(i * 7u + 3u);
    s.x[20] = (idx == 3u) ? DATA_BASE + 0xFF8ull : DATA_BASE + 0x80ull;
    {
        static const unsigned long long entries[] = { __ENTRIES__ };
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


def fail(m):
    print("FAIL: " + m)
    return 2


def infra(m):
    print("infrastructure: " + m)
    return 1


def parse_dump(text):
    toks = text.strip().split()
    # 1 "V" + 64 lanes + FPCR/val FPSR/val + "X" + 31 GPRs + SP/NZCV/NEXT/
    # FAULT/SRC/TARGET/STATUS/BYTES label+value pairs = 117 tokens.
    if len(toks) != 117 or toks[0] != "V":
        return None
    try:
        d = {}
        for i in range(32):
            d["v%d.0" % i] = int(toks[1 + 2 * i], 16)
            d["v%d.1" % i] = int(toks[2 + 2 * i], 16)
        d["FPCR"] = int(toks[66], 16)
        d["FPSR"] = int(toks[68], 16)
        if toks[69] != "X":
            return None
        for i in range(31):
            d["x%d" % i] = int(toks[70 + i], 16)
        d["SP"] = int(toks[102], 16)
        d["NZCV"] = int(toks[104], 16)
        d["NEXT"] = int(toks[106], 16)
        d["FAULT"] = int(toks[108])
        d["SRC"] = int(toks[110], 16)
        d["TARGET"] = int(toks[112], 16)
        d["STATUS"] = int(toks[114])
        d["BYTES"] = toks[116].lower()
        if len(d["BYTES"]) != PAGE * 2:
            return None
        bytes.fromhex(d["BYTES"])
        return d
    except (ValueError, IndexError):
        return None


def page_pattern():
    return bytes((i * 7 + 3) & 0xFF for i in range(PAGE))


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--tools", default="tools/aot")
    ap.add_argument("--repo", default=".")
    ap.add_argument("--llvm", default=None)
    args = ap.parse_args(argv)
    repo = os.path.abspath(args.repo)
    llvm = args.llvm or os.environ.get("AOT_LLVM_BIN", "")
    if not llvm:
        for c in (glob.glob(r"C:/Program Files/LLVM/bin") +
                  glob.glob(os.path.expanduser("~/tools/LLVM/bin"))):
            if os.path.exists(os.path.join(c, "llvm-mc.exe")):
                llvm = c
                break
    if not llvm:
        return infra("LLVM bin dir not found (pass --llvm)")
    vhits = sorted(glob.glob(
        r"C:/Program Files/Microsoft Visual Studio/*/*/VC/Auxiliary/Build/vcvars64.bat"))
    if not vhits:
        return infra("vcvars64.bat not found")
    vcvars = vhits[-1]

    work = tempfile.mkdtemp(prefix="aot_simd_")
    sp = os.path.join(work, "fx.s")
    open(sp, "w").write(ASM)
    obj = os.path.join(work, "fx.o")
    binp = os.path.join(work, "fx.bin")
    mc = subprocess.run([os.path.join(llvm, "llvm-mc.exe"),
                         "-triple=aarch64-none-elf", "-filetype=obj",
                         "-o", obj, sp], capture_output=True, text=True)
    if mc.returncode != 0:
        return infra("llvm-mc: " + mc.stdout + mc.stderr)
    if subprocess.run([os.path.join(llvm, "llvm-objcopy.exe"), "-O", "binary",
                       "--only-section=.text", obj, binp],
                      capture_output=True).returncode != 0:
        return infra("llvm-objcopy failed")
    raw = open(binp, "rb").read()
    nm = subprocess.run([os.path.join(llvm, "llvm-nm.exe"), "-n",
                         "--defined-only", obj], capture_output=True, text=True)
    syms = {}
    for line in nm.stdout.splitlines():
        q = line.split()
        if len(q) == 3 and q[1] in ("T", "t"):
            syms[q[2]] = int(q[0], 16)
    need = ["t_s", "t_d", "t_q", "t_fault"]
    if [n for n in need if n not in syms]:
        return infra("llvm-nm did not resolve entries")
    lay = {"name": "simd", "image_size": len(raw), "bss_size": 0,
           "bss_start": len(raw), "bss_end": len(raw), "text": [0, len(raw)],
           "ro": [len(raw), len(raw)], "data": [len(raw), len(raw)],
           "dynsym_count": 0, "sha256": hashlib.sha256(raw).hexdigest()}
    lp = os.path.join(work, "fx.layout.json")
    json.dump(lay, open(lp, "w"))
    vas = [BASE + syms[n] for n in need]
    ep = os.path.join(work, "fx.entries.json")
    json.dump(vas, open(ep, "w"))

    def translate(mutant, out):
        cmd = [sys.executable, os.path.join(repo, "tools", "aot",
                                            "aot_translate.py"),
               "--module", "--flat", binp, "--layout", lp,
               "--guest-base", "0x%x" % BASE, "--entries", ep,
               "--name", "simd", "--out", out]
        if mutant:
            cmd[2:2] = ["--mutant", mutant]
        return subprocess.run(cmd, capture_output=True, text=True)

    def build(cdir, src):
        os.makedirs(cdir, exist_ok=True)
        open(os.path.join(cdir, "img.c"), "w").write(src)
        cases = "\n".join(
            '        case 0x%xull: (void)aot_blk_%x(&s, &rt); break;' % (v, v)
            for v in vas)
        runner = RUNNER.replace("__IMG__", "img.c").replace(
            "__ENTRIES__", ", ".join("0x%xull" % v for v in vas)).replace(
            "__CASES__", cases)
        rr = os.path.join(cdir, "runner.c")
        open(rr, "w").write(runner)
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
        cp = subprocess.run([bat], capture_output=True, text=True)
        if cp.returncode != 0:
            return None, cp.stdout + cp.stderr
        return exe, ""

    img = os.path.join(work, "img.c")
    p = translate(None, img)
    if p.returncode != 0:
        return infra("translation: " + p.stderr)
    exe, err = build(os.path.join(work, "real"), open(img).read())
    if exe is None:
        return infra("compile: " + err)

    try:
        import unicorn
        from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM, \
            UC_PROT_ALL
        from unicorn.arm64_const import (
            UC_ARM64_REG_X0, UC_ARM64_REG_X29, UC_ARM64_REG_X30,
            UC_ARM64_REG_SP, UC_ARM64_REG_NZCV, UC_ARM64_REG_Q0,
            UC_ARM64_REG_FPCR, UC_ARM64_REG_FPSR, UC_CPU_ARM64_A57)
    except Exception as exc:
        return infra("unicorn unavailable: %r" % (exc,))
    probe = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    try:
        probe.ctl_set_cpu_model(UC_CPU_ARM64_A57)
    except UcError as exc:
        return infra("A57 pin failed: %r" % (exc,))
    print("oracle: unicorn %s pinned to ARM64_A57"
          % getattr(unicorn, "__version__", "unknown"))
    XR = [UC_ARM64_REG_X0 + i for i in range(29)] + [UC_ARM64_REG_X29,
                                                     UC_ARM64_REG_X30]
    counts = {"t_s": 6, "t_d": 5, "t_q": 5, "t_fault": 1}
    seeds = [0, 0x5A5A5A5A, 0x8000000000000000, 0x7FFFFFFFFFFFFFFF]
    results = {}

    def ucq(uc, i):
        v = uc.reg_read(UC_ARM64_REG_Q0 + i)
        return int.from_bytes(v, "little") if isinstance(v, bytes) else v

    for idx, name in enumerate(need):
        for seed in (seeds if name != "t_fault" else [0]):
            r = subprocess.run([exe, str(idx), "0x%x" % seed],
                               capture_output=True, text=True, timeout=60)
            if r.returncode != 0:
                return infra("%s runner failed: %s" % (name, r.stdout + r.stderr))
            d = parse_dump(r.stdout)
            if d is None:
                return infra("%s malformed dump %r" % (name, r.stdout))
            results[(name, seed)] = d
            uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
            try:
                uc.ctl_set_cpu_model(UC_CPU_ARM64_A57)
            except UcError as exc:
                return infra("pin mid-run: %r" % (exc,))
            uc.mem_map(BASE, 0x4000, UC_PROT_ALL)
            uc.mem_write(BASE, raw)
            uc.mem_map(DATA, PAGE, UC_PROT_ALL)
            uc.mem_write(DATA, page_pattern())
            for i in range(32):
                lo = (0x0101010101010101 * (i + 1)) ^ seed
                hi = (0x1111000000000000 + i) ^ ((seed << 1) & 0xFFFFFFFFFFFFFFFF)
                uc.reg_write(UC_ARM64_REG_Q0 + i,
                             int.from_bytes(lo.to_bytes(8, "little") +
                                            hi.to_bytes(8, "little"),
                                            "little"))
            for i in range(31):
                uc.reg_write(XR[i], (0x0101010101010101 * (i + 1)) ^ seed)
            uc.reg_write(UC_ARM64_REG_X30, LR)
            uc.reg_write(UC_ARM64_REG_SP, STACK + 0x800)
            uc.reg_write(UC_ARM64_REG_NZCV, (0xA0000000 ^ seed) & 0xF0000000)
            uc.reg_write(UC_ARM64_REG_FPCR, 0x03000000)
            uc.reg_write(UC_ARM64_REG_FPSR, 0x10)
            uc.reg_write(XR[20], DATA + (0xFF8 if name == "t_fault" else 0x80))
            fault = None
            try:
                uc.emu_start(vas[idx], vas[idx] + 4 * counts[name],
                             count=counts[name])
            except UcError as exc:
                fault = exc.errno
            if name == "t_fault":
                if fault is None:
                    return fail("t_fault: unicorn did not fault")
                if d["FAULT"] != 3 or d["SRC"] != vas[idx] or \
                        d["TARGET"] != DATA + 0xFF8 or d["STATUS"] != 1 or \
                        d["NEXT"] != DATA + 0xFF8:
                    return fail("t_fault typed fields: %r" % d)
                for i in range(32):
                    lo = (0x0101010101010101 * (i + 1)) ^ seed
                    hi = (0x1111000000000000 + i) ^ ((seed << 1) & 0xFFFFFFFFFFFFFFFF)
                    if d["v%d.0" % i] != lo or d["v%d.1" % i] != hi:
                        return fail("t_fault: V%d changed before fault" % i)
                if d["FPCR"] != 0x03000000 or d["FPSR"] != 0x10:
                    return fail("t_fault: FPCR/FPSR changed")
                for i in range(31):
                    want = (0x0101010101010101 * (i + 1)) ^ seed
                    if i == 20:
                        want = DATA + 0xFF8
                    elif i == 30:
                        want = LR
                    if d["x%d" % i] != want:
                        return fail("t_fault: x%d 0x%x != 0x%x"
                                    % (i, d["x%d" % i], want))
                if d["SP"] != STACK + 0x800 or d["NZCV"] !=                         ((0xA0000000 ^ seed) & 0xF0000000):
                    return fail("t_fault: SP/NZCV changed")
                if d["BYTES"] != page_pattern().hex():
                    return fail("t_fault: page changed")
                continue
            if fault is not None:
                return fail("%s: unexpected Unicorn exception %r" % (name, fault))
            for i in range(32):
                if d["v%d.0" % i] != (ucq(uc, i) & 0xFFFFFFFFFFFFFFFF) or \
                        d["v%d.1" % i] != (ucq(uc, i) >> 64):
                    return fail("%s seed %x: V%d raw mismatch 0x%016x%016x != "
                                "0x%032x" % (name, seed, i, d["v%d.1" % i],
                                             d["v%d.0" % i], ucq(uc, i)))
            for i in range(31):
                if d["x%d" % i] != uc.reg_read(XR[i]):
                    return fail("%s seed %x: x%d native 0x%x != unicorn 0x%x"
                                % (name, seed, i, d["x%d" % i],
                                   uc.reg_read(XR[i])))
            if d["SP"] != uc.reg_read(UC_ARM64_REG_SP):
                return fail("%s: SP differs from oracle" % name)
            if d["NZCV"] != uc.reg_read(UC_ARM64_REG_NZCV):
                return fail("%s: NZCV differs from oracle" % name)
            if d["FPCR"] != uc.reg_read(UC_ARM64_REG_FPCR) or                     d["FPSR"] != uc.reg_read(UC_ARM64_REG_FPSR):
                return fail("%s: raw FPCR/FPSR 0x%x/0x%x != oracle 0x%x/0x%x"
                            % (name, d["FPCR"], d["FPSR"],
                               uc.reg_read(UC_ARM64_REG_FPCR),
                               uc.reg_read(UC_ARM64_REG_FPSR)))
            if d["NEXT"] != LR:
                return fail("%s: NEXT 0x%x != LR" % (name, d["NEXT"]))
            if d["BYTES"] != bytes(uc.mem_read(DATA, PAGE)).hex():
                return fail("%s seed %x: page bytes differ" % (name, seed))
            if d["FAULT"] != 0:
                return fail("%s seed %x: unexpected fault %d"
                            % (name, seed, d["FAULT"]))
    print("SIMD&FP memory bit transfers: %d scenarios exact (raw V0..V31, "
          "FPCR, FPSR, page)" % len(results))

    # NATIVE-only row: FPCR/FPSR = 0xffffffff (unsupported numeric bits and
    # signalling-NaN payloads in the loaded/stored data) must remain
    # bit-identical. Unicorn masks those bits, so this row is deliberately NOT
    # an A57 differential claim; it follows the G2 bitwise low-32 ABI policy.
    native_ones = {}
    for idx, name in enumerate(need):
        if name == "t_fault":
            continue
        for seed in seeds:
            r = subprocess.run([exe, str(idx), "0x%x" % seed, "0xffffffff"],
                               capture_output=True, text=True, timeout=60)
            if r.returncode != 0:
                return infra("all-ones native runner failed: %s"
                             % (r.stdout + r.stderr))
            d = parse_dump(r.stdout)
            if d is None:
                return infra("all-ones native dump malformed: %r" % r.stdout)
            legal = results[(name, seed)]
            if d["FPCR"] != 0xFFFFFFFF or d["FPSR"] != 0xFFFFFFFF:
                return fail("all-ones row: FPCR/FPSR changed to 0x%x/0x%x"
                            % (d["FPCR"], d["FPSR"]))
            for f in d:
                if f in ("FPCR", "FPSR"):
                    continue
                if d[f] != legal[f]:
                    return fail("all-ones row changed %s on %s seed %x"
                                % (f, name, seed))
            native_ones[(name, seed)] = d
    print("native-only all-ones FPCR/FPSR row: %d rows bit-identical "
          "(no numeric guard, no quieting, no IOC)" % len(native_ones))

    expected = {"simd_upper_clear": {"v0.1", "v2.1", "v31.1"},
                "simd_v31_discard": {"v31.0", "v31.1"},
                "simd_offset_scale": {"v2.0"}}
    for mutant in ("simd_upper_clear", "simd_v31_discard",
                   "simd_offset_scale"):
        mimg = os.path.join(work, "mut_%s.c" % mutant)
        p = translate(mutant, mimg)
        if p.returncode != 0:
            return infra("mutant %s translation: %s" % (mutant, p.stderr))
        mex, merr = build(os.path.join(work, "mut_" + mutant),
                          open(mimg).read())
        if mex is None:
            return infra("mutant %s compile: %s" % (mutant, merr))
        differed = set()
        for idx, name in enumerate(need):
            for seed in (seeds if name != "t_fault" else [0]):
                r = subprocess.run([mex, str(idx), "0x%x" % seed],
                                   capture_output=True, text=True, timeout=60)
                if r.returncode != 0:
                    return infra("mutant %s runner: %s"
                                 % (mutant, r.stdout + r.stderr))
                md = parse_dump(r.stdout)
                if md is None:
                    return infra("mutant %s malformed dump (never a rejection)"
                                 % mutant)
                real = results[(name, seed)]
                for f in real:
                    if md[f] != real[f]:
                        differed.add(f)
        want = expected[mutant]
        if not (differed & want):
            return fail("mutant %s SURVIVED (expected %r, differed %r)"
                        % (mutant, sorted(want), sorted(differed)))
        print("mutant %s rejected on named field(s) %r"
              % (mutant, sorted(differed & want)))
    print("SIMD&FP ldst suite PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
