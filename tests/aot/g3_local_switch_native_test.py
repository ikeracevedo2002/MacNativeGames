#!/usr/bin/env python3
"""Native + Unicorn differential probe for the D022 local-switch guard.

DEV PROBE ONLY: it embeds the fixture flat image in a real `aot_mem` arena and
direct-calls the translated basic-block functions through the emitted
`AotBlockEntry` table, bounded to 64 blocks.  This is NOT a production runtime
fallback, NOT an ARM decoder and NOT a Program/RO-host-protection test.

Steps:
  1. build the generic N=5 fixture with `g3_local_switch_test.build()`;
  2. close the CFG with the real `aot_translate.module_cfg()` (verified proof);
  3. emit the ACTUAL generated C with the real emitter for four variants:
     baseline guard, no guard, count-off-by-one (one extra allowed target),
     targets-only-first;
  4. compile each variant /W4 /WX /O2 with MSVC (aot_mem.c + aot_as.c +
     host_vm.c; no runtime.c/HLE needed), run the native dev probe;
  5. compare every normal run (idx 0..N and the out-of-bound default) against
     an independent Unicorn 2.1.4 A57 oracle on the SAME raw ARM words, and
     assert the discriminative guard semantics.

Exit: 0 = pass, 1 = semantic mismatch, 2 = infrastructure/setup failure.
Everything is written under the system temp directory, never the repo.
"""

import argparse
import glob
import hashlib
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_REPO = os.path.dirname(os.path.dirname(HERE))


def infra(msg):
    sys.stdout.write("INFRA: %s\n" % msg)
    return 2


def fail(msg):
    sys.stdout.write("FAIL: %s\n" % msg)
    return 1


def fnv64(data):
    h = 0xCBF29CE484222325
    for b in data:
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


WRAPPER = r"""
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aot_runtime.h"
#include "aot_mem.h"
#include "img_%(name)s.c"

extern uint8_t g_raw[];
extern const uint64_t g_raw_size;

static AotBlockFn block_at(uint64_t pc) {
    size_t i;
    for (i = 0; i < aot_image_%(name)s.block_count; ++i) {
        if (aot_image_%(name)s.blocks[i].entry_pc == pc)
            return aot_image_%(name)s.blocks[i].fn;
    }
    return NULL;
}

static uint64_t fnv64(const uint8_t *p, size_t n) {
    uint64_t h = 0xCBF29CE484222325ull;
    size_t i;
    for (i = 0; i < n; ++i) {
        h ^= p[i];
        h *= 0x00000100000001B3ull;
    }
    return h;
}

static void dump(const char *tag, AotGuestState *s, AotRuntime *rt) {
    unsigned i;
    printf("%%s exit=%%u next=0x%%llx site=0x%%llx fault=%%u "
           "fsrc=0x%%llx ftgt=0x%%llx fstat=%%lld\n", tag,
           (unsigned)rt->reason, (unsigned long long)rt->next_pc,
           (unsigned long long)rt->site_pc, (unsigned)rt->fault,
           (unsigned long long)rt->fault_src,
           (unsigned long long)rt->fault_target,
           (long long)rt->fault_status);
    printf("%%s gpr=", tag);
    for (i = 0; i < 31u; ++i)
        printf("%%llx,", (unsigned long long)s->x[i]);
    printf(" sp=%%llx nzcv=%%llx\n", (unsigned long long)s->sp,
           (unsigned long long)s->nzcv);
    printf("%%s memfnv=%%016llx\n", tag,
           (unsigned long long)fnv64(g_raw, (size_t)g_raw_size));
}

int main(int argc, char **argv) {
    AotMemDomain *dom;
    AotMem mem;
    AotRuntime rt;
    AotGuestState s;
    AotMemStatus ms;
    uint32_t tok;
    unsigned i;
    int rc = 0;
    if (argc < 3) { fprintf(stderr, "usage: probe run|bypass <val>\n"); return 2; }
    dom = aot_mem_domain_create();
    if (dom == NULL) { fprintf(stderr, "domain_create failed\n"); return 2; }
    ms = aot_mem_init(&mem, dom, g_raw, g_raw_size, 0x%(gbase)xull);
    if (ms != AOT_MEM_OK) {
        fprintf(stderr, "aot_mem_init failed %%d\n", (int)ms);
        aot_mem_domain_destroy(dom);
        return 2;
    }
    tok = aot_mem_domain_attach(dom);
    if (tok == 0u) {
        fprintf(stderr, "aot_mem_domain_attach failed\n");
        aot_mem_domain_destroy(dom);
        return 2;
    }
    memset(&rt, 0, sizeof rt);
    rt.mem = mem;
    rt.monitor_token = tok;
    memset(&s, 0, sizeof s);
    for (i = 0; i < 31u; ++i)
        s.x[i] = 0xABCD000000000000ull | ((uint64_t)i << 32) |
                 (0x0101010101010101ull * (uint64_t)(i + 1u));
    s.sp = 0x%(sp)xull;
    s.nzcv = (argc > 3 ? strtoull(argv[3], NULL, 0) : 0ull) & 0xF0000000ull;

    if (strcmp(argv[1], "run") == 0) {
        uint64_t pc = 0x%(entry)xull;
        unsigned steps = 0;
        s.x[0] = strtoull(argv[2], NULL, 0);
        for (;;) {
            AotBlockFn fn = block_at(pc);
            AotExit ex;
            if (fn == NULL) { printf("noblock 0x%%llx\n", (unsigned long long)pc); rc = 3; break; }
            if (++steps > 64u) { printf("step_overflow\n"); rc = 4; break; }
            s.pc = pc;
            ex = fn(&s, &rt);
            rt.reason = (uint32_t)ex;  /* dev probe: no dispatcher */
            if (ex == AOT_EXIT_INDIRECT || ex == AOT_EXIT_RET ||
                ex == AOT_EXIT_FAULT) {
                pc = rt.next_pc;
                s.pc = pc;
                break;
            }
            if (ex == AOT_EXIT_COND && rt.next_pc == 0x%(default)xull) {
                pc = rt.next_pc;
                s.pc = pc;
                break;
            }
            if (ex == AOT_EXIT_FALLTHROUGH || ex == AOT_EXIT_BRANCH ||
                ex == AOT_EXIT_COND || ex == AOT_EXIT_CALL ||
                ex == AOT_EXIT_CALL_INDIRECT || ex == AOT_EXIT_STOP) {
                pc = rt.next_pc;
                continue;
            }
            printf("unexpected_exit %%u\n", (unsigned)ex);
            rc = 5;
            break;
        }
        if (rc == 0) dump("run", &s, &rt);
    } else if (strcmp(argv[1], "bypass") == 0) {
        AotBlockFn fn = block_at(0x%(adr)xull);
        AotExit ex;
        s.x[0] = 6u;
        s.x[9] = 0x%(table)xull;  /* proven ADRP+ADD base */
        s.x[10] = 0u;           /* ADR overwrites this */
        if (fn == NULL) { printf("noblock_adr\n"); rc = 3; }
        else {
            s.pc = 0x%(adr)xull;
            ex = fn(&s, &rt);
            rt.reason = (uint32_t)ex;  /* dev probe: no dispatcher */
            (void)ex;
            dump("bypass", &s, &rt);
        }
    } else {
        fprintf(stderr, "bad mode\n");
        rc = 2;
    }
    aot_mem_domain_detach(dom, tok);
    aot_mem_domain_destroy(dom);
    return rc;
}
"""


def c_array(name, data):
    out = ["#include <stdint.h>", "uint8_t %s[] = {" % name]
    for i in range(0, len(data), 16):
        out.append("    " + ",".join("0x%02x" % b for b in data[i:i + 16]) + ",")
    out.append("};")
    out.append("const uint64_t %s_size = %dull;" % (name, len(data)))
    return "\n".join(out) + "\n"


def parse_dump(text, tag):
    rec = {}
    for line in text.splitlines():
        if not line.startswith(tag + " "):
            continue
        body = line[len(tag) + 1:]
        if body.startswith("gpr="):
            body = body[4:]
            gpr, rest = body.split(" ", 1)
            rec["gpr"] = [int(x, 16) for x in gpr.rstrip(",").split(",")]
            for kv in rest.split():
                k, v = kv.split("=")
                rec[k] = int(v, 16)
        elif body.startswith("memfnv="):
            rec["memfnv"] = int(body.split("=")[1], 16)
        else:
            for kv in body.split():
                k, v = kv.split("=")
                rec[k] = int(v, 0)
    return rec


def find_vcvars(explicit):
    if explicit:
        return explicit if os.path.isfile(explicit) else None
    hits = sorted(glob.glob(
        r"C:/Program Files/Microsoft Visual Studio/*/*/VC/Auxiliary/Build/vcvars64.bat"))
    return hits[-1] if hits else None


def build_variant(work, repo, vcvars, name, image_c, gbase, entry, br,
                  default, sp, raw, adr, table):
    img = os.path.join(work, "img_%s.c" % name)
    with open(img, "w", encoding="utf-8") as f:
        f.write(image_c)
    with open(os.path.join(work, "g_raw.c"), "w", encoding="ascii") as f:
        f.write(c_array("g_raw", raw))
    wrapper = os.path.join(work, "probe_%s.c" % name)
    with open(wrapper, "w", encoding="utf-8") as f:
        f.write(WRAPPER % dict(name=name, gbase=gbase, entry=entry, br=br,
                               default=default, sp=sp, adr=adr, table=table))
    obj = os.path.join(work, "obj_%s" % name)
    os.makedirs(obj, exist_ok=True)
    exe = os.path.join(work, "probe_%s.exe" % name)
    bat = os.path.join(work, "build_%s.bat" % name)
    src_aot = os.path.join(repo, "src", "aot").replace("/", "\\")
    src = os.path.join(repo, "src").replace("/", "\\")
    with open(bat, "w", encoding="ascii") as f:
        f.write('@call "%s" >nul\r\n' % vcvars.replace("/", "\\"))
        f.write('cl /nologo /W4 /WX /O2 /std:c11 /D_CRT_SECURE_NO_WARNINGS '
                '/Fo:"%s\\\\" /I"%s" /I"%s" /Fe:"%s" "%s" "%s" '
                '"%s" "%s" "%s"\r\n'
                % (obj.replace("/", "\\"), src_aot, src, exe.replace("/", "\\"),
                   wrapper.replace("/", "\\"),
                   os.path.join(work, "g_raw.c").replace("/", "\\"),
                   os.path.join(repo, "src", "aot", "aot_mem.c").replace("/", "\\"),
                   os.path.join(repo, "src", "aot", "aot_as.c").replace("/", "\\"),
                   os.path.join(repo, "src", "host_vm.c").replace("/", "\\")))
    q = subprocess.run([bat], capture_output=True, text=True)
    if q.returncode != 0 or not os.path.isfile(exe):
        return None, q.stdout + q.stderr
    return exe, ""


class ProbeSemantic(Exception):
    """The probe ran but reported a semantic failure (exit 3/4/5)."""


def run_exe(exe, mode, vals):
    if isinstance(vals, int):
        vals = [vals]
    q = subprocess.run([exe, mode] + [str(v) for v in vals],
                       capture_output=True, text=True)
    if q.returncode in (3, 4, 5):
        raise ProbeSemantic("probe %s exit %d: %s%s"
                            % (mode, q.returncode, q.stdout, q.stderr))
    if q.returncode != 0:
        return None, "exit %d: %s%s" % (q.returncode, q.stdout, q.stderr)
    rec = parse_dump(q.stdout, mode)
    if not rec:
        return None, "no dump: %s%s" % (q.stdout, q.stderr)
    return rec, ""


def unicorn_state(raw, gbase, entry, br, default, gprs, sp, nzcv, idx):
    import unicorn
    from unicorn import (Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_PROT_ALL,
                         UC_HOOK_CODE)
    from unicorn.arm64_const import (UC_ARM64_REG_SP, UC_ARM64_REG_NZCV,
                                     UC_CPU_ARM64_A57)
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    try:
        uc.ctl_set_cpu_model(UC_CPU_ARM64_A57)
    except Exception:
        pass
    size = (len(raw) + 0xFFF) & ~0xFFF
    uc.mem_map(gbase, size, UC_PROT_ALL)
    uc.mem_write(gbase, raw)
    for i in range(31):
        uc.reg_write(getattr(unicorn.arm64_const, "UC_ARM64_REG_X%d" % i), gprs[i])
    uc.reg_write(UC_ARM64_REG_SP, sp)
    uc.reg_write(UC_ARM64_REG_NZCV, nzcv)
    if idx is not None:
        uc.reg_write(unicorn.arm64_const.UC_ARM64_REG_X0, idx)
    seen_br = [False]
    steps = [0]

    def hook(u, addr, size_, ud):
        steps[0] += 1
        if steps[0] > 64:
            u.emu_stop()
            return
        if addr == default:
            u.emu_stop()
            return
        if seen_br[0]:
            u.emu_stop()
            return
        if addr == br:
            seen_br[0] = True

    uc.hook_add(UC_HOOK_CODE, hook)
    uc.emu_start(entry, 0, 0, 64)
    st = dict(
        pc=uc.reg_read(unicorn.arm64_const.UC_ARM64_REG_PC),
        gpr=[uc.reg_read(getattr(unicorn.arm64_const,
                                 "UC_ARM64_REG_X%d" % i)) for i in range(31)],
        sp=uc.reg_read(UC_ARM64_REG_SP),
        nzcv=uc.reg_read(UC_ARM64_REG_NZCV),
        mem=bytes(uc.mem_read(gbase, len(raw))),
        steps=steps[0],
    )
    return st


def compare_native(nat, uni, tag):
    if nat["next"] != uni["pc"]:
        return "%s: next_pc native 0x%x != unicorn 0x%x" % (
            tag, nat["next"], uni["pc"])
    for i in range(31):
        if nat["gpr"][i] != uni["gpr"][i]:
            return "%s: x%d native 0x%x != unicorn 0x%x" % (
                tag, i, nat["gpr"][i], uni["gpr"][i])
    if nat["sp"] != uni["sp"]:
        return "%s: sp native 0x%x != unicorn 0x%x" % (tag, nat["sp"], uni["sp"])
    if nat["nzcv"] != uni["nzcv"]:
        return "%s: nzcv native 0x%x != unicorn 0x%x" % (
            tag, nat["nzcv"], uni["nzcv"])
    if nat["memfnv"] != fnv64(uni["mem"]):
        return "%s: memory bytes differ from the Unicorn execution" % tag
    return None


def _main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=DEFAULT_REPO)
    ap.add_argument("--tools", default=None)
    ap.add_argument("--llvm", default=None, help="accepted for harness parity; unused")
    ap.add_argument("--vcvars", default=None)
    args = ap.parse_args(argv)
    repo = os.path.abspath(args.repo)
    tools = os.path.abspath(args.tools or os.path.join(repo, "tools", "aot"))
    sys.path.insert(0, tools)
    sys.path.insert(0, HERE)
    try:
        import aot_translate as T
        import g3_local_switch_test as G
        import unicorn
    except Exception as exc:
        return infra("import failure: %r" % (exc,))
    vcvars = find_vcvars(args.vcvars)
    if vcvars is None:
        return infra("vcvars64.bat not found (pass --vcvars)")

    # The last case block falls through to a B at 0x1618 that targets the
    # compiled RET block 0x161c: that block is a valid, already-known case
    # which is NOT in the proven site set.  The adjacent RO byte after the
    # N+1 table is set to point at it (test-only fixture edit).
    extra_pc = G.TEXT_OFF + 0x61c
    fx = G.build(switch_n=5, values=[0, 1, 2, 3, 4, 5],
                 extra_words=[(0x1618, G.enc_b((extra_pc - 0x1618) >> 2)),
                              (extra_pc, G.RET)])
    base, layout = fx["base"], dict(fx["layout"])
    raw = bytearray(fx["raw"])
    table_off = fx["table_vas"][0]   # fixture builder stores a flat offset
    raw[table_off + 6] = 7          # (0x161c - label 0x1600) / 4
    raw = bytes(raw)
    layout["sha256"] = hashlib.sha256(raw).hexdigest()
    T.PARTIAL = 0
    ranges = [(base + G.TEXT_OFF, base + G.TEXT_OFF + G.TEXT_SIZE)]
    roots = sorted({base + G.FN_OFF})
    blocks, visited, proofs = T.module_cfg(raw, ranges, roots, base, layout)
    if len(proofs) != 1:
        return fail("expected exactly one verified site, got %d" % len(proofs))
    br, p = next(iter(proofs.items()))
    if p.closure != "verified-final-graph":
        return fail("site is not verified-final-graph: %r" % p.closure)
    targets = tuple(sorted(set(p.targets)))
    default = p.default_target
    entry = base + G.FN_OFF
    sp = base + 0x3000
    status = T.LOCAL_SWITCH_STATUS_BASE - 1
    adr = p.window_pcs[2]
    extra = base + extra_pc               # compiled, valid, out of the site set

    def emit(name, sites):
        return T.emit_c(name, blocks, ranges, layout["sha256"], 0, (0, 0, 0),
                        subset_id="test", abi_expr="AOT_ABI_VERSION_PROGRAM",
                        switch_sites=sites)

    variants = {
        "lsbase": emit("lsbase", {br: p.targets}),
        "lsnoguard": emit("lsnoguard", None),
        "lscount": emit("lscount", {br: tuple(p.targets) + (extra,)}),
        "lsfirst": emit("lsfirst", {br: (p.targets[0],)}),
    }
    work = tempfile.mkdtemp(prefix="aot_ls_native_")
    exes = {}
    for name, text in variants.items():
        exe, err = build_variant(work, repo, vcvars, name, text, base, entry,
                                 br, default, sp, raw, adr, p.table_va)
        if exe is None:
            return infra("%s compile failed: %s" % (name, err))
        exes[name] = exe
    sys.stdout.write("built 4 variants in %s (site 0x%x, %d targets)\n"
                     % (work, br, len(targets)))

    gprs = [0xABCD000000000000 | (i << 32) |
            (0x0101010101010101 * (i + 1)) for i in range(31)]
    gprs[0] = 0
    # 1. normal runs vs Unicorn
    for idx in list(range(6)) + [6]:
        nat, err = run_exe(exes["lsbase"], "run", [idx, 0])
        if nat is None:
            return infra("baseline run %d: %s" % (idx, err))
        uni = unicorn_state(raw, base, entry, br, default, gprs, sp, 0, idx)
        # nzcv is 0 here; the CMP produces the compared flags.
        err = compare_native(nat, uni, "baseline idx=%d" % idx)
        if err:
            return fail(err)
        want = default if idx > 5 else targets[idx]
        if nat["next"] != want:
            return fail("baseline idx=%d: next 0x%x != expected 0x%x"
                        % (idx, nat["next"], want))
    sys.stdout.write("baseline normal idx 0..6: native == Unicorn A57\n")

    # 2. all 16 NZCV combinations at idx 0 (high GPR canaries stay checked)
    for flags in range(16):
        nzcv = flags << 28
        nat, err = run_exe(exes["lsbase"], "run", [0, nzcv])
        if nat is None:
            return infra("nzcv run: %s" % err)
        uni = unicorn_state(raw, base, entry, br, default, gprs, sp, nzcv, 0)
        err = compare_native(nat, uni, "baseline nzcv=%x" % flags)
        if err:
            return fail(err)
    sys.stdout.write("baseline all 16 NZCV values: native == Unicorn A57\n")

    # 3. guard negative: direct ADR fall-through BB entry, bypass CMP
    nat, err = run_exe(exes["lsbase"], "bypass", [extra])
    if nat is None:
        return infra("baseline bypass: %s" % err)
    if nat["exit"] != 11 or nat["fault"] != 6:
        return fail("baseline bypass: expected BAD_STATE fault, got %r" % nat)
    if (nat["fsrc"], nat["ftgt"], nat["fstat"]) != (br, extra, status):
        return fail("baseline bypass: fault fields (%x,%x,%d) != (%x,%x,%d)"
                    % (nat["fsrc"], nat["ftgt"], nat["fstat"],
                       br, extra, status))
    if nat["next"] != extra:
        return fail("baseline bypass: original BR arithmetic changed")
    sys.stdout.write("baseline bypass idx=N+1 Xt=0x%x: BAD_STATE src=0x%x "
                     "target=0x%x status=%d\n" % (extra, br, extra, status))

    # 4. discriminative mutants (test-only switch_sites variants)
    nat, err = run_exe(exes["lsnoguard"], "bypass", [extra])
    if nat is None:
        return infra("noguard bypass: %s" % err)
    if not (nat["exit"] == 5 and nat["next"] == extra):
        return fail("no_guard mutant: expected INDIRECT 0x%x, got %r"
                    % (extra, nat))
    nat, err = run_exe(exes["lscount"], "bypass", [extra])
    if nat is None:
        return infra("count bypass: %s" % err)
    if not (nat["exit"] == 5 and nat["next"] == extra):
        return fail("count_off_by_one mutant: extra target is not admitted")
    nat, err = run_exe(exes["lsfirst"], "run", [1, 0])
    if nat is None:
        return infra("first idx1: %s" % err)
    if not (nat["exit"] == 11 and nat["fault"] == 6
            and nat["ftgt"] == targets[1]):
        return fail("targets_only_first mutant: valid idx=1 did not fault")
    nat0, err = run_exe(exes["lsfirst"], "run", [0, 0])
    if nat0 is None:
        return infra("first idx0: %s" % err)
    if nat0["next"] != targets[0]:
        return fail("targets_only_first mutant: idx=0 changed")
    sys.stdout.write("mutants: no_guard/count admit the extra 0x%x; "
                     "targets_only_first faults valid idx=1 (0x%x)\n"
                     % (extra, targets[1]))
    sys.stdout.write("OK: local-switch native/Unicorn differential passed "
                     "(4 compiled variants, 25 normal runs, 3 bypasses)\n")
    return 0


def main(argv):
    try:
        return _main(argv)
    except ProbeSemantic as exc:
        return fail(str(exc))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
