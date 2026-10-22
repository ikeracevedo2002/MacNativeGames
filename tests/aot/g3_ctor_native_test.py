#!/usr/bin/env python3
"""D023 fixture: lazy constructor admission, real loader/Program, Unicorn A57.

Three separately compiled images contain zero, one and two constructor roots.
The original guest loop is never replaced. Actual native miss state supplies
slot evidence for admitting the next root. The fixture includes a constructor
absent from dynsym and one named STT_FUNC. No title data is used.
"""
import argparse
import hashlib
import glob
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
BASE = 0x100000000
STACK = 0x200000000
SP = STACK + 0x1000
SENTINEL = 0x7000000000
ENTRY = BASE + 0x1000
THUNK = 0x7100000000
ASM = r"""
.text
.global fixture_init
fixture_init:
 stp x29,x30,[sp,#-32]!
 stp x19,x20,[sp,#16]
 mov x29,sp
 adrp x19,bounds_page
 ldr x19,[x19,#0xa00]
 adrp x20,bounds_page
 ldr x20,[x20,#0xa08]
loop:
 ldr x8,[x20],#8
 blr x8
 cmp x20,x19
 b.lo loop
 ldp x19,x20,[sp,#16]
 ldp x29,x30,[sp],#32
 ret
.org 0x200
ctor_stripped:
 adrp x9,bounds_page
 add x9,x9,#0x980
 ldr w10,[x9]
 lsl w10,w10,#4
 add w10,w10,#3
 str w10,[x9]
 ret
.org 0x240
ctor_named:
 adrp x9,bounds_page
 add x9,x9,#0x980
 ldr w10,[x9]
 lsl w10,w10,#4
 add w10,w10,#7
 str w10,[x9]
 ret
"""
C = r'''
#include "aot_loader.h"
#include "aot_as.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
extern const AotImage aot_image_ctorfx;
#include "fixture.inc"
static int setup_fail(int line) {
 fprintf(stderr,"native setup failure at C line %d\n",line); return 2;
}
static uint64_t hash_bytes(const uint8_t *p, size_t n) {
 uint64_t h=14695981039346656037ull; size_t i;
 for(i=0;i<n;i++){h^=p[i];h*=1099511628211ull;} return h;
}
int main(int argc,char **argv) {
 AotMemDomain *d=aot_mem_domain_create();
 AotAddressSpace *as=d?aot_as_create(d):NULL;
 AotLoader loader; AotLoadError err={0}; AotRuntime rt; AotGuestState s;
 AotMem mem; AotProgram *p=NULL; uint32_t code; uint64_t out=0xdeadbeefull;
 uint64_t live=0; uint32_t log=0; unsigned i; uint8_t data[4096],stack[4096];
 const uint8_t *images[]={g_raw}; const uint64_t sizes[]={sizeof g_raw};
 AotModuleDesc desc={"ctorfx",BASE,0x4000,{0,0x2000},{0x2000,0x1000},
  {0x3000,0x1000},0,2,g_sha,ENTRY,g_digest,&aot_image_ctorfx};
 AotModuleSet set={&desc,1};
 AotHostBinding unused={"fixture_unused_host",0};
 AotHostBindings binds={THUNK,SENTINEL,&unused,1,NULL,0};
 (void)argc;(void)argv; memset(&rt,0,sizeof rt);memset(&s,0,sizeof s);
 memset(&loader,0,sizeof loader);
 if(!as || aot_as_add_region(as,STACK,4096,AOT_AS_PERM_RW,
     AOT_AS_STATE_DATA,NULL)!=AOT_MEM_OK) return setup_fail(__LINE__);
 if(aot_loader_init(&loader,as,&set,&err)!=AOT_LOAD_OK) return setup_fail(__LINE__);
 aot_loader_set_host_bindings(&loader,&binds);
 if(aot_loader_load(&loader,images,sizes,&err)!=AOT_LOAD_OK){
  fprintf(stderr,"loader status=%d detail=%s\n",err.status,err.detail);return 2;}
 p=aot_program_create(as);
 if(!p || aot_loader_build_program(&loader,p,1,SENTINEL,16,&err)!=AOT_LOAD_OK ||
    aot_program_finalize(p)!=AOT_FAULT_NONE) {
  fprintf(stderr,"program status=%d detail=%s\n",err.status,
          err.detail?err.detail:"no loader diagnostic");
  return setup_fail(__LINE__);}
 if(aot_mem_init_aspace(&mem,as)!=AOT_MEM_OK) return setup_fail(__LINE__);
 for(i=0;i<31;i++)s.x[i]=0x0101010101010101ull*(i+1);
 s.sp=SP;s.nzcv=0xa0000000u;
 if(aot_rt_init_program(&rt,p,mem,&s,512)!=AOT_FAULT_NONE) return setup_fail(__LINE__);
 code=aot_call_guest(&rt,ENTRY,NULL,0,&out);
 if(aot_as_read(as,BASE+0x3000,data,sizeof data)!=AOT_MEM_OK ||
    aot_as_read(as,STACK,stack,sizeof stack)!=AOT_MEM_OK ||
    aot_as_read(as,BASE+0x3980,&log,4)!=AOT_MEM_OK) return setup_fail(__LINE__);
 if(code==AOT_FAULT_UNTRANSLATED &&
    aot_as_read(as,s.x[20]-8,&live,8)!=AOT_MEM_OK) return setup_fail(__LINE__);
 printf("{\"code\":%u,\"src\":%" PRIu64 ",\"target\":%" PRIu64
  ",\"out\":%" PRIu64 ",\"sp\":%" PRIu64 ",\"pc\":%" PRIu64
  ",\"nzcv\":%" PRIu64 ",\"live\":%" PRIu64 ",\"log\":%u,\"data\":%" PRIu64
  ",\"stack\":%" PRIu64 ",\"x\":[",code,rt.fault_src,rt.fault_target,
  out,s.sp,s.pc,s.nzcv,live,log,hash_bytes(data,sizeof data),
  hash_bytes(stack,sizeof stack));
 for(i=0;i<31;i++)printf("%s%" PRIu64,i?",":"",s.x[i]); puts("]}");
 aot_rt_release(&rt);aot_program_destroy(p);aot_loader_release(&loader);
 aot_as_destroy(as);aot_mem_domain_destroy(d);return 0;
}
'''


def checked(cmd, semantic=False, **kw):
    p = subprocess.run([str(x) for x in cmd], capture_output=True, text=True,
                       **kw)
    if p.returncode:
        error = AssertionError if semantic else RuntimeError
        raise error("command failed (%d): %s\n%s\n%s" %
                    (p.returncode, cmd, p.stdout[-6000:], p.stderr[-6000:]))
    return p.stdout


def array(name, data):
    return "static const uint8_t %s[]={%s};\n" % (
        name, ",".join(str(x) for x in data))


def fnv(data):
    v = 14695981039346656037
    for x in data:
        v = ((v ^ x) * 1099511628211) & 0xffffffffffffffff
    return v


def oracle(linked, stop):
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
    from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X29,
        UC_ARM64_REG_X30, UC_ARM64_REG_SP, UC_ARM64_REG_PC,
        UC_ARM64_REG_NZCV, UC_CPU_ARM64_A57)
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    u.ctl_set_cpu_model(UC_CPU_ARM64_A57)
    u.mem_map(BASE, 0x4000); u.mem_write(BASE, bytes(linked))
    u.mem_map(STACK, 4096)
    u.mem_map(SENTINEL, 4096)
    regs = [UC_ARM64_REG_X0 + i for i in range(29)] + [
        UC_ARM64_REG_X29, UC_ARM64_REG_X30]
    for i, r in enumerate(regs):
        u.reg_write(r, 0x0101010101010101 * (i + 1))
    u.reg_write(UC_ARM64_REG_X30, SENTINEL)
    u.reg_write(UC_ARM64_REG_SP, SP)
    u.reg_write(UC_ARM64_REG_NZCV, 0xa0000000)
    def hook(uc, pc, size, user):
        if pc == stop:
            uc.emu_stop()
    u.hook_add(UC_HOOK_CODE, hook)
    u.emu_start(ENTRY, SENTINEL + 4, count=512)
    if u.reg_read(UC_ARM64_REG_PC) != stop:
        raise AssertionError("oracle failed to reach independent stop")
    return {"x": [u.reg_read(r) for r in regs],
            "sp": u.reg_read(UC_ARM64_REG_SP),
            "pc": u.reg_read(UC_ARM64_REG_PC),
            "nzcv": u.reg_read(UC_ARM64_REG_NZCV),
            "data": fnv(u.mem_read(BASE + 0x3000, 4096)),
            "stack": fnv(u.mem_read(STACK, 4096))}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--tools", required=True)
    ap.add_argument("--llvm", required=True)
    ap.add_argument("--vcvars")
    ap.add_argument("--opt", choices=("O2", "Od"), default="O2")
    args = ap.parse_args()
    repo, tools, llvm = map(Path, (args.repo, args.tools, args.llvm))
    sys.path.insert(0, str(tools))
    sys.path.insert(0, str(repo / "tests/aot"))
    import aot_translate as T
    import g3_init_reach as R
    import g3_local_switch as LS
    import g3_ctor_roots as G
    import g3_ctor_roots_test as F
    vcvars = args.vcvars
    if not vcvars:
        hits = sorted(glob.glob("C:/Program Files/Microsoft Visual Studio/*/*/VC/Auxiliary/Build/vcvars64.bat"))
        if not hits:
            raise RuntimeError("vcvars64.bat not found; supply --vcvars")
        vcvars = hits[-1]
    with tempfile.TemporaryDirectory(prefix="aot_ctor_native_") as td:
        work = Path(td)
        (work / "fixture.s").write_text(ASM)
        checked([llvm / "llvm-mc.exe", "-triple=aarch64-none-elf",
                 "-filetype=obj", work / "fixture.s", "-o", work / "fixture.o"])
        checked([llvm / "ld.lld.exe", "-Ttext=0x1000", "--entry=fixture_init",
                 "--image-base=0", "--defsym=bounds_page=0x3000",
                 work / "fixture.o", "-o", work / "fixture.elf"])
        checked([llvm / "llvm-objcopy.exe", "-O", "binary", "--only-section=.text",
                 work / "fixture.elf", work / "fixture.bin"])
        code = (work / "fixture.bin").read_bytes()
        calls = [BASE + 0x1000 + i for i in range(0, len(code), 4)
                 if struct.unpack_from("<I", code, i)[0] == 0xd63f0100]
        if len(calls) != 1:
            raise AssertionError("LLVM fixture must have one BLR x8")
        expected_site = calls[0]
        words = {0x1000 + i: struct.unpack_from("<I", code, i)[0]
                 for i in range(0, len(code), 4)}
        raw = F.build_flat(slots=[(0x1200, 1027, 0), (0x1240, 1027, 0)],
            words=words,
            syms=[("", 0, 0, 0, 0), ("ctor_named", 0x1240, 28, 2, 1)],
            tags_drop=(12,), tags_extra=[(12, 0x1000)])
        sha = hashlib.sha256(raw).hexdigest()
        layout = {"sha256": sha, "name": "ctorfx", "image_size": 0x4000,
            "bss_size": 0, "mod0_off": 0x100, "dynsym_count": 2,
            "text": [0, 0x2000], "ro": [0x2000, 0x1000],
            "data": [0x3000, 0x1000]}
        sites = {0x3800: BASE + 0x1200, 0x3808: BASE + 0x1240,
                 0x3a08: BASE + 0x3800, 0x3a00: BASE + 0x3810}
        image = R.Image("ctorfx", BASE, raw, layout, sites)
        ctx = LS.Context(raw, layout, BASE, T.decode)
        auth = G.Authority.build([image], {"ctorfx": sha}, {"ctorfx": ctx})
        rawmap = {"ctorfx": (raw, BASE, image.text)}
        digest = hashlib.sha256(image.buf[0x3000:0x4000]).digest()
        include = ("#define BASE %dull\n#define STACK %dull\n#define SP %dull\n"
                   "#define ENTRY %dull\n#define SENTINEL %dull\n#define THUNK %dull\n"
                   % (BASE, STACK, SP, ENTRY, SENTINEL, THUNK))
        include += array("g_raw", raw) + array("g_sha", bytes.fromhex(sha))
        include += array("g_digest", digest)
        (work / "fixture.inc").write_text(include)
        (work / "probe.c").write_text(C)
        roots = [ENTRY]
        core = ["aot_prog_assembly", "aot_program", "aot_runtime", "aot_mem",
                "aot_as", "aot_loader", "aot_sha256", "aot_fp"]
        core = [repo / ("src/aot/" + n + ".c") for n in core] + [
            repo / ("src/" + n + ".c") for n in
            ("host_vm", "host_thread", "host_time", "host_time_convert")]
        for stage in range(3):
            T.PARTIAL = 1
            blocks, visited, proofs = T.module_cfg(raw, [image.text], roots,
                                                   BASE, layout)
            emitted = T.emit_c("ctorfx", blocks, [image.text], sha, 0,
                (0, 0, 0), subset_id="g3-module-v1",
                abi_expr="AOT_ABI_VERSION_PROGRAM",
                switch_sites={pc: p.targets for pc, p in proofs.items()})
            (work / "image.c").write_text(emitted)
            exe = work / ("ctor%d.exe" % stage)
            quote = lambda x: '"%s"' % str(x)
            cmd = ('@echo off\ncall %s >nul\ncd /d %s\n'
                   'cl /nologo /W4 /WX /%s /std:c11 /D_CRT_SECURE_NO_WARNINGS '
                   '/I%s /I%s probe.c image.c %s /Fe:%s\n' %
                   (quote(vcvars), quote(work), args.opt,
                    quote(repo / "src/aot"), quote(repo / "src"),
                    " ".join(map(quote, core)), quote(exe)))
            (work / "build.cmd").write_text(cmd)
            checked(["cmd.exe", "/c", str(work / "build.cmd")])
            result = json.loads(checked([exe], semantic=True).strip())
            stop = BASE + (0x1200 if stage == 0 else 0x1240) if stage < 2 else SENTINEL
            uni = oracle(image.buf, stop)
            for key in ("x", "sp", "pc", "nzcv", "data", "stack"):
                if result[key] != uni[key]:
                    raise AssertionError("stage%d %s native=%r oracle=%r" %
                                         (stage, key, result[key], uni[key]))
            if stage < 2:
                if result["code"] != 10 or result["target"] != stop or result["out"] != 0xdeadbeef:
                    raise AssertionError("missing constructor did not fault honestly")
                if result["src"] != expected_site or result["live"] != stop or result["x"][8] != stop:
                    raise AssertionError("native source/load/target mismatch")
                capture = {"reg": 20, "value": result["x"][20],
                    "slot_bytes": result["live"], "bound_reg": 19,
                    "bound_value": result["x"][19]}
                verdict = auth.prove(stop, result["src"], "blr", capture, rawmap)
                if not verdict.ok:
                    raise AssertionError("real native miss refused: %s %s" %
                                         (verdict.reason, verdict.detail))
                ev = verdict.evidence
                if ev["index"] != stage or int(ev["slot"], 16) != BASE + 0x3800 + 8 * stage or int(ev["target"], 16) != stop:
                    raise AssertionError("proof evidence names the wrong native slot")
                denied = [
                    (auth.prove(stop, expected_site, "blr", dict(capture, slot_bytes=0), rawmap),
                     "cursor-slot-bytes-mismatch"),
                    (auth.prove(stop, expected_site, "blr", dict(capture, value=capture["value"] + 8), rawmap),
                     "cursor-slot-mismatch" if stage == 0 else "cursor-beyond-array-end"),
                    (auth.prove(stop, ENTRY, "blr", capture, rawmap),
                     "fault-site-not-array-walk"),
                ]
                if stage == 0:
                    denied.append((auth.prove(BASE + 0x1240, expected_site, "blr", capture, rawmap),
                                   "cursor-slot-bytes-mismatch"))
                for wrong, reason in denied:
                    if wrong.ok or wrong.reason != reason:
                        raise AssertionError("native admission control: expected %s, got %s" %
                                             (reason, wrong.reason))
                roots.append(int(ev["target"], 16))
                print("native miss%d: slot%d admits one root; %d wrong admission controls refused" % (stage, stage, len(denied)))
            elif result["code"] != 0 or result["log"] != 0x37 or result["sp"] != SP or result["out"] != result["x"][0]:
                raise AssertionError("constructor loop did not return in guest order")
        print("PASS: 3 native/Unicorn stages; stripped + named constructor; actual loader/AS/Program; lazy roots and guest order")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as exc:
        print("FAIL: %s" % exc, file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print("INFRA: %s" % exc, file=sys.stderr)
        sys.exit(2)
