#!/usr/bin/env python3
"""D024 Stage B: candidate catalog + authority table vs today's emission.

Hermetic (no game data).  The fixture `tests/aot/g3/fde_emit_fixture.s` is
assembled with llvm-mc, linked by ld.lld with `tests/aot/g3/fde_emit.ld`
(real `.eh_frame_hdr`), flattened by `aot_module.elf2flat` and linked by the
independent Python reference linker for the loader's link digest.

  X        = today's emission: `aot_translate.py --module --partial` (CLI,
             unchanged) over the single admitted root `fx_entry`;
  Y_all    = `g3_fde_emit.py catalog` over ALL four FDE windows + `table`;
  Y_mixed  = catalog over fx_ctor/fx_switch/fx_unadmitted only, so the table
             unit also carries today-style bodies for fx_entry.

Every variant is compiled with MSVC /W4 /WX into the same probe and run
through the REAL loader / address space / Program / aot_call_guest from the
same fresh load.  X and Y must agree on every observable field (x0..x30, sp,
pc, nzcv, v0..v31, fpcr, fpsr, fault kind/src/target, steps, block trace, HLE
events, RO/data/stack hashes); fault_status is compared through each image's
own metadata (fault kind, src pc, metadata-resolved pc), never as a raw
integer.  Unicorn A57 is a third oracle on the paths it can model (not for
exclusives).  Closed-form expectations pin each negative's specific outcome.

Negative control: a child process re-runs this suite with the authority step
monkeypatched (in that child only) to ALSO list the out-of-closure catalog
bodies in the AotImage; the suite must fail there.

Exit: 0 pass, 1 semantic failure, 2 infrastructure.
"""

import argparse
import glob
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
FIXTURE_ASM = os.path.join(HERE, "g3", "fde_emit_fixture.s")
FIXTURE_LD = os.path.join(HERE, "g3", "fde_emit.ld")

BASE = 0x100000000
STACK = 0x200000000
STACK_SIZE = 0x2000
SP = STACK + 0x1800
SENTINEL = 0x7000000000
THUNK = 0x7100000000
BUDGET = 4096
UNMAPPED = BASE + 0x40000
PAGE = 0x1000

FAULT = {"NONE": 0, "MEMORY": 3, "BAD_STATE": 6, "UNTRANSLATED": 10,
         "BAD_RETURN": 12, "UNSUPPORTED_INSN": 16}
HLE_SVC = 1

FAILS = []
OKS = [0]


def ok(msg):
    OKS[0] += 1
    print("OK: %s" % msg)


def fail(msg):
    FAILS.append(msg)
    print("FAIL: %s" % msg)


class Infra(Exception):
    pass


def checked(cmd, **kw):
    proc = subprocess.run([str(x) for x in cmd], capture_output=True,
                          text=True, **kw)
    if proc.returncode:
        raise Infra("command failed (%d): %s\n%s\n%s"
                    % (proc.returncode, cmd, proc.stdout[-4000:],
                       proc.stderr[-4000:]))
    return proc.stdout


def fnv(data):
    v = 0xCBF29CE484222325
    for b in data:
        v = ((v ^ b) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return v


def page_up(v):
    return (v + PAGE - 1) & ~(PAGE - 1)


# --------------------------------------------------------------- fixture

def symbols(M, elf):
    symtab = elf.section(".symtab")
    strtab = elf.section(".strtab")
    strings = elf.section_bytes(strtab)
    out = {}
    for index in range(symtab["size"] // 24):
        off = symtab["offset"] + index * 24
        name_off, _info, _other, _shndx, value, size = \
            struct.unpack_from("<IBBHQQ", elf.data, off)
        name = strings[name_off:strings.find(b"\x00", name_off)].decode()
        if name:
            out[name] = (value, size)
    return out


def build_fixture(work, llvm, M, F):
    obj = os.path.join(work, "fx.o")
    shared = os.path.join(work, "libfx.so")
    checked([os.path.join(llvm, "llvm-mc.exe"), "-triple=aarch64-none-elf",
             "-filetype=obj", "-o", obj, FIXTURE_ASM])
    checked([os.path.join(llvm, "ld.lld.exe"), "-shared",
             "-z", "max-page-size=4096", "-soname", "libfx.so",
             "--hash-style=both", "-T", FIXTURE_LD, "--eh-frame-hdr",
             "-o", shared, obj])
    layout = M.elf2flat(shared, "fx_v", work)
    flat_path = os.path.join(work, "fx_v.flat")
    layout_path = os.path.join(work, "fx_v.layout.json")
    with open(flat_path, "rb") as handle:
        flat = handle.read()
    with open(shared, "rb") as handle:
        syms = symbols(M, M.Elf64(handle.read(), shared))
    cfg_path = os.path.join(work, "link_config.json")
    with open(cfg_path, "w", encoding="utf-8") as handle:
        json.dump({"thunk_base": "0x%x" % THUNK, "sentinel": "0x%x" % SENTINEL,
                   "modules": [{"name": "fx", "guest_base": "0x%x" % BASE}]},
                  handle)
    link = M.link_modules(cfg_path, work, "v")
    desc = link["modules"][0]
    linked = bytearray(flat)
    for site in link["sites"]:
        struct.pack_into("<Q", linked, site["where"], site["value"])
    manifest = F.manifest_for(flat, layout, name="fx_v")
    manifest_path = os.path.join(work, "fx.fde_candidates.json")
    F.write_manifest(manifest, manifest_path)
    bounds = sorted((int(b["start"], 16), int(b["end"], 16))
                    for b in manifest["boundaries"])
    fx = {"flat": flat, "layout": layout, "flat_path": flat_path,
          "layout_path": layout_path, "manifest": manifest,
          "manifest_path": manifest_path, "bounds": bounds,
          "linked": bytes(linked), "digest": desc["link_digest"],
          "init_va": desc["init_va"], "syms": syms}
    for name in ("fx_entry", "fx_ctor", "fx_switch", "fx_unadmitted",
                 "fx_data", "fx_ro_word"):
        if name not in syms:
            raise Infra("fixture symbol %s missing" % name)
        fx[name] = BASE + syms[name][0]
    starts = [s for s, _e in bounds]
    want = sorted(fx[n] - BASE for n in ("fx_entry", "fx_ctor", "fx_switch",
                                         "fx_unadmitted"))
    if starts != want:
        raise Infra("FDE starts %s != function symbols %s"
                    % ([hex(s) for s in starts], [hex(s) for s in want]))
    fx["window"] = {name: next(b for b in bounds if b[0] == fx[name] - BASE)
                    for name in ("fx_entry", "fx_ctor", "fx_switch",
                                 "fx_unadmitted")}
    entries_path = os.path.join(work, "entries.json")
    with open(entries_path, "w", encoding="utf-8") as handle:
        json.dump(["0x%x" % fx["fx_entry"]], handle)
    fx["entries_path"] = entries_path
    return fx


def words_in(fx, name, word, mask=0xFFFFFFFF):
    lo, hi = fx["window"][name]
    return [BASE + off for off in range(lo, hi, 4)
            if struct.unpack_from("<I", fx["flat"], off)[0] & mask == word]


# --------------------------------------------------------------- generation

def gen_x(fx, work, tools):
    out_c = os.path.join(work, "x_fx.c")
    out_j = os.path.join(work, "x_fx.json")
    checked([sys.executable, os.path.join(tools, "aot_translate.py"),
             "--module", "--partial", "--flat", fx["flat_path"],
             "--layout", fx["layout_path"], "--guest-base", "0x%x" % BASE,
             "--entries", fx["entries_path"], "--name", "fx",
             "--out", out_c, "--meta-out", out_j])
    with open(out_c, "r", encoding="utf-8") as handle:
        text = handle.read()
    with open(out_j, "r", encoding="utf-8") as handle:
        meta = json.load(handle)
    return {"c": [out_c], "text": text, "meta": meta}


def gen_y(fx, work, E, tag, names):
    starts = ",".join("0x%x" % fx["window"][n][0] for n in names)
    paths = {k: os.path.join(work, "%s_%s" % (tag, k))
             for k in ("cat.c", "cat.json", "tab.c", "tab.json", "rep.json")}
    t0 = time.perf_counter()
    rc = E.main(["catalog", "--flat", fx["flat_path"],
                 "--layout", fx["layout_path"], "--guest-base", "0x%x" % BASE,
                 "--name", "fx", "--manifest", fx["manifest_path"],
                 "--select", starts, "--out-c", paths["cat.c"],
                 "--out-json", paths["cat.json"]])
    t1 = time.perf_counter()
    if rc != 0:
        raise Infra("%s: catalog step failed (%d)" % (tag, rc))
    rc = E.main(["table", "--flat", fx["flat_path"],
                 "--layout", fx["layout_path"], "--guest-base", "0x%x" % BASE,
                 "--name", "fx", "--entries", fx["entries_path"],
                 "--catalog-json", paths["cat.json"],
                 "--catalog-c", paths["cat.c"], "--out-c", paths["tab.c"],
                 "--out-json", paths["tab.json"], "--report", paths["rep.json"]])
    t2 = time.perf_counter()
    if rc != 0:
        raise Infra("%s: table step failed (%d)" % (tag, rc))
    out = {"c": [paths["cat.c"], paths["tab.c"]],
           "times": (t1 - t0, t2 - t1)}
    for key in ("cat.c", "tab.c"):
        with open(paths[key], "r", encoding="utf-8") as handle:
            out[key] = handle.read()
    for key in ("cat.json", "tab.json", "rep.json"):
        with open(paths[key], "r", encoding="utf-8") as handle:
            out[key] = json.load(handle)
    out["meta"] = out["tab.json"]
    return out


# ------------------------------------------------------- static equivalence

_BODY_RE = re.compile(r"^(?:static )?AotExit (aot_(?:blk|cand_fx)_([0-9a-f]+))"
                      r"\(AotGuestState \*s, AotRuntime \*rt\) \{\n(.*?)\n\}$",
                      re.M | re.S)
_TABLE_RE = re.compile(r"static const AotBlockEntry aot_blocks_fx\[\] = \{\n"
                       r"(.*?)\n\};", re.S)


def bodies(text):
    return {int(m.group(2), 16): (m.group(1), m.group(3))
            for m in _BODY_RE.finditer(text)}


def table_pcs(text):
    m = _TABLE_RE.search(text)
    if m is None:
        return None
    return [(int(a, 16), b) for a, b in
            re.findall(r"\{ 0x([0-9a-f]+)ull, (\w+) \}", m.group(1))]


def status_maps(meta):
    unsup = {u["status"]: int(u["pc"], 16) for u in meta.get("unsupported", [])}
    switch = {s["status"]: int(s["br_pc"], 16)
              for s in meta.get("local_switch_sites", [])}
    return unsup, switch


def normalize(body, meta):
    """Replace raw status integers by the PC they resolve to in `meta`."""
    unsup, switch = status_maps(meta)

    def u(m):
        return "%s<pc 0x%x>)" % (m.group(1), unsup[int(m.group(2))])

    def w(m):
        return "rt->fault_status = <br 0x%x>;" % switch[int(m.group(1))]
    body = re.sub(r"(aot_fault_unsupported\(rt, 0x[0-9a-f]+ull, )"
                  r"\(int64_t\)(\d+)u\)", u, body)
    return re.sub(r"rt->fault_status = (-?\d+);", w, body)


def static_checks(fx, x, y, tag, E, T):
    x_tab = table_pcs(x["text"])
    y_tab = table_pcs(y["tab.c"])
    if [pc for pc, _ in x_tab] != [pc for pc, _ in y_tab]:
        extra = sorted(set(pc for pc, _ in y_tab) - set(pc for pc, _ in x_tab))
        fail("%s: AotImage table entries differ from today's closure (%d vs "
             "%d; extra %s): the table lists an unadmitted catalog body"
             % (tag, len(y_tab), len(x_tab), [hex(p) for p in extra]))
    else:
        ok("%s: AotImage lists exactly today's %d closure starts"
           % (tag, len(x_tab)))
    if re.search(r"(const AotImage|AotBlockEntry|AotProgImage)",
                 y["cat.c"]):
        fail("%s: the catalog unit contains an AotImage/block table" % tag)
    else:
        ok("%s: catalog unit has no AotImage (authority: %s, %d bodies)"
           % (tag, y["cat.json"]["authority"], len(y["cat.json"]["blocks"])))
    xb = bodies(x["text"])
    yb = bodies(y["cat.c"])
    yb.update(bodies(y["tab.c"]))
    used = dict((pc, sym) for pc, sym in y_tab)
    bad = []
    for pc, _sym in x_tab:
        if pc not in used or used[pc] not in (yb.get(pc) or ("",))[0:1]:
            bad.append(pc)
            continue
        if normalize(xb[pc][1], x["meta"]) != normalize(yb[pc][1], y["meta"]):
            bad.append(pc)
    if bad:
        fail("%s: %d admitted bodies differ from today's after status "
             "normalisation (first 0x%x)" % (tag, len(bad), bad[0]))
    else:
        n_cat = sum(1 for _pc, sym in y_tab if sym.startswith("aot_cand_"))
        ok("%s: every admitted body is today's body modulo status namespace "
           "(%d from the catalog, %d emitted)" % (tag, n_cat,
                                                  len(y_tab) - n_cat))
    # raw status namespaces of catalog bodies are disjoint from today's
    x_unsup, x_switch = status_maps(x["meta"])
    clash = [item for item in (y["meta"]["unsupported"] +
                               y["meta"]["local_switch_sites"])
             if item["body"] == "catalog" and
             item["status"] in set(x_unsup) | set(x_switch)]
    if clash:
        fail("%s: catalog status values reuse today's namespace: %s"
             % (tag, clash))
    else:
        ok("%s: catalog fault_status values are disjoint from today's "
           "PARTIAL_STATUS / LOCAL_SWITCH_STATUS_BASE values" % tag)
    rep = y["rep.json"]
    if rep["mismatch_counts"] or rep["covered_matches"] + \
            rep["outside_candidates"] != rep["closure_blocks"]:
        fail("%s: inconsistent partition report %r" % (tag, rep))
    else:
        ok("%s: partition: %d closure blocks, %d matched catalog, %d outside "
           "windows, %d catalog block(s) compiled but not admitted, 0 "
           "mismatches" % (tag, rep["closure_blocks"], rep["covered_matches"],
                           rep["outside_candidates"],
                           rep["unadmitted_catalog_blocks"]))


# --------------------------------------------------------------- native probe

PROBE_C = r'''
#include "aot_loader.h"
#include "aot_as.h"
#include "aot_runtime.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
extern const AotImage aot_image_fx;
#ifdef FX_CATALOG
typedef struct AotCandBlock {
    uint64_t pc;
    uint64_t end_pc;
    const char *words_sha256;
    AotBlockFn fn;
} AotCandBlock;
extern const AotCandBlock aot_cand_catalog_fx[];
extern const uint32_t aot_cand_catalog_fx_count;
extern const char aot_cand_identity_fx[];
#endif
#include "fixture.inc"

static void svc21(AotRuntime *rt, AotGuestState *s, const AotHleRequest *req,
                  void *user) {
    (void)rt; (void)req; (void)user;
    s->x[0] = s->x[0] * 3u + 1u;
}
static uint64_t hash_bytes(const uint8_t *p, size_t n) {
    uint64_t h = 14695981039346656037ull; size_t i;
    for (i = 0; i < n; i++) { h ^= p[i]; h *= 1099511628211ull; }
    return h;
}
static int setup_fail(int line) {
    fprintf(stderr, "native setup failure at C line %d\n", line);
    return 2;
}
static uint8_t g_text[TEXT_MAP], g_ro[RO_MAP], g_data[DATA_MAP],
    g_stack[STACK_SIZE];
int main(int argc, char **argv) {
    AotMemDomain *d = aot_mem_domain_create();
    AotAddressSpace *as = d ? aot_as_create(d) : NULL;
    AotLoader loader; AotLoadError err; AotRuntime rt; AotGuestState s;
    AotMem mem; AotProgram *p = NULL; uint32_t code; uint64_t out = 0;
    uint64_t args[3], fxdata[10]; unsigned i;
    const uint8_t *images[] = {g_raw}; const uint64_t sizes[] = {sizeof g_raw};
    AotModuleDesc desc = {"fx", BASE, IMAGE_SIZE, {0, TEXT_SIZE},
        {RO_OFF, RO_SIZE}, {DATA_OFF, DATA_SIZE}, BSS_SIZE, DYNSYM,
        g_sha, INIT_VA, g_digest, &aot_image_fx};
    AotModuleSet set = {&desc, 1};
    AotHostBinding unused = {"fixture_unused_host", 0};
    AotHostBindings binds = {THUNK, SENTINEL, &unused, 1, NULL, 0};
    if (argc != 5) return setup_fail(__LINE__);
    args[0] = strtoull(argv[1], NULL, 0);
    args[1] = strtoull(argv[2], NULL, 0);
    args[2] = strtoull(argv[3], NULL, 0);
    memset(&rt, 0, sizeof rt); memset(&s, 0, sizeof s);
    memset(&loader, 0, sizeof loader); memset(&err, 0, sizeof err);
    if (!as || aot_as_add_region(as, STACK, STACK_SIZE, AOT_AS_PERM_RW,
                                 AOT_AS_STATE_DATA, NULL) != AOT_MEM_OK)
        return setup_fail(__LINE__);
    if (aot_loader_init(&loader, as, &set, &err) != AOT_LOAD_OK)
        return setup_fail(__LINE__);
    aot_loader_set_host_bindings(&loader, &binds);
    if (aot_loader_load(&loader, images, sizes, &err) != AOT_LOAD_OK) {
        fprintf(stderr, "loader status=%d detail=%s\n", err.status, err.detail);
        return 2;
    }
    p = aot_program_create(as);
    if (!p || aot_loader_build_program(&loader, p, 1, SENTINEL, 16, &err)
            != AOT_LOAD_OK ||
        aot_program_set_handler(p, AOT_HLE_SVC, 0x21u, svc21, NULL) != 0 ||
        aot_program_finalize(p) != AOT_FAULT_NONE)
        return setup_fail(__LINE__);
    if (aot_mem_init_aspace(&mem, as) != AOT_MEM_OK)
        return setup_fail(__LINE__);
    for (i = 0; i < 31; i++) s.x[i] = 0x0101010101010101ull * (i + 1);
    for (i = 0; i < 32; i++) {
        s.v[i][0] = 0x1111111111111111ull * (uint64_t)((i % 15u) + 1u);
        s.v[i][1] = ~s.v[i][0] ^ (uint64_t)i;
    }
    s.sp = SP; s.nzcv = 0xa0000000u;
    if (aot_rt_init_program(&rt, p, mem, &s, BUDGET) != AOT_FAULT_NONE)
        return setup_fail(__LINE__);
    rt.trace_enabled = 1;
    s.sp = (uint64_t)((int64_t)SP + strtoll(argv[4], NULL, 0));
    code = aot_call_guest(&rt, ENTRY, args, 3, &out);
    if (aot_as_read(as, BASE, g_text, sizeof g_text) != AOT_MEM_OK ||
        aot_as_read(as, BASE + RO_OFF, g_ro, sizeof g_ro) != AOT_MEM_OK ||
        aot_as_read(as, BASE + DATA_OFF, g_data, sizeof g_data) != AOT_MEM_OK ||
        aot_as_read(as, STACK, g_stack, sizeof g_stack) != AOT_MEM_OK ||
        aot_as_read(as, FX_DATA, fxdata, sizeof fxdata) != AOT_MEM_OK)
        return setup_fail(__LINE__);
    printf("{\"code\":%u,\"fault\":%u,\"src\":%" PRIu64 ",\"target\":%" PRIu64
           ",\"status\":%" PRId64 ",\"steps\":%" PRIu64 ",\"out\":%" PRIu64
           ",\"sp\":%" PRIu64 ",\"pc\":%" PRIu64 ",\"nzcv\":%" PRIu64
           ",\"fpcr\":%" PRIu64 ",\"fpsr\":%" PRIu64 ",\"tpidr\":%" PRIu64
           ",\"text\":%" PRIu64 ",\"ro\":%" PRIu64 ",\"data\":%" PRIu64
           ",\"stack\":%" PRIu64,
           code, rt.fault, rt.fault_src, rt.fault_target, rt.fault_status,
           rt.steps, out, s.sp, s.pc, s.nzcv, s.fpcr, s.fpsr, s.tpidr,
           hash_bytes(g_text, sizeof g_text), hash_bytes(g_ro, sizeof g_ro),
           hash_bytes(g_data, sizeof g_data),
           hash_bytes(g_stack, sizeof g_stack));
    printf(",\"lk_entry\":%d,\"lk_unadmitted\":%d,\"is_entry_unadmitted\":%d",
           aot_program_lookup(p, ENTRY) != NULL,
           aot_program_lookup(p, UNADMITTED) != NULL,
           aot_program_is_entry(p, UNADMITTED));
    printf(",\"x\":[");
    for (i = 0; i < 31; i++) printf("%s%" PRIu64, i ? "," : "", s.x[i]);
    printf("],\"v\":[");
    for (i = 0; i < 32; i++)
        printf("%s[%" PRIu64 ",%" PRIu64 "]", i ? "," : "", s.v[i][0],
               s.v[i][1]);
    printf("],\"fxdata\":[");
    for (i = 0; i < 10; i++) printf("%s%" PRIu64, i ? "," : "", fxdata[i]);
    printf("],\"trace\":[");
    for (i = 0; i < rt.trace_count; i++)
        printf("%s%" PRIu64, i ? "," : "", rt.trace[i]);
    printf("],\"trace_overflow\":%d,\"events\":[", rt.trace_overflow);
    for (i = 0; i < rt.event_count; i++)
        printf("%s[%u,%u,%" PRIu64 ",%" PRIu64 "]", i ? "," : "",
               rt.events[i].kind, rt.events[i].id, rt.events[i].site_pc,
               rt.events[i].resume_pc);
    printf("]");
#ifdef FX_CATALOG
    {
        int found = 0, fn_nonnull = 0, fn_in_table = 0; size_t k;
        for (i = 0; i < aot_cand_catalog_fx_count; i++) {
            if (aot_cand_catalog_fx[i].pc != UNADMITTED) continue;
            found = 1;
            fn_nonnull = aot_cand_catalog_fx[i].fn != NULL;
            for (k = 0; k < aot_image_fx.block_count; k++)
                if (aot_image_fx.blocks[k].fn == aot_cand_catalog_fx[i].fn)
                    fn_in_table = 1;
        }
        printf(",\"cand\":{\"count\":%u,\"unadmitted_found\":%d,"
               "\"unadmitted_fn\":%d,\"unadmitted_fn_in_table\":%d,"
               "\"identity\":\"%s\"}", aot_cand_catalog_fx_count, found,
               fn_nonnull, fn_in_table, aot_cand_identity_fx);
    }
#endif
    printf("}\n");
    aot_rt_release(&rt); aot_program_destroy(p); aot_loader_release(&loader);
    aot_as_destroy(as); aot_mem_domain_destroy(d);
    return 0;
}
'''

CORE = (["src/aot/%s.c" % n for n in
         ("aot_prog_assembly", "aot_program", "aot_runtime", "aot_mem",
          "aot_as", "aot_loader", "aot_sha256", "aot_fp")] +
        ["src/%s.c" % n for n in
         ("host_vm", "host_thread", "host_time", "host_time_convert")])


def c_array(name, data):
    return "static const uint8_t %s[] = {%s};\n" % (
        name, ",".join(str(b) for b in data))


def write_inc(fx, work):
    lay = fx["layout"]
    defs = {"BASE": BASE, "STACK": STACK, "STACK_SIZE": STACK_SIZE, "SP": SP,
            "SENTINEL": SENTINEL, "THUNK": THUNK, "BUDGET": BUDGET,
            "IMAGE_SIZE": lay["image_size"], "TEXT_SIZE": lay["text"][1],
            "RO_OFF": lay["ro"][0], "RO_SIZE": lay["ro"][1],
            "DATA_OFF": lay["data"][0], "DATA_SIZE": lay["data"][1],
            "BSS_SIZE": lay["bss_size"], "DYNSYM": lay["dynsym_count"],
            "INIT_VA": fx["init_va"], "ENTRY": fx["fx_entry"],
            "UNADMITTED": fx["fx_unadmitted"], "FX_DATA": fx["fx_data"],
            "TEXT_MAP": page_up(lay["text"][1]),
            "RO_MAP": page_up(lay["ro"][1]),
            "DATA_MAP": page_up(lay["data"][1] + lay["bss_size"])}
    text = "".join("#define %s %dull\n" % kv for kv in sorted(defs.items()))
    text += c_array("g_raw", fx["flat"])
    text += c_array("g_sha", bytes.fromhex(_sha(fx["flat"])))
    text += c_array("g_digest", bytes.fromhex(fx["digest"]))
    with open(os.path.join(work, "fixture.inc"), "w") as handle:
        handle.write(text)
    with open(os.path.join(work, "probe.c"), "w") as handle:
        handle.write(PROBE_C)
    fx["maps"] = defs


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def find_vcvars(explicit):
    if explicit:
        return explicit
    hits = sorted(glob.glob("C:/Program Files/Microsoft Visual Studio/*/*/VC/"
                            "Auxiliary/Build/vcvars64.bat"))
    if not hits:
        raise Infra("vcvars64.bat not found; pass --vcvars")
    return hits[-1]


def q(path):
    return '"%s"' % str(path).replace("/", "\\")


CFLAGS = "/nologo /W4 /WX /%s /std:c11 /D_CRT_SECURE_NO_WARNINGS"


def build_core(work, repo, vcvars, opt):
    objdir = os.path.join(work, "core_obj")
    os.makedirs(objdir, exist_ok=True)
    bat = os.path.join(work, "build_core.cmd")
    with open(bat, "w") as handle:
        handle.write("@echo off\r\ncall %s >nul\r\ncd /d %s\r\n"
                     "cl %s /c /I%s /I%s /Fo:%s\\ %s\r\n"
                     % (q(vcvars), q(work), CFLAGS % opt,
                        q(os.path.join(repo, "src/aot")),
                        q(os.path.join(repo, "src")), q(objdir),
                        " ".join(q(os.path.join(repo, c)) for c in CORE)))
    checked(["cmd.exe", "/c", bat])
    return sorted(glob.glob(os.path.join(objdir, "*.obj")))


def build_probe(work, repo, vcvars, opt, tag, sources, objs, catalog):
    exe = os.path.join(work, "probe_%s.exe" % tag)
    odir = os.path.join(work, "obj_%s" % tag)
    os.makedirs(odir, exist_ok=True)
    bat = os.path.join(work, "build_%s.cmd" % tag)
    with open(bat, "w") as handle:
        handle.write("@echo off\r\ncall %s >nul\r\ncd /d %s\r\n"
                     "cl %s %s /I%s /I%s /Fo:%s\\ probe.c %s %s /Fe:%s\r\n"
                     % (q(vcvars), q(work), CFLAGS % opt,
                        "/DFX_CATALOG" if catalog else "",
                        q(os.path.join(repo, "src/aot")),
                        q(os.path.join(repo, "src")), q(odir),
                        " ".join(q(s) for s in sources),
                        " ".join(q(o) for o in objs), q(exe)))
    out = checked(["cmd.exe", "/c", bat])
    if "warning" in out.lower():
        raise Infra("%s: compiler warning:\n%s" % (tag, out[-2000:]))
    return exe


def run_probe(exe, scen, x1=0, x2=0, spadj=0):
    out = checked([exe, str(scen), str(x1), str(x2), str(spadj)])
    return json.loads(out.strip())


# --------------------------------------------------------------- Unicorn

def unicorn_run(fx, scen, x1, x2, stops, block_starts):
    from unicorn import (Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE,
                         UC_HOOK_INTR)
    from unicorn import arm64_const as A
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    u.ctl_set_cpu_model(A.UC_CPU_ARM64_A57)
    maps = fx["maps"]
    size = maps["DATA_OFF"] + maps["DATA_MAP"]
    u.mem_map(BASE, size)
    u.mem_write(BASE, fx["linked"])
    u.mem_map(STACK, STACK_SIZE)
    u.mem_map(SENTINEL, PAGE)
    xr = [getattr(A, "UC_ARM64_REG_X%d" % i) for i in range(31)]
    for i, r in enumerate(xr):
        u.reg_write(r, 0x0101010101010101 * (i + 1))
    for i, v in enumerate((scen, x1, x2)):
        u.reg_write(xr[i], v)
    u.reg_write(xr[30], SENTINEL)
    u.reg_write(A.UC_ARM64_REG_SP, SP)
    u.reg_write(A.UC_ARM64_REG_NZCV, 0xa0000000)
    for i in range(32):
        lo = 0x1111111111111111 * ((i % 15) + 1)
        hi = (~lo ^ i) & 0xFFFFFFFFFFFFFFFF
        u.reg_write(A.UC_ARM64_REG_V0 + i, (hi << 64) | lo)
    u.reg_write(A.UC_ARM64_REG_FPCR, 0)
    u.reg_write(A.UC_ARM64_REG_FPSR, 0)
    trace, events, stopped = [], [], []

    def hook(uc, pc, _size, _user):
        if pc in stops:
            stopped.append(pc)
            uc.emu_stop()
            return
        if pc in block_starts:
            trace.append(pc)

    def intr(uc, _intno, _user):
        pc = uc.reg_read(A.UC_ARM64_REG_PC)
        word = struct.unpack("<I", bytes(uc.mem_read(pc - 4, 4)))[0]
        if word & 0xFFE0001F != 0xD4000001:
            raise Infra("Unicorn trap at 0x%x is not an SVC" % pc)
        events.append([HLE_SVC, (word >> 5) & 0xFFFF, pc - 4, pc])
        uc.reg_write(xr[0], (uc.reg_read(xr[0]) * 3 + 1)
                     & 0xFFFFFFFFFFFFFFFF)
    u.hook_add(UC_HOOK_CODE, hook)
    u.hook_add(UC_HOOK_INTR, intr)
    u.emu_start(fx["fx_entry"], 0, count=BUDGET)
    if not stopped:
        raise Infra("Unicorn did not reach an independent stop %s"
                    % [hex(s) for s in stops])
    v = []
    for i in range(32):
        val = u.reg_read(A.UC_ARM64_REG_V0 + i)
        v.append([val & 0xFFFFFFFFFFFFFFFF, val >> 64])
    return {"x": [u.reg_read(r) for r in xr],
            "sp": u.reg_read(A.UC_ARM64_REG_SP),
            "pc": u.reg_read(A.UC_ARM64_REG_PC),
            "nzcv": u.reg_read(A.UC_ARM64_REG_NZCV),
            "fpcr": u.reg_read(A.UC_ARM64_REG_FPCR),
            "fpsr": u.reg_read(A.UC_ARM64_REG_FPSR), "v": v,
            "trace": trace, "events": events,
            "text": fnv(u.mem_read(BASE, maps["TEXT_MAP"])),
            "ro": fnv(u.mem_read(BASE + maps["RO_OFF"], maps["RO_MAP"])),
            "data": fnv(u.mem_read(BASE + maps["DATA_OFF"], maps["DATA_MAP"])),
            "stack": fnv(u.mem_read(STACK, STACK_SIZE))}


# --------------------------------------------------------------- scenarios

COMPARED = ("code", "fault", "src", "target", "steps", "out", "x", "sp", "pc",
            "nzcv", "fpcr", "fpsr", "tpidr", "v", "trace", "trace_overflow",
            "events", "text", "ro", "data", "stack", "fxdata", "lk_entry",
            "lk_unadmitted", "is_entry_unadmitted")


def resolve(result, meta):
    """(fault kind, src pc, metadata-resolved pc) for a status-bearing fault."""
    unsup, switch = status_maps(meta)
    if result["code"] == FAULT["UNSUPPORTED_INSN"]:
        return ("unsupported", result["src"], unsup.get(result["status"]))
    if result["code"] == FAULT["BAD_STATE"] and result["status"] in switch:
        return ("local-switch", result["src"], switch[result["status"]])
    return ("raw", result["src"], result["status"])


def scenarios(fx, x_meta):
    data_end = BASE + fx["maps"]["DATA_OFF"] + fx["maps"]["DATA_MAP"]
    sw = x_meta["local_switch_sites"]
    if len(sw) != 1:
        raise Infra("expected one proven local switch, got %d" % len(sw))
    return [("normal x1=%d" % i, 0, i, 0, 0) for i in range(5)] + [
        ("STR to RO", 1, 0, 0, 0),
        ("STP straddling the mapped data end", 2, 0, data_end - 8, 0),
        ("misaligned entry SP", 0, 0, 0, -8),
        ("x30 altered before RET", 4, 0, 0, 0),
        ("SP altered before RET", 5, 0, 0, 0),
        ("exclusive ABA", 6, 0, 0, 0),
        ("exclusive size mismatch", 7, 0, 0, 0),
        ("BLR to compiled-but-unadmitted", 8, 0, 0, 0),
        ("STP straddling RO -> RW", 9, 0, BASE + fx["maps"]["DATA_OFF"] - 8, 0),
        ("LDR unmapped", 10, 0, UNMAPPED, 0),
        ("BLR into the switch ADR block (guard bypass)", 11, 0,
         fx["adr_pc"], 0),
        ("undecodable word (partial)", 12, 0, 0, 0)]


def expect(fx, name, scen, x1, x2, spadj, r, pristine):
    """Closed-form, scenario-specific outcome (independent of X and Y)."""
    d = fx["fxdata0"]
    if spadj:
        return r["code"] == FAULT["BAD_STATE"] and r["steps"] == 0 and \
            r["trace"] == []
    if scen == 0:
        sw = [10, 11, 12, 13, 0x99][x1]
        return (r["code"] == 0 and r["out"] == 0xc1 == r["x"][0] and
                r["fxdata"][:7] == [0x37, sw, 0xc1, d[3], d[4],
                                    0x7ff0000000000000, 0x4000000000000000] and
                r["fpsr"] == 0x2 and r["sp"] == SP and r["events"] ==
                [[HLE_SVC, 0x21, fx["svc_pc"], fx["svc_pc"] + 4]])
    if scen == 1:
        return (r["code"] == FAULT["MEMORY"] and r["target"] == fx["fx_ro_word"]
                and r["ro"] == pristine["ro"] and r["data"] == pristine["data"])
    if scen in (2, 9):
        return (r["code"] == FAULT["MEMORY"] and r["target"] in (x2, x2 + 8)
                and r["ro"] == pristine["ro"] and r["data"] == pristine["data"])
    if scen in (4, 5):
        return r["code"] == FAULT["BAD_RETURN"]
    if scen in (6, 7):
        return (r["code"] == 0 and r["x"][2] & 0xFFFFFFFF == 1 and
                r["x"][1] == 0x1234 and r["fxdata"][8] == 0x1234 and
                r["data"] == pristine["data"])
    if scen == 8:
        return (r["code"] == FAULT["UNTRANSLATED"] and r["src"] == fx["blr8_pc"]
                and r["target"] == fx["fx_unadmitted"] == r["pc"] and
                r["lk_unadmitted"] == 0 and r["is_entry_unadmitted"] == 0 and
                r["lk_entry"] == 1)
    if scen == 10:
        return r["code"] == FAULT["MEMORY"] and r["target"] == UNMAPPED
    if scen == 11:
        return (r["code"] == FAULT["BAD_STATE"] and r["src"] == fx["br_pc"] and
                r["target"] == fx["bad_case"] and
                r["target"] not in fx["switch_targets"])
    if scen == 12:
        return (r["code"] == FAULT["UNSUPPORTED_INSN"] and
                r["src"] == fx["unsup_pc"])
    return False


ORACLE_STOPS = {0: lambda fx: {SENTINEL}, 4: lambda fx: {SENTINEL + 16},
                5: lambda fx: {SENTINEL}, 8: lambda fx: {fx["fx_unadmitted"]},
                11: lambda fx: {fx["bad_case"]}}
ORACLE_FIELDS = ("x", "sp", "pc", "nzcv", "fpcr", "fpsr", "v", "trace",
                 "events", "text", "ro", "data", "stack")


def run_native(fx, x, ys, exes):
    pristine = None
    block_starts = set(pc for pc, _ in table_pcs(x["text"]))
    for name, scen, x1, x2, spadj in scenarios(fx, x["meta"]):
        rx = run_probe(exes["X"], scen, x1, x2, spadj)
        if pristine is None:
            pristine = {"ro": fnv(fx["linked"][fx["maps"]["RO_OFF"]:]
                                  [:fx["maps"]["RO_MAP"]].ljust(
                                      fx["maps"]["RO_MAP"], b"\0")),
                        "data": fnv(fx["linked"][fx["maps"]["DATA_OFF"]:]
                                    .ljust(fx["maps"]["DATA_MAP"], b"\0"))}
        if expect(fx, name, scen, x1, x2, spadj, rx, pristine):
            ok("X  %-46s code=%d src=0x%x target=0x%x steps=%d"
               % (name, rx["code"], rx["src"], rx["target"], rx["steps"]))
        else:
            fail("X  %s: closed-form expectation violated: %s"
                 % (name, {k: rx[k] for k in ("code", "src", "target",
                                              "status", "steps")}))
        for tag, y in ys.items():
            ry = run_probe(exes[tag], scen, x1, x2, spadj)
            diff = [k for k in COMPARED if rx[k] != ry[k]]
            rsx, rsy = resolve(rx, x["meta"]), resolve(ry, y["meta"])
            if rsx != rsy:
                diff.append("status%s" % ((rsx, rsy),))
            if diff:
                fail("%s %s: differs from X in %s (X code=%d target=0x%x, Y "
                     "code=%d target=0x%x)" % (tag, name, diff, rx["code"],
                                               rx["target"], ry["code"],
                                               ry["target"]))
                continue
            note = ""
            if rsx[0] != "raw":
                note = " [%s src=0x%x resolves to 0x%x; raw X=%d Y=%d]" % (
                    rsx[0], rsx[1], rsx[2], rx["status"], ry["status"])
            ok("%s == X: %s (%d fields)%s" % (tag, name, len(COMPARED), note))
            if scen == 8:
                c = ry["cand"]
                if c["unadmitted_found"] and c["unadmitted_fn"] and \
                        not c["unadmitted_fn_in_table"] and \
                        ry["lk_unadmitted"] == 0:
                    ok("%s: catalog body for 0x%x is linked (fn != NULL) but "
                       "aot_program_lookup returns NULL and the AotImage does "
                       "not reference it" % (tag, fx["fx_unadmitted"]))
                else:
                    fail("%s: compiled-but-unadmitted evidence wrong: %r "
                         "lookup=%d" % (tag, c, ry["lk_unadmitted"]))
        if scen in ORACLE_STOPS and not spadj:
            uni = unicorn_run(fx, scen, x1, x2, ORACLE_STOPS[scen](fx),
                              block_starts)
            bad = [k for k in ORACLE_FIELDS if uni[k] != rx[k]]
            if bad:
                fail("Unicorn %s: native differs in %s" % (name, bad))
            else:
                ok("Unicorn A57 == X: %s (%d fields)" % (name,
                                                         len(ORACLE_FIELDS)))


# --------------------------------------------------------------- negatives

def expect_refusal(what, fn, reason):
    import g3_fde_emit as E
    try:
        fn()
    except E.EmitError as exc:
        if exc.reason == reason:
            ok("%s -> refused %s" % (what, reason))
            return exc
        fail("%s -> refused %s, expected %s (%s)" % (what, exc.reason, reason,
                                                     exc.detail))
        return exc
    fail("%s -> ACCEPTED, expected refusal %s" % (what, reason))
    return None


def python_negatives(fx, work, E, T):
    flat, layout, man = fx["flat"], fx["layout"], fx["manifest"]
    all_starts = [s for s, _e in fx["bounds"]]
    ent = fx["window"]["fx_entry"]

    def cat(m=man, starts=all_starts, base=BASE):
        return E.build_catalog(flat, layout, m, base, "fx", starts)

    # manifest contract
    for key, val, reason in (("kind", "authority-table", "manifest-kind"),
                             ("authority", "admitted", "manifest-authority"),
                             ("schema_version", 99, "manifest-schema")):
        bad = json.loads(json.dumps(man))
        bad[key] = val
        expect_refusal("manifest %s=%r" % (key, val),
                       lambda b=bad: cat(b), reason)
    bad = json.loads(json.dumps(man))
    bad["module"]["sha256"] = "0" * 64
    expect_refusal("manifest module sha256 != flat", lambda: cat(bad),
                   "manifest-module-mismatch")
    # boundary shifted +-4 through the public path
    for delta in (-4, 4):
        expect_refusal("select start fx_entry%+d" % delta,
                       lambda d=delta: cat(starts=[ent[0] + d]),
                       "boundary-not-in-manifest")
        bad = json.loads(json.dumps(man))
        for b in bad["boundaries"]:
            if int(b["start"], 16) == ent[0]:
                b["end"] = "0x%x" % (ent[1] + delta)
        expect_refusal("forged manifest end fx_entry%+d" % delta,
                       lambda b=bad: cat(b), "manifest-boundaries-mismatch")
    # windows a manifest would never hold: the authority step re-derives FDEs
    good_c, good_meta = cat()
    entries = [fx["fx_entry"]]
    shifted = {"start-4": (ent[0] - 4, ent[1]), "start+4": (ent[0] + 4, ent[1]),
               "end-4": (ent[0], ent[1] - 4), "end+4": (ent[0], ent[1] + 4)}
    want_kind = {"start-4": {"missing"}, "start+4": {"straddle"},
                 "end-4": {"end"}, "end+4": set()}
    _r, blocks, _v, proofs = E.closure(flat, layout, BASE, entries, True)
    for label, win in shifted.items():
        others = [b for b in fx["bounds"] if b[0] != ent[0]]
        c2, m2 = E._catalog_from_bounds(flat, layout, BASE, "fx",
                                        sorted([win] + others), True,
                                        good_meta["manifest_sha256"])
        expect_refusal("authority over window fx_entry %s" % label,
                       lambda c=c2, m=m2: E.build_table(flat, layout, BASE,
                                                        "fx", entries, m, c),
                       "catalog-window-not-fde")
        _cov, rep = E.check_partition(blocks, proofs, m2)
        kinds = set(rep["mismatch_counts"])
        if kinds == want_kind[label]:
            ok("partition check alone, window %s: mismatch kinds %s%s"
               % (label, sorted(kinds) or "none",
                  "" if kinds else " (the extra word is padding no closure "
                  "block reaches; refused above by the FDE check)"))
        else:
            fail("partition check, window %s: kinds %s, expected %s"
                 % (label, sorted(kinds), sorted(want_kind[label])))
    # natural partition mismatch with exact FDE windows: an admitted root in
    # the middle of fx_ctor splits a block the function-local CFG keeps whole
    mid = fx["fx_ctor"] + 8
    exc = expect_refusal("admitted root mid-fx_ctor (exact FDE windows)",
                         lambda: E.build_table(flat, layout, BASE, "fx",
                                               entries + [mid], good_meta,
                                               good_c), "partition-mismatch")
    if exc is not None and getattr(exc, "report", None):
        counts = exc.report["mismatch_counts"]
        if counts == {"end": 1, "missing": 1}:
            ok("partition mismatch counted: %s" % counts)
        else:
            fail("partition mismatch counts %s != {end:1, missing:1}" % counts)
    # CLI: refusal writes the report and nothing else
    cat_c = os.path.join(work, "neg_cat.c")
    cat_j = os.path.join(work, "neg_cat.json")
    with open(cat_c, "wb") as handle:
        handle.write(good_c.encode("utf-8"))
    with open(cat_j, "wb") as handle:
        handle.write(json.dumps(good_meta).encode("utf-8"))
    ent_p = os.path.join(work, "neg_entries.json")
    with open(ent_p, "w") as handle:
        json.dump(["0x%x" % e for e in entries + [mid]], handle)
    outs = [os.path.join(work, "neg_tab." + s) for s in ("c", "json")]
    rep_p = os.path.join(work, "neg_rep.json")
    proc = subprocess.run(
        [sys.executable, E.__file__, "table", "--flat", fx["flat_path"],
         "--layout", fx["layout_path"], "--guest-base", "0x%x" % BASE,
         "--name", "fx", "--entries", ent_p, "--catalog-json", cat_j,
         "--catalog-c", cat_c, "--out-c", outs[0], "--out-json", outs[1],
         "--report", rep_p], capture_output=True, text=True)
    if proc.returncode == 2 and "REFUSED partition-mismatch" in proc.stdout \
            and not any(os.path.exists(p) for p in outs) \
            and os.path.exists(rep_p):
        with open(rep_p) as handle:
            ok("CLI refusal: exit 2, no table written, report %s"
               % json.load(handle)["mismatch_counts"])
    else:
        fail("CLI partition refusal: rc=%d out=%r files=%s"
             % (proc.returncode, proc.stdout,
                [os.path.exists(p) for p in outs + [rep_p]]))
    # D022: a catalog claim that differs from the admitted-graph proof
    forged = json.loads(json.dumps(good_meta))
    for b in forged["blocks"]:
        if b["switch_targets"]:
            b["switch_targets"] = b["switch_targets"][:-1]
    _cov, rep = E.check_partition(blocks, proofs, forged)
    if rep["mismatch_counts"] == {"switch": 1}:
        ok("D022: catalog target set != admitted-graph proof -> 'switch' "
           "mismatch")
    else:
        fail("D022 claim mismatch not detected: %s" % rep["mismatch_counts"])
    forged = E.seal_catalog(forged, good_c)
    forged_c = good_c.replace(good_meta["identity"], forged["identity"])
    forged = E.seal_catalog(forged, forged_c)
    expect_refusal("authority over a re-sealed forged D022 claim",
                   lambda: E.build_table(flat, layout, BASE, "fx", entries,
                                         forged, forged_c),
                   "catalog-not-reproducible")
    tampered = good_c.replace("rt->fault = AOT_FAULT_BAD_STATE;",
                              "rt->fault = AOT_FAULT_NONE;", 1)
    expect_refusal("authority over a tampered catalog body",
                   lambda: E.build_table(flat, layout, BASE, "fx", entries,
                                         good_meta, tampered),
                   "catalog-c-mismatch")
    expect_refusal("authority over a tampered, re-sealed catalog body",
                   lambda: E.build_table(flat, layout, BASE, "fx", entries,
                                         E.seal_catalog(good_meta, tampered),
                                         tampered),
                   "catalog-not-reproducible")
    expect_refusal("authority with strict mode over a partial catalog",
                   lambda: E.build_table(flat, layout, BASE, "fx", entries,
                                         good_meta, good_c, partial=False),
                   "catalog-partial-mismatch")
    expect_refusal("authority at another guest base",
                   lambda: E.build_table(flat, layout, BASE + PAGE, "fx",
                                         [fx["fx_entry"] + PAGE], good_meta,
                                         good_c), "catalog-base-mismatch")
    # restrict: an entry outside the window is a DecodeError
    try:
        T.build_cfg(flat, [(BASE, BASE + layout["text"][1])],
                    [fx["fx_ctor"]], [], base=BASE, module=True,
                    restrict=(BASE + ent[0], BASE + ent[1]))
        fail("build_cfg accepted an entry outside its restrict window")
    except T.DecodeError:
        ok("build_cfg refuses an entry outside the restrict window")


# --------------------------------------------------------------- main

def wrong_authority(E):
    """Negative control (child only): also list out-of-closure bodies."""
    original = E._table_entries

    def lax(blocks, covered, catalog_meta):
        table = original(blocks, covered, catalog_meta)
        have = set(pc for pc, _s, _c in table)
        for b in catalog_meta["blocks"]:
            pc = int(b["pc"], 16)
            if pc not in have:
                table.append((pc, b["fn"], True))
        return sorted(table)
    E._table_entries = lax


def run_suite(args, work):
    tools = os.path.abspath(args.tools)
    repo = os.path.abspath(args.repo)
    sys.path.insert(0, tools)
    import aot_module as M
    import aot_translate as T
    import g3_fde_emit as E
    import g3_fde_frontend as F
    if args.child_wrong_authority:
        wrong_authority(E)
    vcvars = find_vcvars(args.vcvars)
    fx = build_fixture(work, args.llvm, M, F)
    x = gen_x(fx, work, tools)
    ys = {"Y_all": gen_y(fx, work, E, "yall",
                         ["fx_entry", "fx_ctor", "fx_switch", "fx_unadmitted"]),
          "Y_mixed": gen_y(fx, work, E, "ymix",
                           ["fx_ctor", "fx_switch", "fx_unadmitted"])}
    for tag, y in ys.items():
        print("TIMING %s: catalog %.3fs, authority %.3fs"
              % (tag, y["times"][0], y["times"][1]))
    sw = x["meta"]["local_switch_sites"][0]
    fx["br_pc"] = int(sw["br_pc"], 16)
    fx["switch_targets"] = sorted(int(t, 16) for t in sw["targets"])
    fx["bad_case"] = fx["switch_targets"][0] + 12
    _r, _b, _v, proofs = E.closure(fx["flat"], fx["layout"], BASE,
                                   [fx["fx_entry"]], True)
    fx["adr_pc"] = proofs[fx["br_pc"]].window_pcs[2]
    fx["svc_pc"] = words_in(fx, "fx_entry", 0xD4000421)[0]
    fx["blr8_pc"] = words_in(fx, "fx_entry", 0xD63F0100)[0]
    fx["unsup_pc"] = words_in(fx, "fx_entry", 0)[0]
    off = fx["fx_data"] - BASE
    fx["fxdata0"] = list(struct.unpack_from("<10Q", fx["linked"], off))
    for tag, y in ys.items():
        static_checks(fx, x, y, tag, E, T)
    if not args.child_wrong_authority:
        python_negatives(fx, work, E, T)
    write_inc(fx, work)
    t0 = time.perf_counter()
    objs = build_core(work, repo, vcvars, args.opt)
    exes = {"X": build_probe(work, repo, vcvars, args.opt, "X", x["c"], objs,
                             False)}
    for tag, y in ys.items():
        exes[tag] = build_probe(work, repo, vcvars, args.opt, tag, y["c"],
                                objs, True)
    print("TIMING native build (core + 3 probes, /%s): %.1fs"
          % (args.opt, time.perf_counter() - t0))
    run_native(fx, x, ys, exes)


def negative_control(args):
    proc = subprocess.run(
        [sys.executable, os.path.abspath(__file__), "--repo", args.repo,
         "--tools", args.tools, "--llvm", args.llvm, "--opt", args.opt,
         "--child-wrong-authority"] +
        (["--vcvars", args.vcvars] if args.vcvars else []),
        capture_output=True, text=True,
        env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    fails = [line for line in proc.stdout.splitlines()
             if line.startswith("FAIL: ") and "g3_fde_emit check(s)" not in line]
    static = [line for line in fails if "lists an unadmitted catalog" in line]
    runtime = [line for line in fails
               if "BLR to compiled-but-unadmitted: differs from X" in line]
    if proc.returncode == 1 and static and runtime:
        ok("negative control: the wrong authority step (out-of-closure "
           "catalog bodies listed) makes the suite FAIL (%d checks), incl. "
           "the static table check and the runtime check: %s"
           % (len(fails), runtime[0][:120]))
    else:
        fail("negative control SURVIVED or broke: rc=%d\n%s\n%s"
             % (proc.returncode, proc.stdout[-3000:], proc.stderr[-2000:]))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=REPO)
    ap.add_argument("--tools", default=os.path.join(REPO, "tools", "aot"))
    ap.add_argument("--llvm", required=True)
    ap.add_argument("--vcvars", default=None)
    ap.add_argument("--opt", choices=("O2", "Od"), default="O2")
    ap.add_argument("--keep", default=None)
    ap.add_argument("--child-wrong-authority", action="store_true",
                    help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    work = args.keep or tempfile.mkdtemp(prefix="g3_fde_emit_")
    os.makedirs(work, exist_ok=True)
    try:
        run_suite(args, work)
        if not args.child_wrong_authority:
            negative_control(args)
    except Infra as exc:
        print("INFRA: %s" % exc)
        return 2
    finally:
        if args.keep is None:
            shutil.rmtree(work, ignore_errors=True)
    if FAILS:
        print("FAIL: %d g3_fde_emit check(s)" % len(FAILS))
        return 1
    print("PASS: g3_fde_emit (%d checks)" % OKS[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
