#!/usr/bin/env python3
"""G3 increment 3 brief E: DIFFERENTIAL ORACLE for translated module execution.

The native side (tests/aot/aot_g3_exec_probe.c, ``--oracle-dump``) runs the
NON-NESTED scenarios from a FRESH load and a FIXED initial state and writes:

    final x0..x30, sp, nzcv and the SHA-256 of each module's data segment,
    per scenario, as JSON.

This script replays exactly the same sequence on Unicorn 2.1.4 (A57) over the
same flat images:

    - map each module at its AOT-time guest base: text R+X, rodata R,
      data RW (bss zero-filled) -- so a store into text/rodata would fault,
      exactly like the sealed native address space;
    - apply the reference linker's relocations (the TSV), i.e. the SAME site
      values the loader writes;
    - map the same guest stack region;
    - emulate thunk entry in Python: on PC in the thunk region run the
      deterministic host handler and set PC = x30 AT ENTRY (the same rule as
      the runtime's "rule C"); a RET into a thunk is a BAD_TRANSFER fault;
    - stop at the return sentinel; reaching it other than by a RET is a
      BAD_RETURN fault;
    - emulate MRS CNTPCT_EL0 with the same deterministic tick sequence the C
      side uses in --oracle-dump mode.

Host<->guest NESTED scenarios (observer, host_invoke, module init) are NOT
modelled here: they have closed-form expectations in the native probe and are
explicitly closed-form only.

Exit protocol: 0 = oracle agrees field by field, 1 = MISMATCH/FAIL,
2 = infrastructure error (never a skip).
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys

try:
    import unicorn
    from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
    from unicorn import UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
    from unicorn.arm64_const import (
        UC_ARM64_REG_X0, UC_ARM64_REG_X29, UC_ARM64_REG_X30, UC_ARM64_REG_SP,
        UC_ARM64_REG_PC, UC_ARM64_REG_NZCV, UC_CPU_ARM64_A57,
    )
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
except Exception as e:  # pragma: no cover - infrastructure
    sys.stderr.write("INFRA-ERROR: Unicorn/capstone unavailable: %r\n" % (e,))
    sys.exit(2)

UNICORN_VERSION = getattr(unicorn, "__version__", "unknown")

XREGS = [UC_ARM64_REG_X0 + i for i in range(29)] + [UC_ARM64_REG_X29,
                                                    UC_ARM64_REG_X30]
THUNK_STRIDE = 16
PAGE = 0x1000
STACK_BASE = 0x2000000000
STACK_SIZE = 0x4000
STACK_TOP = STACK_BASE + STACK_SIZE
# The same scenario sequence (and order) as run_oracle_dump().
SCENARIOS = [("main_scn_calls", 0),
             ("main_scn_identity", 1),
             ("main_scn_override", 2),
             ("main_scn_callback", 3),
             ("main_scn_mod0_magic", 4),
             ("main_scn_tick", 5),
             ("main_scn_tick", 6),
             ("main_scn_tick", 7),
             ("main_scn_tick", 8),
             ("main_scn_orr", 9),
             ("main_scn_cntpct_rt8", 10),
             ("main_scn_cntpct_zr", 11),
             ("main_scn_cntvct", 12),
             ("main_scn_tpidr", 13),
             ("main_scn_pair", 14)]

# Fixed guest TPIDR values: the SAME two numbers the native probe seeds into
# AotGuestState before the oracle sequence starts.
TPIDR_EL0_VALUE = 0x1111222233334444
TPIDRRO_EL0_VALUE = 0x5555666677778888
CNTVCT_EL0_VALUE = 0x0C0FFEE0


def fail(msg):
    sys.stdout.write("FAIL: %s\n" % msg)
    return 1


def infra(msg):
    sys.stderr.write("INFRA-ERROR: %s\n" % msg)
    sys.exit(2)


def page_up(n):
    return (n + PAGE - 1) // PAGE * PAGE


class Oracle:
    def __init__(self, fixtures, config, perturb=False):
        self.fixtures = fixtures
        self.perturb = perturb
        with open(config, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        self.thunk_base = int(cfg["thunk_base"], 0)
        self.sentinel = int(cfg["sentinel"], 0)
        self.config = cfg
        self.base = {}
        for m in cfg["modules"]:
            self.base[m["name"]] = int(m["guest_base"], 0)
        self.modules = []
        self.ticks = 0
        self.last_was_ret = False
        self.thunk_span = THUNK_STRIDE * 16
        self.hook_thunk = None
        self.uc = None
        self.mnemonics = {}
        self.mrs_info = {}

    # ---- image mapping ---------------------------------------------------
    def module_name(self, variant_name):
        for name in self.base:
            if variant_name.startswith(name):
                return name
        infra("no guest base for module %r" % variant_name)

    def load(self):
        self.uc = uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        uc.ctl_set_cpu_model(UC_CPU_ARM64_A57)
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        md.detail = True          # operands are needed for the MRS destination

        for variant in ("v0",):
            for name in ("fx_main", "fx_sub", "fx_sdk"):
                img_name = "%s_%s" % (name, variant)
                flat_path = os.path.join(self.fixtures, img_name + ".flat")
                lay_path = os.path.join(self.fixtures, img_name + ".layout.json")
                if not (os.path.exists(flat_path) and os.path.exists(lay_path)):
                    infra("missing fixture %s" % img_name)
                with open(flat_path, "rb") as f:
                    flat = f.read()
                with open(lay_path, "r", encoding="utf-8") as f:
                    lay = json.load(f)
                base = self.base[name]
                image = bytearray(flat)
                if len(image) < lay["image_size"]:
                    image += bytes(lay["image_size"] - len(image))
                regions = [
                    (lay["text"][0], lay["text"][1],
                     UC_PROT_READ | UC_PROT_EXEC),
                    (lay["ro"][0], lay["ro"][1], UC_PROT_READ),
                    (lay["data"][0], lay["data"][1],
                     UC_PROT_READ | UC_PROT_WRITE),
                ]
                for off, size, perm in regions:
                    if size == 0:
                        continue
                    span = page_up(size)
                    uc.mem_map(base + off, span, perm)
                    uc.mem_write(base + off, bytes(image[off:off + size]))
                self.modules.append(dict(name=name, variant=img_name, base=base,
                                         layout=lay))
                # Decode the text once: mnemonic lookup for mrs / ret, and for
                # MRS the (system register, destination) pair, because the
                # value must be written to THAT register (Rt=31 discards).
                for insn in md.disasm(bytes(image[lay["text"][0]:
                                                  lay["text"][1]]),
                                      base + lay["text"][0]):
                    self.mnemonics[insn.address] = insn.mnemonic
                    if insn.mnemonic == "mrs":
                        sysname = insn.op_str.split(",")[-1].strip()
                        rd = 31
                        if insn.operands:
                            rname = insn.reg_name(insn.operands[0].reg)
                            if rname not in ("xzr", "wzr"):
                                rd = int(rname.lstrip("xw"))
                        self.mrs_info[insn.address] = (sysname, rd)

        uc.mem_map(self.thunk_base, page_up(self.thunk_span),
                   UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_map(self.sentinel, page_up(THUNK_STRIDE * 16),
                   UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        self.apply_relocations()

    # ---- the reference linker's relocations (the loader's exact writes) --
    def apply_relocations(self):
        tsv = os.path.join(self.fixtures, "fx_v0.sites.tsv")
        if not os.path.exists(tsv):
            infra("missing %s" % tsv)
        count = {"relative": 0, "symbolic": 0}
        with open(tsv, "r", encoding="utf-8") as f:
            header = f.readline().rstrip("\n").split("\t")
            if header[:5] != ["module", "where", "kind", "symbol", "value"]:
                infra("unexpected TSV header %r" % (header,))
            for line in f:
                if not line.strip():
                    continue
                mod, where, kind, _sym, value = line.rstrip("\n").split("\t")
                base = self.base[self.module_name(mod)]
                addr = base + int(where, 0)
                val = int(value, 0)
                self.uc.mem_write(addr, val.to_bytes(8, "little"))
                count["relative" if int(kind, 0) == 1027 else "symbolic"] += 1
        self.reloc_count = count

    # ---- thunk / sentinel / MRS emulation --------------------------------
    def on_code(self, uc, address, size, _user):
        if address >= self.thunk_base and \
                address < self.thunk_base + self.thunk_span:
            self.enter_thunk(uc, address)
            return
        if address >= self.sentinel and \
                address < self.sentinel + THUNK_STRIDE * 16:
            # Reaching the sentinel IS how a scenario ends, so this is not a
            # fault in the oracle: the BAD_RETURN case (a transfer that reaches
            # the sentinel without a RET) is only reachable from
            # main_scn_bad_br_sentinel, which is NOT part of the oracle
            # sequence -- it stays closed-form in the native probe, where the
            # exact fault_src/fault_target VAs are asserted. (Review fix 10: the
            # dead branch that fabricated a fault here was removed rather than
            # left untested.)
            return
        mnem = self.mnemonics.get(address)
        if mnem == "mrs":
            sysname, rd = self.mrs_info[address]
            if sysname == "cntpct_el0":
                val = 0x1000 + self.ticks      # same sequence as hle_det_tick
                self.ticks += 1
            elif sysname == "cntvct_el0":
                val = CNTVCT_EL0_VALUE
            elif sysname == "tpidr_el0":
                val = TPIDR_EL0_VALUE
            elif sysname == "tpidrro_el0":
                val = TPIDRRO_EL0_VALUE
            else:
                self.fault = ("UNMODELLED_MRS", address, sysname)
                uc.emu_stop()
                return
            # Rt = 31 is the architectural discard: the read still happens, but
            # no register is written (review fix 10).
            if rd != 31:
                uc.reg_write(XREGS[rd], val & 0xFFFFFFFFFFFFFFFF)
            self.last_was_ret = False
            uc.reg_write(UC_ARM64_REG_PC, address + 4)
            return
        self.last_was_ret = (mnem == "ret")

    def enter_thunk(self, uc, address):
        idx = (address - self.thunk_base) // THUNK_STRIDE
        if self.last_was_ret:
            # A RET into a thunk is BAD_TRANSFER in the runtime. That case comes
            # only from main_scn_bad_ret_thunk, which is not in the oracle
            # sequence (fault scenarios stay closed-form in the native probe
            # with exact src/target VAs), so it is reported as an unreachable
            # surprise instead of pretending to model the fault (fix 10).
            self.fault = ("UNEXPECTED_RET_INTO_THUNK", address)
            uc.emu_stop()
            return
        if idx != self.hook_thunk:
            self.fault = ("NO_HANDLER", idx)
            uc.emu_stop()
            return
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        x0 = x0 * 3 + (2 if self.perturb else 1)
        uc.reg_write(UC_ARM64_REG_X0, x0 & 0xFFFFFFFFFFFFFFFF)
        resume = uc.reg_read(UC_ARM64_REG_X30)
        self.last_was_ret = False
        uc.reg_write(UC_ARM64_REG_PC, resume)

def parse_scenario_labels(dump):
    """The C dump labels are '<symbol>#<i>'; the symbol gives the entry."""
    return [s["name"].split("#")[0] for s in dump["scenarios"]]


LAST = {}


def run(args):
    native = [args.probe, "--oracle-dump", args.dump, args.fixtures]
    proc = subprocess.run(native, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stdout.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        return fail("the native --oracle-dump run failed")

    with open(args.dump, "r", encoding="utf-8") as f:
        dump = json.load(f)

    oracle = Oracle(args.fixtures, args.config, perturb=args.perturb)
    oracle.load()
    LAST["oracle"] = oracle
    # Thunk index of host_hook comes from the generated bindings: the same
    # link_config.json overrides the native build used.
    cfg = oracle.config
    if "host_hook" not in cfg.get("overrides", {}):
        infra("host_hook has no override in link_config.json")
    oracle.hook_thunk = cfg["overrides"]["host_hook"]
    oracle.fault = None

    entries = {}
    for mod in oracle.modules:
        path = os.path.join(args.fixtures, mod["variant"] + ".entries.json")
        if not os.path.exists(path):
            infra("missing %s" % path)
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        # <img>.entries.json maps entry VA -> discovery sources, i.e. exactly
        # the Program entries the native loader exposes.
        for va_str, srcs in data["sources"].items():
            for src in srcs:
                if src.startswith("sym:"):
                    entries[src[4:]] = int(va_str, 0)

    labels = parse_scenario_labels(dump)
    if len(labels) != len(SCENARIOS):
        return fail("the dump has %d scenarios, the oracle expects %d"
                    % (len(labels), len(SCENARIOS)))

    uc = oracle.uc
    # Fixed initial state: the native run starts from a zeroed AotGuestState
    # whose only non-zero field is the guest stack pointer.
    uc.reg_write(UC_ARM64_REG_SP, STACK_TOP)
    # Unicorn seeds NZCV with Z set; a zeroed AotGuestState has NZCV == 0, so
    # pin the flags to the native initial state explicitly.
    uc.reg_write(UC_ARM64_REG_NZCV, 0)
    uc.hook_add(UC_HOOK_CODE, oracle.on_code)
    mismatches = 0
    for i, want in enumerate(dump["scenarios"]):
        name = labels[i]
        if name != SCENARIOS[i][0]:
            return fail("scenario %d is %s, the oracle expects %s"
                        % (i, name, SCENARIOS[i][0]))
        va = entries.get(name)
        if va is None:
            infra("no entry VA for %s" % name)
        oracle.last_was_ret = False
        oracle.fault = None
        uc.reg_write(UC_ARM64_REG_X30, oracle.sentinel)
        uc.emu_start(va, oracle.sentinel, timeout=30 * 1000 * 1000, count=0)
        if oracle.fault is not None:
            mismatches += 1
            sys.stdout.write("FAIL: %s faulted in the oracle: %r\n"
                             % (name, oracle.fault))
            continue

        got_x = [uc.reg_read(r) for r in XREGS]
        got_sp = uc.reg_read(UC_ARM64_REG_SP)
        got_nzcv = uc.reg_read(UC_ARM64_REG_NZCV) & 0xF0000000
        want_x = [int(v, 16) for v in want["x"]]
        if len(want_x) != 31:
            infra("dump state has %d registers" % len(want_x))
        for r in range(31):
            if got_x[r] != want_x[r]:
                mismatches += 1
                sys.stdout.write(
                    "FAIL: %s x%d native=0x%016x oracle=0x%016x\n"
                    % (name, r, want_x[r], got_x[r]))
        if got_sp != int(want["sp"], 16):
            mismatches += 1
            sys.stdout.write("FAIL: %s sp native=%s oracle=0x%016x\n"
                             % (name, want["sp"], got_sp))
        if got_nzcv != int(want["nzcv"], 16):
            mismatches += 1
            sys.stdout.write("FAIL: %s nzcv native=%s oracle=0x%08x\n"
                             % (name, want["nzcv"], got_nzcv))
        for k, mod in enumerate(oracle.modules):
            lay = mod["layout"]
            raw = uc.mem_read(mod["base"] + lay["data"][0], lay["data"][1])
            got = hashlib.sha256(bytes(raw)).hexdigest()
            if got != want["data"][k]:
                mismatches += 1
                sys.stdout.write(
                    "FAIL: %s %s data digest native=%s oracle=%s\n"
                    % (name, mod["name"], want["data"][k], got))

    if mismatches:
        return fail("%d field mismatch(es) between the native run and the "
                    "Unicorn oracle" % mismatches)
    return 0


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe", required=True)
    ap.add_argument("--fixtures", required=True)
    ap.add_argument("--config", required=True)
    ap.add_argument("--dump", default=None)
    ap.add_argument("--perturb", action="store_true",
                    help="deliberately corrupt one handler result")
    ap.add_argument("--no-self-control", action="store_true")
    args = ap.parse_args(argv)
    if args.dump is None:
        args.dump = os.path.join(args.fixtures, "oracle_dump.json")

    rc = run(args)
    if args.perturb:
        if rc == 0:
            return fail("--perturb was NOT detected (the comparison is dead)")
        sys.stdout.write("G3 exec oracle: perturbation detected as required\n")
        return 0
    if rc != 0:
        return rc
    if not args.no_self_control:
        # Negative control: the SAME comparison must reject a perturbed
        # handler, otherwise a green oracle proves nothing.
        cmd = [sys.executable, os.path.abspath(__file__),
               "--probe", args.probe, "--fixtures", args.fixtures,
               "--config", args.config,
               "--dump", args.dump + ".perturb.json",
               "--perturb", "--no-self-control"]
        sub = subprocess.run(cmd, capture_output=True, text=True)
        if sub.returncode != 0:
            sys.stdout.write(sub.stdout)
            sys.stderr.write(sub.stderr)
            return fail("the negative control (--perturb) did not run cleanly")
        sys.stdout.write("negative control: a perturbed override result IS "
                         "detected by the same comparison\n")
    oracle = LAST["oracle"]
    sys.stdout.write("G3 exec oracle: native and Unicorn agree on %d "
                     "scenarios / %d modules / %d relocations "
                     "(unicorn %s)\n"
                     % (len(SCENARIOS), len(oracle.modules),
                        oracle.reloc_count["relative"] +
                        oracle.reloc_count["symbolic"], UNICORN_VERSION))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
