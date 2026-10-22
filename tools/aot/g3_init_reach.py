#!/usr/bin/env python3
"""G3 DT_INIT reachability and translatability measurement (report + entries).

The question this tool answers is NOT "what percentage of the text decodes".
It is: **which code does the boot's DT_INIT actually need**, following

  * the three modules' DT_INIT stubs (the same three the Mac loader calls),
  * every address in each module's DT_INIT_ARRAY (after the reference link's
    relocations are applied - these are the real constructors),
  * direct B/B.cond/CBZ/CBNZ/TBZ/TBNZ/BL targets,
  * statically inferable indirect targets: a BR/BLR whose register was loaded
    in the same block chain from a relocated data/rodata slot through the
    normal `adrp; ldr; add; br` / `adrp; ldr; blr` pointer idiom,

and separates:

  * code that is architecturally valid (Capstone 5.0.7 decodes it) but outside
    the current translator subset (`sub` mode) - the real ISA-family work,
  * words reachable by control flow that Capstone cannot decode at all - a
    code/data ambiguity or a missing indirect resolution, never a silent skip,
  * indirect transfers that cannot be resolved statically (fail-closed runtime
    unknowns, listed per site with module/PC/register).

The scan is block based.  Constant state is propagated along intra-function
edges (fallthrough/conditional/unconditional) and discarded at call and
tail-branch entries; a block is processed once per distinct incoming state
(capped, and the cap is reported).  That is a *measurement* over-approximation:
a spurious inferred target would appear as reachable code.  Every inferred
target is recorded with its source, so the report separates `pinned`
(DT_INIT/init_array) roots from inferred ones.

Inputs are the external TotK work directory produced by
`aot_module.py nso2flat` + the reference link:

  <v0>/flat/{main,subsdk0,sdk}.flat + .layout.json
  <v0>/link/real_sites.tsv             (module-relative offset -> guest value)
  <v0>/link/real_counters.json         (module bases / init_va / text ranges)
  <v0>/link/real_link_config.json      (thunk_base; observers/overrides)

Nothing game-derived is written to the repository: the report and any entries
JSON go where `--out` / `--entries-out` point.  The tool is also importable and
is covered by `tests/aot/g3_init_reach_test.py` on fully synthetic images
(code/data classification, fail-closed unknown targets, negative controls).
"""

import argparse
import collections
import json
import os
import struct
import sys

import capstone

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import aot_module as M          # noqa: E402
import aot_translate as T       # noqa: E402

MODULES = ("main", "subsdk0", "sdk")
# ELF dynamic tags the module loader consumes (aot_module only names a subset).
DT_INIT_ARRAY = 25
DT_FINI_ARRAY = 26
DT_INIT_ARRAYSZ = 27
DT_FINI_ARRAYSZ = 28
TOP_N = 25
# The graph's per-block incoming-state cap.  Hitting it is reported, never
# silently ignored: it can under-approximate reachability.
MAX_STATES_PER_BLOCK = 64
# Safety valve for a pathological graph; hitting it is a hard failure.
MAX_INSTRUCTIONS = 40_000_000

_CS = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
_CS.detail = True

CS_GRP_JUMP = capstone.CS_GRP_JUMP
CS_GRP_CALL = capstone.CS_GRP_CALL
CS_GRP_RET = capstone.CS_GRP_RET
CS_GRP_INT = capstone.CS_GRP_INT

ARM64_OP_REG = capstone.arm64.ARM64_OP_REG
ARM64_OP_IMM = capstone.arm64.ARM64_OP_IMM
ARM64_OP_MEM = capstone.arm64.ARM64_OP_MEM

_COND_MNEMONICS = ("b.", "cbz", "cbnz", "tbz", "tbnz")


class ReachError(Exception):
    """Hard, fail-closed tool error (bad image/root, cap exceeded)."""


# ----------------------------------------------------------------- mapping

def reg_index(name):
    """Guest GPR index for a Capstone name; None for SIMD/FP/other views.

    Vector/scalar-FP registers must never alias a GPR: the reachability
    tracker only carries integer pointer values, and silently mapping `d0`
    onto `x0` would invent indirect targets.
    """
    if name in ("sp", "wsp"):
        return 32
    if name in ("xzr", "wzr"):
        return 31
    if name == "fp":
        return 29
    if name == "lr":
        return 30
    if name and name[0] in "xw" and name[1:].isdigit():
        n = int(name[1:])
        if n <= 30:
            return n
    return None


def reg_width(name):
    return 32 if name and name[0] == "w" else 64


def _mask(width):
    return 0xFFFFFFFF if width == 32 else 0xFFFFFFFFFFFFFFFF


def _sx(value, bits):
    if value & (1 << (bits - 1)):
        value -= 1 << bits
    return value


# Constant provenance.  A value derived only from PC-relative encodings is
# "pin" (a translation-time fact).  A value read from the relocated image is
# "snap": the link-time snapshot of a mutable slot.  A later store, an HLE
# call or any guest call can change that slot, so a snap target is a
# CANDIDATE, never a proven runtime target.  Both are reported separately and
# a runtime dispatch into anything else must still fail closed.
PROV_PIN = 0
PROV_SNAP = 1
PROV_NAME = {PROV_PIN: "pin", PROV_SNAP: "snap"}


class Image:
    """One flat NSO image with the reference link's relocations applied.

    `sites` maps a module-relative offset to the final guest value (the
    reference linker's output, byte-identical to the C loader on the real
    set).  The relocated buffer is what MIDR-visible guest memory would hold
    after `aot_loader_relocate`; reads never go through the host.
    """

    def __init__(self, name, base, flat, layout, sites=None):
        self.name = name
        self.base = base
        self.layout = layout
        self.flat = bytes(flat)
        self.image_size = int(layout["image_size"])
        if len(flat) + int(layout.get("bss_size", 0)) != self.image_size:
            raise ReachError(
                "%s: flat 0x%x + bss 0x%x != image_size 0x%x"
                % (name, len(flat), int(layout.get("bss_size", 0)),
                   self.image_size))
        self.buf = bytearray(flat)
        if len(self.buf) < self.image_size:
            self.buf.extend(b"\x00" * (self.image_size - len(self.buf)))
        self.sites = dict(sites or {})
        for off, value in self.sites.items():
            if off < 0 or off + 8 > len(self.buf):
                raise ReachError("%s: relocation site 0x%x outside image"
                                 % (name, off))
            struct.pack_into("<Q", self.buf, off, value)
        toff, tsize = layout["text"]
        roff, rsize = layout["ro"]
        doff, dsize = layout["data"]
        self.text = (base + toff, base + toff + tsize)
        self.ro = (base + roff, base + roff + rsize)
        self.data = (base + doff, base + doff + dsize)
        self.limit = base + self.image_size
        if self.text[1] > self.limit or self.data[1] > self.limit \
                or self.ro[1] > self.limit:
            raise ReachError("%s: segment outside image" % name)
        mod0 = struct.unpack_from("<I", self.flat, 4)[0]
        tags = M.read_dynamic(self.flat, mod0, self.image_size, doff, dsize)
        self.dt_init = tags.get(M.DT_INIT)
        self.dt_init_array = tags.get(DT_INIT_ARRAY)
        self.dt_init_arraysz = tags.get(DT_INIT_ARRAYSZ)
        self.dt_fini_array = tags.get(DT_FINI_ARRAY)
        self.dt_fini_arraysz = tags.get(DT_FINI_ARRAYSZ)

    def contains(self, va):
        return self.base <= va < self.limit

    def kind(self, va):
        if self.text[0] <= va < self.text[1]:
            return "text"
        if self.ro[0] <= va < self.ro[1]:
            return "ro"
        if self.data[0] <= va < self.data[1]:
            return "data"
        if self.contains(va):
            return "bss"
        return None

    def read(self, va, size):
        """Read a little-endian value of `size` bytes at guest VA, or None."""
        if not self.contains(va) or va + size > self.limit:
            return None
        off = va - self.base
        return int.from_bytes(bytes(self.buf[off:off + size]), "little")

    def read_u32(self, va):
        v = self.read(va, 4)
        return None if v is None else v

    def init_va(self):
        if self.dt_init is None:
            return None
        return self.base + self.dt_init

    def init_array_sites(self):
        """[(guest VA, guest value)] for DT_INIT_ARRAY after relocation."""
        if self.dt_init_array is None or not self.dt_init_arraysz:
            return []
        out = []
        start = self.base + self.dt_init_array
        if self.dt_init_arraysz % 8 != 0:
            raise ReachError("%s: DT_INIT_ARRAYSZ 0x%x not a multiple of 8"
                             % (self.name, self.dt_init_arraysz))
        for i in range(0, self.dt_init_arraysz, 8):
            va = start + i
            value = self.read(va, 8)
            if value is None:
                raise ReachError("%s: init_array slot 0x%x outside image"
                                 % (self.name, va))
            out.append((va, value))
        return out


class World:
    """The three module images plus the host thunk window."""

    def __init__(self, images, thunk_base=0, thunk_count=0, sentinel=0):
        self.images = sorted(images, key=lambda im: im.base)
        self.thunk_base = thunk_base
        self.thunk_count = thunk_count
        self.sentinel = sentinel
        start = 0
        for im in self.images:
            if im.base < start:
                raise ReachError("module images overlap at 0x%x" % im.base)
            start = im.limit
        self.by_base = {im.name: im for im in self.images}

    def find(self, va):
        for im in self.images:
            if im.contains(va):
                return im
        return None

    def in_text(self, va):
        im = self.find(va)
        return im is not None and im.kind(va) == "text"

    def read(self, va, size):
        im = self.find(va)
        if im is None:
            return None
        return im.read(va, size)

    def is_thunk(self, va):
        return (self.thunk_count > 0
                and self.thunk_base <= va
                < self.thunk_base + 16 * self.thunk_count)


class Block:
    __slots__ = ("pc", "image", "end_pc", "term", "succs", "n_insns",
                 "unsupported", "data_in_code", "ambiguous", "indirects",
                 "unhandled")

    def __init__(self, pc, image, end_pc, term):
        self.pc = pc
        self.image = image
        self.end_pc = end_pc
        self.term = term
        self.succs = []
        self.n_insns = 0
        self.unsupported = None       # (pc, mnemonic, word, reason)
        self.data_in_code = None      # (pc, word)
        self.ambiguous = []           # [(pc, mnemonic, reg, why)]
        self.indirects = []           # [(pc, mnemonic, reg, value, kind)]
        self.unhandled = None         # control-flow not modelled


class Scan:
    """Reachability result for one root set."""

    def __init__(self):
        self.blocks = {}
        self.visited = {}             # module -> bytearray over text words
        self.insns = {}               # module -> reachable instruction count
        self.subset_ok = {}           # module -> supported by translator
        self.unsupported = collections.Counter()   # (mnem, reason) -> count
        self.unsupported_examples = {}
        self.unsupported_by_mnemonic = collections.Counter()
        self.unsupported_sites = set()
        self.data_in_code = []
        self.ambiguous = []
        self.ambiguous_by_kind = collections.Counter()
        self.ambiguous_sites = set()
        self.indirects = []
        self.indirect_by_kind = collections.Counter()
        self.indirect_sites = set()
        self.roots = []
        self.entries = {}             # pc -> kind
        self.entry_image = {}         # pc -> module name
        self.state_cap_hits = 0
        self.unhandled = []
        self.decoded_ok = 0
        self.decoded_bad = 0

    def entry_counts(self):
        c = collections.Counter()
        for kind in self.entries.values():
            c[kind] += 1
        return c


def _decode_one(pc, word):
    for ins in _CS.disasm(struct.pack("<I", word), pc, count=1):
        return ins
    return None


def _classify_control(ins):
    """(kind, direct targets, indirect register, cond?) or (None, ...)."""
    mn = ins.mnemonic
    groups = ins.groups
    if mn == "b":
        return "b", [ins.operands[0].imm], None
    if mn.startswith("b."):
        return "bcond", [ins.operands[0].imm], None
    if mn in ("cbz", "cbnz", "tbz", "tbnz"):
        return mn, [ins.operands[-1].imm], None
    if mn == "bl":
        return "bl", [ins.operands[0].imm], None
    if mn == "blr":
        return "blr", [], reg_index(ins.reg_name(ins.operands[0].reg))
    if mn == "br":
        return "br", [], reg_index(ins.reg_name(ins.operands[0].reg))
    if mn == "ret":
        return "ret", [], reg_index(ins.reg_name(ins.operands[0].reg)) \
            if ins.operands else 30
    if mn == "svc":
        return "svc", [], None
    if mn in ("udf", "brk", "hlt", "dcps1", "dcps2", "dcps3"):
        return "trap", [], None
    if CS_GRP_RET in groups:
        return "ret*", [], None
    if CS_GRP_JUMP in groups or CS_GRP_CALL in groups:
        return "unhandled", [], None
    return None, None, None


def _mem_address(ins, state):
    """(addr, None) for a known memory operand address, else (None, why)."""
    ops = ins.operands
    if len(ops) < 2:
        return None, "no-memory-operand"
    op = ops[1]
    if op.type == ARM64_OP_IMM:
        return op.imm, None
    if op.type != ARM64_OP_MEM:
        return None, "not-memory"
    mem = op.mem
    if mem.index != 0:
        return None, "indexed"
    base = reg_index(ins.reg_name(mem.base)) if mem.base else None
    if base is None or base not in state:
        return None, "base-unknown"
    return (state[base][0] + mem.disp) & 0xFFFFFFFFFFFFFFFF, None


_LOAD_WIDTH = {
    "ldr": 0, "ldur": 0,
    "ldrb": 1, "ldurb": 1,
    "ldrh": 2, "ldurh": 2,
    "ldrsb": 1, "ldursb": 1,
    "ldrsh": 2, "ldursh": 2,
    "ldrsw": 4, "ldursw": 4,
}
_LOAD_SIGNED = ("ldrsb", "ldursb", "ldrsh", "ldursh", "ldrsw", "ldursw")
_INT_ALU = ("add", "sub", "adds", "subs", "and", "orr", "eor", "bic", "orn",
            "eon", "andS", "tst", "cmp", "cmn", "neg", "mvn")


def _const_effect(ins, state, world):
    """Effect of `ins` on the integer-precision state, evaluated on the
    PRE-instruction state (an instruction may read and write one register).

    Returns ('set', reg, value, width, prov) or None.  Anything not modelled
    here leaves the register unknown; a load result is PROV_SNAP because the
    image is only a link-time snapshot of a mutable slot.
    """
    mn = ins.mnemonic
    ops = ins.operands
    dst = None
    width = 64
    if ops and ops[0].type == ARM64_OP_REG:
        dst = reg_index(ins.reg_name(ops[0].reg))
        width = reg_width(ins.reg_name(ops[0].reg))
    if dst is None and ops and ops[0].type == ARM64_OP_REG:
        return None                       # SIMD/FP destination: no GPR const

    def remember(value, w=None, prov=PROV_PIN):
        return ("set", dst, value & _mask(w or width), w or width, prov)

    if mn in ("adr", "adrp"):
        if len(ops) == 2 and ops[1].type == ARM64_OP_IMM:
            return remember(ops[1].imm)
        return None
    if mn == "mov":
        if len(ops) == 2 and ops[1].type == ARM64_OP_IMM:
            return remember(ops[1].imm)
        if len(ops) == 2 and ops[1].type == ARM64_OP_REG:
            src = reg_index(ins.reg_name(ops[1].reg))
            shift = ops[1].shift
            if src in state and shift.type == capstone.arm64.ARM64_SFT_INVALID                     and shift.value == 0:
                value, sw, prov = state[src]
                return remember(value, min(sw, width), prov)
        return None
    if mn == "movk":
        # Capstone keeps movk's mnemonic (only movz/movn are aliased to mov).
        if len(ops) == 2 and ops[1].type == ARM64_OP_IMM and dst in state:
            value, sw, prov = state[dst]
            shift = ops[1].shift
            if shift.type in (capstone.arm64.ARM64_SFT_INVALID,
                              capstone.arm64.ARM64_SFT_LSL)                     and shift.value in (0, 16, 32, 48):
                mask = 0xFFFF << shift.value
                nv = (value & ~mask) | ((ops[1].imm & 0xFFFF) << shift.value)
                return remember(nv, min(sw, width), prov)
        return None
    if mn in ("add", "sub"):
        if len(ops) != 3 or ops[1].type != ARM64_OP_REG:
            return None
        a = state.get(reg_index(ins.reg_name(ops[1].reg)))
        if a is None:
            return None
        prov = a[2]
        if ops[2].type == ARM64_OP_IMM:
            b = ops[2].imm
            sh = ops[2].shift
            if sh.type == capstone.arm64.ARM64_SFT_LSL:
                b = (b << sh.value) & _mask(64)
            elif sh.type != capstone.arm64.ARM64_SFT_INVALID or sh.value:
                return None
        elif ops[2].type == ARM64_OP_REG:
            if ops[2].ext != capstone.arm64.ARM64_EXT_INVALID:
                return None               # SXTW/UXTW/...: no precision claim
            src = reg_index(ins.reg_name(ops[2].reg))
            if src not in state:
                return None
            b, bw, bprov = state[src]
            prov = max(prov, bprov)
            shift = ops[2].shift
            if shift.type == capstone.arm64.ARM64_SFT_LSL:
                b = (b << shift.value) & _mask(64)
            elif shift.type == capstone.arm64.ARM64_SFT_LSR:
                b = (b & _mask(bw)) >> shift.value
            elif shift.type == capstone.arm64.ARM64_SFT_ASR:
                b = _sx(b & _mask(bw), bw) >> shift.value
            elif shift.type != capstone.arm64.ARM64_SFT_INVALID                     or shift.value:
                return None               # ROR and reserved shifts
        else:
            return None
        value = (a[0] + b) if mn == "add" else (a[0] - b)
        return remember(value, None, prov)
    if mn in _LOAD_WIDTH and dst is not None:
        addr, why = _mem_address(ins, state)
        if addr is None:
            return None
        n = _LOAD_WIDTH[mn] or (8 if width == 64 else 4)
        value = world.read(addr, n)
        if value is None:
            return None
        if mn in _LOAD_SIGNED:
            value = _sx(value, n * 8)
        return remember(value, width, PROV_SNAP)
    return None


def _written_regs(ins):
    """Registers whose pre-instruction value must not survive.

    Returns None when Capstone cannot enumerate the operands; callers must then
    discard the whole constant state rather than keep stale facts.
    """
    regs = set()
    try:
        _, written = ins.regs_access()
    except Exception:                                       # pragma: no cover
        return None
    for name in written:
        if isinstance(name, int):
            name = ins.reg_name(name)
        idx = reg_index(name)
        if idx is not None:
            regs.add(idx)
    # regs_access() reports the explicit operands only; indexed load/store
    # writeback modifies the base register as a side effect.
    try:
        if getattr(ins, "writeback", False) or \
                getattr(ins, "post_index", False):
            for op in ins.operands:
                if op.type == ARM64_OP_MEM:
                    idx = reg_index(ins.reg_name(op.mem.base))
                    if idx is not None:
                        regs.add(idx)
    except Exception:                                       # pragma: no cover
        return None
    return regs


def _apply_const_effect(ins, state, world):
    """Evaluate on the pre-instruction snapshot, then kill writes, then set."""
    eff = _const_effect(ins, state, world)
    written = _written_regs(ins)
    if written is None:
        state.clear()
        return eff
    for reg in written:
        state.pop(reg, None)
    if eff is not None:
        _, reg, value, width, prov = eff
        if reg is not None and reg != 31:
            state[reg] = (value & _mask(width), width, prov)
    return eff


CALLER_CLOBBER = frozenset(list(range(0, 19)) + [30])


def _kill_caller(state):
    """AAPCS64: x0..x18 and x30 may be changed by any call; x19..x29 survive."""
    out = dict(state)
    for reg in CALLER_CLOBBER:
        out.pop(reg, None)
    return out


def _frozen(state):
    return tuple(sorted(state.items()))


def _unfreeze(frozen):
    return dict(frozen)


def _block_of(scan, pc):
    """The block whose start range contains pc (for entry reporting only)."""
    while pc - 4 in scan.blocks:
        pc -= 4
    return scan.blocks.get(pc)


def scan_world(world, roots, subset_decoder=T.decode, module_mode=True,
               stop_entries=None):
    """Build the reachable CFG from `roots` (list of (pc, entry_kind)).

    Returns a Scan.  Every reachable word is decoded exactly once per block
    re-scan; indirect targets inferred from constant pointer state are added
    as new roots.  The fixed point terminates because a new target is only
    enqueued while it is not already a known block start.

    `stop_entries` (default None) is an optional set of PCs that must act as
    hard boundaries: the word at a stop entry is NEVER marked visited and the
    block is NEVER expanded, on every control-flow path (root, call/flow edge,
    inferred indirect target, and linear fallthrough into it).  This exists so
    a caller can keep a deliberately out-of-scope root - e.g. the pre-G4
    `nnMain` boundary - from donating reachability to code that is only
    reachable through it.  None preserves the historical behaviour exactly.
    """
    stops = frozenset(int(pc) for pc in (stop_entries or ()))
    scan = Scan()
    for im in world.images:
        scan.insns[im.name] = 0
        scan.subset_ok[im.name] = 0
        scan.visited[im.name] = bytearray(
            max(0, (im.text[1] - im.text[0]) // 4))
    work = collections.deque()
    known_starts = set()
    state_seen = collections.defaultdict(set)
    pending = []

    def add_entry(pc, kind):
        if pc in stops:
            scan.unhandled.append((pc, kind, "stop-entry"))
            return
        if not world.in_text(pc):
            scan.unhandled.append((pc, kind, "target-outside-text"))
            return
        if pc in scan.entries:
            return
        scan.entries[pc] = kind
        im = world.find(pc)
        scan.entry_image[pc] = im.name
        work.append((pc, (), kind))

    for pc, kind in roots:
        if pc is None:
            continue
        if not world.in_text(pc):
            raise ReachError("root 0x%x (%s) is not in a module text segment"
                             % (pc, kind))
        scan.roots.append((pc, kind))
        add_entry(pc, kind)

    def note_subset(pc, word):
        if subset_decoder is None:
            return True
        try:
            if module_mode:
                subset_decoder(pc, word, module=True)
            else:
                subset_decoder(pc, word)
            return True
        except T.DecodeError as exc:
            return str(exc)

    def scan_block(start, frozen, entry_kind):
        nonlocal pending
        im = world.find(start)
        state = _unfreeze(frozen)
        cur = start
        old = scan.blocks.get(start)
        blk = Block(start, im.name, start, None)
        if old is not None:
            blk.succs = list(old.succs)
            blk.indirects = list(old.indirects)
            blk.ambiguous = list(old.ambiguous)
            blk.unsupported = old.unsupported
            blk.data_in_code = old.data_in_code
            blk.unhandled = old.unhandled
        scan.blocks[start] = blk
        known_starts.add(start)
        flow = []       # (target, state carried along this intra-function edge)
        calls = []      # (target, kind); callee always starts with empty state
        indirect = []
        vmap = scan.visited[im.name]
        tbase = im.text[0]
        term_kind = None
        end_state = state
        while True:
            if cur in stops:
                # Hard boundary: no visited bit, no expansion, no edge beyond.
                blk.end_pc = cur
                blk.term = "stop"
                break
            if cur != start and cur in known_starts:
                # fall through into an existing block start
                flow.append((cur, end_state))
                blk.end_pc = cur
                blk.term = "fallthrough"
                break
            if not im.contains(cur) or not (im.text[0] <= cur < im.text[1]):
                blk.end_pc = cur
                blk.term = "leaves-text"
                blk.unhandled = (cur, "edge", None)
                scan.unhandled.append((cur, "edge", "leaves-text"))
                break
            if cur % 4:
                blk.end_pc = cur
                blk.term = "misaligned"
                blk.unhandled = (cur, "edge", None)
                scan.unhandled.append((cur, "edge", "misaligned"))
                break
            word = im.read_u32(cur)
            if word is None:
                blk.end_pc = cur
                blk.term = "unreadable"
                blk.unhandled = (cur, "edge", None)
                scan.unhandled.append((cur, "edge", "unreadable"))
                break
            ins = _decode_one(cur, word)
            if ins is None:
                blk.data_in_code = (cur, word)
                blk.unhandled = (cur, "<data-in-code>", word)
                blk.end_pc = cur
                blk.term = "data"
                if not vmap[(cur - tbase) // 4]:
                    vmap[(cur - tbase) // 4] = 1
                    scan.decoded_bad += 1
                    scan.data_in_code.append((im.name, cur, word, entry_kind))
                break
            first = not vmap[(cur - tbase) // 4]
            if first:
                vmap[(cur - tbase) // 4] = 1
                scan.decoded_ok += 1
                scan.insns[im.name] += 1
            blk.n_insns += 1
            reason = note_subset(cur, word)
            if reason is True:
                if first:
                    scan.subset_ok[im.name] += 1
            else:
                if first and (im.name, cur) not in scan.unsupported_sites:
                    scan.unsupported_sites.add((im.name, cur))
                    scan.unsupported_by_mnemonic[ins.mnemonic] += 1
                    key = (ins.mnemonic, reason)
                    scan.unsupported[key] += 1
                    if key not in scan.unsupported_examples:
                        scan.unsupported_examples[key] = (im.name, cur, word)
                if blk.unsupported is None:
                    blk.unsupported = (cur, ins.mnemonic, word, reason)
            kind, targets, ind = _classify_control(ins)
            if kind is None:
                _apply_const_effect(ins, state, world)
                cur += 4
                continue
            if kind == "unhandled":
                blk.unhandled = (cur, ins.mnemonic, word)
                scan.unhandled.append((cur, ins.mnemonic, "control-flow"))
                blk.end_pc = cur + 4
                blk.term = "unhandled"
                term_kind = "unhandled"
                break
            # terminator
            blk.end_pc = cur + 4
            blk.term = kind
            term_kind = kind
            if kind in ("b", "bcond", "cbz", "cbnz", "tbz", "tbnz"):
                end_state = state
                for t in targets:
                    # A tail `b` enters its target with a caller state this
                    # scan cannot know (many callers, callee-saved carry).
                    # Carrying our local constants would resolve indirects
                    # that are not proven at a real entry, inflating
                    # callable-complete. Only self-contained constants set
                    # inside the target block may resolve.
                    if t in stops:
                        # Barrier target: no edge into it, and for the
                        # unconditional form no fallthrough either.
                        continue
                    flow.append((t, {}) if kind == "b" else (t, end_state))
                if kind != "b":
                    flow.append((cur + 4, end_state))
            elif kind == "bl":
                end_state = _kill_caller(state)
                blocked_call = any(t in stops for t in targets)
                for t in targets:
                    if t in stops:
                        continue
                    calls.append((t, "bl"))
                if not blocked_call:
                    # A known call into a barrier also blocks its RETURN
                    # continuation: code after `bl <stopped>` is not
                    # reachable through any approved pre-G4 path.
                    flow.append((cur + 4, end_state))
            elif kind == "svc":
                end_state = _kill_caller(state)
                flow.append((cur + 4, end_state))
            elif kind in ("blr", "br"):
                end_state = state
                const_target = state[ind][0] if (ind is not None
                                                 and ind in state) else None
                if ind is not None and ind in state:
                    indirect.append((cur, ins.mnemonic, ind,
                                     state[ind][0], state[ind][2]))
                else:
                    rec = (cur, ins.mnemonic, ind, "register-unknown")
                    if rec not in blk.ambiguous:
                        blk.ambiguous.append(rec)
                    si = (im.name, cur, ins.mnemonic, ind,
                          "register-unknown")
                    if si not in scan.ambiguous_sites:
                        scan.ambiguous_sites.add(si)
                        scan.ambiguous_by_kind["register-unknown"] += 1
                        scan.ambiguous.append((im.name, cur, ins.mnemonic,
                                               ind, "register-unknown"))
                if kind == "blr" and const_target not in stops:
                    # Same barrier for a KNOWN constant indirect call: the
                    # continuation after `blr <stopped>` stays unreachable.
                    end_state = _kill_caller(state)
                    flow.append((cur + 4, end_state))
            elif kind == "ret":
                pass
            else:                       # trap
                pass
            break

        # resolve inferred indirect targets
        def note_indirect(kind, rec, sitekey):
            if sitekey in scan.indirect_sites:
                return
            scan.indirect_sites.add(sitekey)
            scan.indirect_by_kind[kind] += 1
            scan.indirects.append(rec)

        def note_ambiguous(why, rec):
            sitekey = (rec[0], rec[1], rec[2], rec[3], why)
            if sitekey in scan.ambiguous_sites:
                return
            scan.ambiguous_sites.add(sitekey)
            scan.ambiguous_by_kind[why] += 1
            scan.ambiguous.append(rec)

        for (spc, mn, reg, value, prov) in indirect:
            suffix = "-snapshot" if prov == PROV_SNAP else ""
            if world.in_text(value):
                kind = "text" + suffix
                rec = (spc, mn, reg, value, kind)
                if rec not in blk.indirects:
                    blk.indirects.append(rec)
                note_indirect(kind, (im.name, spc, mn, reg, value, kind),
                              (im.name, spc, mn, reg, value))
                if value not in blk.succs:
                    blk.succs.append(value)
                pending.append((value, mn, entry_kind, ()))
            elif world.is_thunk(value):
                kind = "thunk" + suffix
                rec = (spc, mn, reg, value, kind)
                if rec not in blk.indirects:
                    blk.indirects.append(rec)
                note_indirect(kind, (im.name, spc, mn, reg, value, kind),
                              (im.name, spc, mn, reg, value))
            elif value == 0:
                rec = (spc, mn, reg, "null")
                if rec not in blk.ambiguous:
                    blk.ambiguous.append(rec)
                note_ambiguous("null", (im.name, spc, mn, reg, "null"))
            else:
                im2 = world.find(value)
                why = "outside-image" if im2 is None else im2.kind(value)
                # blk.indirects stays UNIFORMLY (spc, mn, reg, value, why)
                # so consumers may index [4]; ambiguity keeps its own 4-tuple.
                irec = (spc, mn, reg, value, why)
                if irec not in blk.indirects:
                    blk.indirects.append(irec)
                note_indirect(why, (im.name, spc, mn, reg, value, why),
                              (im.name, spc, mn, reg, value))
                arec = (spc, mn, reg, why)
                if arec not in blk.ambiguous:
                    blk.ambiguous.append(arec)
                note_ambiguous(why, (im.name, spc, mn, reg, why))
        # intra-function edges
        for t, fstate in flow:
            if t % 4 or not world.in_text(t):
                edge_pc = blk.end_pc - 4
                blk.unhandled = (edge_pc, "edge", None)
                rec = (edge_pc, "edge", None,
                       "target-outside-text:0x%x" % t)
                if rec not in blk.ambiguous:
                    blk.ambiguous.append(rec)
                scan.unhandled.append((t, "edge", "target-outside-text"))
                if (im.name, edge_pc, "edge", None,
                        "target-outside-text") not in scan.ambiguous_sites:
                    scan.ambiguous_sites.add((im.name, edge_pc, "edge", None,
                                              "target-outside-text"))
                    scan.ambiguous.append((im.name, edge_pc, "edge", None,
                                           "target-outside-text:0x%x" % t))
                    scan.ambiguous_by_kind["target-outside-text"] += 1
                continue
            if t not in blk.succs:
                blk.succs.append(t)
            pending.append((t, "flow", entry_kind, _frozen(fstate)))
        for t, ckind in calls:
            if t % 4 or not world.in_text(t):
                blk.unhandled = (blk.end_pc - 4, "bl", None)
                scan.unhandled.append((t, ckind, "target-outside-text"))
                continue
            if t not in blk.succs:
                blk.succs.append(t)
            pending.append((t, ckind, entry_kind, ()))
        return term_kind

    # ---- fixed point -----------------------------------------------------
    steps = 0
    while work or pending:
        while work:
            pc, frozen, kind = work.popleft()
            steps += 1
            if steps > MAX_INSTRUCTIONS:
                raise ReachError("instruction cap reached (%d)" % steps)
            seen = state_seen[pc]
            if frozen in seen:
                continue
            if len(seen) >= MAX_STATES_PER_BLOCK:
                scan.state_cap_hits += 1
                continue
            seen.add(frozen)
            if pc in stops:
                scan.unhandled.append((pc, kind, "stop-entry"))
                continue
            if pc in scan.blocks and frozen != ():
                # A re-scan with a non-empty state replaces the earlier local
                # result; the graph records the union of observed edges.
                pass
            term = scan_block(pc, frozen, kind)
            if term is None:
                continue
        for pc, kind, parent, frozen in pending:
            im = world.find(pc)
            if im is None:
                scan.unhandled.append((pc, kind, "not-in-image"))
                continue
            if kind != "flow" and pc not in scan.entries:
                scan.entries[pc] = kind
                scan.entry_image[pc] = im.name
            work.append((pc, frozen, kind))
            known_starts.add(pc)
        pending = []

    # Re-read the union of block edges: a block re-scanned with another state
    # may have appended edges.  Blocks dict keeps the last scan; merge succs
    # from every block version by re-deriving from the final block contents is
    # not possible here, so keep the union in Block.succs (append is unique).
    for blk in scan.blocks.values():
        blk.succs = sorted(set(blk.succs))
    scan.insns_total = sum(scan.insns.values())
    scan.subset_total = sum(scan.subset_ok.values())
    return scan


# ------------------------------------------------------------------ report

def _propagate(scan, seeds):
    """pc -> first seeded block pc reachable from it (None if clean)."""
    witness = {pc: pc for pc in seeds}
    rev = collections.defaultdict(list)
    for pc, blk in scan.blocks.items():
        for s in blk.succs:
            rev[s].append(pc)
    changed = True
    while changed:
        changed = False
        for pc, blk in scan.blocks.items():
            if pc in witness:
                continue
            for s in blk.succs:
                if s in witness:
                    witness[pc] = witness[s]
                    changed = True
                    break
    return witness


def _witnesses(scan):
    """pc -> first block that cannot be lowered at all."""
    return _propagate(scan, [
        pc for pc, blk in scan.blocks.items()
        if blk.unsupported is not None or blk.data_in_code is not None
        or blk.unhandled is not None])


def _ambiguous_functions(scan):
    """pc -> first block with an unresolved indirect transfer."""
    return _propagate(scan, [
        pc for pc, blk in scan.blocks.items() if blk.ambiguous])


def _candidate_functions(scan):
    """pc -> first block whose target came from a link-time snapshot.

    Such a target is a good candidate but not a proven runtime value (the
    slot can be mutated between the snapshot and the dispatch), so functions
    that depend on it are not callable-complete.
    """
    return _propagate(scan, [
        pc for pc, blk in scan.blocks.items()
        # Records are not uniformly arity-5: data/outside-image indirects are
        # 4-tuples, and only link-time snapshot targets inflate precision.
        if any(len(rec) >= 5 and isinstance(rec[4], str)
               and rec[4].endswith("-snapshot") for rec in blk.indirects)])


def _plt_stub(blk):
    """Recognise the NSO PLT idiom `adrp; ldr; add; br` (loosely).

    blk.indirects records are uniformly (spc, mn, reg, value, why), whatever
    the target kind (text/thunk/data/outside-image/snapshot). A stub whose
    register points at DATA is still a 4-insn stub but is not a code proof;
    only text/thunk targets qualify here.
    """
    return (blk.n_insns == 4 and blk.term == "br"
            and bool(blk.indirects)
            and isinstance(blk.indirects[0][4], str)
            and blk.indirects[0][4].split("-snapshot")[0] in ("text", "thunk"))


def summarize(scan, world):
    """Per-module and total facts, plus the per-function verdicts."""
    witness = _witnesses(scan)
    amb = _ambiguous_functions(scan)
    cand = _candidate_functions(scan)
    per_module = {}
    for im in world.images:
        per_module[im.name] = dict(
            reachable_insns=scan.insns[im.name],
            subset_ok=scan.subset_ok[im.name],
            blocks=sum(1 for b in scan.blocks.values() if b.image == im.name),
            roots=0, constructors=0, entries=0, call_entries=0,
            indirect_entries=0, plt_entries=0,
            subset_complete=0, callable_complete=0, blocked=0,
            ambiguous=0, candidate=0,
            first_blocker=collections.Counter(),
            unsupported=collections.Counter(),
            data_in_code=0, unhandled=0,
        )
    for pc, kind in scan.roots:
        im = world.find(pc)
        if im is not None:
            per_module[im.name]["roots"] += 1
            if kind == "constructor":
                per_module[im.name]["constructors"] += 1
    for pc, kind in scan.entries.items():
        im = world.find(pc)
        if im is None:
            continue
        d = per_module[im.name]
        d["entries"] += 1
        if kind in ("bl", "blr", "br", "indirect"):
            d["call_entries"] += 1
        if kind == "indirect":
            d["indirect_entries"] += 1
        blk = scan.blocks.get(pc)
        if blk is not None and _plt_stub(blk):
            d["plt_entries"] += 1
        if pc in witness:
            d["blocked"] += 1
            wpc = witness[pc]
            wblk = scan.blocks.get(wpc)
            if wblk is not None:
                if wblk.unsupported is not None:
                    key = wblk.unsupported[1]
                elif wblk.data_in_code is not None:
                    key = "<data-in-code>"
                else:
                    key = "<%s>" % (wblk.unhandled[1]
                                    if wblk.unhandled else "unknown")
                d["first_blocker"][key] += 1
        else:
            d["subset_complete"] += 1
            if pc not in amb and pc not in cand:
                d["callable_complete"] += 1
        if pc in amb:
            d["ambiguous"] += 1
        if pc in cand:
            d["candidate"] += 1
    for blk in scan.blocks.values():
        d = per_module[blk.image]
        if blk.unsupported is not None:
            d["unsupported"][blk.unsupported[1]] += 1
        if blk.data_in_code is not None:
            d["data_in_code"] += 1
        if blk.unhandled is not None:
            d["unhandled"] += 1
    # A state-cap hit means the graph is an under-approximation; no entry may
    # be reported as callable-complete in that run.
    if scan.state_cap_hits:
        for d in per_module.values():
            d["callable_complete"] = 0
    totals = dict(
        reachable_insns=scan.insns_total,
        subset_ok=scan.subset_total,
        blocks=len(scan.blocks),
        entries=len(scan.entries),
        subset_complete=sum(d["subset_complete"]
                            for d in per_module.values()),
        callable_complete=sum(d["callable_complete"]
                              for d in per_module.values()),
        blocked=sum(d["blocked"] for d in per_module.values()),
        ambiguous=sum(d["ambiguous"] for d in per_module.values()),
        candidate=sum(d["candidate"] for d in per_module.values()),
        static_proof_complete=(scan.state_cap_hits == 0),
        callable_complete_withheld=bool(scan.state_cap_hits),
        unsupported=collections.Counter(),
        first_blocker=collections.Counter(),
        ambiguous_by_kind=collections.Counter(),
        indirect_by_kind=collections.Counter(),
        data_in_code=len(scan.data_in_code),
        state_cap_hits=scan.state_cap_hits,
        unhandled=len(scan.unhandled),
    )
    for d in per_module.values():
        totals["unsupported"].update(d["unsupported"])
        totals["first_blocker"].update(d["first_blocker"])
    totals["ambiguous_by_kind"].update(scan.ambiguous_by_kind)
    totals["indirect_by_kind"].update(scan.indirect_by_kind)
    return per_module, totals


def _fmt_pct(a, b):
    return "%.2f%%" % (100.0 * a / b) if b else "-"


def markdown_report(scan, per_module, totals, world, measured_roots,
                    split_rows=None):
    L = []
    add = L.append
    add("# G3 DT_INIT reachable-CFG measurement (real TotK 1.0.0 modules)")
    add("")
    add("REPORT ONLY. Generated by `tools/aot/g3_init_reach.py`; contains no "
        "game data. The text below is a structural measurement, not a "
        "translation result.")
    add("")
    add("## Roots")
    add("")
    add("| module | DT_INIT | DT_INIT_ARRAY | constructors |")
    add("|---|---|---|---|")
    for im in world.images:
        add("| %s | %s | %s (0x%x B) | %d |"
            % (im.name,
               ("0x%x" % im.init_va()) if im.init_va() else "-",
               ("0x%x" % (im.base + im.dt_init_array))
               if im.dt_init_array else "-",
               im.dt_init_arraysz or 0, measured_roots.get(im.name, 0)))
    add("")
    add("## Reachable code and current-subset translatability")
    add("")
    add("| module | reachable insns | translator-subset ok | ok % | "
        "blocks | entry roots | PLT stubs | subset-complete entry | "
        "scan-clean entry (not a whole-function proof) | blocked entry | "
        "ambiguous-indirect entry | snapshot-candidate entry |")
    add("|---|---|---|---|---|---|---|---|---|---|---|---|")
    for im in world.images:
        d = per_module[im.name]
        add("| %s | %d | %d | %s | %d | %d | %d | %d | %d | %d | %d | %d |"
            % (im.name, d["reachable_insns"], d["subset_ok"],
               _fmt_pct(d["subset_ok"], d["reachable_insns"]), d["blocks"],
               d["entries"], d["plt_entries"], d["subset_complete"],
               d["callable_complete"], d["blocked"], d["ambiguous"],
               d["candidate"]))
    add("| **total** | **%d** | **%d** | **%s** | **%d** | **%d** | "
        "**%d** | **%d** | **%d** | **%d** | **%d** | **%d** |"
        % (totals["reachable_insns"], totals["subset_ok"],
           _fmt_pct(totals["subset_ok"], totals["reachable_insns"]),
           totals["blocks"], totals["entries"],
           sum(d["plt_entries"] for d in per_module.values()),
           totals["subset_complete"], totals["callable_complete"],
           totals["blocked"], totals["ambiguous"], totals["candidate"]))
    add("")
    add("**subset-complete** = every reachable block decodes in the current "
        "module-mode translator subset, but the graph may still contain an "
        "unresolved indirect transfer. **scan-clean entry** = subset-complete "
        "AND no reachable block has an unresolved indirect or snapshot "
        "candidate. This counts selected ENTRY PCs only; it is NOT the number "
        "of whole required functions that are proven (there is no such count "
        "here) and no executable claim is made. `ambiguous-indirect entry` "
        "counts entries that reach at least one unresolved indirect site. "
        "`snapshot-candidate entry` counts entries whose target came from a "
        "link-time memory snapshot; such a target is a candidate, never proof, "
        "and also disqualifies scan-clean. When the per-block state cap is hit "
        "the graph is an under-approximation, so scan-clean is withheld (0) "
        "and `static proof complete` is false.")
    if not totals.get("static_proof_complete", False):
        add("")
        add("**Not a proof:** the state cap was hit %d time(s); the measured "
            "graph is an under-approximation in those blocks." % scan.state_cap_hits)
    add("")
    if split_rows:
        add("## Per-DT_INIT transitive provenance (each root set scanned alone)")
        add("")
        add("Rows are the DT_INIT root set; columns are the module whose code "
            "is reachable from it. This is transitive: e.g. main's DT_INIT "
            "reaches sdk code through PLT stubs and direct branches.")
        add("")
        add("| DT_INIT of | code module | reachable insns | function entries | "
            "subset-complete | callable-complete | blocked |")
        add("|---|---|---|---|---|---|---|")
        for root_name, rows in split_rows:
            for code_name, d in rows.items():
                add("| %s | %s | %d | %d | %d | %d | %d |"
                    % (root_name, code_name, d["reachable_insns"],
                       d["entries"], d["subset_complete"],
                       d["callable_complete"], d["blocked"]))
        add("")
    add("## First blocker of blocked function entries")
    add("")
    add("| module | blocker | functions |")
    add("|---|---|---|")
    for im in world.images:
        for key, n in per_module[im.name]["first_blocker"].most_common(TOP_N):
            add("| %s | `%s` | %d |" % (im.name, key, n))
    add("")
    add("## Blocks whose FIRST unsupported instruction has this mnemonic")
    add("")
    add("| module | mnemonic | blocks |")
    add("|---|---|---|")
    for im in world.images:
        for key, n in per_module[im.name]["unsupported"].most_common(TOP_N):
            add("| %s | `%s` | %d |" % (im.name, key, n))
    add("")
    add("## Unsupported reasons (exact decoder message)")
    add("")
    add("| mnemonic | reason | count | example |")
    add("|---|---|---|---|")
    for (mn, reason), n in scan.unsupported.most_common(TOP_N):
        ex = scan.unsupported_examples.get((mn, reason))
        add("| `%s` | %s | %d | %s |"
            % (mn, reason, n,
               ("%s 0x%x word 0x%08x" % (ex[0], ex[1], ex[2]))
               if ex else "-"))
    add("")
    add("## Indirect transfers")
    add("")
    add("| resolution | count |")
    add("|---|---|")
    for key, n in scan.indirect_by_kind.most_common():
        add("| %s | %d |" % (key, n))
    for key, n in scan.ambiguous_by_kind.most_common():
        add("| ambiguous:%s | %d |" % (key, n))
    add("")
    if scan.ambiguous:
        add("### Unresolved (fail-closed) indirect sites, first %d"
            % min(TOP_N * 4, len(scan.ambiguous)))
        add("")
        add("| module | PC | instruction | register | why |")
        add("|---|---|---|---|---|")
        for name, pc, mn, reg, why in scan.ambiguous[:TOP_N * 4]:
            add("| %s | 0x%x | `%s` | x%d | %s |"
                % (name, pc, mn, reg if reg is not None else -1, why))
        add("")
    add("## Code/data and control-flow policy")
    add("")
    add("* Reachable words Capstone cannot decode: **%d** (each is a hard "
        "`data-in-code` stop; the PC/word list is in the JSON)."
        % len(scan.data_in_code))
    add("* Unmodelled control-flow instructions: **%d** (fail-closed)."
        % len(scan.unhandled))
    add("* Blocks that hit the %d-state cap: **%d** (can under-approximate "
        "reachability; reported, not hidden)."
        % (MAX_STATES_PER_BLOCK, scan.state_cap_hits))
    if scan.data_in_code:
        add("")
        add("| module | PC | word |")
        add("|---|---|---|")
        for name, pc, word, _kind in scan.data_in_code[:TOP_N * 4]:
            add("| %s | 0x%x | 0x%08x |" % (name, pc, word))
    add("")
    add("## Totals")
    add("")
    add("* reachable instructions: %d" % totals["reachable_insns"])
    add("* reachable instructions inside the current translator subset: "
        "%d (%s)" % (totals["subset_ok"],
                     _fmt_pct(totals["subset_ok"],
                              totals["reachable_insns"])))
    add("* entry roots: %d (subset-complete %d, scan-clean entry %d, "
        "blocked %d, ambiguous-indirect %d, snapshot-candidate %d; "
        "static proof complete: %s)"
        % (totals["entries"], totals["subset_complete"],
           totals["callable_complete"], totals["blocked"],
           totals["ambiguous"], totals["candidate"],
           "yes" if totals["static_proof_complete"] else
           "NO (state cap hit)"))
    return "\n".join(L) + "\n"


# ------------------------------------------------------------------- input

def read_sites(tsv_path):
    """{module: {module-relative offset: guest value}} from the reference link."""
    sites = collections.defaultdict(dict)
    with open(tsv_path, "r", encoding="utf-8") as f:
        header = f.readline().rstrip("\n").split("\t")
        if header[:5] != ["module", "where", "kind", "symbol", "value"]:
            raise ReachError("%s: unexpected TSV header %r"
                             % (tsv_path, header))
        for line in f:
            p = line.rstrip("\n").split("\t")
            if len(p) != 5:
                raise ReachError("%s: malformed TSV row %r" % (tsv_path, p))
            mod, where, _kind, _sym, value = p
            key = mod.rsplit("_", 1)[0]
            sites[key][int(where, 16)] = int(value, 16)
    return sites


def load_world(v0_dir):
    counters_path = os.path.join(v0_dir, "link", "real_counters.json")
    cfg_path = os.path.join(v0_dir, "link", "real_link_config.json")
    tsv_path = os.path.join(v0_dir, "link", "real_sites.tsv")
    with open(counters_path, "r", encoding="utf-8") as f:
        counters = json.load(f)
    with open(cfg_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    sites = read_sites(tsv_path)
    images = []
    for spec in counters["modules"]:
        rel_name = spec["name"]
        base_name = rel_name.rsplit("_", 1)[0]
        flat_path = os.path.join(v0_dir, "flat", base_name + ".flat")
        layout_path = os.path.join(v0_dir, "flat", base_name + ".layout.json")
        with open(flat_path, "rb") as f:
            flat = f.read()
        with open(layout_path, "r", encoding="utf-8") as f:
            layout = json.load(f)
        images.append(Image(base_name, int(spec["guest_base"]), flat, layout,
                            sites.get(base_name, {})))
    thunk_count = len(cfg.get("observers", {})) + len(cfg.get("overrides", {}))
    thunk_base = int(cfg["thunk_base"], 0) if isinstance(cfg["thunk_base"], str) \
        else int(cfg["thunk_base"])
    sentinel = int(cfg.get("sentinel", 0), 0) \
        if isinstance(cfg.get("sentinel", 0), str) else int(cfg.get("sentinel", 0))
    return World(images, thunk_base, thunk_count, sentinel)


def boot_roots(world, only=None):
    """Pinned roots: DT_INIT stubs + every DT_INIT_ARRAY constructor."""
    roots = []
    counts = {}
    for im in world.images:
        if only is not None and im.name != only:
            continue
        n = 0
        if im.init_va() is not None:
            roots.append((im.init_va(), "dt_init"))
        for va, value in im.init_array_sites():
            if value == 0:
                raise ReachError("%s: init_array slot 0x%x is zero after "
                                 "relocation" % (im.name, va))
            if not world.in_text(value):
                raise ReachError("%s: init_array slot 0x%x -> 0x%x is not "
                                 "module text" % (im.name, va, value))
            roots.append((value, "constructor"))
            n += 1
        counts[im.name] = n
    return roots, counts


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--v0-dir", required=True,
                    help="external dir with flat/ and link/")
    ap.add_argument("--out", default=None, help="markdown output path")
    ap.add_argument("--json", default=None, help="JSON output path")
    ap.add_argument("--entries-out", default=None,
                    help="write per-module entries JSON into this directory")
    ap.add_argument("--no-split", action="store_true",
                    help="skip the per-DT_INIT transitive provenance scans")
    ap.add_argument("--no-subset", action="store_true",
                    help="skip current-subset checks (structural ceiling)")
    args = ap.parse_args(argv)

    world = load_world(args.v0_dir)
    roots, counts = boot_roots(world)
    dec = None if args.no_subset else T.decode
    scan = scan_world(world, roots, subset_decoder=dec)
    per_module, totals = summarize(scan, world)
    # Count the pinned roots separately from inferred entries.
    for im in world.images:
        per_module[im.name]["constructors"] = counts.get(im.name, 0)

    if args.entries_out:
        os.makedirs(args.entries_out, exist_ok=True)
        by_mod = collections.defaultdict(list)
        for pc, kind in scan.entries.items():
            im = world.find(pc)
            if im is not None:
                by_mod[im.name].append({"pc": "0x%x" % pc, "kind": kind})
        for name, rows in by_mod.items():
            path = os.path.join(args.entries_out, "entries_%s.json" % name)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(rows, f, indent=1, sort_keys=True)
                f.write("\n")
            print("wrote %s (%d entries)" % (path, len(rows)))

    split_rows = []
    if not args.no_split:
        for im in world.images:
            r, _ = boot_roots(world, only=im.name)
            s = scan_world(world, r, subset_decoder=dec)
            pm, tt = summarize(s, world)
            split_rows.append((im.name,
                               {n: pm[n] for n in (x.name for x in world.images)}))

    text = markdown_report(scan, per_module, totals, world, counts, split_rows)
    if args.out:
        out_dir = os.path.dirname(os.path.abspath(args.out))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
        print("wrote %s" % args.out)
    else:
        print(text)

    if args.json:
        summary = dict(
            roots={im.name: counts.get(im.name, 0) for im in world.images},
            modules={name: {k: (dict(v) if isinstance(v, collections.Counter)
                                else v)
                            for k, v in d.items()}
                     for name, d in per_module.items()},
            totals={k: (dict(v) if isinstance(v, collections.Counter) else v)
                    for k, v in totals.items()},
            unsupported=[{"mnemonic": mn, "reason": reason, "count": n,
                          "example": scan.unsupported_examples.get((mn,
                                                                    reason))}
                         for (mn, reason), n in scan.unsupported.items()],
            indirect=[{"module": nm, "pc": pc, "insn": mn, "reg": reg,
                       "value": value, "kind": kind}
                      for (nm, pc, mn, reg, value, kind) in scan.indirects],
            ambiguous=[{"module": nm, "pc": pc, "insn": mn, "reg": reg,
                        "why": why}
                       for (nm, pc, mn, reg, why) in scan.ambiguous],
            data_in_code=[{"module": nm, "pc": pc, "word": word,
                           "root": kind}
                          for (nm, pc, word, kind) in scan.data_in_code],
            unhandled=[{"pc": pc, "what": what, "why": why}
                       for (pc, what, why) in scan.unhandled],
            entries={("0x%x" % pc): kind
                     for pc, kind in sorted(scan.entries.items())},
            block_count=len(scan.blocks),
            state_cap_hits=scan.state_cap_hits,
            split={root: {code: {k: (dict(v) if isinstance(v,
                                                       collections.Counter)
                                     else v)
                                for k, v in d.items()}
                          for code, d in rows.items()}
                   for root, rows in split_rows},
        )
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=1, sort_keys=True)
            f.write("\n")
        print("wrote %s" % args.json)

    return 0


if __name__ == "__main__":
    sys.exit(main())
