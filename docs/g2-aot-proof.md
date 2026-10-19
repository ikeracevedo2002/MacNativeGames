# G2 AOT proof — scoped finite-subset checkpoint

Referenced by `src/aot/aot_abi.h`. This records a **scoped, opt-in proof** of the
AOT ARM64 -> x86-64 path. **Full G2 is NOT closed** (see "Not closed"). It is
not game/loader/graphics evidence and makes no performance claim.

Build/test is opt-in and dev-only: `-DMN_BUILD_AOT_PROOF=ON`. The existing G1
build and CI do not depend on LLVM, Python, Unicorn or Capstone.

## Architecture (what this proof actually builds)

Offline, out of tree:

```
owned ARM64 fixture .s
  -> LLVM llvm-mc + llvm-objcopy           (bin)
  -> tools/aot/aot_translate.py            (exact-mask decode + manifest CFG)
  -> generated straight-line native C + metadata (subset id, ABI/layout, SHA256,
     FNV1a64, blocks, ranges, thunks)
```

At runtime the generated C dispatcher calls generated block entry functions;
this dispatcher is a finite, sorted, pretranslated-only switch over typed block
exit reasons. There is **no opcode decoder, no interpreter and no JIT**, and no
dynamically allocated or written executable code (the static PE `.text` is
naturally RX). **No ARM64 payload is loaded, decoded or executed at runtime.**

- Translated C is compiled into the static image. Blocks are C functions.
- The native side uses the **Windows x64 standard compiler ABI** for translated
  functions. Host recursion into translated code is not used.
- HLE is a registered **typed native C callback** (`AotHleHandler`,
  `void (*)(AotGuestState *, const AotHleRequest *, void *)`): a fixed native
  function that mutates guest state and returns, with a fixed resume. There are
  no non-local exits and no tail-calls into HLE. PC is owned by the runtime.
  **Host -> guest callback/reentry is not supported.**
- `x[30]` (LR) holds a guest virtual address.
- Diagnostics carry source and target PCs.

### Guest-state ABI (`AotGuestState`, `src/aot/aot_abi.h`)

- 816 bytes total, **8-byte alignment (no 16-byte promise)**.
- `x[31]` (x0..x30), separate `sp` and `pc`, `nzcv` normalized to bits 31..28,
  `v[32]` 128-bit lanes, `fpcr`/`fpsr` low 32 bits meaningful, `tpidr`/`tpidrro`.
- `x18` is an ordinary guest GPR; the Mac x18 platform-register reservation is
  a host detail, not part of the guest contract.
- Single-threaded arena only — **not a real guest VM**. FPCR/FPSR are part of
  the state and are round-tripped; **numerical FP semantics are out of scope**.
  No atomics/ordering model.

### Runtime contract

- Thunk stride is **16 bytes**; count `<= UINT32_MAX`; base non-zero, 4-byte
  aligned; checked span must not overflow or overlap declared code ranges.
- STOP is legal **only immediately after a RET** (the fixture's proof-harness
  sentinel). It is **not** a guest thread-exit ABI: a B/BR/BL/fall-through to
  the sentinel is `AOT_FAULT_UNKNOWN_PC`.
- HLE writes are non-idempotent (`^=`) to prove guest-visible writes rather
  than preservation.

## Independent references (dev-only)

- **Capstone 5.0.7** `tools/aot/reference_cfg.py` independently derives the CFG
  block-start set from the declared manifest ranges. Neither the oracle nor
  this CFG path imports translator semantics. The derived set is compared to
  `meta.blocks` **before any case**, and drives the Unicorn PC trace.
- **Unicorn 2.1.4**, CPU pinned to `UC_CPU_ARM64_A57`, is the differential
  oracle. Normal cases require native STOP + final PC 0 and an oracle with no
  unexpected fault; infra errors/timeouts/nonzero exits fail, never skip.
- The generated-C SHA256 covers raw bytes, manifest, generator config, subset,
  ABI/layout and mutant mode. This is a **config/image fingerprint, not the
  real G3 exact-version loader source hash**.

## Offline guarantees

- Exact decode masks (opcode + fixed fields); unknown/reserved encodings fail
  closed with `DecodeError`.
- Manifest CFG: aligned, in-file, disjoint ranges; entries inside ranges.
- Native C SHA256 + FNV1a64; subset/ABI/layout identity checked at runtime.
- `tests/aot/decoder_cfg_test.py` also checks complete 4-byte Capstone decode
  over every declared range and validates thunk shape offline.

## Coverage (finite subset "g2-core-v1")

- Supported semantics: X/W `add`/`sub` (immediate incl. `lsl #12`, shifted
  register incl. ASR), `movz`/`movk` moves, all 16 conditions with NZCV,
  CBZ/CBNZ W vs X, direct/indirect calls (`bl`/`blr`/`br`) with x30 capture,
  stack frames (`stp`/`ldp` pre/post-index, pair 32/64-bit), offset memory
  (`ldr`/`str`), scalar double bitwise `fmov`/`fabs`/`fneg` (bit ops only),
  and vector `.16B` `and`/`orr`/`eor`/`add`/`sub` (SWAR, no saturating/QC).
- **Integer logical ops (`and`/`orr`/`eor`/`eor`-style scalar) are NOT
  implemented**; the only logical operations are the vector forms above.
- Out of scope: any numeric FP arithmetic, FP rounding/NaN/exceptions,
  conversions, atomics/exclusives/ordering.

## Cases and controls (in-tree)

- **684** differential cases: **683 exact** + **1** deliberately-faulted case
  (`ldr` OOB, expected `AOT_EXIT_FAULT`/`AOT_FAULT_MEMORY`).
- **8** real-lowering negative controls (`aot_translate.py --mutant`):
  `wrongcarry`, `lostwzeroext`, `wrongcond`, `blrorder`, `strdrop`,
  `scalarupper`, `pair32trunc`, `hlex18`. Each must be rejected by the same
  comparator; compiler/crash/timeout/parse errors are infra failures, not
  rejections.
- **Separate** structural tests: `aot_decoder_cfg` (decode masks + independent
  Capstone CFG + SHA identity) and `aot_runtime_contract`
  (`aot_runtime_probe.c` uses fake blocks — not translation coverage).

## Reproducible commands (opt-in, dev-only)

Requirements are **development-only** and pinned in
`tools/aot/requirements.txt` (`unicorn==2.1.4`, `capstone==5.0.7`); they are
not installed by CMake:

```
python -m pip install -r tools/aot/requirements.txt
```

Configure (this tree; tool paths cached by CMake). On a fresh machine pass the
tools explicitly, since only `PATH` is searched by default:

```
cmake -S . -B <BUILDDIR> -G "Visual Studio 18 2026" -A x64 \
      -DMN_BUILD_AOT_PROOF=ON \
      -DAOT_LLVM_MC=<llvm-mc.exe> \
      -DAOT_LLVM_OBJCOPY=<llvm-objcopy.exe> \
      -DAOT_PYTHON=<python.exe>
```

Build and run the AOT tests (15 tests total with AOT on):

```
cmake --build <BUILDDIR> --config Debug
ctest --test-dir <BUILDDIR> -C Debug -R aot_
cmake --build <BUILDDIR> --config Release
ctest --test-dir <BUILDDIR> -C Release -R aot_
```

With `-DMN_BUILD_AOT_PROOF=OFF` (default) the same tree builds and runs only
the 10 G1 host tests.

## Evidence summary (lead-verified local)

```
Debug/Release: cases=684 exact=683 fault_exact=1 mismatch=0
mutants: rejected=8 infra_failures=0
ctest -R aot_ : 5/5 passed (Debug and Release)
ctest full (AOT ON): 15/15 (10 G1 + 5 AOT)
MSVC /W4 /WX: 0 errors
```

Hosted CI has **not** been run from this branch; the above is local
evidence only.

The C backend is a **scoped proof** (readable generated C + installed MSVC +
an actual differential run), not a full-module vs LLVM benchmark.

External (lead-provided, **non-exhaustive, not a committed regression**):
1,000,000 raw words seed `0x62a071` -> 97,411 accepted, 0 Capstone-invalid
accepted; 576 random SIMD/scalar-bit states seed `0xa0762` matched Unicorn on
a stage-3 snapshot; AMD64 imports are CRT+Kernel32, isolated run (only
exe/input/`PATH` to System32) matched. No silicon or native-Mac reference was
executed.

## Not closed

Full G2 remains open for **numerical FP** (FPCR/FPSR rounding/NaN/exceptions
semantics) and **atomics/exclusives/ordering**; both are **PLAN** only. A
runtime **fault/exception policy is a separate G3 row, not a G2 exit
condition**. D008 (global backend choice) stays **OPEN**. Stop reason: new
correctness-sensitive FP/atomic architecture is needed before broadening; the
substantial scoped proof above is done. No real game, loader, graphics or
performance work is claimed.
