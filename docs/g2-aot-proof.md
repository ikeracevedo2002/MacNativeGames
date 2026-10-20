# G2 AOT proof — local controlled-fixture evaluation

Referenced by `src/aot/aot_abi.h`. This records the **scoped, opt-in G2 proof**
of the AOT ARM64 -> x86-64 path.

**G2 evaluation (lead, local):** the GOAL.md G2 / Plan Phase 1
*controlled-fixture* exit conditions are **SATISFIED LOCALLY** and G2 may be
recorded **CLOSED / VALIDATED for the controlled proof**. This is **not**
full-ISA parity, not title/game parity and not backend parity: the global
translated-code backend choice (D008) stays **OPEN**, the graphics backend
choice (D007) stays **OPEN**, and G3 (module loader/linking; the runtime
fault/exception policy is a separate prerequisite) had **NOT STARTED** at G2 integration (G3 status: `docs/g3-module-loader.md`), with
real game boot later still (G4/G6, none begun). The validated proof was
**integrated into `windows-x86-port` in `8793f189` after explicit user approval**.
The integration tool verified a byte-identical tree to the validated worktree.
Nothing was pushed.

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

- 816 bytes total, **8-byte alignment (no 16-byte promise)**;
  `AOT_ABI_VERSION`/`AOT_STATE_LAYOUT` unchanged by the subset expansion.
- `x[31]` (x0..x30), separate `sp` and `pc`, `nzcv` normalized to bits 31..28,
  `v[32]` 128-bit lanes, `fpcr`/`fpsr` low 32 bits meaningful, `tpidr`/`tpidrro`.
- `x18` is an ordinary guest GPR; the Mac x18 platform-register reservation is
  a host detail, not part of the guest contract.
- Subset identity is now `AOT_SUBSET_ID "g2-core-v2"` (expanded finite subset;
  same ABI and layout).

### Runtime contract

- Thunk stride is **16 bytes**; count `<= UINT32_MAX`; base non-zero, 4-byte
  aligned; checked span must not overflow or overlap declared code ranges.
- STOP is legal **only immediately after a RET** (the fixture's proof-harness
  sentinel). It is **not** a guest thread-exit ABI: a B/BR/BL/fall-through to
  the sentinel is `AOT_FAULT_UNKNOWN_PC`.
- Unsupported **numeric** FPCR modes fault **before any destination or FPSR
  write**: fault code `AOT_FAULT_BAD_STATE`, `fault_status`
  `AOT_FP_ERR_UNSUPPORTED_FPCR` (`1`), `fault_src` = operation PC, and the whole
  guest state is unchanged except the runtime-owned PC.
- The SVC/HOSTCALL boundary clears the **local** exclusive reservation as a
  **conservative G2 proof policy** — not an unconditional ARM exception-entry
  guarantee — and does not license direct arena access from HLE.
- `aot_rt_release` detaches every borrowed pointer (arena/domain, guest state,
  image); it never frees caller-owned state/image. A live runtime is
  single-owner/non-copyable with no concurrent run/release.
- HLE writes are non-idempotent (`^=`) to prove guest-visible writes rather
  than preservation.

### Memory model (serialized SC, scoped)

Shared mutable guest memory is defined **only** through the arena API
(`src/aot/aot_mem.c`), where every access (ordinary, HLE, ordered, exclusive)
is serialized under one domain-wide lock: the proof's model is **sequentially
consistent (SC)**. SC is deliberately **stronger** than the guest's weak model,
so it can never be silently weaker. Consequences for evidence:

- Barriers/ordering-demotion are therefore **not valid negative mutants** under
  this model (dropping a barrier cannot change a serialized result), and no
  barrier-drop claim is made. The wrong-backend controls are instead
  **C-race-free**: they exercise the invalidation predicate in a deterministic
  2-runtime schedule, not live-thread races.
- Exclusive/reservation invalidation uses a **64-byte proof granule** (cited
  A57 ERG4) and is deliberately conservative: any store, including a
  same-value (ABA) write or a neighbour in the granule, disarms an overlapping
  reservation; **STXR still requires an exact address+width match**.
- No alias domains (one host byte per live domain, not detectable without a
  global registry), no fixed guest VA layout and no real guest VM.

## Independent references (dev-only)

- **Capstone 5.0.7** `tools/aot/reference_cfg.py` independently derives the CFG
  block-start set from the declared manifest ranges: for the concurrency
  fixture that is an **exact per-chunk** range list (no `.org` gap/padding
  bytes); the differential fixture declares a single containing range with
  unreachable padding, and the reachable block starts come from the explicit
  entries (and indirect targets), re-derived independently by Capstone. Neither
  the oracle nor this CFG path imports translator semantics. The derived set is
  compared to `meta.blocks` **before
  any case**, and drives the Unicorn PC trace.
- **Unicorn 2.1.4**, CPU pinned to `UC_CPU_ARM64_A57`, is the differential
  oracle. Normal cases require native STOP + final PC 0 and an oracle with no
  unexpected fault; infra errors/timeouts/nonzero exits fail, never skip.
- **Known oracle limitations (not a judgment on upstream bugs):** Unicorn is
  **value-based** for exclusives, so it cannot express the same-value/ABA
  invalidation constraint; that constraint is pinned instead by independent
  architectural reasoning plus the locked wrong-backend controls. Unicorn also
  **masks unsupported FPCR bits**, so unsupported-mode rows are **native-only**
  and counted separately.
- The generated-C SHA256 covers raw bytes, manifest, generator config, subset,
  ABI/layout and mutant mode. This is a **config/image fingerprint, not the
  real G3 exact-version loader source hash**.

## Offline guarantees

- Exact decode masks (opcode + fixed fields); unknown/reserved encodings fail
  closed with `DecodeError`.
- Manifest CFG: aligned, in-file, disjoint ranges; the concurrency fixture
  uses **exact per-chunk ranges** (no `.org` gap/padding bytes), while the
  differential fixture uses one containing range with unreachable padding whose
  reachable starts are the explicit manifest entries (plus indirect targets),
  re-derived independently by Capstone. Entries must lie inside ranges; the
  independent Capstone CFG is the source of truth.
- Native C SHA256 + FNV1a64; subset/ABI/layout identity checked at runtime.
- `tests/aot/decoder_cfg_test.py` also checks complete 4-byte Capstone decode
  over every declared range, validates thunk shape offline, and includes three
  committed **width-validator negative controls** (a late D matrix case on the
  S site, a late duplicate S case on a D site, and a post-HLE D case pointed at
  the S FDIV), locking a previously found false positive.

## Coverage (finite subset "g2-core-v2")

- Integer/flags: X/W `add`/`sub` (immediate incl. `lsl #12`, shifted register
  incl. ASR), `movz`/`movk`, all 16 conditions with NZCV, CBZ/CBNZ W vs X,
  direct/indirect calls (`bl`/`blr`/`br`) with x30 capture, stack frames
  (`stp`/`ldp` pre/post-index, pair 32/64-bit), offset memory (`ldr`/`str`).
  **Scalar integer logical ops (`and`/`orr`/`eor`) are NOT implemented**; the
  implemented logical forms are the vector `.16B` ones.
- Vector: `.16B` `and`/`orr`/`eor`/`add`/`sub` (SWAR, no saturating/QC).
- Scalar double: bitwise `fmov`/`fabs`/`fneg` only (bit ops, low-32 ABI
  unmasked by the numeric guard — they must not quiet or reinterpret NaNs).
- **Numeric FP (controlled subset):** F32/F64 `fadd`/`fsub`/`fmul`/`fdiv`/
  `fcmp`/`fcmpe` over RN/RP/RM/RZ × DN × FZ with sticky FPSR.
- **Translated memory/exclusives:** `ldxr`/`stxr` B/H/W/X and `ldar`/`stlr`
  B/H/W/X differential; `ldaxr`/`stlxr` X pair end-to-end (decoder and
  lowering cover all widths, but not every width has a dedicated fixture).
- **Out of scope (unchanged limitation):** FP16, FMA, sqrt, FP conversions,
  full SIMD/NEON, full A64 ISA, weak/TSO-style orderings, alias mappings, a
  real guest VM, host->guest callbacks/reentry, hardware or native-Mac oracle,
  hosted CI, D007/D008 global choices and all of G3.

## Cases and controls (in-tree)

- **3049** differential cases: **3048 exact** + **1** deliberate fault
  (`ldr` OOB, expected `AOT_EXIT_FAULT`/`AOT_FAULT_MEMORY`), `mismatch=0` in
  Debug and Release. This count includes the **2304** numeric-FP matrix cells
  (2 widths × 6 ops × 4 RMode × 2 DN × 2 FZ × 12 operand pairs) with seeds
  0 / QC(`0x08000000`) / sticky(`0x9f`).
- **45** closed-form FP helper rows (`tests/aot/aot_fp_probe.c`, raw integer
  bits, exact FPSR) plus **10** translated closed-form rows
  (`tests/aot/aot_fp_translated_probe.c`) — no host FP arithmetic and no fitted
  expectations (pinned Unicorn A57 oracle + closed form).
- **392** native-only unsupported-FPCR fault rows (28 bits outside the literal
  supported mask `0x03c00000` × 14 numeric sites) + **3** bitwise low-32 ABI
  rows with `FPCR=FPSR=0xffffffff`. These are counted **separately** from the
  3049 oracle-based cases precisely because the oracle masks those bits.
- **12** standard negative rejections, `infra=0`: `wrongcarry`, `lostwzeroext`,
  `wrongcond`, `blrorder`, `strdrop`, `scalarupper`, `pair32trunc`, `hlex18`,
  `fpdropflags`, `stxalwaysok`, `fproundrn`, `fpnanorder`. Eleven are real
  lowering generator mutants (`aot_translate.py --mutant`); **`hlex18` is not
  a generator mutant** — it is the native HLE-callback control built from the
  same real image with the test-only compile define `MN_MUTANT_HLE_X18`. Each
  must be rejected by the same comparator; `pair32trunc` additionally asserts
  the exact fault fields, and compiler/crash/timeout/parse errors are infra
  failures, not rejections.
- **Separate** native guard control: the `fpignoreguard` mutant (unsupported
  numeric FPCR sanitized to `0` instead of faulting) is not in the standard
  Python mutant dict (its positive expectation is a native-only STOP, not an
  oracle mismatch). It has its own generated image and CTest target, which must
  report a clean STOP that violates the guard contract (typed STOP + changed
  FPCR and destination). Cross-checks (normal image in guard mode; mutant image
  in default mode) are **manual exact-exit evidence, not CTest** (the harness
  refuses `WILL_FAIL`, which would count an infrastructure `exit(1)` as an
  accepted negative).
- Translated-memory concurrency: deterministic 2-runtime schedule, real-thread
  counter at **2 and 4 threads**, and **one-way per-slot publication** (renamed
  and documented as **NOT a handshake**). The wrong **program-order** control is
  a control, **not a barrier mutant** (see the SC model above).
- Scalar results are checked with the **upper bits zeroed** per width: an S
  result must have zero bits **127:32**, a D result zero bits **127:64**;
  post-HLE rows compare the **full 128-bit** lane against the zero-extended
  expectation.
- Separate structural tests: `aot_decoder_cfg` (decode masks + independent
  Capstone CFG + SHA identity + width-validator negatives) and
  `aot_runtime_contract` (`aot_runtime_probe.c` uses fake blocks — not
  translation coverage).

## Reproducible commands (opt-in, dev-only)

Requirements are **development-only** and pinned in
`tools/aot/requirements.txt` (`unicorn==2.1.4`, `capstone==5.0.7`); they are
not installed by CMake:

```
python -m pip install -r tools/aot/requirements.txt
```

Configure. An **external build directory outside the source tree is required**
(the tree rejects in-source and source-subdirectory builds), and on a fresh
machine the tool paths must be passed explicitly, since only `PATH` is
searched by default (tool paths are cached by CMake afterwards):

```
cmake -S <SRC> -B <BUILDDIR> -G "Visual Studio 18 2026" -A x64 \
      -DMN_BUILD_AOT_PROOF=ON \
      -DAOT_LLVM_MC=<llvm-mc.exe> \
      -DAOT_LLVM_OBJCOPY=<llvm-objcopy.exe> \
      -DAOT_PYTHON=<python.exe>
```

Build and run the AOT tests (22 tests total with AOT on):

```
cmake --build <BUILDDIR> --config Debug
ctest --test-dir <BUILDDIR> -C Debug -R aot_
cmake --build <BUILDDIR> --config Release
ctest --test-dir <BUILDDIR> -C Release -R aot_
```

With `-DMN_BUILD_AOT_PROOF=OFF` (default) the same tree builds and runs only
the 10 G1 host tests.

## Evidence summary (lead-verified local, external spaces-in-path builds)

```
Fresh external builds  C:/Users/IKER/mn g2 final validation  (source: w6-2)
  Debug   ctest 22/22 passed (58.99 s)   differential cases=3049 exact=3048
                                         fault_exact=1 mismatch=0
  Release ctest 22/22 passed (58.69 s)   differential cases=3049 exact=3048
                                         fault_exact=1 mismatch=0
  standard mutants: rejected=12 infra_failures=0        (both configs)
  native-only: 392 fault + 3 bitwise + 10 closed        (both configs)
  guardmut control: typed STOP with changed FPCR/dest   (PASS)
  AOT-OFF Debug 10/10, Release 10/10
Repeats: each of the 7 runtime/fp/concurrency tests 100x per config
  => 1400 runs, all PASS (16.40 s Debug / 16.08 s Release); stability only.
Manual Release cross-checks (NOT CTest): 4 exact exit 1 with the intended
  semantic diagnostics and no FATAL (real/noinv wrong mode, normal guard mode,
  guardmut default = exactly 392 typed STOP-instead-of-FAULT errors).
FP helper source SHA256 (`src/aot/aot_fp.c`, NOT the generated-C image
fingerprint) e0d04c3b628b6c7dadeb0a937e8b5e1cd2ed4238c824192136b7db91ee75d63b
  unchanged from the lead-rebuilt Release (69,408 raw A57 oracle rows audited,
  ZERO errors).
Release binary is AMD64/COFF x86_64 with CRT+Kernel32 imports. In a
  **non-exhaustive PE/import audit** no Unicorn or dynamic-execution API
  imports were observed.
MSVC /W4 /WX: 0 errors.
```

External audits (lead-provided, **non-exhaustive, not committed
regressions**): 1,000,000 raw words seed `0x62a072` -> 97,287 accepted, 0
Capstone-invalid accepted; a constructed exclusive-encoding audit of 12,288
encodings found zero expected/Capstone conflicts; all **2304** matrix cells were
verified against their actual width/op (192 groups × 12). No silicon, no
native-Mac oracle and no hosted CI run was involved.

## Not claimed / not closed

- G2 is closed **only** for this controlled proof: no full ISA, no title/game
  evidence, no performance claim, no backend parity.
- The full-module translated-code backend (D008) remains **OPEN**; the graphics
  backend (D007) remains RESEARCH/OPEN.
- A runtime **fault/exception policy** is a separate NOT STARTED prerequisite
  row; the translated-image **loader/linking** is **G3**, and real **game
  boot** is later still (**G4/G6**). None of these have begun.
- No alias/guest-VM behavior, no weak/TSO-style orderings, no FP16/FMA/sqrt/FP
  conversion/full SIMD, no host->guest callback/reentry, no hardware/native-Mac
  oracle, no hosted CI.
- Integration was explicitly approved and completed in `8793f189`; no push
  or G3 work was performed. The retained worktree is a validation snapshot,
  not the authoritative checkout for subsequent changes.
