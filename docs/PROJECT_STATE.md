# Project state and handoff (Windows x86-64 port)

Snapshot: 2026-10-22, branch `windows-x86-port`. Written so that someone who has only the
repository (no access to the developer machine, its game data or its agent worktrees)
can understand where the port stands, how to verify it, and what comes next.

Authoritative sources, in order: `GOAL.md` (gates), `DECISIONS.md` (D001–D024),
`ARCHITECTURE.md`, `PORTING_PLAN.md`, `PORTING_STATUS.md` (status board). This file
summarizes and links them; if it disagrees with them, they win.

## 1. Gate status at a glance

| Gate | Status | Notes |
|---|---|---|
| G0 foundation | Done | Docs, inventory, decisions |
| G1 host skeleton | Validated locally | 15 host tests (AOT off); no hosted CI yet |
| G2 AOT proof | Closed (controlled fixtures) | `docs/g2-aot-proof.md`, D010–D013 |
| G3 module loader / linking | **OPEN** | Loader and linking validated, including the real 1.0.0 modules. Real constructors are only partly executed (see §3) |
| G4 headless Horizon | Not started as a gate | The RomFS provider was built early as a G3 prerequisite (D020); AS memory services exist (D018/D019) |
| G5 graphics | Not started | D007 open; Vulkan is the first spike candidate (D024) |
| G6–G8 | Not started | |

## 2. Commit history of this branch

| Commit | Content |
|---|---|
| `42bcbbe` … `1ae17c4` | G0/G1: docs bootstrap, CMake x64 skeleton, host clock, TLS, threads/sync, VM, logger |
| `0a30a28`, `8793f18`, `032071e` | G2: scoped AOT translator proof, FP/atomics, integration record |
| `d3b4520` | G3: guest address space, Program dispatch, thunks, nested host->guest calls, module loader/linker (D014–D017) |
| `a38d7c6` | SavageWind audit, `docs/research/savagewind-audit.md` |
| `761d432` | D024 + roadmap changes in `PORTING_PLAN.md` |
| `be2aff7` | G3 continuation: D018 boot heap, D019 alias mapping, D020 RomFS provider, D021 veneer roots, D022 local switch edges, D023 constructor roots, plus the ISA families needed to reach them and the Start/HLE harness |
| `776bc88` | D024 Stage A: FDE candidate frontend |
| `45c89fa` | D024 Stage B: candidate catalog and authority table |

## 3. Where the real boot stands (G3)

The local Start-prefix driver is `tools/aot/g3_start_prefix.py`. It translates the real 1.0.0
main/subsdk0/sdk with the currently admitted roots, builds the probe, loads and links the
real modules and runs `nn::init::Start` as translated code. It stops at the first typed
fault and admits a new root only through D021/D022/D023 proofs.

The latest run (`start-w21-ctor`, local) had the following state:

- The SDK side of Start is complete:
  - `nnosInitialize`, `nninitInitializeSdkModule` and `nninitStartup` return.
  - The RomFS provider reaches READY with 304,207 files (D020).
  - Heap, alias, GetInfo, QueryMemory and thread-info services answer through the address space (D018/D019).
  - `__nnmusl_init_dso` runs, including its D022 local switch.
- main's DT_INIT is in its original constructor loop (`LDR x8,[x20],#8; BLR x8; CMP; B.LO`).
  - Each iteration: the loop BLRs to a constructor that is not yet translated, faults `UNTRANSLATED` at the BLR `0x1000000148`, and D023 proves the slot and admits it as a root. The driver then re-translates, rebuilds and reruns from the start.
  - 22 main constructors were returned and admitted (main#0 … #22) when the run hit its 24-iteration budget.
  - main has 10,539 init_array entries (subsdk0 45, sdk 116).
- **The cost is iteration, not semantics.** Every new constructor costs a full re-translation of three modules, an MSVC rebuild and a rerun of Start from the beginning.
  - D024 Stages A–C address this cost.
  - The next blockers after the constructors are unknown.

Translator coverage: integer, branches, memory and their addressing modes, a subset of FP/SIMD, exclusives, and the families added in `be2aff7`. These include TBZ/TBNZ, logical shifted forms, CSEL family, bitfields, CLZ/RBIT, UMULH/SMULH, variable shifts, SIMD load/store, MSR/MRS TPIDR, DMB. Unsupported words become typed `UNSUPPORTED_INSN` faults in partial mode; nothing is interpreted at run time.

## 4. D024 work in progress (frontend/build pivot)

Background:
- Source audit: `docs/research/savagewind-audit.md`, pinned to SavageWindRecomp `575ad88e02f9a89a9a885d90039d48af33c982f4`.
- Decision: adapt their frontend and per-module build ideas, keep our runtime (ABI, Program, address space, faults, exclusives, FP).

Stages:
- **Stage A, done (`776bc88`):** `tools/aot/g3_fde_frontend.py`.
  - It parses `.eh_frame_hdr`/`.eh_frame` through MOD0, fails closed on any error and emits `authority: none` candidate manifests.
  - On real 1.0.0: 242,860 / 10,061 / 31,238 FDEs, and all 10,700 constructor targets are FDE starts.
- **Stage B, done (`45c89fa`):** `tools/aot/g3_fde_emit.py`.
  - It compiles FDE functions into a non-dispatchable catalog. An authority step lists only the closure of admitted roots in the `AotImage`.
  - A BLR to a compiled-but-unadmitted body faults exactly like today.
  - Real: main `0x1520` 4/4 and `__nnmusl_init_dso` 173/173 blocks match today's emission.
  - Not executed on real data: no harness links a catalog plus table yet.
- **Stage C, next (not started).** Change the Start-prefix loop so that a newly admitted constructor no longer needs a full re-translation and rebuild:
  - Precompile a stratified batch of about 32 constructors and callees as catalog bodies.
  - Each admission then only regenerates the small table TU and relinks.
  - Measure parse, emit, compile and link time, size, unsupported instructions and rebuilds avoided.
  - The guest loop and its guards must stay; no runtime activation of code; the D023 proof is still required for every root.
  - A real-exec harness for catalog plus table builds is needed first.
- **Decision gate after C:** adopt ahead-of-time catalog generation if it reduces the per-constructor cycle without losing guarantees; then propose a concrete D008. D007 (graphics) has its own later spike, starting with NVN 55.15 / Vulkan compatibility probing (PORTING_PLAN Phase 4).

Open questions recorded but not decided:
- Horizon vs Mac symbol resolution order (D017).
- Finalizers (DT_FINI) are not modeled.
- No code/data classifier for full-module translation.
- No host VEH/SEH fault policy.
- Stage B status numbering for candidate bodies uses disjoint namespaces (see the D024 evidence); a loader-level identity check for stale catalogs does not exist.

## 5. How to build and test

Requirements:
- Windows x64, Visual Studio 2026 (VS 18) with MSVC.
- CMake, plus Python 3 with `tools/aot/requirements.txt` (`unicorn==2.1.4`, `capstone==5.0.7`, pinned on purpose).
- For the AOT tests, an LLVM toolchain with `llvm-mc`, `llvm-objcopy`, `ld.lld` and `llvm-readelf` (the developer used `C:/Users/IKER/tools/LLVM/bin`).

Build directories must be outside the source tree, because CMake refuses in-tree builds.

```bat
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
cmake -S <repo> -B <outside>\build -G "Visual Studio 18 2026" -A x64 ^
  -DMN_BUILD_AOT_PROOF=ON -DAOT_PYTHON=<python with unicorn/capstone> ^
  -DAOT_LLVM_MC=<llvm>\llvm-mc.exe -DAOT_LLVM_OBJCOPY=<llvm>\llvm-objcopy.exe ^
  -DAOT_LLD=<llvm>\ld.lld.exe -DAOT_LLVM_READELF=<llvm>\llvm-readelf.exe ^
  [-DMN_TOTK_V0_DIR=<local 1.0.0 work dir>] [-DMN_TOTK_ROOTS_DIR=<Start-prefix work dir>]
cmake --build <outside>\build --config Debug -j 12
ctest --test-dir <outside>\build -C Debug -j 6 --output-on-failure
```

Expected counts (last verified 2026-10-22 at `45c89fa`, Debug and Release, 0 warnings):

| Configuration | Tests |
|---|---|
| AOT off (default) | 15 |
| AOT on, no game data | 77 (82 minus the five real-data tests; not separately re-run) |
| AOT on + `MN_TOTK_V0_DIR` | 82: adds `aot_g3_real_link`, `aot_g3_real_exec`, `aot_g3_real_exec_neg`, `aot_g3_fde_frontend_real`, `aot_g3_fde_emit_real` |

- Preparing the real-data directory (decrypted NSO -> flat images, layouts, reference link, Mac binding tables) is described in `docs/g3-module-loader.md` §5.1. RomFS preparation is in `docs/romfs-provider.md`.
- A cloud environment without the game cannot run the real-data tests or the Start-prefix driver. Their latest results are recorded in `DECISIONS.md` (D017–D024 evidence) and `docs/evidence/local-notes/`.
- Python tests need site-packages, so do not run them with `python -I`.

## 6. Code map

| Area | Files |
|---|---|
| Host platform layer (G1) | `src/host_*.{h,c}`, `tests/host_*_probe.c` |
| Guest ABI, runtime, Program | `src/aot/aot_abi.h`, `aot_runtime.{h,c}`, `aot_program.c`, `aot_prog_assembly.c` |
| Guest memory | `src/aot/aot_mem.{h,c}` (checked accesses, exclusive monitor), `aot_as.{h,c}` (address space, heap, alias, query) |
| FP | `src/aot/aot_fp.{h,c}` |
| Loader / linker | `src/aot/aot_loader.{h,c}`, `aot_sha256.{h,c}` |
| RomFS provider (D020) | `src/romfs_provider.{h,c}`, `src/romfs_file_win.{h,c}`, `docs/romfs-provider.md` |
| Translator (offline) | `tools/aot/aot_translate.py` (decode, CFG, C emission; `--module`, `--partial`) |
| Module tooling | `aot_module.py` (NSO -> flat), `aot_real_link.py` / `g3_link_check.py` (reference linker), `extract_mac_bindings.py` |
| Root policies | `g3_veneer_roots.py` (D021), `g3_local_switch.py` (D022), `g3_ctor_roots.py` (D023) |
| Start-prefix driver and measurement | `g3_start_prefix.py`, `g3_init_reach.py`, `g3_dtinit_run.py`, `g3_dtinit_batch.py` (measurement only), `g3_coverage_report.py` |
| D024 | `g3_fde_frontend.py` (Stage A), `g3_fde_emit.py` (Stage B) |
| Oracles / negatives | `diff_driver.py` (G2), `g3_exec_oracle.py`, `*_mutant_test.py`, `reference_cfg.py` |
| Start/HLE harness | `tests/aot/g3_start_hle.{h,c}`, `tests/aot/g4_romfs_start_hle.{h,c}`, `tests/aot/aot_g3_start_*_probe.c` |

## 7. Rules that matter for any further work

- Read `AGENTS.md`. Never commit game files, keys, extracted modules, RomFS, generated game C or shader caches (D006). Real-data outputs go to build directories.
- **Compiled is not authorized** (D024): the executable entry set is the CFG closure of the roots admitted by D021/D022/D023 and the existing symbol policy. FDEs, relocations and BL/ADR scans are evidence, never roots.
- Keep the ABI (816-byte state, D010), Program and guest-VA transfers (D015), nested-call checks (D016), typed sticky faults, exclusives with domain invalidation and FP/FPSR semantics.
- Every substantive change needs a negative control that would let a wrong implementation pass otherwise, and the full Debug and Release battery.
- G3 stays OPEN until the real modules' constructors run through translated code (GOAL G3).

## 8. Agent and evidence notes

- Development used a lead agent with worker agents in Git worktrees outside the repository (`pi-agent/*` branches, local only). All accepted work is in the commits above; the remaining worktrees and branches are local scratch.
- `docs/evidence/local-notes/` holds the imported lab notes (index in `docs/evidence/README.md`). They are history, not authority.
- Nothing has been pushed by the agents. Check `git status -sb` against `origin/windows-x86-port` before assuming the remote has these commits.
