# G2 continuation handoff — CURRENT

**Authoritative candidate (this is the latest source):**
`C:/Users/IKER/.pi/agent/harness/worktrees/MacNativeGames-106250b2/w6-2`,
branch `pi-agent/w6-2`, base commit `0a30a282`. Its tracked **and untracked**
files must be preserved exactly; nothing is committed or pushed.
All session workers are stopped. Worker IDs may not persist across sessions;
use the absolute candidate path above.

- `w1-2` is an older **unfinished** worktree and `w5-2` is the **superseded**
  historical source (the original long handoff lives untouched in `w5-2`).
  Neither is the latest candidate.
- The main checkout (**branch `windows-x86-port`**, not a branch named `main`)
  is **CLEAN** at `0a30a282`. No integration, no commit, no push, no G3 or game
  inputs. **Explicit user approval is required before any integration.**

**Current exit state:** G2 is **locally validated for the controlled-fixture
proof** (GOAL.md G2 / Plan Phase 1) and the candidate is **awaiting user
approval**. G2 is **not already integrated into the main checkout**. D008
(global backend) and D007 (graphics backend) remain **OPEN**. G3 is the module
**loader/linking** step, with the runtime fault/exception policy as its
separate **NOT STARTED** prerequisite; real **game boot** is later still
(**G4/G6**), and none of these have begun.

**Next step:** the user reviews and approves (or rejects) integration of this
candidate. Do **not** automatically start G3, and do not queue follow-up tasks
before the worker has SETTLED. Harness watchdog: `900000` ms.

## Lead-verified evidence (external, spaces-in-path builds)

Source is this `w6-2` tree. The **actual final build directories** (both with
spaces in the path) are:

- AOT ON: `C:/Users/IKER/mn g2 final validation`
- AOT OFF: `C:/Users/IKER/mn g2 final off`

Build/test logs (not committed):

- `C:/Users/IKER/mn/g2-final-debug-build.log` /
  `C:/Users/IKER/mn/g2-final-release-build.log`
- `C:/Users/IKER/mn/g2-final-debug-ctest.log` /
  `C:/Users/IKER/mn/g2-final-release-ctest.log`
- repeats: `C:/Users/IKER/mn/g2-final-repeat-Debug.log` /
  `C:/Users/IKER/mn/g2-final-repeat-Release.log`
- AOT-OFF: the lead re-ran the OFF CTest, so
  `C:/Users/IKER/mn/g2-final-off-debug-ctest.log` and
  `C:/Users/IKER/mn/g2-final-off-release-ctest.log` now exist, each **10/10**
  (the `g2-final-off-{debug,release}-{build,ctest}.log` pattern is current)
- external FP audit dir: `C:/Users/IKER/mn g2 closure fp audit`

Results:

```
Debug   ctest 22/22 (58.99 s)   Release ctest 22/22 (58.69 s)
        differential cases=3049 exact=3048 fault_exact=1 mismatch=0
        standard mutants rejected=12 infra_failures=0
        native-only 392 fault + 3 bitwise + 10 closed
        guardmut control: typed STOP with changed FPCR/dest
        AOT-OFF Debug 10/10 and Release 10/10
Repeats 7 tests x 100 x Debug+Release = 1400 runs, all PASS (16.40/16.08 s)
Manual Release cross-checks (NOT CTest): 4 exact exit 1, intended semantic
        diagnostics, no FATAL (real/noinv wrong mode, normal guard mode,
        guardmut default = exactly 392 typed STOP-instead-of-FAULT errors)
```

SHA256 `e0d04c3b628b6c7dadeb0a937e8b5e1cd2ed4238c824192136b7db91ee75d63b` is the
**FP helper source** (`src/aot/aot_fp.c`), unchanged from the lead-rebuilt
Release; 69,408 raw A57 oracle rows audited with ZERO errors. Release binary
is AMD64/COFF x86_64 with CRT+Kernel32 imports; in a **non-exhaustive PE/import
audit** no Unicorn or dynamic-execution API imports were observed. External non-exhaustive audits: 1,000,000 raw words seed
`0x62a072` -> 97,287 accepted, 0 Capstone-invalid; 12,288 constructed
exclusive encodings zero conflicts; all 2304 FP matrix cells verified against
actual width/op (192 groups x 12).

## Commands (full tool paths; external build dir outside the source tree)

CMake/CTest binaries:

```
C:/Program Files/Microsoft Visual Studio/18/Community/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe
C:/Program Files/Microsoft Visual Studio/18/Community/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/ctest.exe
```

Configure (AOT proof ON; tool paths are cached after the first configure):

```
cmake -S C:/Users/IKER/.pi/agent/harness/worktrees/MacNativeGames-106250b2/w6-2       -B <BUILDDIR> -G "Visual Studio 18 2026" -A x64       -DMN_BUILD_AOT_PROOF=ON       -DAOT_LLVM_MC=C:/Users/IKER/tools/LLVM/bin/llvm-mc.exe       -DAOT_LLVM_OBJCOPY=C:/Users/IKER/tools/LLVM/bin/llvm-objcopy.exe       -DAOT_PYTHON=C:/Users/IKER/AppData/Local/Python/pythoncore-3.14-64/python.exe
```

Build/test (generated files land in `<BUILDDIR>/aot_gen/`, not `gen/`):

```
cmake --build <BUILDDIR> --config Debug
ctest --test-dir <BUILDDIR> -C Debug --output-on-failure
cmake --build <BUILDDIR> --config Release
ctest --test-dir <BUILDDIR> -C Release --output-on-failure
```

AOT-OFF (G1 only): configure with `-DMN_BUILD_AOT_PROOF=OFF` (default) -> 10/10.

## Caveats to keep

- The pinned Unicorn A57 oracle **masks unsupported FPCR bits**, so the 392
  unsupported-mode rows are **native-only** and counted separately from the
  3049 oracle cases; the oracle is also **value-based** for exclusives, so the
  same-value/ABA invalidation constraint is pinned by independent architectural
  reasoning plus the locked C-race-free wrong-backend controls. That is a known
  limitation of the oracle model, not a claim about upstream bugs.
- Bitwise `fmov`/`fabs`/`fneg` are the **low-32 ABI caveat**: they are unmasked
  by the numeric guard and must stay bitwise even with `FPCR=FPSR=0xffffffff`
  (all 32 bits set). Scalar upper-lane zeroing is per width: S results zero
  bits 127:32, D results zero bits 127:64.
- The 12 standard mutant rejections are 11 real-lowering generator mutants
  (`--mutant`) plus the `hlex18` native HLE-callback control, which is built
  with the test-only compile define `MN_MUTANT_HLE_X18` rather than by the
  generator; `pair32trunc` also asserts exact fault fields.
- SC ordering is deliberately stronger than the guest's weak model; barrier
  dropping is therefore not a valid mutant, and no weak/TSO backend is claimed.
- Guard cross-checks are manual exact-exit evidence (the harness refuses
  `WILL_FAIL`, which would count an infrastructure `exit(1)` as accepted).
- No FP16/FMA/sqrt/FP-conversion/full SIMD/full ISA, no alias/guest VM, no
  host->guest callback/reentry, no hardware or native-Mac oracle, no hosted CI.
- This handoff is documentation only; the validated code snapshot was frozen
  before it and is not rebuilt here.
