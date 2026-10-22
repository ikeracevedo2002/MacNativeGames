# w33 final validation — G3 increment complete; faithful Start blocked before FS

## Candidate / scope

Current source: `<worktrees>/w33`.
Preserved previous candidate: `w19-2`. w36 supplied only a reviewed AS+AS-probe correction for the inherited Release defect, applied to w33 candidate, not main. No Git commits, integration, pushes or main-checkout modifications. Main clean at d3b45204. Workers stopped; worktrees retained.

Exactly eight delta paths versus w19-2:

- `CMakeLists.txt`: real override probe + three wrong-implementation executables.
- `tests/aot/g3_start_hle.h` and `.c`: seven exact-name Mac overrides, counters, refusal of real filesystem initializer.
- `tests/aot/aot_g3_start_probe.c`: name-bound registration, explicit no-FS-handler post-finalize check, per-name counters and diagnostic-only post-call fault state.
- `tests/aot/aot_g3_start_hle_override_probe.c`: new hermetic full guest-state/byte preservation, argument-width/range, null/unmapped output, exact faults/counters and lookup tests.
- `tools/aot/g3_mutant_test.py`: X0/WRITE/COUNT controls, exact first semantic failures.
- `src/aot/aot_as.c`: map/unmap count pages then convert once to bytes; avoids proven MSVC /O2 weighted-reduction miscompile, with no semantic/order/flag changes.
- `tests/aot/aot_as_alias_map_probe.c`: appended production-path batch/tail/hole accounting regression rows; original fault seams/first-failure checks retained.

Source SHA256 manifest: `w33-final-source-manifest.json`. Existing-file CRLF preserved; new override probe LF. `git diff --check` exit0; independent check found no trailing whitespace in all eight changed paths. No generated game/build artifacts introduced into source. PORTING_STATUS and architectural decisions unchanged by this increment because no gate exit condition/lasting architecture changed.

## Final lead build/test commands and observed results

CMake/CTest executables:
`C:/Program Files/Microsoft Visual Studio/18/Community/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/{cmake.exe,ctest.exe}`.
External build: `<local-work>/build-w34` (source points to w33, VS18 AMD64, MN_BUILD_AOT_PROOF=ON, MN_TOTK_V0_DIR external v0). New targets and touched AOT targets compile `/W4 /WX`; Release optimization was NOT disabled.

For each `cfg` in `Debug`, `Release`, in sequence:

```text
cmake --build <local-work>/build-w34 --config <cfg> --parallel 4
ctest --test-dir <local-work>/build-w34 -C <cfg> --output-on-failure
```

| Configuration | Build exit | CTest exit | Full CTest | Time |
|---|---:|---:|---:|---:|
| Debug | 0 | 0 | 68/68, zero failed | 173.18s |
| Release | 0 | 0 | 68/68, zero failed | 161.41s |

Logs: `w33-final-{Debug,Release}-{build,ctest}.log`.

Additional direct mutant-driver validation BOTH configs:

```text
python w33/tools/aot/g3_mutant_test.py --exedir <local-work>/build-w34/<cfg>
```

Both exits0: **rejected=46, infra_failures=0**. Logs `w33-final-{Debug,Release}-mutants.log`.

New override controls checked independently against real binaries in BOTH configs:

| Executable | Exit | Exact first line |
|---|---:|---|
| aot_g3_start_hle_override_probe | 0 | PASS: g3_start_hle_override |
| aot_g3_start_hle_mut_override_x0 | 2 | FAIL: oe Initialize leaves every guest register, flag and byte unchanged |
| aot_g3_start_hle_mut_override_write | 2 | FAIL: oe Initialize writes no guest byte |
| aot_g3_start_hle_mut_override_count | 2 | FAIL: CountAddOnContent returns 0 in x0 and changes nothing else |

Direct binary logs `w33-{Debug,Release}-aot_g3_start_hle_*.log` are from before the alias-only correction; final full mutant-driver results recheck them on final source.

## Real Start rerun on final source

```text
python w33/tools/aot/g3_start_prefix.py
  --repo <worktrees>/w33
  --work <local-work>/start-w33-final
  --v0-dir <local-work>/v0
  --vcvars "C:/Program Files/Microsoft Visual Studio/18/Community/VC/Auxiliary/Build/vcvars64.bat"
  --max-iterations 8
```

Used Python: `<python>`, PYTHONDONTWRITEBYTECODE=1. Native driver build `/W4 /WX /O2`.

Driver exit0 means captured real typed blocker, NOT successful boot:

```text
STOP code=7 src=0x10205c2fec target=0x10200fa020 status=28 steps=400
image=sdk_real class=hostcall word=0xd61f0220 br x17
```

All seven new name-bound overrides present; only OE/AOC/ERR initialization fired once each. FS thunk28 stays explicitly unregistered. nnosInitialize returned; owner0x1001; ready1/inits0/finis0. No complete real DT_INIT witness. `steps` counts AOT blocks, not individual instructions.

Exact state/source/guest-continuation/G3-vs-G4 analysis: `g3-fs-initialization-boundary.md`. Artifacts `start-w33-final/{result.json,run_start.log,build_start.log}`, driver log `start-w33-final.log`.

## Review and corrections

Lead compared incremental source directly against w19-2 (not the thousands-line inherited HEAD diff). Haiku reviewed the override surface, probes and wiring; final review reported no blockers. Corrected a bad mangled name in the initial brief (`2diag` -> authoritative `4diag`), malformed comment, null-safe lookup assertion, high64 sign/low32 semantics, exact fault fields and nonvacuous memory-write control. The pre-existing nndiagStartup required-binding behavior and its already-existing full-state tests were preserved, not duplicated.

Release audit deliberately expanded beyond the initially green Debug run and found inherited AS counter miscompilation. Lead independently reproduced the standalone C failure and inspected emitted ASM; accepted only page-count-then-scale reformulation, not disabling optimization. Helper executes under the unchanged domain lock after existing bounds/lifecycle validation; normalized boolean count <= request page count, conversion bounded by validated AS window. New batch expectations are closed-form, not calculated by the helper under test. Original-source/new-probe negative control lead-run exits2 with45failures (`w33-lead-alias-negative.log`); corrected direct probes exit0. Full final 46-control driver confirms first-failure labels retained. Details/minimized evidence: `g3-alias-release-codegen.md`, `aliasfix-cl/`.

## Limits / required next decision

G3 remains OPEN. Constructors have not run in faithful Start (inits0). FS was NOT implemented, deferred, patched out or answered with a fake Result. Mac `runtime_fs_init` has real external-resource validation/readiness/proof-file effects; it is G4 implementation work that currently blocks the chosen G3 execution witness. User must decide whether to authorize that narrow prerequisite. No final integration recommendation from this increment alone, and no integration authorized.

All validation is local. No native-Mac runtime oracle for these host overrides, no full-module AOT correctness claim, no other toolchain-version/hosted-CI coverage, no proof that this is the only optimizer issue. D008 remains OPEN.
