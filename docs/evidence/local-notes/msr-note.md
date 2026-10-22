# MSR TPIDR_EL0 evidence clarification (2026-…, w14-2)

## Correction to the final MSR report

The reported claim:
  "newfamily run with NF_OPT=/Od (Debug) and /O2 (Release), both /W4 /WX"

is **WRONG**.

Truth:
- `tests/aot/g3_newfamily_diff_test.py` `build()` hardcodes
  `cl /nologo /W4 /O2 /std:c11 /D_CRT_SECURE_NO_WARNINGS ...`
  (look at the `f.write('cl ...')` near `build()`), and does **not** read
  `NF_OPT` and does **not** pass `/WX`.
- My attempted in-memory Python replacement to add `/WX` + `NF_OPT` did NOT
  apply (escape mismatch); the file was unchanged. The `NF_OPT=/Od` and
  `NF_OPT=/O2` invocations therefore both ran the SAME hardcoded `/W4 /O2`
  build, with no `/WX`.
- Correct evidence classification: **Release-style /O2, /W4, no /WX, run
  twice with identical compiler flags** (not Debug vs Release).

## What is still valid

- Emitted module C for the MSR TPIDR_EL0 family was compiled with `/W4 /O2`
  only.
- Differential result: 90 scenarios exact vs pinned Unicorn A57, including
  `t_msr` (Rt0), `t_msr8`, `t_msr30` (LR), `t_msr31` (XZR, nonzero SP),
  with TPIDR/TPIDRRO in the compared state.
- Mutants `msr_tpidr_noop`, `msr_tpidr_tpidrro`, `msr_tpidr_xzr_sp` were
  compiled and rejected on named fields TPIDR / TPIDRRO.
- No Debug-config /WX evidence exists for the newfamily harness.

## Exact commands actually run

```
cd C:/Users/IKER/.pi/agent/harness/worktrees/MacNativeGames-106250b2/w14-2
export PATH="/c/Users/IKER/tools/LLVM/bin:$PATH"
NF_OPT=/Od PYTHONDONTWRITEBYTECODE=1 <python> -B tests/aot/g3_newfamily_diff_test.py
NF_OPT=/O2 PYTHONDONTWRITEBYTECODE=1 <python> -B tests/aot/g3_newfamily_diff_test.py
```

`NF_OPT` had no effect; both used `/W4 /O2`. Per-run build.bat lives in a
temporary dir created by the test (`tempfile.mkdtemp(prefix="aot_newfam_")`)
and is not preserved by the harness; there is therefore no distinct
`/Od+/WX` vs `/O2+/WX` build.bat path to show.

## Follow-up (not done in the budget run)

Either (a) add `NF_OPT` + `/WX` to `build()` correctly and re-run both, or
(b) record the newfamily MSR evidence as Release `/O2`, no `/WX` only.
