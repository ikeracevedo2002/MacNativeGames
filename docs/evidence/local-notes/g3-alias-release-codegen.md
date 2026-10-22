# G3 Release alias-accounting failure — local codegen evidence

## Reproducer and provenance

Unchanged `w33`/`w19-2` address-space source passes Debug but fails Release. Lead reproduced `build-w34/{Debug,Release}/aot_as_alias_map_probe.exe` twice each: Debug exit0, Release exit2. Release full suite initially 64/68, failing AS alias map, alias fault3, HLE alias, runtime mutants (positive baselines failed; no mutant success claimed).

New override positive and X0/WRITE/COUNT controls separately meet their exact exit/first-failure contracts in both configs. The alias failure predates that increment (the relevant AS/probe files are byte-identical to w19-2).

External minimization: `<local-work>/aliasfix-cl/` (`micro2.c`, `buildmicro2.cmd`, `m2rel/micro2.exe`, `m2dbg/micro2.exe`, `m2rel/asm/micro2.asm`; in-situ assembly `asm/aot_as.asm`). No game data needed by the minimal repro.

Observed compiler: MSVC **19.51.36248.0**, x64, VS18 toolset directory 14.51.36231. Failing flags `/nologo /c /W4 /WX /TC /std:c11 /DWIN32 /D_WINDOWS /O2 /Ob2 /DNDEBUG`; original Debug uses `/Od`.

## Exact defect

Well-defined source idiom:

```c
uint64_t sum = 0;
for (uint64_t i = 0; i < count; ++i)
    if ((bits[i] & 1u) == 0u) sum += 0x1000ull;
```

At `/O2` this compiler's vectorized four-byte reduction compares bytes, then **zero-extends** each true comparison (`0xff`) to a 64-bit lane and ANDs it with `0x1000`. Result is zero, not `0x1000`. Only scalar remainder pages contribute. ASM `micro2.asm:376-470`: `pcmpeqb`, `punpcklbw/lwd/ldq` against zero, `andps` weighted mask, `paddq`.

Lead independently ran the minimized witness: `/O2` original formulation has **12,279 mismatches** across four generated patterns and counts 0..4096; page-count-then-scale variants have **0**. `/Od` all variants have **0**. Expectations are closed-form pattern counts, not a second copy of the reduction.

In real AS mapping, fresh all-zero pages count4 reports out_fresh0 instead of0x4000 while host pages really are committed/mapped. Alias budget/state consequently disagree. The same weighted reduction idiom affects unmap released bytes. No guest-memory or arithmetic UB is needed to reproduce this; emitted assembly directly explains the output.

## Narrow remedy — validated in w33 candidate, not integrated

Count mapped **pages** first (masked 0/1 contributions), convert to bytes once outside the reduction. Map: `(count - mapped_pages) * PAGE`; unmap: `mapped_pages * PAGE`. Keep transaction/budget/locking/host-phase semantics, all assertions and `/O2` unchanged. No `volatile`, optimization suppression, noinline, backend substitution or weakened tests.

Reviewed w36's AS+probe delta and applied it only to w33 candidate (no main-checkout integration). Helper sums normalized `(bits[i] & AS_ALIAS_MAPPED) != 0u`; map/unmap scale once outside. Added production-path n1..12 batch/tail/accounting and hole-release rows, after existing normal rows and outside fault scenarios. Lead ran original AS + new probe as a negative: exit2 with45failures; corrected probe exits0 in /Od and /O2. Existing wrong-implementation first-failure labels are preserved.

Final lead full builds `/W4 /WX` exit0; Debug68/68 and Release68/68 CTest exit0; 46/46 runtime mutants rejected with infra0 BOTH configs. Faithful Start rerun still stops at the intended unregistered FS thunk28 after400blocks; no service or guest state was stubbed. Logs/commands: `w33-final-validation.md`. The original failing Release logs are retained, not overwritten.

Implementation/review and final validation status are tracked in `dtinit-continuation-status.md`. This finding does not establish a general C-backend limitation, choose D008, or prove the absence of other toolchain defects.
