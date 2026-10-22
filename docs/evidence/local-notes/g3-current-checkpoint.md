# Current G3 checkpoint — w17 local-switch + UMULH, first constructor root blocked

## Candidate / disposition
- Current source: `C:/Users/IKER/.pi/agent/harness/worktrees/MacNativeGames-106250b2/w17`.
- Frozen predecessor: `.../w14-3` (D022 local-switch increment). Its evidence is `w14-switch-final-evidence.md`.
- Delta w17 vs w14-3: ONLY `DECISIONS.md`, `tools/aot/aot_translate.py`, `tests/aot/g3_decoder_module_test.py`, `tests/aot/g3_newfamily_diff_test.py`; external patch `w17-from-w14-umulh.patch` (414 lines).
- No commit/integration. Main clean. No PORTING_STATUS exit change; **G3 OPEN**.
- Writable worker w17 hit its harness 900-second deadline without a final report. Do NOT treat worker claims as evidence: primary inspected its exact delta, corrected comments, then independently ran all frozen builds/tests and the real boot below. No worker remains writing the candidate.

## Completed D022 local CFG edges (user-authorized)
- MODULE-ONLY bounded per-BR successor recovery for the admitted guarded U8 table form. No new roots or global indirect-target list.
- Original guard/ADR/LDRB/ADD/BR instructions stay real; pinned table/owner/source binding, code/data exclusions, graph dataflow and two-stage final-graph reproof. Final closure required before emission.
- Opus reviewed core + native; the H1-R corrective review cleared both, conditional on frozen tests and original SDK metadata, which primary then verified.
- H1-R strictly refuses undecoded raw entries into the post-CMP window, including ADD/BR entries after the load (UNKNOWN at those entries cannot propagate back to the load). Other owner entries retain UNKNOWN dataflow seeds and ADRP regeneration. Stage1 records threats, strict-final decides.
- 31 unit functions pass. Durable native CTest uses actual emitted C + real AotMem domain/token and an independent Unicorn A57 oracle; normal/default indices plus ADR-block bypass; compiled no-guard/extra-target/first-target-only variants distinguish the runtime membership guard.
- Native probe is DEV/direct-BB, not a full Program/AS-host-RO proof. NZCV output is compared; root CMP overwrites input flags. Raw branch-word scanning is negative-only and may conservatively refuse DATA-like words. EH exclusion is documented RO-suffix over-approximation. No universal classifier for unannotated TEXT data is claimed.
- w14 frozen full CTest: 76/76 Debug (227.02s), Release (431.07s).
- Same actual boot `start-w14-switch.log`: 2018 ->2096 blocks, passes BR `0x102008db10` ->`0x102008db18`, stops on UMULH. Original red missing-block witness now passes unchanged against its SDK metadata.

## Completed generic UMULH X (MODULE-ONLY)
- Exact fixed-bit decoder; unsigned high64 of the 128-bit product using the EXISTING unchanged portable `aot_umulh` 32-bit-limb helper. No W form. Rn/Rm31 are XZR; Rd31 discards; aliases safe; SP/NZCV untouched. No native runtime/backend/HLE/ABI changes.
- 32768/32768 register encodings independently agree with Capstone and are refused in G2; LLVM-mc fixture words and reserved/W-form negative cases.
- Frozen emitted-C/Unicorn A57 matrix: **1110 exact scenarios**, **40 compiled wrong-implementation controls rejected**, `/O2` and `/Od`, infra0. UMULH adds independent operand pairs for MSB/signedness, all-ones/mid-limb carry, low-vs-high product, ZR, aliases, x18 and all16 NZCV nibbles.
- New UMULH controls: signed-high (actual x2=-1 vs expected0), low-product (-1 vs0), missing middle carry (`...fffd` vs `...fffe`). Each compiles successfully and fails semantically, scoped only to UMULH, not the old SMULH first-mismatch contract.
- Final native builds Debug/Release exit0.
- Final full CTest **76/76 Debug (542.56s), 76/76 Release (304.23s)**. Logs `w17-frozen-ctest-{debug,release}.log`; detailed latest Release output in `build-w17-umulh-full/Testing/Temporary/LastTest.log`.
- Separate primary `/Od` matrix exit0: `w17-frozen-newfamily-Od.log` (CTest's newfamily test defaults to `/O2` even in Debug).
- G2: all16 frozen generated files byte-identical except the same two allowed provenance lines. `git diff --check` passes; no pyc/build products in source.

## New exact real stop — authorization required before code
Same driver command/profile `start-w17-umulh.log` / `start-w17-umulh/run_start.log`:

- **1,263,812 translated BB dispatches**. Original `aligned_alloc` adapter and SDK `__nnmusl_init_dso` returned; main DT_INIT has progressed to its original constructor loop, NOT returned.
- `AOT_FAULT_UNTRANSLATED` code10/status0. main `BLR x8` PC`0x1000000148`, word`0xd63f0100`, target`0x1000001520`, LR`0x100000014c`.
- ready_calls1/inits_calls1/finis_calls0/ctor_fail1; `return_out_valid=0`. No nnMain or completed 10700-slot witness.
- Driver exit1 is correct: destination has no original DEFINED STT_FUNC; D021 compound ADRP+ADD veneer proof refuses. This intentional error path does not create result.json.
- Current SDK metadata still has the ORIGINAL **213 roots**, now3431 blocks because UMULH unlocks the remaining body; the D022 site remains `verified-final-graph`, 13 entries /6 distinct targets.

### Original metadata provenance, independently checked by primary
- Main DT_INIT_ARRAY `[0x456ab68,0x457f4c0)`, size84312 =10539 slots.
- Scanned EVERY original ELF RELA in the interval: 10539 unique complete slots, no gaps/extras/duplicates; all type1027/sym0; all aligned nonzero addends inside owning main TEXT `[0x1000000000,0x1002aa6a10)`; 10539 distinct targets.
- First original slot relocation addend`0x1520` ->linked`0x1000001520`; second`0x16830`. Original ELF slot bytes are zero before relocation.
- GOT relocation at`0x4540430` ->array start; at`0x4540380` ->array end. Original DT_INIT loads these bounds and uses post-indexed LDR/BLR/CMP loop. Runtime x20 is not in the current observer log; do not claim an exact captured current-slot pointer.
- This establishes static provenance, NOT existing Start-root authority. `g3_init_reach.boot_roots()` already enumerates arrays for MEASUREMENT/BATCH only. D017 says only DT_INIT is host-invoked and guest walks the array; D021 does not admit arbitrary relocated targets; D022 does not authorize function roots.

## Proposed next step — NO approval / NO implementation
Read `g3-init-array-root-decision.md`: explicit pinned constructor-root class, complete array/relocation and caller/slot proof, source/hash binding, typed refusal, no fabricated STT_FUNC/FDE fallback/global targets/eager10539 roots, no host-side constructor loop. Preserve D017 guest ordering and ABI. Independent review and discriminative fixtures before same boot. **Await authorization** before recording a new decision or changing the seed policy.

## Retained limitations
D021 static reach is still an over-approximation, not a full executed-path proof. Earlier wrapper/PLT continuation and malformed non-dict diagnostic limitations remain unchanged. No new backend, HLE, FS, concurrency or guest-return semantics were authorized by these increments.

Historical pre-switch checkpoint retained as `g3-checkpoint-w10-before-switch.md`.
