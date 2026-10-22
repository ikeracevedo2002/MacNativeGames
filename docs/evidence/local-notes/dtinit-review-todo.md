# Lead-filtered pending review items (not final evidence)

## Reach tool (Haiku w4; recheck current source)
- Snapshot inferred targets must remain candidates and must not produce callable-complete proof. Keep unknown possibility.
- BL/BLR/SVC continuations must kill x0..x18 (and LR); retaining caller constants makes false indirect precision. Simplest clear all if needed.
- Out-of-image/data indirect records must have uniform tuple arity; _plt_stub previously assumed 5 but some records had 4.
- State cap hit must preclude callable-complete. Metrics must say incomplete/lower bound with unresolved targets.
- Test actual positive PC-built indirect, same-register add pre-state, SIMD nonalias, snapshot candidates, writeback-base invalidation, caller clobber, indirect bad callee propagation.

## Partial/harness (Haiku w7 filtered by lead; recheck current)
- text layout is [offset,size], not [offset,end]; owner range base+offset .. base+offset+size.
- HLE counter on host_time failure must fail explicitly without dest write, never fabricate zero. Verify returned units: guest CNTPCT/CNTVCT values must use the title's expected counter rate (Mac reference 19.2MHz if confirmed), not raw host nanoseconds merely because monotonic. Do not claim HLE timing parity from an unscaled value.
- Native trap test needs valid prefix instruction -> unsupported word preserving prefix effects; dropping prefix must be rejected by compiled mutant.
- Structural negative control must exercise forbidden-fallthrough check specifically, not merely missing-tail parse failure.
- STOP module name must equal requested module; missing requested translated root should fail as inconsistent generation rather than ordinary discovery gap.
- Validate metadata raw word against corresponding flat/source PC before reporting instruction blocker.
- Module bases/init VAs derive or cross-check against reference counters/config rather than unvalidated constants.
- Malformed TSV rows must fail; relocated pointer into RX is candidate evidence, not blanket code proof. Init arrays are stronger metadata evidence.
- Bind input hashes and normalized roots, source revision/generator hashes to external manifest, not only output hashes. Input data stays external. Reject work==repo or descendants, including resolved aliases.
- Bound subprocess execution; distinguish infrastructure from semantic outcome.
- Report every selected module outcome. Discovery report is not constructor PASS: exit 0 may mean report produced, but docs must not claim all constructors or non-transfer completion. Avoid treating mixed faults/returns as completed milestone.
- Rename retpc label if it actually means last dispatched state.pc.
- Update docs accurately before final review. Source hash is loader identity; provenance is intentionally evidence-only, no loader rewrite needed.

## Not accepted as bugs without more evidence
- Partial metadata end_pc=trap_pc+4 is defensible as block encoded-word span; trap does not execute original word. Don't silently alter metadata contract based solely on reviewer opinion.
- Provenance has no runtime consumer by design; flat SHA binding is correct D017. Document evidence-only, no loader rework.
- All typed faults including UNKNOWN_PC are legitimate observable discovery outcomes, not G3 completion. Fix misleading report contract rather than hiding them.

## Mandatory milestone work outstanding
- Emitted-C new integer/memory family differential plus meaningful compiled mutants.
- Real execution from all offline justified init_array roots (10,539/45/116), not just DT_INIT prologues. Need ordered loop CALL_INDIRECT/return witnesses, flags, clean outer return to claim completed constructors. Existing trace4096 cannot prove main10700; ctor_calls_seen based on trace block entry is prefix-only. Minimal option: test-only compile-defined native observer after each generated block exit in Program loop (no state mutation/reentry), validating site+0x148 CALL_INDIRECT next_pc matches each relocated init_array slot, RET target+0x14c counts matching returns, flag2+outer clean return. A bounded runtime trace alone is insufficient. No runtime decoding or guestVA->hostcast.
- Remeasure initial/final using same corrected reach analysis with baseline decoder vs current; per-root transitive attribution and unresolved ambiguity explicit.
- No speculative D008 backend choice; evaluate actual translation/compile scale evidence.
