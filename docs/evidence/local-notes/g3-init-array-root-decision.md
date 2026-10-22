# Proposed next G3 decision — pinned DT_INIT_ARRAY roots

**PENDING USER AUTHORIZATION. No implementation. G3 OPEN.**

## Demonstrated stop

Frozen candidate: `C:/Users/IKER/.pi/agent/harness/worktrees/MacNativeGames-106250b2/w17` (D022 local CFG edges + MODULE-ONLY UMULH).

Same boot profile, `start-w17-umulh.log` and `start-w17-umulh/run_start.log`:

- 1,263,812 translated basic-block dispatches.
- `AOT_FAULT_UNTRANSLATED`, code10/status0, main `BLR x8` at `0x1000000148`, word `0xd63f0100`, target `0x1000001520`, guest LR `0x100000014c`.
- `__nnmusl_init_dso` returned to the original main DT_INIT code; w0=2 is stored/tested before entry into the guest constructor loop. Main DT_INIT itself has NOT returned. `return_out_valid=0`, ready_calls=1, inits_calls=1, finis_calls=0, ctor_fail=1. No nnMain or witness completion.
- Driver fails closed: target is not an original defined STT_FUNC; the ADRP+ADD veneer proof also refuses. Driver exit1 is intentional; this path writes no result.json.

## Independently checked original evidence

The original ELF's dynamic tags, original RELA records, loader layout and emitted caller code agree:

- DT_INIT_ARRAY offset `0x456ab68`, size `84312` bytes = **10539 slots**, exclusive end `0x457f4c0`.
- Primary scanned EVERY original ELF relocation in the range: exactly 10539 sites, no gaps, extras or duplicates; every record is R_AARCH64_RELATIVE (1027), sym0, with an aligned nonzero addend inside owning main TEXT. 10539 distinct target values.
- Original array/GOT bytes are zero before relocation, as expected. Slot `0x456ab68` has addend `0x1520`, yielding `0x1000001520`; the next slot has addend `0x16830`.
- Original GOT records at `0x4540430` and `0x4540380` relocate to the array start/end respectively. The reached original DT_INIT instructions load those bounds, then `LDR x8,[x20],#8; BLR x8; CMP x20,x19; B.LO ...`.
- Owning main TEXT is `[0x1000000000,0x1002aa6a10)`. No STT_FUNC exists at the target. A plausible prologue or EH/FDE coverage is NOT being substituted for authority.
- Runtime x20/current-slot bytes are not presently logged; original first-slot evidence and the actual target agree, but a future exact slot/site proof must not pretend the current log captured x20.

## Why this needs authorization

D017 preserves **only DT_INIT host invocation; the guest walks its own array**. D021's additional Start-driver authority is a proved veneer ending in a defined STT_FUNC, not an arbitrary relocated pointer. D022 authorizes local switch edges inside an already-rooted FUNC, not new functions.

`g3_init_reach.py:boot_roots()` already enumerates array values for MEASUREMENT/BATCH reach analysis. That is not authority to add the same roots to the real Start driver. Reusing its data structures is reasonable; silently promoting its policy is not.

## Proposed bounded contract (to refine/review before code)

1. New explicit constructor-root authority derived from pinned original DT_INIT_ARRAY/DT_INIT_ARRAYSZ and relocation semantics, separate from defined-FUNC and veneer classes. No title address/count exception.
2. Validate the complete declared array, every slot, exact alignment/bounds/unique relocation and permitted same-module TEXT targets. Reject malformed, unsupported, zero, data, mid-instruction, conflicting or ambiguous entries with a typed reason. No implicit cross-module/symbol-based fallback in the initial increment.
3. Prove the consuming guest array-walk site and exact slot provenance, including the post-indexed cursor semantics. A runtime-observed target alone is never evidence. Bind original module/relocation/layout and emitted metadata hashes; reject mutation or stale proof.
4. Enumerate the eligible finite set statically, but compile/admit only the next demanded target using that prior authority; do NOT seed all 10539 constructors eagerly or expose a global indirect-target list.
5. Preserve D017: original guest BLR/loop/order/register ABI remains in control. No host-side iteration/call, skipped constructor, assumed result or synthetic guest return. Other indirect sites keep existing restrictions.
6. Negative fixtures before boot: relocation gap/duplicate/wrong type/symbol; swapped or forged bounds; data/out-of-text/misaligned target; wrong slot/cursor/site; missing source/hash binding; runtime-only target; already-named versus stripped valid constructor. Include a valid stripped target without fabricating STT_FUNC metadata.
7. Independent admission/code-data review, native/Unicorn fixture checks, G2 identity and full Debug/Release regression before the same real boot. Start with first legitimate constructor entry; no subsystem/HLE expansion implied.

Some restrictions may prove too narrow for later legitimate arrays. Such a case must fail closed and be reviewed, not silently reclassified. No new D023 or PORTING_STATUS completion is recorded until authorization and implementation evidence exist.
