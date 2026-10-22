# Authorized bounded intra-function jump-table edges — implementation/review in progress

## Authorization and unchanged limits
The user has now explicitly authorized bounded MODULE-ONLY local CFG edges for this demonstrated switch form. Edges must arise only at already-reachable BR sites; table origin/range must be statically proved; tables must be own-module read-only; all recovered targets must remain in valid same-module code extents; malformed/ambiguous evidence must fail typed. No new roots, no global indirect-policy relaxation, no arbitrary targets. Independent policy/code review, full regression and the identical real reboot remain required. G3 stays OPEN; no integration authorized.

Historical reason for the stop: this was a new data-derived CFG contract, not another instruction. Primary investigation and independent Opus review agreed that introducing local targets through the function-root channel would violate D021. That workaround remains forbidden.

## Frozen actual evidence
Candidate: `C:/Users/IKER/.pi/agent/harness/worktrees/MacNativeGames-106250b2/w10-2`.
Reboot: `start-w10-dmb.log` and `start-w10-dmb/run_start.log` (driver exits 1 on this correctly refused transfer; this path does not emit result.json).

- 2018 blocks, code 10 UNTRANSLATED, status 0.
- BR site `0x102008db10`, word `0xd61f0020`, `br x1`.
- Actual target `0x102008db18`; x0=1, x1=target, x2=1, x17=`0x1020abca67`, SP=`0x200003fe50`, NZCV=`0x80000000`.
- Already-rooted containing DEFINED STT_FUNC: `__nnmusl_init_dso`, start `0x102008d880`, size 2648.
- The target is NOT a function entry or a D021 veneer; the current refusal is correct.
- Main DT_INIT entered, not completed; no nnMain execution, G3 OPEN.

Original code:

    cmp  x0, #12
    b.hi out_of_small_tag_range
    adr  x1, 0x102008db14
    ldrb w2, [x17, x0]
    add  x1, x1, x2, lsl #2
    br   x1

Important: the ADD is an X-register shifted ADD, NOT an ADD-with-UXTB encoding. LDRB zero-extends W2 into X2.

The 13-byte table at `0x1020abca67` is inside SDK rodata (`ro = [6164480,7150872]`, offset/size). Bytes:

[1 line(s) of raw game disassembly/bytes omitted; kept only in the local original]

It describes six unique local targets: db14, db18, db20, db2c, db38, db44 (same SDK address prefix). Index 1 yields db18. That block advances x14 by 16 and branches back to the next dynamic-tag load at `0x102008daf8`; it is not a callback or a new service. Mac executes this original computed branch directly.

Primary replay on Unicorn of the original CMP/B.HI/ADR/LDRB/ADD/BR words verified all 13 in-range selectors; index 1 reproduces the actual target and flags. Thus the evidence points to missing CFG discovery, not an incorrect RBIT/DMB result or incorrect BR arithmetic. Full trace remains `w10-local-br-disassembly.txt`, `w10-local-br-table.txt`, `w10-local-br-unicorn.txt`.

Fast red witness already run: Python `w10-local-br-check.py` -> exit 2, `MISSING translated block for observed BR target ...db18 from ...db10`. This inspects the real dispatch metadata and native stop, not an invented fallback.

## Existing interface gap
- `run_module()` calls `build_cfg(raw, ranges, entries, [], base=..., module=True)`; module-mode indirect targets are hardcoded empty.
- Legacy G2 has a GLOBAL manifest indirect-target list, not site-local edge evidence. It must remain frozen.
- The module --entries channel currently receives justified function roots or the bounded D021 veneer category. Adding db18 there would introduce a mid-function root, which D021 explicitly excludes.
- D008 indirect-flow recovery / D017 code-data distinction are still open. A new local-edge evidence channel is a policy decision, not simply another opcode.

## Authorized narrow decision
Only MODULE-ONLY, per-BR bounded intra-function successors recovered from this guarded U8 table form are authorized. These are CFG edges, NEVER function roots/--entries, and do not amend the strict FOLLOW or D021 rules.

A design to review before coding should require:
1. Exact original CMP-immediate/B.HI guard and ADR/LDRB/shifted-ADD/BR sequence, with correct register/alias/width semantics; no other switch idioms admitted.
2. Guard dominance and no alternative entry/direct edge into the load/branch window. Any unproved condition refuses the recognizer; no partial candidate fallback.
3. A checked table-base derivation inside the same known function. The trust boundary for that base must be stated explicitly, not inferred from the observed register value.
4. The complete N+1-byte table lies in sealed read-only module data, with no relocation-site overlap; pin the original words, table SHA and complete flat SHA to actual generated module source metadata.
5. Recover ALL table successors before considering the observed runtime target; every target must be aligned, inside original TEXT and the same owning defined function. No FDE-only, arbitrary-RVA, cross-function or linear-sweep fallback.
6. Site-local emitted membership checking with a typed failure for an unproved destination; retain actual guest register arithmetic/BR behavior, no runtime ARM decode.
7. Hermetic positive fixture plus independent Unicorn/native comparisons and refusals for writable/out-of-bounds/relocated table, missing/bypassed guard, interior window entry, wrong load width and outside-owner target. Meaningful controls for omitted edge guard, bound error and observed-value-only recovery; G2 16-file identity unchanged.
8. Full Debug/Release regressions and the identical real reboot; the red witness must become green without modifying it to permit db18.

No general jump-table subsystem, alternate table formats, new HLE, new backend or G3 closure follows from this authorization. The implementation candidate records the decision in the repository's existing DECISIONS.md convention; authorization of scope does not establish implementation correctness or authorize integration.
