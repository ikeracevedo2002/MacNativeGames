# Current G3 checkpoint — w10-2 RBIT + DMB ISH, stopped before new CFG decision

## Candidate / disposition
- Current source: `<worktrees>/w10-2` (worker w10), seeded byte-for-byte from frozen w8-2.
- Delta vs w8-2: ONLY `tools/aot/aot_translate.py`, `tests/aot/g3_decoder_module_test.py`, `tests/aot/g3_newfamily_diff_test.py`. External patch: `w10-from-w8.patch`.
- No commit/integration. Main and w8-2 unchanged. No PORTING_STATUS exit change; G3 OPEN.
- RBIT completed, then continued through the real next small blocker DMB ISH, as requested. The new stop needs a new local-CFG-edge policy; nothing implementing that policy has been written.

## Implemented and verified
### RBIT W/X (MODULE-ONLY)
Generic operand-width bit reversal; W ignores upper source bits and zero-extends result; NZCV untouched; Rn/Rd31 are ZR, never SP; aliased operands safe. Helper emitted only when needed; no G2 ISA expansion or native runtime/backend/HLE changes.

- 2048/2048 sf/Rn/Rd encodings checked with Capstone, refused in G2.
- Independent LLVM-mc words + Unicorn A57/native comparisons at /O2 and /Od. Rich zero/ones/asymmetric/alternating/64 single-bit cases, W high-half canaries, all register31 directions, aliasing and all 16 NZCV nibbles with fixed operands.
- Four controls: identity, byte-swap instead of bit reversal, W reversal at 64 bits WITH correct result truncation, flag clobber. The strengthened W control fails x3=0 vs expected 0x80000000, so it tests reversal width independently of zero-extension.
- RBIT-stage full Debug 74/74 (218.29 s), Release 74/74 (216.10 s). Logs `w10-final-ctest-{debug,release}.log`.
- Same real reboot `start-w10-rbit.log`: advances 1514 ->1595 blocks, stops at DMB ISH PC0x102011c4f8/word0xd5033bbf.

### DMB ISH (MODULE-ONLY, only the observed canonical option)
Reuses the EXISTING barrier IR and `aot_mem_fence()` -> production Windows MemoryBarrier under accepted D013 SC. No new memory model, native memory code, ABI, synchronization service or GPU guarantee. Other non-SY options remain refused; old SY IR/output unchanged.

- Decoder grid: 128 option/opc combinations, LLVM-mc/Capstone independent checks.
- Final newfamily matrix: 1050 exact scenarios, 37 compiled wrong-implementation controls rejected, infra 0, /O2 and /Od. DMB controls: NZCV clobber, CLREX substitution, GPR clobber.
- Newfamily exclusive rows use an explicitly labelled HARNESS MODEL, not a production monitor. Separate external real-core probe links actual aot_mem/aot_as/host_vm, creates a real domain and attaches a real monitor token: DMB preserves reservation (STXR status0, value42), no reservation fails (status1/value42), compiled CLREX-substitution diverges (status1/value41). Lead reran both binaries successfully. This core smoke is external, NOT a new CTest case.
- Do NOT claim barrier-drop mutant rejection: SC already provides stronger ordering, so such elision is not a valid distinguishing negative control here.
- All 16 frozen G2 files remain byte-identical except their two allowed provenance lines; the identity check's deliberate carry mutation fails exit2.
- Final full native builds Debug and Release exit0. Final full CTest Debug 74/74 (228.88 s), Release 74/74 (225.42 s), logs `w10-dmb-ctest-{debug,release}.log`.
- Same real reboot `start-w10-dmb.log` / `start-w10-dmb/run_start.log` advances to2018 blocks. Driver exit1 reflects correctly rejected untranslated target; this error path does not write result.json.

## Current exact stop and why implementation paused
- AOT_FAULT_UNTRANSLATED code10/status0, SDK `BR x1` at0x102008db10 (word0xd61f0020), target0x102008db18.
- Containing already-rooted DEFINED STT_FUNC `__nnmusl_init_dso`, start0x102008d880/size2648.
- x0=1, x1=target, x2=1, x17=0x1020abca67, SP=0x200003fe50, NZCV=0x80000000. Main DT_INIT entered, not complete; ready_calls1/inits_calls1/finis_calls0; no guest return or nnMain execution claimed.
- Original code is a CMP#12/B.HI guarded ADR+LDRB+shifted-ADD+BR switch over a read-only 13-byte table. It yields six unique LOCAL targets inside that function; selector1 correctly yields db18. The target advances the dynamic-tag cursor16 bytes and loops, not a callback/HLE service.
- Primary replay of original words on Unicorn verifies all13 selectors and the observed target; this is missing block discovery, not demonstrated wrong instruction arithmetic.
- Fast minimized red witness `w10-local-br-check.py` exits2: actual metadata lacks the observed BR target.
- Independent Opus classification and primary source inspection: module run_module hardcodes `indirect_targets=[]`; the G2 global list is not a per-site module interface. Adding db18 to --entries would bypass the strict/D021 root policy. A new bounded intra-function CFG-edge contract must be approved first, per user's explicit stop condition for architectural decisions.

## Proposed next decision (NO code or approval yet)
Read `g3-local-switch-decision.md`: narrow MODULE-ONLY per-BR edges for this guarded U8-table form, not roots; checked owner/function span, guard/entry dominance, immutable RO table/no relocation overlap, complete derived successor set independent of observed target, source/table SHA binding, typed membership guard and meaningful negative tests. Do not expose arbitrary module indirect roots, use FDE fallback, sweep text or special-case the observed address.

## Retained limits / hygiene
- Existing D021 static reach remains an over-approximation, not a full execution-path proof. Its wrapper/PLT post-call continuation limitation and independently validated real observer producer remain as documented in w8 evidence; no changes to that code.
- Existing malformed non-dict layout diagnostic may fail closed with AttributeError rather than typed DriverError; not changed by these increments.
- `git diff --check` passes; main clean; no __pycache__/pyc found. All build products, NSOs/resources, generated code and probes remain external. No new backend/HLE/FS scope authorized or implemented.
