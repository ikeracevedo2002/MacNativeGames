# G3 constructor witness: reviewed design, not implemented yet

Goal: prove all real init_array slots execute and return in original Start -> module_inits, one AS/process. Main10539/subsdk0 45/sdk116. Flag2 is written BEFORE loop; trace4096/events1024 are bounded prefixes, never completion proof. No G3 closure without module guest-call success + ordered slot evidence. This design is test-only, zero src/aot ABI changes. Source-backed DeepSeek w10 plan, corrected/reviewed Opus w11. No user integration approval yet.

## Exact seam and ownership
AotBlockFn = AotExit (*)(AotGuestState*,AotRuntime*). AotBlockEntry = {uint64_t entry_pc; AotBlockFn fn}. AotModuleDesc.image is const AotImage* (NOT AotProgImage). Loader copies img->blocks pointer into loader.prog and Program borrows it. Runtime sets s->pc immediately before calling fn. classify returned e: rt->reason is stale until Runtime consumes e.

Before aot_loader_init: struct-copy ENTIRE original AotModuleSet, each module desc, each AotImage. Copy entry tables keeping every PC and count unchanged, replace ONLY each fn with generic native adapter. Set clonedImage.blocks, clonedDesc.image, clonedSet.modules. Preserve all other fields with struct copy: source_sha256, descriptor SHA, link digest, ranges, subset/version/layout/base/thunks, etc. Never mutate const generated tables. Original image block tables remain saved and immutable; find original by image+PC binary search. Guest PC is lookup key into existing trusted native function table, NEVER cast to a native function pointer. Clone lifetime outlives Program AND loader; free after program_destroy + loader_release. Allocation/lookup failure is harness infra failure, never fake guest success or call-guest(0).

Adapter signature EXACT two args /W4 /WX. For other runtimes or inactive module, call original unchanged; record only ctx.main_runtime, not background threads. Capture pc before orig(s,rt), run pre-entry/resume checks, call original function, then record returned e/site_pc/next_pc/payload. Return e VERBATIM, never write guest state/runtime scratch in positive implementation. Controlled negative mutant may intentionally rewrite next_pc to prove skipped calls rejected.

## Integrate into faithful route
Use existing aot_g3_start_probe/module_inits and shared tests/aot helper, not a duplicated direct-init-only harness. Begin witness immediately before each original aot_call_guest(DT_INIT, NULL, nargs0), end after API return. Lead source correction: Mac loader.c:421 calls DT_INIT as void(void), and the faithful probe passes NULL/0 at aot_g3_start_probe.c:286. Preserve this no-argument contract; it does NOT imply x0=0/x1=1. Earlier direct-init diagnostic args{0,1} were not the original Mac callback ABI. Original Start/thread prelude remains mandatory, no dummy owner patch. A separate direct-init experiment is diagnostic only, cannot close G3.

Do not inspect rt.next_pc/site_pc after nested API return expecting inner sentinel: D016 correctly restored outer scratch. API success already proves sentinel, SP and frame ownership. Record top guest-call result; fail any sticky fault, budget fault, or missing module completion. Keep finite step budget; 'unbounded' means ledger records, NOT infinite runtime budget.

## Manifest and ledger
Offline tool emits per-module metadata tied to pinned image/descriptor SHA: init_array VA/size, nonempty expected slot list, loop call site, ret_pc=loop_site+4, expected raw instruction word. Derive loop site offline, do not assume every module has +0x148 (current title does). If validating source word at runtime, compare EXACT pinned raw word for identity; no runtime semantic ARM mask/decoder required. Read sealed AS init_array values and crosscheck offline expected list before execution. Expectations NEVER come from observed CALLs. Descriptor/source/profile binding, count and bounds errors fail before guest call. Real three modules require count>0; wrong site/count-zero must not yield 0/0 pass.

Stream only module begin/end, per-slot CALL/ENTRY/RETURN and inter-module/fault records; no per-block giant trace. Dynamic storage sized from manifest count is fine; no fixed4096 cap. FILE errors checked, ferror/fflush/fclose and END marker required; Python ledger checker validates source binding, exact counts/order/sites/SP and END. Log EOF is FAIL even if in-memory counters complete.

## Minimal slot machine (avoid all-internal-call shadow stack)
- Returned e == AOT_EXIT_CALL_INDIRECT at declared loop_site is slot CALL (BLR), not AOT_EXIT_CALL (BL). Match observed target to expected slot[i], LR to ret_pc. No extra call while pending. Record call SP.
- The VERY NEXT main-runtime native adapter invocation must have pc==target: actual callee ENTRY. A CALL logged then dispatcher skips straight to ret_pc must fail. Missing/extra/wrong-site/target/order records never ignored as success.
- Ignore unrelated internal BL/BLR/BR for slot accounting. BR may be a computed jump, not necessarily tail call. Do not force all private functions to preserve public ABI.
- Once actual entry occurred, require arrival at ret_pc with original call SP. Record how control returned: guest RET (actual enum spelling from header, not guessed AOT_EXIT_RET), or proven semantic HLE resume if explicitly supported.
- Record callee-saved/FPCR differences for diagnostics, do NOT impose new per-internal-call ABI checks; a constructor can legitimately call fenv mutators. Existing outer AotCallGuest ABI guard remains authoritative. Don't restore FPCR/state to hide differences.
- Direct thunk slot has no translated callee entry: UNSUPPORTED_HLE_CTOR witness failure until a typed handler-entry/return adapter exists. Never count it silently.
- Tail-HLE inside an entered guest ctor can resume without guest RET. Be careful: transparent observers may nest AotCallGuest and overwrite 'last native exit' with inner sentinel return. Mere last-next-in-thunks is not always enough evidence. Either implement properly scoped four-arg handler adapters capturing underlying handler invocation/success/resume, accounting for module_inits outer baseline handler depth, or mark this return kind explicitly unsupported until actually needed. Do not falsely count/drop it. Filter current module host-call depth if relevant; no accidental return from a nested frame.
- Only end-module API success + all exact ordered triples + no unsupported kinds/errors + complete flushed ledger permits module completion. All three modules in original order required. Boundary at nnMain or clean Start return alone is NOT G3 pass.

## Owned deterministic fixtures / negative controls
Use same clone/witness interface with 2-3 owned constructors and observable data writes. Include internal BL/BLR, tail native helper, FPCR modification accepted per slot but restored by DT_INIT epilogue before outer ABI guard (otherwise unwrapped run itself would fail).
Wrapped vs unwrapped deterministic fixture must match FULL guest state, memory, steps, fault, events, return result (not merely x0). This proves adapter transparency; real BCrypt runs are nondeterministic so don't claim cross-process byte equality there.
Controls with correct positive baseline and assertion-specific semantic failures, no setup crash:
- log CALL then rewrite next_pc to resume: actual ENTRY missing.
- swapped expected slot order / duplicate / expected count low or high.
- missing return / wrong SP / branch past resume.
- manifest source SHA mismatch, wrong loop-site, zero count.
- truncated ledger before END / simulated writer failure.
- thunk slot explicit unsupported.
Manifest checked against linked AS values and pinned source. Native dispatch faults between blocks still caught by top guest-call result, even if adapter never sees offending target.

No runtime ARM decoder, interpreter/JIT, new executable allocations, guest-VA casts, or product Runtime observer hook: only test-side native table interposition invoking original AOT-compiled functions. Evidence covers the wrapped run; transparency to original is supported by controlled fixture differential + read-only adapter implementation, not assumed deterministic equality of random game runs.
