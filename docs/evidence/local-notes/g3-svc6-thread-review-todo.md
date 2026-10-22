# Pending bounded review repairs (reviewed w14-2; current source w19-2)

Not implemented merely by recording this note. G3 remains OPEN. Main checkout remains unchanged; canonical candidate is uncommitted in w19-2. Latest full regression is now61/61 Debug+Release; details in dtinit-continuation-status.md. The60-test snapshot below is historical with its original scope. Do not integrate without explicit user approval.

## Lead regression

External immutable snapshot `src-w14-thread-lead` (740 Git-listed source files; hashes `w14-thread-lead-source-manifest.json`): Debug full CTest **60/60 PASS**, 320.46 s. Includes actual thread HLE and STACK sentinel fix. This does not include subsequently edited MSR implementation. Release full CTest **60/60 PASS**, 344.93 s. Both commands exited 0. These are CTest configurations, not a claim that every Python-driven subcompiler honors that configuration. Earlier w12 red was a stale fixture value: strong RW SC changed `v`; STACK denied-read expected old sentinel without resetting it. Resetting only the sentinel made alias and runtime-mutants pass; no AS permission semantic change was required.

## Independent SVC6 review (w15, source-reading only; lead triaged)

Handler ABI matches Mac: exact LE 40-byte record; output checked/written before x0 changes; x1 input ignored; unknown AS geometry fails closed; fault paths preserve guest registers.

1. The probe's so-called partial-write mutant corrupts a field AFTER a successful full write. Rename it as field corruption. Exercise actual `MN_AOT_MUTANT_PARTIAL_STORE` implementation with same SVC6 probe; require baseline success plus controlled nonzero failure and expected failure witness, not arbitrary crash/nonzero. Cross-permission output must catch a modified writable prefix.
2. Negative-control helper should distinguish setup failure from expected mismatch (tri-state or equivalent). Do not let a broken setup count as rejected mutant.
3. Add wrapping output and region-end straddle output rows; require MEMORY/RANGE, preserved full state and accessible output canaries.
4. Diagnostic `fault_target` is permitted to mean accessed/query VA (aot_runtime.h). Record which value the new query faults carry; do not invent a PC-only contract.
5. Query snapshot and subsequent guest copy use separate locks. This is not established as a correctness bug: ordinary queries describe a snapshot, not a promise that the mapping remains unchanged until output publication. Do NOT broaden AS API or add lock-held copy merely on speculative concurrency grounds in this single-threaded G3 probe.
6. Clarify backwards-sounding sensitivity-control label.

## Independent thread SVC review (w16, source-reading only; lead triaged)

ABI matches live Mac threads.c handlers, NOT shadowed services.c constant-44 / host-TID fallbacks. Actual runtime_svc calls svc_thread first. Full canonical-state preservation helper covers all fields. Borrowed registry exists before execution and outlives the run. Alias is explicitly scoped to single owned main, not general current-thread semantics.

1. Header says NULL/empty registry fails closed; code gates only NULL registry then returns guest BAD_HANDLE for empty or NULL-entry registry. Make malformed/empty borrowed configuration a typed THREAD host fault (unless lookup provider overrides it). Check `{entries,0}` and `{NULL,nonzero}` preserve full state; distinguish genuine unknown handles in a configured registry, which MUST remain guest 0xe401/r1=0.
2. Actual compile-time PRIO_CONST, HOST_TID, PSEUDO_REJECT mutants exist but are NOT built. Probe-local wrappers do not test those production variants. Add existing-mutant-driver targets with exact expected ordinary failure witnesses, baseline-green requirement and no arbitrary-crash acceptance. Guard pseudo-reject branch with #else if MSVC detects unreachable code. Consider first-THREAD alias mutant too.
3. Add non-main THREAD decoy BEFORE main entry, with distinct priority/id. Pseudo alias must still choose main; first-THREAD lookup must fail sensitivity control. Existing first-entry-main fixture cannot distinguish this wrong implementation.
4. High64 garbage + low32 pseudo-handle row (`0xdeadbeefffff8000`) must resolve main.
5. Provider-plus-registry precedence row with differing values: provider wins by documented contract.
6. Native registry sanity assertions can improve wiring witness; do not confuse tautological constant checks with real SDK ThreadType owner initialization. Owner MUST still be written by guest nnosInitialize, never patched by host.

## Worker lifecycle

Assign followups ONLY after agent_status/read says COMPLETED. Elapsed shown during a followup can retain the previous task's completed duration; do not infer actual followup wall time from that stale field. Do not pile queued work onto an active worker. Keep one bounded task below its 900-second watchdog; collect concrete partial evidence if necessary.
