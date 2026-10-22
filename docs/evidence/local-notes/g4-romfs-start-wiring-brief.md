# Next bounded task AFTER provider checkpoint review — early G4 adapter + faithful Start

User full task remains active: implement real initializer, then CONTINUE faithful boot until a substantial out-of-scope subsystem boundary or completed G3 proof. Do NOT return control just because FS succeeds. No integration until explicit Integra; G3 OPEN original DT_INIT exit unchanged. Provider is G4 early prerequisite, not G3 classification.

## Current lineage / evidence

w33 previous validated baseline (68/68 Debug+Release,46 runtime mutants). w39 first provider checkpoint (watchdog15min, not a completed deliverable). w41 successor fixing review edge cases/docs; use CURRENT reviewed provider successor, do not revert to w33. No commits/main edits.

Real resources externally prepared at `C:/Users/IKER/mn-g3-local/v0/romfs-init`: all6 IVFC + repo expected-v1.0.0.json image pin matched; image17069139640bytes SHA4751542f544d8c3406cb63ccfc68b42690ff0387228d1f0af021d1f0037dafcf; index304207files,26012873bytes SHA17272f3836fdfafe3d1537c40b02ecd1bed8cdc95d00ba4efbc3c74c89d61efa; external romfs_config.h usual3defines. No overlays present; no resolution override. Lead standalone w39 fullhash provider passed and read atimageoffset0x100002e20 matched independentstdio64bytes (romfs-real-w39-run.log); final successor still needs actual boot validation.

## Implementation: tiny explicit G4 translated adapter

Use separate `tests/aot/g4_romfs_start_hle.{h,c}` (or similarly scoped narrow module), not a second fake G3 override table. Context borrows owning RomfsProvider and explicit config, retains provider diagnostic/counters. AotProgHandler signature exactly existingABI. HOSTCALL only, thunkid opaque; no hardcoded28. At invocation call real romfs_provider_init (not pre-init before Start). Success writes NO guest register/flags/memory (Mac void); failure sets fatal typed AOT_FAULT_BAD_HLE with documented negative status, req.site_pc/req.resume_pc, leaves guest state untouched and provider EMPTY. Missing config/provider/wrongkind also typed, no success. Counters distinguish calls/success/fail and report actual provider_ready/file_count/diag. Do not write host pointers to guest state. Init/cleanup lifetime host-owned; retain READY provider until guest run ends, destroy afterwards.

Hermetic native adapter probe uses actual synthetic provider valid/missing inputs, checks complete AotGuestState memcmp on success/failure, exact faults+src/resume, provider lifecycle/counters. No TotK data. Existing D015/16 resume tests already cover dispatcher; don't rewrite runtime ABI or invoke real ARM. Native source can use existing fixturegenerator/probe helper rather than duplicate 1Klines; use a small fixture (independent expectedSHA constants) or share test-only helper cleanly. Realadapter must be the path tested, not unrelated fakeensurecallback. Add at least wrong-success/guest-x0-clobber control if needed beyond provider's hash negatives, exactsemantic exit2; no WILL_FAIL catchall.

## Integrate into Start probe BY NAME, optional explicit local configuration

In tests/aot/aot_g3_start_probe.c:
- Keep original Start and all observers/DT_INIT ordering; no direct SDK-init bypass/Abort override/ownerpatch.
- Resolve `_ZN2nn2fs24InitializeForApplicationEv` via bindings name; register G4 handler only when explicit FS config enabled. Default disabled remains old typed boundary, NEVER a no-op handler.
- G3 lookup table continues not modelling FS (correct separation); update comments saying 'never registered' to mean 'not via this G3 table; optional early-G4 adapter separate'. Tests lookup refusals still valid.
- Existing post-finalize FS-unregistered assertion must become expected-registration assertion based on enabled config; print truthful OVRCHECK/explicit G4FSREG, not 'unmodelled' while actually G4-registered.
- Log G4FS after run: calls/ok/fail, provider_ready, file_count, provider diag/status/stage (don't label expected bytes as actually read). Ensure provider cleanup after run, not while guest could use it. All addresses remain guest VAs except explicit HOST-only context.

## Driver optional local configuration (tools/aot/g3_start_prefix.py)

Suggested flags `--romfs-config` (external existing3define header), `--romfs-dir`, optional `--romfs-overlay-dir` or `--romfs-no-overlays`, optional `--romfs-required-overlay-dir` (secondroot). Disabled unless config explicitly supplied, even if unrelated globalenv exists. Core provider takes explicitcfg only; resolve profile in driver.

- STRICTLY parse exactly the known3macros IMAGE_SIZE/IMAGE_SHA256/INDEX_SHA256, reject duplicates/unknown code/include/malformed/no digest; do not directly #include untrusted external config into C. Never compute expecteddigest from runtimecandidatebytes. Pin provided image size/hash against repo assets/expected-v1.0.0.json (this driver v0 only; unchanged multi-version scope).
- Emit external generated C config literal into --work, include in nativebuild; emit NULL config when disabled. Extern declaration in probe enables compile-only CMake object without linking generated profile. No game-specific generated config/binary committed.
- Safely encode arbitrary UTF8 paths in C string literals (fixed octal escapes or /utf-8 literal with proper escaping; avoid unbounded \x hex run/code injection). Reject NUL/controlchars/empty paths; don't execute header/Python source from profile. Add /utf-8 if emitting UTF8 literals.
- When enabled, default resource dir can honor explicit --romfs-dir / TOTK_ROMFS; default base overlay semantics should mirror Mac optional directory with TOTK_ROMFS_PATCHES=0 disabling it, explicitdir optional if absent but fail if present-invalid. Default external profile siblingromfs-patches is fine; document. Requiredsecondroot only explicit selected-profiledependency; no graphics/output-resolution subsystem. If graphics profile env requires unsupported resolution overlay, refuse clearly rather than silently ignore requirements.
- Include provider + privatehost + adapter sources in manual nativebuild; aot_sha256.c already CORE, don't duplicate it. CMake library/test wiring remains gamefree; compile-only Start object includes src header, doesn't need realconfig.
- Hermetic driver tests of config parse/pin/pathescaping/defaultdisabled/overlayselection. Preserve existing prefixclassification/realbuild semantics. Fatal providerfault with negative status must stay typed; don't mislabel it as missing thunk28. If needed log classified FSinitfailure from explicit G4FS evidence, not guessing from a negativecode.

## Task stopping point / validation

For bounded adapter task: compile /W4/WX, native adapter positive/control and driver config tests green Debug/Release, source stable, report concise. Do NOT run fullboot inside worker if lead owns it; lead runs original prefix with external realconfig and max_iterations8 after review, then follows only justified missing translation entries. It must continue past FS if correct, until next actual blocker. All generatedwork dirs external.

Any new substantial G4 subsystem (mount/generalFS API, saves, significant IPC, guest scheduler/sync infrastructure) STOP before implementation and return exactcallsite/state/Maccontract/options to lead/user. Single data-field setters already translated may execute as guest, not a reason to add host answers. Instruction-family coverage blockers are G3 translation work only with exactdecode/differential/negativecontrols, never an excuse to fabricate HLEsuccess.

Eventually full G1/G2/G3 regression on final candidate, AOT-OFF host tests preserved, original constructorwitness (all realmoduleDT_INIT and expected slots in same faithfulStart) required before G3 CLOSED. Neither READY provider nor higher blockcount alone closes it.
