# Porting Status

This file is the shared status board for the Windows x86-64 port.

Statuses: **NOT STARTED**, **RESEARCH**, **IN PROGRESS**, **BLOCKED**, **VALIDATED**.

Do not mark a row VALIDATED because it compiles. Add evidence that satisfies the exit condition.

| Area | Status | Exit condition / evidence |
|---|---|---|
| Project documentation | VALIDATED | Goal, architecture, plan, decisions and agent rules created |
| Windows build skeleton | VALIDATED (build-skeleton row only) | `CMakeLists.txt` rejects non-Windows, non-AMD64, in-source and source-subdirectory builds at configure time. `-A Win32` was driven locally to confirm the `CMAKE_SIZEOF_VOID_P=4` guard fires with `cmake` exit `1` and the message `supports ONLY 64-bit pointers`. `host_check.exe` builds with MSVC `cl.exe` (Visual Studio generator, C11, `/W4`) on Windows 10/11 x86-64 and enforces `_WIN64` + `_M_AMD64` + `sizeof(void *) == 8` at compile time. Original skeleton validation passed its 3/3 CTest cases: `host_check_default` (exit 0, prints `PASS: host architecture satisfied`), `host_check_negative_control` (verifier requires exact exit `1` and the exact diagnostic line `[negative-control] FAIL: expected pointer width 4 byte(s), got 8` against the real host), `romfs_path_cases` (unchanged `tests/test_romfs_paths.c` returns `PASS: 27 RomFS path cases`). Build-dir paths containing spaces were tested locally. Direct invocations of `host_check.exe`, `host_check.exe --negative-control`, and `romfs_probe.exe` match the contracted exit codes and outputs. This row does NOT cover the host platform wrappers (VM, threads/synchronisation, logging), faults, loader, AOT translation, NVN, audio, controller, frontend or packaging. The host monotonic clock, host TLS slots, host VM, host thread/mutex/condition pair and host core logger are covered by their own validated rows below; fault/exception handling and the loader are tracked in their own rows, while AOT translation is covered separately by the scoped G2 proof (not this G1 row). CI is configured but the workflow has not been executed on a hosted runner from this branch. |
| Platform VM abstraction | VALIDATED (host anonymous region only) | `src/host_vm.{h,c}`: owning opaque region handle over `VirtualAlloc`/`VirtualFree`/`VirtualProtect`/`VirtualQuery`/`FlushInstructionCache`; `host_vm.h` is `<windows.h>`-free. Contract: reserve anonymous private pages (no access); **commit requires the WHOLE range reserved and rejects any committed/mixed range BEFORE any mutating native call** (a deliberate rule — `VirtualAlloc` `MEM_COMMIT` would otherwise reset an RX/read-only page to read/write; see D009); decommit/protect require every page committed; query reports the OS's own base/size/state/protection/type; flush is explicit; zero size is `INVALID_ARGUMENT`. `tests/host_vm_probe.c` drives the real backend against raw `VirtualQuery` plus a probe-local SEH guarded-access pair, and rejects: recommit of RO, RX, all-committed and mixed reserved/committed ranges with protection+contents independently unchanged; zero-size commit/decommit/protect; misaligned/out-of-range/overflow; unknown protect bits; reserved-page decommit/protect; and checks decommit-then-recommit zero-fill and release→`MEM_FREE`. Debug and Release 10/10 CTest, `/W4` no warnings. Limitations: the `range_all_state` `VirtualQuery`-failure→`PLATFORM` path and OS `HOST_VM_ERR_ALLOCATION`/`PLATFORM` are implemented but NOT forced; the SEH fixture is NOT the runtime fault-row policy. Scope: anonymous private reserve+commit only (the Mac `mmap(NULL,size,PROT_RW,MAP_PRIVATE|MAP_ANON)+fread` shape); file/COW/alias mapping remains deferred; the fixed guest VA layout is provided by the G3 guest address space (D014). |
| Host timing abstraction | VALIDATED (host monotonic clock only) | Windows QPC/QPF backend (`src/host_time.c`) and pure-integer scaling (`src/host_time_convert.c`). Deterministic `host_time_convert_cases` (20 fixed bigint-computed cases + 5 rejected negative controls: constant, wrong-unit, naive overflow, uint32-truncated frequency, error-output clobber) and live `host_time_live_probe` (NULL rejected, same-thread nondecreasing reads, 200 ms positive elapsed inside a GetTickCount64-bracketed interval, constant + wrong-scale controls rejected) pass locally in MSVC Debug and Release (5/5 CTest each, external build dirs with spaces). API has explicit failure handling, arbitrary non-wall epoch, per-thread nondecreasing reads, no cross-thread strict-ordering promise, no Mach equivalence claim; suspend is documented but not tested. This row does NOT include TLS; host TLS slots are covered by the separate "TLS abstraction" row. |
| TLS abstraction | VALIDATED (host TLS slots only) | Windows `TlsAlloc`/`TlsGetValue`/`TlsSetValue`/`TlsFree` backend (`src/host_tls.c`) behind the `<windows.h>`-free `src/host_tls.h`, with `tests/host_tls_probe.c`. Contract: explicit init/create/destroy lifecycle; create without init, init on a live slot, create twice and any get/set/destroy on an uninitialised or destroyed slot are rejected; a failing init/create/destroy leaves the handle's fields unchanged and a failing get leaves the caller's output at its sentinel; `get` distinguishes a legitimately empty slot (OK + NULL, via TlsGetValue/SetLastError) from a platform failure; set replaces and `set(NULL)` clears; two and four simultaneous slots stay independent; no destructor and no pointee ownership transfer. Per-thread NULL initialization is documented by Microsoft for `TlsAlloc` ("The slots for the index are initialized to zero") and is not attributed to `TlsFree`. Real-thread isolation (CreateThread is fixture-only) uses manual-reset event phase gates with bounded waits and no sleeps: main + 2 workers hold distinct values simultaneously, each observes only its own, a replace/clear in one thread does not disturb the others, a new thread starts NULL, and a writer thread that exits without clearing is followed by a fresh reader on the same live slot that sees NULL; 8 rounds. Five fixture-only wrong backends are rejected by the same battery: process-global per-slot storage (`0` sequential + several thread failures, 17–18 observed, i.e. it passes single-threaded use and is caught only by isolation; the count moves with scheduling but the split does not), aliased slots, clear no-op, error-output clobber, NULL-as-error. Infrastructure failures (event/thread creation, any bounded-wait/join timeout, or `HOST_TLS_ERR_ALLOCATION` where success is required — no fake injects it) print `FATAL` and `ExitProcess(1)` before any cleanup, so they can never be counted as a rejected negative. Debug and Release 6/6 CTest pass at `/W4` with no warnings, external build dirs with spaces. Out-of-tree `/W4 /WX` audit (not committed) forced genuine `TlsAlloc` exhaustion after 1086 live slots: `HOST_TLS_ERR_ALLOCATION` with the handle unchanged and still ready, retry of the same handle after freeing one index, new slot reads NULL, survivor values intact, cleanup successful; a lead rerun of `ctest -R "^host_tls_slot_probe$" --repeat until-fail:100` passed 100/100 in both Debug and Release with ctest exit 0 (out-of-tree logs). Limitations: native index 0 was not observed in the local runs (the first real slot received index 1) so that path is documented, not exercised — validity is the lifecycle tag, never the index, and no foreign index is freed to force it, so this is an observation and not a platform guarantee; TlsGetValue/TlsSetValue/TlsFree failure paths are implemented but not forced; no guest TLS/TLR, thread environment, key destructor (`environment_key` is deliberately out of contract), guest key page or AOT ABI; no integration with `runtime_keys[]`/`g_keythr` and no Mac change; this is not a thread create/join/wake API. |
| Thread/sync abstraction | VALIDATED (host primitives only) | `src/host_thread.{h,c}`: `_beginthreadex`/`_endthreadex` callback (host C, per-thread CRT state), bounded join with `CloseHandle` checked, poll-before-id self-join guard, close-without-wait that does not extend the caller-owned argument's lifetime. `src/host_sync.{h,c}`: SRWLOCK exclusive + CONDITION_VARIABLE, heap-backed typed handles (no array type punning). `tests/host_thread_probe.c`: real battery plus 2 behavioral fakes rejected only by the join behavior they break; real-only self-join, close-while-running (gated worker, later join refused, worker body still runs) and create→join→reuse-spent-handle phases; failure field snapshots. `tests/host_sync_probe.c`: lifecycle battery (real only) including destroy→reinit, mutex-exclusion battery (real + no-op-mutex fake), CV battery (real + 3 condition fakes, all using a GENUINE mutex so no wrong backend is UB); worker `ready` event precedes the exclusion window; bounded predicate loops tolerate spurious wakes; broadcast requires a NON-timeout wake; timeout lower-bounded by an independent `QueryPerformanceCounter`; infrastructure failures FATAL/`ExitProcess(1)`. Debug and Release 10/10 CTest, `/W4` no warnings. Limitations: `HOST_THREAD_ERR_WAIT`, `HOST_SYNC_ERR_PLATFORM` and allocation paths are implemented but not forced; the mutex state after a `host_cond_wait` platform failure is UNKNOWN (documented, not promised). Scope: HOST threads/locks only; no guest thread ABI, scheduler, guest handles/events or address arbiters. |
| Host logging abstraction | VALIDATED (host core logger only) | `src/host_log.{h,c}`: explicit handle, whole record `[LEVEL] tid=0x<8 hex> <message>\n` formatted then `fwrite`+`fflush` under a per-handle SRWLOCK; level filtering; bounded formatting with an explicit `...<truncated>` marker; `host_log_close` returns its OWN final flush/close result and always consumes the handle; no timestamps/rotation/callbacks/singleton and no process-global buffering mutation. `tests/host_log_probe.c`: shape/filter/truncation, CR/LF/NUL normalisation (one call = exactly one line), 4 writers × 200 records verified as one complete non-interleaved stream, a corrupted-stream checker with 5 rejected synthetic negatives, and a real `HOST_LOG_ERR_IO` write forced through a `_pipe`/`_dup2` broken-stderr fixture (no public hook); temporary files are removed after each phase. Debug and Release 10/10 CTest, `/W4` no warnings. Limitations: `host_log_close`'s OWN flush/close IO failure is not forced (stderr is unbuffered, so its close flush is clean — documented); an owned file sink whose `fclose` fails is not exercised. |
| Fault/exception handling | IN PROGRESS (guest-side typed faults only) | Guarded guest memory fault probe passes. G3 evidence: every guest access goes through the checked address space (D014), so unmapped, permission (incl. a straddling STP writing zero bytes), misaligned, untranslated and unknown-PC targets are deterministic typed faults with exact source/target (`aot_g3_as`, `aot_g3_exec`); no host exception is involved. NOT covered: a host VEH/SEH policy (host crashes, a future identity-mapped backend), guest thread exit inside nested calls. |
| AOT decoder/CFG | VALIDATED (scoped G2 controlled proof) | Offline exact-mask decode + explicit manifest CFG. The **concurrency** fixture uses exact per-chunk ranges (no gap/padding bytes); the **differential** fixture declares one containing range with unreachable padding and the reachable starts come from the explicit entries (plus indirect targets). Both are independently re-derived by Capstone 5.0.7 and compared to translator `meta.blocks` before any case. `tests/aot/conc_cfg_test.py` and `tests/aot/decoder_cfg_test.py` add an independent CFG check plus **3 committed width-validator negative controls** (late D case on the S site, late duplicate S case on a D site, post-HLE D case pointed at the S FDIV), locking a found false positive. Opt-in `MN_BUILD_AOT_PROOF=ON`. Full ISA/title parity is NOT claimed; D008 stays OPEN. |
| AOT integer/flags | VALIDATED (scoped G2 controlled proof) | Differential fixture suite (part of 3049 = 3048 exact + 1 deliberate OOB fault) against a pinned Unicorn A57 oracle, `mismatch=0` in Debug and Release; real-lowering mutants rejected (`infra=0`). Covers X/W add/sub (imm incl. lsl#12, shifted ASR), movz/movk moves, all 16 conditions with NZCV, CBZ/CBNZ W vs X. Scalar integer logical ops (`and`/`orr`/`eor`) are NOT implemented. |
| AOT branches/calls | VALIDATED (scoped G2 controlled proof) | Direct/indirect call fixtures (bl/blr/br, x30 capture) plus negative controls pass; STOP only legal after RET. |
| AOT FP/SIMD | VALIDATED (scoped G2 controlled proof) | Numeric FP: F32/F64 `fadd`/`fsub`/`fmul`/`fdiv`/`fcmp`/`fcmpe` over RN/RP/RM/RZ × DN × FZ with sticky FPSR — 2304 differential matrix cells inside the 3049 oracle cases, 45 closed-form helper rows, 10 translated closed-form rows, and **392 native-only unsupported-FPCR faults + 3 bitwise low-32 ABI rows** counted separately (the oracle masks unsupported FPCR bits). Unsupported numeric modes fault before any destination/FPSR write (`AOT_FAULT_BAD_STATE` / `AOT_FP_ERR_UNSUPPORTED_FPCR`). Bitwise `fmov`/`fabs`/`fneg` are unmasked by the numeric guard; vector `.16B` `and`/`orr`/`eor`/`add`/`sub` (SWAR). **No FP16/FMA/sqrt/FP-conversion/full SIMD.** |
| AOT atomics/order | VALIDATED (scoped serialized-SC proof model) | `ldxr`/`stxr` B/H/W/X and `ldar`/`stlr` B/H/W/X differential; `ldaxr`/`stlxr` X pair end-to-end (decoder/lowering all widths, not all fixtures). One domain-wide lock serializes every access (SC, deliberately stronger than the guest's weak model); 64-byte proof granule invalidation incl. same-value/ABA, exact address+width STXR match, per-runtime monitor token, HLE-boundary conservative local clear. The oracle is **value-based** for exclusives, so same-value/ABA is pinned by independent architectural reasoning plus locked **C-race-free wrong-backend controls** (no live-thread mutants); that is a known value-based monitor limitation of the oracle model, not a claim about upstream bugs. Barrier dropping is not a valid mutant under SC. **No weak/TSO-style backend, no alias domains.** |
| Guest/HLE x64 ABI | VALIDATED (scoped G2 controlled proof) | `AotGuestState` (816 B, 8-byte aligned, unchanged layout; subset id `g2-core-v2`) round-trips through native block entries and a registered typed native HLE handler (`void`, state effects, fixed resume). Release detaches every borrowed pointer without freeing caller-owned state/image; a live runtime is single-owner with no concurrent run/release. Host->guest callbacks/reentry not supported in the G2 ABI-v1 path; for ABI-v2 Program images see D015/D016 (G3). See D010/D012. |
| Translated module loader | IN PROGRESS (loader/linker VALIDATED; full-module translation not started) | main/sdk/subsdk0 translated images map/link. Evidence (G3, `docs/g3-module-loader.md`): explicit guest address space + 3 regions per module with Horizon permissions; exact-version verification (flat SHA-256 + pinned layout) before any region; RELA/JMPREL/RELR, kinds 257/1025/1026/1027, Mac resolution order, override/observer thunks, weak/strong rules, independent-reference link digest (D017). Fixture modules (ld.lld, 4 variants) byte-identical to the Python reference and an llvm-readelf checker, 16 negative images, 11 loader mutants. Locally (opt-in `MN_TOTK_V0_DIR`) the real TotK 1.0.0 main/subsdk0/sdk link with 558,865 sites byte-identical to the reference, digest match, 0 unresolved strong imports, relocate 74 ms. Limitation: only a real slice is translated (main's `GetSystemTick` PLT stub, sdk's `GetSystemTick`; subsdk0 link-only); coverage today is 37.5% of the 32,979 exported functions. |
| Module init/callbacks | VALIDATED (translated fixture modules; real constructors pending full-module translation) | Constructors and host callbacks execute correctly. Evidence: `aot_g3_exec` runs an nn::init::Start-shaped flow as translated code (host -> sdk_start -> loader_ready/module_inits thunks -> nested DT_INIT of main, sub, sdk -> init_array walked by the guest -> constructors calling across modules), exact global order and exactly-once, finalizers never called; HLE->guest and translated->translated callbacks; INIT_ARRAY_WALK mutant rejected. Real 1.0.0 DT_INIT bodies are not executed (they need full-module translation). |
| Core Horizon services | NOT STARTED | Headless boot checkpoint on Windows |
| RomFS/filesystem/save | NOT STARTED | Native Windows probes pass |
| Graphics backend decision | RESEARCH | Vulkan vs D3D12 spike recorded in DECISIONS.md |
| NVN device/sync/memory | NOT STARTED | Backend probes for queues, pools, fences pass |
| NVN textures/rendering | NOT STARTED | Clear + textured minimal draw passes |
| Shader translator win-x64 | NOT STARTED | NativeAOT service runs and deterministic fixtures match |
| Shader backend materialization | NOT STARTED | Minimal game shader produces correct draw |
| Window/frontend | NOT STARTED | First present in Win32 window |
| Keyboard/controller | NOT STARTED | Input probe passes |
| Audio | NOT STARTED | Renderer reaches audible verified output / reference probe |
| Movie playback | NOT STARTED | VP9 reference probe passes on Windows |
| First visible game boot | NOT STARTED | G6 checkpoint evidence |
| Basic gameplay 1.0.0 | NOT STARTED | G7 checklist passes |
| 1.4.3 support | NOT STARTED | Same acceptance set on 1.4.3 |
| Windows packaging | NOT STARTED | Clean machine build/package instructions verified |
| Long-session/performance | NOT STARTED | Repeatable measurements and known issues documented |

## G1 gate summary (GOAL.md)

GOAL.md G1 asks for three host-only, game-data-free things. Current
candidate evidence:

| G1 criterion | Evidence | Honest limitation |
|---|---|---|
| A Windows x64 executable builds from the repository | `CMakeLists.txt` rejects non-Windows / non-AMD64 / in-source builds; `host_check`, `romfs_probe` and the host-library probes build with VS 18 x64 MSVC `/W4` (Debug and Release, external dirs with spaces) | Local MSVC 19.51 / VS 18 evidence only; hosted CI not yet run from this branch |
| It can run platform-neutral tests/probes without game data | 10/10 CTest in Debug and Release: build skeleton, RomFS paths, clock conversion + live, TLS slots, thread lifecycle, mutex/condition, VM region, core logger | Probes use no game data/keys; hosted CI has not been executed from this branch |
| Core platform wrappers exist for memory, timing, threading and logging | host VM (memory), host monotonic clock (timing), host thread + mutex/condition (threading), host core logger (logging), plus host TLS slots | HOST primitives only: no guest ABI, scheduler or guest objects. Fault handling is a separately scoped row and is not part of G1's wrapper list |

All three G1 criteria are locally validated in this candidate; hosted CI
has not been run from this branch. G1 is unchanged by the G2 documentation
phase.

## G2 gate summary (GOAL.md G2 / Plan Phase 1, controlled fixtures)

**Evaluation (lead, local): SATISFIED LOCALLY — G2 is recorded CLOSED /
VALIDATED for the controlled proof.** This covers only the controlled fixture
subsets, not full ISA, title/game or backend parity.

| G2 criterion (controlled fixtures) | Evidence | Honest limitation |
|---|---|---|
| AOT ARM64 -> x86-64 execution path with defined guest ABI | `AotGuestState` (816 B, 8-byte aligned) + typed native block exits + transcribed C blocks; see `docs/g2-aot-proof.md`, D010 | Controlled subset only; no full ISA; D008 backend choice OPEN |
| Independent decode/CFG agreement | Exact-mask decoder + manifest CFG (concurrency: exact per-chunk ranges; differential: one containing range with unreachable padding, reached from explicit entries) vs independent Capstone 5.0.7 CFG; 3 width-validator negatives | Capstone/Unicorn are dev-only tools; no hosted CI |
| Differential semantics evidence | 3049 cases = 3048 exact + 1 deliberate fault, `mismatch=0` (Debug 58.99 s and Release 58.69 s, external spaces-in-path builds) | Pinned Unicorn A57 oracle; value-based exclusives; masks unsupported FPCR bits |
| Negative controls | 12 standard rejections, `infra=0` (11 real-lowering generator mutants + the `hlex18` native HLE-callback control, which is not a generator mutant; `pair32trunc` also asserts exact fault fields); separate native `fpignoreguard` guard control (typed STOP + changed FPCR/dest) | Guard cross-checks are manual exact-exit evidence, not CTest (`WILL_FAIL` refused) |
| Numeric FP and memory/exclusive model within the controlled scope | 2304 FP matrix cells + 45 helper + 10 translated closed rows; 392 native-only unsupported-FPCR + 3 bitwise; serialized-SC arena with 2/4 real-thread and wrong-program-order controls | No FP16/FMA/sqrt/conversion/full SIMD; no weak/TSO backend; no alias/guest VM |
| Stability (not a new exit condition) | 7 runtime/FP/concurrency tests × 100 repeats × Debug+Release = 1400 runs, all PASS (16.40 s / 16.08 s); AOT-OFF 10/10 both configs | Stability only; no hosted CI |

Unchanged limitations: no FP16/FMA/sqrt/conversion/full SIMD/full ISA, no
alias/guest VM/weak-TSO backend, no host->guest callback/reentry, no hardware
or native-Mac oracle and no hosted CI. **D008 (global backend) and D007
(graphics backend) remain OPEN; G3 (module loader/linking; the runtime
fault/exception policy is a separate NOT STARTED prerequisite) has NOT
STARTED at G2 integration (current G3 status: see the G3 gate summary), and real game boot is later still (G4/G6, none begun).** The validated
proof was integrated into `windows-x86-port` in `8793f189` after explicit user
approval. The integration tree matched the validated worktree; nothing was pushed.

Repetition evidence (out-of-tree logs, not committed): `ctest -R
"host_(thread_lifecycle|sync_mutex_cond|vm_region|log)_probe" --repeat
until-fail:20` in the external Debug and Release dirs exited `0` with each of
the four probes passing 20/20 (160 new-probe runs total). Stability evidence
only; it does not close any additional exit condition.

## G3 gate summary (GOAL.md G3 / Plan Phase 2)

**Evaluation (lead, local): G3 OPEN** (exit condition unchanged; loader/linking is a completed part of G3, not a separate gate). The loader/linking infrastructure is
validated (fixtures + the real TotK 1.0.0 modules locally), but GOAL.md G3
speaks of *translated main/sdk/subsdk0 images* and of *constructors* running
through translated code; on the real modules only a slice is translated and
the real constructors are not executed. That part needs a full-module
translator, i.e. the still-open D008 backend work.

| G3 criterion | Evidence | Honest limitation |
|---|---|---|
| Translated main/sdk/subsdk0 images are mapped with the required guest layout semantics | D014/D017: explicit guest VA space in [2^32, 2^39), 3 regions per module (text R-X state 3, rodata R state 3, data+bss RW state 4), Horizon query/protect/RELRO-lock semantics, host protection never executable, verified before any region; real 1.0.0 layouts (incl. the `end` symbol at the page-rounded image end) map and seal (`aot_g3_real_link`, opt-in) | Real images are only partially translated (main's `GetSystemTick` PLT stub, sdk's `GetSystemTick`; subsdk0 link-only by name) |
| Relocations/imports resolve correctly | Fixture link byte-identical to an independent Python reference and an llvm-readelf checker (4 variants), 16 negative images, 11 loader mutants; real 1.0.0: 558,865 sites byte-identical to the reference, digest match, 0 unresolved strong imports with the Mac binding tables (6 observers / 171 overrides), 213 thunk-bound sites, 22 weak-zero | Horizon symbol order unverified (Mac order kept; global-first would change 1,112 sites / 111 names) |
| Constructors and host callbacks can execute through translated code | `aot_g3_exec`: nn::init::Start-shaped boot (host -> sdk_start -> module_inits thunk -> nested DT_INIT x3 -> guest-walked init_array -> cross-module constructors), observer + nested real call, HLE->guest and translated->translated callbacks; Unicorn A57 oracle on 15 non-nested scenarios; exec mutants rejected | Real 1.0.0 constructors not executed (need full-module translation) |
| No hidden ARM64 execution remains in the tested path | Dispatch only through translated block tables (no decoder/interpreter/JIT at run time); guest text is host `PAGE_READONLY` (D014, `VirtualQuery`-checked, HOST_EXEC mutant rejected); the real slice runs main stub -> sdk `GetSystemTick` -> CNTPCT HLE on 4 threads x 1000 calls (`aot_g3_real_exec`, opt-in) | Coverage evidence: 83.43% of real text words decode in module mode, but only 37.51% of the 32,979 exported functions are CFG-complete |

Regression: G1 and G2 unchanged — the 22 G2 tests pass, G2 generated C is
byte-identical apart from its two provenance lines (`aot_g2_gen_identity`),
G2 mutants 12/12. Final local runs: Debug 41/41 with `MN_TOTK_V0_DIR`, Release
38/38 without it; runtime 13/13, loader 11/11, exec 5/5 mutants rejected,
`infra=0`. A pre-existing parallel-build race (MSBuild) and a cross-test
coupling found during G3 were fixed at the source.

## Current blockers

1. **G3 closure:** full-module translation of main/subsdk0/sdk (remaining A64
   integer/memory/SIMD/FP forms, indirect-target and code/data discovery) so
   the real modules can be fully translated and their DT_INIT constructors
   run. This is the D008 backend decision plus translator coverage; first
   blocking forms on the real code are `tbz/tbnz`, shifted-register `and`,
   `stp/str/ldur/stur` variants, `mov` aliases and `csel`.
2. A host VEH/SEH fault policy is still not implemented (guest faults are
   typed software faults and do not need it today).
3. Windows graphics backend is not selected or implemented (D007 open).

## Next recommended work

1. G3 stays OPEN with its exit condition unchanged (user decision): the
   loader/linking part is a completed component of G3, not a closed gate.
   Next objective: remove the remaining G3 blocker by translating enough of the
   real main/subsdk0/sdk modules to run their translated DT_INIT constructors
   (D008 evidence and first blocking forms: `docs/g3-module-loader.md` coverage
   section).
2. Keep real-module validation local and opt-in (`MN_TOTK_V0_DIR`); never
   commit game-derived artifacts.
3. G4 (headless Horizon) remains out of scope until G3 is closed.
4. Keep the Apple/ARM64 dependency inventory current as work proceeds.
