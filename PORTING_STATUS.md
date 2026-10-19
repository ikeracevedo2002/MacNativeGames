# Porting Status

This file is the shared status board for the Windows x86-64 port.

Statuses: **NOT STARTED**, **RESEARCH**, **IN PROGRESS**, **BLOCKED**, **VALIDATED**.

Do not mark a row VALIDATED because it compiles. Add evidence that satisfies the exit condition.

| Area | Status | Exit condition / evidence |
|---|---|---|
| Project documentation | VALIDATED | Goal, architecture, plan, decisions and agent rules created |
| Windows build skeleton | VALIDATED (build-skeleton row only) | `CMakeLists.txt` rejects non-Windows, non-AMD64, in-source and source-subdirectory builds at configure time. `-A Win32` was driven locally to confirm the `CMAKE_SIZEOF_VOID_P=4` guard fires with `cmake` exit `1` and the message `supports ONLY 64-bit pointers`. `host_check.exe` builds with MSVC `cl.exe` (Visual Studio generator, C11, `/W4`) on Windows 10/11 x86-64 and enforces `_WIN64` + `_M_AMD64` + `sizeof(void *) == 8` at compile time. Original skeleton validation passed its 3/3 CTest cases: `host_check_default` (exit 0, prints `PASS: host architecture satisfied`), `host_check_negative_control` (verifier requires exact exit `1` and the exact diagnostic line `[negative-control] FAIL: expected pointer width 4 byte(s), got 8` against the real host), `romfs_path_cases` (unchanged `tests/test_romfs_paths.c` returns `PASS: 27 RomFS path cases`). Build-dir paths containing spaces were tested locally. Direct invocations of `host_check.exe`, `host_check.exe --negative-control`, and `romfs_probe.exe` match the contracted exit codes and outputs. This row does NOT cover the host platform wrappers (VM, threads/synchronisation, logging), faults, loader, AOT translation, NVN, audio, controller, frontend or packaging. The host monotonic clock, host TLS slots, host VM, host thread/mutex/condition pair and host core logger are covered by their own validated rows below; fault/exception handling, the loader, AOT translation and every later milestone remain NOT STARTED in their own rows. CI is configured but the workflow has not been executed on a hosted runner from this branch. |
| Platform VM abstraction | VALIDATED (host anonymous region only) | `src/host_vm.{h,c}`: owning opaque region handle over `VirtualAlloc`/`VirtualFree`/`VirtualProtect`/`VirtualQuery`/`FlushInstructionCache`; `host_vm.h` is `<windows.h>`-free. Contract: reserve anonymous private pages (no access); **commit requires the WHOLE range reserved and rejects any committed/mixed range BEFORE any mutating native call** (a deliberate rule — `VirtualAlloc` `MEM_COMMIT` would otherwise reset an RX/read-only page to read/write; see D009); decommit/protect require every page committed; query reports the OS's own base/size/state/protection/type; flush is explicit; zero size is `INVALID_ARGUMENT`. `tests/host_vm_probe.c` drives the real backend against raw `VirtualQuery` plus a probe-local SEH guarded-access pair, and rejects: recommit of RO, RX, all-committed and mixed reserved/committed ranges with protection+contents independently unchanged; zero-size commit/decommit/protect; misaligned/out-of-range/overflow; unknown protect bits; reserved-page decommit/protect; and checks decommit-then-recommit zero-fill and release→`MEM_FREE`. Debug and Release 10/10 CTest, `/W4` no warnings. Limitations: the `range_all_state` `VirtualQuery`-failure→`PLATFORM` path and OS `HOST_VM_ERR_ALLOCATION`/`PLATFORM` are implemented but NOT forced; the SEH fixture is NOT the runtime fault-row policy. Scope: anonymous private reserve+commit only (the Mac `mmap(NULL,size,PROT_RW,MAP_PRIVATE|MAP_ANON)+fread` shape); file/COW/alias mapping and any fixed guest VA layout are deferred to G3. |
| Host timing abstraction | VALIDATED (host monotonic clock only) | Windows QPC/QPF backend (`src/host_time.c`) and pure-integer scaling (`src/host_time_convert.c`). Deterministic `host_time_convert_cases` (20 fixed bigint-computed cases + 5 rejected negative controls: constant, wrong-unit, naive overflow, uint32-truncated frequency, error-output clobber) and live `host_time_live_probe` (NULL rejected, same-thread nondecreasing reads, 200 ms positive elapsed inside a GetTickCount64-bracketed interval, constant + wrong-scale controls rejected) pass locally in MSVC Debug and Release (5/5 CTest each, external build dirs with spaces). API has explicit failure handling, arbitrary non-wall epoch, per-thread nondecreasing reads, no cross-thread strict-ordering promise, no Mach equivalence claim; suspend is documented but not tested. This row does NOT include TLS; host TLS slots are covered by the separate "TLS abstraction" row. |
| TLS abstraction | VALIDATED (host TLS slots only) | Windows `TlsAlloc`/`TlsGetValue`/`TlsSetValue`/`TlsFree` backend (`src/host_tls.c`) behind the `<windows.h>`-free `src/host_tls.h`, with `tests/host_tls_probe.c`. Contract: explicit init/create/destroy lifecycle; create without init, init on a live slot, create twice and any get/set/destroy on an uninitialised or destroyed slot are rejected; a failing init/create/destroy leaves the handle's fields unchanged and a failing get leaves the caller's output at its sentinel; `get` distinguishes a legitimately empty slot (OK + NULL, via TlsGetValue/SetLastError) from a platform failure; set replaces and `set(NULL)` clears; two and four simultaneous slots stay independent; no destructor and no pointee ownership transfer. Per-thread NULL initialization is documented by Microsoft for `TlsAlloc` ("The slots for the index are initialized to zero") and is not attributed to `TlsFree`. Real-thread isolation (CreateThread is fixture-only) uses manual-reset event phase gates with bounded waits and no sleeps: main + 2 workers hold distinct values simultaneously, each observes only its own, a replace/clear in one thread does not disturb the others, a new thread starts NULL, and a writer thread that exits without clearing is followed by a fresh reader on the same live slot that sees NULL; 8 rounds. Five fixture-only wrong backends are rejected by the same battery: process-global per-slot storage (`0` sequential + several thread failures, 17–18 observed, i.e. it passes single-threaded use and is caught only by isolation; the count moves with scheduling but the split does not), aliased slots, clear no-op, error-output clobber, NULL-as-error. Infrastructure failures (event/thread creation, any bounded-wait/join timeout, or `HOST_TLS_ERR_ALLOCATION` where success is required — no fake injects it) print `FATAL` and `ExitProcess(1)` before any cleanup, so they can never be counted as a rejected negative. Debug and Release 6/6 CTest pass at `/W4` with no warnings, external build dirs with spaces. Out-of-tree `/W4 /WX` audit (not committed) forced genuine `TlsAlloc` exhaustion after 1086 live slots: `HOST_TLS_ERR_ALLOCATION` with the handle unchanged and still ready, retry of the same handle after freeing one index, new slot reads NULL, survivor values intact, cleanup successful; a lead rerun of `ctest -R "^host_tls_slot_probe$" --repeat until-fail:100` passed 100/100 in both Debug and Release with ctest exit 0 (out-of-tree logs). Limitations: native index 0 was not observed in the local runs (the first real slot received index 1) so that path is documented, not exercised — validity is the lifecycle tag, never the index, and no foreign index is freed to force it, so this is an observation and not a platform guarantee; TlsGetValue/TlsSetValue/TlsFree failure paths are implemented but not forced; no guest TLS/TLR, thread environment, key destructor (`environment_key` is deliberately out of contract), guest key page or AOT ABI; no integration with `runtime_keys[]`/`g_keythr` and no Mac change; this is not a thread create/join/wake API. |
| Thread/sync abstraction | VALIDATED (host primitives only) | `src/host_thread.{h,c}`: `_beginthreadex`/`_endthreadex` callback (host C, per-thread CRT state), bounded join with `CloseHandle` checked, poll-before-id self-join guard, close-without-wait that does not extend the caller-owned argument's lifetime. `src/host_sync.{h,c}`: SRWLOCK exclusive + CONDITION_VARIABLE, heap-backed typed handles (no array type punning). `tests/host_thread_probe.c`: real battery plus 2 behavioral fakes rejected only by the join behavior they break; real-only self-join, close-while-running (gated worker, later join refused, worker body still runs) and create→join→reuse-spent-handle phases; failure field snapshots. `tests/host_sync_probe.c`: lifecycle battery (real only) including destroy→reinit, mutex-exclusion battery (real + no-op-mutex fake), CV battery (real + 3 condition fakes, all using a GENUINE mutex so no wrong backend is UB); worker `ready` event precedes the exclusion window; bounded predicate loops tolerate spurious wakes; broadcast requires a NON-timeout wake; timeout lower-bounded by an independent `QueryPerformanceCounter`; infrastructure failures FATAL/`ExitProcess(1)`. Debug and Release 10/10 CTest, `/W4` no warnings. Limitations: `HOST_THREAD_ERR_WAIT`, `HOST_SYNC_ERR_PLATFORM` and allocation paths are implemented but not forced; the mutex state after a `host_cond_wait` platform failure is UNKNOWN (documented, not promised). Scope: HOST threads/locks only; no guest thread ABI, scheduler, guest handles/events or address arbiters. |
| Host logging abstraction | VALIDATED (host core logger only) | `src/host_log.{h,c}`: explicit handle, whole record `[LEVEL] tid=0x<8 hex> <message>\n` formatted then `fwrite`+`fflush` under a per-handle SRWLOCK; level filtering; bounded formatting with an explicit `...<truncated>` marker; `host_log_close` returns its OWN final flush/close result and always consumes the handle; no timestamps/rotation/callbacks/singleton and no process-global buffering mutation. `tests/host_log_probe.c`: shape/filter/truncation, CR/LF/NUL normalisation (one call = exactly one line), 4 writers × 200 records verified as one complete non-interleaved stream, a corrupted-stream checker with 5 rejected synthetic negatives, and a real `HOST_LOG_ERR_IO` write forced through a `_pipe`/`_dup2` broken-stderr fixture (no public hook); temporary files are removed after each phase. Debug and Release 10/10 CTest, `/W4` no warnings. Limitations: `host_log_close`'s OWN flush/close IO failure is not forced (stderr is unbuffered, so its close flush is clean — documented); an owned file sink whose `fclose` fails is not exercised. |
| Fault/exception handling | NOT STARTED | Guarded guest memory fault probe passes |
| AOT decoder/CFG | NOT STARTED | Controlled ARM64 fixture recovers expected blocks/edges |
| AOT integer/flags | NOT STARTED | Differential fixture suite passes |
| AOT branches/calls | NOT STARTED | Direct/indirect call fixtures + negative controls pass |
| AOT FP/SIMD | NOT STARTED | Representative differential suite passes |
| AOT atomics/order | NOT STARTED | Exclusive/atomic fixtures pass |
| Guest/HLE x64 ABI | NOT STARTED | Translated code round-trips register state through host call |
| Translated module loader | NOT STARTED | main/sdk/subsdk0 translated images map/link |
| Module init/callbacks | NOT STARTED | Constructors and host callbacks execute correctly |
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
| 1.1.2 support | NOT STARTED | Same acceptance set on 1.1.2 |
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
has not been run from this branch. This does not satisfy any G2+ criterion
and makes no runtime fault-policy claim.

Repetition evidence (out-of-tree logs, not committed): `ctest -R
"host_(thread_lifecycle|sync_mutex_cond|vm_region|log)_probe" --repeat
until-fail:20` in the external Debug and Release dirs exited `0` with each of
the four probes passing 20/20 (160 new-probe runs total). Stability evidence
only; it does not close any additional exit condition.

## Current blockers

1. No AOT ARM64 -> x86-64 execution layer exists yet (**G2**) — the next
   real blocker.
2. Fault/exception handling remains a separate NOT STARTED row; the VM
   probe's local SEH guarded-access fixture is NOT runtime fault policy.
3. Windows graphics backend is not selected or implemented (D007 open).

## Next recommended work

1. The next real gate is **G2**: a controlled ARM64 fixture translated
   ahead-of-time to x86-64, with integer/flags/branch/call/SIMD-FP
   differential checks and a translated call entering and returning through
   a host HLE gate with the agreed guest-register ABI. Define the guest
   register-state ABI before committing to a translation backend (D008).
2. File/COW/alias mapping, fixed guest VA layout and the translated image
   loader stay **G3**; the VM row above is only the anonymous private
   reserve+commit primitive.
3. Fault/exception handling (VEH/SEH abstraction) stays a separate row and
   is a prerequisite for the loader's fault/guard mechanism.
4. The graphics-backend spike (D007) remains open and follows G2/G3.
5. Keep the Apple/ARM64 dependency inventory current as G1 proceeds.
