# Porting Status

This file is the shared status board for the Windows x86-64 port.

Statuses: **NOT STARTED**, **RESEARCH**, **IN PROGRESS**, **BLOCKED**, **VALIDATED**.

Do not mark a row VALIDATED because it compiles. Add evidence that satisfies the exit condition.

| Area | Status | Exit condition / evidence |
|---|---|---|
| Project documentation | VALIDATED | Goal, architecture, plan, decisions and agent rules created |
| Windows build skeleton | VALIDATED (build-skeleton row only) | `CMakeLists.txt` rejects non-Windows, non-AMD64, in-source and source-subdirectory builds at configure time. `-A Win32` was driven locally to confirm the `CMAKE_SIZEOF_VOID_P=4` guard fires with `cmake` exit `1` and the message `supports ONLY 64-bit pointers`. `host_check.exe` builds with MSVC `cl.exe` (Visual Studio generator, C11, `/W4`) on Windows 10/11 x86-64 and enforces `_WIN64` + `_M_AMD64` + `sizeof(void *) == 8` at compile time. Original skeleton validation passed its 3/3 CTest cases: `host_check_default` (exit 0, prints `PASS: host architecture satisfied`), `host_check_negative_control` (verifier requires exact exit `1` and the exact diagnostic line `[negative-control] FAIL: expected pointer width 4 byte(s), got 8` against the real host), `romfs_path_cases` (unchanged `tests/test_romfs_paths.c` returns `PASS: 27 RomFS path cases`). Build-dir paths containing spaces were tested locally. Direct invocations of `host_check.exe`, `host_check.exe --negative-control`, and `romfs_probe.exe` match the contracted exit codes and outputs. This row does NOT cover VM, threads, faults, loader, AOT translation, NVN, audio, controller, frontend or packaging; those rows remain NOT STARTED. The host monotonic clock and the host TLS slot lifecycle are covered by their own rows below. CI is configured but the workflow has not been executed on a hosted runner from this branch. |
| Platform VM abstraction | NOT STARTED | Reserve/commit/protect/map tests pass on Windows |
| Host timing abstraction | VALIDATED (host monotonic clock only) | Windows QPC/QPF backend (`src/host_time.c`) and pure-integer scaling (`src/host_time_convert.c`). Deterministic `host_time_convert_cases` (20 fixed bigint-computed cases + 5 rejected negative controls: constant, wrong-unit, naive overflow, uint32-truncated frequency, error-output clobber) and live `host_time_live_probe` (NULL rejected, same-thread nondecreasing reads, 200 ms positive elapsed inside a GetTickCount64-bracketed interval, constant + wrong-scale controls rejected) pass locally in MSVC Debug and Release (5/5 CTest each, external build dirs with spaces). API has explicit failure handling, arbitrary non-wall epoch, per-thread nondecreasing reads, no cross-thread strict-ordering promise, no Mach equivalence claim; suspend is documented but not tested. This row does NOT include TLS; host TLS slots are covered by the separate "TLS abstraction" row. |
| TLS abstraction | VALIDATED (host TLS slots only) | Windows `TlsAlloc`/`TlsGetValue`/`TlsSetValue`/`TlsFree` backend (`src/host_tls.c`) behind the `<windows.h>`-free `src/host_tls.h`, with `tests/host_tls_probe.c`. Contract: explicit init/create/destroy lifecycle; create without init, init on a live slot, create twice and any get/set/destroy on an uninitialised or destroyed slot are rejected; a failing init/create/destroy leaves the handle's fields unchanged and a failing get leaves the caller's output at its sentinel; `get` distinguishes a legitimately empty slot (OK + NULL, via TlsGetValue/SetLastError) from a platform failure; set replaces and `set(NULL)` clears; two and four simultaneous slots stay independent; no destructor and no pointee ownership transfer. Per-thread NULL initialization is documented by Microsoft for `TlsAlloc` ("The slots for the index are initialized to zero") and is not attributed to `TlsFree`. Real-thread isolation (CreateThread is fixture-only) uses manual-reset event phase gates with bounded waits and no sleeps: main + 2 workers hold distinct values simultaneously, each observes only its own, a replace/clear in one thread does not disturb the others, a new thread starts NULL, and a writer thread that exits without clearing is followed by a fresh reader on the same live slot that sees NULL; 8 rounds. Five fixture-only wrong backends are rejected by the same battery: process-global per-slot storage (`0` sequential + several thread failures, 17–18 observed, i.e. it passes single-threaded use and is caught only by isolation; the count moves with scheduling but the split does not), aliased slots, clear no-op, error-output clobber, NULL-as-error. Infrastructure failures (event/thread creation, any bounded-wait/join timeout, or `HOST_TLS_ERR_ALLOCATION` where success is required — no fake injects it) print `FATAL` and `ExitProcess(1)` before any cleanup, so they can never be counted as a rejected negative. Debug and Release 6/6 CTest pass at `/W4` with no warnings, external build dirs with spaces. Out-of-tree `/W4 /WX` audit (not committed) forced genuine `TlsAlloc` exhaustion after 1086 live slots: `HOST_TLS_ERR_ALLOCATION` with the handle unchanged and still ready, retry of the same handle after freeing one index, new slot reads NULL, survivor values intact, cleanup successful; a lead rerun of `ctest -R "^host_tls_slot_probe$" --repeat until-fail:100` passed 100/100 in both Debug and Release with ctest exit 0 (out-of-tree logs). Limitations: native index 0 was not observed in the local runs (the first real slot received index 1) so that path is documented, not exercised — validity is the lifecycle tag, never the index, and no foreign index is freed to force it, so this is an observation and not a platform guarantee; TlsGetValue/TlsSetValue/TlsFree failure paths are implemented but not forced; no guest TLS/TLR, thread environment, key destructor (`environment_key` is deliberately out of contract), guest key page or AOT ABI; no integration with `runtime_keys[]`/`g_keythr` and no Mac change; this is not a thread create/join/wake API. |
| Thread/sync abstraction | NOT STARTED | Thread lifecycle/wait/wake probes pass |
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

## Current blockers

1. G1 is incomplete: the remaining host platform wrappers (thread/
   synchronization, virtual memory, core logging) do not exist yet; fault
   handling is a separately scoped row. The host monotonic clock and the
   host TLS slot lifecycle rows are validated.
2. No AOT ARM64 -> x86-64 execution layer exists yet.
3. Windows graphics backend is not selected or implemented.

## Next recommended work

1. Close G1 before moving on. The next concrete narrow boundary is the
   host thread/synchronization boundary: thread lifecycle, wait and wake
   for host threads only, not the guest thread ABI, the guest scheduler or
   the guest synchronization objects. The host TLS slot lifecycle plus its
   real-thread isolation probe is validated.
2. Then port the remaining G1 wrappers in order: virtual memory and core
   logging. Fault handling stays a separate row.
3. Defer AOT translation, the translated guest register-state ABI, the
   graphics-backend spike and game integration until the earlier gate is
   done.
4. Keep the Apple/ARM64 dependency inventory current as G1 proceeds.
