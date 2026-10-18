# Porting Status

This file is the shared status board for the Windows x86-64 port.

Statuses: **NOT STARTED**, **RESEARCH**, **IN PROGRESS**, **BLOCKED**, **VALIDATED**.

Do not mark a row VALIDATED because it compiles. Add evidence that satisfies the exit condition.

| Area | Status | Exit condition / evidence |
|---|---|---|
| Project documentation | VALIDATED | Goal, architecture, plan, decisions and agent rules created |
| Windows build skeleton | VALIDATED (build-skeleton row only) | `CMakeLists.txt` rejects non-Windows, non-AMD64, in-source and source-subdirectory builds at configure time. `-A Win32` was driven locally to confirm the `CMAKE_SIZEOF_VOID_P=4` guard fires with `cmake` exit `1` and the message `supports ONLY 64-bit pointers`. `host_check.exe` builds with MSVC `cl.exe` (Visual Studio generator, C11, `/W4`) on Windows 10/11 x86-64 and enforces `_WIN64` + `_M_AMD64` + `sizeof(void *) == 8` at compile time. CTest passes locally (3/3): `host_check_default` (exit 0, prints `PASS: host architecture satisfied`), `host_check_negative_control` (verifier requires exact exit `1` and the exact diagnostic line `[negative-control] FAIL: expected pointer width 4 byte(s), got 8` against the real host), `romfs_path_cases` (unchanged `tests/test_romfs_paths.c` returns `PASS: 27 RomFS path cases`). Build-dir paths containing spaces were tested locally. Direct invocations of `host_check.exe`, `host_check.exe --negative-control`, and `romfs_probe.exe` match the contracted exit codes and outputs. This row does NOT cover VM, timing, TLS, threads, faults, loader, AOT translation, NVN, audio, controller, frontend or packaging; those rows remain NOT STARTED. CI is configured but the workflow has not been executed on a hosted runner from this branch. |
| Platform VM abstraction | NOT STARTED | Reserve/commit/protect/map tests pass on Windows |
| Timing/TLS abstraction | NOT STARTED | Monotonic clock + TLS probes pass |
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

1. No AOT ARM64 -> x86-64 execution layer exists yet.
2. Windows platform wrappers do not exist yet (VM, timing, TLS, threads, faults).
3. Windows graphics backend is not selected or implemented.

## Next recommended work

1. Produce a machine-readable inventory of Apple-specific/ARM64-specific source dependencies.
2. Define the translated guest register-state ABI.
3. Begin porting the remaining G1 platform wrappers (VM, timing, TLS, threads, faults).
4. In parallel, run a tightly scoped Vulkan-vs-D3D12 graphics spike.
5. Begin AOT translation with generated instruction fixtures, not TOTK as the first test case.
