# Porting Status

This file is the shared status board for the Windows x86-64 port.

Statuses: **NOT STARTED**, **RESEARCH**, **IN PROGRESS**, **BLOCKED**, **VALIDATED**.

Do not mark a row VALIDATED because it compiles. Add evidence that satisfies the exit condition.

| Area | Status | Exit condition / evidence |
|---|---|---|
| Project documentation | VALIDATED | Goal, architecture, plan, decisions and agent rules created |
| Windows build skeleton | NOT STARTED | Win-x64 host executable builds and runs a no-game-data probe |
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
2. Windows platform wrappers do not exist yet.
3. Windows graphics backend is not selected or implemented.

## Next recommended work

1. Produce a machine-readable inventory of Apple-specific/ARM64-specific source dependencies.
2. Define the translated guest register-state ABI.
3. Build the smallest Windows x64 host/probe.
4. In parallel, run a tightly scoped Vulkan-vs-D3D12 graphics spike.
5. Begin AOT translation with generated instruction fixtures, not TOTK as the first test case.
