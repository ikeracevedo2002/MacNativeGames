# Windows x86-64 Porting Plan

Work in order unless a later task is a deliberate research spike that unblocks an earlier phase.

## Phase 0 — Inventory and platform boundaries

Goal: make the Mac assumptions explicit before changing behavior.

Tasks:

- inventory Apple/Mach/POSIX dependencies;
- inventory ARM64 assembly/direct-call assumptions;
- classify runtime files as shared, platform wrapper, Mac-only, or guest-ISA-specific;
- define the guest register-state ABI used by translated code and HLE;
- create minimal Windows build scaffolding for platform-neutral probes;
- run a graphics-backend spike for Vulkan vs D3D12.

Exit condition: G0/G1 requirements are concrete and no core subsystem depends on an undocumented platform assumption.

## Phase 1 — AOT translation core

Goal: prove ARM64 code can become correct x86-64 code before integrating the game.

Start with generated fixtures, not full TOTK modules.

Required coverage:

- integer ALU and flags;
- branches and conditional branches;
- direct and indirect calls;
- stack/frame behavior;
- loads/stores and addressing modes;
- FP/SIMD operations used by representative code;
- atomics/exclusive operations;
- calls to host/HLE gates;
- guest-to-translated function pointer resolution.

Use differential/reference validation and negative controls.

Exit condition: G2.

## Phase 2 — Windows image loader

Goal: load translated game modules while preserving guest layout/linking semantics.

Tasks:

- Windows virtual-memory abstraction;
- translated code/data mapping;
- relocation/import handling;
- module symbol lookup;
- executable-page/cache handling;
- translated callbacks/constructors;
- fault/guard mechanism;
- thread entry/exit glue.

Do not integrate graphics yet beyond stubs necessary for boot.

Exit condition: G3.

## Phase 3 — Horizon/runtime bring-up

Goal: reach deterministic headless boot checkpoints.

Port platform dependencies in this order:

1. time and TLS;
2. threads/synchronization;
3. memory/query/permission services;
4. IPC/service dispatch;
5. RomFS/filesystem/save path;
6. account/settings/applet essentials.

Keep shared service semantics intact and replace only host mechanisms.

Exit condition: G4.

## Phase 4 — Graphics backend

Goal: implement the existing NVN behavior on the selected Windows backend.

Suggested order:

1. device/queue/swapchain;
2. guest memory pools and buffer mapping;
3. synchronization/fences/events;
4. texture formats/views;
5. render targets and clears;
6. vertex/index/uniform/storage buffers;
7. shader translation/materialization;
8. descriptors/bindings;
9. draw/dispatch;
10. presentation and cache warm-up.

Port existing GPU probes where possible. Preserve the timing/lifetime lessons encoded in the Metal backend instead of copying its API shape.

Exit condition: G5.

## Phase 5 — Windows host I/O

Goal: replace remaining Apple desktop services.

- Win32 frontend/window lifecycle;
- keyboard;
- controller backend;
- rumble/motion where available;
- Windows audio output;
- VP9 movie path;
- software keyboard/text input;
- user-data/log/cache locations.

Exit condition: prerequisites for G6 are complete.

## Phase 6 — First game boot and gameplay

Progress through deterministic checkpoints:

1. process starts;
2. modules linked;
3. constructors complete;
4. graphics initialized;
5. first frame;
6. title/initial UI;
7. load/new-game scene;
8. movement/input;
9. save/reload;
10. death/retry.

At each checkpoint, record the last known-good boundary and add diagnostics before broad changes.

Exit conditions: G6 then G7.

## Phase 7 — Version parity and packaging

After 1.0.0 works:

- port 1.1.2 translated-code/loader differences;
- port 1.4.3 RELR/GNU-hash/patch differences;
- publish verified `win-x64` shader translator;
- make the top-level builder produce a Windows distribution;
- preserve input/hash/update validation;
- restore shader seed/warm-up behavior;
- document performance and long-session stability.

Exit condition: G8.

## Task sizing for agents

Good agent tasks should normally fit one of these shapes:

- one platform abstraction plus tests;
- one instruction family in the AOT translator plus differential tests;
- one loader feature plus fixture;
- one Horizon service dependency;
- one NVN semantic cluster plus probe;
- one Windows host backend contract.

Avoid tasks such as "port the runtime", "port graphics", or "make the game boot" without a narrower measurable boundary.
