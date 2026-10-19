# Architecture

This document describes the working Mac architecture and the seams that must change for Windows x86-64.

## 1. Current Mac execution model

### Guest CPU

The Switch game is ARM64 and Apple silicon is ARM64. The Mac port therefore keeps almost all game instructions intact.

`games/totk/third_party/d2r/patch_nso.py` rewrites a limited set of instructions/behaviors that cannot execute unchanged on macOS, including system calls, platform-register usage, thread-pointer behavior and counter access.

`games/totk/runtime/loader.c` maps the rewritten modules and calls into them directly.

ARM64 assembly bridges include:

- `runtime/gate.S`
- `runtime/hle_stack.S`
- `runtime/thread_enter.S`
- `third_party/d2r_gfx/gfx/nvn/nvn_entry.S`
- `third_party/d2r_gfx/gfx/nvn/nvn_thunks.S`

This direct-execution model cannot be carried to x86-64.

### Host runtime

`games/totk/runtime` implements the subset of Horizon/Switch services used by the game: memory, threads, synchronization, IPC, filesystem, time, account, input, audio, software keyboard, movie playback and related services.

Much of the service logic is reusable, but several host mechanisms are Apple/POSIX-specific.

### Graphics

The game calls NVN. The current NVN host implementation lives under:

`games/totk/third_party/d2r_gfx/gfx/nvn`

The dominant backend implementation is `nvn_mtl.m`, backed by Metal. MetalFX and other Apple-specific paths are in nearby Objective-C files.

Important behavior to preserve is not "Metal behavior"; it is the guest-visible NVN contract:

- resource and memory-pool semantics;
- ordering;
- queue submission;
- fences/events;
- render-pass behavior;
- texture/buffer formats and aliases;
- shader/reflection binding behavior;
- presentation timing.

### Shaders

The current translator path is approximately:

`Maxwell machine code -> Ryujinx translator -> SPIR-V -> SPIRV-Cross -> MSL -> Metal`

The translator is published NativeAOT as `games/totk/prebuilt/macos-arm64/totk_xlate`.

The SPIR-V stage is a valuable backend-neutral seam for Windows.

### Packaging

`build_app.py` is macOS-oriented: Apple tooling, app bundles, signing/verification and Mac paths. Extraction, exact hash verification, update handling and much of the data preparation should remain reusable.

## 2. Target Windows architecture

### Guest execution: AOT ARM64 -> x86-64

Add an offline/ahead-of-time translation stage:

`verified ARM64 module -> decode/control-flow recovery -> translated x86-64 code + metadata -> Windows loader`

The translator must preserve:

- ARM64 integer semantics;
- NZCV/condition semantics;
- FP/SIMD behavior used by the title;
- guest stack and calling behavior;
- indirect branches/calls;
- atomics and memory ordering;
- exception/HLE boundaries;
- exact guest addresses where guest-visible behavior depends on them.

The host runtime needs a defined **guest register state ABI** for calls into SVC/HLE helpers. The existing ARM64 gate layout is a useful semantic reference, not reusable x64 code.

**Scoped G2 proof status (D010/D011/D012/D013).** A finite-subset offline
C-translation path now exists and is opt-in (`-DMN_BUILD_AOT_PROOF=ON`; see
`docs/g2-aot-proof.md`). It defines the owned `AotGuestState` ABI (816 B,
8-byte aligned; unchanged by the subset expansion), typed native block exits
with the runtime owning PC, a registered typed native HLE handler
(host->guest callbacks/reentry are not supported), a software numeric FP model
(F32/F64 add/sub/mul/div/fcmp/fcmpe over RN/RP/RM/RZ/DN/FZ with sticky FPSR
and an explicit unsupported-FPCR fault before any write), and a serialized
sequentially-consistent arena/exclusive-monitor model (SC is deliberately
stronger than the guest's weak model; barriers are therefore not valid
negative mutants). It is verified by an independent Capstone-derived
reachable CFG and a pinned Unicorn A57 differential oracle with real-lowering
and callback negative controls. The concurrency fixture uses exact per-chunk
ranges; the differential fixture declares a containing range with unreachable
padding.

**G2 evaluation (lead, local):** the GOAL.md G2 / Plan Phase 1
*controlled-fixture* exit conditions are **SATISFIED LOCALLY** and G2 is
recorded **CLOSED/VALIDATED for the controlled proof only** — not full-ISA,
not title/game and not backend parity. The area rows are therefore VALIDATED
in `PORTING_STATUS.md` for their controlled subsets. The full-module
translated-code backend (D008) and the graphics backend (D007) stay **OPEN**;
G3 module loading/linking and its runtime fault/exception prerequisite
remain **NOT STARTED**; real game boot belongs to later G4/G6 gates and has
not begun. The candidate is uncommitted (main checkout on branch `windows-x86-port`,
clean at `0a30a282`) and requires explicit user approval before integration.

### Memory model

The Mac implementation assumes relationships between guest virtual addresses, CPU pointers and GPU addresses.

The preferred first strategy is to preserve a stable guest virtual-address model on Windows where practical, using Windows virtual-memory primitives. Do not assume identity mapping is always possible; prove the required address ranges and constraints before depending on it.

Relevant Windows primitives will likely include `VirtualAlloc`/`VirtualAlloc2`, `VirtualProtect`, mapped files and vectored exception handling, but the final abstraction should expose guest semantics rather than raw Win32 calls.

### Host/platform layer

Create narrow platform boundaries for at least:

- virtual memory / page protection / instruction-cache handling;
- monotonic timers;
- threads, TLS and synchronization;
- exception/fault handling;
- filesystem mapping and file I/O;
- process paths/user-data paths;
- frontend/window lifecycle;
- controller input/rumble/motion;
- audio output;
- dynamic-library/process helpers where needed.

Avoid forking the complete Horizon service implementation.

### Graphics backend

The target keeps the NVN HLE/API layer but replaces Metal execution with a Windows-capable backend.

Candidate backends:

- Vulkan 1.3
- Direct3D 12

The decision is intentionally open until a spike compares required NVN semantics, shader path, synchronization, descriptor model, format support and amount of reusable code.

The architecture should keep NVN semantics above a backend boundary so backend-specific code does not invade service/runtime code.

### Shader pipeline

Publish `totk_xlate` for `win-x64` with NativeAOT.

Prefer separating:

1. Maxwell -> SPIR-V + reflection
2. backend-specific shader materialization

This avoids baking Metal concepts into the reusable translator service. A Vulkan backend may consume SPIR-V directly; a D3D12 backend would need an evidence-based SPIR-V/HLSL/DXIL path.

### Frontend/input/audio

Current Apple-specific source includes Objective-C files such as:

- `runtime/frontend.m`
- `runtime/gamepad.m`
- `runtime/gamepad_feedback.m`

and Apple frameworks linked in `games/totk/Makefile`.

Windows replacements should implement the existing runtime-facing contracts rather than redesigning game-facing behavior.

## 3. Known platform-specific hotspots

| Area | Current files/mechanisms | Windows need |
|---|---|---|
| Guest execution | `patch_nso.py` + native ARM64 | AOT x86-64 translation |
| Loader/VM | Mach/POSIX APIs in `runtime/loader.c` | Win32 VM + translated image loader |
| HLE gate | ARM64 `gate.S`, `hle_stack.S` | x64 translated-call ABI/gates |
| Threads | pthread/TLS + ARM64 entry glue | Win32/shared abstraction + x64 glue |
| Fault tracking | POSIX signals/Mach behavior | VEH/SEH or equivalent abstraction |
| Frontend | AppKit/Cocoa Objective-C | Win32 window frontend |
| Input | GameController/CoreHaptics | Windows controller backend |
| Audio | Apple-linked host output path | Windows audio backend |
| Graphics | `nvn_mtl.m`, Metal/MetalFX | Vulkan or D3D12 backend |
| Shader service | macOS arm64 NativeAOT + MSL | win-x64 NativeAOT + backend-neutral output |
| Build/package | Xcode/Homebrew/.app/signing | Windows toolchain + portable extraction + Windows package |

### G1 host-layer status (narrow)

Of the rows above, only the **host platform layer** has a Windows
implementation so far, and only as narrow, game-data-free primitives:

- **VM**: `src/host_vm.{h,c}` implements an anonymous private
  reserve/commit/decommit/protect/query/flush primitive behind an owning
  handle. It is the host shape of the Mac loader's
  `mmap(NULL, size, PROT_RW, MAP_PRIVATE|MAP_ANON) + fread`, not a guest
  address strategy; file/COW/alias mapping and fixed guest VA layout are
  still open (G3).
- **Threads**: `src/host_thread.{h,c}` (host `_beginthreadex` lifecycle) and
  `src/host_sync.{h,c}` (SRWLOCK + CONDITION_VARIABLE) implement HOST
  threads and the host mutex/condition pair only. The guest thread ABI,
  guest scheduler, guest synchronization objects and the x64 HLE gate glue
  remain open.
- **Timing / TLS / logging**: host monotonic clock (`src/host_time.*`),
  host TLS slots (`src/host_tls.*`) and a host core logger
  (`src/host_log.*`) exist as host primitives.

The `Loader/VM`, `Threads` and `HLE gate` rows above therefore remain
accurate for the *guest-visible* Windows port: none of the guest-facing
behavior is implemented yet, and the Mac implementation is still the
reference. Fault tracking is unchanged: no runtime fault policy exists.

## 4. What should stay conceptually unchanged

Unless evidence proves otherwise, preserve:

- verified input/version selection;
- exact patch-site validation;
- RomFS/update verification;
- Horizon service contracts;
- guest-visible handles and IPC behavior;
- game-specific patch intent;
- save migration/safety behavior;
- shader identity/cache versioning discipline;
- probe/negative-control philosophy.

The port is a host-platform and guest-ISA migration, not a license to alter game semantics.
