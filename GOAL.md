# Goal

## Mission

Produce a native **Windows x86-64** build of the existing Tears of the Kingdom Mac native port while retaining its host-runtime architecture and validation discipline.

The end state is a normal Windows x64 process in which the game's ARM64 code has been translated **ahead of time** into x86-64 code and interacts with a Windows host implementation of the services and graphics interfaces it expects.

## Non-negotiable end-state requirements

1. The supported gameplay path runs x86-64 host code. It must not depend on executing ARM64 instructions at runtime.
2. The final supported path has no JIT fallback.
3. The port must not become a full Switch emulator. Reuse the existing HLE/native-host model.
4. Game data, keys and generated game binaries remain external to the repository.
5. The source must retain exact-version verification before applying version-specific rewrites or patches.
6. Windows-specific behavior must be testable independently where practical.
7. A compile-only result is not considered a porting milestone.

## Compatibility target

### Initial bring-up

Use **TOTK 1.0.0** as the first end-to-end target because it is the smallest compatibility surface already supported by the Mac runtime.

The first useful success is not "gameplay". It is:

> A Windows x64 host executable loads AOT-translated 1.0.0 modules, resolves their imports, crosses host/HLE call boundaries correctly, and reaches a deterministic boot checkpoint without executing ARM64 code.

### Final target

After the 1.0.0 path is stable:

- add 1.1.2;
- add 1.4.3;
- preserve version-specific validation and patches;
- restore equivalent packaging, shader preparation, save handling and diagnostics.

## Milestone acceptance gates

### G0 — Porting foundation

- Windows branch/documentation exists.
- Platform-specific dependencies are inventoried.
- Architectural decisions and open questions are recorded.

### G1 — Windows host skeleton

- A Windows x64 executable builds from the repository.
- It can run platform-neutral tests/probes without game data.
- Core platform wrappers exist for memory, timing, threading and logging.

### G2 — AOT translation proof

- A controlled ARM64 fixture is translated to x86-64 ahead of time.
- Integer, branch, stack, call, SIMD/FP and condition-code behavior are validated against a reference.
- A translated call can enter and return from a host HLE gate with the agreed guest-register ABI.

### G3 — Module loader / linking

- Translated main/sdk/subsdk0 images are mapped with the required guest layout semantics.
- Relocations/imports resolve correctly.
- Constructors and host callbacks can execute through translated code.
- No hidden ARM64 execution remains in the tested path.

### G4 — Headless Horizon bring-up

- Threads, synchronization, memory, IPC, time and filesystem services reach a deterministic boot checkpoint.
- Save/RomFS behavior passes Windows-specific probes.

### G5 — Graphics bring-up

- NVN calls reach a Windows backend.
- A window/swapchain can clear and present.
- Buffer/texture lifetime and synchronization probes pass.
- Maxwell shaders can reach the chosen Windows shader pipeline and produce a working minimal draw.

### G6 — First visible game boot

- Game reaches visible UI/title/initial scene.
- Input works.
- Audio initializes.
- Shader cache can be created and reused.

### G7 — Basic gameplay

- Load/new game path works.
- Movement, menus/map, save/reload and death/retry pass.
- No known correctness failure is being hidden by a fallback emulator/JIT path.

### G8 — Feature/version parity

- 1.0.0, 1.1.2 and 1.4.3 supported.
- Packaging is reproducible.
- Long-session stability, shader warm-up/cache behavior and performance are documented.

## Out of scope until the core port works

- 32-bit Windows.
- Linux.
- macOS refactors unrelated to making the Windows port possible.
- New gameplay mods/features.
- Online services.
- Broad performance tuning before correctness gates pass.
