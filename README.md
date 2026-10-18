# MacNativeGames — Windows x86-64 Port

This branch ports the existing Apple-silicon native port of **The Legend of Zelda: Tears of the Kingdom** to **64-bit Windows on x86-64/AMD64**.

The macOS implementation is the reference implementation. The Windows port is **not playable yet**.

## What "native" means here

The original Switch executable is ARM64. Apple silicon can execute most of that code directly; an x86-64 PC cannot.

The Windows target therefore requires an **ahead-of-time ARM64 -> x86-64 recompilation layer**. The final runtime target is:

- x86-64 machine code running directly in a normal Windows process;
- no ARM64 execution by the host CPU;
- no JIT fallback in the final supported path;
- Horizon/Switch services implemented by the host runtime, as in the Mac port;
- NVN implemented on a Windows graphics API rather than Metal.

This is not a conventional full-system emulator. It is a native host runtime plus statically/AOT-translated game code.

## Target

- **OS:** Windows 10/11 64-bit.
- **CPU:** x86-64 / AMD64. 32-bit x86 is out of scope.
- **Game:** user-supplied Tears of the Kingdom files and keys only.
- **First bring-up version:** 1.0.0.
- **Final compatibility target:** preserve the Mac port's supported 1.0.0, 1.1.2 and 1.4.3 paths.

See [GOAL.md](GOAL.md) for acceptance criteria and [PORTING_PLAN.md](PORTING_PLAN.md) for the staged plan.

Windows build/run instructions for the G1 build-skeleton row live in
[docs/windows-build.md](docs/windows-build.md).

## Current source architecture

The working Mac port has four major pieces:

1. **ARM64 code preparation and loading** — `games/totk/third_party/d2r`, `runtime/loader.c`, ARM64 assembly gates.
2. **Horizon host runtime** — `games/totk/runtime`.
3. **NVN graphics implementation** — `games/totk/third_party/d2r_gfx/gfx/nvn`, currently backed by Metal.
4. **Packaging/tooling** — `build_app.py`, shader tools, extraction and verification scripts.

On Windows, item 1 changes fundamentally because guest ARM64 cannot execute directly. Items 2-4 should be reused where platform-neutral and split behind explicit platform boundaries where they are not.

Read [ARCHITECTURE.md](ARCHITECTURE.md) before changing these areas.

## Ground rules

- Do not commit game files, keys, extracted RomFS/ExeFS, saves, shader caches, generated translated game code, or other copyrighted/user data.
- Keep large build/test artifacts outside the source tree.
- Do not delete the Mac implementation just because a Windows replacement exists. It is the behavioral reference until parity is proven.
- Prefer narrow platform interfaces over duplicated runtime logic.
- Every porting change needs a reproducible test, probe, fixture, or documented manual acceptance check.
- Do not claim a subsystem is ported because it compiles. Update [PORTING_STATUS.md](PORTING_STATUS.md) only when its stated exit condition is met.

## Start here for agents

Read these files in order:

1. [GOAL.md](GOAL.md)
2. [DECISIONS.md](DECISIONS.md)
3. [ARCHITECTURE.md](ARCHITECTURE.md)
4. [PORTING_PLAN.md](PORTING_PLAN.md)
5. [PORTING_STATUS.md](PORTING_STATUS.md)
6. [AGENTS.md](AGENTS.md)

Then inspect the exact Mac code corresponding to the subsystem you are porting.

## Legal / project scope

This repository contains no Nintendo game data. Users must provide their own legally obtained game files and keys. The project is not affiliated with or endorsed by Nintendo.

The repository keeps the existing MIT license and third-party notices.
