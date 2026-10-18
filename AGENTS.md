# Agent instructions

This branch is the Windows x86-64 port of MacNativeGames.

## Before writing code

Read, in order:

1. `GOAL.md`
2. `DECISIONS.md`
3. `ARCHITECTURE.md`
4. `PORTING_PLAN.md`
5. `PORTING_STATUS.md`
6. the Mac source files for the subsystem being changed

Do not start a broad rewrite before identifying the exact Mac behavior that must be preserved.

## Working rules

- Work toward one explicit milestone/exit condition at a time.
- Prefer the smallest change that creates a new verified capability.
- Preserve the Mac implementation as a reference unless removal is explicitly justified by completed parity tests.
- Put platform-neutral logic in shared C/C++ where reasonable; isolate Win32 and graphics-backend code behind narrow interfaces.
- Do not spread `#ifdef _WIN32` through unrelated logic when a platform abstraction can contain it.
- Do not silently change guest-visible semantics to match Windows convenience.
- Treat guest register state, memory ordering, page protection, atomic behavior, FP behavior and GPU synchronization as correctness-sensitive.
- Keep a negative control for tests where a deliberately wrong implementation can otherwise pass accidentally.
- Do not mark work complete merely because it compiles.

## Critical architecture rule

The Mac port executes ARM64 game instructions directly. Windows x86-64 cannot.

The Windows port must therefore introduce an **AOT ARM64 -> x86-64 execution path**. Do not attempt to make the existing ARM64 assembly gates, rewritten NSOs or function pointers "just work" on x64.

Any task touching loader, calls, threads, SVCs, relocations, signals/exceptions or guest callbacks must account for the translated-code ABI.

## Graphics rule

The existing NVN implementation is heavily Metal/Objective-C based. Do not mechanically translate `nvn_mtl.m` line by line.

Preserve the NVN semantics and validated synchronization/lifetime behavior, then implement those semantics on the selected Windows backend. Reuse backend-neutral code and the existing Maxwell -> SPIR-V translation work where possible.

The backend choice is recorded as open in `DECISIONS.md` until an evidence-based spike resolves it.

## Repository hygiene

Never commit:

- XCI/NSP/NSZ/NCA files;
- `prod.keys` or title keys;
- extracted game modules or RomFS;
- generated AOT game code;
- saves;
- shader caches or GPU-specific compiled shader binaries;
- large local build/test artifacts.

Keep build products and local game data outside the source tree. `.gitignore` is not permission to store them inside the project.

## Validation and status

For every substantive change:

1. state which milestone it advances;
2. add or run the narrowest relevant test/probe;
3. record important evidence or limitations;
4. update `PORTING_STATUS.md` only if an exit condition changed;
5. add a decision to `DECISIONS.md` when making a lasting architectural choice.

If a result is uncertain, write it as uncertain. Do not convert assumptions into project facts.

## Scope discipline

Do not spend time on UI polish, performance tuning, installer work or multi-version support while an earlier correctness gate is still blocked unless the task directly removes that blocker.
