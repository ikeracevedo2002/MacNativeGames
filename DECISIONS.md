# Architecture Decisions

Record durable decisions here. Do not silently change an accepted decision; add a superseding entry with evidence.

## D001 — Windows target is x86-64, not 32-bit x86

**Status:** Accepted

The target is Windows 10/11 x86-64 (AMD64). The Switch title is a 64-bit ARM application with memory requirements and pointer semantics incompatible with a practical 32-bit host port.

## D002 — Final guest execution is ahead-of-time translated

**Status:** Accepted

The Mac path relies on same-ISA ARM64 execution. Windows x86-64 cannot.

The supported Windows path will translate guest ARM64 code to x86-64 ahead of time. A JIT may be useful only as a temporary research/reference tool if explicitly isolated; it is not an acceptable final runtime dependency.

## D003 — Keep the HLE/native-host architecture

**Status:** Accepted

Do not turn the project into a general-purpose Switch emulator. Preserve the existing model: translated game code plus a focused host implementation of the Horizon/NVN behavior the title uses.

## D004 — Mac code remains the behavioral reference during the port

**Status:** Accepted

Do not delete working Mac implementations until the corresponding Windows behavior is independently validated. Mac code is the executable specification for many edge cases.

## D005 — First end-to-end game target is 1.0.0

**Status:** Accepted

Bring up the smallest existing supported compatibility surface first. Add 1.1.2 and 1.4.3 after the core Windows architecture is validated.

This does not change the final goal of supporting all versions currently supported by the Mac port.

## D006 — Game/user data stays outside the repository

**Status:** Accepted

Never commit game files, keys, extracted data, saves, generated translated game binaries or user shader caches.

## D007 — Windows graphics API

**Status:** Open

Candidates: Vulkan 1.3 and Direct3D 12.

The decision must be based on a short implementation spike comparing:

- reuse of existing Maxwell -> SPIR-V output;
- synchronization model required by NVN;
- descriptor/binding model;
- texture/format support;
- memory aliasing and guest-address behavior;
- shader compilation/cache story;
- debugging/tooling;
- amount of backend-specific code.

Do not choose solely from familiarity.

## D008 — AOT recompiler implementation strategy

**Status:** Open

Possible strategies include a custom IR/code generator or an LLVM-based backend.

The decision needs evidence from representative ARM64 fixtures and must account for:

- exact flag semantics;
- FP/SIMD behavior;
- indirect control flow;
- atomics/memory ordering;
- guest address mapping;
- HLE call boundaries;
- build/distribution complexity;
- translation time and generated-code performance.

The project should define the guest architectural state/ABI before committing to a backend.
