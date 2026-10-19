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

Bring up the smallest existing supported compatibility surface first. Add 1.4.3 after the core Windows architecture is validated.

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

## D009 — Host VM commit requires the whole range reserved

**Status:** Accepted

`host_vm_commit()` requires every page in the requested range to be currently
`MEM_RESERVE` and rejects any already-committed or mixed reserved/committed
range with `HOST_VM_ERR_INVALID_STATE` **before** any mutating native call
(only read-only preflight queries such as `VirtualQuery` run first). It is not
idempotent, and re-committing is not a supported way to change a page's state.

Reason: `VirtualAlloc(MEM_COMMIT, PAGE_READWRITE)` over an already-committed
page rewrites its protection. A lead experiment showed an RX(32) page changing
to RW(4). That would silently weaken a protection the wrapper promised to
preserve (the Mac loader seals text RX and rodata R with `mprotect`). Requiring
the whole range reserved and rejecting mixed ranges up front is simpler and
safer than multi-run partial mutation with rollback: a partial commit could
leave the range half-changed when a later page fails.

Consequences:

- A caller that wants a fresh zero-filled read/write page must `decommit()`
  then `commit()`.
- An "ensure committed" convenience that commits only the reserved pages of a
  range, if ever wanted, is a separate helper on top of this primitive and is
  not part of this decision.
- `range_all_state()` reports a `VirtualQuery` failure as
  `HOST_VM_ERR_PLATFORM` rather than `HOST_VM_ERR_INVALID_STATE`, so a platform
  failure cannot be mistaken for a wrong-state rejection.
- This is a host VM primitive rule only; file/COW/alias mapping and any fixed
  guest VA layout remain deferred to G3.

## D010 — Canonical guest-state ABI and finite native block exits

**Status:** Accepted (scoped to the G2 proof; D008 remains OPEN)

The translated-code ABI uses one owned struct `AotGuestState`
(`src/aot/aot_abi.h`): `x[31]` (x0..x30, with x18 an ordinary guest GPR),
separate `sp` and `pc`, `nzcv` normalized to bits 31..28, `v[32]` 128-bit
lanes, low-32 `fpcr`/`fpsr`, `tpidr`/`tpidrro`; 816 bytes, 8-byte aligned
(no 16-byte promise). Translated blocks are plain C functions using the
Windows x64 standard compiler ABI; each block returns a typed exit reason and
the runtime owns PC. There is no opcode decoder/interpreter/JIT and no
dynamically allocated or written executable code (the static PE `.text` is
naturally RX); no ARM64 payload is loaded, decoded or executed at runtime.
There is no host recursion into translated code. HLE is a registered typed
native C callback (`AotHleHandler`, `void (*)(AotGuestState *,
const AotHleRequest *, void *)`) that mutates guest state and returns with a
fixed resume; there are no non-local exits or tail-calls into HLE and
**host -> guest callback/reentry is not supported**.

Reason: keeps the translated-call ABI small, testable and compiler-neutral
while avoiding committing to a global backend (D008) prematurely.

Consequences: STOP is only legal immediately after RET (a proof-harness
sentinel, not a guest thread-exit ABI); numeric FP/FPCR/FPSR semantics and
atomics/ordering were PLAN at the time of this entry and are now specified,
within the controlled proof scope, by the superseding D012 and D013 (this
entry's ABI/HLE design is unchanged); a runtime fault policy is a separate G3
row (not a G2 exit condition).

## D011 — The C-backend AOT proof is scoped evidence, not the module backend

**Status:** Accepted (D008 remains OPEN)

The G2 proof emits straight-line native C basic blocks from an offline
exact-mask decode plus an explicit manifest CFG, verified against an
independent Capstone-derived CFG and a pinned Unicorn A57 differential oracle
(dev-only). It is opt-in (`MN_BUILD_AOT_PROOF=ON`) so G1 builds need no LLVM /
Python / Unicorn / Capstone.

Reason: a readable generated-C backend plus installed MSVC gives fast,
inspectable differential evidence now, without claiming a full-module
translator or benchmark.

Consequences: the generated-C SHA256 is a config/image fingerprint, **not**
the real G3 exact-version loader source hash. The full-module backend choice
(D008) is deliberately left open; the FP/atomic architecture left open here is
now specified for the controlled proof scope by D012/D013 (they supersede only
that PLAN consequence, not this decision), and any LLVM vs direct-x64 backend
comparison remains future work. This decision must not be read
as an implicit acceptance of a global backend.

## D012 — Scoped numeric/bitwise FP semantics for the G2 proof

**Status:** Accepted (scoped to the G2 proof; D008 remains OPEN)

Translated numeric FP is implemented in software on integer bit patterns
(`src/aot/aot_fp.c`, `src/aot/aot_fp.h`), never via host floating-point
arithmetic, so no host MXCSR state, x87/SSE NaN propagation, denormal mode or
host flag behavior is assumed. The supported finite subset is F32/F64
FADD/FSUB/FMUL/FDIV/FCMP/FCMPE with FPCR modes RN/RP/RM/RZ and the DN and FZ
bits, plus sticky FPSR flag accumulation (IOC/DZC/OFC/UFC/IXC/IDC, with QC
preserved). DN affects NaN result selection/quieting and FZ flushes denormal
inputs/results with IDC/UFC as specified; signed zeros, NaN precedence and
rounding ties are covered by closed-form rows with raw integer expectations.

The numeric FPCR guard is checked BEFORE the operation and any destination or
FPSR write. An unsupported numeric mode faults with fault CODE
`AOT_FAULT_BAD_STATE` and fault STATUS `AOT_FP_ERR_UNSUPPORTED_FPCR` (`1`),
`fault_src` = operation PC, and leaves the whole guest state unchanged except
the runtime-owned PC. Bitwise FMOV/FABS/FNEG use the low-32 ABI unmasked by
that numeric guard (they are pure bit operations and must not quiet or
reinterpret NaNs).

Reason: the G2 gate must be deterministic and testable without depending on
host FP behavior, and the pinned Unicorn A57 oracle cannot judge unsupported
FPCR bits (it masks them), so those rows are native-only evidence.

Consequences: this supersedes ONLY the "numeric FP/FPCR/FPSR semantics ... are
PLAN" consequence of D010, and any implication in D011 that FP architecture is
still unaddressed. It does not change the D010 ABI/HLE design (`AotGuestState`
stays 816 bytes; `AOT_ABI_VERSION`, `AOT_STATE_LAYOUT` and the layout are
unchanged) and does not choose a global backend (D008 remains OPEN). The
expanded subset is identified as `AOT_SUBSET_ID "g2-core-v2"`.
Guarded by the native-only translated probe (unsupported-mode faults, bitwise
low-32 ABI, closed-form translated rows), the differential matrix and the
`fpdropflags` / `fproundrn` / `fpnanorder` / `fpignoreguard` negative controls.

## D013 — Scoped translated-memory/exclusive-monitor model for the G2 proof

**Status:** Accepted (scoped to the G2 proof; D008 remains OPEN)

Shared mutable guest memory in the proof is defined ONLY through the arena API
(`src/aot/aot_mem.c`, `src/aot/aot_mem.h`), where every access (ordinary, HLE,
ordered and exclusive) is serialized under one domain-wide lock: the proof's
memory model is sequentially consistent. SC is deliberately stronger than the
guest's weak model, so it can never be silently weaker. Each runtime holds an
explicit, stable exclusive-monitor token registered in the domain, while the
reservation itself (address + size, 0 = disarmed) lives in the shared domain,
never in guest state or `AotGuestState`.

Invalidation uses a 64-byte proof granule (cited A57 ERG4) and is deliberately
conservative: any store, including a same-value (ABA) write or a neighbour in
the granule, disarms an overlapping reservation; STXR still requires an exact
address + width match. The SVC/HOSTCALL boundary clears the LOCAL reservation
before and after the handler as a conservative proof policy (not an
unconditional ARM exception-entry guarantee); a RET sentinel preserves the
reservation, while a fault or HLE boundary clears the local one. HLE handlers
must perform all guest-memory access through the API using the provided
`user` pointer (typically the AotMem/arena).

Ownership/lifetime preconditions are part of the contract: `aot_mem_init`
registrations are frozen before concurrent use; one host byte belongs to at
most one live domain; alias domains are not detectable and are out of scope;
an arena outlives every AotMem copy and the domain; release detaches every
borrowed pointer and never frees caller-owned state/image; a live runtime is
single-owner and non-copyable, with no concurrent run/release.

Reason: a proof of correctness first. A faster weak/TSO-style backend or
barrier elision cannot be justified by this evidence, so no barrier-dropping
mutant claim is made; the wrong-backend controls are C-race-free (they exercise
the invalidation predicate in a deterministic 2-runtime schedule rather than
live-thread mutants).

Consequences: this supersedes ONLY the "atomics/ordering remain PLAN"
consequence of D010. It does not change the D010 ABI/HLE design or the ABI
identity, and does not choose a global backend (D008 remains OPEN). It is
guarded by the translated-memory concurrency schedule tests, their
`AOT_MEM_TEST_NO_INVALIDATION` wrong-backend control, and the independent
Capstone CFG checker for exact per-chunk ranges.
