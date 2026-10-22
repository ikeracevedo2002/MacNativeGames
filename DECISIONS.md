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

**Status:** Accepted (scoped to the G2 proof; D008 remains OPEN). For ABI-v2 Program images, the HOSTCALL
resume rule and BR-into-thunk rejection are superseded by D015 and the no-reentry rule by D016; ABI-v1 G2
images are unchanged.

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

## D014 — Explicit guest address space with Horizon page permissions

**Status:** Accepted (G3; D008 remains OPEN)

Guest virtual addresses are a 64-bit space disjoint from host addresses. Host code never dereferences a
guest VA; every guest access goes through `aot_mem_*` / `aot_as_*` (`src/aot/aot_as.{h,c}`), still serialized
under the single D013 domain lock. Regions are 4 KiB-granular, sorted and disjoint, restricted to
[2^32, 2^39) (nothing is mappable below 4 GiB, so 32-bit pointer truncation is detectable; the upper bound
is Horizon's 39-bit address space). Each page carries a Horizon permission {---, R--, RW-, R-X}, a state
(3 = module code/rodata, 4 = module data) and the permanent RELRO lock attribute (16). Loads need R, stores
need W; R-X pages are readable as data (MOD0/literal reads) but "execute" only means "dispatchable through a
translated block table". Spanning accesses check every page before any byte is written. The region table is
built through an init-only path and frozen at seal; a failed load poisons the space so it can never be
sealed. The HOST protection of a guest page is never executable: guest R-X maps to host PAGE_READONLY
(guest X is bookkeeping plus the dispatch check), RW- to read/write, R-- to read-only, --- to no access, so no
ARM64 payload ever sits in host-executable memory and no host-executable memory is allocated at run time. A
G2 single arena is unchanged (no address space attached).

Reason: the Mac port identity-maps guest VA == host VA and writes host pointers into guest memory; that is
not valid with translated code (a guest function pointer is not an x86-64 function pointer), and an explicit
space makes permission, truncation and wild-pointer faults deterministic and testable. Identity mapping
remains a possible later backend optimization behind the same interface (performance is out of scope).

Evidence: `aot_g3_as` (region rules incl. the exact 2^39 bound, permission matrix, zero-byte spanning
stores, protect/lock/query, host protection queried through `host_vm_query` and `VirtualQuery` with no
`PAGE_EXECUTE*` bit), the post-seal permission checks in `aot_g3_link`, and the runtime mutant driver
(`aot_g3_runtime_mutants`: NO_PERM, PARTIAL_STORE, HOST_EXEC among 13, all rejected).

Consequences: supersedes D009's "fixed guest VA layout deferred to G3" and extends D013 from one arena to a
region table. Bulk/zero-copy host access (GPU, filesystem) and the guest heap/alias/stack layout reported by
svcGetInfo are OPEN (G4+). Guest memory faults are typed software faults (no host exception path is needed
for them); a host VEH/SEH policy is still a separate open item.

## D015 — Program dispatch, ABI v2 and host thunks as guest functions

**Status:** Accepted (G3; D008 remains OPEN)

A linked Program is an immutable set of ABI-v2 images (`AOT_ABI_VERSION_PROGRAM`, subset "g3-module-v1")
with disjoint guest text ranges plus one host-thunk region and one host-return sentinel region (both
unmapped for data). One AotRuntime per guest thread shares the Program. Every next PC, whatever exit
produced it, resolves as: misaligned -> MISALIGNED; sentinel -> host return (D016); thunk -> host call;
inside an image's text -> its block or UNTRANSLATED; otherwise UNKNOWN_PC. Guest code pointers are always
guest VAs. A thunk VA behaves as a guest function `{ handler(); ret }`: entering it by BL/BLR/BR/B/cond/
fallthrough captures r = x30 AT ENTRY, which must already be a translated entry or the active sentinel slot
(else BAD_RESUME without calling the handler); the handler may change x30 but control resumes at r; entry
via RET is BAD_TRANSFER. One thunk per symbol name program-wide (function-pointer equality across modules).
`mrs` of CNTPCT_EL0/CNTVCT_EL0 is a new HLE kind AOT_HLE_SYSREG (id = sysreg16<<8 | Rt, resume site+4);
handlers are keyed by the system register (Rt masked) and write the destination themselves (Rt=31 discards).

Evidence: `aot_g3_program` (fake-block images: every thunk entry kind, BAD_RESUME without handler call,
handler x30 clobber, BAD_TRANSFER, UNTRANSLATED vs UNKNOWN_PC vs MISALIGNED, SYSREG incl. XZR), `aot_g3_exec`
on translated fixture modules (PLT `br x17` into an override thunk with exact site/resume, thunk identity
across modules, SYSREG with Rt 0/8/31 and CNTVCT/TPIDR), the Unicorn oracle `aot_g3_exec_oracle`, and the
runtime/exec mutant drivers (THUNK_SITE4, RESUME_AFTER, HANDLER_BEFORE_RESUME_CHECK, SYSREG_XZR, ...).

Reason: real NSO PLT stubs (`adrp x16; ldr x17,[x16,#off]; add x16,x16,#off; br x17`, reached by BL) make
"BR into a thunk with the caller's x30" the normal path to an HLE-overridden import; G2 rejected it
(AOT_FAULT_TAIL_THUNK). Resolving thunks for every exit kind closes the RET/B gaps found in review.

Consequences: changes D010's HOSTCALL resume definition and lifts its BR-into-thunk rejection for ABI-v2
images only; ABI-v1 G2 images keep the legacy single-image semantics byte-for-byte. AOT_STATE_LAYOUT and the
816-byte AotGuestState are unchanged.

## D016 — Synchronous host->guest calls (nested and top-level)

**Status:** Accepted (G3; thread exit/unwinding is OPEN for G4)

`aot_call_guest(rt, fn, args<=8, &x0)` is legal at depth 0 on the owning OS thread or from inside a Program
handler (depth+1, max 16). It sets x0..x7 and x30 = sentinel slot of this depth, requires a 16-byte-aligned
SP, clears the local exclusive monitor on entry/exit, and completes only when a RET reaches this depth's
slot with SP equal to the entry SP (else BAD_RETURN). AAPCS64 callee-saved state (SP, x19-x29, low 64 of
v8-v15, FPCR) is VERIFIED (ABI_VIOLATION), never restored. The runtime saves/restores its own per-block
scratch around the nested loop; the step budget and evidence logs are shared and never reset; an inner fault
is sticky and terminates the outer run even if the handler ignores it; a handler cannot start another nested
call after a sticky fault. Guest thread exit at depth > 0 fails closed (AOT_FAULT_EXIT_IN_NESTED reserved).

Reason: the Mac boot path is host->guest->host->guest (nn::init::Start calls the host module_inits callback,
which calls each module's DT_INIT), and host services call guest allocators/events; D010 forbade reentry.

Evidence: `aot_g3_program` (depth limit, wrong slot/SP/transfer -> BAD_RETURN, ABI_VIOLATION, scratch and
step accounting, sticky fault incl. the no-recall rule, foreign-thread rejection without touching the owner's
runtime, 4 threads x 1000 calls) and `aot_g3_exec` on translated modules (observer calling the real nnMain
nested, HLE->guest callback preserving x19-x28, and the nn::init::Start-shaped module_inits handler running
main/sub/sdk DT_INIT nested with an exact global constructor order), plus the mutants NO_DEPTH_CHECK,
NO_SCRATCH_SAVE, RESET_STEPS, DROP_STICKY, NO_ABI_CHECK, RECALL_AFTER_FAULT (all rejected).

Consequences: supersedes D010's "no host recursion / host->guest reentry not supported" and generalizes the
G2 STOP sentinel for ABI-v2 programs. Fibers/longjmp across a host frame are unsupported (detected at the
next sentinel by slot/SP checks).

## D017 — Module link contract and exact-version verification

**Status:** Accepted (G3)

Modules are flat NSO memory images (text|rodata|data + bss; MOD0 at the u32 at +4) mapped at fixed guest
bases chosen at AOT time, three regions per module (text R-X state 3, rodata R state 3, data+bss RW state 4).
Each module descriptor pins the flat image SHA-256, the layout (incl. the NSO dynsym count used when there is
no DT_HASH) and an expected link digest; the loader verifies every image before adding any region, then
relocates RELR+RELA+JMPREL (sites may not overlap any table the loader consumes) with kinds 257/1025 (S+A, also for thunk targets and unresolved weak = A), 1026 (S;
addend must be 0), 1027 (B+A, 0 <= A < image size); sites must be 8-aligned inside the data segment and
unique. Resolution order follows the Mac reference: JUMP_SLOT observer; override; own module's first defined
symbol; global search in module order (main, subsdk0, sdk); unresolved weak = 0+A; unresolved strong = link
failure naming module and symbol. SHN_ABS/reserved indices, STT_TLS and defined values beyond the image are
rejected (value == image size, e.g. the linker `end` symbol, is valid). All written values are guest VAs.
The link digest (SHA-256 of the relocated data segments) must equal the one computed offline by an
independent Python reference linker. Constructors: only DT_INIT is called (it walks its own init_array); the descriptor's init VA must agree with the
image's DT_INIT. The MOD0 bss rule is data_file_end <= bss_start <= bss_end <= image_size with image_size in
{bss_end, page_up(bss_end)} (real 1.0.0 modules align bss_start up and pin the page-rounded end, where the
linker symbol `end` lives). Loader stages are ordered and single-shot; a failure before seal poisons the
address space (it can never be sealed or run), while a stage re-run after seal is a typed error that touches
nothing. A module may be declared link-only BY NAME (mapped and relocated, no translated image); any transfer
into it faults. Images bind to descriptors by flat SHA-256 and their code ranges must lie inside the module's
text. Real game modules are validated only locally and opt-in (CMake cache var MN_TOTK_V0_DIR); repository
tests never require game data and real-module artifacts never enter the tree (D006).

Reason: exact-version discipline (GOAL requirement 5) and the Mac loader as executable specification (D004),
with deviations made explicit where Mac behavior is undefined for malformed input.

Evidence: fixture modules built by ld.lld in RELA/RELR/GNU-hash-only/shadow variants, linked by the C loader
with a per-site dump byte-identical to the independent Python reference linker and to an llvm-readelf-based
checker (`aot_g3_link`, `aot_g3_link_reference`), 16 crafted negative images rejected with specific details
(`aot_g3_neg`), 11 loader mutants rejected (`aot_g3_loader_mutants`); locally, the real TotK 1.0.0
main/subsdk0/sdk link with 558,865 relocation sites byte-identical to the reference, matching link digest,
0 unresolved strong imports under the Mac binding tables (6 observers, 171 overrides), 213 sites bound to
thunks and 22 weak-zero sites (`aot_g3_real_link`, opt-in).

Consequences: Horizon-vs-Mac symbol resolution order is not independently verified (Mac order kept, OPEN; on
the real 1.0.0 set a global-first order would change 1,112 symbolic sites over 111 names). DT_FINI/module
finalizers are not modeled; Mac game patches must become explicit translation-time overrides (OPEN). Entry
discovery treats link values that land in text as code entries; a data object placed in text and referenced
by address makes translation fail closed (code/data distinction for full-module translation is OPEN).

## D024 — Partial pivot to SavageWind-style module frontend and build; keep our runtime

**Status:** Accepted (direction). D007 and D008 remain Open.

Numbering note: D018–D023 are drafted in the unintegrated G3 candidate (worktree `w21-2`); this entry
is numbered after them so the two can be merged without renumbering.

Source: `docs/research/savagewind-audit.md`, pinned to SavageWindRecomp `575ad88e02f9a89a9a885d90039d48af33c982f4`.

Decision:

- **Adapt** (after hardening and tests): NSO/FDE metadata frontend with typed fail-closed parsing and
  per-boundary provenance; per-module generation organized in chunks with explicit build identity; the
  synthetic-NSO fixture builder; pure lifter operations only after differential equivalence and negatives.
- **Keep ours**: 816-byte guest-state ABI (D010), immutable Program and guest-VA transfers (D015), nested
  host->guest calls (D016), the validated loader (D017), guest address space and page permissions (D014),
  typed/sticky faults, the exclusive monitor with domain invalidation and FP/FPSR semantics (D012/D013),
  and the immutable RomFS provider.
- **Do not copy**: guest==host address identity or autocommit, host pointers stored in guest objects,
  exclusives implemented as value CAS, guest RET lowered to a plain C return, the all-labels BR fallback
  as control-flow authority, success replies for unknown HLE/IPC commands, saves without
  containment/commit, and BOTW-specific version, frame-loop or GPU approximations.
- **Compiled is not authorized.** A function body may be generated or compiled ahead of time, but the set of
  executable entries stays the CFG closure of roots admitted by the current root policy. Executing a
  compiled-but-unadmitted target must produce exactly the same typed result as today. FDE starts are
  evidence for boundaries, not roots; no BL/ADR/RELATIVE scan becomes an entry point by itself.
- No SavageWind code under GPL (Unicorn, the `swgen` helper) enters the runtime or the tree; reused MIT code
  keeps its SavageWind/LAS notices.

Effect on open decisions:

- D008: the concrete prioritized experiment is C generation driven by the adapted frontend, emitted against
  our ABI/memory/control model. SavageWind's BOTW build times and performance do not predict cost under our
  guarantees; D008 is closed only after that measurement.
- D007: Vulkan is the first backend to spike, using SavageWind's NVN 55.15/Vulkan/Maxwell code as study
  material. TotK's NVN guard (major == 55, minor >= 15) is compatible with 55.15; object layouts, entry-point
  corpus, synchronization and shader coverage are unverified, so D007 stays open.

Evidence (offline, local): SavageWind's tools parse our 1.0.0 main/subsdk0/sdk; all 10,700 DT_INIT_ARRAY
targets coincide with FDE starts and are present in `gen.Module.boundaries()`; our structural constructor
validator accepts all three tables. This proves metadata compatibility only, not lifter coverage,
equivalent ABI, init order or execution.

Consequences: G3 constructor progress is pursued by the frontend/build experiment (PORTING_PLAN Phase 2)
before any new root heuristic. No exit condition changes.
