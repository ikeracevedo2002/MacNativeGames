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

## D018 — Boot heap window: one reserve-only AS heap, Mac retained bytes, high-water private

**Status:** Candidate (implemented and probe-verified in an isolated worktree; NOT integrated, G3 remains OPEN)

The address space owns at most one guest heap window. It is added pre-seal with
`aot_as_add_heap_window(base, max, commit_limit)`, lives inside the existing
D014 address layout (probe profile: `[256GiB, 260GiB)`, max 4 GiB), returns no
host pointer, and is RESERVE-only: host pages start reserved/no-access and guest
permission is derived as NONE until the post-seal
`aot_as_set_heap_size(size, &base)` transition commits them.

The transition tracks logical `size` and a PRIVATE committed high-water mark
`hw`; the committed set is always `[0,hw)` and the guest table is
`[0,size)` RW/state 5, `[size,hw)` NONE/Free, `[hw,max)` NONE/Free. Grow
commits fresh `[hw,t)` only when `t>hw`, then protects retained
`[size,min(t,hw))` to RW (it never re-commits committed pages, because D009
makes `host_vm_commit` reject them). A failed retained protect rolls back only
the new fresh commit; a failed rollback is sticky fail-closed. Shrink protects
`[t,size)` to NONE FIRST and never decommits (Mac `mprotect(PROT_NONE)` keeps
the bytes; a later regrow preserves them, while never-committed pages stay
zero), publishing the new size and invalidating overlapping exclusive
reservations only after the OS succeeds. Every transition runs under the
existing D013 domain lock with no guest/HLE callback held. Invalid guest sizes
(non-2 MiB, above max or checked commit limit) are a typed alignment error and
write no output; host refusals are `AOT_MEM_ERR_HOST` appended after the
existing enum values, so no prior numeric value changes.

`seal()` skips the heap window, `protect()/lock()` reject whole and mixed heap
spans, the window counts as claimed for `range_mapped` (no thunk overlap), and
the legacy `aot_as_query` reports truthful heap state (5/RW or 0/NONE) instead
of an invented sentinel. `aot_as_host_page` on heap pages returns the borrowed
reservation plus offset and a NULL page pointer even for reserve/retained pages.

Reason: the Mac runtime is the reference for SetHeapSize (services.c:310-313
plus memory.c query), while D009 forbids the tempting "re-commit retained
pages" shortcut.

Evidence: `aot_g3_as_heap` (normal 8 MiB fixture + 4 GiB reserve-only smoke),
`aot_g3_as_heap_fault_1..4` (host refusals: fresh commit, retained protect,
failed rollback sticky, shrink protect) and 21/21 runtime mutants rejected
including eight heap controls (shrink-decommit, publish-before-host,
no-monitor-invalidate, recommit-retained, high-water-as-used, Info5-reports-size,
no-desync, publish-on-commit-fail); Debug and Release
`/W4 /WX`; existing `aot_g3_as`, `aot_g3_program`, `aot_g3_runtime_mutants`
still pass. Host state is witnessed through `host_vm_query`, never the AS
table.

Consequences/OPEN: the HLE wiring for GetInfo(4/5), SVC 0x01 (SetHeapSize),
GetInfo(2/3, 12/13, 14/15) and the mapped-only SVC 0x06 QueryMemory is
implemented in this candidate and covered by the Start HLE probes. A
whole-domain Free-hole query beyond the registered windows, the GetInfo(7)
budget view and any mapping of unsupported addresses remain unimplemented. No
alias/ASLR/exception-context ids are invented. `commit_limit` is supplied by
the boot profile as checked `APP_POOL - pinned image bytes`; the AS does not
compute game budgets.

Amended (alias capability): the same AS owns one immutable RESERVED role
`ALIAS` via `aot_as_add_reserved_window(as, base, size, role)` and
`aot_as_reserved_info(as, role, &base, &size)`. It shares the window guards
with the heap (no per-page table/AS flags, no SetHeapSize, whole-window
Free/NONE, claimed for range_mapped, host RESERVE-only, `host_page` returns
VM+offset and a NULL host page). The boot profile places alias at
`[0x5000000000, 0x6000000000)` (320-384 GiB, 64 GiB) as a deliberately NEW
AOT guest layout, preserving the queried geometry/state/bounds; it is NOT
literal numeric parity with Mac's 448-512 GiB placement, which would overlap
the validated thunk region. GetInfo(2/3) read this AS geometry only (never
fake constants).

OPEN: physical-map zero-on-remap versus heap retained-byte semantics, and all
ASLR/stack/exception policies, remain undecided until an actual guest path is
reached; no randomization or global-constant claims are made. This does not
close G3.

Amended (SVC 0x06 QueryMemory, mapped-only): the G3 Start HLE answers id 0x06
from `aot_as_query(as, r2)` and writes the Mac 40-byte little-endian record
`{u64 base,size; u32 state,attr,perm,ipc,device,pad}` through ONE whole-span
`aot_as_write` when raw `r0 != 0` (a NULL r0 skips the copy; r1 is never
dereferenced). Success is exactly `r0=0/r1=0`. An address the AS cannot
describe is a typed unsupported diagnostic with the queried VA in
`fault_target`; Mac's state-3/perm-5 fallback and its stack-map/alias
special cases are deliberately NOT reproduced. A read-only or cross-NONE
output span is `AOT_FAULT_MEMORY` with the guest output pointer in
`fault_target` and no partial bytes. A missing or poisoned AS fails closed.
Evidence: `aot_g3_start_hle_query` (Debug/Release) covers stack 0xb/text
3-perm-5/data 4/locked attr 16/heap-alias-stack Free, r0 NULL, writable and
invalid r1, unknown r2, RO and cross-NONE faults, two AS geometries and
wrong-field/constant-state/partial-write/page-info-deref controls. The real
Start driver now reports `svc6_calls=1 success=1` and stops at the next
unhandled SVC 0x0c (main handle 0x1001), not at 0x06. G3 remains OPEN.

Amended (bounds + stack arena): GetInfo(12/13) report the EXISTING D014 AS
extent [AOT_AS_MIN_ADDR, AOT_AS_MAX_ADDR) = [4 GiB, 512 GiB), read from the
validated AS instance via `aot_as_bounds`; this is a description of the
existing address space, not a new allocation and not Mac's ASLR numeric
identity (Mac's ASLR_START is a low-space host choice; its endpoint is 39-bit).
GetInfo(14/15) report a separate AS-owned immutable STACK role
`[0x2800000000, 0x2810000000)` = 160 GiB + 256 MiB, reserve-only, disjoint from
the current main-thread stack at 128 GiB, TLS 192 GiB, heap 256 GiB, alias
320-384 GiB and control 508 GiB. This is the GLOBAL STACK MAPPING ARENA, NOT
the current main-thread SP region; Mac QueryMemory special-cases the native
pthread current stack separately. No MapMemory(4/5) implementation.

Amended (general QueryMemory; supersedes the mapped-only SVC 0x06 limitation):
`aot_as_query_domain` describes every uint64 data VA from one domain-locked,
sealed, unpoisoned AS snapshot. It preserves the mapped-only `aot_as_query`
contract: claimed regions/windows keep their existing permission/attribute
runs; unclaimed holes are Free/NONE bounded by the nearest claimed edges.
The fixed lower profile interval `[0,MIN)` is Free/NONE (Mac services.c:291,
whose endpoint equals GetInfo(12)); adjacent Free records at profile/window
edges need not merge. `[MAX,2^64)` is Inaccessible (state 0x10), base MAX,
size `0ull-MAX`, attributes/permissions/counters zero; the end intentionally
wraps to zero. This is address-query success, not permission to dereference.
Evidence for the upper record: Atmosphere-NX/Atmosphere commit
[`6b0c077b4c608a3a2ee712b8dc35fee87ceb62e8`, KPageTableBase::QueryInfo](https://github.com/Atmosphere-NX/Atmosphere/blob/6b0c077b4c608a3a2ee712b8dc35fee87ceb62e8/libraries/libmesosphere/source/kern_k_page_table_base.cpp#L1911-L1940).
The SVC retains the Mac 40-byte little-endian copy and register ABI; no
state-3/perm-5 catch-all is invented. Host/invalid-output faults remain explicit.

D015's thunk/sentinel VAs are an opaque control-flow namespace, NOT backed
guest memory; general QueryMemory therefore describes their surrounding
Free data-AS gap, with no permissions. This does NOT promise allocatability.
They are not added as physical regions (which would violate Program's
unmapped-for-data proof). **Tripwire:** before any future mapping service can
claim arbitrary ASLR VAs outside the fixed role windows, the Program must
claim its control ranges once through a shared query/mapping-exclusion seam
and report them Inaccessible; do not silently let a guest allocation collide.
That mapping capability is not implemented here. Opus independently reviewed
this scoped interpretation; no loader/linker rule or dispatch ABI changes.

Validation: `aot_g3_as_query_domain` checks exact bounded walks for two AS
geometries, every interval's first/interior/last byte, heap grow/shrink and
retained tail, 0/MIN/MAX/UINT64_MAX, poisoned/unsealed/null rejection without
output writes. The SVC probe checks the full record, register/FP/SIMD
preservation, canaries and output overflow/straddles. Real implementation
mutants for low-base, gap extent, upper state, mapped-only HLE and partial
store are rejected with positive baselines and exact semantic-failure labels.
Debug and Release narrow probes and all 32 runtime mutants pass. The real
Start now returns from original nnosInitialize (owner 0x1001) and executes
loader_ready, with no guest state patch. G3 remains OPEN.

## D019 — Physical alias mapping in the AS: page state machine, stale zero-fill, group decommit

**Status:** Candidate (implemented and probe-verified in an isolated worktree; NOT integrated, G3 remains OPEN)

`MapPhysicalMemory`/`UnmapPhysicalMemory` (Mac `services.c` `alias_map`,
SVC 0x2c/0x2d) commit and release individual 4 KiB pages inside the one
reserve-only alias window (`AOT_AS_RESERVED_ROLE_ALIAS`, D014). The guest-visible
state machine lives in the address space, not in the services layer, so a
QueryMemory run, the budget check and the host mapping can never disagree.

Per page the AS keeps `MAPPED`, `COMMITTED`, `STALE`, `NEW`. Map charges only
pages that are not MAPPED (Mac counts `fresh` before the budget check), checks
`fresh + heap_size + alias_bytes + pinned_bytes <= pool` on *every* map request,
including one whose fresh count is zero, because Mac's guard is `!unmap` rather
than `fresh > 0`: a heap grown afterwards can push the total over the pool and
turn a pure re-map into `0x10801`. The check is taken under the same domain
lock that the heap size is read with (no race with SetHeapSize), then runs the
host phase: commit a non-committed page, raise it to RW, zero-fill it if STALE,
and publish the whole range only after every host step succeeded. Rollback
reverts exactly the pages this call touched; if the rollback itself fails the
space becomes sticky-desynced and every later alias call fails with the same
typed code (Mac aborts the process).

The zero-fill has to happen AFTER the protect: a released page is host NONE
(the unmap phase denies access), so zeroing it first is an access violation,
not a semantic choice. The positive-control probe found this as a hard crash
before the ordering was fixed, which is why the ordering is pinned here.

Unmap is three phases: deny access to every mapped page (fully revertible
because the guest table still says mapped), publish the release (clear MAPPED,
set STALE, subtract `alias_bytes`), then return any 16 KiB group whose four
pages are all unmapped to the host pool (Mac `services.c:138-140`); only the
committed pages of a group need a host call. A host refusal is a typed
`AOT_MEM_ERR_HOST` and sticky, because the Mac reference would have aborted.

Query answers the maximal run of equal page occupancy around the address
(Mac `services.c:296-299`), so a released page inside a partly mapped group
joins its neighbouring Free run instead of reporting a single page.

Validation: `aot_g3_as_alias_map` drives the whole state machine plus a host
witness (`VirtualQuery` through `aot_as_host_page`), with three deterministic
host-refusal seams as positive controls (`aot_g3_as_alias_fault_1/2/3`) and six
wrong-implementation mutants rejected with their exact first semantic failure
(charge-all, keep-stale, keep-mapped, query-no-run, no-budget, omit-usage).
Two defects were found by that evidence and fixed in the source: the stale
zero-fill ordering above, and a drifted control — `MN_AOT_ALIAS_MUT_QUERY_STATE5`
sat on the shared reserved-window branch, so it was silently breaking the STACK
query and no longer proved its alias claim; it now breaks the alias run branch.

Probe exit protocol: semantic failure is exit 2 everywhere the mutant driver
reads a probe (`tools/aot/g3_mutant_test.py` treats 1 as infrastructure).
`tests/aot/g3_start_hle_probe.c` returned 1 for semantic failures; it now
returns 2 so its `sysres` mutant can be counted as a rejection instead of an
infrastructure failure. The driver also accepts the documented `PASS: <name>`
success spelling of the newer probes.

That second increment found two defects of its own, both fixed: (1)
`g3_start_hle_init` listed every counter field by hand and did not zero the new
alias ones, so every counter assertion read stack garbage while the positive
paths still passed -- the counter witness rows are what caught it; (2) the
alias-term edit rewrote `aot_as_usage` and silently dropped its refusal for an
address space with no heap window, so GetInfo 7/22 stopped failing closed and
reported a plausible budget for a space that can never have a heap. The
`aot_g3_start_hle_budget` "missing heap window" row caught that regression the
first time the full suite ran.

Included in this decision (later increments of the same gate): SVC 0x2c/0x2d
dispatch through `g3_start_hle_svc_alias`, the alias term of the GetInfo 7/22
budget in the HLE, and `aot_g3_start_hle_alias` (Result-code ABI, register
preservation, guest read/write state, QueryMemory runs, host page witness,
pool/budget interaction, fail-closed contexts) with four mutants rejected by
exact first failure (limit code, register clobber, unmap bookkeeping, budget
term).

Not in this decision: Mac's moved-stack rules. The 4096-entry table and the
map-side stack/alias overlap check belong to `stack_move` (`services.c`
100-116), while `alias_map` only has the unmap-side source-range overlap check
(`services.c:135`); SVC 0x04/0x05 are not implemented, so that invariant is
asserted, not faked. Mac's `TOTK_PROBE_NEGATIVE==14` hook that swaps 0x10801 for
0xd401 (`services.c:131-132`) is a probe switch inside the reference, not a
guest-visible rule; the port returns the default 0x10801.

## D020 — Immutable RomFS provider is an authorized early G4 prerequisite

**Status:** Candidate (implemented and probe-verified in an isolated worktree;
NOT integrated; G3 remains OPEN)

The user explicitly authorized this narrow Windows counterpart of Mac
`services.c:175 -> runtime_fs_init -> romfs.c:169-191` **only** to unblock a
faithful real G3 constructor witness. It is early G4 work, not a
reclassification of the filesystem into G3 and not permission for G4 generally.
The G3 exit condition is unchanged; no `Start`/boot/translator wiring is part of
this decision.

`src/romfs_provider.{h,c}` is an owning, immutable resource provider whose public
header stays Windows-free. `src/romfs_file_win.{h,c}` is the only Win32
file/path seam: UTF-8 to absolute extended-length (`\?\`) paths, read-only
handles with `FILE_SHARE_READ` only, positional reads, and canonical final-handle
containment checked with an ordinal case-insensitive component compare. The
provider never touches the environment, never derives an expected digest from
candidate bytes and never handles a guest virtual address; `Start` wiring and
profile resolution belong to the caller.

Init is transactional: the index, image/parts, overlays and host handles are
staged privately and published READY only after every size/hash/layout/overlay
check. Any failure releases all staged state, leaves the caller-visible provider
EMPTY and returns a typed status plus stable stage/detail diagnostics. A repeated
init on READY is idempotent (Mac's `image_fd>=0` guard), keeps its snapshot and
clears stale diagnostic text. Destruction consumes the provider and releases
every host handle/buffer; bounded reads may run concurrently because each uses an
explicit offset. Public read failures are uniformly `ROMFS_PROVIDER_ERR_READ`
with the actual prefix count, including the original-image branch.

The contract preserves Mac's meaningful behavior: monolithic `romfs.bin` first,
otherwise consecutive `.000`... parts (<=64) with equal sizes except a smaller
last part and a checked sum equal to the pinned image size; every part must be
present, non-empty and free of gaps; only actual not-found falls back from a
missing monolithic file. The full image and index are ALWAYS hashed against
pinned digests (Mac proof-cache records and the optional mmap accelerator are
deliberately not ported), files are re-identity-checked after hashing, and a
pre-existing writer conflicts with the provider's sharing mode. Index bounds,
NUL/ordering rules and overlay original/replacement hashes, sizes, duplicates and
unknown names follow the reference, with Windows-specific overlay name rejects
(traversal, backslash, ADS/drive, reserved device, trailing slash/dot/space) and
root containment for both manifests and replacement files.

Supported-profile bounds are explicit: index `<128 MiB` and file count
`<1,000,000` are Mac's EXCLUSIVE tests; 64 parts, 16 overlays and 2 overlay roots
are capacities. The 1 MiB whole-manifest cap with <8 KiB lines is a NEW defensive
profile restriction, not a Mac limit (Mac uses `fgets()` without a whole-file
cap); it is documented in `docs/romfs-provider.md` rather than presented as
parity. Empty/blank/comment-only manifests are valid zero-overlay manifests.

A separate, tiny translated adapter now exists at
`tests/aot/g4_romfs_start_hle.{h,c}` for ONLY the
`_ZN2nn2fs24InitializeForApplicationEv` HOSTCALL body. It borrows an owning
provider and an EXPLICIT `romfs_provider_config`, creates nothing itself, and
calls the real `romfs_provider_init()` only when the HOSTCALL is invoked (never
before `Start` runs). Success is Mac's void body: no guest register/flag/byte,
no host pointer and no guest Result is written. Failure sets typed
`AOT_FAULT_BAD_HLE` with `req.site_pc`/`req.resume_pc` and a documented negative
status (`-100 - provider_status`; `-95..-98` for guest-state/context/kind/
config), leaves the guest state untouched and the provider EMPTY. A NULL guest
state is a typed host-ABI fault before any initialization, never a void success.
The index contract allows ZERO files (`strings_offset == 24` plus padding), so
READY alone is the readiness authority; the adapter does not invent a nonzero
file-count predicate. The generic G3 override table still refuses the FS name;
only an explicit generated profile binds the adapter, so an unconfigured run
keeps the original pre-G4 BAD_HLE stop.

Profile resolution is host tooling, not provider logic:
`tools/aot/g4_romfs_config.py` parses the external `romfs_config.h` as DATA
(no `#include`/C execution), requires exactly the three known macros, pins
`ROMFS_IMAGE_SIZE`/`ROMFS_IMAGE_SHA256` to the repo's genuine v1.0.0 expected
JSON, and re-emits a generated C literal with fixed octal UTF-8 escapes OUTSIDE
the source tree. G4 stays disabled unless `--romfs-config` is explicit, even if
unrelated `TOTK_*` variables exist. Optional/required overlay roots are selected
separately; `TOTK_ROMFS_PATCHES=0` disables the optional default. The default
profile is native/headless (`TOTK_OUTPUT_RES=0`): Mac's graphics resolution
patch auto-selection is not ported. `TOTK_OUTPUT_RES` is VALIDATED even when a
required root is supplied - only `0`, `auto` or canonical `WxH` in
640x360..7680x4320 - and merely recorded; a nonzero/`auto` request is REFUSED
unless the caller supplies an explicit required overlay root
(`TOTK_ROMFS_PATCHES_OUT` likewise). It is never silently ignored and never
answered with a fabricated resolution. Explicit CLI options without an
explicit `--romfs-config` are errors, so the default stays disabled while
ambient `TOTK_*` variables alone neither enable nor fail. Every selected root
(CLI or ambient) is frozen to an absolute, resolved path against the CALLER's
cwd at resolution time. This is serialized-profile invariance (defensive
robustness if a caller cwd changes or the config is reused), NOT an observed
boot bug: the prefix driver's native child currently inherits its parent cwd.
The 4096-byte UTF-8 bound is checked on the frozen spelling. Explicit empty
CLI path overrides are errors, not fallthrough, and generated C paths are
limited to 4096 UTF-8 bytes (well below MSVC's literal limit).

Evidence: hermetic `tests/aot/g4_romfs_start_hle_probe.c` calls the real adapter
over the real provider with a PID-suffixed synthetic fixture and independently
pinned SHA constants. It checks provider-not-READY before HOSTCALL, exact
success counters/READY/read bytes with byte-identical guest+runtime state,
idempotent second HOSTCALL, a valid ZERO-entry index reaching READY with 0
files, typed failure with exact site/resume/status and an EMPTY provider, retry
after failure, wrong-kind/missing-config/NULL-guest-state/missing-context
faults, an absent optional overlay, and a MISSING required overlay
(`ERR_OVERLAY_REQUIRED` -> documented negative fault, provider EMPTY).
`tests/aot/g4_romfs_config_test.py` is fully hermetic (no private absolute
user paths; the real profile is validated by the actual Start driver run) and
covers strict parse/reject cases, pinning, defaults, disabled mode (ambient
`TOTK_*` neither enables nor fails), explicit options without a config,
overlay selection, empty CLI paths, the 4096-byte emission bound,
`TOTK_OUTPUT_RES` validation/refusal with and without an explicit required
root, unsafe paths and octal emission. The same strict native
driver now takes `(mutant, exact first FAIL)` pairs; it rejects a void body that
clobbers x0 and one that skips real init, while the two original provider hash
controls remain. All adapter/provider rows are plain C or stdlib Python and the
native rows build in AOT_OFF; no Python is required by the AOT_OFF CMake path.

Evidence: hermetic `tests/romfs_provider_probe.c` (external fixtures,
independently pinned SHA constants) covers mono/split/cross-part reads, 64-part
routing, READY idempotence, full-prefix gap, missing/empty/unequal/extra/65th
parts, layout/digest failures, overlay success and each failure class,
empty/comment manifests, optional-vs-unusable manifests, long Unicode (>260)
resource and overlay paths, pre-existing/live writer conflict, handle release
and EMPTY-after-failure; `tests/romfs_provider_mutant_driver.c` requires the real
probe exit 0/PASS and exactly the two compiled hash-skip mutants at exit 2 with
their exact first semantic failures. Fixtures live under a per-process
(PID-suffixed) external directory, so the probe and the mutant driver's real
child can run concurrently; Debug and Release `/W4 /WX` CTest pass, including
`ctest -j2 -R '^romfs_provider' --repeat until-fail:3` in both configs. Existing
G1/G2/G3 rows are unchanged. Separately, a lead-run independent real-data
validation on a frozen snapshot initialized the external 17 GB image to READY
(304,207 files) and matched a >4 GiB-offset read against an independent stdio
read; that evidence is not a claim about this candidate worktree and did not run
boot/adapter code.

Limitations/OPEN: no guest file handles, mounts, directory enumeration, save
data, IPC or general filesystem behavior; no proof cache, mmap read path or
streaming manifest parser; the adapter has NOT been exercised by a real `Start`
run (the lead owns that after review), and no boot checkpoint is claimed. The
AOT_OFF tests do not exercise the opt-in AOT_ON 68-test/46-mutant suite. This
decision does not close G3, alter its exit condition or mark G4 complete. The verification above is the AOT_OFF build
(`MN_BUILD_AOT_PROOF=OFF`); the opt-in AOT_ON 68-test/46-mutant suite was not
rebuilt in this narrow phase, and no existing AOT/G1/G2/G3 source or test row
was modified by it (the provider rows are additive and not gated on AOT).

## D021 — Narrow offline veneer root inside G3 (Start-prefix follow seam)

**Status:** Candidate (proof frozen; wiring implemented and hermetically tested
in an isolated worktree; NOT integrated; G3 remains OPEN)

The primary and an independent high-specialist review authorized exactly one
additional root category INSIDE G3, not a new subsystem and not new G4 work. It
exists because a compiler thunk has no dynsym of its own: for the observed
`Start` blocker the exact-DEFINED-`STT_FUNC` rule fails by construction (the
value is an ADRP+ADD materialization in already-reached original code and the
thunk's tail is the defined symbol), while a relocation value alone proves
nothing. Treating "nearest FDE", any FDE span, an arbitrary materialized value,
a mid-function address or a recursive root as a root would be a far weaker,
unbounded claim.

The accepted proof is a conjunction, and refusal is final: an adjacent ADRP+ADD
pair in the approved reached map (actual ADD bit 22 clear) materializes the
observed value; `0..3` exact `MOV Xd,Xm` (x0..x15 only) then exactly one
unconditional `B` to a tail that the UNCHANGED exact-DEFINED-`STT_FUNC` rule
justifies; no sized defined symbol and no relocation SITE may cover the span;
the prior word must terminate; and the value must be an EXACT initial location
in the module's `.eh_frame_hdr`, discovered only through MOD0 relative offsets
under the single supported `011b033b` header. That EH check is a mandatory extra
guard for this category, deliberately NOT a general unwind parser and NOT an
FDE-root category (no nearest-start or interior inference). The pre-G4 `nnMain`
guard wins before any proof; `tools/aot/g3_veneer_roots.py` freezes the original
bytes and the dependent metadata (mismatched flat SHA, incomplete descriptor or
unpaired relocation tags raise `InputError`); and everything is offline: no
runtime decode/JIT, no guest-state, owner or memory patch, no fabricated
symbol/binding.

`tools/aot/g3_start_prefix.py` keeps its old `justified()` and symbol-follow
behaviour and consults the prover only after that lookup fails for an
`AOT_FAULT_UNTRANSLATED` target whose ORIGINAL fault-site word is an indirect
`BR`/`BLR` inside known TEXT. A success adds only the observed value, labelled
`veneer:<tail symbol>`, prints `FOLLOW_VENEER` (distinct from `FOLLOW`), and
writes its full evidence as JSON under `--work` only, referenced from
`result.json`; a refusal keeps the old `UNJUSTIFIED` fail-closed path and adds
the specific proof reason. Before the rebuilt image is executed, the proof's
frozen flat SHA is bound to the compiled module metadata `source_sha256` (not
`provenance_sha256`) for the OWNER and for EVERY materialization producer module
(each record carries that module's immutable snapshot SHA; a missing module,
metadata or hash is a hard `DriverError`), so a proof over one snapshot cannot
describe code generated from another.

The old strict symbol `FOLLOW` gate and its line-level behaviour are unchanged, but
the new static batch scan now passes `stop_entries={nnmain}`, so the BATCH seed set
may be SMALLER than before (any fallout still uses the old strict follow at
runtime). `R.scan_world(..., stop_entries=None)` is the default and preserves the
results of every other analyzer byte-for-byte. This barrier fences the exact
`nnMain` entry, fallthrough into it, and the continuation of a KNOWN direct
`BL`/constant `BLR` into it. It is a static-reach over-approximation, not an
executed path proof: a wrapper or PLT stub that calls a stopped callee can still
retain its own post-call continuation, so this is NOT a claim of full
interprocedural post-`nnMain` exclusion.

The current actual producer does not depend on that limit: with a SINGLE approved
observer root validated externally (no Start, DT_INIT or other root), the pruned
scan still reaches the materializing words and the veneer proof succeeds for the
observed value; the external evidence log is
`mn-g3-local/w8-independent-observer-proof.log` and contains the concrete VAs and
hashes, which stay out of this repository. The root category is unchanged: still
the compound proof above, not FDE-only, not an arbitrary RVA, with no policy
relaxation.

Evidence: the hermetic proof suite (170 checks) and the extended prefix suite
pass, and both are registered as AOT_ON CTests (74 total); no game data is used
by either. The lead's full Debug and Release regressions pass, and the frozen
real `Start` rerun passes the veneer before stopping at the next unsupported
instruction; detailed evidence remains external. Limitations: this is offline
code-generation root selection only. No DT_INIT completion, 10700-slot witness
or graphics backend decision follows from it. The G3 exit condition and status
board are unchanged.

## D022 (candidate) - local switch edges are proven site edges, never roots

Status: candidate, Phase B wiring in review; not a completed exit condition.

Module-mode translation may add CFG edges ONLY for BR sites that
`tools/aot/g3_local_switch.Context.discover` proves over the currently
reached, raw-re-decoded graph. `build_cfg` gained a private `local_edges`
argument that appends those proven targets to an already-walked BR's
successors; it never seeds the initial work list (entries and the legacy
indirect targets remain the only seeds). A proven target that is already
visited still becomes a new basic-block start.

Caller-supplied `site_edges` are a CLAIM: the source must be a decoded BR and
a strict-shape window, and the final proof must reproduce the claimed target
set exactly; otherwise it is a typed InputError. A raw word that is not part
of the decoded graph but could be a direct PC-relative branch into the guard
window or the ADRP+ADD pair is a conservative refusal (negative-only threat
scan; it never decodes or seeds anything, and a literal DATA word in TEXT may
cause a conservative false refusal). EH-frame consumption is excluded as an
explicit RO-suffix over-approximation, and DT_INIT_ARRAY/DT_FINI_ARRAY are
paired, bounded consumed intervals.

`module_cfg` iterates to a fixpoint, forbids retraction or target-set change
of an accepted site, and marks proofs `verified-final-graph` only after the
final `discover` ran on the graph built from the final edge set. Codegen keeps
`AOT_EXIT_INDIRECT` on the valid path and adds an `AOT_FAULT_BAD_STATE`
membership assertion (exact site, target and status index) for any other
value. The runtime guard is not a substitute for the proof. The G2 path is
unchanged (new argument defaults to None).

Phase C1 refinements (candidate; corrective core/native review cleared, G3 OPEN):

* The incoming-branch check is two-stage and GRAPH-oriented (H1), not a
  numeric address interval. `Context.discover(..., defer_threats=True)` is
  the module pipeline's expansion phase ONLY: every raw, not-yet-decoded
  source that could be a direct branch into ANY decoded owner node is
  recorded as `deferred_threats` and the proof is marked `pending-expansion`
  (no UNKNOWN seed yet, so the derived case paths can decode). Once the
  derived case paths are decoded, `module_cfg` re-runs the public strict
  default (`defer_threats=False`) on the FINAL graph: it seeds the dataflow
  with UNKNOWN at every such owner node, requires the same site set and every
  target set to be identical, and refuses unless a later ADRP (and its paired
  ADD generation) re-establishes the table base. A DECODED instruction that
  branches into `B.HI`..`BR` is an immediate guard bypass refusal; ordinary
  pre-window nodes and the pair ADD are left to the graph dataflow and the
  explicit ADD jump-in check. This covers blocks numerically after the BR or
  before the pair and removes the old `[ADD, load)` order heuristic. Only
  strict final proofs may be marked `verified-final-graph`; the module
  CLI/`emit_c` path rejects any other proof.
* The runtime guard keeps `AOT_FAULT_BAD_STATE` and uses a reserved,
  disjoint negative `fault_status` namespace:
  `-0x4C530000 - (site_ordinal + 1)` with the ordinal over sorted BR PCs.
  `AOT_STATE_ERR_1..3` and the `AotMemStatus` values are untouched, no ABI or
  enum layout changes, and the value is recorded as `status` in every
  `local_switch_sites` metadata entry.
* H1-R: the strict proof explicitly refuses an UNDECODED raw branch into the
  post-CMP window (`B.HI`..`BR`), including the ADD/BR positions whose UNKNOWN
  seed could never propagate back to the load.  Other owner positions keep the
  graph UNKNOWN seed + later-ADRP regeneration rule; stage 1 only records.
* Native probe limits (honest): the C2 probe is a DEV probe, not a Program/
  AS-host-RO test: it direct-calls emitted basic blocks, sets `rt.reason` from
  the returned `AotExit` (no dispatcher), uses one N=5 fixture, and the wrong
  guard variants intentionally pass test-only `switch_sites` to `emit_c`.
  The raw DATA-bit threat index may conservatively false-refuse, and the EH
  frame exclusion is a RO-suffix over-approximation.
* Consumed-metadata geometry (M1): MOD0+16/+20 are signed offsets RELATIVE to
  MOD0 (not absolute image offsets); the RO-suffix over-approximation must
  cover the complete parsed EH interval. A PRESENT EH-frame header that is
  not fully inside the module's own RO segment is a typed `InputError`
  refusal, never a silent skip of the frame exclusion. DT_PREINIT_ARRAY/
  DT_PREINIT_ARRAYSZ are paired, bounded consumed intervals like the init/
  fini arrays.

## D023 (candidate) - same-module DT_INIT_ARRAY constructor roots (no STT_FUNC)

Status: scoping accepted by the user; validation PENDING (independent review,
native fixture, full Debug/Release regression and a real run are owned by the lead). Not a completed
exit condition and `PORTING_STATUS.md` is intentionally not updated.

Authority: `tools/aot/g3_ctor_roots.py`. A Start-prefix `AOT_FAULT_UNTRANSLATED`
target may be added as a root WITHOUT a defined STT_FUNC only when ALL hold:

* the fault site is the module's own ORIGINAL array-walk call, proven from raw
  words (`LDR Xr,[Xc],#8; BLR Xr; CMP Xc,Xb; B.LO` back to the LDR, operands
  cross-bound, no register overlap), the supplied owner bytes/base/TEXT equal
  the pinned flat SHA, and the loop is reached from the module's OWN DT_INIT
  by a bounded DT_INIT-local CFG (project `T.decode` for control flow; an undecodable word is the typed refusal `dt-init-undecodable`, budget 4096 words) (calls fall through only, callees never
  entered, caller-saved x0-x18/x30 killed, the walk stops at the loop LDR and
  any entry into the loop body elsewhere is refused). Forward dataflow over
  that CFG must show the CMP bound register holding a GOT word that relocates
  the declared array end and the cursor register one that relocates the start
  (ADRP+LDR, ORR moves; every unmodelled write kills the register, so
  information loss can only refuse). Paths leaving the 4096-word (0x4000-byte) budget end
  without proof;
* the owner's COMPLETE declared DT_INIT_ARRAY (from the original `.dynamic`,
  bounded, in RW data, 8-aligned) has exactly one DT_RELA R_AARCH64_RELATIVE
  sym-0 site per slot (no RELR/JMPREL/duplicate/overlap), the relocated image
  holds `base+addend`, and every target is a 4-byte-aligned, non-null,
  non-sentinel, same-module TEXT address that avoids the header/MOD0, every
  loader-consumed metadata extent (DT_HASH = 8+4*(nbucket+nchain)), relocation
  slot and defined non-FUNC storage;
* the supplied original bytes equal the pinned flat SHA, and the probe's live
  capture matches: cursor register == proven LDR base, `slot=cursor-8`
  (cursor==array_end is the last slot), the 8 live bytes read through the
  checked guest address space == target == snapshot, bound register value ==
  declared array end. The capture is mandatory.

Class membership is final: a refused class site never falls back to the old
STT_FUNC rule or D021; non-class sites keep the original rules. The pre-G4
nnMain filter runs first. Aliased/arbitrary BLR targets, cross-module targets
(not authorised until really needed) and eager seeding of the whole array
(`Authority.targets()` is audit-only) are out of scope. The original guest
DT_INIT loop stays in translated control; no host constructor loop or fake
return exists. ISA coverage of a demanded constructor remains a separate
typed-`unsupported` blocker. Probe: `STARTFAULTGPR` lines (all x0..x30,
`read_va=value-8`, checked-AS read) are emitted on UNTRANSLATED stops only.
The pinned array/authority objects are frozen (attribute writes fail, tuples/
read-only mappings) and the derived table digest is re-checked on every
`prove` (`authority-mutated`); the metadata context must match the image's
FULL layout (canonical JSON), not only segment extents. The evidence slot is
chosen by the live cursor index, never by the first slot with the same value.
Limits: owner flat SHA is pinned from the ORIGINAL world flat; binding to the
compiled `source_sha256` (runtime `*_real.flat`) is checked fail-closed before
execution and has NOT been exercised on the real set.

D023 binding (explicit; there is no published `ctor_arrays` metadata and none
is consulted): `bind_flat_sha(authority, metas, audits, meta_name)` takes the
in-memory frozen `Authority`, re-derives the table digest, and checks each
audit entry against the authority's own slot. The compiled metadata must have
`source_sha256` == the pinned flat SHA, `guest_base` == the pinned base, and
the admitted root among its `entries`; any missing field is a typed
`CtorInputError`. The live cursor/bound capture is a mandatory runtime
equality check ON TOP of the static CFG proof; it is never permission to relax
the DT_INIT reachability/provenance proof. Exclusion lookups use a per-module
interval index restricted to the TEXT window (targets are proven inside TEXT
first). Status: validation pending independent review; not Core-clear.

Class gate: `classify_site` requires the loop shape, EITHER DT_INIT_ARRAY or
DT_INIT_ARRAYSZ declared (even unpaired), a valid DT_INIT, and its own
DT_INIT-local CFG reaching the loop LDR. Only this classifier uses
`dt_init_cfg_proof(require_bounds=False)`: it must not depend on table or
bound validity, otherwise malformed constructor metadata could escape to the
old rules. No declared array / no DT_INIT / unreachable / budget / undecodable
means not the class; ordinary callback loops retain the old STT_FUNC and
D021 rules unchanged. A declared array entered mid-body is a final refusal.
The final admission still requires ALL strict checks above, including bound
RELAs, CFG/GOT provenance and live cursor. Malformed declared metadata is the
typed final refusal `ctor-metadata-invalid`; there is no shape-only intercept.

The metadata bind is MEMBERSHIP + source/layout binding over IN-PROCESS
audits; it does not re-prove the site or CFG, and `ctor_audit.json` is output
only, never input authority. `array_consistent` re-derives every slot's index,
VA, offset and target == base+addend; those values are also hashed, so a
rewritten digest or `object.__setattr__` tamper fails closed.

## D024 — Partial pivot to SavageWind-style module frontend and build; keep our runtime

**Status:** Accepted (direction). D007 and D008 remain Open.

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

Stage A evidence: our own fail-closed frontend `tools/aot/g3_fde_frontend.py` (written from the
.eh_frame specification, no SavageWind code) emits `authority: none` candidate manifests. Its hdr table and
linear walk agree exactly on 1.0.0: 242,860 / 10,061 / 31,238 FDEs, 0 known-DATA conflicts, and
10,700/10,700 D023-derived constructor targets on an FDE start (`aot_g3_fde_frontend_real`, opt-in). All real
CIEs use pcrel|sdata4, the only accepted FDE pointer encoding. Synthetic suite `aot_g3_fde_frontend`: typed
refusals for 16 malformed inputs, D006 output guard incl. case-changed and junction paths, two lax mutants
caught. Nothing consumes the manifest yet.

Stage B evidence (offline; no runtime, loader, Program or AotImage change): `tools/aot/g3_fde_emit.py`
builds a non-dispatchable catalog of FDE-window bodies (function-local CFG via the opt-in `restrict` of
`build_cfg`/`module_cfg`, our own `emit_insn`) and an authority step whose AotImage lists only the closure
of the admitted roots. Every closure block inside a window must match a catalog block exactly (start, end,
words, D022 target set from the admitted-graph proof), otherwise it fails closed. Candidate bodies use
disjoint status namespaces; equivalence is (fault kind, source PC, resolved PC). Hermetic
`aot_g3_fde_emit` (99 checks): through the real loader/AS/Program, the catalog+table build equals today's
build field by field for normal paths, STR to RO, RO->RW straddle, exclusive ABA and size mismatch,
unsupported word, and a BLR to a compiled-but-unadmitted body (`UNTRANSLATED`, body linked,
`aot_program_lookup` NULL). Unicorn is a third oracle where it models the path. A wrong authority step that
lists out-of-closure bodies is caught. Real 1.0.0 (`aot_g3_fde_emit_real`, opt-in) with the Start-prefix
roots (main 27, sdk 213): main `0x1520` 4/4 blocks and sdk `__nnmusl_init_dso` 173/173 blocks match, with 0
mismatches. The D022 switch `0x102008db10` has the same 6 unique targets in the catalog and the admitted
proof. The AotImage equals today's 338 / 3,431 closure starts. With `restrict` unused, the translator
output for those closures is byte-identical to the previous translator except the provenance hash line.
Not executed on real data: no existing real-exec harness accepts a catalog+table pair. No timing claim
(Stage C).

Stage C prerequisite (hash-bound verification): `table --verify-mode bound --receipt` checks a hash binding
(catalog identity, C and metadata hashes, flat, base, name, partial, tool hashes, selection) against a receipt
that only a successful `--verify-mode regenerate --write-receipt` run writes. Bound mode skips FDE
re-derivation and catalog regeneration, so it is a hash check, not a regeneration, and it is valid only for
the toolchain state that wrote the receipt. Pending Windows validation (`aot_g3_fde_emit` and the CTest
battery); the hermetic `aot_g3_fde_emit_receipt` covers only the Linux-side logic.

Consequences: G3 constructor progress is pursued by the frontend/build experiment (PORTING_PLAN Phase 2)
before any new root heuristic. No exit condition changes.
