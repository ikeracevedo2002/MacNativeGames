# G3 execution witness blocked at real filesystem initialization

## Decision boundary — no implementation authorized or performed

The user explicitly required stopping BEFORE implementing `nn::fs::InitializeForApplication` or another real filesystem/runtime-state service. The lead has stopped the faithful Start path at this boundary. FS remains unregistered; no fabricated success, Result, TotK-specific data answer, skip-SDK-init, or patched guest state was introduced. G3 remains OPEN. Nothing committed, integrated or pushed.

Current override candidate: `C:/Users/IKER/.pi/agent/harness/worktrees/MacNativeGames-106250b2/w33`. Baseline preserved in `w19-2`. Main checkout remains untouched.

## Measured callsite and state (not a prediction)

Lead-run original Start, offline-generated native AMD64 AOT, `/W4 /WX /O2`:

- Final artifacts after the alias correction: `C:/Users/IKER/mn-g3-local/start-w33-final/{result.json,run_start.log,build_start.log}`; driver log `start-w33-final.log`. Initial measured run `start-w33-overrides/` is preserved and stops at exactly the same boundary. Final Debug/Release full CTest is 68/68 each, runtime mutants46 rejected/infra0 each; see `w33-final-validation.md`.
- Driver exit **0** means **typed blocker captured**, NOT successful Start/G3 closure.
- **400 dispatched AOT basic blocks**, NOT 400 individual ARM instructions. Earlier descriptions that called `steps` instruction counts were inaccurate: the runtime increments it per translated block.
- Fault `AOT_FAULT_BAD_HLE = 7`, status **28**, image `sdk_real`.
- Caller `nninitInitializeSdkModule` at `0x10200fa000`.
- Actual guest import call: `0x10200fa01c: bl 0x10205c2fe0`.
- PLT: `0x10205c2fe0 adrp x16,0x1020d07000`; `...fe4 ldr x17,[x16,#0xa70]`; `...fe8 add x16,x16,#0xa70`; **`0x10205c2fec br x17`**.
- GOT `0x1020d07a70`; native post-call observation `x17=0x7f000001c0`, exactly `thunk_base + 28*16`.
- Symbol `_ZN2nn2fs24InitializeForApplicationEv` bound to thunk **28** by the real link config/JMPREL; handler explicitly absent after Program finalize (`OVRCHECK fs_registered=0`).
- Fault source **`0x10205c2fec`**; fault target **`0x10200fa020` is captured x30/resume**, NOT the host-thunk target.
- Post-call observed registers: `x0=0x1020d25440`, `x1=0x5000000030`, `x2=0x5000000000`, `x3=0x5000000ff0`, `x4=x5=x7=0`, `x6=0x1020d254d8`; `SP=x29=0x200003ffb0`, `x16=0x1020d07a70`, `x30=0x10200fa020`, `NZCV=0x60000000`, `FPCR=FPSR=0`, `TPIDR=0`, `TPIDRRO=0x3000002000`. Diagnostic `depth=0` is AFTER host-call fault unwinding; not original nested depth at thunk entry. This is not a complete all-register/memory dump.
- `nnosInitialize` returned successfully; real ThreadType owner **0x1001**, TLR+0x1f8 **0x1020d25100**, dummy owner still 0.
- `ready_calls=1`; **`inits_calls=0`, `finis_calls=0`**. `nninitInitializeSdkModule` has NOT returned. No constructors or nnMain executed in this witness.
- New overrides actually called once each: OE Initialize, AOC Initialize, ERR InitializeContextWriterApi. AOC Count/List, PCTL Initialize and DIAG AbortObserver counters remain zero.
- Heap logical size **0**; alias first page committed/RW/mapped, tail reserved. Existing SVC0x2c succeeded once. No new FS runtime state is created by the unregistered fault.

Offline, exact-image callsite evidence: `g3-fs-callsite-evidence.txt` (Capstone disassembly + JMPREL symbol association). SDK flat SHA256 `0e573a9f8407e63456baf0632e48a005b0c9ddeee13ec4e69d68af4cfe227d96`. All game-derived evidence remains external.

## What Mac actually does

Sources in the candidate/baseline are identical:

- `games/totk/runtime/services.c:175,239`: the override is **void** `host_fs_init() { runtime_fs_init(); }`.
- `games/totk/runtime/romfs.c:169-191`: actual initializer. This is NOT an empty SDK marker.

On its first invocation it:

1. Resolves `TOTK_ROMFS` or the existing version-selected default directory.
2. Opens `runtime-index.bin`, checks its size, validates its pinned SHA256, maps it read-only, checks magic/header and every entry's image bounds, name bounds/NUL termination and strict sorted order (`romfs.c:171-179`).
3. Opens `romfs.bin` or split image parts and checks expected total size (`:108-116,180-182`).
4. Validates the image SHA256, or reuses a prior full verification record only under the checked file-identity/metadata policy (`:67-141`). `TOTK_ROMFS_VERIFY=full` forces full hashing. Split proofs have their own metadata rules; do not copy a monolithic-file rule blindly.
5. May write/replace a verification-proof record, using temporary-file creation, flush and rename; `TOTK_ROMFS_PROOF_DIR` can redirect it. Thus the service is not host-read-only merely because game resource reads are read-only.
6. Optionally maps the whole image read-only; failure falls back to positional reads (`:183-187`).
7. Loads configured/default overlays, validating manifest paths, file size, SHA256 of both original resource ranges and replacements; requires the resolution-dependent overlay when that profile calls for it (`:143-168`).
8. Reports progress/readiness (`:188-190`).

`need()` calls `runtime_fail()` on invalid/missing data (`romfs.c:57`): fatal startup failure, not an invented guest Result. The idempotency guard is `image_fd>=0` (`:170`); it relies on process abort if later validation fails, not on a recoverable partially initialized provider. A future Windows port must not accidentally treat partial failure as READY.

## State and real effects

Host-side persistent state: mapped index (`index_bytes`, `index_size`, `file_count`, `strings_offset`), image descriptor and optional image map, split descriptors/count/chunk size, validated overlay descriptors/index/size table (`romfs.c:15-49`). These back later `runtime_romfs_open/read/size/close/entry_type` calls (`:205-236`) and routing in `fs_host.c`.

The initializer does NOT set the mount name: `MountRom` does that separately (`romfs.c:198`). Handle tables/locks/counters exist statically; this call does not allocate a guest FS handle or return a guest object. Save/temp/cache setup is separate lazy `fs_host.c:65-83` work, not secretly part of this initializer.

Externally observable effects include host file opens/mappings, optional proof-record writes, validation failure timing and boot-progress/log callbacks. There is no explicit guest-memory output and no defined integer Result for this **void** API. An unspecified caller-saved x0 on native Mac is not C undefined behavior and does not justify inventing a Result.

## What the guest concretely needs next

Verified immediate continuation (not extrapolated from an API name):

- `0x10200fa020 mov w0,#1`; `...024 bl SetLocalApplicationAccessLog`.
- `...028 bl pctl::Initialize`; `...02c mov w0,#1`; `...030 bl SetResultHandledByApplication`.
- `...034` restores frame, `...038` tail-branches to DIAG AbortObserver initializer.

There is **no immediate test of an FS return code**, nor a direct guest load from FS state: x0 is overwritten immediately. That does NOT make FS initialization optional. Mac has already verified/published its real host resource provider before this continuation can run.

Start then calls `nninitStartup`, `_init_libc2`, and reaches `0x10200fa0ac blr x20` (the `module_inits` callback) only AFTER the SDK initializer returns. This is why the missing real service blocks the chosen faithful G3 constructor witness. We have NOT executed beyond this FS call, proven the first later guest file read, or established all constructor filesystem dependencies. Static disassembly alone is not such a proof.

## Legitimate minimum G3 vs beginning G4

**G3 now:** verified symbol binding, thunk identity and translated ABI, captured resume, deterministic typed refusal without handler side effects, and a documented execution boundary. Existing hermetic fixture constructor/callback tests remain valid but cannot replace the outstanding real all-constructor witness. Source-level/offline resource-contract research can inform the next milestone without claiming FS works.

**G4:** actual external resource-provider lifecycle, Windows open/read/file mapping, integrity checks, overlay activation, file identity/proof cache and readiness/failure policy; later mounts/reads and save operations. Even a read-only subset has real runtime state. It is not loader/linker work just because Start invokes it early.

There is no evidence-backed smaller *successful* implementation of this particular Mac call that both omits resource initialization and preserves its effects/failure timing.

## Options and recommendation

1. **Keep the boundary (recommended under current authorization).** Leave FS unregistered; retain this measured dependency; G3 stays OPEN. Continue independent translation/proof preparation only if useful, without declaring the faithful constructor gate closed.
2. **Explicitly authorize a narrow G4 prerequisite to the G3 witness.** Implement a real, validated read-only RomFS provider/initializer with Windows host seams, preserving exact input/hash/overlay and fatal-failure behavior. No graphics, IPC generalization or saves are inherently required by this call. Test valid fixtures plus corrupt index/image/overlay, missing files, failure-before-READY and retry policy, callback/ABI preservation and real readiness consumers. Confirm supported input profiles and proof-cache policy first; do not silently drop split-image or configured-overlay behavior. This is the correct path to resume faithful Start if the user authorizes crossing that boundary.
3. **Investigate shared initialization before entering Start.** A fully initialized provider could potentially be shared by host startup and the thunk's idempotent ensure-ready operation. This still requires the real G4 provider and evidence that shifting initialization earlier preserves relevant failure/side-effect ordering. Not an implementation-free G3 shortcut.

**Rejected:** return success/zero; make FS a no-op; defer validation until MountRom merely to advance the boot; bypass `nninitInitializeSdkModule`; substitute guessed title-specific handles or answers. `MountRom` also calls `runtime_fs_init()` lazily, but that does not justify changing the first validation/failure point. A defined Result is not required by the translated ABI for a void call.

No FS implementation or G3/G4 scope decision was made. The next user decision is whether to keep this boundary or explicitly authorize option 2.
