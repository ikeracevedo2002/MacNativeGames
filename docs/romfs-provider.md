# Immutable RomFS resource provider (early G4 prerequisite)

Status: candidate, implemented and probe-verified in an isolated worktree only.
It is **not integrated**, nothing is wired to `Start`, and **G3 remains OPEN**
with its original exit condition unchanged. See D020 in `DECISIONS.md`.

This module is the Windows counterpart of the Mac `runtime_fs_init` path
(`games/totk/runtime/romfs.c:169-191` -> `src/romfs_provider.{h,c}`). It exists
only because the user explicitly authorized the smallest prerequisite that lets
a later real G3 constructor witness run; it does not reclassify the filesystem
into G3 and does not implement G4 generally.

## Scope

In scope:

- open, fully verify and RETAIN a read-only resource index plus a monolithic or
  split resource image;
- validate up to 16 overlay replacements from up to two caller-supplied roots;
- expose a tiny host-only consumer seam (`find`, `entry`, `effective_size`,
  `is_overlaid`, bounded `read`) proving the retained state works.

Out of scope: guest file handles, mounts, directory APIs, save data, account,
IPC, graphics/audio/input, environment/profile discovery, proof-cache files,
whole-image mmap accelerators, and any guest virtual address. The provider
never dereferences a guest pointer and never returns one.

## Configuration

Configuration is explicit (`romfs_provider_config`): resource directory, pinned
index SHA-256, pinned image size and SHA-256, up to two overlay directories and
an optional/required flag per root. The core provider reads no environment and
never derives an expected digest from candidate bytes; resolving a local
profile belongs to boot tooling.

Paths are UTF-8. The private Win32 seam (`src/romfs_file_win.{h,c}`) converts
them to absolute extended-length (`\\?\`) paths, so paths longer than `MAX_PATH`
and non-ASCII names work without a second path implementation. Logical index
and manifest names are never normalized or rewritten.

## Verification contract

- **Always full verify.** This is Mac's forced-full path. Mac's proof-cache
  records are neither trusted nor written, and the optional whole-image mmap
  read accelerator is not ported. Those omissions remove startup accelerators,
  never an integrity or readiness guarantee.
- Index: size in `[24, 128 MiB)` (upper bound EXCLUSIVE, matching Mac's
  `st_size < 128*1024*1024`), SHA-256 equals the pinned digest, LE header magic
  `TOTKRFS1`, `file_count < 1000000` (EXCLUSIVE), `strings_offset == 24 +
  file_count*24` and inside the index. Every row is bounds-checked by
  subtraction against the pinned image size and the string extent; names are at
  least 2 bytes, exactly NUL terminated at `len-1`, have no embedded NUL, and
  are strictly increasing/unique.
- Image selection follows the Mac order: monolithic `romfs.bin` first. If it is
  absent, consecutive `romfs.bin.000` ... up to 64 parts. In both cases parts
  must be non-empty, equal-sized except the last (which may not be larger), and
  their checked sum must equal the pinned size. A missing middle, an extra 65th
  part, an over-size sum, a gap and an empty part all fail. Only actual
  not-found triggers the parts fallback: a present-but-unusable `romfs.bin`
  (directory, sharing refusal) is an error, never permission to read different
  files.
- The full image SHA-256 must match the pinned digest. Files are opened
  read-only with `FILE_SHARE_READ` only, so ordinary Win32 opens cannot replace
  or delete verified bytes while the provider lives. Sharing is reciprocal: a
  writer that already held the file makes init fail closed. After hashing, the
  opened files' volume/file identity, size and last-write time are re-checked
  and a change is `ROMFS_PROVIDER_ERR_IMAGE_CHANGED`.
- Overlays: an absent optional manifest means originals; an absent required
  manifest fails. Only not-found is tolerated for an optional root: a manifest
  that exists but is not a readable regular file fails. Empty, blank and
  comment-only manifests are valid zero-overlay manifests, as in Mac. Each
  manifest line is `name<TAB>size<TAB>replacement-sha<TAB>original-sha`; a
  malformed line, a fifth trailing tab field, an embedded NUL, unknown index
  name, duplicate replacement, wrong original
  range hash, wrong replacement size/hash or missing file fails. Overlay names
  must be safe relative Windows names (no absolute path, drive, ADS, backslash,
  traversal, trailing slash/dot/space or reserved DOS device name), and both the
  manifest and each replacement must resolve beneath their configured root
  after reparse points are resolved. Containment is a STRICT descendant: a
  resolved path equal to, or shorter than, the configured root is a path
  escape (checked before the ordinal prefix compare, so no read past the
  terminator of a shorter resolved target).

## Lifecycle and reads

Init is transactional. All handles/index/overlays are staged privately; the
provider becomes READY only after every check succeeds. Any failure releases the
staged state, leaves the caller-visible provider EMPTY, and reports a typed
status plus a stable stage and human-readable detail. A failed init publishes no
file count and supports no reads. A successful init (and a repeated init on a
READY provider, Mac's `image_fd>=0` guard) reports `ready` and clears stale
diagnostic detail; repeated init never changes the snapshot.

`romfs_provider_destroy` consumes the provider and releases every retained host
handle and owned buffer. There is no concurrent init/destroy. Once READY the
provider is immutable and bounded positional reads may be issued concurrently;
each read uses an explicit offset, so no shared file pointer is involved.

`romfs_provider_read` clamps to the effective file end. A read at EOF yields
zero bytes, a read crossing EOF yields the short prefix, and `offset > size` is
`ROMFS_PROVIDER_ERR_RANGE`. A host read failure returns the public
`ROMFS_PROVIDER_ERR_READ` in both the overlay and original-image branches, with
`*out_read` holding the actual prefix and the destination holding only that
prefix. Internal part routing fails closed if a request ever lands past the last
part even though index validation normally makes that unreachable.

## Supported-profile limits (not Mac limits)

These bounds keep this narrow increment small and testable:

- index bytes `< 128 MiB` and file count `< 1,000,000` are Mac's own EXCLUSIVE
  tests;
- 64 parts and 16 overlays are inclusive capacities;
- 2 overlay roots;
- the whole overlay manifest is read into memory and capped at 1 MiB with lines
  shorter than 8 KiB. Mac reads the manifest with `fgets()` and has no whole-file
  cap, so this is a **defensive supported-profile restriction, not Mac parity**.
  Real manifests are a few hundred bytes. A bounded streaming parser is future
  work if an input outside this profile is ever required.

## Early-G4 Start adapter

`tests/aot/g4_romfs_start_hle.{h,c}` is a tiny `AotProgHandler` for only the FS
`InitializeForApplication` HOSTCALL. It borrows an owning provider and an
EXPLICIT config; the real `romfs_provider_init()` is called at HOSTCALL
invocation time, never during registration or before `Start` runs. The handler
does not inspect the opaque thunk ordinal. Success is the Mac void body: no
guest register, flag, byte or Result is written. Failure sets typed
`AOT_FAULT_BAD_HLE` at `req.site_pc`/`req.resume_pc` with a negative host status
and leaves the guest state and provider EMPTY. The provider stays READY after
success and is destroyed when the guest run ends.

The generic G3 override table continues to classify the FS name as
not-modelled and refuses it. Only an explicit generated profile adds the
BY-NAME binding. `aot_g3_start_probe` asserts after finalize that the handler is
absent with no profile and present with one, and prints `G4FSSTATE` counters and
provider diagnostics. A no-profile run keeps the old pre-G4 BAD_HLE boundary.

`tools/aot/g4_romfs_config.py` treats the external `romfs_config.h` as data,
not C: it accepts exactly the three known `#define`s, rejects includes, unknown
or duplicate macros and malformed values, and pins size/image SHA to
`games/totk/assets/expected-v1.0.0.json`. It then emits a generated C config
literal with fixed octal UTF-8 escapes under `--work`. G4 remains disabled
unless `--romfs-config` is supplied, even in a shell with unrelated `TOTK_*`
variables. `--romfs-dir`, optional/required overlay flags, and
`TOTK_ROMFS_PATCHES=0` select the local profile. The default profile is
native/headless (`TOTK_OUTPUT_RES=0`): Mac's graphics resolution patch
auto-selection is not ported. `TOTK_OUTPUT_RES` is therefore VALIDATED even
when a required root is supplied — only `0`, `auto` or a canonical `WxH`
inside the Mac range 640x360..7680x4320 is accepted — and the chosen value is
recorded, never translated into a fabricated resolution answer. A nonzero/
`auto` request is refused unless the caller passes an explicit
required overlay root, `TOTK_ROMFS_PATCHES_OUT` likewise. Explicit CLI options
without an explicit `--romfs-config` are errors (the default stays disabled),
ambient `TOTK_*` alone neither enables nor fails. Every selected root is
frozen absolute (resolved against the caller's cwd) before emission, so a
serialized profile does not depend on the consuming process's cwd — defensive
invariance, not a known misresolution. Explicit
empty CLI paths are errors, not fallthrough,
and generated C paths are capped at 4096 UTF-8 bytes on the frozen spelling. No title ordinal and no
digest from candidate bytes is accepted.

## Evidence

`tests/romfs_provider_probe.c` is hermetic, game-data-free and writes all
fixtures under an external build directory. Its fixture roots include the
process id, so the probe and the mutant driver's real child can run under
`ctest -j2` without sharing files or live handles. Fixture digests are independently
pinned constants checked at startup. Rows cover valid mono/split images,
cross-part reads, 64-part routing, READY idempotence, missing/gap/full-prefix
gap/empty/unequal/extra/65th parts, bad digests and layout, overlay success and
every failure class, empty/comment manifests, optional-vs-unusable manifests,
long Unicode (>260) resource and overlay paths, writer conflicts, handle
release, and EMPTY-after-failure. `tests/romfs_provider_mutant_driver.c` runs the
real probe first (exit 0/PASS) then the two compiled hash-skip mutants, each of
which must exit exactly 2 with its exact first semantic failure. Infrastructure
failures are exit 1 and never counted as rejections. `ctest -j2 -R
'^romfs_provider' --repeat until-fail:3` passes in Debug and Release.

`tests/aot/g4_romfs_start_hle_probe.c` exercises the adapter over a tiny
synthetic provider fixture (PID-suffixed, pinned SHA constants). It checks that
the provider is not READY before HOSTCALL, success counters/READY/read bytes and
byte-identical guest+runtime state, an idempotent second HOSTCALL, a valid
zero-entry index reaching READY with 0 files, the exact typed failure
(site/resume/status) with an EMPTY provider, successful retry,
wrong-kind/NULL-guest-state/missing-config/missing-context faults, and an
absent optional overlay. The same strict native driver now takes `(mutant,
exact first FAIL)` pairs. It rejects a void body that clobbers `x0` and one that
skips real init; the two provider hash controls still exit exactly 2.
`tests/aot/g4_romfs_config_test.py` runs without game data and covers strict
parsing, pin mismatches, disabled mode, overlay selection, empty CLI paths,
the 4096-byte emission bound, `TOTK_OUTPUT_RES` refusal with and without an
explicit required root, unsafe paths, UTF-8 octal emission, and the prepared v0
header metadata (without hashing the image).

Not covered here: a direct probe of a manifest symlink escape (the implementation
checks it before reading; the replacement-file junction row covers the same
containment seam), guest-facing FS/IPC semantics, mounts/directories, save data,
profile discovery, the real 17 GB image run, or any real `Start`/boot run. The
adapter's real-config path is compiled and its state machine is probed, but the
lead owns the first real `Start` witness.
