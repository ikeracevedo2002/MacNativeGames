# Authorized narrow G4 prerequisite — implementation brief

## User authorization / unchanged gate

User explicitly authorizes a correct Windows counterpart of Mac `services.c:175 -> runtime_fs_init -> romfs.c:169-191`, solely to unblock faithful real G3 constructor validation. This is EARLY G4 WORK, NOT filesystem reclassified into G3. G3 stays OPEN and its original all-real-DT_INIT exit condition is unchanged. No commits/integration until explicit `Integra`.

Source baseline is current **w33**: `C:/Users/IKER/.pi/agent/harness/worktrees/MacNativeGames-106250b2/w33`. All prior increments uncommitted there. Main checkout clean at d3b45204. User data/build outputs stay outside any source tree.

## Scope and exclusions

Implement only immutable real RomFS resource-provider initialization/lifetime and a tiny host-consumer interface proving the retained state works. No saves, account, filesystem IPC, guest file handles, mounts, directory API, graphics/audio/input, generic Horizon runtime. Do NOT port neighboring fs_host.c functionality. Later broad subsystem blockers must be brought to user.

## Read before implementation

AGENTS.md, GOAL.md, DECISIONS.md, ARCHITECTURE.md, PORTING_PLAN.md, PORTING_STATUS.md in order, then Mac `games/totk/runtime/romfs.c:1-244`, `services.c:167-177,237-240`, `romfs_path.h`, `games/totk/scripts/prepare_romfs_backend.py`. Existing analysis `C:/Users/IKER/mn-g3-local/g3-fs-initialization-boundary.md`; earlier prohibition there is SUPERSEDED only by this narrow user authorization, not by permission for G4 generally. Preserve Mac sources.

## Lead design decisions (document as candidate D020)

1. Small owning provider module, e.g. `src/romfs_provider.{h,c}`. Header Windows-free; isolate Win32 file/path primitives in private `src/romfs_file_win.{h,c}` if useful rather than spreading platform conditionals. Shared parsing/integrity/state logic plain C. Reuse `src/aot/aot_sha256.{h,c}` (already audited FIPS180 pure streaming C); do not rewrite cryptography or link interpreter/runtime.
2. EXPLICIT configuration (caller supplies resource directory, pinned expected image size/SHA256 and index SHA256, up to two overlay directories and optional/required policy). Provider does not silently inspect unrelated environment or derive its expected hash from candidate bytes. Resolve environment/local profile in boot tooling, not the core provider. Paths UTF-8 converted to Win32 wide paths safely. Expected config eventually comes from existing external romfs_config.h/verified extraction metadata; lead inventories data separately.
3. ALWAYS FULL VERIFY, equivalent to Mac's force-full path. Do not implement or trust Mac proof-cache records on Windows. No proof-file writes in this first increment. This omits an optional startup accelerator, not any integrity/readiness guarantee; record explicitly. Optional whole-image mmap is not necessary; retained file handles + bounded positional reads are real provider state. Index may be a private immutable owned copy instead of a file mapping, provided lifetime/bounds/hash guaranteed.
4. Transactional init: stage all handles/index/tables in a private temporary state; publish READY only after ALL size/hash/layout/overlay validation succeeds. On ANY failure close/free everything staged, leave caller-visible provider EMPTY, with structured status/stage diagnostics. Never set image_fd-like readiness early. Mac failures are fatal; provider returns typed errors for testability, and translated adapter later turns them into fatal typed AOT fault, never a fabricated Result. Destruction/close consumes state and permits explicitly documented reuse. Repeated initialization of READY provider is idempotent like Mac guard and must not destroy/change its snapshot. No concurrent init/close; document read ownership/concurrency.
5. Retain regular read-only image/part/overlay handles for lifetime, open with Windows sharing that denies writers/deletion (FILE_SHARE_READ only) so verified bytes cannot be replaced via normal Win32 operations after checking. Reject non-disk files/directories. Source selection like Mac: monolithic `romfs.bin` first; if absent, consecutive `.000` through max64 parts, nonempty, equal size except last, checked sum EXACT expected image size. Missing middle/too many/inconsistent sizes fail. Reads/hashes must traverse part boundaries correctly and detect short/error reads.
6. No pointer identity games: provider's pointers/handles strictly HOST objects. Tiny host-only metadata/find/read-entry or bounded read-range interface is allowed to prove retained provider works; not a guest filesystem API. No direct guest VA dereference anywhere.
7. Image/index and overlay validation MUST match reference meaningful contract, with safe malformed-input checks (bounded memchr before string use, checked sums/ranges, no out-of-bounds strlen). See detailed list below.
8. Overlays: up to16 total; optional base manifest absent => originals (Mac behavior); required extra overlay missing => failure. If manifest present, malformed/missing/inconsistent entries FAIL, never silently ignore. Validate original image range SHA and replacement size/SHA, path must exist in sorted index exactly once and no duplicate replacements across layers. Retain handles and host consumer must observe effective overlay bytes. Existing relative-path validator rejects traversal/backslashes but Windows adds ADS/drive/reserved-name/trailing-dot/space ambiguity: reject unsafe Windows relative paths, do not normalize to another resource. Check resolved file remains beneath configured overlay root (e.g. canonical final-handle path containment) so parent reparse/junction cannot escape. Do not import/output-resolution/graphics subsystem: caller supplies optional required second overlay root for an already chosen profile.

## Exact index contract

Index `runtime-index.bin` >=24 and <128 MiB, SHA256 equals pinned index digest. LE header magic `TOTKRFS1`, u64 file_count<1000000, u64 strings_offset==24+file_count*24 and strings_offset<index_size. Rows LE `{u64 offset,size; u32 name_offset,name_len}`. Each file fits expected image size using subtraction bounds; name offset/length fit string extent, len>1, terminal NUL exactly at len-1, no embedded NUL; names strictly lexicographically increasing, unique. Reject invalid arithmetic/header before dereference. Optionally tighten impossible host-overlay names when overlay selected, not arbitrary logical RomFS names unless documented.

## Hermetic validation / controls

All fixtures under external build directory/temp dir, never inside source. Tiny synthetic binary index + image with independently known SHA fixtures (Python hashlib generation recommended) and optional parts/overlays. Tests cover:
- valid mono and split, cross-part reads, metadata/effective bytes, READY idempotence;
- missing image/index/part; wrong sizes, gaps, extra parts policy; invalid layout/magic/order/duplicate names/embedded NUL/out-of-range offsets/counts; bad index/image digest; same-size changed image;
- overlays valid, optional absent, required absent, missing replacement, wrong original/replacement hash/size, duplicate, unknown index path, traversal/ADS and reparse escape;
- EMPTY after every failure (including late overlay failure), no half-published info/readable state; retry with correct input works;
- cleanup releases handles/mappings (delete/rename files after close/failure, repeated cycles; real Windows handle-count witness if practical); input cannot be written/replaced while provider live;
- bounded read invalid/overflow offsets and no fabricated success/partially reported outputs; document any partial host destination semantics on IO failure;
- compiled wrong implementations at least SKIP_INDEX_HASH and SKIP_IMAGE_HASH rejected by intended rows (not setup failure); add other control if it improves actual state-publication proof. Reals exit0 PASS; semantic mutants exit2 exact first FAIL; infrastructure exit1/FATAL. No WILL_FAIL catchalls, no weakened tests/flags.

CMake test/library available without TotK; `/W4 /WX` Debug and Release (/O2 stays on), normal no-game tests remain hermetic. Existing 68 tests and46 runtime mutants must remain unchanged/passing.

## Deliverable for FIRST bounded task

Implement provider + game-free native probe/fixture generation + explicit negative controls/CMake registration + short docs/D020 candidate. DO NOT yet wire Start, run game boot, or alter translator/HLE/AS code; lead will delegate followup after review. STOP settled after provider's narrow Debug/Release positive and negative tests. If too large for watchdog, deliver stable first code/test checkpoint with exact limits, no fake completion.

Use new build dir `C:/Users/IKER/mn-g3-local/build-g4-romfs`; CMake/CTest from `C:/Program Files/Microsoft Visual Studio/18/Community/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/`. Read `build-w34/CMakeCache.txt` for existing options, but source must point to your own successor worktree. All artifacts external. Prefer precise edit for existing files, preserve CRLF there; new files consistent. No git commit/reset/checkout, no source game artifacts, no broad rewrite. Report concise changed files, contract choices, commands/exits, failure/negative counts, remaining limitations; do not paste giant inherited HEAD diff.
