# Active provider review queue — w39

Source baseline w33, writer w39. User authorizes only early G4 init prerequisite; no integration/G3 exit change.

## Lead source findings already sent to writer

- Align sync OVERLAPPED positional-read docs; no asynchronous rewrite needed. MS Learn ReadFile explicitly permits synchronous handle + OVERLAPPED offset, returns only after completion. FILE_SHARE_READ sharing is reciprocal: existing GENERIC_WRITE handles conflict too. Haiku retracted contrary claims; x64-only rules eliminate 32-bit size_t truncation concern.
- Private host read bounds/overflow guard; exclusive index/count caps match Mac.
- Final path containment actual Windows ordinal casing, long absolute Unicode paths extended-prefix support (>260 test); no logical-index case normalization. Final-path buffer result conservatively checked; source currently being fixed.
- Parts: checked sum, gap detection through .064, reject extra65th, fallback only actual missing monolithic image; never silently treat invalid/nonregular input as absence.
- Optional manifest: ignore ONLY not-found, not permissions/nonregular/alloc errors. Empty manifest is valid zero-overlays (Mac accepts it).

## Haiku second review findings to triage AFTER current task settles

1. Public `romfs_provider_read` original-image branch returns internal ERR_IMAGE_READ whereas header/overlay branch use ERR_READ for host IO. Normalize public status; preserve actual prefix count.
2. `image_read_at` chunk>=part_count must return error with actual prefix, not break-to-OK (currently validation makes it unreachable but fail-closed helper contract).
3. Overlay relative name ending '/' should be rejected explicitly (component loop currently accepts); logical index names unchanged unless overlay selected.
4. Check manifest handle containment under root before reading, like replacements. It is a private staged open, so no need expand the public interface.
5. Clear stale diag.detail on successful READY publish/idempotent init (optional missing manifest currently leaves misleading missing-file text).
6. Document MAX_INDEX/MAX_FILES constants are EXCLUSIVE, any 1MiB manifest cap is a defensive supported-profile restriction vs unbounded Mac comment lines, not an exact Mac limit. Decide whether remove cap via safe streaming or explicitly record restriction; do not silently pretend parity.
7. Ensure real tests for long Unicode path, already-open writer conflict, and any fixed error cases; real positive/2 hash mutants green Debug+Release before claiming complete.

Not genuine blockers from prior review: const parameter preference; private open-before-containment valid IF check precedes read/hash/publish; constant named MAX doesn't prove off-by-one (actual >= comparisons are correct); optional caching/proof records/whole-image mmap need not be ported to preserve full verification.

Real input is ready externally C:/Users/IKER/mn-g3-local/v0/romfs-init, all6 IVFC and repo-pinned image hash match, index generated per Mac format. No game data copied into source. Boot not yet wired. Full details in handoff/brief.
