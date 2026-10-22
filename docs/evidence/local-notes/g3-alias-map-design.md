# G3 alias physical mapping (SVC 0x2c/0x2d) — design under review

Status: DRAFT for independent review. Nothing integrated; main `windows-x86-port` untouched.

## Why now (real evidence, not speculation)

`mn-g3-local/start-w19-diag2/result.json` (faithful original SDK Start in the current `w19-2` worktree):

- 290 steps, then stop code 7, `svc #0x2c` at `sdk_real+0x1584cc` (`src=0x10201584cc`),
  `regs x0=0x5000000000 x1=0x1000 x2=0x1000000000 x3=0 x4=0x40000 x5=0x10`,
  `sp=0x200003ff50`, typed `AOT_FAULT_BAD_HLE` status 44 (no handler registered).
- The previous stop at 283 steps was GetInfo id 16; the GetInfo 16 handler added in this
  checkpoint moved the real guest 7 steps further. So this is the current FIRST native blocker.
- `sdk_real+0x1584cc` is the entire SDK wrapper:
  `svc #0x2c` / `ret` (verified by Capstone on `v0/link/sdk_real.flat`, image base
  `0x1020000000`, offset in text). There is no in-wrapper argument setup, and no
  ADRP/ADD or data reference to the wrapper anywhere in `.text`, so the caller's ABI is
  the x0/x1/x2 triple the guest passed.

## Mac reference (authoritative for this port)

`games/totk/runtime/services.c`:

- L118-150 `alias_map(int unmap, uint64_t addr, uint64_t size)` — the whole behaviour.
- L280 `case 0x2c: case 0x2d: { uint64_t a=r[0], n=r[1]; r[0]=alias_map(num==0x2d,a,n); ... }`
  → **addr = r0, size = r1; r2/r3 are ignored**; the only register written is r0.
- L264 GetInfo 7/22 = `runtime_image_bytes()+heap_size+alias_bytes`.
- L296-299 QueryMemory inside the alias window reports the run of equal occupancy:
  `base/size` of the run, `state = allocated ? 5 : 0`, `perm = allocated ? 3 : 0`, attr 0.
- L48-49 `SYSTEM_RESOURCE_BUDGET (32ULL<<20)`, `HEAP_CAP (4ULL<<30)`; `APP_POOL` = `app_pool()`
  (0xcd500000 in the faithful profile).
- L40 `alias_pages[ALIAS_SIZE_MAX/4096]` + `alias_stale[...]`: two byte tables.
- L136-147 the unmap/map state machine (see the contract table below).

Mac `alias_map` result codes (returned in r0, a normal ERR result, not a host fault):

| condition | Mac code |
| --- | --- |
| `size == 0` or `(addr|size) & 4095` | `0xcc01` |
| `addr < start` or `size > ALIAS_SIZE` or `addr-start > ALIAS_SIZE-size` | `0xdc01` |
| map only: `fresh+alias+heap+image > APP_POOL` | `0x10801` (LimitReached) |
| unmap only: range overlaps a moved-stack source map | `0xdc01` |
| success | `0` |

Host failures in Mac are `runtime_fail` (process abort), not guest results.

## Guest-visible contract this port must preserve

Per 4 KiB page inside the AS alias reserved window, with occupancy `M` (mapped), `S` (stale)
and `C` (host-committed):

| operation | effect |
| --- | --- |
| map page already `M` | untouched (contents preserved), not counted in `fresh` |
| map page `!M`, `!C` (never mapped) | committed, reads zero, becomes `M`+`C` |
| map page `!M`, `C`, `S` | zero-filled, becomes `M`+`C`, `S` cleared |
| map page `!M`, `C`, `!S` | retained contents, becomes `M` (host protected RW) |
| unmap page `M` | becomes `!M`, `S` set, host protected NONE (content not preserved for a later map) |
| unmap, 16 KiB group fully `!M` | host pages decommitted (`C` cleared), `S` cleared for all 4 |
| budget | `fresh` (newly mapped bytes) + alias mapped bytes + heap logical size + pinned image bytes must not exceed the pool, else `0x10801` |

The union of these rules is the observable Mac behaviour: a page that was mapped, unmapped and
mapped again reads as zero; a page mapped twice without an unmap keeps its contents.

Deliberate, documented divergences (both are stricter, neither is relied on by the guest):

1. Mac leaves released pages of a partially-unmapped 16 KiB group host-readable (its
   `mprotect RW` covers group-aligned ranges). This port keeps every unmapped alias page
   `no-access` in the AS and refuses guest access with `AOT_MEM_ERR_PERM`, matching the AS
   QueryMemory answer (`Free`/`perm 0`) instead of exposing retained host bytes.
2. Mac's decommit uses `mmap(MAP_FIXED)` over a group; this port decommits the individually
   committed pages of that group through `host_vm_decommit`. Guest-visible result is the same
   (all four unmapped pages read zero after a later map, `S` cleared).

## AS API (new, in `src/aot/aot_as.h`)

```c
/* Mac services.c alias_map(): map pool pages into the alias reserved window. */
AotMemStatus aot_as_alias_map(AotAddressSpace *as, uint64_t addr, uint64_t size,
                              uint64_t pinned_bytes, uint64_t pool,
                              uint64_t *out_fresh);
AotMemStatus aot_as_alias_unmap(AotAddressSpace *as, uint64_t addr, uint64_t size,
                                uint64_t *out_released);
/* Coherent (heap_size, alias mapped bytes) snapshot for GetInfo 7/22. */
typedef struct AotAsUsage { uint64_t heap_size; uint64_t alias_bytes; } AotAsUsage;
AotMemStatus aot_as_usage(const AotAddressSpace *as, AotAsUsage *out);
/* Coherent alias geometry + mapped-byte counter (diagnostics/tests). */
typedef struct AotAsAliasInfo { uint64_t base, size, mapped_bytes, mapped_pages; } AotAsAliasInfo;
AotMemStatus aot_as_alias_info(const AotAddressSpace *as, AotAsAliasInfo *out);
```

Statuses (`AOT_MEM_ERR_LIMIT` appended to the enum so no existing value changes):

| AS status | cause | HLE result |
| --- | --- | --- |
| `AOT_MEM_OK` | success | `r0 = 0` |
| `AOT_MEM_ERR_ALIGN` | `size==0` or unaligned | `r0 = 0xcc01` |
| `AOT_MEM_ERR_RANGE` | outside the alias window, no alias window, unsealed/poisoned, desync | `r0 = 0xdc01` for geometry; **typed BAD_HLE** for lifecycle/desync |
| `AOT_MEM_ERR_LIMIT` | over APP_POOL | `r0 = 0x10801` |
| `AOT_MEM_ERR_HOST` | host commit/decommit/protect failure | typed `AOT_FAULT_BAD_HLE`, no register write |

Lifecycle split: Mac has no "unsealed space" state, and a poisoned space must never be used, so
those are typed faults rather than invented Metric answers. This is the same rule the existing
GetInfo/SetHeapSize/QueryMemory handlers already follow.

## AS internals

- `AotAsRegion` gains `uint8_t *alias_page` (one byte per 4 KiB page, bits
  `ALIAS_MAPPED`/`ALIAS_STALE`/`ALIAS_COMMITTED`) and `uint64_t alias_bytes`; allocated in
  `aot_as_add_reserved_window` only for role `ALIAS`, freed in `aot_as_destroy`.
  Memory: 16 MiB for the 64 GiB boot window (same order as Mac's static table).
- `as_page_permits()` for the alias window consults `M` (RW when mapped, NONE otherwise).
  `aot_as_host_page()` returns the reservation page pointer only when `M` (unmapped stays NULL).
- `as_query_locked()` for the alias window returns the run of equal `M` with state
  `AOT_AS_STATE_HEAP`(5)/RW or `0`/NONE, matching Mac L296-299; the STACK role keeps its current
  whole-window Free answer.
- Rollback: host calls for a map/unmap are applied per page; the software table is only
  published after every host call in the phase succeeded, and earlier host changes are reverted
  in reverse order. A failed rollback sets a sticky `alias_desync` flag that makes every later
  alias operation fail closed with `AOT_MEM_ERR_HOST` (same protocol as `heap_desync`).
  The unmap decommit phase runs after the unmapped state is published, like Mac (which aborts
  the process on failure): a decommit failure is a typed host fault that stops the run, never a
  silently ignored error.
- The Mac "UnmapPhysicalMemory must not overlap a moved-stack source" check is vacuous here:
  SVC 0x04/0x05 (`map_move_memory`) are not implemented, so the AS has no stack-map table.
  The invariant is asserted in the code comment and covered by the design, not by a fake check.

## HLE

- `g3_start_hle_svc2c()` handles both `0x2c` and `0x2d` (`req->id`), Mac register ABI
  (`x0=addr`, `x1=size`, x2/x3 ignored), r0-only result, success leaves x1..x30 untouched.
- Requires `ctx->as` and `ctx->budget`; a missing budget is a host misconfiguration → typed
  `G3_START_HLE_FAULT_ALIAS_MAP (-13)`, never an invented pool.
- GetInfo 7/22 switches from `image + heap` to `image + heap + alias_bytes` using
  `aot_as_usage()` (one lock, coherent), with the existing fail-closed pool gating preserved
  and overflow-checked.
- Counters: `svc2c_calls/success/invalid/limit/failures`, `svc2d_calls/success/invalid/failures`,
  `alias_desync` visible through the AS status only.

## Test plan (narrow, with negative controls)

1. `aot_as_alias_probe` (extend): geometry/validation rows (`0xcc01`, `0xdc01`), budget
   (`0x10801`) with a real pool, map preserves already-mapped contents, unmap→map reads zero,
   QueryMemory runs around mapped/unmapped neighbours, `aot_as_read/write` succeed only on
   mapped pages, host RESERVE witness for unmapped pages and COMMIT+RW for mapped ones,
   `alias_desync` fail-closed path (fault seam), heap grow/shrink leaves alias alone.
2. `aot_g3_start_hle_probe` (extend): SVC 0x2c/0x2d rows — success register contract
   (only x0 written), `0xcc01`/`0xdc01`/`0x10801` guest results, NULL-AS and NULL-budget typed
   faults, desync typed fault, wrong-id fault, and GetInfo 7/22 including alias bytes.
3. Mutant controls (compiled wrong implementations that the probe must reject):
   `alias_map_ignore_budget`, `alias_map_zero_fresh` (rebudget mapped pages), `alias_map_keep_stale`
   (skip zero-fill), `alias_unmap_keep_mapped`, `alias_query_whole_window`,
   `alias_usage_omit_alias`.
4. `aot_g3_start_probe`: register both SVCs, print `ALIASSTATE` counters, and re-run the
   faithful prefix (`tools/aot/g3_start_prefix.py`) to record the next real blocker.
5. Full `ctest` Debug+Release in the lead build dir.

## Open questions for the reviewer

1. Is `r1 = size` really the guest ABI here (versus `r1 = phys`, `r2 = size`)? Evidence above is
   the wrapper body, the absence of any other reference, the Mac implementation that TOTK runs
   on, and the fact that `r2 = 0x1000000000` would be a 64 GiB mapping that Mac would reject as
   LimitReached. A second independent check (Atmosphere `svcMapPhysicalMemory` signature vs. this
   SDK wrapper) is welcome.
2. Should the unmap path really keep the "no stack map" overlap check out (vacuous) instead of a
   typed unsupported fault? My position: a vacuous check is truthful; a fake failure would
   regress the real guest.
3. Is "unmapped alias page refuses guest access" acceptable as a documented divergence, given
   Mac's host-readable leak?
