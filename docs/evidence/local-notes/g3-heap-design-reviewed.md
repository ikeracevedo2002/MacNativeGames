# Reviewed G3 boot heap design — lead decision brief

Status: design accepted for implementation/testing in an isolated worktree; NOT integrated, G3 OPEN. Extends the heap-policy portion left open by accepted D014; does not reopen validated loader/linking. Record D018 in candidate after implementation is verified. User #1 authorizes minimum HLE directly needed for DT_INIT; only integration requires `Integra`.

## Actual evidence and scope

Latest candidate w5-4, base d3b45204. Real original five-argument nn::init::Start runs native AMD64. Two GetInfo(11) entropy requests completed using BCrypt system-preferred RNG; next actual request is GetInfo(4), svc #0x29 at sdk+0x1584b0, code7/status4 after54blocks. Raw inputs x0=0x200003fe78 x1=4 x2=0xffff8001 x3=0. No callbacks/ctors yet on this faithful route. Earlier isolated-main experiment executed15 ctors and reached16th MVN; it is NOT faithful boot completion. Native logs v0/start-w5-4-hle2 and v0/start-w5-4-repair2. Original v0/link and v0/img stay read-only.

No structural C-backend blocker (D008 provisional for G3). No general Horizon/G4, graphics, nnMain, Abort stub, fabricated owner, interpreter/JIT. NNMain remains an unregistered hostcall boundary; driver must not auto-follow its real function either.

## Authoritative semantics

Mac games/totk/runtime/services.c258-279: GetInfo casts r1 to unsigned32; id4 heap base, id5 HEAP_CAP4GiB, r0=0/r1=value; ignores r2/r3. NEVER dereference raw x0 for GetInfo: the guest wrapper stores r1 through its saved out pointer. Unknown ids abort -> explicit typed failure here, not invented success.

Mac services.c310-313 SetHeapSize: requests 2MiB-multiple, <=HEAP_CAP, size+runtime_image_bytes <= APP_POOL; invalid => r0=0xd401 and other input regs unchanged. Success r0=0/r1=heap base. Host mprotect failure fatal. Shrink uses mprotect NONE, DOES NOT DECOMMIT. Regrowing prior pages PRESERVES BYTES; never-committed anonymous pages are zero. Do not adopt speculative Horizon zero-on-regrow semantics.

Guest heap [256GiB,260GiB) = [0x4000000000,0x4100000000), max4GiB. It is 2MiB-aligned, inside D014 [4GiB,512GiB), disjoint from module64/68/72GiB, stack128GiB, TLS192GiB, thunks508GiB. Core accepts parameterized geometry, no game-specific VAs in src/aot. Probe owns this scoped boot profile. Commit limit = checked APP_POOL(default0xcd500000)-sum pinned image sizes, not underflowing; logical used heap, NOT physical retained high-water, counts against budget. No alias policy invented.

## Deep module: AS is the only heap owner

Small shared interface in src/aot/aot_as.h, implementation private:
- add_heap_window(as, base, max, commit_limit): pre-seal only, at most one, reserve-only HostVm, NONE permission bytes. No host pointer output. Respect poisoned/full/overlap/error rollback rules of add_region.
- heap_info(as,...): read under domain lock; expose guest base/max/logical size. Keep high_water private if possible; tests can inspect HostVm through existing diagnostic seam.
- set_heap_size(as,size,&base): post-seal; typed invalid-request vs host-system-failure distinction. Do not shift existing enum numeric values.
- query_memory(as,addr,&info): coherent heap + ordinary page metadata and Free holes, no parallel HLE fake map. Legacy query behavior on ordinary regions/holes remains unchanged. For NEW heap kind, either provide truthful dynamic state5/0 also in legacy query or clearly reject unsupported legacy interpretation; do not silently return bogus Horizon sentinel state. Private locked query helper avoids recursive non-reentrant lock. New read-only whole-domain query may cover [0,2^39), lower unmappable hole Free; addr>=MAX unsupported. Extents positive and containing addr, clipped at heap prefix/window bounds and neighboring regions. Program thunks/sentinels require authoritative Program overlay only IF such queries are actually reached later.

Internally track heap_size=s and committed high_water=hw; committed set always [0,hw). Table:
[0,s): guest RW/Normal5, host COMMIT/RW.
[s,hw): guest NONE/Free0, host COMMIT/NONE (retained bytes).
[hw,max): guest NONE/Free0, host RESERVE.

## Serialized transition/failure protocol

All under the existing D013 memory domain lock, no guest callback/HLE dispatch while held. Host_vm calls do not call guest code.
- Validate size/cap/2MiB/commit_limit before mutations/output write.
- Same size: success, no memory or monitor change.
- Grow t>s: commit fresh F=[max(s,hw),t) if nonempty; then protect retained R=[s,min(t,hw)) RW if nonempty. host_vm_commit REJECTS already-committed pages (host_vm.h173-179/c323), so cannot recommit retained prefix. On fresh commit failure, no guest publication. On retained protect failure, rollback NEW F via decommit (never-published new zero pages only). If rollback fails, sticky heap_host_desync; all subsequent heap requests fail closed, guest table stays NONE. On success publish RW/state5, size=t, hw=max(hw,t). No previous reservation can exist on inaccessible growth pages.
- Shrink t<s: FIRST host_vm_protect([t,s),NONE) while lock held. On failure old guest map, bytes, size, hw, reservations unchanged. On success publish NONE/Free0 and size=t; invalidate affected monitors inside same critical section. hw unchanged. Never decommit published bytes.
- Existing aot_mem_domain_invalidate_all grabs lock, so cannot call it while already locked. Add a locked internal primitive (range or conservative all) preserving existing public behavior; clearing unrelated monitors spuriously is architecturally allowed.
- Host failures => typed BAD_HLE at HLE; invalid guest size =>0xd401; no success on resource failure. No output base written on failed core call.

## Existing AS operations audit (Opus sources checked)

add_region hands loader host pointer, loader.c474/482 memcpy; no write_initial function. New heap registration has no pointer output. aot_as_write/read and locked memory paths already permission-check before memcpy; NONE rejects before touching reserve. Ensure positive-length pre-seal write to heap returns ERR_PERM, no AV.
Seal skips reserve-only heap pages. protect/lock reject ALL heap-window spans, including mixed spans, before mutations. Counts-as-claimed in range_mapped prevents host thunks overlapping reservation. Destroy HostVm release frees mixed reserve/commit correctly. Poison/new registration rules unchanged.
Diagnostic aot_as_host_page: for heap return borrowed out_vm + out_offset (immutable), *out_page=NULL, including RESERVE/retained NONE; caller may use host_vm_query when no resize in progress. Do not read mutable hw without lock. This keeps inspection independent of AS ledger, no new debug interface. Ordinary module behavior unchanged.

## Narrow kernel adapter

Existing tests/aot/g3_start_hle is deliberately G3-scoped, not general kernel. Inject AS borrow/context. Info4/5 query real AS heap info, ignore r2/r3 as Mac. Register SVC0x01 before Program finalize if implementing SetHeapSize. QueryMemory0x06 only when actual trace needs it; if implemented, Mac has 40byte MemoryInfo through raw r0 and r1=0 pageinfo returned for guest wrapper; checked one-span guest write, not host pointer. No addresses for alias/ASLR/exception context invented. Stack state0xb can be registered with existing caller-defined AS state if actual query hits it.

## Tests, mutants, regression

Use actual public interface and host_vm_query diagnostic, private compile-time fault seams only (no mutable global production setters). Tiny test window e.g8MiB, live probe4GiB reserve-only.
- initial Host RESERVE/NONE, AS Free, read/write fail; overlap both add orders, pre/post seal, second window, poison, zero/misaligned/wrapping/out-of-range, cap/limit errors; end==2^39 VALID when no overlap, >MAX invalid.
- fresh2MiB zero/RW, grow4MiB old bytes retained/new zero, shrink leaves HostCOMMIT/NONE and Free, regrow old patterns retained; shrink0; logical size vs highwater budget.
- failure fresh commit unchanged; failure retained-protect after fresh commit rolls F back; failure shrink-protect old map/reservation unchanged; rollback failure sticky fail-closed.
- runtime/token A LDXR, successful host resize/shrink/regrow clears reservation => STXR fails even though bytes same; failed shrink leaves pending STXR valid. Calling HLE already clears its own token, so use OTHER token/runtime for non-vacuity.
- mutants SHRINK_DECOMMIT, PUBLISH_BEFORE_HOST, NO_MONITOR_INVALIDATE, RECOMMIT_RETAINED, HW_AS_USED, INFO5_REPORTS_SIZE rejected as controlled semantic failures, not setup crashes.
- HLE Info4/5 register-only, ignored r2/r3 as reference, invalid output pointer ignored, size errors preserve r1, unknown ids still fail; actual native Start advances beyondInfo4 with unchanged558865site link digest.
- all old G1/G2/G3 loader tests green. Last lead full49 acrossDebug/Release passed before two new backend/classification tests; latest narrow3 tests pass. Full configured test count is now~51, ask CTest rather than assume.

## Completion witness remains pending, separate from heap

For each module main,subsdk0,sdk original DT_INIT returns SUCCESS under D016 in same AS/process, SP/ABI/frame restored. Every relocated init_array slot must have ordered CALL at MODULE_BASE+0x148 and matching RET target MODULE_BASE+0x14c, no drops/extras; use unbounded witness not trace4096 prefix. Flag2 is written BEFORE loop, NEVER sufficient completion proof. Do not claim G3 CLOSED from Start clean return or nnMain boundary alone. Need all three ctor loops and memory/state evidence.

## Review provenance

Opus w7 architecture+final AS audit, corrected by lead on Mac retained bytes, r2/r3 ignored, flag-before-loop; all accepted. No fundamentally unresolvable decision; user authorized minimal constructor HLE, proceed with scoped D018 and independent post-implementation review. Haiku w8 reviewed RNG/helper/driver; repairs implemented in w5-4. No integration without user Integra.
