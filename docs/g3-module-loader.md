# G3 — translated module loader and linking (reference document)

This is the single reference page for milestone **G3**: loading, linking, sealing
and executing **AOT-translated ARM64 modules** on Windows x86-64. It describes
what the code does, which test proves each rule, and what is deliberately still
missing. Everything here is reproducible from the repository plus (for the
real-module checks) an external TotK 1.0.0 work directory.

Source of truth for behaviour: `src/aot/aot_loader.c`, `src/aot/aot_prog_assembly.c`,
`src/aot/aot_program.c`, `src/aot/aot_runtime.c`, `src/aot/aot_as.c`,
`src/aot/aot_loader.h`, `tools/aot/aot_module.py`, `tools/aot/aot_translate.py`.
Where this page and the code disagree, the code wins and this page is a bug.

## 1. Scope and status

**Gate verdict (lead, local): G3 OPEN.** Loader/linking, constructors and callbacks
through translated code, and the absence of hidden ARM64 execution are validated
(fixtures, plus the real 1.0.0 modules locally). The remaining G3 criterion, fully
translated main/subsdk0/sdk images whose real constructors run, needs a full-module
translator (D008). Decisions: D014-D017. Status board: PORTING_STATUS.md, G3 gate summary.


### What G3 proves

* A **multi-module** NSO-shaped image set (three modules, distinct guest bases,
  cross-module symbols, host overrides and observers) can be verified, mapped,
  relocated, sealed and turned into a runnable `AotProgram`.
* Relocation follows the **Mac loader's rules** exactly: RELATIVE/RELR,
  ABS64/GLOB_DAT/JUMP_SLOT, own-module-first-then-global search, first DEFINED
  symbol wins, unresolved weak imports resolve to 0+A, host thunks are assigned
  once per bound symbol name (observers apply to JUMP_SLOT only) and are stable
  across modules, and every rule is cross-checked
  against an independent Python reference linker (`aot_g3_link_reference`,
  `aot_g3_real_link`).
* Translated guest code of one module can call into another module, into a host
  thunk (a real guest ABI function), and back into the runtime through SVC and
  SYSREG paths, under nested host→guest calls and from several host threads.
* The **real TotK 1.0.0 modules** (main, subsdk0, sdk) link end to end: the C loader's
  relocation dump for all 558 865 sites is byte-identical to the reference
  linker's, and a real translated slice executes (see §5).
* G2 output is untouched: the single-image translation path is byte-identical
  (`aot_g2_gen_identity`, 16 files).

### What G3 does not prove

* **No full-module translation.** The translator decodes a subset of A64 (see
  §3 and §6); only reachable code from requested entries is translated. A
  transfer into untranslated code faults (`AOT_FAULT_UNTRANSLATED` /
  `AOT_FAULT_UNKNOWN_PC`) instead of falling back to an interpreter.
* **Real modules are only partially translated.** For the real-set execution
  test exactly two entries are translated: main's `GetSystemTick` PLT stub and
  sdk's `GetSystemTick` (`subsdk0` stays link-only). The real set is otherwise
  linked and sealed, not executed.
* **No game boot.** Nothing here boots TotK: no scheduler, no NVN/GPU work, no
  guest threads, no Horizon IPC. Guest threads in G3 means *host threads
  entering translated guest code*.
* **No performance claim.** The only optimisation done is the per-module symbol
  index (§2.8); everything else is written for verifiability.

## 2. Architecture

### 2.1 Guest address space

`src/aot/aot_as.c` owns the guest-visible address space: a region table plus
host mappings, with page protection, sealing and poisoning. Guest bases must be
4 KiB aligned and inside `[2^32, 2^39)`, which is why the translator rejects any
other `--guest-base` (§3). A space is one-way: `mapped → relocated → sealed`;
`poisoned` is terminal and only `aot_as_protect`'s own failed rollback or a
genuine loader stage failure may set it.

* `aot_as_is_sealed` / `aot_as_is_poisoned` read their flags **under the domain
  lock** — the same lock the writers take — so a caller never observes a torn
  or stale stage state.
* A bulk host access either applies fully or, if the rollback of a partially
  changed protection fails, `aot_as_protect` **poisons the space**: leaving the
  software table and the host pages disagreeing with no API to observe it is
  worse than failing closed.

### 2.2 Program and dispatch order

`src/aot/aot_prog_assembly.c` builds an `AotProgram` from a loader (or a bare
image list); `src/aot/aot_program.c` finalises and dispatches it.

* `aot_loader_build_program` requires `out->as == loader->as` and an **empty,
  unfinalized** Program (no images, ranges, regions or handlers), so a Program
  can never mix two module sets or two address spaces.
* Images are keyed by `(guest_base, text range)`; a call resolves the PC to the
  owning image, then to a block inside it. A link-only module has no image at
  all and never matches a range.
* `aot_program_finalize` and `aot_rt_init_program` require an unpoisoned space,
  so the residue of a failed load can never become runnable.
* Dispatch is: sticky fault check → owner-thread check → state validation →
  delegate to the owning runtime (`prog_hle`). The order matters and is tested
  in both directions (§4.2).
* A fault raised **inside** a handler is sticky: once `rt->fault` is set the
  runtime reports it even if the state check would also fail.

### 2.3 Thunks are guest functions

A host binding (override or observer) is reached through a **thunk VA** in a
reserved window (`thunk_base`, `sentinel`), not through a host pointer. The
thunk is real translated guest code with the guest calling convention, so:

* the value stored in a relocated slot is always a guest VA — the linker never
  leaks a host address into guest memory;
* thunk identity is global: the same (symbol, kind) gets the same thunk VA in
  every module (`aot_g3_link`'s `thunk_per_module` mutant is rejected by the
  dump digest);
* observers (address-taken slots, e.g. `nnMain`) receive the **real module VA**;
  only call sites get the thunk.

### 2.4 SYSREG and SVC

`MRS`/`MSR` of the handled system registers (`CNTPCT_EL0`, `TPIDR_EL0`, …) and
`SVC` are intercepted by the runtime through generated helper calls, not by
emulating trap state. The handler's effect must be visible as if it happened at
that instruction: the guest-visible tick strictly advances and the counters are
exact (`aot_g3_real_exec`: 4 host threads × 1000 entries = exactly 4000 handler
calls, per-thread `bad=0`, strictly increasing ticks).

### 2.5 Nested host→guest calls

Entering guest code from a host thread pushes an entry frame; a guest SVC/handler
may call back into guest code, so entry depth is tracked per thread. ABI state
(callee-saved registers, stack alignment, FP control) is saved/restored around
each nested entry. `MN_AOT_MUTANT_NO_SCRATCH_SAVE`, `NO_DEPTH_CHECK`,
`RESET_STEPS`, `NO_ABI_CHECK`, `RECALL_AFTER_FAULT` are all mutants of this area
and all are rejected by the runtime mutant driver.

### 2.6 Loader pipeline and link rules

`aot_loader_load` = verify → map → relocate → seal, each stage one-shot:

| stage | what it does |
| --- | --- |
| verify | MOD0 magic + offsets, pinned text/ro/data ranges, sizes and per-module SHA-256 (exact version) |
| map | maps each module's PT_LOAD-shaped ranges at `guest_base + off`, records regions |
| relocate | parses `.dynamic`/`.dynsym`/`.dynstr`/`.hash`, builds the symbol index, applies RELA/RELR/JMPREL, records every site, verifies the link digest |
| seal | drops every write permission, verifies the sealed data digest, marks the space sealed |

Link rules (all in `record_site`/the apply path of `aot_loader.c`):

* site must be 8-byte aligned and fit inside the module's data segment;
* a site may be written at most once (RELR/RELA overlap is `site written twice`);
* **a site may never overlap a table the loader consumes** — `.dynamic`,
  `.dynsym`, `.dynstr`, `.hash`, `.rela`, `.jmprel`, `.relr` (`DT_GNU_HASH` is
  not consumed by this loader, so it is deliberately absent). The ranges are
  registered per module in phase A, before any site is written; a hit is a typed
  `AOT_LOAD_ERR_RELOC` naming the table. The rule exists in both the C loader and
  the Python reference linker with the same message. `.dynamic` is the first
  object of the RW segment (like a real NSO), so this is reachable in practice.
* RELATIVE value = `guest_base + addend` and the addend must be inside the image;
  ABS64/GLOB_DAT/JUMP_SLOT value = `S + A` with `S` from the own-module-first,
  then global order; a JUMP_SLOT must have addend 0; an unresolved WEAK import
  resolves to 0; an unresolved strong import fails the load.

### 2.7 Image ↔ descriptor binding

Each descriptor pins name, `guest_base`, text/ro/data ranges, `bss_size`,
`dynsym_count`, image SHA-256, `init_va` and the expected **link digest**. The
binding is exact-version: a flat whose SHA-256 differs is rejected before any
mapping. Two one-fact-one-owner rules keep the descriptor and the image from
disagreeing:

* **DT_INIT**: `tags->has_init` and `desc->init_va != 0` must agree, and when
  present the value must be `guest_base + DT_INIT` — a descriptor may neither
  claim an initialiser the image cannot run nor drop one it declares.
* **Program shape**: see §2.2.

`aot_loader_set_link_only(loader, names, count)` names modules that have **no**
translated image. It is a list of names, not a boolean: a module with a NULL
image is accepted only if it was named, so a forgotten image still fails with
`invalid-argument` naming the module. A link-only module is still verified,
mapped, relocated, sealed and linkable — it just has no code, and any transfer
into it faults.

### 2.8 Symbol index

`aot_loader_relocate` parses and validates every module's `.dynsym`, then builds
one open-addressed name index per module (FNV-1a, capacity ≥ 2× dynsym, load
factor ≤ 0.5). Each slot keeps the FIRST name match and the FIRST DEFINED name
match, so resolution is exactly the Mac rule while the search is O(1). On the
real set this took `relocate` from ~45 s to **75.7 ms** for 558 865 sites with a
byte-identical dump.

### 2.9 Stage order is a precondition, not a load failure

`map`, `relocate` and `seal` are refused before their body runs when the stage
order is wrong or the space is poisoned (`stage_precheck`):

| call made again | detail |
| --- | --- |
| `map` over a sealed space | `mapping requires an UNSEALED address space` |
| any stage over a poisoned space | `the address space is poisoned by a failed load ...` |
| `map` twice | `already mapped` |
| `relocate` twice | `already relocated` |
| `seal` twice | `already sealed` |
| `relocate`/`seal` before `map` | `relocation requires a mapped loader` / `seal requires a relocated loader` |

Consequences that are tested, not assumed: a repeated stage returns a typed
`AOT_LOAD_ERR_STATE`, never touches guest bytes, and never poisons; and
`aot_loader_poison` is a **no-op on a sealed space**, because a sealed module's
data must never be zeroed.

## 3. Translator module mode

`tools/aot/aot_translate.py` has two modes. The single-image (G2) mode is
unchanged and byte-identical; `--module` selects the module path used by G3.

**Gating.** Module-only behaviour is decided by the global `MODULE_MODE`, set
only by `--module`. Nothing in the G2 path can observe it, which is what
`aot_g2_gen_identity` protects.

**Decoded forms** (module mode): the subset the decoder accepts is listed and
tested by `aot_g3_decoder_module`; it covers the common integer/FP ALU forms,
loads/stores with the addressing modes the subset allows, ADR/ADRP,
branch/branch-link, CBZ/CBNZ, RET/BR/BLR, SVC, MRS/MSR, and the pair forms
described below. Anything outside the subset is a fail-closed decode error, not
a silent skip.

**Single-access pair stores (MAJOR 1).** In module mode a 64-bit `STP` lowers to
**one** `aot_mem_st128(&rt->mem, addr, {Rt, Rt2})` and a 32-bit `STP` to **one**
`aot_mem_st64(addr, Rt | Rt2<<32)`. Before this change a page-straddling `STP`
could write the first element and then fault on the second, leaving a partially
written page — a guest-visible difference from a real store. The mutant
`stp_split` restores the old two-store lowering and is rejected because both of
these fail: the fault now reports the **pair base** address (not base+8) and a
faulting straddling `STP` writes **zero** bytes of the RW page.

**`--guest-base` validation (MINOR 8).** The base must be 4 KiB aligned and
inside `[0x100000000, 0x8000000000)`; anything else is a fail-closed
`DecodeError` naming the offending value (`guest-base-misaligned`,
`guest-base-below-window`, `guest-base-above-window` in `aot_g3_error_paths`).

## 4. Fixtures and validation

Fixtures are **assembler sources** (`tests/aot/g3/*.s`) linked with an NSO-shaped
linker script (`tests/aot/g3/nso.ld`): crt0 header + MOD0 + text in the R+X
segment, dynamic tables in the R segment, `.dynamic` first in the RW segment,
data then bss with no page padding. Three modules — `fx_main` @ `0x1000000000`,
`fx_sub` @ `0x1001000000`, `fx_sdk` @ `0x1002000000` — give cross-module
symbols, weak imports, observers and a shadow variant. Everything is generated
from those sources by `tools/aot/aot_module.py` (`nso2flat`, `link`, `emit-desc`,
`craft-negative`) driven by the `aot_g3_fixtures` rule in `CMakeLists.txt`; no
generated fixture is committed.

### 4.1 CTest targets (v0 build: 41 tests, 19 of them G3)

| test | what it asserts |
| --- | --- |
| `aot_g3_sha256` | SHA-256 against known vectors (the exact-version primitive). |
| `aot_g3_as` | address space: map/relocate/seal, protection, sealing, poisoning, rollback failure poisons. |
| `aot_g3_program` | Program shape, dispatch, sticky faults, owner-thread rule, nested entry. |
| `aot_g3_link` | loader link probe over all fixture variants: per-variant dump digest, stage re-entry refusal (data byte-identical after four refused calls), `init_va` both directions, link-only handling. |
| `aot_g3_exec` | execution probe: 15 translated scenarios + a page-straddling `STP` (fault status `AOT_MEM_ERR_PERM`, pair base address, zero bytes written) + nested/threaded entries. |
| `aot_g3_exec_oracle` | the same scenarios against an independent Unicorn oracle; every returned value and fault must match register-for-register. |
| `aot_g3_decoder_module` (`tests/aot/g3_decoder_module_test.py`) | the module-mode decode subset: accepted forms, plus the rejected ones with their reason. |
| `aot_g3_neg` | 16 crafted negative fixtures, each rejected with its declared status, module and **specific detail**. |
| `aot_g3_neg_details_control` | negative control for the probe: with the expected detail table rotated, the same probe must fail, so a pass means the details really are compared. |
| `aot_g3_link_reference` | the C loader's dump equals the Python reference linker's TSV (independent implementation). |
| `aot_g3_error_paths` | 7 fail-closed single-error cases (CLI/descriptor/translator, incl. the three `guest-base` cases and the identity guard). |
| `aot_g3_mac_bindings` | observer/override tables derived from the Mac sources match the C tables consumed by the loader. |
| `aot_g2_gen_identity` | 16 G2 generated files byte-identical apart from the two provenance lines. |
| `aot_g3_loader_mutants`, `aot_g3_runtime_mutants`, `aot_g3_exec_mutants` | mutant drivers (§4.3). |
| `aot_g3_real_link`, `aot_g3_real_exec`, `aot_g3_real_exec_neg` | local real-module checks (§5), registered only with `MN_TOTK_V0_DIR`. |

### 4.2 Behavioural details asserted by `aot_g3_program`

* Sticky fault wins: a handler that faults and then leaves `sp` misaligned must
  report the inner fault, not `BAD_STATE`.
* Owner-thread check comes first: a call from a foreign thread reports
  `BAD_STATE` and leaves the owner's fault untouched; the `program == NULL` path
  obeys the same order.
* A poisoned space cannot be finalised or initialised, while the same shape
  unpoisoned works.

### 4.3 Mutant drivers (all must be *rejected*)

| driver | mutants | result |
| --- | --- | --- |
| `aot_g3_exec_mutants` (`tools/aot/g3_exec_mutant_test.py`) | translator/assembly: `adrp_offset`, `orr_noshift`, `stp_split`, `init_array_walk`, `image_unbound` | 5/5 rejected, 0 survivors |
| `aot_g3_loader_mutants` (`tools/aot/g3_loader_mutant_test.py`) | link rules: `symbol_first_any`, `relative_no_base`, `abs64_no_addend`, `global_first`, `observer_all_kinds`, `trunc32`, `thunk_per_module`, `weak_strong_swap`, `jumpslot_addend_accept`, `no_dup_check`, `allow_table_overlap` | 11/11 rejected, 0 survivors, 0 wrong-check |
| `aot_g3_runtime_mutants` (`tools/aot/g3_mutant_test.py`) | address space + Program: `partial_store`, `no_perm`, `host_exec`, `thunk_site4`, `resume_after`, `no_depth_check`, `no_scratch_save`, `reset_steps`, `handler_before_resume_check`, `drop_sticky`, `no_abi_check`, `sysreg_xzr`, `recall_after_fault` | 13/13 rejected |
| G2/ABI drivers (`aot_mutant_negatives`, `aot_fp_translated_guardmut`, `aot_conc_control_*`) | staged G2 mutants | 12/12 rejected |

Every `MN_AOT_MUTANT_*` define in the tree is compiled by at least one target:
26 defines = 11 loader + 13 address-space/Program + 2 execution (`init_array_walk`,
`image_unbound`). The three translator mutants (`adrp_offset`, `orr_noshift`,
`stp_split`) are Python-level and need no define. A define with no target would be
dead wrong-code, so the loader set is asserted complete by the driver count above.

The drivers distinguish three outcomes: `rejected` (exit 2 with the expected
specific message), `SURVIVED` (the wrong implementation passed — the check is
vacuous) and `INFRA` (missing executable/timeout — the test did not run). A
survivor or an infrastructure failure fails the CTest.

## 5. Real-module local validation

Real data is **never** committed and never copied into the source tree. It lives
in an external work directory; CMake registers the real tests only when
`-DMN_TOTK_V0_DIR=<V0>` is set, so an absent work directory means "not
registered", never "skipped as passed".

### 5.1 One-time setup

```bash
PY=/path/to/python3      # needs lz4.block
W=<path-to-worktree>; V0=C:/Users/<you>/mn-g3-local/v0

"$PY" "$W/tools/aot/aot_module.py" nso2flat \
    --exefs "$V0/exefs" --out-dir "$V0/flat"          # main, subsdk0, sdk
"$PY" "$W/tools/aot/extract_mac_bindings.py" \
    --repo "$W" --out "$V0/bindings-mac.json"
"$PY" "$W/tools/aot/aot_real_link.py" config \
    --bindings "$V0/bindings-mac.json" --out "$V0/link"
"$PY" "$W/tools/aot/aot_module.py" link \
    --config "$V0/link/real_link_config.json" --dir "$V0/link" --variant real \
    --out-tsv "$V0/link/real_sites.tsv" \
    --out-counters "$V0/link/real_counters.json"

printf '["0x1002aa46e0"]\n' > "$V0/img/entries_main.json"
printf '["0x1020129640"]\n' > "$V0/img/entries_sdk.json"
"$PY" "$W/tools/aot/aot_translate.py" --module \
    --flat "$V0/flat/main.flat" --layout "$V0/flat/main.layout.json" \
    --guest-base 0x1000000000 --entries "$V0/img/entries_main.json" \
    --name real_main --out "$V0/img/real_main.c"
"$PY" "$W/tools/aot/aot_translate.py" --module \
    --flat "$V0/flat/sdk.flat" --layout "$V0/flat/sdk.layout.json" \
    --guest-base 0x1020000000 --entries "$V0/img/entries_sdk.json" \
    --name real_sdk --out "$V0/img/real_sdk.c"

printf '{"main_real": "aot_image_real_main", "sdk_real": "aot_image_real_sdk"}\n' \
    > "$V0/img/real_images.json"
"$PY" "$W/tools/aot/aot_module.py" emit-desc \
    --config "$V0/link/real_link_config.json" --dir "$V0/link" --variant real \
    --out-c "$V0/link/real_desc.c" --images "$V0/img/real_images.json"
```

`subsdk0` stays **link-only** (no image) because translating it is not needed to
prove the loader; the tests exercise exactly that state.

Running:

```bash
cmake -S "$W" -B build -G "Visual Studio 18 2026" -A x64 \
      -DMN_BUILD_AOT_PROOF=ON -DMN_TOTK_V0_DIR="$V0"
cmake --build build --config Debug
ctest --test-dir build -C Debug -R aot_g3_real -j 3
```

The build directory must be external; verify `CMAKE_HOME_DIRECTORY` points at
the worktree you are testing before trusting any result.

### 5.2 What each test asserts, with the measured numbers

**`aot_g3_real_link`** — the C loader verifies all three modules against their
pinned descriptors and their link digest, then its relocation dump must be
byte-identical to the reference linker's TSV.

* 558 865 sites (reference 558 866 incl. the TSV header line), `link_digest`
  `0d8d236c…`.
* Per module: main `relative=502345 symbolic=2091 cross=2079 weak=12`,
  subsdk0 `relative=1623 symbolic=17774 cross=6572 weak=4`,
  sdk `relative=10917 symbolic=24115 cross=10 weak=6`.
* Stage timing in a Debug build: verify 980.9 ms, map 966.7 ms,
  **relocate 75.7 ms**, seal 508.3 ms. Relocate was ~45 s before the symbol
  index.
* 43 980 symbolic sites resolve to 177 thunks (6 observers, 171 overrides);
  **213** sites hold a thunk value; **22** weak imports resolve to 0; **0**
  unresolved strong imports.
* End symbol `0x1004666000` and the probe slice `main+0x453f1e8 → 0x1020129640`
  match the reference on both sides.
* Own-first vs a Horizon-style global-first order would differ on **1112**
  symbolic sites naming **111** distinct symbols. This is the size of the risk
  taken by the "own module first" rule; the Mac loader's order is what the
  reference implements, and Horizon's exact order is *not* verified (§7).

**`aot_g3_real_exec`** — load+link (1547.2 ms, digest matched), build the
Program (177 thunks, sentinel `0x7f00100000`), then:

* a traced call through main's real PLT stub returns `0x1020129640` (3 blocks);
* 4 host threads × 1000 entries each: exactly **4000** handler calls, per-thread
  `bad=0 flat=0`, ticks strictly increasing;
* a transfer into the link-only `subsdk0` at its DT_INIT `0x1010000030` faults
  `AOT_FAULT_UNKNOWN_PC`.

**`aot_g3_real_exec_neg`** — two controls that execute no guest instruction:
an image shifted by `+0x1000` (as if translated for the wrong base) is rejected
by `aot_loader_build_program` with `bad-descriptor-layout`
(`image code range is not a 4-byte aligned range inside the module's text
segment`); and with correct descriptors but an empty link-only declaration the
same call is rejected with `invalid-argument` on module 1
(`module has no translated AotImage and was not declared link-only`).

## 6. Coverage evidence for D008

Measured on the real TotK 1.0.0 modules by `tools/aot/g3_coverage_report.py`;
report only, no game data. Full tables live in the local work directory
(`<V0>/coverage.md`); the numbers that matter for the D008 backend decision:

**(a) Linear sweep of every text word** (`decode(pc, word, module=True)`):

| module | text words | accepted | accepted % | rejected | data-in-text |
| --- | --- | --- | --- | --- | --- |
| main | 11 180 676 | 9 318 224 | 83.34% | 1 862 452 | 391 |
| subsdk0 | 856 112 | 729 093 | 85.16% | 127 019 | 314 |
| sdk | 1 540 280 | 1 279 945 | 83.10% | 260 335 | 282 |
| **total** | **13 577 068** | **11 327 262** | **83.43%** | **2 249 806** | **987** |

The sweep counts data inside the text segment as rejected, so it *understates*
code coverage.

**(b) Whole-function translatability** — a function counts only if every word
reachable from its entry (fallthrough + direct branch targets inside the shipped
text, stopping at `ret`/indirect `br`) decodes:

| module | defined STT_FUNC in text | fully translatable | full % |
| --- | --- | --- | --- |
| main | 28 | 10 | 35.71% |
| subsdk0 | 8 853 | 3 050 | 34.45% |
| sdk | 24 098 | 9 310 | 38.63% |
| **total** | **32 979** | **12 370** | **37.51%** |

**(a') Top rejected mnemonics** (words): `ldr` 251 813, `stp` 120 107,
`str` 115 578, `tbz` 105 070, `mov` 99 944, `fmul` 97 911, `and` 93 577,
`csel` 90 936, `stur` 77 216, `tbnz` 75 295.

**(b') First blocking mnemonic per blocked function**: `tbz` 1 920,
`and` 1 819, `stp` 1 697, `mov` 1 496, `str` 1 209, `ldur` 1 202,
`tbnz` 1 180, `stur` 1 128, `ldr` 1 090, `csel` 729.

Interpretation for D008: roughly 2/3 of functions are blocked by ordinary
instruction forms, not by exotic ones — the blocking set is dominated by
addressing modes (`ldr`/`str`/`stur`/`ldur`), pair forms and the test-bit
branches. This is a decoder-subset gap, not evidence for or against a given
graphics backend; D008 stays open.

## 7. Known limitations and open items

1. **MINOR 6/7 have fixes but no executable test.** `aot_as_protect`'s
   rollback-failure poisoning and the locked sealed/poisoned flag reads are
   implemented and covered only indirectly (all probes green). A test would need
   a host-VM protection failure injector; adding fault injection to the product
   code was judged worse than the gap. Recorded as an accepted gap, not as
   verified behaviour.
2. **Code/data distinction for link values landing in text.** A symbolic
   relocation whose value points into a module's text segment is linked as data;
   nothing verifies that the translator then treats that address as a valid
   entry. Untranslated targets fault, so the failure is safe, but the "link
   value in text ⇒ translated entry" invariant is not checked.
3. **Horizon symbol order is unverified.** The reference implements the Mac
   loader's order (own module first, then global, first DEFINED wins). The real
   set would differ on 1112 sites / 111 names under a strict global-first order.
   Which order the hardware loader uses for these specific names has not been
   confirmed against Horizon.
4. **`DT_FINI`/fini_array** are parsed only as layout data; there is no teardown
   path, so a module's destructors never run (no exit path exists yet).
5. **Thread exit inside a nested call.** Entry depth is tracked and restored, but
   a host thread that exits *while* inside a guest→host→guest nest has no defined
   unwind contract; the runtime assumes the outermost entry returns.
6. **Host bulk access.** Guest memory accesses go through the per-access helpers
   (`aot_mem_*`); there is no bulk/memcpy-style fast path, so large guest copies
   are slower than they could be. Correctness is the current goal.
7. **Performance is otherwise not addressed.** Beyond the per-module symbol index
   (relocate 45 s → 75.7 ms) nothing has been tuned; translate, map and seal
   times above are Debug numbers and are not a claim about shipping behaviour.
8. **Real modules are linked, not executed** (§1): only two real entries are
   translated, and there is no fallback for untranslated code.
