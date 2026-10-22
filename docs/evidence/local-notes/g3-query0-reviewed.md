# Actual next G3 blocker: QueryMemory(0) — investigation, NOT implemented

Canonical source: w19-2. Native evidence `start-w19-budget/result.json` + `run_start.log`:233 steps, SVC6 at sdk+0x158318, queriedVA=x2=0, output x0=0x200003ff38 valid guest RW stack, typed BAD_HLE status-8 (QUERY_UNKNOWN), target0. Guest ThreadType owner0x1001 already written by guest; nnosInitialize has NOT returned, ready/inits0. GetInfo21 and22 succeeded once each, budget_fail0.

Opus w21 readonly source investigation (no implementation/build): legitimate correctness-sensitive use, because guest-visible lower/upper VA window and free-hole records must not be guessed. Full result in session worker w21; key grounded conclusions follow. This is a proposal, NOT an accepted full-domain API decision.

## Grounded Mac behavior

Mac services.c284-308 checks stack/heap/low_space/host-gap, then !addr exactly. For Query(0), line291 returns base0,sizeASLR_START,stateFREE0,attr0,perm0,remaining counters0. ASLR_START is SAME low_space value GetInfo12 returns. No earlier range or later stack-map clipping can hit0. Consequently current explicit AOT profile can faithfully return `{base0,size0x100000000,state0,attr0,perm0}` for0; exact40LEbyte output and normal r0/r1=0. This is NOT proof that arbitrary unsupported addresses are all Free.

Distinguish mappable/ASLR region [2^32,2^39) from architectural39-bit VA window [0,2^39). Below mappable base is Free in this Mac special case; do NOT mark it Inaccessible merely because guest mappings cannot be created there. Mac adjacent Free ranges need not merge.

Mac fallback for other unrecognized addresses (state3/perm5) is made-up and NOT a valid generic rule to port. Do not fabricate success for every unknown geometry.

## Before implementing broadly

- Determine caller of wrapper sdk+0x158318 from x30/frame chain/offline Capstone using local flats: one-shot Query(0) vs full addr=base+size walk. No runtime ARM decoder.
- If a walk, need authoritative AS geometry across registered regions, heap logical RW prefix/free tail, alias/stack reserve-only windows, gaps and end handling. One domain-locked snapshot; no host-pointer leak.
- Proposal: separate `aot_as_query_memory` from mapped-only `aot_as_query`, preserve existing mapped-only contract. New names/types/return classification must be checked against ACTUAL headers before implementation (worker prose is not code).
- Belowbase [0,MIN) Free is Mac-grounded; generic gaps can use sorted guest-region boundaries. Never guess upper/out-of-window behavior. Opus recalled `{MAX,0-MAX,Inaccessible0x10}` wrapping end0 but explicitly UNVERIFIED; research Atmosphere libmesosphere `kern_k_page_table_base.cpp QueryInfo/InitializeForProcess`, `kern_k_address_space_info.cpp`, `source/svc/kern_svc_query_memory.cpp`, Switchbrew states before implementing it. Keep QUERY_UNKNOWN until grounded.
- Program thunk/sentinel control window at508GiB is NOT an AS data region. Full-space query would expose it as a free gap; decide/document correct scoped treatment rather than silently claim a complete VM model. Do not casually register a new region that conflicts with Program's existing overlap guards; loader/linking remains closed.

## Required controls

Exact40bytes plus trailingcanary; base/end containment; 0/MIN-1/MIN/regionedges/windowedges/MAX-1/MAX/UINT64_MAX; Free-vs-Inaccessible state and attr distinct; no read/write permissions for holes; real RX/RELRO/STACK rows defeat Free-for-all. Correct positive baseline and assertion-specific mutants for wrongbase,size,perm,state,offbyone/wrap. Actual partial-store mutant, not only fieldcorruption. If whole walk supported, contiguous finite walk for two geometries before/after heap resize with no host addresses. Preserve typed unknowns outside validated scope. No MapMemory/G4 work.
