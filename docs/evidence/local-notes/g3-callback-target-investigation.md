# Investigation: indirect target 0x1002146110 after the varshift fix (READ-ONLY)

Status: **investigation only. No production edits, no boot, no full tests. G3 OPEN.**
Frozen areas untouched (G4/RFS/HLE/power/N1/CLZ/varshift).

## Observed blocker (lead FS-enabled Start, `mn-g3-local/start-w2-varshift`)

`run_start.log` (result.json empty there):

```
OBS nninitStartup ... -> 0x1001130f10
OBS_RET nninitStartup rc=0 raw_x0=0x1002146110 return_out_x0=0x1002146110
CTOR_FAULT main_real code=10 src=0x102012c89c target=0x1002146110 status=0
STARTSTOP code=10 src=0x102012c89c target=0x1002146110 steps=1442 x0=0x408 x1=0x10
          x2=0x1002146110 x3=0x1004597990 x4=0x1000000001 x5=0x1004597991
          x6=0x1004597990 x7=0x1004597998 sp=0x200003fe50 ...
STARTFAULTSTATE x16=0x1020d06460 x17=0x102012c890 x29=0x200003fed0
          x30=0x102008d974 nzcv=0x80000000 depth=0
```

So: faults are `AOT_FAULT_UNTRANSLATED (10)` at the SDK `br x2`, i.e. a *dispatch*
miss, not a decode gap. The varshift increment is not implicated (no 16/24
status, no unsupported-instruction site; the last decode gap would surface as
code 16 with an `unsupported` site, which is absent).

## 1. Generated SDK code at the fault site (from `start-w2-varshift/img/sdk_real.c`)

`aot_blk_102012c890` — the whole block, not paraphrased:

```c
aot_set_zr(s, 8u, 0x0000001020d25000ull);          /* adrp x8, 0x1020d25000 */
aot_set_zr(s, 1u, 0x0000000000000010ull);          /* mov  x1, #0x10       */
... ld64(aot_gpr_sp(s,8u) + 0x8) -> x2 ...         /* ldr  x2, [x8, #8]    */
rt->site_pc = 0x102012c89cull;
rt->next_pc = aot_gpr_zr(s, 2u);
return AOT_EXIT_INDIRECT;                          /* br   x2              */
```

So x2 is **loaded from SDK data**, not computed: `x2 = *(0x1020d25008)`.
`x0` is untouched by the block (0x408 from the caller), `x1 = 0x10`, and the
site's own page register `x17 = 0x102012c890` matches the ADRP page.

## 2. Original main-module code at the target (read-only, `v0/link/main_real.flat`)

```
1002146100  mov  w21, wzr          <- preceding stub
1002146104  b    #0x1002146080
1002146108  mov  w8, wzr           <- another stub
100214610c  b    #0x10021460bc
1002146110  mov  x8, x0            <=== TARGET
1002146114  mov  x0, x1
1002146118  mov  x1, x8
100214611c  b    #0x10006fead0     <- tail call, no frame
1002146120  b    #0x10006fda20     <- second tail-only stub
1002146124  b    #0x1002146128
1002146128  stp  x29, x30, [sp, #-0x20]!   <- a REAL function starts here
100214612c  str  x19, [sp, #0x10]
1002146130  mov  x29, sp
1002146134  adrp x8, #0x10044e1000
1002146138  add  x8, x8, #0xb8      ; vtable-ish store
100214613c  str  x8, [x0]
```

`0x1002146110` is a **3-instruction argument-swap thunk**: `(x0,x1) ->
(x1,x0)` then `b 0x10006fead0`. It sits in a stub pool (`0x1002146100`–`0x1002146124`
are `mov`/`b`-only adapters). Such compiler-generated thunks are exactly the
class that carries **no STT_FUNC symbol** — hence the current policy refusal
(see §4). It is a real callable entry (it tail-enters a normal function), not a
mid-function interior address: the byte at the target is a complete instruction
and the fall-through predecessor `0x100214610c` is an unconditional branch.

Tail target `0x10006fead0` is an ordinary function with a frame:

```
10006fead0  stp  x29, x30, [sp, #-0x10]!
10006fead4  mov  x29, sp
10006fead8  adrp x8, #0x1004598000
10006fedc  ldr  x8, [x8, #0xec8]     ; global guard
... cbz ...
10006feae4  mov  x2, x0
10006feae8  adrp x0, #0x1004598000
10006feaec  add  x0, x0, #0xed0      ; guard/mutex object
10006feaf0  bl   #0x1002aa4440
```

i.e. the effective callee takes the **swapped** pair (x0=0x10, x1=0x408) and
locks a global guard before proceeding. 0x408 / 0x10 are *consistent with*
(size, align) or (count, stride) but the callee's use of them has not been
traced to an allocation, so **"allocator callback" is NOT proven** — see §6.

## 3. Registration origin (data slot, not a relocation)

- 8 code sites reference the page `0x1020d25000` in one tight SDK cluster:
  `0x102012bfa8`, `0x102012c83c`, `0x102012c84c`, `0x102012c858`,
  `0x102012c870`, `0x102012c890`, `0x102012c8a4`, `0x10201348fc`.
  These are the accessors of one SDK object/TLS-like block; `0x102012c890`
  loads `[+8]` and calls it.
- CORRECTION (retracted overclaim): `OBS_RET raw_x0=0x1002146110` is **not**
  independent provenance. It is most likely the same SetAllocator leaf leaving
  its first argument in x0. The registration store in §8 is the real evidence;
  the observed load at the consumer only shows the value's later path, not how
  it was formed.
- Exact static store (`adrp+add`/`str` of `0x1002146110` into `0x1020d25008`)
  was **not located** in this window: the flat scan only covered
  `adrp -> 0x1020d25000` (8 hits, all in `.text`), and the slot is in SDK
  `.data`, which is populated by an init/registration path (likely
  `nninitStartup`'s callee) that has not been traced. **This is the one
  missing link and it is what a follow-up should prove.**

## 4. Why the current policy refuses it (existing code, unchanged)

`tools/aot/g3_start_prefix.py`:

- docstring: "an indirect target is added only when it is a DEFINED STT_FUNC in
  the module's own dynsym (WEAK included). A relocation value alone is a
  candidate, never proof, so an unknown target is reported fail-closed".
- `justified()` returns `None` unless `index.get(va)` has a unique owning
  module symbol hit — i.e. a defined STT_FUNC at that exact VA.
- `batch_indirect_targets()` collects scanned indirect text targets and puts
  non-STT_FUNC ones in `rejected`, which the driver reports as
  `UNJUSTIFIED target 0x%x is not a DEFINED STT_FUNC` (`tools/aot/g3_start_prefix.py`
  ~line 570).

`0x1002146110` is a symbol-less thunk, so `justified()` correctly returns
`None` and the driver stops with code 10 instead of inventing a root. That is
the desired fail-closed behaviour, not a defect.

## 5. Seam / minimization already available

- The refusal is cheaply reproducible without a boot: the driver's own
  justification gate (`g3_start_prefix.py` → `justified()` + the
  `UNJUSTIFIED target` report) takes the module index and the VA, and the
  probe path is `tests/aot/aot_g3_start_probe.c` with the `real_desc`/`entries`
  JSON already emitted next to the run
  (`start-w2-varshift/{entries_*.json, real_desc_partial.c}`).
- Smallest honest repro: feed `0x1002146110` (and the two other unknown
  indirects, if any) to `justified()` and show `None` while
  `0x1002146128` (the real function that follows) would also be absent from
  dynsym — proving a thunk-pool VA can never pass under a dynsym-only rule.

## 6. What is proven / what is not

PROVEN
- The blocker is a dispatch miss (`code 10`), not a decode gap; varshift/CLZ
  work is not implicated.
- The call is an indirect call through a **data-resident** pointer:
  `x2 = *(0x1020d25008)` then `br x2`, with x0=0x408, x1=0x10 live.
- `0x1002146110` is a well-formed argument-swapping thunk (x0<->x1) tail-calling
  the real function `0x10006fead0`, which enters with a normal frame and locks a
  global guard. It is an entry, not an interior address.
- The registration store (§8) is the primary evidence. The `nninitStartup`
  return value is NOT counted as independent provenance (see the correction in
  §3).
- The target has **no defined STT_FUNC** symbol, which is exactly why the
  current policy refuses it (by design, fail-closed).

NOT PROVEN (must not be asserted as fact)
- That this is an **allocator** callback: the (0x408, 0x10) pair reaches
  `0x10006fead0` swapped and is not yet traced to an allocation.
- The exact static **registration site** that writes the slot (missing link, §3).
- Any new G4 service: nothing here touches or implies one; the fault is in the
  Start/CTOR prefix of the existing SDK path.

## 7. Options and recommendation (no implementation)

A. **Do nothing (recommended for now).** The refusal is correct under the
   current root policy. The missing link is evidence, not code: prove the
   registration store and the callee's use of (0x408, 0x10) before any policy
   change. Cost 0, keeps every candidate intact.

B. **Thunk-pool root rule (needs lead decision).** Allow a root when the VA is a
   *verified thunk* — a short, self-contained instruction sequence in a text
   region whose only job is register moves plus a direct `b` to a defined
   function or another justified entry, with no fall-through entry. This is
   narrower than "mid-symbol roots" and must be specified positively (thunk
   shape, region, tail-target justification), **not** as a known-VA exception.
   Reject unconditionally: arbitrary mid-symbol roots, hard-coded VAs,
   loader re-open without a demonstrated defect, runtime ARM decode/JIT.

C. **Relocation/registration evidence path.** Find the `adrp+add`/`str` (or
   passed function pointer) that installs `0x1002146110` into
   `0x1020d25008`; if the store is in translated code, the value is already
   reachable and only the *call* needs to dispatch. This is the option most
   likely to keep the rule "DEFINED STT_FUNC or nothing" intact.

Recommendation: **A now, then C.** Only if C shows that the SDK genuinely
registers a symbol-less thunk as a callback (which the current evidence
strongly suggests but does not prove) should B be specified — and then as a
thunk-shape rule with its own negative controls, never as a VA exception.

Nothing here authorizes implementation; waiting for the lead after this
evidence. All candidate code preserved.

## 8. VERIFIED registration proof (original bytes, read-only, this session)

### 8a. Main-module registration site — exact words

`v0/link/main_real.flat`, disassembled with Capstone (VA = base 0x1000000000):

```
[6 line(s) of raw game disassembly/bytes omitted; kept only in the local original]
```

These five words are exactly the ones the primary reported. `0x1002146120` is
the second thunk (`b 0x10006fda20` in §2), i.e. the pair is registered
together.

### 8b. `0x1002aa5150` is a PLT stub, not the function

```
[4 line(s) of raw game disassembly/bytes omitted; kept only in the local original]
```

So the call is a normal cross-module PLT call; the import's resolved address is
`*(0x100453f720)`.

### 8c. SDK side: the exact "register once, then call it" pair of blocks

`v0/link/sdk_real.flat` (VA = base 0x1020000000) — ORIGINAL words, verified:

```
[13 line(s) of raw game disassembly/bytes omitted; kept only in the local original]
                                                         ; *(0x1020d25010)=x1
[2 line(s) of raw game disassembly/bytes omitted; kept only in the local original]
```

Then, strictly later, the consumer block (§1) reads the SAME slot:
`adrp x8,0x1020d25000 / ldr x2,[x8,#8] / br x2`.

**This is a complete, asserted registration chain:**

```
main 0x1001130f90  adrp+add  x0=0x1002146110, x1=0x1002146120
  -> b PLT 0x1002aa5150 -> GOT 0x100453f720 -> sdk 0x102012c830
  -> "if not already set, stp x0,x1,[0x1020d25008]"   (exactly once)
  ... later ...
sdk 0x102012c858  ldr x2,[0x1020d25008] ; br x2  -> 0x1002146110
```

The called pointer therefore comes from a **trusted in-image registration
store** (ADRP+ADD of an in-text address written by translated code), not from a
relocation value, not from an arithmetic coincidence, and not from an
arbitrary aligned address.

Trace agreement: `STARTTRACE` contains
`1001130f90 1002aa4a70 ...` and the `0x102012c830 -> c83c -> c848 -> c84c ->
c858` sequence reported by the primary, consistent with §8a–8c.

### 8d. Status of symbol/FDE lookups for the target and the tail callee

- **dynsym name: NOT obtainable offline in this window.** `main_real.layout.json`
  exposes `nso_dynsym.off = 12112408`, `nso_dynstr.off = 12129304`,
  `dynsym_count = 704`, but those offsets are into the **original NSO**, not into
  `main_real.flat`: parsing them against the flat yields 0 resolvable entries.
  The NSO itself is not part of these artifacts. What IS established is the
  driver's own live index refused the VA (`UNJUSTIFIED target ... is not a
  DEFINED STT_FUNC`), and the same index resolved every other root in the run,
  so this is symbol absence at that VA in the live index — not a lookup failure
  of the driver.
- **FDE start: NOT established.** The `eh_frame_hdr` magic (`01 1b 03 3b`) is
  present at module offset 0xd36510 (= 58578192) inside the `.ro` segment, but
  the header/binary-search table was not parsed in this window, so no claim is
  made about whether `0x1002146110` or `0x10006fead0` begin an FDE.
  Per the primary's instruction: **"ordinary framed function" is NOT asserted to
  imply "justified"** — the framed prologue at `0x10006fead0` and the stub pool
  at `0x1002146100` are observations, not a policy argument.

## 9. Refined positive root-policy option (specification only, NOT implemented)

Because §8 makes the *trust* question decidable without symbols, the narrowest
positive rule consistent with all existing evidence is:

A VA may be admitted as an indirect-callback root only when ALL of:

1. **Trusted registration source**, established statically: the VA is materialised
   by an `ADRP`+`ADD` (both words verified, no relocation-only value) in
   translated code of a root-reachable function, and that pointer is stored into
   a data slot by a store instruction in the same registration path — i.e.
   `adrp+add` value -> `stp/str` into slot -> later `ldr` -> `br`. Evidence must
   name the four instructions and the slot.
2. **Finite thunk shape at the target**: at most 4 instructions, every one of
   them either a register-to-register `mov` (or `adrp`+`add` of a constant) or
   the single terminating `b`, with no memory access, no SVC, no conditional
   branch, and no fall-through entry into the target (predecessor is an
   unconditional `b`/`ret`/padding).
3. **Direct terminal `b` to a JUSTIFIED function** (defined STT_FUNC, or itself
   admitted by this rule), so the thunk adds no new behaviour of its own.
4. **Explicitly rejected** (must fail closed, with its own negative controls):
   arbitrary 4-byte-aligned text, mid-function interior addresses, an aligned
   address that merely *looks* like a target, relocation values alone, known-VA
   allow-lists, loader re-open, and any runtime ARM decode/JIT.

Under (1)–(3), `0x1002146110` qualifies: exact registration store proven (§8),
3-instruction mov-only thunk (§2), terminal `b` to `0x10006fead0`. Whether
`0x10006fead0` is itself justified still depends on its dynsym/FDE status,
which is the next lookup to do — so **no architecture choice is made here**.
Every candidate preserved; no implementation.

## 10. Admissibility probe (READ-ONLY, reusing the project's own parser)

Probe script kept as external evidence: `mn-g3-local/probe_admissibility.py`
(it imports `g3_start_prefix`/`reference_cfg`; it does not touch the repo).

### 10a. RETRACTION of the "dynsym not obtainable offline" claim

That §8d claim was **FALSE** and is retracted: the offsets in
`*.layout.json` are NSO-relative, but the project already has a working parser
and I failed to use it. Re-running with `P.load_meta` + `P.symbol_index` gives
**31474 index entries** and reproduces the primary's output exactly:

```
justified(0x1002146110) = None
justified(0x1002146120) = None
justified(0x10006fead0) = ('main_real', 'aligned_alloc', 1, 76)
justified(0x10006fda20) = ('main_real', 'free',          1, 24)
justified(0x102012c830) = ('sdk_real',
    '_ZN2nn2os32SetMemoryAllocatorForThreadLocalEPFPvmmEPFvS1_mE', 1, 64)
justified(0x102012c890) = ('sdk_real', 'nnosAllocateMemoryForThreadLocal',
    1, 16)
justified(0x1001130f90) = None      <- the registering function itself
```

So both veneer VAs are *absent* from the symbol index, and no sized STT_FUNC
covers them (`covering=[]` for A and B, checked over the whole index). The
registering function `0x1001130f90` is itself **outside** the STT_FUNC index
(`exact=None`, `covering=[]`), which is why the registration path has no symbol
name of its own.

### 10b. Registration materialization: derived value == observed

```
[1 line(s) of raw game disassembly/bytes omitted; kept only in the local original]
           -> 0x1002146110   (want 0x1002146110)  MATCH
[1 line(s) of raw game disassembly/bytes omitted; kept only in the local original]
           -> 0x1002146120   (want 0x1002146120)  MATCH
```

### 10c. Veneer shape (original bytes, Capstone; op_str is the evidence)

```
A 0x1002146110: mov x8, x0 ; mov x0, x1 ; mov x1, x8 ; b #0x10006fead0
                prior word: b #0x10021460bc        (terminator, no fall-through)
B 0x1002146120: b #0x10006fda20
                prior word: b #0x10006fead0        (terminator)
```

A = 3 register-only `mov` + direct `b`; B = 0 `mov` + direct `b`. All registers
are x0/x1/x8 (< 16), i.e. exactly "0..3 MOV X rd,X rm, rd/rm in 0..15".
Terminal targets are DEFINED STT_FUNCs **in the same module**: A ->
`aligned_alloc` (main_real, size 76), B -> `free` (main_real, size 24).
(Note: for A the three movs form a swap x0<->x1; RVCT of the pattern is only
"describe it", the shape rule itself is satisfied either way.)

### 10d. Static reach of the registration site: NOT established in-window

`P.R.load_world` + `P.R.scan_world(world, roots)` with
`roots = Start(0x10200fa060) + each module's DT_INIT` scans
`main=220, subsdk0=123, sdk=10455` visited blocks, but **the ADRP at
0x1001130f90 is not a visited block start**, and my linear-decode
"inside a visited block" check aborted with a probe `NameError` (my bug, not a
project defect). So:
- the registration site is reached **at runtime** (STARTTRACE shows
  `... 0x1001130f90 ...` immediately before the SetMemoryAllocator call), and
- the value materialization is proven from the original words (10b),
- but **"statically reachable from a justified root by R.scan_world" is NOT
  proven** in this window; it must be re-run with the reach check fixed.
- "no prior writes to slot 0x1020d25008 before the store" is likewise **not
  checked** (the SDK block itself tests the slot for emptiness first, which is
  a register-level guard, not a proof of no earlier writer).

### 10e. EH contradiction check via MOD0 metadata (no magic scanning)

`mod0_off=0x8`; `mod0+0x10`/`mod0+0x14` = **58578184 / 60521076** (module
offsets, i.e. `eh_frame_hdr` start/end). The bytes at start are not a header but
`start+8` is the documented sequence `01 1b 03 3b`
(ver=1, eh_frame_ptr=DWEH_PE_pcrel|sdata4, fde_count=udata4, table=
DWEH_PE_datarel|sdata4). Parsing that header: **fde_count = 242860**, table
**sorted = True** (verified ascending over all 242860 entries). Binary search:

```
target A 0x1002146110  FDE_start = False  (covering init 0x2146108,
                                           next 0x2146118)
target B 0x1002146120  FDE_start = True   (covers 0x2146120..0x2146178)
tail A   0x10006fead0  FDE_start = False  (covering init 0x6feac8)
tail B   0x10006fda20  FDE_start = False  (covering init 0x6fda18)
regsite  0x1001130f90  FDE_start = False  (covering init 0x1130f88)
```

Two facts, stated plainly and **not reconciled by me**:

1. Under the proposed rule "EH interior => reject", **target A is rejected**
   (`0x1002146110` is interior to the FDE that starts at `0x2146108`), while
   **target B is supported** (`0x1002146120` IS an FDE start). The *observed*
   callback (A) is the one the rule rejects.
2. The same check rejects `aligned_alloc` (interior, init `0x6feac8`) and
   `free` (interior, init `0x6fda18`) — two of the four DEFINED STT_FUNCs in
   this very chain. So "STT_FUNC VA == FDE start" is **not** an invariant of
   this binary, and the EH-interior rule cannot be a *proof* of non-entry; it is
   at best an additional conservative filter that here loses one true target and
   keeps the other.

### 10f. Admissibility verdict for V2 (facts only, no implementation)

| check | A `0x1002146110` | B `0x1002146120` |
|---|---|---|
| registration materialization ADRP+ADD == observed | MATCH | MATCH |
| registration store proven (SDK `stp x0,x1,[slot]`, guarded once) | YES | YES |
| no exact STT_FUNC, no sized cover | YES | YES |
| finite mov-only 0..3 + direct B | 3 movs + b | 0 movs + b |
| terminal B to DEFINED STT_FUNC same module | `aligned_alloc` | `free` |
| prior word is a terminator (no fall-through entry) | YES | YES |
| EH: exact FDE start | **NO (interior)** | YES |
| statically reachable from justified root by R.scan_world | NOT PROVEN (10d) | NOT PROVEN (10d) |
| no prior writer to the slot | NOT CHECKED | NOT CHECKED |

So **A satisfies every check except the EH-start one; B satisfies the EH-start
one as well.** Under the option exactly as specified (EH interior => reject),
only B would be admissible — and B's callback has not been observed being
called yet. That is the decision the lead now has to make; I am not making it
here, and no code was touched.

## 11. CORRECTION: the "interior" FDE finding was a probe bug — RETRACTED

My §10e/§10f used the MOD0-relative `eh_frame_hdr` start as the table base.
The project's loader (`tools/aot/aot_module.py`, elf2flat ~lines 225-251) uses
`pos = mod0_off + rel`; the header VA is `h = mod0_off + eh_start`, and table
entries are relative to **h**, not to `eh_start`. That is exactly the -8 shift
seen in every reported start. Corrected probe: `mn-g3-local/probe_admissibility2.py`.

```
mod0=8  eh_start=58578184  h = 8 + 58578184 = 0x37dd510   end = 0x39b7a7c
header 011b033b   fde_count=242860   sorted=True
target A  0x1002146110  exact_FDE_start=TRUE  (own init 0x2146110, next 0x2146120)
target B  0x1002146120  exact_FDE_start=TRUE  (own init 0x2146120, next 0x2146124)
aligned_alloc 0x10006fead0 exact_FDE_start=TRUE (next 0x6feb1c)
free          0x10006fda20 exact_FDE_start=TRUE (next 0x6fda38)
regsite fn    0x1001130f90 exact_FDE_start=TRUE (next 0x1130fb0)
```

**RETRACTED:** "target A is interior", the claim that `aligned_alloc`/`free` are
interior, and the inference that "STT_FUNC VA == FDE start is not an invariant".
All four VAs are exact FDE starts. No policy relaxation is justified by my bug;
the bug is retracted rather than accommodated.

Corroboration (not proof): A's FDE span 0x2146110..0x2146120 is exactly the
4 instructions of the observed veneer (`mov x8,x0 / mov x0,x1 / mov x1,x8 / b`),
and B's 0x2146120..0x2146124 is exactly its single `b`. Per the primary's
caveat, a header still only gives STARTS: nearest-start does **not** prove the
FDE covers an address, so no cover-range claim is made here.

### 11a. Static reach with the roots P.main actually uses

Previous probe omitted the observer roots. Rebuilt exactly as
`g3_start_prefix.main` (lines ~435-480): Start + every `cfg["observers"]` name
except `nnMain`, resolved through `P.resolve_unique`, + the 3 DT_INIT roots:

```
roots: start 0x10200fa060
       observer _ZN2nn2os19AllocateMemoryPagesEmm  0x102012caa0
       observer _ZN2nn2os21AllocateAddressRegionEPmm 0x102012ca60
       observer nninitInitializeSdkModule           0x10200fa000
       observer nninitStartup                       0x1001130f10
       observer nnosInitialize                      0x1020131210
       dt_init main/subsdk0/sdk 0x1000000030 / 0x1010000030 / 0x1020000030
visited block starts: main=420 subsdk0=123 sdk=14634
  0x1001130f90 visited_block_start=True (main)
  0x1001130f94 visited_block_start=True
  0x1001130f98 visited_block_start=True
  0x1001130f9c visited_block_start=True
  0x1001130fa0 visited_block_start=True
```

So the **registration materialization is statically reachable from justified
roots** (checked on the visited word map directly for each word; no neighbour
or linear-jump inference, no use of an undefined `md`).

### 11b. Sized-symbol cover, using the real index shape

My earlier helper iterated `idx.items()` treating values as tuples and always
failed. Looping the per-module lists the way the primary does:

```
0x1002146110  exact=None  covering=[]      (no sized STT_FUNC covers it)
0x1002146120  exact=None  covering=[]
```

### 11c. Shape via Capstone register names (not numeric enum ids)

```
A 0x1002146110  mov x8,x0 ; mov x0,x1 ; mov x1,x8 ; b 0x10006fead0
                movs=3 (x0/x1/x8)  shape_ok=True  tail=aligned_alloc(main,76)
B 0x1002146120  b 0x10006fda20
                movs=0  shape_ok=True  tail=free(main,24)
```

### 11d. Relocation SITE overlap: NOT done

`aot_module` exposes no reloc-table helper (`dir(M)` has no `reloc*` member;
the loader parses entries inline at `aot_module.py:859`). I did not hand-parse a
new table and did not substitute a guess, so relocation-site overlap against the
two VAs remains **unchecked**. Per the primary, the safe-producer category does
not depend on this: the gate is static reach + exact materialization + observed
match + shape + defined tail + not-mid-function, all of which now hold.

### 11e. Corrected admissibility table (supersedes §10f)

| check | A `0x1002146110` | B `0x1002146120` |
|---|---|---|
| registration materialization (ADRP+ADD == observed) | MATCH (0x110) | MATCH (0x120) |
| materialization statically reachable from justified roots (scan_world) | YES (block start) | YES (block start) |
| registration store proven (SDK `stp x0,x1,[0x1020d25008]`, set-once) | YES | YES |
| no exact STT_FUNC and no sized cover | YES | YES |
| finite 0..3 mov-only + direct B | 3 movs + b | 0 movs + b |
| terminal B -> DEFINED STT_FUNC same module | aligned_alloc (76) | free (24) |
| prior word is a terminator (no fall-through) | YES (`b`) | YES (`b`) |
| exact FDE start (corrected base) | **YES** | **YES** |
| FDE span matches the veneer length (corroboration) | 16 B = 4 insns | 4 B = 1 insn |
| relocation-site overlap | unchecked | unchecked |

Every gate the primary named now holds for **both** A and B. Remaining open
items are explicitly unchecked (reloc sites, cover-range proof, prior-writer
history — the last one the primary says is not required). No code touched; the
architecture/policy decision stays with the lead.
