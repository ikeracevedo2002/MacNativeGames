# Windows x86-64 build (G1 host-wrapper rows)

This document covers the narrow G1 host-wrapper rows on the
`windows-x86-port` branch:

* the **build-skeleton row**: a small Windows x86-64 host executable,
  a platform-neutral RomFS probe compiled unchanged from
  `tests/test_romfs_paths.c`, and a CTest suite whose negative-control
  harness verifies BOTH the exact exit code AND the exact diagnostic
  line printed by the host;
* the **host timing row**: a narrow Windows `QueryPerformanceCounter`
  monotonic-nanosecond primitive with deterministic conversion tests and
  a live Windows probe (see "G1 host monotonic clock" below);
* the **host TLS row**: a narrow Windows TLS *slot lifecycle* primitive
  (`src/host_tls.h` / `src/host_tls.c`) with a lifecycle + real-thread
  isolation probe that also rejects fixture-only wrong backends (see
  "G1 host TLS slots" below). It is host TLS only: no guest TLS/TLR, no
  thread-environment object, no key destructor and no guest ABI;
* the **host VM / thread / synchronisation / logging rows**: narrow host
  primitives (`src/host_vm.*`, `src/host_thread.*`, `src/host_sync.*`,
  `src/host_log.*`) with probes that reject fixture-only wrong backends
  (see "G1 host VM, thread, synchronisation and logging" below).

It explicitly does **not** cover: fault/exception handling, AOT
translation, the translated module loader, guest TLS/TLR and its ABI,
the guest thread ABI/scheduler, guest synchronization objects, Horizon
services, audio, controller, frontend, graphics, packaging, or a
reproducible build of the full game. Those rows stay `NOT STARTED` /
`RESEARCH` in `../PORTING_STATUS.md` until later work satisfies their
individual exit conditions. In particular, the TLS row validates the
**host** slot lifecycle against real OS threads, and the thread/sync row
validates **host** threads and the host mutex/condition pair; neither
implements the guest TLS/TLR mechanism, the guest thread ABI/scheduler,
the Mac thread environment or its destructor. The VM row is the host
anonymous-private reserve/commit primitive only; it is not the guest
address strategy.

There are now **two** independent build paths in the repository:

* **macOS (legacy, game-runtime path)** — `games/totk/Makefile`,
  Apple-silicon native, remains the only path that produces a
  playable game until later Windows rows close.
* **Windows x86-64 (these rows only)** — `CMakeLists.txt`, builds the
  small host executable, the unchanged RomFS probe, and the host
  libraries and probes for the monotonic clock, TLS slots, virtual
  memory, threads, mutex/condition variables and core logging. It does
  not produce a runnable game.

## Scope matrix for this row

Each row distinguishes between **(C)ode guard** (the CMake or C
source contains a guard) and **(T)ested locally** (a local run on
the AMD64 box reproduced the expected behaviour). Statuses without
`(T)` are guarded but not empirically exercised on this branch.

| Item                                          | Status                                            |
|-----------------------------------------------|---------------------------------------------------|
| Out-of-source CMake build                     | VALIDATED (T) — in-source / subdir rejected       |
| Windows-only target guard                     | guard in code (C); non-Windows not run locally    |
| AMD64 processor / 64-bit-pointer target guard | guard in code (C) for processor; (T) for `-A Win32` triggering `CMAKE_SIZEOF_VOID_P=4` guard |
| `_WIN64` / `_M_AMD64` compile-time checks     | VALIDATED (T) — visible from the build itself      |
| `sizeof(void *) == 8` `_Static_assert`        | VALIDATED (T) — visible from the build itself      |
| Negative-control harness with exact exit code 1 plus exact diagnostic-line match | VALIDATED (T) — see "Verifier self-check" below |
| RomFS probe built and run unchanged           | VALIDATED (T) — `tests/test_romfs_paths.c`        |
| Host monotonic clock library + deterministic conversion tests | VALIDATED (T) — 20 fixed cases + 5 rejected negative controls |
| Live host clock probe (nondecreasing + unit scale) | VALIDATED (T) — Debug and Release CTest |
| Host TLS slot library + lifecycle/isolation probe | VALIDATED (T) — host slots only; 5 rejected negative backends |
| Host VM library + reserve/commit/decommit/protect/query/flush probe | VALIDATED (T) — anonymous private region only; independent raw `VirtualQuery` + SEH guarded-access control |
| Host thread library + lifecycle probe | VALIDATED (T) — 2 rejected behavioral fakes; self-join and close-while-running phases |
| Host mutex/condition library + probe | VALIDATED (T) — 4 rejected condition/mutex fakes; no wrong backend is UB |
| Host core logger + probe | VALIDATED (T) — 4×200 concurrent records + corrupted-stream and broken-sink negatives |
| Guest TLS/TLR, thread environment, key destructors, guest ABI | NOT STARTED — outside every row so far |
| Guest thread ABI/scheduler, guest synchronization objects | NOT STARTED — host primitives only |
| Fault/exception handling (VEH/SEH policy) | NOT STARTED — the VM probe's SEH fixture is not runtime fault policy |

Other later-milestone rows (fault/exception handling, the translated
module loader, guest TLS/TLR and its ABI, and every G2..G8 row) are
explicitly NOT STARTED, with one scoped exception: a finite-subset G2 AOT
proof exists behind `-DMN_BUILD_AOT_PROOF=ON` (see `docs/g2-aot-proof.md`,
D010/D011). **Full G2 is still not closed** (no numerical FP or atomics/ordering; a
runtime fault policy is a separate G3 row; D008 open). The timing row below
covers only the host
monotonic clock; the TLS row covers only the host TLS slot lifecycle;
the VM/thread/sync/logging rows cover only their host primitives. The
fault/exception row is unchanged: the VM probe's local SEH fixture is a
probe-local guarded-access control, not a runtime fault policy.

## G1 host monotonic clock (timing row)

This row adds a narrow **host** time primitive only. It is deliberately
not a guest clock: it does not implement `nn::time`, does not touch
`games/totk/runtime/time_host.c`, and does not change the Mac
`runtime_now_ns` implementation. The Mac code remains the behavioral
reference and is unchanged.

### API (`src/host_time.h`)

| Function | Contract |
|---|---|
| `host_time_now_ns(uint64_t *out_ns)` | Reads the Windows monotonic clock and writes exact nanoseconds. |
| `host_time_ticks_to_ns(ticks, frequency_hz, *out_ns)` | Exact `floor(ticks * 1e9 / frequency_hz)`; exposed for deterministic tests and reuse. |

`host_time_result` is `HOST_TIME_OK`,
`HOST_TIME_ERR_INVALID_ARGUMENT` (NULL output or zero frequency),
`HOST_TIME_ERR_CLOCK_FAILED`, or `HOST_TIME_ERR_OVERFLOW`. On any
failure the output parameter is left unchanged.

Semantics:

* Values are `uint64_t` nanoseconds from an **arbitrary, non-wall-clock
  epoch**; only differences between reads are meaningful.
* Scaling uses 128-bit integer intermediates (`_umul128`/`_udiv128` on
  MSVC x64), no floating point, and no silent `ticks * 1e9` wrap. A
  quotient that would exceed `UINT64_MAX` is `HOST_TIME_ERR_OVERFLOW`.
* The Windows backend is `QueryPerformanceCounter` /
  `QueryPerformanceFrequency`.
* Microsoft documents QPC as monotonic, with the frequency fixed at
  boot and consistent across processors, and as including time spent in
  sleep/standby. The QPC FAQ also notes that when comparing reads from
  different threads, values that differ by +/-1 tick have an ambiguous
  ordering. Reads on the **same thread** are therefore
  nondecreasing; this API does **not** promise a globally strictly
  ordered timestamp across threads. Source:
  <https://learn.microsoft.com/en-us/windows/win32/sysinfo/acquiring-high-resolution-time-stamps>
* **No Mach equivalence is claimed.** `mach_absolute_time` excludes
  sleep while `mach_continuous_time` includes it; that Mac distinction
  is not mapped onto this API. Any future guest-clock binding must
  choose its suspend policy explicitly.
* Suspend/standby behaviour is documented from the platform contract but
  is **not measured** by this row's probes.

### Deterministic conversion tests

`host_time_convert_cases` (`tests/test_host_time_convert.c`) uses 20
fixed cases with expected constants computed independently with
arbitrary-precision integers: zero, subsecond, second boundary,
non-divisor frequencies, a large tick count where a naive 64-bit
`ticks * 1e9` wraps but the true result fits, an exact fit, the largest
fitting quotient (`ticks = UINT64_MAX`, `frequency = 1e9`), real
overflow, zero frequency with unchanged output, and uint64 frequency
divisors above 1e9 (`UINT64_MAX`, `2^32 + 1`, `2^63`). NULL output is
checked directly.

The executable fails unless the **same** checker rejects five
deliberately wrong implementations: constant zero, wrong unit
(microseconds), naive 64-bit multiply with silent overflow,
uint32-truncated frequency, and error-output clobber (which proves the
unchanged-output sentinel check). Exit status is the result; there is no
inverted test and no `PASS_REGULAR_EXPRESSION`.

### Live Windows probe

`host_time_live_probe` (`tests/host_time_probe.c`) checks:

* `host_time_now_ns(NULL)` is rejected;
* every read succeeds and same-thread samples are nondecreasing;
* a real 200 ms wait produces positive elapsed time;
* the elapsed nanoseconds fall inside a conservative interval bracketed
  by an independent `GetTickCount64()` reference
  (`ref_b0 - ref_a1` to `ref_b1 - ref_a0`), widened by 32 ms for
  `GetTickCount64` granularity. This catches wrong-scale (microseconds
  labelled nanoseconds) clocks without scheduler false positives and is
  not a performance benchmark.

The same checker must reject a constant clock and the real clock divided
by 1000 (microseconds mislabeled as nanoseconds). CTest applies an
external 60 s timeout.

### Local evidence and commands

External build dirs (with spaces) and the Visual Studio 18 generator:

```cmd
cmake -S "<repo>" -B "C:\Users\IKER\mn time build\debug" -G "Visual Studio 18 2026" -A x64
cmake --build "C:\Users\IKER\mn time build\debug" --config Debug
ctest --test-dir "C:\Users\IKER\mn time build\debug" -C Debug --output-on-failure
:: same with -C Release in a separate external build dir
```

Local results (MSVC 19.51, VS 18):

* Debug: 5/5 CTest pass at the time of the timing row (existing 3 +
  `host_time_convert_cases` + `host_time_live_probe`). The suite now also
  contains `host_tls_slot_probe`; the current total is 6/6 (see the TLS row).
* Release: 5/5 CTest pass at the time of the timing row (6/6 today).
* `host_time_convert_test.exe`: `PASS: 20 conversion cases + 5 negative
  controls`.
* `host_time_probe.exe`: elapsed inside the reference interval, e.g.
  `elapsed=202933900 ns inside reference interval [171000000, 235000000] ns`;
  constant and ns/1000 (microseconds) controls rejected.

Additional out-of-tree local evidence (**not** committed regression
tests): an independent Python arbitrary-precision oracle called the
MSVC-built conversion 343,839 times (boundary pairs, seeded random
64-bit ticks/frequencies, overflow transitions) and matched exactly; a
smaller 1,000-case randomized oracle also passed. The committed fixtures
above are the regression suite.

Limitations: no suspend/standby test, no cross-thread ordering test, and
this is not a guest clock. Host TLS slots are covered by the separate TLS
row below; guest TLS/TLR is not covered anywhere yet. The non-MSVC `__int128` fallback in the
conversion helper exists for portability but is not locally validated;
the tested path is MSVC x64. Hosted CI has not been executed from this
branch.

## G1 host TLS slots (TLS row)

This row adds a narrow **host** thread-local-storage slot primitive only.
It does not implement the guest TLS/TLR mechanism, the Mac thread
environment, any key destructor or the translated-code (AOT) ABI. The Mac
sources are unchanged.

### Mac reference (behavioural source, not code to port)

`games/totk/runtime/loader.c`:

* `runtime_thread_init()` allocates a per-thread `ThreadEnvironment` and
  binds it with `pthread_setspecific(environment_key, e)`, then binds the
  per-thread gate/TLS/TLR pointers into `runtime_keys[0..3]`;
* `thread_cleanup()` clears `environment_key` and `runtime_keys[0..3]` and
  then runs `environment_destroy(e)` explicitly;
* `main()` creates `runtime_keys[8]` with `pthread_key_create(..., NULL)`
  (no destructor) and `environment_key` with
  `pthread_key_create(..., environment_destroy)` (destructor);
  `runtime_hle_stack_init()` turns `runtime_keys[4]` into the Darwin TSD
  offset `key * 8`.

`games/totk/runtime/threads.c` binds a `thr_t` to the current thread
through `g_keythr`, also created with a NULL destructor.

What this row takes: the host TLS slot lifecycle used by the
destructor-less keys (`runtime_keys[]`, `g_keythr`) — create, per-thread
get, per-thread set/replace, clear and release, with explicit errors and
no automatic release of the stored pointer.

What this row excludes on purpose:

* `environment_key` has a destructor and is therefore **outside** this
  contract. Thread-environment teardown stays an explicit caller step for
  a later boundary; no destructor hook exists in this API;
* the ThreadEnvironment struct and its ownership;
* the raw Darwin TSD layout (`TPIDRRO_EL0 + key * 8`) and the guest key
  page. Those are ARM64/Darwin details and are neither preserved nor
  exposed as a Windows ABI;
* guest TLS/TLR values, guest handles, and any guest register/AOT ABI.

### API (`src/host_tls.h`, Windows backend `src/host_tls.c`)

| Function | Contract |
|---|---|
| `host_tls_slot_init(slot)` | Required once before the first create(); rejects a live slot; returns the handle to a ready state. |
| `host_tls_slot_create(slot)` | Allocates a native TLS index (may be 0). On failure the handle is untouched and still ready. |
| `host_tls_slot_destroy(slot)` | Releases the index of a live slot after quiescence. On failure the slot stays live. |
| `host_tls_get(slot, *out)` | Per-thread read. `*out == NULL` on success means "no value on this thread" and is not an error. On failure `*out` is untouched. |
| `host_tls_set(slot, value)` | Per-thread store or replace; `value == NULL` clears. |

`host_tls_result` is `HOST_TLS_OK`, `HOST_TLS_ERR_INVALID_ARGUMENT`
(NULL slot / NULL output), `HOST_TLS_ERR_INVALID_STATE` (lifecycle
misuse: create without init, create twice, init on a live slot, any
get/set/destroy on an uninitialised or destroyed slot),
`HOST_TLS_ERR_ALLOCATION` (TlsAlloc refused a new index) or
`HOST_TLS_ERR_PLATFORM` (TlsGetValue/TlsSetValue/TlsFree failure).

Semantics and preconditions (documented in the header):

* storage is per operating-system thread; a new thread starts with NULL
  and an exited thread does not hand its values to a fresh thread.
  Microsoft documents that `TlsAlloc` initializes the storage slots for the
  new index to zero ("The slots for the index are initialized to zero"), so
  the NULL initial state is a property of index **creation**, not of
  `TlsFree`; the row does not rely on `TlsFree` clearing per-thread
  storage. Source:
  <https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-tlsalloc>;
* the stored `void *` is **caller-owned**: no destructor runs, nothing is
  freed on clear or destroy;
* `create()`/`destroy()` are not internally synchronised, and `destroy()`
  requires prior quiescence of every thread that can still use the slot;
* a live slot must not be copied: there is no registry, no generation
  counter and no anti-stale-copy protection;
* native index 0 is a valid slot, never a falsey sentinel: validity lives
  in the handle's lifecycle tag.

### Probe (`tests/host_tls_probe.c`)

One battery runs twice: first against the real backend (every check must
pass), then against five fixture-only wrong backends (each must be
rejected by the SAME battery). The product header exposes no hook for
this; the seam is a small function table inside the fixture.

Checks: NULL arguments, lifecycle misuse with handle-field snapshots (a
failing init/create/destroy must leave the handle unchanged), output
sentinel checks on failing get, initial NULL, set/replace/clear, two and
four simultaneous slots staying independent, destroy + recreate, and
real `CreateThread` isolation phases driven by manual-reset events (no
sleeps make a phase deterministic): main + two workers hold distinct
values at once, each sees only its own, a replacement or clear in one
thread does not disturb the others, and a writer thread that exits
without clearing is followed by a fresh reader on the same live slot
that must see NULL. Eight rounds of that protocol.

Infrastructure failures (CreateEvent/CreateThread failure, phase-gate
timeout, join timeout, or `HOST_TLS_ERR_ALLOCATION` where success is
required — no fixture backend injects allocation failure) are not check
failures: the harness prints `FATAL: ...` and terminates the process
immediately with `ExitProcess(1)`, without closing handles or reading
results from a thread that may still be running. A harness failure can
therefore never be reported as "the negative backend was rejected" — the
CTest case just fails. The process-global negative's fixture table
likewise aborts the probe when full instead of returning a fake error, so
it cannot mutate a handle or be miscounted as a rejection.

Negative backends and their expected rejection profile:

| Backend | Defect | Must pass sequential |
|---|---|---|
| `negative-process-global-storage` | value store is process-global **per slot** instead of per thread (passes single-threaded use exactly) | yes; must fail only the thread checks |
| `negative-aliased-slots` | every slot aliases one shared TLS storage | no (fails slot independence) |
| `negative-clear-noop` | `set(NULL)` is silently ignored | no |
| `negative-output-clobber` | a failing get writes to the output first | no |
| `negative-null-is-error` | an empty slot is reported as a platform failure | no |

The fixture's own cross-thread state is serialised (SRWLOCK in the
process-global negative, a single real TLS index in the aliasing one), so
the negatives add no data race of their own. Failures are split into
sequential and thread-phase counters, and the process-global negative is
required to have `0` sequential failures — otherwise the probe fails, so
it cannot be "rejected" for an unintended, easier-to-spot defect.

Exit status is the result: no `PASS_REGULAR_EXPRESSION`, no `WILL_FAIL`
and no `assert()`. CTest applies an external 180 s timeout on top of the
bounded waits inside the probe.

### Local evidence and commands

External build dirs (with spaces) and the Visual Studio 18 generator:

```cmd
cmake -S "<repo>" -B "C:\Users\IKER\mn tls build\debug" -G "Visual Studio 18 2026" -A x64
cmake --build "C:\Users\IKER\mn tls build\debug" --config Debug
ctest --test-dir "C:\Users\IKER\mn tls build\debug" -C Debug --output-on-failure
:: same for -C Release in "C:\Users\IKER\mn tls build\release"
```

Local results (MSVC 19.51, VS 18, `/W4`, no warnings):

* Debug: 6/6 CTest pass. Release: 6/6 CTest pass.
* `host_tls_probe.exe` (Debug and Release, exit 0):

```
[coverage] the first real slot received native index 1; no native index 0 was observed, so the zero-index path was not exercised (no foreign index is freed to force it)
checked: 'negative-process-global-storage' rejected by 0 sequential + 17 thread check(s)
checked: 'negative-aliased-slots' rejected by 8 sequential + 2 thread check(s)
checked: 'negative-clear-noop' rejected by 3 sequential + 4 thread check(s)
checked: 'negative-output-clobber' rejected by 3 sequential + 0 thread check(s)
checked: 'negative-null-is-error' rejected by 5 sequential + 12 thread check(s)
PASS: host TLS slot battery (8 thread rounds, zero-native-index not observed) and 5 rejected negative backends
```

The exact thread-phase counts for `negative-process-global-storage` move by a
unit or two between runs (17 and 18 were both observed) because they depend
on which participant's value happened to be stored last, but the rejection
itself and the split are invariant: `0` sequential failures (the defect must
look correct to a single thread) and at least one thread-phase failure. The
acceptance logic uses only `> 0` and the split, never a count, so this does
not make the probe order-dependent.

Additional out-of-tree local evidence (**not** a committed regression
test, and no external artefact is stored in this repository): an
external audit program (`audit.c`, built with `/W4 /WX` against the same
`src/host_tls.c`) drives a **real** `TlsAlloc` exhaustion. Debug and
Release both pass with exit 0:

```
PASS: allocation exhaustion after 1086 live slots; unchanged handle, retry, survivor values and cleanup (0 failures)
```

That audit shows, on a genuine platform failure: exhaustion is reported
as `HOST_TLS_ERR_ALLOCATION`, the failed handle is unchanged and still
ready, freeing one index lets that same handle retry successfully (and
the new slot reads NULL), previously stored values in the surviving
slots are intact, and all slots can then be destroyed. It is recorded as
evidence only; the committed probe deliberately does not force platform
failures.

Repetition evidence (out-of-tree logs, not committed): a lead rerun of
`ctest -R "^host_tls_slot_probe$" --repeat until-fail:100` in both the Debug
and the Release build dirs finished with ctest exit `0` and `100/100`
passes in each configuration (`Start 6` × 100, `Passed` × 100, `100% tests
passed, 0 tests failed out of 1`). This is repetition stability evidence
for the thread-phase protocol; it adds no new exit condition.

`HOST_TLS_ERR_ALLOCATION`-on-required-success evidence (out-of-tree, not
committed): a review harness includes the probe with `main` renamed and
calls `expect_result(HOST_TLS_ERR_ALLOCATION, HOST_TLS_OK)` directly.
Built with `/W4 /WX` in Debug and Release, both terminate with exit code
exactly `1`, empty stdout and the exact stderr line

```
FATAL: probe infrastructure failed: a native TLS index allocation failed where success was required
```

so a real allocation failure aborts the probe and can never be counted as
a rejected negative backend.

### Limitations

* **Native index 0 is not observed in the local runs.** The first real slot
  received native index 1 and no slot received 0, so that path is
  documented, not exercised. Validity is the lifecycle tag and never the
  index value, and no foreign index is freed to manufacture an index-0 slot.
  That index 0 was never handed out here is reported as an observation of
  these runs only, not as a platform guarantee or an unreachability claim.
* `TlsGetValue` / `TlsSetValue` / `TlsFree` failure paths are implemented
  and mapped to `HOST_TLS_ERR_PLATFORM`. `TlsAlloc` exhaustion is exercised
  by the out-of-tree audits below, not by the committed probe; the
  committed probe also does not force get/set/free platform errors (an
  invalid-index get/free failure would require violating the lifecycle
  preconditions, and a `TlsSetValue`
  `ERROR_NOT_ENOUGH_MEMORY` failure is not manufactured).
* No guest TLS/TLR, no thread environment, no key destructor, no guest
  key page, no guest register/AOT ABI and no integration with
  `runtime_keys[]` / `g_keythr` (the Mac code stays untouched).
* The API is not a synchronisation primitive and is not a thread
  lifecycle API: it does not create, start, join or wake threads. The
  thread/synchronisation row remains `NOT STARTED`.

## G1 host VM, thread, synchronisation and logging (host primitives)

These rows add narrow **host** primitives only. They do not implement the
guest address strategy, the guest thread ABI/scheduler, guest
synchronization objects or a guest diagnostic service. The Mac sources
remain the behavioural reference and are unchanged.

### APIs

| Module | Header | Contract (host only) |
|---|---|---|
| VM | `src/host_vm.h` | Owning opaque region handle over reserve / commit / decommit / protect / query / flush. Anonymous private pages. **`commit` requires the whole range reserved and rejects any committed/mixed range before any mutating native call** (D009); decommit/protect require every page committed; query reports the OS's own view; zero size is `INVALID_ARGUMENT`. `<windows.h>`-free. |
| Thread | `src/host_thread.h` | `_beginthreadex`/`_endthreadex` host-C callback, bounded join with `CloseHandle` checked, poll-before-id self-join guard, close-without-wait that does not extend the caller-owned argument's lifetime. `<windows.h>`-free. |
| Mutex/condition | `src/host_sync.h` | SRWLOCK exclusive + CONDITION_VARIABLE, heap-backed typed handles. Predicate contract: wait may wake spuriously and wakes are not stored; re-check the predicate. On a `host_cond_wait` platform failure the lock state is UNKNOWN (fatal). `<windows.h>`-free. |
| Logging | `src/host_log.h` | Explicit handle; whole record `[LEVEL] tid=0x<8 hex> <message>\n` formatted then `fwrite`+`fflush` under a per-handle lock; filtering; explicit `...<truncated>` marker; `host_log_close` returns its own flush/close result and always consumes the handle. No timestamps/rotation/callbacks/singleton and no process-global buffering mutation. `<windows.h>`-free. |

### Probes and negative controls

* `tests/host_vm_probe.c`: drives the real backend and checks the OS's own
  page map with raw `VirtualQuery`, plus a probe-local SEH guarded-access
  pair (a write/read that must succeed vs. one that must fault). Rejects
  recommit of RO, RX, all-committed and mixed reserved/committed ranges
  (protection and contents independently unchanged), zero-size
  commit/decommit/protect, misaligned/out-of-range/overflow, unknown
  protect bits, and reserved-page decommit/protect. The SEH fixture is
  **not** the runtime fault row.
* `tests/host_thread_probe.c`: real lifecycle battery plus two behavioural
  fakes (`negative-join-ignores-wait`, `negative-join-always-times-out`)
  rejected only by the join behaviour they break; real-only self-join,
  close-while-running (gated worker, later join refused, worker body still
  runs) and create→join→reuse-spent-handle phases; a failed call must leave
  the handle's fields unchanged.
* `tests/host_sync_probe.c`: lifecycle battery (real only, including
  destroy→reinit), mutex-exclusion
  battery (real + `negative-mutex-noop`), condition-variable battery (real
  + `negative-cond-signal-noop`, `negative-cond-broadcast-as-signal`,
  `negative-cond-wait-times-out`, all using a GENUINE mutex so no wrong
  backend is UB). A worker `ready` event precedes the exclusion window;
  bounded predicate loops tolerate spurious wakes; broadcast requires a
  NON-timeout wake; the timeout is lower-bounded with an independent
  `QueryPerformanceCounter`; infrastructure failures `FATAL`/`ExitProcess(1)`.
* `tests/host_log_probe.c`: shape/filter/truncation, CR/LF/NUL normalisation
  (one call = exactly one line), 4 writers × 200 records verified as one
  complete non-interleaved stream, a corrupted-stream checker with 5 rejected
  synthetic negatives (interleaved, unterminated, missing, duplicated,
  malformed), a failing open must leave the output pointer untouched, and a
  real `HOST_LOG_ERR_IO` write forced through a `_pipe`/`_dup2` broken-stderr
  fixture (no public hook); temporary files are removed after each phase.

Exit status is the result in every probe: no `PASS_REGULAR_EXPRESSION`, no
`WILL_FAIL`, no `assert()`; bounded waits and CTest timeouts guard a wedged
process.

### Local evidence and commands

External build dirs (with spaces) and the Visual Studio 18 generator:

```cmd
cmake -S "<repo>" -B "C:\Users\IKER\mn g1\debug" -G "Visual Studio 18 2026" -A x64
cmake --build "C:\Users\IKER\mn g1\debug" --config Debug
ctest --test-dir "C:\Users\IKER\mn g1\debug" -C Debug --output-on-failure
:: same for -C Release in a separate external build dir
```

Local results (MSVC 19.51, VS 18, `/W4`, no warnings): Debug 10/10 CTest,
Release 10/10 CTest. Direct probe output (Debug):

```
checked: 'negative-join-ignores-wait' rejected by 1 check(s)
checked: 'negative-join-always-times-out' rejected by 1 check(s)
checked: 'negative-mutex-noop' rejected by 1 check(s)
checked: 'negative-cond-signal-noop' rejected by 2 check(s)
checked: 'negative-cond-broadcast-as-signal' rejected by 2 check(s)
checked: 'negative-cond-wait-times-out' rejected by 5 check(s)
PASS: host VM reserve/commit/decommit/protect/release/query/flush battery ...
PASS: host logging battery (4 writers x 200 records) ...
```

Repetition evidence (out-of-tree logs, not committed): a lead rerun of
`ctest -R "host_(thread_lifecycle|sync_mutex_cond|vm_region|log)_probe"
--repeat until-fail:20` in the external Debug and Release build dirs finished
with ctest exit `0`; each of the four tests ran Start/Passed 20 times (80
new-probe runs per configuration, 160 total, ~176 s each). This is stability
evidence only and adds no new exit condition.

The hosted CI configures the same project with `-DCMAKE_C_FLAGS=/WX`, so the
`/W4` warnings that are clean locally also fail the hosted build.

### Limitations

* The VM `range_all_state` `VirtualQuery`-failure→`PLATFORM` path and the OS
  `HOST_VM_ERR_ALLOCATION`/`HOST_VM_ERR_PLATFORM` results are implemented but
  **not forced**. File/COW/alias mapping and fixed guest VA layout are G3.
* Thread `HOST_THREAD_ERR_WAIT`, sync `HOST_SYNC_ERR_PLATFORM` and backend
  allocation failures are implemented but **not forced**.
* `host_log_close`'s OWN flush/close IO failure is **not forced**: stderr is
  unbuffered, so its close flush is clean (the write path's `ERR_IO` *is*
  forced). An owned file sink whose `fclose` fails is not exercised.
* No guest ABI, scheduler, guest objects, fault policy or guest VA strategy.

## Toolchain requirements

* Windows 10/11 x86-64 host (`AMD64` per `CMAKE_SYSTEM_PROCESSOR`).
* **Visual Studio with the "Desktop development with C++"
  workload.** A bare VS install without the C++ workload does NOT
  provide `cl.exe`, the Windows SDK headers, or the linker that
  this row needs. The Visual Studio generator auto-detects MSVC
  after the workload is installed; no manual `PATH` editing is
  required for hosted runners.
* The MSVC-bundled CMake under
  `Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe`
  is sufficient. No third-party CMake is required.
* No additional SDK, LLVM, game data, keys, NSO/NSZ files, JIT,
  AOT translation, network access or admin privileges are used
  by this row.

## Reproducible developer build / run

```cmd
:: 1. Initialise the x64 MSVC environment.
call "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" -arch=amd64 -host_arch=amd64
:: (Adjust the path for VS 18 / BuildTools / Enterprise if needed.)

:: 2. Configure out-of-source. -A x64 selects the AMD64 target.
cmake -S "%CD%" -B "%TEMP%\mn-build-x64" -A x64

:: 3. Build (any multi-config works; Debug mirrors local validation).
cmake --build "%TEMP%\mn-build-x64" --config Debug

:: 4. Run the CTest suite.
ctest --test-dir "%TEMP%\mn-build-x64" -C Debug --output-on-failure

:: 5. Direct invocation (identical assertions live in the ctest harness).
"%TEMP%\mn-build-x64\Debug\host_check.exe"
echo default exit=%ERRORLEVEL%

"%TEMP%\mn-build-x64\Debug\host_check.exe" --negative-control
echo negative-control exit=%ERRORLEVEL%

"%TEMP%\mn-build-x64\Debug\romfs_probe.exe"
echo romfs_probe exit=%ERRORLEVEL%

"%TEMP%\mn-build-x64\Debug\host_time_convert_test.exe"
echo host_time_convert_test exit=%ERRORLEVEL%

"%TEMP%\mn-build-x64\Debug\host_time_probe.exe"
echo host_time_probe exit=%ERRORLEVEL%

"%TEMP%\mn-build-x64\Debug\host_tls_probe.exe"
echo host_tls_probe exit=%ERRORLEVEL%

"%TEMP%\mn-build-x64\Debug\host_vm_probe.exe"
echo host_vm_probe exit=%ERRORLEVEL%

"%TEMP%\mn-build-x64\Debug\host_thread_probe.exe"
echo host_thread_probe exit=%ERRORLEVEL%

"%TEMP%\mn-build-x64\Debug\host_sync_probe.exe"
echo host_sync_probe exit=%ERRORLEVEL%

"%TEMP%\mn-build-x64\Debug\host_log_probe.exe"
echo host_log_probe exit=%ERRORLEVEL%

:: 6. Verify the unsupported-target guard (Win32) fires locally.
cmake -S "%CD%" -B "%TEMP%\mn-reject-win32" -A Win32 > "%TEMP%\mn-reject-win32.log" 2>&1
if errorlevel 1 (
  findstr /C:"supports ONLY 64-bit pointers" "%TEMP%\mn-reject-win32.log"
) else (
  echo FAIL: 32-bit target was accepted & exit /b 1
)
```

The `> log 2>&1` redirection order in step 6 is mandatory; the
reverse order leaves stderr on the terminal and produces a silent
"looks-empty" log.

### Expected results

| Command                                  | Expected exit | Expected output                                                |
|------------------------------------------|---------------|----------------------------------------------------------------|
| `host_check.exe`                         | 0             | stdout: `[host] pointer width = 8 byte(s)` then `PASS: host architecture satisfied` |
| `host_check.exe --negative-control`      | 1 (exact)     | stderr line: `[negative-control] FAIL: expected pointer width 4 byte(s), got 8` |
| `romfs_probe.exe`                        | 0             | stdout: `PASS: 27 RomFS path cases`                            |
| `host_time_convert_test.exe`             | 0             | stdout: `PASS: 20 conversion cases + 5 negative controls`      |
| `host_time_probe.exe`                    | 0             | stdout: `PASS: live host monotonic clock + scale check; negative controls rejected (...)` |
| `host_tls_probe.exe`                     | 0             | stdout: five `checked: '<negative>' rejected by ...` lines then `PASS: host TLS slot battery (...)`; the `[coverage]` line is on stdout when native index 0 was observed and on stderr otherwise |
| `host_vm_probe.exe`                      | 0             | stdout: `PASS: host VM reserve/commit/decommit/protect/release/query/flush battery ...` |
| `host_thread_probe.exe`                  | 0             | stdout: two `checked: '<negative>' rejected by ...` lines then `PASS: host thread lifecycle battery ...` |
| `host_sync_probe.exe`                    | 0             | stdout: four `checked: '<negative>' rejected by ...` lines then `PASS: host mutex/condition batteries ...` |
| `host_log_probe.exe`                     | 0             | stdout: `checked: stream checker rejects ...` then `PASS: host logging battery ...` |
| `cmake ... -A Win32`                     | non-zero      | configure error containing `supports ONLY 64-bit pointers`    |

The negative-control failure is deliberate: it proves the runtime
checker actually compares expected vs. actual pointer widths and
surfaces the discrepancy on a single literal line. A "hello world"
harness that unconditionally returned 0 (or returned 0 with a
wrong diagnostic) would be rejected by the ctest harness and by
direct invocation.

## Verifier behaviour

`tests/verify_host_negative_control.cmd` invokes the host with
`--negative-control`, captures stdout+stderr, and requires BOTH:

* exit code is exactly `1`, and
* the line `[negative-control] FAIL: expected pointer width 4 byte(s), got 8`
  appears verbatim (`findstr /L /X`).

The only proven run on this branch is against the real
`host_check.exe --negative-control` (the CTest entry
`host_check_negative_control` plus the direct invocation in step 5
above). Exercising the verifier against alternative fixtures would
require additional fixture executables and is intentionally out of
scope for this row.

## What this row does **not** deliver

* No guest address strategy: the VM row is the host anonymous private
  reserve/commit primitive only. File/COW/alias mapping and fixed guest VA
  layout are G3.
* No guest TLS/TLR, no thread environment, no key destructor and no
  guest TLS/register ABI. The TLS row above covers the **host** TLS slot
  lifecycle (and only that).
* No guest thread ABI/scheduler and no guest synchronization objects: the
  thread/sync rows above cover **host** threads and the host mutex/condition
  pair only.
* No fault / vectored-exception handling policy. The VM probe's local SEH
  fixture is a probe-local guarded-access control, not the fault row.
* No translated-module loader.
* No Horizon service ports for the game.
* No RomFS mounting, save-path or filesystem probe beyond the
  pure-C `romfs_path_relative` validator that already shipped in
  `games/totk/runtime/romfs_path.h` and is exercised unchanged by
  `tests/test_romfs_paths.c`.
* No NVN / Vulkan / D3D12 bring-up.
* No controller, audio, frontend or VP9 movie playback.
* No packaging or installer.
* No 1.1.2 / 1.4.3 work.

Treat these rows as evidence that the Windows x86-64 configure / build /
test path and the host monotonic clock, host TLS slots, host virtual
memory, host threads, host mutex/condition pair and host core logger are
plausible end-to-end. Do not mark fault/exception handling, guest
TLS/TLR, the guest thread ABI/scheduler, downstream G1 rows or G2..G8
rows complete based on them.
