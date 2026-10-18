# Windows x86-64 build (G1 build-skeleton + host timing rows)

This document covers two narrow G1 rows on the `windows-x86-port`
branch:

* the **build-skeleton row**: a small Windows x86-64 host executable,
  a platform-neutral RomFS probe compiled unchanged from
  `tests/test_romfs_paths.c`, and a CTest suite whose negative-control
  harness verifies BOTH the exact exit code AND the exact diagnostic
  line printed by the host;
* the **host timing row**: a narrow Windows `QueryPerformanceCounter`
  monotonic-nanosecond primitive with deterministic conversion tests and
  a live Windows probe (see "G1 host monotonic clock" below).

It explicitly does **not** cover: VM, TLS, threads, fault handling, AOT
translation, the translated module loader, Horizon services, audio,
controller, frontend, graphics, packaging, or a reproducible build of
the full game. Those rows stay `NOT STARTED` / `RESEARCH` in
`../PORTING_STATUS.md` until later work satisfies their individual exit
conditions. In particular, the timing row validates the host monotonic
clock only; the combined **Timing/TLS** exit condition is still open
because no TLS abstraction exists yet.

There are now **two** independent build paths in the repository:

* **macOS (legacy, game-runtime path)** — `games/totk/Makefile`,
  Apple-silicon native, remains the only path that produces a
  playable game until later Windows rows close.
* **Windows x86-64 (these rows only)** — `CMakeLists.txt`, builds the
  small host executable, the unchanged RomFS probe, the host monotonic
  clock library and its conversion/live tests. It does not produce a
  runnable game.

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
| Live host clock probe (nondecreasing + unit scale) | VALIDATED (T) — Debug and Release CTest 5/5 |
| TLS abstraction                               | NOT STARTED — not part of the timing row            |

Other G1 platform wrappers (memory, TLS, threads, faults) and every
later milestone (G2..G8) are explicitly NOT STARTED. The timing row
below covers only the host monotonic clock.

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

* Debug: 5/5 CTest pass (existing 3 + `host_time_convert_cases` +
  `host_time_live_probe`).
* Release: 5/5 CTest pass.
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

Limitations: no suspend/standby test, no cross-thread ordering test, no
TLS (so the combined Timing/TLS exit condition is still incomplete), and
this is not a guest clock. The non-MSVC `__int128` fallback in the
conversion helper exists for portability but is not locally validated;
the tested path is MSVC x64. Hosted CI has not been executed from this
branch.

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

* No virtual-memory abstraction (`VirtualAlloc` page-protection
  tests remain `NOT STARTED`).
* No TLS abstraction. The host monotonic clock is covered by the timing
  row above; the combined Timing/TLS exit condition is still open.
* No thread pool or synchronisation primitives.
* No fault / vectored-exception handling probe.
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
test path and the host monotonic clock are plausible end-to-end. Do not
mark TLS, VM, threads, faults, downstream G1 or G2..G8 rows complete
based on them.
