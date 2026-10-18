# Windows x86-64 build (G1 build-skeleton row)

This document covers only the **G1 build-skeleton row** on the
`windows-x86-port` branch: a small Windows x86-64 host executable,
a platform-neutral RomFS probe compiled unchanged from
`tests/test_romfs_paths.c`, and a CTest suite whose
negative-control harness verifies BOTH the exact exit code AND the
exact diagnostic line printed by the host.

It explicitly does **not** cover: VM, timing, TLS, threads, fault
handling, AOT translation, the translated module loader, Horizon
services, audio, controller, frontend, graphics, packaging, or a
reproducible build of the full game. Those rows stay `NOT STARTED`
/ `RESEARCH` in `../PORTING_STATUS.md` until later work satisfies
their individual exit conditions.

There are now **two** independent build paths in the repository:

* **macOS (legacy, game-runtime path)** — `games/totk/Makefile`,
  Apple-silicon native, remains the only path that produces a
  playable game until later Windows rows close.
* **Windows x86-64 (this row only)** — `CMakeLists.txt`, builds a
  tiny host executable and the unchanged RomFS probe. It does not
  produce a runnable game.

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

Other G1 platform wrappers (memory, timing, TLS, threads, faults)
and every later milestone (G2..G8) are explicitly NOT STARTED.

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

:: 6. Verify the unsupported-target guard (Win32) fires locally.
cmake -S "%CD%" -B "%TEMP%\mn-reject-win32" -A Win32
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
* No monotonic clock / TLS abstraction.
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

Treat this row as evidence that the Windows x86-64 configure /
build / test path is now plausible end-to-end. Do not mark
downstream G1 or G2..G8 rows complete based on it.
