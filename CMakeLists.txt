# Build-skeleton row: Windows x86-64 host probes (G1 host-wrapper rows).
#
# What this CMake project does:
#   - rejects non-Windows and non-AMD64 hosts at configure time
#   - refuses in-source and source-subdirectory build dirs
#   - compiles the platform-neutral RomFS path probe unmodified
#   - compiles the small host_check host executable
#   - compiles the narrow host monotonic-clock library (timing row) and
#     its deterministic conversion tests plus live Windows probe
#   - compiles the narrow host TLS slot library (TLS row) and its
#     lifecycle/isolation probe, which also rejects fixture-only wrong
#     backends with the same battery
#   - compiles the narrow host thread, mutex/condition-variable, virtual-
#     memory and core-logging libraries (G1 host rows) and their probes.
#     Each probe carries the controls its contract needs: the VM probe uses
#     an independent raw VirtualQuery plus a guarded-access pair, the thread
#     and sync probes reject fixture-only wrong backends, and the logging
#     probe rejects corrupted streams plus a forced broken-sink write
#   - registers a CTest suite whose negative-control test verifies BOTH
#     the exact non-zero exit code AND the explicit diagnostic via
#     tests/verify_host_negative_control.cmd
#
# What this project does NOT do (see PORTING_STATUS.md): guest threads or
# their ABI, the guest scheduler, guest synchronization objects,
# fault/exception handling, the guest virtual-address strategy, loader,
# AOT translation, graphics, audio, controller, frontend, packaging.

cmake_minimum_required(VERSION 3.20)
project(MacNativeGamesWinX64 LANGUAGES C)

# ---- Platform / build-dir gates ----------------------------------------

# Host must be Windows.
if(NOT WIN32)
    message(FATAL_ERROR
        "This build supports ONLY Windows (D001). Detected system: "
        "${CMAKE_SYSTEM_NAME}. Use the Mac build for the legacy macOS path.")
endif()

# Target processor must be AMD64 / x86_64.
if(NOT CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64"
   AND NOT CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
    message(FATAL_ERROR
        "This build supports ONLY AMD64 / x86_64 (D001). Detected processor: "
        "${CMAKE_SYSTEM_PROCESSOR}.")
endif()

# Target pointer width must be 8 bytes. This guards cross-compile
# configurations (for example a Win32 build) whose host processor still
# appears as AMD64 but whose target sizeof(void *) is 4.
if(NOT CMAKE_SIZEOF_VOID_P STREQUAL "8")
    message(FATAL_ERROR
        "This build supports ONLY 64-bit pointers (D001). "
        "CMAKE_SIZEOF_VOID_P=${CMAKE_SIZEOF_VOID_P}, "
        "CMAKE_SYSTEM_PROCESSOR=${CMAKE_SYSTEM_PROCESSOR}.")
endif()

# Reject in-source and source-subdirectory builds so generated artefacts
# stay out of the tree (D006 / repository-hygiene rule). The check
# normalises paths to forward slashes and compares on the
# "<src>/..." boundary so a sibling directory such as "<src>-build/"
# is NOT mis-flagged.
file(TO_CMAKE_PATH "${CMAKE_SOURCE_DIR}" _src_norm)
file(TO_CMAKE_PATH "${CMAKE_BINARY_DIR}" _bin_norm)
set(_src_prefix "${_src_norm}/")
string(FIND "${_bin_norm}" "${_src_prefix}" _bin_in_src)
if(_bin_norm STREQUAL _src_norm OR _bin_in_src EQUAL 0)
    message(FATAL_ERROR
        "In-source or source-subdirectory builds are NOT supported. "
        "Re-run cmake with -B pointing at a directory OUTSIDE the source tree, "
        "for example: cmake -S ${_src_norm} -B C:/build/mn-x64 -A x64")
endif()

# ---- Compiler settings -------------------------------------------------

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(MSVC)
    add_compile_options(/W4 /utf-8)
endif()

# ---- Targets ------------------------------------------------------------

# Platform-neutral RomFS path probe, compiled unchanged. The
# `#include "../games/.../romfs_path.h"` resolves from tests/ so the
# source layout must stay intact.
add_executable(romfs_probe
    tests/test_romfs_paths.c
)

# host_check: small Windows x86-64 executable. Compile-time Win64/AMD64
# gates plus a single runtime checker shared between normal mode and the
# deliberate --negative-control mode.
add_executable(host_check
    src/host_check.c
)

# Timing row: narrow host monotonic-clock library. host_time_convert.c is
# pure integer/C with no Win32 dependency so the scaling is independently
# testable; host_time.c owns the QueryPerformanceCounter read.
add_library(host_time STATIC
    src/host_time.c
    src/host_time_convert.c
)
target_include_directories(host_time PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

# Deterministic conversion tests (fixed constants + own negative controls).
add_executable(host_time_convert_test
    tests/test_host_time_convert.c
)
target_link_libraries(host_time_convert_test PRIVATE host_time)

# Live Windows probe: nondecreasing reads + positive, correctly-scaled
# elapsed time against an independent GetTickCount64 reference.
add_executable(host_time_probe
    tests/host_time_probe.c
)
target_link_libraries(host_time_probe PRIVATE host_time)

# TLS row: narrow host TLS slot library. host_tls.c owns the Windows
# TlsAlloc/TlsGetValue/TlsSetValue/TlsFree calls; host_tls.h stays free of
# <windows.h> and of any guest TLS/ABI concept.
add_library(host_tls STATIC
    src/host_tls.c
)
target_include_directories(host_tls PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

# Lifecycle + real-thread isolation probe. It runs one battery against the
# real backend and against fixture-only wrong backends; exit status only.
add_executable(host_tls_probe
    tests/host_tls_probe.c
)
target_link_libraries(host_tls_probe PRIVATE host_tls)

# Thread row: narrow host thread-lifecycle library. host_thread.c owns the
# _beginthreadex/WaitForSingleObject/CloseHandle calls; host_thread.h stays
# free of <windows.h> and of any guest thread/ABI concept.
add_library(host_thread STATIC
    src/host_thread.c
)
target_include_directories(host_thread PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_executable(host_thread_probe
    tests/host_thread_probe.c
)
target_link_libraries(host_thread_probe PRIVATE host_thread)

# Synchronisation row: narrow host mutex + condition-variable library.
# host_sync.c owns the SRWLOCK + CONDITION_VARIABLE pair; host_sync.h stays
# free of <windows.h> and of any guest lock/event/handle concept.
add_library(host_sync STATIC
    src/host_sync.c
)
target_include_directories(host_sync PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_executable(host_sync_probe
    tests/host_sync_probe.c
)
target_link_libraries(host_sync_probe PRIVATE host_sync)

# Memory row: narrow host virtual-memory library. host_vm.c owns the
# VirtualAlloc/VirtualFree/VirtualProtect/VirtualQuery/FlushInstructionCache
# calls behind an owning region handle; host_vm.h stays free of <windows.h>
# and of any guest address/layout concept.
add_library(host_vm STATIC
    src/host_vm.c
)
target_include_directories(host_vm PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_executable(host_vm_probe
    tests/host_vm_probe.c
)
target_link_libraries(host_vm_probe PRIVATE host_vm)

# Logging row: narrow host core logger. host_log.c owns the sink and record
# formatting; host_log.h stays free of <windows.h>.
add_library(host_log STATIC
    src/host_log.c
)
target_include_directories(host_log PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_executable(host_log_probe
    tests/host_log_probe.c
)
target_link_libraries(host_log_probe PRIVATE host_log)

# ---- Tests --------------------------------------------------------------

enable_testing()

# Normal-mode test relies on the host's exit status (0 = pass, nonzero =
# fail). PASS_REGULAR_EXPRESSION is intentionally NOT set: CTest treats
# a regex match as pass even on a non-zero exit, which would mask host
# regressions.
add_test(NAME host_check_default
    COMMAND host_check
)

# Negative-control test. The driver script returns 0 ONLY when the host
# actually failed with the contracted non-zero exit AND emitted the
# expected "[negative-control] FAIL: ..." diagnostic. Exit code drives
# the result (no WILL_FAIL inversion, no PASS regex): a buggy host that
# exits 0, exits for the wrong reason, or omits the diagnostic makes
# the driver return nonzero, which CTest reports as FAIL.
add_test(NAME host_check_negative_control
    COMMAND ${CMAKE_SOURCE_DIR}/tests/verify_host_negative_control.cmd
        "$<TARGET_FILE:host_check>"
)

# Stand-alone RomFS probe test. Relies on the probe's exit status.
add_test(NAME romfs_path_cases
    COMMAND romfs_probe
)

# Deterministic clock-conversion tests. Exit status only; the executable
# itself fails if its checker accepts a deliberately wrong implementation.
add_test(NAME host_time_convert_cases
    COMMAND host_time_convert_test
)

# Live host clock probe. Exit status only. A generous external CTest
# timeout guards against a hung wait; the probe is not a benchmark.
add_test(NAME host_time_live_probe
    COMMAND host_time_probe
)
set_tests_properties(host_time_live_probe PROPERTIES TIMEOUT 60)

# Host TLS slot probe. Exit status only: it fails when the real backend
# misses a contract check OR when the same battery accepts a deliberately
# wrong backend. Every phase gate and thread join has its own bounded wait;
# this TIMEOUT only guards against a genuinely wedged process.
add_test(NAME host_tls_slot_probe
    COMMAND host_tls_probe
)
set_tests_properties(host_tls_slot_probe PROPERTIES TIMEOUT 180)

# Host thread lifecycle probe. Exit status only: it fails when the real
# backend misses a contract check OR when the same battery accepts a
# deliberately wrong backend. Every phase gate and join has a bounded wait.
add_test(NAME host_thread_lifecycle_probe
    COMMAND host_thread_probe
)
set_tests_properties(host_thread_lifecycle_probe PROPERTIES TIMEOUT 180)

# Host mutex/condition probe. Exit status only. Bounded waits keep it
# deterministic; the TIMEOUT only guards a genuinely wedged process.
add_test(NAME host_sync_mutex_cond_probe
    COMMAND host_sync_probe
)
set_tests_properties(host_sync_mutex_cond_probe PROPERTIES TIMEOUT 180)

# Host virtual-memory probe. Exit status only; it uses a local SEH fixture for
# guarded accesses and an independent VirtualQuery, not the wrapper.
add_test(NAME host_vm_region_probe
    COMMAND host_vm_probe
)
set_tests_properties(host_vm_region_probe PROPERTIES TIMEOUT 120)

# Host core-logging probe. Exit status only; the sink-error branch is forced
# through an external OS pipe, not a public hook.
add_test(NAME host_log_probe
    COMMAND host_log_probe
)
set_tests_properties(host_log_probe PROPERTIES TIMEOUT 180)
