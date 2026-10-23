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
# graphics, audio, controller, frontend, packaging. AOT translation is not
# built by default; the scoped G2 AOT proof is opt-in via
# -DMN_BUILD_AOT_PROOF=ON (see docs/g2-aot-proof.md).

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

# Narrow host CSPRNG primitive (G3 Start SVC 0x29 support).
add_library(host_random STATIC src/host_random.c)
target_include_directories(host_random PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_options(host_random PRIVATE /W4 /WX)
target_link_libraries(host_random PUBLIC bcrypt)

# Deterministic backend test: includes host_random.c with a fake private
# compile-time provider, so it must not link the real host_random object.
add_executable(host_random_backend_probe tests/aot/host_random_backend_probe.c)
target_include_directories(host_random_backend_probe PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_options(host_random_backend_probe PRIVATE /W4 /WX)
add_test(NAME host_random_backend COMMAND host_random_backend_probe)

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

# ---- Immutable RomFS provider (early G4 prerequisite, D020) -------------
#
# Deliberately NOT behind MN_BUILD_AOT_PROOF: the provider is plain C and must
# build and test without Python, LLVM, Unicorn/Capstone or any game data. It
# reuses the audited FIPS 180-4 SHA-256 from src/aot/aot_sha256.c and does not
# link the interpreter/runtime. The Windows file/path seam is private
# (src/romfs_file_win.*); the public header stays Windows-free.
add_library(romfs_provider STATIC
    src/romfs_provider.c
    src/romfs_file_win.c
    src/aot/aot_sha256.c
)
target_include_directories(romfs_provider PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_options(romfs_provider PRIVATE /W4 /WX)

# Hermetic fixture probe: tiny synthetic index/image/parts/overlays written to
# an EXTERNAL directory (the build dir), with independently pinned SHA-256
# expectations and no game data.
add_executable(romfs_provider_probe
    tests/romfs_provider_probe.c
)
target_link_libraries(romfs_provider_probe PRIVATE romfs_provider)
target_compile_options(romfs_provider_probe PRIVATE /W4 /WX)
add_test(NAME romfs_provider
    COMMAND romfs_provider_probe "${CMAKE_BINARY_DIR}")
set_tests_properties(romfs_provider PROPERTIES TIMEOUT 120)

# Wrong-implementation controls: the SAME sources with one test-only define
# that suppresses exactly one integrity check. Each must be rejected by the
# probe with the exact first failure listed in
# tests/romfs_provider_mutant_driver.c. Not registered as passing tests.
set(ROMFS_MUTANT_TARGETS "")
foreach(mut SKIP_INDEX_HASH SKIP_IMAGE_HASH)
    string(TOLOWER "${mut}" mut_lc)
    add_executable(romfs_provider_mut_${mut_lc}
        tests/romfs_provider_probe.c
        src/romfs_provider.c
        src/romfs_file_win.c
        src/aot/aot_sha256.c
    )
    target_include_directories(romfs_provider_mut_${mut_lc} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_compile_definitions(romfs_provider_mut_${mut_lc} PRIVATE
        MN_ROMFS_MUT_${mut})
    target_compile_options(romfs_provider_mut_${mut_lc} PRIVATE /W4 /WX)
    list(APPEND ROMFS_MUTANT_TARGETS "$<TARGET_FILE:romfs_provider_mut_${mut_lc}>")
endforeach()

# Native driver: the real probe must exit 0/PASS first, then each mutant must
# exit exactly 2 with its contracted first failure. No shell, no WILL_FAIL.
add_executable(romfs_provider_mutant_driver
    tests/romfs_provider_mutant_driver.c
)
target_compile_options(romfs_provider_mutant_driver PRIVATE /W4 /WX)
add_test(NAME romfs_provider_mutants
    COMMAND romfs_provider_mutant_driver "${CMAKE_BINARY_DIR}"
        "$<TARGET_FILE:romfs_provider_probe>"
        "$<TARGET_FILE:romfs_provider_mut_skip_index_hash>"
        "bad index digest is rejected"
        "$<TARGET_FILE:romfs_provider_mut_skip_image_hash>"
        "same-size changed image is rejected")
set_tests_properties(romfs_provider_mutants PROPERTIES TIMEOUT 180)

# ---- Early-G4 RomFS Start adapter (D020) --------------------------------
#
# A tiny AotProgHandler for ONLY the fs InitializeForApplication HOSTCALL. It
# borrows an owning provider and an EXPLICIT config, calls the real provider
# init at invocation time, publishes no guest Result and writes no guest state.
# Plain C, not behind MN_BUILD_AOT_PROOF; no Python/LLVM/game data.
add_library(g4_romfs_start_hle STATIC
    tests/aot/g4_romfs_start_hle.c
)
target_include_directories(g4_romfs_start_hle PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/aot
    ${CMAKE_CURRENT_SOURCE_DIR}/src/aot
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(g4_romfs_start_hle PUBLIC romfs_provider)
target_compile_options(g4_romfs_start_hle PRIVATE /W4 /WX)

add_executable(g4_romfs_start_hle_probe
    tests/aot/g4_romfs_start_hle_probe.c
)
target_link_libraries(g4_romfs_start_hle_probe PRIVATE g4_romfs_start_hle)
target_compile_options(g4_romfs_start_hle_probe PRIVATE /W4 /WX)
add_test(NAME g4_romfs_start_hle
    COMMAND g4_romfs_start_hle_probe "${CMAKE_BINARY_DIR}")
set_tests_properties(g4_romfs_start_hle PROPERTIES TIMEOUT 120)

# Wrong-adapter controls: a void body that clobbers x0, and one that skips the
# real provider init. Both must be rejected by the SAME probe with the exact
# first failure named here, via the same strict native driver.
set(G4_ROMFS_MUTANT_ARGS "")
foreach(pair "SKIP_INIT|success reports one successful HOSTCALL"
             "WRITE_X0|success writes no guest state")
    string(REPLACE "|" ";" parts "${pair}")
    list(GET parts 0 mut)
    list(GET parts 1 label)
    string(TOLOWER "${mut}" mut_lc)
    add_executable(g4_romfs_start_hle_mut_${mut_lc}
        tests/aot/g4_romfs_start_hle_probe.c
        tests/aot/g4_romfs_start_hle.c
        src/romfs_provider.c
        src/romfs_file_win.c
        src/aot/aot_sha256.c
    )
    target_include_directories(g4_romfs_start_hle_mut_${mut_lc} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/aot
        ${CMAKE_CURRENT_SOURCE_DIR}/src/aot
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_compile_definitions(g4_romfs_start_hle_mut_${mut_lc} PRIVATE
        MN_G4_ROMFS_MUT_${mut})
    target_compile_options(g4_romfs_start_hle_mut_${mut_lc} PRIVATE /W4 /WX)
    list(APPEND G4_ROMFS_MUTANT_ARGS
        "$<TARGET_FILE:g4_romfs_start_hle_mut_${mut_lc}>" "${label}")
endforeach()

add_test(NAME g4_romfs_start_hle_mutants
    COMMAND romfs_provider_mutant_driver "${CMAKE_BINARY_DIR}"
        "$<TARGET_FILE:g4_romfs_start_hle_probe>"
        ${G4_ROMFS_MUTANT_ARGS})
set_tests_properties(g4_romfs_start_hle_mutants PROPERTIES TIMEOUT 180)

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

# ---- G2 AOT proof (stage 1): offline ARM64 -> native C ------------------
#
# This is the first translated-execution proof. It is deliberately narrow:
#   - an owned ARM64 fixture (tests/aot/fixture_arith.s) is assembled OUTSIDE
#     the source tree with LLVM llvm-mc + llvm-objcopy;
#   - tools/aot/aot_translate.py decodes it, recovers a CFG from the explicit
#     manifest and emits straight-line native C basic blocks (no runtime
#     opcode switch/interpreter/JIT and no ARM64 payload loaded, decoded or
#     executed at runtime);
#   - tests/aot/aot_fixture_runner.c drives the existing aot_runtime directly
#     and checks the expected scalar result plus the SVC HLE event.
#
# D008 (full-module backend) stays OPEN; this is scoped evidence only.
#
# Opt-in: default OFF so the existing G1 build/CI neither builds nor depends
# on LLVM, Python, Unicorn or Capstone. Enable with -DMN_BUILD_AOT_PROOF=ON
# and, on a fresh machine, point the cached tools explicitly, e.g.
#   -DAOT_LLVM_MC=<...> -DAOT_LLVM_OBJCOPY=<...> -DAOT_PYTHON=<python.exe>
# The dev-only oracle/decoder deps are pinned in tools/aot/requirements.txt.
option(MN_BUILD_AOT_PROOF "Build the G2 AOT offline-translation proof (opt-in)" OFF)
if(MN_BUILD_AOT_PROOF)
    find_program(AOT_LLVM_MC NAMES llvm-mc llvm-mc.exe)
    find_program(AOT_LLVM_OBJCOPY NAMES llvm-objcopy llvm-objcopy.exe)
    # G3 module-loader fixtures also need the ELF linker and the readelf the
    # independent reference checker consumes. They normally sit next to llvm-mc;
    # default to that directory, and allow an explicit override.
    if(AOT_LLVM_MC)
        get_filename_component(AOT_LLVM_BIN_DIR "${AOT_LLVM_MC}" DIRECTORY)
    endif()
    # find_program() skips a name that already exists in the cache (even as an
    # empty string), so each lookup goes through a scratch variable first.
    set(AOT_LLD "" CACHE FILEPATH "ld.lld for the G3 fixture modules")
    if(NOT AOT_LLD)
        find_program(AOT_LLD_FOUND NAMES ld.lld ld.lld.exe
            HINTS "${AOT_LLVM_BIN_DIR}")
        if(AOT_LLD_FOUND)
            set(AOT_LLD "${AOT_LLD_FOUND}" CACHE FILEPATH
                "ld.lld for the G3 fixture modules" FORCE)
        endif()
    endif()
    set(AOT_LLVM_READELF "" CACHE FILEPATH "llvm-readelf for G3 link checks")
    if(NOT AOT_LLVM_READELF)
        find_program(AOT_LLVM_READELF_FOUND NAMES llvm-readelf llvm-readelf.exe
            HINTS "${AOT_LLVM_BIN_DIR}")
        if(AOT_LLVM_READELF_FOUND)
            set(AOT_LLVM_READELF "${AOT_LLVM_READELF_FOUND}" CACHE FILEPATH
                "llvm-readelf for G3 link checks" FORCE)
        endif()
    endif()
    set(AOT_PYTHON "" CACHE FILEPATH
        "Python interpreter for tools/aot; must import unicorn==2.1.4 and capstone==5.0.7")
    if(NOT AOT_LLVM_MC OR NOT AOT_LLVM_OBJCOPY OR NOT AOT_LLD)
        message(FATAL_ERROR
            "MN_BUILD_AOT_PROOF=ON requires llvm-mc, llvm-objcopy and ld.lld. "
            "Install an LLVM toolchain on PATH and/or pass -DAOT_LLVM_MC=<path> "
            "-DAOT_LLVM_OBJCOPY=<path> -DAOT_LLD=<path>.")
    endif()
    if(NOT AOT_PYTHON)
        find_package(Python3 COMPONENTS Interpreter QUIET)
        if(Python3_Interpreter_FOUND)
            set(AOT_PYTHON "${Python3_EXECUTABLE}")
        endif()
    endif()
    if(NOT AOT_PYTHON OR NOT EXISTS "${AOT_PYTHON}")
        message(FATAL_ERROR
            "MN_BUILD_AOT_PROOF=ON requires a Python interpreter. Pass "
            "-DAOT_PYTHON=<python.exe>; dev deps are pinned in "
            "tools/aot/requirements.txt (unicorn==2.1.4, capstone==5.0.7).")
    endif()

    # Runtime core shared by every native AOT executable: dispatcher, guest
    # memory, the G3 address space and the G3 multi-image Program table.
    set(AOT_CORE_SRC
        "${CMAKE_SOURCE_DIR}/src/aot/aot_runtime.c"
        "${CMAKE_SOURCE_DIR}/src/aot/aot_mem.c"
        "${CMAKE_SOURCE_DIR}/src/aot/aot_as.c"
        "${CMAKE_SOURCE_DIR}/src/aot/aot_program.c")
    set(AOT_FP_SRC "${CMAKE_SOURCE_DIR}/src/aot/aot_fp.c")

    # Manual real-module probes are not linked by CMake: they need external
    # flats and generated descriptors. Compile each as an object here so ABI
    # mistakes (callback signatures, printf arguments) are caught by the
    # regular /W4 /WX build instead of only by an external ad-hoc cl.exe run.
    # Separate targets: both files define main(), so one OBJECT library would
    # emit a duplicate-symbol linker warning.
    foreach(_probe aot_g3_dtinit_probe aot_g3_start_probe)
        add_library(${_probe}_compile OBJECT tests/aot/${_probe}.c)
        target_include_directories(${_probe}_compile PRIVATE
            "${CMAKE_SOURCE_DIR}/src/aot"
            "${CMAKE_SOURCE_DIR}/src")
        target_compile_options(${_probe}_compile PRIVATE /W4 /WX)
    endforeach()
    add_library(aot_g3_start_hle_compile OBJECT tests/aot/g3_start_hle.c)
    target_include_directories(aot_g3_start_hle_compile PRIVATE
        "${CMAKE_SOURCE_DIR}/src/aot"
        "${CMAKE_SOURCE_DIR}/src")
    target_compile_options(aot_g3_start_hle_compile PRIVATE /W4 /WX)

    # Game-data-free native test of the minimal GetInfo(id 11) HLE.
    add_executable(aot_g3_start_hle_probe
        tests/aot/g3_start_hle_probe.c
        tests/aot/g3_start_hle.c
        ${AOT_CORE_SRC})
    target_include_directories(aot_g3_start_hle_probe PRIVATE
        "${CMAKE_SOURCE_DIR}/src/aot"
        "${CMAKE_SOURCE_DIR}/src")
    target_compile_options(aot_g3_start_hle_probe PRIVATE /W4 /WX)
    target_link_libraries(aot_g3_start_hle_probe PRIVATE host_random host_vm)
    add_test(NAME aot_g3_start_hle COMMAND aot_g3_start_hle_probe)

    # Real address-space rows for GetInfo(4/5) and SetHeapSize SVC 0x01
    # (host_vm_query witnesses the OS page state).
    add_executable(aot_g3_start_hle_heap_probe
        tests/aot/aot_g3_start_hle_heap_probe.c
        tests/aot/g3_start_hle.c
        ${AOT_CORE_SRC})
    target_include_directories(aot_g3_start_hle_heap_probe PRIVATE
        "${CMAKE_SOURCE_DIR}/src/aot"
        "${CMAKE_SOURCE_DIR}/src")
    target_compile_options(aot_g3_start_hle_heap_probe PRIVATE /W4 /WX)
    target_link_libraries(aot_g3_start_hle_heap_probe PRIVATE host_vm)
    add_test(NAME aot_g3_start_hle_heap COMMAND aot_g3_start_hle_heap_probe)
    set_tests_properties(aot_g3_start_hle_heap PROPERTIES TIMEOUT 120)

    # Whole-domain SVC 0x06: mapped records, Free holes, upper Inaccessible
    # extent, whole-span output faults and wrong-implementation controls.
    add_executable(aot_g3_start_hle_query_probe
        tests/aot/aot_g3_start_hle_query_probe.c
        tests/aot/g3_start_hle.c
        ${AOT_CORE_SRC})
    target_include_directories(aot_g3_start_hle_query_probe PRIVATE
        "${CMAKE_SOURCE_DIR}/src/aot"
        "${CMAKE_SOURCE_DIR}/src")
    target_compile_options(aot_g3_start_hle_query_probe PRIVATE /W4 /WX)
    target_link_libraries(aot_g3_start_hle_query_probe PRIVATE host_vm)
    add_test(NAME aot_g3_start_hle_query COMMAND aot_g3_start_hle_query_probe)
    set_tests_properties(aot_g3_start_hle_query PROPERTIES TIMEOUT 120)

    add_executable(aot_as_query_domain_probe
        tests/aot/aot_as_query_domain_probe.c ${AOT_CORE_SRC})
    target_include_directories(aot_as_query_domain_probe PRIVATE
        "${CMAKE_SOURCE_DIR}/src/aot" "${CMAKE_SOURCE_DIR}/src")
    target_compile_options(aot_as_query_domain_probe PRIVATE /W4 /WX)
    target_link_libraries(aot_as_query_domain_probe PRIVATE host_vm)
    add_test(NAME aot_g3_as_query_domain COMMAND aot_as_query_domain_probe)

    foreach(kind LOW_FROM_ADDR GAP_PAGE ABOVE_FREE)
        string(TOLOWER "${kind}" lower_kind)
        set(target "aot_as_domain_mut_${lower_kind}")
        add_executable(${target} tests/aot/aot_as_query_domain_probe.c ${AOT_CORE_SRC})
        target_include_directories(${target} PRIVATE
            "${CMAKE_SOURCE_DIR}/src/aot" "${CMAKE_SOURCE_DIR}/src")
        target_compile_options(${target} PRIVATE /W4 /WX)
        target_compile_definitions(${target} PRIVATE "MN_AOT_DOMAIN_MUT_${kind}")
        target_link_libraries(${target} PRIVATE host_vm)
    endforeach()
    foreach(kind PARTIAL_STORE MAPPED_ONLY)
        string(TOLOWER "${kind}" lower_kind)
        set(target "aot_g3_query_mut_${lower_kind}")
        add_executable(${target} tests/aot/aot_g3_start_hle_query_probe.c
            tests/aot/g3_start_hle.c ${AOT_CORE_SRC})
        target_include_directories(${target} PRIVATE
            "${CMAKE_SOURCE_DIR}/src/aot" "${CMAKE_SOURCE_DIR}/src")
        target_compile_options(${target} PRIVATE /W4 /WX)
        if(kind STREQUAL "PARTIAL_STORE")
            target_compile_definitions(${target} PRIVATE MN_AOT_MUTANT_PARTIAL_STORE)
        else()
            target_compile_definitions(${target} PRIVATE MN_G3_QUERY_MUT_MAPPED_ONLY)
        endif()
        target_link_libraries(${target} PRIVATE host_vm)
    endforeach()

    # SVC 0x0c/0x25 thread HLE: real borrowed registry + deterministic fake,
    # 32-bit handle truncation, pseudo alias, guest-id (not host TID) and
    # wrong-implementation controls.
    add_executable(aot_g3_start_hle_thread_probe
        tests/aot/aot_g3_start_hle_thread_probe.c
        tests/aot/g3_start_hle.c
        ${AOT_CORE_SRC})
    target_include_directories(aot_g3_start_hle_thread_probe PRIVATE
        "${CMAKE_SOURCE_DIR}/src/aot"
        "${CMAKE_SOURCE_DIR}/src")
    target_compile_options(aot_g3_start_hle_thread_probe PRIVATE /W4 /WX)
    target_link_libraries(aot_g3_start_hle_thread_probe PRIVATE host_vm)
    add_test(NAME aot_g3_start_hle_thread
             COMMAND aot_g3_start_hle_thread_probe)
    set_tests_properties(aot_g3_start_hle_thread PROPERTIES TIMEOUT 120)

    # GetInfo 6/21 (pool) and 7/22 (image + logical heap + 0 alias) against
    # the real AS heap, with grow/shrink/regrow and fail-closed budgets.
    add_executable(aot_g3_start_hle_budget_probe
        tests/aot/aot_g3_start_hle_budget_probe.c
        tests/aot/g3_start_hle.c
        ${AOT_CORE_SRC})
    target_include_directories(aot_g3_start_hle_budget_probe PRIVATE
        "${CMAKE_SOURCE_DIR}/src/aot"
        "${CMAKE_SOURCE_DIR}/src")
    target_compile_options(aot_g3_start_hle_budget_probe PRIVATE /W4 /WX)
    target_link_libraries(aot_g3_start_hle_budget_probe PRIVATE host_vm)
    add_test(NAME aot_g3_start_hle_budget
             COMMAND aot_g3_start_hle_budget_probe)
    set_tests_properties(aot_g3_start_hle_budget PROPERTIES TIMEOUT 120)

    # MapPhysicalMemory/UnmapPhysicalMemory (SVC 0x2c/0x2d) through the HLE and
    # the address-space page state: exact Mac Result codes, register ABI, real
    # host page state, QueryMemory runs and the GetInfo 7/22 alias term.
    add_executable(aot_g3_start_hle_alias_probe
        tests/aot/aot_g3_start_hle_alias_probe.c
        tests/aot/g3_start_hle.c
        ${AOT_CORE_SRC})
    target_include_directories(aot_g3_start_hle_alias_probe PRIVATE
        "${CMAKE_SOURCE_DIR}/src/aot"
        "${CMAKE_SOURCE_DIR}/src")
    target_compile_options(aot_g3_start_hle_alias_probe PRIVATE /W4 /WX)
    target_link_libraries(aot_g3_start_hle_alias_probe PRIVATE host_vm)
    add_test(NAME aot_g3_start_hle_alias
             COMMAND aot_g3_start_hle_alias_probe)
    set_tests_properties(aot_g3_start_hle_alias PROPERTIES TIMEOUT 120)

    # Mac HOST OVERRIDES reached from nn::init::Start (services.c:168-177).
    # Game-data-free: the probe resolves the name table and calls the entry
    # points directly, exactly like the Start-prefix registration driver does.
    add_executable(aot_g3_start_hle_override_probe
        tests/aot/aot_g3_start_hle_override_probe.c
        tests/aot/g3_start_hle.c
        ${AOT_CORE_SRC})
    target_include_directories(aot_g3_start_hle_override_probe PRIVATE
        "${CMAKE_SOURCE_DIR}/src/aot"
        "${CMAKE_SOURCE_DIR}/src")
    target_compile_options(aot_g3_start_hle_override_probe PRIVATE /W4 /WX)
    target_link_libraries(aot_g3_start_hle_override_probe PRIVATE host_vm)
    add_test(NAME aot_g3_start_hle_override
             COMMAND aot_g3_start_hle_override_probe)
    set_tests_properties(aot_g3_start_hle_override PROPERTIES TIMEOUT 120)

    # Wrong-implementation controls for the host overrides: each must be
    # rejected by aot_g3_start_hle_override_probe with the exact failure listed
    # in tools/aot/g3_mutant_test.py. Not registered as passing tests.
    foreach(mut OVERRIDE_X0 OVERRIDE_WRITE OVERRIDE_COUNT SKIP_BOOST_RANGE)
        string(TOLOWER "${mut}" mut_lc)
        add_executable(aot_g3_start_hle_mut_${mut_lc}
            tests/aot/aot_g3_start_hle_override_probe.c
            tests/aot/g3_start_hle.c
            ${AOT_CORE_SRC})
        target_include_directories(aot_g3_start_hle_mut_${mut_lc} PRIVATE
            "${CMAKE_SOURCE_DIR}/src/aot"
            "${CMAKE_SOURCE_DIR}/src")
        target_compile_options(aot_g3_start_hle_mut_${mut_lc} PRIVATE /W4 /WX)
        target_link_libraries(aot_g3_start_hle_mut_${mut_lc} PRIVATE host_vm)
        target_compile_definitions(aot_g3_start_hle_mut_${mut_lc} PRIVATE
            MN_G3_HLE_MUT_${mut})
    endforeach()

    # Wrong-implementation controls for the alias SVC: each must be rejected by
    # aot_g3_start_hle_alias_probe with the exact failure listed in
    # tools/aot/g3_mutant_test.py. Not registered as passing tests.
    foreach(mut ALIAS_LIMIT_CODE ALIAS_CLOBBER BUDGET_OMIT_ALIAS)
        string(TOLOWER "${mut}" mut_lc)
        add_executable(aot_g3_start_hle_mut_${mut_lc}
            tests/aot/aot_g3_start_hle_alias_probe.c
            tests/aot/g3_start_hle.c
            ${AOT_CORE_SRC})
        target_include_directories(aot_g3_start_hle_mut_${mut_lc} PRIVATE
            "${CMAKE_SOURCE_DIR}/src/aot"
            "${CMAKE_SOURCE_DIR}/src")
        target_compile_options(aot_g3_start_hle_mut_${mut_lc} PRIVATE /W4 /WX)
        target_link_libraries(aot_g3_start_hle_mut_${mut_lc} PRIVATE host_vm)
        target_compile_definitions(aot_g3_start_hle_mut_${mut_lc} PRIVATE
            MN_G3_HLE_MUT_${mut})
    endforeach()
    add_executable(aot_g3_start_hle_mut_alias_no_unmap
        tests/aot/aot_g3_start_hle_alias_probe.c
        tests/aot/g3_start_hle.c
        ${AOT_CORE_SRC})
    target_include_directories(aot_g3_start_hle_mut_alias_no_unmap PRIVATE
        "${CMAKE_SOURCE_DIR}/src/aot"
        "${CMAKE_SOURCE_DIR}/src")
    target_compile_options(aot_g3_start_hle_mut_alias_no_unmap PRIVATE /W4 /WX)
    target_link_libraries(aot_g3_start_hle_mut_alias_no_unmap PRIVATE host_vm)
    target_compile_definitions(aot_g3_start_hle_mut_alias_no_unmap PRIVATE
        MN_G3_HLE_MUT_ALIAS_NO_UNMAP)

    add_executable(aot_g3_start_hle_mut_sysres_const
        tests/aot/g3_start_hle_probe.c tests/aot/g3_start_hle.c ${AOT_CORE_SRC})
    target_include_directories(aot_g3_start_hle_mut_sysres_const PRIVATE
        "${CMAKE_SOURCE_DIR}/src/aot" "${CMAKE_SOURCE_DIR}/src")
    target_compile_options(aot_g3_start_hle_mut_sysres_const PRIVATE /W4 /WX)
    target_compile_definitions(aot_g3_start_hle_mut_sysres_const PRIVATE
        MN_G3_HLE_MUT_SYSRES_CONST)
    target_link_libraries(aot_g3_start_hle_mut_sysres_const PRIVATE host_random host_vm)

    # Wrong-implementation control: GetInfo(2/3) fake constants.
    add_executable(aot_g3_start_hle_mut_info_const
        tests/aot/aot_g3_start_hle_heap_probe.c
        tests/aot/g3_start_hle.c
        ${AOT_CORE_SRC})
    target_include_directories(aot_g3_start_hle_mut_info_const PRIVATE
        "${CMAKE_SOURCE_DIR}/src/aot"
        "${CMAKE_SOURCE_DIR}/src")
    target_compile_options(aot_g3_start_hle_mut_info_const PRIVATE /W4 /WX)
    target_link_libraries(aot_g3_start_hle_mut_info_const PRIVATE host_vm)
    target_compile_definitions(aot_g3_start_hle_mut_info_const PRIVATE
        MN_G3_HLE_MUT_INFO_CONST)
    # Wrong-implementation control: Info14/15 return the ALIAS geometry.
    add_executable(aot_g3_start_hle_mut_info14_alias
        tests/aot/aot_g3_start_hle_heap_probe.c
        tests/aot/g3_start_hle.c
        ${AOT_CORE_SRC})
    target_include_directories(aot_g3_start_hle_mut_info14_alias PRIVATE
        "${CMAKE_SOURCE_DIR}/src/aot"
        "${CMAKE_SOURCE_DIR}/src")
    target_compile_options(aot_g3_start_hle_mut_info14_alias PRIVATE /W4 /WX)
    target_link_libraries(aot_g3_start_hle_mut_info14_alias PRIVATE host_vm)
    target_compile_definitions(aot_g3_start_hle_mut_info14_alias PRIVATE
        MN_G3_HLE_MUT_INFO14_ALIAS)
    add_test(NAME aot_g3_start_prefix_classification
        COMMAND "${AOT_PYTHON}"
            "${CMAKE_SOURCE_DIR}/tests/aot/g3_start_prefix_test.py")
    add_test(NAME aot_g3_veneer_roots
        COMMAND "${AOT_PYTHON}"
            "${CMAKE_SOURCE_DIR}/tests/aot/g3_veneer_roots_test.py")
    add_test(NAME aot_g4_romfs_config
        COMMAND "${AOT_PYTHON}"
            "${CMAKE_SOURCE_DIR}/tests/aot/g4_romfs_config_test.py")
    set_tests_properties(aot_g4_romfs_config PROPERTIES TIMEOUT 120)

    set(AOT_FIXTURE_S   "${CMAKE_SOURCE_DIR}/tests/aot/fixture_arith.s")
    set(AOT_MANIFEST    "${CMAKE_SOURCE_DIR}/tests/aot/fixture_arith.manifest.json")
    set(AOT_GEN_DIR     "${CMAKE_BINARY_DIR}/aot_gen")
    set(AOT_FIXTURE_OBJ "${AOT_GEN_DIR}/fixture_arith.o")
    set(AOT_FIXTURE_BIN "${AOT_GEN_DIR}/fixture_arith.bin")
    set(AOT_FIXTURE_C   "${AOT_GEN_DIR}/fixture_blocks.c")

    add_custom_command(
        OUTPUT "${AOT_FIXTURE_BIN}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${AOT_GEN_DIR}"
        COMMAND "${AOT_LLVM_MC}" -triple=aarch64-none-elf -filetype=obj
                -o "${AOT_FIXTURE_OBJ}" "${AOT_FIXTURE_S}"
        COMMAND "${AOT_LLVM_OBJCOPY}" -O binary --only-section=.text
                "${AOT_FIXTURE_OBJ}" "${AOT_FIXTURE_BIN}"
        DEPENDS "${AOT_FIXTURE_S}"
        COMMENT "Assembling G2 ARM64 fixture with LLVM"
        VERBATIM)

    add_custom_command(
        OUTPUT "${AOT_FIXTURE_C}"
        COMMAND "${AOT_PYTHON}" "${CMAKE_SOURCE_DIR}/tools/aot/aot_translate.py"
                --manifest "${AOT_MANIFEST}"
                --bin "${AOT_FIXTURE_BIN}"
                --out "${AOT_FIXTURE_C}"
                --name fixture
        DEPENDS "${AOT_FIXTURE_BIN}"
                "${CMAKE_SOURCE_DIR}/tools/aot/aot_translate.py"
                "${AOT_MANIFEST}"
        COMMENT "Translating G2 ARM64 fixture to native C"
        VERBATIM)

    set_source_files_properties("${AOT_FIXTURE_C}" PROPERTIES GENERATED TRUE)
    add_executable(aot_fixture_runner
        tests/aot/aot_fixture_runner.c
        ${AOT_CORE_SRC}
        ${AOT_FP_SRC}
        "${AOT_FIXTURE_C}"
    )
    target_include_directories(aot_fixture_runner PRIVATE "${CMAKE_SOURCE_DIR}/src/aot")
    target_compile_options(aot_fixture_runner PRIVATE /W4 /WX)
    target_link_libraries(aot_fixture_runner PRIVATE host_vm)

    add_test(NAME aot_fixture_stage1
        COMMAND aot_fixture_runner
    )
    set_tests_properties(aot_fixture_stage1 PROPERTIES TIMEOUT 60)
endif()

# ---- G2 stage-2: differential fixture + binary-I/O native runner -------
if(MN_BUILD_AOT_PROOF)
    set(AOT_DIFF_S        "${CMAKE_SOURCE_DIR}/tests/aot/fixture_diff.s")
    set(AOT_DIFF_MANIFEST "${CMAKE_SOURCE_DIR}/tests/aot/fixture_diff.manifest.json")
    set(AOT_DIFF_OBJ      "${AOT_GEN_DIR}/fixture_diff.o")
    set(AOT_DIFF_BIN      "${AOT_GEN_DIR}/fixture_diff.bin")
    set(AOT_DIFF_C        "${AOT_GEN_DIR}/fixture_diff_blocks.c")
    set(AOT_DIFF_META     "${AOT_GEN_DIR}/fixture_diff.meta.json")

    # One owning custom target generates EVERY artifact of this fixture family
    # (object, binary, translated blocks, mutant blocks). Rationale: an
    # OUTPUT-based add_custom_command whose output is consumed by several
    # targets is copied into each of their vcxprojs, so parallel MSBuild runs
    # the same llvm-mc/objcopy/translate sequence concurrently on the same
    # paths and they clobber each other. With one target, generation happens
    # exactly once and every consumer only declares an ordering dependency.
    set(AOT_GEN_DIFF_INPUTS
        "${AOT_DIFF_S}" "${AOT_DIFF_MANIFEST}"
        "${CMAKE_SOURCE_DIR}/tools/aot/aot_translate.py")
    add_custom_target(aot_gen_diff
        COMMAND ${CMAKE_COMMAND} -E make_directory "${AOT_GEN_DIR}"
        COMMAND "${AOT_LLVM_MC}" -triple=aarch64-none-elf -filetype=obj
                -o "${AOT_DIFF_OBJ}" "${AOT_DIFF_S}"
        COMMAND "${AOT_LLVM_OBJCOPY}" -O binary --only-section=.text
                "${AOT_DIFF_OBJ}" "${AOT_DIFF_BIN}"
        COMMAND "${AOT_PYTHON}" "${CMAKE_SOURCE_DIR}/tools/aot/aot_translate.py"
                --manifest "${AOT_DIFF_MANIFEST}"
                --bin "${AOT_DIFF_BIN}"
                --out "${AOT_DIFF_C}"
                --meta-out "${AOT_DIFF_META}"
                --name diff
        DEPENDS ${AOT_GEN_DIFF_INPUTS}
        COMMENT "Generating G2 differential ARM64 fixture + blocks" VERBATIM)

    set_source_files_properties("${AOT_DIFF_C}" PROPERTIES GENERATED TRUE)
    # The translated blocks are consumed by SEVERAL targets, so they are
    # compiled ONCE into a static library instead of being listed (and thus
    # re-compiled / re-generated) in each of them.
    add_library(aot_diff_blocks STATIC "${AOT_DIFF_C}")
    add_dependencies(aot_diff_blocks aot_gen_diff)
    target_include_directories(aot_diff_blocks PRIVATE "${CMAKE_SOURCE_DIR}/src/aot")
    target_compile_options(aot_diff_blocks PRIVATE /W4 /WX)

    add_executable(aot_bin_runner
        tests/aot/aot_bin_runner.c
        ${AOT_CORE_SRC}
        ${AOT_FP_SRC}
    )
    target_include_directories(aot_bin_runner PRIVATE "${CMAKE_SOURCE_DIR}/src/aot")
    target_compile_options(aot_bin_runner PRIVATE /W4 /WX)
    target_link_libraries(aot_bin_runner PRIVATE host_vm aot_diff_blocks)
    add_dependencies(aot_bin_runner aot_gen_diff)

    add_test(NAME aot_differential_stage2
        COMMAND "${AOT_PYTHON}" "${CMAKE_SOURCE_DIR}/tools/aot/diff_driver.py"
                --exe "$<TARGET_FILE:aot_bin_runner>"
                --bin "${AOT_DIFF_BIN}"
                --meta "${AOT_DIFF_META}"
                --manifest "${AOT_DIFF_MANIFEST}"
                --work "${AOT_GEN_DIR}/diff_cases"
    )
    set_tests_properties(aot_differential_stage2 PROPERTIES TIMEOUT 600
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

    # ---- negative controls: real-lowering mutants on separate images ----
    set(AOT_MUT_NAMES wrongcarry lostwzeroext wrongcond blrorder strdrop
                       scalarupper pair32trunc fpdropflags stxalwaysok
                       fproundrn fpnanorder fpignoreguard)
    # Every mutant block file is generated by the SAME owning target: they are
    # all derived from the one fixture binary, so generating them up front
    # keeps a parallel build from racing on the shared .o/.bin.
    foreach(mut ${AOT_MUT_NAMES})
        set(AOT_MUT_C   "${AOT_GEN_DIR}/mut_${mut}.c")
        set(AOT_MUT_META "${AOT_GEN_DIR}/mut_${mut}.meta.json")
        add_custom_command(TARGET aot_gen_diff POST_BUILD
            COMMAND "${AOT_PYTHON}" "${CMAKE_SOURCE_DIR}/tools/aot/aot_translate.py"
                    --manifest "${AOT_DIFF_MANIFEST}" --bin "${AOT_DIFF_BIN}"
                    --out "${AOT_MUT_C}" --meta-out "${AOT_MUT_META}"
                    --name diff --mutant ${mut}
            COMMENT "Translating negative-control mutant ${mut}" VERBATIM)
        set_source_files_properties("${AOT_MUT_C}" PROPERTIES GENERATED TRUE)
        add_executable(aot_mut_${mut}
            tests/aot/aot_bin_runner.c
            ${AOT_CORE_SRC}
            ${AOT_FP_SRC}
            "${AOT_MUT_C}")
        target_include_directories(aot_mut_${mut} PRIVATE "${CMAKE_SOURCE_DIR}/src/aot")
        target_compile_options(aot_mut_${mut} PRIVATE /W4 /WX)
        target_link_libraries(aot_mut_${mut} PRIVATE host_vm)
        add_dependencies(aot_mut_${mut} aot_gen_diff)
    endforeach()

    # HLE-callback mutant (real callback mutation via a test-only compile define).
    add_executable(aot_mut_hlex18
        tests/aot/aot_bin_runner.c
        ${AOT_CORE_SRC}
        ${AOT_FP_SRC})
    target_include_directories(aot_mut_hlex18 PRIVATE "${CMAKE_SOURCE_DIR}/src/aot")
    target_compile_options(aot_mut_hlex18 PRIVATE /W4 /WX)
    target_link_libraries(aot_mut_hlex18 PRIVATE host_vm aot_diff_blocks)
    add_dependencies(aot_mut_hlex18 aot_gen_diff)
    target_compile_definitions(aot_mut_hlex18 PRIVATE MN_MUTANT_HLE_X18)

    add_test(NAME aot_mutant_negatives
        COMMAND "${AOT_PYTHON}" "${CMAKE_SOURCE_DIR}/tools/aot/mutant_test.py"
                --exedir "$<TARGET_FILE_DIR:aot_bin_runner>"
                --bin "${AOT_DIFF_BIN}" --meta "${AOT_DIFF_META}"
                --manifest "${AOT_DIFF_MANIFEST}"
                --work "${AOT_GEN_DIR}/mut_cases")
    set_tests_properties(aot_mutant_negatives PROPERTIES TIMEOUT 600
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

    # Runtime contract probe: fake blocks, NOT translation coverage.
    add_executable(aot_runtime_probe
        tests/aot/aot_runtime_probe.c
        ${AOT_CORE_SRC})
    target_include_directories(aot_runtime_probe PRIVATE "${CMAKE_SOURCE_DIR}/src/aot")
    target_compile_options(aot_runtime_probe PRIVATE /W4 /WX)
    target_link_libraries(aot_runtime_probe PRIVATE host_vm)
    add_test(NAME aot_runtime_contract COMMAND aot_runtime_probe)
    set_tests_properties(aot_runtime_contract PROPERTIES TIMEOUT 60)

    # Scalar FP core probe: exact integer F32/F64 add/sub/mul/div/compare
    # contract vectors. No translation, no oracle, no game data.
    add_executable(aot_fp_probe
        tests/aot/aot_fp_probe.c
        src/aot/aot_fp.c)
    target_include_directories(aot_fp_probe PRIVATE "${CMAKE_SOURCE_DIR}/src/aot")
    target_compile_options(aot_fp_probe PRIVATE /W4 /WX)
    add_test(NAME aot_fp_core COMMAND aot_fp_probe)
    set_tests_properties(aot_fp_core PROPERTIES TIMEOUT 60)

    # Native-only translated FP contract probe: links the real generated
    # differential image and drives the runtime directly. Covers unsupported
    # FPCR faults (the pinned oracle masks those bits), unrestricted bitwise
    # FMOV/FABS/FNEG under all-ones FPCR/FPSR, and closed-form translated rows.
    add_executable(aot_fp_translated_probe
        tests/aot/aot_fp_translated_probe.c
        ${AOT_CORE_SRC}
        ${AOT_FP_SRC})
    target_include_directories(aot_fp_translated_probe
        PRIVATE "${CMAKE_SOURCE_DIR}/src/aot")
    target_compile_options(aot_fp_translated_probe PRIVATE /W4 /WX)
    target_link_libraries(aot_fp_translated_probe PRIVATE host_vm aot_diff_blocks)
    add_dependencies(aot_fp_translated_probe aot_gen_diff)
    add_test(NAME aot_fp_translated COMMAND aot_fp_translated_probe)
    set_tests_properties(aot_fp_translated PROPERTIES TIMEOUT 120)

    # Guard-mutant control: the SAME probe source linked against the
    # fpignoreguard image (unsupported FPCR is sanitized to 0 instead of
    # faulting). Positive expectation is a clean STOP that violates the guard
    # contract; the normal image must NOT be accepted in this mode.
    add_executable(aot_fp_translated_probe_guardmut
        tests/aot/aot_fp_translated_probe.c
        ${AOT_CORE_SRC}
        ${AOT_FP_SRC}
        "${AOT_GEN_DIR}/mut_fpignoreguard.c")
    add_dependencies(aot_fp_translated_probe_guardmut aot_mut_fpignoreguard)
    target_include_directories(aot_fp_translated_probe_guardmut
        PRIVATE "${CMAKE_SOURCE_DIR}/src/aot")
    target_compile_options(aot_fp_translated_probe_guardmut PRIVATE /W4 /WX)
    target_link_libraries(aot_fp_translated_probe_guardmut PRIVATE host_vm)
    add_test(NAME aot_fp_translated_guardmut
        COMMAND aot_fp_translated_probe_guardmut --expect-guard-reject)
    set_tests_properties(aot_fp_translated_guardmut PROPERTIES TIMEOUT 120)
    # Cross-checks (manual evidence, NOT CTest registrations). WILL_FAIL is
    # forbidden here: a FATAL infrastructure exit(1) would be counted as an
    # accepted negative. The two cross-checks are recorded manually instead:
    #   aot_fp_translated_probe --expect-guard-reject   -> exit 1, prints
    #       "guard mode: image correctly rejected the unsupported FPCR"
    #   aot_fp_translated_probe_guardmut                -> exit 1, 392 typed
    #       STOP-instead-of-FAULT mismatches, no FATAL line


    # Decoder + independent (Capstone) CFG structural test.
    add_test(NAME aot_decoder_cfg
        COMMAND "${AOT_PYTHON}" "${CMAKE_SOURCE_DIR}/tests/aot/decoder_cfg_test.py"
                --bin "${AOT_DIFF_BIN}" --meta "${AOT_DIFF_META}"
                --manifest "${AOT_DIFF_MANIFEST}")
    set_tests_properties(aot_decoder_cfg PROPERTIES TIMEOUT 120
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

    # ---- translated-memory concurrency probe ---------------------------
    set(AOT_CONC_S        "${CMAKE_SOURCE_DIR}/tests/aot/fixture_concurrency.s")
    set(AOT_CONC_MANIFEST "${CMAKE_SOURCE_DIR}/tests/aot/fixture_concurrency.manifest.json")
    set(AOT_CONC_OBJ      "${AOT_GEN_DIR}/fixture_concurrency.o")
    set(AOT_CONC_BIN      "${AOT_GEN_DIR}/fixture_concurrency.bin")
    set(AOT_CONC_C        "${AOT_GEN_DIR}/fixture_concurrency_blocks.c")
    set(AOT_CONC_MUT_C    "${AOT_GEN_DIR}/fixture_concurrency_mut.c")

    add_custom_target(aot_gen_conc
        COMMAND ${CMAKE_COMMAND} -E make_directory "${AOT_GEN_DIR}"
        COMMAND "${AOT_LLVM_MC}" -triple=aarch64-none-elf -filetype=obj
                -o "${AOT_CONC_OBJ}" "${AOT_CONC_S}"
        COMMAND "${AOT_LLVM_OBJCOPY}" -O binary --only-section=.text
                "${AOT_CONC_OBJ}" "${AOT_CONC_BIN}"
        COMMAND "${AOT_PYTHON}" "${CMAKE_SOURCE_DIR}/tools/aot/aot_translate.py"
                --manifest "${AOT_CONC_MANIFEST}" --bin "${AOT_CONC_BIN}"
                --out "${AOT_CONC_C}" --name conc
        COMMAND "${AOT_PYTHON}" "${CMAKE_SOURCE_DIR}/tools/aot/aot_translate.py"
                --manifest "${AOT_CONC_MANIFEST}" --bin "${AOT_CONC_BIN}"
                --out "${AOT_CONC_MUT_C}" --name conc_mut --mutant stxalwaysok
        DEPENDS "${AOT_CONC_S}" "${AOT_CONC_MANIFEST}"
                "${CMAKE_SOURCE_DIR}/tools/aot/aot_translate.py"
        COMMENT "Generating G2 concurrency fixture + blocks" VERBATIM)

    set_source_files_properties("${AOT_CONC_C}" "${AOT_CONC_MUT_C}"
        PROPERTIES GENERATED TRUE)
    # Shared generated blocks: compiled once, linked by the three consumers.
    add_library(aot_conc_blocks STATIC "${AOT_CONC_C}")
    add_dependencies(aot_conc_blocks aot_gen_conc)
    target_include_directories(aot_conc_blocks PRIVATE "${CMAKE_SOURCE_DIR}/src/aot")
    target_compile_options(aot_conc_blocks PRIVATE /W4 /WX)

    add_executable(aot_concurrency_probe
        tests/aot/aot_concurrency_probe.c
        ${AOT_CORE_SRC}
        ${AOT_FP_SRC}
        "${AOT_CONC_MUT_C}")
    target_include_directories(aot_concurrency_probe PRIVATE "${CMAKE_SOURCE_DIR}/src/aot")
    target_compile_options(aot_concurrency_probe PRIVATE /W4 /WX)
    target_link_libraries(aot_concurrency_probe PRIVATE host_vm aot_conc_blocks)
    add_dependencies(aot_concurrency_probe aot_gen_conc)
    add_test(NAME aot_concurrency COMMAND aot_concurrency_probe)
    set_tests_properties(aot_concurrency PROPERTIES TIMEOUT 120)

    # ---- TEST-ONLY wrong-backend control: no store invalidation ----------
    # Same probe source, IDENTICAL deterministic schedule and explicit
    # constraint, two separately compiled mem.c instances. The noinv target
    # compiles the shipping aot_mem.c with AOT_MEM_TEST_NO_INVALIDATION, which
    # suppresses only mon_invalidate_locked's body (locks, arena registration
    # and monitor-token lifetime are retained). The real target must OBSERVE the
    # constraint hold; the noinv target must OBSERVE it violated on status+data.
    set(AOT_CONC_CONTROL_SOURCES
        tests/aot/aot_conc_wrongbackend_probe.c
        ${AOT_CORE_SRC}
        ${AOT_FP_SRC})
    add_executable(aot_conc_control_real ${AOT_CONC_CONTROL_SOURCES})
    target_include_directories(aot_conc_control_real PRIVATE "${CMAKE_SOURCE_DIR}/src/aot")
    target_compile_options(aot_conc_control_real PRIVATE /W4 /WX)
    target_link_libraries(aot_conc_control_real PRIVATE host_vm aot_conc_blocks)
    add_dependencies(aot_conc_control_real aot_gen_conc)
    add_executable(aot_conc_control_noinv ${AOT_CONC_CONTROL_SOURCES})
    target_include_directories(aot_conc_control_noinv PRIVATE "${CMAKE_SOURCE_DIR}/src/aot")
    target_compile_options(aot_conc_control_noinv PRIVATE /W4 /WX)
    target_link_libraries(aot_conc_control_noinv PRIVATE host_vm aot_conc_blocks)
    add_dependencies(aot_conc_control_noinv aot_gen_conc)
    target_compile_definitions(aot_conc_control_noinv PRIVATE AOT_MEM_TEST_NO_INVALIDATION)
    add_test(NAME aot_conc_control_real COMMAND aot_conc_control_real)
    add_test(NAME aot_conc_control_noinv COMMAND aot_conc_control_noinv --expect-reject)
    set_tests_properties(aot_conc_control_real aot_conc_control_noinv
        PROPERTIES TIMEOUT 60)

    # Independent (Capstone) CFG + exact-range check for the concurrency
    # fixture. Deliberately does not trust the translator's emitted meta as
    # the source of truth, and rejects ranges that cover .org gap/padding
    # bytes or extend past the raw image.
    add_test(NAME aot_conc_cfg
        COMMAND "${AOT_PYTHON}" "${CMAKE_SOURCE_DIR}/tests/aot/conc_cfg_test.py"
                --bin "${AOT_CONC_BIN}" --manifest "${AOT_CONC_MANIFEST}"
                --python "${AOT_PYTHON}"
                --translator "${CMAKE_SOURCE_DIR}/tools/aot/aot_translate.py")
    set_tests_properties(aot_conc_cfg PROPERTIES TIMEOUT 120
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

    # ---- G3 increment 1: runtime core (address space + Program dispatch) --
    # These probes use hand-written FAKE blocks at guest virtual addresses.
    # They are NOT translator output and prove nothing about translation; they
    # pin the dispatcher/address-space contract only.
    add_executable(aot_as_probe
        tests/aot/aot_as_probe.c
        ${AOT_CORE_SRC})
    target_include_directories(aot_as_probe PRIVATE "${CMAKE_SOURCE_DIR}/src/aot")
    target_compile_options(aot_as_probe PRIVATE /W4 /WX)
    target_link_libraries(aot_as_probe PRIVATE host_vm)
    add_test(NAME aot_g3_as COMMAND aot_as_probe)
    set_tests_properties(aot_g3_as PROPERTIES TIMEOUT 120)

    # G3 boot-heap window: the reviewed SetHeapSize transition contract, driven
    # through the REAL public AS interface with host_vm_query as the independent
    # OS witness. Fixture heap is 8 MiB (MAXSZ), so nothing commits 4 GiB.
    add_executable(aot_as_heap_probe
        tests/aot/aot_as_heap_probe.c
        ${AOT_CORE_SRC})
    target_include_directories(aot_as_heap_probe
        PRIVATE "${CMAKE_SOURCE_DIR}/src/aot")
    target_compile_options(aot_as_heap_probe PRIVATE /W4 /WX)
    target_link_libraries(aot_as_heap_probe PRIVATE host_vm)
    add_test(NAME aot_g3_as_heap COMMAND aot_as_heap_probe)
    set_tests_properties(aot_g3_as_heap PROPERTIES TIMEOUT 120)

    # Immutable AS-owned alias reserved window (64 GiB reserve-only).
    add_executable(aot_as_alias_probe
        tests/aot/aot_as_alias_probe.c
        ${AOT_CORE_SRC})
    target_include_directories(aot_as_alias_probe
        PRIVATE "${CMAKE_SOURCE_DIR}/src/aot")
    target_compile_options(aot_as_alias_probe PRIVATE /W4 /WX)
    target_link_libraries(aot_as_alias_probe PRIVATE host_vm)
    add_test(NAME aot_g3_as_alias COMMAND aot_as_alias_probe)
    set_tests_properties(aot_g3_as_alias PROPERTIES TIMEOUT 120)

    # Physical alias mapping (MapPhysicalMemory/UnmapPhysicalMemory): the
    # guest-visible page state machine, budget, accounting and the OS-level
    # host witness. Wrong-implementation controls live in
    # tools/aot/g3_mutant_test.py; the fault seams are positive controls.
    add_executable(aot_as_alias_map_probe
        tests/aot/aot_as_alias_map_probe.c
        ${AOT_CORE_SRC})
    target_include_directories(aot_as_alias_map_probe
        PRIVATE "${CMAKE_SOURCE_DIR}/src/aot")
    target_compile_options(aot_as_alias_map_probe PRIVATE /W4 /WX)
    target_link_libraries(aot_as_alias_map_probe PRIVATE host_vm)
    add_test(NAME aot_g3_as_alias_map COMMAND aot_as_alias_map_probe)
    set_tests_properties(aot_g3_as_alias_map PROPERTIES TIMEOUT 180)

    foreach(fault 1 2 3)
        add_executable(aot_as_alias_fault_${fault}
            tests/aot/aot_as_alias_map_probe.c
            ${AOT_CORE_SRC})
        target_include_directories(aot_as_alias_fault_${fault}
            PRIVATE "${CMAKE_SOURCE_DIR}/src/aot")
        target_compile_options(aot_as_alias_fault_${fault} PRIVATE /W4 /WX)
        target_link_libraries(aot_as_alias_fault_${fault} PRIVATE host_vm)
        target_compile_definitions(aot_as_alias_fault_${fault}
            PRIVATE MN_AOT_ALIAS_FAULT_MODE=${fault})
        add_test(NAME aot_g3_as_alias_fault_${fault}
            COMMAND aot_as_alias_fault_${fault})
        set_tests_properties(aot_g3_as_alias_fault_${fault}
            PROPERTIES TIMEOUT 180)
    endforeach()

    foreach(mut charge_all keep_stale keep_mapped query_no_run no_budget omit_usage)
        string(TOUPPER "${mut}" mut_uc)
        add_executable(aot_as_alias_map_mut_${mut}
            tests/aot/aot_as_alias_map_probe.c
            ${AOT_CORE_SRC})
        target_include_directories(aot_as_alias_map_mut_${mut}
            PRIVATE "${CMAKE_SOURCE_DIR}/src/aot")
        target_compile_options(aot_as_alias_map_mut_${mut} PRIVATE /W4 /WX)
        target_link_libraries(aot_as_alias_map_mut_${mut} PRIVATE host_vm)
        target_compile_definitions(aot_as_alias_map_mut_${mut}
            PRIVATE MN_AOT_ALIAS_MUT_${mut_uc})
    endforeach()

    # Alias wrong-implementation controls (not passing tests).
    foreach(mut query_state5 range_omit heap_selects keep_monitor_on_perm_fail)
        add_executable(aot_as_alias_mut_${mut}
            tests/aot/aot_as_alias_probe.c
            ${AOT_CORE_SRC})
        target_include_directories(aot_as_alias_mut_${mut}
            PRIVATE "${CMAKE_SOURCE_DIR}/src/aot")
        target_compile_options(aot_as_alias_mut_${mut} PRIVATE /W4 /WX)
        target_link_libraries(aot_as_alias_mut_${mut} PRIVATE host_vm)
        if(mut STREQUAL "query_state5")
            target_compile_definitions(aot_as_alias_mut_${mut}
                PRIVATE MN_AOT_ALIAS_MUT_QUERY_STATE5)
        elseif(mut STREQUAL "range_omit")
            target_compile_definitions(aot_as_alias_mut_${mut}
                PRIVATE MN_AOT_ALIAS_MUT_RANGE_OMIT)
        elseif(mut STREQUAL "keep_monitor_on_perm_fail")
            target_compile_definitions(aot_as_alias_mut_${mut}
                PRIVATE MN_AOT_MEM_MUT_KEEP_MONITOR_ON_PERM_FAIL)
        else()
            target_compile_definitions(aot_as_alias_mut_${mut}
                PRIVATE MN_AOT_ALIAS_MUT_HEAP_SELECTS)
        endif()
    endforeach()

    # Deterministic host-refusal injection (private compile-time seam). Each of
    # these is a POSITIVE control that must pass: it drives the failure and
    # rollback protocol. Only the MN_AOT_HEAP_MUT_* executables below are
    # negative controls (not registered as passing tests).
    foreach(fault 1 2 3 4)
        add_executable(aot_as_heap_fault_${fault}
            tests/aot/aot_as_heap_probe.c
            ${AOT_CORE_SRC})
        target_include_directories(aot_as_heap_fault_${fault}
            PRIVATE "${CMAKE_SOURCE_DIR}/src/aot")
        target_compile_options(aot_as_heap_fault_${fault} PRIVATE /W4 /WX)
        target_link_libraries(aot_as_heap_fault_${fault} PRIVATE host_vm)
        target_compile_definitions(aot_as_heap_fault_${fault}
            PRIVATE MN_AOT_HEAP_FAULT_MODE=${fault})
        add_test(NAME aot_g3_as_heap_fault_${fault}
            COMMAND aot_as_heap_fault_${fault})
        set_tests_properties(aot_g3_as_heap_fault_${fault}
            PROPERTIES TIMEOUT 120)
    endforeach()

    # Wrong-implementation heap controls: each must be REJECTED by
    # aot_as_heap_probe with a specific semantic failure (see
    # tools/aot/g3_mutant_test.py). Not registered as passing tests.
    set(AOT_G3_HEAP_MUTANTS shrink_decommit no_monitor_invalidate
                              recommit_retained hw_as_used info5_size)
    foreach(mut ${AOT_G3_HEAP_MUTANTS})
        string(TOUPPER "${mut}" mut_uc)
        add_executable(aot_as_heap_mut_${mut}
            tests/aot/aot_as_heap_probe.c
            ${AOT_CORE_SRC})
        target_include_directories(aot_as_heap_mut_${mut}
            PRIVATE "${CMAKE_SOURCE_DIR}/src/aot")
        target_compile_options(aot_as_heap_mut_${mut} PRIVATE /W4 /WX)
        target_link_libraries(aot_as_heap_mut_${mut} PRIVATE host_vm)
        target_compile_definitions(aot_as_heap_mut_${mut}
            PRIVATE MN_AOT_HEAP_MUT_${mut_uc})
    endforeach()
    # Publish-before-host is only observable when a host call fails, so this
    # control pairs the mutation with the shrink-failure injection.
    add_executable(aot_as_heap_mut_publish_before_host
        tests/aot/aot_as_heap_probe.c
        ${AOT_CORE_SRC})
    target_include_directories(aot_as_heap_mut_publish_before_host
        PRIVATE "${CMAKE_SOURCE_DIR}/src/aot")
    target_compile_options(aot_as_heap_mut_publish_before_host PRIVATE /W4 /WX)
    target_link_libraries(aot_as_heap_mut_publish_before_host PRIVATE host_vm)
    target_compile_definitions(aot_as_heap_mut_publish_before_host PRIVATE
        MN_AOT_HEAP_MUT_PUBLISH_BEFORE_HOST MN_AOT_HEAP_FAULT_MODE=4)
    # Two guards on the shared production failure branch: they must be
    # observable only with the matching injected host refusal.
    add_executable(aot_as_heap_mut_no_desync
        tests/aot/aot_as_heap_probe.c
        ${AOT_CORE_SRC})
    target_include_directories(aot_as_heap_mut_no_desync
        PRIVATE "${CMAKE_SOURCE_DIR}/src/aot")
    target_compile_options(aot_as_heap_mut_no_desync PRIVATE /W4 /WX)
    target_link_libraries(aot_as_heap_mut_no_desync PRIVATE host_vm)
    target_compile_definitions(aot_as_heap_mut_no_desync PRIVATE
        MN_AOT_HEAP_MUT_NO_DESYNC MN_AOT_HEAP_FAULT_MODE=3)
    add_executable(aot_as_heap_mut_publish_on_commit_fail
        tests/aot/aot_as_heap_probe.c
        ${AOT_CORE_SRC})
    target_include_directories(aot_as_heap_mut_publish_on_commit_fail
        PRIVATE "${CMAKE_SOURCE_DIR}/src/aot")
    target_compile_options(aot_as_heap_mut_publish_on_commit_fail PRIVATE /W4 /WX)
    target_link_libraries(aot_as_heap_mut_publish_on_commit_fail PRIVATE host_vm)
    target_compile_definitions(aot_as_heap_mut_publish_on_commit_fail PRIVATE
        MN_AOT_HEAP_MUT_PUBLISH_ON_COMMIT_FAIL MN_AOT_HEAP_FAULT_MODE=1)

    add_executable(aot_program_probe
        tests/aot/aot_program_probe.c
        ${AOT_CORE_SRC})
    target_include_directories(aot_program_probe PRIVATE "${CMAKE_SOURCE_DIR}/src/aot")
    target_compile_options(aot_program_probe PRIVATE /W4 /WX)
    target_link_libraries(aot_program_probe PRIVATE host_vm host_thread)
    add_test(NAME aot_g3_program COMMAND aot_program_probe)
    set_tests_properties(aot_g3_program PROPERTIES TIMEOUT 180)

    # Negative controls: the SAME probe source linked against shipping runtime
    # code compiled with a test-only wrong-implementation switch. Each mutant
    # executable must exit 2 having printed its specific "FAIL: <check>" line;
    # g3_mutant_test.py treats anything else (0, 1, crash, timeout, missing
    # check) as an INFRASTRUCTURE failure.
    set(AOT_G3_AS_MUTANTS partial_store no_perm host_exec)
    foreach(mut ${AOT_G3_AS_MUTANTS})
        string(TOUPPER "${mut}" mut_uc)
        add_executable(aot_as_mut_${mut}
            tests/aot/aot_as_probe.c
            ${AOT_CORE_SRC})
        target_include_directories(aot_as_mut_${mut}
            PRIVATE "${CMAKE_SOURCE_DIR}/src/aot")
        target_compile_options(aot_as_mut_${mut} PRIVATE /W4 /WX)
        target_link_libraries(aot_as_mut_${mut} PRIVATE host_vm)
        target_compile_definitions(aot_as_mut_${mut}
            PRIVATE MN_AOT_MUTANT_${mut_uc})
    endforeach()

    set(AOT_G3_PROG_MUTANTS thunk_site4 resume_after no_depth_check
                            no_scratch_save reset_steps
                            handler_before_resume_check drop_sticky no_abi_check
                            sysreg_xzr recall_after_fault)
    foreach(mut ${AOT_G3_PROG_MUTANTS})
        string(TOUPPER "${mut}" mut_uc)
        add_executable(aot_prog_mut_${mut}
            tests/aot/aot_program_probe.c
            ${AOT_CORE_SRC})
        target_include_directories(aot_prog_mut_${mut}
            PRIVATE "${CMAKE_SOURCE_DIR}/src/aot")
        target_compile_options(aot_prog_mut_${mut} PRIVATE /W4 /WX)
        target_link_libraries(aot_prog_mut_${mut} PRIVATE host_vm host_thread)
        target_compile_definitions(aot_prog_mut_${mut}
            PRIVATE MN_AOT_MUTANT_${mut_uc})
    endforeach()

    # ---- G3 increment 2: translated-module loader fixtures -------------
    # Three NSO-like AArch64 modules (main/sub/sdk) assembled with llvm-mc and
    # linked with ld.lld -shared against tests/aot/g3/nso.ld, then converted to
    # NSO byte images (.flat) + layout JSON by tools/aot/aot_module.py. Three
    # link variants exercise the loader's dynamic-section paths:
    #   v0      : DT_HASH + DT_GNU_HASH, RELA only (TotK 1.0.0 shape)
    #   relr    : same + DT_RELR packed relative relocations (later firmware)
    #   gnuonly : DT_GNU_HASH only, no DT_HASH (symbol count from the
    #             descriptor's pinned dynsym count)
    # ONE owning target builds everything so a parallel build cannot race on the
    # shared objects/ELFs (same pattern as aot_gen_diff).
    set(AOT_G3_DIR       "${AOT_GEN_DIR}/g3")
    set(AOT_G3_LD_SCRIPT "${CMAKE_SOURCE_DIR}/tests/aot/g3/nso.ld")
    set(AOT_G3_TOOL      "${CMAKE_SOURCE_DIR}/tools/aot/aot_module.py")
    set(AOT_G3_MODULES   main sub sdk)
    # Link order must be sdk -> sub -> main: every module links against the
    # already-built libraries it references (DT_NEEDED, realistic shape).
    set(AOT_G3_LINK_ORDER sdk sub main)
    set(AOT_G3_VARIANTS  v0 relr gnuonly shadow)
    set(AOT_G3_CONFIG    "${CMAKE_SOURCE_DIR}/tests/aot/g3/link_config.json")
    set(AOT_G3_CHECK     "${CMAKE_SOURCE_DIR}/tools/aot/g3_link_check.py")
    set(AOT_G3_TRANSLATE "${CMAKE_SOURCE_DIR}/tools/aot/aot_translate.py")
    set(AOT_G3_INPUTS    "${AOT_G3_LD_SCRIPT}" "${AOT_G3_TOOL}"
                         "${AOT_G3_CONFIG}" "${AOT_G3_CHECK}"
                         "${AOT_G3_TRANSLATE}")
    foreach(mod ${AOT_G3_MODULES})
        list(APPEND AOT_G3_INPUTS
            "${CMAKE_SOURCE_DIR}/tests/aot/g3/fx_${mod}.s")
    endforeach()

    # ONE owning target: every command goes into a SINGLE add_custom_target
    # COMMAND list so the execution order is exactly the link/flatten order
    # (sdk -> sub -> main). Separate add_custom_command(TARGET ...) calls are
    # emitted as independent MSBuild steps and MSBuild may run them out of
    # order, which broke the module->dependency link order. It also keeps a
    # parallel build from racing on the shared .o/.so files.
    set(AOT_G3_CMDS COMMAND ${CMAKE_COMMAND} -E make_directory "${AOT_G3_DIR}")
    foreach(mod ${AOT_G3_MODULES})
        list(APPEND AOT_G3_CMDS
            COMMAND
            "${AOT_LLVM_MC}" -triple=aarch64-none-elf -filetype=obj
            -o "${AOT_G3_DIR}/fx_${mod}.o"
            "${CMAKE_SOURCE_DIR}/tests/aot/g3/fx_${mod}.s")
    endforeach()

    foreach(var ${AOT_G3_VARIANTS})
        if(var STREQUAL "v0")
            set(AOT_G3_HASH_FLAGS --hash-style=both)
            set(AOT_G3_RELR_FLAGS "")
        elseif(var STREQUAL "relr")
            set(AOT_G3_HASH_FLAGS --hash-style=both)
            set(AOT_G3_RELR_FLAGS -z pack-relative-relocs)
        elseif(var STREQUAL "shadow")
            # Same shape as v0 (DT_HASH + DT_GNU_HASH, no RELR). The only
            # difference is a main-only injected UNDEFINED STB_WEAK duplicate of
            # a DEFINED symbol's name, so the variant isolates the resolution
            # rule "the first DEFINED symbol with a name wins".
            set(AOT_G3_HASH_FLAGS --hash-style=both)
            set(AOT_G3_RELR_FLAGS "")
        else()
            set(AOT_G3_HASH_FLAGS --hash-style=gnu)
            set(AOT_G3_RELR_FLAGS "")
        endif()
        # Link order sdk -> sub -> main: the later modules reference the
        # earlier ones and get realistic DT_NEEDED entries.
        foreach(mod ${AOT_G3_LINK_ORDER})
            set(AOT_G3_DEPS "")
            if(mod STREQUAL "sub")
                set(AOT_G3_DEPS "${AOT_G3_DIR}/libfx_sdk_${var}.so")
            elseif(mod STREQUAL "main")
                set(AOT_G3_DEPS "${AOT_G3_DIR}/libfx_sub_${var}.so"
                                "${AOT_G3_DIR}/libfx_sdk_${var}.so")
            endif()
            list(APPEND AOT_G3_CMDS
                COMMAND
                "${AOT_LLD}" -shared -z max-page-size=4096
                -soname libfx_${mod}.so
                ${AOT_G3_HASH_FLAGS} ${AOT_G3_RELR_FLAGS}
                -T "${AOT_G3_LD_SCRIPT}"
                --init=${mod}_init
                -o "${AOT_G3_DIR}/libfx_${mod}_${var}.so"
                "${AOT_G3_DIR}/fx_${mod}.o" ${AOT_G3_DEPS})
            # The `shadow` variant is the negative control for the loader's
            # symbol index: main gets an UNDEFINED STB_WEAK dynsym entry that
            # reuses a DEFINED symbol's name at a SMALLER index. The ELF is
            # patched BEFORE elf2flat, so the flat, the reference linker and the
            # llvm-readelf checker all see exactly the same bytes.
            if(var STREQUAL "shadow" AND mod STREQUAL "main")
                list(APPEND AOT_G3_CMDS
                    COMMAND
                    "${AOT_PYTHON}" "${AOT_G3_TOOL}" shadow-undefined
                    --elf "${AOT_G3_DIR}/libfx_${mod}_${var}.so"
                    --undef fx_missing_sym --with main_vtable)
            endif()
            list(APPEND AOT_G3_CMDS
                COMMAND
                "${AOT_PYTHON}" "${AOT_G3_TOOL}" elf2flat
                --elf "${AOT_G3_DIR}/libfx_${mod}_${var}.so"
                --name "fx_${mod}_${var}"
                --out-dir "${AOT_G3_DIR}")
        endforeach()
        # Reference linker over the flat images (independent of the ELFs),
        # then the generated descriptors for the C loader.
        list(APPEND AOT_G3_CMDS
            COMMAND
            "${AOT_PYTHON}" "${AOT_G3_TOOL}" link
            --config "${AOT_G3_CONFIG}" --dir "${AOT_G3_DIR}"
            --variant ${var}
            --out-tsv "${AOT_G3_DIR}/fx_${var}.sites.tsv"
            --out-counters "${AOT_G3_DIR}/fx_${var}.counters.json"
            COMMAND
            "${AOT_PYTHON}" "${AOT_G3_TOOL}" emit-desc
            --config "${AOT_G3_CONFIG}" --dir "${AOT_G3_DIR}"
            --variant ${var}
            --out-c "${AOT_G3_DIR}/g3_desc_${var}.c")
        # Increment 3: only the v0 variant has translated module images. The
        # entry discovery and the module-mode translation run AFTER the
        # reference link of this variant (the TSV is an entry source).
        if(var STREQUAL "v0")
            foreach(spec "fx_main_v0:0x1000000000" "fx_sub_v0:0x1001000000"
                         "fx_sdk_v0:0x1002000000")
                string(REPLACE ":" ";" spec_parts "${spec}")
                list(GET spec_parts 0 img_name)
                list(GET spec_parts 1 img_base)
                list(APPEND AOT_G3_CMDS
                    COMMAND
                    "${AOT_PYTHON}" "${AOT_G3_TOOL}" entries
                    --flat "${AOT_G3_DIR}/${img_name}.flat"
                    --layout "${AOT_G3_DIR}/${img_name}.layout.json"
                    --name "${img_name}" --guest-base "${img_base}"
                    --link "${AOT_G3_DIR}/fx_${var}.sites.tsv"
                    --link-module "${img_name}"
                    --out "${AOT_G3_DIR}/${img_name}.entries.json"
                    COMMAND
                    "${AOT_PYTHON}" "${AOT_G3_TRANSLATE}" --module
                    --flat "${AOT_G3_DIR}/${img_name}.flat"
                    --layout "${AOT_G3_DIR}/${img_name}.layout.json"
                    --guest-base "${img_base}"
                    --entries "${AOT_G3_DIR}/${img_name}.entries.json"
                    --name "${img_name}"
                    --out "${AOT_G3_DIR}/${img_name}_blocks.c")
            endforeach()
        endif()
    endforeach()

    # Brief F: MODULE-mode translator mutants. Each mutant image is produced
    # by the SAME owning target, after the v0 flats/TSV it consumes.
    foreach(mut adrp_offset orr_noshift stp_split)
        list(APPEND AOT_G3_CMDS
            COMMAND ${CMAKE_COMMAND} -E make_directory
            "${AOT_G3_DIR}/mut_${mut}")
        foreach(spec "fx_main_v0:0x1000000000" "fx_sub_v0:0x1001000000"
                     "fx_sdk_v0:0x1002000000")
            string(REPLACE ":" ";" spec_parts "${spec}")
            list(GET spec_parts 0 img_name)
            list(GET spec_parts 1 img_base)
            list(APPEND AOT_G3_CMDS
                COMMAND
                "${AOT_PYTHON}" "${AOT_G3_TRANSLATE}" --module
                --mutant ${mut}
                --flat "${AOT_G3_DIR}/${img_name}.flat"
                --layout "${AOT_G3_DIR}/${img_name}.layout.json"
                --guest-base "${img_base}"
                --entries "${AOT_G3_DIR}/${img_name}.entries.json"
                --name "${img_name}"
                --out "${AOT_G3_DIR}/mut_${mut}/${img_name}_blocks.c")
        endforeach()
    endforeach()

    # T4: mutated flats + their own descriptors. Runs once, after every
    # variant's flats exist; the generator knows which variant each case needs.
    list(APPEND AOT_G3_CMDS
        COMMAND
        "${AOT_PYTHON}" "${AOT_G3_TOOL}" craft-negative
        --config "${AOT_G3_CONFIG}" --dir "${AOT_G3_DIR}"
        --neg-dir "${AOT_G3_DIR}/neg"
        --out-c "${AOT_G3_DIR}/g3_neg_cases.c")

    # ALL so a plain build leaves the fixtures (and the reference test) ready.
    add_custom_target(aot_g3_fixtures ALL
        ${AOT_G3_CMDS}
        DEPENDS ${AOT_G3_INPUTS}
        COMMENT "Building G3 module-loader fixtures (3 modules x 3 variants)"
        VERBATIM)

    # ---- T3: the C loader core and the generated descriptors -----------
    # aot_loader.c/aot_sha256.c are always compiled (even before the link
    # probe exists) so the loader cannot rot between turns; the descriptor .c
    # files are the offline reference linker's output and each variant gets its
    # own tiny static library g_aot_g3_<variant>_modules[].
    add_library(aot_g3_loader STATIC
        ${CMAKE_SOURCE_DIR}/src/aot/aot_loader.c
        ${CMAKE_SOURCE_DIR}/src/aot/aot_sha256.c)
    target_include_directories(aot_g3_loader PUBLIC
        "${CMAKE_SOURCE_DIR}/src/aot")
    target_compile_options(aot_g3_loader PRIVATE /W4 /WX)
    target_link_libraries(aot_g3_loader PUBLIC host_vm)

    add_executable(aot_sha256_probe
        tests/aot/aot_sha256_probe.c
        ${CMAKE_SOURCE_DIR}/src/aot/aot_sha256.c)
    target_include_directories(aot_sha256_probe PRIVATE
        "${CMAKE_SOURCE_DIR}/src/aot")
    target_compile_options(aot_sha256_probe PRIVATE /W4 /WX)
    add_test(NAME aot_g3_sha256 COMMAND aot_sha256_probe)
    set_tests_properties(aot_g3_sha256 PROPERTIES TIMEOUT 120)

    foreach(var ${AOT_G3_VARIANTS})
        set(AOT_G3_DESC_C "${AOT_G3_DIR}/g3_desc_${var}.c")
        set_source_files_properties("${AOT_G3_DESC_C}" PROPERTIES GENERATED TRUE)
        add_library(aot_g3_desc_${var} STATIC "${AOT_G3_DESC_C}")
        target_include_directories(aot_g3_desc_${var} PRIVATE
            "${CMAKE_SOURCE_DIR}/src/aot")
        target_compile_options(aot_g3_desc_${var} PRIVATE /W4 /WX)
        add_dependencies(aot_g3_desc_${var} aot_g3_fixtures)
    endforeach()

    # T3 link probe: loads, relocates and seals all three variants through the
    # generated descriptors and folds the site dump into a TSV the Python
    # driver compares with the reference linker and g3_link_check.py.
    add_executable(aot_g3_link_probe tests/aot/aot_g3_link_probe.c
        ${CMAKE_SOURCE_DIR}/src/aot/aot_as.c
        ${CMAKE_SOURCE_DIR}/src/aot/aot_mem.c)
    target_include_directories(aot_g3_link_probe PRIVATE
        "${CMAKE_SOURCE_DIR}/src/aot")
    target_compile_options(aot_g3_link_probe PRIVATE /W4 /WX)
    target_link_libraries(aot_g3_link_probe PRIVATE host_vm aot_g3_loader
        aot_g3_desc_v0 aot_g3_desc_relr aot_g3_desc_gnuonly aot_g3_desc_shadow
        aot_g3_blocks_v0)
    add_dependencies(aot_g3_link_probe aot_g3_fixtures)

    # G3 increment 3: the translated v0 module images as one static library
    # (aot_translate.py --module output) and the first execution probe.
    set(AOT_G3_BLOCKS_C
        "${AOT_G3_DIR}/fx_main_v0_blocks.c"
        "${AOT_G3_DIR}/fx_sub_v0_blocks.c"
        "${AOT_G3_DIR}/fx_sdk_v0_blocks.c")
    set_source_files_properties(${AOT_G3_BLOCKS_C} PROPERTIES GENERATED TRUE)
    add_library(aot_g3_blocks_v0 STATIC ${AOT_G3_BLOCKS_C})
    target_include_directories(aot_g3_blocks_v0 PUBLIC
        "${CMAKE_SOURCE_DIR}/src/aot")
    target_compile_options(aot_g3_blocks_v0 PRIVATE /W4 /WX)
    add_dependencies(aot_g3_blocks_v0 aot_g3_fixtures)

    add_executable(aot_g3_exec_probe tests/aot/aot_g3_exec_probe.c
        ${CMAKE_SOURCE_DIR}/src/aot/aot_prog_assembly.c
        ${AOT_CORE_SRC})
    target_include_directories(aot_g3_exec_probe PRIVATE
        "${CMAKE_SOURCE_DIR}/src/aot")
    target_compile_options(aot_g3_exec_probe PRIVATE /W4 /WX)
    target_link_libraries(aot_g3_exec_probe PRIVATE host_vm host_thread
        host_time aot_g3_loader aot_g3_desc_v0 aot_g3_desc_relr
        aot_g3_blocks_v0)
    add_dependencies(aot_g3_exec_probe aot_g3_fixtures)
    add_test(NAME aot_g3_exec COMMAND aot_g3_exec_probe "${AOT_G3_DIR}")
    set_tests_properties(aot_g3_exec PROPERTIES TIMEOUT 180)

    # ---- Brief F: exec negative controls -------------------------------
    # (a) translator mutants: the same probe over mutant translated blocks;
    # (b) loader/program mutants: the same probe over one test-only compile
    # define. Each must be REJECTED by its specific check (see
    # tools/aot/g3_exec_mutant_test.py) -- a survivor means the check is
    # vacuous.
    set(AOT_G3_MUT_EXES "")
    foreach(mut adrp_offset orr_noshift stp_split)
        set(AOT_G3_MUT_BLOCKS
            "${AOT_G3_DIR}/mut_${mut}/fx_main_v0_blocks.c"
            "${AOT_G3_DIR}/mut_${mut}/fx_sub_v0_blocks.c"
            "${AOT_G3_DIR}/mut_${mut}/fx_sdk_v0_blocks.c")
        set_source_files_properties(${AOT_G3_MUT_BLOCKS} PROPERTIES
            GENERATED TRUE)
        add_library(aot_g3_blocks_v0_${mut} STATIC ${AOT_G3_MUT_BLOCKS})
        target_include_directories(aot_g3_blocks_v0_${mut} PUBLIC
            "${CMAKE_SOURCE_DIR}/src/aot")
        target_compile_options(aot_g3_blocks_v0_${mut} PRIVATE /W4 /WX)
        add_dependencies(aot_g3_blocks_v0_${mut} aot_g3_fixtures)
        add_executable(aot_g3_exec_probe_mut_${mut}
            tests/aot/aot_g3_exec_probe.c
            ${CMAKE_SOURCE_DIR}/src/aot/aot_prog_assembly.c
            ${AOT_CORE_SRC})
        target_include_directories(aot_g3_exec_probe_mut_${mut} PRIVATE
            "${CMAKE_SOURCE_DIR}/src/aot")
        target_compile_options(aot_g3_exec_probe_mut_${mut} PRIVATE /W4 /WX)
        target_link_libraries(aot_g3_exec_probe_mut_${mut} PRIVATE
            host_vm host_thread host_time aot_g3_loader aot_g3_desc_v0
            aot_g3_desc_relr aot_g3_blocks_v0_${mut})
        add_dependencies(aot_g3_exec_probe_mut_${mut} aot_g3_fixtures)
        list(APPEND AOT_G3_MUT_EXES aot_g3_exec_probe_mut_${mut})
    endforeach()

    foreach(mut init_array_walk image_unbound)
        string(TOUPPER ${mut} mut_upper)
        add_executable(aot_g3_exec_probe_mut_${mut}
            tests/aot/aot_g3_exec_probe.c
            ${CMAKE_SOURCE_DIR}/src/aot/aot_prog_assembly.c
            ${AOT_CORE_SRC})
        target_include_directories(aot_g3_exec_probe_mut_${mut} PRIVATE
            "${CMAKE_SOURCE_DIR}/src/aot")
        target_compile_options(aot_g3_exec_probe_mut_${mut} PRIVATE /W4 /WX)
        target_compile_definitions(aot_g3_exec_probe_mut_${mut} PRIVATE
            MN_AOT_MUTANT_${mut_upper})
        target_link_libraries(aot_g3_exec_probe_mut_${mut} PRIVATE
            host_vm host_thread host_time aot_g3_loader aot_g3_desc_v0
            aot_g3_desc_relr aot_g3_blocks_v0)
        add_dependencies(aot_g3_exec_probe_mut_${mut} aot_g3_fixtures)
        list(APPEND AOT_G3_MUT_EXES aot_g3_exec_probe_mut_${mut})
    endforeach()

    # Brief F: module-mode decoder cross-check against Capstone 5.0.7.
    add_test(NAME aot_g3_decoder_module
        COMMAND "${AOT_PYTHON}"
                "${CMAKE_SOURCE_DIR}/tests/aot/g3_decoder_module_test.py"
                --tools "${CMAKE_SOURCE_DIR}/tools/aot")
    set_tests_properties(aot_g3_decoder_module PROPERTIES TIMEOUT 300
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

    # Bounded local-switch CFG edge prover + Phase-B module pipeline
    # (lazy Context, site-local edges, final closure, codegen guard).
    add_test(NAME aot_g3_local_switch
        COMMAND "${AOT_PYTHON}"
                "${CMAKE_SOURCE_DIR}/tests/aot/g3_local_switch_test.py")
    set_tests_properties(aot_g3_local_switch PROPERTIES TIMEOUT 300
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

    # D023 same-module DT_INIT_ARRAY constructor roots: hermetic synthetic
    # fixtures (core derivation + prove + driver seam), no game data.
    add_test(NAME aot_g3_ctor_roots
        COMMAND "${AOT_PYTHON}"
                "${CMAKE_SOURCE_DIR}/tests/aot/g3_ctor_roots_test.py")
    set_tests_properties(aot_g3_ctor_roots PROPERTIES TIMEOUT 120
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

    # D024 Stage A: NSO/FDE metadata frontend producing a CANDIDATE boundary
    # manifest. The fixture is a real llvm-mc/ld.lld --eh-frame-hdr module
    # (tests/aot/g3/fde_fixture.s + fde.ld) flattened by aot_module.elf2flat;
    # no game data. The suite also runs its own assertions in a child process
    # against a deliberately lax frontend (monkeypatched in that child only),
    # which must FAIL: a mutant that passes is a survivor.
    add_test(NAME aot_g3_fde_frontend
        COMMAND "${AOT_PYTHON}"
                "${CMAKE_SOURCE_DIR}/tests/aot/g3_fde_frontend_test.py"
                --llvm "${AOT_LLVM_BIN_DIR}")
    set_tests_properties(aot_g3_fde_frontend PROPERTIES TIMEOUT 300
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

    # D024 Stage C step 1.4: pure stratified catalog-window selector
    # (authority none; its output feeds `g3_fde_emit.py catalog --select`).
    add_test(NAME aot_g3_stage_c_select
        COMMAND "${AOT_PYTHON}" "${CMAKE_SOURCE_DIR}/tests/aot/g3_stage_c_select_test.py")
    set_tests_properties(aot_g3_stage_c_select PROPERTIES TIMEOUT 300
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

    # D023 lazy root discovery through actual loader/AS/Program dispatch.
    # Native misses supply the slot evidence; the guest walks both constructors.
    add_test(NAME aot_g3_ctor_native
        COMMAND "${AOT_PYTHON}"
                "${CMAKE_SOURCE_DIR}/tests/aot/g3_ctor_native_test.py"
                --repo "${CMAKE_SOURCE_DIR}"
                --tools "${CMAKE_SOURCE_DIR}/tools/aot"
                --llvm "${AOT_LLVM_BIN_DIR}")
    set_tests_properties(aot_g3_ctor_native PROPERTIES TIMEOUT 300
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

    # D024 Stage B: candidate catalog + authority table ("compiled is not
    # authorized"). Today's emission (X) and the catalog/table emission (Y)
    # run through the actual loader/AS/Program from the same fresh load and
    # must agree field by field (Unicorn A57 as a third oracle where it can
    # model the path). A child process re-runs the suite with a wrong
    # authority step (monkeypatched in that child only), which must FAIL.
    add_test(NAME aot_g3_fde_emit
        COMMAND "${AOT_PYTHON}"
                "${CMAKE_SOURCE_DIR}/tests/aot/g3_fde_emit_test.py"
                --repo "${CMAKE_SOURCE_DIR}"
                --tools "${CMAKE_SOURCE_DIR}/tools/aot"
                --llvm "${AOT_LLVM_BIN_DIR}")
    set_tests_properties(aot_g3_fde_emit PROPERTIES TIMEOUT 600
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

    # D024 plan 1.2.6: hash-bound catalog verification (`table --verify-mode
    # bound --receipt`). Hermetic (no game data, no MSVC): the same fixture
    # as aot_g3_fde_emit, through the real CLI; bound output must equal the
    # regenerate output and every tampered receipt must be refused.
    add_test(NAME aot_g3_fde_emit_receipt
        COMMAND "${AOT_PYTHON}"
                "${CMAKE_SOURCE_DIR}/tests/aot/g3_fde_emit_receipt_test.py"
                --llvm "${AOT_LLVM_BIN_DIR}")
    set_tests_properties(aot_g3_fde_emit_receipt PROPERTIES TIMEOUT 300
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

    # Native + Unicorn A57 differential of the emitted local-switch guard:
    # compiles the ACTUAL generated C for four variants with MSVC /W4 /WX /O2
    # in an external temp dir and direct-calls the translated basic blocks
    # through the emitted AotBlockEntry table (dev probe; no game data).
    add_test(NAME aot_g3_local_switch_native
        COMMAND "${AOT_PYTHON}"
                "${CMAKE_SOURCE_DIR}/tests/aot/g3_local_switch_native_test.py"
                --repo "${CMAKE_SOURCE_DIR}"
                --tools "${CMAKE_SOURCE_DIR}/tools/aot")
    set_tests_properties(aot_g3_local_switch_native PROPERTIES TIMEOUT 900
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

    # G3 DT_INIT reachability scanner: synthetic images, no game data.
    add_test(NAME aot_g3_init_reach
        COMMAND "${AOT_PYTHON}"
                "${CMAKE_SOURCE_DIR}/tests/aot/g3_init_reach_test.py"
                --tools "${CMAKE_SOURCE_DIR}/tools/aot")
    set_tests_properties(aot_g3_init_reach PROPERTIES TIMEOUT 300
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

    # Exhaustive SBFM/UBFM/BFM helper differential (every immr/imms geometry,
    # both widths) against Unicorn A57; the C text is the translator's helper.
    add_test(NAME aot_g3_bitfield_diff
        COMMAND "${AOT_PYTHON}"
                "${CMAKE_SOURCE_DIR}/tests/aot/g3_bitfield_diff_test.py"
                --tools "${CMAKE_SOURCE_DIR}/tools/aot")
    set_tests_properties(aot_g3_bitfield_diff PROPERTIES TIMEOUT 300
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

    # Partial-AOT trap: structural metadata/edge checks + a NATIVE run of the
    # emitted block (code 16, exact src/status, unchanged guest state) with
    # compiled NOP and BAD_STATE generator mutants that must be rejected.
    add_test(NAME aot_g3_partial
        COMMAND "${AOT_PYTHON}"
                "${CMAKE_SOURCE_DIR}/tests/aot/g3_partial_test.py"
                --tools "${CMAKE_SOURCE_DIR}/tools/aot")
    set_tests_properties(aot_g3_partial PROPERTIES TIMEOUT 300
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_test(NAME aot_g3_partial_exec
        COMMAND "${AOT_PYTHON}"
                "${CMAKE_SOURCE_DIR}/tests/aot/g3_partial_exec_test.py"
                --tools "${CMAKE_SOURCE_DIR}/tools/aot"
                --repo "${CMAKE_SOURCE_DIR}")
    set_tests_properties(aot_g3_partial_exec PROPERTIES TIMEOUT 300
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    # New integer/memory families: EMITTED-C blocks compiled and run natively
    # vs Unicorn A57 (exact GPR/SP/NZCV/PC-after-branch/page), plus compiled
    # translator mutants that must diverge.
    add_test(NAME aot_g3_newfamily_diff
        COMMAND "${AOT_PYTHON}"
                "${CMAKE_SOURCE_DIR}/tests/aot/g3_newfamily_diff_test.py"
                --tools "${CMAKE_SOURCE_DIR}/tools/aot"
                --repo "${CMAKE_SOURCE_DIR}"
                --llvm "${AOT_LLVM_BIN_DIR}")
    set_tests_properties(aot_g3_newfamily_diff PROPERTIES TIMEOUT 600
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    # Full CSEL/CSINC/CSINV/CSNEG condition x width x NZCV matrix on EMITTED C
    # against Unicorn A57 (all 16 conditions and 16 NZCV nibbles per cell),
    # ZR destinations and a compiled csel_cond mutant. LLVM paths come from the
    # CMake cache discovery above, never a hardcoded developer directory.
    add_test(NAME aot_g3_csel_matrix
        COMMAND "${AOT_PYTHON}"
                "${CMAKE_SOURCE_DIR}/tests/aot/g3_csel_matrix_test.py"
                --tools "${CMAKE_SOURCE_DIR}/tools/aot"
                --repo "${CMAKE_SOURCE_DIR}"
                --llvm "${AOT_LLVM_BIN_DIR}")
    set_tests_properties(aot_g3_csel_matrix PROPERTIES TIMEOUT 900
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    # Module-only SIMD&FP MEMORY bit transfers (LDR/STR S/D/Q unsigned offset)
    # on EMITTED C vs Unicorn A57: full raw V0..V31/FPCR/FPSR/page. Unicorn
    # masks unsupported FPCR/FPSR bits, so the all-ones row is NATIVE-only and
    # explicitly not a differential claim (G2 bitwise ABI policy).
    add_test(NAME aot_g3_simd_ldst
        COMMAND "${AOT_PYTHON}"
                "${CMAKE_SOURCE_DIR}/tests/aot/g3_simd_ldst_diff_test.py"
                --tools "${CMAKE_SOURCE_DIR}/tools/aot"
                --repo "${CMAKE_SOURCE_DIR}"
                --llvm "${AOT_LLVM_BIN_DIR}")
    set_tests_properties(aot_g3_simd_ldst PROPERTIES TIMEOUT 600
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

    add_test(NAME aot_g3_exec_mutants
        COMMAND "${AOT_PYTHON}"
                "${CMAKE_SOURCE_DIR}/tools/aot/g3_exec_mutant_test.py"
                --exe-dir "$<TARGET_FILE_DIR:aot_g3_exec_probe>"
                --fixtures "${AOT_G3_DIR}")
    set_tests_properties(aot_g3_exec_mutants PROPERTIES TIMEOUT 600
                         DEPENDS "aot_g3_exec;aot_g3_exec_oracle")

    # G3 increment 3 brief E: differential oracle. The native probe dumps the
    # non-nested scenarios (final x0..x30/sp/nzcv + per-module data digests)
    # and tools/aot/g3_exec_oracle.py replays them on Unicorn 2.1.4 (A57) and
    # compares field by field. It also runs its own --perturb negative control.
    add_test(NAME aot_g3_exec_oracle
             COMMAND "${AOT_PYTHON}"
                     "${CMAKE_SOURCE_DIR}/tools/aot/g3_exec_oracle.py"
                     --probe $<TARGET_FILE:aot_g3_exec_probe>
                     --fixtures "${AOT_G3_DIR}"
                     --config "${AOT_G3_CONFIG}")
    set_tests_properties(aot_g3_exec_oracle PROPERTIES TIMEOUT 300
                         DEPENDS aot_g3_exec)

    # Negative fixtures: generated descriptors + their own probe.
    set_source_files_properties("${AOT_G3_DIR}/g3_neg_cases.c"
        PROPERTIES GENERATED TRUE)
    add_library(aot_g3_neg_desc STATIC "${AOT_G3_DIR}/g3_neg_cases.c")
    target_include_directories(aot_g3_neg_desc PRIVATE
        "${CMAKE_SOURCE_DIR}/src/aot" "${CMAKE_SOURCE_DIR}/tests/aot")
    target_compile_options(aot_g3_neg_desc PRIVATE /W4 /WX)
    add_dependencies(aot_g3_neg_desc aot_g3_fixtures)

    add_executable(aot_g3_neg_probe tests/aot/aot_g3_neg_probe.c
        ${CMAKE_SOURCE_DIR}/src/aot/aot_as.c
        ${CMAKE_SOURCE_DIR}/src/aot/aot_mem.c)
    target_include_directories(aot_g3_neg_probe PRIVATE
        "${CMAKE_SOURCE_DIR}/src/aot" "${CMAKE_SOURCE_DIR}/tests/aot")
    target_compile_options(aot_g3_neg_probe PRIVATE /W4 /WX)
    target_link_libraries(aot_g3_neg_probe PRIVATE host_vm aot_g3_loader
        aot_g3_neg_desc)
    add_dependencies(aot_g3_neg_probe aot_g3_fixtures)

    # T4 loader mutants: the same probes over a loader compiled with ONE
    # deliberately wrong rule (MN_AOT_MUTANT_* in src/aot/aot_loader.c). Each
    # executable must be rejected by the probe with the specific failure the
    # driver expects; a surviving mutant means that check is vacuous.
    set(AOT_LOADER_MUTANTS
        RELATIVE_NO_BASE ABS64_NO_ADDEND JUMPSLOT_ADDEND_ACCEPT GLOBAL_FIRST
        OBSERVER_ALL_KINDS WEAK_STRONG_SWAP TRUNC32 THUNK_PER_MODULE
        NO_DUP_CHECK SYMBOL_FIRST_ANY)
    set(AOT_LOADER_SRC_ALL
        ${CMAKE_SOURCE_DIR}/src/aot/aot_loader.c
        ${CMAKE_SOURCE_DIR}/src/aot/aot_sha256.c
        ${CMAKE_SOURCE_DIR}/src/aot/aot_as.c
        ${CMAKE_SOURCE_DIR}/src/aot/aot_mem.c)
    foreach(mut ${AOT_LOADER_MUTANTS})
        add_executable(aot_g3_link_mut_${mut}
            tests/aot/aot_g3_link_probe.c ${AOT_LOADER_SRC_ALL})
        target_include_directories(aot_g3_link_mut_${mut} PRIVATE
            "${CMAKE_SOURCE_DIR}/src/aot")
        target_compile_options(aot_g3_link_mut_${mut} PRIVATE /W4 /WX)
        target_compile_definitions(aot_g3_link_mut_${mut}
            PRIVATE MN_AOT_MUTANT_${mut})
        target_link_libraries(aot_g3_link_mut_${mut} PRIVATE host_vm
            aot_g3_desc_v0 aot_g3_desc_relr aot_g3_desc_gnuonly aot_g3_desc_shadow
            aot_g3_blocks_v0)
        add_dependencies(aot_g3_link_mut_${mut} aot_g3_fixtures)
    endforeach()
    # Only these are detected by the negative-fixture probe (the link probe
    # cannot see them: a good image never has a non-zero JUMP_SLOT addend, never
    # writes a site twice, and never relocates a site into a consumed table).
    set(AOT_LOADER_NEG_MUTANTS JUMPSLOT_ADDEND_ACCEPT NO_DUP_CHECK
        ALLOW_TABLE_OVERLAP)
    foreach(mut ${AOT_LOADER_NEG_MUTANTS})
        add_executable(aot_g3_neg_mut_${mut}
            tests/aot/aot_g3_neg_probe.c ${AOT_LOADER_SRC_ALL})
        target_include_directories(aot_g3_neg_mut_${mut} PRIVATE
            "${CMAKE_SOURCE_DIR}/src/aot" "${CMAKE_SOURCE_DIR}/tests/aot")
        target_compile_options(aot_g3_neg_mut_${mut} PRIVATE /W4 /WX)
        target_compile_definitions(aot_g3_neg_mut_${mut}
            PRIVATE MN_AOT_MUTANT_${mut})
        target_link_libraries(aot_g3_neg_mut_${mut} PRIVATE host_vm
            aot_g3_neg_desc)
        add_dependencies(aot_g3_neg_mut_${mut} aot_g3_fixtures)
    endforeach()

    add_test(NAME aot_g3_loader_mutants
        COMMAND "${AOT_PYTHON}"
                "${CMAKE_SOURCE_DIR}/tools/aot/g3_loader_mutant_test.py"
                --exedir "$<TARGET_FILE_DIR:aot_g3_link_probe>"
                --dir "${AOT_G3_DIR}")
    set_tests_properties(aot_g3_loader_mutants PROPERTIES TIMEOUT 600
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

    # Driver: runs the probe per variant, diffs the C dump against the
    # reference TSV, re-runs the independent llvm-readelf checker against the
    # C dump, and compares the C counters with the reference counters. Missing
    # files, crashes and timeouts are failures, never skips.
    add_test(NAME aot_g3_link
        COMMAND "${AOT_PYTHON}" "${CMAKE_SOURCE_DIR}/tools/aot/g3_link_test.py"
                --dir "${AOT_G3_DIR}"
                --probe "$<TARGET_FILE:aot_g3_link_probe>"
                --check "${AOT_G3_CHECK}"
                --python "${AOT_PYTHON}"
                --config "${AOT_G3_CONFIG}"
                --readelf "${AOT_LLVM_READELF}")
    set_tests_properties(aot_g3_link PROPERTIES TIMEOUT 300
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

    add_test(NAME aot_g3_neg
        COMMAND aot_g3_neg_probe "${AOT_G3_DIR}/neg")
    set_tests_properties(aot_g3_neg PROPERTIES TIMEOUT 300)

    # Negative control for the review-fix-11 detail comparison: comparing each
    # case against ANOTHER case's declared detail MUST fail.
    add_test(NAME aot_g3_neg_details_control
        COMMAND aot_g3_neg_probe "${AOT_G3_DIR}/neg" --drift-details)
    set_tests_properties(aot_g3_neg_details_control PROPERTIES TIMEOUT 300)

    # Independent check: llvm-readelf-derived expected sites/digest must agree
    # with the reference linker for every variant.
    add_test(NAME aot_g3_link_reference
        COMMAND "${AOT_PYTHON}" "${AOT_G3_CHECK}"
                --dir "${AOT_G3_DIR}" --config "${AOT_G3_CONFIG}"
                --readelf "${AOT_LLVM_READELF}")
    set_tests_properties(aot_g3_link_reference PROPERTIES TIMEOUT 300
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

    # G2 generated-code identity guard (G3 increment 3): every G2 translation
    # unit must stay byte-identical to the committed baseline apart from the
    # two provenance-derived lines (the translator self-fingerprint).
    add_test(NAME aot_g2_gen_identity
        COMMAND "${AOT_PYTHON}"
                "${CMAKE_SOURCE_DIR}/tools/aot/g2_gen_identity_check.py"
                --dir "${AOT_GEN_DIR}"
                --baseline "${CMAKE_SOURCE_DIR}/tests/aot/g2_gen_identity.txt")
    set_tests_properties(aot_g2_gen_identity PROPERTIES TIMEOUT 120
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

    # Typed-error paths of the offline toolchain + a negative control proving
    # the identity guard rejects a semantic change.
    add_test(NAME aot_g3_error_paths
        COMMAND "${AOT_PYTHON}"
                "${CMAKE_SOURCE_DIR}/tools/aot/g3_error_paths_test.py"
                --g3-dir "${AOT_G3_DIR}"
                --aot-gen "${AOT_GEN_DIR}"
                --tools "${CMAKE_SOURCE_DIR}/tools/aot"
                --python "${AOT_PYTHON}"
                --config "${CMAKE_SOURCE_DIR}/tests/aot/g3/link_config.json"
                --readelf "${AOT_LLVM_READELF}"
                --baseline "${CMAKE_SOURCE_DIR}/tests/aot/g2_gen_identity.txt")
    set_tests_properties(aot_g3_error_paths PROPERTIES TIMEOUT 300
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

    add_test(NAME aot_g3_runtime_mutants
        COMMAND "${AOT_PYTHON}" "${CMAKE_SOURCE_DIR}/tools/aot/g3_mutant_test.py"
                --exedir "$<TARGET_FILE_DIR:aot_as_probe>")
    set_tests_properties(aot_g3_runtime_mutants PROPERTIES TIMEOUT 900
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

    # G3 increment 4, work item A: the Mac observer/override tables are derived
    # from THIS repository's sources, so this test needs no game data and is
    # always registered. It pins the derivation result (6 observers, 171
    # overrides) and the documented configuration sensitivity (rumble/gyro/
    # libvpx switches change the tables in a known direction).
    add_test(NAME aot_g3_mac_bindings
        COMMAND "${AOT_PYTHON}"
                "${CMAKE_SOURCE_DIR}/tests/aot/g3_mac_bindings_test.py"
                --tools "${CMAKE_SOURCE_DIR}/tools/aot")
    set_tests_properties(aot_g3_mac_bindings PROPERTIES TIMEOUT 120
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

    # G3 increment 4, work items B/C: real TotK 1.0.0 modules. LOCAL ONLY and
    # opt-in: when MN_TOTK_V0_DIR is unset, neither of these is registered (a
    # real-module test is never silently skipped). The directory must hold the
    # flats produced by `aot_module.py nso2flat` (flat/), the Mac bindings
    # (bindings-mac.json) and the generated descriptors (link/real_desc.c).
    set(MN_TOTK_V0_DIR "" CACHE PATH
        "Local TotK v1.0.0 work dir (flat/, bindings-mac.json, link/) -- enables real-module tests")
    if(MN_TOTK_V0_DIR)
        if(NOT EXISTS "${MN_TOTK_V0_DIR}/link/real_desc.c")
            message(FATAL_ERROR
                "MN_TOTK_V0_DIR=${MN_TOTK_V0_DIR} but link/real_desc.c is "
                "missing: run tools/aot/aot_module.py emit-desc for the real "
                "link set first (see docs/g3-module-loader.md).")
        endif()
        foreach(img real_main real_sdk)
            if(NOT EXISTS "${MN_TOTK_V0_DIR}/img/${img}.c")
                message(FATAL_ERROR
                    "MN_TOTK_V0_DIR=${MN_TOTK_V0_DIR} but "
                    "img/${img}.c is missing: run tools/aot/aot_translate.py "
                    "--module for the real slice first (see "
                    "docs/g3-module-loader.md).")
            endif()
        endforeach()
        add_library(aot_g3_desc_real STATIC
            "${MN_TOTK_V0_DIR}/link/real_desc.c")
        target_include_directories(aot_g3_desc_real PRIVATE
            "${CMAKE_SOURCE_DIR}/src/aot")
        target_compile_options(aot_g3_desc_real PRIVATE /W4 /WX)
        # The real descriptor points at these two translated images (main and
        # sdk); subsdk0 stays link-only (image == NULL).
        add_library(aot_g3_img_real STATIC
            "${MN_TOTK_V0_DIR}/img/real_main.c"
            "${MN_TOTK_V0_DIR}/img/real_sdk.c")
        target_include_directories(aot_g3_img_real PRIVATE
            "${CMAKE_SOURCE_DIR}/src/aot")
        target_compile_options(aot_g3_img_real PRIVATE /W4 /WX)

        add_executable(aot_g3_real_link_probe
            tests/aot/aot_g3_real_link_probe.c
            ${CMAKE_SOURCE_DIR}/src/aot/aot_as.c
            ${CMAKE_SOURCE_DIR}/src/aot/aot_mem.c)
        target_include_directories(aot_g3_real_link_probe PRIVATE
            "${CMAKE_SOURCE_DIR}/src/aot")
        target_compile_options(aot_g3_real_link_probe PRIVATE /W4 /WX)
        target_link_libraries(aot_g3_real_link_probe PRIVATE host_vm
            aot_g3_loader aot_g3_desc_real aot_g3_img_real)

        add_test(NAME aot_g3_real_link
            COMMAND "${AOT_PYTHON}"
                    "${CMAKE_SOURCE_DIR}/tests/aot/aot_real_link_test.py"
                    --probe "$<TARGET_FILE:aot_g3_real_link_probe>"
                    --python "${AOT_PYTHON}"
                    --v0-dir "${MN_TOTK_V0_DIR}"
                    --work "${CMAKE_CURRENT_BINARY_DIR}/aot_gen/real")
        set_tests_properties(aot_g3_real_link PROPERTIES TIMEOUT 900
            ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

        # D024 Stage A on the real modules: parse each flat fail-closed through
        # MOD0 -> .eh_frame_hdr, write the candidate manifests under the BUILD
        # dir and assert that every D023-derived DT_INIT_ARRAY target is an FDE
        # start. Nothing it produces may reach the source tree.
        add_test(NAME aot_g3_fde_frontend_real
            COMMAND "${AOT_PYTHON}"
                    "${CMAKE_SOURCE_DIR}/tests/aot/g3_fde_frontend_real_test.py"
                    --v0-dir "${MN_TOTK_V0_DIR}"
                    --work "${CMAKE_CURRENT_BINARY_DIR}/aot_gen/fde_frontend")
        set_tests_properties(aot_g3_fde_frontend_real PROPERTIES TIMEOUT 900
            ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

        # D024 Stage B on the real modules: catalog main 0x1520 and sdk
        # __nnmusl_init_dso, run the authority step over the registered real
        # slice roots and require today's AotImage/bodies. Optional
        # MN_TOTK_ROOTS_DIR points at a Start-prefix work dir whose admitted
        # roots reach the targets (entries_<m>_real.json). Not executed.
        set(_fde_emit_real_args --v0-dir "${MN_TOTK_V0_DIR}"
            --work "${CMAKE_CURRENT_BINARY_DIR}/aot_gen/fde_emit")
        if(MN_TOTK_ROOTS_DIR)
            list(APPEND _fde_emit_real_args --roots-dir "${MN_TOTK_ROOTS_DIR}")
        endif()
        add_test(NAME aot_g3_fde_emit_real
            COMMAND "${AOT_PYTHON}"
                    "${CMAKE_SOURCE_DIR}/tests/aot/g3_fde_emit_real_test.py"
                    ${_fde_emit_real_args})
        set_tests_properties(aot_g3_fde_emit_real PROPERTIES TIMEOUT 900
            ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

        # ---- Item D: execute the translated real slice ------------------
        add_executable(aot_g3_real_exec_probe
            tests/aot/aot_g3_real_exec_probe.c
            ${CMAKE_SOURCE_DIR}/src/aot/aot_prog_assembly.c
            ${AOT_CORE_SRC})
        target_include_directories(aot_g3_real_exec_probe PRIVATE
            "${CMAKE_SOURCE_DIR}/src/aot")
        target_compile_options(aot_g3_real_exec_probe PRIVATE /W4 /WX)
        target_link_libraries(aot_g3_real_exec_probe PRIVATE host_vm
            host_thread host_time aot_g3_loader aot_g3_desc_real
            aot_g3_img_real)
        add_test(NAME aot_g3_real_exec
            COMMAND aot_g3_real_exec_probe "${MN_TOTK_V0_DIR}/link")
        set_tests_properties(aot_g3_real_exec PROPERTIES TIMEOUT 900)
        # Negative control: the same main image at a wrong guest base must be
        # refused by build_program before any guest instruction runs.
        add_test(NAME aot_g3_real_exec_neg
            COMMAND aot_g3_real_exec_probe "${MN_TOTK_V0_DIR}/link"
                    --wrong-base)
        set_tests_properties(aot_g3_real_exec_neg PROPERTIES TIMEOUT 900)
    endif()
endif()
