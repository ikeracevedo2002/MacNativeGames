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
    set(AOT_PYTHON "" CACHE FILEPATH
        "Python interpreter for tools/aot; must import unicorn==2.1.4 and capstone==5.0.7")
    if(NOT AOT_LLVM_MC OR NOT AOT_LLVM_OBJCOPY)
        message(FATAL_ERROR
            "MN_BUILD_AOT_PROOF=ON requires llvm-mc and llvm-objcopy. Install "
            "an LLVM toolchain on PATH and/or pass -DAOT_LLVM_MC=<path> "
            "-DAOT_LLVM_OBJCOPY=<path>.")
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
        src/aot/aot_runtime.c
        src/aot/aot_mem.c
        src/aot/aot_fp.c
        "${AOT_FIXTURE_C}"
    )
    target_include_directories(aot_fixture_runner PRIVATE "${CMAKE_SOURCE_DIR}/src/aot")
    target_compile_options(aot_fixture_runner PRIVATE /W4 /WX)

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

    add_custom_command(
        OUTPUT "${AOT_DIFF_BIN}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${AOT_GEN_DIR}"
        COMMAND "${AOT_LLVM_MC}" -triple=aarch64-none-elf -filetype=obj
                -o "${AOT_DIFF_OBJ}" "${AOT_DIFF_S}"
        COMMAND "${AOT_LLVM_OBJCOPY}" -O binary --only-section=.text
                "${AOT_DIFF_OBJ}" "${AOT_DIFF_BIN}"
        DEPENDS "${AOT_DIFF_S}"
        COMMENT "Assembling G2 differential ARM64 fixture with LLVM"
        VERBATIM)

    add_custom_command(
        OUTPUT "${AOT_DIFF_C}" "${AOT_DIFF_META}"
        COMMAND "${AOT_PYTHON}" "${CMAKE_SOURCE_DIR}/tools/aot/aot_translate.py"
                --manifest "${AOT_DIFF_MANIFEST}"
                --bin "${AOT_DIFF_BIN}"
                --out "${AOT_DIFF_C}"
                --meta-out "${AOT_DIFF_META}"
                --name diff
        DEPENDS "${AOT_DIFF_BIN}"
                "${CMAKE_SOURCE_DIR}/tools/aot/aot_translate.py"
                "${AOT_DIFF_MANIFEST}"
        COMMENT "Translating G2 differential ARM64 fixture to native C"
        VERBATIM)

    set_source_files_properties("${AOT_DIFF_C}" PROPERTIES GENERATED TRUE)
    add_executable(aot_bin_runner
        tests/aot/aot_bin_runner.c
        src/aot/aot_runtime.c
        src/aot/aot_mem.c
        src/aot/aot_fp.c
        "${AOT_DIFF_C}"
    )
    target_include_directories(aot_bin_runner PRIVATE "${CMAKE_SOURCE_DIR}/src/aot")
    target_compile_options(aot_bin_runner PRIVATE /W4 /WX)

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
    foreach(mut ${AOT_MUT_NAMES})
        set(AOT_MUT_C   "${AOT_GEN_DIR}/mut_${mut}.c")
        set(AOT_MUT_META "${AOT_GEN_DIR}/mut_${mut}.meta.json")
        add_custom_command(
            OUTPUT "${AOT_MUT_C}" "${AOT_MUT_META}"
            COMMAND ${CMAKE_COMMAND} -E make_directory "${AOT_GEN_DIR}"
            COMMAND "${AOT_PYTHON}" "${CMAKE_SOURCE_DIR}/tools/aot/aot_translate.py"
                    --manifest "${AOT_DIFF_MANIFEST}" --bin "${AOT_DIFF_BIN}"
                    --out "${AOT_MUT_C}" --meta-out "${AOT_MUT_META}"
                    --name diff --mutant ${mut}
            DEPENDS "${AOT_DIFF_BIN}"
                    "${CMAKE_SOURCE_DIR}/tools/aot/aot_translate.py"
                    "${AOT_DIFF_MANIFEST}"
            COMMENT "Translating negative-control mutant ${mut}" VERBATIM)
        set_source_files_properties("${AOT_MUT_C}" PROPERTIES GENERATED TRUE)
        add_executable(aot_mut_${mut}
            tests/aot/aot_bin_runner.c
            src/aot/aot_runtime.c
            src/aot/aot_mem.c
            src/aot/aot_fp.c
            "${AOT_MUT_C}")
        target_include_directories(aot_mut_${mut} PRIVATE "${CMAKE_SOURCE_DIR}/src/aot")
        target_compile_options(aot_mut_${mut} PRIVATE /W4 /WX)
    endforeach()

    # HLE-callback mutant (real callback mutation via a test-only compile define).
    add_executable(aot_mut_hlex18
        tests/aot/aot_bin_runner.c
        src/aot/aot_runtime.c
        src/aot/aot_mem.c
        src/aot/aot_fp.c
        "${AOT_DIFF_C}")
    target_include_directories(aot_mut_hlex18 PRIVATE "${CMAKE_SOURCE_DIR}/src/aot")
    target_compile_options(aot_mut_hlex18 PRIVATE /W4 /WX)
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
        src/aot/aot_runtime.c
        src/aot/aot_mem.c)
    target_include_directories(aot_runtime_probe PRIVATE "${CMAKE_SOURCE_DIR}/src/aot")
    target_compile_options(aot_runtime_probe PRIVATE /W4 /WX)
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
        src/aot/aot_runtime.c
        src/aot/aot_mem.c
        src/aot/aot_fp.c
        "${AOT_DIFF_C}")
    target_include_directories(aot_fp_translated_probe
        PRIVATE "${CMAKE_SOURCE_DIR}/src/aot")
    target_compile_options(aot_fp_translated_probe PRIVATE /W4 /WX)
    add_test(NAME aot_fp_translated COMMAND aot_fp_translated_probe)
    set_tests_properties(aot_fp_translated PROPERTIES TIMEOUT 120)

    # Guard-mutant control: the SAME probe source linked against the
    # fpignoreguard image (unsupported FPCR is sanitized to 0 instead of
    # faulting). Positive expectation is a clean STOP that violates the guard
    # contract; the normal image must NOT be accepted in this mode.
    add_executable(aot_fp_translated_probe_guardmut
        tests/aot/aot_fp_translated_probe.c
        src/aot/aot_runtime.c
        src/aot/aot_mem.c
        src/aot/aot_fp.c
        "${AOT_GEN_DIR}/mut_fpignoreguard.c")
    add_dependencies(aot_fp_translated_probe_guardmut aot_mut_fpignoreguard)
    target_include_directories(aot_fp_translated_probe_guardmut
        PRIVATE "${CMAKE_SOURCE_DIR}/src/aot")
    target_compile_options(aot_fp_translated_probe_guardmut PRIVATE /W4 /WX)
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

    add_custom_command(
        OUTPUT "${AOT_CONC_BIN}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${AOT_GEN_DIR}"
        COMMAND "${AOT_LLVM_MC}" -triple=aarch64-none-elf -filetype=obj
                -o "${AOT_CONC_OBJ}" "${AOT_CONC_S}"
        COMMAND "${AOT_LLVM_OBJCOPY}" -O binary --only-section=.text
                "${AOT_CONC_OBJ}" "${AOT_CONC_BIN}"
        DEPENDS "${AOT_CONC_S}"
        COMMENT "Assembling G2 concurrency ARM64 fixture" VERBATIM)

    add_custom_command(
        OUTPUT "${AOT_CONC_C}"
        COMMAND "${AOT_PYTHON}" "${CMAKE_SOURCE_DIR}/tools/aot/aot_translate.py"
                --manifest "${AOT_CONC_MANIFEST}" --bin "${AOT_CONC_BIN}"
                --out "${AOT_CONC_C}" --name conc
        DEPENDS "${AOT_CONC_BIN}" "${AOT_CONC_MANIFEST}"
                "${CMAKE_SOURCE_DIR}/tools/aot/aot_translate.py"
        COMMENT "Translating G2 concurrency fixture" VERBATIM)

    add_custom_command(
        OUTPUT "${AOT_CONC_MUT_C}"
        COMMAND "${AOT_PYTHON}" "${CMAKE_SOURCE_DIR}/tools/aot/aot_translate.py"
                --manifest "${AOT_CONC_MANIFEST}" --bin "${AOT_CONC_BIN}"
                --out "${AOT_CONC_MUT_C}" --name conc_mut --mutant stxalwaysok
        DEPENDS "${AOT_CONC_BIN}" "${AOT_CONC_MANIFEST}"
                "${CMAKE_SOURCE_DIR}/tools/aot/aot_translate.py"
        COMMENT "Translating G2 concurrency stxalwaysok control" VERBATIM)

    set_source_files_properties("${AOT_CONC_C}" "${AOT_CONC_MUT_C}"
        PROPERTIES GENERATED TRUE)
    add_executable(aot_concurrency_probe
        tests/aot/aot_concurrency_probe.c
        src/aot/aot_runtime.c
        src/aot/aot_mem.c
        src/aot/aot_fp.c
        "${AOT_CONC_C}"
        "${AOT_CONC_MUT_C}")
    target_include_directories(aot_concurrency_probe PRIVATE "${CMAKE_SOURCE_DIR}/src/aot")
    target_compile_options(aot_concurrency_probe PRIVATE /W4 /WX)
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
        src/aot/aot_runtime.c
        src/aot/aot_mem.c
        src/aot/aot_fp.c
        "${AOT_CONC_C}")
    add_executable(aot_conc_control_real ${AOT_CONC_CONTROL_SOURCES})
    target_include_directories(aot_conc_control_real PRIVATE "${CMAKE_SOURCE_DIR}/src/aot")
    target_compile_options(aot_conc_control_real PRIVATE /W4 /WX)
    add_executable(aot_conc_control_noinv ${AOT_CONC_CONTROL_SOURCES})
    target_include_directories(aot_conc_control_noinv PRIVATE "${CMAKE_SOURCE_DIR}/src/aot")
    target_compile_options(aot_conc_control_noinv PRIVATE /W4 /WX)
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
endif()
