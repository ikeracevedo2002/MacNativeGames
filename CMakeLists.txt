# Build-skeleton row: Windows x86-64 host probe (G1, narrow scope).
#
# What this CMake project does:
#   - rejects non-Windows and non-AMD64 hosts at configure time
#   - refuses in-source and source-subdirectory build dirs
#   - compiles the platform-neutral RomFS path probe unmodified
#   - compiles the small host_check host executable
#   - registers a CTest suite whose negative-control test verifies BOTH
#     the exact non-zero exit code AND the explicit diagnostic via
#     tests/verify_host_negative_control.cmd
#
# What this project does NOT do (G1 is broader than this row; see
# PORTING_STATUS.md): VM, timing, TLS, threads, loader, AOT translation,
# graphics, audio, controller, frontend, packaging.

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
