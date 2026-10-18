/* Build-skeleton host probe.
 *
 * Windows x86-64 architecture gate (compile-time + runtime). The single
 * check_pointer_width() path is shared by normal mode and the deliberate
 * --negative-control mode: the latter only changes the expected argument
 * so the diagnostic has identical shape in both cases.
 *
 * The platform-neutral RomFS probe (tests/test_romfs_paths.c) is built
 * and run separately by CTest so a regression in it is visible on its
 * own, without coupling to this host executable.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Compile-time architecture gates: fail the build for any host that is
 * not Windows x64. */
#if !defined(_WIN32)
#  error "host_check: requires _WIN32."
#endif
#if !defined(_WIN64)
#  error "host_check: requires _WIN64 (32-bit Windows is out of scope per D001)."
#endif
#if !defined(_M_AMD64) && !defined(__amd64__)
#  error "host_check: requires AMD64 / x86-64 (ARM64 Windows is out of scope per D001)."
#endif

/* _Static_assert, unlike #if, can read sizeof(void *) at compile time. */
_Static_assert(sizeof(void *) == 8,
               "host_check: sizeof(void *) must be 8 on AMD64.");
_Static_assert(sizeof(uintptr_t) == 8,
               "host_check: sizeof(uintptr_t) must be 8 on AMD64.");

/* Single checker path for both normal and --negative-control modes.
 * The diagnostic includes both expected and actual so the failure is
 * unambiguous. */
static int check_pointer_width(uintptr_t expected, const char *label) {
    uintptr_t actual = (uintptr_t)sizeof(void *);
    fprintf(stdout, "[%s] pointer width = %llu byte(s)\n",
            label, (unsigned long long)actual);
    if (actual != expected) {
        fprintf(stderr,
                "[%s] FAIL: expected pointer width %llu byte(s), got %llu\n",
                label,
                (unsigned long long)expected,
                (unsigned long long)actual);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    /* Strict argument parsing: the only recognised form is a single
     * optional --negative-control token. Anything else is rejected so
     * unknown flags cannot silently change behaviour. */
    int negative = 0;
    if (argc == 2 && strcmp(argv[1], "--negative-control") == 0) {
        negative = 1;
    } else if (argc != 1) {
        fprintf(stderr, "usage: %s [--negative-control]\n", argv[0]);
        return 2;
    }

    const char *label = negative ? "negative-control" : "host";
    uintptr_t expected = negative ? (uintptr_t)4 : (uintptr_t)8;

    int rc = check_pointer_width(expected, label);
    if (rc == 0 && !negative) {
        fprintf(stdout, "PASS: host architecture satisfied\n");
    }
    return rc;
}
