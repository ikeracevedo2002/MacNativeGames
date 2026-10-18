/* Live Windows host monotonic clock probe (G1 timing row).
 *
 * Checks the real host_time_now_ns on the running Windows x64 host:
 *   1. every read succeeds;
 *   2. repeated reads on this thread are nondecreasing;
 *   3. a real host wait produces a positive elapsed time;
 *   4. the elapsed nanoseconds fall inside a conservative interval built
 *      from an independent Windows reference (GetTickCount64,
 *      milliseconds) that brackets BOTH clock reads, so a merely-
 *      monotonic wrong-scale implementation (for example microseconds
 *      labelled nanoseconds) is rejected without depending on scheduler
 *      timing.
 *
 * This is a correctness probe, not a performance benchmark: the bound is
 * wide enough to absorb scheduler and GetTickCount64 granularity effects.
 *
 * Negative controls: the SAME check_live() checker is run against (a) a
 * constant clock and (b) the real clock divided by 1000 (wrong scale).
 * The process fails unless the checker rejects both. There is no
 * inverted test and no PASS_REGULAR_EXPRESSION; exit status is the
 * result, and CTest applies an external timeout for the live wait.
 */

#include "host_time.h"

#include <windows.h>

#include <stdio.h>

#define HOST_TIME_PROBE_WAIT_MS 200u
/* GetTickCount64 has coarse (typically ~16 ms) granularity, so each
 * interval bound can be off by one update tick. 32 ms of slack is applied
 * to both ends of the bracketed reference interval; this is still far
 * below the ~1000x error produced by a wrong-unit clock. */
#define HOST_TIME_PROBE_QUANTIZATION_NS 32000000ull

typedef host_time_result (*now_fn)(uint64_t *out_ns);

static host_time_result constant_now(uint64_t *out_ns)
{
    if (out_ns == 0) {
        return HOST_TIME_ERR_INVALID_ARGUMENT;
    }
    *out_ns = 0x123456789ABCDEFull;
    return HOST_TIME_OK;
}

static host_time_result wrong_scale_now(uint64_t *out_ns)
{
    uint64_t ns = 0;
    host_time_result rc = host_time_now_ns(&ns);
    if (rc == HOST_TIME_OK) {
        *out_ns = ns / 1000ull; /* wrong unit (ns -> microseconds); still monotonic */
    }
    return rc;
}

/* Shared checker. Returns the number of failed checks (0 == pass). */
static int check_live(now_fn fn, const char *label, int explain, unsigned wait_ms)
{
    int failures = 0;
    uint64_t first = 0;
    uint64_t prev;
    uint64_t before = 0;
    uint64_t after = 0;
    uint64_t elapsed_ns = 0;
    uint64_t reference_lower_ns = 0;
    uint64_t reference_upper_ns = 0;
    int i;

    if (fn(&first) != HOST_TIME_OK) {
        if (explain) {
            fprintf(stderr, "[%s] first read failed\n", label);
        }
        return 1;
    }

    /* 2. nondecreasing samples, same thread. */
    prev = first;
    for (i = 0; i < 4; i++) {
        uint64_t now = 0;
        Sleep(1);
        if (fn(&now) != HOST_TIME_OK) {
            if (explain) {
                fprintf(stderr, "[%s] sample %d read failed\n", label, i);
            }
            failures++;
            break;
        }
        if (now < prev) {
            if (explain) {
                fprintf(stderr,
                        "[%s] sample %d went backwards: %llu < %llu\n", label,
                        i, (unsigned long long)now, (unsigned long long)prev);
            }
            failures++;
        }
        prev = now;
    }

    /* 3/4. positive, correctly-scaled elapsed time across a real wait.
     *
     * The independent reference is read on BOTH sides of each clock read:
     *
     *   ref_a0, before, ref_a1, Sleep, ref_b0, after, ref_b1
     *
     * If both clocks measure the same real timeline, then the true
     * elapsed host time lies inside the conservative interval
     *
     *   [ref_b0 - ref_a1, ref_b1 - ref_a0]
     *
     * regardless of scheduling delays around either clock read. The
     * quantization constant widens both ends to absorb GetTickCount64
     * granularity. This keeps the unit check independent without the
     * false positives a single outer bracket would have. */
    {
        ULONGLONG ref_a0;
        ULONGLONG ref_a1;
        ULONGLONG ref_b0;
        ULONGLONG ref_b1;
        uint64_t lower_raw_ns;
        uint64_t upper_raw_ns;

        ref_a0 = GetTickCount64();
        if (fn(&before) != HOST_TIME_OK) {
            if (explain) {
                fprintf(stderr, "[%s] pre-wait read failed\n", label);
            }
            return failures + 1;
        }
        ref_a1 = GetTickCount64();

        Sleep(wait_ms);

        ref_b0 = GetTickCount64();
        if (fn(&after) != HOST_TIME_OK) {
            if (explain) {
                fprintf(stderr, "[%s] post-wait read failed\n", label);
            }
            return failures + 1;
        }
        ref_b1 = GetTickCount64();

        /* Explicitly reject a backwards post-wait read before the unsigned
         * subtraction: a smaller value would wrap elapsed_ns to a huge
         * value and mask the real failure direction. */
        if (after < before) {
            if (explain) {
                fprintf(stderr,
                        "[%s] post-wait read went backwards: %llu < %llu\n",
                        label, (unsigned long long)after,
                        (unsigned long long)before);
            }
            return failures + 1;
        }

        elapsed_ns = after - before;

        /* Conservative raw interval; clamp a negative coarse lower bound. */
        lower_raw_ns = ref_b0 > ref_a1
                           ? (uint64_t)(ref_b0 - ref_a1) * 1000000ull
                           : 0ull;
        upper_raw_ns = (uint64_t)(ref_b1 - ref_a0) * 1000000ull;

        reference_lower_ns =
            lower_raw_ns > HOST_TIME_PROBE_QUANTIZATION_NS
                ? lower_raw_ns - HOST_TIME_PROBE_QUANTIZATION_NS
                : 0ull;
        reference_upper_ns =
            upper_raw_ns + HOST_TIME_PROBE_QUANTIZATION_NS;

        if (elapsed_ns == 0) {
            if (explain) {
                fprintf(stderr,
                        "[%s] no elapsed time across a %u ms wait (constant "
                        "clock?)\n",
                        label, wait_ms);
            }
            failures++;
        }
        if (elapsed_ns < reference_lower_ns ||
            elapsed_ns > reference_upper_ns) {
            if (explain) {
                fprintf(stderr,
                        "[%s] scale check failed: elapsed=%llu ns outside "
                        "allowed reference interval [%llu, %llu] ns "
                        "(raw interval [%llu, %llu] ns, quantization "
                        "%llu ns)\n",
                        label, (unsigned long long)elapsed_ns,
                        (unsigned long long)reference_lower_ns,
                        (unsigned long long)reference_upper_ns,
                        (unsigned long long)lower_raw_ns,
                        (unsigned long long)upper_raw_ns,
                        (unsigned long long)HOST_TIME_PROBE_QUANTIZATION_NS);
            }
            failures++;
        }
    }

    if (explain && failures == 0) {
        printf("[%s] nondecreasing samples; %u ms wait elapsed=%llu ns "
               "inside reference interval [%llu, %llu] ns\n",
               label, wait_ms, (unsigned long long)elapsed_ns,
               (unsigned long long)reference_lower_ns,
               (unsigned long long)reference_upper_ns);
    }
    return failures;
}

int main(void)
{
    int real;
    int const_rejected;
    int scale_rejected;
    host_time_result null_rc;

    /* NULL output is part of the API contract even though the live checker
     * always passes a valid pointer. */
    null_rc = host_time_now_ns(0);
    if (null_rc != HOST_TIME_ERR_INVALID_ARGUMENT) {
        fprintf(stderr,
                "FAIL: host_time_now_ns(NULL) returned %d, want %d\n",
                (int)null_rc, (int)HOST_TIME_ERR_INVALID_ARGUMENT);
        return 1;
    }

    real = check_live(host_time_now_ns, "live", 1, HOST_TIME_PROBE_WAIT_MS);
    if (real != 0) {
        fprintf(stderr, "FAIL: live host clock probe reported %d failure(s)\n",
                real);
        return 1;
    }

    const_rejected =
        check_live(constant_now, "neg-constant", 0, HOST_TIME_PROBE_WAIT_MS);
    scale_rejected =
        check_live(wrong_scale_now, "neg-scale", 0, HOST_TIME_PROBE_WAIT_MS);

    if (const_rejected == 0 || scale_rejected == 0) {
        fprintf(stderr,
                "FAIL: negative control not rejected (constant=%d, "
                "wrong-scale=%d)\n",
                const_rejected, scale_rejected);
        return 1;
    }

    printf("PASS: live host monotonic clock + scale check; negative controls "
           "rejected (constant=%d, wrong-scale=%d)\n",
           const_rejected, scale_rejected);
    return 0;
}
