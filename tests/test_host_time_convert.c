/* Deterministic tests for host_time_ticks_to_ns (G1 timing row).
 *
 * The expected constants in `cases` were computed independently with
 * arbitrary-precision arithmetic (Python integers), not by calling the
 * implementation under test. They cover:
 *   - zero ticks;
 *   - subsecond and exact-second boundaries;
 *   - frequencies that do not divide 1e9 (so the result must be floored);
 *   - a large tick count where a naive 64-bit ticks*1e9 wraps but the
 *     true floor(ticks*1e9/frequency) still fits in uint64_t;
 *   - an exact fit and the largest quotient that still fits;
 *   - real overflow (naive and correct implementations must both refuse);
 *   - zero frequency and NULL output, which must leave output untouched.
 *
 * Negative controls: the SAME run_suite() checker is run against five
 * deliberately wrong implementations (constant zero, wrong unit, naive
 * 64-bit multiply, uint32-truncated frequency, and error-output clobber).
 * The executable FAILS unless the checker rejects each one, so a checker
 * that accidentally accepts everything cannot pass. There is no inverted
 * test and no PASS_REGULAR_EXPRESSION: the process exit status is the
 * result.
 */

#include "host_time.h"

#include <stdint.h>
#include <stdio.h>

typedef host_time_result (*convert_fn)(uint64_t ticks, uint64_t frequency,
                                       uint64_t *out_ns);

typedef struct {
    const char *name;
    uint64_t ticks;
    uint64_t frequency;
    host_time_result want_rc;
    uint64_t want_ns; /* only meaningful when want_rc == HOST_TIME_OK */
} ConvertCase;

static const ConvertCase cases[] = {
    /* zero */
    {"zero ticks", 0ull, 10000000ull, HOST_TIME_OK, 0ull},
    /* subsecond */
    {"subsecond 10MHz", 1ull, 10000000ull, HOST_TIME_OK, 100ull},
    {"subsecond us", 123456ull, 1000000ull, HOST_TIME_OK, 123456000ull},
    {"1 GHz -> 1 ns", 1ull, 1000000000ull, HOST_TIME_OK, 1ull},
    /* second boundary */
    {"second boundary 1Hz", 1ull, 1ull, HOST_TIME_OK, 1000000000ull},
    {"second boundary 10MHz", 10000000ull, 10000000ull, HOST_TIME_OK,
     1000000000ull},
    /* non-divisor frequency: result must be floored */
    {"non-divisor /3", 1ull, 3ull, HOST_TIME_OK, 333333333ull},
    {"non-divisor /7", 11ull, 7ull, HOST_TIME_OK, 1571428571ull},
    /* exact fit */
    {"exact fit /8", 125000000ull, 8ull, HOST_TIME_OK, 15625000000000000ull},
    {"exact fit /1000", 123456789ull, 1000ull, HOST_TIME_OK,
     123456789000000ull},
    {"numerator just below 2^64", 18446744073ull, 1000000000ull, HOST_TIME_OK,
     18446744073ull},
    /* naive ticks*1e9 wraps here, but the true result fits */
    {"naive-wrap 1e9", 12345678901234ull, 1000000000ull, HOST_TIME_OK,
     12345678901234ull},
    {"naive-wrap non-divisor", 12345678901234ull, 999999937ull, HOST_TIME_OK,
     12345679679011ull},
    /* largest quotient that still fits: ticks=UINT64_MAX, freq=1e9 */
    {"max fits @1e9", UINT64_MAX, 1000000000ull, HOST_TIME_OK, UINT64_MAX},
    /* actual overflow: floor(ticks*1e9/freq) >= 2^64 */
    {"overflow @1Hz", UINT64_MAX, 1ull, HOST_TIME_ERR_OVERFLOW, 0ull},
    {"overflow boundary", 18446744074ull, 1ull, HOST_TIME_ERR_OVERFLOW, 0ull},
    /* uint64 frequency divisors are legal and must not be truncated */
    {"divisor UINT64_MAX", UINT64_MAX, UINT64_MAX, HOST_TIME_OK,
     1000000000ull},
    {"divisor above 1e9", 1ull, 4294967297ull, HOST_TIME_OK, 0ull},
    {"divisor 2^63", UINT64_MAX, 9223372036854775808ull, HOST_TIME_OK,
     1999999999ull},
    /* zero frequency is rejected and leaves the output untouched */
    {"zero frequency", 1ull, 0ull, HOST_TIME_ERR_INVALID_ARGUMENT, 0ull},
};

/* -------- deliberately wrong implementations used as negative controls -------- */

static host_time_result wrong_constant_zero(uint64_t ticks, uint64_t frequency,
                                            uint64_t *out_ns)
{
    (void)ticks;
    (void)frequency;
    if (out_ns == 0) {
        return HOST_TIME_ERR_INVALID_ARGUMENT;
    }
    *out_ns = 0ull;
    return HOST_TIME_OK;
}

static host_time_result wrong_unit_us(uint64_t ticks, uint64_t frequency,
                                      uint64_t *out_ns)
{
    if (out_ns == 0 || frequency == 0) {
        return HOST_TIME_ERR_INVALID_ARGUMENT;
    }
    /* Wrong scale: microseconds labelled as nanoseconds. */
    *out_ns = (ticks * 1000000ull) / frequency;
    return HOST_TIME_OK;
}

static host_time_result wrong_naive_overflow(uint64_t ticks, uint64_t frequency,
                                             uint64_t *out_ns)
{
    if (out_ns == 0 || frequency == 0) {
        return HOST_TIME_ERR_INVALID_ARGUMENT;
    }
    /* Correct scale but naive 64-bit multiply, so overflow wraps silently. */
    *out_ns = (ticks * 1000000000ull) / frequency;
    return HOST_TIME_OK;
}

static host_time_result wrong_truncated_frequency(uint64_t ticks,
                                                  uint64_t frequency,
                                                  uint64_t *out_ns)
{
    /* Uses the correct converter but truncates a 64-bit frequency to 32
     * bits first. Truncation can also produce zero, which the converter
     * safely rejects instead of dividing by zero. */
    return host_time_ticks_to_ns(ticks, (uint32_t)frequency, out_ns);
}

static host_time_result wrong_clobber_on_error(uint64_t ticks,
                                               uint64_t frequency,
                                               uint64_t *out_ns)
{
    host_time_result rc = host_time_ticks_to_ns(ticks, frequency, out_ns);
    if (rc != HOST_TIME_OK && out_ns != 0) {
        *out_ns = 0ull; /* violates "output unchanged on failure" */
    }
    return rc;
}

/* -------- shared checker -------- */

static int run_case(convert_fn fn, const ConvertCase *c, int explain)
{
    const uint64_t sentinel = 0xA5A5A5A5A5A5A5A5ull;
    uint64_t got = sentinel;
    host_time_result rc = fn(c->ticks, c->frequency, &got);
    int ok = 1;

    if (rc != c->want_rc) {
        ok = 0;
        if (explain) {
            fprintf(stderr,
                    "  FAIL %-24s ticks=%llu freq=%llu: rc=%d want=%d\n",
                    c->name, (unsigned long long)c->ticks,
                    (unsigned long long)c->frequency, (int)rc,
                    (int)c->want_rc);
        }
    } else if (c->want_rc == HOST_TIME_OK) {
        if (got != c->want_ns) {
            ok = 0;
            if (explain) {
                fprintf(stderr,
                        "  FAIL %-24s ticks=%llu freq=%llu: got=%llu want=%llu\n",
                        c->name, (unsigned long long)c->ticks,
                        (unsigned long long)c->frequency,
                        (unsigned long long)got,
                        (unsigned long long)c->want_ns);
            }
        }
    } else if (got != sentinel) {
        ok = 0;
        if (explain) {
            fprintf(stderr,
                    "  FAIL %-24s: output was modified on error (got=%llu)\n",
                    c->name, (unsigned long long)got);
        }
    }
    return ok;
}

static int run_suite(convert_fn fn, const char *label, int explain)
{
    const size_t n = sizeof cases / sizeof cases[0];
    size_t i;
    int failures = 0;

    for (i = 0; i < n; i++) {
        if (!run_case(fn, &cases[i], explain)) {
            failures++;
        }
    }
    if (explain) {
        printf("[%s] %d/%d conversion cases passed\n", label,
               (int)(n - (size_t)failures), (int)n);
    }
    return failures;
}

int main(void)
{
    const size_t n = sizeof cases / sizeof cases[0];
    int real_failures;
    int negative_controls_failed = 0;
    size_t i;

    static const struct {
        const char *name;
        convert_fn fn;
    } wrong[] = {
        {"constant-zero", wrong_constant_zero},
        {"wrong-unit-microseconds", wrong_unit_us},
        {"naive-64bit-overflow", wrong_naive_overflow},
        {"uint32-truncated-frequency", wrong_truncated_frequency},
        {"clobber-output-on-error", wrong_clobber_on_error},
    };

    real_failures = run_suite(host_time_ticks_to_ns, "host_time_ticks_to_ns", 1);

    /* NULL output cannot be exercised through the table (it passes a valid
     * pointer), so check it directly. The implementation must reject it. */
    {
        host_time_result rc = host_time_ticks_to_ns(1ull, 1ull, 0);
        if (rc != HOST_TIME_ERR_INVALID_ARGUMENT) {
            fprintf(stderr,
                    "  FAIL null-output: rc=%d want=%d\n", (int)rc,
                    (int)HOST_TIME_ERR_INVALID_ARGUMENT);
            real_failures++;
        }
    }

    for (i = 0; i < sizeof wrong / sizeof wrong[0]; i++) {
        int rejected = run_suite(wrong[i].fn, wrong[i].name, 0);
        if (rejected == 0) {
            fprintf(stderr,
                    "  FAIL negative control '%s' was NOT rejected by the "
                    "checker\n",
                    wrong[i].name);
            negative_controls_failed++;
        } else {
            printf("negative control '%s' correctly rejected (%d case "
                   "mismatch(es))\n",
                   wrong[i].name, rejected);
        }
    }

    if (real_failures != 0 || negative_controls_failed != 0) {
        fprintf(stderr,
                "FAIL: host_time_ticks_to_ns (%d real failure(s), %d "
                "un-rejected negative control(s))\n",
                real_failures, negative_controls_failed);
        return 1;
    }

    printf("PASS: %d conversion cases + %d negative controls\n", (int)n,
           (int)(sizeof wrong / sizeof wrong[0]));
    return 0;
}
