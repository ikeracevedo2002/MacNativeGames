/* Pure-integer tick -> nanosecond scaling.
 *
 * Deliberately free of any Win32 / OS dependency so the scaling can be
 * compiled and tested on its own, and so the backend (host_time.c) only
 * owns the platform counter read. Uses 128-bit intermediates so
 * ticks * 1e9 never wraps, and rejects a quotient that does not fit in
 * uint64_t instead of silently truncating.
 *
 * floor(ticks * 1e9 / frequency) is computed exactly:
 *   numerator   = ticks * 1e9               (up to 94 bits)
 *   quotient    = numerator / frequency     (128 -> 64 bit divide)
 *
 * Overflow condition: with numerator = hi*2^64 + lo, floor(numerator /
 * frequency) >= 2^64 exactly when hi >= frequency. That is checked
 * before the 128-bit divide, because the divide primitive requires
 * hi < divisor.
 */

#include "host_time.h"

#define HOST_TIME_NS_PER_SECOND 1000000000ull

#if defined(_MSC_VER) && defined(_M_X64)
#  include <intrin.h>
#  define HOST_TIME_USE_MSVC_INTRINSICS 1
/* Non-MSVC fallback for portability. It is NOT the locally validated
 * path on this branch (the MSVC x64 intrinsic path is); do not infer
 * broader compiler support from it. */
#elif defined(__SIZEOF_INT128__)
#  define HOST_TIME_USE_INT128 1
#else
#  error "host_time_convert.c requires MSVC x64 (_umul128/_udiv128) or a compiler with __int128."
#endif

/* Unsigned 64x64 -> 128 multiply; returns the low half, writes the high
 * half. */
static uint64_t host_time_mul_u64(uint64_t a, uint64_t b, uint64_t *hi_out)
{
#if defined(HOST_TIME_USE_MSVC_INTRINSICS)
    return _umul128(a, b, hi_out);
#else
    unsigned __int128 p = (unsigned __int128)a * (unsigned __int128)b;
    *hi_out = (uint64_t)(p >> 64);
    return (uint64_t)p;
#endif
}

/* Unsigned 128/64 divide. Precondition: divisor != 0 and hi < divisor.
 * Returns the quotient and writes the remainder. */
static uint64_t host_time_div_u128_u64(uint64_t hi, uint64_t lo,
                                       uint64_t divisor, uint64_t *rem_out)
{
#if defined(HOST_TIME_USE_MSVC_INTRINSICS)
    return _udiv128(hi, lo, divisor, rem_out);
#else
    unsigned __int128 numerator = ((unsigned __int128)hi << 64) |
                                  (unsigned __int128)lo;
    unsigned __int128 d = (unsigned __int128)divisor;
    *rem_out = (uint64_t)(numerator % d);
    return (uint64_t)(numerator / d);
#endif
}

host_time_result host_time_ticks_to_ns(uint64_t ticks, uint64_t frequency_hz,
                                       uint64_t *out_ns)
{
    uint64_t hi = 0;
    uint64_t lo;
    uint64_t rem = 0;
    uint64_t quotient;

    if (out_ns == 0) {
        return HOST_TIME_ERR_INVALID_ARGUMENT;
    }
    /* No implicit zero-frequency policy: a zero rate cannot be scaled. */
    if (frequency_hz == 0) {
        return HOST_TIME_ERR_INVALID_ARGUMENT;
    }

    lo = host_time_mul_u64(ticks, HOST_TIME_NS_PER_SECOND, &hi);

    /* hi >= frequency_hz => floor(numerator / frequency_hz) >= 2^64. */
    if (hi >= frequency_hz) {
        return HOST_TIME_ERR_OVERFLOW;
    }

    quotient = host_time_div_u128_u64(hi, lo, frequency_hz, &rem);
    (void)rem; /* floor: remainder intentionally discarded */

    *out_ns = quotient;
    return HOST_TIME_OK;
}
