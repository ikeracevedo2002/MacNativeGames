/* Windows x64 host monotonic clock backend.
 *
 * Reads QueryPerformanceCounter and scales it with the exact integer
 * helper in host_time_convert.c. No floating point is used anywhere on
 * this path. See host_time.h for the documented semantics (arbitrary
 * non-wall epoch, per-thread nondecreasing, no cross-thread ordering
 * guarantee, no equivalence to either Mach clock).
 *
 * QueryPerformanceFrequency is documented to be fixed at system boot, so
 * it is re-read on every call rather than cached: the call is cheap and
 * re-reading avoids introducing shared mutable state / a once-guard on
 * a primitive that may be called from several threads.
 */

#include "host_time.h"

#if !defined(_WIN32)
#  error "host_time.c is the Windows x64 backend; the Mac path keeps its own clock."
#endif

#include <windows.h>

host_time_result host_time_now_ns(uint64_t *out_ns)
{
    LARGE_INTEGER frequency;
    LARGE_INTEGER counter;
    uint64_t scaled = 0;

    if (out_ns == 0) {
        return HOST_TIME_ERR_INVALID_ARGUMENT;
    }

    if (!QueryPerformanceFrequency(&frequency) || frequency.QuadPart <= 0) {
        return HOST_TIME_ERR_CLOCK_FAILED;
    }
    if (!QueryPerformanceCounter(&counter) || counter.QuadPart < 0) {
        return HOST_TIME_ERR_CLOCK_FAILED;
    }

    /* On failure the scaling helper leaves `scaled` untouched; we only
     * publish it to the caller after a successful conversion. */
    if (host_time_ticks_to_ns((uint64_t)counter.QuadPart,
                              (uint64_t)frequency.QuadPart,
                              &scaled) != HOST_TIME_OK) {
        return HOST_TIME_ERR_OVERFLOW;
    }

    *out_ns = scaled;
    return HOST_TIME_OK;
}
