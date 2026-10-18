/* Host monotonic clock abstraction (G1 timing row).
 *
 * Scope: this is a HOST-platform time source. It is NOT an nn::time /
 * Horizon guest clock and it defines no guest clock policy. The Mac
 * guest time service (games/totk/runtime/time_host.c) and the Mac
 * runtime clock (games/totk/runtime/loader.c runtime_now_ns) are
 * deliberately untouched; this header only provides a new, separately
 * testable Windows host primitive.
 *
 * Semantics of host_time_now_ns():
 *
 *   - Returns nanoseconds in a uint64_t. Values are exact integer
 *     nanoseconds derived from the platform counter; no floating point
 *     is used.
 *
 *   - The epoch is arbitrary and NOT a wall-clock epoch. A value is only
 *     meaningful as a difference between two reads, never as a date or
 *     a time-of-day. A later process run may start at a different value.
 *
 *   - On Windows the value is QueryPerformanceCounter() scaled by
 *     QueryPerformanceFrequency() with exact integer scaling
 *     floor(ticks * 1e9 / frequency). Overflow is reported, never
 *     silently wrapped.
 *
 *   - Microsoft documents QueryPerformanceCounter as monotonic, with a
 *     frequency fixed at system boot and consistent across processors,
 *     and as including time the system spends in sleep/standby. The QPC
 *     FAQ also notes that when comparing reads from different threads,
 *     values that differ by +/-1 tick have an ambiguous ordering. Reads
 *     on the SAME thread are therefore nondecreasing,
 *     but this API does NOT promise a globally strictly ordered
 *     timestamp across threads, so callers must not assume that a read
 *     on one thread is >= a read on another thread.
 *     Source (Microsoft, "Acquiring high-resolution time stamps", QPC
 *     FAQ):
 *     https://learn.microsoft.com/en-us/windows/win32/sysinfo/acquiring-high-resolution-time-stamps
 *
 *   - Suspend/standby behaviour is documented from the platform
 *     contract; it is NOT measured by the probes in this row. Treat it
 *     as documented-but-unverified here.
 *
 *   - This API makes NO claim that Windows QueryPerformanceCounter is
 *     equivalent to Apple's mach_absolute_time or mach_continuous_time.
 *     Those two Mach clocks differ exactly in whether they advance
 *     across sleep (absolute_time excludes sleep, continuous_time
 *     includes it). That Mac distinction is a Mac-specific contract and
 *     is not mapped onto this API. Any future guest-clock binding must
 *     choose its suspend policy explicitly and must not assume this
 *     host source matches either Mach clock.
 *
 * Error handling is explicit: every entry point can fail and reports a
 * host_time_result. On any failure the output parameter is left
 * unchanged, so a caller may safely pass an initialised value and only
 * consume it on HOST_TIME_OK.
 */

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum host_time_result {
    /* Success; the output parameter was written. */
    HOST_TIME_OK = 0,
    /* A mandatory output pointer was NULL, or frequency was zero. The
     * output parameter (if any) is unchanged. */
    HOST_TIME_ERR_INVALID_ARGUMENT = 1,
    /* The host clock could not be queried. The output parameter is
     * unchanged. */
    HOST_TIME_ERR_CLOCK_FAILED = 2,
    /* ticks * 1e9 / frequency does not fit in uint64_t. The output
     * parameter is unchanged. */
    HOST_TIME_ERR_OVERFLOW = 3
} host_time_result;

/* Read the host monotonic clock as nanoseconds.
 *
 * On success writes the current host time to *out_ns and returns
 * HOST_TIME_OK. On failure *out_ns is left unchanged. A NULL out_ns is
 * rejected with HOST_TIME_ERR_INVALID_ARGUMENT.
 */
host_time_result host_time_now_ns(uint64_t *out_ns);

/* Exact floor(ticks * 1000000000 / frequency_hz), without floating
 * point and without intermediate overflow.
 *
 * Exposed separately from the platform read so the scaling can be
 * tested deterministically on fixed inputs, and so a caller that
 * already has raw counter ticks can reuse it.
 *
 * Supported domain: frequency_hz > 0 and ticks * 1e9 / frequency_hz
 * representable in uint64_t. Out-of-domain inputs are rejected:
 *   - out_ns == NULL or frequency_hz == 0
 *       -> HOST_TIME_ERR_INVALID_ARGUMENT (out_ns unchanged);
 *   - result would exceed UINT64_MAX
 *       -> HOST_TIME_ERR_OVERFLOW (out_ns unchanged).
 * On HOST_TIME_OK, *out_ns == floor(ticks * 1e9 / frequency_hz) exactly.
 */
host_time_result host_time_ticks_to_ns(uint64_t ticks,
                                       uint64_t frequency_hz,
                                       uint64_t *out_ns);

#ifdef __cplusplus
}
#endif
