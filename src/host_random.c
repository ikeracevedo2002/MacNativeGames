/* Windows x64 host CSPRNG backend (BCryptGenRandom). */

#include "host_random.h"

#if !defined(_WIN32)
#  error "host_random.c is the Windows x64 backend."
#endif

#include <windows.h>
#include <bcrypt.h>

/* Private compile-time seam for the deterministic backend test. Production
 * builds always use the real platform API; there is no runtime setter. */
#ifndef MN_HOST_RANDOM_GEN_RANDOM
#define MN_HOST_RANDOM_GEN_RANDOM(h, out, len, flags) \
    BCryptGenRandom((h), (out), (len), (flags))
#endif

host_random_result host_random_u64(uint64_t *out)
{
    uint64_t tmp = 0;
    NTSTATUS status;

    if (out == NULL) {
        return HOST_RANDOM_ERR_INVALID_ARGUMENT;
    }

    status = MN_HOST_RANDOM_GEN_RANDOM(NULL, (PUCHAR)&tmp,
                                      (ULONG)sizeof tmp,
                                      BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status < 0) {
        /* Do not publish a partially filled or zero value as success. */
        return HOST_RANDOM_ERR_PLATFORM;
    }

    *out = tmp;
    return HOST_RANDOM_OK;
}
