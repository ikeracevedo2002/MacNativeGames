/* Narrow Windows host entropy primitive (G3 Start HLE support).
 *
 * Scope: this is a HOST-platform CSPRNG source, not a Horizon random
 * service and not an nn::os API. It exists only so the translated
 * GetInfo(id 11) path can obtain real entropy from the platform instead
 * of a constant/LCG or a host pointer.
 *
 * Contract:
 *   - host_random_u64() returns HOST_RANDOM_OK and writes exactly 8 bytes
 *     of BCryptGenRandom output on success;
 *   - on any platform/argument failure it returns a typed error and leaves
 *     the caller's output value unchanged (a failed call must never be
 *     mistaken for zero entropy);
 *   - zero is a valid successful output, because CSPRNG output may be zero.
 *
 * Windows backend: BCryptGenRandom(NULL, ..., BCRYPT_USE_SYSTEM_PREFERRED_RNG)
 * as documented by Microsoft. That flag requires hAlgorithm == NULL.
 */

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum host_random_result {
    HOST_RANDOM_OK = 0,
    HOST_RANDOM_ERR_INVALID_ARGUMENT = 1,
    HOST_RANDOM_ERR_PLATFORM = 2
} host_random_result;

host_random_result host_random_u64(uint64_t *out);

#ifdef __cplusplus
}
#endif
