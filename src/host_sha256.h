/* Narrow Windows host SHA-256 primitive (streaming).
 *
 * Scope: hashes PUBLIC bulk data on the host (the RomFS image, D020) at
 * platform speed. It is not a guest service and does not replace
 * src/aot/aot_sha256 for the loader; both must produce identical FIPS 180-4
 * digests, which tests/host_sha256_probe.c checks.
 *
 * Contract:
 *   - host_sha256_begin() creates an owning handle; on failure *out is NULL
 *     and a typed error is returned;
 *   - host_sha256_update() feeds any number of bytes (n may exceed 4 GiB;
 *     the backend splits it); data may be NULL only when n == 0;
 *   - host_sha256_finish() writes the 32-byte digest on success and ALWAYS
 *     consumes the handle; on failure `out` is left unchanged;
 *   - host_sha256_abort() frees a handle without producing a digest (NULL
 *     is accepted);
 *   - after a failed update the handle must only be aborted.
 *
 * Windows backend: CNG BCryptCreateHash/BCryptHashData/BCryptFinishHash on
 * the BCRYPT_SHA256_ALG_HANDLE pseudo-handle (uses the CPU SHA extensions
 * when present).
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HOST_SHA256_DIGEST_BYTES 32u

typedef enum host_sha256_result {
    HOST_SHA256_OK = 0,
    HOST_SHA256_ERR_INVALID_ARGUMENT = 1,
    HOST_SHA256_ERR_PLATFORM = 2,
    HOST_SHA256_ERR_ALLOCATION = 3
} host_sha256_result;

typedef struct HostSha256 HostSha256;

host_sha256_result host_sha256_begin(HostSha256 **out);
host_sha256_result host_sha256_update(HostSha256 *h, const void *data,
                                      size_t n);
host_sha256_result host_sha256_finish(HostSha256 *h,
                                      uint8_t out[HOST_SHA256_DIGEST_BYTES]);
void host_sha256_abort(HostSha256 *h);

#ifdef __cplusplus
}
#endif
