/*
 * G3 increment 2: SHA-256 (FIPS 180-4) used by the module loader.
 *
 * Two uses:
 *   - exact-version verification: the SHA-256 of every flat module image is
 *     compared with the value pinned in its AotModuleDesc BEFORE any region is
 *     added or any byte is written;
 *   - the link digest: after relocation the loader hashes the concatenation,
 *     in module order, of every module's relocated data segment and compares
 *     it with the digest produced offline by the independent Python reference
 *     linker.
 *
 * This is a plain, dependency-free implementation. It is deliberately NOT
 * constant-time and must not be used for secrets; it only ever hashes public
 * module bytes.
 */
#ifndef MN_AOT_SHA256_H
#define MN_AOT_SHA256_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AOT_SHA256_DIGEST_BYTES 32u
#define AOT_SHA256_BLOCK_BYTES 64u

/* Streaming state. Treat the fields as opaque; only the functions below may
 * touch them. It carries no pointers, so it can be copied by value. */
typedef struct AotSha256 {
    uint32_t state[8];
    uint64_t total;                    /* total message bytes fed so far */
    uint8_t buf[AOT_SHA256_BLOCK_BYTES];
    uint32_t buffered;                 /* bytes currently in buf (< 64) */
} AotSha256;

/* Reset to the initial state (equivalent to a fresh aot_sha256_init). */
void aot_sha256_init(AotSha256 *ctx);

/* Feed `n` bytes. `data` may be NULL only when `n` == 0. */
void aot_sha256_update(AotSha256 *ctx, const void *data, size_t n);

/* Finish and write the 32-byte digest to `out`. The context must not be used
 * again without aot_sha256_init(). Calling final on an all-zero context is
 * undefined; callers always init first. */
void aot_sha256_final(AotSha256 *ctx, uint8_t out[AOT_SHA256_DIGEST_BYTES]);

/* One-shot convenience: digest of data[0..n). */
void aot_sha256(const void *data, size_t n,
                uint8_t out[AOT_SHA256_DIGEST_BYTES]);

/* Lower-case hex (64 chars + NUL) of a digest. `out` must have 65 bytes.
 * Used for diagnostics only; comparisons are always on the raw bytes. */
void aot_sha256_hex(const uint8_t digest[AOT_SHA256_DIGEST_BYTES],
                    char out[2u * AOT_SHA256_DIGEST_BYTES + 1u]);

#ifdef __cplusplus
}
#endif

#endif /* MN_AOT_SHA256_H */
