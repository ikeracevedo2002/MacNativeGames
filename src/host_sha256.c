/* Windows x64 host SHA-256 backend (CNG). Contract: host_sha256.h. */
#include "host_sha256.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

#include <stdlib.h>
#include <string.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(status) (((NTSTATUS)(status)) >= 0)
#endif

/* BCryptHashData takes a ULONG length; larger inputs are split. */
#define HOST_SHA256_MAX_CHUNK ((size_t)0x40000000u)

struct HostSha256 {
    BCRYPT_HASH_HANDLE hash;
};

host_sha256_result host_sha256_begin(HostSha256 **out)
{
    if (!out) return HOST_SHA256_ERR_INVALID_ARGUMENT;
    *out = NULL;
    HostSha256 *h = (HostSha256 *)calloc(1, sizeof(*h));
    if (!h) return HOST_SHA256_ERR_ALLOCATION;
    /* NULL hash-object buffer: CNG allocates it (Windows 7+). */
    NTSTATUS st = BCryptCreateHash(BCRYPT_SHA256_ALG_HANDLE, &h->hash, NULL,
                                   0, NULL, 0, 0);
    if (!NT_SUCCESS(st)) {
        free(h);
        return HOST_SHA256_ERR_PLATFORM;
    }
    *out = h;
    return HOST_SHA256_OK;
}

host_sha256_result host_sha256_update(HostSha256 *h, const void *data,
                                      size_t n)
{
    if (!h || (!data && n != 0)) return HOST_SHA256_ERR_INVALID_ARGUMENT;
    const unsigned char *p = (const unsigned char *)data;
#ifdef MN_HOST_SHA256_MUT_DROP_LAST_BYTE
    /* Test-only wrong backend: silently drops the last byte of each update. */
    if (n > 0) n -= 1;
#endif
    while (n > 0) {
        size_t chunk = n < HOST_SHA256_MAX_CHUNK ? n : HOST_SHA256_MAX_CHUNK;
        NTSTATUS st = BCryptHashData(h->hash, (PUCHAR)p, (ULONG)chunk, 0);
        if (!NT_SUCCESS(st)) return HOST_SHA256_ERR_PLATFORM;
        p += chunk;
        n -= chunk;
    }
    return HOST_SHA256_OK;
}

host_sha256_result host_sha256_finish(HostSha256 *h,
                                      uint8_t out[HOST_SHA256_DIGEST_BYTES])
{
    if (!h) return HOST_SHA256_ERR_INVALID_ARGUMENT;
    if (!out) {
        host_sha256_abort(h);
        return HOST_SHA256_ERR_INVALID_ARGUMENT;
    }
    uint8_t digest[HOST_SHA256_DIGEST_BYTES];
    NTSTATUS st = BCryptFinishHash(h->hash, digest, sizeof(digest), 0);
    host_sha256_abort(h);
    if (!NT_SUCCESS(st)) return HOST_SHA256_ERR_PLATFORM;
    memcpy(out, digest, sizeof(digest));
    return HOST_SHA256_OK;
}

void host_sha256_abort(HostSha256 *h)
{
    if (!h) return;
    if (h->hash) BCryptDestroyHash(h->hash);
    free(h);
}
