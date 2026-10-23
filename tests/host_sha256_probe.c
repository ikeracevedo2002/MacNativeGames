/*
 * host_sha256 probe: the CNG backend must equal FIPS 180-4.
 *
 *   - NIST/FIPS 180-2 vectors (empty, "abc", the 448-bit message, one million
 *     'a' fed in uneven chunks);
 *   - differential against the independent src/aot/aot_sha256 for 4,099
 *     deterministic pseudo-random messages (lengths 0..4096 plus three near
 *     8 MiB +/- small), each split into random update chunks, including
 *     zero-length updates;
 *   - API contract: argument rejection, finish(NULL out) consumes the handle,
 *     a failed finish leaves the caller's digest unchanged, abort(NULL).
 *
 * Exit: 0 PASS, 2 first semantic failure ("FAIL: <label>"), 1 infrastructure
 * ("FATAL: ..."). argv[1] (fixture root) is accepted and ignored so the
 * shared native mutant driver can run it.
 */
#include "host_sha256.h"
#include "aot/aot_sha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(const char *label)
{
    printf("FAIL: %s\n", label);
    return 2;
}

static int fatal(const char *what)
{
    printf("FATAL: %s\n", what);
    return 1;
}

static uint64_t rng_state = 0x9E3779B97F4A7C15ull;

static uint64_t rng(void)
{
    uint64_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng_state = x;
    return x;
}

static int hex_eq(const uint8_t d[32], const char *hex)
{
    char buf[65];
    aot_sha256_hex(d, buf);
    return strcmp(buf, hex) == 0;
}

/* Hash `data` with the host backend in random chunk sizes up to `max_chunk`
 * (0 means one update). Returns HOST_SHA256_OK or the first error. */
static host_sha256_result host_digest(const uint8_t *data, size_t n,
                                      size_t max_chunk, uint8_t out[32])
{
    HostSha256 *h = NULL;
    host_sha256_result r = host_sha256_begin(&h);
    if (r != HOST_SHA256_OK) return r;
    size_t done = 0;
    if (max_chunk == 0) {
        r = host_sha256_update(h, data, n);
        done = n;
    }
    while (r == HOST_SHA256_OK && done < n) {
        size_t chunk = (size_t)(rng() % (max_chunk + 1)); /* may be 0 */
        if (chunk > n - done) chunk = n - done;
        r = host_sha256_update(h, data + done, chunk);
        done += chunk;
    }
    if (r != HOST_SHA256_OK) {
        host_sha256_abort(h);
        return r;
    }
    return host_sha256_finish(h, out);
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    uint8_t d[32];

    /* 1. NIST vectors. */
    if (host_digest((const uint8_t *)"", 0, 0, d) != HOST_SHA256_OK)
        return fatal("backend unavailable (empty message)");
    if (!hex_eq(d, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))
        return fail("NIST empty");
    if (host_digest((const uint8_t *)"abc", 3, 0, d) != HOST_SHA256_OK)
        return fatal("backend error (abc)");
    if (!hex_eq(d, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"))
        return fail("NIST abc");
    {
        const char *m = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        if (host_digest((const uint8_t *)m, strlen(m), 0, d) != HOST_SHA256_OK)
            return fatal("backend error (448-bit)");
        if (!hex_eq(d, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"))
            return fail("NIST 448-bit message");
    }
    {
        uint8_t *a = (uint8_t *)malloc(1000000);
        if (!a) return fatal("allocation");
        memset(a, 'a', 1000000);
        host_sha256_result r = host_digest(a, 1000000, 65537, d);
        free(a);
        if (r != HOST_SHA256_OK) return fatal("backend error (million a)");
        if (!hex_eq(d, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"))
            return fail("NIST one million a (chunked)");
    }
    printf("OK: NIST vectors (4)\n");

    /* 2. Differential against aot_sha256. */
    {
        const size_t big = 8u * 1024u * 1024u;
        uint8_t *buf = (uint8_t *)malloc(big + 8);
        if (!buf) return fatal("allocation");
        for (size_t i = 0; i < big + 8; ++i) buf[i] = (uint8_t)rng();
        unsigned cases = 0;
        for (size_t len = 0; len <= 4096 + 3; ++len) {
            size_t n = len <= 4096 ? len : big - 4096 + (len - 4096) * 3;
            uint8_t ref[32];
            aot_sha256(buf, n, ref);
            size_t max_chunk = (len % 3 == 0) ? 0 : (size_t)(1 + rng() % 200);
            if (n > 4096) max_chunk = (size_t)(1 + rng() % (3u << 20));
            if (host_digest(buf, n, max_chunk, d) != HOST_SHA256_OK) {
                free(buf);
                return fatal("backend error (differential)");
            }
            if (memcmp(d, ref, 32) != 0) {
                printf("FAIL: differential vs aot_sha256 (length %zu)\n", n);
                free(buf);
                return 2;
            }
            ++cases;
        }
        free(buf);
        printf("OK: differential vs aot_sha256 (%u messages)\n", cases);
    }

    /* 3. API contract. */
    {
        HostSha256 *h = NULL;
        if (host_sha256_begin(NULL) != HOST_SHA256_ERR_INVALID_ARGUMENT)
            return fail("begin(NULL) is rejected");
        if (host_sha256_begin(&h) != HOST_SHA256_OK || !h)
            return fatal("begin");
        if (host_sha256_update(NULL, "x", 1) != HOST_SHA256_ERR_INVALID_ARGUMENT)
            return fail("update(NULL handle) is rejected");
        if (host_sha256_update(h, NULL, 1) != HOST_SHA256_ERR_INVALID_ARGUMENT)
            return fail("update(NULL data, n>0) is rejected");
        if (host_sha256_update(h, NULL, 0) != HOST_SHA256_OK)
            return fail("update(NULL data, 0) is accepted");
        if (host_sha256_finish(h, NULL) != HOST_SHA256_ERR_INVALID_ARGUMENT)
            return fail("finish(NULL out) is rejected and consumes the handle");
        if (host_sha256_finish(NULL, d) != HOST_SHA256_ERR_INVALID_ARGUMENT)
            return fail("finish(NULL handle) is rejected");
        uint8_t sentinel[32];
        memset(sentinel, 0xA5, sizeof(sentinel));
        memcpy(d, sentinel, sizeof(d));
        if (host_sha256_finish(NULL, d) == HOST_SHA256_OK ||
            memcmp(d, sentinel, sizeof(d)) != 0)
            return fail("a failed finish leaves the digest unchanged");
        host_sha256_abort(NULL);
        printf("OK: API contract\n");
    }

    printf("PASS: host_sha256\n");
    return 0;
}
