/*
 * G3 increment 2: SHA-256 contract probe.
 *
 * Checks the FIPS 180-4 / NIST sample vectors that the module loader's
 * exact-version verification and link digest depend on:
 *   ""                                                     (empty message)
 *   "abc"                                                  (single block)
 *   the 448-bit "abcdbcde..." message                      (two-block padding)
 *   one million 'a'                                        (many blocks)
 *
 * Negative controls (so a broken implementation cannot pass accidentally):
 *   - every vector digest is also compared against a deliberately wrong
 *     expected value and MUST differ;
 *   - a one-byte tamper of the "abc" message MUST change the digest;
 *   - streaming in 1-, 7-, 63-, 64- and 65-byte chunks MUST equal one-shot,
 *     which pins the buffering boundaries.
 *
 * Exit protocol (same as the other AOT probes so a driver can classify):
 *   0 = every check passed
 *   2 = at least one check failed (prints "FAIL: <check>")
 *   1 = infrastructure failure (prints "FATAL: <reason>")
 */
#include "aot_sha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail = 0;

static void check(int cond, const char *msg)
{
    if (!cond) {
        printf("FAIL: %s\n", msg);
        g_fail = 1;
    }
}

static void fatal(const char *msg)
{
    printf("FATAL: %s\n", msg);
    exit(1);
}

/* 32 raw bytes from 64 hex chars. The probe keeps its vectors as hex text so
 * they can be compared to the published NIST values by eye. */
static void unhex(const char *hex, uint8_t out[32])
{
    unsigned i;

    if (strlen(hex) != 64u) {
        fatal("vector hex is not 64 chars");
    }
    for (i = 0; i < 32u; i++) {
        unsigned v = 0;
        unsigned k;
        for (k = 0; k < 2u; k++) {
            char c = hex[2u * i + k];
            unsigned d;
            if (c >= '0' && c <= '9') {
                d = (unsigned)(c - '0');
            } else if (c >= 'a' && c <= 'f') {
                d = (unsigned)(c - 'a') + 10u;
            } else {
                /* Set a harmless value first: fatal() never returns, and an
                 * assignment after it is unreachable code (C4702 in Release). */
                d = 0;
                fatal("vector hex has a non-lowercase-hex digit");
            }
            v = (v << 4) | d;
        }
        out[i] = (uint8_t)v;
    }
}

/* One published vector: one-shot digest, streaming in every chunk size, and
 * both negative controls. */
static void vector(const char *name, const void *msg, size_t len,
                   const char *hex)
{
    uint8_t want[32];
    uint8_t got[32];
    uint8_t wrong[32];
    static const size_t chunk[] = { 1u, 7u, 63u, 64u, 65u, 1000u };
    char label[160];
    unsigned c;

    unhex(hex, want);

    aot_sha256(msg, len, got);
    (void)snprintf(label, sizeof label, "%s: one-shot digest", name);
    check(memcmp(got, want, 32u) == 0, label);

    /* Negative control: a wrong expected digest must not match. */
    memcpy(wrong, want, 32u);
    wrong[31] ^= 0x01u;
    (void)snprintf(label, sizeof label,
                   "%s: wrong expected digest must differ", name);
    check(memcmp(got, wrong, 32u) != 0, label);

    for (c = 0; c < (unsigned)(sizeof chunk / sizeof chunk[0]); c++) {
        AotSha256 ctx;
        size_t off = 0;

        aot_sha256_init(&ctx);
        while (off < len) {
            size_t take = (len - off < chunk[c]) ? (len - off) : chunk[c];
            aot_sha256_update(&ctx, (const uint8_t *)msg + off, take);
            off += take;
        }
        aot_sha256_final(&ctx, got);
        (void)snprintf(label, sizeof label,
                       "%s: streaming in %u-byte chunks", name,
                       (unsigned)chunk[c]);
        check(memcmp(got, want, 32u) == 0, label);
    }
}

/* A 1 MiB buffer of 'a' fed as a single update, plus the million-'a' vector
 * fed in 1000-byte pieces (the NIST definition of that vector). */
static void million_a(void)
{
    static uint8_t big[1000000];
    uint8_t want[32];
    uint8_t got[32];
    AotSha256 ctx;
    size_t off;

    memset(big, 'a', sizeof big);
    unhex("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
          want);

    aot_sha256(big, sizeof big, got);
    check(memcmp(got, want, 32u) == 0, "1e6 'a': one-shot digest");

    aot_sha256_init(&ctx);
    for (off = 0; off < sizeof big; off += 1000u) {
        aot_sha256_update(&ctx, big + off, 1000u);
    }
    aot_sha256_final(&ctx, got);
    check(memcmp(got, want, 32u) == 0, "1e6 'a': 1000-byte chunks");
}

/* The abi carries raw digests, but diagnostics print hex: pin the encoder. */
static void hex_encoding(void)
{
    uint8_t d[32];
    char hex[65];
    unsigned i;

    for (i = 0; i < 32u; i++) {
        d[i] = (uint8_t)i;
    }
    aot_sha256_hex(d, hex);
    check(strcmp(hex, "000102030405060708090a0b0c0d0e0f"
                      "101112131415161718191a1b1c1d1e1f") == 0,
          "hex encoder");
}

int main(void)
{
    static const char abc[] = "abc";
    static const char two_block[] =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    uint8_t a[32];
    uint8_t b[32];
    uint8_t tampered[32];

    /* Empty message. */
    vector("empty",
           "", 0u,
           "e3b0c44298fc1c149afbf4c8996fb924"
           "27ae41e4649b934ca495991b7852b855");

    /* One block: 3 bytes + 0x80 + zeros + 8-byte bit length. */
    vector("abc",
           abc, 3u,
           "ba7816bf8f01cfea414140de5dae2223"
           "b00361a396177a9cb410ff61f20015ad");

    /* 56 bytes: 0x80 lands in the first block and the length in a second one
     * (the classic padding boundary). */
    vector("two-block",
           two_block, strlen(two_block),
           "248d6a61d20638b8e5c026930c3e6039"
           "a33ce45964ff2167f6ecedd419db06c1");

    million_a();
    hex_encoding();

    /* Negative control at the API level: a tampered message must not produce
     * the untampered digest. */
    aot_sha256(abc, 3u, a);
    aot_sha256("abd", 3u, b);
    check(memcmp(a, b, 32u) != 0, "one-byte tamper changes the digest");

    /* ... and re-initialising a used context must forget the old message. */
    {
        AotSha256 ctx;

        aot_sha256_init(&ctx);
        aot_sha256_update(&ctx, "xyz", 3u);
        aot_sha256_init(&ctx);
        aot_sha256_update(&ctx, abc, 3u);
        aot_sha256_final(&ctx, tampered);
        check(memcmp(tampered, a, 32u) == 0, "re-init forgets the old message");
    }

    /* update(NULL, 0) is a documented no-op that keeps the digest. */
    {
        AotSha256 ctx;

        aot_sha256_init(&ctx);
        aot_sha256_update(&ctx, NULL, 0u);
        aot_sha256_update(&ctx, abc, 3u);
        aot_sha256_update(&ctx, NULL, 0u);
        aot_sha256_final(&ctx, b);
        check(memcmp(a, b, 32u) == 0, "zero-length update is a no-op");
    }

    if (g_fail) {
        printf("aot_sha256_probe: FAILED\n");
        return 2;
    }
    printf("aot_sha256_probe: all SHA-256 vectors passed\n");
    return 0;
}
