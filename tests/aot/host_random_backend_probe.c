/* Deterministic backend test for src/host_random.c.
 *
 * This TU deliberately includes the backend source and substitutes the private
 * compile-time API seam. It must not link the real host_random object, so the
 * fake provider is the only implementation exercised. Production keeps the
 * real BCryptGenRandom default.
 */

#include <windows.h>
#include <bcrypt.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int g_failures;
#define CHECK(cond, msg)                                                   \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("FAIL: %s (%s:%d)\n", (msg), __FILE__, __LINE__);       \
            g_failures++;                                                  \
        }                                                                  \
    } while (0)

static uint64_t g_value;
static NTSTATUS g_status;
static int g_partial;
static unsigned g_calls;
static BCRYPT_ALG_HANDLE g_h;
static PUCHAR g_out;
static ULONG g_len;
static ULONG g_flags;

static NTSTATUS WINAPI fake_gen_random(BCRYPT_ALG_HANDLE h, PUCHAR out,
                                       ULONG len, ULONG flags)
{
    g_calls++;
    g_h = h;
    g_out = out;
    g_len = len;
    g_flags = flags;
    if (g_status < 0) {
        if (g_partial && out != NULL && len >= sizeof g_value)
            memcpy(out, &g_value, sizeof g_value);
        return g_status;
    }
    if (out != NULL && len == sizeof g_value)
        memcpy(out, &g_value, sizeof g_value);
    return 0;
}

#define MN_HOST_RANDOM_GEN_RANDOM(h, out, len, flags) \
    fake_gen_random((h), (out), (len), (flags))
#include "../../src/host_random.c"

static void reset_fake(void)
{
    g_value = 0u;
    g_status = 0;
    g_partial = 0;
    g_calls = 0u;
    g_h = (BCRYPT_ALG_HANDLE)(uintptr_t)1u;
    g_out = NULL;
    g_len = 0u;
    g_flags = 0u;
}

int main(void)
{
    uint64_t out;
    host_random_result rr;

    reset_fake();
    out = 0x1111111111111111ull;
    g_value = 0u;
    rr = host_random_u64(&out);
    CHECK(rr == HOST_RANDOM_OK && out == 0u,
          "all-zero success is preserved");
    CHECK(g_calls == 1u && g_h == NULL && g_len == 8u &&
          g_flags == BCRYPT_USE_SYSTEM_PREFERRED_RNG,
          "algorithm NULL, length 8, system-preferred flags, one call");

    reset_fake();
    out = 0u;
    g_value = UINT64_MAX;
    rr = host_random_u64(&out);
    CHECK(rr == HOST_RANDOM_OK && out == UINT64_MAX,
          "MAXBITS value is preserved exactly");

    reset_fake();
    out = 0u;
    g_value = 0x0123456789abcdefull;
    rr = host_random_u64(&out);
    CHECK(rr == HOST_RANDOM_OK && out == 0x0123456789abcdefull,
          "exact provider vector is preserved");

    reset_fake();
    out = 0xfeedfacecafebeefull;
    g_value = 0xa5a5a5a5a5a5a5a5ull;
    g_status = (NTSTATUS)0xC0000001u;   /* negative status */
    g_partial = 1;
    rr = host_random_u64(&out);
    CHECK(rr == HOST_RANDOM_ERR_PLATFORM,
          "negative provider status is a typed platform error");
    CHECK(out == 0xfeedfacecafebeefull,
          "caller output unchanged after partial write + failure");
    CHECK(g_calls == 1u && g_len == 8u &&
          g_flags == BCRYPT_USE_SYSTEM_PREFERRED_RNG,
          "failure still uses the required API shape");

    reset_fake();
    rr = host_random_u64(NULL);
    CHECK(rr == HOST_RANDOM_ERR_INVALID_ARGUMENT,
          "NULL caller output is invalid argument");
    CHECK(g_calls == 0u, "NULL output invokes no provider");

    if (g_failures != 0) {
        printf("FAIL: %d check(s) failed\n", g_failures);
        return 1;
    }
    printf("PASS: host_random_backend\n");
    return 0;
}
