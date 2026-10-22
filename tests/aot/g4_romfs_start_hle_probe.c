/*
 * Hermetic native probe for the tiny early-G4 RomFS Start adapter (D020).
 *
 * No game data, no Python, no LLVM, no real ARM64. Fixtures are tiny synthetic
 * files under argv[1] with a PID-suffixed directory, and their SHA-256 values
 * are independently pinned constants checked at startup. The probe calls the
 * REAL adapter handler over a REAL immutable provider and checks the complete
 * AotGuestState is byte-identical on success and failure, exact typed faults,
 * provider lifecycle/counters, and one successful retry after a failure.
 *
 * Exit protocol: 0 PASS, 2 first semantic FAIL, 1 infrastructure FATAL.
 */
#include "g4_romfs_start_hle.h"

#include "aot/aot_sha256.h"

#include <windows.h>

#include <direct.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FIXTURE_IMAGE_SIZE 32u
#define PATH_CAP 1024

static const char *const IMAGE_SHA256 =
    "626c4ed5cb6893c7a708f5d84df0020fd7896a4e1c982e2e4c7ba2b09d084961";
static const char *const INDEX_SHA256 =
    "b234d8ef3747fe5903ef9cf167c6cb084321cdaafebf1b16e171ddcc08b6b0da";
/* Valid zero-entry index: 24-byte header, strings_offset=24, 1 pad byte. */
static const char *const ZERO_INDEX_SHA256 =
    "125b0616ad773f736e842d441823f659a9135ca05550664661215663bca5a209";

static char g_dir[PATH_CAP];
static uint8_t g_image[FIXTURE_IMAGE_SIZE];
static uint8_t g_index[54];
static size_t g_index_size;
static uint8_t g_zero_index[25];

#define CHECK_TRUE(cond, label) \
    do {                        \
        if (!(cond)) return fail(label); \
    } while (0)

static int fail(const char *label)
{
    printf("FAIL: %s\n", label);
    return 2;
}

static int fatal(const char *why, long long detail)
{
    printf("FATAL: %s (%lld)\n", why, detail);
    return 1;
}

static int write_file(const char *path, const void *data, size_t n)
{
    FILE *f = NULL;
    if (fopen_s(&f, path, "wb") != 0 || f == NULL) return 0;
    size_t written = n ? fwrite(data, 1u, n, f) : 0u;
    int ok = fclose(f) == 0;
    return ok && written == n;
}

static void path_join(char *out, size_t cap, const char *name)
{
    snprintf(out, cap, "%s/%s", g_dir, name);
}

static void make_image(void)
{
    for (unsigned i = 0; i < FIXTURE_IMAGE_SIZE; i++)
        g_image[i] = (uint8_t)((i * 7u + 11u) & 0xffu);
}

static size_t make_zero_index(void)
{
    memcpy(g_zero_index, "TOTKRFS1", 8);
    uint64_t count = 0u, strings = 24u;
    memcpy(g_zero_index + 8, &count, 8);
    memcpy(g_zero_index + 16, &strings, 8);
    g_zero_index[24] = 0u;
    return 25u;
}

static size_t make_index(void)
{
    memcpy(g_index, "TOTKRFS1", 8);
    uint64_t count = 1u, strings = 48u;
    uint64_t offset = 0u, size = 8u;
    uint32_t name_off = 0u, name_len = 6u;
    memcpy(g_index + 8, &count, 8);
    memcpy(g_index + 16, &strings, 8);
    memcpy(g_index + 24, &offset, 8);
    memcpy(g_index + 32, &size, 8);
    memcpy(g_index + 40, &name_off, 4);
    memcpy(g_index + 44, &name_len, 4);
    memcpy(g_index + 48, "a.txt", 6);
    return 54u;
}

static void hex_of(const uint8_t digest[32], char out[65])
{
    static const char digits[] = "0123456789abcdef";
    for (unsigned i = 0; i < 32; i++) {
        out[i * 2] = digits[digest[i] >> 4];
        out[i * 2 + 1] = digits[digest[i] & 0xf];
    }
    out[64] = '\0';
}

static void sha_hex(const void *data, size_t n, char out[65])
{
    uint8_t digest[32];
    aot_sha256(data, n, digest);
    hex_of(digest, out);
}

static int install_fixture(void)
{
    char path[PATH_CAP];
    path_join(path, sizeof(path), "runtime-index.bin");
    if (!write_file(path, g_index, g_index_size)) return 0;
    path_join(path, sizeof(path), "romfs.bin");
    return write_file(path, g_image, FIXTURE_IMAGE_SIZE);
}

static int install_zero_fixture(void)
{
    char path[PATH_CAP];
    path_join(path, sizeof(path), "runtime-index.bin");
    if (!write_file(path, g_zero_index, sizeof(g_zero_index))) return 0;
    path_join(path, sizeof(path), "romfs.bin");
    return write_file(path, g_image, FIXTURE_IMAGE_SIZE);
}

static void remove_image(void)
{
    char path[PATH_CAP];
    path_join(path, sizeof(path), "romfs.bin");
    DeleteFileA(path);
}

static void cfg_clear(romfs_provider_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->resource_dir = g_dir;
    cfg->index_sha256_hex = INDEX_SHA256;
    cfg->image_sha256_hex = IMAGE_SHA256;
    cfg->image_size = FIXTURE_IMAGE_SIZE;
}

static G4RomfsStartHle make_ctx(RomfsProvider **out_provider,
                                const romfs_provider_config *cfg)
{
    G4RomfsStartHle ctx;
    *out_provider = romfs_provider_create();
    g4_romfs_start_hle_init(&ctx, *out_provider, cfg);
    return ctx;
}

static AotHleRequest hostcall_req(void)
{
    AotHleRequest req;
    memset(&req, 0, sizeof(req));
    req.kind = AOT_HLE_HOSTCALL;
    req.id = 77u; /* opaque thunk ordinal; the adapter must not inspect it */
    req.site_pc = 0x10200fe100ull;
    req.resume_pc = req.site_pc + 4u;
    return req;
}

static int rows_success(void)
{
    romfs_provider_config cfg;
    RomfsProvider *provider = NULL;
    G4RomfsStartHle ctx;
    AotGuestState st, before_st;
    AotRuntime rt, before_rt;
    AotHleRequest req = hostcall_req();
    uint64_t got = 0u;
    uint8_t bytes[8];

    CHECK_TRUE(install_fixture(), "success fixture");
    cfg_clear(&cfg);
    ctx = make_ctx(&provider, &cfg);
    if (provider == NULL) return fatal("provider allocation", 0);
    CHECK_TRUE(!romfs_provider_is_ready(provider),
               "provider is not initialized before HOSTCALL");

    memset(&st, 0xa5, sizeof(st));
    memset(&rt, 0, sizeof(rt));
    memcpy(&before_st, &st, sizeof(st));
    memcpy(&before_rt, &rt, sizeof(rt));
    g4_romfs_start_hle_handler(&rt, &st, &req, &ctx);

    CHECK_TRUE(memcmp(&st, &before_st, sizeof(st)) == 0,
               "success writes no guest state");
    CHECK_TRUE(ctx.calls == 1u && ctx.success == 1u && ctx.fail == 0u,
               "success reports one successful HOSTCALL");
    CHECK_TRUE(memcmp(&rt, &before_rt, sizeof(rt)) == 0,
               "success writes no runtime fault state");
    CHECK_TRUE(romfs_provider_is_ready(provider),
               "success leaves the provider READY");
    CHECK_TRUE(ctx.last_provider_status == ROMFS_PROVIDER_OK &&
                   ctx.last_provider_ready == 1 &&
                   ctx.last_file_count == 1u &&
                   strcmp(ctx.last_stage, "ready") == 0 &&
                   ctx.last_detail[0] == '\0',
               "success publishes the provider witness");
    memset(bytes, 0, sizeof(bytes));
    CHECK_TRUE(romfs_provider_find(provider, "a.txt", &got) ==
                       ROMFS_PROVIDER_OK &&
                   romfs_provider_read(provider, got, 0u, bytes, 8u,
                                       &got) == ROMFS_PROVIDER_OK &&
                   got == 8u && memcmp(bytes, g_image, 8u) == 0,
               "READY provider serves the fixture bytes");

    /* A second HOSTCALL is idempotent (Mac image_fd guard) and still void. */
    memcpy(&before_st, &st, sizeof(st));
    memcpy(&before_rt, &rt, sizeof(rt));
    g4_romfs_start_hle_handler(&rt, &st, &req, &ctx);
    CHECK_TRUE(memcmp(&st, &before_st, sizeof(st)) == 0 &&
                   memcmp(&rt, &before_rt, sizeof(rt)) == 0,
               "idempotent HOSTCALL writes no guest/runtime state");
    CHECK_TRUE(ctx.calls == 2u && ctx.success == 2u && ctx.fail == 0u,
               "idempotent HOSTCALL reports two successes");
    romfs_provider_destroy(provider);
    return 0;
}

static int rows_zero_entry_success(void)
{
    romfs_provider_config cfg;
    RomfsProvider *provider = NULL;
    G4RomfsStartHle ctx;
    AotGuestState st, before_st;
    AotRuntime rt, before_rt;
    AotHleRequest req = hostcall_req();
    uint64_t index = 0u;

    CHECK_TRUE(install_zero_fixture(), "zero-entry fixture");
    cfg_clear(&cfg);
    cfg.index_sha256_hex = ZERO_INDEX_SHA256;
    ctx = make_ctx(&provider, &cfg);
    if (provider == NULL) return fatal("provider allocation", 0);
    CHECK_TRUE(!romfs_provider_is_ready(provider),
               "zero-entry provider is not initialized before HOSTCALL");
    memset(&st, 0x99, sizeof(st));
    memset(&rt, 0, sizeof(rt));
    memcpy(&before_st, &st, sizeof(st));
    memcpy(&before_rt, &rt, sizeof(rt));
    g4_romfs_start_hle_handler(&rt, &st, &req, &ctx);

    CHECK_TRUE(memcmp(&st, &before_st, sizeof(st)) == 0,
               "zero-entry success writes no guest state");
    CHECK_TRUE(memcmp(&rt, &before_rt, sizeof(rt)) == 0,
               "zero-entry success writes no runtime fault state");
    CHECK_TRUE(ctx.calls == 1u && ctx.success == 1u && ctx.fail == 0u,
               "zero-entry success reports one successful HOSTCALL");
    CHECK_TRUE(romfs_provider_is_ready(provider) &&
                   romfs_provider_file_count(provider) == 0u &&
                   ctx.last_file_count == 0u,
               "zero-entry success leaves the provider READY with 0 files");
    CHECK_TRUE(strcmp(ctx.last_stage, "ready") == 0 &&
                   ctx.last_detail[0] == '\0',
               "zero-entry success publishes the READY witness");
    CHECK_TRUE(romfs_provider_find(provider, "a.txt", &index) ==
                       ROMFS_PROVIDER_ERR_NOT_FOUND,
               "zero-entry READY provider has no entries");
    romfs_provider_destroy(provider);
    return 0;
}

static int rows_failure_and_retry(void)
{
    romfs_provider_config cfg;
    RomfsProvider *provider = NULL;
    G4RomfsStartHle ctx;
    AotGuestState st, before_st;
    AotRuntime rt;
    AotHleRequest req = hostcall_req();
    int64_t want_status;

    /* The previous row left the zero-entry index on disk. Restore the
     * one-entry fixture first so the ONLY failure here is the missing image
     * (otherwise the index digest gate rejects before the image stage). */
    CHECK_TRUE(install_fixture(), "failure fixture index");
    remove_image();
    cfg_clear(&cfg);
    ctx = make_ctx(&provider, &cfg);
    if (provider == NULL) return fatal("provider allocation", 0);
    memset(&st, 0x5a, sizeof(st));
    memset(&rt, 0, sizeof(rt));
    memcpy(&before_st, &st, sizeof(st));
    g4_romfs_start_hle_handler(&rt, &st, &req, &ctx);

    want_status = G4_ROMFS_START_HLE_FAULT_PROVIDER_BASE -
                  (int64_t)ROMFS_PROVIDER_ERR_IMAGE_OPEN;
    CHECK_TRUE(memcmp(&st, &before_st, sizeof(st)) == 0,
               "failure writes no guest state");
    CHECK_TRUE(ctx.calls == 1u && ctx.success == 0u && ctx.fail == 1u,
               "failure reports no successful HOSTCALL");
    CHECK_TRUE(rt.fault == AOT_FAULT_BAD_HLE &&
                   rt.fault_src == req.site_pc &&
                   rt.fault_target == req.resume_pc &&
                   rt.fault_status == want_status,
               "failure is the documented typed fault with site/resume");
    CHECK_TRUE(ctx.last_provider_status == ROMFS_PROVIDER_ERR_IMAGE_OPEN &&
                   !romfs_provider_is_ready(provider) &&
                   romfs_provider_file_count(provider) == 0u,
               "failure leaves the provider EMPTY");

    /* Restore input and retry the same provider: transactional EMPTY state. */
    CHECK_TRUE(install_fixture(), "retry fixture");
    memset(&rt, 0, sizeof(rt));
    g4_romfs_start_hle_handler(&rt, &st, &req, &ctx);
    CHECK_TRUE(ctx.calls == 2u && ctx.success == 1u && ctx.fail == 1u,
               "retry after typed failure succeeds");
    CHECK_TRUE(romfs_provider_is_ready(provider),
               "retry leaves the provider READY");
    romfs_provider_destroy(provider);
    return 0;
}

static int rows_typed_misconfiguration(void)
{
    romfs_provider_config cfg;
    RomfsProvider *provider = NULL;
    G4RomfsStartHle ctx;
    AotGuestState st, before_st;
    AotRuntime rt;
    AotHleRequest req = hostcall_req();

    CHECK_TRUE(install_fixture(), "misconfiguration fixture");
    cfg_clear(&cfg);

    /* Wrong request kind: no provider init, typed fault, guest untouched. */
    ctx = make_ctx(&provider, &cfg);
    if (provider == NULL) return fatal("provider allocation", 0);
    memset(&st, 0x33, sizeof(st));
    memset(&rt, 0, sizeof(rt));
    memcpy(&before_st, &st, sizeof(st));
    req.kind = AOT_HLE_SVC;
    g4_romfs_start_hle_handler(&rt, &st, &req, &ctx);
    CHECK_TRUE(memcmp(&st, &before_st, sizeof(st)) == 0,
               "wrong-kind failure writes no guest state");
    CHECK_TRUE(ctx.fail == 1u && ctx.success == 0u &&
                   rt.fault == AOT_FAULT_BAD_HLE &&
                   rt.fault_src == req.site_pc &&
                   rt.fault_target == req.resume_pc &&
                   rt.fault_status == G4_ROMFS_START_HLE_FAULT_KIND &&
                   !romfs_provider_is_ready(provider),
               "wrong-kind request is typed and does not initialize");
    romfs_provider_destroy(provider);

    /* Missing explicit config: typed, no init. */
    ctx = make_ctx(&provider, NULL);
    if (provider == NULL) return fatal("provider allocation", 0);
    req = hostcall_req();
    memset(&rt, 0, sizeof(rt));
    g4_romfs_start_hle_handler(&rt, &st, &req, &ctx);
    CHECK_TRUE(ctx.fail == 1u && ctx.success == 0u &&
                   rt.fault == AOT_FAULT_BAD_HLE &&
                   rt.fault_status == G4_ROMFS_START_HLE_FAULT_CONFIG &&
                   !romfs_provider_is_ready(provider),
               "missing config is typed and does not initialize");
    romfs_provider_destroy(provider);

    /* NULL guest state with otherwise valid context/request: typed fault and
     * no provider initialization. */
    ctx = make_ctx(&provider, &cfg);
    if (provider == NULL) return fatal("provider allocation", 0);
    memset(&rt, 0, sizeof(rt));
    g4_romfs_start_hle_handler(&rt, NULL, &req, &ctx);
    CHECK_TRUE(ctx.calls == 1u && ctx.fail == 1u && ctx.success == 0u &&
                   rt.fault == AOT_FAULT_BAD_HLE &&
                   rt.fault_src == req.site_pc &&
                   rt.fault_target == req.resume_pc &&
                   rt.fault_status == G4_ROMFS_START_HLE_FAULT_GUEST &&
                   !romfs_provider_is_ready(provider),
               "NULL guest state is typed and does not initialize");
    romfs_provider_destroy(provider);

    /* Missing context: typed fault, no success. */
    memset(&rt, 0, sizeof(rt));
    g4_romfs_start_hle_handler(&rt, &st, &req, NULL);
    CHECK_TRUE(rt.fault == AOT_FAULT_BAD_HLE &&
                   rt.fault_src == req.site_pc &&
                   rt.fault_target == req.resume_pc &&
                   rt.fault_status == G4_ROMFS_START_HLE_FAULT_CONTEXT,
               "missing context is a typed fault");
    return 0;
}

static int rows_required_overlay_missing(void)
{
    romfs_provider_config cfg;
    RomfsProvider *provider = NULL;
    G4RomfsStartHle ctx;
    AotGuestState st, before_st;
    AotRuntime rt;
    AotHleRequest req = hostcall_req();
    char missing[PATH_CAP];

    CHECK_TRUE(install_fixture(), "required overlay fixture");
    path_join(missing, sizeof(missing), "absent-required-overlay");
    cfg_clear(&cfg);
    cfg.overlay_root_count = 1u;
    cfg.overlay_dirs[0] = missing;
    cfg.overlay_required[0] = 1u;
    ctx = make_ctx(&provider, &cfg);
    if (provider == NULL) return fatal("provider allocation", 0);
    memset(&st, 0x33, sizeof(st));
    memset(&rt, 0, sizeof(rt));
    memcpy(&before_st, &st, sizeof(st));
    g4_romfs_start_hle_handler(&rt, &st, &req, &ctx);
    CHECK_TRUE(ctx.calls == 1u && ctx.success == 0u && ctx.fail == 1u,
               "required overlay failure reports one failed HOSTCALL");
    CHECK_TRUE(ctx.last_provider_status == ROMFS_PROVIDER_ERR_OVERLAY_REQUIRED &&
                   ctx.last_provider_ready == 0 && ctx.last_file_count == 0u,
               "required overlay failure leaves the provider EMPTY");
    CHECK_TRUE(rt.fault == AOT_FAULT_BAD_HLE && rt.fault_src == req.site_pc &&
                   rt.fault_target == req.resume_pc &&
                   rt.fault_status ==
                       (int64_t)G4_ROMFS_START_HLE_FAULT_PROVIDER_BASE -
                           (int64_t)ROMFS_PROVIDER_ERR_OVERLAY_REQUIRED,
               "required overlay failure is the documented typed fault");
    CHECK_TRUE(memcmp(&st, &before_st, sizeof(st)) == 0,
               "required overlay failure writes no guest state");
    romfs_provider_destroy(provider);
    return 0;
}

static int rows_optional_overlay(void)
{
    romfs_provider_config cfg;
    RomfsProvider *provider = NULL;
    G4RomfsStartHle ctx;
    AotGuestState st, before_st;
    AotRuntime rt;
    AotHleRequest req = hostcall_req();
    char missing[PATH_CAP];

    CHECK_TRUE(install_fixture(), "optional overlay fixture");
    path_join(missing, sizeof(missing), "absent-overlay");
    cfg_clear(&cfg);
    cfg.overlay_root_count = 1u;
    cfg.overlay_dirs[0] = missing;
    cfg.overlay_required[0] = 0u;
    ctx = make_ctx(&provider, &cfg);
    if (provider == NULL) return fatal("provider allocation", 0);
    memset(&st, 0x77, sizeof(st));
    memset(&rt, 0, sizeof(rt));
    memcpy(&before_st, &st, sizeof(st));
    g4_romfs_start_hle_handler(&rt, &st, &req, &ctx);
    CHECK_TRUE(memcmp(&st, &before_st, sizeof(st)) == 0,
               "optional-overlay success writes no guest state");
    CHECK_TRUE(ctx.success == 1u && ctx.fail == 0u &&
                   romfs_provider_is_ready(provider),
               "optional absent overlay keeps the originals READY");
    romfs_provider_destroy(provider);
    return 0;
}

int main(int argc, char **argv)
{
    char hex[65];
    if (argc < 2) return fatal("usage: <external fixture root>", argc);
    snprintf(g_dir, sizeof(g_dir), "%s/g4-romfs-adapter-%lu", argv[1],
             (unsigned long)GetCurrentProcessId());
    if (_mkdir(g_dir) != 0 && errno != EEXIST)
        return fatal("could not create fixture directory", errno);

    make_image();
    g_index_size = make_index();
    if (g_index_size != 54u) return fatal("index fixture size", 0);
    if (make_zero_index() != sizeof(g_zero_index))
        return fatal("zero index fixture size", 0);
    sha_hex(g_image, FIXTURE_IMAGE_SIZE, hex);
    if (strcmp(hex, IMAGE_SHA256) != 0)
        return fatal("image fixture digest drift", 0);
    sha_hex(g_index, g_index_size, hex);
    if (strcmp(hex, INDEX_SHA256) != 0)
        return fatal("index fixture digest drift", 0);
    sha_hex(g_zero_index, sizeof(g_zero_index), hex);
    if (strcmp(hex, ZERO_INDEX_SHA256) != 0)
        return fatal("zero index fixture digest drift", 0);

    int rc = rows_success();
    if (rc) return rc;
    rc = rows_zero_entry_success();
    if (rc) return rc;
    rc = rows_failure_and_retry();
    if (rc) return rc;
    rc = rows_typed_misconfiguration();
    if (rc) return rc;
    rc = rows_required_overlay_missing();
    if (rc) return rc;
    rc = rows_optional_overlay();
    if (rc) return rc;
    printf("PASS: g4 RomFS Start adapter (32 image bytes, 1 index row)\n");
    return 0;
}
