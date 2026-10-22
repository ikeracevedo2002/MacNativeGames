/*
 * Hermetic native probe for the immutable RomFS provider (D020).
 *
 * No game data, no Python, no LLVM, no AOT proof: the fixtures are tiny
 * synthetic files written under an EXTERNAL directory (argv[1], normally the
 * build dir) and every expected digest is a pinned constant produced
 * independently with Python hashlib when this probe was written. The fixture
 * byte layout is checked against those constants at startup (FATAL if it
 * drifts), so a fixture change cannot silently weaken a row.
 *
 * Exit protocol (same as the G3 probes):
 *   0 = every row passed
 *   2 = one SEMANTIC check failed; the first failure prints "FAIL: <label>"
 *   1 = INFRASTRUCTURE failure (fixture IO, allocation, argv)
 *
 * Malformed-layout rows deliberately use the SHA-256 of the malformed bytes:
 * those rows exist to prove LAYOUT rejection, so the digest gate must not be
 * what rejects them. Digest correctness is covered by the pinned-constant
 * positive rows and by the bad-index/same-size-changed-image rows.
 */
#include "romfs_provider.h"

#include "romfs_file_win.h"

#include "aot/aot_sha256.h"

#include <windows.h>

#include <direct.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define FIXTURE_IMAGE_SIZE 300u
#define FIXTURE2_IMAGE_SIZE 640u /* large enough for exactly 64 equal parts */
#define PATH_CAP 2048

static const char *const IMAGE_SHA256 =
    "3adecd435ffed32b75b4a5e553c21fdcf239b8bf9baedf2117b16c3062e14910";
static const char *const IMAGE2_SHA256 =
    "6913ca727efd439eba8db6cf80487feb89b8cff06f6a69c8b4c8422f15417567";
static const char *const INDEX_SHA256 =
    "4ac41e25dad444e1dd92bcd135b5af1228d957de98e759c545714917741cd02c";
static const char *const INDEX2_SHA256 =
    "07294b3abc2a638b722a2dcf16c63de9f9241b3cc396977354af352a2555fdf9";
static const char *const OVL_DIRB_SHA256 =
    "a9e81ee35d477cdd6c6b4297703850315d600df99993e30b6f87b7b3f4fe8f1b";
static const char *const ORIG_DIRB_SHA256 =
    "52c07c51f876ad04654c553f7edf2b699e6afad5205490832165a510f2582211";
static const char *const OVL_ATXT_SHA256 =
    "71f3e86c42376ed1c9583f0117fad889f5139926594992b3f573e17939cb038f";
static const char *const ORIG_ATXT_SHA256 =
    "78cd0ee5fb7223351901f391c1aeafb4a1b4d87b475f9c4ae77247c3e10d5a98";
static const char *const ORIG_LINK_SHA256 =
    "52bc373dfde0430a5853e8e53536c1d5fca940344467dc04a538e5a779bdd310";
static const char *const OVL_LINK_SHA256 =
    "7d2e64b7d650520da72a41769f7f5b8398c91f03a9828042038e516227b64d06";

typedef struct {
    uint64_t offset;
    uint64_t size;
    const char *name;
} Row;

static const Row ROWS3[3] = {{0, 8, "a.txt"},
                             {8, 200, "dir/b.bin"},
                             {208, 92, "z/last.dat"}};

static char g_fix[PATH_CAP];
static char g_fix2[PATH_CAP];
static char g_ovl1[PATH_CAP];
static char g_ovl2[PATH_CAP];
static char g_ovl3[PATH_CAP];
static char g_outside[PATH_CAP];
static char g_long_resource[PATH_CAP];
static char g_long_overlay[PATH_CAP];

static uint8_t g_image[FIXTURE_IMAGE_SIZE];
static uint8_t g_image2[FIXTURE2_IMAGE_SIZE];
static uint8_t g_index1[512];
static size_t g_index1_size;

#define CHECK_TRUE(cond, label)      \
    do {                             \
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

static void path_join(char *out, size_t cap, const char *a, const char *b)
{
    snprintf(out, cap, "%s/%s", a, b);
}

/* Fixture paths can legitimately exceed MAX_PATH (the long-path row), so every
 * probe-side file operation goes through the extended-length form too. This is
 * fixture plumbing, not a second copy of the provider seam. */
static const wchar_t *extended_path(const char *utf8, wchar_t *out, size_t cap)
{
    wchar_t wide[PATH_CAP];
    if (MultiByteToWideChar(CP_UTF8, 0, utf8, -1, wide, PATH_CAP) <= 0)
        return NULL;
    for (size_t i = 0; wide[i]; i++)
        if (wide[i] == L'/') wide[i] = L'\\';
    if (wide[0] && wide[1] == L':')
        _snwprintf_s(out, cap, _TRUNCATE, L"\\\\?\\%s", wide);
    else
        _snwprintf_s(out, cap, _TRUNCATE, L"%s", wide);
    return out;
}

static int file_exists(const char *path)
{
    wchar_t wide[PATH_CAP + 8];
    if (!extended_path(path, wide, PATH_CAP + 8)) return 0;
    FILE *f = _wfopen(wide, L"rb");
    if (!f) return 0;
    fclose(f);
    return 1;
}

static int write_bytes(const char *path, const void *data, size_t n)
{
    wchar_t wide[PATH_CAP + 8];
    if (!extended_path(path, wide, PATH_CAP + 8)) return 0;
    FILE *f = _wfopen(wide, L"wb");
    if (!f) return 0;
    size_t written = n ? fwrite(data, 1, n, f) : 0;
    int ok = fclose(f) == 0;
    return ok && written == n;
}

static void remove_file(const char *path)
{
    wchar_t wide[PATH_CAP + 8];
    if (!extended_path(path, wide, PATH_CAP + 8)) return;
    DeleteFileW(wide);
}

static void remove_dir(const char *path)
{
    wchar_t wide[PATH_CAP + 8];
    if (!extended_path(path, wide, PATH_CAP + 8)) return;
    RemoveDirectoryW(wide);
}

/* Fixture-only raw opens, also used by the lifetime rows so they exercise the
 * same extended-length path spelling as the provider. */
static HANDLE open_write_raw(const char *path, DWORD share)
{
    wchar_t wide[PATH_CAP + 8];
    if (!extended_path(path, wide, PATH_CAP + 8)) return INVALID_HANDLE_VALUE;
    return CreateFileW(wide, GENERIC_WRITE, share, NULL, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL, NULL);
}

static int delete_raw(const char *path)
{
    wchar_t wide[PATH_CAP + 8];
    if (!extended_path(path, wide, PATH_CAP + 8)) return 0;
    return DeleteFileW(wide) != 0;
}

static void ensure_dir(const char *path)
{
    wchar_t wide[PATH_CAP + 8];
    if (!extended_path(path, wide, PATH_CAP + 8)) {
        printf("FATAL: fixture directory path is invalid\n");
        exit(1);
    }
    if (!CreateDirectoryW(wide, NULL) &&
        GetLastError() != ERROR_ALREADY_EXISTS) {
        printf("FATAL: could not create fixture directory %s\n", path);
        exit(1);
    }
}

/* Create every component of a fixture path; long-path rows need parents that
 * do not exist yet, and MAX_PATH-aware helpers cannot do that in one call. */
static void ensure_dir_tree(const char *path)
{
    char current[PATH_CAP];
    size_t len = strlen(path);
    if (len == 0 || len >= sizeof(current)) {
        printf("FATAL: fixture directory path is invalid\n");
        exit(1);
    }
    memcpy(current, path, len + 1u);
    for (size_t i = 1; i < len; i++) {
        if (current[i] != '/' && current[i] != '\\') continue;
        char saved = current[i];
        current[i] = '\0';
        if (!(strlen(current) == 2 && current[1] == ':')) ensure_dir(current);
        current[i] = saved;
    }
    ensure_dir(current);
}

/* ---- fixture bytes ---------------------------------------------------- */

static void make_image(uint8_t *out, size_t size)
{
    for (size_t i = 0; i < size; i++)
        out[i] = (uint8_t)((i * 7u + 11u) & 0xffu);
}

static size_t build_index(uint8_t *out, size_t cap, const Row *rows,
                          unsigned count)
{
    if (cap < 24u + (size_t)count * 24u) return 0;
    memcpy(out, "TOTKRFS1", 8);
    uint64_t fc = count;
    uint64_t strings_offset = 24u + (uint64_t)count * 24u;
    memcpy(out + 8, &fc, 8);
    memcpy(out + 16, &strings_offset, 8);
    uint32_t string_at = 0;
    for (unsigned i = 0; i < count; i++) {
        uint8_t *row = out + 24u + (size_t)i * 24u;
        memcpy(row, &rows[i].offset, 8);
        memcpy(row + 8, &rows[i].size, 8);
        size_t len = strlen(rows[i].name) + 1;
        uint32_t at32 = string_at;
        uint32_t len32 = (uint32_t)len;
        memcpy(row + 16, &at32, 4);
        memcpy(row + 20, &len32, 4);
        memcpy(out + strings_offset + string_at, rows[i].name, len);
        string_at += (uint32_t)len;
    }
    return (size_t)strings_offset + string_at;
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

/* ---- fixture installation -------------------------------------------- */

static int install_index_at(const char *dir, const uint8_t *bytes, size_t n)
{
    char path[PATH_CAP];
    path_join(path, sizeof(path), dir, "runtime-index.bin");
    return write_bytes(path, bytes, n);
}

static int install_index(const uint8_t *bytes, size_t n)
{
    return install_index_at(g_fix, bytes, n);
}

static int install_image(void)
{
    char path[PATH_CAP];
    path_join(path, sizeof(path), g_fix, "romfs.bin");
    return write_bytes(path, g_image, FIXTURE_IMAGE_SIZE);
}

static void remove_parts_at(const char *dir, unsigned max)
{
    char path[PATH_CAP];
    char name[32];
    for (unsigned i = 0; i < max; i++) {
        snprintf(name, sizeof(name), "romfs.bin.%03u", i);
        path_join(path, sizeof(path), dir, name);
        remove_file(path);
    }
}

static void remove_parts(void)
{
    remove_parts_at(g_fix, 128);
}

static int install_parts_at(const char *dir, unsigned count, uint64_t part_size,
                            const uint8_t *image, size_t image_size)
{
    remove_parts_at(dir, 128);
    for (unsigned i = 0; i < count; i++) {
        char path[PATH_CAP];
        char name[32];
        snprintf(name, sizeof(name), "romfs.bin.%03u", i);
        path_join(path, sizeof(path), dir, name);
        uint64_t at = (uint64_t)i * part_size;
        if (at >= image_size) return 0;
        uint64_t n = (uint64_t)image_size - at;
        if (n > part_size) n = part_size;
        if (!write_bytes(path, image + at, (size_t)n)) return 0;
    }
    return 1;
}

static int install_parts(unsigned count, uint64_t part_size)
{
    return install_parts_at(g_fix, count, part_size, g_image,
                            FIXTURE_IMAGE_SIZE);
}

/* Parts whose checked sum exceeds the pinned image size. */
static int install_extra_parts(unsigned count, uint64_t part_size)
{
    remove_parts();
    for (unsigned i = 0; i < count; i++) {
        char path[PATH_CAP];
        char name[32];
        snprintf(name, sizeof(name), "romfs.bin.%03u", i);
        path_join(path, sizeof(path), g_fix, name);
        if (!write_bytes(path, g_image + (i % 3u) * 100u, (size_t)part_size))
            return 0;
    }
    return 1;
}

static void write_manifest(const char *dir, const char *text)
{
    char path[PATH_CAP];
    path_join(path, sizeof(path), dir, "manifest.tsv");
    if (!write_bytes(path, text, strlen(text))) {
        printf("FATAL: could not write overlay manifest\n");
        exit(1);
    }
}

static void clear_manifests(void)
{
    char path[PATH_CAP];
    const char *const dirs[3] = {g_ovl1, g_ovl2, g_ovl3};
    for (unsigned i = 0; i < 3; i++) {
        path_join(path, sizeof(path), dirs[i], "manifest.tsv");
        remove_file(path);
    }
}

static void overlay_file(const char *dir, const char *name, const char *text)
{
    char path[PATH_CAP];
    path_join(path, sizeof(path), dir, name);
    size_t len = strlen(text);
    if (!write_bytes(path, text, len)) {
        printf("FATAL: could not write overlay replacement\n");
        exit(1);
    }
}

static void cfg_clear(romfs_provider_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->resource_dir = g_fix;
    cfg->index_sha256_hex = INDEX_SHA256;
    cfg->image_sha256_hex = IMAGE_SHA256;
    cfg->image_size = FIXTURE_IMAGE_SIZE;
}

static void cfg2_clear(romfs_provider_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->resource_dir = g_fix2;
    cfg->index_sha256_hex = INDEX_SHA256;
    cfg->image_sha256_hex = IMAGE2_SHA256;
    cfg->image_size = FIXTURE2_IMAGE_SIZE;
}

/* Init on a throwaway provider; asserts the EMPTY-after-failure invariant. */
static romfs_provider_status init_fresh(const romfs_provider_config *cfg,
                                        romfs_provider_diag *diag,
                                        const char *label)
{
    RomfsProvider *p = romfs_provider_create();
    if (!p) {
        printf("FATAL: provider allocation\n");
        exit(1);
    }
    romfs_provider_status rs = romfs_provider_init(p, cfg, diag);
    if (rs != ROMFS_PROVIDER_OK) {
        if (romfs_provider_is_ready(p)) {
            printf("FATAL: provider became READY after a failed init\n");
            exit(1);
        }
        if (romfs_provider_file_count(p) != 0) {
            printf("FATAL: failed init published a file count (%s)\n", label);
            exit(1);
        }
        {
            uint64_t index = 0, got = 0;
            uint8_t byte = 0;
            if (romfs_provider_find(p, "a.txt", &index) !=
                    ROMFS_PROVIDER_ERR_NOT_READY ||
                romfs_provider_read(p, 0, 0, &byte, 1, &got) !=
                    ROMFS_PROVIDER_ERR_NOT_READY) {
                printf("FATAL: failed init left a readable provider (%s)\n",
                       label);
                exit(1);
            }
        }
    }
    romfs_provider_destroy(p);
    return rs;
}

static int expect_status(romfs_provider_status got, romfs_provider_status want,
                         const char *label)
{
    if (got != want) {
        printf("FAIL: %s (status %d, expected %d)\n", label, (int)got,
               (int)want);
        return 0;
    }
    return 1;
}

#define CHK_STATUS(call, want, label) \
    do {                              \
        if (!expect_status((call), (want), (label))) return 2; \
    } while (0)

/* ---- reparse point helper (no administrator rights) ------------------ */

typedef struct {
    ULONG tag;
    USHORT data_length;
    USHORT reserved;
    USHORT substitute_offset;
    USHORT substitute_length;
    USHORT print_offset;
    USHORT print_length;
    WCHAR buffer[1];
} MountPointBuffer;

static DWORD g_junction_error;

static int make_junction(const char *link_path, const char *target_utf8)
{
    g_junction_error = 0;
    char target_full[PATH_CAP];
    wchar_t target_w[1024];
    wchar_t substitute[1200];
    unsigned char buffer[16384];
    MountPointBuffer *mp = (MountPointBuffer *)buffer;
    HANDLE h;
    DWORD returned = 0;
    BOOL ok;
    size_t substitute_bytes;
    size_t print_bytes;

    if (!_fullpath(target_full, target_utf8, sizeof(target_full))) return 0;
    if (MultiByteToWideChar(CP_ACP, 0, target_full, -1, target_w, 1024) <= 0)
        return 0;
    if (_snwprintf_s(substitute, 1200, _TRUNCATE, L"\\??\\%s", target_w) < 0)
        return 0;
    substitute_bytes = wcslen(substitute) * sizeof(wchar_t);
    print_bytes = wcslen(target_w) * sizeof(wchar_t);
    if (substitute_bytes + print_bytes + 4u > 15000u) return 0;
    _mkdir(link_path);
    h = CreateFileA(link_path, GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                    NULL);
    if (h == INVALID_HANDLE_VALUE) {
        g_junction_error = GetLastError();
        return 0;
    }
    memset(buffer, 0, sizeof(buffer));
    mp->tag = IO_REPARSE_TAG_MOUNT_POINT;
    /* MountPointReparseBuffer: offsets are from the start of that structure;
     * the path buffer holds substitute NUL print NUL, so the print name starts
     * one WCHAR after the substitute name. */
    mp->substitute_offset = 0;
    mp->substitute_length = (USHORT)substitute_bytes;
    mp->print_offset = (USHORT)(substitute_bytes + sizeof(wchar_t));
    mp->print_length = (USHORT)print_bytes;
    memcpy(mp->buffer, substitute, substitute_bytes);
    memcpy((unsigned char *)mp->buffer + substitute_bytes + sizeof(wchar_t),
           target_w, print_bytes);
    mp->data_length = (USHORT)(8u + substitute_bytes + 2u * sizeof(wchar_t) +
                               print_bytes);
    ok = DeviceIoControl(h, FSCTL_SET_REPARSE_POINT, buffer,
                         8u + (DWORD)mp->data_length, NULL, 0, &returned, NULL);
    if (!ok) g_junction_error = GetLastError();
    CloseHandle(h);
    return ok != 0;
}

/* ---- row groups ------------------------------------------------------- */

static int rows_valid_mono(void)
{
    romfs_provider_config cfg;
    romfs_provider_diag diag;
    RomfsProvider *p;
    uint64_t index = 0, offset = 0, size = 0, got = 0;
    const char *name = NULL;
    uint8_t buffer[512];

    remove_parts();
    CHECK_TRUE(install_index(g_index1, g_index1_size) && install_image(),
               "fixture setup");
    cfg_clear(&cfg);
    p = romfs_provider_create();
    if (!p) return fatal("provider allocation", 0);
    CHK_STATUS(romfs_provider_init(p, &cfg, &diag), ROMFS_PROVIDER_OK,
               "valid mono init returns OK");
    CHECK_TRUE(romfs_provider_is_ready(p), "valid mono is READY");
    CHECK_TRUE(romfs_provider_file_count(p) == 3,
               "valid mono exposes the pinned file count");
    CHK_STATUS(romfs_provider_find(p, "dir/b.bin", &index), ROMFS_PROVIDER_OK,
               "lookup finds an existing path");
    CHK_STATUS(romfs_provider_find(p, "dir/absent", &index),
               ROMFS_PROVIDER_ERR_NOT_FOUND,
               "lookup of an absent path is NOT_FOUND");
    CHK_STATUS(romfs_provider_find(p, "dir/b.bin", &index), ROMFS_PROVIDER_OK,
               "lookup finds an existing path");
    CHK_STATUS(romfs_provider_entry(p, index, &offset, &size, &name),
               ROMFS_PROVIDER_OK, "entry metadata matches the index row");
    CHECK_TRUE(offset == 8 && size == 200 && strcmp(name, "dir/b.bin") == 0,
               "entry metadata matches the index row");
    memset(buffer, 0, sizeof(buffer));
    CHK_STATUS(romfs_provider_read(p, index, 0, buffer, 200, &got),
               ROMFS_PROVIDER_OK, "read returns original image bytes");
    CHECK_TRUE(got == 200 && memcmp(buffer, g_image + 8, 200) == 0,
               "read returns original image bytes");
    CHK_STATUS(romfs_provider_read(p, index, size, buffer, 1, &got),
               ROMFS_PROVIDER_OK, "read at EOF returns zero bytes");
    CHECK_TRUE(got == 0, "read at EOF returns zero bytes");
    CHK_STATUS(romfs_provider_read(p, index, size + 1, buffer, 1, &got),
               ROMFS_PROVIDER_ERR_RANGE, "offset beyond EOF is rejected");
    CHK_STATUS(romfs_provider_read(p, index, 190, buffer, 1000, &got),
               ROMFS_PROVIDER_OK, "oversized read clamps to the file end");
    CHECK_TRUE(got == 10 && memcmp(buffer, g_image + 198, 10) == 0,
               "oversized read clamps to the file end");
    /* A ready provider must ignore a later, unusable config (Mac guard). */
    {
        romfs_provider_config bogus = cfg;
        bogus.resource_dir = "C:/definitely/not/here";
        CHK_STATUS(romfs_provider_init(p, &bogus, &diag), ROMFS_PROVIDER_OK,
                   "ready provider init is idempotent and keeps its snapshot");
        CHECK_TRUE(romfs_provider_file_count(p) == 3 &&
                       romfs_provider_read(p, index, 0, buffer, 8, &got) ==
                           ROMFS_PROVIDER_OK &&
                       got == 8 && memcmp(buffer, g_image + 8, 8) == 0,
                   "idempotent init leaves reads working");
    }
    romfs_provider_destroy(p);
    return 0;
}

static int rows_split_image(void)
{
    romfs_provider_config cfg;
    romfs_provider_diag diag;
    RomfsProvider *p;
    uint64_t index = 0, got = 0;
    uint8_t buffer[512];
    char path[PATH_CAP];

    path_join(path, sizeof(path), g_fix, "romfs.bin");
    remove_file(path);
    CHECK_TRUE(install_parts(3, 100), "split part fixture");
    cfg_clear(&cfg);
    p = romfs_provider_create();
    if (!p) return fatal("provider allocation", 0);
    CHK_STATUS(romfs_provider_init(p, &cfg, &diag), ROMFS_PROVIDER_OK,
               "split image init returns OK");
    CHK_STATUS(romfs_provider_find(p, "dir/b.bin", &index), ROMFS_PROVIDER_OK,
               "split image lookup");
    memset(buffer, 0, sizeof(buffer));
    CHK_STATUS(romfs_provider_read(p, index, 0, buffer, 200, &got),
               ROMFS_PROVIDER_OK,
               "split image cross-part read returns exact bytes");
    CHECK_TRUE(got == 200 && memcmp(buffer, g_image + 8, 200) == 0,
               "split image cross-part read returns exact bytes");
    CHK_STATUS(romfs_provider_read(p, index, 70, buffer, 360, &got),
               ROMFS_PROVIDER_OK,
               "split image read spanning two boundaries returns exact bytes");
    CHECK_TRUE(got == 130 && memcmp(buffer, g_image + 78, 130) == 0,
               "split image read spanning two boundaries returns exact bytes");
    romfs_provider_destroy(p);

    /* gap: .001 absent while .002 exists */
    path_join(path, sizeof(path), g_fix, "romfs.bin.001");
    remove_file(path);
    CHK_STATUS(init_fresh(&cfg, &diag, "gap"), ROMFS_PROVIDER_ERR_IMAGE_PARTS,
               "part gap is rejected");

    /* unequal sizes: 100 + 50 + 150 still sums to 300 */
    path_join(path, sizeof(path), g_fix, "romfs.bin.000");
    CHECK_TRUE(write_bytes(path, g_image, 100), "unequal part fixture 0");
    path_join(path, sizeof(path), g_fix, "romfs.bin.001");
    CHECK_TRUE(write_bytes(path, g_image + 100, 50), "unequal part fixture 1");
    path_join(path, sizeof(path), g_fix, "romfs.bin.002");
    CHECK_TRUE(write_bytes(path, g_image + 150, 150), "unequal part fixture 2");
    CHK_STATUS(init_fresh(&cfg, &diag, "unequal"), ROMFS_PROVIDER_ERR_IMAGE_PARTS,
               "unequal part sizes are rejected");

    /* empty part */
    path_join(path, sizeof(path), g_fix, "romfs.bin.001");
    CHECK_TRUE(write_bytes(path, g_image, 0), "empty part fixture");
    CHK_STATUS(init_fresh(&cfg, &diag, "empty"), ROMFS_PROVIDER_ERR_IMAGE_PARTS,
               "empty part is rejected");

    /* extra parts: 4 x 100 bytes for a 300-byte image */
    CHECK_TRUE(install_extra_parts(4, 100), "extra part fixture");
    CHK_STATUS(init_fresh(&cfg, &diag, "extra"), ROMFS_PROVIDER_ERR_IMAGE_PARTS,
               "extra parts are rejected");
    remove_parts();
    return 0;
}

static int rows_parts_edges(void)
{
    romfs_provider_config cfg;
    romfs_provider_diag diag;
    RomfsProvider *p;
    uint64_t index = 0, got = 0;
    uint8_t buffer[256];
    char path[PATH_CAP];

    /* Missing middle with the prefix already summing to the pinned size: a
     * full-width .000 followed by a real .002 must still be a GAP, not a
     * complete image of 300 bytes. */
    remove_parts();
    CHECK_TRUE(install_index(g_index1, g_index1_size), "gap setup index");
    path_join(path, sizeof(path), g_fix, "romfs.bin");
    remove_file(path);
    path_join(path, sizeof(path), g_fix, "romfs.bin.000");
    CHECK_TRUE(write_bytes(path, g_image, FIXTURE_IMAGE_SIZE),
               "full-prefix gap part 0");
    path_join(path, sizeof(path), g_fix, "romfs.bin.002");
    CHECK_TRUE(write_bytes(path, g_image, FIXTURE_IMAGE_SIZE),
               "full-prefix gap part 2");
    cfg_clear(&cfg);
    CHK_STATUS(init_fresh(&cfg, &diag, "full-prefix gap"),
               ROMFS_PROVIDER_ERR_IMAGE_PARTS,
               "missing middle part is rejected even when the prefix sums to the image size");

    /* A present-but-unusable monolithic file must not fall back to parts. */
    remove_parts();
    CHECK_TRUE(install_index(g_index1, g_index1_size), "mono-dir setup index");
    path_join(path, sizeof(path), g_fix, "romfs.bin");
    ensure_dir(path);
    CHECK_TRUE(install_parts(3, 100), "mono-dir setup parts");
    CHK_STATUS(init_fresh(&cfg, &diag, "mono directory"),
               ROMFS_PROVIDER_ERR_IMAGE_OPEN,
               "present-but-unusable romfs.bin does not fall back to parts");
    remove_dir(path);
    remove_parts();
    CHECK_TRUE(install_image(), "restore image after mono-dir row");

    /* Exactly 64 valid parts (the inclusive cap), then a 65th part. */
    ensure_dir(g_fix2);
    CHECK_TRUE(install_index_at(g_fix2, g_index1, g_index1_size),
               "64-part setup index");
    path_join(path, sizeof(path), g_fix2, "romfs.bin");
    remove_file(path);
    CHECK_TRUE(install_parts_at(g_fix2, 64, 10, g_image2,
                                FIXTURE2_IMAGE_SIZE),
               "64-part fixture");
    cfg2_clear(&cfg);
    p = romfs_provider_create();
    if (!p) return fatal("provider allocation", 0);
    CHK_STATUS(romfs_provider_init(p, &cfg, &diag), ROMFS_PROVIDER_OK,
               "exactly 64 parts are accepted");
    CHK_STATUS(romfs_provider_find(p, "dir/b.bin", &index), ROMFS_PROVIDER_OK,
               "64-part lookup");
    memset(buffer, 0, sizeof(buffer));
    CHK_STATUS(romfs_provider_read(p, index, 0, buffer, 200, &got),
               ROMFS_PROVIDER_OK,
               "64-part read crosses many part boundaries exactly");
    CHECK_TRUE(got == 200 && memcmp(buffer, g_image2 + 8, 200) == 0,
               "64-part read crosses many part boundaries exactly");
    romfs_provider_destroy(p);

    path_join(path, sizeof(path), g_fix2, "romfs.bin.064");
    CHECK_TRUE(write_bytes(path, g_image2, 10), "65th part fixture");
    CHK_STATUS(init_fresh(&cfg, &diag, "65 parts"),
               ROMFS_PROVIDER_ERR_IMAGE_PARTS,
               "a 65th part is rejected");
    remove_parts_at(g_fix2, 128);
    return 0;
}

static int rows_diag(void)
{
    romfs_provider_config cfg;
    romfs_provider_diag diag;
    RomfsProvider *p;

    remove_parts();
    CHECK_TRUE(install_index(g_index1, g_index1_size) && install_image(),
               "diagnostic fixture setup");
    clear_manifests();
    cfg_clear(&cfg);
    memset(&diag, 0xaa, sizeof(diag));
    p = romfs_provider_create();
    if (!p) return fatal("provider allocation", 0);
    CHK_STATUS(romfs_provider_init(p, &cfg, &diag), ROMFS_PROVIDER_OK,
               "successful init clears the diagnostic");
    CHECK_TRUE(diag.status == ROMFS_PROVIDER_OK &&
                   strcmp(diag.stage, "ready") == 0 &&
                   diag.detail[0] == '\0',
               "successful init reports READY with an empty detail");
    memset(&diag, 0xaa, sizeof(diag));
    {
        romfs_provider_config bogus = cfg;
        bogus.resource_dir = "C:/definitely/not/here";
        CHK_STATUS(romfs_provider_init(p, &bogus, &diag), ROMFS_PROVIDER_OK,
                   "idempotent init is reported as READY");
        CHECK_TRUE(diag.status == ROMFS_PROVIDER_OK &&
                       strcmp(diag.stage, "ready") == 0 &&
                       diag.detail[0] == '\0',
                   "idempotent init clears stale diagnostic detail");
    }
    romfs_provider_destroy(p);

    /* A failed optional/required-manifest probe leaves a diagnostic, and the
     * next successful init on the same caller buffer must clear it. */
    cfg.overlay_root_count = 1;
    cfg.overlay_dirs[0] = g_ovl1;
    cfg.overlay_required[0] = 1;
    memset(&diag, 0xaa, sizeof(diag));
    CHK_STATUS(init_fresh(&cfg, &diag, "diagnostic required missing"),
               ROMFS_PROVIDER_ERR_OVERLAY_REQUIRED,
               "required overlay missing reports a typed diagnostic");
    CHECK_TRUE(diag.status == ROMFS_PROVIDER_ERR_OVERLAY_REQUIRED &&
                   strcmp(diag.stage, "overlay") == 0 && diag.detail[0] != '\0',
               "required overlay missing names its stage and detail");
    cfg.overlay_root_count = 0;
    memset(&diag, 0xaa, sizeof(diag));
    p = romfs_provider_create();
    if (!p) return fatal("provider allocation", 0);
    CHK_STATUS(romfs_provider_init(p, &cfg, &diag), ROMFS_PROVIDER_OK,
               "recovery init clears the previous failure detail");
    CHECK_TRUE(diag.status == ROMFS_PROVIDER_OK &&
                   strcmp(diag.stage, "ready") == 0 && diag.detail[0] == '\0',
               "recovery init clears the previous failure detail");
    romfs_provider_destroy(p);
    return 0;
}

static int rows_long_paths(void)
{
    static const char UNICODE_SEGMENT[] = "\xE6\x95\xB0\xE6\x8D\xAE-\xCE\x94";
    romfs_provider_config cfg;
    romfs_provider_diag diag;
    RomfsProvider *p;
    uint64_t index = 0, got = 0;
    int overlaid = 0;
    uint8_t buffer[32];
    char pad[200];
    char sub[PATH_CAP];
    char line[512];

    memset(pad, 'u', sizeof(pad) - 1u);
    pad[sizeof(pad) - 1u] = '\0';
    snprintf(g_long_resource, sizeof(g_long_resource),
             "%s/long-resource-%s-%s/deep/resource", g_fix, pad,
             UNICODE_SEGMENT);
    snprintf(g_long_overlay, sizeof(g_long_overlay),
             "%s/long-overlay-%s-%s/deep/overlay", g_fix, pad,
             UNICODE_SEGMENT);
    if (strlen(g_long_resource) <= 260u || strlen(g_long_overlay) <= 260u)
        return fatal("long-path fixture is not longer than MAX_PATH",
                     (long long)strlen(g_long_resource));

    ensure_dir_tree(g_long_resource);
    CHECK_TRUE(install_index_at(g_long_resource, g_index1, g_index1_size),
               "long resource index fixture");
    {
        char path[PATH_CAP];
        path_join(path, sizeof(path), g_long_resource, "romfs.bin");
        CHECK_TRUE(write_bytes(path, g_image, FIXTURE_IMAGE_SIZE),
                   "long resource image fixture");
    }
    cfg_clear(&cfg);
    cfg.resource_dir = g_long_resource;
    p = romfs_provider_create();
    if (!p) return fatal("provider allocation", 0);
    CHK_STATUS(romfs_provider_init(p, &cfg, &diag), ROMFS_PROVIDER_OK,
               "long Unicode resource path initializes");
    CHK_STATUS(romfs_provider_find(p, "dir/b.bin", &index), ROMFS_PROVIDER_OK,
               "long Unicode resource lookup");
    memset(buffer, 0, sizeof(buffer));
    CHK_STATUS(romfs_provider_read(p, index, 0, buffer, 8, &got),
               ROMFS_PROVIDER_OK, "long Unicode resource read");
    CHECK_TRUE(got == 8 && memcmp(buffer, g_image + 8, 8) == 0,
               "long Unicode resource read returns the verified bytes");
    romfs_provider_destroy(p);

    ensure_dir_tree(g_long_overlay);
    path_join(sub, sizeof(sub), g_long_overlay, "dir");
    ensure_dir_tree(sub);
    overlay_file(sub, "b.bin", "OVLY!");
    snprintf(line, sizeof(line), "dir/b.bin\t5\t%s\t%s\n", OVL_DIRB_SHA256,
             ORIG_DIRB_SHA256);
    write_manifest(g_long_overlay, line);
    cfg_clear(&cfg);
    cfg.overlay_root_count = 1;
    cfg.overlay_dirs[0] = g_long_overlay;
    cfg.overlay_required[0] = 0;
    p = romfs_provider_create();
    if (!p) return fatal("provider allocation", 0);
    CHK_STATUS(romfs_provider_init(p, &cfg, &diag), ROMFS_PROVIDER_OK,
               "long Unicode overlay path initializes");
    CHK_STATUS(romfs_provider_find(p, "dir/b.bin", &index), ROMFS_PROVIDER_OK,
               "long Unicode overlay lookup");
    CHK_STATUS(romfs_provider_is_overlaid(p, index, &overlaid),
               ROMFS_PROVIDER_OK, "long Unicode overlay is active");
    CHECK_TRUE(overlaid == 1, "long Unicode overlay is active");
    memset(buffer, 0, sizeof(buffer));
    CHK_STATUS(romfs_provider_read(p, index, 0, buffer, 32, &got),
               ROMFS_PROVIDER_OK, "long Unicode overlay read");
    CHECK_TRUE(got == 5 && memcmp(buffer, "OVLY!", 5) == 0,
               "long Unicode overlay serves the replacement bytes");
    romfs_provider_destroy(p);
    return 0;
}

static int rows_integrity(void)
{
    static const char ZERO_SHA[65] =
        "0000000000000000000000000000000000000000000000000000000000000000";
    romfs_provider_config cfg;
    romfs_provider_diag diag;
    RomfsProvider *p;
    uint64_t index = 0, got = 0;
    uint8_t buffer[8];
    char path[PATH_CAP];

    remove_parts();
    CHECK_TRUE(install_index(g_index1, g_index1_size) && install_image(),
               "integrity fixture setup");

    /* 1. bad index digest (valid layout) */
    cfg_clear(&cfg);
    cfg.index_sha256_hex = ZERO_SHA;
    CHK_STATUS(init_fresh(&cfg, &diag, "index digest"),
               ROMFS_PROVIDER_ERR_INDEX_DIGEST,
               "bad index digest is rejected");

    /* 2. same-size changed image */
    {
        uint8_t changed[FIXTURE_IMAGE_SIZE];
        memcpy(changed, g_image, sizeof(changed));
        changed[150] ^= 0x40;
        path_join(path, sizeof(path), g_fix, "romfs.bin");
        CHECK_TRUE(write_bytes(path, changed, sizeof(changed)),
                   "changed image fixture");
    }
    cfg_clear(&cfg);
    CHK_STATUS(init_fresh(&cfg, &diag, "image digest"),
               ROMFS_PROVIDER_ERR_IMAGE_DIGEST,
               "same-size changed image is rejected");

    /* 3. missing index */
    path_join(path, sizeof(path), g_fix, "runtime-index.bin");
    remove_file(path);
    CHK_STATUS(init_fresh(&cfg, &diag, "index missing"),
               ROMFS_PROVIDER_ERR_INDEX_OPEN, "missing index is rejected");

    /* 4. missing image (and no parts) */
    CHECK_TRUE(install_index(g_index1, g_index1_size), "reinstall index");
    path_join(path, sizeof(path), g_fix, "romfs.bin");
    remove_file(path);
    remove_parts();
    CHK_STATUS(init_fresh(&cfg, &diag, "image missing"),
               ROMFS_PROVIDER_ERR_IMAGE_OPEN, "missing image is rejected");

    /* 5. wrong image size */
    CHECK_TRUE(write_bytes(path, g_image, FIXTURE_IMAGE_SIZE - 1),
               "truncated image fixture");
    CHK_STATUS(init_fresh(&cfg, &diag, "image size"),
               ROMFS_PROVIDER_ERR_IMAGE_SIZE, "wrong image size is rejected");

    /* 6. retry after failures, and the EMPTY invariant with a live provider */
    CHECK_TRUE(install_image(), "restore image");
    p = romfs_provider_create();
    if (!p) return fatal("provider allocation", 0);
    CHK_STATUS(romfs_provider_init(p, &cfg, &diag), ROMFS_PROVIDER_OK,
               "retry with correct input succeeds");
    CHECK_TRUE(romfs_provider_file_count(p) == 3,
               "retry with correct input succeeds");
    CHK_STATUS(romfs_provider_find(p, "a.txt", &index), ROMFS_PROVIDER_OK,
               "retry lookup succeeds");
    CHK_STATUS(romfs_provider_read(p, index, 0, buffer, 4, &got),
               ROMFS_PROVIDER_OK, "retry read succeeds");
    CHECK_TRUE(got == 4 && memcmp(buffer, g_image, 4) == 0,
               "retry read succeeds");
    romfs_provider_destroy(p);

    p = romfs_provider_create();
    if (!p) return fatal("provider allocation", 0);
    cfg_clear(&cfg);
    cfg.image_sha256_hex = ZERO_SHA;
    CHK_STATUS(romfs_provider_init(p, &cfg, &diag),
               ROMFS_PROVIDER_ERR_IMAGE_DIGEST,
               "failed init returns the typed status");
    CHECK_TRUE(!romfs_provider_is_ready(p) &&
                   romfs_provider_file_count(p) == 0,
               "failed init leaves the provider EMPTY");
    CHK_STATUS(romfs_provider_find(p, "a.txt", &index),
               ROMFS_PROVIDER_ERR_NOT_READY,
               "failed init leaves the provider EMPTY");
    CHK_STATUS(romfs_provider_read(p, 0, 0, buffer, 1, &got),
               ROMFS_PROVIDER_ERR_NOT_READY,
               "failed init leaves the provider EMPTY");
    romfs_provider_destroy(p);

    /* a small index is a size error, not a layout error */
    CHECK_TRUE(install_image(), "restore image");
    {
        uint8_t tiny[10];
        memset(tiny, 0, sizeof(tiny));
        path_join(path, sizeof(path), g_fix, "runtime-index.bin");
        CHECK_TRUE(write_bytes(path, tiny, sizeof(tiny)), "tiny index fixture");
        cfg_clear(&cfg);
        {
            char hex[65];
            sha_hex(tiny, sizeof(tiny), hex);
            cfg.index_sha256_hex = hex;
            CHK_STATUS(init_fresh(&cfg, &diag, "tiny index"),
                       ROMFS_PROVIDER_ERR_INDEX_SIZE,
                       "index smaller than 24 bytes is rejected");
        }
    }
    CHECK_TRUE(install_index(g_index1, g_index1_size), "restore index");
    return 0;
}

static int expect_layout_reject(uint8_t *bytes, size_t n, const char *label)
{
    char path[PATH_CAP];
    char hex[65];
    romfs_provider_config cfg;
    romfs_provider_diag diag;
    path_join(path, sizeof(path), g_fix, "runtime-index.bin");
    if (!write_bytes(path, bytes, n)) return fatal("layout fixture", 0);
    cfg_clear(&cfg);
    sha_hex(bytes, n, hex);
    cfg.index_sha256_hex = hex;
    return expect_status(init_fresh(&cfg, &diag, label),
                         ROMFS_PROVIDER_ERR_INDEX_LAYOUT, label)
               ? 0
               : 2;
}

static int rows_index_layout(void)
{
    uint8_t buf[512];
    CHECK_TRUE(install_image(), "layout fixture image");

    /* bad magic */
    memcpy(buf, g_index1, g_index1_size);
    buf[0] = 'X';
    {
        int rc = expect_layout_reject(buf, g_index1_size,
                                      "bad index magic is rejected");
        if (rc) return rc;
    }
    /* file count at the limit */
    memcpy(buf, g_index1, g_index1_size);
    {
        uint64_t count = 1000000u;
        memcpy(buf + 8, &count, 8);
    }
    {
        int rc = expect_layout_reject(buf, g_index1_size,
                                      "index file count limit is rejected");
        if (rc) return rc;
    }
    /* strings offset inconsistent with the count */
    memcpy(buf, g_index1, g_index1_size);
    {
        uint64_t strings_offset = 96u + 8u;
        memcpy(buf + 16, &strings_offset, 8);
    }
    {
        int rc = expect_layout_reject(buf, g_index1_size,
                                      "index strings offset mismatch is rejected");
        if (rc) return rc;
    }
    /* entry range beyond the pinned image size */
    memcpy(buf, g_index1, g_index1_size);
    {
        uint64_t size = FIXTURE_IMAGE_SIZE + 1u;
        memcpy(buf + 24 + 8, &size, 8);
    }
    {
        int rc = expect_layout_reject(buf, g_index1_size,
                                      "index entry range beyond image is rejected");
        if (rc) return rc;
    }
    /* name range beyond the string table */
    memcpy(buf, g_index1, g_index1_size);
    {
        uint32_t name_len = 0xffffu;
        memcpy(buf + 24 + 20, &name_len, 4);
    }
    {
        int rc = expect_layout_reject(buf, g_index1_size,
                                      "index name range beyond string table is rejected");
        if (rc) return rc;
    }
    /* embedded NUL inside a name ("a.txt" -> "a\0txt") */
    memcpy(buf, g_index1, g_index1_size);
    buf[96 + 2] = '\0';
    {
        int rc = expect_layout_reject(buf, g_index1_size,
                                      "index embedded NUL is rejected");
        if (rc) return rc;
    }
    /* unsorted names */
    {
        static const Row rows[2] = {{0, 8, "b.txt"}, {0, 8, "a.txt"}};
        size_t n = build_index(buf, sizeof(buf), rows, 2);
        int rc = expect_layout_reject(buf, n,
                                      "index unsorted names are rejected");
        if (rc) return rc;
    }
    /* duplicate names */
    {
        static const Row rows[2] = {{0, 8, "a.txt"}, {0, 8, "a.txt"}};
        size_t n = build_index(buf, sizeof(buf), rows, 2);
        int rc = expect_layout_reject(buf, n,
                                      "index duplicate names are rejected");
        if (rc) return rc;
    }
    /* name length 1 (empty name) */
    {
        static const Row rows[1] = {{0, 8, ""}};
        size_t n = build_index(buf, sizeof(buf), rows, 1);
        int rc = expect_layout_reject(buf, n,
                                      "index empty name is rejected");
        if (rc) return rc;
    }
    CHECK_TRUE(install_index(g_index1, g_index1_size), "restore index");
    return 0;
}

static int rows_overlays(void)
{
    romfs_provider_config cfg;
    romfs_provider_diag diag;
    RomfsProvider *p;
    uint64_t index = 0, got = 0, effective = 0;
    int overlaid = 0;
    uint8_t buffer[64];
    char line[512];

    CHECK_TRUE(install_index(g_index1, g_index1_size) && install_image(),
               "overlay fixture setup");
    clear_manifests();

    /* optional root without a manifest serves the originals */
    cfg_clear(&cfg);
    cfg.overlay_root_count = 1;
    cfg.overlay_dirs[0] = g_ovl1;
    cfg.overlay_required[0] = 0;
    memset(&diag, 0xaa, sizeof(diag));
    p = romfs_provider_create();
    if (!p) return fatal("provider allocation", 0);
    CHK_STATUS(romfs_provider_init(p, &cfg, &diag), ROMFS_PROVIDER_OK,
               "optional overlay absent serves originals");
    /* This is the real-data regression: the optional-missing-manifest branch
     * sets a diagnostic while probing, so success must not publish that stale
     * text as if it belonged to the READY provider. */
    CHECK_TRUE(diag.status == ROMFS_PROVIDER_OK &&
                   strcmp(diag.stage, "ready") == 0 && diag.detail[0] == '\0',
               "optional-missing manifest success clears stale diagnostic detail");
    CHK_STATUS(romfs_provider_find(p, "dir/b.bin", &index), ROMFS_PROVIDER_OK,
               "optional overlay absent serves originals");
    CHK_STATUS(romfs_provider_effective_size(p, index, &effective),
               ROMFS_PROVIDER_OK, "optional overlay absent serves originals");
    CHK_STATUS(romfs_provider_is_overlaid(p, index, &overlaid),
               ROMFS_PROVIDER_OK, "optional overlay absent serves originals");
    CHECK_TRUE(effective == 200 && overlaid == 0,
               "optional overlay absent serves originals");
    romfs_provider_destroy(p);

    /* Empty/blank/comment-only manifests are valid zero-overlay manifests in
     * the Mac reference; only a missing manifest is optional. */
    {
        static const char *const texts[] = {"", "\n", "# only a comment\n\n"};
        for (unsigned i = 0; i < sizeof(texts) / sizeof(texts[0]); i++) {
            write_manifest(g_ovl1, texts[i]);
            cfg.overlay_root_count = 1;
            cfg.overlay_dirs[0] = g_ovl1;
            cfg.overlay_required[0] = 0;
            p = romfs_provider_create();
            if (!p) return fatal("provider allocation", 0);
            CHK_STATUS(romfs_provider_init(p, &cfg, &diag), ROMFS_PROVIDER_OK,
                       "empty/blank/comment-only manifest serves originals");
            CHK_STATUS(romfs_provider_find(p, "dir/b.bin", &index),
                       ROMFS_PROVIDER_OK,
                       "empty/blank/comment-only manifest serves originals");
            CHK_STATUS(romfs_provider_is_overlaid(p, index, &overlaid),
                       ROMFS_PROVIDER_OK,
                       "empty/blank/comment-only manifest serves originals");
            CHECK_TRUE(overlaid == 0,
                       "empty/blank/comment-only manifest serves originals");
            romfs_provider_destroy(p);
        }
        clear_manifests();
    }

    /* An optional root may ignore only NOT_FOUND: a manifest that exists but
     * cannot be opened as a regular file must fail, never serve originals. */
    {
        char manifest[PATH_CAP];
        path_join(manifest, sizeof(manifest), g_ovl1, "manifest.tsv");
        remove_file(manifest);
        ensure_dir(manifest);
        cfg.overlay_root_count = 1;
        cfg.overlay_dirs[0] = g_ovl1;
        cfg.overlay_required[0] = 0;
        CHK_STATUS(init_fresh(&cfg, &diag, "manifest not regular"),
                   ROMFS_PROVIDER_ERR_OVERLAY_MANIFEST,
                   "optional overlay ignores only a missing manifest, not an unusable one");
        remove_dir(manifest);
    }

    /* required root with no manifest */
    cfg.overlay_dirs[0] = g_ovl1;
    cfg.overlay_required[0] = 1;
    CHK_STATUS(init_fresh(&cfg, &diag, "required missing"),
               ROMFS_PROVIDER_ERR_OVERLAY_REQUIRED,
               "required overlay missing is rejected");

    /* valid overlay */
    {
        char sub[PATH_CAP];
        path_join(sub, sizeof(sub), g_ovl1, "dir");
        ensure_dir(sub);
        overlay_file(sub, "b.bin", "OVLY!");
        snprintf(line, sizeof(line), "dir/b.bin\t5\t%s\t%s\n", OVL_DIRB_SHA256,
                 ORIG_DIRB_SHA256);
        write_manifest(g_ovl1, line);
    }
    cfg.overlay_required[0] = 0;
    p = romfs_provider_create();
    if (!p) return fatal("provider allocation", 0);
    CHK_STATUS(romfs_provider_init(p, &cfg, &diag), ROMFS_PROVIDER_OK,
               "overlay replacement bytes are served");
    CHK_STATUS(romfs_provider_find(p, "dir/b.bin", &index), ROMFS_PROVIDER_OK,
               "overlay replacement bytes are served");
    CHK_STATUS(romfs_provider_effective_size(p, index, &effective),
               ROMFS_PROVIDER_OK, "overlay replacement bytes are served");
    CHK_STATUS(romfs_provider_is_overlaid(p, index, &overlaid),
               ROMFS_PROVIDER_OK, "overlay replacement bytes are served");
    CHECK_TRUE(effective == 5 && overlaid == 1,
               "overlay replacement bytes are served");
    memset(buffer, 0, sizeof(buffer));
    CHK_STATUS(romfs_provider_read(p, index, 0, buffer, 64, &got),
               ROMFS_PROVIDER_OK, "overlay replacement bytes are served");
    CHECK_TRUE(got == 5 && memcmp(buffer, "OVLY!", 5) == 0,
               "overlay replacement bytes are served");
    {
        uint64_t offset = 0, original_size = 0;
        const char *name = NULL;
        CHK_STATUS(romfs_provider_entry(p, index, &offset, &original_size, &name),
                   ROMFS_PROVIDER_OK,
                   "overlay keeps the original index metadata");
        CHECK_TRUE(offset == 8 && original_size == 200 &&
                       strcmp(name, "dir/b.bin") == 0,
                   "overlay keeps the original index metadata");
    }
    romfs_provider_destroy(p);
    clear_manifests();

    /* unknown index path */
    snprintf(line, sizeof(line), "nope.txt\t5\t%s\t%s\n", OVL_DIRB_SHA256,
             ORIG_DIRB_SHA256);
    write_manifest(g_ovl1, line);
    cfg.overlay_required[0] = 0;
    CHK_STATUS(init_fresh(&cfg, &diag, "unknown"), ROMFS_PROVIDER_ERR_OVERLAY_UNKNOWN,
               "overlay unknown path is rejected");
    clear_manifests();

    /* original hash mismatch */
    snprintf(line, sizeof(line),
             "dir/b.bin\t5\t%s\t"
             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
             OVL_DIRB_SHA256);
    write_manifest(g_ovl1, line);
    CHK_STATUS(init_fresh(&cfg, &diag, "original"),
               ROMFS_PROVIDER_ERR_OVERLAY_ORIGINAL,
               "overlay original hash mismatch is rejected");
    clear_manifests();

    /* replacement hash mismatch (size still correct) */
    snprintf(line, sizeof(line),
             "dir/b.bin\t5\t"
             "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\t%s\n",
             ORIG_DIRB_SHA256);
    write_manifest(g_ovl1, line);
    CHK_STATUS(init_fresh(&cfg, &diag, "replacement hash"),
               ROMFS_PROVIDER_ERR_OVERLAY_REPLACEMENT,
               "overlay replacement hash mismatch is rejected");
    clear_manifests();

    /* replacement size mismatch */
    snprintf(line, sizeof(line), "dir/b.bin\t6\t%s\t%s\n", OVL_DIRB_SHA256,
             ORIG_DIRB_SHA256);
    write_manifest(g_ovl1, line);
    CHK_STATUS(init_fresh(&cfg, &diag, "replacement size"),
               ROMFS_PROVIDER_ERR_OVERLAY_REPLACEMENT,
               "overlay replacement size mismatch is rejected");
    clear_manifests();

    /* malformed manifest line (three fields) */
    write_manifest(g_ovl1, "dir/b.bin\t5\tabc\n");
    CHK_STATUS(init_fresh(&cfg, &diag, "manifest line"),
               ROMFS_PROVIDER_ERR_OVERLAY_MANIFEST,
               "overlay malformed manifest line is rejected");
    clear_manifests();

    /* A FIFTH tab field must be rejected, not silently truncated: the
     * reference row is exactly four fields and the fourth holds the original
     * digest, so dropping a trailing field would accept a longer row. */
    snprintf(line, sizeof(line), "dir/b.bin\t5\t%s\t%s\textra\n",
             OVL_DIRB_SHA256, ORIG_DIRB_SHA256);
    write_manifest(g_ovl1, line);
    CHK_STATUS(init_fresh(&cfg, &diag, "manifest extra tab"),
               ROMFS_PROVIDER_ERR_OVERLAY_MANIFEST,
               "overlay manifest with a fifth field is rejected");
    snprintf(line, sizeof(line), "dir/b.bin\t5\t%s\t%s\t\n",
             OVL_DIRB_SHA256, ORIG_DIRB_SHA256);
    write_manifest(g_ovl1, line);
    CHK_STATUS(init_fresh(&cfg, &diag, "manifest trailing tab"),
               ROMFS_PROVIDER_ERR_OVERLAY_MANIFEST,
               "overlay manifest with a trailing tab is rejected");
    clear_manifests();

    /* An embedded NUL after a VALID four-field prefix must be rejected before
     * the line splitter runs; otherwise the valid prefix would be accepted
     * while the rest of the file was hidden from the parser. */
    {
        char path[PATH_CAP];
        char raw[512];
        int prefix = snprintf(raw, sizeof(raw), "dir/b.bin\t5\t%s\t%s\n",
                              OVL_DIRB_SHA256, ORIG_DIRB_SHA256);
        CHECK_TRUE(prefix > 0 && (size_t)prefix + 9u < sizeof(raw),
                   "nul manifest fixture size");
        memcpy(raw + prefix, "garbage\0x", 9u);
        path_join(path, sizeof(path), g_ovl1, "manifest.tsv");
        CHECK_TRUE(write_bytes(path, raw, (size_t)prefix + 9u),
                   "nul manifest fixture");
        CHK_STATUS(init_fresh(&cfg, &diag, "manifest nul"),
                   ROMFS_PROVIDER_ERR_OVERLAY_MANIFEST,
                   "overlay manifest with an embedded NUL is rejected");
        clear_manifests();
    }

    /* unsafe Windows paths */
    {
        static const struct {
            const char *name;
            const char *label;
        } cases[] = {
            {"../x", "overlay traversal name is rejected"},
            {"C:/x", "overlay drive/ADS name is rejected"},
            {"dir/b.bin.", "overlay trailing dot name is rejected"},
            {"dir/", "overlay trailing slash name is rejected"},
            {"con.txt", "overlay reserved device name is rejected"},
            {"dir\\b.bin", "overlay backslash name is rejected"},
        };
        for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            snprintf(line, sizeof(line), "%s\t5\t%s\t%s\n", cases[i].name,
                     OVL_DIRB_SHA256, ORIG_DIRB_SHA256);
            write_manifest(g_ovl1, line);
            CHK_STATUS(init_fresh(&cfg, &diag, cases[i].name),
                       ROMFS_PROVIDER_ERR_OVERLAY_PATH, cases[i].label);
            clear_manifests();
        }
    }

    /* duplicate replacement across two layers */
    {
        char sub[PATH_CAP];
        snprintf(line, sizeof(line), "a.txt\t3\t%s\t%s\n", OVL_ATXT_SHA256,
                 ORIG_ATXT_SHA256);
        write_manifest(g_ovl1, line);
        write_manifest(g_ovl2, line);
        (void)sub;
        overlay_file(g_ovl1, "a.txt", "ZZZ");
        overlay_file(g_ovl2, "a.txt", "ZZZ");
        cfg.overlay_root_count = 2;
        cfg.overlay_dirs[0] = g_ovl1;
        cfg.overlay_dirs[1] = g_ovl2;
        cfg.overlay_required[0] = 0;
        cfg.overlay_required[1] = 0;
        CHK_STATUS(init_fresh(&cfg, &diag, "duplicate"),
                   ROMFS_PROVIDER_ERR_OVERLAY_DUPLICATE,
                   "overlay duplicate replacement is rejected");
        cfg.overlay_root_count = 1;
        cfg.overlay_dirs[1] = NULL;
        clear_manifests();
    }

    /* reparse-point escape: a junction inside the overlay root must not let a
     * validated name resolve outside the root. */
    {
        char sub[PATH_CAP];
        char link[PATH_CAP];
        uint8_t index2[512];
        size_t index2_size;
        static const Row rows4[4] = {{0, 8, "a.txt"},
                                     {8, 200, "dir/b.bin"},
                                     {0, 2, "link/a.txt"},
                                     {208, 92, "z/last.dat"}};
        index2_size = build_index(index2, sizeof(index2), rows4, 4);
        path_join(sub, sizeof(sub), g_outside, "a.txt");
        CHECK_TRUE(write_bytes(sub, "LINK2", 5), "escape fixture file");
        path_join(link, sizeof(link), g_ovl3, "link");
        if (make_junction(link, g_outside)) {
            snprintf(line, sizeof(line), "link/a.txt\t5\t%s\t%s\n",
                     OVL_LINK_SHA256, ORIG_LINK_SHA256);
            write_manifest(g_ovl3, line);
            CHECK_TRUE(install_index(index2, index2_size), "escape index fixture");
            cfg_clear(&cfg);
            cfg.index_sha256_hex = INDEX2_SHA256;
            cfg.overlay_root_count = 1;
            cfg.overlay_dirs[0] = g_ovl3;
            cfg.overlay_required[0] = 0;
            CHK_STATUS(init_fresh(&cfg, &diag, "escape"),
                       ROMFS_PROVIDER_ERR_OVERLAY_ESCAPE,
                       "overlay reparse escape is rejected");
            clear_manifests();
        } else {
            /* This host supports real junctions; failing to build the fixture
             * means the escape row could not run, which is an infrastructure
             * failure. Never silently pass it. */
            return fatal("could not create the overlay junction fixture",
                         (long long)g_junction_error);
        }
        CHECK_TRUE(install_index(g_index1, g_index1_size), "restore index");
    }

    /* late overlay failure leaves the provider EMPTY (checked by init_fresh) */
    cfg_clear(&cfg);
    cfg.overlay_root_count = 1;
    cfg.overlay_dirs[0] = g_ovl1;
    cfg.overlay_required[0] = 1;
    snprintf(line, sizeof(line),
             "dir/b.bin\t5\t%s\t"
             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
             OVL_DIRB_SHA256);
    write_manifest(g_ovl1, line);
    CHK_STATUS(init_fresh(&cfg, &diag, "late overlay"),
               ROMFS_PROVIDER_ERR_OVERLAY_ORIGINAL,
               "late overlay failure leaves the provider EMPTY");
    clear_manifests();
    return 0;
}

/* Direct seam rows for romfs_host_verify_under(): containment must be a
 * STRICT descendant, and a target final path SHORTER than the configured root
 * must be rejected without indexing past the shorter buffer. */
static int rows_host_seam(void)
{
    char root[PATH_CAP];
    char file[PATH_CAP];
    char link[PATH_CAP];
    RomfsHostFile *h;
    romfs_host_status hs = ROMFS_HOST_OK;

    snprintf(root, sizeof(root), "%s/containment-root-with-a-long-name", g_fix);
    ensure_dir(root);
    path_join(file, sizeof(file), root, "seam.txt");
    CHECK_TRUE(write_bytes(file, "SEAM", 4), "seam positive fixture");

    /* positive: a real strict descendant is accepted */
    h = romfs_host_open_readonly(file, &hs);
    if (!h) return fatal("seam positive open", (long long)hs);
    CHECK_TRUE(romfs_host_verify_under(h, root) == ROMFS_HOST_OK,
               "containment accepts a real descendant");
    romfs_host_close(h);

    /* negative: reach the OUTSIDE file through a junction inside the root. Its
     * canonical final path is shorter than the root spelling (root_len >
     * file_len), the case the ordinal prefix compare used to read past. */
    path_join(file, sizeof(file), g_outside, "seam.txt");
    CHECK_TRUE(write_bytes(file, "SEAM", 4), "seam escape fixture");
    path_join(link, sizeof(link), root, "link");
    if (!make_junction(link, g_outside))
        return fatal("could not create the containment junction fixture",
                     (long long)g_junction_error);
    CHECK_TRUE(strlen(root) > strlen(g_outside) + strlen("seam.txt") + 1u,
               "containment fixture keeps the root longer than the target");
    path_join(file, sizeof(file), link, "seam.txt");
    h = romfs_host_open_readonly(file, &hs);
    if (!h) return fatal("seam escape open", (long long)hs);
    CHECK_TRUE(romfs_host_verify_under(h, root) == ROMFS_HOST_ERR_PATH_ESCAPE,
               "containment rejects a shorter junction target");
    romfs_host_close(h);
    return 0;
}

static int rows_lifetime(void)
{
    romfs_provider_config cfg;
    romfs_provider_diag diag;
    RomfsProvider *p;
    char path[PATH_CAP];

    remove_parts();
    CHECK_TRUE(install_index(g_index1, g_index1_size) && install_image(),
               "lifetime fixture setup");
    cfg_clear(&cfg);
    path_join(path, sizeof(path), g_fix, "romfs.bin");

    p = romfs_provider_create();
    if (!p) return fatal("provider allocation", 0);
    CHK_STATUS(romfs_provider_init(p, &cfg, &diag), ROMFS_PROVIDER_OK,
               "lifetime init returns OK");
    {
        /* A writer opened AFTER the provider must be denied by the provider's
         * FILE_SHARE_READ-only handle. The writer itself shares read/write/
         * delete so the denial can only come from the provider's pinning handle
         * (share == 0 would also conflict for reasons unrelated to it). */
        HANDLE writer = open_write_raw(
            path, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
        if (writer != INVALID_HANDLE_VALUE) {
            CloseHandle(writer);
            return fail("live provider denies a write open of the image");
        }
        if (delete_raw(path)) {
            return fail("live provider denies deleting the image");
        }
    }
    romfs_provider_destroy(p);
    CHECK_TRUE(delete_raw(path) != 0,
               "destroyed provider releases its handles");

    /* A writer opened BEFORE init is the reciprocal-sharing case: its existing
     * GENERIC_WRITE access makes the provider's read open fail, so init must
     * reject the image instead of publishing bytes it cannot pin. */
    CHECK_TRUE(install_image(), "pre-existing writer fixture");
    {
        HANDLE writer = open_write_raw(path, FILE_SHARE_READ | FILE_SHARE_WRITE);
        if (writer == INVALID_HANDLE_VALUE)
            return fatal("could not open the pre-existing writer fixture",
                         (long long)GetLastError());
        CHK_STATUS(init_fresh(&cfg, &diag, "pre-existing writer"),
                   ROMFS_PROVIDER_ERR_IMAGE_OPEN,
                   "an already-open writer conflicts with provider init");
        CloseHandle(writer);
    }
    CHECK_TRUE(install_image(), "restore image after writer conflict");

    /* repeated cycles close every handle each time */
    for (unsigned cycle = 0; cycle < 5; cycle++) {
        CHECK_TRUE(install_image(), "cycle image fixture");
        p = romfs_provider_create();
        if (!p) return fatal("provider allocation", 0);
        CHK_STATUS(romfs_provider_init(p, &cfg, &diag), ROMFS_PROVIDER_OK,
                   "repeated create/init/destroy cycles succeed");
        CHECK_TRUE(romfs_provider_file_count(p) == 3,
                   "repeated create/init/destroy cycles succeed");
        romfs_provider_destroy(p);
        CHECK_TRUE(delete_raw(path) != 0,
                   "repeated create/init/destroy cycles succeed");
    }
    return 0;
}

int main(int argc, char **argv)
{
    char root[PATH_CAP];
    char hex[65];
    int rc;

    if (argc < 2) return fatal("usage: <external fixture root>", argc);
    snprintf(root, sizeof(root), "%s", argv[1]);
    ensure_dir(root);
    /* Per-process fixture roots: CTest may run the real probe and the mutant
     * driver's real child concurrently with the same external root. A PID
     * suffix keeps their handles/files independent; it is not a parallelism
     * suppression and every row still runs. */
    unsigned long process_id = (unsigned long)GetCurrentProcessId();
    snprintf(g_fix, sizeof(g_fix), "%s/romfs-provider-fixtures-%lu", root,
             process_id);
    snprintf(g_fix2, sizeof(g_fix2), "%s/romfs-provider-fixtures2-%lu", root,
             process_id);
    snprintf(g_ovl1, sizeof(g_ovl1), "%s/ovl1", g_fix);
    snprintf(g_ovl2, sizeof(g_ovl2), "%s/ovl2", g_fix);
    snprintf(g_ovl3, sizeof(g_ovl3), "%s/ovl3", g_fix);
    snprintf(g_outside, sizeof(g_outside), "%s/outside", g_fix);
    ensure_dir(g_fix);
    ensure_dir(g_fix2);
    ensure_dir(g_ovl1);
    ensure_dir(g_ovl2);
    ensure_dir(g_ovl3);
    ensure_dir(g_outside);
    {
        char sub[PATH_CAP];
        path_join(sub, sizeof(sub), g_ovl1, "dir");
        ensure_dir(sub);
    }

    make_image(g_image, FIXTURE_IMAGE_SIZE);
    make_image(g_image2, FIXTURE2_IMAGE_SIZE);
    g_index1_size = build_index(g_index1, sizeof(g_index1), ROWS3, 3);
    if (g_index1_size != 123u)
        return fatal("index fixture size", (long long)g_index1_size);
    sha_hex(g_index1, g_index1_size, hex);
    if (strcmp(hex, INDEX_SHA256) != 0)
        return fatal("index fixture does not match its pinned digest", 0);
    sha_hex(g_image, FIXTURE_IMAGE_SIZE, hex);
    if (strcmp(hex, IMAGE_SHA256) != 0)
        return fatal("image fixture does not match its pinned digest", 0);
    sha_hex(g_image2, FIXTURE2_IMAGE_SIZE, hex);
    if (strcmp(hex, IMAGE2_SHA256) != 0)
        return fatal("64-part image fixture does not match its pinned digest", 0);
    /* the overlay constants are pinned expectations, so prove the literals the
     * probe writes match them before any row relies on them */
    sha_hex("OVLY!", 5, hex);
    if (strcmp(hex, OVL_DIRB_SHA256) != 0)
        return fatal("overlay fixture digest drift", 0);
    sha_hex(g_image + 8, 200, hex);
    if (strcmp(hex, ORIG_DIRB_SHA256) != 0)
        return fatal("original range digest drift", 0);
    sha_hex(g_image, 8, hex);
    if (strcmp(hex, ORIG_ATXT_SHA256) != 0)
        return fatal("a.txt original digest drift", 0);
    sha_hex("ZZZ", 3, hex);
    if (strcmp(hex, OVL_ATXT_SHA256) != 0)
        return fatal("a.txt replacement digest drift", 0);
    sha_hex(g_image, 2, hex);
    if (strcmp(hex, ORIG_LINK_SHA256) != 0)
        return fatal("link original digest drift", 0);
    sha_hex("LINK2", 5, hex);
    if (strcmp(hex, OVL_LINK_SHA256) != 0)
        return fatal("link replacement digest drift", 0);

    rc = rows_valid_mono();
    if (rc) return rc;
    rc = rows_split_image();
    if (rc) return rc;
    rc = rows_parts_edges();
    if (rc) return rc;
    rc = rows_diag();
    if (rc) return rc;
    rc = rows_integrity();
    if (rc) return rc;
    rc = rows_index_layout();
    if (rc) return rc;
    rc = rows_overlays();
    if (rc) return rc;
    rc = rows_long_paths();
    if (rc) return rc;
    rc = rows_host_seam();
    if (rc) return rc;
    rc = rows_lifetime();
    if (rc) return rc;
    printf("PASS: romfs immutable provider (%u image bytes, 3 index rows)\n",
           FIXTURE_IMAGE_SIZE);
    return 0;
}
