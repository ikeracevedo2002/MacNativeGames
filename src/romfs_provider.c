/*
 * Immutable RomFS provider — shared (Windows-free) parsing, integrity and state
 * logic. Contract and scope: see romfs_provider.h.
 *
 * The Mac reference is games/totk/runtime/romfs.c:169-191 (runtime_fs_init) with
 * its index contract (:171-179), image/part selection (:108-116,180-182) and
 * overlay loading (:143-168). Meaningful behavior is preserved; differences are
 * deliberate and documented:
 *   - explicit config instead of getenv()/default paths;
 *   - always full verify, no proof-cache read/write (see the header);
 *   - typed errors instead of runtime_fail() so the adapter can later turn them
 *     into a fatal typed AOT fault, and so tests can distinguish EMPTY states;
 *   - Windows-unsafe overlay paths (absolute, ADS, drive, reserved device name,
 *     trailing dot/space) are rejected instead of being opened literally;
 *   - every overlay file must still resolve beneath its configured root after
 *     reparse points are resolved;
 *   - parts must be contiguous from .000 with equal sizes except the last; a
 *     reading of an absent part stops the scan and the checked sum decides.
 */
#include "romfs_provider.h"

#include "aot/aot_sha256.h"
#include "host_sha256.h"
#include "romfs_file_win.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ROMFS_INDEX_HEADER_BYTES 24u
#define ROMFS_INDEX_ROW_BYTES 24u
#define ROMFS_HASH_BUFFER_BYTES (8u * 1024u * 1024u)
/* Defensive supported-profile limits, NOT Mac limits: Mac reads the manifest
 * with fgets() and has no whole-file cap. Real manifests are a few hundred
 * bytes; a bounded streaming parser is not needed for this profile, so the
 * restriction is documented instead of pretending parity. */
#define ROMFS_MANIFEST_MAX_BYTES (1024u * 1024u)
#define ROMFS_MANIFEST_MAX_LINE 8192u
#define ROMFS_NAME_MAX_BYTES 4096u

typedef struct {
    uint64_t offset;
    uint64_t size;
    uint32_t name_offset;
    uint32_t name_len;
} RomfsIndexRow;

typedef struct {
    uint64_t index;
    uint64_t size;
    RomfsHostFile *file;
} RomfsOverlay;

typedef struct RomfsProviderStage {
    uint8_t *index;
    size_t index_size;
    uint64_t file_count;
    uint64_t strings_offset;
    uint64_t image_size;
    RomfsHostFile *image;
    RomfsHostFile *parts[ROMFS_PROVIDER_MAX_PARTS];
    unsigned part_count;
    uint64_t part_size;
    RomfsOverlay overlays[ROMFS_PROVIDER_MAX_OVERLAYS];
    unsigned overlay_count;
} RomfsProviderStage;

struct RomfsProvider {
    int ready;
    uint8_t *index;
    size_t index_size;
    uint64_t file_count;
    uint64_t strings_offset;
    uint64_t image_size;
    RomfsHostFile *image;
    RomfsHostFile *parts[ROMFS_PROVIDER_MAX_PARTS];
    unsigned part_count;
    uint64_t part_size;
    RomfsOverlay overlays[ROMFS_PROVIDER_MAX_OVERLAYS];
    unsigned overlay_count;
};

/* ---- helpers ---------------------------------------------------------- */

static void set_diag(romfs_provider_diag *diag, romfs_provider_status status,
                     const char *stage, const char *detail)
{
    if (!diag) return;
    diag->status = status;
    diag->stage = stage;
    if (!detail) {
        diag->detail[0] = '\0';
        return;
    }
    size_t n = strlen(detail);
    if (n >= sizeof(diag->detail)) n = sizeof(diag->detail) - 1;
    memcpy(diag->detail, detail, n);
    diag->detail[n] = '\0';
}

/* Exactly 64 lowercase hex characters -> 32 bytes. Uppercase is rejected so a
 * config typo cannot silently pass through a lenient parser. */
static int parse_sha256_hex(const char *hex, uint8_t out[32])
{
    if (!hex) return 0;
    for (unsigned i = 0; i < 64; i++) {
        char c = hex[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
    }
    if (hex[64] != '\0') return 0;
    for (unsigned i = 0; i < 32; i++) {
        unsigned hi = (unsigned)(hex[i * 2] <= '9' ? hex[i * 2] - '0'
                                                   : hex[i * 2] - 'a' + 10);
        unsigned lo = (unsigned)(hex[i * 2 + 1] <= '9' ? hex[i * 2 + 1] - '0'
                                                       : hex[i * 2 + 1] - 'a' + 10);
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 1;
}

static RomfsIndexRow index_row(const RomfsProvider *p, uint64_t index)
{
    RomfsIndexRow row;
    const uint8_t *at = p->index + ROMFS_INDEX_HEADER_BYTES +
                        (size_t)index * ROMFS_INDEX_ROW_BYTES;
    memcpy(&row.offset, at, 8);
    memcpy(&row.size, at + 8, 8);
    memcpy(&row.name_offset, at + 16, 4);
    memcpy(&row.name_len, at + 20, 4);
    return row;
}

static const char *entry_name(const RomfsProvider *p, RomfsIndexRow row)
{
    return (const char *)(p->index + p->strings_offset + row.name_offset);
}

static int overlay_name_ok(const char *name);

/* Mac's romfs_path_valid_relative plus the Windows ambiguity rules. Kept here
 * (shared C) rather than in the Win32 seam: it is a name contract, not a path
 * API. */
static int overlay_name_ok(const char *name)
{
    if (!name || !*name || *name == '/' || *name == '\\') return 0;
    size_t len = 0;
    for (; name[len]; len++) {
        unsigned char c = (unsigned char)name[len];
        if (c < 0x20 || c == 0x7f) return 0;
        if (c == '\\' || c == ':' || c == '"' || c == '*' || c == '?' ||
            c == '<' || c == '>' || c == '|')
            return 0;
        if (len >= ROMFS_NAME_MAX_BYTES) return 0;
    }
    /* A trailing separator is never a file name; Mac's component walk accepts
     * it, which on Windows would turn "dir/" into the directory itself. */
    if (name[len - 1] == '/') return 0;
    /* Components: non-empty, not "." or "..", no trailing dot/space, and not a
     * reserved DOS device name (which Win32 would redirect to a device). */
    static const char *const reserved[] = {
        "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5",
        "com6", "com7", "com8", "com9", "lpt1", "lpt2", "lpt3", "lpt4",
        "lpt5", "lpt6", "lpt7", "lpt8", "lpt9"};
    for (size_t at = 0; at < len;) {
        size_t end = at;
        while (end < len && name[end] != '/') end++;
        size_t part = end - at;
        if (part == 0) return 0;
        if (part == 1 && name[at] == '.') return 0;
        if (part == 2 && name[at] == '.' && name[at + 1] == '.') return 0;
        char last = name[at + part - 1];
        if (last == '.' || last == ' ') return 0;
        size_t base = 0;
        while (base < part && name[at + base] != '.') base++;
        if (base > 0 && base <= 4) {
            char lower[5];
            size_t n = 0;
            for (size_t i = 0; i < base; i++) {
                char c = name[at + i];
                if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
                lower[n++] = c;
            }
            lower[n] = '\0';
            for (size_t i = 0; i < sizeof(reserved) / sizeof(reserved[0]); i++) {
                if (strcmp(lower, reserved[i]) == 0) return 0;
            }
        }
        at = end + 1;
    }
    return 1;
}

/* ---- staged teardown -------------------------------------------------- */

static void stage_release(RomfsProviderStage *s)
{
    free(s->index);
    s->index = NULL;
    if (s->image) {
        romfs_host_close(s->image);
        s->image = NULL;
    }
    for (unsigned i = 0; i < s->part_count; i++) {
        if (s->parts[i]) romfs_host_close(s->parts[i]);
        s->parts[i] = NULL;
    }
    s->part_count = 0;
    for (unsigned i = 0; i < s->overlay_count; i++) {
        if (s->overlays[i].file) romfs_host_close(s->overlays[i].file);
        s->overlays[i].file = NULL;
    }
    s->overlay_count = 0;
}

/* ---- image access ----------------------------------------------------- */

/* One checked positional read of the image. Part routing mirrors the Mac
 * src_pread: offsets are translated into (part, in-part offset) and a read is
 * clamped to the part it starts in; callers loop for multi-part spans. */
static romfs_provider_status image_read_at(const RomfsProviderStage *s,
                                           uint64_t offset, void *buffer,
                                           uint64_t size, uint64_t *out_read)
{
    uint64_t done = 0;
    if (out_read) *out_read = 0;
    while (done < size) {
        uint64_t at = offset + done;
        RomfsHostFile *file;
        uint64_t in_part = at;
        if (s->part_count) {
            uint64_t chunk = at / s->part_size;
            if (chunk >= s->part_count) {
                /* Fail closed even though validation makes this unreachable: a
                 * request past the last part is a host-read failure with the
                 * actual prefix, never a silent short success. */
                if (out_read) *out_read = done;
                return ROMFS_PROVIDER_ERR_IMAGE_READ;
            }
            in_part = at % s->part_size;
            file = s->parts[chunk];
        } else {
            file = s->image;
        }
        uint64_t want = size - done;
        if (s->part_count && want > s->part_size - in_part)
            want = s->part_size - in_part;
        size_t got = 0;
        romfs_host_status hs = romfs_host_read_at(
            file, in_part, (unsigned char *)buffer + done, (size_t)want, &got);
        done += got;
        if (hs != ROMFS_HOST_OK) {
            if (out_read) *out_read = done;
            return ROMFS_PROVIDER_ERR_IMAGE_READ;
        }
    }
    if (out_read) *out_read = done;
    return ROMFS_PROVIDER_OK;
}

/* Bulk hashing uses the host SHA-256 (CNG, hardware accelerated): full
 * verification of a 17 GB image is mandatory on every init (D020), so its
 * cost is paid on every Start. Digests are identical to aot_sha256
 * (tests/host_sha256_probe.c); the small index keeps aot_sha256. */
static romfs_provider_status hash_status(host_sha256_result r)
{
    if (r == HOST_SHA256_OK) return ROMFS_PROVIDER_OK;
    if (r == HOST_SHA256_ERR_ALLOCATION) return ROMFS_PROVIDER_ERR_ALLOCATION;
    return ROMFS_PROVIDER_ERR_HASH;
}

static romfs_provider_status hash_image(const RomfsProviderStage *s,
                                        uint8_t out[32])
{
    HostSha256 *ctx = NULL;
    uint8_t *buffer = (uint8_t *)malloc(ROMFS_HASH_BUFFER_BYTES);
    if (!buffer) return ROMFS_PROVIDER_ERR_ALLOCATION;
    romfs_provider_status begin = hash_status(host_sha256_begin(&ctx));
    if (begin != ROMFS_PROVIDER_OK) {
        free(buffer);
        return begin;
    }
    uint64_t done = 0;
    romfs_provider_status result = ROMFS_PROVIDER_OK;
    while (done < s->image_size) {
        uint64_t chunk = s->image_size - done;
        if (chunk > ROMFS_HASH_BUFFER_BYTES) chunk = ROMFS_HASH_BUFFER_BYTES;
        uint64_t got = 0;
        result = image_read_at(s, done, buffer, chunk, &got);
        if (result != ROMFS_PROVIDER_OK) break;
        if (got != chunk) {
            result = ROMFS_PROVIDER_ERR_IMAGE_READ; /* short read */
            break;
        }
        result = hash_status(host_sha256_update(ctx, buffer, (size_t)got));
        if (result != ROMFS_PROVIDER_OK) break;
        done += got;
    }
    if (result == ROMFS_PROVIDER_OK)
        result = hash_status(host_sha256_finish(ctx, out));
    else
        host_sha256_abort(ctx);
    free(buffer);
    return result;
}

static romfs_provider_status hash_image_range(const RomfsProviderStage *s,
                                              uint64_t offset, uint64_t size,
                                              uint8_t out[32])
{
    HostSha256 *ctx = NULL;
    uint8_t *buffer = (uint8_t *)malloc(ROMFS_HASH_BUFFER_BYTES);
    if (!buffer) return ROMFS_PROVIDER_ERR_ALLOCATION;
    romfs_provider_status begin = hash_status(host_sha256_begin(&ctx));
    if (begin != ROMFS_PROVIDER_OK) {
        free(buffer);
        return begin;
    }
    uint64_t done = 0;
    romfs_provider_status result = ROMFS_PROVIDER_OK;
    while (done < size) {
        uint64_t chunk = size - done;
        if (chunk > ROMFS_HASH_BUFFER_BYTES) chunk = ROMFS_HASH_BUFFER_BYTES;
        uint64_t got = 0;
        result = image_read_at(s, offset + done, buffer, chunk, &got);
        if (result != ROMFS_PROVIDER_OK) break;
        if (got != chunk) {
            result = ROMFS_PROVIDER_ERR_IMAGE_READ;
            break;
        }
        result = hash_status(host_sha256_update(ctx, buffer, (size_t)got));
        if (result != ROMFS_PROVIDER_OK) break;
        done += got;
    }
    if (result == ROMFS_PROVIDER_OK)
        result = hash_status(host_sha256_finish(ctx, out));
    else
        host_sha256_abort(ctx);
    free(buffer);
    return result;
}

static romfs_provider_status hash_host_file(RomfsHostFile *file,
                                            uint64_t size, uint8_t out[32])
{
    HostSha256 *ctx = NULL;
    uint8_t *buffer = (uint8_t *)malloc(ROMFS_HASH_BUFFER_BYTES);
    if (!buffer) return ROMFS_PROVIDER_ERR_ALLOCATION;
    romfs_provider_status begin = hash_status(host_sha256_begin(&ctx));
    if (begin != ROMFS_PROVIDER_OK) {
        free(buffer);
        return begin;
    }
    uint64_t done = 0;
    romfs_provider_status result = ROMFS_PROVIDER_OK;
    while (done < size) {
        uint64_t chunk = size - done;
        if (chunk > ROMFS_HASH_BUFFER_BYTES) chunk = ROMFS_HASH_BUFFER_BYTES;
        size_t got = 0;
        romfs_host_status hs =
            romfs_host_read_at(file, done, buffer, (size_t)chunk, &got);
        if (hs != ROMFS_HOST_OK || got != chunk) {
            result = ROMFS_PROVIDER_ERR_READ;
            break;
        }
        result = hash_status(host_sha256_update(ctx, buffer, (size_t)got));
        if (result != ROMFS_PROVIDER_OK) break;
        done += got;
    }
    if (result == ROMFS_PROVIDER_OK)
        result = hash_status(host_sha256_finish(ctx, out));
    else
        host_sha256_abort(ctx);
    free(buffer);
    return result;
}

/* ---- index ----------------------------------------------------------- */

static romfs_provider_status load_index(const romfs_provider_config *cfg,
                                        RomfsProviderStage *s,
                                        const char *stage,
                                        romfs_provider_diag *diag,
                                        const uint8_t expected[32])
{
    char *path = romfs_host_join(cfg->resource_dir, "runtime-index.bin");
    if (!path) {
        set_diag(diag, ROMFS_PROVIDER_ERR_INVALID_ARGUMENT, stage,
                 "index path too long");
        return ROMFS_PROVIDER_ERR_INVALID_ARGUMENT;
    }
    romfs_host_status hs = ROMFS_HOST_OK;
    RomfsHostFile *file = romfs_host_open_readonly(path, &hs);
    free(path);
    if (!file) {
        set_diag(diag, ROMFS_PROVIDER_ERR_INDEX_OPEN, stage,
                 "runtime-index.bin missing or not a regular file");
        return ROMFS_PROVIDER_ERR_INDEX_OPEN;
    }
    uint64_t size = romfs_host_size(file);
    if (size < ROMFS_PROVIDER_MIN_INDEX_BYTES ||
        size >= ROMFS_PROVIDER_MAX_INDEX_BYTES) {
        romfs_host_close(file);
        set_diag(diag, ROMFS_PROVIDER_ERR_INDEX_SIZE, stage,
                 "index size outside [24, 128 MiB)");
        return ROMFS_PROVIDER_ERR_INDEX_SIZE;
    }
    s->index = (uint8_t *)malloc((size_t)size);
    if (!s->index) {
        romfs_host_close(file);
        set_diag(diag, ROMFS_PROVIDER_ERR_ALLOCATION, stage, "index buffer");
        return ROMFS_PROVIDER_ERR_ALLOCATION;
    }
    size_t got = 0;
    hs = romfs_host_read_at(file, 0, s->index, (size_t)size, &got);
    romfs_host_close(file);
    if (hs != ROMFS_HOST_OK || got != size) {
        set_diag(diag, ROMFS_PROVIDER_ERR_INDEX_READ, stage, "short index read");
        return ROMFS_PROVIDER_ERR_INDEX_READ;
    }
    s->index_size = (size_t)size;
    uint8_t digest[32];
    aot_sha256(s->index, s->index_size, digest);
    int digest_ok = memcmp(digest, expected, 32) == 0;
#ifdef MN_ROMFS_MUT_SKIP_INDEX_HASH
    /* Test-only wrong implementation (D020 negative control): accept the index
     * bytes without checking the pinned digest. Never in the shipping build. */
    digest_ok = 1;
#endif
    if (!digest_ok) {
        set_diag(diag, ROMFS_PROVIDER_ERR_INDEX_DIGEST, stage,
                 "index SHA-256 does not match the pinned digest");
        return ROMFS_PROVIDER_ERR_INDEX_DIGEST;
    }
    return ROMFS_PROVIDER_OK;
}

static romfs_provider_status validate_index(const romfs_provider_config *cfg,
                                            RomfsProviderStage *s,
                                            const char *stage,
                                            romfs_provider_diag *diag)
{
    const uint8_t *p = s->index;
    size_t size = s->index_size;
    if (memcmp(p, "TOTKRFS1", 8) != 0) {
        set_diag(diag, ROMFS_PROVIDER_ERR_INDEX_LAYOUT, stage,
                 "index magic is not TOTKRFS1");
        return ROMFS_PROVIDER_ERR_INDEX_LAYOUT;
    }
    memcpy(&s->file_count, p + 8, 8);
    memcpy(&s->strings_offset, p + 16, 8);
    if (s->file_count >= ROMFS_PROVIDER_MAX_FILES) {
        set_diag(diag, ROMFS_PROVIDER_ERR_INDEX_LAYOUT, stage,
                 "file count >= 1000000");
        return ROMFS_PROVIDER_ERR_INDEX_LAYOUT;
    }
    uint64_t expected_strings =
        (uint64_t)ROMFS_INDEX_HEADER_BYTES + s->file_count * ROMFS_INDEX_ROW_BYTES;
    if (s->strings_offset != expected_strings ||
        s->strings_offset >= (uint64_t)size) {
        set_diag(diag, ROMFS_PROVIDER_ERR_INDEX_LAYOUT, stage,
                 "strings offset is inconsistent with the file count");
        return ROMFS_PROVIDER_ERR_INDEX_LAYOUT;
    }
    RomfsProvider view;
    memset(&view, 0, sizeof(view));
    view.index = s->index;
    view.index_size = s->index_size;
    view.file_count = s->file_count;
    view.strings_offset = s->strings_offset;
    view.image_size = cfg->image_size;
    const char *previous = NULL;
    for (uint64_t i = 0; i < s->file_count; i++) {
        RomfsIndexRow row = index_row(&view, i);
        if (row.offset > cfg->image_size ||
            row.size > cfg->image_size - row.offset) {
            set_diag(diag, ROMFS_PROVIDER_ERR_INDEX_LAYOUT, stage,
                     "entry range exceeds the pinned image size");
            return ROMFS_PROVIDER_ERR_INDEX_LAYOUT;
        }
        size_t strings_bytes = size - (size_t)s->strings_offset;
        if (row.name_offset >= (uint64_t)strings_bytes ||
            row.name_len < 2 ||
            (uint64_t)row.name_len > (uint64_t)strings_bytes - row.name_offset) {
            set_diag(diag, ROMFS_PROVIDER_ERR_INDEX_LAYOUT, stage,
                     "entry name range exceeds the string table");
            return ROMFS_PROVIDER_ERR_INDEX_LAYOUT;
        }
        const char *name = entry_name(&view, row);
        if (name[row.name_len - 1] != '\0' ||
            memchr(name, '\0', row.name_len - 1) != NULL) {
            set_diag(diag, ROMFS_PROVIDER_ERR_INDEX_LAYOUT, stage,
                     "entry name is not exactly NUL terminated");
            return ROMFS_PROVIDER_ERR_INDEX_LAYOUT;
        }
        if (previous && strcmp(previous, name) >= 0) {
            set_diag(diag, ROMFS_PROVIDER_ERR_INDEX_LAYOUT, stage,
                     "entry names are not strictly increasing");
            return ROMFS_PROVIDER_ERR_INDEX_LAYOUT;
        }
        previous = name;
    }
    return ROMFS_PROVIDER_OK;
}

/* ---- image ----------------------------------------------------------- */

static romfs_provider_status open_image(const romfs_provider_config *cfg,
                                        RomfsProviderStage *s,
                                        const char *stage,
                                        romfs_provider_diag *diag,
                                        const uint8_t expected[32])
{
    char *path = romfs_host_join(cfg->resource_dir, "romfs.bin");
    if (!path) {
        set_diag(diag, ROMFS_PROVIDER_ERR_INVALID_ARGUMENT, stage,
                 "image path too long");
        return ROMFS_PROVIDER_ERR_INVALID_ARGUMENT;
    }
    romfs_host_status hs = ROMFS_HOST_OK;
    RomfsHostFile *mono = romfs_host_open_readonly(path, &hs);
    free(path);
    if (mono) {
        s->image = mono;
        if (romfs_host_size(mono) != cfg->image_size) {
            set_diag(diag, ROMFS_PROVIDER_ERR_IMAGE_SIZE, stage,
                     "romfs.bin size does not match the pinned image size");
            return ROMFS_PROVIDER_ERR_IMAGE_SIZE;
        }
    } else if (hs != ROMFS_HOST_ERR_OPEN_NOT_FOUND) {
        /* Only ABSENCE falls back to parts. A present-but-unusable romfs.bin
         * (directory, sharing/open refusal) is an error, never a reason to
         * silently read different files. */
        set_diag(diag, ROMFS_PROVIDER_ERR_IMAGE_OPEN, stage,
                 "romfs.bin exists but could not be opened");
        return ROMFS_PROVIDER_ERR_IMAGE_OPEN;
    } else {
        uint64_t total = 0;
        for (unsigned i = 0; i < ROMFS_PROVIDER_MAX_PARTS; i++) {
            char name[32];
            snprintf(name, sizeof(name), "romfs.bin.%03u", i);
            char *part_path = romfs_host_join(cfg->resource_dir, name);
            if (!part_path) {
                set_diag(diag, ROMFS_PROVIDER_ERR_INVALID_ARGUMENT, stage,
                         "part path too long");
                return ROMFS_PROVIDER_ERR_INVALID_ARGUMENT;
            }
            RomfsHostFile *part = romfs_host_open_readonly(part_path, &hs);
            free(part_path);
            if (!part) {
                if (hs != ROMFS_HOST_ERR_OPEN_NOT_FOUND) {
                    set_diag(diag, ROMFS_PROVIDER_ERR_IMAGE_OPEN, stage,
                             "RomFS part exists but could not be opened");
                    return ROMFS_PROVIDER_ERR_IMAGE_OPEN;
                }
                /* Stop at the first absent part, but a LATER existing part
                 * means the sequence has a hole: reject instead of serving a
                 * shorter image than the player has. */
                for (unsigned k = i + 1; k < ROMFS_PROVIDER_MAX_PARTS; k++) {
                    char later_name[32];
                    snprintf(later_name, sizeof(later_name),
                             "romfs.bin.%03u", k);
                    char *later_path =
                        romfs_host_join(cfg->resource_dir, later_name);
                    if (!later_path) {
                        set_diag(diag, ROMFS_PROVIDER_ERR_INVALID_ARGUMENT,
                                 stage, "part path too long");
                        return ROMFS_PROVIDER_ERR_INVALID_ARGUMENT;
                    }
                    romfs_host_status ls = ROMFS_HOST_OK;
                    RomfsHostFile *later =
                        romfs_host_open_readonly(later_path, &ls);
                    free(later_path);
                    if (later) {
                        romfs_host_close(later);
                        set_diag(diag, ROMFS_PROVIDER_ERR_IMAGE_PARTS, stage,
                                 "RomFS part sequence has a gap");
                        return ROMFS_PROVIDER_ERR_IMAGE_PARTS;
                    }
                    if (ls != ROMFS_HOST_ERR_OPEN_NOT_FOUND) {
                        set_diag(diag, ROMFS_PROVIDER_ERR_IMAGE_OPEN, stage,
                                 "a later RomFS part could not be opened");
                        return ROMFS_PROVIDER_ERR_IMAGE_OPEN;
                    }
                }
                break;
            }
            uint64_t part_size = romfs_host_size(part);
            if (part_size == 0) {
                romfs_host_close(part);
                set_diag(diag, ROMFS_PROVIDER_ERR_IMAGE_PARTS, stage,
                         "a RomFS part is empty");
                return ROMFS_PROVIDER_ERR_IMAGE_PARTS;
            }
            if (i == 0) s->part_size = part_size;
            /* Checked accumulation: the running total can never exceed the
             * pinned image size, so no part can push it over or wrap. */
            if (part_size > cfg->image_size - total) {
                romfs_host_close(part);
                set_diag(diag, ROMFS_PROVIDER_ERR_IMAGE_PARTS, stage,
                         "RomFS parts exceed the pinned image size");
                return ROMFS_PROVIDER_ERR_IMAGE_PARTS;
            }
            total += part_size;
            s->parts[i] = part;
            s->part_count = i + 1;
        }
        if (s->part_count == 0) {
            set_diag(diag, ROMFS_PROVIDER_ERR_IMAGE_OPEN, stage,
                     "RomFS image missing (romfs.bin or romfs.bin.000...)");
            return ROMFS_PROVIDER_ERR_IMAGE_OPEN;
        }
        if (s->part_count == ROMFS_PROVIDER_MAX_PARTS) {
            char extra_name[32];
            snprintf(extra_name, sizeof(extra_name), "romfs.bin.%03u",
                     ROMFS_PROVIDER_MAX_PARTS);
            char *extra_path = romfs_host_join(cfg->resource_dir, extra_name);
            if (!extra_path) {
                set_diag(diag, ROMFS_PROVIDER_ERR_INVALID_ARGUMENT, stage,
                         "part path too long");
                return ROMFS_PROVIDER_ERR_INVALID_ARGUMENT;
            }
            romfs_host_status es = ROMFS_HOST_OK;
            RomfsHostFile *extra = romfs_host_open_readonly(extra_path, &es);
            free(extra_path);
            if (extra) {
                romfs_host_close(extra);
                set_diag(diag, ROMFS_PROVIDER_ERR_IMAGE_PARTS, stage,
                         "more than 64 RomFS parts");
                return ROMFS_PROVIDER_ERR_IMAGE_PARTS;
            }
            if (es != ROMFS_HOST_ERR_OPEN_NOT_FOUND) {
                set_diag(diag, ROMFS_PROVIDER_ERR_IMAGE_OPEN, stage,
                         "a 65th RomFS part could not be opened");
                return ROMFS_PROVIDER_ERR_IMAGE_OPEN;
            }
        }
        /* Middle/last part sizes: every part except the last must equal
         * part_size exactly; the sum must equal the pinned image size. */
        for (unsigned i = 0; i + 1 < s->part_count; i++) {
            if (romfs_host_size(s->parts[i]) != s->part_size) {
                set_diag(diag, ROMFS_PROVIDER_ERR_IMAGE_PARTS, stage,
                         "RomFS parts must have equal sizes except the last");
                return ROMFS_PROVIDER_ERR_IMAGE_PARTS;
            }
        }
        if (romfs_host_size(s->parts[s->part_count - 1]) > s->part_size) {
            set_diag(diag, ROMFS_PROVIDER_ERR_IMAGE_PARTS, stage,
                     "the last RomFS part is larger than the first");
            return ROMFS_PROVIDER_ERR_IMAGE_PARTS;
        }
        if (total != cfg->image_size) {
            set_diag(diag, ROMFS_PROVIDER_ERR_IMAGE_PARTS, stage,
                     "RomFS parts do not add up to the pinned image size");
            return ROMFS_PROVIDER_ERR_IMAGE_PARTS;
        }
    }
    s->image_size = cfg->image_size;
    uint8_t digest[32];
    romfs_provider_status rs = hash_image(s, digest);
    if (rs == ROMFS_PROVIDER_ERR_ALLOCATION) {
        set_diag(diag, rs, stage, "hash buffer");
        return rs;
    }
    if (rs != ROMFS_PROVIDER_OK) {
        set_diag(diag, ROMFS_PROVIDER_ERR_IMAGE_READ, stage,
                 "short or failed image read while hashing");
        return ROMFS_PROVIDER_ERR_IMAGE_READ;
    }
    int image_digest_ok = memcmp(digest, expected, 32) == 0;
#ifdef MN_ROMFS_MUT_SKIP_IMAGE_HASH
    /* Test-only wrong implementation (D020 negative control). */
    image_digest_ok = 1;
#endif
    if (!image_digest_ok) {
        set_diag(diag, ROMFS_PROVIDER_ERR_IMAGE_DIGEST, stage,
                 "image SHA-256 does not match the pinned digest");
        return ROMFS_PROVIDER_ERR_IMAGE_DIGEST;
    }
    /* Mac re-stats the image after the full hash and refuses a changed file
     * (romfs.c:133-136). FILE_SHARE_READ already excludes ordinary writers,
     * but a writer that was granted access BEFORE init (sharing is reciprocal)
     * or a changed metadata identity must never be published as READY. */
    if (s->part_count) {
        for (unsigned i = 0; i < s->part_count; i++) {
            if (!romfs_host_identity_unchanged(s->parts[i])) {
                set_diag(diag, ROMFS_PROVIDER_ERR_IMAGE_CHANGED, stage,
                         "a RomFS part changed during verification");
                return ROMFS_PROVIDER_ERR_IMAGE_CHANGED;
            }
        }
    } else if (s->image && !romfs_host_identity_unchanged(s->image)) {
        set_diag(diag, ROMFS_PROVIDER_ERR_IMAGE_CHANGED, stage,
                 "the RomFS image changed during verification");
        return ROMFS_PROVIDER_ERR_IMAGE_CHANGED;
    }
    return ROMFS_PROVIDER_OK;
}

/* ---- overlays -------------------------------------------------------- */

typedef struct {
    uint64_t index;
    uint64_t size;
    uint8_t replacement[32];
    uint8_t original[32];
    char name[ROMFS_NAME_MAX_BYTES + 1];
    RomfsHostFile *file;
} RomfsManifestEntry;

static romfs_provider_status read_manifest(const char *root, char **out,
                                           size_t *out_size,
                                           romfs_provider_diag *diag,
                                           const char *stage)
{
    char *path = romfs_host_join(root, "manifest.tsv");
    if (!path) {
        set_diag(diag, ROMFS_PROVIDER_ERR_INVALID_ARGUMENT, stage,
                 "overlay manifest path too long");
        return ROMFS_PROVIDER_ERR_INVALID_ARGUMENT;
    }
    romfs_host_status hs = ROMFS_HOST_OK;
    RomfsHostFile *file = romfs_host_open_readonly(path, &hs);
    free(path);
    if (!file) {
        if (hs == ROMFS_HOST_ERR_OPEN_NOT_FOUND) {
            /* Only ABSENCE may be tolerated by an optional root. A manifest
             * that exists but cannot be opened (directory, sharing refusal,
             * allocation) is always an error. */
            set_diag(diag, ROMFS_PROVIDER_ERR_OVERLAY_REQUIRED, stage,
                     "overlay manifest.tsv missing");
            return ROMFS_PROVIDER_ERR_OVERLAY_REQUIRED;
        }
        set_diag(diag, ROMFS_PROVIDER_ERR_OVERLAY_MANIFEST, stage,
                 "overlay manifest.tsv exists but could not be opened");
        return ROMFS_PROVIDER_ERR_OVERLAY_MANIFEST;
    }
    /* Containment before any read, exactly like a replacement file: a manifest
     * that resolves outside the configured root (e.g. through a junction) must
     * not be parsed or hashed into the overlay set. */
    if (romfs_host_verify_under(file, root) != ROMFS_HOST_OK) {
        romfs_host_close(file);
        set_diag(diag, ROMFS_PROVIDER_ERR_OVERLAY_ESCAPE, stage,
                 "overlay manifest.tsv resolves outside its configured root");
        return ROMFS_PROVIDER_ERR_OVERLAY_ESCAPE;
    }
    uint64_t size = romfs_host_size(file);
    if (size > ROMFS_MANIFEST_MAX_BYTES) {
        romfs_host_close(file);
        set_diag(diag, ROMFS_PROVIDER_ERR_OVERLAY_MANIFEST, stage,
                 "overlay manifest is larger than 1 MiB");
        return ROMFS_PROVIDER_ERR_OVERLAY_MANIFEST;
    }
    /* Mac accepts an EMPTY (or blank/comment-only) manifest: zero overlays.
     * Only the size CAP is a contract. */
    char *buffer = (char *)malloc((size_t)size + 1u);
    if (!buffer) {
        romfs_host_close(file);
        set_diag(diag, ROMFS_PROVIDER_ERR_ALLOCATION, stage, "manifest buffer");
        return ROMFS_PROVIDER_ERR_ALLOCATION;
    }
    size_t got = 0;
    if (size) {
        hs = romfs_host_read_at(file, 0, buffer, (size_t)size, &got);
    }
    romfs_host_close(file);
    if (hs != ROMFS_HOST_OK || got != size) {
        free(buffer);
        set_diag(diag, ROMFS_PROVIDER_ERR_OVERLAY_MANIFEST, stage,
                 "overlay manifest short read");
        return ROMFS_PROVIDER_ERR_OVERLAY_MANIFEST;
    }
    /* A manifest is a text TSV. An embedded NUL would silently hide the rest
     * of the file from the line splitter, so reject it before any strlen() or
     * parser call rather than accepting a truncated prefix. */
    if (size != 0u && memchr(buffer, 0, (size_t)size) != NULL) {
        free(buffer);
        set_diag(diag, ROMFS_PROVIDER_ERR_OVERLAY_MANIFEST, stage,
                 "overlay manifest contains an embedded NUL");
        return ROMFS_PROVIDER_ERR_OVERLAY_MANIFEST;
    }
    buffer[size] = '\0';
    *out = buffer;
    *out_size = (size_t)size;
    return ROMFS_PROVIDER_OK;
}

/* Descending lower-bound over the sorted index (Mac `lower`). */
static uint64_t index_lower(const RomfsProvider *p, const char *name)
{
    uint64_t lo = 0, hi = p->file_count;
    while (lo < hi) {
        uint64_t mid = lo + (hi - lo) / 2;
        RomfsIndexRow row = index_row(p, mid);
        if (strcmp(entry_name(p, row), name) < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo;
}

static int hex_field_ok(const char *text, size_t len)
{
    if (len != 64) return 0;
    for (size_t i = 0; i < len; i++) {
        char c = text[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
    }
    return 1;
}

static romfs_provider_status parse_manifest_line(char *line,
                                                 RomfsManifestEntry *entry,
                                                 romfs_provider_diag *diag,
                                                 const char *stage)
{
    /* Trim CR/LF so a CRLF manifest parses like the Mac sscanf() path. */
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
        line[--len] = '\0';
    /* name \t size \t replacement-sha \t original-sha */
    char *fields[4];
    unsigned count = 0;
    char *at = line;
    while (count < 4) {
        fields[count++] = at;
        char *tab = strchr(at, '\t');
        if (!tab) break;
        *tab = '\0';
        at = tab + 1;
        if (count == 4) {
            /* A fifth field follows. The reference row is exactly four
             * fields; truncating the fourth and ignoring the rest would
             * accept a manifest the Mac reference would not. */
            set_diag(diag, ROMFS_PROVIDER_ERR_OVERLAY_MANIFEST, stage,
                     "overlay manifest line has more than four tab fields");
            return ROMFS_PROVIDER_ERR_OVERLAY_MANIFEST;
        }
    }
    if (count != 4) {
        set_diag(diag, ROMFS_PROVIDER_ERR_OVERLAY_MANIFEST, stage,
                 "overlay manifest line does not have four tab fields");
        return ROMFS_PROVIDER_ERR_OVERLAY_MANIFEST;
    }
    size_t name_len = strlen(fields[0]);
    if (name_len == 0 || name_len > ROMFS_NAME_MAX_BYTES) {
        set_diag(diag, ROMFS_PROVIDER_ERR_OVERLAY_MANIFEST, stage,
                 "overlay manifest name length");
        return ROMFS_PROVIDER_ERR_OVERLAY_MANIFEST;
    }
    memcpy(entry->name, fields[0], name_len + 1);
    if (!overlay_name_ok(entry->name)) {
        set_diag(diag, ROMFS_PROVIDER_ERR_OVERLAY_PATH, stage,
                 "overlay manifest names an unsafe path");
        return ROMFS_PROVIDER_ERR_OVERLAY_PATH;
    }
    /* size: decimal digits only (no sign, no overflow). */
    uint64_t size = 0;
    const char *digits = fields[1];
    if (!*digits) {
        set_diag(diag, ROMFS_PROVIDER_ERR_OVERLAY_MANIFEST, stage,
                 "overlay manifest size is empty");
        return ROMFS_PROVIDER_ERR_OVERLAY_MANIFEST;
    }
    for (const char *c = digits; *c; c++) {
        if (*c < '0' || *c > '9') {
            set_diag(diag, ROMFS_PROVIDER_ERR_OVERLAY_MANIFEST, stage,
                     "overlay manifest size is not decimal");
            return ROMFS_PROVIDER_ERR_OVERLAY_MANIFEST;
        }
        if (size > (UINT64_MAX - (uint64_t)(*c - '0')) / 10u) {
            set_diag(diag, ROMFS_PROVIDER_ERR_OVERLAY_MANIFEST, stage,
                     "overlay manifest size overflows");
            return ROMFS_PROVIDER_ERR_OVERLAY_MANIFEST;
        }
        size = size * 10u + (uint64_t)(*c - '0');
    }
    entry->size = size;
    if (!hex_field_ok(fields[2], strlen(fields[2])) ||
        !hex_field_ok(fields[3], strlen(fields[3]))) {
        set_diag(diag, ROMFS_PROVIDER_ERR_OVERLAY_MANIFEST, stage,
                 "overlay manifest hash field is not 64 lowercase hex");
        return ROMFS_PROVIDER_ERR_OVERLAY_MANIFEST;
    }
    (void)parse_sha256_hex(fields[2], entry->replacement);
    (void)parse_sha256_hex(fields[3], entry->original);
    return ROMFS_PROVIDER_OK;
}

static romfs_provider_status load_overlays(const romfs_provider_config *cfg,
                                           RomfsProviderStage *s,
                                           const char *stage,
                                           romfs_provider_diag *diag)
{
    RomfsProvider view;
    memset(&view, 0, sizeof(view));
    view.index = s->index;
    view.index_size = s->index_size;
    view.file_count = s->file_count;
    view.strings_offset = s->strings_offset;
    for (unsigned root = 0; root < cfg->overlay_root_count; root++) {
        char *manifest = NULL;
        size_t manifest_size = 0;
        romfs_provider_status rs = read_manifest(
            cfg->overlay_dirs[root], &manifest, &manifest_size, diag, stage);
        if (rs == ROMFS_PROVIDER_ERR_OVERLAY_REQUIRED) {
            if (cfg->overlay_required[root]) {
                /* Mac refuses a missing REQUIRED (profile) overlay. */
                set_diag(diag, ROMFS_PROVIDER_ERR_OVERLAY_REQUIRED, stage,
                         "required overlay manifest.tsv is missing");
                return ROMFS_PROVIDER_ERR_OVERLAY_REQUIRED;
            }
            continue; /* optional overlay root absent => originals */
        }
        if (rs != ROMFS_PROVIDER_OK) return rs;
        /* parse lines */
        size_t at = 0;
        while (at < manifest_size) {
            size_t end = at;
            while (end < manifest_size && manifest[end] != '\n') end++;
            size_t line_len = end - at;
            if (line_len >= ROMFS_MANIFEST_MAX_LINE) {
                free(manifest);
                set_diag(diag, ROMFS_PROVIDER_ERR_OVERLAY_MANIFEST, stage,
                         "overlay manifest line is longer than 8 KiB");
                return ROMFS_PROVIDER_ERR_OVERLAY_MANIFEST;
            }
            char line[ROMFS_MANIFEST_MAX_LINE];
            memcpy(line, manifest + at, line_len);
            line[line_len] = '\0';
            at = end + 1;
            if (line_len == 0 || line[0] == '#') continue;
            RomfsManifestEntry entry;
            memset(&entry, 0, sizeof(entry));
            rs = parse_manifest_line(line, &entry, diag, stage);
            if (rs != ROMFS_PROVIDER_OK) {
                free(manifest);
                return rs;
            }
            if (s->overlay_count >= ROMFS_PROVIDER_MAX_OVERLAYS) {
                free(manifest);
                set_diag(diag, ROMFS_PROVIDER_ERR_OVERLAY_MANIFEST, stage,
                         "more than 16 overlay replacements");
                return ROMFS_PROVIDER_ERR_OVERLAY_MANIFEST;
            }
            uint64_t found = index_lower(&view, entry.name);
            if (found >= s->file_count ||
                strcmp(entry_name(&view, index_row(&view, found)),
                       entry.name) != 0) {
                free(manifest);
                set_diag(diag, ROMFS_PROVIDER_ERR_OVERLAY_UNKNOWN, stage,
                         "overlay names a file the index lacks");
                return ROMFS_PROVIDER_ERR_OVERLAY_UNKNOWN;
            }
            for (unsigned k = 0; k < s->overlay_count; k++) {
                if (s->overlays[k].index == found) {
                    free(manifest);
                    set_diag(diag, ROMFS_PROVIDER_ERR_OVERLAY_DUPLICATE,
                             stage, "two overlays replace the same file");
                    return ROMFS_PROVIDER_ERR_OVERLAY_DUPLICATE;
                }
            }
            RomfsIndexRow row = index_row(&view, found);
            uint8_t digest[32];
            rs = hash_image_range(s, row.offset, row.size, digest);
            if (rs != ROMFS_PROVIDER_OK) {
                free(manifest);
                set_diag(diag, rs == ROMFS_PROVIDER_ERR_ALLOCATION
                                   ? rs
                                   : ROMFS_PROVIDER_ERR_OVERLAY_ORIGINAL,
                         stage, "could not hash the original range");
                return rs == ROMFS_PROVIDER_ERR_ALLOCATION
                           ? rs
                           : ROMFS_PROVIDER_ERR_OVERLAY_ORIGINAL;
            }
            if (memcmp(digest, entry.original, 32) != 0) {
                free(manifest);
                set_diag(diag, ROMFS_PROVIDER_ERR_OVERLAY_ORIGINAL, stage,
                         "original range SHA-256 does not match the manifest");
                return ROMFS_PROVIDER_ERR_OVERLAY_ORIGINAL;
            }
            char *file_path = romfs_host_join(cfg->overlay_dirs[root], entry.name);
            if (!file_path) {
                free(manifest);
                set_diag(diag, ROMFS_PROVIDER_ERR_OVERLAY_MANIFEST, stage,
                         "overlay file path too long");
                return ROMFS_PROVIDER_ERR_OVERLAY_MANIFEST;
            }
            romfs_host_status hs = ROMFS_HOST_OK;
            RomfsHostFile *file = romfs_host_open_readonly(file_path, &hs);
            free(file_path);
            if (!file) {
                set_diag(diag, ROMFS_PROVIDER_ERR_OVERLAY_MANIFEST, stage,
                         "overlay replacement file is missing");
                free(manifest);
                return ROMFS_PROVIDER_ERR_OVERLAY_MANIFEST;
            }
            if (romfs_host_verify_under(file, cfg->overlay_dirs[root]) !=
                ROMFS_HOST_OK) {
                romfs_host_close(file);
                free(manifest);
                set_diag(diag, ROMFS_PROVIDER_ERR_OVERLAY_ESCAPE, stage,
                         "overlay file resolves outside its configured root");
                return ROMFS_PROVIDER_ERR_OVERLAY_ESCAPE;
            }
            if (romfs_host_size(file) != entry.size) {
                romfs_host_close(file);
                free(manifest);
                set_diag(diag, ROMFS_PROVIDER_ERR_OVERLAY_REPLACEMENT, stage,
                         "overlay replacement size does not match the manifest");
                return ROMFS_PROVIDER_ERR_OVERLAY_REPLACEMENT;
            }
            uint8_t actual[32];
            rs = hash_host_file(file, entry.size, actual);
            if (rs != ROMFS_PROVIDER_OK) {
                romfs_host_close(file);
                free(manifest);
                set_diag(diag, ROMFS_PROVIDER_ERR_OVERLAY_REPLACEMENT, stage,
                         "could not hash the overlay replacement");
                return ROMFS_PROVIDER_ERR_OVERLAY_REPLACEMENT;
            }
            if (memcmp(actual, entry.replacement, 32) != 0) {
                romfs_host_close(file);
                free(manifest);
                set_diag(diag, ROMFS_PROVIDER_ERR_OVERLAY_REPLACEMENT, stage,
                         "replacement SHA-256 does not match the manifest");
                return ROMFS_PROVIDER_ERR_OVERLAY_REPLACEMENT;
            }
            s->overlays[s->overlay_count].index = found;
            s->overlays[s->overlay_count].size = entry.size;
            s->overlays[s->overlay_count].file = file;
            s->overlay_count++;
        }
        free(manifest);
    }
    return ROMFS_PROVIDER_OK;
}

/* ---- publish / lifecycle --------------------------------------------- */

RomfsProvider *romfs_provider_create(void)
{
    RomfsProvider *p = (RomfsProvider *)calloc(1, sizeof(*p));
    return p;
}

void romfs_provider_destroy(RomfsProvider *p)
{
    if (!p) return;
    RomfsProviderStage stage;
    memset(&stage, 0, sizeof(stage));
    stage.index = p->index;
    stage.image = p->image;
    memcpy(stage.parts, p->parts, sizeof(p->parts));
    stage.part_count = p->part_count;
    memcpy(stage.overlays, p->overlays, sizeof(p->overlays));
    stage.overlay_count = p->overlay_count;
    stage_release(&stage);
    memset(p, 0, sizeof(*p));
    free(p);
}

static void publish(RomfsProvider *p, RomfsProviderStage *s)
{
    memset(p, 0, sizeof(*p));
    p->ready = 1;
    p->index = s->index;
    p->index_size = s->index_size;
    p->file_count = s->file_count;
    p->strings_offset = s->strings_offset;
    p->image_size = s->image_size;
    p->image = s->image;
    memcpy(p->parts, s->parts, sizeof(p->parts));
    p->part_count = s->part_count;
    p->part_size = s->part_size;
    memcpy(p->overlays, s->overlays, sizeof(p->overlays));
    p->overlay_count = s->overlay_count;
    /* ownership moved */
    s->index = NULL;
    s->image = NULL;
    memset(s->parts, 0, sizeof(s->parts));
    s->part_count = 0;
    memset(s->overlays, 0, sizeof(s->overlays));
    s->overlay_count = 0;
}

romfs_provider_status romfs_provider_init(RomfsProvider *p,
                                          const romfs_provider_config *cfg,
                                          romfs_provider_diag *diag)
{
    if (diag) {
        diag->status = ROMFS_PROVIDER_OK;
        diag->stage = "none";
        diag->detail[0] = '\0';
    }
    if (!p || !cfg) {
        set_diag(diag, ROMFS_PROVIDER_ERR_INVALID_ARGUMENT, "arguments",
                 "provider/config is NULL");
        return ROMFS_PROVIDER_ERR_INVALID_ARGUMENT;
    }
    /* Idempotent: a READY provider keeps its verified snapshot untouched. */
    if (p->ready) {
        if (diag) {
            diag->status = ROMFS_PROVIDER_OK;
            diag->stage = "ready";
            diag->detail[0] = '\0';
        }
        return ROMFS_PROVIDER_OK;
    }
    if (!cfg->resource_dir || !*cfg->resource_dir ||
        cfg->overlay_root_count > ROMFS_PROVIDER_MAX_OVERLAY_ROOTS ||
        cfg->image_size == 0) {
        set_diag(diag, ROMFS_PROVIDER_ERR_INVALID_ARGUMENT, "arguments",
                 "resource dir/image size/overlay root count is invalid");
        return ROMFS_PROVIDER_ERR_INVALID_ARGUMENT;
    }
    uint8_t expected_index[32], expected_image[32];
    if (!parse_sha256_hex(cfg->index_sha256_hex, expected_index)) {
        set_diag(diag, ROMFS_PROVIDER_ERR_INVALID_ARGUMENT, "arguments",
                 "index digest is not 64 lowercase hex characters");
        return ROMFS_PROVIDER_ERR_INVALID_ARGUMENT;
    }
    if (!parse_sha256_hex(cfg->image_sha256_hex, expected_image)) {
        set_diag(diag, ROMFS_PROVIDER_ERR_INVALID_ARGUMENT, "arguments",
                 "image digest is not 64 lowercase hex characters");
        return ROMFS_PROVIDER_ERR_INVALID_ARGUMENT;
    }
    for (unsigned i = 0; i < cfg->overlay_root_count; i++) {
        if (!cfg->overlay_dirs[i] || !*cfg->overlay_dirs[i] ||
            cfg->overlay_required[i] > 1) {
            set_diag(diag, ROMFS_PROVIDER_ERR_INVALID_ARGUMENT, "arguments",
                     "overlay root is invalid");
            return ROMFS_PROVIDER_ERR_INVALID_ARGUMENT;
        }
    }

    RomfsProviderStage stage;
    memset(&stage, 0, sizeof(stage));
    romfs_provider_status rs;
    rs = load_index(cfg, &stage, "index-open", diag, expected_index);
    if (rs != ROMFS_PROVIDER_OK) goto fail;
    rs = validate_index(cfg, &stage, "index-layout", diag);
    if (rs != ROMFS_PROVIDER_OK) goto fail;
    rs = open_image(cfg, &stage, "image", diag, expected_image);
    if (rs != ROMFS_PROVIDER_OK) goto fail;
    rs = load_overlays(cfg, &stage, "overlay", diag);
    if (rs != ROMFS_PROVIDER_OK) goto fail;
    publish(p, &stage);
    if (diag) {
        diag->status = ROMFS_PROVIDER_OK;
        diag->stage = "ready";
        diag->detail[0] = '\0';
    }
    return ROMFS_PROVIDER_OK;

fail:
    stage_release(&stage);
    if (diag) diag->status = rs;
    return rs;
}

int romfs_provider_is_ready(const RomfsProvider *p)
{
    return p && p->ready;
}

uint64_t romfs_provider_file_count(const RomfsProvider *p)
{
    return p && p->ready ? p->file_count : 0;
}

romfs_provider_status romfs_provider_find(const RomfsProvider *p,
                                          const char *path,
                                          uint64_t *out_index)
{
    if (!p || !path || !out_index) return ROMFS_PROVIDER_ERR_INVALID_ARGUMENT;
    if (!p->ready) return ROMFS_PROVIDER_ERR_NOT_READY;
    uint64_t found = index_lower(p, path);
    if (found >= p->file_count ||
        strcmp(entry_name(p, index_row(p, found)), path) != 0)
        return ROMFS_PROVIDER_ERR_NOT_FOUND;
    *out_index = found;
    return ROMFS_PROVIDER_OK;
}

static int overlay_for(const RomfsProvider *p, uint64_t index, uint64_t *slot)
{
    for (unsigned i = 0; i < p->overlay_count; i++) {
        if (p->overlays[i].index == index) {
            if (slot) *slot = i;
            return 1;
        }
    }
    return 0;
}

romfs_provider_status romfs_provider_entry(const RomfsProvider *p,
                                           uint64_t index, uint64_t *out_offset,
                                           uint64_t *out_size,
                                           const char **out_name)
{
    if (!p) return ROMFS_PROVIDER_ERR_INVALID_ARGUMENT;
    if (!p->ready) return ROMFS_PROVIDER_ERR_NOT_READY;
    if (index >= p->file_count) return ROMFS_PROVIDER_ERR_INVALID_ARGUMENT;
    RomfsIndexRow row = index_row(p, index);
    if (out_offset) *out_offset = row.offset;
    if (out_size) *out_size = row.size;
    if (out_name) *out_name = entry_name(p, row);
    return ROMFS_PROVIDER_OK;
}

romfs_provider_status romfs_provider_effective_size(const RomfsProvider *p,
                                                    uint64_t index,
                                                    uint64_t *out_size)
{
    if (!p || !out_size) return ROMFS_PROVIDER_ERR_INVALID_ARGUMENT;
    if (!p->ready) return ROMFS_PROVIDER_ERR_NOT_READY;
    if (index >= p->file_count) return ROMFS_PROVIDER_ERR_INVALID_ARGUMENT;
    uint64_t slot = 0;
    if (overlay_for(p, index, &slot)) {
        *out_size = p->overlays[slot].size;
        return ROMFS_PROVIDER_OK;
    }
    *out_size = index_row(p, index).size;
    return ROMFS_PROVIDER_OK;
}

romfs_provider_status romfs_provider_is_overlaid(const RomfsProvider *p,
                                                 uint64_t index,
                                                 int *out_overlaid)
{
    if (!p || !out_overlaid) return ROMFS_PROVIDER_ERR_INVALID_ARGUMENT;
    if (!p->ready) return ROMFS_PROVIDER_ERR_NOT_READY;
    if (index >= p->file_count) return ROMFS_PROVIDER_ERR_INVALID_ARGUMENT;
    *out_overlaid = overlay_for(p, index, NULL);
    return ROMFS_PROVIDER_OK;
}

romfs_provider_status romfs_provider_read(RomfsProvider *p, uint64_t index,
                                          uint64_t offset, void *buffer,
                                          uint64_t size, uint64_t *out_read)
{
    if (out_read) *out_read = 0;
    if (!p || !p->ready) return ROMFS_PROVIDER_ERR_NOT_READY;
    if (index >= p->file_count || (!buffer && size))
        return ROMFS_PROVIDER_ERR_INVALID_ARGUMENT;
    uint64_t file_size = 0;
    romfs_provider_status rs =
        romfs_provider_effective_size(p, index, &file_size);
    if (rs != ROMFS_PROVIDER_OK) return rs;
    if (offset > file_size) return ROMFS_PROVIDER_ERR_RANGE;
    uint64_t n = size;
    if (n > file_size - offset) n = file_size - offset;
    if (n == 0) return ROMFS_PROVIDER_OK;
    uint64_t slot = 0;
    if (overlay_for(p, index, &slot)) {
        size_t got = 0;
        romfs_host_status hs = romfs_host_read_at(
            p->overlays[slot].file, offset, buffer, (size_t)n, &got);
        if (out_read) *out_read = got;
        if (hs != ROMFS_HOST_OK) return ROMFS_PROVIDER_ERR_READ;
        return ROMFS_PROVIDER_OK;
    }
    uint64_t got = 0;
    RomfsProviderStage view;
    memset(&view, 0, sizeof(view));
    view.image = p->image;
    memcpy(view.parts, p->parts, sizeof(view.parts));
    view.part_count = p->part_count;
    view.part_size = p->part_size;
    view.image_size = p->image_size;
    RomfsIndexRow row = index_row(p, index);
    rs = image_read_at(&view, row.offset + offset, buffer, n, &got);
    if (out_read) *out_read = got;
    /* Public status is uniform: the internal image-read code never escapes.
     * The actual prefix stays in *out_read and the destination holds that
     * prefix only, matching the overlay branch above. */
    return rs == ROMFS_PROVIDER_ERR_IMAGE_READ ? ROMFS_PROVIDER_ERR_READ : rs;
}
