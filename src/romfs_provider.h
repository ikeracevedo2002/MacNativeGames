/*
 * Immutable RomFS resource provider — Windows counterpart of the Mac
 * `runtime_fs_init` (games/totk/runtime/romfs.c:169-191).
 *
 * SCOPE (D020, early G4 prerequisite for the G3 constructor witness):
 *   - open, validate and RETAIN a fully verified read-only resource image and
 *     its parsed binary index;
 *   - validate and retain up to 16 overlay replacements from up to two caller
 *     supplied overlay roots;
 *   - expose a tiny HOST consumer seam (find/entry/effective-size/bounded read)
 *     proving the retained state works.
 *
 * OUT OF SCOPE: guest file handles, mounts, directory enumeration, save data,
 * IPC, account/settings, graphics/audio/input, proof-cache files, environment
 * inspection and any guest virtual address.
 *
 * Configuration is EXPLICIT. The caller supplies the resource directory, the
 * pinned expected image size and SHA-256, the pinned index SHA-256 and up to
 * two overlay roots with an optional/required policy. The provider never
 * inspects the environment and never derives an expected digest from candidate
 * bytes. Resolving a local profile belongs to boot tooling.
 *
 * Always FULL VERIFY: this is Mac's forced-full path. Mac's file-identity proof
 * cache records are neither trusted nor written here; that omits a startup
 * accelerator only, never an integrity or readiness guarantee. The optional
 * whole-image mmap read accelerator is likewise not implemented: reads are
 * bounded positional reads on retained host handles. See docs/romfs-provider.md
 * for the supported profile limits (including the defensive manifest cap).
 *
 * INIT IS TRANSACTIONAL. Every handle/table is staged privately; the provider
 * becomes READY only after all size/digest/layout/overlay checks succeed. On
 * any failure every staged handle is released, the caller-visible provider is
 * left EMPTY and a typed status plus the failing stage is reported. A later
 * init on a READY provider is idempotent (Mac's `image_fd>=0` guard) and never
 * changes its snapshot.
 *
 * THREADING: no concurrent init/destroy. After a successful init the provider
 * is immutable and bounded reads may be issued concurrently from several
 * threads; each call is an explicit-offset positional read, so results do not
 * depend on a shared file pointer (Win32 does update the handle's file pointer
 * as a side effect of a synchronous ReadFile with OVERLAPPED; nothing here
 * reads or relies on it) and no lock is taken.
 */
#ifndef MN_ROMFS_PROVIDER_H
#define MN_ROMFS_PROVIDER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* EXCLUSIVE bounds, matching Mac romfs.c's `st_size<128*1024*1024` and
 * `file_count<1000000` tests: an index of exactly 128 MiB or a count of exactly
 * 1,000,000 is rejected. ROMFS_PROVIDER_MAX_PARTS (64) and
 * ROMFS_PROVIDER_MAX_OVERLAYS (16) are inclusive capacities. */
#define ROMFS_PROVIDER_MAX_PARTS 64u
#define ROMFS_PROVIDER_MAX_OVERLAYS 16u
#define ROMFS_PROVIDER_MAX_OVERLAY_ROOTS 2u
#define ROMFS_PROVIDER_MAX_INDEX_BYTES (128u * 1024u * 1024u)
#define ROMFS_PROVIDER_MIN_INDEX_BYTES 24u
#define ROMFS_PROVIDER_MAX_FILES 1000000u

typedef struct RomfsProvider RomfsProvider;

typedef enum {
    ROMFS_PROVIDER_OK = 0,
    ROMFS_PROVIDER_ERR_INVALID_ARGUMENT = 1,
    ROMFS_PROVIDER_ERR_INDEX_OPEN = 2,
    ROMFS_PROVIDER_ERR_INDEX_SIZE = 3,
    ROMFS_PROVIDER_ERR_INDEX_DIGEST = 4,
    ROMFS_PROVIDER_ERR_INDEX_READ = 5,
    ROMFS_PROVIDER_ERR_INDEX_LAYOUT = 6, /* magic/header/rows/names/order */
    ROMFS_PROVIDER_ERR_IMAGE_OPEN = 7,
    ROMFS_PROVIDER_ERR_IMAGE_SIZE = 8,
    ROMFS_PROVIDER_ERR_IMAGE_PARTS = 9, /* gap, too many, unequal, empty */
    ROMFS_PROVIDER_ERR_IMAGE_DIGEST = 10,
    ROMFS_PROVIDER_ERR_IMAGE_READ = 11,
    ROMFS_PROVIDER_ERR_OVERLAY_REQUIRED = 12, /* required manifest absent */
    ROMFS_PROVIDER_ERR_OVERLAY_MANIFEST = 13, /* malformed line/file/count */
    ROMFS_PROVIDER_ERR_OVERLAY_PATH = 14,     /* unsafe Windows path */
    ROMFS_PROVIDER_ERR_OVERLAY_UNKNOWN = 15,  /* names an absent resource */
    ROMFS_PROVIDER_ERR_OVERLAY_DUPLICATE = 16,
    ROMFS_PROVIDER_ERR_OVERLAY_ORIGINAL = 17, /* original range mismatch */
    ROMFS_PROVIDER_ERR_OVERLAY_REPLACEMENT = 18,
    ROMFS_PROVIDER_ERR_OVERLAY_ESCAPE = 19,   /* left the overlay root */
    ROMFS_PROVIDER_ERR_NOT_READY = 20,
    ROMFS_PROVIDER_ERR_RANGE = 21,            /* offset beyond the file */
    ROMFS_PROVIDER_ERR_READ = 22,             /* host read failure */
    ROMFS_PROVIDER_ERR_NOT_FOUND = 23,
    ROMFS_PROVIDER_ERR_ALLOCATION = 24,
    ROMFS_PROVIDER_ERR_IMAGE_CHANGED = 25   /* identity/metadata moved */
} romfs_provider_status;

typedef struct {
    const char *resource_dir;        /* UTF-8; index + image or parts */
    const char *index_sha256_hex;    /* exactly 64 lowercase hex chars */
    uint64_t image_size;             /* pinned expected total image size */
    const char *image_sha256_hex;    /* exactly 64 lowercase hex chars */
    unsigned overlay_root_count;     /* 0..ROMFS_PROVIDER_MAX_OVERLAY_ROOTS */
    const char *overlay_dirs[ROMFS_PROVIDER_MAX_OVERLAY_ROOTS];
    unsigned overlay_required[ROMFS_PROVIDER_MAX_OVERLAY_ROOTS]; /* 0 or 1 */
} romfs_provider_config;

/* Diagnostics for the failing init call. `stage` is a stable short label;
 * `detail` is for humans and never carries expected/actual bytes. */
typedef struct {
    romfs_provider_status status;
    const char *stage;
    char detail[192];
} romfs_provider_diag;

/* Create an EMPTY provider (no handles, not ready). NULL on allocation
 * failure. The caller owns the returned object. */
RomfsProvider *romfs_provider_create(void);

/* Consume a provider: close every retained handle and free all owned memory.
 * After this the pointer must not be used; reuse means a fresh create. */
void romfs_provider_destroy(RomfsProvider *provider);

/* Transactionally initialize. On ROMFS_PROVIDER_OK the provider is READY. On
 * any other status it is EMPTY (unchanged if it was already READY — in that
 * case init is idempotent and returns OK without touching the snapshot). */
romfs_provider_status romfs_provider_init(RomfsProvider *provider,
                                         const romfs_provider_config *config,
                                         romfs_provider_diag *diag);

int romfs_provider_is_ready(const RomfsProvider *provider);

/* Number of index entries (0 when not ready). */
uint64_t romfs_provider_file_count(const RomfsProvider *provider);

/* Host-only path lookup. Paths use '/' separators and are matched exactly
 * against the sorted index names (no normalization, no Windows rewriting). */
romfs_provider_status romfs_provider_find(const RomfsProvider *provider,
                                          const char *path,
                                          uint64_t *out_index);

/* Original index metadata for one entry. `out_name` borrows provider-owned
 * storage valid until destroy(). */
romfs_provider_status romfs_provider_entry(const RomfsProvider *provider,
                                           uint64_t index, uint64_t *out_offset,
                                           uint64_t *out_size,
                                           const char **out_name);

/* Effective size served for the entry (overlay replacement size if any). */
romfs_provider_status romfs_provider_effective_size(const RomfsProvider *provider,
                                                    uint64_t index,
                                                    uint64_t *out_size);

/* Bounded positional read of effective bytes. Bytes are clamped to the end of
 * the file like the Mac backend, so a read at EOF yields *out_read == 0 and a
 * read crossing EOF yields the short prefix. offset > file size is
 * ROMFS_PROVIDER_ERR_RANGE. On ROMFS_PROVIDER_ERR_READ *out_read holds the
 * number of bytes actually read and the destination holds that prefix only. */
romfs_provider_status romfs_provider_read(RomfsProvider *provider,
                                          uint64_t index, uint64_t offset,
                                          void *buffer, uint64_t size,
                                          uint64_t *out_read);

/* True when the entry is served from an overlay replacement. */
romfs_provider_status romfs_provider_is_overlaid(const RomfsProvider *provider,
                                                 uint64_t index,
                                                 int *out_overlaid);

#ifdef __cplusplus
}
#endif

#endif /* MN_ROMFS_PROVIDER_H */
