/*
 * Private Win32 file/path seam for the immutable RomFS provider (D020).
 *
 * This header is the ONLY place where the provider meets Win32 file and path
 * primitives. `src/romfs_provider.h` stays Windows-free; the shared parsing /
 * integrity / state logic in `src/romfs_provider.c` uses only this narrow
 * interface, so no `#ifdef _WIN32` leaks into provider logic.
 *
 * Lifetime: every RomfsHostFile is an owning handle that must be released with
 * romfs_host_close(). Handles are opened read-only with FILE_SHARE_READ only,
 * so after verification normal Win32 opens for write/delete are denied for as
 * long as the provider retains the handle.
 *
 * Concurrency: read_at() is safe from several threads on distinct handles and
 * offsets (positional reads, no shared file pointer). One handle is never used
 * by two threads through this module at the same time by design; the provider
 * documents its own read/lifetime rule.
 */
#ifndef MN_ROMFS_FILE_WIN_H
#define MN_ROMFS_FILE_WIN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct RomfsHostFile RomfsHostFile;

typedef enum {
    ROMFS_HOST_OK = 0,
    ROMFS_HOST_ERR_OPEN_NOT_FOUND = 1, /* path does not exist / not openable */
    ROMFS_HOST_ERR_NOT_REGULAR = 2,    /* directory, device or other non-file */
    ROMFS_HOST_ERR_READ = 3,           /* ReadFile failed */
    ROMFS_HOST_ERR_SHORT_READ = 4,     /* fewer bytes than requested */
    ROMFS_HOST_ERR_PATH_ESCAPE = 5,    /* final path outside the root */
    ROMFS_HOST_ERR_INVALID_ARGUMENT = 6,
    ROMFS_HOST_ERR_ALLOCATION = 7,
    ROMFS_HOST_ERR_OPEN_FAILED = 8    /* exists but could not be opened */
} romfs_host_status;

/* Open an existing regular file read-only. Returns NULL on failure and writes
 * the reason to *status (NULL status is allowed). A directory is rejected. */
RomfsHostFile *romfs_host_open_readonly(const char *utf8_path,
                                       romfs_host_status *status);

/* Size recorded when the handle was opened (regular files only). */
uint64_t romfs_host_size(const RomfsHostFile *file);

/* Positional read of exactly `n` bytes at `offset`. On success *out_read == n.
 * A shorter read (including EOF) is ROMFS_HOST_ERR_SHORT_READ with *out_read
 * holding the number of bytes actually read; the caller-visible destination
 * then contains that prefix only. No bytes beyond *out_read are promised. */
romfs_host_status romfs_host_read_at(RomfsHostFile *file, uint64_t offset,
                                     void *destination, size_t n,
                                     size_t *out_read);

void romfs_host_close(RomfsHostFile *file);

/* Identity/metadata check against the state recorded when the handle was
 * opened: volume serial, file index, size and last-write time must be
 * unchanged. Returns 1 when unchanged, 0 when changed or unqueryable. This is
 * Mac's before/after stat comparison (romfs.c:133-136) in the form this seam
 * can offer: it can only observe the file this handle already refers to. */
int romfs_host_identity_unchanged(RomfsHostFile *file);

/* Join a UTF-8 directory and a relative ASCII/UTF-8 name with '/'. Returns a
 * heap string (caller frees) or NULL when the result would overflow a
 * 32 KiB UTF-16 Windows path or the parts are empty. This is a lexical join
 * only: containment is proven separately by romfs_host_verify_under(). */
char *romfs_host_join(const char *utf8_dir, const char *relative_name);

/* Prove the opened file still resolves beneath `utf8_root`: compares the
 * canonical final path of the file handle with the canonical final path of the
 * root directory, so a reparse point/junction inside the root cannot redirect
 * a validated name outside it. Case-insensitive, component-boundary aware. */
romfs_host_status romfs_host_verify_under(RomfsHostFile *file,
                                          const char *utf8_root);

#ifdef __cplusplus
}
#endif

#endif /* MN_ROMFS_FILE_WIN_H */
