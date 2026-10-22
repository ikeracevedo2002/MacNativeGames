/*
 * Win32 implementation of the RomFS provider's file/path seam (see
 * romfs_file_win.h). Deliberately small: open read-only with FILE_SHARE_READ,
 * size from the opened handle, positional reads, lexical join and canonical
 * final-path containment.
 *
 * The expected provider config is supplied by the caller. Nothing here reads
 * the environment, derives an expected hash from candidate bytes or writes a
 * proof cache record.
 */
#include "romfs_file_win.h"

#include <windows.h>

#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define ROMFS_HOST_PATH_CHARS 32767u /* Win32 extended-length path limit */

struct RomfsHostFile {
    HANDLE handle;
    uint64_t size;
    BY_HANDLE_FILE_INFORMATION info; /* identity/metadata at open time */
};

/* UTF-8 -> Win32 path in the extended-length form.
 *
 * GetFullPathNameW makes the path absolute and backslash-separated in a
 * bounded buffer; the result is then prefixed with \?\ (or \?\UNC\ for a
 * share), which is what lets a path beyond MAX_PATH (260) work instead of
 * being silently rejected or truncated. Nothing here normalizes the LOGICAL
 * resource names used by the index/overlay manifest. */
static wchar_t *utf8_to_wide(const char *utf8)
{
    if (!utf8 || !*utf8) return NULL;
    int need = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1,
                                   NULL, 0);
    if (need <= 0) return NULL;
    if ((unsigned)need > (unsigned)ROMFS_HOST_PATH_CHARS) return NULL;
    wchar_t *relative = (wchar_t *)malloc(sizeof(wchar_t) * (size_t)need);
    if (!relative) return NULL;
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1, relative,
                            need) != need) {
        free(relative);
        return NULL;
    }
    DWORD full_need = GetFullPathNameW(relative, 0, NULL, NULL);
    if (full_need == 0 || full_need > ROMFS_HOST_PATH_CHARS) {
        free(relative);
        return NULL;
    }
    wchar_t *full = (wchar_t *)malloc(sizeof(wchar_t) * (size_t)full_need);
    if (!full) {
        free(relative);
        return NULL;
    }
    DWORD written = GetFullPathNameW(relative, full_need, full, NULL);
    free(relative);
    if (written == 0 || written >= full_need) {
        free(full);
        return NULL;
    }
    int unc = full[0] == L'\\' && full[1] == L'\\';
    size_t len = wcslen(full);
    const wchar_t *extended_prefix = unc ? L"\\\\?\\UNC\\" : L"\\\\?\\";
    size_t prefix = unc ? 8u : 4u; /* \\?\UNC\ or \\?\ */
    const wchar_t *rest = unc ? full + 2 : full;
    if (len + prefix + 1u > ROMFS_HOST_PATH_CHARS) {
        free(full);
        return NULL;
    }
    wchar_t *out = (wchar_t *)malloc(sizeof(wchar_t) * (len + prefix + 1u));
    if (!out) {
        free(full);
        return NULL;
    }
    memcpy(out, extended_prefix, prefix * sizeof(wchar_t));
    memcpy(out + prefix, rest, (len + 1u - (unc ? 2u : 0u)) * sizeof(wchar_t));
    free(full);
    return out;
}

RomfsHostFile *romfs_host_open_readonly(const char *utf8_path,
                                       romfs_host_status *status)
{
    if (status) *status = ROMFS_HOST_ERR_INVALID_ARGUMENT;
    wchar_t *wide = utf8_to_wide(utf8_path);
    if (!wide) return NULL;
    /* FILE_SHARE_READ only: a live provider's verified bytes cannot be
     * replaced or deleted by ordinary Win32 opens after the checks. */
    HANDLE handle = CreateFileW(wide, GENERIC_READ, FILE_SHARE_READ, NULL,
                                OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS,
                                NULL);
    free(wide);
    if (handle == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (status) {
            *status = (err == ERROR_FILE_NOT_FOUND ||
                       err == ERROR_PATH_NOT_FOUND)
                          ? ROMFS_HOST_ERR_OPEN_NOT_FOUND
                          : ROMFS_HOST_ERR_OPEN_FAILED;
        }
        return NULL;
    }
    if (GetFileType(handle) != FILE_TYPE_DISK) {
        CloseHandle(handle);
        if (status) *status = ROMFS_HOST_ERR_NOT_REGULAR;
        return NULL;
    }
    BY_HANDLE_FILE_INFORMATION info;
    if (!GetFileInformationByHandle(handle, &info)) {
        CloseHandle(handle);
        if (status) *status = ROMFS_HOST_ERR_READ;
        return NULL;
    }
    if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        CloseHandle(handle);
        if (status) *status = ROMFS_HOST_ERR_NOT_REGULAR;
        return NULL;
    }
    RomfsHostFile *file = (RomfsHostFile *)malloc(sizeof(*file));
    if (!file) {
        CloseHandle(handle);
        if (status) *status = ROMFS_HOST_ERR_ALLOCATION;
        return NULL;
    }
    file->handle = handle;
    file->info = info;
    file->size = ((uint64_t)info.nFileSizeHigh << 32) | info.nFileSizeLow;
    if (status) *status = ROMFS_HOST_OK;
    return file;
}

int romfs_host_identity_unchanged(RomfsHostFile *file)
{
    if (!file) return 0;
    BY_HANDLE_FILE_INFORMATION now;
    if (!GetFileInformationByHandle(file->handle, &now)) return 0;
    if (now.dwVolumeSerialNumber != file->info.dwVolumeSerialNumber) return 0;
    if (now.nFileIndexHigh != file->info.nFileIndexHigh ||
        now.nFileIndexLow != file->info.nFileIndexLow)
        return 0;
    if (now.nFileSizeHigh != file->info.nFileSizeHigh ||
        now.nFileSizeLow != file->info.nFileSizeLow)
        return 0;
    if (now.ftLastWriteTime.dwHighDateTime !=
            file->info.ftLastWriteTime.dwHighDateTime ||
        now.ftLastWriteTime.dwLowDateTime !=
            file->info.ftLastWriteTime.dwLowDateTime)
        return 0;
    return 1;
}

uint64_t romfs_host_size(const RomfsHostFile *file)
{
    return file ? file->size : 0;
}

romfs_host_status romfs_host_read_at(RomfsHostFile *file, uint64_t offset,
                                     void *destination, size_t n,
                                     size_t *out_read)
{
    if (out_read) *out_read = 0;
    if (!file || (!destination && n)) return ROMFS_HOST_ERR_INVALID_ARGUMENT;
    /* Range guard by subtraction against the size recorded at open time: the
     * requested range can never wrap or run past EOF, and a request that does
     * exceed EOF is answered with the available prefix plus SHORT_READ. */
    uint64_t available = offset < file->size ? file->size - offset : 0;
    int short_request = 0;
    size_t want_total = n;
    if ((uint64_t)want_total > available) {
        want_total = (size_t)available;
        short_request = 1;
    }
    if (want_total == 0)
        return n == 0 ? ROMFS_HOST_OK : ROMFS_HOST_ERR_SHORT_READ;
    size_t done = 0;
    while (done < want_total) {
        uint64_t at = offset + (uint64_t)done;
        OVERLAPPED overlapped;
        memset(&overlapped, 0, sizeof(overlapped));
        overlapped.Offset = (DWORD)(at & 0xffffffffu);
        overlapped.OffsetHigh = (DWORD)(at >> 32);
        DWORD got = 0;
        size_t want = want_total - done;
        DWORD request = want > 0x10000000u ? 0x10000000u : (DWORD)want;
        if (!ReadFile(file->handle, (unsigned char *)destination + done,
                      request, &got, &overlapped)) {
            DWORD err = GetLastError();
            if (out_read) *out_read = done;
            if (err == ERROR_HANDLE_EOF) return ROMFS_HOST_ERR_SHORT_READ;
            return ROMFS_HOST_ERR_READ;
        }
        if (got == 0) {
            if (out_read) *out_read = done;
            return ROMFS_HOST_ERR_SHORT_READ;
        }
        done += got;
    }
    if (out_read) *out_read = done;
    return short_request ? ROMFS_HOST_ERR_SHORT_READ : ROMFS_HOST_OK;
}

void romfs_host_close(RomfsHostFile *file)
{
    if (!file) return;
    CloseHandle(file->handle);
    free(file);
}

char *romfs_host_join(const char *utf8_dir, const char *relative_name)
{
    if (!utf8_dir || !*utf8_dir || !relative_name || !*relative_name) return NULL;
    size_t dir_len = strlen(utf8_dir);
    size_t name_len = strlen(relative_name);
    int needs_slash = utf8_dir[dir_len - 1] != '/' && utf8_dir[dir_len - 1] != '\\';
    size_t total = dir_len + (size_t)needs_slash + name_len + 1;
    if (total >= 32767u) return NULL;
    char *out = (char *)malloc(total);
    if (!out) return NULL;
    memcpy(out, utf8_dir, dir_len);
    size_t at = dir_len;
    if (needs_slash) out[at++] = '/';
    memcpy(out + at, relative_name, name_len);
    out[at + name_len] = '\0';
    return out;
}

/* Canonical (final, reparse-resolved) path of an already opened handle. */
static wchar_t *final_path_of(HANDLE handle)
{
    /* GetFinalPathNameByHandleW returns the required capacity INCLUDING the
     * terminating NUL when the buffer is too small, so the second call passes
     * `needed + 1` and any `written >= needed + 1` means the result did not
     * fit. Text from a partially filled buffer is never used. */
    DWORD needed = GetFinalPathNameByHandleW(handle, NULL, 0,
                                             FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (needed == 0 || needed > 32000u) return NULL;
    DWORD capacity = needed + 1u;
    wchar_t *buffer = (wchar_t *)malloc(sizeof(wchar_t) * (size_t)capacity);
    if (!buffer) return NULL;
    DWORD written = GetFinalPathNameByHandleW(handle, buffer, capacity,
                                              FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (written == 0 || written >= capacity) {
        free(buffer);
        return NULL;
    }
    buffer[written] = L'\0';
    /* Drop the \\?\ prefix so both sides compare in the same spelling.
     * \\?\UNC\server\share becomes \\server\share. */
    wchar_t *result = buffer;
    if (wcsncmp(result, L"\\\\?\\", 4) == 0) {
        if (wcsncmp(result + 4, L"UNC\\", 4) == 0) {
            result += 6;
            result[0] = L'\\';
            result[1] = L'\\';
        } else {
            result += 4;
        }
    }
    wchar_t *copy = _wcsdup(result);
    free(buffer);
    return copy;
}

static wchar_t *final_path_of_directory(const char *utf8_root)
{
    wchar_t *wide = utf8_to_wide(utf8_root);
    if (!wide) return NULL;
    HANDLE handle = CreateFileW(wide, 0,
                                FILE_SHARE_READ | FILE_SHARE_WRITE |
                                    FILE_SHARE_DELETE,
                                NULL, OPEN_EXISTING,
                                FILE_FLAG_BACKUP_SEMANTICS, NULL);
    free(wide);
    if (handle == INVALID_HANDLE_VALUE) return NULL;
    BY_HANDLE_FILE_INFORMATION info;
    int is_directory = 0;
    if (GetFileInformationByHandle(handle, &info))
        is_directory = (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    wchar_t *path = is_directory ? final_path_of(handle) : NULL;
    CloseHandle(handle);
    return path;
}

romfs_host_status romfs_host_verify_under(RomfsHostFile *file,
                                          const char *utf8_root)
{
    if (!file || !utf8_root || !*utf8_root) return ROMFS_HOST_ERR_INVALID_ARGUMENT;
    wchar_t *file_path = final_path_of(file->handle);
    wchar_t *root_path = final_path_of_directory(utf8_root);
    romfs_host_status result = ROMFS_HOST_ERR_PATH_ESCAPE;
    if (file_path && root_path) {
        size_t root_len = wcslen(root_path);
        while (root_len > 0 && (root_path[root_len - 1] == L'\\' ||
                                root_path[root_len - 1] == L'/')) {
            root_path[--root_len] = L'\0';
        }
        /* Final paths may differ from the configured spelling only by case on
         * a normal Windows volume, so the prefix compare is ORDINAL
         * case-insensitive (never locale-aware) and requires a path-component
         * boundary. Logical index names are never normalized. */
        size_t file_len = wcslen(file_path);
        /* A STRICT descendant needs a longer path than the root. Checking the
         * length first keeps the fixed-size ordinal compare (and the
         * component-boundary index below) inside the shorter escaped target
         * buffer instead of reading past its terminator. */
        if (file_len > root_len &&
            CompareStringOrdinal(file_path, (int)root_len, root_path,
                                 (int)root_len, TRUE) == CSTR_EQUAL) {
            wchar_t edge = file_path[root_len];
            if (edge == L'\\' || edge == L'/')
                result = ROMFS_HOST_OK;
        }
    }
    free(file_path);
    free(root_path);
    return result;
}
