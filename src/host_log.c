/* Windows x64 host logger backend.
 *
 * Owns only the sink (<stdio.h>), a Windows SRWLOCK and the record
 * formatting. See host_log.h for the contract and the reentrancy note.
 *
 * The whole record is formatted into stack storage first, then written under
 * the lock in one fwrite, and flushed in the same locked step. The SRWLOCK
 * covers the write+flush and the error attribution as one operation: fwrite
 * itself also serialises on the CRT stream lock, but the outer lock is what
 * stops one caller's record from being interleaved with another caller's
 * flush/error handling. That is what makes records from different threads
 * atomic within one process using one handle.
 *
 * A record is one line: over the written length, embedded CR, LF and NUL
 * bytes in the formatted output are normalised to spaces, so a caller cannot
 * forge a record boundary and an embedded NUL (for example `%c` with 0)
 * cannot silently cut the record.
 *
 * IO is NOT transactional: if the sink fails partway through a record, the
 * stream can hold a partial record and `HOST_LOG_ERR_IO` is returned. See
 * host_log.h; the caller must treat a failed stream as unusable.
 *
 * Buffering is deliberately NOT changed: setvbuf is never called on the
 * sink. Touching the buffering of a caller-supplied stream (in particular
 * stderr) after the caller may already have performed I/O would be a
 * process-global side effect this module must not have. Instead the lock
 * covers an explicit fflush, so a logging call that returns OK has already
 * handed the record to the OS.
 */

#include "host_log.h"

#if !defined(_WIN32)
#  error "host_log.c is the Windows x64 backend; the Mac path keeps its own logs."
#endif

#include <windows.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

/* Message body limit (without the `...<truncated>` marker or newline). The
 * record buffer is sized so a truncated record always fits. */
#define HOST_LOG_MESSAGE_MAX 1500
#define HOST_LOG_RECORD_MAX 1600

struct host_log {
    FILE *sink;
    int owns_sink;
    host_log_level min_level;
    SRWLOCK lock;
};

static const char *level_name(host_log_level level)
{
    switch (level) {
    case HOST_LOG_LEVEL_TRACE:
        return "TRACE";
    case HOST_LOG_LEVEL_DEBUG:
        return "DEBUG";
    case HOST_LOG_LEVEL_INFO:
        return "INFO";
    case HOST_LOG_LEVEL_WARN:
        return "WARN";
    case HOST_LOG_LEVEL_ERROR:
        return "ERROR";
    default:
        return "UNKNOWN";
    }
}

static int level_valid(host_log_level level)
{
    return (int)level >= (int)HOST_LOG_LEVEL_TRACE &&
           (int)level <= (int)HOST_LOG_LEVEL_ERROR;
}

host_log_result host_log_open(const host_log_options *options,
                              host_log **out_log)
{
    host_log *log;

    if (options == NULL || out_log == NULL) {
        return HOST_LOG_ERR_INVALID_ARGUMENT;
    }
    if (!level_valid(options->min_level)) {
        return HOST_LOG_ERR_INVALID_ARGUMENT;
    }

    log = (host_log *)calloc(1, sizeof(*log));
    if (log == NULL) {
        return HOST_LOG_ERR_ALLOCATION;
    }

    if (options->path != NULL) {
        errno_t open_error = fopen_s(&log->sink, options->path, "wb");
        if (open_error != 0 || log->sink == NULL) {
            free(log);
            return HOST_LOG_ERR_OPEN;
        }
        log->owns_sink = 1;
    } else {
        log->sink = stderr;
        log->owns_sink = 0;
    }

    /* Buffering of the sink is intentionally left untouched: see the file
     * header. host_log_write() flushes under its lock. */
    log->min_level = options->min_level;
    InitializeSRWLock(&log->lock);

    *out_log = log;
    return HOST_LOG_OK;
}

host_log_result host_log_close(host_log *log)
{
    host_log_result result = HOST_LOG_OK;

    if (log == NULL) {
        return HOST_LOG_OK;
    }

    /* The caller guarantees quiescence; the lock is taken only so an
     * in-flight write cannot race the close. The handle is consumed even if
     * the sink reports an error. */
    AcquireSRWLockExclusive(&log->lock);
    if (log->sink != NULL) {
        if (fflush(log->sink) != 0) {
            result = HOST_LOG_ERR_IO;
        }
        if (log->owns_sink) {
            if (fclose(log->sink) != 0) {
                result = HOST_LOG_ERR_IO;
            }
        }
    }
    ReleaseSRWLockExclusive(&log->lock);
    free(log);
    return result;
}

host_log_result host_log_write(host_log *log, host_log_level level,
                               const char *format, ...)
{
    char message[HOST_LOG_MESSAGE_MAX];
    char record[HOST_LOG_RECORD_MAX];
    va_list args;
    int would;
    int truncated;
    int prefix;
    int written;
    size_t length;
    host_log_result result = HOST_LOG_OK;

    if (log == NULL || format == NULL) {
        return HOST_LOG_ERR_INVALID_ARGUMENT;
    }
    if (!level_valid(level)) {
        return HOST_LOG_ERR_INVALID_ARGUMENT;
    }
    if ((int)level < (int)log->min_level) {
        return HOST_LOG_SKIPPED;
    }

    va_start(args, format);
    would = vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    if (would < 0) {
        return HOST_LOG_ERR_FORMAT;
    }
    /* One record is one line: over the WRITTEN length, normalise embedded
     * CR, LF and NUL to spaces. A `%c` of zero writes an embedded NUL that
     * would otherwise truncate the record at `%s`; normalising it keeps the
     * whole formatted message and stops a caller forging a record boundary. */
    {
        size_t i;
        size_t span = ((size_t)would < sizeof(message)) ? (size_t)would
                                                        : sizeof(message) - 1;
        for (i = 0; i < span; i++) {
            char ch = message[i];
            if (ch == '\r' || ch == '\n' || ch == '\0') {
                message[i] = ' ';
            }
        }
        message[span] = '\0';
    }
    truncated = ((size_t)would >= sizeof(message));

    prefix = snprintf(record, sizeof(record), "[%s] tid=0x%08lx ",
                      level_name(level), (unsigned long)GetCurrentThreadId());
    if (prefix < 0 || (size_t)prefix >= sizeof(record)) {
        return HOST_LOG_ERR_FORMAT;
    }

    if (truncated) {
        written = snprintf(record + prefix, sizeof(record) - (size_t)prefix,
                           "%s...<truncated>\n", message);
        result = HOST_LOG_ERR_TRUNCATED;
    } else {
        written = snprintf(record + prefix, sizeof(record) - (size_t)prefix,
                           "%s\n", message);
    }
    if (written < 0 || (size_t)written >= sizeof(record) - (size_t)prefix) {
        /* Cannot happen with the buffer sizes above; report rather than
         * emit a half record. */
        return HOST_LOG_ERR_FORMAT;
    }
    length = (size_t)prefix + (size_t)written;

    AcquireSRWLockExclusive(&log->lock);
    if (fwrite(record, 1, length, log->sink) != length ||
        fflush(log->sink) != 0 || ferror(log->sink)) {
        clearerr(log->sink);
        result = HOST_LOG_ERR_IO;
    }
    ReleaseSRWLockExclusive(&log->lock);

    return result;
}

host_log_result host_log_flush(host_log *log)
{
    int failed;

    if (log == NULL) {
        return HOST_LOG_ERR_INVALID_ARGUMENT;
    }

    AcquireSRWLockExclusive(&log->lock);
    failed = fflush(log->sink) != 0 || ferror(log->sink);
    if (ferror(log->sink)) {
        clearerr(log->sink);
    }
    ReleaseSRWLockExclusive(&log->lock);

    return failed ? HOST_LOG_ERR_IO : HOST_LOG_OK;
}
