/* Host core logging abstraction (G1 logging row).
 *
 * Scope: a small, self-contained host logger that produces one whole record
 * per call and is safe to call from several host threads at once. It is
 * testable without any game data. It is NOT a guest diagnostic service, has
 * no guest handle, and does not replace the Mac runtime's stderr diagnostics.
 *
 * What this module deliberately does not do (out of the G1 contract):
 *
 *   - no timestamps, no rotation, no severity-side effects, no callbacks;
 *   - no global logger singleton: the caller owns an explicit handle, so the
 *     lifecycle is local and there is no init/shutdown race on shared state;
 *   - no automatic release of the sink beyond close().
 *
 * Record contract:
 *
 *   - A record is `[LEVEL] tid=0x<8 hex digits> <message>` plus a newline.
 *   - Embedded CR/LF and NUL in `message` are normalised to spaces over the
 *     written length, so one call always produces exactly one line and a
 *     caller cannot forge a record boundary or silently cut the record at an
 *     embedded NUL (for example `%c` with 0).
 *   - The whole record is formatted into caller-local storage first and then
 *     written in one locked step, so records from different threads are not
 *     interleaved within one process using one handle.
 *   - IO is NOT transactional. If the sink fails partway through a record,
 *     the stream can hold a partial record and HOST_LOG_ERR_IO is returned;
 *     the caller must treat the stream as unusable, abandon the handle, and
 *     open a NEW sink path if the previous output must be preserved
 *     (reopening the same `"wb"` path would truncate it).
 *   - A message that does not fit is truncated, marked with `...<truncated>`,
 *     terminated with a newline and reported as HOST_LOG_ERR_TRUNCATED. The
 *     message is never silently cut and never left unterminated.
 *   - Level filtering is applied before formatting; a filtered record writes
 *     nothing and returns HOST_LOG_SKIPPED.
 *
 * Reentrancy:
 *
 *   - There are no callbacks, and no user code runs while the internal lock
 *     is held: the lock only surrounds the sink write. A caller can therefore
 *     log from any thread without re-entering this module, and a future
 *     callback sink would have to be added outside the lock.
 *
 * Error handling is explicit: every entry point reports a host_log_result.
 * `host_log_write(NULL, ...)` is HOST_LOG_ERR_INVALID_ARGUMENT; using a handle
 * after host_log_close() is undefined (the handle is freed).
 *
 * Backend: a narrow <stdio.h> + Windows SRWLOCK implementation in
 * src/host_log.c. This header is deliberately free of <windows.h>.
 */

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum host_log_level {
    HOST_LOG_LEVEL_TRACE = 0,
    HOST_LOG_LEVEL_DEBUG = 1,
    HOST_LOG_LEVEL_INFO = 2,
    HOST_LOG_LEVEL_WARN = 3,
    HOST_LOG_LEVEL_ERROR = 4
} host_log_level;

typedef enum host_log_result {
    /* The record was written whole. */
    HOST_LOG_OK = 0,
    /* The record was filtered out by the minimum level; nothing was written.
     * This is not an error. */
    HOST_LOG_SKIPPED = 1,
    /* A mandatory argument was NULL or a level was outside its range. */
    HOST_LOG_ERR_INVALID_ARGUMENT = 2,
    /* The sink could not be opened. open() left *out_log untouched. */
    HOST_LOG_ERR_OPEN = 3,
    /* The sink reported a write/flush failure. IO is NOT transactional: the
     * sink may hold a partial record. The caller must treat the stream as
     * unusable (abandon the handle; open a NEW path if the prior output must
     * be preserved) and must not rely on whole records after this result. */
    HOST_LOG_ERR_IO = 4,
    /* The record was written but the message did not fit and was truncated
     * with an explicit marker. */
    HOST_LOG_ERR_TRUNCATED = 5,
    /* Message formatting failed. Nothing was written. */
    HOST_LOG_ERR_FORMAT = 6,
    /* open() could not allocate the logger object. *out_log is untouched. */
    HOST_LOG_ERR_ALLOCATION = 7
} host_log_result;

/* Opaque logger handle; owned by the caller and freed by host_log_close(). */
typedef struct host_log host_log;

typedef struct host_log_options {
    /* NULL selects stderr (not closed by close()). Otherwise the file is
     * created or truncated and is closed by close(). */
    const char *path;
    /* Records below this level are skipped. Must be a valid host_log_level. */
    host_log_level min_level;
} host_log_options;

/* Open a logger. `options` and `out_log` must be non-NULL.
 *
 * On success *out_log owns a logger and returns HOST_LOG_OK. On failure
 * *out_log is left untouched. */
host_log_result host_log_open(const host_log_options *options,
                              host_log **out_log);

/* Close and free a logger. `log == NULL` is a documented no-op that returns
 * HOST_LOG_OK. After close() the handle is consumed and must not be used
 * again. The caller must have reached quiescence: no other thread is inside
 * host_log_write()/host_log_flush().
 *
 * close() flushes and (for an owned file sink) closes the sink, then frees
 * the logger object even if the sink reported an error, so the handle is
 * ALWAYS consumed. It returns HOST_LOG_ERR_IO when the flush or close
 * reported a sink error and HOST_LOG_OK otherwise; the result describes the
 * sink, not the handle, which is gone either way. */
host_log_result host_log_close(host_log *log);

/* Write one atomic record at `level`.
 *
 * `log` and `format` must be non-NULL. `format` is a printf-style format and
 * is followed by its arguments. Returns HOST_LOG_SKIPPED when filtered,
 * HOST_LOG_ERR_TRUNCATED when the record was written truncated, HOST_LOG_OK
 * when written whole, or an error. */
host_log_result host_log_write(host_log *log, host_log_level level,
                               const char *format, ...);

/* Flush the sink. Returns HOST_LOG_ERR_IO if the sink reported an error. */
host_log_result host_log_flush(host_log *log);

#ifdef __cplusplus
}
#endif
