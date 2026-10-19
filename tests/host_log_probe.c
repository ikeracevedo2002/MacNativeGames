/* Host core logging probe (G1 logging row).
 *
 * The real logger from src/host_log.c is driven end to end without any game
 * data:
 *   - open/write/flush/close and the record's shape;
 *   - level filtering (a filtered record writes nothing);
 *   - explicit truncation (marker + still one terminated record);
 *   - argument and open-failure handling;
 *   - many threads writing to one handle, then a full record-stream check.
 *
 * The stream checker is the same one used positively (the real output must
 * pass) and negatively: synthetic corrupted streams that model realistic
 * wrong behaviour (records interleaved without a lock, an unterminated final
 * record, a missing record, a duplicated record, a malformed prefix) must be
 * rejected. That is what proves the atomicity/format checks are sensitive:
 * a checker that accepted everything would pass the real output but also
 * accept the corrupted streams, and the probe would fail.
 *
 * The real HOST_LOG_ERR_IO branch is forced through a genuine OS resource,
 * not a test hook: the fixture temporarily points the process's stderr file
 * descriptor at a pipe whose reader end is closed, so a write to a path==NULL
 * logger must fail. stderr is restored before any result is reported.
 *
 * Synchronisation: writer threads are joined with bounded waits. There is no
 * sleep-based sequencing. Exit status is the result; no
 * PASS_REGULAR_EXPRESSION, no WILL_FAIL, no assert().
 */

#include "host_log.h"

#include <windows.h>

#include <fcntl.h>
#include <io.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_PROBE_WAIT_MS 30000u
#define LOG_PROBE_WRITERS 4
#define LOG_PROBE_RECORDS_PER_WRITER 200
#define LOG_PROBE_TOKEN_DOMAIN \
    (LOG_PROBE_WRITERS * LOG_PROBE_RECORDS_PER_WRITER)

static int g_failures;

static void fail(const char *what)
{
    g_failures++;
    fprintf(stderr, "[log-probe] FAIL: %s\n", what);
}

static void expect_result(host_log_result got, host_log_result want,
                          const char *what)
{
    if (got != want) {
        g_failures++;
        fprintf(stderr, "[log-probe] FAIL: %s returned %d, want %d\n", what,
                (int)got, (int)want);
    }
}

static void make_temp_path(char *out, size_t cap, const char *tag)
{
    char dir[MAX_PATH];
    DWORD length = GetTempPathA(MAX_PATH, dir);

    if (length == 0 || length >= MAX_PATH) {
        fprintf(stderr, "FATAL: GetTempPathA failed\n");
        ExitProcess(1);
    }
    _snprintf_s(out, cap, _TRUNCATE, "%smn_host_log_%s_%lu.log", dir, tag,
                (unsigned long)GetCurrentProcessId());
}

static int read_whole_file(const char *path, char **out, size_t *out_len)
{
    FILE *file = fopen(path, "rb");
    long size;
    char *buffer;
    size_t got;

    if (file == NULL) {
        return 0;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return 0;
    }
    size = ftell(file);
    if (size < 0 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return 0;
    }
    buffer = (char *)malloc((size_t)size + 1);
    if (buffer == NULL) {
        fclose(file);
        return 0;
    }
    got = fread(buffer, 1, (size_t)size, file);
    fclose(file);
    buffer[got] = '\0';
    *out = buffer;
    *out_len = got;
    return 1;
}

/* ---- record-stream checker ------------------------------------------- */

static int valid_prefix(const char *line, size_t length)
{
    static const char *const levels[5] = {
        "TRACE", "DEBUG", "INFO", "WARN", "ERROR"
    };
    size_t close;
    const char *after;
    size_t remaining;
    int level;
    int found = 0;

    if (length < 16 || line[0] != '[') {
        return 0;
    }
    for (close = 1; close < length && line[close] != ']'; close++) {
    }
    if (close < 2 || close > 6 || close >= length) {
        return 0;
    }
    for (level = 0; level < 5; level++) {
        if (strlen(levels[level]) == close - 1 &&
            memcmp(line + 1, levels[level], close - 1) == 0) {
            found = 1;
        }
    }
    if (!found) {
        return 0;
    }

    after = line + close + 1;
    remaining = length - (size_t)(after - line);
    if (remaining < 16 || memcmp(after, " tid=0x", 7) != 0) {
        return 0;
    }
    for (level = 0; level < 8; level++) {
        char ch = after[7 + level];
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) {
            return 0;
        }
    }
    return after[15] == ' ';
}

static int verify_stream(const char *data, size_t length, int expected_records,
                         int token_domain, int require_all_tokens, int explain)
{
    int failures = 0;
    int records = 0;
    int *counts;
    size_t i = 0;
    int t;

    if (token_domain < 1) {
        token_domain = 1;
    }
    counts = (int *)calloc((size_t)token_domain, sizeof(int));
    if (counts == NULL) {
        return 1;
    }

    while (i < length) {
        size_t start = i;
        size_t line_length;
        int token_count = 0;
        int token_value = -1;
        size_t k;

        while (i < length && data[i] != '\n') {
            i++;
        }
        if (i >= length) {
            failures++;
            if (explain) {
                fprintf(stderr, "[log-probe]   unterminated final record\n");
            }
            break;
        }
        line_length = i - start;
        i++;
        records++;

        if (!valid_prefix(data + start, line_length)) {
            failures++;
            if (explain) {
                fprintf(stderr, "[log-probe]   malformed record prefix\n");
            }
            continue;
        }

        for (k = 0; k + 6 <= line_length; k++) {
            if (memcmp(data + start + k, "token=", 6) == 0) {
                size_t j = k + 6;
                int digits = 0;
                int value = 0;

                token_count++;
                while (j < line_length && data[start + j] >= '0' &&
                       data[start + j] <= '9') {
                    value = value * 10 + (data[start + j] - '0');
                    if (value > 1000000) {
                        value = 1000000;
                    }
                    j++;
                    digits++;
                }
                token_value = (digits == 0) ? -1 : value;
                k = (j > k) ? (j - 1) : k;
            }
        }

        if (token_count != 1) {
            failures++;
            if (explain) {
                fprintf(stderr, "[log-probe]   record has %d tokens\n",
                        token_count);
            }
        } else if (token_value < 0 || token_value >= token_domain) {
            failures++;
            if (explain) {
                fprintf(stderr, "[log-probe]   token out of range\n");
            }
        } else {
            counts[token_value]++;
        }
    }

    if (records != expected_records) {
        failures++;
        if (explain) {
            fprintf(stderr, "[log-probe]   record count %d, want %d\n",
                    records, expected_records);
        }
    }
    for (t = 0; t < token_domain; t++) {
        if (require_all_tokens) {
            if (counts[t] != 1) {
                failures++;
                if (explain) {
                    fprintf(stderr, "[log-probe]   token %d count %d\n", t,
                            counts[t]);
                }
            }
        } else if (counts[t] > 1) {
            failures++;
            if (explain) {
                fprintf(stderr, "[log-probe]   token %d duplicated\n", t);
            }
        }
    }

    free(counts);
    return failures;
}

static int verify_file(const char *path, int expected_records,
                       int token_domain, int require_all_tokens, int explain)
{
    char *data = NULL;
    size_t length = 0;
    int failures;

    if (!read_whole_file(path, &data, &length)) {
        fprintf(stderr, "FATAL: could not read the log file\n");
        ExitProcess(1);
    }
    failures = verify_stream(data, length, expected_records, token_domain,
                             require_all_tokens, explain);
    free(data);
    return failures;
}

/* ---- deterministic phases -------------------------------------------- */

static void run_basic_and_filter_checks(void)
{
    char path[MAX_PATH];
    host_log_options options;
    host_log *log = NULL;
    char *data = NULL;
    size_t length = 0;

    /* Basic shape. */
    make_temp_path(path, sizeof(path), "basic");
    DeleteFileA(path);
    options.path = path;
    options.min_level = HOST_LOG_LEVEL_TRACE;
    expect_result(host_log_open(&options, &log), HOST_LOG_OK, "open basic");
    if (log != NULL) {
        expect_result(host_log_write(log, HOST_LOG_LEVEL_INFO, "token=%d", 0),
                      HOST_LOG_OK, "write basic");
        expect_result(host_log_flush(log), HOST_LOG_OK, "flush basic");
        expect_result(host_log_close(log), HOST_LOG_OK, "close basic");
        log = NULL;
    }
    g_failures += verify_file(path, 1, 1, 1, 1);
    DeleteFileA(path);

    /* Level filtering: an INFO below a WARN minimum writes nothing. */
    make_temp_path(path, sizeof(path), "filter");
    DeleteFileA(path);
    options.min_level = HOST_LOG_LEVEL_WARN;
    expect_result(host_log_open(&options, &log), HOST_LOG_OK, "open filter");
    if (log != NULL) {
        expect_result(host_log_write(log, HOST_LOG_LEVEL_INFO,
                                     "token=%d filtered", 0),
                      HOST_LOG_SKIPPED, "filtered write");
        expect_result(host_log_write(log, HOST_LOG_LEVEL_WARN, "token=%d", 0),
                      HOST_LOG_OK, "kept write");
        expect_result(host_log_close(log), HOST_LOG_OK, "close filter");
        log = NULL;
    }
    g_failures += verify_file(path, 1, 1, 1, 1);
    if (read_whole_file(path, &data, &length)) {
        if (strstr(data, "filtered") != NULL) {
            fail("a filtered record reached the sink");
        }
        free(data);
        data = NULL;
    }
    DeleteFileA(path);
}

static void run_truncation_check(void)
{
    char path[MAX_PATH];
    host_log_options options;
    host_log *log = NULL;
    char *long_message;
    size_t long_length = 4000;
    char *data = NULL;
    size_t length = 0;

    long_message = (char *)malloc(long_length + 1);
    if (long_message == NULL) {
        fprintf(stderr, "FATAL: allocation failed\n");
        ExitProcess(1);
    }
    memset(long_message, 'x', long_length);
    long_message[long_length] = '\0';

    make_temp_path(path, sizeof(path), "truncate");
    DeleteFileA(path);
    options.path = path;
    options.min_level = HOST_LOG_LEVEL_TRACE;
    expect_result(host_log_open(&options, &log), HOST_LOG_OK, "open truncate");
    if (log != NULL) {
        expect_result(host_log_write(log, HOST_LOG_LEVEL_INFO,
                                     "token=%d %s", 0, long_message),
                      HOST_LOG_ERR_TRUNCATED, "truncated write");
        expect_result(host_log_close(log), HOST_LOG_OK, "close truncate");
        log = NULL;
    }

    /* The truncated record is still one well-formed, newline-terminated
     * record that carries the marker and the leading token. */
    g_failures += verify_file(path, 1, 1, 1, 1);
    if (read_whole_file(path, &data, &length)) {
        if (strstr(data, "...<truncated>") == NULL) {
            fail("a truncated record has no truncation marker");
        }
        if (length == 0 || data[length - 1] != '\n') {
            fail("a truncated record is not newline-terminated");
        }
        free(data);
    }
    free(long_message);
    DeleteFileA(path);
}

/* Embedded CR/LF or NUL in a message must not forge a record boundary or
 * silently cut the record: one call is exactly one line after normalisation. */
static void run_multiline_normalization_check(void)
{
    char path[MAX_PATH];
    host_log_options options;
    host_log *log = NULL;
    char *data = NULL;
    size_t length = 0;

    make_temp_path(path, sizeof(path), "multiline");
    DeleteFileA(path);
    options.path = path;
    options.min_level = HOST_LOG_LEVEL_TRACE;
    expect_result(host_log_open(&options, &log), HOST_LOG_OK,
                  "open multiline");
    if (log != NULL) {
        expect_result(host_log_write(log, HOST_LOG_LEVEL_INFO,
                                     "token=%d first\r\nsecond\nthird", 0),
                      HOST_LOG_OK, "multiline write");
        /* `%c` with 0 writes an embedded NUL; it must become a space, not a
         * silent cut before the trailing `b`. */
        expect_result(host_log_write(log, HOST_LOG_LEVEL_INFO,
                                     "token=%d a%cb", 1, 0),
                      HOST_LOG_OK, "embedded-NUL write");
        expect_result(host_log_close(log), HOST_LOG_OK, "close multiline");
        log = NULL;
    }
    g_failures += verify_file(path, 2, 2, 1, 1);
    if (read_whole_file(path, &data, &length)) {
        if (strstr(data, "a b") == NULL) {
            fail("an embedded NUL was not normalised to a space");
        }
        if (memchr(data, '\0', length) != NULL) {
            fail("an embedded NUL reached the sink");
        }
        free(data);
    }
    DeleteFileA(path);
}

static void run_argument_and_open_checks(void)
{
    char path[MAX_PATH];
    char missing_dir_path[MAX_PATH];
    host_log_options options;
    host_log_options bad_options;
    host_log *log = NULL;

    options.path = NULL;
    options.min_level = HOST_LOG_LEVEL_TRACE;

    /* Every failing open must leave the caller's output pointer untouched. */
    log = (host_log *)0x1;
    expect_result(host_log_open(NULL, &log), HOST_LOG_ERR_INVALID_ARGUMENT,
                  "open(NULL options)");
    if (log != (host_log *)0x1) {
        fail("open(NULL options) changed the output pointer");
    }
    expect_result(host_log_open(&options, NULL), HOST_LOG_ERR_INVALID_ARGUMENT,
                  "open(NULL out)");
    bad_options.path = NULL;
    bad_options.min_level = (host_log_level)99;
    expect_result(host_log_open(&bad_options, &log),
                  HOST_LOG_ERR_INVALID_ARGUMENT, "open(bad level)");
    if (log != (host_log *)0x1) {
        fail("open(bad level) changed the output pointer");
    }

    expect_result(host_log_write(NULL, HOST_LOG_LEVEL_INFO, "x"),
                  HOST_LOG_ERR_INVALID_ARGUMENT, "write(NULL)");
    expect_result(host_log_flush(NULL), HOST_LOG_ERR_INVALID_ARGUMENT,
                  "flush(NULL)");
    expect_result(host_log_close(NULL), HOST_LOG_OK, "close(NULL) no-op");

    /* Open a path inside a directory that does not exist. */
    make_temp_path(path, sizeof(path), "openfail");
    _snprintf_s(missing_dir_path, sizeof(missing_dir_path), _TRUNCATE,
                "%s.missing_dir\\x.log", path);
    options.path = missing_dir_path;
    options.min_level = HOST_LOG_LEVEL_TRACE;
    expect_result(host_log_open(&options, &log), HOST_LOG_ERR_OPEN,
                  "open(nonexistent directory)");
    if (log != (host_log *)0x1) {
        fail("open(nonexistent directory) changed the output pointer");
    }
}

/* ---- concurrency ------------------------------------------------------ */

typedef struct log_writer {
    host_log *log;
    int first_token;
    LONG failures;
} log_writer;

static DWORD WINAPI log_writer_main(LPVOID arg)
{
    log_writer *writer = (log_writer *)arg;
    int i;

    for (i = 0; i < LOG_PROBE_RECORDS_PER_WRITER; i++) {
        host_log_result result =
            host_log_write(writer->log, HOST_LOG_LEVEL_INFO, "token=%d",
                           writer->first_token + i);
        if (result != HOST_LOG_OK) {
            InterlockedIncrement(&writer->failures);
        }
    }
    return 0;
}

static void run_concurrency_check(void)
{
    char path[MAX_PATH];
    host_log_options options;
    host_log *log = NULL;
    log_writer writers[LOG_PROBE_WRITERS];
    HANDLE threads[LOG_PROBE_WRITERS];
    int i;

    make_temp_path(path, sizeof(path), "threads");
    DeleteFileA(path);
    options.path = path;
    options.min_level = HOST_LOG_LEVEL_TRACE;
    expect_result(host_log_open(&options, &log), HOST_LOG_OK,
                  "open concurrency");
    if (log == NULL) {
        return;
    }

    for (i = 0; i < LOG_PROBE_WRITERS; i++) {
        writers[i].log = log;
        writers[i].first_token = i * LOG_PROBE_RECORDS_PER_WRITER;
        writers[i].failures = 0;
        threads[i] = CreateThread(NULL, 0, log_writer_main, &writers[i], 0,
                                  NULL);
        if (threads[i] == NULL) {
            fprintf(stderr, "FATAL: CreateThread failed\n");
            ExitProcess(1);
        }
    }
    for (i = 0; i < LOG_PROBE_WRITERS; i++) {
        if (WaitForSingleObject(threads[i], LOG_PROBE_WAIT_MS) !=
            WAIT_OBJECT_0) {
            fprintf(stderr, "FATAL: writer join wait failed\n");
            ExitProcess(1);
        }
        CloseHandle(threads[i]);
        if (InterlockedCompareExchange(&writers[i].failures, 0, 0) != 0) {
            fail("a writer's host_log_write call failed");
        }
    }

    expect_result(host_log_close(log), HOST_LOG_OK, "close concurrency");
    g_failures += verify_file(path, LOG_PROBE_TOKEN_DOMAIN,
                              LOG_PROBE_TOKEN_DOMAIN, 1, 1);
    DeleteFileA(path);
}

/* ---- checker negative controls ---------------------------------------- */

static void run_stream_checker_negatives(void)
{
    static const char *const correct =
        "[INFO] tid=0x00000001 token=0\n"
        "[INFO] tid=0x00000002 token=1\n";
    static const char *const interleaved =
        "[INFO] tid=0x00000001 token=0[INFO] tid=0x00000002 token=1\n";
    static const char *const unterminated =
        "[INFO] tid=0x00000001 token=0";
    static const char *const missing =
        "[INFO] tid=0x00000001 token=0\n";
    static const char *const duplicate =
        "[INFO] tid=0x00000001 token=0\n"
        "[INFO] tid=0x00000002 token=0\n";
    static const char *const malformed =
        "junk\n";

    if (verify_stream(correct, strlen(correct), 2, 2, 1, 0) != 0) {
        fail("the stream checker rejected a correct stream");
    }
    if (verify_stream(interleaved, strlen(interleaved), 2, 2, 1, 0) == 0) {
        fail("the stream checker accepted interleaved records");
    }
    if (verify_stream(unterminated, strlen(unterminated), 1, 1, 1, 0) == 0) {
        fail("the stream checker accepted an unterminated record");
    }
    if (verify_stream(missing, strlen(missing), 2, 2, 1, 0) == 0) {
        fail("the stream checker accepted a missing record");
    }
    if (verify_stream(duplicate, strlen(duplicate), 2, 1, 1, 0) == 0) {
        fail("the stream checker accepted a duplicated record");
    }
    if (verify_stream(malformed, strlen(malformed), 1, 1, 0, 0) == 0) {
        fail("the stream checker accepted a malformed record");
    }
    printf("checked: stream checker rejects interleaved, unterminated, "
           "missing, duplicated and malformed streams\n");
}

/* ---- real sink error (broken stderr pipe) ---------------------------- */

/* Force a genuine write failure with an external OS resource: temporarily
 * redirect the process's stderr file descriptor to a pipe whose read end is
 * closed, then use a path==NULL logger (stderr sink). This exercises the real
 * HOST_LOG_ERR_IO path and the documented "close always consumes the handle
 * and reports the sink error" behaviour. Only the fixture process's stderr
 * descriptor is touched; it is restored before any result is reported. */
static void run_sink_error_check(void)
{
    int stderr_fd = _fileno(stderr);
    int saved_fd;
    int pipe_fds[2];
    host_log_options options;
    host_log *log = NULL;
    host_log_result open_result;
    host_log_result write_result;
    host_log_result close_result;

    fflush(stderr);
    saved_fd = _dup(stderr_fd);
    if (saved_fd < 0) {
        fprintf(stderr, "FATAL: _dup(stderr) failed\n");
        ExitProcess(1);
    }
    if (_pipe(pipe_fds, 4096, _O_BINARY) != 0 ||
        _dup2(pipe_fds[1], stderr_fd) < 0) {
        fprintf(stderr, "FATAL: could not redirect stderr to a pipe\n");
        ExitProcess(1);
    }
    _close(pipe_fds[1]);
    _close(pipe_fds[0]); /* no reader: the next write must fail */

    options.path = NULL;
    options.min_level = HOST_LOG_LEVEL_TRACE;
    open_result = host_log_open(&options, &log);
    write_result = (open_result == HOST_LOG_OK && log != NULL)
                       ? host_log_write(log, HOST_LOG_LEVEL_INFO, "token=%d", 0)
                       : HOST_LOG_ERR_OPEN;
    close_result = (log != NULL) ? host_log_close(log) : HOST_LOG_ERR_OPEN;

    /* Restore stderr before reporting, so a failure message is visible. */
    if (_dup2(saved_fd, stderr_fd) < 0) {
        ExitProcess(1);
    }
    _close(saved_fd);
    clearerr(stderr);

    expect_result(open_result, HOST_LOG_OK, "open stderr sink");
    expect_result(write_result, HOST_LOG_ERR_IO,
                  "write to a broken stderr sink");
    /* close() reports its OWN final flush/close result, not the historical
     * write error: stderr is unbuffered and host_log_write() already cleared
     * the stream error, so there is nothing left for close's flush to fail
     * on and the close result is clean. The write above is the real
     * HOST_LOG_ERR_IO evidence. */
    expect_result(close_result, HOST_LOG_OK,
                  "close reports its own clean flush result");
}

int main(void)
{
    g_failures = 0;

    run_basic_and_filter_checks();
    run_truncation_check();
    run_multiline_normalization_check();
    run_argument_and_open_checks();
    run_concurrency_check();
    run_sink_error_check();
    run_stream_checker_negatives();

    if (g_failures != 0) {
        fprintf(stderr, "FAIL: host log probe failed %d check(s)\n",
                g_failures);
        return 1;
    }

    printf("PASS: host logging battery (%d writers x %d records) with "
           "rejected corrupted streams\n",
           LOG_PROBE_WRITERS, LOG_PROBE_RECORDS_PER_WRITER);
    return 0;
}
