/*
 * Generic native negative-control driver (D020).
 *
 * Runs a real probe first (must exit 0 and print "PASS:") and then each
 * compiled wrong implementation. A mutant is REJECTED only when it
 *   - exits with exactly the semantic-failure code 2 (not 1, not a crash),
 *   - prints no "FATAL:" line, and
 *   - its FIRST "FAIL: <label>" line is the exact label supplied for it.
 *
 * Anything else is reported as an infrastructure/unexpected failure, so a
 * mutant that fails for an unrelated reason can never be counted as a
 * rejection. No WILL_FAIL inversion and no weakened exit-code matching.
 *
 * argv: <external fixture root> <real probe exe>
 *       [<mutant exe> <exact first FAIL label>]...
 *
 * Logs carry this process's PID so two CTest instances (provider and adapter)
 * can run concurrently with the same external root.
 */
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LOG_BYTES (256u * 1024u)

static int run_capture(const char *exe, const char *root, const char *log_path,
                       DWORD *exit_code)
{
    char command[4096];
    SECURITY_ATTRIBUTES inherit;
    STARTUPINFOA startup;
    PROCESS_INFORMATION process;
    HANDLE log;
    int ok;

    snprintf(command, sizeof(command), "\"%s\" \"%s\"", exe, root);
    inherit.nLength = sizeof(inherit);
    inherit.lpSecurityDescriptor = NULL;
    inherit.bInheritHandle = TRUE;
    log = CreateFileA(log_path, GENERIC_WRITE, FILE_SHARE_READ, &inherit,
                      CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (log == INVALID_HANDLE_VALUE) return 0;
    memset(&startup, 0, sizeof(startup));
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = log;
    startup.hStdError = log;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    memset(&process, 0, sizeof(process));
    ok = CreateProcessA(NULL, command, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                        NULL, NULL, &startup, &process) != 0;
    CloseHandle(log);
    if (!ok) return 0;
    WaitForSingleObject(process.hProcess, INFINITE);
    *exit_code = 1;
    if (!GetExitCodeProcess(process.hProcess, exit_code)) *exit_code = 1;
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return 1;
}

static char *read_log(const char *log_path)
{
    FILE *f = fopen(log_path, "rb");
    if (!f) return NULL;
    char *buffer = (char *)malloc(MAX_LOG_BYTES + 1u);
    if (!buffer) {
        fclose(f);
        return NULL;
    }
    size_t n = fread(buffer, 1, MAX_LOG_BYTES, f);
    fclose(f);
    buffer[n] = '\0';
    return buffer;
}

static const char *first_line_with(const char *log, const char *prefix)
{
    static char line[512];
    size_t prefix_len = strlen(prefix);
    for (const char *at = log; at && *at;) {
        const char *end = strchr(at, '\n');
        size_t len = end ? (size_t)(end - at) : strlen(at);
        if (len < sizeof(line) && len >= prefix_len &&
            strncmp(at, prefix, prefix_len) == 0) {
            /* The child's stdout is a text-mode file, so the captured line
             * keeps a trailing CR. Drop it before the exact-label compare. */
            while (len > 0 && at[len - 1] == '\r') len--;
            memcpy(line, at, len);
            line[len] = '\0';
            return line;
        }
        at = end ? end + 1 : at + len;
    }
    return NULL;
}

static int contains(const char *log, const char *needle)
{
    return log && strstr(log, needle) != NULL;
}

int main(int argc, char **argv)
{
    if (argc < 3 || ((argc - 3) & 1) != 0) {
        printf("FATAL: usage: <fixture root> <real probe> "
               "[<mutant> <expected first FAIL>]...\n");
        return 1;
    }
    const char *root = argv[1];
    const char *real_probe = argv[2];
    char log_path[2048];
    DWORD code = 0;
    int failures = 0;
    unsigned long pid = (unsigned long)GetCurrentProcessId();

    snprintf(log_path, sizeof(log_path),
             "%s/romfs-native-mutants-%lu-real.log", root, pid);
    if (!run_capture(real_probe, root, log_path, &code)) {
        printf("FATAL: could not launch the real probe\n");
        return 1;
    }
    char *log = read_log(log_path);
    if (!log) {
        printf("FATAL: could not read the real probe log\n");
        return 1;
    }
    if (code != 0 || contains(log, "FAIL:") || contains(log, "FATAL:") ||
        !contains(log, "PASS:")) {
        printf("FATAL: real probe did not pass cleanly (exit %lu)\n",
               (unsigned long)code);
        free(log);
        return 1;
    }
    printf("baseline: real probe exit 0 (PASS)\n");
    free(log);

    unsigned mutant_count = (unsigned)((argc - 3) / 2);
    for (unsigned i = 0; i < mutant_count; i++) {
        const char *mutant = argv[3 + i * 2];
        const char *expected = argv[4 + i * 2];
        snprintf(log_path, sizeof(log_path),
                 "%s/romfs-native-mutants-%lu-%u.log", root, pid, i);
        code = 0;
        if (!run_capture(mutant, root, log_path, &code)) {
            printf("FATAL: could not launch mutant %u\n", i);
            failures++;
            continue;
        }
        log = read_log(log_path);
        if (!log) {
            printf("FATAL: could not read mutant %u log\n", i);
            failures++;
            continue;
        }
        const char *fail_line = first_line_with(log, "FAIL: ");
        int label_ok = 0;
        if (fail_line && strncmp(fail_line, "FAIL: ", 6) == 0) {
            size_t want = strlen(expected);
            /* Exact label: the documented text, optionally followed by the
             * probe's own " (status N, expected M)" annotation. */
            label_ok = strncmp(fail_line + 6, expected, want) == 0 &&
                       (fail_line[6 + want] == '\0' ||
                        fail_line[6 + want] == ' ');
        }
        int rejected = code == 2 && !contains(log, "FATAL:") && label_ok;
        if (rejected) {
            printf("rejected: mutant %u -> exit 2, \"%s\"\n", i, expected);
        } else {
            printf("NOT REJECTED: mutant %u (exit %lu, first failure: %s)\n",
                   i, (unsigned long)code,
                   fail_line ? fail_line : "(none)");
            failures++;
        }
        free(log);
    }
    if (failures) {
        printf("FAIL: %d mutant negative control(s) were not rejected correctly\n",
               failures);
        return 2;
    }
    printf("PASS: %u runtime mutants rejected with exact first failures\n",
           mutant_count);
    return 0;
}
