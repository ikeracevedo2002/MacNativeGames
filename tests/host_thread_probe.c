/* Host thread lifecycle probe (G1 thread row).
 *
 * One battery, two kinds of backend:
 *
 *   1. the real backend from src/host_thread.c, which must pass every check;
 *   2. fixture-only deliberately-wrong backends, each of which the SAME
 *      battery must reject. They live in this test executable only: the
 *      product header exposes no hook, callback or injection point.
 *
 * Coverage:
 *   - NULL arguments and lifecycle misuse (create after join, join/close on
 *     an empty or spent handle, double close);
 *   - the entry callback really runs (a side effect is observed only after a
 *     join);
 *   - a bounded join of a still-gated worker reports "not joined" and leaves
 *     the handle usable; releasing the gate then lets a second join reap it
 *     and close the native handle;
 *   - close() releases a finished thread without waiting and makes a later
 *     join fail as spent;
 *   - self-join is rejected from inside the callback, with a phase gate so
 *     the handle is published before the callback reads it.
 *
 * Synchronisation discipline: every phase is completed by a manual-reset
 * event, so no sleep makes a phase deterministic and every wait is bounded
 * (PROBE_WAIT_MS). A worker's stack context is only released after the
 * worker itself has signalled completion, so no join result is ever read
 * from a thread that may still be running.
 *
 * Infrastructure failure discipline: if an event or thread cannot be created
 * or a worker does not report completion inside the bounded wait, the round
 * cannot prove anything and the harness itself is in an unknown state. The
 * process terminates immediately with ExitProcess(1) -- no context is read
 * and no handle is closed -- so a harness failure can never be counted as a
 * rejected negative backend; the CTest case just fails.
 *
 * Exit status is the result. No PASS_REGULAR_EXPRESSION, no WILL_FAIL, and no
 * assert(): the checks are ordinary code compiled identically in Debug and
 * Release.
 */

#include "host_thread.h"

#include <windows.h>

#include <stdio.h>
#include <string.h>

#define PROBE_WAIT_MS 30000u        /* generous bounded reap */
#define PROBE_REJECT_WAIT_MS 100u   /* bounded window where a worker must stay gated */

static void fatal_infrastructure(const char *what)
{
    fprintf(stderr, "FATAL: probe infrastructure failed: %s\n", what);
    /* A worker may still be running on this frame's context, so nothing is
     * cleaned up and no result is read. Leave the process immediately. */
    ExitProcess(1);
}

/* ---- backend seam used by the battery -------------------------------- */

typedef struct thread_ops {
    const char *name;
    host_thread_result (*create)(host_thread *thread, host_thread_fn entry,
                                 void *arg);
    host_thread_result (*join)(host_thread *thread, uint32_t timeout_ms,
                               int *out_joined);
    host_thread_result (*close)(host_thread *thread);
} thread_ops;

static host_thread_result real_create(host_thread *thread,
                                      host_thread_fn entry, void *arg)
{
    return host_thread_create(thread, entry, arg);
}

static host_thread_result real_join(host_thread *thread, uint32_t timeout_ms,
                                    int *out_joined)
{
    return host_thread_join(thread, timeout_ms, out_joined);
}

static host_thread_result real_close(host_thread *thread)
{
    return host_thread_close(thread);
}

static const thread_ops real_ops = {
    "real",
    real_create,
    real_join,
    real_close
};

/* Claims a join without waiting: reports every join as completed. */
static host_thread_result negative_ignore_wait_join(host_thread *thread,
                                                    uint32_t timeout_ms,
                                                    int *out_joined)
{
    (void)thread;
    (void)timeout_ms;
    if (out_joined != NULL) {
        *out_joined = 1;
    }
    return HOST_THREAD_OK;
}

static const thread_ops negative_ignore_wait_ops = {
    "negative-join-ignores-wait",
    real_create,
    negative_ignore_wait_join,
    real_close
};

/* Never reaps: reports every join as a timeout. */
static host_thread_result negative_timeout_join(host_thread *thread,
                                                uint32_t timeout_ms,
                                                int *out_joined)
{
    (void)thread;
    (void)timeout_ms;
    if (out_joined != NULL) {
        *out_joined = 0;
    }
    return HOST_THREAD_OK;
}

static const thread_ops negative_timeout_ops = {
    "negative-join-always-times-out",
    real_create,
    negative_timeout_join,
    real_close
};

/* ---- check bookkeeping ----------------------------------------------- */

typedef struct checks {
    const char *label;
    int explain;
    int failures;
} checks;

static void note(checks *c, const char *what)
{
    c->failures++;
    if (c->explain) {
        fprintf(stderr, "[%s] FAIL: %s\n", c->label, what);
    }
}

static void expect_result(checks *c, host_thread_result got,
                          host_thread_result want, const char *what)
{
    if (got != want) {
        c->failures++;
        if (c->explain) {
            fprintf(stderr, "[%s] FAIL: %s returned %d, want %d\n", c->label,
                    what, (int)got, (int)want);
        }
    }
}

/* ---- worker fixture -------------------------------------------------- */

typedef struct thread_worker {
    HANDLE gate;       /* manual-reset; test releases the worker */
    HANDLE done;       /* manual-reset; worker sets on completion */
    HANDLE published;  /* self-join test: handle is ready to read */
    host_thread *self; /* self-join test: the caller's own handle */
    host_thread_result self_join_result;
    LONG ran;
} thread_worker;

static void thread_worker_main(void *arg)
{
    thread_worker *worker = (thread_worker *)arg;

    if (worker->published != NULL) {
        if (WaitForSingleObject(worker->published, PROBE_WAIT_MS) !=
            WAIT_OBJECT_0) {
            fatal_infrastructure("published gate wait");
        }
    }
    if (worker->self != NULL) {
        int joined = -1;
        worker->self_join_result = host_thread_join(worker->self, 0, &joined);
    }
    if (worker->gate != NULL) {
        if (WaitForSingleObject(worker->gate, PROBE_WAIT_MS) !=
            WAIT_OBJECT_0) {
            fatal_infrastructure("worker gate wait");
        }
    }

    InterlockedExchange(&worker->ran, 1);
    if (worker->done != NULL) {
        SetEvent(worker->done);
    }
}

static HANDLE make_event(void)
{
    HANDLE event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (event == NULL) {
        fatal_infrastructure("CreateEvent");
    }
    return event;
}

/* ---- battery phases -------------------------------------------------- */

static void run_argument_checks(checks *c, const thread_ops *ops)
{
    host_thread thread;
    int joined = -1;

    memset(&thread, 0, sizeof(thread));

    expect_result(c, ops->create(NULL, thread_worker_main, NULL),
                  HOST_THREAD_ERR_INVALID_ARGUMENT, "create(NULL)");
    expect_result(c, ops->create(&thread, NULL, NULL),
                  HOST_THREAD_ERR_INVALID_ARGUMENT, "create(NULL entry)");
    expect_result(c, ops->join(NULL, 0, &joined),
                  HOST_THREAD_ERR_INVALID_ARGUMENT, "join(NULL)");
    expect_result(c, ops->join(&thread, 0, NULL),
                  HOST_THREAD_ERR_INVALID_ARGUMENT, "join(NULL out)");
    expect_result(c, ops->close(NULL),
                  HOST_THREAD_ERR_INVALID_ARGUMENT, "close(NULL)");

    /* A zero-initialised handle is empty, not live. */
    expect_result(c, ops->join(&thread, 0, &joined),
                  HOST_THREAD_ERR_INVALID_STATE, "join(empty)");
    expect_result(c, ops->close(&thread),
                  HOST_THREAD_ERR_INVALID_STATE, "close(empty)");

    /* A failed call must leave the handle's fields unchanged. */
    if (thread.native_handle != 0 || thread.native_id != 0 ||
        thread.state != 0) {
        note(c, "a failed create/join/close changed the empty handle's fields");
    }
}

static void run_join_protocol(checks *c, const thread_ops *ops)
{
    thread_worker worker;
    host_thread thread;
    HANDLE gate;
    HANDLE done;
    host_thread_result result;
    int joined;

    memset(&worker, 0, sizeof(worker));
    memset(&thread, 0, sizeof(thread));

    gate = make_event();
    done = make_event();
    worker.gate = gate;
    worker.done = done;

    result = ops->create(&thread, thread_worker_main, &worker);
    expect_result(c, result, HOST_THREAD_OK, "create gated worker");
    if (result != HOST_THREAD_OK) {
        CloseHandle(gate);
        CloseHandle(done);
        return;
    }

    /* The worker is gated, so a bounded join must not claim a completion. */
    joined = -1;
    result = ops->join(&thread, PROBE_REJECT_WAIT_MS, &joined);
    expect_result(c, result, HOST_THREAD_OK, "bounded join result");
    if (result == HOST_THREAD_OK && joined != 0) {
        note(c, "bounded join claimed a still-gated worker had finished");
    }

    /* Release the worker and let it report completion before any context is
     * reused. This also covers a backend whose join returned early. */
    SetEvent(gate);
    if (WaitForSingleObject(done, PROBE_WAIT_MS) != WAIT_OBJECT_0) {
        fatal_infrastructure("gated worker completion wait");
    }

    joined = -1;
    result = ops->join(&thread, PROBE_WAIT_MS, &joined);
    expect_result(c, result, HOST_THREAD_OK, "final join result");
    if (result == HOST_THREAD_OK && joined != 1) {
        note(c, "final join did not reap the terminated worker");
    }
    if (InterlockedCompareExchange(&worker.ran, 0, 0) != 1) {
        note(c, "worker body did not run");
    }

    /* Reaping closes the native handle, so the handle is spent. */
    joined = -1;
    result = ops->join(&thread, 0, &joined);
    expect_result(c, result, HOST_THREAD_ERR_INVALID_STATE,
                  "join of a spent handle");

    (void)ops->close(&thread); /* harmless on a spent handle */
    CloseHandle(gate);
    CloseHandle(done);
}

static void run_create_on_live_check(checks *c, const thread_ops *ops)
{
    thread_worker worker;
    host_thread thread;
    HANDLE gate;
    HANDLE done;
    host_thread_result result;
    int joined;

    memset(&worker, 0, sizeof(worker));
    memset(&thread, 0, sizeof(thread));

    gate = make_event();
    done = make_event();
    worker.gate = gate;
    worker.done = done;

    result = ops->create(&thread, thread_worker_main, &worker);
    if (result != HOST_THREAD_OK) {
        CloseHandle(gate);
        CloseHandle(done);
        fatal_infrastructure("create for live-handle check");
    }

    /* A live handle must not be silently reused, and the rejected call must
     * leave its fields unchanged. */
    {
        uintptr_t saved_handle = thread.native_handle;
        uint32_t saved_id = thread.native_id;
        uint32_t saved_state = thread.state;
        expect_result(c, ops->create(&thread, thread_worker_main, &worker),
                      HOST_THREAD_ERR_INVALID_STATE, "create on a live handle");
        if (thread.native_handle != saved_handle ||
            thread.native_id != saved_id || thread.state != saved_state) {
            note(c, "a rejected create-on-live changed the live handle");
        }
    }

    SetEvent(gate);
    if (WaitForSingleObject(done, PROBE_WAIT_MS) != WAIT_OBJECT_0) {
        fatal_infrastructure("live-handle worker completion wait");
    }
    joined = -1;
    (void)ops->join(&thread, PROBE_WAIT_MS, &joined);
    (void)ops->close(&thread);
    CloseHandle(gate);
    CloseHandle(done);
}

static void run_close_protocol(checks *c, const thread_ops *ops)
{
    thread_worker worker;
    host_thread thread;
    HANDLE done;
    host_thread_result result;
    int joined;

    memset(&worker, 0, sizeof(worker));
    memset(&thread, 0, sizeof(thread));

    done = make_event();
    worker.done = done;

    result = ops->create(&thread, thread_worker_main, &worker);
    expect_result(c, result, HOST_THREAD_OK, "create close-protocol worker");
    if (result != HOST_THREAD_OK) {
        CloseHandle(done);
        return;
    }

    if (WaitForSingleObject(done, PROBE_WAIT_MS) != WAIT_OBJECT_0) {
        fatal_infrastructure("close-protocol worker completion wait");
    }

    expect_result(c, ops->close(&thread), HOST_THREAD_OK, "close finished");
    joined = -1;
    expect_result(c, ops->join(&thread, 0, &joined),
                  HOST_THREAD_ERR_INVALID_STATE, "join after close");
    expect_result(c, ops->close(&thread), HOST_THREAD_ERR_INVALID_STATE,
                  "close after close");

    CloseHandle(done);
}

/* Behavioural join core shared with the deliberately-wrong fixtures. It
 * never calls an argument/lifecycle entry point, so a fixture is only ever
 * rejected by the join behaviour it actually breaks. */
static void run_behavioral_join_checks(checks *c, const thread_ops *ops)
{
    thread_worker worker;
    host_thread thread;
    HANDLE gate;
    HANDLE done;
    host_thread_result result;
    int joined;

    memset(&worker, 0, sizeof(worker));
    memset(&thread, 0, sizeof(thread));

    gate = make_event();
    done = make_event();
    worker.gate = gate;
    worker.done = done;

    result = ops->create(&thread, thread_worker_main, &worker);
    if (result != HOST_THREAD_OK) {
        CloseHandle(gate);
        CloseHandle(done);
        fatal_infrastructure("create gated worker");
    }

    joined = -1;
    result = ops->join(&thread, PROBE_REJECT_WAIT_MS, &joined);
    if (result != HOST_THREAD_OK) {
        note(c, "bounded join reported a failure");
    } else if (joined != 0) {
        note(c, "bounded join claimed a still-gated worker had finished");
    }

    SetEvent(gate);
    if (WaitForSingleObject(done, PROBE_WAIT_MS) != WAIT_OBJECT_0) {
        fatal_infrastructure("gated worker completion wait");
    }

    joined = -1;
    result = ops->join(&thread, PROBE_WAIT_MS, &joined);
    if (result != HOST_THREAD_OK) {
        note(c, "final join reported a failure");
    } else if (joined != 1) {
        note(c, "final join did not reap the terminated worker");
    }

    /* Harmless on an already-reaped handle; releases a fixture that did not
     * reap. */
    (void)ops->close(&thread);
    CloseHandle(gate);
    CloseHandle(done);
}

/* Create, join, then reuse the SAME spent handle for a fresh thread: a
 * spent (joined) handle must be reusable, not a one-shot. */
static void run_reuse_spent_handle_check(checks *c, const thread_ops *ops)
{
    thread_worker worker1;
    thread_worker worker2;
    host_thread thread;
    HANDLE done1;
    HANDLE done2;
    host_thread_result result;
    int joined;

    memset(&thread, 0, sizeof(thread));
    memset(&worker1, 0, sizeof(worker1));
    memset(&worker2, 0, sizeof(worker2));

    done1 = make_event();
    worker1.done = done1;
    result = ops->create(&thread, thread_worker_main, &worker1);
    if (result != HOST_THREAD_OK) {
        CloseHandle(done1);
        fatal_infrastructure("reuse: first create");
    }
    if (WaitForSingleObject(done1, PROBE_WAIT_MS) != WAIT_OBJECT_0) {
        fatal_infrastructure("reuse: first completion wait");
    }
    joined = -1;
    result = ops->join(&thread, PROBE_WAIT_MS, &joined);
    expect_result(c, result, HOST_THREAD_OK, "reuse: first join");
    if (result == HOST_THREAD_OK && joined != 1) {
        note(c, "reuse: first join did not reap");
    }

    done2 = make_event();
    worker2.done = done2;
    result = ops->create(&thread, thread_worker_main, &worker2);
    expect_result(c, result, HOST_THREAD_OK, "reuse: create on a spent handle");
    if (result != HOST_THREAD_OK) {
        CloseHandle(done1);
        CloseHandle(done2);
        return;
    }
    if (WaitForSingleObject(done2, PROBE_WAIT_MS) != WAIT_OBJECT_0) {
        fatal_infrastructure("reuse: second completion wait");
    }
    joined = -1;
    result = ops->join(&thread, PROBE_WAIT_MS, &joined);
    expect_result(c, result, HOST_THREAD_OK, "reuse: second join");
    if (result == HOST_THREAD_OK && joined != 1) {
        note(c, "reuse: second join did not reap");
    }
    if (InterlockedCompareExchange(&worker2.ran, 0, 0) != 1) {
        note(c, "reuse: second worker body did not run");
    }

    CloseHandle(done1);
    CloseHandle(done2);
}

/* Run the whole shared battery. Returns the number of failed checks. */
static int run_battery(const thread_ops *ops, int explain, const char *label)
{
    checks c;

    c.label = label;
    c.explain = explain;
    c.failures = 0;

    run_argument_checks(&c, ops);
    run_join_protocol(&c, ops);
    run_create_on_live_check(&c, ops);
    run_close_protocol(&c, ops);
    run_reuse_spent_handle_check(&c, ops);

    return c.failures;
}

/* Behavioural-only battery for the deliberately-wrong fixtures: it exercises
 * only the join behaviour they break, never an unrelated argument/lifecycle
 * check that would reject them for the wrong reason. */
static int run_behavioral_battery(const thread_ops *ops, int explain,
                                  const char *label)
{
    checks c;

    c.label = label;
    c.explain = explain;
    c.failures = 0;

    run_behavioral_join_checks(&c, ops);

    return c.failures;
}

/* Self-join rejection is specific to the real backend (the fixtures do not
 * implement the check), so it is a separate real-only phase. */
static int run_self_join_check(void)
{
    checks c;
    thread_worker worker;
    host_thread thread;
    HANDLE published;
    HANDLE done;
    host_thread_result result;
    int joined;
    int failures = 0;

    c.label = "real";
    c.explain = 1;
    c.failures = 0;

    memset(&worker, 0, sizeof(worker));
    memset(&thread, 0, sizeof(thread));

    published = make_event();
    done = make_event();
    worker.published = published;
    worker.done = done;
    worker.self = &thread;

    result = host_thread_create(&thread, thread_worker_main, &worker);
    expect_result(&c, result, HOST_THREAD_OK, "create self-join worker");
    if (result != HOST_THREAD_OK) {
        CloseHandle(published);
        CloseHandle(done);
        return c.failures;
    }

    /* Publish the handle only after create() has filled it in. */
    SetEvent(published);
    if (WaitForSingleObject(done, PROBE_WAIT_MS) != WAIT_OBJECT_0) {
        fatal_infrastructure("self-join worker completion wait");
    }
    if (worker.self_join_result != HOST_THREAD_ERR_INVALID_STATE) {
        failures++;
        fprintf(stderr, "[real] FAIL: self-join returned %d, want %d\n",
                (int)worker.self_join_result,
                (int)HOST_THREAD_ERR_INVALID_STATE);
    }

    joined = -1;
    result = host_thread_join(&thread, PROBE_WAIT_MS, &joined);
    expect_result(&c, result, HOST_THREAD_OK, "join after self-join attempt");
    if (result == HOST_THREAD_OK && joined != 1) {
        failures++;
        fprintf(stderr, "[real] FAIL: join after self-join did not reap\n");
    }

    failures += c.failures;
    CloseHandle(published);
    CloseHandle(done);
    return failures;
}

/* Close a thread while it is still running. Real-only: it proves close()
 * releases the native handle without ending the thread and without extending
 * the caller-owned argument's lifetime, and that a later join is refused. The
 * worker is gated so it is provably still running when close() is called, and
 * the caller-owned context stays alive until the worker's own done event. */
static int run_close_while_running_check(void)
{
    checks c;
    thread_worker worker;
    host_thread thread;
    HANDLE gate;
    HANDLE done;
    host_thread_result result;
    int joined;

    c.label = "real";
    c.explain = 1;
    c.failures = 0;

    memset(&worker, 0, sizeof(worker));
    memset(&thread, 0, sizeof(thread));

    gate = make_event();
    done = make_event();
    worker.gate = gate;
    worker.done = done;

    result = host_thread_create(&thread, thread_worker_main, &worker);
    if (result != HOST_THREAD_OK) {
        CloseHandle(gate);
        CloseHandle(done);
        fatal_infrastructure("create close-while-running worker");
    }

    expect_result(&c, host_thread_close(&thread), HOST_THREAD_OK,
                  "close a still-running thread");
    joined = -1;
    expect_result(&c, host_thread_join(&thread, 0, &joined),
                  HOST_THREAD_ERR_INVALID_STATE,
                  "join after close-while-running");

    /* Release the worker and wait for its own done event; never read the
     * host_thread handle again. */
    SetEvent(gate);
    if (WaitForSingleObject(done, PROBE_WAIT_MS) != WAIT_OBJECT_0) {
        fatal_infrastructure("close-while-running worker completion wait");
    }
    if (InterlockedCompareExchange(&worker.ran, 0, 0) != 1) {
        note(&c, "close-while-running worker body did not run");
    }

    CloseHandle(gate);
    CloseHandle(done);
    return c.failures;
}

int main(void)
{
    int real_failures;
    int negative_failures;
    int self_failures;
    int close_failures;

    real_failures = run_battery(&real_ops, 1, "real");
    if (real_failures != 0) {
        fprintf(stderr,
                "FAIL: the real host thread backend failed %d check(s)\n",
                real_failures);
        return 1;
    }

    negative_failures =
        run_behavioral_battery(&negative_ignore_wait_ops, 0,
                               "negative-join-ignores-wait");
    if (negative_failures == 0) {
        fprintf(stderr,
                "FAIL: the battery accepted 'negative-join-ignores-wait'\n");
        return 1;
    }
    printf("checked: 'negative-join-ignores-wait' rejected by %d check(s)\n",
           negative_failures);

    negative_failures =
        run_behavioral_battery(&negative_timeout_ops, 0,
                               "negative-join-always-times-out");
    if (negative_failures == 0) {
        fprintf(stderr,
                "FAIL: the battery accepted 'negative-join-always-times-out'\n");
        return 1;
    }
    printf("checked: 'negative-join-always-times-out' rejected by %d check(s)\n",
           negative_failures);

    self_failures = run_self_join_check();
    if (self_failures != 0) {
        fprintf(stderr, "FAIL: self-join check failed %d time(s)\n",
                self_failures);
        return 1;
    }

    close_failures = run_close_while_running_check();
    if (close_failures != 0) {
        fprintf(stderr, "FAIL: close-while-running check failed %d time(s)\n",
                close_failures);
        return 1;
    }

    printf("PASS: host thread lifecycle battery and 2 rejected negative "
           "backends\n");
    return 0;
}
