/* Host mutex + condition-variable probe (G1 synchronisation row).
 *
 * The battery is split so a deliberately-wrong backend is only ever rejected
 * by a check that exercises the behaviour it breaks, never by an unrelated
 * argument/lifecycle check:
 *
 *   - the LIFECYCLE battery runs against the real backend only;
 *   - the MUTEX battery (exclusion) runs against the real backend and the
 *     no-op-mutex fixture. That fixture never runs a condition variable, so
 *     it can never be used to release a mutex the caller does not hold;
 *   - the CONDITION-VARIABLE battery (wait/wake, broadcast, timeout) runs
 *     against the real backend and the condition fixtures. Every condition
 *     fixture uses a GENUINE mutex, so SleepConditionVariableSRW is always
 *     handed a real SRW lock and there is no undefined behaviour even for a
 *     wrong backend.
 *
 * Deterministic thread protocols (no sleep-only sequencing):
 *   - "the lock really blocks": the worker publishes a `ready` event, then
 *     attempts the lock. The main thread, holding the lock, waits for `ready`
 *     and only then opens a bounded window for the worker to enter. The
 *     window therefore measures exclusion, not thread-startup scheduling.
 *   - "a wait really blocks and a signal really wakes it": the worker takes
 *     the mutex and signals `started` BEFORE it waits, so the main thread
 *     cannot signal before the worker is blocked. The worker waits in a
 *     predicate loop, so a spurious wake is tolerated and the real wake is
 *     still observed.
 *   - "broadcast wakes every waiter": each worker registers under the mutex
 *     and then waits; the last registration lets the main thread proceed.
 *     A worker is only counted as woken when it observed the predicate from a
 *     NON-TIMEOUT wait, so a broadcast that wakes one waiter (or none) is
 *     rejected even though a timed-out worker would eventually see the
 *     predicate.
 *
 * The predicate contract is exercised, not a persistent wake: the timeout
 * probe expects HOST_SYNC_ERR_TIMEOUT, and an immediate-timeout backend is
 * rejected by a positive lower bound measured with an independent clock
 * (QueryPerformanceCounter), not by the wrapper's own bookkeeping.
 *
 * Infrastructure failures (event/thread creation, any bounded wait that
 * should succeed not completing) print FATAL and ExitProcess(1) before any
 * cleanup; they can never be counted as a rejected negative backend. Exit
 * status is the result; no PASS_REGULAR_EXPRESSION, no WILL_FAIL, no assert().
 */

#include "host_sync.h"

#include <windows.h>

#include <stdio.h>
#include <string.h>

#define PROBE_WAIT_MS 30000u
#define PROBE_BLOCK_WINDOW_MS 250u  /* window in which a held lock must block */
#define PROBE_SIGNAL_WAIT_MS 2000u  /* worker wait a real signal must end */
#define PROBE_BROADCAST_WAIT_MS 3000u
#define PROBE_TIMEOUT_MS 60u
#define PROBE_TIMEOUT_MIN_MS 30u    /* independent-clock lower bound */
#define PROBE_TIMEOUT_MAX_ATTEMPTS 1000
#define BROADCAST_WORKERS 3

static void fatal_infrastructure(const char *what)
{
    fprintf(stderr, "FATAL: probe infrastructure failed: %s\n", what);
    ExitProcess(1);
}

/* ---- backend seam ---------------------------------------------------- */

typedef struct sync_ops {
    const char *name;
    host_sync_result (*mutex_init)(host_mutex *);
    host_sync_result (*mutex_destroy)(host_mutex *);
    host_sync_result (*mutex_lock)(host_mutex *);
    host_sync_result (*mutex_unlock)(host_mutex *);
    host_sync_result (*cond_init)(host_cond *);
    host_sync_result (*cond_destroy)(host_cond *);
    host_sync_result (*cond_wait)(host_cond *, host_mutex *, uint32_t);
    host_sync_result (*cond_signal)(host_cond *);
    host_sync_result (*cond_broadcast)(host_cond *);
} sync_ops;

static const sync_ops real_ops = {
    "real",
    host_mutex_init,
    host_mutex_destroy,
    host_mutex_lock,
    host_mutex_unlock,
    host_cond_init,
    host_cond_destroy,
    host_cond_wait,
    host_cond_signal,
    host_cond_broadcast
};

/* lock/unlock do nothing: mutual exclusion is gone. Used ONLY by the mutex
 * battery, which never runs a condition variable. */
static host_sync_result negative_mutex_lock(host_mutex *mutex)
{
    (void)mutex;
    return HOST_SYNC_OK;
}

static host_sync_result negative_mutex_unlock(host_mutex *mutex)
{
    (void)mutex;
    return HOST_SYNC_OK;
}

static const sync_ops negative_mutex_noop_ops = {
    "negative-mutex-noop",
    host_mutex_init,
    host_mutex_destroy,
    negative_mutex_lock,
    negative_mutex_unlock,
    host_cond_init,
    host_cond_destroy,
    host_cond_wait,
    host_cond_signal,
    host_cond_broadcast
};

/* signals/broadcasts do nothing: no waiter is ever woken. Genuine mutex. */
static host_sync_result negative_signal_noop(host_cond *cond)
{
    (void)cond;
    return HOST_SYNC_OK;
}

static const sync_ops negative_signal_noop_ops = {
    "negative-cond-signal-noop",
    host_mutex_init,
    host_mutex_destroy,
    host_mutex_lock,
    host_mutex_unlock,
    host_cond_init,
    host_cond_destroy,
    host_cond_wait,
    negative_signal_noop,
    negative_signal_noop
};

/* broadcast wakes only ONE waiter: wake-all sensitivity is gone. Genuine
 * mutex, so the waiters remain well-defined. */
static host_sync_result negative_broadcast_as_signal(host_cond *cond)
{
    return host_cond_signal(cond);
}

static const sync_ops negative_broadcast_as_signal_ops = {
    "negative-cond-broadcast-as-signal",
    host_mutex_init,
    host_mutex_destroy,
    host_mutex_lock,
    host_mutex_unlock,
    host_cond_init,
    host_cond_destroy,
    host_cond_wait,
    host_cond_signal,
    negative_broadcast_as_signal
};

/* wait always times out immediately, ignoring any signal. Genuine mutex. */
static host_sync_result negative_wait_timeout(host_cond *cond,
                                              host_mutex *mutex,
                                              uint32_t timeout_ms)
{
    (void)timeout_ms;
    /* Still release and reacquire the mutex so the protocol cannot deadlock:
     * this is the "wait that returns without observing the wake" defect. */
    return host_cond_wait(cond, mutex, 0);
}

static const sync_ops negative_wait_timeout_ops = {
    "negative-cond-wait-times-out",
    host_mutex_init,
    host_mutex_destroy,
    host_mutex_lock,
    host_mutex_unlock,
    host_cond_init,
    host_cond_destroy,
    negative_wait_timeout,
    host_cond_signal,
    host_cond_broadcast
};

/* ---- check bookkeeping ----------------------------------------------- */

typedef struct checks {
    const char *label;
    int explain;
    int failures;
} checks;

static void expect_result(checks *c, host_sync_result got,
                          host_sync_result want, const char *what)
{
    if (got != want) {
        c->failures++;
        if (c->explain) {
            fprintf(stderr, "[%s] FAIL: %s returned %d, want %d\n", c->label,
                    what, (int)got, (int)want);
        }
    }
}

static void note(checks *c, const char *what)
{
    c->failures++;
    if (c->explain) {
        fprintf(stderr, "[%s] FAIL: %s\n", c->label, what);
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

static void wait_or_fatal(HANDLE event, DWORD timeout_ms, const char *what)
{
    if (WaitForSingleObject(event, timeout_ms) != WAIT_OBJECT_0) {
        fatal_infrastructure(what);
    }
}

static void start_worker(HANDLE *thread, LPTHREAD_START_ROUTINE entry, void *arg)
{
    *thread = CreateThread(NULL, 0, entry, arg, 0, NULL);
    if (*thread == NULL) {
        fatal_infrastructure("CreateThread");
    }
}

static void join_worker(HANDLE thread)
{
    if (WaitForSingleObject(thread, PROBE_WAIT_MS) != WAIT_OBJECT_0) {
        fatal_infrastructure("worker join wait");
    }
    CloseHandle(thread);
}

/* ---- mutex battery: exclusion ---------------------------------------- */

typedef struct mutex_ctx {
    const sync_ops *ops;
    host_mutex *mutex;
    HANDLE ready;   /* set immediately BEFORE the lock attempt */
    HANDLE entered; /* set immediately AFTER the lock returns */
    HANDLE done;
} mutex_ctx;

static DWORD WINAPI mutex_worker(LPVOID arg)
{
    mutex_ctx *c = (mutex_ctx *)arg;

    SetEvent(c->ready);
    if (c->ops->mutex_lock(c->mutex) != HOST_SYNC_OK) {
        fatal_infrastructure("worker lock");
    }
    SetEvent(c->entered);
    if (c->ops->mutex_unlock(c->mutex) != HOST_SYNC_OK) {
        fatal_infrastructure("worker unlock");
    }
    SetEvent(c->done);
    return 0;
}

static void run_mutex_exclusion(checks *c, const sync_ops *ops)
{
    host_mutex mutex;
    mutex_ctx ctx;
    HANDLE thread;
    DWORD waited;

    memset(&mutex, 0, sizeof(mutex));
    memset(&ctx, 0, sizeof(ctx));
    if (ops->mutex_init(&mutex) != HOST_SYNC_OK) {
        fatal_infrastructure("mutex init");
    }
    ctx.ops = ops;
    ctx.mutex = &mutex;
    ctx.ready = make_event();
    ctx.entered = make_event();
    ctx.done = make_event();

    if (ops->mutex_lock(&mutex) != HOST_SYNC_OK) {
        fatal_infrastructure("main lock");
    }
    start_worker(&thread, mutex_worker, &ctx);

    /* The worker is known to be attempting the lock before the window opens,
     * so a timed-out window proves exclusion, not slow thread startup. */
    wait_or_fatal(ctx.ready, PROBE_WAIT_MS, "worker readiness");
    waited = WaitForSingleObject(ctx.entered, PROBE_BLOCK_WINDOW_MS);
    if (waited != WAIT_TIMEOUT) {
        note(c, "a worker entered a mutex the main thread was holding");
    }

    if (ops->mutex_unlock(&mutex) != HOST_SYNC_OK) {
        fatal_infrastructure("main unlock");
    }
    wait_or_fatal(ctx.done, PROBE_WAIT_MS, "blocked worker completion");
    join_worker(thread);

    expect_result(c, ops->mutex_destroy(&mutex), HOST_SYNC_OK,
                  "mutex destroy after lock phase");
    CloseHandle(ctx.ready);
    CloseHandle(ctx.entered);
    CloseHandle(ctx.done);
}

/* ---- condition-variable battery -------------------------------------- */

/* wait/wake: the worker holds the mutex until it is inside cond_wait and only
 * then can the main thread set the predicate and signal. The worker loops on
 * the predicate, so a spurious wake does not make the check flaky and does
 * not mask a missing real wake. */
typedef struct wait_ctx {
    const sync_ops *ops;
    host_mutex *mutex;
    host_cond *cond;
    HANDLE started;
    HANDLE done;
    int *predicate;
    int observed;
    int timed_out;
} wait_ctx;

static DWORD WINAPI wait_worker(LPVOID arg)
{
    wait_ctx *c = (wait_ctx *)arg;
    host_sync_result r = HOST_SYNC_OK;

    if (c->ops->mutex_lock(c->mutex) != HOST_SYNC_OK) {
        fatal_infrastructure("worker lock");
    }
    SetEvent(c->started); /* set while the mutex is held */
    while (*c->predicate == 0) {
        r = c->ops->cond_wait(c->cond, c->mutex, PROBE_SIGNAL_WAIT_MS);
        if (r == HOST_SYNC_ERR_TIMEOUT) {
            c->timed_out = 1;
            break;
        }
        if (r != HOST_SYNC_OK) {
            fatal_infrastructure("worker cond_wait platform failure");
        }
    }
    c->observed = (*c->predicate != 0);
    if (c->ops->mutex_unlock(c->mutex) != HOST_SYNC_OK) {
        fatal_infrastructure("worker unlock");
    }
    SetEvent(c->done);
    return 0;
}

static void run_wait_wakes(checks *c, const sync_ops *ops)
{
    host_mutex mutex;
    host_cond cond;
    wait_ctx ctx;
    HANDLE thread;
    int predicate = 0;

    memset(&mutex, 0, sizeof(mutex));
    memset(&cond, 0, sizeof(cond));
    memset(&ctx, 0, sizeof(ctx));
    if (ops->mutex_init(&mutex) != HOST_SYNC_OK ||
        ops->cond_init(&cond) != HOST_SYNC_OK) {
        fatal_infrastructure("mutex/cond init");
    }
    ctx.ops = ops;
    ctx.mutex = &mutex;
    ctx.cond = &cond;
    ctx.started = make_event();
    ctx.done = make_event();
    ctx.predicate = &predicate;

    start_worker(&thread, wait_worker, &ctx);
    wait_or_fatal(ctx.started, PROBE_WAIT_MS, "worker started wait");

    /* The worker holds the mutex until it is inside cond_wait. */
    if (ops->mutex_lock(&mutex) != HOST_SYNC_OK) {
        fatal_infrastructure("main lock");
    }
    predicate = 1;
    if (ops->cond_signal(&cond) != HOST_SYNC_OK) {
        note(c, "cond_signal reported failure");
    }
    if (ops->mutex_unlock(&mutex) != HOST_SYNC_OK) {
        fatal_infrastructure("main unlock");
    }

    wait_or_fatal(ctx.done, PROBE_WAIT_MS, "woken worker completion");
    if (ctx.timed_out) {
        note(c, "a signalled waiter timed out instead of waking");
    } else if (!ctx.observed) {
        note(c, "a signalled waiter did not observe the predicate");
    }

    join_worker(thread);
    expect_result(c, ops->cond_destroy(&cond), HOST_SYNC_OK,
                  "cond destroy after wait phase");
    expect_result(c, ops->mutex_destroy(&mutex), HOST_SYNC_OK,
                  "mutex destroy after wait phase");
    CloseHandle(ctx.started);
    CloseHandle(ctx.done);
}

/* broadcast: every worker registers under the mutex and then waits; the last
 * registration lets the main thread set the predicate and broadcast. A worker
 * counts as woken only when it observed the predicate from a non-timeout
 * wait, so a broadcast that wakes one (or none) is rejected. */
typedef struct broadcast_ctx {
    const sync_ops *ops;
    host_mutex *mutex;
    host_cond *cond;
    HANDLE all_started;
    HANDLE done;
    LONG *registered;
    int *predicate;
    int observed;
    int timed_out;
} broadcast_ctx;

static DWORD WINAPI broadcast_worker(LPVOID arg)
{
    broadcast_ctx *c = (broadcast_ctx *)arg;
    host_sync_result r = HOST_SYNC_OK;

    if (c->ops->mutex_lock(c->mutex) != HOST_SYNC_OK) {
        fatal_infrastructure("worker lock");
    }
    if (InterlockedIncrement(c->registered) == BROADCAST_WORKERS) {
        SetEvent(c->all_started);
    }
    while (*c->predicate == 0) {
        r = c->ops->cond_wait(c->cond, c->mutex, PROBE_BROADCAST_WAIT_MS);
        if (r == HOST_SYNC_ERR_TIMEOUT) {
            c->timed_out = 1;
            break;
        }
        if (r != HOST_SYNC_OK) {
            fatal_infrastructure("worker cond_wait platform failure");
        }
    }
    c->observed = (*c->predicate != 0);
    if (c->ops->mutex_unlock(c->mutex) != HOST_SYNC_OK) {
        fatal_infrastructure("worker unlock");
    }
    SetEvent(c->done);
    return 0;
}

static void run_broadcast(checks *c, const sync_ops *ops)
{
    host_mutex mutex;
    host_cond cond;
    broadcast_ctx contexts[BROADCAST_WORKERS];
    HANDLE threads[BROADCAST_WORKERS];
    LONG registered = 0;
    int predicate = 0;
    HANDLE all_started;
    int i;

    memset(&mutex, 0, sizeof(mutex));
    memset(&cond, 0, sizeof(cond));
    if (ops->mutex_init(&mutex) != HOST_SYNC_OK ||
        ops->cond_init(&cond) != HOST_SYNC_OK) {
        fatal_infrastructure("mutex/cond init");
    }
    all_started = make_event();

    for (i = 0; i < BROADCAST_WORKERS; i++) {
        memset(&contexts[i], 0, sizeof(contexts[i]));
        contexts[i].ops = ops;
        contexts[i].mutex = &mutex;
        contexts[i].cond = &cond;
        contexts[i].all_started = all_started;
        contexts[i].done = make_event();
        contexts[i].registered = &registered;
        contexts[i].predicate = &predicate;
        start_worker(&threads[i], broadcast_worker, &contexts[i]);
    }

    wait_or_fatal(all_started, PROBE_WAIT_MS, "all-start registration wait");

    if (ops->mutex_lock(&mutex) != HOST_SYNC_OK) {
        fatal_infrastructure("main lock");
    }
    predicate = 1;
    if (ops->cond_broadcast(&cond) != HOST_SYNC_OK) {
        note(c, "cond_broadcast reported failure");
    }
    if (ops->mutex_unlock(&mutex) != HOST_SYNC_OK) {
        fatal_infrastructure("main unlock");
    }

    for (i = 0; i < BROADCAST_WORKERS; i++) {
        wait_or_fatal(contexts[i].done, PROBE_WAIT_MS,
                      "broadcast worker completion wait");
        if (contexts[i].timed_out) {
            note(c, "a broadcast waiter timed out instead of waking");
        } else if (!contexts[i].observed) {
            note(c, "a broadcast waiter did not observe the predicate");
        }
        join_worker(threads[i]);
        CloseHandle(contexts[i].done);
    }

    expect_result(c, ops->cond_destroy(&cond), HOST_SYNC_OK,
                  "cond destroy after broadcast");
    expect_result(c, ops->mutex_destroy(&mutex), HOST_SYNC_OK,
                  "mutex destroy after broadcast");
    CloseHandle(all_started);
}

/* A wait with no signal must reach a real deadline (measured with an
 * independent clock, so an immediate-timeout backend is rejected), and a
 * signal sent with no waiter must not be remembered. The predicate loop
 * tolerates spurious wakes. */
static void timed_wait_must_timeout(checks *c, const sync_ops *ops,
                                    host_mutex *mutex, host_cond *cond,
                                    const char *what, int require_lower_bound)
{
    LARGE_INTEGER frequency;
    LARGE_INTEGER start;
    LARGE_INTEGER end;
    double elapsed_ms;
    int attempts = 0;

    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);
    for (;;) {
        host_sync_result r = ops->cond_wait(cond, mutex, PROBE_TIMEOUT_MS);
        if (r == HOST_SYNC_ERR_TIMEOUT) {
            break;
        }
        if (r != HOST_SYNC_OK) {
            note(c, what);
            return;
        }
        /* A spurious wake is allowed, but not an unbounded stream of them. */
        if (++attempts >= PROBE_TIMEOUT_MAX_ATTEMPTS) {
            note(c, "a wait never reached its deadline");
            return;
        }
    }
    QueryPerformanceCounter(&end);
    elapsed_ms = (double)(end.QuadPart - start.QuadPart) * 1000.0 /
                 (double)frequency.QuadPart;
    if (require_lower_bound && elapsed_ms < (double)PROBE_TIMEOUT_MIN_MS) {
        note(c, "a timed wait returned far too early (no real timeout)");
    }
}

static void run_timeout_and_nonpersistence(checks *c, const sync_ops *ops)
{
    host_mutex mutex;
    host_cond cond;

    memset(&mutex, 0, sizeof(mutex));
    memset(&cond, 0, sizeof(cond));
    if (ops->mutex_init(&mutex) != HOST_SYNC_OK ||
        ops->cond_init(&cond) != HOST_SYNC_OK) {
        fatal_infrastructure("mutex/cond init");
    }

    if (ops->mutex_lock(&mutex) != HOST_SYNC_OK) {
        fatal_infrastructure("main lock");
    }
    timed_wait_must_timeout(c, ops, &mutex, &cond,
                            "timed wait with no signal", 1);

    /* Signal with no waiter: the wake is not stored, so the next wait still
     * times out. */
    if (ops->cond_signal(&cond) != HOST_SYNC_OK) {
        note(c, "cond_signal reported failure");
    }
    timed_wait_must_timeout(c, ops, &mutex, &cond,
                            "wait after a signal with no waiter", 0);
    if (ops->mutex_unlock(&mutex) != HOST_SYNC_OK) {
        fatal_infrastructure("main unlock");
    }

    expect_result(c, ops->cond_destroy(&cond), HOST_SYNC_OK,
                  "cond destroy after timeout phase");
    expect_result(c, ops->mutex_destroy(&mutex), HOST_SYNC_OK,
                  "mutex destroy after timeout phase");
}

/* ---- lifecycle battery (real backend only) --------------------------- */

static void run_lifecycle_checks(checks *c, const sync_ops *ops)
{
    host_mutex mutex;
    host_cond cond;

    memset(&mutex, 0, sizeof(mutex));
    memset(&cond, 0, sizeof(cond));

    /* NULL arguments. */
    expect_result(c, ops->mutex_init(NULL), HOST_SYNC_ERR_INVALID_ARGUMENT,
                  "mutex_init(NULL)");
    expect_result(c, ops->mutex_destroy(NULL),
                  HOST_SYNC_ERR_INVALID_ARGUMENT, "mutex_destroy(NULL)");
    expect_result(c, ops->mutex_lock(NULL), HOST_SYNC_ERR_INVALID_ARGUMENT,
                  "mutex_lock(NULL)");
    expect_result(c, ops->mutex_unlock(NULL), HOST_SYNC_ERR_INVALID_ARGUMENT,
                  "mutex_unlock(NULL)");
    expect_result(c, ops->cond_init(NULL), HOST_SYNC_ERR_INVALID_ARGUMENT,
                  "cond_init(NULL)");
    expect_result(c, ops->cond_destroy(NULL), HOST_SYNC_ERR_INVALID_ARGUMENT,
                  "cond_destroy(NULL)");
    expect_result(c, ops->cond_signal(NULL), HOST_SYNC_ERR_INVALID_ARGUMENT,
                  "cond_signal(NULL)");
    expect_result(c, ops->cond_broadcast(NULL), HOST_SYNC_ERR_INVALID_ARGUMENT,
                  "cond_broadcast(NULL)");
    expect_result(c, ops->cond_wait(NULL, &mutex, 0),
                  HOST_SYNC_ERR_INVALID_ARGUMENT, "cond_wait(NULL)");
    expect_result(c, ops->cond_wait(&cond, NULL, 0),
                  HOST_SYNC_ERR_INVALID_ARGUMENT, "cond_wait(NULL mutex)");

    /* Uninitialised handles. */
    expect_result(c, ops->mutex_lock(&mutex), HOST_SYNC_ERR_INVALID_STATE,
                  "mutex_lock(uninitialised)");
    expect_result(c, ops->cond_wait(&cond, &mutex, 0),
                  HOST_SYNC_ERR_INVALID_STATE, "cond_wait(uninitialised)");
    expect_result(c, ops->cond_signal(&cond), HOST_SYNC_ERR_INVALID_STATE,
                  "cond_signal(uninitialised)");

    /* init, double init, destroy, use-after-destroy. */
    expect_result(c, ops->mutex_init(&mutex), HOST_SYNC_OK, "mutex_init");
    expect_result(c, ops->mutex_init(&mutex), HOST_SYNC_ERR_INVALID_STATE,
                  "mutex_init twice");
    expect_result(c, ops->cond_init(&cond), HOST_SYNC_OK, "cond_init");
    expect_result(c, ops->cond_init(&cond), HOST_SYNC_ERR_INVALID_STATE,
                  "cond_init twice");

    expect_result(c, ops->cond_destroy(&cond), HOST_SYNC_OK, "cond_destroy");
    expect_result(c, ops->cond_destroy(&cond), HOST_SYNC_ERR_INVALID_STATE,
                  "cond_destroy twice");
    expect_result(c, ops->cond_signal(&cond), HOST_SYNC_ERR_INVALID_STATE,
                  "cond_signal after destroy");
    expect_result(c, ops->cond_broadcast(&cond), HOST_SYNC_ERR_INVALID_STATE,
                  "cond_broadcast after destroy");

    expect_result(c, ops->mutex_destroy(&mutex), HOST_SYNC_OK, "mutex_destroy");
    expect_result(c, ops->mutex_destroy(&mutex), HOST_SYNC_ERR_INVALID_STATE,
                  "mutex_destroy twice");
    expect_result(c, ops->mutex_lock(&mutex), HOST_SYNC_ERR_INVALID_STATE,
                  "mutex_lock after destroy");
    expect_result(c, ops->mutex_unlock(&mutex), HOST_SYNC_ERR_INVALID_STATE,
                  "mutex_unlock after destroy");

    /* destroy() then init() again must produce a fresh usable handle. */
    expect_result(c, ops->mutex_init(&mutex), HOST_SYNC_OK,
                  "mutex re-init after destroy");
    expect_result(c, ops->mutex_lock(&mutex), HOST_SYNC_OK,
                  "mutex re-lock after re-init");
    expect_result(c, ops->mutex_unlock(&mutex), HOST_SYNC_OK,
                  "mutex re-unlock after re-init");
    expect_result(c, ops->mutex_destroy(&mutex), HOST_SYNC_OK,
                  "mutex re-destroy");
    expect_result(c, ops->cond_init(&cond), HOST_SYNC_OK,
                  "cond re-init after destroy");
    expect_result(c, ops->cond_destroy(&cond), HOST_SYNC_OK,
                  "cond re-destroy");
}

/* ---- drivers --------------------------------------------------------- */

static int run_lifecycle_battery(void)
{
    checks c;

    c.label = "real";
    c.explain = 1;
    c.failures = 0;
    run_lifecycle_checks(&c, &real_ops);
    return c.failures;
}

static int run_mutex_battery(const sync_ops *ops, int explain,
                             const char *label)
{
    checks c;

    c.label = label;
    c.explain = explain;
    c.failures = 0;
    run_mutex_exclusion(&c, ops);
    return c.failures;
}

static int run_cv_battery(const sync_ops *ops, int explain, const char *label)
{
    checks c;

    c.label = label;
    c.explain = explain;
    c.failures = 0;
    run_wait_wakes(&c, ops);
    run_broadcast(&c, ops);
    run_timeout_and_nonpersistence(&c, ops);
    return c.failures;
}

static void require_rejected(int failures, const char *label)
{
    if (failures == 0) {
        fprintf(stderr, "FAIL: the battery accepted '%s'\n", label);
        ExitProcess(1);
    }
    printf("checked: '%s' rejected by %d check(s)\n", label, failures);
}

int main(void)
{
    int failures;

    failures = run_lifecycle_battery();
    if (failures != 0) {
        fprintf(stderr, "FAIL: the real sync lifecycle battery failed %d "
                "check(s)\n", failures);
        return 1;
    }

    failures = run_mutex_battery(&real_ops, 1, "real");
    if (failures != 0) {
        fprintf(stderr, "FAIL: the real mutex battery failed %d check(s)\n",
                failures);
        return 1;
    }

    failures = run_cv_battery(&real_ops, 1, "real");
    if (failures != 0) {
        fprintf(stderr, "FAIL: the real condition-variable battery failed %d "
                "check(s)\n", failures);
        return 1;
    }

    require_rejected(run_mutex_battery(&negative_mutex_noop_ops, 0,
                                       "negative-mutex-noop"),
                     "negative-mutex-noop");
    require_rejected(run_cv_battery(&negative_signal_noop_ops, 0,
                                    "negative-cond-signal-noop"),
                     "negative-cond-signal-noop");
    require_rejected(run_cv_battery(&negative_broadcast_as_signal_ops, 0,
                                    "negative-cond-broadcast-as-signal"),
                     "negative-cond-broadcast-as-signal");
    require_rejected(run_cv_battery(&negative_wait_timeout_ops, 0,
                                    "negative-cond-wait-times-out"),
                     "negative-cond-wait-times-out");

    printf("PASS: host mutex/condition batteries and 4 rejected negative "
           "backends\n");
    return 0;
}
