/* Host TLS slot probe (G1 TLS row).
 *
 * One battery, two kinds of backend:
 *
 *   1. the real backend from src/host_tls.c, which must pass every check;
 *   2. fixture-only deliberately-wrong backends, each of which the SAME
 *      battery must reject. They live in this test executable only: the
 *      product header exposes no hook, callback or injection point.
 *
 * Coverage:
 *   - explicit lifecycle (init / create / destroy / init again) and its
 *     rejects: NULL arguments, create-before-init, create twice, init on a
 *     live slot, get/set/destroy on a dead slot;
 *   - output-intact-on-failure (a sentinel stays put whenever a call fails);
 *   - initial value NULL, set, replace, clear with NULL, on several slots;
 *   - two and four simultaneously live slots stay independent;
 *   - real Windows threads (CreateThread in this fixture only) with event
 *     based phase gates: the main thread and two workers each hold a
 *     distinct value at the same time, each observes only its own value,
 *     and a replacement or a clear in one thread does not disturb the
 *     others;
 *   - thread-exit leakage, measured in two steps: a writer thread stores a
 *     value and exits WITHOUT clearing it, then a brand-new reader thread is
 *     started on the same live slot and must observe NULL (and must not
 *     disturb the parent's value);
 *   - several rounds of that protocol;
 *   - whether a real slot actually received native index 0. That is
 *     reported as observed evidence, never forced and never assumed.
 *
 * Synchronisation discipline: every phase completes through a manual-reset
 * event, so no sleep makes a phase deterministic and every wait is bounded
 * (PROBE_WAIT_MS). Per-thread results are read only after
 * WaitForSingleObject has confirmed the join.
 *
 * Infrastructure failure discipline: if a thread cannot be created or does
 * not finish inside the bounded wait, the round cannot prove anything and
 * the harness itself is in an unknown state (a worker may still be running
 * on this frame's participants, slot or gates). The process therefore
 * terminates immediately with ExitProcess(1) — no gate/handle is closed and
 * no participant memory is read after a failed join. A harness failure can
 * therefore never be reported as "the negative backend was rejected"; the
 * probe test just fails.
 *
 * The negative backends must not add C data races of their own:
 *   - the "process-global per-slot storage" backend keeps its values in a
 *     fixture-owned table guarded by an SRWLOCK, so every access is
 *     serialised;
 *   - the "all slots alias one storage" backend stores through a single real
 *     TlsAlloc index, so its accesses are per-thread by construction;
 *   - the remaining negatives are thin wrappers over the real calls.
 * Their first deterministic defect is visible in the sequential phase for
 * the aliasing/clear/clobber/NULL negatives, and in the threaded phase for
 * the process-global one (which deliberately passes the single-threaded
 * checks, so it proves the isolation checks are sensitive rather than
 * relying on the slot-independence check).
 *
 * Exit status is the result. No PASS_REGULAR_EXPRESSION, no WILL_FAIL, and no
 * assert(): the checks are ordinary code compiled identically in Debug and
 * Release.
 */

#include "host_tls.h"

#include <windows.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define PROBE_WAIT_MS 30000u
#define PROBE_ROUNDS 8
#define PROBE_ROUNDS_NEGATIVE 2
#define PROBE_WORKERS 2
#define PROBE_PARTICIPANTS (1 + PROBE_WORKERS)
#define PROBE_GATES 5

/* A value that is never stored through the API; used to prove that a failed
 * call leaves the caller's output alone. */
#define PROBE_SENTINEL ((void *)(uintptr_t)0x5EADBEEF5EADBEEFull)

/* ---- backend seam used by the battery -------------------------------- */

typedef struct tls_ops {
    const char *name;
    host_tls_result (*init)(host_tls_slot *slot);
    host_tls_result (*create)(host_tls_slot *slot);
    host_tls_result (*destroy)(host_tls_slot *slot);
    host_tls_result (*get)(const host_tls_slot *slot, void **out_value);
    host_tls_result (*set)(host_tls_slot *slot, void *value);
} tls_ops;

typedef struct checks {
    const char *label;
    int explain;         /* print each failing check (real backend only) */
    int in_thread_phase; /* routes failures to the phase counter below */
    int single_failures; /* sequential (single-threaded) battery phase */
    int thread_failures; /* real-thread isolation phase */
    int zero_index_seen;
    uint32_t first_native_index; /* native index of the first created slot */
} checks;

/* Distinct, never-freed storage so a stored pointer is recognisable. */
static int probe_value_a;
static int probe_value_b;
static int probe_value_c;
static int probe_value_replaced;
static int probe_value_writer;
static int probe_value_fresh;
static int probe_value_many[4];
static int probe_value_round[PROBE_PARTICIPANTS];

/* ---- infrastructure failure: stop the process now -------------------- */

static void fatal_infrastructure(const char *what)
{
    fprintf(stderr, "FATAL: probe infrastructure failed: %s\n", what);
    /* Threads may still be running on this frame's participants, slot and
     * gates, and an event may still have a pending wait, so nothing is
     * cleaned up and no result is read: leave the process immediately. */
    ExitProcess(1);
}

/* ---- check helpers --------------------------------------------------- */

static void fail_count(checks *c)
{
    if (c->in_thread_phase) {
        c->thread_failures++;
    } else {
        c->single_failures++;
    }
}

static void note_failure(checks *c, const char *what)
{
    fail_count(c);
    if (c->explain) {
        fprintf(stderr, "[%s] FAIL: %s\n", c->label, what);
    }
}

static void expect_result(checks *c, host_tls_result got, host_tls_result want,
                          const char *what)
{
    if (want == HOST_TLS_OK && got == HOST_TLS_ERR_ALLOCATION) {
        /* No fixture backend injects an allocation failure, so this can only
         * mean the process really ran out of native TLS indices. That is
         * harness infrastructure, never a behavioural rejection of a fake,
         * and the round cannot be interpreted: stop now. */
        fatal_infrastructure("a native TLS index allocation failed where success "
                             "was required");
    }
    if (got != want) {
        fail_count(c);
        if (c->explain) {
            fprintf(stderr, "[%s] FAIL: %s returned %d, want %d\n", c->label,
                    what, (int)got, (int)want);
        }
    }
}

static void expect_value(checks *c, const tls_ops *ops,
                         const host_tls_slot *slot, void *want,
                         const char *what)
{
    void *out = PROBE_SENTINEL;
    host_tls_result rc = ops->get(slot, &out);

    if (rc != HOST_TLS_OK) {
        fail_count(c);
        if (c->explain) {
            fprintf(stderr, "[%s] FAIL: %s returned %d, want %d\n", c->label,
                    what, (int)rc, (int)HOST_TLS_OK);
        }
        return;
    }
    if (out != want) {
        fail_count(c);
        if (c->explain) {
            fprintf(stderr, "[%s] FAIL: %s returned %p, want %p\n", c->label,
                    what, out, want);
        }
    }
}

static void expect_rejected_get(checks *c, const tls_ops *ops,
                                const host_tls_slot *slot,
                                host_tls_result want, const char *what)
{
    void *out = PROBE_SENTINEL;
    host_tls_result rc = ops->get(slot, &out);

    if (rc != want) {
        fail_count(c);
        if (c->explain) {
            fprintf(stderr, "[%s] FAIL: %s returned %d, want %d\n", c->label,
                    what, (int)rc, (int)want);
        }
    }
    if (out != PROBE_SENTINEL) {
        fail_count(c);
        if (c->explain) {
            fprintf(stderr, "[%s] FAIL: %s clobbered the output on failure "
                            "(got %p, sentinel was %p)\n",
                    c->label, what, out, PROBE_SENTINEL);
        }
    }
}

/* A failing lifecycle call must leave the handle exactly as it was. Only the
 * two diagnostic fields are read; the handle itself is never copied. */
static void expect_handle_unchanged(checks *c, const host_tls_slot *slot,
                                    uint32_t before_index,
                                    uint32_t before_state, const char *what)
{
    if (slot->native_index != before_index || slot->state != before_state) {
        fail_count(c);
        if (c->explain) {
            fprintf(stderr, "[%s] FAIL: %s modified the handle "
                            "(index %u->%u, state 0x%08X->0x%08X)\n",
                    c->label, what, (unsigned)before_index,
                    (unsigned)slot->native_index, (unsigned)before_state,
                    (unsigned)slot->state);
        }
    }
}

/* ---- phase gate: deterministic, bounded, no sleeps ------------------- */

typedef struct phase_gate {
    HANDLE release;
    LONG participants;
    LONG arrivals;
} phase_gate;

static int phase_gate_open(phase_gate *gate, LONG participants)
{
    gate->release = CreateEventW(NULL, TRUE, FALSE, NULL);
    gate->participants = participants;
    gate->arrivals = 0;
    return gate->release != NULL;
}

static void phase_gate_close(phase_gate *gate)
{
    if (gate->release != NULL) {
        CloseHandle(gate->release);
        gate->release = NULL;
    }
}

/* Single-use barrier: every participant arrives, then all proceed. A
 * timeout is an infrastructure failure: the peer threads may still be
 * blocked on this event, so the process cannot continue safely. */
static void phase_gate_wait(phase_gate *gate)
{
    if (gate->release == NULL) {
        fatal_infrastructure("phase gate event was not created");
    }
    if (InterlockedIncrement(&gate->arrivals) == gate->participants) {
        (void)SetEvent(gate->release);
    }
    if (WaitForSingleObject(gate->release, PROBE_WAIT_MS) != WAIT_OBJECT_0) {
        fatal_infrastructure("a phase gate timed out");
    }
}

typedef struct round_participant {
    const tls_ops *ops;
    host_tls_slot *slot; /* participants may also set(), so not const */
    void *own_value;
    void *replaced_value; /* only the main participant uses this */
    phase_gate *gates;    /* PROBE_GATES entries */
    /* Results below are written by this thread only, and read by the main
     * thread only after this thread has been joined. */
    int api_ok;
    int initial_null_ok;
    int own_value_ok;
    int after_replace_ok;
    int clear_ok;
    int clear_isolated_ok;
} round_participant;

static void participant_init(round_participant *p, const tls_ops *ops,
                             host_tls_slot *slot, void *own_value,
                             phase_gate *gates)
{
    memset(p, 0, sizeof *p);
    p->ops = ops;
    p->slot = slot;
    p->own_value = own_value;
    p->gates = gates;
    p->api_ok = 1;
}

static DWORD WINAPI round_worker(LPVOID param)
{
    round_participant *p = (round_participant *)param;
    void *out;

    /* A brand-new OS thread must see the slot as empty. */
    out = PROBE_SENTINEL;
    if (p->ops->get(p->slot, &out) == HOST_TLS_OK && out == NULL) {
        p->initial_null_ok = 1;
    }

    if (p->ops->set(p->slot, p->own_value) != HOST_TLS_OK) {
        p->api_ok = 0;
    }
    phase_gate_wait(&p->gates[0]);

    /* Every participant has stored a value by now: only ours may be seen. */
    out = PROBE_SENTINEL;
    if (p->ops->get(p->slot, &out) == HOST_TLS_OK && out == p->own_value) {
        p->own_value_ok = 1;
    }
    phase_gate_wait(&p->gates[1]);

    /* The main participant replaces its own value in this phase. */
    phase_gate_wait(&p->gates[2]);

    out = PROBE_SENTINEL;
    if (p->ops->get(p->slot, &out) == HOST_TLS_OK && out == p->own_value) {
        p->after_replace_ok = 1;
    }
    phase_gate_wait(&p->gates[3]);

    /* Clearing our own value must not disturb the other threads. */
    if (p->ops->set(p->slot, NULL) != HOST_TLS_OK) {
        p->api_ok = 0;
    }
    phase_gate_wait(&p->gates[4]);

    out = PROBE_SENTINEL;
    if (p->ops->get(p->slot, &out) == HOST_TLS_OK && out == NULL) {
        p->clear_ok = 1;
    }
    return 0;
}

/* Stores a value and exits WITHOUT clearing it. */
static DWORD WINAPI writer_thread_main(LPVOID param)
{
    round_participant *p = (round_participant *)param;

    if (p->ops->set(p->slot, p->own_value) != HOST_TLS_OK) {
        p->api_ok = 0;
    }
    return 0;
}

/* Started only after the writer has been joined: the same live slot must
 * look empty to it. Read-only, so the parent's value must stay untouched. */
static DWORD WINAPI fresh_reader_main(LPVOID param)
{
    round_participant *p = (round_participant *)param;
    void *out = PROBE_SENTINEL;

    if (p->ops->get(p->slot, &out) == HOST_TLS_OK && out == NULL) {
        p->initial_null_ok = 1;
    }
    return 0;
}

/* Run one short-lived probe thread and join it. Any failure is an
 * infrastructure failure: the process stops before anything is cleaned up. */
static void run_thread_and_join(round_participant *p,
                                LPTHREAD_START_ROUTINE body,
                                const char *what)
{
    HANDLE handle = CreateThread(NULL, 0, body, p, 0, NULL);

    if (handle == NULL) {
        fatal_infrastructure(what);
    }
    if (WaitForSingleObject(handle, PROBE_WAIT_MS) != WAIT_OBJECT_0) {
        fatal_infrastructure(what);
    }
    CloseHandle(handle);
}

/* One round of the real-thread protocol. It reports check failures through
 * `c`; infrastructure failures terminate the process (see the file header). */
static void run_thread_round(checks *c, const tls_ops *ops)
{
    host_tls_slot slot;
    round_participant parts[PROBE_PARTICIPANTS];
    phase_gate gates[PROBE_GATES];
    HANDLE threads[PROBE_WORKERS];
    unsigned i;
    void *out;

    memset(&slot, 0, sizeof slot);
    memset(gates, 0, sizeof gates);
    memset(threads, 0, sizeof threads);

    /* Failures from here on belong to the thread-isolation phase. */
    c->in_thread_phase = 1;

    expect_result(c, ops->init(&slot), HOST_TLS_OK, "round init()");
    expect_result(c, ops->create(&slot), HOST_TLS_OK, "round create()");
    if (slot.native_index == 0) {
        c->zero_index_seen = 1;
    }

    for (i = 0; i < PROBE_GATES; i++) {
        if (!phase_gate_open(&gates[i], (LONG)PROBE_PARTICIPANTS)) {
            fatal_infrastructure("CreateEvent failed for a phase gate");
        }
    }
    for (i = 0; i < PROBE_PARTICIPANTS; i++) {
        participant_init(&parts[i], ops, &slot, &probe_value_round[i], gates);
    }
    parts[0].replaced_value = &probe_value_replaced;

    /* Main participates inline as participant 0: its own value must be
     * empty on the freshly created slot. */
    out = PROBE_SENTINEL;
    if (ops->get(&slot, &out) == HOST_TLS_OK && out == NULL) {
        parts[0].initial_null_ok = 1;
    }

    for (i = 0; i < PROBE_WORKERS; i++) {
        threads[i] = CreateThread(NULL, 0, round_worker, &parts[i + 1], 0, NULL);
        if (threads[i] == NULL) {
            fatal_infrastructure("CreateThread failed for a worker");
        }
    }

    if (ops->set(&slot, parts[0].own_value) != HOST_TLS_OK) {
        parts[0].api_ok = 0;
    }
    phase_gate_wait(&gates[0]);

    out = PROBE_SENTINEL;
    if (ops->get(&slot, &out) == HOST_TLS_OK && out == parts[0].own_value) {
        parts[0].own_value_ok = 1;
    }
    phase_gate_wait(&gates[1]);

    if (ops->set(&slot, parts[0].replaced_value) != HOST_TLS_OK) {
        parts[0].api_ok = 0;
    }
    phase_gate_wait(&gates[2]);

    out = PROBE_SENTINEL;
    if (ops->get(&slot, &out) == HOST_TLS_OK && out == parts[0].replaced_value) {
        parts[0].after_replace_ok = 1;
    }
    phase_gate_wait(&gates[3]);

    /* Workers clear their own values before this gate releases. */
    phase_gate_wait(&gates[4]);

    out = PROBE_SENTINEL;
    if (ops->get(&slot, &out) == HOST_TLS_OK && out == parts[0].replaced_value) {
        parts[0].clear_isolated_ok = 1;
    }

    for (i = 0; i < PROBE_WORKERS; i++) {
        if (WaitForSingleObject(threads[i], PROBE_WAIT_MS) != WAIT_OBJECT_0) {
            fatal_infrastructure("a worker thread did not finish in time");
        }
    }
    /* Only now, with every participant joined, is it safe to close the gates
     * and to read the per-thread results. */
    for (i = 0; i < PROBE_WORKERS; i++) {
        CloseHandle(threads[i]);
        threads[i] = NULL;
    }
    for (i = 0; i < PROBE_GATES; i++) {
        phase_gate_close(&gates[i]);
    }

    for (i = 0; i < PROBE_PARTICIPANTS; i++) {
        if (!parts[i].api_ok) {
            note_failure(c, "a TLS operation failed");
        }
        if (!parts[i].initial_null_ok) {
            note_failure(c, "a new thread did not observe an empty slot");
        }
        if (!parts[i].own_value_ok) {
            note_failure(c, "a thread did not observe its own value");
        }
        if (!parts[i].after_replace_ok) {
            note_failure(c, "another thread's replacement changed this thread's value");
        }
        if (i == 0) {
            if (!parts[i].clear_isolated_ok) {
                note_failure(c, "a clear in another thread disturbed the main value");
            }
        } else if (!parts[i].clear_ok) {
            note_failure(c, "clearing this thread's value did not take effect");
        }
    }

    /* A thread that exits must not hand its value to a later thread: the
     * writer stores and exits, then a *new* thread on the same live slot must
     * see NULL. */
    {
        round_participant writer;
        round_participant reader;

        participant_init(&writer, ops, &slot, &probe_value_writer, gates);
        run_thread_and_join(&writer, writer_thread_main,
                            "the writer thread did not finish in time");
        if (!writer.api_ok) {
            note_failure(c, "the writer thread's TLS operation failed");
        }

        participant_init(&reader, ops, &slot, &probe_value_fresh, gates);
        run_thread_and_join(&reader, fresh_reader_main,
                            "the fresh reader thread did not finish in time");
        if (!reader.initial_null_ok) {
            note_failure(c, "a fresh thread inherited a value from an exited thread");
        }
        /* The reader made no change, so the parent value must survive it. */
        out = PROBE_SENTINEL;
        if (ops->get(&slot, &out) != HOST_TLS_OK ||
            out != parts[0].replaced_value) {
            note_failure(c, "the writer/reader threads disturbed the parent value");
        }
    }

    /* Every thread that could use the slot has been joined: quiescent. */
    expect_result(c, ops->destroy(&slot), HOST_TLS_OK, "round destroy()");
    c->in_thread_phase = 0;
}

/* ---- single-threaded battery ----------------------------------------- */

static void run_battery(checks *c, const tls_ops *ops, unsigned rounds)
{
    host_tls_slot slot_a;
    host_tls_slot slot_b;
    host_tls_slot many[4];
    unsigned i;

    /* NULL argument rejection (host_tls_get also rejects a NULL output even
     * on a live slot, checked below). */
    expect_result(c, ops->init(NULL), HOST_TLS_ERR_INVALID_ARGUMENT, "init(NULL)");
    expect_result(c, ops->create(NULL), HOST_TLS_ERR_INVALID_ARGUMENT, "create(NULL)");
    expect_result(c, ops->destroy(NULL), HOST_TLS_ERR_INVALID_ARGUMENT, "destroy(NULL)");
    expect_result(c, ops->set(NULL, &probe_value_a),
                  HOST_TLS_ERR_INVALID_ARGUMENT, "set(NULL slot)");
    {
        void *out = PROBE_SENTINEL;
        expect_result(c, ops->get(NULL, &out), HOST_TLS_ERR_INVALID_ARGUMENT,
                      "get(NULL slot)");
        if (out != PROBE_SENTINEL) {
            note_failure(c, "get(NULL slot) clobbered the output");
        }
    }

    /* Lifecycle: init() is required before create(). Every rejected call must
     * leave the handle exactly as it was, not only the caller's output. */
    memset(&slot_a, 0, sizeof slot_a);
    memset(&slot_b, 0, sizeof slot_b);
    {
        uint32_t before_index = slot_a.native_index;
        uint32_t before_state = slot_a.state;

        expect_result(c, ops->create(&slot_a), HOST_TLS_ERR_INVALID_STATE,
                      "create() before init()");
        expect_handle_unchanged(c, &slot_a, before_index, before_state,
                                "create() before init()");
        expect_result(c, ops->destroy(&slot_a), HOST_TLS_ERR_INVALID_STATE,
                      "destroy() before init()");
        expect_handle_unchanged(c, &slot_a, before_index, before_state,
                                "destroy() before init()");
        expect_result(c, ops->set(&slot_a, &probe_value_a),
                      HOST_TLS_ERR_INVALID_STATE, "set() before init()");
        expect_handle_unchanged(c, &slot_a, before_index, before_state,
                                "set() before init()");
    }
    expect_rejected_get(c, ops, &slot_a, HOST_TLS_ERR_INVALID_STATE,
                        "get() before init()");

    expect_result(c, ops->init(&slot_a), HOST_TLS_OK, "init()");
    expect_result(c, ops->create(&slot_a), HOST_TLS_OK, "create()");
    c->first_native_index = slot_a.native_index;
    if (slot_a.native_index == 0) {
        c->zero_index_seen = 1;
    }
    expect_result(c, ops->get(&slot_a, NULL), HOST_TLS_ERR_INVALID_ARGUMENT,
                  "get(slot, NULL output)");

    /* Per-thread value semantics on one slot. */
    expect_value(c, ops, &slot_a, NULL, "new slot initial value");
    expect_result(c, ops->set(&slot_a, &probe_value_a), HOST_TLS_OK, "set()");
    expect_value(c, ops, &slot_a, &probe_value_a, "get() after set()");
    expect_result(c, ops->set(&slot_a, &probe_value_b), HOST_TLS_OK,
                  "set() replacing a value");
    expect_value(c, ops, &slot_a, &probe_value_b, "get() after replace");
    expect_result(c, ops->set(&slot_a, NULL), HOST_TLS_OK, "set(NULL) clearing");
    expect_value(c, ops, &slot_a, NULL, "get() after clear");
    {
        uint32_t before_index = slot_a.native_index;
        uint32_t before_state = slot_a.state;

        expect_result(c, ops->create(&slot_a), HOST_TLS_ERR_INVALID_STATE,
                      "create() twice on a live slot");
        expect_handle_unchanged(c, &slot_a, before_index, before_state,
                                "create() twice on a live slot");
        expect_result(c, ops->init(&slot_a), HOST_TLS_ERR_INVALID_STATE,
                      "init() on a live slot");
        expect_handle_unchanged(c, &slot_a, before_index, before_state,
                                "init() on a live slot");
    }

    /* Two live slots are independent. */
    expect_result(c, ops->init(&slot_b), HOST_TLS_OK, "init() second slot");
    expect_result(c, ops->create(&slot_b), HOST_TLS_OK, "create() second slot");
    if (slot_b.native_index == 0) {
        c->zero_index_seen = 1;
    }
    expect_result(c, ops->set(&slot_a, &probe_value_a), HOST_TLS_OK, "set(slot A)");
    expect_result(c, ops->set(&slot_b, &probe_value_b), HOST_TLS_OK, "set(slot B)");
    expect_value(c, ops, &slot_a, &probe_value_a, "slot A value while B is set");
    expect_value(c, ops, &slot_b, &probe_value_b, "slot B value while A is set");
    expect_result(c, ops->set(&slot_a, NULL), HOST_TLS_OK, "clear(slot A)");
    expect_value(c, ops, &slot_a, NULL, "slot A cleared");
    expect_value(c, ops, &slot_b, &probe_value_b, "slot B unaffected by clear(A)");
    expect_result(c, ops->set(&slot_b, &probe_value_a), HOST_TLS_OK, "replace(slot B)");
    expect_value(c, ops, &slot_b, &probe_value_a, "slot B replaced");
    expect_value(c, ops, &slot_a, NULL, "slot A still cleared");

    /* Several simultaneously live slots. */
    memset(many, 0, sizeof many);
    for (i = 0; i < 4; i++) {
        expect_result(c, ops->init(&many[i]), HOST_TLS_OK, "init() many-slots");
        expect_result(c, ops->create(&many[i]), HOST_TLS_OK, "create() many-slots");
        if (many[i].native_index == 0) {
            c->zero_index_seen = 1;
        }
        expect_result(c, ops->set(&many[i], &probe_value_many[i]), HOST_TLS_OK,
                      "set() many-slots");
    }
    for (i = 0; i < 4; i++) {
        expect_value(c, ops, &many[i], &probe_value_many[i],
                     "get() many-slots keeps its own value");
    }
    for (i = 0; i < 4; i++) {
        expect_result(c, ops->destroy(&many[i]), HOST_TLS_OK,
                      "destroy() many-slots");
    }

    /* Destroy: the dead handle is rejected, a survivor is unaffected, and a
     * destroyed handle can be re-initialised and recreated. */
    expect_result(c, ops->destroy(&slot_a), HOST_TLS_OK, "destroy(slot A)");
    expect_value(c, ops, &slot_b, &probe_value_a, "slot B unaffected by destroy(A)");
    expect_rejected_get(c, ops, &slot_a, HOST_TLS_ERR_INVALID_STATE,
                        "get() on a destroyed slot");
    {
        uint32_t before_index = slot_a.native_index;
        uint32_t before_state = slot_a.state;

        expect_result(c, ops->set(&slot_a, &probe_value_c),
                      HOST_TLS_ERR_INVALID_STATE, "set() on a destroyed slot");
        expect_handle_unchanged(c, &slot_a, before_index, before_state,
                                "set() on a destroyed slot");
        expect_result(c, ops->destroy(&slot_a), HOST_TLS_ERR_INVALID_STATE,
                      "destroy() on a destroyed slot");
        expect_handle_unchanged(c, &slot_a, before_index, before_state,
                                "destroy() on a destroyed slot");
        expect_result(c, ops->create(&slot_a), HOST_TLS_ERR_INVALID_STATE,
                      "create() on a destroyed slot (needs init())");
        expect_handle_unchanged(c, &slot_a, before_index, before_state,
                                "create() on a destroyed slot (needs init())");
    }
    expect_result(c, ops->init(&slot_a), HOST_TLS_OK, "init() after destroy()");
    expect_result(c, ops->create(&slot_a), HOST_TLS_OK, "create() after destroy()");
    if (slot_a.native_index == 0) {
        c->zero_index_seen = 1;
    }
    expect_value(c, ops, &slot_a, NULL, "recreated slot initial value");
    expect_result(c, ops->set(&slot_a, &probe_value_b), HOST_TLS_OK,
                  "set() on the recreated slot");
    expect_value(c, ops, &slot_a, &probe_value_b, "get() on the recreated slot");
    expect_result(c, ops->destroy(&slot_a), HOST_TLS_OK, "destroy() recreated slot");
    expect_result(c, ops->destroy(&slot_b), HOST_TLS_OK, "destroy(slot B)");

    /* Real OS threads: per-thread isolation, several rounds. */
    for (i = 0; i < rounds; i++) {
        run_thread_round(c, ops);
    }
}

/* ---- fixture-only negative backends --------------------------------- */

/* Defect: the value store is process-global PER SLOT instead of per thread.
 * A single-threaded use looks completely correct, so this negative passes
 * every sequential check and is only rejected by the thread-isolation
 * checks. The table is fixture-owned and every access is serialised with an
 * SRWLOCK, so the negative itself has no data race. */
#define NEG_GLOBAL_SLOTS 16

typedef struct neg_global_entry {
    const host_tls_slot *slot; /* NULL = free */
    void *value;
} neg_global_entry;

static SRWLOCK neg_global_lock = SRWLOCK_INIT;
static neg_global_entry neg_global_entries[NEG_GLOBAL_SLOTS];

static neg_global_entry *neg_global_find_locked(const host_tls_slot *slot)
{
    unsigned i;

    for (i = 0; i < NEG_GLOBAL_SLOTS; i++) {
        if (neg_global_entries[i].slot == slot) {
            return &neg_global_entries[i];
        }
    }
    return NULL;
}

static host_tls_result neg_global_create(host_tls_slot *slot)
{
    host_tls_result rc = host_tls_slot_create(slot);
    neg_global_entry *entry = NULL;
    unsigned i;

    if (rc != HOST_TLS_OK) {
        return rc;
    }
    AcquireSRWLockExclusive(&neg_global_lock);
    for (i = 0; i < NEG_GLOBAL_SLOTS; i++) {
        if (neg_global_entries[i].slot == NULL) {
            entry = &neg_global_entries[i];
            entry->slot = slot;
            entry->value = NULL;
            break;
        }
    }
    ReleaseSRWLockExclusive(&neg_global_lock);

    if (entry == NULL) {
        /* The fixture table is harness infrastructure: exhausting it is not a
         * property of the backend under test, and returning a fake error here
         * (after the real create succeeded) would both mutate the handle and
         * be miscounted as a behavioural rejection. Stop instead. */
        fatal_infrastructure("the process-global negative's fixture table is full");
    }
    return HOST_TLS_OK;
}

static host_tls_result neg_global_destroy(host_tls_slot *slot)
{
    host_tls_result rc = host_tls_slot_destroy(slot);
    neg_global_entry *entry;

    if (rc != HOST_TLS_OK) {
        return rc;
    }
    AcquireSRWLockExclusive(&neg_global_lock);
    entry = neg_global_find_locked(slot);
    if (entry != NULL) {
        entry->slot = NULL;
        entry->value = NULL;
    }
    ReleaseSRWLockExclusive(&neg_global_lock);
    return HOST_TLS_OK;
}

static host_tls_result neg_global_get(const host_tls_slot *slot, void **out_value)
{
    host_tls_result rc = host_tls_get(slot, out_value); /* argument/lifecycle */
    neg_global_entry *entry;

    if (rc != HOST_TLS_OK) {
        return rc;
    }
    AcquireSRWLockShared(&neg_global_lock);
    entry = neg_global_find_locked(slot);
    if (entry != NULL) {
        *out_value = entry->value;
    }
    ReleaseSRWLockShared(&neg_global_lock);
    return entry != NULL ? HOST_TLS_OK : HOST_TLS_ERR_INVALID_STATE;
}

static host_tls_result neg_global_set(host_tls_slot *slot, void *value)
{
    void *ignored = NULL;
    neg_global_entry *entry;
    host_tls_result rc = host_tls_get(slot, &ignored); /* argument/lifecycle */

    if (rc != HOST_TLS_OK) {
        return rc;
    }
    AcquireSRWLockExclusive(&neg_global_lock);
    entry = neg_global_find_locked(slot);
    if (entry != NULL) {
        entry->value = value;
    }
    ReleaseSRWLockExclusive(&neg_global_lock);
    return entry != NULL ? HOST_TLS_OK : HOST_TLS_ERR_INVALID_STATE;
}

/* Defect: every slot aliases one shared storage. The storage is a real TLS
 * index, so accesses stay per-thread by construction; only slot identity is
 * wrong. Rejected by the sequential slot-independence checks. */
static DWORD neg_alias_index = TLS_OUT_OF_INDEXES;
static int neg_alias_state; /* 0 = unprepared, 2 = prepare failed, 3 = ready */

/* Called once from main, before the alias battery and after the real one, so
 * it cannot take a native index the real backend would otherwise observe. */
static int neg_alias_prepare(void)
{
    if (neg_alias_state == 0) {
        neg_alias_index = TlsAlloc();
        neg_alias_state = neg_alias_index == TLS_OUT_OF_INDEXES ? 2 : 3;
    }
    return neg_alias_state == 3;
}

static host_tls_result neg_alias_get(const host_tls_slot *slot, void **out_value)
{
    host_tls_result rc = host_tls_get(slot, out_value); /* argument/lifecycle */

    if (rc != HOST_TLS_OK) {
        return rc;
    }
    *out_value = TlsGetValue(neg_alias_index);
    return HOST_TLS_OK;
}

static host_tls_result neg_alias_set(host_tls_slot *slot, void *value)
{
    void *ignored = NULL;
    host_tls_result rc = host_tls_get(slot, &ignored); /* argument/lifecycle */

    if (rc != HOST_TLS_OK) {
        return rc;
    }
    if (!TlsSetValue(neg_alias_index, value)) {
        return HOST_TLS_ERR_PLATFORM;
    }
    return HOST_TLS_OK;
}

/* Defect: set(NULL) is silently ignored, so a clear never takes effect. */
static host_tls_result neg_sticky_clear_set(host_tls_slot *slot, void *value)
{
    if (value == NULL) {
        void *current = NULL;
        return host_tls_get(slot, &current); /* validate, then drop the clear */
    }
    return host_tls_set(slot, value);
}

/* Defect: a failing get() writes to the output before it fails. */
static host_tls_result neg_clobber_get(const host_tls_slot *slot, void **out_value)
{
    if (out_value != NULL) {
        *out_value = (void *)(uintptr_t)0xC0B1E5u;
    }
    return host_tls_get(slot, out_value);
}

/* Defect: an empty slot is reported as a platform failure instead of NULL. */
static host_tls_result neg_null_as_error_get(const host_tls_slot *slot,
                                             void **out_value)
{
    host_tls_result rc = host_tls_get(slot, out_value);

    if (rc == HOST_TLS_OK && out_value != NULL && *out_value == NULL) {
        return HOST_TLS_ERR_PLATFORM;
    }
    return rc;
}

static const tls_ops real_ops = {
    "real",
    host_tls_slot_init,
    host_tls_slot_create,
    host_tls_slot_destroy,
    host_tls_get,
    host_tls_set
};

static const tls_ops neg_global_ops = {
    "negative-process-global-storage",
    host_tls_slot_init,
    neg_global_create,
    neg_global_destroy,
    neg_global_get,
    neg_global_set
};

static const tls_ops neg_alias_ops = {
    "negative-aliased-slots",
    host_tls_slot_init,
    host_tls_slot_create,
    host_tls_slot_destroy,
    neg_alias_get,
    neg_alias_set
};

static const tls_ops neg_sticky_clear_ops = {
    "negative-clear-noop",
    host_tls_slot_init,
    host_tls_slot_create,
    host_tls_slot_destroy,
    host_tls_get,
    neg_sticky_clear_set
};

static const tls_ops neg_clobber_ops = {
    "negative-output-clobber",
    host_tls_slot_init,
    host_tls_slot_create,
    host_tls_slot_destroy,
    neg_clobber_get,
    host_tls_set
};

static const tls_ops neg_null_as_error_ops = {
    "negative-null-is-error",
    host_tls_slot_init,
    host_tls_slot_create,
    host_tls_slot_destroy,
    neg_null_as_error_get,
    host_tls_set
};

/* Expected rejection profile of each deliberately wrong backend.
 * must_pass_sequential: the defect is invisible to a single thread, so the
 * backend must clear every sequential check and be rejected ONLY by the
 * thread-isolation checks. That keeps the rejection attributable to the
 * intended defect instead of some other, easier-to-spot one. */
typedef struct negative_case {
    const tls_ops *ops;
    int must_pass_sequential;
} negative_case;

static const negative_case negatives[] = {
    { &neg_global_ops, 1 }, /* process-global per-slot storage: only threads catch it */
    { &neg_alias_ops, 0 },
    { &neg_sticky_clear_ops, 0 },
    { &neg_clobber_ops, 0 },
    { &neg_null_as_error_ops, 0 }
};

int main(void)
{
    unsigned negative_count = (unsigned)(sizeof negatives / sizeof negatives[0]);
    checks real;
    unsigned i;

    real.label = "real";
    real.explain = 1;
    real.in_thread_phase = 0;
    real.single_failures = 0;
    real.thread_failures = 0;
    real.zero_index_seen = 0;
    real.first_native_index = 0;

    run_battery(&real, &real_ops, PROBE_ROUNDS);
    if (real.single_failures != 0 || real.thread_failures != 0) {
        fprintf(stderr, "FAIL: host TLS battery reported %d sequential + %d thread "
                        "failure(s) against the real backend\n",
                real.single_failures, real.thread_failures);
        return 1;
    }

    /* Observed evidence only: the design puts validity in the lifecycle tag,
     * so native index 0 must not behave as a sentinel. Whether TlsAlloc hands
     * out 0 is reported, never assumed, and no foreign index is ever freed to
     * manufacture an index-0 slot. */
    if (real.zero_index_seen) {
        printf("[coverage] a real slot with native index 0 passed the whole battery\n");
    } else {
        fprintf(stderr, "[coverage] the first real slot received native index %u; "
                        "no native index 0 was observed, so the zero-index path "
                        "was not exercised (no foreign index is freed to force "
                        "it)\n",
                (unsigned)real.first_native_index);
    }

    /* Allocated after the real battery so the fixture cannot consume the
     * index the real backend's first slot would otherwise see. */
    if (!neg_alias_prepare()) {
        fprintf(stderr, "FAIL: fixture could not allocate its aliasing TLS index\n");
        return 1;
    }

    for (i = 0; i < negative_count; i++) {
        const char *name = negatives[i].ops->name;
        checks negative;

        negative.label = name;
        negative.explain = 0;
        negative.in_thread_phase = 0;
        negative.single_failures = 0;
        negative.thread_failures = 0;
        negative.zero_index_seen = 0;
        negative.first_native_index = 0;

        run_battery(&negative, negatives[i].ops, PROBE_ROUNDS_NEGATIVE);

        if (negative.single_failures == 0 && negative.thread_failures == 0) {
            fprintf(stderr, "FAIL: the battery accepted the deliberately wrong "
                            "backend '%s'\n", name);
            return 1;
        }
        if (negatives[i].must_pass_sequential) {
            if (negative.single_failures != 0) {
                fprintf(stderr, "FAIL: '%s' was rejected by %d sequential check(s); "
                                "this defect must survive single-threaded use and be "
                                "rejected only by the thread-isolation checks\n",
                        name, negative.single_failures);
                return 1;
            }
            if (negative.thread_failures == 0) {
                fprintf(stderr, "FAIL: '%s' passed the thread-isolation phase\n",
                        name);
                return 1;
            }
        }
        printf("checked: '%s' rejected by %d sequential + %d thread check(s)\n",
               name, negative.single_failures, negative.thread_failures);
    }

    printf("PASS: host TLS slot battery (%d thread rounds, zero-native-index %s) "
           "and %u rejected negative backends\n",
           PROBE_ROUNDS, real.zero_index_seen ? "observed" : "not observed",
           negative_count);
    return 0;
}
