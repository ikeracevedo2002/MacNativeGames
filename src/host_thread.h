/* Host thread lifecycle abstraction (G1 thread row).
 *
 * Scope: this is a HOST operating-system thread. It is NOT the guest thread
 * ABI: it does not create, start, suspend, cancel, prioritise or schedule
 * guest threads, it defines no guest register state, no guest stack, no
 * guest handle and no virtual-core hand-off. Those belong to later loader /
 * HLE boundaries.
 *
 * Mac reference (behavioural only; the Mac sources are unchanged):
 *
 *   games/totk/runtime/threads.c maps each guest thread to a host pthread
 *   (pthread_create / pthread_mutex / pthread_cond) and runs the guest
 *   entry on a guest stack under a global kernel lock. The Mac code also
 *   implements Horizon thread SVCs (CreateThread, StartThread, priorities,
 *   core masks, ExitThread, ...). None of that is reproduced here.
 *
 * What this module takes from that reference is only the host-level
 * question "how does the host create and reap an operating-system thread".
 * The thread body is ordinary host C code, so this backend creates the
 * thread through the C runtime's supported entry point (_beginthreadex /
 * _endthreadex), which is the documented way for C code to get per-thread
 * CRT state (errno, locale, ...) set up and torn down. This is not a claim
 * that no program could ever use CreateThread directly; it is the safe
 * default for a callback that may call the CRT.
 *
 * Preconditions (caller obligations):
 *
 *   - The handle must be zero-initialised before the first create()
 *     (for example `host_thread t = {0};` or a memset to 0), exactly as the
 *     host TLS slot requires a zero-initialised handle.
 *   - The handle is caller-owned storage. create() overwrites a spent
 *     (joined/closed) handle; join()/close() are only valid on a live one.
 *   - Do NOT copy a live handle: this module owns one native thread handle
 *     per live value, so a copy would be closed twice. There is no registry
 *     and no stale-copy detection.
 *   - join()/close() on the same handle are externally synchronised by the
 *     caller: no other thread may touch the handle while a join/close runs.
 *   - The entry function and its argument are caller-owned. This module
 *     never frees the argument and installs no destructor. The caller must
 *     keep the argument alive until the thread has finished running: close()
 *     releases the native handle only, it does not end the thread and does
 *     not extend the argument's lifetime.
 *
 * Semantics:
 *
 *   - create() starts the thread immediately and RETURNS only after the
 *     native thread exists, but the entry callback may begin running BEFORE
 *     create() returns. The callback must therefore not read or write its
 *     owning `host_thread` handle until the creator has published the handle
 *     under external synchronisation (for example a phase event set after
 *     create() returns). The callback's argument is independent of the
 *     handle and needs no such gate. When the callback returns, the CRT
 *     cleans the thread up (_endthreadex).
 *   - join() waits for the thread to terminate. A finite timeout is the
 *     normal contract; HOST_THREAD_WAIT_INFINITE is accepted for callers
 *     that deliberately want an unbounded reap. On WAIT_OBJECT_0 the native
 *     handle is closed, the handle becomes JOINED and *out_joined is 1. On
 *     WAIT_TIMEOUT the handle stays LIVE, *out_joined is 0 and join() may
 *     be called again (this is what makes a bounded probe deterministic).
 *     If closing the native handle after a successful wait fails, join()
 *     leaves the handle LIVE and *out_joined unchanged; waiting again is
 *     safe because the terminated thread stays signalled.
 *   - join() rejects a handle whose native id is the calling thread's own
 *     while that thread is still running. A self-join can never succeed and
 *     HOST_THREAD_WAIT_INFINITE would deadlock; the call is reported as
 *     HOST_THREAD_ERR_INVALID_STATE. The check polls the handle first, so a
 *     thread that already terminated and whose numeric id was reused by the
 *     caller is still joinable.
 *   - close() releases the native handle WITHOUT waiting. It is a host
 *     lifecycle operation (avoid leaking the OS handle and the kernel
 *     thread object for a thread the caller does not intend to join); it is
 *     deliberately not named detach and has no guest meaning. The thread
 *     keeps running and still runs its CRT cleanup. After close() the handle
 *     is spent (CLOSED) and cannot be joined.
 *
 * Error handling is explicit: every entry point reports a host_thread_result.
 * On failure the handle's fields are left unchanged, so a failed create
 * leaves it spent/empty and a failed join leaves it live.
 *
 * Backend: a narrow _beginthreadex / WaitForSingleObject / CloseHandle
 * implementation in src/host_thread.c. This header is deliberately free of
 * <windows.h> and of any platform type: the handle carries only an opaque
 * native handle value, a diagnostic id and a lifecycle tag.
 */

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum host_thread_result {
    /* Success; the documented output (if any) was written. */
    HOST_THREAD_OK = 0,
    /* A mandatory pointer argument was NULL, or the entry function was
     * NULL. The handle is unchanged. */
    HOST_THREAD_ERR_INVALID_ARGUMENT = 1,
    /* The handle is not live (never created, already joined, already
     * closed). The handle is unchanged. */
    HOST_THREAD_ERR_INVALID_STATE = 2,
    /* The operating system refused to create the thread. The handle stays
     * empty/spent and may be retried. */
    HOST_THREAD_ERR_CREATE = 3,
    /* WaitForSingleObject or CloseHandle reported failure. The handle is
     * unchanged and still live. */
    HOST_THREAD_ERR_WAIT = 4
} host_thread_result;

/* Thread entry callback. This is HOST C code, not a guest entry point. */
typedef void (*host_thread_fn)(void *arg);

/* join() timeout sentinel: wait without a deadline. */
#define HOST_THREAD_WAIT_INFINITE 0xFFFFFFFFu

/* Thread handle. Treat the fields as opaque; read them only for diagnostics.
 * `state` is the validity marker and `native_id` is the OS thread id that
 * create() observed (0 while not created). `native_handle` is meaningful
 * only while the handle is LIVE. */
typedef struct host_thread {
    uintptr_t native_handle;
    uint32_t  native_id;
    uint32_t  state;
} host_thread;

/* Start a host thread that runs `entry(arg)`.
 *
 * `thread` and `entry` must be non-NULL. On success the handle becomes LIVE
 * and the thread has already started. On failure the handle is unchanged.
 * create() on a LIVE handle is rejected; create() on a spent handle reuses
 * the caller's storage for a fresh thread. */
host_thread_result host_thread_create(host_thread *thread,
                                      host_thread_fn entry,
                                      void *arg);

/* Join a LIVE host thread with a bounded (or infinite) timeout.
 *
 * On HOST_THREAD_OK, *out_joined is 1 when the thread terminated (the native
 * handle is then closed and the handle becomes JOINED) or 0 when the wait
 * timed out (the handle stays LIVE and join() may be retried).
 *
 * `thread` and `out_joined` must be non-NULL. On any failure *out_joined is
 * left untouched and the handle stays LIVE. Joining a non-LIVE handle, or
 * joining the calling thread itself while it is still running, is
 * HOST_THREAD_ERR_INVALID_STATE.
 */
host_thread_result host_thread_join(host_thread *thread,
                                    uint32_t timeout_ms,
                                    int *out_joined);

/* Release the native handle of a LIVE thread WITHOUT waiting for it.
 *
 * The thread keeps running; the handle becomes CLOSED and can no longer be
 * joined. On failure the handle stays LIVE. `thread` must be non-NULL. */
host_thread_result host_thread_close(host_thread *thread);

#ifdef __cplusplus
}
#endif
