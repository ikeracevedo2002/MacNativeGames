/* Host mutex + condition-variable abstraction (G1 synchronisation row).
 *
 * Scope: these are HOST synchronisation primitives. They are NOT the guest
 * locks / condition variables / address arbiters / events of the Horizon
 * kernel and they expose no guest handle. The Mac guest kernel
 * (games/totk/runtime/threads.c) is the behavioural reference for the guest
 * SVCs; this module only replaces the host mechanism underneath a future
 * host runtime.
 *
 * Mac reference (behavioural only; the Mac sources are unchanged):
 *
 *   games/totk/runtime/threads.c uses one global
 *   pthread_mutex_t (G) plus one pthread_cond_t per waiting thread, and a
 *   hand-written wake/pick policy over its own wait chains. The guest
 *   semantics (priority order, condition keys, address arbiters, event
 *   handles) are deliberately NOT reproduced here.
 *
 * What this module takes from that reference is only the host primitive
 * pair: a mutex, and a condition variable waited on while holding it. A
 * condition variable is always used together with a predicate that is
 * guarded by the same mutex; that predicate, not the wake-up itself, carries
 * the state.
 *
 * Predicate contract (this is the point of the module):
 *
 *   - The caller holds the mutex while it checks or changes the predicate
 *     and while it signals/broadcasts.
 *   - host_cond_wait() atomically releases the mutex and blocks, then
 *     reacquires the mutex before returning. On HOST_SYNC_OK or
 *     HOST_SYNC_ERR_TIMEOUT the mutex is held by the caller again.
 *   - A wake-up is not a stored event. A signal sent with no waiter, or a
 *     signal sent before a waiter starts waiting, is not remembered and is
 *     not an error. Waits may also return HOST_SYNC_OK spuriously.
 *     Therefore the caller MUST re-check the predicate in a loop after
 *     every wait; a "signal before wait" is handled by the predicate still
 *     being true. This is exactly the Mac pattern and the reason this API
 *     does not promise a persistent wake.
 *
 * Preconditions (caller obligations):
 *
 *   - A handle must be zero-initialised before the first init().
 *   - init()/destroy() are not internally synchronised: the caller
 *     serialises the handle lifecycle and only calls lock/unlock/wait/
 *     signal/broadcast on an initialised handle.
 *   - destroy() may only run after quiescence: no thread is holding the
 *     mutex and no thread is waiting on the condition.
 *   - Do NOT copy a live handle. There is no registry and no stale-copy
 *     detection; a copy would share (and later double-destroy) the same
 *     native object.
 *   - The mutex is exclusive and non-recursive: locking it twice from the
 *     same thread is a deadlock, exactly as an SRW exclusive lock is.
 *     No owner check is performed; the caller must not call unlock() on a
 *     mutex it does not hold.
 *
 * Error handling is explicit: every entry point reports a host_sync_result.
 * On failure a handle is unchanged, and outputs (if any) are untouched.
 *
 * Backend: a narrow Windows SRWLOCK + CONDITION_VARIABLE implementation in
 * src/host_sync.c. This header is deliberately free of <windows.h> and of
 * any platform type. The backend object is a heap allocation owned by the
 * handle, so the native types are stored in their proper declared type and
 * there is no type-punning of an opaque byte buffer.
 */

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum host_sync_result {
    /* Success; the documented output (if any) was written. */
    HOST_SYNC_OK = 0,
    /* A mandatory pointer argument was NULL. Nothing was changed. */
    HOST_SYNC_ERR_INVALID_ARGUMENT = 1,
    /* The handle is not initialised (or is not live any more) for the
     * operation. Nothing was changed. */
    HOST_SYNC_ERR_INVALID_STATE = 2,
    /* host_cond_wait() reached its deadline without being signalled. The
     * mutex is held again and the caller must re-check its predicate. */
    HOST_SYNC_ERR_TIMEOUT = 3,
    /* The platform primitive reported failure. Microsoft documents that
     * SleepConditionVariableSRW reacquires the lock for a wake and a timeout,
     * but does NOT document the lock state after a platform failure. For
     * host_cond_wait() the mutex state is therefore UNKNOWN after this result:
     * treat it as fatal and do not re-check a predicate, unlock the mutex, or
     * reuse the handle. Nothing else was changed. */
    HOST_SYNC_ERR_PLATFORM = 4,
    /* init() could not allocate its backend object. The handle is unchanged
     * and still ready to retry. */
    HOST_SYNC_ERR_ALLOCATION = 5
} host_sync_result;

/* host_cond_wait() timeout sentinel: wait without a deadline. */
#define HOST_SYNC_WAIT_INFINITE 0xFFFFFFFFu

/* Handle. `impl` points at this module's own backend object while the handle
 * is live and is NULL otherwise. Treat the fields as opaque: validity lives
 * in the lifecycle tag, never in `impl` being non-NULL. Because the object is
 * heap-owned, do NOT copy a live handle (a copy would share and later
 * double-destroy the same backend); there is no registry and no stale-copy
 * detection. */
typedef struct host_mutex {
    void *impl;
    uint32_t state;
    uint32_t reserved;
} host_mutex;

typedef struct host_cond {
    void *impl;
    uint32_t state;
    uint32_t reserved;
} host_cond;

/* Prepare a mutex/condition handle. `handle` must be non-NULL and
 * zero-initialised. init() on a live handle is rejected; destroy() first to
 * recreate it. On failure the handle is unchanged. */
host_sync_result host_mutex_init(host_mutex *mutex);
host_sync_result host_cond_init(host_cond *cond);

/* Release a live handle after quiescence. On failure the handle stays live.
 * destroy() frees the handle's backend allocation; the caller must have
 * reached quiescence (no other thread is locked, waiting or about to use the
 * handle) before calling it. */
host_sync_result host_mutex_destroy(host_mutex *mutex);
host_sync_result host_cond_destroy(host_cond *cond);

/* Acquire/release the exclusive (non-recursive) mutex. A NULL or
 * non-initialised handle is rejected. */
host_sync_result host_mutex_lock(host_mutex *mutex);
host_sync_result host_mutex_unlock(host_mutex *mutex);

/* Wait on `cond` while holding `mutex`.
 *
 * `cond` and `mutex` must both be initialised (and their handle lifecycle
 * externally synchronised). The caller MUST hold `mutex`. The mutex is
 * atomically released while blocked and reacquired before return, so on
 * HOST_SYNC_OK and HOST_SYNC_ERR_TIMEOUT the mutex is held by the caller
 * again. On HOST_SYNC_ERR_PLATFORM the lock state is UNKNOWN (see the
 * result doc): the call is fatal and the handle must not be reused.
 * HOST_SYNC_WAIT_INFINITE waits without a deadline.
 *
 * The return value is not a predicate result: the caller re-checks its
 * predicate after every return (see the predicate contract above). */
host_sync_result host_cond_wait(host_cond *cond, host_mutex *mutex,
                                uint32_t timeout_ms);

/* Wake one / all current waiters. A signal with no waiter is not stored and
 * is not an error. The caller normally holds the same mutex (see the
 * predicate contract). */
host_sync_result host_cond_signal(host_cond *cond);
host_sync_result host_cond_broadcast(host_cond *cond);

#ifdef __cplusplus
}
#endif
