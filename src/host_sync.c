/* Windows x64 host mutex + condition-variable backend.
 *
 * Owns only the narrow platform pair (SRWLOCK exclusive + CONDITION_VARIABLE)
 * and the lifecycle tag that decides validity. See host_sync.h for the
 * contract, the Mac reference points and the caller preconditions.
 *
 * The backend object is a heap allocation owned by the handle, so the native
 * types live in their proper declared type instead of being placed into an
 * opaque byte buffer (which would be an effective-type violation in C).
 *
 * SRWLOCK is used in exclusive mode because it is the documented lock for
 * SleepConditionVariableSRW and because it needs no explicit destroy call.
 * Microsoft documents that SleepConditionVariableSRW reacquires the lock for
 * a wake and for a timeout, which is what makes the "caller holds the mutex
 * again" contract hold for HOST_SYNC_OK and HOST_SYNC_ERR_TIMEOUT. The lock
 * state after a platform failure is NOT documented and this module does not
 * promise it: that result is fatal for the handle.
 *
 * No shared mutable state is kept here (no registry, no table): each handle
 * owns its own backend, so two handles never alias.
 */

#include "host_sync.h"

#if !defined(_WIN32)
#  error "host_sync.c is the Windows x64 backend; the Mac path keeps pthreads."
#endif

#include <windows.h>

#include <stdlib.h>

/* Lifecycle tags per handle kind. The empty value is what a zero-initialised
 * handle contains. Distinct non-zero "live" and "destroyed" values make a
 * destroyed handle clearly invalid instead of silently usable. */
#define HOST_SYNC_STATE_EMPTY 0u
#define HOST_MUTEX_STATE_READY 0x4D555431u    /* "MUT1" after init() */
#define HOST_MUTEX_STATE_DESTROYED 0x4D555432u/* "MUT2" after destroy() */
#define HOST_COND_STATE_READY 0x434E4431u     /* "CND1" after init() */
#define HOST_COND_STATE_DESTROYED 0x434E4432u /* "CND2" after destroy() */

typedef struct host_mutex_backend {
    SRWLOCK lock;
} host_mutex_backend;

typedef struct host_cond_backend {
    CONDITION_VARIABLE cond;
} host_cond_backend;

static host_mutex_backend *mutex_backend(host_mutex *mutex)
{
    return (host_mutex_backend *)mutex->impl;
}

static host_cond_backend *cond_backend(host_cond *cond)
{
    return (host_cond_backend *)cond->impl;
}

host_sync_result host_mutex_init(host_mutex *mutex)
{
    host_mutex_backend *backend;

    if (mutex == NULL) {
        return HOST_SYNC_ERR_INVALID_ARGUMENT;
    }
    if (mutex->state == HOST_MUTEX_STATE_READY) {
        /* Re-initialising a live lock would discard its state. */
        return HOST_SYNC_ERR_INVALID_STATE;
    }

    backend = (host_mutex_backend *)malloc(sizeof(*backend));
    if (backend == NULL) {
        return HOST_SYNC_ERR_ALLOCATION;
    }
    InitializeSRWLock(&backend->lock);
    mutex->impl = backend;
    mutex->state = HOST_MUTEX_STATE_READY;
    return HOST_SYNC_OK;
}

host_sync_result host_mutex_destroy(host_mutex *mutex)
{
    if (mutex == NULL) {
        return HOST_SYNC_ERR_INVALID_ARGUMENT;
    }
    if (mutex->state != HOST_MUTEX_STATE_READY) {
        return HOST_SYNC_ERR_INVALID_STATE;
    }

    /* SRWLOCK needs no platform destroy. The caller must have reached
     * quiescence; free the backend and mark the handle dead. */
    free(mutex->impl);
    mutex->impl = NULL;
    mutex->state = HOST_MUTEX_STATE_DESTROYED;
    return HOST_SYNC_OK;
}

host_sync_result host_mutex_lock(host_mutex *mutex)
{
    if (mutex == NULL) {
        return HOST_SYNC_ERR_INVALID_ARGUMENT;
    }
    if (mutex->state != HOST_MUTEX_STATE_READY) {
        return HOST_SYNC_ERR_INVALID_STATE;
    }

    AcquireSRWLockExclusive(&mutex_backend(mutex)->lock);
    return HOST_SYNC_OK;
}

host_sync_result host_mutex_unlock(host_mutex *mutex)
{
    if (mutex == NULL) {
        return HOST_SYNC_ERR_INVALID_ARGUMENT;
    }
    if (mutex->state != HOST_MUTEX_STATE_READY) {
        return HOST_SYNC_ERR_INVALID_STATE;
    }

    ReleaseSRWLockExclusive(&mutex_backend(mutex)->lock);
    return HOST_SYNC_OK;
}

host_sync_result host_cond_init(host_cond *cond)
{
    host_cond_backend *backend;

    if (cond == NULL) {
        return HOST_SYNC_ERR_INVALID_ARGUMENT;
    }
    if (cond->state == HOST_COND_STATE_READY) {
        return HOST_SYNC_ERR_INVALID_STATE;
    }

    backend = (host_cond_backend *)malloc(sizeof(*backend));
    if (backend == NULL) {
        return HOST_SYNC_ERR_ALLOCATION;
    }
    InitializeConditionVariable(&backend->cond);
    cond->impl = backend;
    cond->state = HOST_COND_STATE_READY;
    return HOST_SYNC_OK;
}

host_sync_result host_cond_destroy(host_cond *cond)
{
    if (cond == NULL) {
        return HOST_SYNC_ERR_INVALID_ARGUMENT;
    }
    if (cond->state != HOST_COND_STATE_READY) {
        return HOST_SYNC_ERR_INVALID_STATE;
    }

    /* CONDITION_VARIABLE needs no platform destroy; free the backend. */
    free(cond->impl);
    cond->impl = NULL;
    cond->state = HOST_COND_STATE_DESTROYED;
    return HOST_SYNC_OK;
}

host_sync_result host_cond_wait(host_cond *cond, host_mutex *mutex,
                                uint32_t timeout_ms)
{
    DWORD timeout;
    BOOL ok;

    if (cond == NULL || mutex == NULL) {
        return HOST_SYNC_ERR_INVALID_ARGUMENT;
    }
    if (cond->state != HOST_COND_STATE_READY ||
        mutex->state != HOST_MUTEX_STATE_READY) {
        return HOST_SYNC_ERR_INVALID_STATE;
    }

    timeout = (timeout_ms == HOST_SYNC_WAIT_INFINITE) ? INFINITE
                                                      : (DWORD)timeout_ms;
    /* Flags 0 = exclusive lock. Windows releases the lock while blocked and
     * reacquires it before returning, for both a wake and a timeout. */
    ok = SleepConditionVariableSRW(&cond_backend(cond)->cond,
                                   &mutex_backend(mutex)->lock, timeout, 0);
    if (ok) {
        return HOST_SYNC_OK;
    }
    if (GetLastError() == ERROR_TIMEOUT) {
        return HOST_SYNC_ERR_TIMEOUT;
    }
    return HOST_SYNC_ERR_PLATFORM;
}

host_sync_result host_cond_signal(host_cond *cond)
{
    if (cond == NULL) {
        return HOST_SYNC_ERR_INVALID_ARGUMENT;
    }
    if (cond->state != HOST_COND_STATE_READY) {
        return HOST_SYNC_ERR_INVALID_STATE;
    }

    WakeConditionVariable(&cond_backend(cond)->cond);
    return HOST_SYNC_OK;
}

host_sync_result host_cond_broadcast(host_cond *cond)
{
    if (cond == NULL) {
        return HOST_SYNC_ERR_INVALID_ARGUMENT;
    }
    if (cond->state != HOST_COND_STATE_READY) {
        return HOST_SYNC_ERR_INVALID_STATE;
    }

    WakeAllConditionVariable(&cond_backend(cond)->cond);
    return HOST_SYNC_OK;
}
