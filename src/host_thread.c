/* Windows x64 host thread backend.
 *
 * Owns only the narrow platform calls (_beginthreadex / WaitForSingleObject /
 * CloseHandle) and the lifecycle tag that decides validity. See
 * host_thread.h for the contract, the Mac reference points and the caller
 * preconditions.
 *
 * Why _beginthreadex: the entry callback is host C code that may call the
 * CRT (errno, locale, malloc, stdio). _beginthreadex is the C runtime's
 * supported entry point for creating a thread from C code and its wrapper
 * calls _endthreadex when the start routine returns, so per-thread CRT state
 * is set up and torn down. This is the safe default here, not a claim that
 * CreateThread can never be used correctly.
 *
 * The start routine is a small trampoline over a heap context holding the
 * caller's function pointer and argument. The context exists so no function
 * pointer is cast to void *: that cast is not guaranteed portable. The
 * context is freed by the trampoline before it invokes the callback, so a
 * callback that never returns would still not leak it.
 */

#include "host_thread.h"

#if !defined(_WIN32)
#  error "host_thread.c is the Windows x64 backend; the Mac path keeps pthreads."
#endif

#include <windows.h>
#include <process.h>

#include <stdlib.h>

/* Lifecycle tags. HOST_THREAD_STATE_EMPTY (0) is what a zero-initialised
 * handle contains; the others are non-zero so a zero-initialised handle is
 * never mistaken for a live one. */
#define HOST_THREAD_STATE_EMPTY 0u
#define HOST_THREAD_STATE_LIVE 0x54485231u   /* "THR1" after create() */
#define HOST_THREAD_STATE_JOINED 0x54485232u /* "THR2" after a successful join */
#define HOST_THREAD_STATE_CLOSED 0x54485233u /* "THR3" after close() */

typedef struct host_thread_context {
    host_thread_fn entry;
    void *arg;
} host_thread_context;

/* _beginthreadex start routine. It deletes its context first, so the context
 * is not leaked even if the callback exits the thread itself. */
static unsigned __stdcall host_thread_trampoline(void *raw_context)
{
    host_thread_context *context = (host_thread_context *)raw_context;
    host_thread_fn entry = context->entry;
    void *arg = context->arg;

    free(context);
    entry(arg);
    return 0;
}

host_thread_result host_thread_create(host_thread *thread,
                                      host_thread_fn entry,
                                      void *arg)
{
    host_thread_context *context;
    uintptr_t native_handle;
    unsigned native_id = 0;

    if (thread == NULL || entry == NULL) {
        return HOST_THREAD_ERR_INVALID_ARGUMENT;
    }
    if (thread->state == HOST_THREAD_STATE_LIVE) {
        /* Reusing a live handle would orphan the running thread's handle. */
        return HOST_THREAD_ERR_INVALID_STATE;
    }

    context = (host_thread_context *)malloc(sizeof(*context));
    if (context == NULL) {
        return HOST_THREAD_ERR_CREATE;
    }
    context->entry = entry;
    context->arg = arg;

    /* Flag 0: start immediately; default stack size; inherit no handle.
     * _beginthreadex returns 0 on failure and sets errno. */
    native_handle = _beginthreadex(NULL, 0, host_thread_trampoline,
                                   context, 0, &native_id);
    if (native_handle == 0) {
        free(context);
        return HOST_THREAD_ERR_CREATE;
    }

    thread->native_handle = native_handle;
    thread->native_id = (uint32_t)native_id;
    thread->state = HOST_THREAD_STATE_LIVE;
    return HOST_THREAD_OK;
}

host_thread_result host_thread_join(host_thread *thread,
                                    uint32_t timeout_ms,
                                    int *out_joined)
{
    DWORD timeout;
    DWORD waited;

    if (thread == NULL || out_joined == NULL) {
        return HOST_THREAD_ERR_INVALID_ARGUMENT;
    }
    if (thread->state != HOST_THREAD_STATE_LIVE) {
        return HOST_THREAD_ERR_INVALID_STATE;
    }
    if (GetCurrentThreadId() == (DWORD)thread->native_id) {
        /* The native id matches the caller's, but the thread may already have
         * terminated and had its id reused by the calling thread. Poll
         * without blocking: only a still-running thread is a real self-join.
         * A terminated thread stays signalled, so joining it is safe whatever
         * its id. */
        DWORD poll = WaitForSingleObject((HANDLE)thread->native_handle, 0);
        if (poll == WAIT_FAILED) {
            return HOST_THREAD_ERR_WAIT;
        }
        if (poll == WAIT_TIMEOUT) {
            return HOST_THREAD_ERR_INVALID_STATE;
        }
        if (poll != WAIT_OBJECT_0) {
            return HOST_THREAD_ERR_WAIT;
        }
    }

    timeout = (timeout_ms == HOST_THREAD_WAIT_INFINITE) ? INFINITE
                                                        : (DWORD)timeout_ms;
    waited = WaitForSingleObject((HANDLE)thread->native_handle, timeout);

    if (waited == WAIT_OBJECT_0) {
        /* The thread has terminated. If closing its handle fails, keep the
         * handle live and report the failure: the terminated thread stays
         * signalled, so waiting again is safe and *out_joined is untouched. */
        if (!CloseHandle((HANDLE)thread->native_handle)) {
            return HOST_THREAD_ERR_WAIT;
        }
        thread->native_handle = 0;
        thread->state = HOST_THREAD_STATE_JOINED;
        *out_joined = 1;
        return HOST_THREAD_OK;
    }
    if (waited == WAIT_TIMEOUT) {
        /* Still running: the handle stays live and join() may be retried. */
        *out_joined = 0;
        return HOST_THREAD_OK;
    }

    /* WAIT_FAILED (or WAIT_ABANDONED, not produced by thread handles). The
     * handle is untouched and still live. */
    return HOST_THREAD_ERR_WAIT;
}

host_thread_result host_thread_close(host_thread *thread)
{
    if (thread == NULL) {
        return HOST_THREAD_ERR_INVALID_ARGUMENT;
    }
    if (thread->state != HOST_THREAD_STATE_LIVE) {
        return HOST_THREAD_ERR_INVALID_STATE;
    }

    if (!CloseHandle((HANDLE)thread->native_handle)) {
        /* Keep the handle live: it still owns the native handle. */
        return HOST_THREAD_ERR_WAIT;
    }

    thread->native_handle = 0;
    thread->state = HOST_THREAD_STATE_CLOSED;
    return HOST_THREAD_OK;
}
