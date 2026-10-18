/* Windows x64 host TLS slot backend.
 *
 * Owns only the narrow platform calls (TlsAlloc / TlsGetValue / TlsSetValue
 * / TlsFree) and the lifecycle tag that decides validity. See host_tls.h for
 * the contract, the Mac reference points and the caller preconditions.
 *
 * Two details matter for correctness and are exercised by the probe:
 *
 *   1. TlsAlloc() may return 0. The handle therefore records validity in
 *      `state`, never in `native_index`; index 0 is a normal live slot.
 *   2. TlsGetValue() returning NULL is ambiguous on its own: it means either
 *      "no value on this thread" (the normal initial state) or "that index
 *      is invalid". Microsoft's documented disambiguation is the last-error
 *      value: TlsGetValue sets it to 0 on success and to a nonzero code
 *      when the index is out of range, so the call is bracketed by
 *      SetLastError(0) / GetLastError(). Only then is NULL turned into
 *      HOST_TLS_OK with *out_value == NULL.
 *   3. Microsoft documents that TlsAlloc initializes the storage slots for
 *      the new index to zero ("The slots for the index are initialized to
 *      zero"), so a fresh slot reads NULL on every thread with no set() call
 *      and no reliance on TlsFree clearing per-thread storage.
 *      Source: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-tlsalloc
 *
 * No shared mutable state is kept here (no registry, no table of slots), so
 * get()/set() need no locking: the platform slot itself is per thread.
 */

#include "host_tls.h"

#if !defined(_WIN32)
#  error "host_tls.c is the Windows x64 backend; the Mac path keeps pthread TLS."
#endif

#include <windows.h>

/* Lifecycle tags. HOST_TLS_STATE_UNINITIALIZED (0) is what a zero-initialised
 * handle contains. The other values are deliberately non-zero so that a
 * zero-initialised handle is NOT accepted by create(): init() is required.
 * They also make a destroyed handle distinguishable from a ready one, so a
 * dead slot is rejected instead of silently reading a released index. */
#define HOST_TLS_STATE_UNINITIALIZED 0u
#define HOST_TLS_STATE_READY 0x54534C31u   /* "TLS1" after init() */
#define HOST_TLS_STATE_LIVE 0x54534C32u    /* "TLS2" after create() */
#define HOST_TLS_STATE_DESTROYED 0x54534C33u /* "TLS3" after destroy() */

/* Storage for "this handle owns no native index". 0xFFFFFFFF is
 * TLS_OUT_OF_INDEXES, the only index value the platform never hands out for
 * a successful allocation; 0 is a valid index. */
#define HOST_TLS_NATIVE_INDEX_NONE 0xFFFFFFFFu

host_tls_result host_tls_slot_init(host_tls_slot *slot)
{
    if (slot == NULL) {
        return HOST_TLS_ERR_INVALID_ARGUMENT;
    }
    if (slot->state == HOST_TLS_STATE_LIVE) {
        /* Re-initialising a live handle would drop its index on the floor. */
        return HOST_TLS_ERR_INVALID_STATE;
    }

    slot->native_index = HOST_TLS_NATIVE_INDEX_NONE;
    slot->state = HOST_TLS_STATE_READY;
    return HOST_TLS_OK;
}

host_tls_result host_tls_slot_create(host_tls_slot *slot)
{
    DWORD index;

    if (slot == NULL) {
        return HOST_TLS_ERR_INVALID_ARGUMENT;
    }
    if (slot->state != HOST_TLS_STATE_READY) {
        /* Covers create() before init(), create() twice and create() on a
         * destroyed handle (a destroyed handle needs a fresh init()). */
        return HOST_TLS_ERR_INVALID_STATE;
    }

    index = TlsAlloc();
    if (index == TLS_OUT_OF_INDEXES) {
        return HOST_TLS_ERR_ALLOCATION;
    }

    slot->native_index = (uint32_t)index;
    slot->state = HOST_TLS_STATE_LIVE;
    return HOST_TLS_OK;
}

host_tls_result host_tls_slot_destroy(host_tls_slot *slot)
{
    if (slot == NULL) {
        return HOST_TLS_ERR_INVALID_ARGUMENT;
    }
    if (slot->state != HOST_TLS_STATE_LIVE) {
        return HOST_TLS_ERR_INVALID_STATE;
    }

    if (!TlsFree((DWORD)slot->native_index)) {
        /* Keep the handle live: it still owns the index. */
        return HOST_TLS_ERR_PLATFORM;
    }

    slot->state = HOST_TLS_STATE_DESTROYED;
    slot->native_index = HOST_TLS_NATIVE_INDEX_NONE;
    return HOST_TLS_OK;
}

host_tls_result host_tls_get(const host_tls_slot *slot, void **out_value)
{
    void *value;

    if (slot == NULL || out_value == NULL) {
        return HOST_TLS_ERR_INVALID_ARGUMENT;
    }
    if (slot->state != HOST_TLS_STATE_LIVE) {
        return HOST_TLS_ERR_INVALID_STATE;
    }

    /* Clear the thread's last-error so GetLastError() afterwards means "what
     * TlsGetValue did", not some earlier unrelated failure. */
    SetLastError(ERROR_SUCCESS);
    value = TlsGetValue((DWORD)slot->native_index);
    if (value == NULL) {
        DWORD error = GetLastError();
        if (error != ERROR_SUCCESS) {
            /* A platform failure is not a value: leave *out_value untouched. */
            return HOST_TLS_ERR_PLATFORM;
        }
    }

    *out_value = value; /* NULL here is a legitimate "no value on this thread". */
    return HOST_TLS_OK;
}

host_tls_result host_tls_set(host_tls_slot *slot, void *value)
{
    if (slot == NULL) {
        return HOST_TLS_ERR_INVALID_ARGUMENT;
    }
    if (slot->state != HOST_TLS_STATE_LIVE) {
        return HOST_TLS_ERR_INVALID_STATE;
    }

    if (!TlsSetValue((DWORD)slot->native_index, value)) {
        return HOST_TLS_ERR_PLATFORM;
    }

    return HOST_TLS_OK;
}
