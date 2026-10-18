/* Host TLS slot abstraction (G1 TLS row).
 *
 * Scope: this is a HOST-platform thread-local storage slot. It is NOT the
 * guest TLS/TLR mechanism, defines no guest-thread ABI, and is not wired to
 * any guest-visible behaviour.
 *
 * Mac reference (behavioural only; the Mac sources are unchanged):
 *
 *   games/totk/runtime/loader.c
 *     - runtime_thread_init() allocates a per-thread ThreadEnvironment and
 *       binds it with pthread_setspecific(environment_key, e), then binds
 *       the per-thread gate/TLS/TLR pointers into runtime_keys[0..3];
 *     - thread_cleanup() clears environment_key and runtime_keys[0..3]
 *       before running environment_destroy(e) explicitly;
 *     - the keys themselves are created in main():
 *         runtime_keys[8]   -> pthread_key_create(..., NULL)   no destructor
 *         environment_key   -> pthread_key_create(..., environment_destroy)
 *       and runtime_hle_stack_init() turns runtime_keys[4] into the Darwin
 *       TSD offset key*8.
 *   games/totk/runtime/threads.c binds a thr_t to the current thread through
 *   g_keythr, also created with a NULL destructor.
 *
 * What this module takes from that reference is the host TLS *slot
 * lifecycle* used by the destructor-less keys (runtime_keys[], g_keythr):
 * create, per-thread get, per-thread set/replace, clear and release, with an
 * explicit error result and no automatic release of the stored pointer.
 *
 * What this module deliberately does NOT reproduce (out of contract here):
 *
 *   - key destructors / automatic pointee release. environment_key has a
 *     destructor and is therefore outside this contract: tearing down the
 *     thread environment stays an explicit caller step for a later
 *     boundary. No destructor hook exists in this API.
 *   - the ThreadEnvironment struct, its allocations or its ownership.
 *   - the raw Darwin TSD layout (TPIDRRO_EL0 + key * 8), the guest key page
 *     and the guest TLS/TLR values. That layout is an ARM64/Darwin detail
 *     and must not be preserved or exposed as a Windows ABI.
 *   - any guest register / translated-code (AOT) ABI.
 *
 * Preconditions (caller obligations; not enforced across threads):
 *
 *   - init() must be called exactly once before the first create() on a
 *     given slot object, and that object must be zero-initialised before
 *     the first init() (for example `host_tls_slot slot = {0};` or a
 *     memset to 0). A live slot refuses init(): destroy() it first, then
 *     init() again to recreate.
 *   - create() and destroy() are NOT internally synchronised. The handle is
 *     owned by whichever code performs the lifecycle, and no other thread
 *     may use the handle while create()/destroy() is running. Callers must
 *     provide their own external synchronisation for the handle lifecycle.
 *   - Do NOT copy a live slot handle. This module keeps no registry, no
 *     generation counter and no stale-copy detection, so a copy taken while
 *     the slot is live is indistinguishable from the original and using it
 *     is undefined. Copies taken before init() or after destroy() are plain
 *     data and own no platform resource.
 *   - get()/set() may be called concurrently by any number of threads on
 *     the same live slot — that is the point of a TLS slot — but never
 *     concurrently with destroy() of that slot.
 *   - destroy() may only be called after quiescence: every thread that can
 *     still call get()/set() on the slot must have finished its last such
 *     call, and either exited or be synchronised away. Windows then releases
 *     the index. Nothing here relies on TlsFree clearing per-thread storage:
 *     the documented NULL initialization belongs to TlsAlloc (index
 *     creation), not to TlsFree. A value still stored for that index on
 *     another thread is neither observed nor freed by this API. Violating
 *     this precondition is a data race in the caller and is not detectable
 *     here.
 *
 * Value ownership:
 *
 *   - The stored `void *` is caller-owned opaque data. This module never
 *     dereferences it, never frees it, and installs no destructor. Clearing
 *     a slot (set(NULL)) or destroying the slot never releases the pointee.
 *     A Windows thread exit drops that thread's slot storage, not the
 *     pointee either.
 *
 * Semantics:
 *
 *   - Storage is per operating-system thread. A slot has no value on a
 *     thread that has not set one: get() on a new thread succeeds and
 *     reports NULL. Microsoft documents that TlsAlloc initializes the
 *     storage slots for the new index to zero ("The slots for the index are
 *     initialized to zero"), so this initialization is a property of index
 *     creation, not of TlsFree. A thread that exits does not hand its values
 *     to a fresh thread. Source:
 *     https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-tlsalloc
 *   - set() replaces the caller's value for the calling thread; set(NULL)
 *     clears it (leaving the slot live and usable). set() therefore accepts
 *     NULL, and both a replacement and a clear are plain caller-owned
 *     pointer swaps.
 *   - A successful get() reporting *out_value == NULL means "this thread
 *     has no value in this slot" and is NOT an error. get() distinguishes
 *     that case from a platform failure by clearing and then re-reading the
 *     thread's last-error value around TlsGetValue().
 *   - Distinct live slots are independent: the same value may be stored in
 *     several slots, and different values in different slots, without any
 *     aliasing between them.
 *
 * Error handling is explicit: every entry point can fail and reports a
 * host_tls_result. On failure no output is written — *out_value is left
 * untouched by get(), and init()/create()/destroy() leave the handle's
 * fields untouched — so a caller may park a sentinel in the output and only
 * consume it on HOST_TLS_OK.
 *
 * Backend: a narrow Windows TlsAlloc/TlsGetValue/TlsSetValue/TlsFree
 * implementation in src/host_tls.c. This header is deliberately free of
 * <windows.h> and of any platform type: the handle carries only a native
 * index and an internal lifecycle tag.
 *
 * Known coverage limits (see docs/windows-build.md):
 *   - TlsAlloc() may legitimately return native index 0, and a native index of
 *     0 is a valid slot, never a falsey failure sentinel: validity lives in
 *     the handle's lifecycle tag, not in the index. The probe reports the
 *     native index it actually observed; index 0 was not observed in the local
 *     runs, so that particular path is NOT exercised, and no foreign index is
 *     freed to force it.
 *   - The platform failure paths are implemented and mapped to explicit
 *     results but are NOT forced by the committed probe. Allocation
 *     exhaustion (TlsAlloc) was exercised by a separate out-of-tree audit
 *     documented in docs/windows-build.md; the TlsGetValue / TlsSetValue /
 *     TlsFree platform-error paths remain unforced.
 */

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum host_tls_result {
    /* Success; the documented output (if any) was written. */
    HOST_TLS_OK = 0,
    /* A mandatory pointer argument was NULL. No output was written. */
    HOST_TLS_ERR_INVALID_ARGUMENT = 1,
    /* The handle is not in the lifecycle state the call requires: create()
     * without a prior init(), init() on a live slot, any get()/set()/
     * destroy() on an uninitialised or already destroyed slot, or a second
     * create() on a live slot. The handle is unchanged. */
    HOST_TLS_ERR_INVALID_STATE = 2,
    /* The platform refused a new TLS slot (all indices in use). The handle
     * stays initialised and can be retried. */
    HOST_TLS_ERR_ALLOCATION = 3,
    /* TlsGetValue / TlsSetValue / TlsFree reported failure. Output
     * untouched; the handle's lifecycle state is unchanged. */
    HOST_TLS_ERR_PLATFORM = 4
} host_tls_result;

/* Slot handle. Allocate it where it can outlive every user of the slot
 * (usually the lifecycle owner's storage); it holds no pointer to heap data
 * owned by this module, so it needs no freeing of its own.
 *
 * The fields are implementation detail and must be treated as opaque: read
 * them only for diagnostics. `state` is the validity marker; `native_index`
 * is meaningful only while the slot is live and may legitimately be 0. */
typedef struct host_tls_slot {
    uint32_t native_index;
    uint32_t state;
} host_tls_slot;

/* Prepare a slot object for create().
 *
 * Requirement: `slot` must be zero-initialised before its first init()
 * (see the header comment). A live slot is rejected with
 * HOST_TLS_ERR_INVALID_STATE rather than silently leaking its index; call
 * destroy() first. init() on an already initialised or destroyed slot
 * succeeds and simply returns it to the ready state. */
host_tls_result host_tls_slot_init(host_tls_slot *slot);

/* Allocate a native TLS index for an initialised slot.
 *
 * Requires init() to have run. The native index may be 0; a success is
 * reported only through HOST_TLS_OK. On failure the handle is unchanged
 * (still ready, not live). The lifecycles of create()/destroy() are
 * externally synchronised by the caller (see preconditions). */
host_tls_result host_tls_slot_create(host_tls_slot *slot);

/* Release the native TLS index of a live slot.
 *
 * Requires a live slot and prior quiescence of every thread that may still
 * use it. The stored pointers themselves are never freed. On success the
 * slot becomes destroyed (init() may be called again to recreate it). On
 * failure the slot stays live and still owns its index. */
host_tls_result host_tls_slot_destroy(host_tls_slot *slot);

/* Read the calling thread's value from a live slot.
 *
 * On HOST_TLS_OK, *out_value is the stored pointer, or NULL when this
 * thread has no value (a valid, non-error state). On failure *out_value is
 * left untouched. Both arguments must be non-NULL. */
host_tls_result host_tls_get(const host_tls_slot *slot, void **out_value);

/* Store `value` for the calling thread in a live slot, replacing any
 * previous value. `value == NULL` clears the slot for the calling thread.
 * The stored pointer stays caller-owned: no destructor runs, nothing is
 * freed. `slot` must be non-NULL. */
host_tls_result host_tls_set(host_tls_slot *slot, void *value);

#ifdef __cplusplus
}
#endif
