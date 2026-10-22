/* Minimal, game-data-free G3 Start HLE for SVC 0x29 (GetInfo), SVC 0x01
 * (SetHeapSize) and SVC 0x06 (QueryMemory).
 *
 * Scope: ONLY the path observed while running ORIGINAL nn::init::Start.
 * Current surface: GetInfo ids 2/3, 4/5, 6/7, 11, 12/13, 14/15, 21/22;
 * SetHeapSize (0x01), QueryMemory (0x06), thread priority/id (0x0c/0x25),
 * MapPhysicalMemory/UnmapPhysicalMemory (0x2c/0x2d), and the Mac HOST
 * OVERRIDE table (services.c:168-177) that the prefix's PLT `br x17` thunks
 * bind to by name.
 * Everything else stays a
 * typed AOT_FAULT_BAD_HLE with the guest register state untouched.
 *
 * SVC ABI rule (Mac services.c:258-279): the RegisterGroup handlers write
 * guest REGISTERS only for GetInfo/thread info, never their x0/x1 pointers.
 * QueryMemory is the explicit memory-output exception below. The guest
 * wrapper pushes the output pointer, then stores the returned w1 itself.
 *
 * SVC 0x06 describes the whole data AS: mapped permission runs, Free holes,
 * and an Inaccessible upper extent (Horizon). Mac's invented state-3/perm-5
 * fallback is NOT reproduced. An unusable AS is a typed failure, not a
 * guessed mapping. If the raw x0 output
 * pointer is nonzero, the 40-byte Mac MemoryInfo record is written through ONE
 * permission-checked aot_as_write (no host cast of a guest VA, no partial
 * write on failure).
 *
 * id 11 (random): call the injected entropy provider. Success is exactly
 * r0=0, r1=value; zero is a valid value. A provider failure is a typed
 * AOT_FAULT_BAD_HLE and leaves all guest registers/memory unchanged.
 */

#pragma once

#include "aot_runtime.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Provider contract: return 0 and write *out on success; return nonzero on
 * failure and leave *out unspecified (the HLE does not consume it). */
typedef int (*G3StartHleEntropy)(uint64_t *out, void *user);

typedef struct AotAddressSpace AotAddressSpace;

#define G3_START_HLE_INFO_RANDOM 11u
#define G3_START_HLE_FAULT_ENTROPY (-1)
/* Heap queries without a registered address space, or with no heap window,
 * fail closed with a NEGATIVE status (host/resource fault). Query ids keep
 * their non-negative id as the unknown-id status, as before. */
#define G3_START_HLE_FAULT_HEAP (-2)
#define G3_START_HLE_FAULT_SVC1_HOST (-3)
/* GetInfo(2/3) without an AS-owned alias reserved window. */
#define G3_START_HLE_FAULT_ALIAS (-4)
/* GetInfo(12/13) without a validated address-space instance. */
#define G3_START_HLE_FAULT_BOUNDS (-5)
/* GetInfo(14/15) without the AS-owned immutable global stack arena. */
#define G3_START_HLE_FAULT_STACK (-6)
/* SVC 0x06 without a usable (present, unpoisoned) address space. */
#define G3_START_HLE_FAULT_QUERY (-7)
/* Defensive SVC 0x06 query rejection (e.g. AS became unusable). Whole-domain
 * queries on a usable AS describe every uint64 address, including holes. */
#define G3_START_HLE_FAULT_QUERY_UNKNOWN (-8)
/* SVC 0x0c/0x25 without a borrowed thread registry (host misconfiguration).
 * An UNKNOWN handle is NOT this fault: it is the Mac Result 0xe401. */
#define G3_START_HLE_FAULT_THREAD (-9)
/* Mac services.c:310-313 invalid SetHeapSize result (r0). */
#define G3_START_HLE_INVALID_HEAP_SIZE 0xd401u
/* Mac threads.c:37 R_BAD_HANDLE. */
#define G3_START_HLE_BAD_HANDLE 0xe401u
/* Mac threads.c:41 H_CUR_THREAD. */
#define G3_START_HLE_CUR_THREAD 0xffff8000u
/* GetInfo 6/21/7/22 without a usable borrowed boot budget. */
#define G3_START_HLE_FAULT_BUDGET (-10)
#define G3_START_HLE_FAULT_DIAG (-11)
#define G3_START_HLE_FAULT_SYSRES (-12)
/* SVC 0x2c/0x2d without a usable address space or budget, or a host
 * commit/protect/decommit refusal. Mac aborts the process on a host failure,
 * so this port never invents a guest Result for it. */
#define G3_START_HLE_FAULT_ALIAS_MAP (-13)

/* Mac services.c:283 MapPhysicalMemory 0x2c / UnmapPhysicalMemory 0x2d
 * Result codes, returned in r0 verbatim. */
#define G3_START_HLE_ALIAS_INVALID_ALIGN 0xcc01u
#define G3_START_HLE_ALIAS_INVALID_RANGE 0xdc01u
#define G3_START_HLE_ALIAS_LIMIT 0x10801u

/* Borrowed IMMUTABLE boot budget: the Mac APP_POOL and the ACTUAL pinned
 * module image bytes (sum from the descriptors, page-up applied by the
 * caller profile). Only these two are viewed; heap logical size and mapped
 * alias bytes both come from the address space under ONE domain lock
 * (aot_as_heap_info / aot_as_usage), so GetInfo 7/22 cannot mix two
 * snapshots. */
typedef struct G3StartBudget {
    uint64_t pool;
    uint64_t image_bytes;
} G3StartBudget;

/* Borrowed view of the probe-owned thread registry. The HLE never allocates,
 * frees or mutates entries and implements no general Horizon handle manager. */
typedef struct G3StartThreadInfo {
    uint32_t handle;            /* 0x1001-style h_new value */
    uint32_t type;              /* 1 = THREAD; only THREAD resolves */
    uint32_t owner_os_thread;   /* host OS thread identity */
    uint32_t is_main;           /* pseudo-handle aliases ONLY this entry */
    uint64_t guest_id;          /* Horizon thread id (e.g. 0x51), NOT host TID */
    int32_t priority;
    int32_t core;
    uint64_t affinity_mask;
} G3StartThreadInfo;

typedef struct G3StartThreadRegistry {
    const G3StartThreadInfo *entries;
    uint32_t count;
} G3StartThreadRegistry;

/* Optional lookup provider. When set it REPLACES the borrowed-registry
 * adapter below; this keeps the SVC ABI testable with a deterministic
 * provider without introducing a general handle manager. */
typedef int (*G3StartHleThreadLookup)(uint32_t handle, G3StartThreadInfo *out,
                                      void *user);

/* ---- Mac host overrides (games/totk/runtime/services.c:168-177) ---------
 *
 * The faithful nn::init::Start prefix leaves guest code through PLT stubs
 * (`br x17`) into host thunks that the loader binds to a THUNK ORDINAL.
 * Mac substitutes a tiny host function for exactly the names in its override
 * table (services.c:237-240); those thunks then run host code instead of
 * guest code. Every override here is identified BY BINDING NAME, never by a
 * title-specific ordinal: the ordinal is data from the link configuration.
 *
 * Semantics are the Mac bodies, nothing more:
 *   _ZN2nn2oe10InitializeEv                            void, one print
 *   _ZN2nn3aoc10InitializeEv                            void, one print
 *   _ZN2nn3aoc17CountAddOnContentEv                     returns int 0
 *   _ZN2nn3aoc16ListAddOnContentEPiii                   returns int 0 and
 *                                                       writes nothing; a
 *                                                       negative offset or
 *                                                       count is the Mac
 *                                                       runtime_fail
 *   _ZN2nn3err26InitializeContextWriterApiEv            void, one print
 *   _ZN2nn4pctl10InitializeEv                           void, one print
 *   _ZN2nn4diag34InitializeApplicationAbortObserverEv   void, one print
 *   _ZN2nn2oe15SetCpuBoostModeENS0_12CpuBoostModeE     void, one print;
 *                                                       mode<0 || mode>2 is
 *                                                       the Mac runtime_fail
 * (The nn::diag namespace mangles as `4diag`; `2diag` is not a Mac symbol.)
 *
 * A void override writes NO guest register, NO flag and NO byte (the Mac
 * substitute only prints). CountAddOnContent writes x0 = 0 and nothing else.
 * ListAddOnContent writes x0 = 0 and nothing else for a non-negative
 * (offset,count) = ((int)x1,(int)x2); a negative value is a typed
 * AOT_FAULT_BAD_HLE with G3_START_HLE_FAULT_AOC_RANGE, touching neither a
 * register nor a guest byte (Mac aborts the process; there is no Result).
 *
 * _ZN2nn2fs24InitializeForApplicationEv (services.c:175) is deliberately NOT
 * in the table: its Mac body calls runtime_fs_init() and has real behaviour,
 * so it needs its own decision. It stays unregistered and keeps failing
 * closed; g3_start_hle_override_not_modelled() names it for a driver.
 *
 * A name the table does not know must be REFUSED at registration time, never
 * silently mapped to a default handler.
 */

/* An override handler was invoked with a request that is not a host call
 * (kind != AOT_HLE_HOSTCALL), or with a missing context: host configuration
 * error, not guest-visible. The request `id` is deliberately NOT checked --
 * it is the opaque thunk index owned by the link configuration. */
#define G3_START_HLE_FAULT_OVERRIDE (-14)
/* Mac services.c:172 runtime_fail: negative AddOnContent list offset/count. */
#define G3_START_HLE_FAULT_AOC_RANGE (-15)
/* Mac services.c:184 cpu_boost(): an unknown boost mode. A private status that
 * does not collide with the G4 RomFS adapter's -95..-125 band. */
#define G3_START_HLE_FAULT_CPU_BOOST (-16)

/* Per-name counter slots (G3StartHle.override_calls). */
typedef enum G3StartHleOverrideId {
    G3_START_HLE_OVERRIDE_OE_INIT = 0,
    G3_START_HLE_OVERRIDE_AOC_INIT,
    G3_START_HLE_OVERRIDE_AOC_COUNT,
    G3_START_HLE_OVERRIDE_AOC_LIST,
    G3_START_HLE_OVERRIDE_ERR_INIT,
    G3_START_HLE_OVERRIDE_PCTL_INIT,
    G3_START_HLE_OVERRIDE_ABORT_INIT,
    G3_START_HLE_OVERRIDE_OE_CPU_BOOST,
    G3_START_HLE_OVERRIDE_ID_COUNT
} G3StartHleOverrideId;

typedef struct G3StartHleOverride {
    const char *name;            /* exact Mac override symbol name */
    AotProgHandler handler;      /* AOT_HLE_HOSTCALL entry point */
    G3StartHleOverrideId id;     /* this name's counter slot */
} G3StartHleOverride;

/* Resolve one binding name to its entry. Returns NULL for anything the table
 * does not know (including the not-yet-modelled names): a registration driver
 * must then refuse the binding instead of installing a fallback. */
const G3StartHleOverride *g3_start_hle_override_lookup(const char *name);

/* 1 for a name whose Mac body is real host work this increment does not
 * model (currently only _ZN2nn2fs24InitializeForApplicationEv). Such a name
 * is also absent from the lookup table, so it can never be registered. */
int g3_start_hle_override_not_modelled(const char *name);

/* The whole name table, for a driver that has to report known names that the
 * link configuration did not bind (absent is NOT an error). */
unsigned g3_start_hle_override_table_count(void);
const G3StartHleOverride *g3_start_hle_override_table_at(unsigned index);

typedef struct G3StartHle {
    G3StartHleEntropy entropy;
    void *entropy_user;
    /* Borrowed address space used by GetInfo(2/3,4/5,12/13,14/15), SVC 0x01
     * and SVC 0x06. NULL is valid for the pure GetInfo(11) unit: queries then
     * fail closed. */
    AotAddressSpace *as;
    /* Borrowed handle registry for SVC 0x0c (GetThreadPriority) and SVC 0x25
     * (GetThreadId). NULL/empty makes those SVCs fail closed. */
    const G3StartThreadRegistry *threads;
    G3StartHleThreadLookup thread_lookup;
    void *thread_lookup_user;
    const G3StartBudget *budget;
    /* Per-NAME Mac host-override call counters (G3StartHleOverrideId order).
     * A void override increments only its slot; ListAddOnContent additionally
     * increments override_range_faults for the Mac runtime_fail case, and a
     * handler invoked with the wrong kind increments override_host_failures.
     * A missing context faults but cannot record a counter. */
    unsigned override_calls[G3_START_HLE_OVERRIDE_ID_COUNT];
    unsigned override_range_faults;
    /* Mac cpu_boost() runtime_fail rows (unknown CPU boost mode). */
    unsigned override_boost_range_faults;
    unsigned override_host_failures;
    unsigned entropy_calls;
    unsigned entropy_failures;
    unsigned unknown_info_calls;
    unsigned info2_calls;
    unsigned info3_calls;
    unsigned info12_calls;
    unsigned info13_calls;
    unsigned info14_calls;
    unsigned info15_calls;
    unsigned info4_calls;
    unsigned info5_calls;
    unsigned heap_query_failures;
    unsigned svc1_calls;
    unsigned svc1_invalid;
    unsigned svc1_host_failures;
    unsigned svc6_calls;
    unsigned svc6_success;
    unsigned svc6_null_out;
    unsigned svc6_unsupported;
    unsigned svc6_write_faults;
    unsigned svc6_host_failures;
    unsigned svc0c_calls;
    unsigned svc0c_success;
    unsigned svc0c_invalid;
    unsigned svc25_calls;
    unsigned svc25_success;
    unsigned svc25_invalid;
    unsigned thread_host_failures;
    unsigned info6_calls;
    unsigned info21_calls;
    unsigned info7_calls;
    unsigned info22_calls;
    unsigned budget_failures;
    unsigned host_diag_calls;
    unsigned svc2c_calls;
    unsigned svc2c_success;
    unsigned svc2c_invalid;
    unsigned svc2c_limit;
    unsigned svc2d_calls;
    unsigned svc2d_success;
    unsigned svc2d_invalid;
    unsigned alias_host_failures;
    uint64_t sysres_limit;
    unsigned sysres_configured;
    unsigned info16_calls;
    unsigned sysres_failures;
} G3StartHle;

/* Calls recorded for one table entry (0 for NULL). */
unsigned g3_start_hle_override_calls(const G3StartHle *ctx,
                                    const G3StartHleOverride *override_entry);

void g3_start_hle_init(G3StartHle *ctx, G3StartHleEntropy entropy,
                       void *entropy_user);

/* Borrow the real address space. Call before registering the SVC handlers. */
void g3_start_hle_set_address_space(G3StartHle *ctx, AotAddressSpace *as);

/* Borrow the immutable boot budget (never copied; must outlive execution). */
void g3_start_hle_set_budget(G3StartHle *ctx, const G3StartBudget *budget);
/* Process-profile SystemResourceBudget (GetInfo16); explicit presence permits
 * a configured zero without confusing it with a missing host configuration. */
void g3_start_hle_set_system_resource_limit(G3StartHle *ctx, uint64_t limit);

/* Borrow the probe-owned thread registry (never copied). */
void g3_start_hle_set_thread_registry(G3StartHle *ctx,
                                      const G3StartThreadRegistry *threads);

/* Override handle resolution with a deterministic provider (tests, or a
 * later real thread manager). */
void g3_start_hle_set_thread_lookup(G3StartHle *ctx,
                                    G3StartHleThreadLookup lookup,
                                    void *user);

/* Resolve a 32-bit guest handle to a THREAD entry. 0xFFFF8000
 * (H_CUR_THREAD) aliases ONLY the entry marked is_main: the borrowed
 * registry represents the single owned main thread, not general multithread
 * ownership. Returns 1 when found. */
int g3_start_hle_registry_lookup(const G3StartThreadRegistry *reg,
                                 uint32_t handle, G3StartThreadInfo *out);

/* AotProgHandler for AOT_HLE_SVC id 0x0c (GetThreadPriority). The Mac
 * semantics are exact: handle = (uint32_t)x1; unknown handle ->
 * r0=0xe401/r1=0; otherwise r0=0/r1=priority. No output pointer is read. */
void g3_start_hle_svc0c(AotRuntime *rt, AotGuestState *s,
                        const AotHleRequest *req, void *user);

/* AotProgHandler for AOT_HLE_SVC id 0x25 (GetThreadId): same handle lookup,
 * r1 is the GUEST id (0x51), never the host thread id. */
void g3_start_hle_svc25(AotRuntime *rt, AotGuestState *s,
                        const AotHleRequest *req, void *user);

/* AotProgHandler for AOT_HLE_SVC id 0x29. */
void g3_start_hle_svc(AotRuntime *rt, AotGuestState *s,
                      const AotHleRequest *req, void *user);

/* AotProgHandler for AOT_HLE_SVC id 0x01 (SetHeapSize). Invalid sizes return
 * r0=0xd401 with every other register untouched; host failures are a typed
 * BAD_HLE with no guest-register write. */
void g3_start_hle_svc1(AotRuntime *rt, AotGuestState *s,
                       const AotHleRequest *req, void *user);

/* AotProgHandler for AOT_HLE_SVC id 0x06 (whole data-AS QueryMemory).
 * r2 is the queried guest VA; r0 (if nonzero) receives the 40-byte record;
 * r1 is NEVER dereferenced. Success is exactly r0=0/r1=0, including Free and
 * upper Inaccessible records. An unusable AS fails closed, leaving every
 * guest register and byte unchanged. A failed 40-byte write is
 * AOT_FAULT_MEMORY with fault_target = the guest output pointer. */
void g3_start_hle_svc6(AotRuntime *rt, AotGuestState *s,
                       const AotHleRequest *req, void *user);

/* AotProgHandler for AOT_HLE_SVC id 0x2c (MapPhysicalMemory) and 0x2d
 * (UnmapPhysicalMemory): Mac services.c:283 `a=r[0], n=r[1]`, Result in r[0].
 * Maps/releases pages of the immutable alias reserved window through the
 * address space (D019), so QueryMemory and the GetInfo 7/22 budget agree with
 * the real page state. Only r0 is written; every other register is preserved.
 *   AOT_MEM_OK        -> r0=0
 *   AOT_MEM_ERR_ALIGN -> r0=0xcc01 (zero or unaligned size/address)
 *   AOT_MEM_ERR_RANGE -> r0=0xdc01 (request leaves the alias window)
 *   AOT_MEM_ERR_LIMIT -> r0=0x10801 (fresh bytes exceed the pool; map only)
 *   anything else     -> typed AOT_FAULT_BAD_HLE, no guest write (Mac aborts) */
void g3_start_hle_svc_alias(AotRuntime *rt, AotGuestState *s,
                            const AotHleRequest *req, void *user);

/* Mac nndiagStartup: void host diagnostics hook; preserves ALL guest state.
 * Registered by symbol name, not a fixed title-specific thunk ordinal. */
void g3_start_hle_host_diag(AotRuntime *rt, AotGuestState *s,
                           const AotHleRequest *req, void *user);

#ifdef __cplusplus
}
#endif
