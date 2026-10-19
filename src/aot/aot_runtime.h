/*
 * G2 AOT proof: translated-code runtime, exits, dispatcher and HLE gate.
 *
 * The dispatcher ONLY resolves a guest PC to a pretranslated native function
 * through a finite table. There is no opcode switch, no decoder and no JIT in
 * the native artifact; an unknown or misaligned target fails closed with the
 * source PC recorded. Generated code contains no ARM64 bytes.
 */
#ifndef AOT_RUNTIME_H
#define AOT_RUNTIME_H

#include "aot_abi.h"
#include "aot_mem.h"

#include <stddef.h>
#include <stdint.h>

/* Typed block exit reasons. Every block returns one of these and sets
 * `rt->next_pc` explicitly (for terminal reasons `next_pc` is the stop/fault
 * PC). */
typedef enum {
    AOT_EXIT_NONE          = 0u,
    AOT_EXIT_FALLTHROUGH   = 1u,  /* continue at block end */
    AOT_EXIT_BRANCH        = 2u,  /* unconditional direct B */
    AOT_EXIT_COND          = 3u,  /* B.cond / CBZ / TBZ, resolved to next_pc */
    AOT_EXIT_CALL          = 4u,  /* BL: x30 = site+4, continue at target */
    AOT_EXIT_INDIRECT      = 5u,  /* BR (and BLR's non-thunk path handled as CALL_INDIRECT) */
    AOT_EXIT_CALL_INDIRECT = 6u,  /* BLR: x30 = site+4, target in next_pc */
    AOT_EXIT_RET           = 7u,  /* RET xN / RET: next_pc = xN (or x30) */
    AOT_EXIT_SVC           = 8u,  /* SVC: emit AOT_HLE_SVC */
    AOT_EXIT_HOSTCALL      = 9u,  /* BLR into thunk: emit AOT_HLE_HOSTCALL */
    AOT_EXIT_STOP          = 10u, /* runtime-only terminal: emitted ONLY by the
                                     dispatcher at the stop sentinel after a RET;
                                     a generated block returning STOP is BAD_STATE */
    AOT_EXIT_FAULT         = 11u  /* fail-closed runtime fault */
} AotExit;

/* Fault codes (recorded in rt->fault). */
typedef enum {
    AOT_FAULT_NONE         = 0u,
    AOT_FAULT_UNKNOWN_PC   = 1u,  /* dispatch target not a translated entry */
    AOT_FAULT_MISALIGNED   = 2u,  /* dispatch target not 4-byte aligned */
    AOT_FAULT_MEMORY       = 3u,  /* arena access rejected */
    AOT_FAULT_BUDGET       = 4u,  /* step budget exhausted */
    AOT_FAULT_BAD_RESUME   = 5u,  /* HLE resume PC not a translated entry */
    AOT_FAULT_BAD_STATE    = 6u,  /* state invariant violated */
    AOT_FAULT_BAD_HLE      = 7u,  /* no handler for (kind,id) */
    AOT_FAULT_TAIL_THUNK   = 8u,  /* BR/tail branch into a host thunk */
    AOT_FAULT_NO_IMAGE     = 9u   /* dispatcher started without an image */
} AotFault;

typedef struct AotRuntime AotRuntime;
typedef AotExit (*AotBlockFn)(AotGuestState *s, AotRuntime *rt);

/* One translated entry. `entry_pc` is the guest PC of the block. */
typedef struct AotBlockEntry {
    uint64_t entry_pc;
    AotBlockFn fn;
} AotBlockEntry;

/* Explicit code ranges, for target validation and evidence. */
typedef struct AotCodeRange {
    uint64_t start;   /* inclusive */
    uint64_t end;     /* exclusive */
} AotCodeRange;

typedef struct AotImage {
    const char *subset_id;      /* AOT_SUBSET_ID identity */
    uint32_t abi_version;
    uint32_t state_layout;
    const char *source_sha256;  /* SHA-256 over fixtures+manifest+translator */
    uint64_t fixture_fnv64;     /* quick fixture checksum, NOT provenance */
    const AotBlockEntry *blocks;
    size_t block_count;         /* sorted by entry_pc */
    const AotCodeRange *ranges;
    size_t range_count;
    uint64_t thunk_base;        /* host-call thunk range start, 0 if none */
    uint64_t thunk_count;       /* number of 16-byte thunks */
    uint64_t thunk_stride;
} AotImage;

/* Bounded HLE event log. */
typedef struct AotHleEvent {
    uint32_t kind;
    uint32_t id;
    uint64_t site_pc;
    uint64_t resume_pc;
} AotHleEvent;

#define AOT_MAX_HANDLERS 32u
#define AOT_MAX_EVENTS   256u
#define AOT_MAX_TRACE    4096u
#define AOT_THUNK_STRIDE 16u

struct AotRuntime {
    AotMem mem;
    /* Exclusive monitor token attached to mem.domain for this runtime's
     * lifetime (0 = none). It is runtime-owned scratch, NOT guest state, so
     * the 816-byte AotGuestState ABI is unchanged. Re-init detaches the
     * previous token; aot_rt_release() detaches explicitly. The storage must
     * be zero-initialized before the FIRST aot_rt_init. */
    uint32_t monitor_token;
    uint32_t init_magic;
    AotGuestState *state;
    const AotImage *image;
    int identity_ok;      /* image identity validated at init */
    int running;          /* re-entrancy guard */
    uint64_t next_pc;
    AotExit reason;
    /* Per-block scratch set by generated code for HLE/call bookkeeping:
     * `site_pc` is the guest PC of the relevant instruction and `hle_id` is
     * the SVC imm16 (block sets it for EXIT_SVC). */
    uint64_t site_pc;
    uint32_t hle_id;

    uint64_t step_budget;
    uint64_t steps;

    /* Last fault. `fault_src` is the terminal transfer/source instruction
     * (native diagnostic); `fault_target` is the transfer target or the
     * accessed address and is the value compared against the reference. */
    uint32_t fault;
    uint64_t fault_src;
    uint64_t fault_target;
    int64_t fault_status;   /* AotMemStatus or AOT_STATE_ERR_* where relevant */

    /* HLE handlers keyed by (kind,id). */
    struct {
        uint32_t kind;
        uint32_t id;
        AotHleHandler fn;
        void *user;
    } handlers[AOT_MAX_HANDLERS];
    size_t handler_count;

    /* Bounded evidence logs. */
    AotHleEvent events[AOT_MAX_EVENTS];
    size_t event_count;
    int events_overflow;

    uint64_t trace[AOT_MAX_TRACE];
    size_t trace_count;
    int trace_overflow;
    int trace_enabled;
};

/* Initialize a runtime over an initialized arena and state. The image may be
 * NULL only for a runtime that will never dispatch (input validation still
 * runs). Returns AOT_FAULT_NONE or a fault code; image identity, metadata and
 * state invariants are validated fail-closed here. */
/* Detach this runtime's exclusive-monitor token (idempotent) and detach ALL
 * borrowed pointers (mem/domain, guest state, image). It never frees or owns
 * the caller's state or image, and it leaves the runtime non-runnable until a
 * fresh aot_rt_init. Call when the runtime is finished; reservations do not
 * survive the domain. A live AotRuntime is single-owner and not copyable: the
 * caller must not run it concurrently and must not release it concurrently
 * with a run. */
void aot_rt_release(AotRuntime *rt);

uint32_t aot_rt_init(AotRuntime *rt, const AotImage *image, AotMem mem,
                     AotGuestState *state, uint64_t step_budget);

/* Validate image metadata: non-NULL subset id matching AOT_SUBSET_ID, sorted
 * non-overlapping block entries, sorted non-overlapping code ranges, every
 * block inside a range, and sane thunk metadata. Returns AOT_FAULT_NONE or a
 * fault code. */
uint32_t aot_image_validate(const AotImage *image);

/* Register the handler for a (kind,id) pair. Duplicate (kind,id) is a
 * programming error and returns nonzero without changing the table. */
int aot_rt_set_handler(AotRuntime *rt, uint32_t kind, uint32_t id,
                       AotHleHandler fn, void *user);

/* Resolve a guest PC to a translated entry, or NULL. Misaligned targets and
 * targets outside the declared code ranges return NULL. */
AotBlockFn aot_rt_lookup(const AotRuntime *rt, uint64_t pc);

/* Run from `entry_pc` until STOP/FAULT. Returns the terminal reason and
 * leaves rt->reason / rt->next_pc / logs populated. */
AotExit aot_rt_run(AotRuntime *rt, uint64_t entry_pc, uint64_t stop_pc);

#endif /* AOT_RUNTIME_H */
