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
                                     dispatcher at the return sentinel after a
                                     RET; a generated block returning STOP is
                                     BAD_STATE */
    AOT_EXIT_FAULT         = 11u, /* fail-closed runtime fault */
    /* Program mode: `mrs Xt, <sysreg>`. Generated code sets rt->site_pc and
     * rt->hle_id = AOT_SYSREG_ID(sysreg16, Rt) and returns this; the runtime
     * dispatches AOT_HLE_SYSREG and resumes at site_pc + 4. */
    AOT_EXIT_SYSREG        = 12u
} AotExit;

/* Fault codes (recorded in rt->fault). Values 1..9 are the G2 codes and are
 * unchanged; 10.. are Program-mode codes appended by G3 increment 1. */
typedef enum {
    AOT_FAULT_NONE         = 0u,
    AOT_FAULT_UNKNOWN_PC   = 1u,  /* dispatch target not inside any image range */
    AOT_FAULT_MISALIGNED   = 2u,  /* dispatch target not 4-byte aligned */
    AOT_FAULT_MEMORY       = 3u,  /* arena/address-space access rejected */
    AOT_FAULT_BUDGET       = 4u,  /* step budget exhausted */
    AOT_FAULT_BAD_RESUME   = 5u,  /* HLE resume PC not a translated entry */
    AOT_FAULT_BAD_STATE    = 6u,  /* state invariant violated */
    AOT_FAULT_BAD_HLE      = 7u,  /* no handler for (kind,id) */
    AOT_FAULT_TAIL_THUNK   = 8u,  /* G2 only: BR/tail branch into a host thunk */
    AOT_FAULT_NO_IMAGE     = 9u,  /* dispatcher started without an image */
    /* Program mode additions. */
    AOT_FAULT_UNTRANSLATED = 10u, /* inside an image text range, no block */
    AOT_FAULT_BAD_TRANSFER = 11u, /* invalid entry into a thunk/transfer region */
    AOT_FAULT_BAD_RETURN   = 12u, /* sentinel reached not by a valid RET */
    AOT_FAULT_ABI_VIOLATION = 13u,/* callee-saved AAPCS64 state changed */
    AOT_FAULT_DEPTH        = 14u, /* host->guest call depth limit (16) */
    /* RESERVED, never produced in this increment: a guest thread-exit from a
     * nested (depth > 0) call is NOT modeled yet, and when the thread-exit ABI
     * lands it must fail closed with this code instead of unwinding a frame. */
    AOT_FAULT_EXIT_IN_NESTED = 15u,
    /* Partial-AOT image (-\-partial): the executed block reached a guest word
     * the module subset cannot decode. fault_src is that instruction's PC and
     * fault_status indexes the offline metadata table (raw word + decoder
     * reason). Appended without renumbering, so the existing contract and
     * AOT_STATE_LAYOUT/ABI version are unchanged. Never produced by a
     * non-partial image and never a substitute for decoding at run time. */
    AOT_FAULT_UNSUPPORTED_INSN = 16u
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

/* Program mode call depth (host -> guest frames). Slot `d` of the return
 * sentinel is sentinel_base + 16*d, so a Program needs sentinel_count >=
 * AOT_MAX_CALL_DEPTH. */
#define AOT_MAX_CALL_DEPTH 16u

/* ---------------------------------------------------------------- Program --
 *
 * A G3 "Program" is the validated, immutable-after-link set of ABI-v2 images
 * that one or more runtimes dispatch over. It owns nothing but borrowed
 * descriptors: the caller keeps every image/block table alive.
 *
 * Validation performed at link time (aot_program_finalize), fail-closed:
 *   - one to AOT_PROGRAM_MAX_IMAGES images, each AOT_ABI_VERSION_PROGRAM;
 *   - every image's text ranges sorted, 4-byte aligned and inside [2^32, 2^39)
 *     and disjoint from every OTHER image's ranges (sorted merged table);
 *   - every block entry inside one of its own ranges, strictly increasing;
 *   - one thunk region (16-byte stride) and one sentinel region (count >=
 *     AOT_MAX_CALL_DEPTH), both 16-byte aligned and disjoint from every image
 *     range, from each other, and UNMAPPED in the address space (a thunk or
 *     sentinel must never be readable/writable guest data);
 *   - an image declares no thunks of its own: AotProgImage has no thunk
 *     fields at all, so a v1 AotImage cannot be mistaken for a Program image;
 *   - handler keys (kind,id) unique, sorted for lookup.
 */
#define AOT_PROGRAM_MAX_IMAGES  16u
#define AOT_PROGRAM_MAX_RANGES  64u
#define AOT_PROGRAM_MAX_HANDLERS 65536u

typedef struct AotProgImage {
    const char *subset_id;      /* must equal AOT_SUBSET_ID_MODULE */
    uint32_t abi_version;       /* must equal AOT_ABI_VERSION_PROGRAM */
    uint32_t state_layout;      /* must equal AOT_STATE_LAYOUT */
    /* NOT merely a label: aot_loader_build_program BINDS this image to a
     * module descriptor by comparing it against the descriptor's flat SHA-256
     * (lowercase hex). An image whose value differs from the linked bytes is
     * refused (AOT_LOAD_ERR_SHA256), so it is the execution-time identity of
     * the translated code. */
    const char *source_sha256;
    uint64_t fixture_fnv64;     /* quick fixture checksum, NOT provenance */
    const AotBlockEntry *blocks;
    size_t block_count;         /* sorted by entry_pc, strictly increasing */
    const AotCodeRange *ranges;
    size_t range_count;         /* sorted, 4-byte aligned, non-overlapping */
} AotProgImage;

typedef struct AotProgHandlerEntry {
    uint32_t kind;   /* AotHleKind */
    uint32_t id;     /* svc imm16, thunk index or AOT_SYSREG_ID(...) */
    AotProgHandler fn;
    void *user;
} AotProgHandlerEntry;

typedef struct AotProgramRange {
    uint64_t start;
    uint64_t end;
    uint32_t image;  /* index into AotProgram.image */
} AotProgramRange;

typedef struct AotProgram {
    const AotAddressSpace *as;   /* borrowed; may be NULL (no AS check) */
    int finalized;
    uint32_t image_count;
    const AotProgImage *image[AOT_PROGRAM_MAX_IMAGES];
    uint32_t range_count;
    AotProgramRange range[AOT_PROGRAM_MAX_RANGES];
    uint64_t thunk_base;
    uint64_t thunk_count;
    uint64_t sentinel_base;
    uint64_t sentinel_count;
    AotProgHandlerEntry *handlers;   /* heap, sorted by (kind,id) */
    size_t handler_count;
    size_t handler_capacity;
} AotProgram;

/* Build a Program. `as` is optional: when non-NULL the thunk and sentinel
 * regions are additionally required to be unmapped in it. Returns NULL on
 * allocation failure. The returned Program owns its handler table only. */
AotProgram *aot_program_create(const AotAddressSpace *as);
void aot_program_destroy(AotProgram *p);

/* Pre-link builder calls. All return AOT_FAULT_NONE on success. */
uint32_t aot_program_add_image(AotProgram *p, const AotProgImage *img);
uint32_t aot_program_set_host_regions(AotProgram *p, uint64_t thunk_base,
                                     uint64_t thunk_count,
                                     uint64_t sentinel_base,
                                     uint64_t sentinel_count);
/* Duplicate (kind,id) is a programming error: returns nonzero and changes
 * nothing. Registration is only accepted before aot_program_finalize. */
int aot_program_set_handler(AotProgram *p, uint32_t kind, uint32_t id,
                            AotProgHandler fn, void *user);

/* Validate everything and freeze the Program. Returns AOT_FAULT_NONE or the
 * fault the Program would raise; a rejected Program is left unusable. */
uint32_t aot_program_finalize(AotProgram *p);

/* Queries (valid after finalize; aot_program_image_at/lookup also work on a
 * partially built Program for diagnostics). */
const AotProgImage *aot_program_image_at(const AotProgram *p, uint64_t pc);
AotBlockFn aot_program_lookup(const AotProgram *p, uint64_t pc);
int aot_program_is_entry(const AotProgram *p, uint64_t pc);
/* 1 and *off_bytes = pc - base when pc is inside the thunk/sentinel REGION. */
int aot_program_in_thunks(const AotProgram *p, uint64_t pc, uint64_t *off_bytes);
int aot_program_in_sentinel(const AotProgram *p, uint64_t pc, uint64_t *off_bytes);
const AotProgHandlerEntry *aot_program_handler(const AotProgram *p,
                                              uint32_t kind, uint32_t id);

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

    /* ---- Program mode (G3 increment 1) ----------------------------------
     * `program` is non-NULL only for a runtime initialized with
     * aot_rt_init_program; the legacy aot_rt_run path is then refused.
     * `owner_thread` is the OS thread id that created the runtime: only it
     * may make host->guest calls. `in_handler` counts active Program handlers
     * (a nested call is legal only while it is non-zero). `call_depth` is the
     * number of active aot_call_guest frames; the innermost frame index is
     * call_depth - 1 and selects the return sentinel slot. `call[]` holds the
     * per-frame return record (AAPCS64 callee-saved snapshot). */
    const AotProgram *program;
    int program_ok;
    uint32_t owner_thread;
    uint32_t in_handler;
    uint32_t call_depth;
    struct {
        uint64_t entry_sp;
        uint64_t sentinel_pc;
        uint64_t x19_x29[11];   /* x19..x29 at entry */
        uint64_t v8_v15[8];     /* low 64 bits of v8..v15 at entry */
        uint64_t fpcr;
    } call[AOT_MAX_CALL_DEPTH];
};

/* Initialize a runtime in Program mode over a finalized Program. `mem` must
 * be an address-space handle (aot_mem_init_aspace) when the Program was linked
 * against an address space, and it must be the SAME address space. Validates
 * the Program, the address-space binding and the state invariants fail-closed. */
uint32_t aot_rt_init_program(AotRuntime *rt, const AotProgram *program,
                             AotMem mem, AotGuestState *state,
                             uint64_t step_budget);

/* Run a guest function to completion (Program mode only).
 *
 * Legal at depth 0 (top-level entry from the owning host thread) and from
 * inside a Program HLE handler (one frame deeper). Max depth
 * AOT_MAX_CALL_DEPTH -> AOT_FAULT_DEPTH. Must be called on the thread that
 * initialized the runtime, else AOT_FAULT_BAD_STATE.
 *
 * Sets x0..x(nargs-1), sets x30 = sentinel slot for this depth, requires a
 * 16-byte aligned sp, records the entry sp and the AAPCS64 callee-saved state,
 * clears the LOCAL exclusive monitor before and after, and runs the dispatch
 * loop until a transfer reaches a sentinel slot. A return is valid only when
 * it was a RET (or a thunk resume) to THIS depth's slot with the entry sp;
 * otherwise AOT_FAULT_BAD_RETURN. A valid return then verifies sp, x19..x29,
 * the low 64 bits of v8..v15 and fpcr against the entry snapshot, else
 * AOT_FAULT_ABI_VIOLATION. Guest state is NEVER restored by the runtime.
 *
 * Returns AOT_FAULT_NONE on a clean return (x0 out-parameter) or the fault
 * code. Diagnostics (steps, events, trace) are shared by all depths and are
 * reset only by a depth-0 call, never by a nested one. */
uint32_t aot_call_guest(AotRuntime *rt, uint64_t fn, const uint64_t *args,
                        unsigned nargs, uint64_t *x0_out);

/* Initialize a runtime over an initialized arena and state (legacy G2 mode).
 * The image may be NULL only for a runtime that will never dispatch (input
 * validation still runs). Returns AOT_FAULT_NONE or a fault code; image
 * identity, metadata and state invariants are validated fail-closed here. */
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
