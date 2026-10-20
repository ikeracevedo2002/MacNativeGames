/*
 * G2 AOT proof: guest architectural state ABI.
 *
 * This header is the *owned* Windows x86-64 guest-state schema for the G2
 * proof. It is deliberately NOT binary compatible with the Mac ARM64 gate
 * frame in games/totk/runtime/gate.S: that frame is an ARM64 call-preservation
 * layout, while here the state is an explicit C struct materialized at native
 * C function boundaries and passed to HLE handlers as a pointer.
 *
 * Design rules (see docs/g2-aot-proof.md):
 *   - memory-backed canonical state owned by the runtime, one entry per guest
 *     register class; no host pointers inside;
 *   - x18 is a NORMAL guest GPR. The macOS port reserves x18 for the platform
 *     register, but that reservation is a host detail, not a guest contract;
 *   - separate sp and pc; LR is the ordinary x30 slot;
 *   - nzcv is always normalized so only bits 31..28 can be set, and carries
 *     N,Z,C,V at those positions; no other CPSR bits are modeled in G2;
 *   - v[32] holds 16-byte lanes; fpcr/fpsr are preserved 32-bit-visible
 *     values (upper bits kept zero);
 *   - guest tpidr/tpidrro are modeled (not host TLS);
 *   - a stable layout version and static asserts pin offsets.
 */
#ifndef AOT_ABI_H
#define AOT_ABI_H

#include <stddef.h>
#include <stdint.h>

/* Identity triple. Any of these changing is an ABI/subset change and must be
 * reflected in the CFG manifest identity and in the generated code.
 *
 * Subset id g2-core-v2: the same ABI (AOT_ABI_VERSION / AOT_STATE_LAYOUT and
 * the 816-byte AotGuestState layout are UNCHANGED) over an expanded finite
 * instruction subset: the FP differential matrix (F32/F64 add/sub/mul/div/
 * fcmp/fcmpe, RN/RP/RM/RZ x DN x FZ), the post-SVC/post-HOSTCALL numeric
 * fixtures and the translated-memory concurrency fixtures. v1 was the smaller
 * first-subset id; see DECISIONS.md D012 for the scoped supersession. */
#define AOT_ABI_VERSION        1u
/* ABI version of an image intended for the G3 multi-image Program runtime:
 * thunks are guest functions entered by any transfer and the resume PC is the
 * guest's own x30, not site_pc + 4. AOT_ABI_VERSION (1) stays the G2
 * single-image ABI and behaves EXACTLY as before. A Program accepts only v2
 * images; the legacy G2 runtime accepts only v1 images. */
#define AOT_ABI_VERSION_PROGRAM 2u
#define AOT_STATE_LAYOUT       1u
#define AOT_SUBSET_ID          "g2-core-v2"
/* Program (ABI v2) images carry their OWN subset id: the multi-module
 * translator emits it and aot_program_finalize accepts ONLY this value for
 * ABI-v2 images. The legacy G2 single-image runtime keeps requiring
 * AOT_SUBSET_ID (they are different instruction subsets, not aliases). */
#define AOT_SUBSET_ID_MODULE   "g3-module-v1"

#define AOT_GPR_COUNT          31u   /* x0..x30 */
#define AOT_VREG_COUNT         32u
#define AOT_VREG_BYTES         16u

typedef struct AotGuestState {
    uint64_t x[AOT_GPR_COUNT];          /* x0..x30; x18 is ordinary */
    uint64_t sp;
    uint64_t pc;                        /* next PC owned by the runtime */
    uint64_t nzcv;                      /* N,Z,C,V in bits 31..28 only */
    uint64_t v[AOT_VREG_COUNT][2];      /* v[i][0]=low64, v[i][1]=high64 */
    uint64_t fpcr;
    uint64_t fpsr;
    uint64_t tpidr;
    uint64_t tpidrro;
} AotGuestState;

/* The runtime owns `pc`. `AOT_GUEST_STATE_FIXED` is the number of bytes
 * through `nzcv` that are integer GPR/flags state. */
#define AOT_GUEST_STATE_FIXED (offsetof(AotGuestState, v))

_Static_assert(AOT_GPR_COUNT == 31u, "ABI: 31 GPR slots");
_Static_assert(offsetof(AotGuestState, x) == 0u, "ABI: x offset");
_Static_assert(offsetof(AotGuestState, sp) == 31u * 8u, "ABI: sp offset");
_Static_assert(offsetof(AotGuestState, pc) == 32u * 8u, "ABI: pc offset");
_Static_assert(offsetof(AotGuestState, nzcv) == 33u * 8u, "ABI: nzcv offset");
_Static_assert(offsetof(AotGuestState, v) == 34u * 8u, "ABI: v offset");
_Static_assert(offsetof(AotGuestState, fpcr) == 34u * 8u + 32u * 16u, "ABI: fpcr offset");
_Static_assert(offsetof(AotGuestState, fpsr) == 35u * 8u + 32u * 16u, "ABI: fpsr offset");
_Static_assert(offsetof(AotGuestState, tpidr) == 36u * 8u + 32u * 16u, "ABI: tpidr offset");
_Static_assert(offsetof(AotGuestState, tpidrro) == 37u * 8u + 32u * 16u, "ABI: tpidrro offset");
_Static_assert(sizeof(AotGuestState) % 8u == 0u, "ABI: state is 8-byte multiple");
_Static_assert(_Alignof(AotGuestState) == 8u, "ABI: state alignment");
_Static_assert(sizeof(AotGuestState) == 38u * 8u + 32u * 16u, "ABI: state size");

/* NZCV accessors. These are the ONLY way the runtime/helpers pack flags, so
 * an `nzcv` value can never carry stray CPSR bits into comparisons. */
#define AOT_NZCV_MASK 0xfu
#define AOT_NZCV_SHIFT 28u

/* Invariant validation. The state schema claims three invariants and they are
 * CHECKED (not merely asserted) at dispatch entry and after every HLE handler:
 *   - nzcv has no bits outside 31..28 (normalized flags);
 *   - fpcr fits in 32 bits (upper 32 kept zero);
 *   - fpsr fits in 32 bits (upper 32 kept zero).
 * A violation is a fail-closed runtime fault, never a silent comparison. */
enum {
    AOT_STATE_OK = 0,
    AOT_STATE_ERR_NZCV = 1,
    AOT_STATE_ERR_FPCR = 2,
    AOT_STATE_ERR_FPSR = 3
};
static inline int aot_state_validate(const AotGuestState *s) {
    if (s == NULL) return AOT_STATE_ERR_NZCV;
    if ((s->nzcv & ~((uint64_t)AOT_NZCV_MASK << AOT_NZCV_SHIFT)) != 0u) {
        return AOT_STATE_ERR_NZCV;
    }
    if (s->fpcr > 0xffffffffULL) return AOT_STATE_ERR_FPCR;
    if (s->fpsr > 0xffffffffULL) return AOT_STATE_ERR_FPSR;
    return AOT_STATE_OK;
}
#define AOT_NZCV_PACK(n, z, c, v) \
    ((((uint64_t)((n) & 1u)) << 31) | (((uint64_t)((z) & 1u)) << 30) | \
     (((uint64_t)((c) & 1u)) << 29) | (((uint64_t)((v) & 1u)) << 28))
#define AOT_NZCV_N(s) (((s)->nzcv >> 31) & 1u)
#define AOT_NZCV_Z(s) (((s)->nzcv >> 30) & 1u)
#define AOT_NZCV_C(s) (((s)->nzcv >> 29) & 1u)
#define AOT_NZCV_V(s) (((s)->nzcv >> 28) & 1u)

/* A64 condition codes (low nibble of the B.cond/CSEL encoding). */
enum {
    AOT_COND_EQ = 0x0, AOT_COND_NE = 0x1, AOT_COND_CS = 0x2, AOT_COND_CC = 0x3,
    AOT_COND_MI = 0x4, AOT_COND_PL = 0x5, AOT_COND_VS = 0x6, AOT_COND_VC = 0x7,
    AOT_COND_HI = 0x8, AOT_COND_LS = 0x9, AOT_COND_GE = 0xa, AOT_COND_LT = 0xb,
    AOT_COND_GT = 0xc, AOT_COND_LE = 0xd, AOT_COND_AL = 0xe, AOT_COND_NV = 0xf
};

/* HLE request kinds. SVC and a host-call are distinct events:
 *   - SVC: a guest `svc #imm`; id = imm16; site_pc = the SVC instruction;
 *     the runtime resumes at site_pc + 4 (kernel ELR), regardless of x30.
 *   - HOSTCALL: a guest BL/BLR whose target lies in a host thunk range;
 *     id = thunk index; site_pc = the call-site PC; resume_pc = site_pc + 4
 *     (the architectural BL/BLR continuation, which is also what x30 holds).
 *
 * G2 scope: HOSTCALL is reached only through BL/BLR. A BR/tail branch whose
 * target lands in a thunk range is explicitly REJECTED (fail-closed) because
 * a tail entry would need the incoming guest LR, which G2 does not support.
 * resume_pc is always a guest PC, never a host pointer. */
typedef enum {
    AOT_HLE_SVC      = 1u,
    AOT_HLE_HOSTCALL = 2u,
    /* Program mode only: a guest `mrs Xt, <sysreg>` (AOT_EXIT_SYSREG).
     * id = AOT_SYSREG_ID(sysreg16, Rt); site_pc = the MRS instruction;
     * the runtime resumes at site_pc + 4 (the next instruction). */
    AOT_HLE_SYSREG   = 3u
} AotHleKind;

typedef struct AotHleRequest {
    uint32_t kind;          /* AotHleKind */
    uint32_t id;            /* svc imm16 or host thunk index */
    uint64_t site_pc;       /* guest PC of the call site */
    uint64_t resume_pc;     /* guest PC to resume at after the handler */
} AotHleRequest;

/*
 * Handler contract (a NEW Windows gate ABI; NOT the Mac ARM64 gate frame ABI):
 *   - the handler may read/modify every guest register class (x0..x30, sp,
 *     nzcv, v[], fpcr, fpsr, tpidr, tpidrro), including x30, sp and flags;
 *   - the handler must NOT be relied on to redirect control: the runtime owns
 *     pc and computes resume_pc itself, ignoring any handler change to pc;
 *   - ALL guest-memory access in a handler MUST go through the shared aot_mem_*
 *     API (the `user` pointer may carry the AotMem/arena). The runtime clears
 *     the LOCAL exclusive monitor at the SVC/HOSTCALL boundary, including
 *     after the handler; that clear is a CONSERVATIVE G2 PROOF POLICY, not an
 *     unconditional ARM exception-entry guarantee, and it is NOT a licence to
 *     read/write arena bytes directly;
 *   - nonlocal PC exits and callback reentry into guest code from a handler
 *     are NOT supported in G2. A handler that wants to observe/report does so
 *     through its own out-of-band state; it does not re-enter the dispatcher;
 *   - after the handler returns the runtime re-validates the state invariants
 *     and the resume PC before continuing.
 * This is a scoped G2 gate contract and does not claim compatibility with the
 * Mac binary gate/frame layout.
 */
typedef void (*AotHleHandler)(AotGuestState *s, const AotHleRequest *req, void *user);

/* Program-mode handler. It receives the runtime so it may make a NESTED
 * host->guest call (aot_call_guest) while the outer dispatch loop is suspended.
 * Everything the AotHleHandler contract says still applies, plus:
 *   - the runtime owns pc and the resume PC exactly as before;
 *   - a nested call's fault is STICKY: even if the handler ignores the
 *     returned fault code, the outer dispatch loop terminates with it. */
typedef struct AotRuntime AotRuntime;
typedef void (*AotProgHandler)(AotRuntime *rt, AotGuestState *s,
                              const AotHleRequest *req, void *user);

/*
 * System-register IDs (Program mode).
 *
 * An A64 MRS instruction encodes <sysreg> in bits 20..5 as the 16-bit field
 * `1:o0:op1:CRn:CRm:op2` (bit 20 is the constant opcode bit, bit 19 is o0,
 * op1 is bits 18..16, CRn bits 15..12, CRm bits 11..8, op2 bits 7..5).
 * The ARCHITECTURAL op0 is 2 + o0, which is why AOT_SYSREG16() takes op0.
 *
 * The runtime's HLE id folds that field together with the destination
 * register: id = (sysreg16 << 8) | Rt, so one handler can serve every
 * destination register of the same sysreg.
 */
#define AOT_SYSREG16(op0, op1, crn, crm, op2)                          \
    ((uint32_t)(0x8000u | ((((op0) - 2u) & 1u) << 14) |               \
                (((op1) & 7u) << 11) | (((crn) & 15u) << 7) |          \
                (((crm) & 15u) << 3) | ((op2) & 7u)))
#define AOT_SYSREG_ID(sysreg16, rt) \
    (((uint32_t)(sysreg16) << 8) | ((uint32_t)(rt) & 31u))
/* Handler-lookup key for an HLE id.
 *
 * AOT_HLE_SYSREG ids fold the DESTINATION REGISTER into the low 5 bits, but a
 * system register has at most ONE handler: handlers are registered with Rt=0
 * and looked up through this key, so one handler serves every Rt of that
 * register.  The handler learns the real destination from
 * AOT_SYSREG_ID_RT(req->id) -- aot_sysreg_write_dest() does exactly that and
 * writes nothing when Rt == 31, so an `mrs xzr, <sysreg>` still performs the
 * architectural read and still calls the handler exactly once.
 *
 * Every other HLE kind keys on the full id: SVC ids are the imm16 and
 * AOT_HLE_HOSTCALL ids are thunk indices, neither of which carries a register
 * number, so masking them would silently alias unrelated handlers. */
static inline uint32_t aot_hle_id_key(uint32_t kind, uint32_t id)
{
    return (kind == (uint32_t)AOT_HLE_SYSREG) ? (id & ~31u) : id;
}
#define AOT_SYSREG_ID_FIELD(id) ((uint32_t)((id) >> 8) & 0xffffu)
#define AOT_SYSREG_ID_RT(id)    ((uint32_t)(id) & 31u)

/* CNTPCT_EL0: op0=3, op1=3, CRn=14, CRm=0, op2=1 -> 0xDF01.
 * CNTVCT_EL0: same but op2=2 -> 0xDF02. */
#define AOT_SYSREG_CNTPCT_EL0 AOT_SYSREG16(3u, 3u, 14u, 0u, 1u)
#define AOT_SYSREG_CNTVCT_EL0 AOT_SYSREG16(3u, 3u, 14u, 0u, 2u)
/* TPIDR_EL0 (op2=2) / TPIDRRO_EL0 (op2=3): translated INLINE from the guest
 * state (no HLE request), so these exist for fixture/probe clarity. */
#define AOT_SYSREG_TPIDR_EL0   AOT_SYSREG16(3u, 3u, 13u, 0u, 2u)
#define AOT_SYSREG_TPIDRRO_EL0 AOT_SYSREG16(3u, 3u, 13u, 0u, 3u)

_Static_assert(AOT_SYSREG_CNTPCT_EL0 == 0xDF01u, "SYSREG: CNTPCT_EL0 field");
_Static_assert(AOT_SYSREG_CNTVCT_EL0 == 0xDF02u, "SYSREG: CNTVCT_EL0 field");
_Static_assert(AOT_SYSREG_ID_RT(AOT_SYSREG_ID(AOT_SYSREG_CNTPCT_EL0, 31u)) == 31u,
               "SYSREG: id carries Rt");

/* Deliver a SYSREG handler result to the guest destination encoded in
 * req->id. Rt == 31 is XZR: the value is DISCARDED (there is no x31 slot in
 * AotGuestState, and a discarded write must not disturb any other register).
 * Handlers must use this helper (or the same rule) for MRS results. */
static inline void aot_sysreg_write_dest(AotGuestState *s,
                                        const AotHleRequest *req,
                                        uint64_t value) {
    uint32_t rt;
    if (s == NULL || req == NULL) return;
    rt = AOT_SYSREG_ID_RT(req->id);
#ifdef MN_AOT_MUTANT_SYSREG_XZR
    /* TEST-ONLY wrong-implementation control: an Rt=31 (XZR) write is not
     * discarded; it is redirected into x0, which guest code can observe. */
    s->x[(rt < AOT_GPR_COUNT) ? rt : 0u] = value;
#else
    if (rt < AOT_GPR_COUNT) s->x[rt] = value;
#endif
}

#endif /* AOT_ABI_H */
