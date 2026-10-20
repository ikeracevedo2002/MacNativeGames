/*
 * G3 increment 1: Program (multi-image dispatch) contract probe.
 *
 * The "images" are hand-written FAKE block functions at guest virtual
 * addresses above 4 GiB. They are NOT translator output and prove nothing about
 * translation; they exist only to drive the dispatcher boundary rules
 * (resolution order, thunks as guest functions, sentinel returns, nested
 * host->guest calls, SYSREG/SVC HLE) deterministically. No game data, no ARM
 * bytes.
 *
 * Exit protocol (the mutant driver depends on it):
 *   0 = every contract check passed
 *   2 = at least one semantic check failed (prints "FAIL: <check>")
 *   1 = infrastructure failure (prints "FATAL: <reason>")
 */
#include "aot_runtime.h"
#include "aot_as.h"

#include "host_thread.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail = 0;

static void check(int cond, const char *msg) {
    if (!cond) {
        printf("FAIL: %s\n", msg);
        g_fail = 1;
    }
}

static void fatal(const char *msg) {
    printf("FATAL: %s\n", msg);
    exit(1);
}

#define IMG_A 0x100000000ull
#define IMG_B 0x101000000ull
#define IMG_C 0x102000000ull
#define TEXT_SIZE 0x1000ull
#define THUNK_BASE 0x103000000ull
#define THUNK_COUNT 10ull
#define SENTINEL_BASE 0x104000000ull
#define SENTINEL_COUNT 16ull
#define DATA_BASE 0x105000000ull
#define DATA_SIZE 0x8000ull
#define STACK_TOP (DATA_BASE + 0x4000ull)

/* Read-only guest page used by the memory-fault probe. */
#define REG_RO 0x106000000ull
#define DATA_RO_ADDR (REG_RO + 0x40ull)
/* Slot stride for the per-thread shared-memory test. */
#define SMEM_SLOT(i) (DATA_BASE + 0x2000ull + 64ull * (uint64_t)(i))

#define THUNK(n) (THUNK_BASE + 16ull * (uint64_t)(n))
#define SENTINEL(n) (SENTINEL_BASE + 16ull * (uint64_t)(n))

/* ---- Image A block addresses ------------------------------------------- */
#define A_CALL_B         (IMG_A + 0x000ull)
#define A_AFTER_B        (IMG_A + 0x004ull)
#define A_CALL_BLR       (IMG_A + 0x008ull)
#define A_AFTER_BLR      (IMG_A + 0x00cull)
#define A_CALL_BR        (IMG_A + 0x010ull)
#define A_ENTRY_RET      (IMG_A + 0x014ull)
#define A_T_BY_BL        (IMG_A + 0x020ull)
#define A_T_AFTER_BL     (IMG_A + 0x024ull)
#define A_PLT_CALLER     (IMG_A + 0x040ull)
#define A_PLT_CONT       (IMG_A + 0x044ull)
#define A_B_THUNK        (IMG_A + 0x050ull)
#define A_RET_THUNK      (IMG_A + 0x060ull)
#define A_BAD_LR         (IMG_A + 0x070ull)
#define A_T5_BL          (IMG_A + 0x080ull)
#define A_T5_CONT        (IMG_A + 0x084ull)
#define A_SVC            (IMG_A + 0x090ull)
#define A_SVC_CONT       (IMG_A + 0x094ull)
#define A_SVC_BAD        (IMG_A + 0x098ull)
#define A_SYSREG         (IMG_A + 0x0a0ull)
#define A_SYSREG_CONT    (IMG_A + 0x0a4ull)
#define A_SYSREG_ZR      (IMG_A + 0x0b0ull)
#define A_SYSREG_ZR_CONT (IMG_A + 0x0b4ull)
#define A_UNTRANSLATED   (IMG_A + 0x0c0ull)
#define A_DATA_TARGET    (IMG_A + 0x0c4ull)
#define A_MISALIGNED     (IMG_A + 0x0c8ull)
#define A_WRONG_SLOT     (IMG_A + 0x0d0ull)
#define A_WRONG_SP       (IMG_A + 0x0d4ull)
#define A_BR_SENTINEL    (IMG_A + 0x0d8ull)
#define A_CLOBBER_X19    (IMG_A + 0x0e0ull)
#define A_DEPTH          (IMG_A + 0x0e4ull)
#define A_DEPTH_CONT     (IMG_A + 0x0e8ull)
#define A_INNER_FAULT    (IMG_A + 0x0f0ull)
#define A_INNER_CONT     (IMG_A + 0x0f4ull)
#define A_NESTED         (IMG_A + 0x100ull)
#define A_NESTED_CONT    (IMG_A + 0x104ull)
#define A_FALL_THUNK     (IMG_A + 0x110ull)
#define A_BLR_THUNK      (IMG_A + 0x114ull)
#define A_BLR_THUNK_CONT (IMG_A + 0x118ull)
#define A_COND_THUNK     (IMG_A + 0x120ull)
#define A_SMEM           (IMG_A + 0x130ull)
#define A_RO_STORE       (IMG_A + 0x134ull)
/* Deliberately inside image A's declared range but with no block. */
#define A_NOT_A_BLOCK    (IMG_A + 0x800ull)

#define B_FUNC     (IMG_B + 0x000ull)
#define B_FUNC2    (IMG_B + 0x010ull)
#define B_FUNC3    (IMG_B + 0x020ull)
#define B_MAIN     (IMG_B + 0x030ull)
#define B_MAIN_CONT (IMG_B + 0x034ull)

#define C_PLT      (IMG_C + 0x000ull)
#define C_FN       (IMG_C + 0x010ull)
#define C_FN_CONT  (IMG_C + 0x014ull)

/* ---- probe state -------------------------------------------------------- */
static AotMemDomain *g_dom;
static AotAddressSpace *g_as;
static AotProgram *g_prog;
static AotRuntime g_rt;
static AotGuestState g_state;
static AotMem g_mem;

static uint64_t g_entry_lr;
static uint64_t g_lr_bmain;
static uint64_t g_lr_cfn;
static uint64_t g_lr_depth[16];
static uint64_t g_depth_lr_used;

static int g_hit[THUNK_COUNT + 4u];
static uint64_t g_last_site;
static uint64_t g_last_resume;
static uint32_t g_last_kind;
static uint32_t g_last_id;
static uint64_t g_obs_x30;
static int g_zr_ok;
static int g_scratch_ok;
static int g_depth_calls;
static uint32_t g_depth_last_rc;
static uint32_t g_inner_rc;
static int g_inner_cont_ran;
static uint64_t g_inner_marker;
static uint32_t g_recall_rc;
static uint64_t g_recall_steps;
static uint64_t g_recall_steps_before;
static uint32_t g_smem_rc;
static uint32_t g_ro_status;
static int g_scenario;

enum { SCN_DEFAULT = 0, SCN_NESTED = 1, SCN_INNER = 2, SCN_INNER_BAD = 3 };

static AotExit exit_at(AotRuntime *rt, uint64_t site, uint64_t next, AotExit e) {
    rt->site_pc = site;
    rt->next_pc = next;
    return e;
}

/* ---- fake blocks: image A ---------------------------------------------- */
static AotExit a_call_b(AotGuestState *s, AotRuntime *rt) {
    g_entry_lr = s->x[30];
    s->x[30] = A_CALL_B + 4u;
    return exit_at(rt, A_CALL_B, B_FUNC, AOT_EXIT_CALL);
}
static AotExit a_after_b(AotGuestState *s, AotRuntime *rt) {
    s->x[1] = s->x[0];
    s->x[30] = g_entry_lr;
    return exit_at(rt, A_AFTER_B, s->x[30], AOT_EXIT_RET);
}
static AotExit a_call_blr(AotGuestState *s, AotRuntime *rt) {
    g_entry_lr = s->x[30];
    s->x[2] = B_FUNC2;
    s->x[30] = A_CALL_BLR + 4u;
    return exit_at(rt, A_CALL_BLR, s->x[2], AOT_EXIT_CALL_INDIRECT);
}
static AotExit a_after_blr(AotGuestState *s, AotRuntime *rt) {
    s->x[3] = s->x[0];
    s->x[30] = g_entry_lr;
    return exit_at(rt, A_AFTER_BLR, s->x[30], AOT_EXIT_RET);
}
static AotExit a_call_br(AotGuestState *s, AotRuntime *rt) {
    (void)s;
    /* BR does not touch x30: B_FUNC3 returns straight to the sentinel. */
    return exit_at(rt, A_CALL_BR, B_FUNC3, AOT_EXIT_INDIRECT);
}
static AotExit a_entry_ret(AotGuestState *s, AotRuntime *rt) {
    s->x[0] += 1u;
    return exit_at(rt, A_ENTRY_RET, s->x[30], AOT_EXIT_RET);
}
static AotExit a_t_by_bl(AotGuestState *s, AotRuntime *rt) {
    g_entry_lr = s->x[30];
    s->x[30] = A_T_BY_BL + 4u;
    return exit_at(rt, A_T_BY_BL, THUNK(0), AOT_EXIT_CALL);
}
static AotExit a_t_after_bl(AotGuestState *s, AotRuntime *rt) {
    s->x[4] = s->x[30];
    s->x[30] = g_entry_lr;
    return exit_at(rt, A_T_AFTER_BL, s->x[30], AOT_EXIT_RET);
}
static AotExit a_plt_caller(AotGuestState *s, AotRuntime *rt) {
    g_entry_lr = s->x[30];
    s->x[30] = A_PLT_CONT;
    return exit_at(rt, A_PLT_CALLER, C_PLT, AOT_EXIT_CALL);
}
static AotExit a_plt_cont(AotGuestState *s, AotRuntime *rt) {
    s->x[6] = s->x[30];
    s->x[30] = g_entry_lr;
    return exit_at(rt, A_PLT_CONT, s->x[30], AOT_EXIT_RET);
}
static AotExit a_b_thunk(AotGuestState *s, AotRuntime *rt) {
    (void)s;
    /* Tail B: x30 stays the sentinel slot, so the thunk returns to the host. */
    return exit_at(rt, A_B_THUNK, THUNK(9), AOT_EXIT_BRANCH);
}
static AotExit a_ret_thunk(AotGuestState *s, AotRuntime *rt) {
    (void)s;
    return exit_at(rt, A_RET_THUNK, THUNK(3), AOT_EXIT_RET);
}
static AotExit a_bad_lr(AotGuestState *s, AotRuntime *rt) {
    s->x[30] = DATA_BASE + 0x1000ull;   /* mapped data, not a translated entry */
    return exit_at(rt, A_BAD_LR, THUNK(4), AOT_EXIT_CALL);
}
static AotExit a_t5_bl(AotGuestState *s, AotRuntime *rt) {
    g_entry_lr = s->x[30];
    s->x[30] = A_T5_BL + 4u;
    return exit_at(rt, A_T5_BL, THUNK(5), AOT_EXIT_CALL);
}
static AotExit a_t5_cont(AotGuestState *s, AotRuntime *rt) {
    g_obs_x30 = s->x[30];
    s->x[30] = g_entry_lr;
    return exit_at(rt, A_T5_CONT, s->x[30], AOT_EXIT_RET);
}
static AotExit a_svc(AotGuestState *s, AotRuntime *rt) {
    (void)s;
    rt->hle_id = 0x40u;
    return exit_at(rt, A_SVC, 0, AOT_EXIT_SVC);
}
static AotExit a_svc_cont(AotGuestState *s, AotRuntime *rt) {
    return exit_at(rt, A_SVC_CONT, s->x[30], AOT_EXIT_RET);
}
static AotExit a_svc_bad(AotGuestState *s, AotRuntime *rt) {
    (void)s;
    rt->hle_id = 0x41u;
    return exit_at(rt, A_SVC_BAD, 0, AOT_EXIT_SVC);
}
static AotExit a_sysreg(AotGuestState *s, AotRuntime *rt) {
    (void)s;
    rt->hle_id = AOT_SYSREG_ID(AOT_SYSREG_CNTPCT_EL0, 3u);
    return exit_at(rt, A_SYSREG, 0, AOT_EXIT_SYSREG);
}
static AotExit a_sysreg_cont(AotGuestState *s, AotRuntime *rt) {
    return exit_at(rt, A_SYSREG_CONT, s->x[30], AOT_EXIT_RET);
}
static AotExit a_sysreg_zr(AotGuestState *s, AotRuntime *rt) {
    (void)s;
    rt->hle_id = AOT_SYSREG_ID(AOT_SYSREG_CNTPCT_EL0, 31u);
    return exit_at(rt, A_SYSREG_ZR, 0, AOT_EXIT_SYSREG);
}
static AotExit a_sysreg_zr_cont(AotGuestState *s, AotRuntime *rt) {
    return exit_at(rt, A_SYSREG_ZR_CONT, s->x[30], AOT_EXIT_RET);
}
static AotExit a_untranslated(AotGuestState *s, AotRuntime *rt) {
    (void)s;
    return exit_at(rt, A_UNTRANSLATED, A_NOT_A_BLOCK, AOT_EXIT_BRANCH);
}
static AotExit a_data_target(AotGuestState *s, AotRuntime *rt) {
    (void)s;
    return exit_at(rt, A_DATA_TARGET, DATA_BASE, AOT_EXIT_BRANCH);
}
static AotExit a_misaligned(AotGuestState *s, AotRuntime *rt) {
    (void)s;
    return exit_at(rt, A_MISALIGNED, IMG_B + 2u, AOT_EXIT_BRANCH);
}
static AotExit a_wrong_slot(AotGuestState *s, AotRuntime *rt) {
    (void)s;
    return exit_at(rt, A_WRONG_SLOT, SENTINEL(1), AOT_EXIT_RET);
}
static AotExit a_wrong_sp(AotGuestState *s, AotRuntime *rt) {
    s->sp += 8u;
    return exit_at(rt, A_WRONG_SP, SENTINEL(0), AOT_EXIT_RET);
}
static AotExit a_br_sentinel(AotGuestState *s, AotRuntime *rt) {
    (void)s;
    return exit_at(rt, A_BR_SENTINEL, SENTINEL(0), AOT_EXIT_INDIRECT);
}
static AotExit a_clobber_x19(AotGuestState *s, AotRuntime *rt) {
    s->x[19] += 1u;
    return exit_at(rt, A_CLOBBER_X19, s->x[30], AOT_EXIT_RET);
}
static AotExit a_depth(AotGuestState *s, AotRuntime *rt) {
    uint32_t idx = rt->call_depth - 1u;
    if (idx < 16u) {
        g_lr_depth[idx] = s->x[30];
        g_depth_lr_used = idx + 1u;
    }
    s->x[30] = A_DEPTH + 4u;
    return exit_at(rt, A_DEPTH, THUNK(6), AOT_EXIT_CALL);
}
static AotExit a_depth_cont(AotGuestState *s, AotRuntime *rt) {
    uint32_t idx = rt->call_depth - 1u;
    s->x[30] = (idx < 16u) ? g_lr_depth[idx] : s->x[30];
    return exit_at(rt, A_DEPTH_CONT, s->x[30], AOT_EXIT_RET);
}
static AotExit a_inner_fault(AotGuestState *s, AotRuntime *rt) {
    g_entry_lr = s->x[30];
    s->x[30] = A_INNER_CONT;
    return exit_at(rt, A_INNER_FAULT, THUNK(7), AOT_EXIT_CALL);
}
static AotExit a_inner_cont(AotGuestState *s, AotRuntime *rt) {
    /* Marker: this OUTER resume block must never run once the handler's inner
     * fault is sticky. Both a counter and a guest-memory write are recorded so
     * the sticky contract is checked on the observable guest side too. */
    g_inner_cont_ran++;
    {
        AotMemStatus st = aot_mem_st64(&rt->mem, DATA_BASE + 0x3000ull,
                                       0xdeadbeefull);
        if (st == AOT_MEM_OK) g_inner_marker = 0xdeadbeefull;
    }
    s->x[30] = g_entry_lr;
    return exit_at(rt, A_INNER_CONT, s->x[30], AOT_EXIT_RET);
}
/* Publishes s->x[0] to the guest address in s->x[1] THROUGH THE ADDRESS SPACE:
 * the shared region is the only channel between the probe's threads. */
static AotExit a_smem(AotGuestState *s, AotRuntime *rt) {
    AotMemStatus st = aot_mem_st64(&rt->mem, s->x[1], s->x[0]);
    g_smem_rc = (uint32_t)st;
    return exit_at(rt, A_SMEM, s->x[30], AOT_EXIT_RET);
}
/* Attempts a store into a READ-ONLY guest page and reports the fault the
 * runtime must surface (MEMORY with the AOT_MEM status and the target VA). */
static AotExit a_ro_store(AotGuestState *s, AotRuntime *rt) {
    (void)s;
    {
        AotMemStatus st = aot_mem_st64(&rt->mem, DATA_RO_ADDR, 0x7777ull);
        g_ro_status = (uint32_t)st;
        rt->fault = AOT_FAULT_MEMORY;
        rt->fault_status = (uint32_t)st;
        rt->fault_target = DATA_RO_ADDR;
        rt->fault_src = A_RO_STORE;
    }
    return exit_at(rt, A_RO_STORE, 0, AOT_EXIT_FAULT);
}
static AotExit a_nested(AotGuestState *s, AotRuntime *rt) {
    g_entry_lr = s->x[30];
    s->x[30] = A_NESTED + 4u;
    return exit_at(rt, A_NESTED, B_MAIN, AOT_EXIT_CALL);
}
static AotExit a_nested_cont(AotGuestState *s, AotRuntime *rt) {
    s->x[9] = s->x[0];
    s->x[30] = g_entry_lr;
    return exit_at(rt, A_NESTED_CONT, s->x[30], AOT_EXIT_RET);
}
static AotExit a_fall_thunk(AotGuestState *s, AotRuntime *rt) {
    (void)s;
    /* Fallthrough into a thunk: x30 is still the sentinel slot. */
    return exit_at(rt, A_FALL_THUNK, THUNK(8), AOT_EXIT_FALLTHROUGH);
}
static AotExit a_blr_thunk(AotGuestState *s, AotRuntime *rt) {
    /* BLR into a thunk. The BLR continuation is placed in x30 and is what the
     * thunk resumes at (architecturally the same value as site + 4). */
    g_entry_lr = s->x[30];
    s->x[2] = THUNK(1);
    s->x[30] = A_BLR_THUNK + 4u;
    return exit_at(rt, A_BLR_THUNK, s->x[2], AOT_EXIT_CALL_INDIRECT);
}
static AotExit a_blr_thunk_cont(AotGuestState *s, AotRuntime *rt) {
    s->x[10] = s->x[30];
    s->x[30] = g_entry_lr;
    return exit_at(rt, A_BLR_THUNK_CONT, s->x[30], AOT_EXIT_RET);
}
static AotExit a_cond_thunk(AotGuestState *s, AotRuntime *rt) {
    (void)s;
    /* B.cond / CBZ / TBZ all resolve to AOT_EXIT_COND with a taken target. */
    return exit_at(rt, A_COND_THUNK, THUNK(9), AOT_EXIT_COND);
}

/* ---- fake blocks: images B and C --------------------------------------- */
static AotExit b_func(AotGuestState *s, AotRuntime *rt) {
    s->x[0] += 0x10u;
    return exit_at(rt, B_FUNC, s->x[30], AOT_EXIT_RET);
}
static AotExit b_func2(AotGuestState *s, AotRuntime *rt) {
    s->x[0] *= 2u;
    return exit_at(rt, B_FUNC2, s->x[30], AOT_EXIT_RET);
}
static AotExit b_func3(AotGuestState *s, AotRuntime *rt) {
    s->x[0] += 0x100u;
    return exit_at(rt, B_FUNC3, s->x[30], AOT_EXIT_RET);
}
static AotExit b_main(AotGuestState *s, AotRuntime *rt) {
    g_lr_bmain = s->x[30];
    s->x[30] = B_MAIN + 4u;
    return exit_at(rt, B_MAIN, THUNK(0), AOT_EXIT_CALL);
}
static AotExit b_main_cont(AotGuestState *s, AotRuntime *rt) {
    s->x[7] = s->x[0];
    s->x[30] = g_lr_bmain;
    return exit_at(rt, B_MAIN_CONT, s->x[30], AOT_EXIT_RET);
}
static AotExit c_plt(AotGuestState *s, AotRuntime *rt) {
    (void)s;
    /* PLT-like stub: BR to the thunk with x30 = the caller's return address. */
    return exit_at(rt, C_PLT, THUNK(1), AOT_EXIT_INDIRECT);
}
static AotExit c_fn(AotGuestState *s, AotRuntime *rt) {
    g_lr_cfn = s->x[30];
    s->x[30] = C_FN + 4u;
    return exit_at(rt, C_FN, THUNK(2), AOT_EXIT_CALL);
}
static AotExit c_fn_cont(AotGuestState *s, AotRuntime *rt) {
    s->x[8] = s->x[0];
    s->x[30] = g_lr_cfn;
    return exit_at(rt, C_FN_CONT, s->x[30], AOT_EXIT_RET);
}

/* ---- handlers ---------------------------------------------------------- */
static void hle_thunk0(AotRuntime *rt, AotGuestState *s,
                       const AotHleRequest *req, void *u) {
    (void)u;
    g_hit[0]++;
    g_last_site = req->site_pc;
    g_last_resume = req->resume_pc;
    g_last_kind = req->kind;
    g_last_id = req->id;
    if (g_scenario == SCN_NESTED) {
        uint64_t v = 0;
        uint64_t save_next = rt->next_pc;
        uint64_t save_site = rt->site_pc;
        uint32_t save_hle = rt->hle_id;
        AotExit save_reason = rt->reason;
        uint64_t save_pc = s->pc;
        uint32_t rc = aot_call_guest(rt, C_FN, &s->x[0], 1, &v);
        if (rt->next_pc != save_next || rt->site_pc != save_site ||
            rt->hle_id != save_hle || rt->reason != save_reason ||
            s->pc != save_pc) {
            g_scratch_ok = 0;
        }
        if (rc == AOT_FAULT_NONE) s->x[0] = v + 1u;
    } else {
        s->x[0] += 7u;
    }
}
static void hle_thunk1(AotRuntime *rt, AotGuestState *s,
                       const AotHleRequest *req, void *u) {
    (void)rt; (void)u;
    g_hit[1]++;
    g_last_site = req->site_pc;
    g_last_resume = req->resume_pc;
    s->x[0] += 1u;
}
static void hle_thunk2(AotRuntime *rt, AotGuestState *s,
                       const AotHleRequest *req, void *u) {
    (void)rt; (void)u; (void)req;
    g_hit[2]++;
    s->x[0] += 100u;
}
static void hle_thunk3(AotRuntime *rt, AotGuestState *s,
                       const AotHleRequest *req, void *u) {
    (void)rt; (void)s; (void)req; (void)u;
    g_hit[3]++;
}
static void hle_thunk4(AotRuntime *rt, AotGuestState *s,
                       const AotHleRequest *req, void *u) {
    (void)rt; (void)s; (void)req; (void)u;
    g_hit[4]++;
}
static void hle_thunk5(AotRuntime *rt, AotGuestState *s,
                       const AotHleRequest *req, void *u) {
    (void)rt; (void)req; (void)u;
    g_hit[5]++;
    s->x[30] = 0xdeadbeefull;   /* must NOT redirect control flow */
}
static void hle_thunk6(AotRuntime *rt, AotGuestState *s,
                       const AotHleRequest *req, void *u) {
    (void)s; (void)req; (void)u;
    g_hit[6]++;
    g_depth_calls++;
    g_depth_last_rc = aot_call_guest(rt, A_DEPTH, NULL, 0, NULL);
}
static void hle_thunk7(AotRuntime *rt, AotGuestState *s,
                       const AotHleRequest *req, void *u) {
    (void)req; (void)u;
    g_hit[7]++;
    /* Inner fault the handler deliberately IGNORES. */
    g_inner_rc = aot_call_guest(rt, A_NOT_A_BLOCK, NULL, 0, NULL);
    /* A SECOND nested call after that sticky fault must be refused with the
     * same fault and must not run anything (item-3 guard). */
    {
        g_recall_steps_before = rt->steps;
        g_recall_rc = aot_call_guest(rt, A_ENTRY_RET, NULL, 0, NULL);
        g_recall_steps = rt->steps;
    }
    s->x[0] = 0x9999ull;
    if (g_scenario == SCN_INNER_BAD) {
        /* Minor 1: leave the guest state INVALID after the inner fault. The
         * sticky INNER fault must still win over the state diagnosis (an
         * implementation that validates the state first reports BAD_STATE and
         * loses the real cause). */
        s->sp |= 4u;
    }
}
static void hle_thunk8(AotRuntime *rt, AotGuestState *s,
                       const AotHleRequest *req, void *u) {
    (void)rt; (void)req; (void)u;
    g_hit[8]++;
    s->x[0] += 1000u;
}
static void hle_thunk9(AotRuntime *rt, AotGuestState *s,
                       const AotHleRequest *req, void *u) {
    (void)rt; (void)req; (void)u;
    g_hit[9]++;
    s->x[0] += 500u;
}
static void hle_svc_40(AotRuntime *rt, AotGuestState *s,
                       const AotHleRequest *req, void *u) {
    (void)rt; (void)u; (void)req;
    s->x[5] += 1u;
}
/* ONE handler per CNTPCT_EL0 (review fix 1): the id carries Rt and lookup
 * keys on (kind, id & ~31u), so this single handler serves every Rt; it must
 * therefore handle both an ordinary destination and the Rt=31 (XZR) discard. */
static void hle_sysreg_reg(AotRuntime *rt, AotGuestState *s,
                           const AotHleRequest *req, void *u) {
    uint64_t before[AOT_GPR_COUNT];
    (void)rt; (void)u;
    if (AOT_SYSREG_ID_FIELD(req->id) != AOT_SYSREG_CNTPCT_EL0) g_zr_ok = 0;
    if (AOT_SYSREG_ID_RT(req->id) == 31u) {
        memcpy(before, s->x, sizeof(before));
        aot_sysreg_write_dest(s, req, 0x1122ull);
        if (memcmp(before, s->x, sizeof(before)) != 0) g_zr_ok = 0;
    } else {
        aot_sysreg_write_dest(s, req, 0x1122ull);
    }
}

/* ---- block tables ------------------------------------------------------ */
static const AotBlockEntry blocks_a[] = {
    { A_CALL_B, a_call_b },
    { A_AFTER_B, a_after_b },
    { A_CALL_BLR, a_call_blr },
    { A_AFTER_BLR, a_after_blr },
    { A_CALL_BR, a_call_br },
    { A_ENTRY_RET, a_entry_ret },
    { A_T_BY_BL, a_t_by_bl },
    { A_T_AFTER_BL, a_t_after_bl },
    { A_PLT_CALLER, a_plt_caller },
    { A_PLT_CONT, a_plt_cont },
    { A_B_THUNK, a_b_thunk },
    { A_RET_THUNK, a_ret_thunk },
    { A_BAD_LR, a_bad_lr },
    { A_T5_BL, a_t5_bl },
    { A_T5_CONT, a_t5_cont },
    { A_SVC, a_svc },
    { A_SVC_CONT, a_svc_cont },
    { A_SVC_BAD, a_svc_bad },
    { A_SYSREG, a_sysreg },
    { A_SYSREG_CONT, a_sysreg_cont },
    { A_SYSREG_ZR, a_sysreg_zr },
    { A_SYSREG_ZR_CONT, a_sysreg_zr_cont },
    { A_UNTRANSLATED, a_untranslated },
    { A_DATA_TARGET, a_data_target },
    { A_MISALIGNED, a_misaligned },
    { A_WRONG_SLOT, a_wrong_slot },
    { A_WRONG_SP, a_wrong_sp },
    { A_BR_SENTINEL, a_br_sentinel },
    { A_CLOBBER_X19, a_clobber_x19 },
    { A_DEPTH, a_depth },
    { A_DEPTH_CONT, a_depth_cont },
    { A_INNER_FAULT, a_inner_fault },
    { A_INNER_CONT, a_inner_cont },
    { A_NESTED, a_nested },
    { A_NESTED_CONT, a_nested_cont },
    { A_FALL_THUNK, a_fall_thunk },
    { A_BLR_THUNK, a_blr_thunk },
    { A_BLR_THUNK_CONT, a_blr_thunk_cont },
    { A_COND_THUNK, a_cond_thunk },
    { A_SMEM, a_smem },
    { A_RO_STORE, a_ro_store },
};
static const AotCodeRange ranges_a[] = { { IMG_A, IMG_A + TEXT_SIZE } };

static const AotBlockEntry blocks_b[] = {
    { B_FUNC, b_func },
    { B_FUNC2, b_func2 },
    { B_FUNC3, b_func3 },
    { B_MAIN, b_main },
    { B_MAIN_CONT, b_main_cont },
};
static const AotCodeRange ranges_b[] = { { IMG_B, IMG_B + TEXT_SIZE } };

static const AotBlockEntry blocks_c[] = {
    { C_PLT, c_plt },
    { C_FN, c_fn },
    { C_FN_CONT, c_fn_cont },
};
static const AotCodeRange ranges_c[] = { { IMG_C, IMG_C + TEXT_SIZE } };

static const AotProgImage img_a = {
    AOT_SUBSET_ID_MODULE, AOT_ABI_VERSION_PROGRAM, AOT_STATE_LAYOUT, "sha-a", 0,
    blocks_a, sizeof(blocks_a) / sizeof(blocks_a[0]), ranges_a, 1
};
static const AotProgImage img_b = {
    AOT_SUBSET_ID_MODULE, AOT_ABI_VERSION_PROGRAM, AOT_STATE_LAYOUT, "sha-b", 0,
    blocks_b, sizeof(blocks_b) / sizeof(blocks_b[0]), ranges_b, 1
};
static const AotProgImage img_c = {
    AOT_SUBSET_ID_MODULE, AOT_ABI_VERSION_PROGRAM, AOT_STATE_LAYOUT, "sha-c", 0,
    blocks_c, sizeof(blocks_c) / sizeof(blocks_c[0]), ranges_c, 1
};

/* ---- helpers ----------------------------------------------------------- */
static void probe_reset(void) {
    memset(g_hit, 0, sizeof(g_hit));
    g_last_site = 0;
    g_last_resume = 0;
    g_last_kind = 0;
    g_last_id = 0;
    g_obs_x30 = 0;
    g_entry_lr = 0;
    g_lr_bmain = 0;
    g_lr_cfn = 0;
    g_depth_calls = 0;
    g_depth_last_rc = AOT_FAULT_NONE;
    g_inner_rc = AOT_FAULT_NONE;
    g_inner_cont_ran = 0;
    g_inner_marker = 0;
    g_recall_rc = AOT_FAULT_NONE;
    g_recall_steps = 0;
    g_recall_steps_before = 0;
    g_smem_rc = AOT_MEM_OK;
    g_ro_status = AOT_MEM_OK;
    g_depth_lr_used = 0;
}

static void reset_state(void) {
    memset(&g_state, 0, sizeof(g_state));
    g_state.sp = STACK_TOP;
    g_scratch_ok = 1;
    g_zr_ok = 1;
    probe_reset();
}

static uint32_t call1(uint64_t fn, uint64_t arg, uint64_t *x0) {
    reset_state();
    g_scenario = SCN_DEFAULT;
    return aot_call_guest(&g_rt, fn, &arg, 1, x0);
}

static void build_program(void) {
    uint32_t rc;
    g_prog = aot_program_create(g_as);
    if (g_prog == NULL) fatal("program create");
    if (aot_program_add_image(g_prog, &img_a) != AOT_FAULT_NONE)
        fatal("add image A");
    if (aot_program_add_image(g_prog, &img_b) != AOT_FAULT_NONE)
        fatal("add image B");
    if (aot_program_add_image(g_prog, &img_c) != AOT_FAULT_NONE)
        fatal("add image C");
    if (aot_program_set_host_regions(g_prog, THUNK_BASE, THUNK_COUNT,
                                    SENTINEL_BASE, SENTINEL_COUNT) !=
        AOT_FAULT_NONE)
        fatal("set host regions");
    if (aot_program_set_handler(g_prog, AOT_HLE_HOSTCALL, 0, hle_thunk0, NULL))
        fatal("handler 0");
    if (aot_program_set_handler(g_prog, AOT_HLE_HOSTCALL, 1, hle_thunk1, NULL))
        fatal("handler 1");
    if (aot_program_set_handler(g_prog, AOT_HLE_HOSTCALL, 2, hle_thunk2, NULL))
        fatal("handler 2");
    if (aot_program_set_handler(g_prog, AOT_HLE_HOSTCALL, 3, hle_thunk3, NULL))
        fatal("handler 3");
    if (aot_program_set_handler(g_prog, AOT_HLE_HOSTCALL, 4, hle_thunk4, NULL))
        fatal("handler 4");
    if (aot_program_set_handler(g_prog, AOT_HLE_HOSTCALL, 5, hle_thunk5, NULL))
        fatal("handler 5");
    if (aot_program_set_handler(g_prog, AOT_HLE_HOSTCALL, 6, hle_thunk6, NULL))
        fatal("handler 6");
    if (aot_program_set_handler(g_prog, AOT_HLE_HOSTCALL, 7, hle_thunk7, NULL))
        fatal("handler 7");
    if (aot_program_set_handler(g_prog, AOT_HLE_HOSTCALL, 8, hle_thunk8, NULL))
        fatal("handler 8");
    if (aot_program_set_handler(g_prog, AOT_HLE_HOSTCALL, 9, hle_thunk9, NULL))
        fatal("handler 9");
    if (aot_program_set_handler(g_prog, AOT_HLE_SVC, 0x40, hle_svc_40, NULL))
        fatal("handler svc");
    if (aot_program_set_handler(g_prog, AOT_HLE_SYSREG,
                                AOT_SYSREG_ID(AOT_SYSREG_CNTPCT_EL0, 0u),
                                hle_sysreg_reg, NULL))
        fatal("handler sysreg");
    /* Review fix 1: a second registration of the SAME system register with a
     * different Rt in the id must be a DUPLICATE (one handler serves all Rt). */
    if (aot_program_set_handler(g_prog, AOT_HLE_SYSREG,
                                AOT_SYSREG_ID(AOT_SYSREG_CNTPCT_EL0, 31u),
                                hle_sysreg_reg, NULL) != 2)
        fatal("handler sysreg duplicate Rt was accepted");
    rc = aot_program_finalize(g_prog);
    if (rc != AOT_FAULT_NONE) fatal("program finalize");
    check(aot_program_finalize(g_prog) == AOT_FAULT_NONE,
          "program finalize is idempotent");
}

/* ---- link-time validation ---------------------------------------------- */
static void test_link_validation(void) {
    AotProgram *p;
    AotProgImage bad;

    p = aot_program_create(g_as);
    if (p == NULL) fatal("validation program create");
    bad = img_a;
    bad.abi_version = AOT_ABI_VERSION;   /* v1 image is not a Program image */
    check(aot_program_add_image(p, &bad) == AOT_FAULT_BAD_STATE,
          "ABI v1 image is rejected by a Program");
    bad = img_a;
    bad.subset_id = "other-subset";
    check(aot_program_add_image(p, &bad) == AOT_FAULT_BAD_STATE,
          "image with a foreign subset id is rejected");
    bad = img_a;
    bad.state_layout = 99u;
    check(aot_program_add_image(p, &bad) == AOT_FAULT_BAD_STATE,
          "image with a foreign state layout is rejected");
    /* A block outside the declared ranges. */
    {
        static const AotBlockEntry outside[] = {
            { IMG_A, a_entry_ret },
            { IMG_A + TEXT_SIZE, a_entry_ret },
        };
        bad = img_a;
        bad.blocks = outside;
        bad.block_count = 2;
        check(aot_program_add_image(p, &bad) == AOT_FAULT_BAD_STATE,
              "block outside the image text range is rejected");
    }
    check(aot_program_add_image(p, &img_a) == AOT_FAULT_NONE,
          "valid image is accepted");
    check(aot_program_add_image(p, &img_b) == AOT_FAULT_NONE,
          "second valid image is accepted");
    /* Overlapping image text ranges (blocks stay valid for the new range). */
    {
        static const AotCodeRange overlap_r[] = {
            { IMG_B + 0x800ull, IMG_B + 0x1800ull },
        };
        static const AotBlockEntry overlap_b[] = {
            { IMG_B + 0x800ull, b_func },
        };
        bad = img_b;
        bad.ranges = overlap_r;
        bad.blocks = overlap_b;
        bad.block_count = 1;
        check(aot_program_add_image(p, &bad) == AOT_FAULT_BAD_STATE,
              "overlapping image text ranges are rejected");
    }
    /* Duplicate handler key. */
    check(aot_program_set_handler(p, AOT_HLE_SVC, 0x40, hle_svc_40, NULL) == 0,
          "handler registration");
    check(aot_program_set_handler(p, AOT_HLE_SVC, 0x40, hle_svc_40, NULL) != 0,
          "duplicate handler key is rejected");
    /* Thunk region overlapping an image range. */
    check(aot_program_set_host_regions(p, IMG_A + 0x200ull, 4u, SENTINEL_BASE,
                                       SENTINEL_COUNT) == AOT_FAULT_NONE,
          "host region set");
    check(aot_program_finalize(p) == AOT_FAULT_BAD_STATE,
          "thunk region overlapping image text is rejected");
    aot_program_destroy(p);

    /* Sentinel count below the call-depth requirement. */
    p = aot_program_create(g_as);
    if (p == NULL) fatal("validation program create 2");
    if (aot_program_add_image(p, &img_a) != AOT_FAULT_NONE) fatal("img a");
    if (aot_program_set_host_regions(p, THUNK_BASE, THUNK_COUNT, SENTINEL_BASE,
                                     8u) != AOT_FAULT_NONE)
        fatal("regions 2");
    check(aot_program_finalize(p) == AOT_FAULT_BAD_STATE,
          "sentinel region with fewer slots than the call depth is rejected");
    aot_program_destroy(p);

    /* Thunk/sentinel regions must be unmapped guest data. */
    p = aot_program_create(g_as);
    if (p == NULL) fatal("validation program create 3");
    if (aot_program_add_image(p, &img_a) != AOT_FAULT_NONE) fatal("img a3");
    if (aot_program_set_host_regions(p, DATA_BASE, 4u, SENTINEL_BASE,
                                     SENTINEL_COUNT) != AOT_FAULT_NONE)
        fatal("regions 3");
    check(aot_program_finalize(p) == AOT_FAULT_BAD_STATE,
          "thunk region mapped in the address space is rejected");
    aot_program_destroy(p);

    /* Thunk and sentinel regions overlapping each other. */
    p = aot_program_create(g_as);
    if (p == NULL) fatal("validation program create 4");
    if (aot_program_add_image(p, &img_a) != AOT_FAULT_NONE) fatal("img a4");
    if (aot_program_set_host_regions(p, SENTINEL_BASE, 4u, SENTINEL_BASE,
                                     SENTINEL_COUNT) != AOT_FAULT_NONE)
        fatal("regions 4");
    check(aot_program_finalize(p) == AOT_FAULT_BAD_STATE,
          "overlapping thunk and sentinel regions are rejected");
    aot_program_destroy(p);

    /* Handler table: thousands of entries, unique keys, frozen at finalize. */
    p = aot_program_create(g_as);
    if (p == NULL) fatal("validation program create 5");
    if (aot_program_add_image(p, &img_a) != AOT_FAULT_NONE) fatal("img a5");
    if (aot_program_set_host_regions(p, THUNK_BASE, THUNK_COUNT, SENTINEL_BASE,
                                     SENTINEL_COUNT) != AOT_FAULT_NONE)
        fatal("regions 5");
    for (unsigned i = 0; i < 4096u; i++) {
        if (aot_program_set_handler(p, AOT_HLE_SVC, i, hle_svc_40, NULL) != 0)
            fatal("bulk handler registration");
    }
    check(aot_program_set_handler(p, AOT_HLE_SVC, 1234u, hle_svc_40, NULL) != 0,
          "duplicate key among thousands of handlers is rejected");
    check(aot_program_finalize(p) == AOT_FAULT_NONE,
          "program with thousands of handlers finalizes");
    check(aot_program_handler(p, AOT_HLE_SVC, 0u) != NULL &&
              aot_program_handler(p, AOT_HLE_SVC, 500u) != NULL &&
              aot_program_handler(p, AOT_HLE_SVC, 4095u) != NULL,
          "handler lookup works across thousands of entries");
    check(aot_program_handler(p, AOT_HLE_SVC, 4096u) == NULL,
          "absent handler key is not found");
    check(aot_program_set_handler(p, AOT_HLE_SVC, 9999u, hle_svc_40, NULL) != 0,
          "handler table is frozen at finalize");
    check(aot_program_add_image(p, &img_b) == AOT_FAULT_BAD_STATE,
          "image table is frozen at finalize");
    aot_program_destroy(p);
}

/* ---- dispatch scenarios ------------------------------------------------ */
static void test_cross_image(void) {
    uint64_t x0 = 0, arg = 5;
    uint32_t rc = call1(A_CALL_B, arg, &x0);
    check(rc == AOT_FAULT_NONE, "cross-image BL returns cleanly");
    check(x0 == 0x15ull, "cross-image BL result");
    check(g_state.x[1] == 0x15ull, "BL continuation saw the callee result");
    check(g_state.x[30] == SENTINEL(0), "BL frame returned via x30");
    check(g_rt.steps == 3u, "cross-image BL step count");

    rc = call1(A_CALL_BLR, arg, &x0);
    check(rc == AOT_FAULT_NONE, "cross-image BLR returns cleanly");
    check(x0 == 10ull && g_state.x[3] == 10ull, "BLR result and continuation");
    check(g_rt.steps == 3u, "BLR step count");

    rc = call1(A_CALL_BR, arg, &x0);
    check(rc == AOT_FAULT_NONE, "cross-image BR returns cleanly");
    check(x0 == 0x105ull, "BR tail-call result");
    check(g_rt.steps == 2u, "BR step count");
}

static void test_resolution_faults(void) {
    uint64_t x0 = 0;
    uint32_t rc = call1(A_UNTRANSLATED, 0, &x0);
    check(rc == AOT_FAULT_UNTRANSLATED,
          "target inside a text range without a block is UNTRANSLATED");
    check(g_rt.fault_src == A_UNTRANSLATED &&
              g_rt.fault_target == A_NOT_A_BLOCK,
          "UNTRANSLATED diagnostics (source and target)");

    rc = call1(A_DATA_TARGET, 0, &x0);
    check(rc == AOT_FAULT_UNKNOWN_PC,
          "mapped data address target is UNKNOWN_PC (not UNTRANSLATED)");
    check(g_rt.fault_target == DATA_BASE, "UNKNOWN_PC target is the data address");

    rc = call1(A_MISALIGNED, 0, &x0);
    check(rc == AOT_FAULT_MISALIGNED, "misaligned target is MISALIGNED");
    check(g_rt.fault_src == A_MISALIGNED && g_rt.fault_target == IMG_B + 2u,
          "MISALIGNED diagnostics");

    /* The entry PC itself is resolved by the same rules. */
    rc = call1(A_NOT_A_BLOCK, 0, &x0);
    check(rc == AOT_FAULT_UNTRANSLATED, "untranslated entry is UNTRANSLATED");
    check(g_rt.fault_src == A_NOT_A_BLOCK &&
              g_rt.fault_target == A_NOT_A_BLOCK,
          "untranslated entry diagnostics");
}

static void test_thunks(void) {
    uint64_t x0 = 0, arg = 10;
    uint32_t rc = call1(A_T_BY_BL, arg, &x0);
    check(rc == AOT_FAULT_NONE, "thunk entered by BL returns cleanly");
    check(x0 == 17ull, "thunk handler side effect");
    check(g_hit[0] == 1, "thunk handler called once");
    check(g_last_kind == AOT_HLE_HOSTCALL && g_last_id == 0u,
          "thunk request kind/id");
    check(g_last_site == A_T_BY_BL, "thunk request site_pc is the BL site");
    check(g_last_resume == A_T_AFTER_BL,
          "thunk request resume_pc is x30 (BL site + 4)");
    check(g_state.x[4] == A_T_AFTER_BL, "BL thunk resumed at site+4");
    check(g_rt.event_count == 1u, "one HOSTCALL event recorded");

    /* PLT-like stub: BR to the thunk keeps x30 = the caller's return address. */
    rc = call1(A_PLT_CALLER, 0, &x0);
    check(rc == AOT_FAULT_NONE, "thunk entered by BR (PLT stub) returns cleanly");
    check(x0 == 1ull, "PLT thunk side effect");
    check(g_hit[1] == 1, "PLT thunk handler called once");
    check(g_last_site == C_PLT, "PLT thunk site_pc is the BR site");
    check(g_last_resume == A_PLT_CONT,
          "PLT thunk resume_pc is the caller return, not site+4");
    check(g_state.x[6] == A_PLT_CONT,
          "PLT thunk resumed at the caller return address");

    /* Tail B into a thunk: x30 is still the sentinel, so it returns to host. */
    rc = call1(A_B_THUNK, 0, &x0);
    check(rc == AOT_FAULT_NONE, "thunk entered by B returns to the host");
    check(x0 == 500ull && g_hit[9] == 1, "B thunk side effect");

    /* Fallthrough into a thunk. */
    rc = call1(A_FALL_THUNK, 0, &x0);
    check(rc == AOT_FAULT_NONE, "thunk reached by fallthrough returns to the host");
    check(x0 == 1000ull && g_hit[8] == 1, "fallthrough thunk side effect");

    /* BLR into a thunk. */
    rc = call1(A_BLR_THUNK, 0, &x0);
    check(rc == AOT_FAULT_NONE, "thunk entered by BLR returns cleanly");
    check(x0 == 1ull && g_hit[1] == 1, "BLR thunk side effect");
    check(g_last_site == A_BLR_THUNK, "BLR thunk site_pc is the BLR site");
    check(g_last_resume == A_BLR_THUNK + 4u,
          "BLR thunk resume_pc is the BLR continuation");
    check(g_state.x[10] == A_BLR_THUNK + 4u,
          "BLR thunk resumed at the continuation");

    /* B.cond / CBZ / TBZ share AOT_EXIT_COND; a taken condition into a thunk
     * enters it exactly like a B. */
    rc = call1(A_COND_THUNK, 0, &x0);
    check(rc == AOT_FAULT_NONE, "thunk entered by a conditional branch returns");
    check(x0 == 500ull && g_hit[9] == 1, "conditional-branch thunk side effect");

    /* RET into a thunk is not a guest function call. */
    rc = call1(A_RET_THUNK, 0, &x0);
    check(rc == AOT_FAULT_BAD_TRANSFER, "thunk entered by RET is BAD_TRANSFER");
    check(g_rt.fault_src == A_RET_THUNK &&
              g_rt.fault_target == THUNK(3),
          "BAD_TRANSFER diagnostics");
    check(g_hit[3] == 0, "BAD_TRANSFER does not run the handler");

    /* Invalid x30 at entry: no side effects, handler not called. */
    rc = call1(A_BAD_LR, 0x1234ull, &x0);
    check(rc == AOT_FAULT_BAD_RESUME, "thunk with an invalid x30 is BAD_RESUME");
    check(g_rt.fault_src == A_BAD_LR &&
              g_rt.fault_target == DATA_BASE + 0x1000ull,
          "BAD_RESUME diagnostics");
    check(g_hit[4] == 0, "BAD_RESUME does not run the handler");
    check(g_state.x[0] == 0x1234ull, "BAD_RESUME has no side effects");

    /* A handler that writes x30 must not redirect control flow. */
    rc = call1(A_T5_BL, 0, &x0);
    check(rc == AOT_FAULT_NONE,
          "handler x30 clobber does not affect control flow");
    check(g_obs_x30 == 0xdeadbeefull,
          "handler x30 clobber is visible in guest state");
    check(g_hit[5] == 1, "clobbering handler ran");
}

static void test_svc_and_sysreg(void) {
    uint64_t x0 = 0;
    uint32_t rc = call1(A_SVC, 0, &x0);
    check(rc == AOT_FAULT_NONE, "SVC returns cleanly");
    check(g_state.x[5] == 1u, "SVC handler side effect");
    check(g_rt.event_count == 1u && g_rt.events[0].kind == AOT_HLE_SVC &&
              g_rt.events[0].id == 0x40u &&
              g_rt.events[0].site_pc == A_SVC &&
              g_rt.events[0].resume_pc == A_SVC + 4u,
          "SVC event carries site+4 resume");

    rc = call1(A_SVC_BAD, 0, &x0);
    check(rc == AOT_FAULT_BAD_HLE, "SVC without a handler is BAD_HLE");

    rc = call1(A_SYSREG, 0, &x0);
    check(rc == AOT_FAULT_NONE, "SYSREG exit returns cleanly");
    check(g_state.x[3] == 0x1122ull, "SYSREG handler wrote the destination");
    check(g_rt.event_count == 1u && g_rt.events[0].kind == AOT_HLE_SYSREG &&
              g_rt.events[0].id ==
                  AOT_SYSREG_ID(AOT_SYSREG_CNTPCT_EL0, 3u) &&
              g_rt.events[0].site_pc == A_SYSREG &&
              g_rt.events[0].resume_pc == A_SYSREG + 4u,
          "SYSREG event carries the sysreg/rt id and site+4 resume");

    rc = call1(A_SYSREG_ZR, 0, &x0);
    check(rc == AOT_FAULT_NONE, "SYSREG with Rt=31 returns cleanly");
    check(g_zr_ok, "SYSREG Rt=31 write is discarded (XZR)");
}

static void test_nested_and_diagnostics(void) {
    uint64_t x0 = 0, arg = 5;
    uint32_t rc;

    reset_state();
    g_scenario = SCN_NESTED;
    rc = aot_call_guest(&g_rt, A_NESTED, &arg, 1, &x0);
    check(rc == AOT_FAULT_NONE, "nested host->guest call scenario returns cleanly");
    check(x0 == 106ull, "nested call final x0");
    check(g_state.x[7] == 106ull, "outer continuation value");
    check(g_state.x[8] == 105ull, "inner guest function value");
    check(g_state.x[9] == 106ull, "outer entry continuation value");
    check(g_hit[0] == 1 && g_hit[2] == 1, "both thunk handlers ran");
    check(g_scratch_ok, "nested call preserves outer dispatch scratch");
    check(g_rt.steps == 6u, "steps are shared and not reset by a nested call");
    check(g_rt.event_count == 2u,
          "events append across depths (nested call did not reset them)");
    check(g_rt.events[0].id == 2u && g_rt.events[1].id == 0u,
          "event order is inner-then-outer (append, not reset)");
}

static void test_return_rules(void) {
    uint64_t x0 = 0;
    uint32_t rc = call1(A_WRONG_SLOT, 0, &x0);
    check(rc == AOT_FAULT_BAD_RETURN,
          "sentinel reached at the wrong depth is BAD_RETURN");
    check(g_rt.fault_target == SENTINEL(1), "wrong-slot fault target");

    rc = call1(A_WRONG_SP, 0, &x0);
    check(rc == AOT_FAULT_BAD_RETURN,
          "sentinel reached with a changed sp is BAD_RETURN");

    rc = call1(A_BR_SENTINEL, 0, &x0);
    check(rc == AOT_FAULT_BAD_RETURN,
          "sentinel reached by BR instead of RET is BAD_RETURN");

    rc = call1(A_CLOBBER_X19, 0, &x0);
    check(rc == AOT_FAULT_ABI_VIOLATION,
          "callee that clobbers x19 is ABI_VIOLATION");

    /* Misaligned sp is refused before anything runs. */
    reset_state();
    g_state.sp = STACK_TOP + 8u;
    rc = aot_call_guest(&g_rt, A_ENTRY_RET, NULL, 0, &x0);
    check(rc == AOT_FAULT_BAD_STATE, "misaligned sp is refused before running");
    check(g_rt.steps == 0u, "misaligned sp ran no block");
}

static void test_depth_and_sticky_fault(void) {
    uint32_t rc;
    uint64_t x0 = 0;

    reset_state();
    g_scenario = SCN_INNER;
    {
        uint64_t arg = 0;
        uint64_t slot = 0;
        rc = aot_call_guest(&g_rt, A_INNER_FAULT, &arg, 1, &x0);
        /* The guest-memory marker must be untouched too. */
        if (aot_mem_ld64(&g_mem, DATA_BASE + 0x3000ull, &slot) != AOT_MEM_OK)
            fatal("read sticky marker slot");
        check(slot == 0, "sticky inner fault left the outer marker slot alone");
    }
    check(rc == AOT_FAULT_UNTRANSLATED,
          "ignored inner fault still terminates the outer call");
    check(g_inner_rc == AOT_FAULT_UNTRANSLATED,
          "handler observed the inner fault code");
    check(g_rt.fault == AOT_FAULT_UNTRANSLATED && g_rt.fault_src == A_NOT_A_BLOCK,
          "sticky inner fault keeps the inner source");
    check(g_state.x[0] == 0x9999ull,
          "handler ran after the inner fault (its write is visible)");
    /* THE sticky contract: the outer run terminates AT the fault. No outer
     * resume block may execute afterwards, and the step count must stop at the
     * single outer block that entered the faulting handler. */
    check(g_inner_cont_ran == 0,
          "no outer block runs after an ignored inner fault");
    check(g_inner_marker == 0,
          "sticky inner fault wrote nothing through the outer resume block");
    /* Item-3 guard: a SECOND nested call after the sticky fault returns that
     * fault immediately and runs no block (steps unchanged). Checked BEFORE the
     * exact step count so this scenario reports its own intent first. */
    check(g_recall_rc == AOT_FAULT_UNTRANSLATED,
          "second nested call after a sticky fault returns that fault");
    check(g_recall_steps == g_recall_steps_before,
          "second nested call after a sticky fault runs no block");
    check(g_rt.steps == 1u, "sticky inner fault stops the step counter at the "
                            "faulting outer block");

    /* Depth probe last: under a mutant that drops sticky faults this scenario
     * runs away, so it must not mask the sticky checks above. */
    reset_state();
    g_scenario = SCN_DEFAULT;
    rc = aot_call_guest(&g_rt, A_DEPTH, NULL, 0, &x0);
    check(rc == AOT_FAULT_DEPTH, "call depth limit is AOT_FAULT_DEPTH");
    check(g_rt.fault == AOT_FAULT_DEPTH, "depth fault recorded");
    check(g_depth_calls == (int)AOT_MAX_CALL_DEPTH,
          "exactly AOT_MAX_CALL_DEPTH frames ran");
    check(g_depth_last_rc == AOT_FAULT_DEPTH,
          "innermost nested call reported the depth fault");
    check(g_rt.steps == (uint64_t)AOT_MAX_CALL_DEPTH,
          "shared step counter covered every frame");
}

static void test_entry_api(void) {
    uint64_t x0 = 0;
    uint64_t nine[9] = { 0 };
    check(aot_rt_run(&g_rt, A_ENTRY_RET, 0) == AOT_EXIT_FAULT,
          "legacy run entry point is refused in Program mode");
    check(g_rt.fault == AOT_FAULT_BAD_STATE, "refused legacy run is BAD_STATE");

    reset_state();
    check(aot_call_guest(&g_rt, A_ENTRY_RET, NULL, 0, &x0) == AOT_FAULT_NONE,
          "top-level call after the refused legacy run works");
    check(x0 == 1u, "top-level call result");
    check(g_rt.steps == 1u && g_rt.event_count == 0u,
          "top-level call resets steps/events");

    /* More than the eight AAPCS64 argument registers is refused before any
     * block runs. */
    reset_state();
    check(aot_call_guest(&g_rt, A_ENTRY_RET, nine, 9, &x0) ==
              AOT_FAULT_BAD_STATE,
          "more than 8 arguments is refused");
    check(g_rt.steps == 0u, "rejected argument count ran no block");
}

/* ---- thread ownership and concurrency ---------------------------------- */
typedef struct owner_arg {
    uint32_t rc;
} owner_arg;

static void owner_thread_main(void *arg) {
    owner_arg *a = (owner_arg *)arg;
    uint64_t x0 = 0;
    uint64_t v = 1;
    a->rc = aot_call_guest(&g_rt, A_ENTRY_RET, &v, 1, &x0);
}

static void test_thread_ownership(void) {
    host_thread t = { 0 };
    owner_arg a;
    int joined = 0;
    /* Snapshot the OWNER's runtime: a foreign thread must not write a single
     * field of it, so every diagnostic must survive the refused call. */
    const uint32_t save_fault = g_rt.fault;
    const AotExit save_reason = g_rt.reason;
    const uint64_t save_next_pc = g_rt.next_pc;
    const uint64_t save_fault_src = g_rt.fault_src;
    const uint64_t save_steps = g_rt.steps;
    a.rc = AOT_FAULT_NONE;
    if (host_thread_create(&t, owner_thread_main, &a) != HOST_THREAD_OK)
        fatal("owner thread create");
    if (host_thread_join(&t, 30000u, &joined) != HOST_THREAD_OK || !joined)
        fatal("owner thread join");
    /* Only the RETURN CODE reports the refusal; the runtime is untouched
     * (negative control: an implementation that calls rt_fault here writes
     * fault/fault_src/fault_status and would flip at least one assertion). */
    check(a.rc == AOT_FAULT_BAD_STATE,
          "host->guest call from a non-owner thread is BAD_STATE");
    check(g_rt.fault == save_fault, "non-owner call left rt->fault unchanged");
    check(g_rt.reason == save_reason,
          "non-owner call left rt->reason unchanged");
    check(g_rt.next_pc == save_next_pc,
          "non-owner call left rt->next_pc unchanged");
    check(g_rt.fault_src == save_fault_src,
          "non-owner call left rt->fault_src unchanged");
    check(g_rt.steps == save_steps, "non-owner call left rt->steps unchanged");
}

/* Minor 1: a sticky INNER fault is checked BEFORE the post-handler state
 * validation, so a handler that faults AND leaves invalid state reports the
 * inner fault (the real cause) instead of AOT_FAULT_BAD_STATE. */
static void test_sticky_before_state_check(void) {
    uint64_t x0 = 0;
    uint64_t arg = 0;
    uint32_t rc;

    reset_state();
    g_scenario = SCN_INNER_BAD;
    rc = aot_call_guest(&g_rt, A_INNER_FAULT, &arg, 1, &x0);
    check(rc == AOT_FAULT_UNTRANSLATED,
          "an inner fault wins over the handler's invalid state");
    check(g_rt.fault == AOT_FAULT_UNTRANSLATED,
          "the recorded fault is the inner one, not BAD_STATE");
    check(g_rt.fault_src == A_NOT_A_BLOCK,
          "the sticky fault keeps the inner source");
    check(g_inner_rc == AOT_FAULT_UNTRANSLATED,
          "the handler observed the inner fault code");
    g_scenario = SCN_DEFAULT;
}

/* Minor 2: the owner-thread check precedes EVERY write to the runtime,
 * including the program==NULL path. A legacy (no Program) runtime called from a
 * foreign thread must return BAD_STATE and must not acquire a fault record. */
static AotRuntime g_rt_legacy;
static AotGuestState g_state_legacy;

static void legacy_thread_main(void *arg) {
    owner_arg *a = (owner_arg *)arg;
    uint64_t x0 = 0;
    a->rc = aot_call_guest(&g_rt_legacy, A_ENTRY_RET, NULL, 0, &x0);
}

static void test_nonprogram_thread_ownership(void) {
    host_thread t = { 0 };
    owner_arg a;
    AotMem mem;
    uint64_t x0 = 0;
    int joined = 0;

    memset(&mem, 0, sizeof mem);   /* no address space: legacy single-image */
    memset(&g_state_legacy, 0, sizeof g_state_legacy);
    g_state_legacy.sp = STACK_TOP;
    memset(&g_rt_legacy, 0, sizeof g_rt_legacy);
    check(aot_rt_init(&g_rt_legacy, NULL, mem, &g_state_legacy, 16) ==
              AOT_FAULT_NONE,
          "a no-image runtime initialises in legacy mode");
    /* Owned call: the Program-only entry point refuses a runtime without a
     * Program and records that refusal on the OWNER's runtime. */
    check(aot_call_guest(&g_rt_legacy, A_ENTRY_RET, NULL, 0, &x0) ==
              AOT_FAULT_NO_IMAGE,
          "a Program call on a no-image runtime is NO_IMAGE");
    check(g_rt_legacy.fault == AOT_FAULT_NO_IMAGE,
          "the owned call recorded NO_IMAGE");
    /* Foreign call: the owner check must come FIRST, so the returned code is
     * BAD_STATE (not NO_IMAGE) and the owner's fault is untouched. */
    a.rc = AOT_FAULT_NONE;
    if (host_thread_create(&t, legacy_thread_main, &a) != HOST_THREAD_OK)
        fatal("legacy owner thread create");
    if (host_thread_join(&t, 30000u, &joined) != HOST_THREAD_OK || !joined)
        fatal("legacy owner thread join");
    check(a.rc == AOT_FAULT_BAD_STATE,
          "non-owner call on a no-image runtime is BAD_STATE (owner check "
          "first)");
    check(g_rt_legacy.fault == AOT_FAULT_NO_IMAGE,
          "non-owner call left the no-image runtime's fault unchanged");
    aot_rt_release(&g_rt_legacy);
}


typedef struct worker {
    int index;
    int failures;
    uint64_t first_bad_arg;
    uint64_t last_slot_value;
} worker;

static void worker_main(void *arg) {
    worker *w = (worker *)arg;
    AotGuestState state;
    AotRuntime rt;
    AotMem mem;
    int i;

    memset(&state, 0, sizeof(state));
    state.sp = STACK_TOP + 0x100ull * (uint64_t)w->index;
    if (aot_mem_init_aspace(&mem, g_as) != AOT_MEM_OK) {
        w->failures++;
        return;
    }
    memset(&rt, 0, sizeof(rt));
    if (aot_rt_init_program(&rt, g_prog, mem, &state, 64) != AOT_FAULT_NONE) {
        w->failures++;
        return;
    }
    for (i = 0; i < 1000; i++) {
        uint64_t x0 = 0;
        uint64_t v = ((uint64_t)(uint32_t)w->index << 32) | (uint64_t)i;
        uint32_t rc = aot_call_guest(&rt, A_ENTRY_RET, &v, 1, &x0);
        if (rc != AOT_FAULT_NONE || x0 != v + 1u) {
            w->failures++;
            if (w->first_bad_arg == 0u) w->first_bad_arg = v + 1u;
        }
        /* Shared guest memory: the block stores v into THIS thread's own slot
         * through the address space; the reload must observe exactly v even
         * while the other three threads write their slots. */
        {
            uint64_t args[2];
            uint64_t slot = SMEM_SLOT(w->index);
            uint64_t back = 0;
            args[0] = v;
            args[1] = slot;
            rc = aot_call_guest(&rt, A_SMEM, args, 2, NULL);
            if (rc != AOT_FAULT_NONE || g_smem_rc != (uint32_t)AOT_MEM_OK ||
                aot_mem_ld64(&mem, slot, &back) != AOT_MEM_OK ||
                back != v) {
                w->failures++;
                if (w->first_bad_arg == 0u) w->first_bad_arg = v;
            }
            w->last_slot_value = back;
        }
    }
    /* Final per-slot readback after the write phase. */
    {
        uint64_t back = 0;
        if (aot_mem_ld64(&mem, SMEM_SLOT(w->index), &back) != AOT_MEM_OK ||
            back != w->last_slot_value)
            w->failures++;
    }
    aot_rt_release(&rt);
}

static void test_concurrent_calls(void) {
    host_thread threads[4];
    worker workers[4];
    int i;

    memset(threads, 0, sizeof(threads));
    memset(workers, 0, sizeof(workers));
    for (i = 0; i < 4; i++) {
        workers[i].index = i;
        if (host_thread_create(&threads[i], worker_main, &workers[i]) !=
            HOST_THREAD_OK)
            fatal("concurrency thread create");
    }
    for (i = 0; i < 4; i++) {
        int joined = 0;
        if (host_thread_join(&threads[i], 60000u, &joined) != HOST_THREAD_OK ||
            !joined)
            fatal("concurrency thread join");
        check(workers[i].failures == 0,
              "4x1000 concurrent top-level calls all returned exact results");
    }
}

/* A block that stores into a READ-ONLY guest page must surface AOT_FAULT_MEMORY
 * carrying AOT_MEM_ERR_PERM and the faulting guest VA. */
static void test_readonly_store_fault(void) {
    uint64_t x0 = 0;
    reset_state();
    g_scenario = SCN_DEFAULT;
    check(aot_call_guest(&g_rt, A_RO_STORE, NULL, 0, &x0) ==
              AOT_FAULT_MEMORY,
          "store into an R page faults with AOT_FAULT_MEMORY");
    check(g_ro_status == AOT_MEM_ERR_PERM,
          "R-page store reports AOT_MEM_ERR_PERM (not a range error)");
    check(g_rt.fault_status == (uint32_t)AOT_MEM_ERR_PERM,
          "runtime fault_status carries the memory status");
    check(g_rt.fault_target == DATA_RO_ADDR,
          "runtime fault_target is the read-only guest address");
    check(g_rt.fault_src == A_RO_STORE, "runtime fault_src is the faulting block");
    /* The page still holds its original content. */
    {
        uint64_t v = 0;
        check(aot_mem_ld64(&g_mem, DATA_RO_ADDR, &v) == AOT_MEM_OK &&
                  v != 0x7777ull,
              "rejected R-page store wrote nothing");
    }
}

/* The 2^39 upper bound is exclusive but not off by one, at image level too. */
static void test_image_top_bound(void) {
    AotProgram *p = aot_program_create(NULL);
    AotCodeRange r[1];
    AotProgImage img;
    if (p == NULL) fatal("bound program create");
    memset(&img, 0, sizeof(img));
    img.subset_id = AOT_SUBSET_ID_MODULE;
    img.abi_version = AOT_ABI_VERSION_PROGRAM;
    img.state_layout = AOT_STATE_LAYOUT;
    img.ranges = r;
    img.range_count = 1;
    r[0].start = AOT_AS_MAX_ADDR - 0x1000ull;
    r[0].end = AOT_AS_MAX_ADDR;
    check(aot_program_add_image(p, &img) == AOT_FAULT_NONE,
          "image range ending exactly at 2^39 is accepted");
    aot_program_destroy(p);
    p = aot_program_create(NULL);
    if (p == NULL) fatal("bound program create 2");
    r[0].start = AOT_AS_MAX_ADDR - 0x1000ull;
    r[0].end = AOT_AS_MAX_ADDR + 0x1000ull;
    check(aot_program_add_image(p, &img) == AOT_FAULT_BAD_STATE,
          "image range ending one page past 2^39 is rejected");
    r[0].start = AOT_AS_MAX_ADDR + 0x1000ull;
    r[0].end = AOT_AS_MAX_ADDR + 0x2000ull;
    check(aot_program_add_image(p, &img) == AOT_FAULT_BAD_STATE,
          "image range entirely above 2^39 is rejected");
    aot_program_destroy(p);
}

/* ------------------------------------------------------------------------ */
int main(void) {
    uint64_t x0 = 0;

    g_dom = aot_mem_domain_create();
    if (g_dom == NULL) fatal("domain create");
    g_as = aot_as_create(g_dom);
    if (g_as == NULL) fatal("address space create");
    if (aot_as_add_region(g_as, DATA_BASE, DATA_SIZE, AOT_AS_PERM_RW,
                          AOT_AS_STATE_DATA, NULL) != AOT_MEM_OK)
        fatal("add data region");
    /* Upper bound: exactly 2^39 is admissible, one page past it is not. */
    if (aot_as_add_region(g_as, AOT_AS_MAX_ADDR, 0x1000ull, AOT_AS_PERM_R,
                          AOT_AS_STATE_DATA, NULL) == AOT_MEM_OK)
        fatal("region at 2^39 was accepted");
    if (aot_as_add_region(g_as, AOT_AS_MAX_ADDR - 0x1000ull, 0x2000ull,
                          AOT_AS_PERM_R, AOT_AS_STATE_DATA, NULL) ==
        AOT_MEM_OK)
        fatal("region ending past 2^39 was accepted");
    if (aot_as_add_region(g_as, AOT_AS_MAX_ADDR - 0x1000ull, 0x1000ull,
                          AOT_AS_PERM_R, AOT_AS_STATE_DATA, NULL) != AOT_MEM_OK)
        fatal("add region ending exactly at 2^39");
    /* Read-only page for the memory-fault probe. */
    if (aot_as_add_region(g_as, REG_RO, 0x1000ull, AOT_AS_PERM_R,
                          AOT_AS_STATE_DATA, NULL) != AOT_MEM_OK)
        fatal("add read-only region");
    if (aot_as_seal(g_as) != AOT_MEM_OK) fatal("seal address space");
    if (aot_mem_init_aspace(&g_mem, g_as) != AOT_MEM_OK)
        fatal("mem handle over the address space");

    test_link_validation();
    build_program();
    check(aot_rt_init_program(&g_rt, g_prog, g_mem, &g_state, 1024) ==
              AOT_FAULT_NONE,
          "program runtime init");
    reset_state();

    test_cross_image();
    test_resolution_faults();
    test_thunks();
    test_svc_and_sysreg();
    test_nested_and_diagnostics();
    test_return_rules();
    test_depth_and_sticky_fault();
    test_sticky_before_state_check();
    test_entry_api();
    test_thread_ownership();
    test_nonprogram_thread_ownership();
    test_concurrent_calls();
    test_readonly_store_fault();
    test_image_top_bound();

    /* A runtime bound to the wrong address space is refused. */
    {
        AotRuntime bad_rt;
        AotMem arena_mem;
        uint8_t arena[64];
        memset(&bad_rt, 0, sizeof(bad_rt));
        check(aot_mem_init(&arena_mem, g_dom, arena, sizeof(arena), 0x100000ull) ==
                  AOT_MEM_OK,
              "arena handle for the binding check");
        check(aot_rt_init_program(&bad_rt, g_prog, arena_mem, &g_state, 16) ==
                  AOT_FAULT_BAD_STATE,
              "runtime over a different memory handle is refused");
        /* A legacy v1 runtime cannot make host->guest calls, and a legacy
         * aot_rt_init call never accepts an address-space handle at all (a
         * Program handle is Program-mode only). */
        aot_rt_release(&bad_rt);
        memset(&bad_rt, 0, sizeof(bad_rt));
        check(aot_rt_init(&bad_rt, NULL, g_mem, &g_state, 16) ==
                  AOT_FAULT_BAD_STATE,
              "legacy runtime init rejects an address-space handle");
        aot_rt_release(&bad_rt);
        memset(&bad_rt, 0, sizeof(bad_rt));
        if (aot_rt_init(&bad_rt, NULL, arena_mem, &g_state, 16) != AOT_FAULT_NONE)
            fatal("legacy no-image runtime init");
        check(aot_call_guest(&bad_rt, A_ENTRY_RET, NULL, 0, &x0) ==
                  AOT_FAULT_NO_IMAGE,
              "host->guest call on a legacy runtime is NO_IMAGE");
        aot_rt_release(&bad_rt);
        /* The legacy G2 runtime accepts ABI v1 only: a v2 (Program) image
         * must be refused so a Program image can never run on the single-image
         * path. */
        memset(&bad_rt, 0, sizeof(bad_rt));
        {
            AotImage v2img;
            memset(&v2img, 0, sizeof(v2img));
            v2img.subset_id = AOT_SUBSET_ID_MODULE;
            v2img.abi_version = AOT_ABI_VERSION_PROGRAM;
            v2img.state_layout = AOT_STATE_LAYOUT;
            v2img.blocks = blocks_a;
            v2img.block_count = sizeof(blocks_a) / sizeof(blocks_a[0]);
            v2img.ranges = ranges_a;
            v2img.range_count = 1;
            check(aot_rt_init(&bad_rt, &v2img, arena_mem, &g_state, 16) ==
                      AOT_FAULT_BAD_STATE,
                  "legacy runtime rejects an ABI v2 image");
        }
        aot_rt_release(&bad_rt);
    }

    aot_rt_release(&g_rt);
    aot_program_destroy(g_prog);
    aot_as_destroy(g_as);
    aot_mem_domain_destroy(g_dom);

    if (g_fail) {
        printf("aot_program_probe: semantic failures\n");
        return 2;
    }
    printf("aot_program_probe: all Program contract checks passed\n");
    return 0;
}
