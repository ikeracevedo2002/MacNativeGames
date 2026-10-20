#include "aot_runtime.h"
#include "aot_as.h"

#include <string.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static uint32_t rt_current_thread(void) {
    return (uint32_t)GetCurrentThreadId();
}

static void rt_trace(AotRuntime *rt, uint64_t pc) {
    if (!rt->trace_enabled) return;
    if (rt->trace_count < AOT_MAX_TRACE) {
        rt->trace[rt->trace_count++] = pc;
    } else {
        rt->trace_overflow = 1;
    }
}

/* Record a fault. `src` is the instruction that caused the transfer (the
 * terminal instruction of the previous block), `target` is the transfer
 * target. For an invalid initial entry both are the entry PC. */
static void rt_fault(AotRuntime *rt, uint32_t code, uint64_t src,
                     uint64_t target, int64_t status) {
    rt->fault = code;
    rt->fault_src = src;
    rt->fault_target = target;
    rt->fault_status = status;
    rt->reason = AOT_EXIT_FAULT;
    rt->next_pc = target;
}

static int rt_range_contains(const AotImage *img, uint64_t pc) {
    for (size_t i = 0; i < img->range_count; i++) {
        if (pc >= img->ranges[i].start && pc < img->ranges[i].end) return 1;
    }
    return 0;
}

uint32_t aot_image_validate(const AotImage *img) {
    if (img == NULL) return AOT_FAULT_NO_IMAGE;
    if (img->subset_id == NULL || strcmp(img->subset_id, AOT_SUBSET_ID) != 0)
        return AOT_FAULT_BAD_STATE;
    if (img->abi_version != AOT_ABI_VERSION ||
        img->state_layout != AOT_STATE_LAYOUT)
        return AOT_FAULT_BAD_STATE;
    if (img->block_count != 0 && img->blocks == NULL) return AOT_FAULT_BAD_STATE;
    if (img->range_count != 0 && img->ranges == NULL) return AOT_FAULT_BAD_STATE;

    for (size_t i = 0; i < img->range_count; i++) {
        if (img->ranges[i].end <= img->ranges[i].start) return AOT_FAULT_BAD_STATE;
        if ((img->ranges[i].start & 3u) != 0u) return AOT_FAULT_BAD_STATE;
        if (i != 0 && img->ranges[i].start < img->ranges[i - 1].end)
            return AOT_FAULT_BAD_STATE;   /* sorted, non-overlapping */
    }
    for (size_t i = 0; i < img->block_count; i++) {
        uint64_t pc = img->blocks[i].entry_pc;
        if ((pc & 3u) != 0u) return AOT_FAULT_BAD_STATE;
        if (img->blocks[i].fn == NULL) return AOT_FAULT_BAD_STATE;
        if (i != 0 && pc <= img->blocks[i - 1].entry_pc)
            return AOT_FAULT_BAD_STATE;   /* strictly increasing */
        if (!rt_range_contains(img, pc)) return AOT_FAULT_BAD_STATE;
    }
    if (img->thunk_count != 0u) {
        /* Scoped thunk shape: 16-byte stride, at most UINT32_MAX thunks.
         * span = count*16 <= 2^36, so it cannot overflow before checking. */
        if (img->thunk_stride != AOT_THUNK_STRIDE) return AOT_FAULT_BAD_STATE;
        if (img->thunk_count > 0xffffffffULL) return AOT_FAULT_BAD_STATE;
        if (img->thunk_base == 0u) return AOT_FAULT_BAD_STATE;
        if ((img->thunk_base & 3u) != 0u) return AOT_FAULT_BAD_STATE;
        uint64_t span = img->thunk_count * AOT_THUNK_STRIDE;
        if (img->thunk_base > UINT64_MAX - span) return AOT_FAULT_BAD_STATE;
        uint64_t tend = img->thunk_base + span;
        for (size_t i = 0; i < img->range_count; i++) {
            if (img->thunk_base < img->ranges[i].end && img->ranges[i].start < tend)
                return AOT_FAULT_BAD_STATE;   /* code/thunk ranges must be disjoint */
        }
    }
    return AOT_FAULT_NONE;
}

#define AOT_RT_INIT_MAGIC 0xA07B0001u

void aot_rt_release(AotRuntime *rt) {
    if (rt == NULL) return;
    if (rt->init_magic == AOT_RT_INIT_MAGIC) {
        if (rt->mem.domain != NULL && rt->monitor_token != 0u)
            aot_mem_domain_detach(rt->mem.domain, rt->monitor_token);
        rt->monitor_token = 0u;
        rt->init_magic = 0u;
        /* Release must leave the runtime NON-runnable: the domain may be
         * destroyed immediately after the last release, so a later run must
         * not touch a dangling domain/image. Re-init (which first checks the
         * magic) is the supported way to reuse the storage. */
        memset(&rt->mem, 0, sizeof(rt->mem));
        rt->image = NULL;
        rt->identity_ok = 0;
        rt->program = NULL;
        rt->program_ok = 0;
        /* Detach the BORROWED guest state too (release never owns or frees
         * it). Without this, a later erroneous run would still write
         * rt->state->pc in fault_out after the caller has freed or poisoned
         * the backing state. */
        rt->state = NULL;
        rt->running = 0;
    }
}

/* A failed init after the monitor token was attached must not leak that slot,
 * so every post-attach failure goes through here: the token is detached, the
 * magic is cleared (the runtime is left non-runnable, which is exactly what a
 * failed init must produce) and the fault code is returned unchanged. */
static uint32_t rt_init_fail(AotRuntime *rt, uint32_t code, int64_t detail) {
    rt_fault(rt, code, 0, 0, detail);
    if (rt->mem.domain != NULL && rt->monitor_token != 0u)
        aot_mem_domain_detach(rt->mem.domain, rt->monitor_token);
    rt->monitor_token = 0u;
    rt->init_magic = 0u;
    rt->running = 0;
    rt->program_ok = 0;
    rt->identity_ok = 0;
    return code;
}

static uint32_t aot_rt_init_common(AotRuntime *rt, const AotImage *image,
                                   const AotProgram *program, AotMem mem,
                                   AotGuestState *state, uint64_t step_budget) {
    if (rt == NULL) return AOT_FAULT_BAD_STATE;
    /* The caller must zero the runtime before its first init; after that the
     * magic lets re-init detach the previous monitor token instead of leaking
     * a slot in the domain's bounded monitor table. */
    if (rt->init_magic == AOT_RT_INIT_MAGIC) {
        if (rt->mem.domain != NULL && rt->monitor_token != 0u)
            aot_mem_domain_detach(rt->mem.domain, rt->monitor_token);
    }
    memset(rt, 0, sizeof(*rt));
    rt->init_magic = AOT_RT_INIT_MAGIC;
    rt->monitor_token = 0u;
    rt->mem = mem;
    rt->state = state;
    if (mem.domain != NULL) {
        rt->monitor_token = aot_mem_domain_attach(mem.domain);
        if (rt->monitor_token == 0u) {
            return rt_init_fail(rt, AOT_FAULT_BAD_STATE, -1);
        }
    }
    rt->step_budget = step_budget;
    rt->reason = AOT_EXIT_NONE;
    rt->running = 0;
    rt->identity_ok = 0;
    rt->owner_thread = rt_current_thread();
    rt->program = NULL;
    rt->program_ok = 0;
    if (state == NULL) {
        return rt_init_fail(rt, AOT_FAULT_BAD_STATE, -1);
    }
    if (program != NULL) {
        /* Program mode: the Program is immutable after finalize and is linked
         * against one address space; a runtime over a different handle could
         * silently read the wrong guest memory. The identity must match
         * EXACTLY, in both directions: a Program finalized without a space
         * cannot run over one, and a Program linked to a space cannot run over
         * a handle that carries none (or a different one). */
        if (!program->finalized) {
            return rt_init_fail(rt, AOT_FAULT_BAD_STATE, -2);
        }
        if (program->as == NULL || program->as != mem.as) {
            return rt_init_fail(rt, AOT_FAULT_BAD_STATE, -3);
        }
        /* The Program's link-time proofs (unmapped thunks/sentinels, frozen
         * region table) only hold for a SEALED space, and a POISONED space
         * (residue of a failed load) is never runnable. */
        if (!aot_as_is_sealed(program->as) || aot_as_is_poisoned(program->as)) {
            return rt_init_fail(rt, AOT_FAULT_BAD_STATE, -8);
        }
        rt->program = program;
        if (aot_state_validate(state) != AOT_STATE_OK) {
            return rt_init_fail(rt, AOT_FAULT_BAD_STATE, -1);
        }
        rt->program_ok = 1;
        return AOT_FAULT_NONE;
    }
    if (image == NULL) {
        rt->image = NULL;
        return AOT_FAULT_NONE;   /* no-dispatch runtime */
    }
    uint32_t rc = aot_image_validate(image);
    if (rc != AOT_FAULT_NONE) {
        rt->image = NULL;
        return rt_init_fail(rt, rc, -1);
    }
    if (aot_state_validate(state) != AOT_STATE_OK) {
        rt->image = image;
        return rt_init_fail(rt, AOT_FAULT_BAD_STATE, -1);
    }
    rt->image = image;
    rt->identity_ok = 1;
    return AOT_FAULT_NONE;
}

uint32_t aot_rt_init(AotRuntime *rt, const AotImage *image, AotMem mem,
                     AotGuestState *state, uint64_t step_budget) {
    /* The legacy single-arena (G2) mode never had an address space. Accepting
     * a handle that carries one would pick the arena path for a value that is
     * a Program handle, so it is rejected outright. */
    if (mem.as != NULL) return AOT_FAULT_BAD_STATE;
    return aot_rt_init_common(rt, image, NULL, mem, state, step_budget);
}

uint32_t aot_rt_init_program(AotRuntime *rt, const AotProgram *program,
                             AotMem mem, AotGuestState *state,
                             uint64_t step_budget) {
    return aot_rt_init_common(rt, NULL, program, mem, state, step_budget);
}

int aot_rt_set_handler(AotRuntime *rt, uint32_t kind, uint32_t id,
                       AotHleHandler fn, void *user) {
    if (fn == NULL) return 1;
    for (size_t i = 0; i < rt->handler_count; i++) {
        if (rt->handlers[i].kind == kind &&
            aot_hle_id_key(kind, rt->handlers[i].id) ==
                aot_hle_id_key(kind, id)) {
            return 2;
        }
    }
    if (rt->handler_count >= AOT_MAX_HANDLERS) return 3;
    rt->handlers[rt->handler_count].kind = kind;
    rt->handlers[rt->handler_count].id = id;
    rt->handlers[rt->handler_count].fn = fn;
    rt->handlers[rt->handler_count].user = user;
    rt->handler_count++;
    return 0;
}

AotBlockFn aot_rt_lookup(const AotRuntime *rt, uint64_t pc) {
    if (rt->image == NULL || rt->image->blocks == NULL) return NULL;
    if ((pc & 3u) != 0u) return NULL;   /* A64 instruction alignment */
    if (!rt_range_contains(rt->image, pc)) return NULL;
    size_t lo = 0, hi = rt->image->block_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        uint64_t e = rt->image->blocks[mid].entry_pc;
        if (e == pc) return rt->image->blocks[mid].fn;
        if (e < pc) lo = mid + 1;
        else hi = mid;
    }
    return NULL;
}

static int rt_in_thunks(const AotImage *img, uint64_t pc, uint32_t *id_out) {
    if (img->thunk_base == 0u || img->thunk_count == 0u || img->thunk_stride == 0u)
        return 0;
    if (pc < img->thunk_base) return 0;
    uint64_t off = pc - img->thunk_base;
    uint64_t idx = off / img->thunk_stride;
    if (idx >= img->thunk_count) return 0;
    if (off % img->thunk_stride != 0u) return 0;
    if (id_out) *id_out = (uint32_t)idx;
    return 1;
}

/* Deliver an HLE request. The runtime computes resume_pc itself and ignores
 * any handler change to pc. Returns 0 on success, else a fault code. */
static uint32_t rt_hle(AotRuntime *rt, uint32_t kind, uint32_t id,
                       uint64_t site_pc, uint64_t resume_pc) {
    AotHleHandler handler = NULL;
    void *user = NULL;
    for (size_t i = 0; i < rt->handler_count; i++) {
        if (rt->handlers[i].kind == kind &&
            aot_hle_id_key(kind, rt->handlers[i].id) ==
                aot_hle_id_key(kind, id)) {
            handler = rt->handlers[i].fn;
            user = rt->handlers[i].user;
            break;
        }
    }
    if (handler == NULL) {
        rt_fault(rt, AOT_FAULT_BAD_HLE, site_pc, resume_pc, (int64_t)id);
        return AOT_FAULT_BAD_HLE;
    }

    if (aot_rt_lookup(rt, resume_pc) == NULL) {
        rt_fault(rt, AOT_FAULT_BAD_RESUME, site_pc, resume_pc, (int64_t)kind);
        return AOT_FAULT_BAD_RESUME;
    }

    AotHleRequest req;
    req.kind = kind;
    req.id = id;
    req.site_pc = site_pc;
    req.resume_pc = resume_pc;

    /* CONSERVATIVE PROOF POLICY, not an ARM exception-entry claim: this G2
     * proof clears the LOCAL monitor across an SVC/host-call boundary, before
     * and after, so a handler cannot leave a stale reservation behind. The
     * handler MUST access guest memory through the shared aot_mem_* API (its
     * `user` pointer can carry the arena): those calls perform their own
     * reservation invalidation. This boundary clear is NOT a substitute for
     * the shared memory API and does not assert wider exception-entry
     * semantics. */
    aot_mem_clrex(&rt->mem, rt->monitor_token);
    rt->state->pc = resume_pc;   /* runtime-owned; handler must not rely on it */
    handler(rt->state, &req, user);
    aot_mem_clrex(&rt->mem, rt->monitor_token);
    rt->state->pc = resume_pc;   /* ignore any handler attempt to redirect */

    if (aot_state_validate(rt->state) != AOT_STATE_OK) {
        rt_fault(rt, AOT_FAULT_BAD_STATE, site_pc, resume_pc, -1);
        return AOT_FAULT_BAD_STATE;
    }

    if (rt->event_count < AOT_MAX_EVENTS) {
        rt->events[rt->event_count].kind = kind;
        rt->events[rt->event_count].id = id;
        rt->events[rt->event_count].site_pc = req.site_pc;
        rt->events[rt->event_count].resume_pc = req.resume_pc;
        rt->event_count++;
    } else {
        rt->events_overflow = 1;
    }

    rt->next_pc = resume_pc;
    return AOT_FAULT_NONE;
}

/* =================== Program-mode dispatch (G3 increment 1) ============== */

/* Rule D: a transfer reached a sentinel slot. A return is valid ONLY when the
 * arrival was a RET (or the resume of a thunk entered as a guest function,
 * which is architecturally the same call returning) to THIS frame's slot with
 * the recorded entry sp. The callee-saved AAPCS64 state is then VERIFIED and
 * never restored. */
static uint32_t prog_return_to_host(AotRuntime *rt, uint64_t off,
                                    int arrival_ret, uint64_t src,
                                    uint64_t pc) {
    uint32_t frame = rt->call_depth - 1u;
    uint64_t expected = (uint64_t)AOT_THUNK_STRIDE * (uint64_t)frame;
#ifdef MN_AOT_MUTANT_NO_DEPTH_CHECK
    /* TEST-ONLY wrong-implementation control: any sentinel slot is accepted
     * as this frame's. Compiled only into aot_prog_mut_no_depth_check. */
    if (!arrival_ret) {
        rt_fault(rt, AOT_FAULT_BAD_RETURN, src, pc, 1);
        return AOT_FAULT_BAD_RETURN;
    }
    (void)expected;
    (void)off;
#else
    if (!arrival_ret || off != expected) {
        rt_fault(rt, AOT_FAULT_BAD_RETURN, src, pc,
                 arrival_ret ? 2 : 1);
        return AOT_FAULT_BAD_RETURN;
    }
#endif
    if (rt->state->sp != rt->call[frame].entry_sp) {
        rt_fault(rt, AOT_FAULT_BAD_RETURN, src, pc, 3);
        return AOT_FAULT_BAD_RETURN;
    }
#ifndef MN_AOT_MUTANT_NO_ABI_CHECK
    for (uint32_t i = 0; i < 11u; i++) {
        if (rt->state->x[19u + i] != rt->call[frame].x19_x29[i]) {
            rt_fault(rt, AOT_FAULT_ABI_VIOLATION, src, pc, (int64_t)(i + 1u));
            return AOT_FAULT_ABI_VIOLATION;
        }
    }
    for (uint32_t i = 0; i < 8u; i++) {
        if (rt->state->v[8u + i][0] != rt->call[frame].v8_v15[i]) {
            rt_fault(rt, AOT_FAULT_ABI_VIOLATION, src, pc,
                     (int64_t)(0x100u + i));
            return AOT_FAULT_ABI_VIOLATION;
        }
    }
    if (rt->state->fpcr != rt->call[frame].fpcr) {
        rt_fault(rt, AOT_FAULT_ABI_VIOLATION, src, pc, 4);
        return AOT_FAULT_ABI_VIOLATION;
    }
#else
    /* TEST-ONLY wrong-implementation control: the callee-saved verification
     * (x19-x29, v8-v15, fpcr) is skipped entirely. */
#endif
    return AOT_FAULT_NONE;
}

/* Deliver one Program HLE request. The runtime owns pc and resume; the handler
 * is NEVER called with the domain lock held (D013). */
static uint32_t prog_hle(AotRuntime *rt, uint32_t kind, uint32_t id,
                         uint64_t site_pc, uint64_t resume_pc) {
    const AotProgHandlerEntry *h = aot_program_handler(rt->program, kind, id);
    AotHleRequest req;
    if (h == NULL) {
        rt_fault(rt, AOT_FAULT_BAD_HLE, site_pc, resume_pc, (int64_t)id);
        return AOT_FAULT_BAD_HLE;
    }
    req.kind = kind;
    req.id = id;
    req.site_pc = site_pc;
    req.resume_pc = resume_pc;

    aot_mem_clrex(&rt->mem, rt->monitor_token);
    rt->state->pc = resume_pc;
    rt->in_handler++;
    h->fn(rt, rt->state, &req, h->user);
    rt->in_handler--;
    aot_mem_clrex(&rt->mem, rt->monitor_token);
    rt->state->pc = resume_pc;   /* the handler may not redirect control */

    /* Minor 1: an inner (nested) fault is STICKY and must WIN over every other
     * post-handler diagnosis: a handler that both faulted and left invalid
     * state reports the INNER fault (the real cause), not BAD_STATE, and the
     * fault fields already hold it, so next_pc is not touched. The sticky check
     * therefore precedes the state validation below. */
#ifndef MN_AOT_MUTANT_DROP_STICKY
    if (rt->fault != AOT_FAULT_NONE) {
        rt->reason = AOT_EXIT_FAULT;
        return rt->fault;
    }
#else
    /* TEST-ONLY wrong-implementation control: an inner fault is swallowed and
     * the outer run continues as if the handler had succeeded. */
#endif
    if (aot_state_validate(rt->state) != AOT_STATE_OK) {
        rt_fault(rt, AOT_FAULT_BAD_STATE, site_pc, resume_pc, -1);
        return AOT_FAULT_BAD_STATE;
    }
    if (rt->event_count < AOT_MAX_EVENTS) {
        rt->events[rt->event_count].kind = kind;
        rt->events[rt->event_count].id = id;
        rt->events[rt->event_count].site_pc = site_pc;
        rt->events[rt->event_count].resume_pc = resume_pc;
        rt->event_count++;
    } else {
        rt->events_overflow = 1;
    }
    rt->next_pc = resume_pc;
    return AOT_FAULT_NONE;
}

/* Rule C: entering a thunk VA makes it a guest function. r = x30 AT ENTRY is
 * the resume PC; it must ALREADY be a translated Program entry or this
 * frame's return sentinel, checked BEFORE the handler runs. */
static uint32_t prog_thunk_enter(AotRuntime *rt, uint32_t thunk_id,
                                 int arrival_ret, uint64_t src,
                                 uint64_t pc) {
    const AotProgram *p = rt->program;
    uint64_t r = rt->state->x[30];
    int ok;
    if (arrival_ret) {
        rt_fault(rt, AOT_FAULT_BAD_TRANSFER, src, pc, (int64_t)thunk_id);
        return AOT_FAULT_BAD_TRANSFER;
    }
    ok = aot_program_is_entry(p, r);
    if (!ok && rt->call_depth != 0u) {
        uint64_t slot = p->sentinel_base + (uint64_t)AOT_THUNK_STRIDE *
                                              (uint64_t)(rt->call_depth - 1u);
        if (r == slot) ok = 1;
    }
#ifdef MN_AOT_MUTANT_HANDLER_BEFORE_RESUME_CHECK
    /* TEST-ONLY wrong-implementation control: the x30 validity check is
     * skipped, so the handler runs and control is transferred to an
     * unvalidated resume PC. */
    ok = 1;
#endif
    if (!ok) {
        /* No side effects: the handler is not called. */
        rt_fault(rt, AOT_FAULT_BAD_RESUME, src, r, (int64_t)thunk_id);
        return AOT_FAULT_BAD_RESUME;
    }
    {
        uint32_t rc = prog_hle(rt, AOT_HLE_HOSTCALL, thunk_id, src, r);
        if (rc != AOT_FAULT_NONE) return rc;
    }
#ifdef MN_AOT_MUTANT_THUNK_SITE4
    /* TEST-ONLY wrong-implementation control: a BR/PLT entry resumes at
     * site+4 instead of at the guest's own x30. */
    rt->next_pc = src + 4u;
#elif defined(MN_AOT_MUTANT_RESUME_AFTER)
    /* TEST-ONLY wrong-implementation control: the resume PC is re-read from
     * x30 AFTER the handler, so a handler's x30 write redirects control. */
    rt->next_pc = rt->state->x[30];
#else
    rt->next_pc = r;
#endif
    return AOT_FAULT_NONE;
}

/* Rule (dispatcher): every next_pc is resolved in this order - misaligned,
 * sentinel, thunk, image text range (binary search; absent = UNTRANSLATED),
 * otherwise UNKNOWN_PC. */
static AotExit prog_loop(AotRuntime *rt) {
    const AotProgram *p = rt->program;
    uint64_t pc = rt->next_pc;
    uint64_t src = pc;
    int arrival_ret = 0;   /* the transfer that produced `pc` was a RET */

    for (;;) {
        rt->state->pc = pc;
        if ((pc & 3u) != 0u) {
            rt_fault(rt, AOT_FAULT_MISALIGNED, src, pc, 0);
            return AOT_EXIT_FAULT;
        }
        {
            uint64_t off = 0;
            uint32_t rc;
            if (aot_program_in_sentinel(p, pc, &off)) {
                rc = prog_return_to_host(rt, off, arrival_ret, src, pc);
                if (rc != AOT_FAULT_NONE) return AOT_EXIT_FAULT;
                rt->reason = AOT_EXIT_STOP;
                rt->next_pc = pc;
                return AOT_EXIT_STOP;
            }
            if (aot_program_in_thunks(p, pc, &off)) {
                if ((off % AOT_THUNK_STRIDE) != 0u) {
                    rt_fault(rt, AOT_FAULT_BAD_TRANSFER, src, pc, 0);
                    return AOT_EXIT_FAULT;
                }
                rc = prog_thunk_enter(rt, (uint32_t)(off / AOT_THUNK_STRIDE),
                                      arrival_ret, src, pc);
                if (rc != AOT_FAULT_NONE) return AOT_EXIT_FAULT;
                /* The transfer that produced the new PC is the THUNK itself,
                 * so a failure while running the target reports the thunk PC
                 * as its site (rt->site_pc still describes the guest block
                 * that branched into the thunk). */
                src = pc;
                pc = rt->next_pc;
                /* A thunk that resumes at this frame's sentinel IS the guest
                 * function returning: its x30 was the sentinel slot. */
                arrival_ret = aot_program_in_sentinel(p, pc, NULL) ? 1 : 0;
                continue;
            }
        }
        {
            AotBlockFn fn;
            AotExit e;
            if (aot_program_image_at(p, pc) == NULL) {
                rt_fault(rt, AOT_FAULT_UNKNOWN_PC, src, pc, 0);
                return AOT_EXIT_FAULT;
            }
            fn = aot_program_lookup(p, pc);
            if (fn == NULL) {
                rt_fault(rt, AOT_FAULT_UNTRANSLATED, src, pc, 0);
                return AOT_EXIT_FAULT;
            }
            if (rt->steps >= rt->step_budget) {
                rt_fault(rt, AOT_FAULT_BUDGET, pc, 0, (int64_t)rt->step_budget);
                return AOT_EXIT_FAULT;
            }
            rt->steps++;
            rt_trace(rt, pc);

            rt->state->pc = pc;
            e = fn(rt->state, rt);
            rt->reason = e;

            switch (e) {
            case AOT_EXIT_FALLTHROUGH:
            case AOT_EXIT_BRANCH:
            case AOT_EXIT_COND:
            case AOT_EXIT_CALL:
            case AOT_EXIT_INDIRECT:
            case AOT_EXIT_CALL_INDIRECT:
            case AOT_EXIT_RET:
                src = rt->site_pc;
                pc = rt->next_pc;
                arrival_ret = (e == AOT_EXIT_RET);
                break;
            case AOT_EXIT_SVC: {
                uint64_t site = rt->site_pc;
                uint32_t rc = prog_hle(rt, AOT_HLE_SVC, rt->hle_id, site,
                                       site + 4u);
                if (rc != AOT_FAULT_NONE) return AOT_EXIT_FAULT;
                src = site;
                pc = rt->next_pc;
                arrival_ret = 0;
                break;
            }
            case AOT_EXIT_SYSREG: {
                uint64_t site = rt->site_pc;
                uint32_t rc = prog_hle(rt, AOT_HLE_SYSREG, rt->hle_id, site,
                                       site + 4u);
                if (rc != AOT_FAULT_NONE) return AOT_EXIT_FAULT;
                src = site;
                pc = rt->next_pc;
                arrival_ret = 0;
                break;
            }
            case AOT_EXIT_HOSTCALL:
                /* ABI-v2 images never emit this: the dispatcher resolves a
                 * thunk target itself and the resume is the guest's x30. */
                rt_fault(rt, AOT_FAULT_BAD_STATE, pc, rt->next_pc, (int64_t)e);
                return AOT_EXIT_FAULT;
            case AOT_EXIT_STOP:
                rt_fault(rt, AOT_FAULT_BAD_STATE, pc, rt->next_pc, (int64_t)e);
                return AOT_EXIT_FAULT;
            case AOT_EXIT_FAULT:
                if (rt->fault == AOT_FAULT_NONE)
                    rt_fault(rt, AOT_FAULT_MEMORY, pc, 0, -1);
                return AOT_EXIT_FAULT;
            default:
                rt_fault(rt, AOT_FAULT_BAD_STATE, pc, rt->next_pc, (int64_t)e);
                return AOT_EXIT_FAULT;
            }
        }
    }
}

uint32_t aot_call_guest(AotRuntime *rt, uint64_t fn, const uint64_t *args,
                        unsigned nargs, uint64_t *x0_out) {
    uint32_t d, rc;
    uint64_t save_next_pc, save_site_pc, save_state_pc;
    uint32_t save_hle_id;
    AotExit save_reason;
    AotExit e;

    if (rt == NULL || rt->state == NULL || rt->init_magic != AOT_RT_INIT_MAGIC)
        return AOT_FAULT_BAD_STATE;
    /* Minor 2: the OWNER-THREAD check comes FIRST, before any rt_fault write and
     * therefore also before the program==NULL path. A foreign thread must not
     * touch a single field of `rt` (fault, diagnostics, depth, state): the
     * refusal is reported through the return value only. */
    if (rt_current_thread() != rt->owner_thread) {
        /* FOREIGN THREAD: nothing in `rt` may be touched. The runtime is
         * single-owner state (diagnostics, fault, depth, monitor bookkeeping
         * and guest state are all owned by the creating thread), so an
         * out-of-owner call reports the refusal through its RETURN VALUE only
         * and leaves every field - including the sticky fault - untouched. */
        return AOT_FAULT_BAD_STATE;
    }
    if (rt->program == NULL || !rt->program_ok) {
        /* Owned by the calling thread, so this path may report through the
         * fault fields (a runtime in legacy single-image mode has no Program
         * entry point: aot_call_guest is Program-only). */
        rt_fault(rt, AOT_FAULT_NO_IMAGE, fn, 0, 0);
        return AOT_FAULT_NO_IMAGE;
    }
    d = rt->call_depth;
#ifndef MN_AOT_MUTANT_RECALL_AFTER_FAULT
    if (d != 0u && rt->fault != AOT_FAULT_NONE) {
        /* A sticky fault ends the run: no second nested guest call (which
         * would overwrite the fault that callers must observe). */
        return rt->fault;
    }
#else
    /* TEST-ONLY wrong-implementation control: the sticky-fault guard is gone,
     * so a second nested call runs after an inner fault. */
#endif
    if (d == 0u) {
        if (rt->running) {
            rt_fault(rt, AOT_FAULT_BAD_STATE, fn, 0, -5);
            return AOT_FAULT_BAD_STATE;
        }
    } else if (rt->in_handler == 0u) {
        /* A nested call is legal ONLY from inside a Program handler. */
        rt_fault(rt, AOT_FAULT_BAD_STATE, fn, 0, -6);
        return AOT_FAULT_BAD_STATE;
    }
    if (d == 0u) {
        /* Fresh top-level diagnostics. A nested call NEVER resets these. The
         * reset happens BEFORE the remaining input validation so a rejected
         * top-level attempt (misaligned sp, bad state) is also reported with
         * steps == 0: no block ran for THIS call. */
        rt->fault = AOT_FAULT_NONE;
        rt->fault_src = 0;
        rt->fault_target = 0;
        rt->fault_status = 0;
        rt->steps = 0;
        rt->event_count = 0;
        rt->events_overflow = 0;
        rt->trace_count = 0;
        rt->trace_overflow = 0;
        rt->reason = AOT_EXIT_NONE;
    }
    if (nargs > 8u || (nargs != 0u && args == NULL)) {
        rt_fault(rt, AOT_FAULT_BAD_STATE, fn, 0, -4);
        return AOT_FAULT_BAD_STATE;
    }
    if (d >= AOT_MAX_CALL_DEPTH) {
        rt_fault(rt, AOT_FAULT_DEPTH, fn, 0, (int64_t)d);
        if (d != 0u) rt->reason = AOT_EXIT_FAULT;
        return AOT_FAULT_DEPTH;
    }
    if ((rt->state->sp & 15u) != 0u) {
        /* Fault BEFORE running anything. */
        rt_fault(rt, AOT_FAULT_BAD_STATE, fn, 0, -7);
        return AOT_FAULT_BAD_STATE;
    }
    if (aot_state_validate(rt->state) != AOT_STATE_OK) {
        rt_fault(rt, AOT_FAULT_BAD_STATE, fn, 0, -1);
        return AOT_FAULT_BAD_STATE;
    }

    /* Per-frame return record. */
    rt->call[d].entry_sp = rt->state->sp;
    rt->call[d].sentinel_pc = rt->program->sentinel_base +
                              (uint64_t)AOT_THUNK_STRIDE * (uint64_t)d;
    for (uint32_t i = 0; i < 11u; i++)
        rt->call[d].x19_x29[i] = rt->state->x[19u + i];
    for (uint32_t i = 0; i < 8u; i++)
        rt->call[d].v8_v15[i] = rt->state->v[8u + i][0];
    rt->call[d].fpcr = rt->state->fpcr;

    save_next_pc = rt->next_pc;
    save_site_pc = rt->site_pc;
    save_hle_id = rt->hle_id;
    save_reason = rt->reason;
    save_state_pc = rt->state->pc;

    if (d == 0u) {
        rt->running = 1;
    }
#ifdef MN_AOT_MUTANT_RESET_STEPS
    else {
        /* TEST-ONLY wrong-implementation control: a nested call RESETS the
         * shared diagnostics instead of leaving them to the depth-0 call.
         * Compiled only into aot_prog_mut_reset_steps. */
        rt->steps = 0;
        rt->event_count = 0;
    }
#endif

    for (unsigned i = 0; i < nargs; i++) rt->state->x[i] = args[i];
    rt->state->x[30] = rt->call[d].sentinel_pc;
    rt->next_pc = fn;
    rt->site_pc = fn;
    rt->call_depth = d + 1u;

    aot_mem_clrex(&rt->mem, rt->monitor_token);
    e = prog_loop(rt);
    aot_mem_clrex(&rt->mem, rt->monitor_token);
    rt->call_depth = d;

    if (e == AOT_EXIT_STOP && rt->fault == AOT_FAULT_NONE) {
        rc = AOT_FAULT_NONE;
    } else if (rt->fault != AOT_FAULT_NONE) {
        rc = rt->fault;
        rt->reason = AOT_EXIT_FAULT;
    } else {
        rt_fault(rt, AOT_FAULT_BAD_STATE, fn, 0, -8);
        rc = AOT_FAULT_BAD_STATE;
    }

    if (d != 0u) {
#ifndef MN_AOT_MUTANT_NO_SCRATCH_SAVE
        /* Restore the suspended OUTER dispatch scratch (and the guest pc) so
         * the outer HOSTCALL resumes correctly. Diagnostics (fault, steps,
         * events, trace) are deliberately NOT restored: an inner fault is
         * sticky. Compiled without this block only for the scratch mutant. */
        rt->next_pc = save_next_pc;
        rt->site_pc = save_site_pc;
        rt->hle_id = save_hle_id;
        rt->reason = save_reason;
        rt->state->pc = save_state_pc;
#else
        (void)save_next_pc;
        (void)save_site_pc;
        (void)save_hle_id;
        (void)save_reason;
        (void)save_state_pc;
#endif
    } else {
        rt->running = 0;
        if (rc != AOT_FAULT_NONE) rt->state->pc = rt->fault_target;
    }
    if (rc == AOT_FAULT_NONE && x0_out != NULL) *x0_out = rt->state->x[0];
    return rc;
}

AotExit aot_rt_run(AotRuntime *rt, uint64_t entry_pc, uint64_t stop_pc) {
    if (rt->running) {
        /* Re-entrancy from a handler is NOT supported (see AotHleHandler
         * contract). Fail rather than resetting the logs of the live run. */
        rt->fault = AOT_FAULT_BAD_STATE;
        rt->fault_src = entry_pc;
        rt->fault_target = 0;
        rt->fault_status = -2;
        rt->reason = AOT_EXIT_FAULT;
        return AOT_EXIT_FAULT;
    }
    if (rt->program != NULL) {
        /* Program mode has exactly one entry API: aot_call_guest at depth 0. */
        rt->fault = AOT_FAULT_BAD_STATE;
        rt->fault_src = entry_pc;
        rt->fault_target = 0;
        rt->fault_status = -9;
        rt->reason = AOT_EXIT_FAULT;
        return AOT_EXIT_FAULT;
    }
    rt->running = 1;

    rt->fault = AOT_FAULT_NONE;
    rt->fault_src = 0;
    rt->fault_target = 0;
    rt->fault_status = 0;
    rt->event_count = 0;
    rt->events_overflow = 0;
    rt->trace_count = 0;
    rt->trace_overflow = 0;
    rt->steps = 0;
    rt->site_pc = entry_pc;

    if (rt->state == NULL) {
        rt_fault(rt, AOT_FAULT_BAD_STATE, entry_pc, 0, -1);
        goto fault_out;
    }
    if (rt->image == NULL) {
        rt_fault(rt, AOT_FAULT_NO_IMAGE, entry_pc, 0, 0);
        goto fault_out;
    }
    /* Re-validate identity: a runtime constructed against a mismatched image
     * must not execute even if init's error was ignored. */
    if (!rt->identity_ok || aot_image_validate(rt->image) != AOT_FAULT_NONE) {
        rt_fault(rt, AOT_FAULT_BAD_STATE, entry_pc, 0, -1);
        goto fault_out;
    }
    if (aot_state_validate(rt->state) != AOT_STATE_OK) {
        rt_fault(rt, AOT_FAULT_BAD_STATE, entry_pc, 0, -1);
        goto fault_out;
    }

    uint64_t pc = entry_pc;
    uint64_t src = entry_pc;
    int stop_ok = 0;   /* the narrow fixture STOP is only legal after a RET */
    for (;;) {
        rt->state->pc = pc;
        if ((pc & 3u) != 0u) {
            rt_fault(rt, AOT_FAULT_MISALIGNED, src, pc, 0);
            goto fault_out;
        }
        if (pc == stop_pc) {
            if (!stop_ok) {
                /* B/BR/BL/call/fallthrough/entry reaching the reserved stop
                 * PC is NOT a clean stop: fail closed as an unknown target. */
                rt_fault(rt, AOT_FAULT_UNKNOWN_PC, src, pc, 0);
                goto fault_out;
            }
            rt->reason = AOT_EXIT_STOP;
            rt->next_pc = pc;
            goto done;
        }
        AotBlockFn fn = aot_rt_lookup(rt, pc);
        if (fn == NULL) {
            rt_fault(rt, AOT_FAULT_UNKNOWN_PC, src, pc, 0);
            goto fault_out;
        }
        if (rt->steps >= rt->step_budget) {
            rt_fault(rt, AOT_FAULT_BUDGET, pc, 0, (int64_t)rt->step_budget);
            goto fault_out;
        }
        rt->steps++;
        rt_trace(rt, pc);

        rt->state->pc = pc;
        AotExit e = fn(rt->state, rt);
        rt->reason = e;

        switch (e) {
        case AOT_EXIT_FALLTHROUGH:
        case AOT_EXIT_BRANCH:
        case AOT_EXIT_COND:
        case AOT_EXIT_CALL:
        case AOT_EXIT_INDIRECT:
        case AOT_EXIT_CALL_INDIRECT:
        case AOT_EXIT_RET:
            /* Generated code set rt->site_pc to the transfer instruction. */
            src = rt->site_pc;
            pc = rt->next_pc;
            stop_ok = (e == AOT_EXIT_RET);
            break;
        case AOT_EXIT_SVC: {
            uint32_t rc = rt_hle(rt, AOT_HLE_SVC, rt->hle_id, rt->site_pc,
                                 rt->site_pc + 4u);
            if (rc != AOT_FAULT_NONE) goto fault_out;
            src = rt->site_pc;
            pc = rt->next_pc;
            stop_ok = 0;
            break;
        }
        case AOT_EXIT_HOSTCALL: {
            uint32_t rc = rt_hle(rt, AOT_HLE_HOSTCALL, rt->hle_id, rt->site_pc,
                                 rt->site_pc + 4u);
            if (rc != AOT_FAULT_NONE) goto fault_out;
            src = rt->site_pc;
            pc = rt->next_pc;
            stop_ok = 0;
            break;
        }
        case AOT_EXIT_STOP:
            /* A generated block must NEVER return STOP. The terminal STOP is
             * owned by the runtime and emitted only at the stop sentinel after
             * a RET. Fail closed like any other invalid block exit. */
            rt_fault(rt, AOT_FAULT_BAD_STATE, pc, rt->next_pc, (int64_t)e);
            goto fault_out;
        case AOT_EXIT_FAULT:
            if (rt->fault == AOT_FAULT_NONE)
                rt_fault(rt, AOT_FAULT_MEMORY, pc, 0, -1);
            goto fault_out;
        default:
            /* Unknown/unrecognized block exit: fail closed rather than
             * continuing with a stale next_pc. */
            rt_fault(rt, AOT_FAULT_BAD_STATE, pc, rt->next_pc, (int64_t)e);
            goto fault_out;
        }

        /* Indirect transfers may land in the host-thunk range. */
        if (e == AOT_EXIT_CALL_INDIRECT || e == AOT_EXIT_INDIRECT ||
            e == AOT_EXIT_CALL) {
            uint32_t thunk_id = 0;
            if (rt_in_thunks(rt->image, rt->next_pc, &thunk_id)) {
                if (e == AOT_EXIT_INDIRECT) {
                    rt_fault(rt, AOT_FAULT_TAIL_THUNK, rt->site_pc, rt->next_pc, 0);
                    goto fault_out;
                }
                uint32_t rc = rt_hle(rt, AOT_HLE_HOSTCALL, thunk_id,
                                     rt->site_pc, rt->site_pc + 4u);
                if (rc != AOT_FAULT_NONE) goto fault_out;
                pc = rt->next_pc;
                stop_ok = 0;
            }
        }
    }

fault_out:
    /* A fault is not a clean stop: conservatively clear this runtime's LOCAL
     * reservation. The RET/STOP sentinel deliberately preserves it (tested). */
    aot_mem_clrex(&rt->mem, rt->monitor_token);
    if (rt->state != NULL) rt->state->pc = rt->fault_target;
done:
    rt->running = 0;
    return rt->reason;
}
