#include "aot_runtime.h"

#include <string.h>

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
        /* Detach the BORROWED guest state too (release never owns or frees
         * it). Without this, a later erroneous run would still write
         * rt->state->pc in fault_out after the caller has freed or poisoned
         * the backing state. */
        rt->state = NULL;
        rt->running = 0;
    }
}

uint32_t aot_rt_init(AotRuntime *rt, const AotImage *image, AotMem mem,
                     AotGuestState *state, uint64_t step_budget) {
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
            rt_fault(rt, AOT_FAULT_BAD_STATE, 0, 0, -1);
            return AOT_FAULT_BAD_STATE;
        }
    }
    rt->step_budget = step_budget;
    rt->reason = AOT_EXIT_NONE;
    rt->running = 0;
    rt->identity_ok = 0;
    if (state == NULL) {
        rt_fault(rt, AOT_FAULT_BAD_STATE, 0, 0, -1);
        return AOT_FAULT_BAD_STATE;
    }
    if (image == NULL) {
        rt->image = NULL;
        return AOT_FAULT_NONE;   /* no-dispatch runtime */
    }
    uint32_t rc = aot_image_validate(image);
    if (rc != AOT_FAULT_NONE) {
        rt->image = NULL;
        rt_fault(rt, rc, 0, 0, -1);
        return rc;
    }
    if (aot_state_validate(state) != AOT_STATE_OK) {
        rt->image = image;
        rt_fault(rt, AOT_FAULT_BAD_STATE, 0, 0, -1);
        return AOT_FAULT_BAD_STATE;
    }
    rt->image = image;
    rt->identity_ok = 1;
    return AOT_FAULT_NONE;
}

int aot_rt_set_handler(AotRuntime *rt, uint32_t kind, uint32_t id,
                       AotHleHandler fn, void *user) {
    if (fn == NULL) return 1;
    for (size_t i = 0; i < rt->handler_count; i++) {
        if (rt->handlers[i].kind == kind && rt->handlers[i].id == id) return 2;
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
        if (rt->handlers[i].kind == kind && rt->handlers[i].id == id) {
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
