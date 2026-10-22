/* Minimal G3 Start SVC 0x29 (GetInfo), SVC 0x01 (SetHeapSize),
 * SVC 0x06 (QueryMemory), SVC 0x0c (GetThreadPriority), SVC 0x25
 * (GetThreadId) and Mac host-override HLE. See g3_start_hle.h. */

#include "g3_start_hle.h"

#include "aot_as.h"

#include <string.h>

static void put_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void put_le64(uint8_t *p, uint64_t v)
{
    put_le32(p, (uint32_t)v);
    put_le32(p + 4, (uint32_t)(v >> 32));
}

static void hle_fault(AotRuntime *rt, const AotHleRequest *req,
                      int64_t status)
{
    rt->fault = AOT_FAULT_BAD_HLE;
    rt->fault_src = req->site_pc;
    rt->fault_target = req->resume_pc;
    rt->fault_status = status;
}

void g3_start_hle_init(G3StartHle *ctx, G3StartHleEntropy entropy,
                       void *entropy_user)
{
    if (ctx == 0) return;
    ctx->entropy = entropy;
    ctx->entropy_user = entropy_user;
    ctx->as = 0;
    ctx->threads = 0;
    ctx->thread_lookup = 0;
    ctx->thread_lookup_user = 0;
    ctx->budget = 0;
    ctx->entropy_calls = 0u;
    ctx->entropy_failures = 0u;
    ctx->unknown_info_calls = 0u;
    ctx->info2_calls = 0u;
    ctx->info3_calls = 0u;
    ctx->info12_calls = 0u;
    ctx->info13_calls = 0u;
    ctx->info14_calls = 0u;
    ctx->info15_calls = 0u;
    ctx->info4_calls = 0u;
    ctx->info5_calls = 0u;
    ctx->heap_query_failures = 0u;
    ctx->svc1_calls = 0u;
    ctx->svc1_invalid = 0u;
    ctx->svc1_host_failures = 0u;
    ctx->svc6_calls = 0u;
    ctx->svc6_success = 0u;
    ctx->svc6_null_out = 0u;
    ctx->svc6_unsupported = 0u;
    ctx->svc6_write_faults = 0u;
    ctx->svc6_host_failures = 0u;
    ctx->svc0c_calls = 0u;
    ctx->svc0c_success = 0u;
    ctx->svc0c_invalid = 0u;
    ctx->svc25_calls = 0u;
    ctx->svc25_success = 0u;
    ctx->svc25_invalid = 0u;
    ctx->thread_host_failures = 0u;
    ctx->info6_calls = 0u;
    ctx->info21_calls = 0u;
    ctx->info7_calls = 0u;
    ctx->info22_calls = 0u;
    ctx->budget_failures = 0u;
    ctx->host_diag_calls = 0u;
    ctx->svc2c_calls = 0u;
    ctx->svc2c_success = 0u;
    ctx->svc2c_invalid = 0u;
    ctx->svc2c_limit = 0u;
    ctx->svc2d_calls = 0u;
    ctx->svc2d_success = 0u;
    ctx->svc2d_invalid = 0u;
    ctx->alias_host_failures = 0u;
    ctx->sysres_limit = 0u;
    ctx->sysres_configured = 0u;
    ctx->info16_calls = 0u;
    ctx->sysres_failures = 0u;
    {
        unsigned i;
        for (i = 0u; i < (unsigned)G3_START_HLE_OVERRIDE_ID_COUNT; i++)
            ctx->override_calls[i] = 0u;
    }
    ctx->override_range_faults = 0u;
    ctx->override_boost_range_faults = 0u;
    ctx->override_host_failures = 0u;
}

void g3_start_hle_set_budget(G3StartHle *ctx, const G3StartBudget *budget)
{
    if (ctx == 0) return;
    ctx->budget = budget;
}

void g3_start_hle_set_system_resource_limit(G3StartHle *ctx, uint64_t limit) {
    if (ctx == 0) return;
    ctx->sysres_limit = limit;
    ctx->sysres_configured = 1u;
}

void g3_start_hle_set_thread_registry(G3StartHle *ctx,
                                      const G3StartThreadRegistry *threads)
{
    if (ctx == 0) return;
    ctx->threads = threads;
}

void g3_start_hle_set_thread_lookup(G3StartHle *ctx,
                                    G3StartHleThreadLookup lookup,
                                    void *user)
{
    if (ctx == 0) return;
    ctx->thread_lookup = lookup;
    ctx->thread_lookup_user = user;
}

static int resolve_thread(G3StartHle *ctx, uint32_t handle,
                          G3StartThreadInfo *out)
{
    if (ctx->thread_lookup != 0)
        return ctx->thread_lookup(handle, out, ctx->thread_lookup_user);
    return g3_start_hle_registry_lookup(ctx->threads, handle, out);
}

int g3_start_hle_registry_lookup(const G3StartThreadRegistry *reg,
                                 uint32_t handle, G3StartThreadInfo *out)
{
    uint32_t i;

    if (reg == 0 || out == 0 || reg->entries == 0 || reg->count == 0u)
        return 0;
    if (handle == G3_START_HLE_CUR_THREAD) {
#ifdef MN_G3_HLE_MUT_PSEUDO_REJECT
        /* WRONG (controlled mutant): reject the pseudo-handle. */
        return 0;
#endif
        /* Mac threads.c h_peek resolves H_CUR_THREAD to the CURRENT thread.
         * This borrowed registry has exactly one owned thread (main), so the
         * alias is restricted to is_main; it is not a general thread table. */
        for (i = 0u; i < reg->count; i++) {
            if (reg->entries[i].type == 1u && reg->entries[i].is_main != 0u) {
                *out = reg->entries[i];
                return 1;
            }
        }
        return 0;
    }
    for (i = 0u; i < reg->count; i++) {
        if (reg->entries[i].type == 1u &&
            reg->entries[i].handle == handle) {
            *out = reg->entries[i];
            return 1;
        }
    }
    return 0;
}

void g3_start_hle_set_address_space(G3StartHle *ctx, AotAddressSpace *as)
{
    if (ctx == 0) return;
    ctx->as = as;
}

void g3_start_hle_svc(AotRuntime *rt, AotGuestState *s,
                      const AotHleRequest *req, void *user)
{
    G3StartHle *ctx = (G3StartHle *)user;
    uint32_t info_id;

    if (rt == 0 || s == 0 || req == 0) return;
    if (req->kind != AOT_HLE_SVC || req->id != 0x29u) {
        hle_fault(rt, req, (int64_t)req->id);
        return;
    }

    /* Mac services.c: `unsigned id = (unsigned)r[1]` (32-bit truncation). */
    info_id = (uint32_t)s->x[1];
    switch (info_id) {
    case G3_START_HLE_INFO_RANDOM: {
        uint64_t value = 0u;
        int rc;
        if (ctx == 0 || ctx->entropy == 0) {
            if (ctx != 0) ctx->entropy_failures++;
            hle_fault(rt, req, G3_START_HLE_FAULT_ENTROPY);
            return;
        }
        ctx->entropy_calls++;
        rc = ctx->entropy(&value, ctx->entropy_user);
        if (rc != 0) {
            ctx->entropy_failures++;
            /* No zero-entropy success: guest registers stay unchanged. */
            hle_fault(rt, req, G3_START_HLE_FAULT_ENTROPY);
            return;
        }
        /* Register-only result ABI: r0=0, r1=value. Never touch [x0]. */
        s->x[0] = 0u;
        s->x[1] = value;
        return;
    }
    case 2u:
    case 3u: {
        /* Immutable alias geometry from the AS-owned reserved window. Never a
         * fake constant; missing AS/role fails closed with a negative status
         * like the heap ids. x0 is not dereferenced and x2/x3 are ignored. */
        uint64_t base = 0u, size = 0u;
        if (ctx == 0 || ctx->as == 0 ||
            aot_as_reserved_info(ctx->as, AOT_AS_RESERVED_ROLE_ALIAS, &base,
                                 &size) != AOT_MEM_OK) {
            if (ctx != 0) ctx->heap_query_failures++;
            hle_fault(rt, req, G3_START_HLE_FAULT_ALIAS);
            return;
        }
#ifdef MN_G3_HLE_MUT_INFO_CONST
        /* WRONG (controlled mutant): after a successful AS lookup, report
         * fake constants instead of the queried geometry. */
        base = 0x5100000000ull;
        size = 0x300000000ull;
#endif
        if (info_id == 2u) {
            ctx->info2_calls++;
            s->x[1] = base;
        } else {
            ctx->info3_calls++;
            s->x[1] = size;
        }
        s->x[0] = 0u;
        return;
    }
    case 12u:
    case 13u: {
        /* Existing D014 address-space extent [4 GiB, 512 GiB): base/size from
         * the authoritative AS bounds, never Mac's ASLR numeric identity. */
        uint64_t base = 0u, size = 0u;
        if (ctx == 0 || ctx->as == 0 ||
            aot_as_bounds(ctx->as, &base, &size) != AOT_MEM_OK) {
            if (ctx != 0) ctx->heap_query_failures++;
            hle_fault(rt, req, G3_START_HLE_FAULT_BOUNDS);
            return;
        }
        if (info_id == 12u) {
            ctx->info12_calls++;
            s->x[1] = base;
        } else {
            ctx->info13_calls++;
            s->x[1] = size;
        }
        s->x[0] = 0u;
        return;
    }
    case 14u:
    case 15u: {
        /* Immutable GLOBAL STACK MAPPING ARENA geometry, not the current
         * main-thread stack. AS-owned role only; no MapMemory implementation. */
        uint64_t base = 0u, size = 0u;
        uint32_t role = AOT_AS_RESERVED_ROLE_STACK;
#ifdef MN_G3_HLE_MUT_INFO14_ALIAS
        /* WRONG (controlled mutant): Info14/15 return the alias geometry. */
        role = AOT_AS_RESERVED_ROLE_ALIAS;
#endif
        if (ctx == 0 || ctx->as == 0 ||
            aot_as_reserved_info(ctx->as, role, &base,
                                 &size) != AOT_MEM_OK) {
            if (ctx != 0) ctx->heap_query_failures++;
            hle_fault(rt, req, G3_START_HLE_FAULT_STACK);
            return;
        }
        if (info_id == 14u) {
            ctx->info14_calls++;
            s->x[1] = base;
        } else {
            ctx->info15_calls++;
            s->x[1] = size;
        }
        s->x[0] = 0u;
        return;
    }
    case 4u:
    case 5u: {
        /* Mac services.c:258-279: id 4 = heap base, id 5 = HEAP_CAP. The
         * handler writes registers only; it NEVER dereferences x0 (the guest
         * wrapper stores r1 through its own saved out pointer). x2/x3 are
         * ignored exactly like the Mac reference. Without the real address
         * space (or its heap window) this fails closed with a negative status
         * instead of inventing a base/max. */
        AotAsHeapInfo heap;
        if (ctx == 0 || ctx->as == 0 ||
            aot_as_heap_info(ctx->as, &heap) != AOT_MEM_OK) {
            if (ctx != 0) ctx->heap_query_failures++;
            hle_fault(rt, req, G3_START_HLE_FAULT_HEAP);
            return;
        }
        if (info_id == 4u) {
            ctx->info4_calls++;
            s->x[1] = heap.base;
        } else {
            ctx->info5_calls++;
            s->x[1] = heap.max_size;   /* window maximum, NOT logical size */
        }
        s->x[0] = 0u;
        return;
    }
    case 6u:
    case 21u:
    case 7u:
    case 22u: {
        /* Mac services.c:264: 6/21 = APP_POOL, 7/22 = image+heap+alias. The
         * pool and pinned image bytes are the borrowed immutable budget; the
         * heap and alias contributions are the AS's COHERENT state, read under
         * ONE domain lock, never the 4 GiB max window, the host committed
         * high-water mark, or a stale copy of either counter. */
        AotAsUsage usage;
        uint64_t used;
        if (ctx == 0 || ctx->as == 0 || ctx->budget == 0 ||
            aot_as_is_poisoned(ctx->as) ||
            aot_as_usage(ctx->as, &usage) != AOT_MEM_OK ||
            ctx->budget->image_bytes > ctx->budget->pool) {
            if (ctx != 0) ctx->budget_failures++;
            hle_fault(rt, req, G3_START_HLE_FAULT_BUDGET);
            return;
        }
        if (usage.heap_size > ctx->budget->pool - ctx->budget->image_bytes) {
            if (ctx != 0) ctx->budget_failures++;
            hle_fault(rt, req, G3_START_HLE_FAULT_BUDGET);
            return;
        }
        used = ctx->budget->image_bytes + usage.heap_size;
#ifdef MN_G3_HLE_MUT_BUDGET_OMIT_ALIAS
        /* WRONG (controlled mutant): the pre-alias G3 behaviour, where mapped
         * physical pages were not charged against the pool. */
        usage.alias_bytes = 0u;
#endif
        if (usage.alias_bytes > ctx->budget->pool - used) {
            if (ctx != 0) ctx->budget_failures++;
            hle_fault(rt, req, G3_START_HLE_FAULT_BUDGET);
            return;
        }
        used += usage.alias_bytes;
        if (used > ctx->budget->pool) {
            if (ctx != 0) ctx->budget_failures++;
            hle_fault(rt, req, G3_START_HLE_FAULT_BUDGET);
            return;
        }
        if (info_id == 6u) {
            ctx->info6_calls++;
            s->x[1] = ctx->budget->pool;
        } else if (info_id == 21u) {
            ctx->info21_calls++;
            s->x[1] = ctx->budget->pool;
        } else if (info_id == 7u) {
            ctx->info7_calls++;
            s->x[1] = used;
        } else {
            ctx->info22_calls++;
            s->x[1] = used;
        }
        s->x[0] = 0u;
        return;
    }
    case 16u:
        /* Mac services.c:48,271: configured process system-resource limit. */
        if (ctx == 0 || !ctx->sysres_configured) {
            if (ctx != 0) ctx->sysres_failures++;
            hle_fault(rt, req, G3_START_HLE_FAULT_SYSRES);
            return;
        }
        ctx->info16_calls++;
        s->x[0] = 0u;
#ifdef MN_G3_HLE_MUT_SYSRES_CONST
        s->x[1] = 32ull << 20; /* wrong: ignore the configured profile */
#else
        s->x[1] = ctx->sysres_limit;
#endif
        return;
    default:
        if (ctx != 0) ctx->unknown_info_calls++;
        /* Fail closed and preserve every guest input register. */
        hle_fault(rt, req, (int64_t)info_id);
        return;
    }
}

void g3_start_hle_svc1(AotRuntime *rt, AotGuestState *s,
                       const AotHleRequest *req, void *user)
{
    G3StartHle *ctx = (G3StartHle *)user;
    uint64_t base = 0u;
    AotMemStatus st;

    if (rt == 0 || s == 0 || req == 0) return;
    if (req->kind != AOT_HLE_SVC || req->id != 0x01u) {
        hle_fault(rt, req, (int64_t)req->id);
        return;
    }
    if (ctx != 0) ctx->svc1_calls++;
    if (ctx == 0 || ctx->as == 0) {
        if (ctx != 0) ctx->svc1_host_failures++;
        hle_fault(rt, req, G3_START_HLE_FAULT_SVC1_HOST);
        return;
    }
    /* Mac services.c:310-313: size is the uint64 x1. An invalid request is a
     * normal ERR result (r0=0xd401) with every other register input preserved,
     * not a host fault and not a success. */
    st = aot_as_set_heap_size(ctx->as, s->x[1], &base);
    if (st == AOT_MEM_ERR_ALIGN) {
        if (ctx != 0) ctx->svc1_invalid++;
        s->x[0] = G3_START_HLE_INVALID_HEAP_SIZE;
        return;
    }
    if (st != AOT_MEM_OK) {
        /* Host/resource refusal: typed BAD_HLE, no guest register write and no
         * fabricated 0xd401 success/failure. No base output is written. */
        if (ctx != 0) ctx->svc1_host_failures++;
        hle_fault(rt, req, G3_START_HLE_FAULT_SVC1_HOST);
        return;
    }
    s->x[0] = 0u;
    s->x[1] = base;
}

void g3_start_hle_svc6(AotRuntime *rt, AotGuestState *s,
                       const AotHleRequest *req, void *user)
{
    G3StartHle *ctx = (G3StartHle *)user;
    uint64_t out_ptr;
    uint64_t query_addr;
    AotAsQuery q;
    uint8_t rec[40];
    AotMemStatus st;

    if (rt == 0 || s == 0 || req == 0) return;
    if (req->kind != AOT_HLE_SVC || req->id != 0x06u) {
        hle_fault(rt, req, (int64_t)req->id);
        return;
    }
    if (ctx != 0) ctx->svc6_calls++;
    /* r0 is the raw MemoryInfo output pointer; r2 is the queried address.
     * r1 (the guest PageInfo wrapper pointer) is deliberately not read. */
    out_ptr = s->x[0];
    query_addr = s->x[2];
    if (ctx == 0 || ctx->as == 0 || aot_as_is_poisoned(ctx->as)) {
        if (ctx != 0) ctx->svc6_host_failures++;
        hle_fault(rt, req, G3_START_HLE_FAULT_QUERY);
        return;
    }
#ifdef MN_G3_QUERY_MUT_MAPPED_ONLY
    if (!aot_as_query(ctx->as, query_addr, &q)) {
#else
    if (!aot_as_query_domain(ctx->as, query_addr, &q)) {
#endif
        if (ctx != 0) ctx->svc6_unsupported++;
        /* Typed unsupported: keep the queried guest VA in fault_target as a
         * diagnostic. No Mac state-3/perm-5 fallback is invented. */
        rt->fault = AOT_FAULT_BAD_HLE;
        rt->fault_src = req->site_pc;
        rt->fault_target = query_addr;
        rt->fault_status = G3_START_HLE_FAULT_QUERY_UNKNOWN;
        return;
    }
    put_le64(rec + 0, q.base);
    put_le64(rec + 8, q.size);
    put_le32(rec + 16, q.state);
    put_le32(rec + 20, q.attr);
    put_le32(rec + 24, q.perm);
    put_le32(rec + 28, 0u);   /* ipc */
    put_le32(rec + 32, 0u);   /* device */
    put_le32(rec + 36, 0u);   /* pad */
    /* Mac services.c: if(r0) memcpy(...); ONE write of the whole 40-byte
     * record. aot_as_write checks the entire span before copying, so a bad,
     * read-only or cross-NONE span leaves every byte unchanged. */
    if (out_ptr != 0u) {
        st = aot_as_write(ctx->as, out_ptr, rec, sizeof rec);
        if (st != AOT_MEM_OK) {
            if (ctx != 0) ctx->svc6_write_faults++;
            rt->fault = AOT_FAULT_MEMORY;
            rt->fault_src = req->site_pc;
            rt->fault_target = out_ptr;
            rt->fault_status = (int64_t)st;
            return;
        }
    } else if (ctx != 0) {
        ctx->svc6_null_out++;
    }
    if (ctx != 0) ctx->svc6_success++;
    /* Register-only result: exactly r0=0/r1=0, all other state unchanged. */
    s->x[0] = 0u;
    s->x[1] = 0u;
}

/* Mac threads.c:378: regs[0] = t ? 0 : R_BAD_HANDLE; regs[1] = t ? prio : 0.
 * The handle is the low 32 bits of x1 (Mac: (uint32_t)regs[1]); a missing
 * registry is a host misconfiguration (typed), an unknown handle is the
 * normal guest-visible Result 0xe401. */
void g3_start_hle_svc0c(AotRuntime *rt, AotGuestState *s,
                        const AotHleRequest *req, void *user)
{
    G3StartHle *ctx = (G3StartHle *)user;
    G3StartThreadInfo t;
    uint32_t handle;

    if (rt == 0 || s == 0 || req == 0) return;
    if (req->kind != AOT_HLE_SVC || req->id != 0x0cu) {
        hle_fault(rt, req, (int64_t)req->id);
        return;
    }
    if (ctx != 0) ctx->svc0c_calls++;
    if (ctx == 0 ||
        (ctx->threads == 0 && ctx->thread_lookup == 0)) {
        if (ctx != 0) ctx->thread_host_failures++;
        hle_fault(rt, req, G3_START_HLE_FAULT_THREAD);
        return;
    }
    handle = (uint32_t)s->x[1];
    if (!resolve_thread(ctx, handle, &t)) {
        ctx->svc0c_invalid++;
        s->x[0] = G3_START_HLE_BAD_HANDLE;
        s->x[1] = 0u;
        return;
    }
    ctx->svc0c_success++;
#ifdef MN_G3_HLE_MUT_PRIO_CONST
    /* WRONG (controlled mutant): same priority for every handle. */
    (void)t;
    s->x[0] = 0u;
    s->x[1] = 44u;
#else
    s->x[0] = 0u;
    s->x[1] = (uint64_t)(int64_t)t.priority;
#endif
}

/* Mac threads.c:389: identical lookup; r1 is the Horizon thread id. */
void g3_start_hle_svc25(AotRuntime *rt, AotGuestState *s,
                        const AotHleRequest *req, void *user)
{
    G3StartHle *ctx = (G3StartHle *)user;
    G3StartThreadInfo t;
    uint32_t handle;

    if (rt == 0 || s == 0 || req == 0) return;
    if (req->kind != AOT_HLE_SVC || req->id != 0x25u) {
        hle_fault(rt, req, (int64_t)req->id);
        return;
    }
    if (ctx != 0) ctx->svc25_calls++;
    if (ctx == 0 ||
        (ctx->threads == 0 && ctx->thread_lookup == 0)) {
        if (ctx != 0) ctx->thread_host_failures++;
        hle_fault(rt, req, G3_START_HLE_FAULT_THREAD);
        return;
    }
    handle = (uint32_t)s->x[1];
    if (!resolve_thread(ctx, handle, &t)) {
        ctx->svc25_invalid++;
        s->x[0] = G3_START_HLE_BAD_HANDLE;
        s->x[1] = 0u;
        return;
    }
    ctx->svc25_success++;
#ifdef MN_G3_HLE_MUT_HOST_TID
    /* WRONG (controlled mutant): host OS thread id instead of guest id. */
    s->x[0] = 0u;
    s->x[1] = (uint64_t)t.owner_os_thread;
#else
    s->x[0] = 0u;
    s->x[1] = t.guest_id;
#endif
}

/* Mac services.c:167: void, host logging only. No guest result to invent. */
void g3_start_hle_host_diag(AotRuntime *rt, AotGuestState *s,
                           const AotHleRequest *req, void *user) {
    G3StartHle *ctx = (G3StartHle *)user;
    if (rt == 0 || s == 0 || req == 0) return;
    if (req->kind != AOT_HLE_HOSTCALL || ctx == 0) {
        hle_fault(rt, req, G3_START_HLE_FAULT_DIAG);
        return;
    }
    ctx->host_diag_calls++;
}

/* ---- Mac host overrides (services.c:168-177) --------------------------
 *
 * Each entry is one Mac override symbol. Registration is BY NAME: the thunk
 * ordinal comes from the link configuration, so nothing here can be a title-
 * specific constant, and the request `id` is never validated against a fixed
 * value. Only the request KIND (host call), the context and the per-entry
 * semantics are checked.
 */
static void override_enter(AotRuntime *rt, AotGuestState *s,
                           const AotHleRequest *req, void *user,
                           G3StartHleOverrideId id)
{
    G3StartHle *ctx = (G3StartHle *)user;
    int32_t offset, count, mode;

    if (rt == 0 || s == 0 || req == 0 ||
        id < 0 || id >= G3_START_HLE_OVERRIDE_ID_COUNT)
        return;
    if (ctx == 0 || req->kind != AOT_HLE_HOSTCALL) {
        if (ctx != 0) ctx->override_host_failures++;
        hle_fault(rt, req, G3_START_HLE_FAULT_OVERRIDE);
        return;
    }
    ctx->override_calls[id]++;
    switch (id) {
    case G3_START_HLE_OVERRIDE_AOC_COUNT:
        /* Mac services.c:170: `static int host_aoc_count(void){return 0;}`.
         * Only the return register moves. */
#ifdef MN_G3_HLE_MUT_OVERRIDE_COUNT
        /* WRONG (controlled mutant): reports one add-on content. */
        s->x[0] = 1u;
#else
        s->x[0] = 0u;
#endif
        return;
    case G3_START_HLE_OVERRIDE_AOC_LIST:
        /* Mac services.c:171: `(void)out;` -- the output pointer is never
         * dereferenced -- and `if(offset<0||count<0)runtime_fail(...)`. The
         * arguments are C ints, so the sign test is on the LOW 32 bits. */
        offset = (int32_t)(uint32_t)s->x[1];
        count = (int32_t)(uint32_t)s->x[2];
        if (offset < 0 || count < 0) {
            /* Mac aborts; this port raises a typed fault and writes nothing
             * (no x0 Result, no memory), so the caller's state stays intact. */
            ctx->override_range_faults++;
            hle_fault(rt, req, G3_START_HLE_FAULT_AOC_RANGE);
            return;
        }
        s->x[0] = 0u;
        return;
    case G3_START_HLE_OVERRIDE_OE_CPU_BOOST:
        /* Mac services.c:184: `static void cpu_boost(int mode){ if(mode<0||
         * mode>2) runtime_fail(...); fprintf(stderr, ...); }`. The parameter is
         * a C int, so only the LOW 32 bits of x0 are the mode. It is void: no
         * Result, no state, no actual frequency change -- all guest state is
         * preserved either way. */
        mode = (int32_t)(uint32_t)s->x[0];
#ifdef MN_G3_HLE_MUT_SKIP_BOOST_RANGE
        /* WRONG (controlled mutant): drops the Mac mode range check, so a
         * later out-of-range request looks like a normal void call. */
        (void)mode;
#else
        if (mode < 0 || mode > 2) {
            ctx->override_boost_range_faults++;
            hle_fault(rt, req, G3_START_HLE_FAULT_CPU_BOOST);
            return;
        }
#endif
        return;
    default:
        /* Every remaining Mac body is `void` and only prints to stderr. No
         * guest register, flag or byte may change. */
#ifdef MN_G3_HLE_MUT_OVERRIDE_X0
        /* WRONG (controlled mutant): a void override fabricates x0 = 0. */
        s->x[0] = 0u;
#endif
#ifdef MN_G3_HLE_MUT_OVERRIDE_WRITE
        /* WRONG (controlled mutant): the void override writes one guest byte
         * through the PRODUCTION write path (the borrowed address space at the
         * caller's out pointer), which Mac's print-only substitute never does. */
        if (ctx->as != 0) {
            uint8_t byte = 0xa5u;
            (void)aot_as_write(ctx->as, s->x[0], &byte, 1u);
        }
#endif
        return;
    }
}

static void override_oe_init(AotRuntime *rt, AotGuestState *s,
                            const AotHleRequest *req, void *user)
{
    override_enter(rt, s, req, user, G3_START_HLE_OVERRIDE_OE_INIT);
}

static void override_aoc_init(AotRuntime *rt, AotGuestState *s,
                             const AotHleRequest *req, void *user)
{
    override_enter(rt, s, req, user, G3_START_HLE_OVERRIDE_AOC_INIT);
}

static void override_aoc_count(AotRuntime *rt, AotGuestState *s,
                              const AotHleRequest *req, void *user)
{
    override_enter(rt, s, req, user, G3_START_HLE_OVERRIDE_AOC_COUNT);
}

static void override_aoc_list(AotRuntime *rt, AotGuestState *s,
                             const AotHleRequest *req, void *user)
{
    override_enter(rt, s, req, user, G3_START_HLE_OVERRIDE_AOC_LIST);
}

static void override_err_init(AotRuntime *rt, AotGuestState *s,
                             const AotHleRequest *req, void *user)
{
    override_enter(rt, s, req, user, G3_START_HLE_OVERRIDE_ERR_INIT);
}

static void override_pctl_init(AotRuntime *rt, AotGuestState *s,
                              const AotHleRequest *req, void *user)
{
    override_enter(rt, s, req, user, G3_START_HLE_OVERRIDE_PCTL_INIT);
}

static void override_abort_init(AotRuntime *rt, AotGuestState *s,
                               const AotHleRequest *req, void *user)
{
    override_enter(rt, s, req, user, G3_START_HLE_OVERRIDE_ABORT_INIT);
}

static void override_oe_cpu_boost(AotRuntime *rt, AotGuestState *s,
                                 const AotHleRequest *req, void *user)
{
    override_enter(rt, s, req, user, G3_START_HLE_OVERRIDE_OE_CPU_BOOST);
}

/* The shipping name table. Order follows G3StartHleOverrideId; a caller
 * indexes it by NAME, never by position. */
static const G3StartHleOverride g_overrides[G3_START_HLE_OVERRIDE_ID_COUNT] = {
    { "_ZN2nn2oe10InitializeEv", override_oe_init,
      G3_START_HLE_OVERRIDE_OE_INIT },
    { "_ZN2nn3aoc10InitializeEv", override_aoc_init,
      G3_START_HLE_OVERRIDE_AOC_INIT },
    { "_ZN2nn3aoc17CountAddOnContentEv", override_aoc_count,
      G3_START_HLE_OVERRIDE_AOC_COUNT },
    { "_ZN2nn3aoc16ListAddOnContentEPiii", override_aoc_list,
      G3_START_HLE_OVERRIDE_AOC_LIST },
    { "_ZN2nn3err26InitializeContextWriterApiEv", override_err_init,
      G3_START_HLE_OVERRIDE_ERR_INIT },
    { "_ZN2nn4pctl10InitializeEv", override_pctl_init,
      G3_START_HLE_OVERRIDE_PCTL_INIT },
    { "_ZN2nn4diag34InitializeApplicationAbortObserverEv", override_abort_init,
      G3_START_HLE_OVERRIDE_ABORT_INIT },
    { "_ZN2nn2oe15SetCpuBoostModeENS0_12CpuBoostModeE", override_oe_cpu_boost,
      G3_START_HLE_OVERRIDE_OE_CPU_BOOST }
};

/* Names whose Mac body is real host work this increment does NOT model. They
 * are absent from g_overrides, so the lookup refuses them and a driver can
 * never register them; the guest call keeps failing closed (BAD_HLE).
 * Mac services.c:175 host_fs_init calls runtime_fs_init(). */
static const char *const g_overrides_not_modelled[] = {
    "_ZN2nn2fs24InitializeForApplicationEv"
};

const G3StartHleOverride *g3_start_hle_override_lookup(const char *name)
{
    unsigned i;

    if (name == 0) return 0;
    for (i = 0u; i < (unsigned)G3_START_HLE_OVERRIDE_ID_COUNT; i++) {
        if (strcmp(g_overrides[i].name, name) == 0) return &g_overrides[i];
    }
    return 0;   /* unknown OR not-yet-modelled: never a fallback handler */
}

int g3_start_hle_override_not_modelled(const char *name)
{
    unsigned i;

    if (name == 0) return 0;
    for (i = 0u; i < (unsigned)(sizeof g_overrides_not_modelled /
                                sizeof g_overrides_not_modelled[0]); i++) {
        if (strcmp(g_overrides_not_modelled[i], name) == 0) return 1;
    }
    return 0;
}

unsigned g3_start_hle_override_table_count(void)
{
    return (unsigned)G3_START_HLE_OVERRIDE_ID_COUNT;
}

const G3StartHleOverride *g3_start_hle_override_table_at(unsigned index)
{
    if (index >= (unsigned)G3_START_HLE_OVERRIDE_ID_COUNT) return 0;
    return &g_overrides[index];
}

unsigned g3_start_hle_override_calls(const G3StartHle *ctx,
                                    const G3StartHleOverride *override_entry)
{
    if (ctx == 0 || override_entry == 0 || override_entry->id < 0 ||
        override_entry->id >= G3_START_HLE_OVERRIDE_ID_COUNT)
        return 0u;
    if (g_overrides[override_entry->id].name != override_entry->name)
        return 0u;   /* not an entry of THIS table */
    return ctx->override_calls[override_entry->id];
}

/* Mac services.c:283 MapPhysicalMemory (0x2c) / UnmapPhysicalMemory (0x2d):
 * `uint64_t a = r[0], n = r[1]; r[0] = alias_map(num == 0x2d, a, n);`
 * The AS owns the page state, the ipc/pool budget and the host mapping; this
 * handler only validates the request shape, maps the typed status back to
 * Mac's Result codes and writes r0. Nothing else is touched, so a failed call
 * leaves every input register and every guest byte unchanged. */
void g3_start_hle_svc_alias(AotRuntime *rt, AotGuestState *s,
                            const AotHleRequest *req, void *user)
{
    G3StartHle *ctx = (G3StartHle *)user;
    int unmap;
    uint64_t addr, size, fresh = 0u;
#ifndef MN_G3_HLE_MUT_ALIAS_NO_UNMAP
    uint64_t released = 0u;
#endif
    AotMemStatus st;

    if (rt == 0 || s == 0 || req == 0) return;
    if (req->kind != AOT_HLE_SVC ||
        (req->id != 0x2cu && req->id != 0x2du)) {
        hle_fault(rt, req, (int64_t)req->id);
        return;
    }
    unmap = (req->id == 0x2du);
    addr = s->x[0];
    size = s->x[1];
    if (ctx != 0) {
        if (unmap) ctx->svc2d_calls++;
        else ctx->svc2c_calls++;
    }
    if (ctx == 0 || ctx->as == 0 || ctx->budget == 0 ||
        aot_as_is_poisoned(ctx->as)) {
        if (ctx != 0) ctx->alias_host_failures++;
        hle_fault(rt, req, G3_START_HLE_FAULT_ALIAS_MAP);
        return;
    }
    if (unmap) {
#ifdef MN_G3_HLE_MUT_ALIAS_NO_UNMAP
        /* WRONG (controlled mutant): an unmap is serviced as a map, so the
         * released pages stay mapped and keep answering state 5. */
        st = aot_as_alias_map(ctx->as, addr, size, ctx->budget->image_bytes,
                              ctx->budget->pool, &fresh);
#else
        st = aot_as_alias_unmap(ctx->as, addr, size, &released);
#endif
    } else {
        st = aot_as_alias_map(ctx->as, addr, size, ctx->budget->image_bytes,
                              ctx->budget->pool, &fresh);
    }
    switch (st) {
    case AOT_MEM_OK:
        break;
    case AOT_MEM_ERR_ALIGN:
        if (ctx != 0) {
            if (unmap) ctx->svc2d_invalid++;
            else ctx->svc2c_invalid++;
        }
        s->x[0] = (uint64_t)G3_START_HLE_ALIAS_INVALID_ALIGN;
        return;
    case AOT_MEM_ERR_RANGE:
        if (unmap) {
            if (ctx != 0) ctx->svc2d_invalid++;
        } else if (ctx != 0) {
            ctx->svc2c_invalid++;
        }
        s->x[0] = (uint64_t)G3_START_HLE_ALIAS_INVALID_RANGE;
        return;
    case AOT_MEM_ERR_LIMIT:
        /* Map only (Mac checks no budget on unmap). */
        if (ctx != 0) ctx->svc2c_limit++;
#ifdef MN_G3_HLE_MUT_ALIAS_LIMIT_CODE
        /* WRONG (controlled mutant): a physical-memory pool refusal reported
         * as the generic invalid-handle result instead of LimitReached. */
        s->x[0] = (uint64_t)G3_START_HLE_INVALID_HEAP_SIZE;
#else
        s->x[0] = (uint64_t)G3_START_HLE_ALIAS_LIMIT;
#endif
        return;
    default:
        /* PERM/HOST: Mac aborts the process. Never fabricate a Result. */
        if (ctx != 0) ctx->alias_host_failures++;
        hle_fault(rt, req, G3_START_HLE_FAULT_ALIAS_MAP);
        return;
    }
    if (unmap) {
        if (ctx != 0) ctx->svc2d_success++;
    } else if (ctx != 0) {
        ctx->svc2c_success++;
    }
    s->x[0] = 0u;
#ifdef MN_G3_HLE_MUT_ALIAS_CLOBBER
    /* WRONG (controlled mutant): the handler also writes r1, which Mac never
     * touches, so a caller's live size stays observable in the register. */
    s->x[1] = (unmap ? released : fresh);
#endif
}
