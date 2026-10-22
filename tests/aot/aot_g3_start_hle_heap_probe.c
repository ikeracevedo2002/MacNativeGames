/*
 * Game-data-free unit rows for the G3 Start HLE heap wiring.
 *
 * Proves the register-only GetInfo(4/5) and SetHeapSize SVC 0x01 contract
 * against the REAL address-space heap window, with host_vm_query as the
 * independent OS witness. No translation, no game data.
 *
 * Exit: 0 all rows passed, 1 infrastructure, 2 semantic failure.
 */
#include "aot_as.h"
#include "g3_start_hle.h"
#include "host_vm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HBASE 0x4000000000ull
#define HMAX  0x100000000ull
#define HLIMIT 0x600000ull
#define ABASE  0x5000000000ull
#define ASIZE  0x200000000ull
#define SBASE  0x2800000000ull
#define SSIZE  0x10000000ull
#define PG 0x1000ull

static int g_fail;

static void check(int cond, const char *msg) {
    if (!cond) {
        printf("FAIL: %s\n", msg);
        g_fail = 1;
    }
}

static int provider_zero(uint64_t *out, void *user) {
    (void)user;
    *out = 0u;
    return 0;
}

static void init_state(AotGuestState *s) {
    memset(s, 0, sizeof *s);
    for (unsigned i = 0; i < 31u; i++)
        s->x[i] = 0x1111000000000000ull + i;
    s->sp = 0x2000040000ull;
    s->pc = 0x10201584b4ull;
    s->nzcv = 0x80000000ull;
    s->fpcr = 0x12345678ull;
    s->fpsr = 1u;
    s->tpidr = 0x3000000000ull;
    s->tpidrro = 0x3000002000ull;
}

static void run(AotProgHandler fn, G3StartHle *ctx, uint32_t id,
                AotGuestState *s, AotRuntime *rt, AotHleRequest *req) {
    memset(rt, 0, sizeof *rt);
    req->kind = AOT_HLE_SVC;
    req->id = id;
    req->site_pc = 0x10201584b0ull;
    req->resume_pc = 0x10201584b4ull;
    fn(rt, s, req, ctx);
}

static int rest_unchanged(const AotGuestState *s, const AotGuestState *b) {
    if (s->sp != b->sp || s->pc != b->pc || s->nzcv != b->nzcv ||
        s->fpcr != b->fpcr || s->fpsr != b->fpsr || s->tpidr != b->tpidr ||
        s->tpidrro != b->tpidrro)
        return 0;
    if (memcmp(s->v, b->v, sizeof s->v) != 0) return 0;
    for (unsigned i = 2u; i < 31u; i++)
        if (s->x[i] != b->x[i]) return 0;
    return 1;
}

static host_vm_info os_page(AotAddressSpace *as, uint64_t addr) {
    host_vm_region *vm = NULL;
    const uint8_t *page = (const uint8_t *)(uintptr_t)1;
    size_t off = 0u;
    host_vm_info info;
    if (!aot_as_host_page(as, addr, &vm, &page, &off) || vm == NULL ||
        page != NULL || off != (size_t)(addr - HBASE))
        exit(1);
    memset(&info, 0, sizeof info);
    if (host_vm_query(vm, off, &info) != HOST_VM_OK) exit(1);
    return info;
}

int main(void) {
    AotMemDomain *dom = aot_mem_domain_create();
    AotAddressSpace *as = NULL;
    AotAsHeapInfo heap;
    G3StartHle ctx;
    AotGuestState s, b;
    AotRuntime rt;
    AotHleRequest req;
    host_vm_info os;
    uint8_t pat[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t back[8];
    uint64_t v;

    if (dom == NULL) { printf("FATAL: domain\n"); return 1; }

    /* Pure RNG-only context (AS NULL): Info 11 still works, Info 4/5 fail
     * closed with a NEGATIVE host status. */
    g3_start_hle_init(&ctx, provider_zero, NULL);
    init_state(&s);
    s.x[0] = 0xdeadbeefull;
    s.x[1] = 4u;
    b = s;
    run(g3_start_hle_svc, &ctx, 0x29u, &s, &rt, &req);
    check(rt.fault == AOT_FAULT_BAD_HLE &&
              rt.fault_status == G3_START_HLE_FAULT_HEAP &&
              memcmp(&s, &b, sizeof s) == 0,
          "Info4 without an address space fails closed and writes nothing");
    s.x[1] = 5u;
    b = s;
    run(g3_start_hle_svc, &ctx, 0x29u, &s, &rt, &req);
    check(rt.fault == AOT_FAULT_BAD_HLE &&
              rt.fault_status == G3_START_HLE_FAULT_HEAP &&
              memcmp(&s, &b, sizeof s) == 0,
          "Info5 without an address space fails closed and writes nothing");
    s.x[1] = 2u;
    b = s;
    run(g3_start_hle_svc, &ctx, 0x29u, &s, &rt, &req);
    check(rt.fault == AOT_FAULT_BAD_HLE &&
              rt.fault_status == G3_START_HLE_FAULT_ALIAS &&
              memcmp(&s, &b, sizeof s) == 0,
          "Info2 without an alias window fails closed");
    s.x[1] = 14u;
    b = s;
    run(g3_start_hle_svc, &ctx, 0x29u, &s, &rt, &req);
    check(rt.fault == AOT_FAULT_BAD_HLE &&
              rt.fault_status == G3_START_HLE_FAULT_STACK &&
              memcmp(&s, &b, sizeof s) == 0,
          "Info14 without an address space fails closed");
    s.x[1] = 12u;
    b = s;
    run(g3_start_hle_svc, &ctx, 0x29u, &s, &rt, &req);
    check(rt.fault == AOT_FAULT_BAD_HLE &&
              rt.fault_status == G3_START_HLE_FAULT_BOUNDS &&
              memcmp(&s, &b, sizeof s) == 0,
          "Info12 without an address space fails closed");
    s.x[1] = 11u;
    run(g3_start_hle_svc, &ctx, 0x29u, &s, &rt, &req);
    check(rt.fault == AOT_FAULT_NONE && s.x[0] == 0u && s.x[1] == 0u,
          "pure RNG context keeps Info11 working with a NULL address space");

    /* Real heap window (8 MiB max, 6 MiB checked budget). */
    as = aot_as_create(dom);
    if (as == NULL) { printf("FATAL: as\n"); return 1; }
    if (aot_as_add_heap_window(as, HBASE, HMAX, HLIMIT) != AOT_MEM_OK) {
        printf("FATAL: heap add\n");
        return 1;
    }
    if (aot_as_add_reserved_window(as, ABASE, ASIZE,
                                   AOT_AS_RESERVED_ROLE_ALIAS) != AOT_MEM_OK) {
        printf("FATAL: alias add\n");
        return 1;
    }
    if (aot_as_add_reserved_window(as, SBASE, SSIZE,
                                   AOT_AS_RESERVED_ROLE_STACK) != AOT_MEM_OK) {
        printf("FATAL: stack add\n");
        return 1;
    }
    if (aot_as_seal(as) != AOT_MEM_OK) { printf("FATAL: seal\n"); return 1; }
    g3_start_hle_init(&ctx, provider_zero, NULL);
    g3_start_hle_set_address_space(&ctx, as);

    /* Info 4: real base, raw r0=0, x2/x3 ignored, x0 never dereferenced. */
    init_state(&s);
    s.x[0] = 0xdeadbeefdeadbeefull;   /* invalid/unwritable if dereferenced */
    s.x[1] = 4u;
    s.x[2] = 0x2222222222222222ull;
    s.x[3] = 0x3333333333333333ull;
    b = s;
    run(g3_start_hle_svc, &ctx, 0x29u, &s, &rt, &req);
    check(rt.fault == AOT_FAULT_NONE && s.x[0] == 0u && s.x[1] == HBASE &&
              s.x[2] == b.x[2] && s.x[3] == b.x[3] &&
              rest_unchanged(&s, &b) && ctx.info4_calls == 1u,
          "Info4 returns the real AS base and ignores x2/x3");
    check(HBASE > 0xffffffffull, "Info4 base is above 32 bits");

    /* Info 5: window MAX, not the logical size (which is 0 here). */
    init_state(&s);
    s.x[0] = 0xdeadbeefdeadbeefull;
    s.x[1] = 5u;
    s.x[2] = 0x4444444444444444ull;
    s.x[3] = 0x5555555555555555ull;
    b = s;
    run(g3_start_hle_svc, &ctx, 0x29u, &s, &rt, &req);
    check(rt.fault == AOT_FAULT_NONE && s.x[0] == 0u && s.x[1] == HMAX &&
              s.x[1] > 0xffffffffull && s.x[2] == b.x[2] &&
              s.x[3] == b.x[3] && rest_unchanged(&s, &b),
          "Info5 returns the 4 GiB-class window max, not the logical size");
    check(aot_as_heap_info(as, &heap) == AOT_MEM_OK && heap.size == 0u,
          "Info5 did not change the logical heap size");

    /* Info 2/3: AS-owned alias geometry, distinct from the heap, x0 never
     * dereferenced, x2/x3 ignored, and dynamic if the AS geometry differs. */
    init_state(&s);
    s.x[0] = 0xdeadbeefdeadbeefull;
    s.x[1] = 2u;
    s.x[2] = 0x8888888888888888ull;
    s.x[3] = 0x9999999999999999ull;
    b = s;
    run(g3_start_hle_svc, &ctx, 0x29u, &s, &rt, &req);
    check(rt.fault == AOT_FAULT_NONE && s.x[0] == 0u && s.x[1] == ABASE &&
              s.x[2] == b.x[2] && s.x[3] == b.x[3] &&
              rest_unchanged(&s, &b) && ctx.info2_calls == 1u,
          "Info2 returns the AS alias base, not a constant");
    check(ABASE != HBASE && ABASE > 0xffffffffull,
          "Info2 and Info4 geometries are distinct above 32 bits");
    init_state(&s);
    s.x[0] = 0xdeadbeefdeadbeefull;
    s.x[1] = 3u;
    s.x[2] = 0xaaaaaaaaaaaaaaaaull;
    s.x[3] = 0xbbbbbbbbbbbbbbbbull;
    b = s;
    run(g3_start_hle_svc, &ctx, 0x29u, &s, &rt, &req);
    check(rt.fault == AOT_FAULT_NONE && s.x[0] == 0u && s.x[1] == ASIZE &&
              s.x[2] == b.x[2] && s.x[3] == b.x[3] &&
              rest_unchanged(&s, &b) && ctx.info3_calls == 1u,
          "Info3 returns the AS alias size, not a constant");

    /* Info 12/13: authoritative AS bounds, derived in this test from the same
     * Core getter, above 32 bits, no host pointer leakage. */
    {
        uint64_t bb = 0u, bn = 0u;
        if (aot_as_bounds(as, &bb, &bn) != AOT_MEM_OK) {
            printf("FATAL: bounds\n");
            return 1;
        }
        check(bb == AOT_AS_MIN_ADDR && bb + bn == AOT_AS_MAX_ADDR &&
                  bn > 0xffffffffull,
              "AS bounds are [4 GiB, 512 GiB) and >32-bit");
        init_state(&s);
        s.x[0] = 0xdeadbeefdeadbeefull;
        s.x[1] = 12u;
        s.x[2] = 0xccccccccccccccccull;
        s.x[3] = 0xddddddddddddddddull;
        b = s;
        run(g3_start_hle_svc, &ctx, 0x29u, &s, &rt, &req);
        check(rt.fault == AOT_FAULT_NONE && s.x[0] == 0u && s.x[1] == bb &&
                  s.x[2] == b.x[2] && s.x[3] == b.x[3] &&
                  rest_unchanged(&s, &b) && ctx.info12_calls == 1u,
              "Info12 returns the AS bounds base and ignores x2/x3");
        check(bb > 0xffffffffull, "Info12 base is above 32 bits");
        init_state(&s);
        s.x[0] = 0xdeadbeefdeadbeefull;
        s.x[1] = 13u;
        s.x[2] = 0xeeeeeeeeeeeeeeeeull;
        s.x[3] = 0xffffffffffffffffull;
        b = s;
        run(g3_start_hle_svc, &ctx, 0x29u, &s, &rt, &req);
        check(rt.fault == AOT_FAULT_NONE && s.x[0] == 0u && s.x[1] == bn &&
                  s.x[2] == b.x[2] && s.x[3] == b.x[3] &&
                  rest_unchanged(&s, &b) && ctx.info13_calls == 1u,
              "Info13 returns the AS bounds size and ignores x2/x3");
        check(bn > 0xffffffffull, "Info13 size is above 32 bits");
    }

    /* Info 14/15: AS-owned immutable global stack arena, distinct from alias
     * and heap; x0 never dereferenced, x2/x3 ignored. */
    init_state(&s);
    s.x[0] = 0xdeadbeefdeadbeefull;
    s.x[1] = 14u;
    s.x[2] = 0x1234123412341234ull;
    s.x[3] = 0x5678567856785678ull;
    b = s;
    run(g3_start_hle_svc, &ctx, 0x29u, &s, &rt, &req);
    check(rt.fault == AOT_FAULT_NONE && s.x[0] == 0u && s.x[1] == SBASE &&
              s.x[2] == b.x[2] && s.x[3] == b.x[3] &&
              rest_unchanged(&s, &b) && ctx.info14_calls == 1u,
          "Info14 returns the AS stack arena base, not a constant");
    check(SBASE != ABASE && SBASE != HBASE, "stack arena is distinct");
    init_state(&s);
    s.x[0] = 0xdeadbeefdeadbeefull;
    s.x[1] = 15u;
    s.x[2] = 0x9abc9abc9abc9abcull;
    s.x[3] = 0xdef0def0def0def0ull;
    b = s;
    run(g3_start_hle_svc, &ctx, 0x29u, &s, &rt, &req);
    check(rt.fault == AOT_FAULT_NONE && s.x[0] == 0u && s.x[1] == SSIZE &&
              s.x[2] == b.x[2] && s.x[3] == b.x[3] &&
              rest_unchanged(&s, &b) && ctx.info15_calls == 1u,
          "Info15 returns the AS stack arena size, not a constant");

    /* Unknown query id: typed, same non-negative status convention. */
    init_state(&s);
    s.x[1] = 99u;
    b = s;
    run(g3_start_hle_svc, &ctx, 0x29u, &s, &rt, &req);
    check(rt.fault == AOT_FAULT_BAD_HLE && rt.fault_status == 99 &&
              memcmp(&s, &b, sizeof s) == 0,
          "unknown Info id stays a typed non-negative status");

    /* Invalid SVC1: Mac 0xd401, other inputs preserved, no fault. */
    init_state(&s);
    s.x[1] = 0x100000ull;
    s.x[2] = 0x6666666666666666ull;
    s.x[3] = 0x7777777777777777ull;
    b = s;
    run(g3_start_hle_svc1, &ctx, 0x01u, &s, &rt, &req);
    check(rt.fault == AOT_FAULT_NONE &&
              s.x[0] == G3_START_HLE_INVALID_HEAP_SIZE &&
              s.x[1] == b.x[1] && s.x[2] == b.x[2] && s.x[3] == b.x[3] &&
              rest_unchanged(&s, &b) && ctx.svc1_invalid == 1u,
          "invalid SetHeapSize returns 0xd401 and preserves inputs");
    check(aot_as_heap_info(as, &heap) == AOT_MEM_OK && heap.size == 0u,
          "invalid SetHeapSize changed nothing");

    /* SVC1 success: 2 MiB commit, register-only result, host COMMIT/RW. */
    init_state(&s);
    s.x[1] = 0x200000ull;
    b = s;
    run(g3_start_hle_svc1, &ctx, 0x01u, &s, &rt, &req);
    check(rt.fault == AOT_FAULT_NONE && s.x[0] == 0u && s.x[1] == HBASE &&
              rest_unchanged(&s, &b) && ctx.svc1_calls == 2u,
          "SetHeapSize success writes r0=0/r1=base only");
    os = os_page(as, HBASE);
    check(os.state == HOST_VM_STATE_COMMIT &&
              os.protection == (HOST_VM_PROT_READ | HOST_VM_PROT_WRITE),
          "SetHeapSize commits the real host page RW");
    if (aot_as_write(as, HBASE + 0x1000ull, pat, 8u) != AOT_MEM_OK) {
        printf("FATAL: write 2M page\n");
        return 1;
    }

    /* Grow/shrink/regrow through SVC1: retained bytes preserved. */
    init_state(&s);
    s.x[1] = 0x400000ull;
    run(g3_start_hle_svc1, &ctx, 0x01u, &s, &rt, &req);
    check(rt.fault == AOT_FAULT_NONE && aot_as_read(as, HBASE + 0x1000ull,
                                                    back, 8u) == AOT_MEM_OK &&
              memcmp(back, pat, 8u) == 0,
          "grow through SVC1 preserves retained bytes");
    if (aot_as_write(as, HBASE + 0x300000ull, pat, 8u) != AOT_MEM_OK) {
        printf("FATAL: write 3M page\n");
        return 1;
    }
    init_state(&s);
    s.x[1] = 0x200000ull;
    run(g3_start_hle_svc1, &ctx, 0x01u, &s, &rt, &req);
    os = os_page(as, HBASE + 0x200000ull);
    check(rt.fault == AOT_FAULT_NONE &&
              os.state == HOST_VM_STATE_COMMIT && os.protection == 0u &&
              aot_as_write(as, HBASE + 0x200000ull, pat, 8u) ==
                  AOT_MEM_ERR_PERM,
          "shrink through SVC1 keeps host COMMIT/NONE and denies access");
    init_state(&s);
    s.x[1] = 0x400000ull;
    run(g3_start_hle_svc1, &ctx, 0x01u, &s, &rt, &req);
    check(rt.fault == AOT_FAULT_NONE &&
              aot_as_read(as, HBASE + 0x300000ull, back, 8u) == AOT_MEM_OK &&
              memcmp(back, pat, 8u) == 0,
          "regrow through SVC1 preserves the shrunk block's bytes");

    /* Align succeeds; above the checked budget is invalid, not a host fault. */
    init_state(&s);
    s.x[1] = HLIMIT;
    run(g3_start_hle_svc1, &ctx, 0x01u, &s, &rt, &req);
    check(rt.fault == AOT_FAULT_NONE && s.x[0] == 0u && s.x[1] == HBASE,
          "SetHeapSize accepts the checked commit limit");
    init_state(&s);
    s.x[1] = HMAX;
    b = s;
    run(g3_start_hle_svc1, &ctx, 0x01u, &s, &rt, &req);
    check(rt.fault == AOT_FAULT_NONE &&
              s.x[0] == G3_START_HLE_INVALID_HEAP_SIZE &&
              s.x[1] == b.x[1],
          "SetHeapSize above commit_limit is 0xd401, not a host fault");
    v = 0u;
    check(aot_as_read(as, HBASE, &v, 8u) == AOT_MEM_OK && v == 0u,
          "grew heap bytes remain readable/zero where never written");

    /* Host fault: no address space -> typed BAD_HLE, no guest write. */
    g3_start_hle_init(&ctx, provider_zero, NULL);
    init_state(&s);
    s.x[1] = 0x200000ull;
    b = s;
    run(g3_start_hle_svc1, &ctx, 0x01u, &s, &rt, &req);
    check(rt.fault == AOT_FAULT_BAD_HLE &&
              rt.fault_status == G3_START_HLE_FAULT_SVC1_HOST &&
              memcmp(&s, &b, sizeof s) == 0,
          "host SetHeapSize failure is typed BAD_HLE with no register write");

    aot_as_destroy(as);
    aot_mem_domain_destroy(dom);
    if (g_fail) return 2;
    printf("aot_g3_start_hle_heap: all heap HLE rows passed\n");
    return 0;
}
