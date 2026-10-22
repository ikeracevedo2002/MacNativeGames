/* Whole data-AS QueryMemory: independent declared interval expectations.
 * Compile the same probe with MN_AOT_DOMAIN_MUT_* to reject wrong backends.
 * Exit 1 = fixture failure; 2 = semantic mismatch; never accept a crash. */
#include "aot_as.h"
#include <stdio.h>
#include <string.h>

#define T 0x1001000000ull
#define D 0x1002000000ull
#define S 0x2800000000ull
#define H 0x4000000000ull
#define A 0x5000000000ull
#define HM 0x800000ull
#define B 0x2400000000ull
#define MAX AOT_AS_MAX_ADDR
#define MIN AOT_AS_MIN_ADDR
#define E(b,e,st,at,p) { (b), (uint64_t)(e)-(uint64_t)(b), (p), (st), (at) }
static int failed;

static int same(const AotAsQuery *a, const AotAsQuery *b) {
    return a->base == b->base && a->size == b->size && a->perm == b->perm &&
           a->state == b->state && a->attr == b->attr;
}
static void check(int yes, const char *msg) {
    if (!yes) { printf("FAIL: %s\n", msg); failed = 1; }
}
static void at(AotAddressSpace *as, uint64_t addr, const AotAsQuery *expected) {
    AotAsQuery q = {0};
    const char *label = expected->base == 0u ? "domain low interval" :
                        expected->base == MAX ? "domain upper interval" :
                        "domain interval";
    if (!aot_as_query_domain(as, addr, &q) || !same(&q, expected)) {
        printf("FAIL: %s\n", label);
        printf("  at %llx: base=%llx size=%llx state=%u attr=%u perm=%u\n",
               (unsigned long long)addr, (unsigned long long)q.base,
               (unsigned long long)q.size, q.state, q.attr, q.perm);
        failed = 1;
    }
}
/* A literal ordered partition, not inferred from observed query results.
 * Verify both a bounded walk and every interval's first/interior/last byte. */
static void walk(AotAddressSpace *as, const AotAsQuery *table, size_t n) {
    uint64_t cursor = 0u;
    for (size_t i = 0u; i < n; i++) {
        const AotAsQuery *e = &table[i];
        AotAsQuery q = {0};
        check(e->size != 0u && e->base == cursor, "declared partition contiguous");
        at(as, e->base, e);
        at(as, e->base + e->size / 2u, e);
        at(as, e->base + e->size - 1u, e);
        if (!aot_as_query_domain(as, cursor, &q)) {
            check(0, "walk query failed"); return;
        }
        check(same(&q, e), "walk exact record order and fields");
        cursor = q.base + q.size; /* final upper record wraps deliberately */
    }
    check(cursor == 0u, "walk ends exactly at unsigned wrap to zero");
}
static void geometry1(AotAddressSpace *as, uint64_t size) {
    AotAsQuery table[] = {
        E(0ull, MIN, 0u, 0u, 0u), E(MIN, T, 0u, 0u, 0u),
        E(T, T+0x2000ull, 3u, 0u, 5u),
        E(T+0x2000ull, D, 0u, 0u, 0u),
        E(D, D+0x1000ull, 4u, 0u, 3u),
        E(D+0x1000ull, D+0x2000ull, 4u, 16u, 3u),
        E(D+0x2000ull, S, 0u, 0u, 0u),
        E(S, S+0x10000ull, 0u, 0u, 0u),
        E(S+0x10000ull, H, 0u, 0u, 0u),
        E(H, H+size, 5u, 0u, 3u),
        E(H+size, H+HM, 0u, 0u, 0u),
        E(H+HM, A, 0u, 0u, 0u),
        E(A, A+0x8000ull, 0u, 0u, 0u),
        E(A+0x8000ull, MAX, 0u, 0u, 0u),
        E(MAX, 0ull, 16u, 0u, 0u)
    };
    /* Omit the empty RW prefix when logical size is zero. */
    if (size == 0u) {
        memmove(&table[9], &table[10], 5u * sizeof table[0]);
        walk(as, table, 14u);
    } else walk(as, table, 15u);
    {
        const AotAsQuery low = E(0ull, MIN, 0u, 0u, 0u);
        const AotAsQuery upper = E(MAX, 0ull, 16u, 0u, 0u);
        const AotAsQuery control_gap = E(A+0x8000ull, MAX, 0u, 0u, 0u);
        AotAsQuery q;
        at(as, 0u, &low); at(as, MIN-1u, &low);
        at(as, MAX-1u, &control_gap); at(as, MAX, &upper);
        at(as, UINT64_MAX, &upper);
        /* D015 control namespace is NOT memory or a new physical region. */
        at(as, 0x7f00000000ull, &control_gap);
        check(!aot_as_query(as, 0x7f00000000ull, &q), "control PC unmapped for data");
        check(!aot_as_query(as, MIN, &q), "legacy query still rejects gaps");
        check(aot_as_query(as, T, &q) && q.state == 3u && q.perm == 5u,
              "legacy query still reports mapped RX");
    }
}
static int rejected_unchanged(AotAddressSpace *as) {
    AotAsQuery q;
    unsigned char before[sizeof q];
    memset(&q, 0xa5, sizeof q); memcpy(before, &q, sizeof q);
    return !aot_as_query_domain(as, 0u, &q) && !memcmp(before, &q, sizeof q);
}
int main(void) {
    AotMemDomain *dom = aot_mem_domain_create();
    AotAddressSpace *as, *as2;
    uint64_t base;
    const AotAsQuery second[] = {
        E(0ull, MIN, 0u, 0u, 0u), E(MIN, B, 0u, 0u, 0u),
        E(B, B+0x3000ull, 11u, 0u, 3u),
        E(B+0x3000ull, MAX, 0u, 0u, 0u), E(MAX, 0ull, 16u, 0u, 0u)
    };
    if (!dom) { puts("FATAL: domain"); return 1; }
    as = aot_as_create(dom); as2 = aot_as_create(dom);
    if (!as || !as2) { puts("FATAL: spaces"); return 1; }
    check(rejected_unchanged(as), "unsealed query leaves output untouched");
    if (aot_as_add_region(as, T, 0x2000u, AOT_AS_PERM_RX, 3u, NULL) ||
        aot_as_add_region(as, D, 0x2000u, AOT_AS_PERM_RW, 4u, NULL) ||
        aot_as_add_heap_window(as, H, HM, HM) ||
        aot_as_add_reserved_window(as, S, 0x10000u, AOT_AS_RESERVED_ROLE_STACK) ||
        aot_as_add_reserved_window(as, A, 0x8000u, AOT_AS_RESERVED_ROLE_ALIAS) ||
        aot_as_seal(as) || aot_as_lock(as, D+0x1000u, 0x1000u) ||
        aot_as_add_region(as2, B, 0x3000u, AOT_AS_PERM_RW, 11u, NULL) ||
        aot_as_seal(as2)) { puts("FATAL: geometry setup"); return 1; }
    geometry1(as, 0u);
    if (aot_as_set_heap_size(as, 0x400000u, &base)) { puts("FATAL: grow"); return 1; }
    geometry1(as, 0x400000u);
    if (aot_as_set_heap_size(as, 0x200000u, &base)) { puts("FATAL: shrink"); return 1; }
    geometry1(as, 0x200000u);
    walk(as2, second, sizeof second / sizeof second[0]);
    check(rejected_unchanged(NULL), "null AS leaves output untouched");
    check(!aot_as_query_domain(as, 0u, NULL), "null output rejected");
    aot_as_poison(as2);
    check(rejected_unchanged(as2), "poisoned AS leaves output untouched");
    aot_as_destroy(as2); aot_as_destroy(as); aot_mem_domain_destroy(dom);
    if (failed) return 2;
    puts("aot_as_query_domain: all exact partitions and boundaries passed");
    return 0;
}
