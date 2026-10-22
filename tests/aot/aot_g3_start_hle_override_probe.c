/* Game-data-free G3 rows for the MAC HOST OVERRIDES reached from
 * nn::init::Start (games/totk/runtime/services.c:168-177).
 *
 * Mac substitutes a tiny host function for exactly these names and nothing
 * else. This probe drives the name -> handler table the same way a Start-prefix
 * registration driver would (lookup BY NAME, then call that entry point with a
 * fabricated HOSTCALL request), so it needs neither the link configuration nor
 * game data and stays hermetic.
 *
 * Contract pinned per Mac body:
 *   - a void override (_ZN2nn2oe10InitializeEv, _ZN2nn3aoc10InitializeEv,
 *     _ZN2nn3err26InitializeContextWriterApiEv, _ZN2nn4pctl10InitializeEv,
 *     _ZN2nn4diag34InitializeApplicationAbortObserverEv) does not fault and
 *     leaves x0..x30, sp, nzcv, fpcr, fpsr, every v register and every guest
 *     byte it could reach unchanged: the Mac substitute only prints;
 *   - CountAddOnContent returns 0 in x0 and changes nothing else;
 *   - ListAddOnContent returns 0 in x0 for a non-negative (offset,count) and
 *     does not dereference the out pointer; a negative offset or count is the
 *     Mac runtime_fail, modelled as a typed BAD_HLE with
 *     G3_START_HLE_FAULT_AOC_RANGE and NO guest write at all;
 *   - the lookup refuses every name the table does not know (including the
 *     deliberately not-modelled _ZN2nn2fs24InitializeForApplicationEv), so a
 *     registration driver can never install a fallback handler;
 *   - per-name counters move exactly once per invocation and only for their own
 *     name; a wrong request shape is typed and counted separately.
 *
 * The wrong-implementation controls are separate executables built from the
 * same shipping sources with MN_G3_HLE_MUT_OVERRIDE_X0 /
 * MN_G3_HLE_MUT_OVERRIDE_WRITE / MN_G3_HLE_MUT_OVERRIDE_COUNT
 * (see tools/aot/g3_mutant_test.py); this probe
 * has to stay green for their rejections to mean anything.
 *
 * Exit: 0 all rows passed, 1 infrastructure, 2 semantic failure.
 */
#include "aot_as.h"
#include "g3_start_hle.h"

#include <stdio.h>
#include <string.h>

/* Guest RW page window the overrides must never write (they only print). */
#define MBASE 0x7000000000ull
#define MSIZE 0x2000ull
#define MSTATE 0xbu

/* An OPAQUE thunk index: the handler must not require a title-specific value,
 * so the rows use ids that are not any real link-config ordinal. */
#define REQ_ID_BASE 900u

#define NAME_OE "_ZN2nn2oe10InitializeEv"
#define NAME_AOC_INIT "_ZN2nn3aoc10InitializeEv"
#define NAME_AOC_COUNT "_ZN2nn3aoc17CountAddOnContentEv"
#define NAME_AOC_LIST "_ZN2nn3aoc16ListAddOnContentEPiii"
#define NAME_ERR "_ZN2nn3err26InitializeContextWriterApiEv"
#define NAME_PCTL "_ZN2nn4pctl10InitializeEv"
#define NAME_ABORT "_ZN2nn4diag34InitializeApplicationAbortObserverEv"
#define NAME_BOOST "_ZN2nn2oe15SetCpuBoostModeENS0_12CpuBoostModeE"
#define NAME_FS "_ZN2nn2fs24InitializeForApplicationEv"

static int g_fail;

static void check(int cond, const char *msg)
{
    if (!cond) {
        printf("FAIL: %s\n", msg);
        g_fail++;
    }
}

static void init_state(AotGuestState *s)
{
    unsigned i;
    memset(s, 0, sizeof *s);
    for (i = 0u; i < 31u; i++) s->x[i] = 0x1111000000000000ull + i;
    s->sp = 0x200003fe10ull;
    s->pc = 0x10205c2fb0ull;
    s->nzcv = 0x80000000ull;
    s->fpcr = 0x12345678ull;
    s->fpsr = 0x87654321ull;
    s->tpidr = 0x3000000000ull;
    s->tpidrro = 0x3000002000ull;
    for (i = 0u; i < 32u; i++) {
        s->v[i][0] = 0x3333000000000000ull + i;
        s->v[i][1] = 0x4444000000000000ull + i;
    }
}

/* Invoke one table entry exactly like the Start-prefix registration would:
 * a HOSTCALL request whose id is the (opaque here) thunk index. */
static void run_override(const G3StartHleOverride *entry, G3StartHle *ctx,
                         AotGuestState *s, AotRuntime *rt, AotHleRequest *req,
                         unsigned id_value)
{
    memset(rt, 0, sizeof *rt);
    req->kind = AOT_HLE_HOSTCALL;
    req->id = (uint32_t)id_value;
    req->site_pc = 0x10205c2fb0ull;
    req->resume_pc = 0x10205c2fb8ull;
    entry->handler(rt, s, req, ctx);
}

static AotAddressSpace *make_space(AotMemDomain *dom)
{
    AotAddressSpace *as = aot_as_create(dom);
    if (as == 0) return 0;
    if (aot_as_add_region(as, MBASE, MSIZE, AOT_AS_PERM_RW, MSTATE, 0) !=
        AOT_MEM_OK)
        return 0;
    if (aot_as_seal(as) != AOT_MEM_OK) return 0;
    return as;
}

static int fill_pattern(AotAddressSpace *as, uint8_t *pattern)
{
    size_t i;
    for (i = 0u; i < (size_t)MSIZE; i++)
        pattern[i] = (uint8_t)(0x5au + (uint8_t)(i * 7u));
    return aot_as_write(as, MBASE, pattern, MSIZE) == AOT_MEM_OK;
}

static int bytes_unchanged(AotAddressSpace *as, const uint8_t *pattern)
{
    uint8_t buf[MSIZE];
    if (aot_as_read(as, MBASE, buf, MSIZE) != AOT_MEM_OK) return 0;
    return memcmp(buf, pattern, MSIZE) == 0;
}

/* ---- rows ------------------------------------------------------------- */

/* Mac services.c:168/169/174/176/177: void, prints only. */
static void row_void(G3StartHle *ctx, AotAddressSpace *as,
                     const uint8_t *pattern, const char *name,
                     const char *label)
{
    const G3StartHleOverride *entry = g3_start_hle_override_lookup(name);
    AotGuestState s, before;
    AotRuntime rt;
    AotHleRequest req;
    char msg[192];
    unsigned calls;

    snprintf(msg, sizeof msg, "%s is in the override table", label);
    check(entry != 0, msg);
    if (entry == 0) return;
    calls = g3_start_hle_override_calls(ctx, entry);
    init_state(&s);
    s.x[0] = MBASE;   /* a mapped guest pointer the substitute must not touch */
    before = s;
    run_override(entry, ctx, &s, &rt, &req, REQ_ID_BASE + (unsigned)entry->id);

    snprintf(msg, sizeof msg, "%s does not fault", label);
    check(rt.fault == AOT_FAULT_NONE, msg);
    snprintf(msg, sizeof msg,
             "%s leaves every guest register, flag and byte unchanged", label);
    check(memcmp(&s, &before, sizeof s) == 0, msg);
    snprintf(msg, sizeof msg, "%s writes no guest byte", label);
    check(bytes_unchanged(as, pattern), msg);
    snprintf(msg, sizeof msg, "%s increments its own counter once", label);
    check(g3_start_hle_override_calls(ctx, entry) == calls + 1u, msg);
}

/* Mac services.c:170: `static int host_aoc_count(void){return 0;}`. */
static void row_count(G3StartHle *ctx, AotAddressSpace *as,
                      const uint8_t *pattern)
{
    const G3StartHleOverride *entry = g3_start_hle_override_lookup(NAME_AOC_COUNT);
    AotGuestState s, before, want;
    AotRuntime rt;
    AotHleRequest req;
    unsigned calls;

    check(entry != 0, "CountAddOnContent is in the override table");
    if (entry == 0) return;
    calls = g3_start_hle_override_calls(ctx, entry);
    init_state(&s);
    s.x[0] = MBASE;   /* return register; must become 0, nothing else */
    before = s;
    run_override(entry, ctx, &s, &rt, &req,
                 REQ_ID_BASE + (unsigned)entry->id);

    check(rt.fault == AOT_FAULT_NONE, "CountAddOnContent does not fault");
    want = before;
    want.x[0] = 0u;
    check(memcmp(&s, &want, sizeof s) == 0,
          "CountAddOnContent returns 0 in x0 and changes nothing else");
    check(bytes_unchanged(as, pattern), "CountAddOnContent writes no guest byte");
    check(g3_start_hle_override_calls(ctx, entry) == calls + 1u,
          "CountAddOnContent increments its own counter once");
}

/* Mac services.c:171: `(void)out; ... return 0;` for a non-negative range.
 * The Mac arguments are C ints, so ONLY the low 32 bits decide the sign; the
 * raw x1/x2 are passed through unchanged so the high-half/truncation rows are
 * pinned too. The out pointer is never dereferenced (the Mac body casts it to
 * void), so NULL and an unmapped VA must both succeed. */
static void row_list_ok(G3StartHle *ctx, AotAddressSpace *as,
                        const uint8_t *pattern, uint64_t out,
                        uint64_t raw_offset, uint64_t raw_count,
                        const char *label)
{
    const G3StartHleOverride *entry = g3_start_hle_override_lookup(NAME_AOC_LIST);
    AotGuestState s, before, want;
    AotRuntime rt;
    AotHleRequest req;
    char msg[192];

    snprintf(msg, sizeof msg, "%s is in the override table", label);
    check(entry != 0, msg);
    if (entry == 0) return;
    init_state(&s);
    s.x[0] = out;   /* out pointer: never dereferenced */
    s.x[1] = raw_offset;
    s.x[2] = raw_count;
    before = s;
    run_override(entry, ctx, &s, &rt, &req,
                 REQ_ID_BASE + (unsigned)entry->id);

    snprintf(msg, sizeof msg, "%s does not fault", label);
    check(rt.fault == AOT_FAULT_NONE, msg);
    want = before;
    want.x[0] = 0u;
    snprintf(msg, sizeof msg, "%s returns 0 in x0 and changes nothing else",
             label);
    check(memcmp(&s, &want, sizeof s) == 0, msg);
    snprintf(msg, sizeof msg, "%s writes no guest byte", label);
    check(bytes_unchanged(as, pattern), msg);
}

/* Mac services.c:172 runtime_fail: typed here, and NOTHING is written. The
 * typed fault keeps the Mac call shape observable: fault_src is the guest call
 * site and fault_target the captured resume PC. */
static void row_list_fault(G3StartHle *ctx, AotAddressSpace *as,
                           const uint8_t *pattern, uint64_t raw_offset,
                           uint64_t raw_count, const char *what)
{
    const G3StartHleOverride *entry = g3_start_hle_override_lookup(NAME_AOC_LIST);
    AotGuestState s, before;
    AotRuntime rt;
    AotHleRequest req;
    char msg[192];

    snprintf(msg, sizeof msg, "ListAddOnContent rejects %s", what);
    if (entry == 0) {
        check(0, msg);
        return;
    }
    init_state(&s);
    s.x[0] = MBASE;
    s.x[1] = raw_offset;
    s.x[2] = raw_count;
    before = s;
    run_override(entry, ctx, &s, &rt, &req,
                 REQ_ID_BASE + (unsigned)entry->id);
    check(rt.fault == AOT_FAULT_BAD_HLE &&
              rt.fault_status == G3_START_HLE_FAULT_AOC_RANGE &&
              rt.fault_src == req.site_pc &&
              rt.fault_target == req.resume_pc &&
              memcmp(&s, &before, sizeof s) == 0 &&
              bytes_unchanged(as, pattern),
          msg);
    snprintf(msg, sizeof msg,
             "ListAddOnContent rejects %s at its call site", what);
    check(rt.fault == AOT_FAULT_BAD_HLE && rt.fault_src == req.site_pc &&
              rt.fault_target == req.resume_pc,
          msg);
}

/* Mac services.c:184: `static void cpu_boost(int mode)` -- VOID, prints only,
 * no actual frequency change. A valid mode writes NOTHING at all (all guest
 * registers/flags/bytes preserved); an unknown mode is the Mac runtime_fail,
 * modelled as a typed BAD_HLE with G3_START_HLE_FAULT_CPU_BOOST and no write. */
static void row_boost_ok(G3StartHle *ctx, AotAddressSpace *as,
                         const uint8_t *pattern, uint64_t raw_mode,
                         const char *what)
{
    const G3StartHleOverride *entry = g3_start_hle_override_lookup(NAME_BOOST);
    AotGuestState s, before;
    AotRuntime rt;
    AotHleRequest req;
    char msg[192];
    unsigned calls;

    snprintf(msg, sizeof msg, "CPU boost entry for %s is in the override table",
             what);
    check(entry != 0, msg);
    if (entry == 0) return;
    calls = g3_start_hle_override_calls(ctx, entry);
    init_state(&s);
    s.x[0] = raw_mode;   /* C int mode: only the low 32 bits are the argument */
    before = s;
    run_override(entry, ctx, &s, &rt, &req,
                 REQ_ID_BASE + (unsigned)entry->id);
    snprintf(msg, sizeof msg, "CPU boost accepts %s and writes nothing", what);
    check(rt.fault == AOT_FAULT_NONE && memcmp(&s, &before, sizeof s) == 0 &&
              bytes_unchanged(as, pattern),
          msg);
    snprintf(msg, sizeof msg, "CPU boost %s increments its own counter once",
             what);
    check(g3_start_hle_override_calls(ctx, entry) == calls + 1u, msg);
}

static void row_boost_fault(G3StartHle *ctx, AotAddressSpace *as,
                            const uint8_t *pattern, uint64_t raw_mode,
                            const char *what)
{
    const G3StartHleOverride *entry = g3_start_hle_override_lookup(NAME_BOOST);
    AotGuestState s, before;
    AotRuntime rt;
    AotHleRequest req;
    char msg[192];

    snprintf(msg, sizeof msg, "CPU boost rejects %s", what);
    if (entry == 0) {
        check(0, msg);
        return;
    }
    init_state(&s);
    s.x[0] = raw_mode;
    before = s;
    run_override(entry, ctx, &s, &rt, &req,
                 REQ_ID_BASE + (unsigned)entry->id);
    check(rt.fault == AOT_FAULT_BAD_HLE &&
              rt.fault_status == G3_START_HLE_FAULT_CPU_BOOST &&
              rt.fault_src == req.site_pc &&
              rt.fault_target == req.resume_pc &&
              memcmp(&s, &before, sizeof s) == 0 &&
              bytes_unchanged(as, pattern),
          msg);
}

int main(void)
{
    static const char *const names[G3_START_HLE_OVERRIDE_ID_COUNT] = {
        NAME_OE, NAME_AOC_INIT, NAME_AOC_COUNT, NAME_AOC_LIST,
        NAME_ERR, NAME_PCTL, NAME_ABORT, NAME_BOOST
    };
    static const char *const void_names[5] = {
        NAME_OE, NAME_AOC_INIT, NAME_ERR, NAME_PCTL, NAME_ABORT
    };
    static const char *const void_labels[5] = {
        "oe Initialize",
        "aoc Initialize",
        "err InitializeContextWriterApi",
        "pctl Initialize",
        "diag InitializeApplicationAbortObserver"
    };
    AotMemDomain *dom = aot_mem_domain_create();
    AotAddressSpace *as;
    G3StartHle ctx;
    AotGuestState s, before;
    AotRuntime rt;
    AotHleRequest req;
    uint8_t pattern[MSIZE];
    unsigned i;

    if (dom == 0) {
        printf("FATAL: memory domain\n");
        return 1;
    }
    as = make_space(dom);
    if (as == 0) {
        printf("FATAL: address space fixture\n");
        aot_mem_domain_destroy(dom);
        return 1;
    }
    if (!fill_pattern(as, pattern)) {
        printf("FATAL: guest pattern\n");
        return 1;
    }
    g3_start_hle_init(&ctx, 0, 0);
    g3_start_hle_set_address_space(&ctx, as);

    /* ---- name table: exactly the eight Mac bodies, reachable by name ---- */
    check(g3_start_hle_override_table_count() ==
              (unsigned)G3_START_HLE_OVERRIDE_ID_COUNT,
          "the override table enumerates exactly eight Mac names");
    for (i = 0u; i < (unsigned)G3_START_HLE_OVERRIDE_ID_COUNT; i++) {
        const G3StartHleOverride *at = g3_start_hle_override_table_at(i);
        const G3StartHleOverride *by_name = g3_start_hle_override_lookup(names[i]);
        char msg[192];
        snprintf(msg, sizeof msg, "table slot %u is %s", i, names[i]);
        check(at != 0 && strcmp(at->name, names[i]) == 0 && at->id == (int)i,
              msg);
        snprintf(msg, sizeof msg, "%s resolves by name to its own slot",
                 names[i]);
        check(by_name != 0 && by_name == at && by_name->handler != 0, msg);
        snprintf(msg, sizeof msg, "%s starts with a zero counter", names[i]);
        check(g3_start_hle_override_calls(&ctx, by_name) == 0u, msg);
    }
    check(g3_start_hle_override_table_at(
              (unsigned)G3_START_HLE_OVERRIDE_ID_COUNT) == 0,
          "the table refuses an out-of-range index");

    /* ---- lookup refusal: no fallback handler, ever --------------------- */
    check(g3_start_hle_override_lookup(0) == 0, "lookup rejects a NULL name");
    check(g3_start_hle_override_lookup("") == 0, "lookup rejects an empty name");
    check(g3_start_hle_override_lookup("_ZN2nn9NotAService10InitializeEv") == 0,
          "lookup refuses an unknown name");
    check(g3_start_hle_override_lookup("nndiagStartup") == 0,
          "nndiagStartup is not an override-table name");
    /* The nn::diag namespace mangles as `4diag` (services.c:240). The
     * `2diag` spelling is NOT a Mac symbol and must never be accepted. */
    check(g3_start_hle_override_lookup(
              "_ZN2nn2diag34InitializeApplicationAbortObserverEv") == 0,
          "the misspelled 2diag abort-observer name is refused");
    check(g3_start_hle_override_not_modelled(
              "_ZN2nn2diag34InitializeApplicationAbortObserverEv") == 0,
          "the misspelled 2diag name is not on the not-modelled list");
    /* services.c:175 host_fs_init calls runtime_fs_init(): real behaviour, so
     * it is not modelled here and can never be registered. */
    check(g3_start_hle_override_lookup(NAME_FS) == 0,
          "the not-modelled fs InitializeForApplication is refused");
    check(g3_start_hle_override_not_modelled(NAME_FS) == 1,
          "fs InitializeForApplication is on the not-modelled list");
    check(g3_start_hle_override_not_modelled(NAME_OE) == 0,
          "a modelled name is not on the not-modelled list");
    check(g3_start_hle_override_not_modelled(0) == 0,
          "the not-modelled check rejects a NULL name");

    /* ---- void overrides: no fault, no register/flag/byte write --------- */
    for (i = 0u; i < 5u; i++)
        row_void(&ctx, as, pattern, void_names[i], void_labels[i]);

    /* ---- CountAddOnContent: x0 = 0, nothing else ----------------------- */
    row_count(&ctx, as, pattern);

    /* ---- ListAddOnContent: 0 for non-negative, typed fault otherwise --- */
    row_list_ok(&ctx, as, pattern, MBASE, 0u, 0u, "ListAddOnContent(0,0)");
    row_list_ok(&ctx, as, pattern, MBASE, 0u, 1u, "ListAddOnContent(0,1)");
    row_list_ok(&ctx, as, pattern, MBASE, 4u, 2u, "ListAddOnContent(4,2)");
    /* The out pointer is cast to void on Mac, so a NULL and an UNMAPPED guest
     * VA must both be accepted: nothing may be dereferenced. */
    row_list_ok(&ctx, as, pattern, 0u, 0u, 0u,
                "ListAddOnContent(0,0) with a NULL out pointer");
    row_list_ok(&ctx, as, pattern, 0xdeadbeef000ull, 2u, 3u,
                "ListAddOnContent(2,3) with an unmapped out pointer");
    /* Only the LOW 32 bits are the Mac C ints: a non-negative low half must
     * succeed even when the upper half of x1/x2 is set. */
    row_list_ok(&ctx, as, pattern, MBASE, 0xffffffff00000004ull,
                0x8000000000000002ull,
                "ListAddOnContent(low32 4, low32 2)");
    row_list_ok(&ctx, as, pattern, MBASE, 0x7fffffffull, 0x7fffffffull,
                "ListAddOnContent(INT_MAX,INT_MAX)");
    row_list_fault(&ctx, as, pattern, 0xffffffffull, 0u,
                   "a negative offset");
    row_list_fault(&ctx, as, pattern, 0u, 0xffffffffull,
                   "a negative count");
    row_list_fault(&ctx, as, pattern, 0x80000000ull, 0xffffffffull,
                   "a negative offset and count");
    row_list_fault(&ctx, as, pattern, 0xffffffff80000000ull, 1u,
                   "a negative low-32 offset with high bits set");

    /* ---- SetCpuBoostMode: void for 0/1/2, typed fault otherwise -------- */
    row_boost_ok(&ctx, as, pattern, 0u, "mode 0");
    row_boost_ok(&ctx, as, pattern, 1u, "mode 1");
    row_boost_ok(&ctx, as, pattern, 2u, "mode 2");
    /* The Mac argument is a C int: the high half of x0 is not part of it. */
    row_boost_ok(&ctx, as, pattern, 0xfeedface00000001ull,
                 "low-32 mode 1 with high bits set");
    row_boost_fault(&ctx, as, pattern, 0xffffffffull, "mode -1");
    row_boost_fault(&ctx, as, pattern, 3u, "mode 3");
    row_boost_fault(&ctx, as, pattern, 0x80000000ull, "mode INT_MIN");
    row_boost_fault(&ctx, as, pattern, 0x7fffffffull, "mode INT_MAX");
    row_boost_fault(&ctx, as, pattern, 0xfffffffeull, "mode -2");

    /* ---- wrong request shape: typed host fault, per-name counter intact - */
    {
        const G3StartHleOverride *entry = g3_start_hle_override_lookup(NAME_OE);
        unsigned calls = g3_start_hle_override_calls(&ctx, entry);
        check(entry != 0, "oe Initialize is in the override table");
        if (entry != 0) {
            init_state(&s);
            before = s;
            memset(&rt, 0, sizeof rt);
            req.kind = AOT_HLE_SVC;   /* NOT the host-call thunk */
            req.id = 0x29u;
            req.site_pc = 0x10205c2fb0ull;
            req.resume_pc = 0x10205c2fb8ull;
            entry->handler(&rt, &s, &req, &ctx);
            check(rt.fault == AOT_FAULT_BAD_HLE &&
                      rt.fault_status == G3_START_HLE_FAULT_OVERRIDE &&
                      memcmp(&s, &before, sizeof s) == 0,
                  "a non-HOSTCALL request on an override is typed and writes "
                  "nothing");
            check(g3_start_hle_override_calls(&ctx, entry) == calls,
                  "a wrong request shape is not counted as an override call");
            check(ctx.override_host_failures == 1u,
                  "a wrong request shape is counted as a host failure");
        }
    }

    /* ---- counters: exactly the rows above, per name -------------------- */
    check(g3_start_hle_override_calls(&ctx,
                                      g3_start_hle_override_lookup(NAME_OE)) == 1u,
          "oe Initialize counter matches its rows");
    check(g3_start_hle_override_calls(&ctx,
                                      g3_start_hle_override_lookup(
                                          NAME_AOC_INIT)) == 1u,
          "aoc Initialize counter matches its rows");
    check(g3_start_hle_override_calls(&ctx,
                                      g3_start_hle_override_lookup(
                                          NAME_AOC_COUNT)) == 1u,
          "CountAddOnContent counter matches its rows");
    check(g3_start_hle_override_calls(&ctx,
                                      g3_start_hle_override_lookup(
                                          NAME_AOC_LIST)) == 11u,
          "ListAddOnContent counter counts successes and range faults");
    check(g3_start_hle_override_calls(&ctx,
                                      g3_start_hle_override_lookup(NAME_ERR)) == 1u,
          "err InitializeContextWriterApi counter matches its rows");
    check(g3_start_hle_override_calls(&ctx,
                                      g3_start_hle_override_lookup(
                                          NAME_PCTL)) == 1u,
          "pctl Initialize counter matches its rows");
    check(g3_start_hle_override_calls(&ctx,
                                      g3_start_hle_override_lookup(
                                          NAME_ABORT)) == 1u,
          "diag InitializeApplicationAbortObserver counter matches its rows");
    check(ctx.override_range_faults == 4u,
          "the Mac runtime_fail rows are counted as range faults");
    check(g3_start_hle_override_calls(&ctx,
                                      g3_start_hle_override_lookup(
                                          NAME_BOOST)) == 9u,
          "SetCpuBoostMode counter counts void successes and mode faults");
    check(ctx.override_boost_range_faults == 5u,
          "the cpu_boost runtime_fail rows are counted as boost range faults");
    check(ctx.override_host_failures == 1u,
          "only the wrong request shape counts as a host failure");

    /* ---- counter-slot binding is by NAME, not by an arbitrary index ---- */
    {
        G3StartHleOverride foreign;
        foreign.name = "_ZN2nn2oe10InitializeEv";   /* equal text, other slot */
        foreign.handler = 0;
        foreign.id = G3_START_HLE_OVERRIDE_PCTL_INIT;
        check(g3_start_hle_override_calls(&ctx, &foreign) == 0u,
              "a foreign entry does not read another name's counter");
        check(g3_start_hle_override_calls(0,
                                          g3_start_hle_override_lookup(
                                              NAME_OE)) == 0u,
              "a NULL context reads no counter");
        check(g3_start_hle_override_calls(&ctx, 0) == 0u,
              "a NULL entry reads no counter");
    }

    aot_as_destroy(as);
    aot_mem_domain_destroy(dom);
    if (g_fail != 0) {
        printf("FAIL: %d check(s) failed\n", g_fail);
        return 2;
    }
    printf("PASS: g3_start_hle_override\n");
    return 0;
}
