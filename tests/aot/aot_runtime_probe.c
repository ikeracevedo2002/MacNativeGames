/*
 * G2 runtime contract probe.
 *
 * Exercises aot_runtime / aot_mem CONTRACTS against tiny FAKE blocks. These
 * blocks are NOT translator coverage and are NOT counted as translation
 * evidence; they exist only to drive the dispatcher's failure and boundary
 * paths deterministically. No game data, no ARM bytes.
 *
 * The probe is buildable with NDEBUG: it uses CHECK(), not assert().
 */
#include "aot_runtime.h"

#include <stdio.h>
#include <string.h>

static int g_fail = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", msg); g_fail = 1; } \
} while (0)

static AotGuestState g_state;
static int g_probe_hle_calls = 0;

/* ---- fake blocks (test fixtures only) ---- */
static AotExit blk_ret_stop(AotGuestState *s, AotRuntime *rt) {
    (void)s; rt->site_pc = 0x1000; rt->next_pc = 0; return AOT_EXIT_RET;
}
static AotExit blk_b_stop(AotGuestState *s, AotRuntime *rt) {
    (void)s; rt->site_pc = 0x1000; rt->next_pc = 0; return AOT_EXIT_BRANCH;
}
static AotExit blk_br_stop(AotGuestState *s, AotRuntime *rt) {
    (void)s; rt->site_pc = 0x1000; rt->next_pc = 0; return AOT_EXIT_INDIRECT;
}
static AotExit blk_fall_stop(AotGuestState *s, AotRuntime *rt) {
    (void)s; rt->site_pc = 0x1000; rt->next_pc = 0; return AOT_EXIT_FALLTHROUGH;
}
static AotExit blk_loop(AotGuestState *s, AotRuntime *rt) {
    (void)s; rt->site_pc = 0x1000; rt->next_pc = 0x1000; return AOT_EXIT_BRANCH;
}
static AotExit blk_bad_exit(AotGuestState *s, AotRuntime *rt) {
    (void)s; (void)rt; return (AotExit)99;
}
static AotExit blk_svc(AotGuestState *s, AotRuntime *rt) {
    (void)s; rt->site_pc = 0x1000; rt->hle_id = 0x40; return AOT_EXIT_SVC;
}
static AotExit blk_stop(AotGuestState *s, AotRuntime *rt) {
    (void)s; (void)rt; return AOT_EXIT_STOP;
}
static AotExit blk_br_thunk(AotGuestState *s, AotRuntime *rt) {
    (void)s; rt->site_pc = 0x1000; rt->next_pc = 0x2000; return AOT_EXIT_INDIRECT;
}
static AotExit blk_ret_thunk(AotGuestState *s, AotRuntime *rt) {
    (void)s; rt->site_pc = 0x1000; rt->next_pc = 0x2000; return AOT_EXIT_RET;
}
static void hle_count(AotGuestState *s, const AotHleRequest *req, void *u) {
    (void)s; (void)req; (void)u; g_probe_hle_calls++;
}

static AotBlockEntry blocks1[] = { { 0x1000ull, blk_ret_stop } };
static AotCodeRange  range1[]  = { { 0x1000ull, 0x1010ull } };
static AotBlockEntry blocks_svc_ret[] = { { 0x1000ull, blk_svc },
                                          { 0x1004ull, blk_ret_stop } };
static AotImage img_base = {
    AOT_SUBSET_ID, AOT_ABI_VERSION, AOT_STATE_LAYOUT, "sha", 0,
    blocks1, 1, range1, 1, 0, 0, 0
};

/* ---- image validation ---- */
static void test_image_validate(void) {
    AotImage im;
    CHECK(aot_image_validate(NULL) == AOT_FAULT_NO_IMAGE, "null image");
    CHECK(aot_image_validate(&img_base) == AOT_FAULT_NONE, "valid image");

    im = img_base; im.subset_id = "not-the-subset";
    CHECK(aot_image_validate(&im) == AOT_FAULT_BAD_STATE, "bad subset");
    im = img_base; im.abi_version = 999;
    CHECK(aot_image_validate(&im) == AOT_FAULT_BAD_STATE, "bad abi");
    im = img_base; im.state_layout = 999;
    CHECK(aot_image_validate(&im) == AOT_FAULT_BAD_STATE, "bad layout");
    im = img_base; im.blocks = NULL;
    CHECK(aot_image_validate(&im) == AOT_FAULT_BAD_STATE, "null blocks");
    im = img_base; im.ranges = NULL;
    CHECK(aot_image_validate(&im) == AOT_FAULT_BAD_STATE, "null ranges");

    AotCodeRange r = { 0x1008ull, 0x1004ull };
    im = img_base; im.ranges = &r;
    CHECK(aot_image_validate(&im) == AOT_FAULT_BAD_STATE, "range end<=start");
    r.start = 0x1002ull; r.end = 0x1010ull;
    CHECK(aot_image_validate(&im) == AOT_FAULT_BAD_STATE, "range start misaligned");

    AotCodeRange r2[2] = { { 0x1000ull, 0x1010ull }, { 0x1008ull, 0x1020ull } };
    im = img_base; im.ranges = r2; im.range_count = 2;
    CHECK(aot_image_validate(&im) == AOT_FAULT_BAD_STATE, "ranges overlap/unsorted");
    for (size_t i = 0; i < 2; i++) r2[i].start = 0x1000ull + i * 2ull, r2[i].end = 0x1008ull + i * 2ull;
    im = img_base; im.ranges = r2; im.range_count = 2;
    CHECK(aot_image_validate(&im) == AOT_FAULT_BAD_STATE, "range misaligned second");

    AotBlockEntry b2[2] = { { 0x1004ull, blk_ret_stop }, { 0x1000ull, blk_ret_stop } };
    im = img_base; im.blocks = b2; im.block_count = 2;
    CHECK(aot_image_validate(&im) == AOT_FAULT_BAD_STATE, "blocks unsorted");
    b2[0].entry_pc = 0x1002ull; b2[1].entry_pc = 0x1000ull;
    CHECK(aot_image_validate(&im) == AOT_FAULT_BAD_STATE, "block misaligned");
    b2[0].entry_pc = 0x1000ull; b2[1].entry_pc = 0x1004ull;
    im.ranges = range1; im.range_count = 1; im.blocks = b2;
    CHECK(aot_image_validate(&im) == AOT_FAULT_NONE, "valid 2-block image");

    im = img_base; im.blocks = blocks1;
    AotBlockEntry boob = { 0x2000ull, blk_ret_stop };
    im.blocks = &boob;
    CHECK(aot_image_validate(&im) == AOT_FAULT_BAD_STATE, "block outside range");
    AotBlockEntry bnull = { 0x1000ull, NULL };
    im.blocks = &bnull;
    CHECK(aot_image_validate(&im) == AOT_FAULT_BAD_STATE, "null block fn");

    /* thunks */
    im = img_base;
    im.thunk_base = 0x2000ull; im.thunk_count = 1; im.thunk_stride = 8;
    CHECK(aot_image_validate(&im) == AOT_FAULT_BAD_STATE, "bad thunk stride");
    im.thunk_stride = AOT_THUNK_STRIDE; im.thunk_count = 0x100000000ull;
    CHECK(aot_image_validate(&im) == AOT_FAULT_BAD_STATE, "thunk count overflow");
    im.thunk_count = 1ull; im.thunk_base = 0x1008ull;   /* overlaps range1 */
    CHECK(aot_image_validate(&im) == AOT_FAULT_BAD_STATE, "code/thunk overlap");
    im.thunk_base = 0x2000ull;
    im.thunk_stride = AOT_THUNK_STRIDE; im.thunk_count = 4;
    CHECK(aot_image_validate(&im) == AOT_FAULT_NONE, "valid thunks");
    im.thunk_count = UINT64_MAX / AOT_THUNK_STRIDE;      /* checked span */
    CHECK(aot_image_validate(&im) == AOT_FAULT_BAD_STATE, "thunk span end overflow");
    /* valid count, aligned base near the top: the SPAN check must fire. */
    im.thunk_base = UINT64_MAX - 63ull;   /* 0xFFFFFFFFFFFFFFC0, 4-aligned */
    im.thunk_count = 4; im.thunk_stride = AOT_THUNK_STRIDE;
    CHECK(aot_image_validate(&im) == AOT_FAULT_BAD_STATE, "thunk span overflow valid count");
}

/* ---- init / lookup ---- */
static void test_init_lookup(void) {
    AotMem mem;
    uint8_t arena[64];
    CHECK(aot_mem_init(&mem, arena, sizeof(arena), 0x100000ull) == AOT_MEM_OK, "mem init");

    AotRuntime rt;
    CHECK(aot_rt_init(&rt, &img_base, mem, NULL, 10) == AOT_FAULT_BAD_STATE,
          "init null state rejected");
    CHECK(aot_rt_init(&rt, NULL, mem, &g_state, 10) == AOT_FAULT_NONE,
          "no-image runtime allowed");
    CHECK(aot_rt_run(&rt, 0x1000ull, 0) == AOT_EXIT_FAULT, "no-image run faults");
    CHECK(rt.fault == AOT_FAULT_NO_IMAGE, "no-image fault code");

    CHECK(aot_rt_init(&rt, &img_base, mem, &g_state, 10) == AOT_FAULT_NONE, "init ok");
    CHECK(aot_rt_lookup(&rt, 0x1000ull) == blk_ret_stop, "lookup exact");
    CHECK(aot_rt_lookup(&rt, 0x1002ull) == NULL, "lookup misaligned");
    CHECK(aot_rt_lookup(&rt, 0x1008ull) == NULL, "lookup mid-range unknown");
    CHECK(aot_rt_lookup(&rt, 0x2000ull) == NULL, "lookup out of range");
}

/* ---- run / stop sentinel ---- */
static void run_img(AotRuntime *rt, const AotImage *im, uint64_t entry,
                    uint64_t budget) {
    AotMem mem; uint8_t arena[64];
    (void)entry;   /* entry is supplied to aot_rt_run by the caller */
    memset(&g_state, 0, sizeof(g_state));
    aot_mem_init(&mem, arena, sizeof(arena), 0x100000ull);
    aot_rt_init(rt, im, mem, &g_state, budget);
}

static void test_run_stop(void) {
    AotRuntime rt;
    AotImage im;

    im = img_base; im.blocks = blocks1;
    run_img(&rt, &im, 0x1000ull, 10);
    CHECK(aot_rt_run(&rt, 0x1000ull, 0) == AOT_EXIT_STOP, "RET->stop clean STOP");

    run_img(&rt, &im, 0x1000ull, 10);
    CHECK(aot_rt_run(&rt, 0x1000ull, 0x1000ull) == AOT_EXIT_FAULT, "entry==stop rejected");
    CHECK(rt.fault == AOT_FAULT_UNKNOWN_PC, "entry==stop UNKNOWN_PC");

    AotBlockEntry bb = { 0x1000ull, blk_b_stop };
    im = img_base; im.blocks = &bb;
    run_img(&rt, &im, 0x1000ull, 10);
    CHECK(aot_rt_run(&rt, 0x1000ull, 0) == AOT_EXIT_FAULT, "B->stop rejected");
    CHECK(rt.fault == AOT_FAULT_UNKNOWN_PC && rt.fault_target == 0ull, "B->stop diagnostics");

    AotBlockEntry br = { 0x1000ull, blk_br_stop };
    im.blocks = &br;
    run_img(&rt, &im, 0x1000ull, 10);
    CHECK(aot_rt_run(&rt, 0x1000ull, 0) == AOT_EXIT_FAULT, "BR->stop rejected");

    AotBlockEntry bf = { 0x1000ull, blk_fall_stop };
    im.blocks = &bf;
    run_img(&rt, &im, 0x1000ull, 10);
    CHECK(aot_rt_run(&rt, 0x1000ull, 0) == AOT_EXIT_FAULT, "fallthrough->stop rejected");

    AotBlockEntry bl = { 0x1000ull, blk_loop };
    im.blocks = &bl;
    run_img(&rt, &im, 0x1000ull, 5);
    CHECK(aot_rt_run(&rt, 0x1000ull, 0) == AOT_EXIT_FAULT, "budget exhausted");
    CHECK(rt.fault == AOT_FAULT_BUDGET, "budget fault code");

    AotBlockEntry bx = { 0x1000ull, blk_bad_exit };
    im.blocks = &bx;
    run_img(&rt, &im, 0x1000ull, 10);
    CHECK(aot_rt_run(&rt, 0x1000ull, 0) == AOT_EXIT_FAULT, "invalid exit rejected");
    CHECK(rt.fault == AOT_FAULT_BAD_STATE, "invalid exit fault code");

    /* a generated block must never emit the terminal STOP */
    AotBlockEntry bs = { 0x1000ull, blk_stop };
    im.blocks = &bs;
    run_img(&rt, &im, 0x1000ull, 10);
    CHECK(aot_rt_run(&rt, 0x1000ull, 0) == AOT_EXIT_FAULT, "block STOP rejected");
    CHECK(rt.fault == AOT_FAULT_BAD_STATE, "block STOP BAD_STATE");

    /* unknown/misaligned entry diagnostics */
    run_img(&rt, &im, 0x1002ull, 10);
    CHECK(aot_rt_run(&rt, 0x1002ull, 0) == AOT_EXIT_FAULT, "misaligned entry");
    CHECK(rt.fault == AOT_FAULT_MISALIGNED && rt.fault_src == 0x1002ull &&
          rt.fault_target == 0x1002ull, "misaligned diagnostics");
    im = img_base; im.blocks = blocks1;
    run_img(&rt, &im, 0x1008ull, 10);
    CHECK(aot_rt_run(&rt, 0x1008ull, 0) == AOT_EXIT_FAULT, "unknown entry");
    CHECK(rt.fault == AOT_FAULT_UNKNOWN_PC && rt.fault_target == 0x1008ull,
          "unknown diagnostics");

    /* re-entrancy guard */
    run_img(&rt, &im, 0x1000ull, 10);
    aot_rt_init(&rt, &im, rt.mem, &g_state, 10);
    rt.running = 1;
    CHECK(aot_rt_run(&rt, 0x1000ull, 0) == AOT_EXIT_FAULT, "reentry rejected");
    CHECK(rt.fault == AOT_FAULT_BAD_STATE, "reentry fault code");
    rt.running = 0;
}

/* ---- HLE gate ---- */
static int g_hle_calls = 0;
static void hle_redirect(AotGuestState *s, const AotHleRequest *req, void *u) {
    (void)req; (void)u; g_hle_calls++; s->pc = 0x7777ull;
}
static void hle_badstate(AotGuestState *s, const AotHleRequest *req, void *u) {
    (void)req; (void)u; g_hle_calls++; s->nzcv = 1ull;   /* invalid: bit 0 */
}

static void test_hle(void) {
    AotRuntime rt;
    AotImage im = img_base;
    AotBlockEntry svc = { 0x1000ull, blk_svc };

    /* resume PC is not a translated entry -> BAD_RESUME, handler NOT called */
    AotCodeRange only_site = { 0x1000ull, 0x1004ull };
    im.blocks = &svc; im.block_count = 1; im.ranges = &only_site; im.range_count = 1;
    run_img(&rt, &im, 0x1000ull, 10);
    aot_rt_set_handler(&rt, AOT_HLE_SVC, 0x40, hle_redirect, NULL);
    g_hle_calls = 0;
    CHECK(aot_rt_run(&rt, 0x1000ull, 0) == AOT_EXIT_FAULT, "bad resume faults");
    CHECK(rt.fault == AOT_FAULT_BAD_RESUME, "bad resume code");
    CHECK(g_hle_calls == 0, "handler not called on bad resume");

    /* valid resume (0x1004 is RET->stop); handler PC redirect ignored */
    im.blocks = blocks_svc_ret; im.block_count = 2;
    im.ranges = range1; im.range_count = 1;
    run_img(&rt, &im, 0x1000ull, 10);
    aot_rt_set_handler(&rt, AOT_HLE_SVC, 0x40, hle_redirect, NULL);
    g_hle_calls = 0;
    rt.trace_enabled = 1;
    CHECK(aot_rt_run(&rt, 0x1000ull, 0) == AOT_EXIT_STOP, "HLE resume continues to STOP");
    CHECK(g_hle_calls == 1, "handler called once");
    CHECK(rt.trace_count >= 2 && rt.trace[1] == 0x1004ull,
          "PC redirect ignored; resumed at fixed resume");

    /* invalid state written by handler -> BAD_STATE */
    run_img(&rt, &im, 0x1000ull, 10);
    aot_rt_set_handler(&rt, AOT_HLE_SVC, 0x40, hle_badstate, NULL);
    g_hle_calls = 0;
    CHECK(aot_rt_run(&rt, 0x1000ull, 0) == AOT_EXIT_FAULT, "bad state after handler");
    CHECK(rt.fault == AOT_FAULT_BAD_STATE && g_hle_calls == 1, "bad-state code + called");

    /* no handler registered for (kind,id) */
    run_img(&rt, &im, 0x1000ull, 10);
    CHECK(aot_rt_run(&rt, 0x1000ull, 0) == AOT_EXIT_FAULT, "missing handler faults");
    CHECK(rt.fault == AOT_FAULT_BAD_HLE, "missing handler code");
}

/* ---- arena + state invariants ---- */
static void test_arena_state(void) {
    AotMem m; uint8_t a[32];
    CHECK(aot_mem_init(&m, a, 0, 0x100000ull) == AOT_MEM_ERR_RANGE, "zero-size arena");
    CHECK(aot_mem_init(&m, a, sizeof(a), UINT64_MAX - 8ull) == AOT_MEM_ERR_RANGE,
          "guest_base+size wrap");
    CHECK(aot_mem_init(&m, a, sizeof(a), 0x1000ull) == AOT_MEM_OK, "arena ok");

    uint64_t v = 0;
    CHECK(aot_mem_st64(&m, 0x1000ull, 0x1122334455667788ull) == AOT_MEM_OK, "st64");
    CHECK(aot_mem_ld64(&m, 0x1000ull, &v) == AOT_MEM_OK && v == 0x1122334455667788ull,
          "aligned LE rd");
    CHECK(aot_mem_st64(&m, 0x1001ull, 0xAABBCCDDEEFF0011ull) == AOT_MEM_OK, "unaligned st");
    CHECK(aot_mem_ld64(&m, 0x1001ull, &v) == AOT_MEM_OK && v == 0xAABBCCDDEEFF0011ull,
          "unaligned LE rd");
    CHECK(aot_mem_ld64(&m, 0x1019ull, &v) == AOT_MEM_ERR_RANGE, "edge beyond arena");
    CHECK(aot_mem_check(&m, 0x1020ull, 0) == AOT_MEM_OK, "end-of-arena zero length");
    CHECK(aot_mem_ld8(&m, 0x1020ull, (uint8_t *)&v) == AOT_MEM_ERR_RANGE, "load at end");

    AotGuestState s; memset(&s, 0, sizeof(s));
    CHECK(aot_state_validate(&s) == AOT_STATE_OK, "state ok");
    s.nzcv = 1ull;
    CHECK(aot_state_validate(&s) == AOT_STATE_ERR_NZCV, "stray nzcv");
    s.nzcv = 0; s.fpcr = 1ull << 40;
    CHECK(aot_state_validate(&s) == AOT_STATE_ERR_FPCR, "fpcr >32");
    s.fpcr = 0; s.fpsr = 1ull << 40;
    CHECK(aot_state_validate(&s) == AOT_STATE_ERR_FPSR, "fpsr >32");
}

/* ---- thunk transfer contract ---- */
static void test_thunk_transfer(void) {
    AotRuntime rt;
    AotImage im = img_base;
    im.thunk_base = 0x2000ull; im.thunk_count = 1; im.thunk_stride = AOT_THUNK_STRIDE;

    /* BR/tail (INDIRECT) into a host thunk is TAIL_THUNK, handler not called */
    AotBlockEntry bb = { 0x1000ull, blk_br_thunk };
    im.blocks = &bb; im.block_count = 1;
    run_img(&rt, &im, 0x1000ull, 10);
    g_probe_hle_calls = 0;
    aot_rt_set_handler(&rt, AOT_HLE_HOSTCALL, 0, hle_count, NULL);
    CHECK(aot_rt_run(&rt, 0x1000ull, 0) == AOT_EXIT_FAULT, "BR->thunk faults");
    CHECK(rt.fault == AOT_FAULT_TAIL_THUNK && rt.fault_src == 0x1000ull &&
          rt.fault_target == 0x2000ull, "BR->thunk TAIL_THUNK diagnostics");
    CHECK(g_probe_hle_calls == 0, "BR->thunk handler not called");

    /* RET into a host thunk is UNKNOWN_PC, handler not called */
    AotBlockEntry br = { 0x1000ull, blk_ret_thunk };
    im.blocks = &br;
    run_img(&rt, &im, 0x1000ull, 10);
    g_probe_hle_calls = 0;
    aot_rt_set_handler(&rt, AOT_HLE_HOSTCALL, 0, hle_count, NULL);
    CHECK(aot_rt_run(&rt, 0x1000ull, 0) == AOT_EXIT_FAULT, "RET->thunk faults");
    CHECK(rt.fault == AOT_FAULT_UNKNOWN_PC && rt.fault_src == 0x1000ull &&
          rt.fault_target == 0x2000ull, "RET->thunk UNKNOWN_PC diagnostics");
    CHECK(g_probe_hle_calls == 0, "RET->thunk handler not called");
}

int main(void) {
    test_image_validate();
    test_init_lookup();
    test_run_stop();
    test_hle();
    test_arena_state();
    test_thunk_transfer();
    if (g_fail) { printf("FAIL: aot_runtime_probe\n"); return 1; }
    printf("PASS: aot_runtime_probe\n");
    return 0;
}
