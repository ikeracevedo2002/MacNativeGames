/*
 * G3 increment 3: translated multi-module EXECUTION probe (first capability).
 *
 * This is the smallest end-to-end proof that the linked Program dispatches
 * TRANSLATED code (tools/aot/aot_translate.py --module output), not fake
 * blocks:
 *
 *   1. load the three v0 fixture modules (verify -> map -> relocate -> digest
 *      -> seal) through the generated descriptors;
 *   2. aot_loader_build_program: bind each descriptor to its translated
 *      AotImage by flat SHA-256, require every code range inside that module's
 *      text, set the thunk/sentinel regions;
 *   3. finalize the Program with NO handlers registered (a leaf call needs
 *      none) and run sdk_add(1, 2) through aot_call_guest -> 3.
 *
 * Negative controls (each must be REFUSED with its typed status):
 *   - a deliberately wrong pairing: main's descriptor given sdk's image
 *     (identity mismatch -> AOT_LOAD_ERR_SHA256);
 *   - the relr descriptor set (link-only, image == NULL) must not be
 *     executable -> AOT_LOAD_ERR_ARG.
 *
 * Usage: aot_g3_exec_probe <fixture-dir>
 * Exit protocol: 0 = all checks passed, 2 = a semantic check failed
 * ("FAIL: <check>"), 1 = infrastructure failure ("FATAL: <reason>").
 */
#include "aot_as.h"
#include "aot_loader.h"
#include "aot_mem.h"
#include "aot_runtime.h"
#include "aot_sha256.h"
#include "host_thread.h"
#include "host_time.h"

#include <windows.h>   /* InterlockedIncrement: scenario-9 handler counter */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern const AotModuleDesc g_aot_g3_v0_modules[];
extern const uint32_t g_aot_g3_v0_module_count;
extern const AotHostBindings g_aot_g3_v0_bindings;
extern const AotModuleDesc g_aot_g3_relr_modules[];
extern const uint32_t g_aot_g3_relr_module_count;
extern const AotHostBindings g_aot_g3_relr_bindings;

/* Derived by tools/aot/aot_module.py emit-desc for the v0 variant (never
 * hand-coded: the generator fails if they cannot be found exactly once). */
extern const uint64_t g_aot_g3_v0_host_hook_br_va;
extern const uint64_t g_aot_g3_v0_host_hook_resume_va;
/* Scenario 7: the guest VA of the ONE transfer instruction each invalid-target
 * entry performs (derived by emit-desc, never hand-coded here). */
extern const uint64_t g_aot_g3_v0_bad_blr_data_va;
extern const uint64_t g_aot_g3_v0_bad_blr_mid_va;
extern const uint64_t g_aot_g3_v0_bad_blr_align_va;
extern const uint64_t g_aot_g3_v0_bad_ret_va;
extern const uint64_t g_aot_g3_v0_bad_br_va;

#define MODULE_COUNT 3u
/* Guest stack for host->guest calls: unmapped scratch high inside the guest
 * range, 16-byte aligned (sdk_add never touches memory). */
/* Guest stack: RW region the probe reserves in the address space BEFORE the
 * loader seals it (2^37, inside [2^32, 2^39), disjoint from every module and
 * from the thunk/sentinel regions). */
#define STACK_BASE 0x2000000000ull
#define STACK_SIZE 0x4000ull
#define STACK_TOP (STACK_BASE + STACK_SIZE)
/* Scenario 9: one guest stack per host thread, reserved before the seal. */
#define TICK_THREADS 4u
#define TICK_STACK_BASE 0x2000100000ull
#define THUNK_COUNT 6u
#define SENTINEL_COUNT 16u
/* Major 1: one 4 KiB guest page (the straddle test protects the last stack
 * page). */
#define PAGE_SIZE 0x1000ull

static int g_fail;

/* ---- scenario 3: the overridden import's host handler ------------------ */
static uint32_t g_override_calls;
static uint64_t g_override_site;
static uint64_t g_override_resume;

static void hle_override(AotRuntime *rt, AotGuestState *s,
                         const AotHleRequest *req, void *user)
{
    (void)rt;
    (void)user;
    g_override_calls++;
    g_override_site = req->site_pc;
    g_override_resume = req->resume_pc;
    s->x[0] = s->x[0] * 3u + 1u;
}

/* ---- scenario 4: the OBSERVED import's host handler ------------------- */
static uint32_t g_obs_calls;
static uint32_t g_obs_fault;
static uint64_t g_obs_real_x0;
static uint64_t g_real_nnmain;

static void hle_observer(AotRuntime *rt, AotGuestState *s,
                         const AotHleRequest *req, void *user)
{
    uint64_t x0 = 0;
    uint32_t rc;

    (void)req;
    (void)user;
    g_obs_calls++;
    /* Address-taken reference to nnMain must be the REAL module VA. */
    rc = aot_call_guest(rt, g_real_nnmain, NULL, 0u, &x0);
    if (rc != AOT_FAULT_NONE) {
        g_obs_fault = rc;
        s->x[0] = 0u;
        return;
    }
    g_obs_real_x0 = x0;
    s->x[0] = x0 + 0x4000u;   /* marker: the observer chain ran */
}

/* ---- scenario 5b: HLE -> guest (nested host->guest call) -------------- */
static uint32_t g_invoke_calls;
static uint32_t g_invoke_depth_ok;
static uint32_t g_invoke_rc;

static void hle_invoke(AotRuntime *rt, AotGuestState *s,
                       const AotHleRequest *req, void *user)
{
    uint64_t args[1];
    uint64_t x0 = 0;

    (void)req;
    (void)user;
    g_invoke_calls++;
    if (rt->call_depth == 1u) {
        g_invoke_depth_ok++;
    } else {
        g_invoke_depth_ok = 0u;
    }
    args[0] = s->x[1];
    g_invoke_rc = aot_call_guest(rt, s->x[0], args, 1u, &x0);
    if (rt->call_depth != 1u) {
        g_invoke_depth_ok = 0u;
    }
    s->x[0] = (g_invoke_rc == AOT_FAULT_NONE) ? x0 + 1000u : 0u;
}

/* ---- scenario 6: module init (the nn::init::Start shape) ---------------
 * The host calls sdk_start(loader_ready_thunk, module_inits_thunk,
 * module_finis_thunk). sdk_start must call ready, then inits, and never
 * finis. The inits handler drives each module's DT_INIT through a NESTED
 * host->guest call; every DT_INIT walks its OWN init_array. */
typedef struct InitCtx {
    const AotLoader *loader;
    const char *dir;      /* fixture dir (mutant init-array walk only) */
} InitCtx;

static InitCtx g_init_ctx;
static uint32_t g_ready_calls;
static uint32_t g_ready_arg_ok;
static uint32_t g_inits_calls;
static uint32_t g_finis_calls;
static uint32_t g_inits_depth;
static uint32_t g_init_fault;
static uint64_t g_init_va_called[MODULE_COUNT];
/* Host-side arrival record: 0 = ready, 1 = module_inits. */
static uint32_t g_order[8];
static uint32_t g_order_len;

static void order_push(uint32_t v)
{
    if (g_order_len < (uint32_t)(sizeof g_order / sizeof g_order[0])) {
        g_order[g_order_len] = v;
    }
    g_order_len++;
}

static void hle_loader_ready(AotRuntime *rt, AotGuestState *s,
                             const AotHleRequest *req, void *user)
{
    (void)rt;
    (void)req;
    (void)user;
    g_ready_calls++;
    order_push(0u);
    if (s->x[0] == 7u) {
        g_ready_arg_ok++;
    }
    s->x[0] = 0x5a59u;   /* sdk_start adds 1 -> its marker */
}

static void hle_module_inits(AotRuntime *rt, AotGuestState *s,
                             const AotHleRequest *req, void *user)
{
    InitCtx *ctx = (InitCtx *)user;
    uint32_t i;

    (void)req;
    g_inits_calls++;
    order_push(1u);
    g_inits_depth = rt->call_depth;
    for (i = 0u; i < MODULE_COUNT; i++) {
        uint64_t init_va = ctx->loader->modules[i].init_va;
        uint64_t rx0 = 0;
        uint32_t rc;

        g_init_va_called[i] = init_va;
        if (init_va == 0u) {
            g_init_fault = AOT_FAULT_UNKNOWN_PC;
            break;
        }
        rc = aot_call_guest(rt, init_va, NULL, 0u, &rx0);
        if (rc != AOT_FAULT_NONE && g_init_fault == 0u) {
            g_init_fault = rc;
            printf("NOTE: DT_INIT[%u] 0x%llx fault %u\n", i,
                   (unsigned long long)init_va, rc);
        }
        if (rt->call_depth != g_inits_depth) {
            g_inits_depth = 0xffffffffu;   /* depth was not restored */
        }
#ifdef MN_AOT_MUTANT_INIT_ARRAY_WALK
        /* TEST-ONLY wrong implementation: the loader ALSO walks this module's
         * DT_INIT_ARRAY itself, on top of the guest's DT_INIT, so every
         * constructor runs twice (detected by the exactly-once ctor log). */
        {
            char path[1024];
            FILE *lf = NULL;
            char buf[4096];
            size_t got = 0u;
            char *hit;
            unsigned long long off = 0ull, size = 0ull;

            snprintf(path, sizeof path, "%s/%s.layout.json", ctx->dir,
                     ctx->loader->modules[i].desc->name);
#if defined(_MSC_VER)
            if (fopen_s(&lf, path, "rb") != 0) {
                lf = NULL;
            }
#else
            lf = fopen(path, "rb");
#endif
            if (lf != NULL) {
                got = fread(buf, 1u, sizeof buf - 1u, lf);
                fclose(lf);
            }
            buf[got] = 0;
            hit = strstr(buf, "\"init_array\": [");
            if (hit != NULL &&
                sscanf_s(hit, "\"init_array\": [%llu, %llu]", &off,
                         &size) == 2) {
                uint64_t k;
                uint64_t base = ctx->loader->modules[i].desc->guest_base;

                for (k = 0u; k + 8u <= size; k += 8u) {
                    uint64_t entry_va = 0;
                    uint64_t walk_x0 = 0;
                    uint32_t mrc;

                    if (aot_mem_ld64(&rt->mem, base + off + k, &entry_va) !=
                        AOT_MEM_OK) {
                        break;
                    }
                    mrc = aot_call_guest(rt, entry_va, NULL, 0u, &walk_x0);
                    if (mrc != AOT_FAULT_NONE && g_init_fault == 0u) {
                        g_init_fault = mrc;
                    }
                }
            }
        }
#endif
    }
    s->x[0] = 0u;
}

static void hle_module_finis(AotRuntime *rt, AotGuestState *s,
                             const AotHleRequest *req, void *user)
{
    (void)rt;
    (void)req;
    (void)user;
    g_finis_calls++;
    s->x[0] = 0u;
}

/* ---- scenario 9: CNTPCT_EL0 SYSREG handler and its host threads ------- */
static volatile LONG g_tick_calls;

static void hle_sysreg_cntpct(AotRuntime *rt, AotGuestState *s,
                              const AotHleRequest *req, void *user)
{
    uint64_t ns = 0;

    (void)rt;
    (void)user;
    /* The handler owns the destination register (Rt may be 31 = ZR). */
    if (AOT_SYSREG_ID_FIELD(req->id) != AOT_SYSREG_CNTPCT_EL0 ||
        host_time_now_ns(&ns) != HOST_TIME_OK) {
        aot_sysreg_write_dest(s, req, 0u);
        return;
    }
    InterlockedIncrement(&g_tick_calls);
        /* A57 CNTFRQ_EL0 is 19.2 MHz (not 62.5): ticks = ns * 19.2e6 / 1e9
     * = ns * 12 / 625.  (fix 8: the old comment claimed 62.5 MHz.) */
    aot_sysreg_write_dest(s, req, ns / 52u + (ns % 52u) * 12u / 625u);
}

typedef struct TickJob {
    AotProgram *program;
    AotAddressSpace *as;
    uint64_t entry;
    uint64_t sp;
    uint32_t calls;
    uint32_t bad;
    uint64_t last;
    uint64_t first;
} TickJob;

/* Each thread owns its runtime (a runtime is single-owner state) and its own
 * guest stack, and runs 1000 guest entries through the shared Program. */
static void tick_thread(void *arg)
{
    TickJob *j = (TickJob *)arg;
    AotMem mem;
    AotRuntime rt;
    AotGuestState st;
    uint32_t i;

    if (aot_mem_init_aspace(&mem, j->as) != AOT_MEM_OK) {
        j->bad++;
        return;
    }
    memset(&rt, 0, sizeof rt);
    memset(&st, 0, sizeof st);
    st.sp = j->sp;
    if (aot_rt_init_program(&rt, j->program, mem, &st, 100000u) !=
        AOT_FAULT_NONE) {
        j->bad++;
        return;
    }
    for (i = 0u; i < 1000u; i++) {
        uint64_t x0 = 0;

        if (aot_call_guest(&rt, j->entry, NULL, 0u, &x0) != AOT_FAULT_NONE) {
            j->bad++;
            continue;
        }
        if (x0 == 0u || x0 < j->last) {
            j->bad++;
        }
        if (i == 0u) {
            j->first = x0;
        }
        j->last = x0;
        j->calls++;
    }
    aot_rt_release(&rt);
}

/* Resolve a thunk INDEX from the generated bindings (never a constant). */
static uint32_t binding_thunk(const AotHostBindings *b, const char *name)
{
    uint32_t k;

    for (k = 0u; k < b->override_count; k++) {
        if (strcmp(b->overrides[k].name, name) == 0) {
            return b->overrides[k].thunk;
        }
    }
    for (k = 0u; k < b->observer_count; k++) {
        if (strcmp(b->observers[k].name, name) == 0) {
            return b->observers[k].thunk;
        }
    }
    return 0xffffffffu;
}

static void check(int cond, const char *what)
{
    if (!cond) {
        printf("FAIL: %s\n", what);
        g_fail = 1;
    }
}

/* Scenario 7/8: after a fault the SAME runtime must still run a clean
 * top-level guest call (a fault must not poison later top-level calls). */
static void clean_after_fault(AotRuntime *rt, uint64_t fn, const char *what)
{
    uint64_t args[2];
    uint64_t x0 = 0;
    uint32_t rc;

    args[0] = 1u;
    args[1] = 2u;
    rc = aot_call_guest(rt, fn, args, 2u, &x0);
    check(rc == AOT_FAULT_NONE && x0 == 3u, what);
}

static void fatal(const char *what)
{
    printf("FATAL: %s\n", what);
    exit(1);
}

static uint8_t *read_file(const char *path, uint64_t *out_size)
{
    FILE *f = fopen(path, "rb");
    long size = 0;
    uint8_t *buf;

    if (f == NULL) {
        printf("FATAL: cannot open %s\n", path);
        exit(1);
    }
    if (fseek(f, 0, SEEK_END) != 0 || (size = ftell(f)) <= 0 ||
        fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        fatal("unseekable or empty fixture file");
    }
    buf = (uint8_t *)malloc((size_t)size);
    if (buf == NULL) {
        fclose(f);
        fatal("out of memory");
    }
    if (fread(buf, 1, (size_t)size, f) != (size_t)size) {
        fclose(f);
        fatal("short read");
    }
    fclose(f);
    *out_size = (uint64_t)size;
    return buf;
}

typedef struct Fixture {
    AotModuleSet set;
    AotLoader loader;
    AotAddressSpace *as;
    AotMemDomain *domain;
    const uint8_t *images[MODULE_COUNT];
    uint64_t sizes[MODULE_COUNT];
    uint8_t *owned[MODULE_COUNT];
} Fixture;

/* Load one variant from its own flats through its own descriptors. */
static int load_variant(Fixture *fx, const char *dir,
                        const AotModuleDesc *mods, uint32_t count,
                        const AotHostBindings *bindings)
{
    AotLoadError err;
    uint32_t i;

    memset(fx, 0, sizeof *fx);
    if (count != MODULE_COUNT) {
        fatal("unexpected module count");
    }
    for (i = 0u; i < count; i++) {
        char path[512];
        int n = snprintf(path, sizeof path, "%s/%s.flat", dir,
                         mods[i].name);

        if (n <= 0 || (size_t)n >= sizeof path) {
            fatal("fixture path too long");
        }
        fx->owned[i] = read_file(path, &fx->sizes[i]);
        fx->images[i] = fx->owned[i];
    }
    fx->set.modules = mods;
    fx->set.count = count;
    fx->domain = aot_mem_domain_create();
    if (fx->domain == NULL) {
        fatal("aot_mem_domain_create failed");
    }
    fx->as = aot_as_create(fx->domain);
    if (fx->as == NULL) {
        fatal("aot_as_create failed");
    }
    if (aot_loader_init(&fx->loader, fx->as, &fx->set, &err) != AOT_LOAD_OK) {
        printf("FATAL: loader init: %s\n", err.detail);
        return 0;
    }
    /* Guest stack for host->guest calls. It must exist BEFORE the loader
     * seals the space (seal freezes the region table and applies the declared
     * permissions); a plain RW region is exactly what an AAPCS64 stack needs. */
    if (aot_as_add_region(fx->as, STACK_BASE, STACK_SIZE, AOT_AS_PERM_RW,
                          AOT_AS_STATE_DATA, NULL) != AOT_MEM_OK) {
        fatal("aot_as_add_region(stack)");
    }
    /* Scenario 9: one RW guest stack per host thread, also before the seal. */
    for (i = 0u; i < TICK_THREADS; i++) {
        if (aot_as_add_region(fx->as,
                              TICK_STACK_BASE + (uint64_t)i * STACK_SIZE,
                              STACK_SIZE, AOT_AS_PERM_RW,
                              AOT_AS_STATE_DATA, NULL) != AOT_MEM_OK) {
            fatal("aot_as_add_region(tick stack)");
        }
    }
    aot_loader_set_host_bindings(&fx->loader, bindings);
    if (aot_loader_load(&fx->loader, fx->images, fx->sizes, &err) !=
        AOT_LOAD_OK) {
        printf("FATAL: loader load: %s\n", err.detail);
        return 0;
    }
    return 1;
}

static void release_variant(Fixture *fx)
{
    uint32_t i;

    aot_as_destroy(fx->as);
    aot_mem_domain_destroy(fx->domain);
    for (i = 0u; i < MODULE_COUNT; i++) {
        free(fx->owned[i]);
        fx->owned[i] = NULL;
    }
}

/* A wrong pairing: main's descriptor is handed sdk's translated image. The
 * flat SHA-256 binding must reject it before anything is added. */
static void wrong_pairing_check(const char *dir)
{
    AotModuleDesc patched[MODULE_COUNT];
    AotModuleSet set;
    AotLoader loader;
    AotLoadError err;
    AotProgram *p;
    AotLoadStatus st;
    AotAddressSpace *as;
    AotMemDomain *domain;
    const uint8_t *images[MODULE_COUNT];
    uint64_t sizes[MODULE_COUNT];
    uint8_t *owned[MODULE_COUNT];
    uint32_t i;

    /* A fresh address space: the v0 one is already sealed, and a sealed space
     * must refuse to map anything else. */
    domain = aot_mem_domain_create();
    if (domain == NULL) {
        fatal("aot_mem_domain_create failed (wrong pairing)");
    }
    as = aot_as_create(domain);
    if (as == NULL) {
        fatal("aot_as_create failed (wrong pairing)");
    }
    memset(&loader, 0, sizeof loader);
    memset(owned, 0, sizeof owned);
    for (i = 0u; i < MODULE_COUNT; i++) {
        char path[512];
        int n = snprintf(path, sizeof path, "%s/%s.flat", dir,
                         g_aot_g3_v0_modules[i].name);

        if (n <= 0 || (size_t)n >= sizeof path) {
            fatal("fixture path too long");
        }
        owned[i] = read_file(path, &sizes[i]);
        images[i] = owned[i];
    }
    memcpy(patched, g_aot_g3_v0_modules, sizeof patched);
    patched[0].image = g_aot_g3_v0_modules[1].image;   /* main <- sdk's ??? */
    set.modules = patched;
    set.count = MODULE_COUNT;
    st = aot_loader_init(&loader, as, &set, &err);
    check(st == AOT_LOAD_OK, "wrong-pairing loader init");
    aot_loader_set_host_bindings(&loader, &g_aot_g3_v0_bindings);
    st = aot_loader_load(&loader, images, sizes, &err);
    check(st == AOT_LOAD_OK, "wrong-pairing load (same bytes, same digests)");
    p = aot_program_create(as);
    if (p == NULL) {
        fatal("program create (wrong pairing)");
    }
    st = aot_loader_build_program(&loader, p, THUNK_COUNT,
                                  g_aot_g3_v0_bindings.sentinel,
                                  SENTINEL_COUNT, &err);
    check(st == AOT_LOAD_ERR_SHA256,
          "a mismatched image/descriptor pairing is refused (SHA256)");
    check(err.module == 0u, "the refusal names the offending module");
    aot_program_destroy(p);
    aot_as_destroy(as);
    aot_mem_domain_destroy(domain);
    for (i = 0u; i < MODULE_COUNT; i++) {
        free(owned[i]);
    }
}

/* =====================================================================
 * Brief E: --oracle-dump <file> <fixture-dir>
 *
 * Runs the NON-NESTED scenarios only (observer / host_invoke / module init are
 * host<->guest nested and stay closed-form in the main probe) from a FRESH
 * load and a FIXED initial state, and writes the final x0..x30, sp, nzcv and
 * the SHA-256 of every module's data segment per scenario. The Unicorn oracle
 * (tools/aot/g3_exec_oracle.py) replays the same sequence and compares field
 * by field.
 * ===================================================================== */
static uint32_t g_det_ticks;

static void hle_det_override(AotRuntime *rt, AotGuestState *s,
                             const AotHleRequest *req, void *user)
{
    (void)rt;
    (void)req;
    (void)user;
    s->x[0] = s->x[0] * 3u + 1u;
}

/* A second counter, to prove one handler per register serves every Rt. */
static volatile LONG g_cntvct_calls;

static void hle_sysreg_cntvct(AotRuntime *rt, AotGuestState *s,
                              const AotHleRequest *req, void *user)
{
    (void)rt;
    (void)user;
    InterlockedIncrement(&g_cntvct_calls);
    /* Rt = 31 (mrs xzr) writes nothing: aot_sysreg_write_dest honours that. */
    aot_sysreg_write_dest(s, req, 0x0c0ffee0ull);
}

/* Deterministic CNTPCT_EL0: both sides return the same fixed sequence. */
static void hle_det_tick(AotRuntime *rt, AotGuestState *s,
                         const AotHleRequest *req, void *user)
{
    (void)rt;
    (void)user;
    aot_sysreg_write_dest(s, req, 0x1000u + (uint64_t)g_det_ticks);
    g_det_ticks++;
}

static int data_digest(const AotMem *mem, uint32_t index, char out[65])
{
    const AotModuleDesc *d = &g_aot_g3_v0_modules[index];
    AotSha256 ctx;
    uint8_t dig[AOT_SHA256_DIGEST_BYTES];
    uint64_t off;

    if ((d->data.size & 7u) != 0u) {
        return 0;
    }
    aot_sha256_init(&ctx);
    for (off = 0u; off < d->data.size; off += 8u) {
        uint8_t raw[8];
        uint64_t v = 0;
        uint32_t k;

        if (aot_mem_ld64(mem, d->guest_base + d->data.off + off, &v) !=
            AOT_MEM_OK) {
            return 0;
        }
        for (k = 0u; k < 8u; k++) {
            raw[k] = (uint8_t)(v >> (8u * k));
        }
        aot_sha256_update(&ctx, raw, sizeof raw);
    }
    aot_sha256_final(&ctx, dig);
    aot_sha256_hex(dig, out);
    return 1;
}

static void dump_state(FILE *f, const char *name, const AotGuestState *st,
                       const AotMem *mem, int first)
{
    char sha[MODULE_COUNT][65];
    uint32_t i;

    for (i = 0u; i < MODULE_COUNT; i++) {
        if (!data_digest(mem, i, sha[i])) {
            fatal("oracle dump: data digest failed");
        }
    }
    fprintf(f, "%s\n  { \"name\": \"%s\",\n    \"x\": [", first ? "" : ",",
            name);
    for (i = 0u; i < 31u; i++) {
        fprintf(f, "%s\"0x%016llx\"", i ? ", " : "",
                (unsigned long long)st->x[i]);
    }
    fprintf(f, "],\n    \"sp\": \"0x%016llx\",\n    \"nzcv\": \"0x%08llx\",\n"
               "    \"data\": [\"%s\", \"%s\", \"%s\"] }",
            (unsigned long long)st->sp, (unsigned long long)st->nzcv,
            sha[0], sha[1], sha[2]);
}

static int run_oracle_dump(const char *dir, const char *out_path)
{
    Fixture v0;
    AotProgram *prog;
    AotRuntime rt;
    AotGuestState state;
    AotMem mem;
    AotLoadError err;
    AotLoadStatus st;
    FILE *f;
    uint32_t i;
    static const char *const names[15] = {
        "main_scn_calls", "main_scn_identity", "main_scn_override",
        "main_scn_callback", "main_scn_mod0_magic", "main_scn_tick",
        "main_scn_tick", "main_scn_tick", "main_scn_tick", "main_scn_orr",
        "main_scn_cntpct_rt8", "main_scn_cntpct_zr", "main_scn_cntvct",
        "main_scn_tpidr",
        /* Major 1: in-page STP/LDP round trip (X and W forms). */
        "main_scn_pair"
    };
    /* Only NON-FAULT, NON-NESTED scenarios are dumped. The transfer faults
     * (RET into a thunk -> BAD_TRANSFER, BR into the sentinel -> BAD_RETURN)
     * stay closed-form in the main probe, where the exact src/target VAs are
     * asserted; they are deliberately NOT part of the oracle sequence. */
    enum { SCEN_COUNT = 15 };
    uint32_t order[SCEN_COUNT] = { 0, 1, 2, 3, 4, 5, 5, 5, 5, 9, 10, 11, 12,
                                   13, 14 };

    if (!load_variant(&v0, dir, g_aot_g3_v0_modules, g_aot_g3_v0_module_count,
                      &g_aot_g3_v0_bindings)) {
        fatal("oracle dump: loading the v0 fixtures");
    }
    prog = aot_program_create(v0.as);
    if (prog == NULL) {
        fatal("oracle dump: program create");
    }
    st = aot_loader_build_program(&v0.loader, prog, THUNK_COUNT,
                                  g_aot_g3_v0_bindings.sentinel,
                                  SENTINEL_COUNT, &err);
    if (st != AOT_LOAD_OK) {
        fatal("oracle dump: build_program");
    }
    {
        uint32_t hook = binding_thunk(&g_aot_g3_v0_bindings, "host_hook");
        if (hook == 0xffffffffu) {
            fatal("oracle dump: host_hook binding");
        }
        if (aot_program_set_handler(prog, AOT_HLE_HOSTCALL, hook,
                                    hle_det_override, NULL) != 0 ||
            aot_program_set_handler(prog, AOT_HLE_SYSREG,
                                    AOT_SYSREG_ID(AOT_SYSREG_CNTPCT_EL0, 0u),
                                    hle_det_tick, NULL) != 0 ||
            aot_program_set_handler(prog, AOT_HLE_SYSREG,
                                    AOT_SYSREG_ID(AOT_SYSREG_CNTVCT_EL0, 0u),
                                    hle_sysreg_cntvct, NULL) != 0) {
            fatal("oracle dump: handler registration");
        }
    }
    if (aot_program_finalize(prog) != AOT_FAULT_NONE) {
        fatal("oracle dump: finalize");
    }
    if (aot_mem_init_aspace(&mem, v0.as) != AOT_MEM_OK) {
        fatal("oracle dump: aot_mem_init_aspace");
    }
    memset(&rt, 0, sizeof rt);
    memset(&state, 0, sizeof state);
    state.sp = STACK_TOP;
    /* Fixed TPIDR values: the oracle is given exactly these two numbers, so a
     * TPIDR read is compared against known guest state, not against zero. */
    state.tpidr = 0x1111222233334444ull;
    state.tpidrro = 0x5555666677778888ull;
    if (aot_rt_init_program(&rt, prog, mem, &state, 100000u) !=
        AOT_FAULT_NONE) {
        fatal("oracle dump: aot_rt_init_program");
    }
#if defined(_MSC_VER)
    if (fopen_s(&f, out_path, "wb") != 0) {
        f = NULL;
    }
#else
    f = fopen(out_path, "wb");
#endif
    if (f == NULL) {
        fatal("oracle dump: cannot open the output file");
    }
    fprintf(f, "{ \"scenarios\": [");
    for (i = 0u; i < (uint32_t)SCEN_COUNT; i++) {
        uint64_t va = 0;
        uint64_t x0 = 0;
        char label[64];
        uint32_t rc;

        if (aot_loader_symbol(&v0.loader, names[order[i]], &va) !=
                AOT_LOAD_OK || va == 0u) {
            fatal("oracle dump: scenario symbol");
        }
        rc = aot_call_guest(&rt, va, NULL, 0u, &x0);
        if (rc != AOT_FAULT_NONE) {
            printf("FATAL: oracle dump: %s faulted (%u)\n", names[order[i]],
                   rc);
            fclose(f);
            return 1;
        }
        snprintf(label, sizeof label, "%s#%u", names[order[i]], i);
        dump_state(f, label, &state, &mem, i == 0u);
    }
    fprintf(f, "\n] }\n");
    fclose(f);
    aot_rt_release(&rt);
    aot_program_destroy(prog);
    release_variant(&v0);
    printf("aot_g3_exec_probe: oracle dump written to %s\n", out_path);
    return 0;
}

/* Minor 4 + Major 2: the Program assembly gate and the poison gate.
 *
 *   (a) build_program must refuse a Program created over a DIFFERENT address
 *       space (the Program would dispatch code whose memory was never the one
 *       the descriptors were validated against);
 *   (b) build_program must refuse a Program that is not EMPTY (a pre-set thunk
 *       region, i.e. images/regions already assigned, would be mixed with the
 *       new module set);
 *   (c) a POISONED address space can never be finalized into a runnable
 *       Program (aot_program_finalize) and can never be run
 *       (aot_rt_init_program), while the same shape finalizes/runs when the
 *       space is not poisoned - the only difference is the poison flag. */
static void build_program_shape_check(const char *dir)
{
    Fixture fx;
    AotProgram *p;
    AotLoadError err;
    AotLoadStatus st;
    AotMemDomain *other_dom;
    AotAddressSpace *other_as;
    AotRuntime rt2;
    AotMem mem;
    AotGuestState state;

    if (!load_variant(&fx, dir, g_aot_g3_v0_modules,
                      g_aot_g3_v0_module_count, &g_aot_g3_v0_bindings)) {
        fatal("build shape: loading the v0 fixtures");
    }

    /* (a) wrong address space. */
    other_dom = aot_mem_domain_create();
    if (other_dom == NULL) {
        fatal("build shape: domain create");
    }
    other_as = aot_as_create(other_dom);
    if (other_as == NULL) {
        fatal("build shape: address space create");
    }
    p = aot_program_create(other_as);
    if (p == NULL) {
        fatal("build shape: program create (other space)");
    }
    st = aot_loader_build_program(&fx.loader, p, THUNK_COUNT,
                                  g_aot_g3_v0_bindings.sentinel,
                                  SENTINEL_COUNT, &err);
    check(st == AOT_LOAD_ERR_ARG,
          "a Program built over a different address space is refused (ARG)");
    check(err.detail != NULL &&
              strstr(err.detail, "different address space") != NULL,
          "the refusal names the address space mismatch");
    aot_program_destroy(p);
    aot_as_destroy(other_as);
    aot_mem_domain_destroy(other_dom);

    /* (b) Program that is not empty: its thunk/sentinel regions are preset. */
    p = aot_program_create(fx.as);
    if (p == NULL) {
        fatal("build shape: program create (preset regions)");
    }
    check(aot_program_set_host_regions(p, g_aot_g3_v0_bindings.thunk_base,
                                       THUNK_COUNT,
                                       g_aot_g3_v0_bindings.sentinel,
                                       SENTINEL_COUNT) == AOT_FAULT_NONE,
          "host regions can be preset on a fresh Program");
    st = aot_loader_build_program(&fx.loader, p, THUNK_COUNT,
                                  g_aot_g3_v0_bindings.sentinel,
                                  SENTINEL_COUNT, &err);
    check(st == AOT_LOAD_ERR_ARG,
          "a Program that already has regions is refused (ARG)");
    check(err.detail != NULL && strstr(err.detail, "EMPTY") != NULL,
          "the refusal says the Program must be empty");
    aot_program_destroy(p);

    /* (c1) finalize over a POISONED (but sealed) space. */
    p = aot_program_create(fx.as);
    if (p == NULL) {
        fatal("build shape: program create (finalize)");
    }
    st = aot_loader_build_program(&fx.loader, p, THUNK_COUNT,
                                  g_aot_g3_v0_bindings.sentinel,
                                  SENTINEL_COUNT, &err);
    check(st == AOT_LOAD_OK,
          "the empty/unbound-Program checks do not block a valid build");
    check(aot_as_is_poisoned(fx.as) == 0, "the loaded space is not poisoned");
    aot_as_poison(fx.as);
    check(aot_program_finalize(p) == AOT_FAULT_BAD_STATE,
          "a POISONED address space cannot be finalized into a Program");
    aot_program_destroy(p);
    release_variant(&fx);

    /* (c2) the same shape finalizes and runs when the space is NOT poisoned,
     * and is then refused by the runtime as soon as it is. */
    if (!load_variant(&fx, dir, g_aot_g3_v0_modules,
                      g_aot_g3_v0_module_count, &g_aot_g3_v0_bindings)) {
        fatal("build shape: reloading the v0 fixtures");
    }
    p = aot_program_create(fx.as);
    if (p == NULL) {
        fatal("build shape: program create (runtime)");
    }
    st = aot_loader_build_program(&fx.loader, p, THUNK_COUNT,
                                  g_aot_g3_v0_bindings.sentinel,
                                  SENTINEL_COUNT, &err);
    check(st == AOT_LOAD_OK, "the runtime-gate Program builds");
    check(aot_program_finalize(p) == AOT_FAULT_NONE,
          "an UNPOISONED sealed space finalizes");
    if (aot_mem_init_aspace(&mem, fx.as) != AOT_MEM_OK) {
        fatal("build shape: mem handle");
    }
    memset(&state, 0, sizeof state);
    state.sp = STACK_TOP;
    memset(&rt2, 0, sizeof rt2);
    check(aot_rt_init_program(&rt2, p, mem, &state, 16) == AOT_FAULT_NONE,
          "the runtime starts on an unpoisoned Program");
    aot_rt_release(&rt2);
    aot_as_poison(fx.as);
    memset(&rt2, 0, sizeof rt2);
    check(aot_rt_init_program(&rt2, p, mem, &state, 16) ==
              AOT_FAULT_BAD_STATE,
          "a runtime refuses a POISONED address space");
    check(rt2.fault == AOT_FAULT_BAD_STATE, "the refusal is recorded");
    aot_rt_release(&rt2);
    aot_program_destroy(p);
    release_variant(&fx);
    printf("build-shape: address-space, empty-Program and poison gates bite\n");
}

int main(int argc, char **argv)
{
    const char *dir;

    if (argc >= 3 && strcmp(argv[1], "--oracle-dump") == 0) {
        return run_oracle_dump(argv[3] ? argv[3] : ".", argv[2]);
    }
    dir = (argc > 1) ? argv[1] : ".";
    Fixture v0;
    Fixture relr;
    AotLoadError err;
    AotLoadStatus st;
    AotProgram *prog;
    AotProgram *prog_relr;
    AotRuntime rt;
    AotGuestState state;
    AotMem mem;
    uint64_t args[2];
    uint64_t x0 = 0;
    uint64_t sdk_add = 0;
    uint32_t rc;

    if (!load_variant(&v0, dir, g_aot_g3_v0_modules,
                      g_aot_g3_v0_module_count, &g_aot_g3_v0_bindings)) {
        fatal("loading the v0 fixtures");
    }

    /* ---- Program assembly from the loaded, sealed modules --------------- */
    prog = aot_program_create(v0.as);
    if (prog == NULL) {
        fatal("program create");
    }
    /* ---- review fixes 4/11/12: geometry, guest base, single assembly ---- */
    {
        AotProgram *pbad;

        /* fix 4: a thunk region that cannot hold the highest binding index. */
        pbad = aot_program_create(v0.as);
        if (pbad == NULL) {
            fatal("program create (thunk-range negative)");
        }
        st = aot_loader_build_program(&v0.loader, pbad, 0u,
                                      g_aot_g3_v0_bindings.sentinel,
                                      SENTINEL_COUNT, &err);
        check(st == AOT_LOAD_ERR_ARG,
              "a thunk region too small for the bindings is refused (ARG)");
        check(err.detail != NULL && strstr(err.detail, "thunk") != NULL,
              "the thunk-region refusal names the thunk geometry");
        aot_program_destroy(pbad);

        /* fix 4: a sentinel that is not the one the bindings were built with. */
        pbad = aot_program_create(v0.as);
        if (pbad == NULL) {
            fatal("program create (sentinel negative)");
        }
        st = aot_loader_build_program(&v0.loader, pbad, THUNK_COUNT,
                                      g_aot_g3_v0_bindings.sentinel + 0x10u,
                                      SENTINEL_COUNT, &err);
        check(st == AOT_LOAD_ERR_ARG,
              "a sentinel base that is not the bindings' sentinel is refused "
              "(ARG)");
        check(err.detail != NULL && strstr(err.detail, "sentinel") != NULL,
              "the sentinel refusal names the sentinel geometry");
        aot_program_destroy(pbad);
    }

    st = aot_loader_build_program(&v0.loader, prog, THUNK_COUNT,
                                  g_aot_g3_v0_bindings.sentinel,
                                  SENTINEL_COUNT, &err);
    if (st != AOT_LOAD_OK) {
        printf("FATAL: build_program: %s\n", err.detail);
        return 1;
    }
    /* fix 12: the Program borrows loader->prog[], so a SECOND successful
     * assembly from the same loader must be refused (typed STATE error). */
    {
        AotProgram *p2 = aot_program_create(v0.as);

        if (p2 == NULL) {
            fatal("program create (second-build negative)");
        }
        st = aot_loader_build_program(&v0.loader, p2, THUNK_COUNT,
                                      g_aot_g3_v0_bindings.sentinel,
                                      SENTINEL_COUNT, &err);
        check(st == AOT_LOAD_ERR_STATE,
              "assembling a second Program from one loader is refused (STATE)");
        check(err.detail != NULL && strstr(err.detail, "already") != NULL,
              "the second-build refusal says the loader is already used");
        aot_program_destroy(p2);
    }

    /* fix 11: guest-base negative. A descriptor whose text segment does not
     * contain its image's code range must be refused, so a wrong guest base
     * can never be executed. Only the descriptor's guest base moves: the
     * images stay the real (read-only) ones the loader assembled. */
    {
        AotProgram *p3;
        AotLoader shifted;
        AotModuleDesc shifted_desc;

        shifted = v0.loader;                 /* prog[] is copied with the struct */
        shifted.program_built = 0u;
        shifted_desc = *shifted.modules[0].desc;
        shifted_desc.guest_base += 0x1000u;  /* text no longer contains r[] */
        shifted.modules[0].desc = &shifted_desc;
        p3 = aot_program_create(v0.as);
        if (p3 == NULL) {
            fatal("program create (guest-base negative)");
        }
        st = aot_loader_build_program(&shifted, p3, THUNK_COUNT,
                                      g_aot_g3_v0_bindings.sentinel,
                                      SENTINEL_COUNT, &err);
        check(st == AOT_LOAD_ERR_LAYOUT,
              "a descriptor whose text does not contain its image's code range "
              "is refused (LAYOUT)");
        check(err.detail != NULL && strstr(err.detail, "code range") != NULL,
              "the guest-base refusal names the code range");
        check(err.module == 0u, "the guest-base refusal names module 0");
        aot_program_destroy(p3);
    }

    /* Scenario 3/5b: override thunk handlers. The thunk indices come from the
     * generated bindings (link_config.json), not from constants. */
    {
        uint32_t thunk_host_hook = 0xffffffffu;
        uint32_t thunk_host_invoke = 0xffffffffu;
        uint32_t thunk_nnmain = 0xffffffffu;
        uint32_t thunk_ready = 0xffffffffu;
        uint32_t thunk_inits = 0xffffffffu;
        uint32_t thunk_finis = 0xffffffffu;
        uint32_t k;

        for (k = 0u; k < g_aot_g3_v0_bindings.override_count; k++) {
            if (strcmp(g_aot_g3_v0_bindings.overrides[k].name,
                       "host_hook") == 0) {
                thunk_host_hook = g_aot_g3_v0_bindings.overrides[k].thunk;
            }
            if (strcmp(g_aot_g3_v0_bindings.overrides[k].name,
                       "host_invoke") == 0) {
                thunk_host_invoke = g_aot_g3_v0_bindings.overrides[k].thunk;
            }
        }
        for (k = 0u; k < g_aot_g3_v0_bindings.observer_count; k++) {
            if (strcmp(g_aot_g3_v0_bindings.observers[k].name,
                       "nnMain") == 0) {
                thunk_nnmain = g_aot_g3_v0_bindings.observers[k].thunk;
            }
        }
        check(thunk_host_hook != 0xffffffffu,
              "host_hook has an override thunk binding");
        check(thunk_host_invoke != 0xffffffffu,
              "host_invoke has an override thunk binding");
        check(thunk_nnmain != 0xffffffffu,
              "nnMain has an observer thunk binding");
        check(aot_program_set_handler(prog, AOT_HLE_HOSTCALL, thunk_host_hook,
                                      hle_override, NULL) == 0,
              "override handler is registered before finalize");
        check(aot_program_set_handler(prog, AOT_HLE_HOSTCALL, thunk_host_invoke,
                                      hle_invoke, NULL) == 0,
              "host_invoke handler is registered before finalize");
        check(aot_program_set_handler(prog, AOT_HLE_HOSTCALL, thunk_nnmain,
                                      hle_observer, NULL) == 0,
              "observer handler is registered before finalize");

        /* Scenario 6: the three nn::init::Start thunks. */
        thunk_ready = binding_thunk(&g_aot_g3_v0_bindings, "fx_loader_ready");
        thunk_inits = binding_thunk(&g_aot_g3_v0_bindings, "fx_module_inits");
        thunk_finis = binding_thunk(&g_aot_g3_v0_bindings, "fx_module_finis");
        check(thunk_ready != 0xffffffffu && thunk_inits != 0xffffffffu &&
                  thunk_finis != 0xffffffffu,
              "the init-sequence thunks have override bindings");
        check(thunk_inits != thunk_finis && thunk_ready != thunk_inits,
              "the init-sequence thunks have distinct indices");
        g_init_ctx.loader = &v0.loader;
        g_init_ctx.dir = dir;
        check(aot_program_set_handler(prog, AOT_HLE_HOSTCALL, thunk_ready,
                                      hle_loader_ready, &g_init_ctx) == 0,
              "loader_ready handler is registered");
        check(aot_program_set_handler(prog, AOT_HLE_HOSTCALL, thunk_inits,
                                      hle_module_inits, &g_init_ctx) == 0,
              "module_inits handler is registered");
        check(aot_program_set_handler(prog, AOT_HLE_HOSTCALL, thunk_finis,
                                      hle_module_finis, &g_init_ctx) == 0,
              "module_finis handler is registered");

        /* The observer must invoke the REAL module body by address. */
        st = aot_loader_symbol(&v0.loader, "nnMain", &g_real_nnmain);
        check(st == AOT_LOAD_OK && g_real_nnmain != 0,
              "nnMain resolves to its real module VA");
        check(aot_program_is_entry(prog, g_real_nnmain),
              "the real nnMain VA is a translated Program entry");
    }
    check(aot_program_set_handler(prog, AOT_HLE_SYSREG,
                                  AOT_SYSREG_ID(AOT_SYSREG_CNTPCT_EL0, 0u),
                                  hle_sysreg_cntpct, NULL) == 0,
          "the CNTPCT_EL0 (Rt=0) SYSREG handler is registered");
    /* Review fix 1: ONE handler per system register. The id carries Rt but
     * lookup keys on (kind, id & ~31u), so a second registration of the SAME
     * register with a DIFFERENT Rt must be refused as a duplicate. */
    check(aot_program_set_handler(prog, AOT_HLE_SYSREG,
                                  AOT_SYSREG_ID(AOT_SYSREG_CNTVCT_EL0, 5u),
                                  hle_sysreg_cntvct, NULL) == 0,
          "the CNTVCT_EL0 handler is registered with Rt=5 in its id");
    check(aot_program_set_handler(prog, AOT_HLE_SYSREG,
                                  AOT_SYSREG_ID(AOT_SYSREG_CNTVCT_EL0, 0u),
                                  hle_sysreg_cntvct, NULL) == 2,
          "a second CNTVCT_EL0 handler with another Rt IS a duplicate "
          "(one handler per sysreg)");
    check(aot_program_finalize(prog) == AOT_FAULT_NONE,
          "Program finalizes with its handlers");

    /* ---- one runtime, one leaf guest call (sdk_add(1, 2) == 3) --------- */
    if (aot_mem_init_aspace(&mem, v0.as) != AOT_MEM_OK) {
        fatal("aot_mem_init_aspace");
    }
    memset(&rt, 0, sizeof rt);
    memset(&state, 0, sizeof state);
    state.sp = STACK_TOP;
    rc = aot_rt_init_program(&rt, prog, mem, &state, 100000u);
    if (rc != AOT_FAULT_NONE) {
        printf("FATAL: aot_rt_init_program: %u\n", rc);
        return 1;
    }
    st = aot_loader_symbol(&v0.loader, "sdk_add", &sdk_add);
    check(st == AOT_LOAD_OK && sdk_add != 0, "sdk_add resolves in the loader");
    check(aot_program_is_entry(prog, sdk_add),
          "sdk_add is a translated Program entry");

    args[0] = 1u;
    args[1] = 2u;
    rc = aot_call_guest(&rt, sdk_add, args, 2u, &x0);
    check(rc == AOT_FAULT_NONE, "translated sdk_add(1,2) returns cleanly");
    check(x0 == 3u, "translated sdk_add(1,2) == 3");

    /* ---- scenarios 1-3 (translated multi-module behaviour) ------------- */
    {
        static const char *const names[3] = { "main_scn_calls",
                                              "main_scn_identity",
                                              "main_scn_override" };
        static const uint64_t want[8] = {
            3u,                    /* main -> sdk PLT (sdk_add(1,2))          */
            11u,                   /* main -> sub PLT (sub_entry -> sdk 5+6)  */
            0x1122334455667788ull, /* GLOB_DAT read of sdk_data[0]            */
            0x99aabbccddeeff00ull, /* ABS64 (sdk_data + 8) read               */
            0xd2u,                 /* RELATIVE vtable[1] (main_vfn_b)         */
            0x10u,                 /* weak import == 0 through the cbz path   */
            0x1111u,               /* shared_impl from main -> sub's          */
            0x2222u                /* shared_impl from sdk -> sdk's own       */
        };
        const uint64_t sum = 3u + 11u + 0x1122334455667788ull +
                             0x99aabbccddeeff00ull + 0xd2u + 0x10u +
                             0x1111u + 0x2222u;
        uint64_t va[3];
        uint64_t results = 0;
        uint32_t i;

        for (i = 0u; i < 3u; i++) {
            va[i] = 0;
            check(aot_loader_symbol(&v0.loader, names[i], &va[i]) ==
                      AOT_LOAD_OK && va[i] != 0, names[i]);
        }

        /* Scenario 1 */
        rc = aot_call_guest(&rt, va[0], NULL, 0, &x0);
        if (rc != AOT_FAULT_NONE) {
            printf("NOTE: main_scn_calls fault %u src=0x%llx target=0x%llx status=%lld", rc, (unsigned long long)rt.fault_src,
                   (unsigned long long)rt.fault_target,
                   (long long)rt.fault_status);
            printf("\n");
        }
        check(rc == AOT_FAULT_NONE, "main_scn_calls returns cleanly");
        check(x0 == sum, "main_scn_calls checksum");
        check(aot_loader_symbol(&v0.loader, "main_results", &results) ==
                  AOT_LOAD_OK && results != 0, "main_results resolves");
        for (i = 0u; results != 0 && i < 8u; i++) {
            uint64_t got = 0;
            char label[64];

            if (aot_mem_ld64(&mem, results + i * 8u, &got) != AOT_MEM_OK) {
                check(0, "read main_results through the address space");
                break;
            }
            snprintf(label, sizeof label, "main_results[%u] == 0x%llx", i,
                     (unsigned long long)want[i]);
            check(got == want[i], label);
        }

        /* Scenario 2: thunk identity across modules */
        rc = aot_call_guest(&rt, va[1], NULL, 0, &x0);
        check(rc == AOT_FAULT_NONE, "main_scn_identity returns cleanly");
        check(x0 == 1u,
              "main's and sub's host_hook GOT values are the same thunk");

        /* Scenario 3: override through the PLT stub / BR x17 */
        rc = aot_call_guest(&rt, va[2], NULL, 0, &x0);
        check(rc == AOT_FAULT_NONE, "main_scn_override returns cleanly");
        check(x0 == 116u, "override: handler x0*3+1, then +100");
        check(g_override_calls == 1u, "override handler ran exactly once");
        check(g_override_site == g_aot_g3_v0_host_hook_br_va,
              "req.site_pc is the PLT stub's br x17");
        check(g_override_resume == g_aot_g3_v0_host_hook_resume_va,
              "req.resume_pc is the instruction after main's bl");
    }

    /* ---- ORR (shifted register) with a non-zero shift (mutant control) -- */
    {
        uint64_t va = 0;

        check(aot_loader_symbol(&v0.loader, "main_scn_orr", &va) ==
                  AOT_LOAD_OK && va != 0, "main_scn_orr resolves");
        rc = aot_call_guest(&rt, va, NULL, 0u, &x0);
        check(rc == AOT_FAULT_NONE, "main_scn_orr returns cleanly");
        check(x0 == 0x2121u, "ORR shifted register honours the shift amount");
    }

    /* ---- review fix 1: SYSREG ids carry Rt; one handler per register ---- */
    {
        uint64_t va = 0;
        LONG before_c = 0;

        check(aot_loader_symbol(&v0.loader, "main_scn_cntpct_rt8", &va) ==
                  AOT_LOAD_OK && va != 0, "main_scn_cntpct_rt8 resolves");
        before_c = InterlockedCompareExchange(&g_tick_calls, 0, 0);
        rc = aot_call_guest(&rt, va, NULL, 0u, &x0);
        check(rc == AOT_FAULT_NONE, "mrs x8, cntpct_el0 returns cleanly");
        check(x0 != 0u, "mrs x8, cntpct_el0 delivers the counter through x8");
        check(InterlockedCompareExchange(&g_tick_calls, 0, 0) == before_c + 1,
              "the CNTPCT_EL0 handler (registered with Rt=0) served Rt=8");

        check(aot_loader_symbol(&v0.loader, "main_scn_cntpct_zr", &va) ==
                  AOT_LOAD_OK && va != 0, "main_scn_cntpct_zr resolves");
        before_c = InterlockedCompareExchange(&g_tick_calls, 0, 0);
        rc = aot_call_guest(&rt, va, NULL, 0u, &x0);
        check(rc == AOT_FAULT_NONE, "mrs xzr, cntpct_el0 returns cleanly");
        check(x0 == 0x1234u,
              "mrs xzr, cntpct_el0 leaves every register unchanged");
        check(InterlockedCompareExchange(&g_tick_calls, 0, 0) == before_c + 1,
              "mrs xzr still calls the SYSREG handler exactly once");

        check(aot_loader_symbol(&v0.loader, "main_scn_cntvct", &va) ==
                  AOT_LOAD_OK && va != 0, "main_scn_cntvct resolves");
        before_c = InterlockedCompareExchange(&g_cntvct_calls, 0, 0);
        rc = aot_call_guest(&rt, va, NULL, 0u, &x0);
        check(rc == AOT_FAULT_NONE, "CNTVCT_EL0 reads return cleanly");
        check(x0 == 2u * 0x0c0ffee0ull,
              "both CNTVCT_EL0 reads (Rt=9, Rt=10) used the ONE handler");
        check(InterlockedCompareExchange(&g_cntvct_calls, 0, 0) ==
                  before_c + 3,
              "three CNTVCT_EL0 reads (Rt=31, 9, 10) called it three times");

        check(aot_loader_symbol(&v0.loader, "main_scn_tpidr", &va) ==
                  AOT_LOAD_OK && va != 0, "main_scn_tpidr resolves");
        rt.state->tpidr = 0x1111u;
        rt.state->tpidrro = 0x2222u;
        rc = aot_call_guest(&rt, va, NULL, 0u, &x0);
        check(rc == AOT_FAULT_NONE, "TPIDR_EL0/TPIDRRO_EL0 reads are clean");
        check(x0 == 0x3333u,
              "TPIDR_EL0 + TPIDRRO_EL0 come from the guest state");
    }

    /* ---- scenarios 4-5 (nested host<->guest transfers) ----------------- */
    {
        static const char *const names[4] = { "main_scn_observer",
                                              "main_scn_callback",
                                              "main_scn_invoke",
                                              "main_nnmain_slot" };
        uint64_t va[4];
        uint64_t slot = 0, marker = 0, sdk_data = 0;
        uint32_t i;

        for (i = 0u; i < 4u; i++) {
            va[i] = 0;
            check(aot_loader_symbol(&v0.loader, names[i], &va[i]) ==
                      AOT_LOAD_OK && va[i] != 0, names[i]);
        }
        check(aot_loader_symbol(&v0.loader, "sdk_data", &sdk_data) ==
                  AOT_LOAD_OK && sdk_data != 0, "sdk_data resolves");

        /* Scenario 4: observed import -> host handler -> nested real nnMain */
        rc = aot_call_guest(&rt, va[0], NULL, 0, &x0);
        check(rc == AOT_FAULT_NONE, "main_scn_observer returns cleanly");
        check(x0 == 0xb977u, "observer: (0x7777 + 0x4000) + 0x200");
        check(g_obs_calls == 1u, "observer handler ran exactly once");
        check(g_obs_fault == 0u, "the nested real-nnMain call did not fault");
        check(g_obs_real_x0 == 0x7777u,
              "the REAL nnMain body returned through the observer");
        check(aot_mem_ld64(&mem, sdk_data + 88u, &marker) == AOT_MEM_OK &&
                  marker == 1u,
              "the real nnMain ran (side effect in sdk data)");
        check(aot_mem_ld64(&mem, va[3], &slot) == AOT_MEM_OK &&
                  slot == g_real_nnmain,
              "the ABS64 nnMain slot still holds the REAL VA");

        /* Scenario 5a: translated -> translated cross-module callback */
        rc = aot_call_guest(&rt, va[1], NULL, 0, &x0);
        check(rc == AOT_FAULT_NONE, "main_scn_callback returns cleanly");
        check(x0 == 0xdbu, "cross-module callback: 21 + 0xc1 + 5");

        /* Scenario 5b: HLE -> guest, nested call + callee-saved survival */
        rc = aot_call_guest(&rt, va[2], NULL, 0, &x0);
        check(rc == AOT_FAULT_NONE, "main_scn_invoke returns cleanly");
        check(x0 == 0x4b1u,
              "HLE: nested fn(7) = 0xc8, +1000, +1 (x19..x28 intact)");
        check(g_invoke_calls == 1u, "host_invoke handler ran exactly once");
        check(g_invoke_depth_ok == 1u,
              "nested call sees depth 1 before and after");
        check(g_invoke_rc == AOT_FAULT_NONE,
              "the nested host->guest call from HLE succeeded");
        check(rt.call_depth == 0u, "call depth is back to 0 after the call");
    }

    /* ---- main_entry, end to end (review fix 3) ------------------------- */
    /* main_entry used to store through an UNINITIALISED caller-saved x2, so
     * nothing could be asserted about it. It now keeps sdk_data in x19 and the
     * whole body is executed here with exact expectations. It runs after the
     * scenario 1-5 counters were checked because it calls host_hook/nnMain. */
    {
        uint64_t entry_va = 0;
        uint64_t sdata = 0;
        uint64_t v48 = 0;
        uint64_t v24 = 0;

        check(aot_loader_symbol(&v0.loader, "main_entry", &entry_va) ==
                  AOT_LOAD_OK && entry_va != 0, "main_entry resolves");
        check(aot_loader_symbol(&v0.loader, "sdk_data", &sdata) == AOT_LOAD_OK &&
                  sdata != 0, "sdk_data resolves");
        rc = aot_call_guest(&rt, entry_va, NULL, 0u, &x0);
        check(rc == AOT_FAULT_NONE, "main_entry (PLT -> sdk/sub/hooks) returns "
                                   "cleanly");
        check(aot_mem_ld64(&mem, sdata + 48u, &v48) == AOT_MEM_OK &&
                  v48 == 3u,
              "main_entry stored sdk_add(1,2) == 3 in sdk_data+48");
        check(aot_mem_ld64(&mem, sdata + 24u, &v24) == AOT_MEM_OK &&
                  v24 != 0u,
              "main_entry stored a non-zero override thunk VA in sdk_data+24");
        check(rt.call_depth == 0u, "main_entry left the call depth at 0");
    }

    /* ---- scenario 6: module init (nn::init::Start shape) --------------- */
    {
        static const char *const init_names[MODULE_COUNT] = {
            "main_init", "sub_init", "sdk_init"
        };
        static const char *const count_names[MODULE_COUNT] = {
            "main_init_count", "sub_init_count", "sdk_init_count"
        };
        static const char *const state_names[MODULE_COUNT] = {
            "main_ctor_state", "sub_ctor_state", "sdk_ctor_state"
        };
        /* main_ctor0 +1, main_ctor1 +0x20; sub_ctor0 +3;
         * sdk_ctor_a +1, sdk_ctor_b +0x10 -- each exactly once. */
        static const uint32_t want_count[MODULE_COUNT] = { 1u + 0x20u, 3u,
                                                           1u + 0x10u };
        uint64_t sdk_start = 0;
        uint64_t log_buf = 0;
        uint64_t log_cursor = 0;
        uint64_t sargs[3];
        uint32_t t_ready, t_inits, t_finis;
        uint32_t i;

        check(aot_loader_symbol(&v0.loader, "sdk_start", &sdk_start) ==
                  AOT_LOAD_OK && sdk_start != 0, "sdk_start resolves");
        check(aot_program_is_entry(prog, sdk_start),
              "sdk_start is a translated Program entry");
        check(aot_loader_symbol(&v0.loader, "sdk_log_buf", &log_buf) ==
                  AOT_LOAD_OK && log_buf != 0, "sdk_log_buf resolves");
        check(aot_loader_symbol(&v0.loader, "sdk_log_cursor", &log_cursor) ==
                  AOT_LOAD_OK && log_cursor != 0, "sdk_log_cursor resolves");
        /* The DT_INIT VAs the handler will call must be the descriptors' and
         * each symbol's own, in module order main, sub, sdk. */
        for (i = 0u; i < MODULE_COUNT; i++) {
            uint64_t sym = 0;

            check(aot_loader_symbol(&v0.loader, init_names[i], &sym) ==
                      AOT_LOAD_OK && sym != 0, init_names[i]);
            check(v0.loader.modules[i].init_va == sym,
                  "the descriptor's DT_INIT VA is the module's init body");
        }
        /* The thunk VAs come from the generated bindings (index -> VA). */
        t_ready = binding_thunk(&g_aot_g3_v0_bindings, "fx_loader_ready");
        t_inits = binding_thunk(&g_aot_g3_v0_bindings, "fx_module_inits");
        t_finis = binding_thunk(&g_aot_g3_v0_bindings, "fx_module_finis");
        check(t_ready != 0xffffffffu && t_inits != 0xffffffffu &&
                  t_finis != 0xffffffffu,
              "the init-sequence thunk VAs are bound");
        sargs[0] = g_aot_g3_v0_bindings.thunk_base +
                   AOT_LOADER_THUNK_STRIDE * (uint64_t)t_ready;
        sargs[1] = g_aot_g3_v0_bindings.thunk_base +
                   AOT_LOADER_THUNK_STRIDE * (uint64_t)t_inits;
        sargs[2] = g_aot_g3_v0_bindings.thunk_base +
                   AOT_LOADER_THUNK_STRIDE * (uint64_t)t_finis;

        check(rt.call_depth == 0u,
              "the host calls sdk_start at call depth 0");
        rc = aot_call_guest(&rt, sdk_start, sargs, 3u, &x0);
        check(rc == AOT_FAULT_NONE, "sdk_start returns cleanly");
        check(x0 == 0x5a5au, "sdk_start marker == ready() + 1");
        check(rt.call_depth == 0u, "depth is 0 after sdk_start");

        /* ready/inits/finis call discipline (host-side record). */
        check(g_ready_calls == 1u, "loader_ready called exactly once");
        check(g_ready_arg_ok == 1u,
              "loader_ready received sdk_start's argument");
        check(g_inits_calls == 1u, "module_inits called exactly once");
        check(g_finis_calls == 0u, "module_finis is NEVER called");
        check(g_order_len == 2u && g_order[0] == 0u && g_order[1] == 1u,
              "ready is called BEFORE inits");

        /* The nested DT_INIT calls: clean returns, depth restored. */
        check(g_init_fault == 0u, "every nested DT_INIT returned cleanly");
        check(g_inits_depth == 1u,
              "the inits handler runs at depth 1 and gets it back");
        for (i = 0u; i < MODULE_COUNT; i++) {
            uint64_t sym = 0;

            aot_loader_symbol(&v0.loader, init_names[i], &sym);
            check(g_init_va_called[i] == sym,
                  "the inits handler called this module's DT_INIT");
        }

        /* The exact GLOBAL constructor order: main's ctors in init_array
         * order, then sub's, then sdk's -- appended by sdk_log. */
        {
            uint32_t cursor = 0u;
            uint32_t n = 0u;

            check(aot_mem_ld32(&mem, log_cursor, &cursor) == AOT_MEM_OK,
                  "read sdk_log_cursor");
            check(cursor == 4u * (uint32_t)5u,
                  "the ctor log holds exactly five markers");
            n = cursor / 4u;
            for (i = 0u; i < n && i < 5u; i++) {
                uint32_t id = 0xffffffffu;
                char label[96];

                if (aot_mem_ld32(&mem, log_buf + 4u * i, &id) != AOT_MEM_OK) {
                    check(0, "read an ordered-log entry");
                    break;
                }
                snprintf(label, sizeof label,
                         "global ctor order[%u] == %u (got %u)", i, i, id);
                check(id == i, label);
            }
        }

        /* Each module: its own count exactly once and ctor_state == 2. */
        for (i = 0u; i < MODULE_COUNT; i++) {
            uint64_t va = 0;
            uint32_t got = 0xffffffffu;
            char label[96];

            if (aot_loader_symbol(&v0.loader, count_names[i], &va) !=
                    AOT_LOAD_OK || va == 0) {
                check(0, count_names[i]);
                continue;
            }
            if (aot_mem_ld32(&mem, va, &got) == AOT_MEM_OK) {
                snprintf(label, sizeof label, "%s == 0x%x (got 0x%x)",
                         count_names[i], want_count[i], got);
                check(got == want_count[i], label);
            } else {
                check(0, "read a module's init count");
            }

            if (aot_loader_symbol(&v0.loader, state_names[i], &va) !=
                    AOT_LOAD_OK || va == 0) {
                check(0, state_names[i]);
                continue;
            }
            got = 0xffffffffu;
            if (aot_mem_ld32(&mem, va, &got) == AOT_MEM_OK) {
                snprintf(label, sizeof label, "%s == 2 (got %u)",
                         state_names[i], got);
                check(got == 2u, label);
            } else {
                check(0, "read a module's ctor state");
            }
        }
    }

    /* ---- scenario 7: invalid transfer targets, one host call each ----- */
    {
        uint64_t bad_blr_data = 0, bad_blr_mid = 0, bad_blr_align = 0;
        uint64_t bad_ret = 0, bad_br = 0, sdk_data_va = 0, results_va = 0;
        uint64_t main_entry_va = 0, mid_target = 0, align_target = 0;
        uint64_t targs[1];
        uint64_t thunk_hook;

        check(aot_loader_symbol(&v0.loader, "main_scn_bad_blr_data",
                                &bad_blr_data) == AOT_LOAD_OK &&
                  bad_blr_data != 0, "main_scn_bad_blr_data resolves");
        check(aot_loader_symbol(&v0.loader, "main_scn_bad_blr_mid",
                                &bad_blr_mid) == AOT_LOAD_OK &&
                  bad_blr_mid != 0, "main_scn_bad_blr_mid resolves");
        check(aot_loader_symbol(&v0.loader, "main_scn_bad_blr_align",
                                &bad_blr_align) == AOT_LOAD_OK &&
                  bad_blr_align != 0, "main_scn_bad_blr_align resolves");
        check(aot_loader_symbol(&v0.loader, "main_scn_bad_ret_thunk",
                                &bad_ret) == AOT_LOAD_OK && bad_ret != 0,
              "main_scn_bad_ret_thunk resolves");
        check(aot_loader_symbol(&v0.loader, "main_scn_bad_br_sentinel",
                                &bad_br) == AOT_LOAD_OK && bad_br != 0,
              "main_scn_bad_br_sentinel resolves");
        check(aot_loader_symbol(&v0.loader, "sdk_data", &sdk_data_va) ==
                  AOT_LOAD_OK && sdk_data_va != 0, "sdk_data resolves");
        check(aot_loader_symbol(&v0.loader, "main_results", &results_va) ==
                  AOT_LOAD_OK && results_va != 0, "main_results resolves");
        check(aot_loader_symbol(&v0.loader, "main_entry", &main_entry_va) ==
                  AOT_LOAD_OK && main_entry_va != 0, "main_entry resolves");
        thunk_hook = g_aot_g3_v0_bindings.thunk_base +
                     AOT_LOADER_THUNK_STRIDE *
                         (uint64_t)binding_thunk(&g_aot_g3_v0_bindings,
                                                 "host_hook");

        /* (a) BLR to a module DATA address -> UNKNOWN_PC */
        targs[0] = sdk_data_va;
        rc = aot_call_guest(&rt, bad_blr_data, targs, 1u, &x0);
        check(rc == AOT_FAULT_UNKNOWN_PC,
              "BLR to a module DATA address -> UNKNOWN_PC");
        check(rt.fault_src == g_aot_g3_v0_bad_blr_data_va,
              "the fault names that BLR instruction as its source");
        check(rt.fault_target == sdk_data_va,
              "the fault target is the module DATA address");
        clean_after_fault(&rt, sdk_add,
                          "a clean call still works after UNKNOWN_PC");

        /* (b) BLR to a mid-function address that is NOT a block entry ->
         *     UNTRANSLATED. The expected target comes from the module. */
        rc = aot_call_guest(&rt, bad_blr_mid, NULL, 0u, &x0);
        check(aot_mem_ld64(&mem, results_va, &mid_target) == AOT_MEM_OK &&
                  mid_target != 0, "the fixture published its mid-text target");
        check(rc == AOT_FAULT_UNTRANSLATED,
              "BLR to a mid-function text address -> UNTRANSLATED");
        check(rt.fault_src == g_aot_g3_v0_bad_blr_mid_va,
              "the fault names that BLR instruction as its source");
        check(rt.fault_target == mid_target,
              "the fault target is the published mid-text address");
        check(!aot_program_is_entry(prog, mid_target),
              "the UNTRANSLATED target is really NOT a block entry");
        check(aot_program_is_entry(prog, mid_target - 8u),
              "CONTROL: the enclosing function's first instruction IS an entry");
        clean_after_fault(&rt, sdk_add,
                          "a clean call still works after UNTRANSLATED");

        /* (c) BLR to a misaligned VA -> MISALIGNED */
        rc = aot_call_guest(&rt, bad_blr_align, NULL, 0u, &x0);
        check(aot_mem_ld64(&mem, results_va + 8u, &align_target) ==
                  AOT_MEM_OK && align_target != 0,
              "the fixture published its misaligned target");
        check(align_target == main_entry_va + 2u,
              "the published target is main_entry + 2");
        check(rc == AOT_FAULT_MISALIGNED,
              "BLR to a misaligned VA -> MISALIGNED");
        check(rt.fault_src == g_aot_g3_v0_bad_blr_align_va,
              "the fault names that BLR instruction as its source");
        check(rt.fault_target == align_target,
              "the fault target is the misaligned VA");
        clean_after_fault(&rt, sdk_add,
                          "a clean call still works after MISALIGNED");

        /* (d) RET into a host thunk -> BAD_TRANSFER */
        targs[0] = thunk_hook;
        rc = aot_call_guest(&rt, bad_ret, targs, 1u, &x0);
        check(rc == AOT_FAULT_BAD_TRANSFER,
              "RET into a thunk VA -> BAD_TRANSFER");
        check(rt.fault_src == g_aot_g3_v0_bad_ret_va,
              "the fault names the RET instruction as its source");
        check(rt.fault_target == thunk_hook,
              "the fault target is the thunk VA");
        clean_after_fault(&rt, sdk_add,
                          "a clean call still works after BAD_TRANSFER");

        /* (e) BR into the sentinel region -> BAD_RETURN */
        targs[0] = g_aot_g3_v0_bindings.sentinel;
        rc = aot_call_guest(&rt, bad_br, targs, 1u, &x0);
        check(rc == AOT_FAULT_BAD_RETURN,
              "BR to the sentinel region -> BAD_RETURN");
        check(rt.fault_src == g_aot_g3_v0_bad_br_va,
              "the fault names the BR instruction as its source");
        check(rt.fault_target == g_aot_g3_v0_bindings.sentinel,
              "the fault target is the sentinel slot");
        clean_after_fault(&rt, sdk_add,
                          "a clean call still works after BAD_RETURN");
        check(rt.call_depth == 0u, "depth is 0 after every invalid target");
    }

    /* ---- scenario 8: memory permissions ------------------------------- */
    {
        uint64_t store_ro = 0, store_text = 0, mod0 = 0;
        uint64_t ro_word = 0, entry_va = 0;

        check(aot_loader_symbol(&v0.loader, "main_scn_store_ro", &store_ro) ==
                  AOT_LOAD_OK && store_ro != 0, "main_scn_store_ro resolves");
        check(aot_loader_symbol(&v0.loader, "main_scn_store_text",
                                &store_text) == AOT_LOAD_OK &&
                  store_text != 0, "main_scn_store_text resolves");
        check(aot_loader_symbol(&v0.loader, "main_scn_mod0_magic", &mod0) ==
                  AOT_LOAD_OK && mod0 != 0, "main_scn_mod0_magic resolves");
        check(aot_loader_symbol(&v0.loader, "main_ro_word", &ro_word) ==
                  AOT_LOAD_OK && ro_word != 0, "main_ro_word resolves");
        check(aot_loader_symbol(&v0.loader, "main_entry", &entry_va) ==
                  AOT_LOAD_OK && entry_va != 0, "main_entry resolves");

        /* store to main's OWN rodata: R only -> MEMORY / PERM, exact address */
        rc = aot_call_guest(&rt, store_ro, NULL, 0u, &x0);
        check(rc == AOT_FAULT_MEMORY,
              "a store to main's rodata -> FAULT_MEMORY");
        check(rt.fault_status == AOT_MEM_ERR_PERM,
              "rodata store status == AOT_MEM_ERR_PERM");
        check(rt.fault_target == ro_word,
              "the rodata store reports main_ro_word's exact VA");
        clean_after_fault(&rt, sdk_add,
                          "a clean call still works after the rodata store");

        /* store to main's OWN text: R-X -> MEMORY / PERM, exact address */
        rc = aot_call_guest(&rt, store_text, NULL, 0u, &x0);
        check(rc == AOT_FAULT_MEMORY,
              "a store to main's text -> FAULT_MEMORY");
        check(rt.fault_status == AOT_MEM_ERR_PERM,
              "text store status == AOT_MEM_ERR_PERM");
        check(rt.fault_target == entry_va,
              "the text store reports main_entry's exact VA");
        clean_after_fault(&rt, sdk_add,
                          "a clean call still works after the text store");

        /* ... while the SAME text stays readable as data (MOD0 header). */
        rc = aot_call_guest(&rt, mod0, NULL, 0u, &x0);
        check(rc == AOT_FAULT_NONE, "the MOD0 magic load returns cleanly");
        check(x0 == 0x30444f4du,
              "ADRP/ADD + ldr w of main's MOD0 magic is the MOD0 word");
    }

    /* ---- scenario 9: SYSREG (CNTPCT_EL0) from 4 host threads ---------- */
    {
        uint64_t tick_va = 0;
        TickJob jobs[TICK_THREADS];
        host_thread th[TICK_THREADS];
        uint32_t i;
        LONG before;

        check(aot_loader_symbol(&v0.loader, "main_scn_tick", &tick_va) ==
                  AOT_LOAD_OK && tick_va != 0, "main_scn_tick resolves");
        check(aot_program_is_entry(prog, tick_va),
              "main_scn_tick is a translated Program entry");
        before = InterlockedCompareExchange(&g_tick_calls, 0, 0);
        rc = aot_call_guest(&rt, tick_va, NULL, 0u, &x0);
        check(rc == AOT_FAULT_NONE, "main -> sdk_tick (PLT) returns cleanly");
        check(x0 != 0u, "CNTPCT_EL0 yields a non-zero tick value");
        check(InterlockedCompareExchange(&g_tick_calls, 0, 0) == before + 1,
              "the CNTPCT handler ran exactly once for the single call");

        for (i = 0u; i < TICK_THREADS; i++) {
            memset(&jobs[i], 0, sizeof jobs[i]);
            jobs[i].program = prog;
            jobs[i].as = v0.as;
            jobs[i].entry = tick_va;
            jobs[i].sp = TICK_STACK_BASE + (uint64_t)(i + 1u) * STACK_SIZE;
            memset(&th[i], 0, sizeof th[i]);
            check(host_thread_create(&th[i], tick_thread, &jobs[i]) ==
                      HOST_THREAD_OK, "a scenario-9 host thread starts");
        }
        for (i = 0u; i < TICK_THREADS; i++) {
            int joined = 0;

            check(host_thread_join(&th[i], 60000u, &joined) ==
                      HOST_THREAD_OK && joined == 1,
                  "the scenario-9 host thread joins");
        }
        for (i = 0u; i < TICK_THREADS; i++) {
            check(jobs[i].calls == 1000u,
                  "each thread ran exactly 1000 guest entries");
            check(jobs[i].bad == 0u,
                  "every thread tick was non-zero and non-decreasing");
            /* A clock that never advances (constant handler) is a WRONG
             * implementation, so monotonic-only is not enough (fix 8). */
            check(jobs[i].last > jobs[i].first,
                  "each thread's tick STRICTLY advanced (a constant clock "
                  "fails)");
        }
        check(InterlockedCompareExchange(&g_tick_calls, 0, 0) ==
                  before + 1 + (LONG)(TICK_THREADS * 1000u),
              "the CNTPCT handler ran exactly 4000 times across 4 threads");
    }

    /* ---- major 1: a page-straddling STP writes NOTHING -------------------
     * The last page of the guest stack is made inaccessible (---) after the
     * seal, so a 16-byte pair store placed at [page_end-8, page_end+8) has its
     * first half in a RW page and its second half in an inaccessible one. The
     * hardware faults BEFORE writing either half, so the single-access lowering
     * must report the PERM fault at the pair's BASE address and leave the RW
     * page byte-identical. The old two-store lowering writes the first half and
     * reports the SECOND address (mutant `stp_split`). ---------------------- */
    {
        uint64_t pair_va = 0;
        const uint64_t page = STACK_TOP - PAGE_SIZE;
        const uint64_t straddle = page - 8u;   /* first half = last 8 of RW */
        uint64_t before = 0, after = 0;

        check(aot_as_protect(v0.as, page, PAGE_SIZE, AOT_AS_PERM_NONE) ==
                  AOT_MEM_OK,
              "the top stack page can be made inaccessible");
        check(aot_loader_symbol(&v0.loader, "main_scn_pair_straddle",
                                &pair_va) == AOT_LOAD_OK && pair_va != 0,
              "main_scn_pair_straddle resolves");
        check(aot_program_is_entry(prog, pair_va),
              "main_scn_pair_straddle is a translated Program entry");
        if (aot_mem_ld64(&mem, straddle, &before) != AOT_MEM_OK) {
            fatal("read the straddle page (before)");
        }
        {
            uint64_t sargs[1];
            sargs[0] = straddle;
            rc = aot_call_guest(&rt, pair_va, sargs, 1u, &x0);
        }
        check(rc == AOT_FAULT_MEMORY,
              "a page-straddling STP -> FAULT_MEMORY");
        check(rt.fault_status == AOT_MEM_ERR_PERM,
              "the straddling pair's status is AOT_MEM_ERR_PERM");
        check(rt.fault_target == straddle,
              "the fault reports the PAIR's base address, not base+8");
        if (aot_mem_ld64(&mem, straddle, &after) != AOT_MEM_OK) {
            fatal("read the straddle page (after)");
        }
        check(before == after,
              "a faulting straddling STP wrote ZERO bytes of the RW page");
        check(aot_as_protect(v0.as, page, PAGE_SIZE, AOT_AS_PERM_RW) ==
                  AOT_MEM_OK,
              "the stack page is restored to RW");
    }

    aot_rt_release(&rt);

    /* ---- major 2: the loader stages are ONE-SHOT; refused stages must leave
     * the sealed program byte-identical and still runnable ---------------- */
    {
        AotLoadError rerr;

        check(aot_loader_map(&v0.loader, v0.images, v0.sizes, &rerr) ==
                  AOT_LOAD_ERR_STATE,
              "map after seal is refused (STATE)");
        check(aot_loader_relocate(&v0.loader, &rerr) == AOT_LOAD_ERR_STATE,
              "relocate after seal is refused (STATE)");
        check(aot_loader_seal(&v0.loader, &rerr) == AOT_LOAD_ERR_STATE,
              "a second seal is refused (STATE)");
        check(aot_loader_load(&v0.loader, v0.images, v0.sizes, &rerr) ==
                  AOT_LOAD_ERR_STATE,
              "a second load is refused (STATE)");
        check(aot_as_is_poisoned(v0.as) == 0,
              "the refused stages never poisoned the sealed space");
        check(aot_as_is_sealed(v0.as) == 1, "the space is still sealed");
    }

    /* ---- negative: link-only (relr) descriptors are not executable ------ */
    if (!load_variant(&relr, dir, g_aot_g3_relr_modules,
                      g_aot_g3_relr_module_count, &g_aot_g3_relr_bindings)) {
        fatal("loading the relr fixtures");
    }
    prog_relr = aot_program_create(relr.as);
    if (prog_relr == NULL) {
        fatal("program create (relr)");
    }
    st = aot_loader_build_program(&relr.loader, prog_relr, THUNK_COUNT,
                                  g_aot_g3_relr_bindings.sentinel,
                                  SENTINEL_COUNT, &err);
    check(st == AOT_LOAD_ERR_ARG,
          "link-only descriptors (image == NULL) are refused (ARG)");
    aot_program_destroy(prog_relr);

    /* ---- negative: wrong image/descriptor pairing ----------------------- */
    wrong_pairing_check(dir);

    /* ---- Program assembly gates and the poison gate -------------------- */
    build_program_shape_check(dir);

    aot_program_destroy(prog);
    release_variant(&v0);
    release_variant(&relr);

    if (g_fail) {
        printf("aot_g3_exec_probe: FAILED\n");
        return 2;
    }
    printf("aot_g3_exec_probe: OK\n");
    return 0;
}
