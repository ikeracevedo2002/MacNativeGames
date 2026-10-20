/* G3 increment 4, item D: execute a REAL TotK 1.0.0 slice through the AOT
 * Program, locally only.
 *
 * The modules, flats, generated descriptors, translated AotImages and the
 * bindings table all live OUTSIDE this repository (C:/Users/IKER/mn-g3-local
 * on this machine); nothing here contains game data. The build compiles this
 * probe only when MN_TOTK_V0_DIR is set.
 *
 * What it proves, on real bytes:
 *   1. three real NSO modules load, relocate and seal with the reference link
 *      digest (the link itself is covered by aot_g3_real_link);
 *   2. aot_loader_build_program assembles a Program from the two translated
 *      modules (main + sdk) and tolerates the third as LINK-ONLY
 *      (subsdk0: loaded/relocated/sealed, no code translated, never entered);
 *   3. aot_call_guest(main + 0x2aa46e0) runs the real PLT stub
 *      (ADRP; LDR; ADD; BR) whose GOT slot holds sdk + 0x129640, and the sdk
 *      block executes MRS CNTPCT_EL0 through the host SYSREG handler;
 *   4. four host threads x 1000 entries, each with its own AotRuntime and its
 *      own guest stack, all return cleanly with ticks > 0 that do not go
 *      backwards, and the handler sees exactly 4000 calls;
 *   5. NEGATIVE CONTROL: the same main image declared at a WRONG guest base
 *      (+0x1000) is rejected by build_program (code range outside text)
 *      BEFORE any guest instruction runs.
 *
 * Usage: aot_g3_real_exec_probe <dir-with-*.flat>
 *        aot_g3_real_exec_probe <dir> --wrong-base   (negative control only)
 */

#include "aot_as.h"
#include "aot_loader.h"
#include "aot_mem.h"
#include "aot_runtime.h"

#include "host_thread.h"
#include "host_time.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/* Generated for variant "real" under MN_TOTK_V0_DIR. */
extern const AotModuleDesc g_aot_g3_real_modules[];
extern const uint32_t g_aot_g3_real_module_count;
extern const AotHostBindings g_aot_g3_real_bindings;

#define MAIN_BASE 0x1000000000ull
#define MAIN_STUB_OFF 0x2aa46e0ull   /* GetSystemTick PLT stub in main */
#define MAIN_GOT_SLOT 0x453f1e8ull   /* the stub's LDR target (JUMP_SLOT site) */
#define SDK_BASE 0x1020000000ull
#define SDK_TICK_OFF 0x129640ull     /* GetSystemTick: mrs x0, cntpct_el0; ret */

#define THREADS 4u
#define ITERS 1000u
#define STACK_BASE 0x2000000000ull
#define STACK_SIZE 0x4000ull

/* The ONLY module without translated code in this slice. It is named here (not
 * "any module with a NULL image"): build_program accepts a NULL image only for
 * a module on this list. */
static const char *const LINK_ONLY[] = { "subsdk0_real" };
#define LINK_ONLY_COUNT 1u
/* A subsdk0 address to try to enter: its DT_INIT. There is no block for it and
 * subsdk0 has no image, so dispatch must refuse with UNKNOWN_PC. */
#define SUBSDK0_INIT_VA 0x1010000030ull

/* Upper bound for the shifted range copy in the negative control. */
#define AOT_MAX_CODE_RANGES_LOCAL 8u

static volatile LONG g_tick_calls;
static int g_failures;

static void check(int cond, const char *what)
{
    if (!cond) {
        printf("FAIL: %s\n", what);
        g_failures++;
    }
}

static double now_ms(void)
{
    LARGE_INTEGER f, c;

    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&c);
    return (double)c.QuadPart * 1000.0 / (double)f.QuadPart;
}

static uint8_t *read_file(const char *path, uint64_t *size)
{
    FILE *f = NULL;
    long len;
    uint8_t *buf = NULL;

#if defined(_MSC_VER)
    if (fopen_s(&f, path, "rb") != 0) {
        f = NULL;
    }
#else
    f = fopen(path, "rb");
#endif
    if (f == NULL) {
        printf("FATAL: cannot open %s\n", path);
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0 || (len = ftell(f)) <= 0 ||
        fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        printf("FATAL: cannot size %s\n", path);
        return NULL;
    }
    buf = (uint8_t *)malloc((size_t)len);
    if (buf == NULL || fread(buf, 1u, (size_t)len, f) != (size_t)len) {
        fclose(f);
        free(buf);
        printf("FATAL: cannot read %s\n", path);
        return NULL;
    }
    fclose(f);
    *size = (uint64_t)len;
    return buf;
}

/* A57 CNTFRQ_EL0 is 19.2 MHz: ticks = ns * 12 / 625. */
static void hle_sysreg_cntpct(AotRuntime *rt, AotGuestState *s,
                              const AotHleRequest *req, void *user)
{
    uint64_t ns = 0;

    (void)rt;
    (void)user;
    if (AOT_SYSREG_ID_FIELD(req->id) != AOT_SYSREG_CNTPCT_EL0 ||
        host_time_now_ns(&ns) != HOST_TIME_OK) {
        aot_sysreg_write_dest(s, req, 0u);
        return;
    }
    InterlockedIncrement(&g_tick_calls);
    aot_sysreg_write_dest(s, req, ns / 52u + (ns % 52u) * 12u / 625u);
}

typedef struct Job {
    AotProgram *program;
    AotAddressSpace *as;
    uint64_t entry;
    uint64_t sp;
    uint32_t calls;
    uint32_t bad;
    uint32_t flat;   /* iterations whose tick did not STRICTLY advance */
    uint64_t first;
    uint64_t last;
} Job;

/* Each thread owns its AotRuntime (single-owner state) and its own guest
 * stack region; the Program and the address space are shared. */
static void run_thread(void *arg)
{
    Job *j = (Job *)arg;
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
    for (i = 0u; i < ITERS; i++) {
        uint64_t x0 = 0;

        if (aot_call_guest(&rt, j->entry, NULL, 0u, &x0) != AOT_FAULT_NONE) {
            j->bad++;
            continue;
        }
        if (x0 == 0u || x0 < j->last) {
            j->bad++;
        }
        /* CNTPCT is a free-running counter at 19.2 MHz: 1000 calls in a tight
         * loop MUST advance, so a non-advancing tick means the handler returned
         * a constant (e.g. a stale or zero value). */
        if (i != 0u && x0 <= j->last) {
            j->flat++;
        }
        if (i == 0u) {
            j->first = x0;
        }
        j->last = x0;
        j->calls++;
    }
    aot_rt_release(&rt);
}

/* Load `count` real modules from `dir` into a fresh address space + loader.
 * The flats are named "<descriptor name>.flat" by the reference linker.
 * `link_only`/`link_only_count` are handed to aot_loader_set_link_only. */
static int load_real(AotAddressSpace **out_as, AotLoader *loader,
                     const AotModuleDesc *mods, uint32_t count,
                     uint8_t **owned, uint64_t *sizes, const char *dir,
                     const char *const *link_only, uint32_t link_only_count)
{
    AotLoadError err;
    AotMemDomain *domain;
    uint32_t i;

    for (i = 0u; i < count; i++) {
        char path[512];
        int n = snprintf(path, sizeof path, "%s/%s.flat", dir, mods[i].name);

        if (n <= 0 || (size_t)n >= sizeof path) {
            printf("FATAL: path too long\n");
            return 0;
        }
        owned[i] = read_file(path, &sizes[i]);
        if (owned[i] == NULL) {
            return 0;
        }
    }
    domain = aot_mem_domain_create();
    if (domain == NULL) {
        printf("FATAL: aot_mem_domain_create\n");
        return 0;
    }
    *out_as = aot_as_create(domain);
    if (*out_as == NULL) {
        printf("FATAL: aot_as_create\n");
        return 0;
    }
    {
        AotModuleSet set;
        static AotModuleSet keep;

        set.modules = mods;
        set.count = count;
        keep = set;
        if (aot_loader_init(loader, *out_as, &keep, &err) != AOT_LOAD_OK) {
            printf("FATAL: loader init: %s\n", err.detail);
            return 0;
        }
    }
    /* One RW guest stack per host thread, reserved before the seal: seal
     * freezes the region table and applies the declared permissions. */
    for (i = 0u; i < THREADS; i++) {
        if (aot_as_add_region(loader->as,
                              STACK_BASE + (uint64_t)i * STACK_SIZE,
                              STACK_SIZE, AOT_AS_PERM_RW, AOT_AS_STATE_DATA,
                              NULL) != AOT_MEM_OK) {
            printf("FATAL: aot_as_add_region(stack %u)\n", i);
            return 0;
        }
    }
    aot_loader_set_host_bindings(loader, &g_aot_g3_real_bindings);
    /* subsdk0 has no translated image: DECLARE it link-only by name. Every
     * other module must still carry an image or build_program refuses the set. */
    aot_loader_set_link_only(loader, link_only, link_only_count);
    if (aot_loader_load(loader, (const uint8_t *const *)owned, sizes, &err) !=
        AOT_LOAD_OK) {
        printf("FATAL: loader load: %s (module %d)\n", err.detail,
               (int)err.module);
        return 0;
    }
    return 1;
}

/* Negative control 2: the link-only declaration is NARROW. With the CORRECT
 * descriptors but an EMPTY link-only list, build_program must REFUSE the set on
 * subsdk0 (module 1) instead of silently skipping it -- i.e. "no image" is only
 * tolerated for a module the caller named. */
static int link_only_narrow_negative(const char *dir)
{
    AotAddressSpace *as = NULL;
    AotLoader loader;
    AotProgram *p;
    AotLoadError err;
    uint8_t *owned[3] = { NULL, NULL, NULL };
    uint64_t sizes[3] = { 0u, 0u, 0u };
    uint64_t thunks;
    AotLoadStatus st;
    int ok = 0;

    if (!load_real(&as, &loader, g_aot_g3_real_modules, 3u, owned, sizes, dir,
                   NULL, 0u)) {
        check(0, "link-only control: the load itself still succeeds");
        return 0;
    }
    p = aot_program_create(as);
    if (p == NULL) {
        check(0, "link-only control: program create");
        aot_loader_release(&loader);
        return 0;
    }
    thunks = (uint64_t)g_aot_g3_real_bindings.override_count +
             (uint64_t)g_aot_g3_real_bindings.observer_count;
    st = aot_loader_build_program(&loader, p, thunks,
                                  g_aot_g3_real_bindings.sentinel,
                                  (uint64_t)AOT_MAX_CALL_DEPTH, &err);
    printf("negative-control(no link-only declaration): status=%s module=%d "
           "detail=%s\n", aot_load_status_name((int)st), (int)err.module,
           err.detail != NULL ? err.detail : "(none)");
    check(st == AOT_LOAD_ERR_ARG,
          "an undeclared NULL image is refused as AOT_LOAD_ERR_ARG");
    check(err.module == 1u, "rejection names module 1 (subsdk0)");
    check(err.detail != NULL && strstr(err.detail, "link-only") != NULL,
          "rejection names the missing link-only declaration");
    ok = 1;
    aot_program_destroy(p);
    aot_loader_release(&loader);
    return ok;
}

/* Negative control: the main image is "translated for base + 0x1000", i.e.
 * its code ranges sit 0x1000 above the ones the descriptor's text segment
 * allows. build_program must refuse the set (AOT_LOAD_ERR_LAYOUT, "code
 * range") BEFORE anything enters the guest. The image struct is borrowed and
 * const, so this builds a shifted copy over a local range array. */
static int wrong_base_negative(const char *dir)
{
    extern const AotImage aot_image_real_main;
    AotModuleDesc mods[3];
    AotCodeRange shifted[AOT_MAX_CODE_RANGES_LOCAL];
    AotImage img = aot_image_real_main;
    AotLoadError neg_err;
    AotAddressSpace *as = NULL;
    AotLoader loader;
    AotProgram *neg;
    uint8_t *owned[3] = { NULL, NULL, NULL };
    uint64_t sizes[3] = { 0u, 0u, 0u };
    uint64_t thunks;
    AotLoadStatus st;
    uint32_t i;

    /* A LOADER BORROWS THE DESCRIPTOR ARRAY, so the wrong descriptor must be
     * the one the loader is given: copy the set and shift ONLY main's image
     * ranges (its data/text layout, bases and SHA-256 stay correct, which is
     * exactly the "translated for base + 0x1000" mistake). */
    for (i = 0u; i < 3u; i++) {
        mods[i] = g_aot_g3_real_modules[i];
    }
    if (img.range_count > AOT_MAX_CODE_RANGES_LOCAL) {
        check(0, "negative control: range count fits the local array");
        return 0;
    }
    for (i = 0u; i < (uint32_t)img.range_count; i++) {
        shifted[i].start = img.ranges[i].start + 0x1000u;
        shifted[i].end = img.ranges[i].end + 0x1000u;
    }
    img.ranges = shifted;
    mods[0].image = &img;
    if (!load_real(&as, &loader, mods, 3u, owned, sizes, dir, LINK_ONLY,
                   LINK_ONLY_COUNT)) {
        check(0, "negative control: the load itself still succeeds");
        return 0;
    }
    neg = aot_program_create(as);
    if (neg == NULL) {
        check(0, "negative control: program create");
        return 0;
    }
    thunks = (uint64_t)g_aot_g3_real_bindings.override_count +
             (uint64_t)g_aot_g3_real_bindings.observer_count;
    st = aot_loader_build_program(&loader, neg, thunks,
                                  g_aot_g3_real_bindings.sentinel,
                                  (uint64_t)AOT_MAX_CALL_DEPTH, &neg_err);
    printf("negative-control(wrong base +0x1000): status=%s module=%d "
           "detail=%s\n", aot_load_status_name((int)st), (int)neg_err.module,
           neg_err.detail != NULL ? neg_err.detail : "(none)");
    check(st == AOT_LOAD_ERR_LAYOUT,
          "wrong-base image is rejected as AOT_LOAD_ERR_LAYOUT");
    check(neg_err.module == 0u, "rejection names module 0 (main)");
    check(neg_err.detail != NULL && strstr(neg_err.detail, "code range") != NULL,
          "rejection names the code range");
    aot_program_destroy(neg);
    aot_loader_release(&loader);
    return 1;
}

int main(int argc, char **argv)
{
    const char *dir;
    uint8_t *owned[3] = { NULL, NULL, NULL };
    uint64_t sizes[3] = { 0u, 0u, 0u };
    AotAddressSpace *as = NULL;
    AotLoader loader;
    AotProgram *prog;
    AotLoadError err;
    AotMem mem;
    AotRuntime rt;
    AotGuestState st;
    uint64_t thunks;
    uint32_t i;
    double t0;
    int wrong_base_only;

    if (argc < 2) {
        printf("usage: %s <dir-with-flats> [--wrong-base]\n", argv[0]);
        return 2;
    }
    dir = argv[1];
    if (g_aot_g3_real_module_count != 3u) {
        printf("FATAL: expected 3 real modules\n");
        return 2;
    }

    wrong_base_only = (argc > 2 && strcmp(argv[2], "--wrong-base") == 0);

    if (wrong_base_only) {
        link_only_narrow_negative(dir);
        wrong_base_negative(dir);
        printf("real-exec negative control: %s\n",
               g_failures == 0 ? "OK" : "FAILED");
        return g_failures == 0 ? 0 : 1;
    }

    /* ---- 1. load + link the three real modules -------------------------- */
    t0 = now_ms();
    if (!load_real(&as, &loader, g_aot_g3_real_modules,
                   g_aot_g3_real_module_count, owned, sizes, dir, LINK_ONLY,
                   LINK_ONLY_COUNT)) {
        return 2;
    }
    printf("load+link: %.1f ms (%u sites), digest_matched=%d\n",
           now_ms() - t0, (unsigned)loader.site_count, loader.digest_matched);
    check(loader.site_count == 558865u, "site count is the reference count");
    check(loader.digest_matched == 1, "link digest matched");

    /* ---- 2. Program: main + sdk translated, subsdk0 link-only ----------- */
    prog = aot_program_create(as);
    if (prog == NULL) {
        printf("FATAL: program create\n");
        return 2;
    }
    thunks = (uint64_t)g_aot_g3_real_bindings.override_count +
             (uint64_t)g_aot_g3_real_bindings.observer_count;
    t0 = now_ms();
    if (aot_loader_build_program(&loader, prog, thunks,
                                 g_aot_g3_real_bindings.sentinel,
                                            (uint64_t)AOT_MAX_CALL_DEPTH,
                                 &err) != AOT_LOAD_OK) {
        printf("FATAL: build_program: %s (module %d)\n", err.detail,
               (int)err.module);
        return 2;
    }
    printf("build_program: %.1f ms (thunks %u, sentinel 0x%llx)\n",
           now_ms() - t0, (unsigned)thunks,
           (unsigned long long)g_aot_g3_real_bindings.sentinel);
    check(thunks == 177u, "thunk count is the real bindings' count");
    if (aot_program_set_handler(prog, AOT_HLE_SYSREG,
                                AOT_SYSREG_ID(AOT_SYSREG_CNTPCT_EL0, 0u),
                                hle_sysreg_cntpct, NULL) != 0) {
        printf("FATAL: handler registration\n");
        return 2;
    }
    if (aot_program_finalize(prog) != AOT_FAULT_NONE) {
        printf("FATAL: program finalize\n");
        return 2;
    }

    /* ---- 3. one traced call: main stub -> GOT -> sdk GetSystemTick ------ */
    if (aot_mem_init_aspace(&mem, as) != AOT_MEM_OK) {
        printf("FATAL: aot_mem_init_aspace\n");
        return 2;
    }
    memset(&rt, 0, sizeof rt);
    memset(&st, 0, sizeof st);
    st.sp = STACK_BASE + STACK_SIZE;
    if (aot_rt_init_program(&rt, prog, mem, &st, 100000u) != AOT_FAULT_NONE) {
        printf("FATAL: aot_rt_init_program\n");
        return 2;
    }
    {
        uint64_t x0 = 0;
        uint64_t got = 0;
        uint32_t rc;

        rt.trace_enabled = 1;
        rc = aot_call_guest(&rt, MAIN_BASE + MAIN_STUB_OFF, NULL, 0u, &x0);
        check(rc == AOT_FAULT_NONE, "traced call returns cleanly");
        check(x0 != 0u, "traced call leaves ticks in x0");
        if (aot_mem_ld64(&mem, MAIN_BASE + MAIN_GOT_SLOT, &got) != AOT_MEM_OK) {
            printf("FATAL: reading the GOT slot\n");
            return 2;
        }
        printf("traced: rc=%u x0=%llu got=0x%llx want 0x%llx trace=%u\n",
               rc, (unsigned long long)x0, (unsigned long long)got,
               (unsigned long long)(SDK_BASE + SDK_TICK_OFF),
               (unsigned)rt.trace_count);
        check(got == SDK_BASE + SDK_TICK_OFF,
              "GOT slot holds sdk + 0x129640");
        check(rt.trace_count >= 2u &&
              rt.trace[0] == MAIN_BASE + MAIN_STUB_OFF &&
              rt.trace[1] == SDK_BASE + SDK_TICK_OFF,
              "trace is main stub -> sdk GetSystemTick");
        check(InterlockedCompareExchange(&g_tick_calls, 0, 0) == 1,
              "the traced call used the CNTPCT handler exactly once");
    }
    aot_rt_release(&rt);

    /* ---- 4. four host threads x 1000 entries --------------------------- */
    /* The per-thread stacks were reserved inside load_real(), before the
     * seal; the space must now refuse to grow. */
    check(aot_as_add_region(as, STACK_BASE + THREADS * STACK_SIZE, STACK_SIZE,
                            AOT_AS_PERM_RW, AOT_AS_STATE_DATA, NULL) !=
          AOT_MEM_OK, "a sealed space refuses a new region");
    {
        AotMem m0;
        uint64_t probe_val = 0u;

        if (aot_mem_init_aspace(&m0, as) != AOT_MEM_OK ||
            aot_mem_st64(&m0, STACK_BASE, 0x1122334455667788ull) !=
            AOT_MEM_OK ||
            aot_mem_ld64(&m0, STACK_BASE, &probe_val) != AOT_MEM_OK) {
            printf("FATAL: the guest stack region is not writable\n");
            return 2;
        }
        check(probe_val == 0x1122334455667788ull, "stack region is RW");
    }

    {
        static Job jobs[THREADS];
        host_thread th[THREADS];
        int joined = 0;
        LONG before = InterlockedCompareExchange(&g_tick_calls, 0, 0);
        LONG after;

        memset(jobs, 0, sizeof jobs);
        for (i = 0u; i < THREADS; i++) {
            jobs[i].program = prog;
            jobs[i].as = as;
            jobs[i].entry = MAIN_BASE + MAIN_STUB_OFF;
            jobs[i].sp = STACK_BASE + STACK_SIZE -
                         (uint64_t)(i + 1u) * 0x100u;
            if (host_thread_create(&th[i], run_thread, &jobs[i]) !=
                HOST_THREAD_OK) {
                printf("FATAL: host_thread_create %u\n", i);
                return 2;
            }
        }
        for (i = 0u; i < THREADS; i++) {
            int ok = 0;

            if (host_thread_join(&th[i], 120000u, &ok) == HOST_THREAD_OK &&
                ok) {
                joined++;
            }
        }
        after = InterlockedCompareExchange(&g_tick_calls, 0, 0);
        printf("threads: %u joined, handler calls %ld (this run)\n",
               (unsigned)joined, (long)(after - before));
        check(joined == (int)THREADS, "all threads joined");
        check((after - before) == (LONG)(THREADS * ITERS),
              "the handler saw exactly THREADS*ITERS calls");
        for (i = 0u; i < THREADS; i++) {
            check(jobs[i].bad == 0u, "thread had no bad iteration");
            check(jobs[i].calls == ITERS, "thread ran every iteration");
            check(jobs[i].first > 0u, "first tick is positive");
            check(jobs[i].last >= jobs[i].first,
                  "ticks are non-decreasing per thread");
            check(jobs[i].flat == 0u,
                  "ticks STRICTLY advance on every iteration per thread");
            printf("thread %u: calls=%u first=%llu last=%llu bad=%u flat=%u\n",
                   (unsigned)i, (unsigned)jobs[i].calls,
                   (unsigned long long)jobs[i].first,
                   (unsigned long long)jobs[i].last,
                   (unsigned)jobs[i].bad, (unsigned)jobs[i].flat);
        }
    }

    /* ---- 5. a transfer into the LINK-ONLY module must fault ------------- */
    /* subsdk0 was loaded, relocated and sealed but has no translated code and
     * no image code range: entering its DT_INIT must be refused, never
     * executed. Run LAST because a fault makes the Program sticky. */
    {
        AotMem lmem;
        AotRuntime lrt;
        AotGuestState lst;
        uint64_t x0 = 0u;
        uint32_t rc;

        if (aot_mem_init_aspace(&lmem, as) != AOT_MEM_OK) {
            printf("FATAL: aot_mem_init_aspace (link-only check)\n");
            return 2;
        }
        memset(&lrt, 0, sizeof lrt);
        memset(&lst, 0, sizeof lst);
        lst.sp = STACK_BASE + STACK_SIZE;
        if (aot_rt_init_program(&lrt, prog, lmem, &lst, 1000u) !=
            AOT_FAULT_NONE) {
            printf("FATAL: aot_rt_init_program (link-only check)\n");
            return 2;
        }
        rc = aot_call_guest(&lrt, SUBSDK0_INIT_VA, NULL, 0u, &x0);
        printf("link-only transfer: 0x%llx -> rc=%u (AOT_FAULT_UNKNOWN_PC=%u)\n",
               (unsigned long long)SUBSDK0_INIT_VA, rc,
               (unsigned)AOT_FAULT_UNKNOWN_PC);
        check(rc == AOT_FAULT_UNKNOWN_PC,
              "a transfer into the link-only module faults as UNKNOWN_PC");
        aot_rt_release(&lrt);
    }

    aot_loader_release(&loader);
    printf("real-exec: %s\n", g_failures == 0 ? "OK" : "FAILED");
    return g_failures == 0 ? 0 : 1;
}
