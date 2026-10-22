/* G3 faithful-start prefix partial-AOT first-fault probe (no game data).
 *
 * Calls the ORIGINAL nn::init::Start (sdk+0xfa060) with the Mac boot shape:
 *   Start(main_handle, 0, loader_ready, module_inits, module_finis)
 * The callbacks are guest-VA thunks (AOT_HLE_HOSTCALL), never host function
 * pointers. main_handle is an opaque REGISTERED handle created by the harness
 * (Mac threads_main_init shape); the harness never writes the owner field.
 * Guest code (nnosInitialize) may install a new ThreadType or initialize the
 * dummy in place; the harness only logs [[TLR+0x1f8]+0x1b0] before/after and
 * asserts the main handle once the original nnosInitialize has returned.
 *
 * module_inits runs the three real DT_INITs nested in main/sub/sdk order in
 * the same address space; fini is an unexpected-path failure. The run stops
 * at the first real AOT/SVC blocker BEFORE executing nnMain (no G4). It never
 * fabricates SVC success: an unhandled SVC is typed BAD_HLE with its id/site.
 *
 * Original G3 DT_INIT probe text follows.
 *
 * Loads the three real TotK 1.0.0 modules from a directory of flats, runs the
 * generated (possibly PARTIAL) translated images and calls each module's
 * DT_INIT through aot_call_guest. It prints one machine-readable STOP line:
 *
 *   STOP <module> code=<n> src=0x<hex> status=<n>
 *
 * code is the AotFault value. For AOT_FAULT_UNSUPPORTED_INSN (16) the source
 * PC is the exact guest instruction that ended its block and status indexes
 * the offline metadata table emitted by aot_translate.py --meta-out (raw word
 * and decoder reason). The runtime never decodes or executes anything itself.
 *
 * Usage: aot_g3_dtinit_probe <dir-with-*.flat> [--module NAME]
 */

#include "aot_as.h"
#include "aot_loader.h"
#include "aot_mem.h"
#include "aot_runtime.h"
#include "host_time.h"
#include "host_random.h"
#include "host_vm.h"
#include "g3_start_hle.h"
#include "g4_romfs_start_hle.h"

#include <stdio.h>
#include <windows.h>
#include <stdlib.h>
#include <string.h>

/* Generated for variant "real" (emit-desc) in the external work dir. */
extern const AotModuleDesc g_aot_g3_real_modules[];
extern const uint32_t g_aot_g3_real_module_count;
extern const AotHostBindings g_aot_g3_real_bindings;
/* Generated OUTSIDE the source tree by tools/aot/g4_romfs_config.py. NULL
 * keeps G4 RomFS disabled (the default). The compile-only object target does
 * not link this definition. */
extern const romfs_provider_config *const g_g4_romfs_start_config;

#define STACK_BASE 0x2000000000ull
#define STACK_SIZE 0x40000ull
/* The ORIGINAL nn::init::Start path queries sdk+0x158318 with r2=current SP.
 * Mac services.c 0x06 reports the native current stack as state 0xb/RW; this
 * probe-owned main-stack region carries that state explicitly. The immutable
 * global stack arena below remains Free/NONE (it is a different object). */
#define STACK_STATE 0xbu
/* Minimal faithful per-thread guest environment (Mac loader.c
 * runtime_thread_init): 8192 zero TLS bytes, 0x200 zero TLR bytes, 0x400
 * zero dummy bytes, and [TLR+0x1f8] = dummy guest VA. These are GUEST VAs in
 * RW data regions, never host pointers; no signal stack is needed because
 * guest faults are typed software faults. */
#define ENV_TLS_BASE    0x3000000000ull
#define ENV_TLS_SIZE    0x2000ull      /* page-rounded 8192 */
#define ENV_TLR_BASE    0x3000002000ull
#define ENV_TLR_SIZE    0x1000ull      /* page-rounded 0x200 */
#define ENV_DUMMY_BASE  0x3000003000ull
#define ENV_DUMMY_SIZE  0x1000ull      /* page-rounded 0x400 */
#define ENV_SLOT_OFF    0x1f8ull       /* TLR[0x1f8] = dummy */
#define STEP_BUDGET 50000000ull

/* Probe-owned boot heap profile (D018 Candidate): [256GiB, 260GiB) with the
 * Mac HEAP_CAP maximum. It is registered RESERVE-ONLY before the loader seal;
 * commit_limit is the checked Mac APP_POOL budget minus the pinned module
 * image bytes. No 4 GiB commit and no fake logical heap size at boot. */
#define HEAP_BASE 0x4000000000ull
#define HEAP_MAX  0x100000000ull
/* Immutable alias geometry owned by the AS, NOT copied from Mac's 448-512 GiB
 * placement (that overlaps the validated thunk region). */
#define ALIAS_BASE 0x5000000000ull
#define ALIAS_SIZE 0x1000000000ull
/* Global stack MAPPING ARENA (not the current main-thread SP region). */
#define ARENA_BASE 0x2800000000ull
#define ARENA_SIZE 0x10000000ull
#define APP_POOL  0xcd500000ull
/* Mac services.c:48: process policy, not a title-specific HLE response. */
#define MAC_SYSTEM_RESOURCE_BUDGET (32ull << 20)

/* Original nn::init::Start (DEFINED STT_FUNC in sdk dynsym, size 96). */
#define START_VA 0x10200fa060ull
/* Mac loader.c:436 resolves exactly this name. */
#define START_SYM "_ZN2nn4init5StartEmmPFvvES2_S2_"
/* Mac threads_main_init()'s h_new(O_THREAD) handle for the main thread. */
#define MAIN_THREAD_HANDLE 0x1001u

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

/* Counter reads only: the same host clock the real probe uses (never a
 * fabricated value). TPIDR is NOT registered here: it is inlined from the
 * guest state (aot_abi.h tpidr/tpidrro), and an unhandled service is a
 * typed BAD_HLE, never a fake success. */
static uint64_t g_tick_calls;
static uint64_t g_clock_fail;
static G3StartHle g_start_hle;
static G3StartBudget g_budget;
/* Mac host-override registration witnesses (by NAME, never by ordinal). */
static unsigned g_override_registered;
static unsigned g_override_unmodelled;
static unsigned g_override_absent;
static unsigned g_diag_bound;
static int g_fs_override_bound;
static uint64_t g_fs_override_thunk;
/* Early-G4 RomFS adapter: ONLY when an explicit external config is linked. */
static G4RomfsStartHle g_g4_romfs_hle;
static RomfsProvider *g_g4_romfs_provider;
static int g_g4_romfs_registered;

static void g4_romfs_cleanup(void)
{
    romfs_provider_destroy(g_g4_romfs_provider);
    g_g4_romfs_provider = NULL;
}

static int start_entropy(uint64_t *out, void *user)
{
    (void)user;
    return host_random_u64(out) == HOST_RANDOM_OK ? 0 : 1;
}
static void hle_cnt(AotRuntime *rtx, AotGuestState *s,
                    const AotHleRequest *req, void *user)
{
    uint64_t ns = 0u;
    uint32_t field = AOT_SYSREG_ID_FIELD(req->id);

    (void)user;
    if ((field != AOT_SYSREG_CNTPCT_EL0 && field != AOT_SYSREG_CNTVCT_EL0) ||
        host_time_now_ns(&ns) != HOST_TIME_OK) {
        /* Typed sticky fault, destination NOT written (no fabricated value):
         * prog_hle checks rt->fault after the handler (D016). */
        g_clock_fail += 1u;
        rtx->fault = AOT_FAULT_BAD_HLE;
        rtx->fault_src = req->site_pc;
        rtx->fault_target = req->resume_pc;
        rtx->fault_status = (int64_t)req->id;
        return;
    }
    g_tick_calls += 1u;
    /* 19.2 MHz exact, overflow-free: ticks = ns * 12 / 625. */
    aot_sysreg_write_dest(s, req, (ns / 625u) * 12u + (ns % 625u) * 12u / 625u);
}

typedef struct G3Start {
    uint64_t inits_thunk;
    uint64_t finis_thunk;
    uint32_t main_handle;
    AotRuntime *rt;
    unsigned ready_calls;
    unsigned inits_calls;
    unsigned finis_calls;
    unsigned ctor_fail;
} G3Start;
static G3Start g_start;

typedef struct G3Observer {
    const char *name;
    uint64_t va;      /* real guest symbol VA, 0 when not defined */
    uint32_t thunk;
    uint32_t calls;
    uint32_t returned_ok;
} G3Observer;
static G3Observer g_obs[8];

/* Thread-pointer readback, logged only (no invariant on the pointer value):
 * the guest may legitimately initialize the dummy ThreadType in place, so
 * ptr == dummy is not by itself a wrong state. Owner = u32 [[TLR+0x1f8]+0x1b0].
 * The probe never writes the owner; only guest code may. */
static AotAddressSpace *g_as;
static uint32_t log_thread_ptr(const char *tag)
{
    uint64_t tptr = 0u, d1b0 = ~0ull;
    uint32_t own32 = 0u;
    int ok = aot_as_read(g_as, ENV_TLR_BASE + ENV_SLOT_OFF, &tptr,
                         sizeof tptr) == AOT_MEM_OK &&
             aot_as_read(g_as, tptr + 0x1b0ull, &own32, sizeof own32) ==
                 AOT_MEM_OK;
    (void)aot_as_read(g_as, ENV_DUMMY_BASE + 0x1b0ull, &d1b0, sizeof d1b0);
    printf("THREADPTR %s tlr_1f8=0x%llx is_dummy=%d read_ok=%d "
           "owner_u32=0x%x dummy_1b0=0x%llx\n", tag,
           (unsigned long long)tptr, tptr == ENV_DUMMY_BASE, ok,
           (unsigned)own32, (unsigned long long)d1b0);
    return ok ? own32 : 0u;
}
/* Transparent observer: delegates to the REAL defined guest function (never
 * a thunk) with the caller's x0..x7; SP/stack are untouched. The WRAPPER does
 * not write x8 (the real callee may still clobber it per the AAPCS). The
 * callee's own x0 is the result (no fabricated success). A nested fault is
 * sticky (D016). */
static void hle_observer(AotRuntime *rt, AotGuestState *s,
                         const AotHleRequest *req, void *user)
{
    G3Observer *o = (G3Observer *)user;
    uint64_t args[8];
    uint64_t rx0 = 0u;
    uint32_t rc;
    unsigned i;

    o->calls += 1u;
    printf("OBS %s site=0x%llx x0=0x%llx x1=0x%llx -> 0x%llx\n", o->name,
           (unsigned long long)req->site_pc,
           (unsigned long long)s->x[0], (unsigned long long)s->x[1],
           (unsigned long long)o->va);
    for (i = 0u; i < 8u; i++) args[i] = s->x[i];
    rc = aot_call_guest(rt, o->va, args, 8u, &rx0);
    printf("OBS_RET %s rc=%u raw_x0=0x%llx return_out_valid=%d "
           "return_out_x0=0x%llx\n", o->name, (unsigned)rc,
           (unsigned long long)s->x[0], rc == 0u ? 1 : 0,
           (unsigned long long)rx0);
    if (rc == 0u) o->returned_ok = 1u;
    if (strcmp(o->name, "nnosInitialize") == 0) {
        uint32_t own = log_thread_ptr("after_nnosInitialize");
        printf("OWNER_CHECK after_nnosInitialize rc=%u owner=0x%x %s\n",
               (unsigned)rc, (unsigned)own,
               rc != 0u ? "NOT_RETURNED"
                        : (own == MAIN_THREAD_HANDLE ? "PASS" : "FAIL"));
    }
}

/* Probe-owned minimal handle registry: exactly the first h_new(O_THREAD) of
 * Mac threads_main_init (threads.c 72-85, 272-283). Nothing else is
 * registered; unknown SVCs stay unregistered (typed BAD_HLE). The registry is
 * BORROWED by the Start HLE: SVC 0x0c/0x25 resolve against these entries. */
static G3StartThreadInfo g_handles[1];
static G3StartThreadRegistry g_threads;
static uint32_t g_handle_count;

static void hle_ready(AotRuntime *rt, AotGuestState *s,
                      const AotHleRequest *req, void *user)
{
    (void)rt; (void)s; (void)req;
    ((G3Start *)user)->ready_calls += 1u;
}

static void hle_module_inits(AotRuntime *rt, AotGuestState *s,
                             const AotHleRequest *req, void *user)
{
    G3Start *g = (G3Start *)user;
    uint32_t i;

    (void)s;
    g->inits_calls += 1u;
    for (i = 0u; i < g_aot_g3_real_module_count; i++) {
        const AotModuleDesc *m = &g_aot_g3_real_modules[i];
        uint64_t x0 = 0u;
        uint32_t f;
        if (m->image == NULL) {
            /* A link-only module with DT_INIT has no translated image. This
             * is a hard typed failure, never a silent success. */
            g->ctor_fail = 1u;
            rt->fault = AOT_FAULT_NO_IMAGE;
            rt->fault_src = req->site_pc;
            rt->fault_target = m->init_va;
            rt->fault_status = (int64_t)i;
            printf("CTOR_NO_IMAGE %s module=%u site=0x%llx init=0x%llx\n",
                   m->name, i, (unsigned long long)req->site_pc,
                   (unsigned long long)m->init_va);
            return;
        }
        /* D016/D010 Program ABI: nested guest calls from a handler are
         * explicitly supported; BAD_STATE here is a real error, not a
         * documented blocker. */
        f = aot_call_guest(rt, m->init_va, NULL, 0u, &x0);
        if (f != 0u) {
            g->ctor_fail = 1u;
            printf("CTOR_FAULT %s code=%u src=0x%llx target=0x%llx "
                   "status=%lld\n", m->name, (unsigned)f,
                   (unsigned long long)g->rt->fault_src,
                   (unsigned long long)g->rt->fault_target,
                   (long long)g->rt->fault_status);
            return;
        }
    }
}

static void hle_module_finis(AotRuntime *rt, AotGuestState *s,
                             const AotHleRequest *req, void *user)
{
    G3Start *g = (G3Start *)user;

    (void)s;
    g->finis_calls += 1u;
    printf("FINI_UNEXPECTED site=0x%llx\n",
           (unsigned long long)req->site_pc);
    /* Not modeled before G4: typed sticky BAD_HLE, never a fake success. */
    rt->fault = AOT_FAULT_BAD_HLE;
    rt->fault_src = req->site_pc;
    rt->fault_target = req->resume_pc;
    rt->fault_status = (int64_t)req->id;
}

int main(int argc, char **argv)
{
    const char *dir;
    const char *only = NULL;
    uint8_t *owned[8] = { NULL };
    uint64_t sizes[8] = { 0u };
    AotAddressSpace *as = NULL;
    AotLoader loader;
    AotProgram *prog;
    AotLoadError err;
    AotMem mem;
    AotRuntime rt;
    AotGuestState st;
    AotMemDomain *domain;
    uint32_t i;
    uint64_t thunks;

    if (argc < 2) {
        printf("usage: %s <dir-with-flats> [--module NAME]\n", argv[0]);
        return 2;
    }
    dir = argv[1];
    for (i = 2u; i + 1u < (uint32_t)argc; i++) {
        if (strcmp(argv[i], "--module") == 0) {
            only = argv[++i];
        }
    }
    if (g_aot_g3_real_module_count > 8u) {
        printf("FATAL: module count\n");
        return 2;
    }
    for (i = 0u; i < g_aot_g3_real_module_count; i++) {
        char path[512];
        int n = snprintf(path, sizeof path, "%s/%s.flat", dir,
                         g_aot_g3_real_modules[i].name);
        if (n <= 0 || (size_t)n >= sizeof path) {
            printf("FATAL: path too long\n");
            return 2;
        }
        owned[i] = read_file(path, &sizes[i]);
        if (owned[i] == NULL) {
            return 2;
        }
    }
    domain = aot_mem_domain_create();
    if (domain == NULL) {
        printf("FATAL: aot_mem_domain_create\n");
        return 2;
    }
    as = aot_as_create(domain);
    if (as == NULL) {
        printf("FATAL: aot_as_create\n");
        return 2;
    }
    {
        static AotModuleSet keep;
        keep.modules = g_aot_g3_real_modules;
        keep.count = g_aot_g3_real_module_count;
        if (aot_loader_init(&loader, as, &keep, &err) != AOT_LOAD_OK) {
            printf("FATAL: loader init: %s\n", err.detail);
            return 2;
        }
    }
    if (aot_as_add_region(as, STACK_BASE, STACK_SIZE, AOT_AS_PERM_RW,
                          STACK_STATE, NULL) != AOT_MEM_OK) {
        printf("FATAL: stack region\n");
        return 2;
    }
    /* Mac loader.c runtime_thread_init precondition: 8192 zero TLS bytes,
     * 0x200 zero TLR bytes, 0x400 zero dummy bytes, [TLR+0x1f8] = dummy
     * GUEST VA. All are RW data regions added BEFORE aot_loader_load() seals
     * the space; the pointer is written through the address-space API, never
     * a host pointer. */
    if (aot_as_add_region(as, ENV_TLS_BASE, ENV_TLS_SIZE, AOT_AS_PERM_RW,
                          AOT_AS_STATE_DATA, NULL) != AOT_MEM_OK ||
        aot_as_add_region(as, ENV_TLR_BASE, ENV_TLR_SIZE, AOT_AS_PERM_RW,
                          AOT_AS_STATE_DATA, NULL) != AOT_MEM_OK ||
        aot_as_add_region(as, ENV_DUMMY_BASE, ENV_DUMMY_SIZE, AOT_AS_PERM_RW,
                          AOT_AS_STATE_DATA, NULL) != AOT_MEM_OK) {
        printf("FATAL: thread environment regions\n");
        return 2;
    }
    {
        uint64_t dummy = ENV_DUMMY_BASE;
        uint64_t back = 0u;
        uint64_t tls_word = ~0ull, dummy_word = ~0ull;
        uint64_t dummy_1b0 = ~0ull;
        if (aot_as_write(as, ENV_TLR_BASE + ENV_SLOT_OFF, &dummy,
                         sizeof dummy) != AOT_MEM_OK ||
            aot_as_read(as, ENV_TLR_BASE + ENV_SLOT_OFF, &back,
                        sizeof back) != AOT_MEM_OK || back != dummy ||
            aot_as_read(as, ENV_TLS_BASE, &tls_word, sizeof tls_word) !=
                AOT_MEM_OK || tls_word != 0u ||
            aot_as_read(as, ENV_DUMMY_BASE, &dummy_word, sizeof dummy_word) !=
                AOT_MEM_OK || dummy_word != 0u ||
            aot_as_read(as, ENV_DUMMY_BASE + 0x1b0ull, &dummy_1b0,
                        sizeof dummy_1b0) != AOT_MEM_OK || dummy_1b0 != 0u) {
            printf("FATAL: thread environment init/readback\n");
            return 2;
        }
        printf("THREADENV tls=0x%llx tlr=0x%llx dummy=0x%llx "
               "tlr_1f8=0x%llx tls_zero=%d dummy_zero=%d dummy_1b0=0x%llx\n",
               (unsigned long long)ENV_TLS_BASE,
               (unsigned long long)ENV_TLR_BASE,
               (unsigned long long)ENV_DUMMY_BASE,
               (unsigned long long)back, tls_word == 0u, dummy_word == 0u,
               (unsigned long long)dummy_1b0);
    }
    aot_loader_set_host_bindings(&loader, &g_aot_g3_real_bindings);
    {
        /* Checked commit budget: APP_POOL - sum(image_size), never underflowing. */
        uint64_t image_bytes = 0u;
        uint64_t commit_limit;
        AotAsHeapInfo heap;
        for (i = 0u; i < g_aot_g3_real_module_count; i++) {
            if (g_aot_g3_real_modules[i].image_size > APP_POOL - image_bytes) {
                printf("FATAL: pinned image bytes exceed APP_POOL\n");
                return 2;
            }
            image_bytes += g_aot_g3_real_modules[i].image_size;
        }
        commit_limit = APP_POOL - image_bytes;
        g_budget.pool = APP_POOL;
        g_budget.image_bytes = image_bytes;
        if (aot_as_add_heap_window(as, HEAP_BASE, HEAP_MAX, commit_limit) !=
            AOT_MEM_OK) {
            printf("FATAL: add_heap_window\n");
            return 2;
        }
        if (aot_as_heap_info(as, &heap) != AOT_MEM_OK ||
            heap.base != HEAP_BASE || heap.max_size != HEAP_MAX ||
            heap.size != 0u) {
            printf("FATAL: heap window info\n");
            return 2;
        }
        printf("HEAPREG base=0x%llx max=0x%llx "
               "commit_limit=0x%llx image_bytes=0x%llx logical=0x%llx "
               "reserve_only=1\n",
               (unsigned long long)heap.base,
               (unsigned long long)heap.max_size,
               (unsigned long long)commit_limit,
               (unsigned long long)image_bytes,
               (unsigned long long)heap.size);
        if (aot_as_add_reserved_window(as, ALIAS_BASE, ALIAS_SIZE,
                                       AOT_AS_RESERVED_ROLE_ALIAS) !=
            AOT_MEM_OK) {
            printf("FATAL: add_reserved_window\n");
            return 2;
        }
        {
            uint64_t ab = 0u, an = 0u;
            if (aot_as_reserved_info(as, AOT_AS_RESERVED_ROLE_ALIAS, &ab,
                                     &an) != AOT_MEM_OK ||
                ab != ALIAS_BASE || an != ALIAS_SIZE) {
                printf("FATAL: alias window info\n");
                return 2;
            }
            printf("ALIASREG base=0x%llx size=0x%llx role=alias "
                   "reserve_only=1\n",
                   (unsigned long long)ab, (unsigned long long)an);
        }
        if (aot_as_add_reserved_window(as, ARENA_BASE, ARENA_SIZE,
                                       AOT_AS_RESERVED_ROLE_STACK) !=
            AOT_MEM_OK) {
            printf("FATAL: add_stack_arena\n");
            return 2;
        }
        {
            uint64_t sb = 0u, sn = 0u;
            if (aot_as_reserved_info(as, AOT_AS_RESERVED_ROLE_STACK, &sb,
                                     &sn) != AOT_MEM_OK ||
                sb != ARENA_BASE || sn != ARENA_SIZE) {
                printf("FATAL: stack arena info\n");
                return 2;
            }
            printf("STACKREG base=0x%llx size=0x%llx role=stack "
                   "reserve_only=1\n",
                   (unsigned long long)sb, (unsigned long long)sn);
        }
    }
    if (aot_loader_load(&loader, (const uint8_t *const *)owned, sizes, &err) !=
        AOT_LOAD_OK) {
        printf("FATAL: load: %s (module %d)\n", err.detail, (int)err.module);
        return 2;
    }
    printf("LOAD ok sites=%u digest=%d\n", (unsigned)loader.site_count,
           (int)loader.digest_matched);

    prog = aot_program_create(as);
    if (prog == NULL) {
        printf("FATAL: program create\n");
        return 2;
    }
    /* N = max bound thunk index + 1; the program window is extended to N+3
     * BEFORE finalize so the three Start callback thunks lie inside it. */
    thunks = 0u;
    for (i = 0u; i < g_aot_g3_real_bindings.override_count; i++)
        if ((uint64_t)g_aot_g3_real_bindings.overrides[i].thunk + 1u > thunks)
            thunks = (uint64_t)g_aot_g3_real_bindings.overrides[i].thunk + 1u;
    for (i = 0u; i < g_aot_g3_real_bindings.observer_count; i++)
        if ((uint64_t)g_aot_g3_real_bindings.observers[i].thunk + 1u > thunks)
            thunks = (uint64_t)g_aot_g3_real_bindings.observers[i].thunk + 1u;
    printf("THUNKS N=%llu window=%llu callbacks=[%llu,%llu]\n",
           (unsigned long long)thunks, (unsigned long long)(thunks + 3u),
           (unsigned long long)thunks, (unsigned long long)(thunks + 2u));
    {
        uint64_t start_va = 0u;
        if (aot_loader_symbol(&loader, START_SYM, &start_va) != AOT_LOAD_OK ||
            start_va != START_VA) {
            printf("FATAL: Start symbol va=0x%llx expected=0x%llx\n",
                   (unsigned long long)start_va,
                   (unsigned long long)START_VA);
            return 2;
        }
        printf("STARTSYM va=0x%llx (sdk+0xfa060)\n",
               (unsigned long long)start_va);
    }
    if (aot_loader_build_program(&loader, prog, thunks + 3u,
                                 g_aot_g3_real_bindings.sentinel,
                                 (uint64_t)AOT_MAX_CALL_DEPTH, &err) !=
        AOT_LOAD_OK) {
        printf("FATAL: build_program: %s (module %d)\n", err.detail,
               (int)err.module);
        return 2;
    }
    if (aot_program_set_handler(prog, AOT_HLE_SYSREG,
                                AOT_SYSREG_ID(AOT_SYSREG_CNTPCT_EL0, 0u),
                                hle_cnt, NULL) != 0 ||
        aot_program_set_handler(prog, AOT_HLE_SYSREG,
                                AOT_SYSREG_ID(AOT_SYSREG_CNTVCT_EL0, 0u),
                                hle_cnt, NULL) != 0) {
        printf("FATAL: handler registration\n");
        return 2;
    }
    /* Minimal GetInfo HLE only: SVC 0x29, id 11 (random). Other ids stay
     * typed BAD_HLE inside the handler; no other SVC is approximated. */
    g3_start_hle_init(&g_start_hle, start_entropy, NULL);
    g3_start_hle_set_address_space(&g_start_hle, as);
    g3_start_hle_set_budget(&g_start_hle, &g_budget);
    g3_start_hle_set_system_resource_limit(&g_start_hle, MAC_SYSTEM_RESOURCE_BUDGET);
    if (aot_program_set_handler(prog, AOT_HLE_SVC, 0x29u,
                                g3_start_hle_svc, &g_start_hle) != 0) {
        printf("FATAL: SVC 0x29 handler registration\n");
        return 2;
    }
    /* SetHeapSize is registered only because the boot path uses the real AS
     * heap window; invalid sizes are the Mac 0xd401 result. */
    if (aot_program_set_handler(prog, AOT_HLE_SVC, 0x01u,
                                g3_start_hle_svc1, &g_start_hle) != 0) {
        printf("FATAL: SVC 0x01 handler registration\n");
        return 2;
    }
    if (aot_program_set_handler(prog, AOT_HLE_SVC, 0x06u,
                                g3_start_hle_svc6, &g_start_hle) != 0) {
        printf("FATAL: SVC 0x06 handler registration\n");
        return 2;
    }
    /* Mac services.c:283 MapPhysicalMemory/UnmapPhysicalMemory over the
     * immutable alias reserved window (D019). */
    if (aot_program_set_handler(prog, AOT_HLE_SVC, 0x2cu,
                                g3_start_hle_svc_alias, &g_start_hle) != 0 ||
        aot_program_set_handler(prog, AOT_HLE_SVC, 0x2du,
                                g3_start_hle_svc_alias, &g_start_hle) != 0) {
        printf("FATAL: SVC 0x2c/0x2d handler registration\n");
        return 2;
    }
    /* Mac threads.c:378/389 thread lookup against the BORROWED registry. */
    if (aot_program_set_handler(prog, AOT_HLE_SVC, 0x0cu,
                                g3_start_hle_svc0c, &g_start_hle) != 0 ||
        aot_program_set_handler(prog, AOT_HLE_SVC, 0x25u,
                                g3_start_hle_svc25, &g_start_hle) != 0) {
        printf("FATAL: SVC 0x0c/0x25 handler registration\n");
        return 2;
    }
    {
        uint32_t thunk_ready = (uint32_t)thunks;
        uint32_t thunk_inits = thunk_ready + 1u;
        uint32_t thunk_finis = thunk_ready + 2u;
        uint64_t va_inits = g_aot_g3_real_bindings.thunk_base +
                            (uint64_t)thunk_inits *
                            AOT_LOADER_THUNK_STRIDE;
        uint64_t va_finis = g_aot_g3_real_bindings.thunk_base +
                            (uint64_t)thunk_finis *
                            AOT_LOADER_THUNK_STRIDE;

        g_start.inits_thunk = va_inits;
        g_start.finis_thunk = va_finis;
        g_start.main_handle = MAIN_THREAD_HANDLE;
        g_start.rt = &rt;
        if (aot_program_set_handler(prog, AOT_HLE_HOSTCALL,
                                    thunk_ready,
                                    hle_ready, &g_start) != 0 ||
            aot_program_set_handler(prog, AOT_HLE_HOSTCALL,
                                    thunk_inits,
                                    hle_module_inits, &g_start) != 0 ||
            aot_program_set_handler(prog, AOT_HLE_HOSTCALL,
                                    thunk_finis,
                                    hle_module_finis, &g_start) != 0) {
            printf("FATAL: Start callback handlers\n");
            return 2;
        }
    }
    /* Observers: the first five delegate to the real guest function; nnMain
     * stays UNREGISTERED as the explicit pre-G4 boundary (BAD_HLE). */
    for (i = 0u; i < g_aot_g3_real_bindings.observer_count; i++) {
        const AotHostBinding *b = &g_aot_g3_real_bindings.observers[i];
        G3Observer *o;
        if (i >= 8u) {
            printf("FATAL: observer count\n");
            return 2;
        }
        o = &g_obs[i];
        o->name = b->name;
        o->thunk = b->thunk;
        if (strcmp(b->name, "nnMain") == 0) {
            printf("OBSREG %s thunk=%u UNREGISTERED (pre-G4 stop)\n",
                   b->name, (unsigned)b->thunk);
            continue;
        }
        if (aot_loader_symbol(&loader, b->name, &o->va) != AOT_LOAD_OK ||
            (o->va >= g_aot_g3_real_bindings.thunk_base &&
             o->va < g_aot_g3_real_bindings.thunk_base +
                     (thunks + 3u) * AOT_LOADER_THUNK_STRIDE)) {
            printf("FATAL: observer %s has no real guest definition\n",
                   b->name);
            return 2;
        }
        if (aot_program_set_handler(prog, AOT_HLE_HOSTCALL, b->thunk,
                                    hle_observer, o) != 0) {
            printf("FATAL: observer handler %s\n", b->name);
            return 2;
        }
        printf("OBSREG %s thunk=%u real=0x%llx\n", b->name,
               (unsigned)b->thunk, (unsigned long long)o->va);
    }
    /* Mac host overrides (services.c:168-177). The link configuration owns the
     * THUNK ORDINAL; this probe owns nothing but the name -> handler table, so
     * ONE pass over the bindings registers every name that table knows. A name
     * the table does not know is never registered, a known name missing from
     * the bindings is not an error, and the one documented real-behaviour
     * exclusion stays unregistered. No thunk ordinal is hardcoded here. */
    {
        static const char *const fs_init_name =
            "_ZN2nn2fs24InitializeForApplicationEv";
        unsigned k, t;

        for (k = 0u; k < g_aot_g3_real_bindings.override_count; k++) {
            const AotHostBinding *b = &g_aot_g3_real_bindings.overrides[k];
            const G3StartHleOverride *ovr;

            if (strcmp(b->name, "nndiagStartup") == 0) {
                /* Mac host_diag_init is void: resolve by name, never a
                 * title-specific ordinal; no guest register is patched. */
                if (aot_program_set_handler(prog, AOT_HLE_HOSTCALL, b->thunk,
                                            g3_start_hle_host_diag,
                                            &g_start_hle) != 0) {
                    printf("FATAL: nndiagStartup registration\n");
                    return 2;
                }
                printf("DIAGREG name=%s thunk=%u\n", b->name,
                       (unsigned)b->thunk);
                g_diag_bound = 1;
                continue;
            }
            if (strcmp(b->name, fs_init_name) == 0 &&
                g_g4_romfs_start_config != NULL) {
                /* Early-G4 explicit profile. The provider is created but NOT
                 * initialized here; the adapter calls romfs_provider_init()
                 * only at the real HOSTCALL. Success writes no guest state. */
                if (g_g4_romfs_provider != NULL || g_g4_romfs_registered) {
                    printf("FATAL: duplicate G4 fs binding\n");
                    return 2;
                }
                g_g4_romfs_provider = romfs_provider_create();
                if (g_g4_romfs_provider == NULL) {
                    printf("FATAL: G4 RomFS provider allocation\n");
                    return 2;
                }
                g4_romfs_start_hle_init(&g_g4_romfs_hle, g_g4_romfs_provider,
                                        g_g4_romfs_start_config);
                if (aot_program_set_handler(prog, AOT_HLE_HOSTCALL, b->thunk,
                                            g4_romfs_start_hle_handler,
                                            &g_g4_romfs_hle) != 0) {
                    printf("FATAL: G4 fs InitializeForApplication "
                           "registration\n");
                    /* Registration failed: no guest path can reach the
                     * provider, so release the created (still EMPTY)
                     * provider instead of leaking it. */
                    g4_romfs_cleanup();
                    return 2;
                }
                printf("G4FSREG name=%s thunk=%u provider_init=pending "
                       "overlay_roots=%u\n", b->name, (unsigned)b->thunk,
                       g_g4_romfs_start_config->overlay_root_count);
                g_fs_override_bound = 1;
                g_fs_override_thunk = b->thunk;
                g_g4_romfs_registered = 1;
                if (atexit(g4_romfs_cleanup) != 0) {
                    printf("FATAL: G4 RomFS cleanup registration\n");
                    g4_romfs_cleanup();
                    return 2;
                }
                continue;
            }
            if (g3_start_hle_override_not_modelled(b->name)) {
                /* The generic G3 override table still refuses fs: with no
                 * explicit G4 config this name stays UNREGISTERED and fails
                 * closed. Only the separate early-G4 adapter above may bind
                 * it, and only from an explicit external profile. */
                if (g3_start_hle_override_lookup(b->name) != 0) {
                    printf("FATAL: not-modelled override %s is modelled\n",
                           b->name);
                    return 2;
                }
                printf("OVRUNMODELLED name=%s thunk=%u registered=0\n",
                       b->name, (unsigned)b->thunk);
                g_override_unmodelled++;
                if (strcmp(b->name, fs_init_name) == 0) {
                    g_fs_override_bound = 1;
                    g_fs_override_thunk = b->thunk;
                }
                continue;
            }
            ovr = g3_start_hle_override_lookup(b->name);
            if (ovr == 0) continue;   /* another Mac override family */
            if (aot_program_set_handler(prog, AOT_HLE_HOSTCALL, b->thunk,
                                        ovr->handler, &g_start_hle) != 0) {
                printf("FATAL: override registration %s\n", b->name);
                return 2;
            }
            printf("OVRREG name=%s thunk=%u\n", b->name,
                   (unsigned)b->thunk);
            g_override_registered++;
        }
        if (!g_diag_bound) {
            printf("FATAL: nndiagStartup binding missing\n");
            return 2;
        }
        /* Known-but-unbound override names are NOT an error. */
        for (t = 0u; t < g3_start_hle_override_table_count(); t++) {
            const G3StartHleOverride *o = g3_start_hle_override_table_at(t);
            int seen = 0;
            for (k = 0u; k < g_aot_g3_real_bindings.override_count; k++) {
                if (strcmp(g_aot_g3_real_bindings.overrides[k].name,
                           o->name) == 0)
                    seen = 1;
            }
            if (seen) continue;
            printf("SKIP name=%s absent from bindings\n", o->name);
            g_override_absent++;
        }
        /* The documented exclusion must never be modelled, with or without a
         * binding in this configuration. */
        if (g3_start_hle_override_lookup(fs_init_name) != 0 ||
            !g3_start_hle_override_not_modelled(fs_init_name)) {
            printf("FATAL: fs InitializeForApplication is modelled\n");
            return 2;
        }
        printf("OVRSUMMARY registered=%u unmodelled=%u absent=%u fs_bound=%d "
               "g4_registered=%d\n",
               g_override_registered, g_override_unmodelled,
               g_override_absent, g_fs_override_bound, g_g4_romfs_registered);
    }
    if (g_g4_romfs_start_config != NULL && !g_fs_override_bound) {
        printf("FATAL: explicit G4 RomFS config but fs symbol is not bound\n");
        return 2;
    }
    if (aot_program_finalize(prog) != AOT_FAULT_NONE) {
        printf("FATAL: program finalize\n");
        return 2;
    }
    /* Checked AFTER finalize. With no explicit G4 config the fs override must
     * NOT be installed (the BAD_HLE boundary remains). With one it must be
     * installed, and the generic table must still report it not modelled. */
    {
        int fs_registered = 0;
        if (g_fs_override_bound) {
            fs_registered =
                aot_program_handler(prog, AOT_HLE_HOSTCALL,
                                    (uint32_t)g_fs_override_thunk) != 0;
        }
        if (g_g4_romfs_start_config != NULL) {
            if (!g_g4_romfs_registered || !fs_registered) {
                printf("FATAL: explicit G4 fs handler is not registered\n");
                return 2;
            }
        } else if (fs_registered) {
            printf("FATAL: fs InitializeForApplication is registered\n");
            return 2;
        }
        printf("OVRCHECK fs_bound=%d fs_registered=%d modelled_by_table=0 "
               "g4_config=%d g4_registered=%d\n",
               g_fs_override_bound, fs_registered,
               g_g4_romfs_start_config != NULL, g_g4_romfs_registered);
    }
    if (aot_mem_init_aspace(&mem, as) != AOT_MEM_OK) {
        printf("FATAL: aot_mem_init_aspace\n");
        return 2;
    }
    memset(&st, 0, sizeof st);
    g_handles[0].handle = MAIN_THREAD_HANDLE;
    g_handles[0].type = 1u;
    g_handles[0].owner_os_thread = (uint32_t)GetCurrentThreadId();
    g_handles[0].is_main = 1u;
    g_handles[0].guest_id = 0x51u;
    g_handles[0].priority = 44;
    g_handles[0].core = 0;
    g_handles[0].affinity_mask = 7u;
    g_handle_count = 1u;
    g_threads.entries = g_handles;
    g_threads.count = g_handle_count;
    g3_start_hle_set_thread_registry(&g_start_hle, &g_threads);
    printf("REGISTRY handle=0x%x type=THREAD owner=%u main=%u id=0x%llx "
           "prio=%d core=%d mask=0x%llx\n", g_handles[0].handle,
           (unsigned)g_handles[0].owner_os_thread,
           (unsigned)g_handles[0].is_main,
           (unsigned long long)g_handles[0].guest_id, g_handles[0].priority,
           g_handles[0].core, (unsigned long long)g_handles[0].affinity_mask);
    st.sp = STACK_BASE + STACK_SIZE;
    st.tpidr = ENV_TLS_BASE;
    st.tpidrro = ENV_TLR_BASE;
    st.x[18] = 0u;
    printf("THREADSTATE sp=0x%llx align16=%d tpidr=0x%llx tpidrro=0x%llx "
           "x18=0x%llx main_handle=0x%x registered=%u\n",
           (unsigned long long)st.sp, (st.sp & 0xFull) == 0u,
           (unsigned long long)st.tpidr,
           (unsigned long long)st.tpidrro,
           (unsigned long long)st.x[18], MAIN_THREAD_HANDLE,
           (unsigned)g_handle_count);
    if (aot_rt_init_program(&rt, prog, mem, &st, STEP_BUDGET) !=
        AOT_FAULT_NONE) {
        printf("FATAL: rt init\n");
        return 2;
    }
    rt.trace_enabled = 1;
    {
        uint32_t f;
        uint64_t x0 = 0u;
        uint32_t thunk_ready = (uint32_t)thunks;
        uint32_t thunk_inits = thunk_ready + 1u;
        uint32_t thunk_finis = thunk_ready + 2u;
        uint64_t va_ready = g_aot_g3_real_bindings.thunk_base +
                            (uint64_t)thunk_ready *
                            AOT_LOADER_THUNK_STRIDE;
        uint64_t va_inits = g_aot_g3_real_bindings.thunk_base +
                            (uint64_t)thunk_inits *
                            AOT_LOADER_THUNK_STRIDE;
        uint64_t va_finis = g_aot_g3_real_bindings.thunk_base +
                            (uint64_t)thunk_finis *
                            AOT_LOADER_THUNK_STRIDE;
        uint64_t owner = 0u;

        g_start.inits_thunk = va_inits;
        g_start.finis_thunk = va_finis;
        g_start.main_handle = MAIN_THREAD_HANDLE;
        g_start.rt = &rt;
        printf("STARTENTRY sdk+0xfa060 va=0x%llx ready=0x%llx inits=0x%llx "
               "finis=0x%llx handle=0x%x\n",
               (unsigned long long)START_VA, (unsigned long long)va_ready,
               (unsigned long long)va_inits, (unsigned long long)va_finis,
               MAIN_THREAD_HANDLE);
        {
            /* Mac loader.c: Start(main_handle, 0, ready, inits, finis). */
            uint64_t sargs[5];
            sargs[0] = MAIN_THREAD_HANDLE;
            sargs[1] = 0u;
            sargs[2] = va_ready;
            sargs[3] = va_inits;
            sargs[4] = va_finis;
            printf("STARTARGS x0=0x%llx x1=0x%llx x2=0x%llx x3=0x%llx "
                   "x4=0x%llx\n", (unsigned long long)sargs[0],
                   (unsigned long long)sargs[1], (unsigned long long)sargs[2],
                   (unsigned long long)sargs[3], (unsigned long long)sargs[4]);
            g_as = as;
            (void)log_thread_ptr("before_start");
            f = aot_call_guest(&rt, START_VA, sargs, 5u, &x0);
            owner = log_thread_ptr("after_start");
            {
                const G3Observer *nnos = NULL;
                for (i = 0u; i < 8u; i++)
                    if (g_obs[i].name != NULL &&
                        strcmp(g_obs[i].name, "nnosInitialize") == 0)
                        nnos = &g_obs[i];
                /* The main-handle assertion applies only once the ORIGINAL
                 * nnosInitialize has returned; before that it is a partial
                 * stage, not a wrong state. */
                printf("OWNER_CHECK final nnos_calls=%u nnos_returned=%u "
                       "owner=0x%llx %s\n",
                       nnos ? (unsigned)nnos->calls : 0u,
                       nnos ? (unsigned)nnos->returned_ok : 0u,
                       (unsigned long long)owner,
                       (nnos == NULL || !nnos->returned_ok)
                           ? "NOT_REACHED(partial stage)"
                           : (owner == MAIN_THREAD_HANDLE ? "PASS" : "FAIL"));
            }
        }
        printf("STARTSTOP code=%u src=0x%llx target=0x%llx status=%lld "
               "steps=%llu x0=0x%llx x1=0x%llx x2=0x%llx x3=0x%llx "
               "x4=0x%llx x5=0x%llx x6=0x%llx x7=0x%llx sp=0x%llx "
               "return_out_valid=%d return_out_x0=0x%llx "
               "retpc=0x%llx trace=%llu over=%d "
               "ready_calls=%u inits_calls=%u finis_calls=%u "
               "ctor_fail=%u thread_owner=0x%llx "
               "cntpct_calls=%llu\n",
               (unsigned)f, (unsigned long long)rt.fault_src,
               (unsigned long long)rt.fault_target,
               (long long)rt.fault_status,
               (unsigned long long)rt.steps, (unsigned long long)st.x[0],
               (unsigned long long)st.x[1], (unsigned long long)st.x[2],
               (unsigned long long)st.x[3], (unsigned long long)st.x[4],
               (unsigned long long)st.x[5], (unsigned long long)st.x[6],
               (unsigned long long)st.x[7], (unsigned long long)st.sp,
               f == AOT_FAULT_NONE ? 1 : 0,
               (unsigned long long)x0,
               (unsigned long long)st.pc,
               (unsigned long long)rt.trace_count,
               (int)rt.trace_overflow, g_start.ready_calls,
               g_start.inits_calls, g_start.finis_calls,
               g_start.ctor_fail,
               (unsigned long long)owner,
               (unsigned long long)g_tick_calls);
        /* Post-call observation, not a snapshot taken inside the thunk:
         * fault_target retains the authoritative captured resume PC. */
        printf("STARTFAULTSTATE post_call=1 x16=0x%llx x17=0x%llx "
               "x29=0x%llx x30=0x%llx nzcv=0x%llx fpcr=0x%llx "
               "fpsr=0x%llx tpidr=0x%llx tpidrro=0x%llx depth=%u\n",
               (unsigned long long)st.x[16], (unsigned long long)st.x[17],
               (unsigned long long)st.x[29], (unsigned long long)st.x[30],
               (unsigned long long)st.nzcv, (unsigned long long)st.fpcr,
               (unsigned long long)st.fpsr, (unsigned long long)st.tpidr,
               (unsigned long long)st.tpidrro, (unsigned)rt.call_depth);
        /* Generic per-GPR fault observability (D023): for each x0..x30 the
         * guest value, the post-index read VA (value-8) and the live 8 bytes
         * there read through the CHECKED guest address space (the guest VA is
         * never a host pointer).  Bounded, read-only, no state is altered. */
        if (f == AOT_FAULT_UNTRANSLATED) {
            unsigned r;
            for (r = 0; r < 31; r++) {
                uint64_t v = st.x[r];
                uint64_t live = 0;
                long long rs = -1;
                if (v >= 8) {
                    rs = (long long)aot_as_read(as, v - 8, &live, sizeof live);
                }
                printf("STARTFAULTGPR code=10 reg=%u value=0x%llx "
                       "read_va=0x%llx read_status=%lld live=0x%llx\n", r,
                       (unsigned long long)v,
                       (unsigned long long)(v >= 8 ? v - 8 : 0), rs,
                       (unsigned long long)(rs == 0 ? live : 0));
            }
        }
        printf("DIAGSTATE calls=%u\n", g_start_hle.host_diag_calls);
        printf("SYSRESSTATE info16=%u fail=%u limit=0x%llx configured=%u\n",
               g_start_hle.info16_calls, g_start_hle.sysres_failures,
               (unsigned long long)g_start_hle.sysres_limit,
               g_start_hle.sysres_configured);
        printf("CLOCKFAIL %llu\n", (unsigned long long)g_clock_fail);
        printf("G3HLE entropy_calls=%u entropy_failures=%u "
               "unknown_info_calls=%u info2=%u info3=%u info4=%u info5=%u "
               "info12=%u info13=%u info14=%u info15=%u heap_fail=%u "
               "svc1_calls=%u svc1_invalid=%u svc1_host_fail=%u "
               "svc6_calls=%u svc6_success=%u svc6_null_out=%u "
               "svc6_unsupported=%u svc6_write_faults=%u "
               "svc6_host_fail=%u svc0c_calls=%u svc0c_success=%u "
               "svc0c_invalid=%u svc25_calls=%u svc25_success=%u "
               "svc25_invalid=%u thread_host_fail=%u info6=%u info21=%u "
               "info7=%u info22=%u budget_fail=%u "
               "svc2c_calls=%u svc2c_ok=%u svc2c_invalid=%u svc2c_limit=%u "
               "svc2d_calls=%u svc2d_ok=%u svc2d_invalid=%u alias_host_fail=%u "
               "ovr_oe_init=%u ovr_aoc_init=%u ovr_aoc_count=%u "
               "ovr_aoc_list=%u ovr_err_init=%u ovr_pctl_init=%u "
               "ovr_abort_init=%u ovr_range_fault=%u ovr_host_fail=%u\n",
               g_start_hle.entropy_calls, g_start_hle.entropy_failures,
               g_start_hle.unknown_info_calls, g_start_hle.info2_calls,
               g_start_hle.info3_calls, g_start_hle.info4_calls,
               g_start_hle.info5_calls, g_start_hle.info12_calls,
               g_start_hle.info13_calls, g_start_hle.info14_calls,
               g_start_hle.info15_calls, g_start_hle.heap_query_failures,
               g_start_hle.svc1_calls, g_start_hle.svc1_invalid,
               g_start_hle.svc1_host_failures, g_start_hle.svc6_calls,
               g_start_hle.svc6_success, g_start_hle.svc6_null_out,
               g_start_hle.svc6_unsupported, g_start_hle.svc6_write_faults,
               g_start_hle.svc6_host_failures,
               g_start_hle.svc0c_calls, g_start_hle.svc0c_success,
               g_start_hle.svc0c_invalid, g_start_hle.svc25_calls,
               g_start_hle.svc25_success, g_start_hle.svc25_invalid,
               g_start_hle.thread_host_failures, g_start_hle.info6_calls,
               g_start_hle.info21_calls, g_start_hle.info7_calls,
               g_start_hle.info22_calls, g_start_hle.budget_failures,
               g_start_hle.svc2c_calls, g_start_hle.svc2c_success,
               g_start_hle.svc2c_invalid, g_start_hle.svc2c_limit,
               g_start_hle.svc2d_calls, g_start_hle.svc2d_success,
               g_start_hle.svc2d_invalid, g_start_hle.alias_host_failures,
               g_start_hle.override_calls[G3_START_HLE_OVERRIDE_OE_INIT],
               g_start_hle.override_calls[G3_START_HLE_OVERRIDE_AOC_INIT],
               g_start_hle.override_calls[G3_START_HLE_OVERRIDE_AOC_COUNT],
               g_start_hle.override_calls[G3_START_HLE_OVERRIDE_AOC_LIST],
               g_start_hle.override_calls[G3_START_HLE_OVERRIDE_ERR_INIT],
               g_start_hle.override_calls[G3_START_HLE_OVERRIDE_PCTL_INIT],
               g_start_hle.override_calls[G3_START_HLE_OVERRIDE_ABORT_INIT],
               g_start_hle.override_range_faults,
               g_start_hle.override_host_failures);
        {
            uint64_t bb = 0u, bn = 0u;
            if (aot_as_bounds(as, &bb, &bn) != AOT_MEM_OK) {
                printf("FATAL: bounds witness\n");
                return 2;
            }
            printf("BOUNDS base=0x%llx size=0x%llx end=0x%llx\n",
                   (unsigned long long)bb, (unsigned long long)bn,
                   (unsigned long long)(bb + bn));
        }
        {
            AotAsHeapInfo heap;
            host_vm_region *vm = NULL;
            const uint8_t *page = (const uint8_t *)(uintptr_t)1;
            size_t vm_off = 0u;
            host_vm_info os;
            if (aot_as_heap_info(as, &heap) != AOT_MEM_OK ||
                !aot_as_host_page(as, HEAP_BASE, &vm, &page, &vm_off) ||
                vm == NULL || page != NULL || vm_off != 0u ||
                host_vm_query(vm, vm_off, &os) != HOST_VM_OK) {
                printf("FATAL: heap state witness\n");
                return 2;
            }
            printf("HEAPSTATE base=0x%llx max=0x%llx logical=0x%llx "
                   "host0_state=%u host0_prot=%u page_ptr_null=%d\n",
                   (unsigned long long)heap.base,
                   (unsigned long long)heap.max_size,
                   (unsigned long long)heap.size, os.state, os.protection,
                   page == NULL);
        }
        {
            host_vm_region *vm = NULL;
            const uint8_t *first_page = NULL;
            const uint8_t *last_page = (const uint8_t *)(uintptr_t)1;
            size_t off = 0u;
            host_vm_info first, last;
            uint64_t ab = 0u, an = 0u;
            int first_reserve, first_mapped;
            /* The window base is no longer guaranteed reserve-only: the real
             * Start identity-maps the first alias page through SVC 0x2c. So
             * the base must be EITHER an untouched reserve page OR a committed
             * RW page, never a committed page without guest permission. The
             * last page of the window is still untouched, which pins that the
             * reservation really covers the whole declared size. */
            if (aot_as_reserved_info(as, AOT_AS_RESERVED_ROLE_ALIAS, &ab,
                                     &an) != AOT_MEM_OK ||
                !aot_as_host_page(as, ab, &vm, &first_page, &off) ||
                vm == NULL || off != 0u ||
                host_vm_query(vm, off, &first) != HOST_VM_OK) {
                printf("FATAL: alias state witness\n");
                return 2;
            }
            first_reserve = (first_page == NULL &&
                             first.state == HOST_VM_STATE_RESERVE &&
                             first.protection == 0u);
            first_mapped = (first_page != NULL &&
                            first.state == HOST_VM_STATE_COMMIT &&
                            (first.protection & (HOST_VM_PROT_READ |
                                                 HOST_VM_PROT_WRITE)) ==
                                (HOST_VM_PROT_READ | HOST_VM_PROT_WRITE));
            if (!first_reserve && !first_mapped) {
                printf("FATAL: alias state witness (base state=%u prot=%u "
                       "page_null=%d)\n", first.state, first.protection,
                       first_page == NULL);
                return 2;
            }
            if (!aot_as_host_page(as, ab + an - 0x1000ull, &vm, &last_page,
                                  &off) ||
                vm == NULL || last_page != NULL ||
                off != (size_t)(an - 0x1000ull) ||
                host_vm_query(vm, off, &last) != HOST_VM_OK ||
                last.state != HOST_VM_STATE_RESERVE ||
                last.protection != 0u) {
                printf("FATAL: alias state witness (tail)\n");
                return 2;
            }
            printf("ALIASSTATE base=0x%llx size=0x%llx first_state=%u "
                   "first_prot=%u first_mapped=%d last_state=%u "
                   "last_prot=%u last_page_null=%d\n",
                   (unsigned long long)ab, (unsigned long long)an,
                   first.state, first.protection, first_mapped, last.state,
                   last.protection, last_page == NULL);
        }
        {
            host_vm_region *vm = NULL;
            const uint8_t *page = (const uint8_t *)(uintptr_t)1;
            size_t off = 0u;
            host_vm_info first, last;
            uint64_t sb = 0u, sn = 0u;
            if (aot_as_reserved_info(as, AOT_AS_RESERVED_ROLE_STACK, &sb,
                                     &sn) != AOT_MEM_OK ||
                !aot_as_host_page(as, sb, &vm, &page, &off) || vm == NULL ||
                page != NULL || off != 0u ||
                host_vm_query(vm, off, &first) != HOST_VM_OK ||
                !aot_as_host_page(as, sb + sn - 0x1000ull, &vm, &page, &off) ||
                vm == NULL || page != NULL ||
                off != (size_t)(sn - 0x1000ull) ||
                host_vm_query(vm, off, &last) != HOST_VM_OK) {
                printf("FATAL: stack arena witness\n");
                return 2;
            }
            printf("STACKSTATE base=0x%llx size=0x%llx first_state=%u "
                   "first_prot=%u last_state=%u last_prot=%u "
                   "page_ptr_null=%d\n",
                   (unsigned long long)sb, (unsigned long long)sn,
                   first.state, first.protection, last.state,
                   last.protection, page == NULL);
        }
        printf("RNGFAIL %u\n", g_start_hle.entropy_failures);
        printf("STARTTRACE");
        {
            size_t ti;
            for (ti = 0u; ti < rt.trace_count; ti++)
                printf(" %llx", (unsigned long long)rt.trace[ti]);
        }
        printf("\n");
    }
    if (g_g4_romfs_start_config != NULL) {
        printf("G4FSSTATE enabled=1 registered=%d calls=%llu success=%llu "
               "fail=%llu provider_ready=%d files=%llu status=%d "
               "stage=%s detail=%s\n",
               g_g4_romfs_registered,
               (unsigned long long)g_g4_romfs_hle.calls,
               (unsigned long long)g_g4_romfs_hle.success,
               (unsigned long long)g_g4_romfs_hle.fail,
               g_g4_romfs_hle.last_provider_ready,
               (unsigned long long)g_g4_romfs_hle.last_file_count,
               (int)g_g4_romfs_hle.last_provider_status,
               g_g4_romfs_hle.last_stage[0] ? g_g4_romfs_hle.last_stage
                                            : "(none)",
               g_g4_romfs_hle.last_detail[0] ? g_g4_romfs_hle.last_detail
                                             : "(none)");
    } else {
        printf("G4FSSTATE enabled=0 registered=0 calls=0 success=0 fail=0\n");
    }
    g4_romfs_cleanup();
    return 0;
}
