/* G3 DT_INIT partial-AOT first-fault probe (locally only, no game data).
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Generated for variant "real" (emit-desc) in the external work dir. */
extern const AotModuleDesc g_aot_g3_real_modules[];
extern const uint32_t g_aot_g3_real_module_count;
extern const AotHostBindings g_aot_g3_real_bindings;

#define STACK_BASE 0x2000000000ull
#define STACK_SIZE 0x40000ull
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
static void hle_cnt(AotRuntime *rtx, AotGuestState *s,
                    const AotHleRequest *req, void *user)
{
    uint64_t ns = 0u;
    uint32_t field = AOT_SYSREG_ID_FIELD(req->id);

    (void)rtx; (void)user;
    if ((field != AOT_SYSREG_CNTPCT_EL0 && field != AOT_SYSREG_CNTVCT_EL0) ||
        host_time_now_ns(&ns) != HOST_TIME_OK) {
        aot_sysreg_write_dest(s, req, 0u);
        return;
    }
    g_tick_calls += 1u;
    aot_sysreg_write_dest(s, req, ns / 52u + (ns % 52u) * 12u / 625u);
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
    uint32_t ran = 0u;
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
                          AOT_AS_STATE_DATA, NULL) != AOT_MEM_OK) {
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
    thunks = (uint64_t)g_aot_g3_real_bindings.override_count +
             (uint64_t)g_aot_g3_real_bindings.observer_count;
    if (aot_loader_build_program(&loader, prog, thunks,
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
    if (aot_program_finalize(prog) != AOT_FAULT_NONE) {
        printf("FATAL: program finalize\n");
        return 2;
    }
    if (aot_mem_init_aspace(&mem, as) != AOT_MEM_OK) {
        printf("FATAL: aot_mem_init_aspace\n");
        return 2;
    }
    memset(&st, 0, sizeof st);
    st.sp = STACK_BASE + STACK_SIZE;
    /* Mac runtime_thread_init: TPIDR_EL0 -> TLS, TPIDRRO_EL0 -> TLR, and
     * runtime_keys[0] (x18) starts NULL. Guest VAs only. */
    st.tpidr = ENV_TLS_BASE;
    st.tpidrro = ENV_TLR_BASE;
    st.x[18] = 0u;
    if ((st.sp & 0xFull) != 0u) {
        printf("FATAL: unaligned guest SP\n");
        return 2;
    }
    printf("THREADSTATE sp=0x%llx align16=1 tpidr=0x%llx tpidrro=0x%llx "
           "x18=0x%llx\n",
           (unsigned long long)st.sp, (unsigned long long)st.tpidr,
           (unsigned long long)st.tpidrro, (unsigned long long)st.x[18]);
    if (aot_rt_init_program(&rt, prog, mem, &st, STEP_BUDGET) !=
        AOT_FAULT_NONE) {
        printf("FATAL: rt init\n");
        return 2;
    }

    rt.trace_enabled = 1;
    for (i = 0u; i < g_aot_g3_real_module_count; i++) {
        const AotModuleDesc *m = &g_aot_g3_real_modules[i];
        uint64_t x0 = 0u;
        uint32_t f;

        if (only != NULL && strcmp(only, m->name) != 0) {
            continue;
        }
        ran += 1u;
        if (m->image == NULL) {
            printf("STOP %s code=-1 src=0x0 status=0 (link-only)\n", m->name);
            continue;
        }
        printf("ENTRY %s init=0x%llx\n", m->name,
               (unsigned long long)m->init_va);
        f = aot_call_guest(&rt, m->init_va, NULL, 0u, &x0);
        printf("STOP %s code=%u src=0x%llx target=0x%llx status=%lld "
               "steps=%llu x0=0x%llx retpc=0x%llx entered=1 exited=%d "
               "cntpct_calls=%llu\n",
               m->name, (unsigned)f,
               (unsigned long long)rt.fault_src,
               (unsigned long long)rt.fault_target,
               (long long)rt.fault_status,
               (unsigned long long)rt.steps, (unsigned long long)x0,
               (unsigned long long)st.pc, f == 0u ? 1 : 0,
               (unsigned long long)g_tick_calls);
        printf("STOPX %s nzcv=0x%llx sp=0x%llx trace=%llu over=%d\n",
               m->name, (unsigned long long)st.nzcv,
               (unsigned long long)st.sp,
               (unsigned long long)rt.trace_count, (int)rt.trace_overflow);
        printf("TRACE");
        {
            size_t ti;
            for (ti = 0u; ti < rt.trace_count; ti++)
                printf(" %llx", (unsigned long long)rt.trace[ti]);
        }
        printf("\n");
    }
    if (ran == 0u) {
        printf("FATAL: --module matched no module\n");
        return 2;
    }
    return 0;
}
