/*
 * G3 increment 4 (work item C): real-module link probe.
 *
 * Loads the three REAL TotK 1.0.0 modules (main, subsdk0, sdk) through the C
 * loader from their .flat images, using the generated descriptors
 * (g_aot_g3_real_modules / g_aot_g3_real_bindings) that the offline reference
 * linker produced from the same inputs:
 *
 *   verify SHA-256 + layout -> map three regions/module -> parse
 *   MOD0/.dynamic/.dynsym -> relocate RELA + JMPREL -> link digest -> seal ->
 *   per-site TSV dump.
 *
 * Everything it needs is passed on the command line, nothing is compiled in
 * except the descriptor: this translation unit never sees game data, and the
 * test that runs it is registered only when MN_TOTK_V0_DIR is set.
 *
 * Usage: aot_g3_real_link_probe <flat-dir> <dump-tsv> [--sites N]
 *
 * Exit protocol:
 *   0 = the load succeeded and every semantic check passed
 *   2 = a semantic check failed (prints "FAIL: <check>")
 *   1 = infrastructure failure (prints "FATAL: <reason>")
 */
#include "aot_as.h"
#include "aot_loader.h"
#include "aot_mem.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

extern const AotModuleDesc g_aot_g3_real_modules[];
extern const uint32_t g_aot_g3_real_module_count;
extern const AotHostBindings g_aot_g3_real_bindings;

#define MAX_MODULES 8u

static int g_fail = 0;

static void check(int cond, const char *what)
{
    if (!cond) {
        printf("FAIL: %s\n", what);
        g_fail = 1;
    }
}

static void fatal(const char *what)
{
    printf("FATAL: %s\n", what);
    exit(1);
}

static double now_ms(void)
{
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
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
        fatal("unseekable or empty module image");
    }
    buf = (uint8_t *)malloc((size_t)size);
    if (buf == NULL) {
        fclose(f);
        fatal("out of memory");
    }
    if (fread(buf, 1, (size_t)size, f) != (size_t)size) {
        fclose(f);
        free(buf);
        fatal("short read");
    }
    fclose(f);
    *out_size = (uint64_t)size;
    return buf;
}

/* Order the dump exactly like the reference TSV: module name, then offset. */
static int site_cmp(const void *a, const void *b)
{
    const AotLinkSite *x = (const AotLinkSite *)a;
    const AotLinkSite *y = (const AotLinkSite *)b;
    int cmp = strcmp(g_aot_g3_real_modules[x->module].name,
                     g_aot_g3_real_modules[y->module].name);

    if (cmp != 0) {
        return cmp;
    }
    return (x->where < y->where) ? -1 : (x->where > y->where) ? 1 : 0;
}

/* The probe slice's jump target: main's JUMP_SLOT for sdk's GetSystemTick must
 * resolve to sdk base + 0x129640 (work item D starts from this value). */
static void probe_slice_check(const AotLoader *loader)
{
    static const char *k_name = "_ZN2nn2os13GetSystemTickEv";
    uint32_t i;

    for (i = 0; i < aot_loader_site_count(loader); i++) {
        AotLinkSite site;
        if (!aot_loader_site(loader, i, &site)) {
            fatal("site iterator failed");
        }
        if (site.symbol != NULL && strcmp(site.symbol, k_name) == 0) {
            uint64_t want = g_aot_g3_real_modules[2].guest_base + 0x129640ull;
            printf("probe-slice: %s site 0x%llx -> 0x%llx (want 0x%llx)\n",
                   g_aot_g3_real_modules[site.module].name,
                   (unsigned long long)site.where,
                   (unsigned long long)site.value, (unsigned long long)want);
            check(site.value == want,
                  "main's GetSystemTick PLT slot resolves to sdk+0x129640");
            return;
        }
    }
    check(0, "a GetSystemTick JUMP_SLOT site exists");
}

int main(int argc, char **argv)
{
    const char *dir;
    const char *dump_path;
    AotModuleSet set;
    AotMemDomain *domain;
    AotAddressSpace *as;
    AotLoader loader;
    AotLoadError err;
    uint8_t *buffers[MAX_MODULES];
    const uint8_t *images[MAX_MODULES];
    uint64_t sizes[MAX_MODULES];
    AotLoadStatus st;
    double t0;
    double load_ms;
    uint32_t m;
    uint32_t n;
    AotLinkSite *sites;

    if (argc < 3) {
        printf("usage: %s <flat-dir> <dump-tsv>\n", argv[0]);
        return 1;
    }
    dir = argv[1];
    dump_path = argv[2];

    set.modules = g_aot_g3_real_modules;
    set.count = g_aot_g3_real_module_count;
    if (set.count != 3u) {
        printf("FATAL: expected 3 real modules, descriptor has %u\n",
               (unsigned)set.count);
        return 1;
    }
    for (m = 0; m < set.count; m++) {
        char path[1024];
        (void)snprintf(path, sizeof path, "%s/%s.flat", dir,
                       g_aot_g3_real_modules[m].name);
        buffers[m] = read_file(path, &sizes[m]);
        images[m] = buffers[m];
        check(sizes[m] ==
                  g_aot_g3_real_modules[m].data.off +
                      g_aot_g3_real_modules[m].data.size,
              "flat file size matches the descriptor layout");
    }

    {
        uint64_t va = 0;
        if (aot_loader_symbol(NULL, "x", &va) != AOT_LOAD_ERR_ARG) {
            /* a NULL loader must be a typed error, not a crash */
            check(0, "NULL loader is rejected by aot_loader_symbol");
        }
    }

    {
        uint64_t va = 0;
        if (aot_loader_symbol(NULL, "x", &va) != AOT_LOAD_ERR_ARG) {
            /* a NULL loader must be a typed error, not a crash */
            check(0, "NULL loader is rejected by aot_loader_symbol");
        }
    }

    domain = aot_mem_domain_create();
    if (domain == NULL) {
        fatal("aot_mem_domain_create failed");
    }
    as = aot_as_create(domain);
    if (as == NULL) {
        fatal("aot_as_create failed");
    }
    memset(&loader, 0, sizeof loader);
    st = aot_loader_init(&loader, as, &set, &err);
    if (st != AOT_LOAD_OK) {
        fatal("aot_loader_init failed");
    }
    aot_loader_set_host_bindings(&loader, &g_aot_g3_real_bindings);

    /* The stages are timed separately: on the real set the stage costs differ
     * by three orders of magnitude, and the report needs to say which one is
     * the expensive half of an AOT link. */
    t0 = now_ms();
    st = aot_loader_verify_images(&set, images, sizes, &err);
    printf("stage verify: %.1f ms\n", now_ms() - t0);
    if (st == AOT_LOAD_OK) {
        t0 = now_ms();
        st = aot_loader_map(&loader, images, sizes, &err);
        printf("stage map: %.1f ms\n", now_ms() - t0);
    }
    if (st == AOT_LOAD_OK) {
        t0 = now_ms();
        st = aot_loader_relocate(&loader, &err);
        printf("stage relocate: %.1f ms (%u sites)\n", now_ms() - t0,
               (unsigned)aot_loader_site_count(&loader));
    }
    if (st == AOT_LOAD_OK) {
        t0 = now_ms();
        st = aot_loader_seal(&loader, &err);
        printf("stage seal: %.1f ms\n", now_ms() - t0);
    }
    load_ms = now_ms() - t0;
    if (st != AOT_LOAD_OK) {
        printf("FAIL: real load failed: %s (module %u %s, off 0x%llx, "
               "site 0x%llx, symbol %s, detail: %s)\n",
               aot_load_status_name((int)st), (unsigned)err.module,
               err.module < set.count ? g_aot_g3_real_modules[err.module].name
                                      : "-",
               (unsigned long long)err.image_off,
               (unsigned long long)err.site,
               err.symbol != NULL ? err.symbol : "-", err.detail);
        return 2;
    }

    printf("real: loaded (digest matched), %u sites\n",
           (unsigned)aot_loader_site_count(&loader));
    check(loader.digest_matched == 1, "link digest matched");
    check(loader.sealed == 1, "address space sealed");
    check(aot_as_is_sealed(as) == 1, "aot_as reports sealed");
    for (m = 0; m < loader.count; m++) {
        const AotLinkCounters *c = &loader.modules[m].counters;
        printf("counters %s relative=%u symbolic=%u cross=%u weak=%u\n",
               g_aot_g3_real_modules[m].name, c->relative, c->symbolic,
               c->cross, c->weak);
    }
    {
        uint64_t va = 0;
        uint64_t want = g_aot_g3_real_modules[0].guest_base +
                        g_aot_g3_real_modules[0].image_size;
        st = aot_loader_symbol(&loader, "end", &va);
        check(st == AOT_LOAD_OK && va == want,
              "`end` resolves to main base + image_size");
        printf("end-symbol: 0x%llx (want 0x%llx)\n", (unsigned long long)va,
               (unsigned long long)want);
    }
    probe_slice_check(&loader);

    n = aot_loader_site_count(&loader);
    sites = (AotLinkSite *)malloc(sizeof(AotLinkSite) * (size_t)n);
    if (sites == NULL) {
        fatal("out of memory for the site dump");
    }
    for (m = 0; m < n; m++) {
        if (!aot_loader_site(&loader, m, &sites[m])) {
            fatal("site iterator failed");
        }
    }
    qsort(sites, (size_t)n, sizeof(AotLinkSite), site_cmp);
    {
        FILE *f = fopen(dump_path, "wb");
        uint32_t i;
        if (f == NULL) {
            fatal("cannot write the site dump");
        }
        fprintf(f, "module\twhere\tkind\tsymbol\tvalue\n");
        for (i = 0; i < n; i++) {
            fprintf(f, "%s\t0x%x\t%u\t%s\t0x%016llx\n",
                    g_aot_g3_real_modules[sites[i].module].name,
                    (unsigned)sites[i].where, (unsigned)sites[i].kind,
                    sites[i].symbol != NULL ? sites[i].symbol : "-",
                    (unsigned long long)sites[i].value);
        }
        fclose(f);
    }
    printf("real: wrote %s (%u sites)\n", dump_path, (unsigned)n);
    free(sites);

    aot_loader_release(&loader);
    aot_as_destroy(as);
    aot_mem_domain_destroy(domain);
    for (m = 0; m < set.count; m++) {
        free(buffers[m]);
    }

    if (g_fail) {
        printf("aot_g3_real_link_probe: FAILED\n");
        return 2;
    }
    printf("aot_g3_real_link_probe: real modules loaded, relocated, sealed\n");
    return 0;
}
