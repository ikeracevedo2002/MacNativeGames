/*
 * G3 increment 2 (T4): negative-fixture probe.
 *
 * Every case is a mutated flat image whose descriptor carries the SHA-256 of
 * the MUTATED bytes, so the loader's exact-version check passes and the case
 * reaches the rule it exists to test. For each case the loader must return
 * exactly the declared AotLoadStatus (and name the declared module), must not
 * seal the address space, and must not silently accept the image.
 *
 * The cases (see NEG_CASES in tools/aot/aot_module.py):
 *   dup_relr_rela      one site written by both RELR and RELA   -> ERR_RELOC
 *   jumpslot_addend    JUMP_SLOT with addend 8                  -> ERR_RELOC
 *   unknown_kind       relocation kind 999 (low r_info 32 bits)  -> ERR_RELOC
 *   site_outside_data  site at 0x10 (inside text)               -> ERR_RELOC
 *   relative_oob       RELATIVE addend past the image           -> ERR_RELOC
 *   unresolved_strong  weak import strengthened to GLOBAL       -> ERR_SYMBOL
 *   relaent_not_24     DT_RELAENT 8                             -> ERR_DYNAMIC
 *   bad_mod0_magic     "XOD0" instead of "MOD0"                 -> ERR_MOD0
 *
 * Usage: aot_g3_neg_probe <fixture-dir>
 * (the case directories are baked into the generated table by CMake's
 * configure-time path, so <fixture-dir> is only used for diagnostics)
 *
 * Exit: 0 = every case failed with its declared status, 2 = mismatch,
 *       1 = infrastructure failure.
 */
#include "aot_as.h"
#include "aot_g3_neg_cases.h"
#include "aot_loader.h"
#include "aot_mem.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail = 0;

static void check(int cond, const char *what, const char *case_name)
{
    if (!cond) {
        printf("FAIL: %s: %s\n", case_name, what);
        g_fail = 1;
    }
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
        free(buf);
        fatal("short read");
    }
    fclose(f);
    *out_size = (uint64_t)size;
    return buf;
}

int main(int argc, char **argv)
{
    uint32_t c;
    int drift = 0;

    /* Negative control for review fix 11 (see the aot_g3_neg_details_control
     * CTest entry): with --drift-details every case is compared against ANOTHER
     * case's declared detail, so the detail comparison itself must fail. That
     * is what proves the check is not vacuous. */
    if (argc > 1 && strcmp(argv[1], "--drift-details") == 0) {
        drift = 1;
    }

    for (c = 0; c < g_aot_g3_neg_case_count; c++) {
        const AotNegCase *neg = &g_aot_g3_neg_cases[c];
        AotModuleSet set;
        AotMemDomain *domain;
        AotAddressSpace *as;
        AotLoader loader;
        AotLoadError err;
        const uint8_t *images[AOT_LOADER_MAX_MODULES];
        uint64_t sizes[AOT_LOADER_MAX_MODULES];
        uint8_t *buffers[AOT_LOADER_MAX_MODULES];
        AotLoadStatus st;
        const char *expect;
        char path[1024];
        uint32_t m;

        if (neg->count > AOT_LOADER_MAX_MODULES) {
            fatal("negative case has too many modules");
        }
        set.modules = neg->modules;
        set.count = neg->count;

        for (m = 0; m < neg->count; m++) {
            (void)snprintf(path, sizeof path, "%s/%s.flat", neg->dir,
                           neg->modules[m].name);
            buffers[m] = read_file(path, &sizes[m]);
            images[m] = buffers[m];
            /* The descriptor pins the mutated bytes, so this must hold; if it
             * does not, the case would fail verification for the wrong
             * reason and prove nothing. */
            check(sizes[m] == neg->modules[m].data.off +
                                  neg->modules[m].data.size,
                  "mutated flat size matches its descriptor", neg->name);
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
        check(st == AOT_LOAD_OK, "aot_loader_init", neg->name);
        aot_loader_set_host_bindings(&loader, neg->bindings);

        st = aot_loader_load(&loader, images, sizes, &err);
        if ((int)st != neg->expected_status) {
            printf("FAIL: %s: expected %s, got %s (module %u, off 0x%llx, "
                   "detail: %s)\n",
                   neg->name, aot_load_status_name(neg->expected_status),
                   aot_load_status_name((int)st), (unsigned)err.module,
                   (unsigned long long)err.image_off, err.detail);
            g_fail = 1;
        } else {
            check(neg->expected_module == AOT_LOADER_NO_MODULE ||
                      err.module == neg->expected_module,
                  "error names the mutated module", neg->name);
            /* Review fix 11: the SPECIFIC detail, not just the status family. */
            expect = neg->expected_detail;
            if (drift) {
                expect = g_aot_g3_neg_cases[
                    (c + 1) % g_aot_g3_neg_case_count].expected_detail;
            }
            check(err.detail != NULL && expect != NULL &&
                      strcmp(err.detail, expect) == 0,
                  "error reports the case's specific detail", neg->name);
            if (err.detail != NULL && expect != NULL &&
                strcmp(err.detail, expect) != 0) {
                printf("  detail: expected \"%s\", got \"%s\"\n",
                       expect, err.detail);
            }
            check(aot_as_is_sealed(as) == 0,
                  "rejected case leaves the space unsealed", neg->name);
            /* Review fix 1: every one of these cases fails AFTER the regions
             * were added, so the space must be poisoned and must refuse a
             * later seal; otherwise a retry could seal a half-loaded space. */
            check(aot_as_is_poisoned(as) == 1,
                  "rejected case poisons the space", neg->name);
            check(aot_as_seal(as) != AOT_MEM_OK,
                  "poisoned space refuses a later seal", neg->name);
            check(loader.digest_matched == 0,
                  "rejected case never matched a digest", neg->name);
            printf("neg %-18s -> %s (module %u, off 0x%llx, detail: %s)\n",
                   neg->name, aot_load_status_name((int)st),
                   (unsigned)err.module, (unsigned long long)err.image_off,
                   err.detail);
        }

        aot_loader_release(&loader);
        aot_as_destroy(as);
        aot_mem_domain_destroy(domain);
        for (m = 0; m < neg->count; m++) {
            free(buffers[m]);
        }
    }

    if (drift) {
        /* Every case must have been reported as a detail mismatch. */
        if (g_fail == 0) {
            printf("aot_g3_neg_probe: drifted details were ACCEPTED\n");
            return 2;
        }
        printf("aot_g3_neg_probe: drifted details rejected as expected\n");
        return 0;
    }
    if (g_fail) {
        printf("aot_g3_neg_probe: FAILED\n");
        return 2;
    }
    printf("aot_g3_neg_probe: all %u negative fixtures rejected with their "
           "declared status\n", (unsigned)g_aot_g3_neg_case_count);
    return 0;
}
