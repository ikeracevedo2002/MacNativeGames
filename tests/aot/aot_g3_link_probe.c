/*
 * G3 increment 2 (T3): C loader contract probe.
 *
 * For each generated link variant (v0, relr, gnuonly, shadow) this loads the three
 * NSO-like fixture modules from their .flat images using ONLY the generated
 * descriptors (g_aot_g3_<variant>_modules / _bindings):
 *
 *   verify SHA-256 + layout -> map three regions/module -> parse
 *   MOD0/.dynamic/.dynsym -> relocate RELR + RELA + JMPREL -> link digest ->
 *   seal -> symbol lookup -> per-site TSV dump.
 *
 * It also pins the failure and post-seal contracts:
 *   - a tampered image is rejected with AOT_LOAD_ERR_SHA256 and NO region is
 *     added (the module VA is still unmapped);
 *   - a descriptor with a wrong link digest fails at seal with
 *     AOT_LOAD_ERR_DIGEST and the address space is NOT sealed;
 *   - after seal: a guest store to text and to rodata fails with
 *     AOT_MEM_ERR_PERM, a store to data succeeds, and aot_as_query reports
 *     perm 5/1/3 with state 3/3/4.
 *
 * Usage: aot_g3_link_probe <fixture-dir> [variant]
 *
 * Exit protocol (the driver depends on it):
 *   0 = every check passed
 *   2 = at least one semantic check failed (prints "FAIL: <check>")
 *   1 = infrastructure failure (prints "FATAL: <reason>")
 */
#include "aot_as.h"
#include "aot_loader.h"
#include "aot_mem.h"
#include "aot_sha256.h"
#include "host_vm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

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

static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

/* The generated descriptors, one set per link variant. */
extern const AotModuleDesc g_aot_g3_v0_modules[];
extern const uint32_t g_aot_g3_v0_module_count;
extern const AotHostBindings g_aot_g3_v0_bindings;
extern const AotModuleDesc g_aot_g3_relr_modules[];
extern const uint32_t g_aot_g3_relr_module_count;
extern const AotHostBindings g_aot_g3_relr_bindings;
extern const AotModuleDesc g_aot_g3_gnuonly_modules[];
extern const uint32_t g_aot_g3_gnuonly_module_count;
extern const AotHostBindings g_aot_g3_gnuonly_bindings;

/* `shadow`: v0's shape plus an UNDEFINED STB_WEAK dynsym entry in main whose
 * name is main_vtable (DEFINED later in the same table), injected by
 * `aot_module.py shadow-undefined` before elf2flat. It pins the loader rule "the
 * first DEFINED symbol with a name wins", which MN_AOT_MUTANT_SYMBOL_FIRST_ANY
 * breaks by taking the first name match whatever its definition state. */
extern const AotModuleDesc g_aot_g3_shadow_modules[];
extern const uint32_t g_aot_g3_shadow_module_count;
extern const AotHostBindings g_aot_g3_shadow_bindings;

typedef struct Variant {
    const char *name;
    const AotModuleDesc *modules;
    const uint32_t *count;
    const AotHostBindings *bindings;
} Variant;

static const Variant g_variants[] = {
    { "v0",      g_aot_g3_v0_modules,      &g_aot_g3_v0_module_count,
      &g_aot_g3_v0_bindings },
    { "relr",    g_aot_g3_relr_modules,    &g_aot_g3_relr_module_count,
      &g_aot_g3_relr_bindings },
    { "gnuonly", g_aot_g3_gnuonly_modules, &g_aot_g3_gnuonly_module_count,
      &g_aot_g3_gnuonly_bindings },
    { "shadow",  g_aot_g3_shadow_modules,  &g_aot_g3_shadow_module_count,
      &g_aot_g3_shadow_bindings }
};

#define MODULE_COUNT 3u

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

static AotAddressSpace *fresh_space(AotMemDomain **out_domain)
{
    AotMemDomain *domain = aot_mem_domain_create();
    AotAddressSpace *as;

    if (domain == NULL) {
        fatal("aot_mem_domain_create failed");
    }
    as = aot_as_create(domain);
    if (as == NULL) {
        fatal("aot_as_create failed");
    }
    *out_domain = domain;
    return as;
}

/* Tampered image: SHA-256 must fail BEFORE any region exists. */
static void tamper_check(const Variant *var, const uint8_t *const images[],
                        const uint64_t sizes[])
{
    AotModuleSet set;
    AotLoadError err;
    AotMemDomain *domain;
    AotAddressSpace *as;
    AotLoader loader;
    const uint8_t *tampered[MODULE_COUNT];
    uint64_t tampered_sizes[MODULE_COUNT];
    uint32_t m;
    uint32_t bad = 2u;   /* review fix 6: corrupt the LAST module, keep 0/1 good */
    AotAsQuery q;

    uint64_t size = sizes[bad];
    uint8_t *copy = (uint8_t *)malloc((size_t)size);

    if (copy == NULL) {
        fatal("out of memory");
    }
    memcpy(copy, images[bad], (size_t)size);
    copy[8] ^= 0x5au; /* one byte inside the text segment */

    set.modules = var->modules;
    set.count = *var->count;
    if (set.count != MODULE_COUNT) {
        fatal("unexpected module count");
    }
    for (m = 0; m < set.count; m++) {
        tampered[m] = images[m];
        tampered_sizes[m] = sizes[m];
    }
    tampered[bad] = copy;
    tampered_sizes[bad] = size;

    as = fresh_space(&domain);
    memset(&loader, 0, sizeof loader);
    if (aot_loader_init(&loader, as, &set, &err) != AOT_LOAD_OK) {
        fatal("loader init failed in the tamper check");
    }
    aot_loader_set_host_bindings(&loader, var->bindings);

    {
        /* map() re-verifies, so this must fail with the SHA error naming the
         * tampered module and must not have added a region for ANY module
         * (verification is a full pass before the first aot_as_add_region). */
        AotLoadStatus st = aot_loader_map(&loader, tampered, tampered_sizes,
                                          &err);
        check(st == AOT_LOAD_ERR_SHA256, "tampered image rejected by SHA-256");
        check(err.module == bad, "SHA-256 error names the tampered module");
        for (m = 0; m < set.count; m++) {
            check(aot_as_query(as, var->modules[m].guest_base, &q) == 0,
                  "no region was added for any module (incl. the good ones)");
        }
        check(aot_as_is_sealed(as) == 0, "tampered address space is unsealed");
        /* Review fix 1: the failed load poisons the space. */
        check(aot_as_is_poisoned(as) == 1, "failed map poisons the space");
        check(aot_as_seal(as) != AOT_MEM_OK,
              "poisoned space refuses a later seal");
    }

    aot_loader_release(&loader);
    aot_as_destroy(as);
    aot_mem_domain_destroy(domain);
    free(copy);
}

/* A descriptor with the right SHA but a wrong link digest: everything maps and
 * relocates, and the ONLY failure is the digest at seal time. */
static void digest_check(const Variant *var, const uint8_t *const images[],
                         const uint64_t sizes[])
{
    AotModuleDesc wrong[MODULE_COUNT];
    uint8_t bad_digest[AOT_SHA256_DIGEST_BYTES];
    AotModuleSet set;
    AotLoadError err;
    AotMemDomain *domain;
    AotAddressSpace *as;
    AotLoader loader;
    uint32_t m;

    if (*var->count != MODULE_COUNT) {
        fatal("unexpected module count");
    }
    memcpy(wrong, var->modules, sizeof wrong);
    memcpy(bad_digest, var->modules[0].link_digest, sizeof bad_digest);
    bad_digest[0] ^= 0x01u;
    for (m = 0; m < MODULE_COUNT; m++) {
        wrong[m].link_digest = bad_digest;
    }
    set.modules = wrong;
    set.count = MODULE_COUNT;

    as = fresh_space(&domain);
    memset(&loader, 0, sizeof loader);
    if (aot_loader_init(&loader, as, &set, &err) != AOT_LOAD_OK) {
        fatal("loader init failed in the digest check");
    }
    aot_loader_set_host_bindings(&loader, var->bindings);

    {
        AotLoadStatus st = aot_loader_load(&loader, images, sizes, &err);
        check(st == AOT_LOAD_ERR_DIGEST, "wrong link digest is rejected");
        check(loader.digest_matched == 0, "digest flag stays clear");
        check(aot_as_is_sealed(as) == 0,
              "address space is NOT sealed after a digest mismatch");
        /* Review fix 1: the residue must not be sealable (nor growable). */
        check(aot_as_is_poisoned(as) == 1, "failed seal poisons the space");
        check(aot_as_seal(as) != AOT_MEM_OK,
              "poisoned space refuses a later seal");
        check(aot_as_add_region(as, var->modules[2].guest_base + 0x80000000ull,
                                AOT_AS_PAGE_BYTES, AOT_AS_PERM_RW,
                                AOT_AS_STATE_DATA, NULL) != AOT_MEM_OK,
              "poisoned space refuses a later region");
    }

    aot_loader_release(&loader);
    aot_as_destroy(as);
    aot_mem_domain_destroy(domain);
}

/* Review fix 4, positive case: a definition whose value is EXACTLY the image
 * size (the real modules' `end` linker symbol) must be accepted and resolve to
 * base + image_size, while an undefined name still fails. */
static void end_symbol_check(const Variant *var, const AotLoader *loader)
{
    uint64_t va = 0;

    if (aot_loader_symbol(loader, "fx_sdk_end", &va) != AOT_LOAD_OK) {
        check(0, "a symbol defined at value == image_size is accepted");
        return;
    }
    check(va == var->modules[2].guest_base + var->modules[2].image_size,
          "image-end symbol resolves to base + image_size");
    check(aot_loader_symbol(loader, "fx_missing_sym", &va) != AOT_LOAD_OK,
          "an undefined symbol is not resolved by the loader");
    printf("end-symbol: value == image_size accepted (0x%llx)\n",
           (unsigned long long)va);
}

/* Post-seal permissions: text/rodata refuse writes, data accepts them, and the
 * query view reports the Mac states (text 3, data 4). */
static void permission_check(AotAddressSpace *as, const AotModuleDesc *d)
{
    AotAsQuery q;
    uint64_t value = 0x1122334455667788ull;

    check(aot_as_query(as, d->guest_base, &q) == 1, "text page is mapped");
    check(q.perm == AOT_AS_PERM_RX && q.state == AOT_AS_STATE_TEXT,
          "text reports perm 5 state 3");
    check(aot_as_query(as, d->guest_base + d->ro.off, &q) == 1,
          "rodata page is mapped");
    check(q.perm == AOT_AS_PERM_R && q.state == AOT_AS_STATE_TEXT,
          "rodata reports perm 1 state 3");
    check(aot_as_query(as, d->guest_base + d->data.off, &q) == 1,
          "data page is mapped");
    check(q.perm == AOT_AS_PERM_RW && q.state == AOT_AS_STATE_DATA,
          "data reports perm 3 state 4");

    check(aot_as_write(as, d->guest_base + d->text.size - 8u, &value, 8u) ==
              AOT_MEM_ERR_PERM,
          "guest store to text is refused after seal");
    if (d->ro.size >= 8u) {
        check(aot_as_write(as, d->guest_base + d->ro.off, &value, 8u) ==
                  AOT_MEM_ERR_PERM,
              "guest store to rodata is refused after seal");
    }
    /* The last 8 bytes of the file-backed data are a plain data slot. This
     * write happens after the link digest was verified and sealed, so it does
     * not perturb the digest contract. */
    {
        uint64_t probe_addr = d->guest_base + d->data.off + d->data.size - 8u;
        AotMemStatus wst = aot_as_write(as, probe_addr, &value, 8u);
        uint64_t readback = 0;
        AotMemStatus rst = aot_as_read(as, probe_addr, &readback, 8u);
        check(wst == AOT_MEM_OK, "guest store to data is allowed after seal");
        check(rst == AOT_MEM_OK && readback == value,
              "the data store is visible to guest loads");
    }

    /* HOST protection after seal (lead finding): the guest text page is R-X for
     * the GUEST, but the host mapping must be READ-ONLY with no EXECUTE bit -
     * guest text holds ARM64 bytes the host CPU can never execute. Ask the OS
     * (host_vm_query + VirtualQuery), not the software table. */
    {
        host_vm_region *vm = NULL;
        const uint8_t *page = NULL;
        size_t off = 0;
        host_vm_info info;
        MEMORY_BASIC_INFORMATION mbi;

        check(aot_as_host_page(as, d->guest_base, &vm, &page, &off) == 1 &&
                  vm != NULL && page != NULL,
              "sealed text page has a host locator");
        if (vm != NULL && page != NULL) {
            memset(&info, 0, sizeof info);
            check(host_vm_query(vm, off, &info) == HOST_VM_OK,
                  "host_vm_query on the sealed text page succeeds");
            check(info.protection == HOST_VM_PROT_READ,
                  "sealed text page carries host protection READ only");
            check((info.protection & HOST_VM_PROT_EXEC) == 0u,
                  "sealed text page has no HOST_VM_PROT_EXEC bit");

            memset(&mbi, 0, sizeof mbi);
            check(VirtualQuery((LPCVOID)page, &mbi, sizeof mbi) ==
                      sizeof mbi,
                  "VirtualQuery on the sealed text page succeeds");
            check(mbi.Protect == PAGE_READONLY,
                  "sealed guest text page is host READ-ONLY (no EXECUTE)");
            check((mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                  PAGE_EXECUTE_READWRITE |
                                  PAGE_EXECUTE_WRITECOPY)) == 0u,
                  "sealed guest text page carries no PAGE_EXECUTE* bit");
        }
    }
}

/* Review fix 2: a descriptor whose data.size wraps the image size must be
 * rejected as a bad layout BEFORE any memcpy or region exists. */
static void layout_overflow_check(const Variant *var,
                                  const uint8_t *const images[],
                                  const uint64_t sizes[])
{
    AotModuleDesc bad[MODULE_COUNT];
    AotModuleSet set;
    AotLoadError err;
    AotMemDomain *domain;
    AotAddressSpace *as;
    AotLoader loader;
    AotAsQuery q;
    uint32_t m;
    AotLoadStatus st;

    memcpy(bad, var->modules, sizeof bad);
    /* data.off + data.size wraps to a small value; image_size and bss are
     * adjusted so that a naive `off + size` and the
     * `image_size == flat + bss` identity would both appear to hold. */
    bad[1].data.size = UINT64_MAX - bad[1].data.off + 0x1000ull;
    bad[1].image_size = bad[1].data.off + bad[1].data.size; /* wrapped */
    bad[1].bss_size = 0u;
    set.modules = bad;
    set.count = MODULE_COUNT;

    as = fresh_space(&domain);
    memset(&loader, 0, sizeof loader);
    st = aot_loader_init(&loader, as, &set, &err);
    check(st == AOT_LOAD_OK, "overflow case: loader init");
    aot_loader_set_host_bindings(&loader, var->bindings);

    st = aot_loader_verify_images(&set, images, sizes, &err);
    check(st == AOT_LOAD_ERR_LAYOUT, "wrapped data.size is a bad layout");
    check(err.module == 1u, "wrapped data.size names its module");
    st = aot_loader_map(&loader, images, sizes, &err);
    check(st == AOT_LOAD_ERR_LAYOUT, "wrapped data.size rejected by map");
    for (m = 0; m < MODULE_COUNT; m++) {
        check(aot_as_query(as, bad[m].guest_base, &q) == 0,
              "wrapped data.size added no region at all");
    }
    printf("layout-overflow: wrapped data.size rejected before any region\n");

    aot_loader_release(&loader);
    aot_as_destroy(as);
    aot_mem_domain_destroy(domain);
}

/* Review fix 14: the host bindings are mandatory and self-consistent. */
static void bindings_gate_check(const Variant *var,
                               const uint8_t *const images[],
                               const uint64_t sizes[])
{
    static const AotHostBinding dup_overrides[2] = {
        { "host_hook", 0u }, { "host_invoke", 0u }   /* same thunk index */
    };
    AotHostBindings empty;
    AotHostBindings bad;
    AotModuleSet set;
    AotLoadError err;
    AotMemDomain *domain;
    AotAddressSpace *as;
    AotLoader loader;
    AotLoadStatus st;

    set.modules = var->modules;
    set.count = MODULE_COUNT;
    memset(&empty, 0, sizeof empty);
    empty.thunk_base = var->bindings->thunk_base;
    empty.sentinel = var->bindings->sentinel;
    bad = *var->bindings;
    bad.overrides = dup_overrides;
    bad.override_count = 2u;

    /* (a) no bindings attached at all -> typed argument error, no seal. */
    as = fresh_space(&domain);
    memset(&loader, 0, sizeof loader);
    st = aot_loader_init(&loader, as, &set, &err);
    check(st == AOT_LOAD_OK, "bindings gate: loader init");
    st = aot_loader_load(&loader, images, sizes, &err);
    check(st == AOT_LOAD_ERR_ARG, "missing host bindings is an ARG error");
    check(aot_as_is_sealed(as) == 0, "missing bindings never seals");
    aot_loader_release(&loader);
    aot_as_destroy(as);
    aot_mem_domain_destroy(domain);

    /* (b) the same thunk index in two override entries -> ARG error. */
    as = fresh_space(&domain);
    memset(&loader, 0, sizeof loader);
    st = aot_loader_init(&loader, as, &set, &err);
    check(st == AOT_LOAD_OK, "bindings gate: loader init (dup)");
    aot_loader_set_host_bindings(&loader, &bad);
    st = aot_loader_load(&loader, images, sizes, &err);
    check(st == AOT_LOAD_ERR_ARG, "duplicate thunk index is an ARG error");
    aot_loader_release(&loader);
    aot_as_destroy(as);
    aot_mem_domain_destroy(domain);

    /* (c) an EXPLICIT empty table is allowed and still loads. */
    as = fresh_space(&domain);
    memset(&loader, 0, sizeof loader);
    st = aot_loader_init(&loader, as, &set, &err);
    check(st == AOT_LOAD_OK, "bindings gate: loader init (empty)");
    aot_loader_set_host_bindings(&loader, &empty);
    st = aot_loader_load(&loader, images, sizes, &err);
    check(st == AOT_LOAD_ERR_SYMBOL,
          "an empty table makes host-bound imports unresolved");
    aot_loader_release(&loader);
    aot_as_destroy(as);
    aot_mem_domain_destroy(domain);
    printf("bindings-gate: mandatory table, unique thunks, empty table ok\n");
}

/* Major 2: the loader stages are ONE-SHOT. After a successful load, every stage
 * entry point must refuse with a typed AOT_LOAD_ERR_STATE and must not touch a
 * byte: the sealed space stays sealed, unpoisoned and byte-identical (a
 * re-entered stage that poisoned or re-mapped would destroy a runnable
 * program). */
static void stage_rerun_check(const Variant *var, AotLoader *loader,
                              AotAddressSpace *as,
                              const uint8_t *const images[],
                              const uint64_t sizes[])
{
    const AotModuleDesc *d = &var->modules[0];
    const uint64_t data_va = d->guest_base + d->data.off;
    static uint8_t before[256];
    static uint8_t after[256];
    const uint32_t sites_before = aot_loader_site_count(loader);
    AotLoadError err;
    AotLoadStatus st;

    memset(&err, 0, sizeof err);
    if (aot_as_read(as, data_va, before, sizeof before) != AOT_MEM_OK) {
        fatal("stage rerun: cannot snapshot guest data");
    }

    /* map over a sealed space, relocate, seal and the full load again. */
    st = aot_loader_map(loader, images, sizes, &err);
    check(st == AOT_LOAD_ERR_STATE, "map after seal is a STATE error");
    check(err.detail != NULL && strstr(err.detail, "UNSEALED") != NULL,
          "the map refusal names the sealed space");

    st = aot_loader_relocate(loader, &err);
    check(st == AOT_LOAD_ERR_STATE, "relocate after seal is a STATE error");

    st = aot_loader_seal(loader, &err);
    check(st == AOT_LOAD_ERR_STATE, "a second seal is a STATE error");
    check(err.detail != NULL && strstr(err.detail, "already sealed") != NULL,
          "the second-seal refusal says already sealed");

    st = aot_loader_load(loader, images, sizes, &err);
    check(st == AOT_LOAD_ERR_STATE, "a second load is a STATE error");

    /* Nothing may have been poisoned, zeroed, remapped or re-relocated. */
    check(aot_as_is_poisoned(as) == 0,
          "a repeated stage never poisons a sealed space");
    check(aot_as_is_sealed(as) == 1, "the space is still sealed");
    check(loader->sealed == 1, "the loader is still sealed");
    check(loader->digest_matched == 1, "the link digest still matched");
    check(aot_loader_site_count(loader) == sites_before,
          "the site table was not rebuilt");
    if (aot_as_read(as, data_va, after, sizeof after) != AOT_MEM_OK) {
        fatal("stage rerun: cannot re-read guest data");
    }
    check(memcmp(before, after, sizeof before) == 0,
          "guest data is byte-identical after the refused stages");
    printf("%s: repeated map/relocate/seal/load refused, data unchanged\n",
           var->name);
}

/* Minor 3: the image's DT_INIT and the descriptor's init_va are ONE fact. Both
 * mismatches are caught at relocate time with the same typed status:
 *   (a) descriptor init_va == 0 while the image declares DT_INIT (descriptor
 *       copy patched, image untouched);
 *   (b) the image's DT_INIT tag is retagged to an ignored tag while the
 *       descriptor still carries init_va (flat patched, SHA-256 re-pinned).
 * The fixtures carry DT_INIT in all three modules, so (a) is the descriptor
 * side and (b) the image side of the same rule. */
static void init_va_check(const Variant *var, const uint8_t *const images[],
                          const uint64_t sizes[])
{
    AotModuleDesc patched[MODULE_COUNT];
    AotModuleSet set;
    AotLoadError err;
    AotMemDomain *domain;
    AotAddressSpace *as;
    AotLoader loader;
    AotLoadStatus st;

    if (*var->count != MODULE_COUNT) {
        fatal("unexpected module count");
    }

    /* (a) descriptor says "no initialiser", the image declares one. */
    memcpy(patched, var->modules, sizeof patched);
    check(patched[0].init_va != 0u,
          "the fixture descriptors carry a DT_INIT init_va");
    patched[0].init_va = 0u;
    set.modules = patched;
    set.count = MODULE_COUNT;
    as = fresh_space(&domain);
    memset(&loader, 0, sizeof loader);
    if (aot_loader_init(&loader, as, &set, &err) != AOT_LOAD_OK) {
        fatal("init_va check: loader init (a)");
    }
    aot_loader_set_host_bindings(&loader, var->bindings);
    st = aot_loader_load(&loader, images, sizes, &err);
    check(st == AOT_LOAD_ERR_DYNAMIC,
          "a descriptor without init_va for a DT_INIT image is DYNAMIC");
    check(err.detail != NULL &&
              strcmp(err.detail, "DT_INIT presence disagrees with the "
                                 "descriptor's init_va") == 0,
          "the init_va refusal names the DT_INIT presence mismatch");
    check(aot_as_is_sealed(as) == 0, "init_va mismatch never seals");
    aot_loader_release(&loader);
    aot_as_destroy(as);
    aot_mem_domain_destroy(domain);

    /* (b) image declares no initialiser, the descriptor still carries one. */
    {
        const uint32_t size = (uint32_t)sizes[0];
        uint8_t *flat = (uint8_t *)malloc(size);
        uint64_t mod0, dyn_off, off;
        int found = 0;
        uint8_t sha[AOT_SHA256_DIGEST_BYTES];
        AotSha256 ctx;
        uint8_t *patched_images[MODULE_COUNT];

        if (flat == NULL) {
            fatal("out of memory");
        }
        memcpy(flat, images[0], size);
        /* Walk MOD0 -> .dynamic and retag DT_INIT (12) as DT_DEBUG (21), an
         * entry the loader ignores. The tag WORD changes, nothing else. */
        mod0 = rd32(flat + 4u);
        dyn_off = mod0 + (uint64_t)(int32_t)rd32(flat + mod0 + 4u);
        for (off = dyn_off; off + 16u <= (uint64_t)size; off += 16u) {
            uint32_t tag = rd32(flat + off);
            if (tag == 0u) {
                break;
            }
            if (tag == 12u) {
                flat[off] = 21u;
                flat[off + 1u] = 0u;
                flat[off + 2u] = 0u;
                flat[off + 3u] = 0u;
                found = 1;
                break;
            }
        }
        check(found == 1, "the fixture image carries a DT_INIT tag to retag");
        aot_sha256_init(&ctx);
        aot_sha256_update(&ctx, flat, (size_t)size);
        aot_sha256_final(&ctx, sha);

        memcpy(patched, var->modules, sizeof patched);
        patched[0].sha256 = sha;   /* re-pin: the loader verifies the bytes */
        set.modules = patched;
        set.count = MODULE_COUNT;
        memcpy(patched_images, images, sizeof patched_images);
        patched_images[0] = flat;

        as = fresh_space(&domain);
        memset(&loader, 0, sizeof loader);
        if (aot_loader_init(&loader, as, &set, &err) != AOT_LOAD_OK) {
            fatal("init_va check: loader init (b)");
        }
        aot_loader_set_host_bindings(&loader, var->bindings);
        st = aot_loader_load(&loader, patched_images, sizes, &err);
        check(st == AOT_LOAD_ERR_DYNAMIC,
              "an image without DT_INIT for a descriptor init_va is DYNAMIC");
        check(err.detail != NULL &&
                  strcmp(err.detail, "DT_INIT presence disagrees with the "
                                     "descriptor's init_va") == 0,
              "the image-side init_va refusal names the DT_INIT presence "
              "mismatch");
        check(err.module == 0u, "the init_va refusal names module 0");
        aot_loader_release(&loader);
        aot_as_destroy(as);
        aot_mem_domain_destroy(domain);
        free(flat);
    }
    printf("%s: DT_INIT presence and descriptor init_va must agree (both "
           "directions)\n", var->name);
}

int main(int argc, char **argv)
{
    const char *dir;
    const char *only;
    static const char *mods[MODULE_COUNT] = { "fx_main", "fx_sub", "fx_sdk" };
    unsigned v;

    if (argc < 2) {
        printf("usage: %s <fixture-dir> [variant]\n", argv[0]);
        return 1;
    }
    dir = argv[1];
    only = (argc >= 3) ? argv[2] : NULL;

    for (v = 0; v < sizeof g_variants / sizeof g_variants[0]; v++) {
        const Variant *var = &g_variants[v];
        AotModuleSet set;
        AotMemDomain *domain;
        AotAddressSpace *as;
        AotLoader loader;
        AotLoadError err;
        const uint8_t *images[MODULE_COUNT];
        uint64_t sizes[MODULE_COUNT];
        uint8_t *buffers[MODULE_COUNT];
        AotLoadStatus st;
        char path[1024];
        unsigned m;

        if (only != NULL && strcmp(only, var->name) != 0) {
            continue;
        }
        set.modules = var->modules;
        set.count = *var->count;
        check(set.count == MODULE_COUNT, "module count is 3");

        for (m = 0; m < set.count; m++) {
            (void)snprintf(path, sizeof path, "%s/%s_%s.flat", dir, mods[m],
                           var->name);
            buffers[m] = read_file(path, &sizes[m]);
            images[m] = buffers[m];
            check(sizes[m] == var->modules[m].data.off +
                                  var->modules[m].data.size,
                  "flat file size matches the descriptor layout");
        }

        /* The tamper check runs before the good load: it must not depend on
         * the good load having succeeded. The wrong-digest check runs after it,
         * so a loader that breaks the GOOD link reports that failure first
         * (which is the rule the mutant broke), not the digest case. */
        tamper_check(var, images, sizes);
        layout_overflow_check(var, images, sizes);
        bindings_gate_check(var, images, sizes);
        init_va_check(var, images, sizes);

        as = fresh_space(&domain);
        memset(&loader, 0, sizeof loader);
        st = aot_loader_init(&loader, as, &set, &err);
        check(st == AOT_LOAD_OK, "aot_loader_init");
        aot_loader_set_host_bindings(&loader, var->bindings);

        st = aot_loader_load(&loader, images, sizes, &err);
        if (st != AOT_LOAD_OK) {
            printf("FAIL: %s: load failed: %s (module %u, off 0x%llx, "
                   "site 0x%llx, symbol %s, detail: %s)\n",
                   var->name, aot_load_status_name((int)st),
                   (unsigned)err.module, (unsigned long long)err.image_off,
                   (unsigned long long)err.site,
                   err.symbol != NULL ? err.symbol : "-", err.detail);
            g_fail = 1;
        } else {
            printf("%s: loaded, digest matched, %u sites\n", var->name,
                   (unsigned)aot_loader_site_count(&loader));
            check(loader.digest_matched == 1, "link digest matched");
            check(loader.sealed == 1, "address space sealed");
            check(aot_as_is_sealed(as) == 1, "aot_as reports sealed");
            check(aot_loader_site_count(&loader) > 0u, "sites recorded");
            end_symbol_check(var, &loader);

            for (m = 0; m < loader.count; m++) {
                const AotLinkCounters *c = &loader.modules[m].counters;
                printf("counters %s relative=%u symbolic=%u cross=%u "
                       "weak=%u\n",
                       var->modules[m].name, c->relative, c->symbolic,
                       c->cross, c->weak);
            }

            /* Symbol API. */
            {
                uint64_t va = 0;
                st = aot_loader_symbol(&loader, "sdk_add", &va);
                check(st == AOT_LOAD_OK &&
                          (va >> 32) ==
                              (var->modules[2].guest_base >> 32),
                      "aot_loader_symbol(sdk_add) resolves into fx_sdk");
                check(va >= var->modules[2].guest_base &&
                          va < var->modules[2].guest_base +
                                   var->modules[2].image_size,
                      "symbol VA is inside the module's own guest range");
                st = aot_loader_symbol(&loader, "no_such_symbol_xyz", &va);
                check(st == AOT_LOAD_ERR_SYMBOL, "unknown symbol is not found");
            }

            /* Values are guest VAs (or a weak import resolved to 0). */
            {
                static AotLinkSite sites[4096];
                uint32_t i;
                uint32_t n = aot_loader_site_count(&loader);
                check(n <= 4096u, "site count fits the dump buffer");
                if (n > 4096u) {
                    n = 4096u;
                }
                for (i = 0; i < n; i++) {
                    check(aot_loader_site(&loader, i, &sites[i]) == 1,
                          "site iterator");
                    /* Review fix 5: a resolved symbol value S is a guest VA
                     * (module or thunk) or 0 for an unresolved weak import;
                     * the SITE value is S + A, so a small non-zero value is
                     * legitimate exactly when A != 0 on such a site. */
                    check(sites[i].value >= AOT_AS_MIN_ADDR ||
                              sites[i].value <= 0x10000ull,
                          "relocated value is a guest VA or a small 0+A");
                }
                /* Dump in the reference TSV order (module name, then offset). */
                {
                    static AotLinkSite sorted[4096];
                    uint32_t k;
                    for (k = 0; k < n; k++) {
                        uint32_t p = k;
                        for (;;) {
                            if (p == 0u) {
                                break;
                            }
                            {
                                const AotLinkSite *prev = &sorted[p - 1u];
                                int cmp = strcmp(
                                    var->modules[prev->module].name,
                                    var->modules[sites[k].module].name);
                                if (cmp == 0) {
                                    cmp = (prev->where < sites[k].where)
                                              ? -1
                                              : (prev->where > sites[k].where)
                                                    ? 1
                                                    : 0;
                                }
                                if (cmp <= 0) {
                                    break;
                                }
                            }
                            sorted[p] = sorted[p - 1u];
                            p--;
                        }
                        sorted[p] = sites[k];
                    }
                    (void)snprintf(path, sizeof path, "%s/fx_%s.c_dump.tsv",
                                   dir, var->name);
                    {
                        FILE *f = fopen(path, "wb");
                        if (f == NULL) {
                            fatal("cannot write the site dump");
                        }
                        fprintf(f, "module\twhere\tkind\tsymbol\tvalue\n");
                        for (k = 0; k < n; k++) {
                            fprintf(f, "%s\t0x%x\t%u\t%s\t0x%016llx\n",
                                    var->modules[sorted[k].module].name,
                                    (unsigned)sorted[k].where,
                                    (unsigned)sorted[k].kind,
                                    sorted[k].symbol != NULL
                                        ? sorted[k].symbol
                                        : "-",
                                    (unsigned long long)sorted[k].value);
                        }
                        fclose(f);
                    }
                    printf("%s: wrote %s (%u sites)\n", var->name, path,
                           (unsigned)n);
                }
            }

            permission_check(as, &var->modules[0]);
            stage_rerun_check(var, &loader, as, images, sizes);
            digest_check(var, images, sizes);
        }

        aot_loader_release(&loader);
        aot_as_destroy(as);
        aot_mem_domain_destroy(domain);
        for (m = 0; m < set.count; m++) {
            free(buffers[m]);
        }
    }

    if (g_fail) {
        printf("aot_g3_link_probe: FAILED\n");
        return 2;
    }
    printf("aot_g3_link_probe: all variants loaded, relocated and sealed\n");
    return 0;
}
