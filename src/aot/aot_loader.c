/*
 * G3 increment 2: translated-module loader (T3).
 *
 * Staged contract (src/aot/aot_loader.h):
 *   verify_images : pinned layout + flat size + SHA-256 for EVERY module,
 *                   before any region exists or any byte is written.
 *   map           : three regions per module (text R-X, rodata R, data+bss RW),
 *                   flat bytes copied and bss/page tails zero-filled through
 *                   INIT-ONLY host pointers. The space stays unsealed, and
 *                   aot_as keeps every host page committed RW until seal, so
 *                   the declared text/rodata permissions cannot block the
 *                   initial population.
 *   relocate      : MOD0/.dynamic/.dynsym parsing, RELR + RELA + JMPREL with
 *                   the Mac reference linker's exact resolution order. Every
 *                   written value is a 64-bit guest VA.
 *   seal          : link digest over each module's relocated data segment,
 *                   compared with the descriptor's offline digest, then
 *                   aot_as_seal() applies the declared permissions.
 *
 * Behavioural reference (read only, games/ unchanged):
 *   games/totk/runtime/loader.c (relocate / verify_identity / module_inits),
 *   games/totk/scripts/prepare_runtime.py (MOD0, dynamic, dynsym, RELA/RELR),
 *   games/totk/third_party/d2r/relr.py (RELR decoding).
 * MUTANTS (T4). Each MN_AOT_MUTANT_* below is a deliberately WRONG loader used
 * only by tests/aot/... via tools/aot/g3_mutant_test.py: it must be caught by a
 * specific probe check. None of them may ever be defined in a shipping build;
 * each is a one-line deviation from the rule stated next to it.
 *
 * The independent Python reference linker (tools/aot/aot_module.py link) is
 * the executable statement of the same rules; this file must agree with it
 * site for site (checked by tests/aot/aot_g3_link_probe.c).
 */
#include "aot_loader.h"

#include "aot_as.h"
#include "aot_sha256.h"

#include <stdlib.h>
#include <string.h>

/* ---- ELF constants used by the NSO-shaped flat image ------------------- */
#define DT_NULL     0
#define DT_PLTRELSZ 2
#define DT_HASH     4
#define DT_STRTAB   5
#define DT_SYMTAB   6
#define DT_RELA     7
#define DT_RELASZ   8
#define DT_RELAENT  9
#define DT_STRSZ    10
#define DT_SYMENT   11
#define DT_INIT     12
#define DT_PLTREL   20
#define DT_JMPREL   23
#define DT_RELRSZ   35
#define DT_RELR     36
#define DT_RELRENT  37

#define DT_PLTREL_RELA 7

#define R_AARCH64_ABS64     257u
#define R_AARCH64_GLOB_DAT  1025u
#define R_AARCH64_JUMP_SLOT 1026u
#define R_AARCH64_RELATIVE  1027u

#define SYM_ENTRY_BYTES   24u
#define RELA_ENTRY_BYTES  24u
#define RELR_ENTRY_BYTES  8u

#define STB_WEAK 2u
#define STT_TLS  6u
#define SHN_LORESERVE 0xff00u

#define AOT_LOADER_INITIAL_SITES 64u

static uint64_t aot_loader_page_up(uint64_t v)
{
    return (v + AOT_AS_PAGE_MASK) & ~AOT_AS_PAGE_MASK;
}

/* end = page_up(off + size), computed WITHOUT any addition that can wrap
 * (review fix 2). Returns 0 when the range cannot be mapped, so every caller
 * can reject the descriptor before a memcpy or a region exists. */
static int range_page_end(uint64_t off, uint64_t size, uint64_t *end)
{
    uint64_t sum;

    if (size > UINT64_MAX - off) {
        return 0;
    }
    sum = off + size;
    if (sum > UINT64_MAX - AOT_AS_PAGE_MASK) {
        return 0;
    }
    *end = (sum + AOT_AS_PAGE_MASK) & ~AOT_AS_PAGE_MASK;
    return 1;
}

/* Little-endian readers over guest memory (the guest is little-endian and
 * every table in the image is LE; spelling it out keeps the loader independent
 * of the host byte order). */
static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t rd64(const uint8_t *p)
{
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

static void wr64(uint8_t *p, uint64_t v)
{
    unsigned i;

    for (i = 0; i < 8u; i++) {
        p[i] = (uint8_t)(v >> (8u * i));
    }
}

const char *aot_load_status_name(int status)
{
    switch (status) {
    case AOT_LOAD_OK:              return "ok";
    case AOT_LOAD_ERR_ARG:         return "invalid-argument";
    case AOT_LOAD_ERR_COUNT:       return "bad-module-count";
    case AOT_LOAD_ERR_LAYOUT:      return "bad-descriptor-layout";
    case AOT_LOAD_ERR_SIZE:        return "image-size-mismatch";
    case AOT_LOAD_ERR_SHA256:      return "image-sha256-mismatch";
    case AOT_LOAD_ERR_OVERLAP:     return "module-range-overlap";
    case AOT_LOAD_ERR_STATE:       return "bad-loader-state";
    case AOT_LOAD_ERR_MAP:         return "address-space-refused-region";
    case AOT_LOAD_ERR_MOD0:        return "bad-mod0";
    case AOT_LOAD_ERR_DYNAMIC:     return "bad-dynamic";
    case AOT_LOAD_ERR_SYMBOLS:     return "bad-symbols";
    case AOT_LOAD_ERR_RELOC:       return "bad-relocation";
    case AOT_LOAD_ERR_DIGEST:      return "link-digest-mismatch";
    case AOT_LOAD_ERR_SEAL:        return "seal-failed";
    case AOT_LOAD_ERR_SYMBOL:      return "unresolved-symbol";
    case AOT_LOAD_ERR_OOM:         return "out-of-memory";
    default:                       return "unknown-status";
    }
}

static AotLoadStatus aot_loader_fail(AotLoadError *err, AotLoadStatus status,
                                     uint32_t module, uint64_t image_off,
                                     uint64_t site, const char *symbol,
                                     const char *detail)
{
    if (err != NULL) {
        err->status = (int)status;
        err->module = module;
        err->image_off = image_off;
        err->site = site;
        err->symbol = symbol;
        err->detail = (detail != NULL)
                          ? detail
                          : aot_load_status_name((int)status);
    }
    return status;
}

/* The three regions of a module are separate host reservations, so every access
 * to image bytes goes through this resolver. A range that would cross a region
 * boundary (or land in an unmapped gap) is rejected: no table in an NSO-shaped
 * image straddles segments, so a straddle means the image is not what the
 * descriptor pinned. */
static const uint8_t *image_ptr(const AotLoaderModule *m, uint64_t off,
                                uint64_t len)
{
    const AotLoaderRegion *regions[3];
    unsigned i;

    regions[0] = &m->text;
    regions[1] = &m->ro;
    regions[2] = &m->data;
    if (len == 0u || off > m->image_size || len > m->image_size - off) {
        return NULL;
    }
    for (i = 0; i < 3u; i++) {
        const AotLoaderRegion *r = regions[i];
        if (r->host == NULL || r->image_len == 0u) {
            continue;
        }
        if (off >= r->image_off && off - r->image_off <= r->image_len &&
            len <= r->image_len - (off - r->image_off)) {
            return r->host + (off - r->image_off);
        }
    }
    return NULL;
}

static uint8_t *image_ptr_rw(AotLoaderModule *m, uint64_t off, uint64_t len)
{
    return (uint8_t *)image_ptr(m, off, len);
}

AotLoadStatus aot_loader_init(AotLoader *loader, AotAddressSpace *as,
                              const AotModuleSet *set, AotLoadError *err)
{
    if (loader == NULL || as == NULL || set == NULL || set->modules == NULL) {
        return aot_loader_fail(err, AOT_LOAD_ERR_ARG, AOT_LOADER_NO_MODULE,
                               0u, 0u, NULL, "loader/space/module set is NULL");
    }
    if (set->count == 0u || set->count > AOT_LOADER_MAX_MODULES) {
        return aot_loader_fail(err, AOT_LOAD_ERR_COUNT, AOT_LOADER_NO_MODULE,
                               0u, 0u, NULL,
                               "module count outside 1..AOT_LOADER_MAX_MODULES");
    }
    memset(loader, 0, sizeof *loader);
    loader->as = as;
    loader->set = set;
    loader->count = set->count;
    if (err != NULL) {
        memset(err, 0, sizeof *err);
        err->module = AOT_LOADER_NO_MODULE;
        err->detail = "ok";
    }
    return AOT_LOAD_OK;
}

static void aot_loader_free_tables(AotLoader *loader)
{
    uint32_t i;

    free(loader->sites);
    loader->sites = NULL;
    loader->site_count = 0;
    loader->site_capacity = 0;
    for (i = 0; i < AOT_LOADER_MAX_MODULES; i++) {
        free(loader->modules[i].site_bits);
        loader->modules[i].site_bits = NULL;
        loader->modules[i].site_bits_bytes = 0u;
        free(loader->modules[i].sym_index);
        loader->modules[i].sym_index = NULL;
        loader->modules[i].sym_index_cap = 0u;
    }
}

/* Review fix 1: a load that failed AFTER a region was added leaves a partially
 * populated space. Its RW data regions are zeroed (the loader's own writes must
 * not survive as apparent state) and the space is poisoned so it can never be
 * sealed or grown; the caller destroys it.
 *
 * Major 2: a SEALED space is untouchable. A stage call made after a successful
 * load is a caller error, not a load failure: zeroing a sealed module's data
 * would corrupt a runnable program and poisoning would stop it from running, so
 * the poison is a NO-OP once sealed (the stage re-entry itself is refused by
 * stage_precheck before it can reach here). */
static void aot_loader_poison(AotLoader *loader)
{
    uint32_t i;

    if (loader == NULL || loader->as == NULL) {
        return;
    }
    if (aot_as_is_sealed(loader->as)) {
        return;
    }
    for (i = 0; i < loader->count; i++) {
        AotLoaderRegion *r = &loader->modules[i].data;
        if (r->host != NULL && r->size != 0u) {
            memset(r->host, 0, (size_t)r->size);
        }
    }
    aot_as_poison(loader->as);
}

void aot_loader_set_host_bindings(AotLoader *loader,
                                  const AotHostBindings *bindings)
{
    if (loader != NULL) {
        loader->bindings = bindings;
    }
}

void aot_loader_set_link_only(AotLoader *loader, const char *const *names,
                              uint32_t count)
{
    if (loader != NULL) {
        loader->link_only = (count != 0u) ? names : NULL;
        loader->link_only_count = (count != 0u) ? count : 0u;
    }
}

void aot_loader_release(AotLoader *loader)
{
    if (loader == NULL) {
        return;
    }
    aot_loader_free_tables(loader);
    memset(loader->modules, 0, sizeof loader->modules);
    /* A new load invalidates any Program assembled from the old one. */
    loader->program_built = 0u;
    loader->verified = 0;
    loader->mapped = 0;
    loader->relocated = 0;
    loader->sealed = 0;
    loader->digest_matched = 0;
    loader->count = 0;
}

/* Static checks on one descriptor: ranges are ordered, non-empty where they
 * must be, inside the declared image, page-separated (three regions may not
 * overlap) and the guest range is mappable. */
static AotLoadStatus aot_loader_check_layout(const AotModuleDesc *d,
                                             uint64_t *out_flat,
                                             AotLoadError *err, uint32_t index)
{
    uint64_t flat;
    uint64_t map;
    uint64_t t_end;
    uint64_t ro_end;

    if (d->name == NULL || d->sha256 == NULL || d->link_digest == NULL) {
        return aot_loader_fail(err, AOT_LOAD_ERR_LAYOUT, index, 0u, 0u, NULL,
                               "descriptor is missing name/sha256/link_digest");
    }
    /* The flat image starts with the text segment at offset 0: byte 4 is the
     * MOD0 offset, so an image that does not start with text is not
     * NSO-shaped. */
    if (d->text.off != 0u || d->text.size == 0u) {
        return aot_loader_fail(err, AOT_LOAD_ERR_LAYOUT, index, d->text.off,
                               0u, NULL, "text must start at image offset 0");
    }
    /* Every segment boundary check is written in SUBTRACTION form (review fix
     * 2): an `off + size` that wraps must be rejected as a bad layout rather
     * than passing a comparison and reaching page_up()/memcpy() later. */
    if (d->ro.off < d->text.off || d->text.size > d->ro.off - d->text.off) {
        return aot_loader_fail(err, AOT_LOAD_ERR_LAYOUT, index, d->text.off,
                               0u, NULL, "text overlaps the rodata segment");
    }
    if (d->data.off < d->ro.off || d->ro.size > d->data.off - d->ro.off) {
        return aot_loader_fail(err, AOT_LOAD_ERR_LAYOUT, index, d->ro.off,
                               0u, NULL, "rodata overlaps the data segment");
    }
    /* Every region is page-granular, so a segment must not share a page with
     * its neighbour: text's last page may not reach rodata's first byte, and
     * rodata's may not reach data's. */
    if (!range_page_end(d->text.off, d->text.size, &t_end) ||
        t_end > d->ro.off) {
        return aot_loader_fail(err, AOT_LOAD_ERR_LAYOUT, index, 0u, 0u, NULL,
                               "segments are not page-separated");
    }
    if (!range_page_end(d->ro.off, d->ro.size, &ro_end) ||
        ro_end > d->data.off) {
        return aot_loader_fail(err, AOT_LOAD_ERR_LAYOUT, index, 0u, 0u, NULL,
                               "segments are not page-separated");
    }
    if ((d->ro.off & AOT_AS_PAGE_MASK) != 0u ||
        (d->data.off & AOT_AS_PAGE_MASK) != 0u || d->data.size == 0u) {
        return aot_loader_fail(err, AOT_LOAD_ERR_LAYOUT, index, d->data.off,
                               0u, NULL, "segment offsets are not page aligned");
    }
    /* flat = data.off + data.size, and image_size must equal flat + bss with
     * neither sum wrapping. A wrapped data.size therefore dies HERE, long
     * before aot_loader_map() copies anything. */
    if (d->data.size > UINT64_MAX - d->data.off) {
        return aot_loader_fail(err, AOT_LOAD_ERR_LAYOUT, index, d->data.off,
                               0u, NULL, "data segment wraps the image size");
    }
    flat = d->data.off + d->data.size;
    if (d->image_size < flat || d->bss_size != d->image_size - flat) {
        return aot_loader_fail(err, AOT_LOAD_ERR_LAYOUT, index, flat, 0u, NULL,
                               "image_size != flat bytes + bss_size");
    }
    if (d->guest_base < AOT_AS_MIN_ADDR ||
        (d->guest_base & AOT_AS_PAGE_MASK) != 0u) {
        return aot_loader_fail(err, AOT_LOAD_ERR_LAYOUT, index, 0u,
                               d->guest_base, NULL,
                               "guest_base is below 2^32 or not page aligned");
    }
    if (d->guest_base >= AOT_AS_MAX_ADDR ||
        !range_page_end(0u, d->image_size, &map) || map == 0u ||
        map > AOT_AS_MAX_ADDR - d->guest_base) {
        return aot_loader_fail(err, AOT_LOAD_ERR_LAYOUT, index, 0u,
                               d->guest_base, NULL,
                               "guest range is empty, wraps or reaches 2^39");
    }
    *out_flat = flat;
    return AOT_LOAD_OK;
}

AotLoadStatus aot_loader_verify_images(const AotModuleSet *set,
                                       const uint8_t *const images[],
                                       const uint64_t sizes[],
                                       AotLoadError *err)
{
    uint64_t flats[AOT_LOADER_MAX_MODULES];
    uint32_t i;
    uint32_t j;

    if (err != NULL) {
        memset(err, 0, sizeof *err);
        err->module = AOT_LOADER_NO_MODULE;
        err->detail = "ok";
    }
    if (set == NULL || set->modules == NULL || images == NULL ||
        sizes == NULL) {
        return aot_loader_fail(err, AOT_LOAD_ERR_ARG, AOT_LOADER_NO_MODULE,
                               0u, 0u, NULL,
                               "module set or image/size arrays are NULL");
    }
    if (set->count == 0u || set->count > AOT_LOADER_MAX_MODULES) {
        return aot_loader_fail(err, AOT_LOAD_ERR_COUNT, AOT_LOADER_NO_MODULE,
                               0u, 0u, NULL,
                               "module count outside 1..AOT_LOADER_MAX_MODULES");
    }

    /* Pass 1: layout of every module and no overlapping guest ranges, before
     * hashing a single byte. */
    for (i = 0; i < set->count; i++) {
        AotLoadStatus st = aot_loader_check_layout(&set->modules[i],
                                                   &flats[i], err, i);
        if (st != AOT_LOAD_OK) {
            return st;
        }
        for (j = 0; j < i; j++) {
            uint64_t a_lo = set->modules[j].guest_base;
            uint64_t a_hi = a_lo +
                            aot_loader_page_up(set->modules[j].image_size);
            uint64_t b_lo = set->modules[i].guest_base;
            uint64_t b_hi = b_lo +
                            aot_loader_page_up(set->modules[i].image_size);
            if (a_lo < b_hi && b_lo < a_hi) {
                return aot_loader_fail(err, AOT_LOAD_ERR_OVERLAP, i, 0u, b_lo,
                                       set->modules[i].name,
                                       "module range overlaps an earlier module");
            }
        }
    }

    /* Pass 2: exact size and SHA-256 per module. Nothing has been mapped. */
    for (i = 0; i < set->count; i++) {
        const AotModuleDesc *d = &set->modules[i];
        uint8_t digest[AOT_SHA256_DIGEST_BYTES];

        if (images[i] == NULL) {
            return aot_loader_fail(err, AOT_LOAD_ERR_ARG, i, 0u, 0u, d->name,
                                   "image pointer is NULL");
        }
        if (sizes[i] != flats[i]) {
            return aot_loader_fail(err, AOT_LOAD_ERR_SIZE, i, sizes[i], 0u,
                                   d->name,
                                   "flat image size != data.off + data.size");
        }
        aot_sha256(images[i], (size_t)sizes[i], digest);
        if (memcmp(digest, d->sha256, AOT_SHA256_DIGEST_BYTES) != 0) {
            return aot_loader_fail(err, AOT_LOAD_ERR_SHA256, i, 0u, 0u, d->name,
                                   "image SHA-256 does not match the descriptor");
        }
    }
    return AOT_LOAD_OK;
}

/* Add one region for `image_off..image_off+image_len`, copy the flat bytes from
 * `src`, and zero everything from image_len to the mapped end. */
static AotLoadStatus add_region(AotLoader *loader, uint32_t index,
                                AotLoaderRegion *r, uint64_t image_off,
                                uint64_t image_len, uint64_t map_end,
                                uint32_t perm, uint32_t state,
                                const uint8_t *src, AotLoadError *err)
{
    const AotModuleDesc *d = &loader->set->modules[index];
    uint64_t base = d->guest_base + image_off;
    uint64_t size = map_end - image_off;
    void *host = NULL;
    AotMemStatus ms;

    if (image_len == 0u || size == 0u) {
        return AOT_LOAD_OK;
    }
    ms = aot_as_add_region(loader->as, base, size, perm, state, &host);
    if (ms != AOT_MEM_OK || host == NULL) {
        return aot_loader_fail(err, AOT_LOAD_ERR_MAP, index, image_off, base,
                               d->name,
                               (ms == AOT_MEM_OK)
                                   ? "add_region returned no host pointer"
                                   : "aot_as_add_region rejected the range");
    }
    memcpy(host, src, (size_t)image_len);
    memset((uint8_t *)host + image_len, 0, (size_t)(size - image_len));

    r->image_off = image_off;
    r->image_len = image_len;
    r->guest_base = base;
    r->size = size;
    r->host = (uint8_t *)host;
    return AOT_LOAD_OK;
}

/* ---- stage order ------------------------------------------------------- */

/* Major 2: the stage order is a PRECONDITION, not a load failure. A repeated or
 * out-of-order stage call (map after map, anything after seal, a map over a
 * sealed space) is refused here, BEFORE the stage body runs, with a typed
 * AOT_LOAD_ERR_STATE: nothing is mapped, written, zeroed or poisoned, so a
 * program that already loaded successfully stays byte-identical and runnable.
 * The public entry points call this; a body is only reached in-stage, which is
 * also why a body failure can still legitimately poison. */
typedef enum {
    AOT_LOADER_STAGE_MAP = 0,
    AOT_LOADER_STAGE_RELOCATE = 1,
    AOT_LOADER_STAGE_SEAL = 2
} AotLoaderStage;

static AotLoadStatus stage_precheck(const AotLoader *loader, AotLoaderStage want,
                                    AotLoadError *err)
{
    if (loader == NULL || loader->as == NULL || loader->set == NULL) {
        return aot_loader_fail(err, AOT_LOAD_ERR_ARG, AOT_LOADER_NO_MODULE,
                               0u, 0u, NULL, "loader is not initialised");
    }
    if (loader->count == 0u || loader->count != loader->set->count) {
        return aot_loader_fail(err, AOT_LOAD_ERR_STATE, AOT_LOADER_NO_MODULE,
                               0u, 0u, NULL, "module table is empty or stale");
    }
    if (aot_as_is_poisoned(loader->as)) {
        /* The residue of a FAILED load: no stage may run on it. */
        return aot_loader_fail(err, AOT_LOAD_ERR_STATE, AOT_LOADER_NO_MODULE,
                               0u, 0u, NULL,
                               "the address space is poisoned by a failed "
                               "load and refuses every stage");
    }
    switch (want) {
    case AOT_LOADER_STAGE_MAP:
        if (loader->sealed || aot_as_is_sealed(loader->as)) {
            return aot_loader_fail(err, AOT_LOAD_ERR_STATE,
                                   AOT_LOADER_NO_MODULE, 0u, 0u, NULL,
                                   "mapping requires an UNSEALED address "
                                   "space");
        }
        if (loader->mapped) {
            return aot_loader_fail(err, AOT_LOAD_ERR_STATE,
                                   AOT_LOADER_NO_MODULE, 0u, 0u, NULL,
                                   "already mapped");
        }
        if (loader->relocated) {
            return aot_loader_fail(err, AOT_LOAD_ERR_STATE,
                                   AOT_LOADER_NO_MODULE, 0u, 0u, NULL,
                                   "already relocated");
        }
        break;
    case AOT_LOADER_STAGE_RELOCATE:
        if (loader->sealed || aot_as_is_sealed(loader->as)) {
            return aot_loader_fail(err, AOT_LOAD_ERR_STATE,
                                   AOT_LOADER_NO_MODULE, 0u, 0u, NULL,
                                   "relocation requires an UNSEALED address "
                                   "space");
        }
        if (!loader->mapped) {
            return aot_loader_fail(err, AOT_LOAD_ERR_STATE,
                                   AOT_LOADER_NO_MODULE, 0u, 0u, NULL,
                                   "relocation requires a mapped loader");
        }
        if (loader->relocated) {
            return aot_loader_fail(err, AOT_LOAD_ERR_STATE,
                                   AOT_LOADER_NO_MODULE, 0u, 0u, NULL,
                                   "already relocated");
        }
        break;
    case AOT_LOADER_STAGE_SEAL:
    default:
        if (loader->sealed || aot_as_is_sealed(loader->as)) {
            return aot_loader_fail(err, AOT_LOAD_ERR_STATE,
                                   AOT_LOADER_NO_MODULE, 0u, 0u, NULL,
                                   "already sealed");
        }
        if (!loader->relocated) {
            return aot_loader_fail(err, AOT_LOAD_ERR_STATE,
                                   AOT_LOADER_NO_MODULE, 0u, 0u, NULL,
                                   "seal requires a relocated loader");
        }
        break;
    }
    return AOT_LOAD_OK;
}

static AotLoadStatus map_impl(AotLoader *loader, const uint8_t *const images[],
                              const uint64_t sizes[], AotLoadError *err)
{
    const AotModuleSet *set;
    AotLoadStatus st;
    uint32_t i;

    /* The stage order (mapped / relocated / sealed / poisoned) was checked by
     * stage_precheck before this body ran. */
    set = loader->set;

    /* Verification is not a precondition the caller may skip. */
    st = aot_loader_verify_images(set, images, sizes, err);
    if (st != AOT_LOAD_OK) {
        return st;
    }

    for (i = 0; i < loader->count; i++) {
        const AotModuleDesc *d = &set->modules[i];
        AotLoaderModule *m = &loader->modules[i];
        uint64_t flat = d->data.off + d->data.size;
        uint64_t data_end = aot_loader_page_up(d->image_size);

        m->desc = d;
        m->image_size = d->image_size;
        m->flat_size = flat;
        m->sym_count = d->dynsym_count;
        m->init_va = d->init_va;

        /* text: [0, page_up(text.size)) RX */
        st = add_region(loader, i, &m->text, 0u, d->text.size,
                        aot_loader_page_up(d->text.size), AOT_AS_PERM_RX,
                        AOT_AS_STATE_TEXT, images[i], err);
        if (st != AOT_LOAD_OK) {
            return st;
        }
        /* rodata: [ro.off, page_up(ro.off+ro.size)) R, reported as state 3 */
        st = add_region(loader, i, &m->ro, d->ro.off, d->ro.size,
                        aot_loader_page_up(d->ro.off + d->ro.size),
                        AOT_AS_PERM_R, AOT_AS_STATE_TEXT,
                        images[i] + d->ro.off, err);
        if (st != AOT_LOAD_OK) {
            return st;
        }
        /* data: [data.off, page_up(image_size)) RW; bss is the tail */
        st = add_region(loader, i, &m->data, d->data.off, d->data.size,
                        data_end, AOT_AS_PERM_RW, AOT_AS_STATE_DATA,
                        images[i] + d->data.off, err);
        if (st != AOT_LOAD_OK) {
            return st;
        }
    }

    loader->mapped = 1;
    if (err != NULL) {
        memset(err, 0, sizeof *err);
        err->module = AOT_LOADER_NO_MODULE;
        err->detail = "ok";
    }
    return AOT_LOAD_OK;
}

/* ---- dynamic section ------------------------------------------------- */

typedef struct DynamicTags {
    uint64_t hash, strtab, symtab, strsz;
    uint64_t rela, relasz, relaent;
    uint64_t jmprel, pltrelsz, pltrel;
    uint64_t relr, relrsz, relrent;
    uint64_t syment;
    uint64_t init;
    uint64_t dyn_off;   /* Minor 5: .dynamic [off, off+dyn_size) */
    uint64_t dyn_size;
    int has_hash, has_strtab, has_symtab, has_strsz, has_rela, has_relasz;
    int has_relaent, has_jmprel, has_pltrelsz, has_pltrel, has_relr;
    int has_relrsz, has_relrent, has_syment, has_init;
} DynamicTags;

static AotLoadStatus parse_dynamic(AotLoaderModule *m, DynamicTags *tags,
                                   AotLoadError *err, uint32_t index)
{
    const uint8_t *p = image_ptr(m, 4u, 4u);
    uint64_t mod0_off;
    const uint8_t *hdr;
    uint64_t dyn_off;
    uint64_t off;

    memset(tags, 0, sizeof *tags);
    if (p == NULL) {
        return aot_loader_fail(err, AOT_LOAD_ERR_MOD0, index, 4u, 0u,
                               m->desc->name, "no MOD0 offset word at +4");
    }
    mod0_off = rd32(p);
    if ((mod0_off & 3u) != 0u || mod0_off + 32u > m->image_size) {
        return aot_loader_fail(err, AOT_LOAD_ERR_MOD0, index, 4u, 0u,
                               m->desc->name, "MOD0 offset out of the image");
    }
    hdr = image_ptr(m, mod0_off, 32u);
    if (hdr == NULL) {
        return aot_loader_fail(err, AOT_LOAD_ERR_MOD0, index, mod0_off, 0u,
                               m->desc->name, "MOD0 header is not mapped");
    }
    if (memcmp(hdr, "MOD0", 4u) != 0) {
        return aot_loader_fail(err, AOT_LOAD_ERR_MOD0, index, mod0_off, 0u,
                               m->desc->name, "missing MOD0 magic");
    }
    /* MOD0 fields are relative to the MOD0 header.
     *
     * Increment 4 (measured on the real v1.0.0 modules): bss_start is NOT the
     * end of the file-backed data -- the linker aligns it up, so a zero gap of
     * up to a page may sit between the flat image and bss (main +0x10,
     * subsdk0 +0x508, sdk +0x170).  What must hold is the ordering and the
     * page-rounded image end:
     *
     *     flat_size <= bss_start <= bss_end <= image_size
     *     image_size is bss_end or page_up(bss_end)
     *
     * The fixtures pin the exact end (bss_end == image_size); the real modules
     * pin the page-rounded end (main 0x4665c60 -> 0x4666000). Both map to
     * page_up(image_size) identically, so accepting the pair costs nothing and
     * keeps the fixtures' `end == image_size` invariant.
     *
     * The previous rule (both equalities) rejected every real module.  All
     * checks are written so that a negative or wrapping offset cannot pass. */
    {
        int32_t dyn_rel = (int32_t)rd32(hdr + 4);
        int32_t bss_start_rel = (int32_t)rd32(hdr + 8);
        int32_t bss_end_rel = (int32_t)rd32(hdr + 12);
        uint64_t bss_start;
        uint64_t bss_end;

        if (dyn_rel < 0) {
            return aot_loader_fail(err, AOT_LOAD_ERR_MOD0, index, mod0_off, 0u,
                                   m->desc->name, "negative dynamic offset");
        }
        dyn_off = mod0_off + (uint64_t)dyn_rel;
        if (bss_start_rel < 0 || bss_end_rel < 0) {
            return aot_loader_fail(err, AOT_LOAD_ERR_MOD0, index, mod0_off, 0u,
                                   m->desc->name, "negative MOD0 bss offset");
        }
        bss_start = mod0_off + (uint64_t)bss_start_rel;
        bss_end = mod0_off + (uint64_t)bss_end_rel;
        if (bss_start < m->flat_size) {
            return aot_loader_fail(err, AOT_LOAD_ERR_MOD0, index, mod0_off, 0u,
                                   m->desc->name,
                                   "MOD0 bss_start is before the data end");
        }
        if (bss_end < bss_start) {
            return aot_loader_fail(err, AOT_LOAD_ERR_MOD0, index, mod0_off, 0u,
                                   m->desc->name,
                                   "MOD0 bss_end is before bss_start");
        }
        if (bss_end > m->image_size) {
            return aot_loader_fail(err, AOT_LOAD_ERR_MOD0, index, mod0_off, 0u,
                                   m->desc->name,
                                   "MOD0 bss_end is past the image end");
        }
        if (bss_end != m->image_size &&
            aot_loader_page_up(bss_end) != m->image_size) {
            return aot_loader_fail(err, AOT_LOAD_ERR_MOD0, index, mod0_off, 0u,
                                   m->desc->name,
                                   "image_size is neither MOD0 bss_end nor "
                                   "page_up(bss_end)");
        }
    }
    /* .dynamic always lives in the RW (data) segment of an NSO. */
    if (m->data.image_len < 16u) {
        return aot_loader_fail(err, AOT_LOAD_ERR_LAYOUT, index, 0u, 0u,
                               m->desc->name, "data segment is too small");
    }
    if (dyn_off < m->data.image_off || (dyn_off & 7u) != 0u ||
        dyn_off > m->data.image_off + m->data.image_len - 16u) {
        return aot_loader_fail(err, AOT_LOAD_ERR_DYNAMIC, index, dyn_off, 0u,
                               m->desc->name,
                               "dynamic table is outside the data segment");
    }

    off = dyn_off;
    for (;;) {
        const uint8_t *e = image_ptr(m, off, 16u);
        uint64_t tag;
        uint64_t val;

        if (e == NULL) {
            return aot_loader_fail(err, AOT_LOAD_ERR_DYNAMIC, index, off, 0u,
                                   m->desc->name, "unterminated .dynamic");
        }
        tag = rd64(e);
        val = rd64(e + 8);
        if (tag == DT_NULL) {
            break;
        }
        /* Review fix 9: a tag the loader CONSUMES may appear at most once.
         * Ambiguous duplicates are rejected instead of silently taking the
         * first or last value (unconsumed tags stay ignored). */
        {
            int *flag = NULL;
            switch (tag) {
            case DT_HASH:     flag = &tags->has_hash; tags->hash = val; break;
            case DT_STRTAB:   flag = &tags->has_strtab; tags->strtab = val; break;
            case DT_SYMTAB:   flag = &tags->has_symtab; tags->symtab = val; break;
            case DT_STRSZ:    flag = &tags->has_strsz; tags->strsz = val; break;
            case DT_RELA:     flag = &tags->has_rela; tags->rela = val; break;
            case DT_RELASZ:   flag = &tags->has_relasz; tags->relasz = val; break;
            case DT_RELAENT:  flag = &tags->has_relaent; tags->relaent = val; break;
            case DT_JMPREL:   flag = &tags->has_jmprel; tags->jmprel = val; break;
            case DT_PLTRELSZ: flag = &tags->has_pltrelsz; tags->pltrelsz = val; break;
            case DT_PLTREL:   flag = &tags->has_pltrel; tags->pltrel = val; break;
            case DT_RELR:     flag = &tags->has_relr; tags->relr = val; break;
            case DT_RELRSZ:   flag = &tags->has_relrsz; tags->relrsz = val; break;
            case DT_RELRENT:  flag = &tags->has_relrent; tags->relrent = val; break;
            case DT_SYMENT:   flag = &tags->has_syment; tags->syment = val; break;
            case DT_INIT:     flag = &tags->has_init; tags->init = val; break;
            default: break; /* tags the loader does not consume are ignored */
            }
            if (flag != NULL) {
                if (*flag != 0) {
                    return aot_loader_fail(err, AOT_LOAD_ERR_DYNAMIC, index,
                                           off, tag, m->desc->name,
                                           "duplicate dynamic tag");
                }
                *flag = 1;
            }
        }
        off += 16u;
    }

    /* Review fix 10: the entry sizes and PLTREL are REQUIRED, not merely
     * checked when present. The image is AArch64 RELA-only, exactly as the
     * fixture linker (and every real NSO) produces it. */
    if (!tags->has_relaent || tags->relaent != RELA_ENTRY_BYTES) {
        return aot_loader_fail(err, AOT_LOAD_ERR_DYNAMIC, index, off, 0u,
                               m->desc->name,
                               "DT_RELAENT is missing or not 24");
    }
    if (!tags->has_syment || tags->syment != SYM_ENTRY_BYTES) {
        return aot_loader_fail(err, AOT_LOAD_ERR_DYNAMIC, index, off, 0u,
                               m->desc->name,
                               "DT_SYMENT is missing or not 24");
    }
    if (tags->has_jmprel &&
        (!tags->has_pltrel || tags->pltrel != DT_PLTREL_RELA)) {
        return aot_loader_fail(err, AOT_LOAD_ERR_DYNAMIC, index, off, 0u,
                               m->desc->name,
                               "DT_PLTREL is missing or not RELA (7)");
    }
    /* RELR is all-or-nothing: DT_RELR + DT_RELRSZ must appear together, and
     * DT_RELRENT must be 8 when present. A partial set is a bad .dynamic,
     * never "no RELR". */
    if (tags->has_relr != tags->has_relrsz) {
        return aot_loader_fail(err, AOT_LOAD_ERR_DYNAMIC, index, off, 0u,
                               m->desc->name,
                               "DT_RELR and DT_RELRSZ must appear together");
    }
    if (tags->has_relrent && tags->relrent != RELR_ENTRY_BYTES) {
        return aot_loader_fail(err, AOT_LOAD_ERR_DYNAMIC, index, off, 0u,
                               m->desc->name, "DT_RELRENT is not 8");
    }
    /* Minor 5: the .dynamic extent, for the site/table overlap rule. */
    tags->dyn_off = dyn_off;
    tags->dyn_size = (off > dyn_off) ? (off - dyn_off) : 0u;
    /* Minor 3: "the image has DT_INIT" and "the descriptor has an init_va"
     * are ONE fact. A module with DT_INIT must have a non-zero init_va that is
     * exactly that guest VA, and a module WITHOUT DT_INIT must have init_va 0:
     * otherwise a descriptor could claim an initialiser the image cannot run, or
     * silently drop one the image declares. */
    if (tags->has_init != (m->init_va != 0u)) {
        return aot_loader_fail(err, AOT_LOAD_ERR_DYNAMIC, index, off, 0u,
                               m->desc->name,
                               "DT_INIT presence disagrees with the "
                               "descriptor's init_va");
    }
    if (tags->has_init && m->init_va != m->desc->guest_base + tags->init) {
        return aot_loader_fail(err, AOT_LOAD_ERR_DYNAMIC, index, off, 0u,
                               m->desc->name,
                               "DT_INIT disagrees with the descriptor");
    }
    return AOT_LOAD_OK;
}

/* ---- symbols --------------------------------------------------------- */

typedef struct Symbol {
    uint64_t name_off;
    uint64_t value;
    uint16_t shndx;
    uint8_t bind;
    uint8_t type;
    const char *name; /* resolved lazily against dynstr, NULL when empty */
} Symbol;

static AotLoadStatus sym_read(const AotLoaderModule *m, uint32_t i,
                              Symbol *s, AotLoadError *err, uint32_t index)
{
    uint64_t off;
    const uint8_t *e;

    memset(s, 0, sizeof *s);
    if (i >= m->sym_count) {
        return aot_loader_fail(err, AOT_LOAD_ERR_SYMBOLS, index, 0u, 0u,
                               m->desc->name, "symbol index out of range");
    }
    off = m->symtab_off + (uint64_t)i * SYM_ENTRY_BYTES;
    e = image_ptr(m, off, SYM_ENTRY_BYTES);
    if (e == NULL) {
        return aot_loader_fail(err, AOT_LOAD_ERR_SYMBOLS, index, off, 0u,
                               m->desc->name, "dynsym entry is not mapped");
    }
    s->name_off = rd32(e);
    s->bind = (uint8_t)(e[4] >> 4);
    s->type = (uint8_t)(e[4] & 0xfu);
    s->shndx = (uint16_t)(e[6] | ((uint16_t)e[7] << 8));
    s->value = rd64(e + 8);
    if (s->name_off >= m->strsz) {
        return aot_loader_fail(err, AOT_LOAD_ERR_SYMBOLS, index, off, 0u,
                               m->desc->name, "st_name outside .dynstr");
    }
    if (s->name_off != 0u) {
        const uint8_t *str = image_ptr(m, m->strtab_off + s->name_off,
                                       m->strsz - s->name_off);
        const char *name = (const char *)str;
        if (str == NULL ||
            memchr(str, 0, (size_t)(m->strsz - s->name_off)) == NULL) {
            return aot_loader_fail(err, AOT_LOAD_ERR_SYMBOLS, index,
                                   m->strtab_off + s->name_off, 0u,
                                   m->desc->name,
                                   "symbol name is not NUL-terminated in .dynstr");
        }
        s->name = name;
    }
    return AOT_LOAD_OK;
}

/* Review fix 4: a DEFINED symbol is one whose st_shndx is a real section
 * index (1..SHN_LORESERVE-1) and whose value lies in [0, image_size].
 * value == image_size is VALID and important: every real TotK 1.0.0 module
 * defines the linker symbol "end" exactly at its page-aligned image end, and it
 * resolves to base + image_size. Values past the end are rejected at parse
 * time (see sym_validate), so this predicate never has to guess. */
static int sym_defined(const AotLoaderModule *m, const Symbol *s)
{
    return s->shndx != 0u && s->shndx < SHN_LORESERVE &&
           s->value <= m->image_size;
}

/* Fail-closed symbol validation (review fix 4). Called for EVERY symbol of
 * every module before any relocation runs, so an image that declares an
 * absolute / reserved-section / TLS / out-of-image DEFINITION is rejected with
 * a typed error instead of resolving to a silently wrong VA. */
static AotLoadStatus sym_validate(const AotLoaderModule *m, uint32_t i,
                                  AotLoadError *err, uint32_t index)
{
    Symbol s;
    AotLoadStatus st = sym_read(m, i, &s, err, index);

    if (st != AOT_LOAD_OK) {
        return st;
    }
    if (s.type == STT_TLS) {
        return aot_loader_fail(err, AOT_LOAD_ERR_SYMBOLS, index,
                               m->symtab_off + (uint64_t)i * SYM_ENTRY_BYTES,
                               0u, s.name,
                               "TLS symbol (the loader has no TLS model)");
    }
    if (s.shndx >= SHN_LORESERVE) {
        return aot_loader_fail(err, AOT_LOAD_ERR_SYMBOLS, index,
                               m->symtab_off + (uint64_t)i * SYM_ENTRY_BYTES,
                               0u, s.name,
                               "symbol uses a reserved st_shndx (SHN_ABS/COMMON)");
    }
    if (s.shndx != 0u && s.value > m->image_size) {
        return aot_loader_fail(err, AOT_LOAD_ERR_SYMBOLS, index,
                               m->symtab_off + (uint64_t)i * SYM_ENTRY_BYTES,
                               0u, s.name,
                               "defined symbol value is past the image end");
    }
    return AOT_LOAD_OK;
}

/* Name match. `name` of an empty symbol is never equal to a real name. */
static int sym_name_is(const Symbol *s, const char *name)
{
    return s->name != NULL && strcmp(s->name, name) == 0;
}

/* ---- symbol name index ----------------------------------------------- */

/* FNV-1a, exactly the Mac loader's hash_name (32-bit, 2166136261/16777619).
 * The Mac builds one index per module in make_hash() and this is its Windows
 * equivalent; only the RESULT is shared with the Mac (first DEFINED match wins
 * for definitions), the layout here also remembers the first name match so an
 * unresolved WEAK import still finds its binding. */
static uint32_t sym_name_hash(const char *s)
{
    uint32_t h = 2166136261u;

    for (; *s != '\0'; s++) {
        h = (h ^ (uint32_t)(uint8_t)*s) * 16777619u;
    }
    return h;
}

/* Build the open-addressed index for module `m`. Called ONCE, after every
 * symbol of the module has been validated, so neither a symbol read nor a name
 * can fail from here on. Semantics preserved exactly:
 *   first_defined = smallest symbol index i with name == n and sym_defined(i)
 *   first         = smallest symbol index i with name == n
 * which is what the old linear scan (sym_find_name) produced. */
static AotLoadStatus sym_index_build(AotLoaderModule *m, AotLoadError *err,
                                     uint32_t index)
{
    uint32_t cap = 16u;
    uint32_t mask;
    uint32_t i;

    if (m->sym_index != NULL) {
        return AOT_LOAD_OK; /* already built */
    }
    /* Load factor <= 0.5 keeps probe chains short and guarantees an empty slot
     * (the number of distinct names is < sym_count < cap). */
    if (m->sym_count > 0x20000000u) {
        return aot_loader_fail(err, AOT_LOAD_ERR_OOM, index, 0u, 0u,
                               m->desc->name,
                               "dynsym too large for a symbol index");
    }
    while (cap < m->sym_count * 2u) {
        cap <<= 1;
    }
    m->sym_index = (AotSymIndexEntry *)calloc((size_t)cap,
                                             sizeof(AotSymIndexEntry));
    if (m->sym_index == NULL) {
        return aot_loader_fail(err, AOT_LOAD_ERR_OOM, index, 0u, 0u,
                               m->desc->name,
                               "symbol index allocation failed");
    }
    m->sym_index_cap = cap;
    mask = cap - 1u;

    for (i = 0; i < m->sym_count; i++) {
        Symbol cur;
        uint32_t h;
        uint32_t p;
        AotLoadStatus st = sym_read(m, i, &cur, err, index);

        if (st != AOT_LOAD_OK) {
            return st;
        }
        if (cur.name == NULL) {
            continue; /* an empty st_name is never equal to a real name */
        }
        h = sym_name_hash(cur.name);
        p = h & mask;
        while (m->sym_index[p].name != NULL &&
               strcmp(m->sym_index[p].name, cur.name) != 0) {
            p = (p + 1u) & mask;
        }
        if (m->sym_index[p].name == NULL) {
            m->sym_index[p].name = cur.name;
            m->sym_index[p].hash = h;
            m->sym_index[p].first = i;
            m->sym_index[p].first_defined = AOT_SYM_INDEX_NONE;
        }
        /* i increases, so the FIRST occurrence of each role wins. */
        if (m->sym_index[p].first_defined == AOT_SYM_INDEX_NONE &&
            sym_defined(m, &cur)) {
            m->sym_index[p].first_defined = i;
        }
    }
    return AOT_LOAD_OK;
}

/* Symbol index for `name` (see sym_index_build for the two roles), or
 * AOT_SYM_INDEX_NONE. */
static uint32_t sym_index_lookup(const AotLoaderModule *m, const char *name,
                                 int want_defined)
{
    uint32_t mask;
    uint32_t p;

    if (m->sym_index == NULL || m->sym_index_cap == 0u || name == NULL) {
        return AOT_SYM_INDEX_NONE;
    }
    mask = m->sym_index_cap - 1u;
    p = sym_name_hash(name) & mask;
    while (m->sym_index[p].name != NULL) {
        if (strcmp(m->sym_index[p].name, name) == 0) {
            return want_defined ? m->sym_index[p].first_defined
                                : m->sym_index[p].first;
        }
        p = (p + 1u) & mask;
    }
    return AOT_SYM_INDEX_NONE;
}

/* Owner of a relocation's symbol: NULL when the module relocated itself. */
static AotLoadStatus sym_find_name(AotLoaderModule *m, const char *name,
                                   Symbol *out, int *found,
                                   AotLoadError *err, uint32_t index)
{
    uint32_t i;

    Symbol first;
    int have_first = 0;

    memset(&first, 0, sizeof first);

    *found = 0;

    /* Indexed path: one hash probe instead of a full dynsym scan. The Mac rule
     * (first DEFINED match), with the first-any-match fallback for the binding
     * information of an unresolved WEAK import, is preserved bit for bit. */
    if (m->sym_index != NULL) {
#ifdef MN_AOT_MUTANT_SYMBOL_FIRST_ANY
        /* WRONG: the lookup takes the FIRST name match whatever its definition
         * state, so an UNDEFINED duplicate earlier in .dynsym shadows a later
         * DEFINED entry (Mac rule: the first DEFINED match wins). The `shadow`
         * link variant carries exactly that shape in main (an UNDEFINED STB_WEAK
         * "main_vtable" at a lower index than the definition), so the sites that
         * reference it resolve to 0+A and the link digest differs. */
        uint32_t at = sym_index_lookup(m, name, 0);
        AotLoadStatus st;

        if (at == AOT_SYM_INDEX_NONE) {
            return AOT_LOAD_OK;
        }
        st = sym_read(m, at, out, err, index);
        if (st != AOT_LOAD_OK) {
            return st;
        }
        *found = 1;
        return AOT_LOAD_OK;
#else
        uint32_t at = sym_index_lookup(m, name, 1);
        AotLoadStatus st;

        if (at == AOT_SYM_INDEX_NONE) {
            at = sym_index_lookup(m, name, 0);
        }
        if (at == AOT_SYM_INDEX_NONE) {
            return AOT_LOAD_OK;
        }
        st = sym_read(m, at, out, err, index);
        if (st != AOT_LOAD_OK) {
            return st;
        }
        *found = 1;
        return AOT_LOAD_OK;
#endif
    }

    /* Fallback (no index built: resolution before relocate_impl's phase A). */
    for (i = 0; i < m->sym_count; i++) {
        Symbol cur;
        AotLoadStatus st = sym_read(m, i, &cur, err, index);
        if (st != AOT_LOAD_OK) {
            return st;
        }
        if (!sym_name_is(&cur, name)) {
            continue;
        }
        /* Review fix 8 (Mac rule): the first DEFINED symbol with this name
         * wins. A duplicate UNDEFINED entry earlier in the table must not
         * shadow a later definition. */
        if (sym_defined(m, &cur)) {
            *out = cur;
            *found = 1;
            return AOT_LOAD_OK;
        }
        if (!have_first) {
            first = cur;
            have_first = 1;
        }
    }
    if (have_first) {
        *out = first;
        *found = 1;
    }
    return AOT_LOAD_OK;
}

/* ---- relocation ------------------------------------------------------ */

/* Guest VA of a host thunk. Program-wide by contract: one thunk per symbol
 * name, so every module sees the SAME VA. */
static uint64_t thunk_va(const AotLoader *loader, uint32_t module_index,
                         uint32_t thunk)
{
#ifdef MN_AOT_MUTANT_THUNK_PER_MODULE
    /* WRONG: thunks become per-module. Two modules importing the same name then
     * get different VAs, which the thunk-identity fixture detects. */
    return loader->bindings->thunk_base +
           16u * ((uint64_t)thunk + (uint64_t)module_index);
#else
    (void)module_index;
    return loader->bindings->thunk_base + 16u * (uint64_t)thunk;
#endif
}

typedef struct Resolution {
    const char *symbol;
    uint64_t value;         /* S + A: the value written to the site */
    uint64_t symbol_value;  /* S only (review fix 16: cross counts S != 0) */
    uint32_t how; /* 0 own, 1 global, 2 weak, 3 override, 4 observer */
} Resolution;

/* Own-module definition: only a DEFINED symbol (st_shndx != 0 with a value
 * inside the image) counts; an undefined import in the same table does not. */
static int resolve_own(AotLoaderModule *m, const char *name, uint64_t addend,
                       Resolution *res, AotLoadError *err, uint32_t index,
                       AotLoadStatus *st_out)
{
    Symbol sym;
    int found = 0;

    *st_out = sym_find_name(m, name, &sym, &found, err, index);
    if (*st_out != AOT_LOAD_OK) {
        return 0;
    }
    if (found && sym_defined(m, &sym)) {
        res->symbol = sym.name;
        res->symbol_value = m->desc->guest_base + sym.value;
        res->value = res->symbol_value + addend;
        res->how = 0u;
        return 1;
    }
    return 0;
}

/* Global search in module order (main, subsdk0, sdk). */
static int resolve_global(AotLoader *loader, const char *name, uint64_t addend,
                          Resolution *res, AotLoadError *err,
                          AotLoadStatus *st_out)
{
    uint32_t i;

    for (i = 0; i < loader->count; i++) {
        AotLoaderModule *o = &loader->modules[i];
        Symbol sym;
        int found = 0;

        *st_out = sym_find_name(o, name, &sym, &found, err, i);
        if (*st_out != AOT_LOAD_OK) {
            return 0;
        }
        if (found && sym_defined(o, &sym)) {
            res->symbol = sym.name;
            res->symbol_value = o->desc->guest_base + sym.value;
            res->value = res->symbol_value + addend;
            res->how = 1u;
            return 1;
        }
    }
    return 0;
}

static AotLoadStatus resolve_symbol(AotLoader *loader, uint32_t index,
                                    const char *name, int jump_slot,
                                    uint64_t addend, Resolution *res,
                                    AotLoadError *err)
{
    AotLoaderModule *m = &loader->modules[index];
    AotLoadStatus st = AOT_LOAD_OK;
    Symbol sym;
    int found = 0;
    int global_first = 0;
    uint32_t i;

    /* JUMP_SLOT observers first, then overrides (any kind). Both are host
     * thunks, whose guest VA is program-wide: thunk_base + 16*index. */
#ifdef MN_AOT_MUTANT_OBSERVER_ALL_KINDS
    /* WRONG: observers are applied to every kind, not only JUMP_SLOT, so an
     * address-taken (GLOB_DAT) reference loses the real module VA. */
    if (loader->bindings != NULL) {
    (void)jump_slot;
#else
    if (jump_slot && loader->bindings != NULL) {
#endif
        for (i = 0; i < loader->bindings->observer_count; i++) {
            if (strcmp(loader->bindings->observers[i].name, name) == 0) {
                res->symbol = loader->bindings->observers[i].name;
                /* Review fix 5: S+A holds for host thunks too. */
                res->symbol_value = thunk_va(loader, index,
                                             loader->bindings->observers[i].thunk);
                res->value = res->symbol_value + addend;
                res->how = 4u;
                return AOT_LOAD_OK;
            }
        }
    }
    if (loader->bindings != NULL) {
        for (i = 0; i < loader->bindings->override_count; i++) {
            if (strcmp(loader->bindings->overrides[i].name, name) == 0) {
                res->symbol = loader->bindings->overrides[i].name;
                /* Review fix 5: S+A holds for host thunks too. */
                res->symbol_value = thunk_va(loader, index,
                                             loader->bindings->overrides[i].thunk);
                res->value = res->symbol_value + addend;
                res->how = 3u;
                return AOT_LOAD_OK;
            }
        }
    }

#ifdef MN_AOT_MUTANT_GLOBAL_FIRST
    /* WRONG: the global module-order search runs BEFORE the referencing
     * module's own definition (the Mac loader resolves own-first). */
    global_first = 1;
#endif

    if (!global_first) {
        if (resolve_own(m, name, addend, res, err, index, &st)) {
            return AOT_LOAD_OK;
        }
        if (st != AOT_LOAD_OK) {
            return st;
        }
    }
    if (resolve_global(loader, name, addend, res, err, &st)) {
        return AOT_LOAD_OK;
    }
    if (st != AOT_LOAD_OK) {
        return st;
    }
    if (global_first) {
        if (resolve_own(m, name, addend, res, err, index, &st)) {
            return AOT_LOAD_OK;
        }
        if (st != AOT_LOAD_OK) {
            return st;
        }
    }

    /* An unresolved WEAK import is 0; anything else is a link error. */
    st = sym_find_name(m, name, &sym, &found, err, index);
    if (st != AOT_LOAD_OK) {
        return st;
    }
#ifdef MN_AOT_MUTANT_WEAK_STRONG_SWAP
    /* WRONG: weak imports become hard errors and unresolved strong imports
     * silently become 0. Both directions change accepted output. */
    if (!(found && sym.bind == STB_WEAK)) {
        res->symbol = (found) ? sym.name : name;
        res->symbol_value = 0u;
        res->value = 0u;
        res->how = 2u;
        return AOT_LOAD_OK;
    }
    return aot_loader_fail(err, AOT_LOAD_ERR_SYMBOL, index, 0u, 0u, name,
                           "unresolved strong import");
#else
    if (found && sym.bind == STB_WEAK) {
        /* Review fix 5: an unresolved WEAK import is 0 + A, not 0. */
        res->symbol = sym.name;
        res->symbol_value = 0u;
        res->value = addend;
        res->how = 2u;
        return AOT_LOAD_OK;
    }
    return aot_loader_fail(err, AOT_LOAD_ERR_SYMBOL, index, 0u, 0u, name,
                           "unresolved strong import");
#endif
}

/* Grow the site table so the NEXT site can be appended without allocating
 * (review fix 13: the allocation happens BEFORE any byte is written, so a
 * failed load never leaves a recorded site whose value is missing). Capacity
 * growth is overflow-checked and an allocation failure is the typed
 * AOT_LOAD_ERR_OOM. */
static AotLoadStatus site_reserve(AotLoader *loader, uint32_t module,
                                  AotLoadError *err)
{
    uint32_t cap;
    AotLinkSite *grown;

    if (loader->site_count < loader->site_capacity) {
        return AOT_LOAD_OK;
    }
    if (loader->site_capacity > 0x40000000u) {
        return aot_loader_fail(err, AOT_LOAD_ERR_OOM, module, 0u, 0u, NULL,
                               "site table capacity would overflow");
    }
    cap = (loader->site_capacity == 0u) ? AOT_LOADER_INITIAL_SITES
                                        : loader->site_capacity * 2u;
    if ((uint64_t)cap * sizeof(AotLinkSite) > (uint64_t)SIZE_MAX) {
        return aot_loader_fail(err, AOT_LOAD_ERR_OOM, module, 0u, 0u, NULL,
                               "site table size would overflow");
    }
    grown = (AotLinkSite *)realloc(loader->sites,
                                   (size_t)cap * sizeof(AotLinkSite));
    if (grown == NULL) {
        return aot_loader_fail(err, AOT_LOAD_ERR_OOM, module, 0u, 0u, NULL,
                               "out of memory growing the site table");
    }
    loader->sites = grown;
    loader->site_capacity = cap;
    return AOT_LOAD_OK;
}

static AotLoadStatus site_append(AotLoader *loader, const AotLinkSite *site,
                                 AotLoadError *err)
{
    AotLoadStatus st = site_reserve(loader, site->module, err);
    if (st != AOT_LOAD_OK) {
        return st;
    }
    loader->sites[loader->site_count++] = *site;
    return AOT_LOAD_OK;
}

/* Duplicate-site detection (review fix 12): a site written twice (by RELR and
 * RELA, or by two RELA entries) is rejected rather than silently taking the
 * last write. One bit per 8-byte slot of the module's data segment makes the
 * test O(1) and bounded, which is what real modules with 10^5..10^6
 * relocations need; a linear scan of the site table was O(n^2). */
static AotLoadStatus site_bits_reserve(AotLoaderModule *m, uint32_t index,
                                       AotLoadError *err)
{
    uint64_t slots;

    if (m->site_bits != NULL) {
        return AOT_LOAD_OK;
    }
    if (m->data.image_len == 0u) {
        return aot_loader_fail(err, AOT_LOAD_ERR_RELOC, index, m->data.image_off,
                               0u, m->desc->name, "data segment is empty");
    }
    slots = m->data.image_len / 8u;            /* 8-byte, 8-aligned slots */
    m->site_bits_bytes = (slots + 7u) / 8u;    /* one bit per slot */
    m->site_bits = (uint8_t *)calloc((size_t)m->site_bits_bytes, 1u);
    if (m->site_bits == NULL) {
        m->site_bits_bytes = 0u;
        return aot_loader_fail(err, AOT_LOAD_ERR_OOM, index, m->data.image_off,
                               0u, m->desc->name,
                               "out of memory allocating the duplicate-site map");
    }
    return AOT_LOAD_OK;
}

/* 1 = already recorded, 0 = first time (now marked). The site must have passed
 * record_site's alignment/range checks, so the computed slot is in range. */
static int site_bit_claim(AotLoaderModule *m, uint64_t where)
{
    uint64_t bit = (where - m->data.image_off) >> 3;
    uint8_t mask = (uint8_t)(1u << (unsigned)(bit & 7u));

    if ((m->site_bits[bit >> 3] & mask) != 0u) {
        return 1;
    }
    m->site_bits[bit >> 3] |= mask;
    return 0;
}

/* Minor 5: remember one consumed table for this module. */
static void table_add(AotLoaderModule *m, uint64_t off, uint64_t size,
                      const char *name)
{
    if (size == 0u || m->table_count >= AOT_LOADER_TABLE_MAX) {
        return;
    }
    m->table[m->table_count].off = off;
    m->table[m->table_count].size = size;
    m->table[m->table_count].name = name;
    m->table_count++;
}

static AotLoadStatus record_site(AotLoader *loader, uint32_t index,
                                 uint64_t where, uint32_t kind,
                                 uint64_t value, const char *symbol,
                                 const char *table, AotLoadError *err)
{
    AotLoaderModule *m = &loader->modules[index];
    uint64_t data_lo = m->data.image_off;
    uint64_t data_hi = m->data.image_off + m->data.image_len;
    AotLinkSite site;
    uint8_t *dst;

    if ((where & 7u) != 0u) {
        return aot_loader_fail(err, AOT_LOAD_ERR_RELOC, index, where,
                               m->desc->guest_base + where, symbol,
                               "misaligned relocation site");
    }
    if (data_hi < 8u || where < data_lo || where > data_hi - 8u) {
        return aot_loader_fail(err, AOT_LOAD_ERR_RELOC, index, where,
                               m->desc->guest_base + where, symbol,
                               "relocation site outside the data segment");
    }
    /* Minor 5: a site may never land inside a table the loader consumes. The
     * write below would corrupt .dynamic/.dynsym/.dynstr/.hash/.rela/.jmprel/
     * .relr, and the loader reads those tables (or has already read them), so
     * such an image is rejected as a relocation error instead of being applied.
     * Checked BEFORE the duplicate bitmap and before any byte is written. */
    {
        uint32_t t;
        static const char *const overlap_detail[AOT_LOADER_TABLE_MAX] = {
            "relocation site overlaps the .dynamic table",
            "relocation site overlaps the .dynsym table",
            "relocation site overlaps the .dynstr table",
            "relocation site overlaps the .hash table",
            "relocation site overlaps the .rela table",
            "relocation site overlaps the .jmprel table",
            "relocation site overlaps the .relr table",
            "relocation site overlaps a consumed table",
            "relocation site overlaps a consumed table"
        };

        for (t = 0u; t < m->table_count; t++) {
            const AotLoaderTable *tab = &m->table[t];
            if (where < tab->off + tab->size && tab->off < where + 8u) {
#ifndef MN_AOT_MUTANT_ALLOW_TABLE_OVERLAP
                return aot_loader_fail(err, AOT_LOAD_ERR_RELOC, index, where,
                                       m->desc->guest_base + where, symbol,
                                       overlap_detail[t]);
#else
                /* TEST-ONLY wrong implementation: the overlap is accepted. */
#endif
            }
        }
    }
    {
        AotLoadStatus st = site_reserve(loader, index, err);
        if (st != AOT_LOAD_OK) {
            return st;
        }
    }
#ifndef MN_AOT_MUTANT_NO_DUP_CHECK
    {
        AotLoadStatus st = site_bits_reserve(m, index, err);
        if (st != AOT_LOAD_OK) {
            return st;
        }
        if (site_bit_claim(m, where)) {
            return aot_loader_fail(err, AOT_LOAD_ERR_RELOC, index, where,
                                   m->desc->guest_base + where, symbol,
                                   "site written twice");
        }
    }
#else
    {
        /* The mutant accepts duplicates; keep the map allocated so the rest of
         * the accounting is unchanged. */
        AotLoadStatus st = site_bits_reserve(m, index, err);
        if (st != AOT_LOAD_OK) {
            return st;
        }
    }
#endif
#ifdef MN_AOT_MUTANT_TRUNC32
    /* WRONG: relocated values are truncated to 32 bits, so guest VAs above
     * 4 GiB (every fixed module base) are silently corrupted. */
    value &= 0xffffffffu;
#endif
    dst = image_ptr_rw(m, where, 8u);
    if (dst == NULL) {
        return aot_loader_fail(err, AOT_LOAD_ERR_RELOC, index, where,
                               m->desc->guest_base + where, symbol,
                               "relocation site is not mapped");
    }
    wr64(dst, value);

    site.module = index;
    site.kind = kind;
    site.where = where;
    site.value = value;
    site.symbol = symbol;
    {
        AotLoadStatus st = site_append(loader, &site, err);
        if (st != AOT_LOAD_OK) {
            return st;
        }
    }
    if (kind == R_AARCH64_RELATIVE) {
        m->counters.relative++;
    } else {
        m->counters.symbolic++;
    }
    (void)table;
    return AOT_LOAD_OK;
}

static AotLoadStatus apply_relr(AotLoader *loader, uint32_t index,
                                const DynamicTags *tags, AotLoadError *err)
{
    AotLoaderModule *m = &loader->modules[index];
    uint64_t base = 0;
    uint64_t i;
    uint64_t count;
    int have_base = 0;

    if (tags->relrsz == 0u) {
        return AOT_LOAD_OK;
    }
    if ((tags->relrsz % RELR_ENTRY_BYTES) != 0u) {
        return aot_loader_fail(err, AOT_LOAD_ERR_DYNAMIC, index, tags->relr, 0u,
                               m->desc->name,
                               "DT_RELRSZ is not a multiple of 8");
    }
    count = tags->relrsz / RELR_ENTRY_BYTES;
    for (i = 0; i < count; i++) {
        const uint8_t *e = image_ptr(m, tags->relr + i * RELR_ENTRY_BYTES, 8u);
        uint64_t entry;
        if (e == NULL) {
            return aot_loader_fail(err, AOT_LOAD_ERR_DYNAMIC, index,
                                   tags->relr + i * RELR_ENTRY_BYTES, 0u,
                                   m->desc->name, "DT_RELR table not mapped");
        }
        entry = rd64(e);
        if ((entry & 1u) == 0u) {
            const uint8_t *dst;
            uint64_t addend;
            AotLoadStatus st;

            if ((entry & 7u) != 0u) {
                return aot_loader_fail(err, AOT_LOAD_ERR_RELOC, index, entry,
                                       m->desc->guest_base + entry, NULL,
                                       "unaligned DT_RELR address");
            }
            dst = image_ptr(m, entry, 8u);
            if (dst == NULL) {
                return aot_loader_fail(err, AOT_LOAD_ERR_RELOC, index, entry,
                                       m->desc->guest_base + entry, NULL,
                                       "DT_RELR site is not mapped");
            }
            addend = rd64(dst);
            if (addend >= m->image_size) {
                return aot_loader_fail(err, AOT_LOAD_ERR_RELOC, index, entry,
                                       m->desc->guest_base + entry, NULL,
                                       "RELR addend outside the image");
            }
#ifdef MN_AOT_MUTANT_RELATIVE_NO_BASE
            /* WRONG: RELATIVE omits the module base, so the site holds a raw
             * image offset instead of a guest VA. */
            st = record_site(loader, index, entry, R_AARCH64_RELATIVE,
                             addend, NULL, "RELR", err);
#else
            st = record_site(loader, index, entry, R_AARCH64_RELATIVE,
                             m->desc->guest_base + addend, NULL, "RELR", err);
#endif
            if (st != AOT_LOAD_OK) {
                return st;
            }
            base = entry + 8u;
            have_base = 1;
        } else {
            uint64_t bits = entry >> 1;
            unsigned bit;
            if (!have_base) {
                return aot_loader_fail(err, AOT_LOAD_ERR_RELOC, index,
                                       tags->relr + i * RELR_ENTRY_BYTES, 0u,
                                       m->desc->name,
                                       "DT_RELR bitmap without an address");
            }
            for (bit = 0; bit < 63u; bit++) {
                if ((bits >> bit) & 1u) {
                    uint64_t where = base + 8u * (uint64_t)bit;
                    const uint8_t *dst = image_ptr(m, where, 8u);
                    uint64_t addend;
                    AotLoadStatus st;
                    if (dst == NULL) {
                        return aot_loader_fail(err, AOT_LOAD_ERR_RELOC, index,
                                               where,
                                               m->desc->guest_base + where,
                                               NULL,
                                               "DT_RELR site is not mapped");
                    }
                    addend = rd64(dst);
                    if (addend >= m->image_size) {
                        return aot_loader_fail(err, AOT_LOAD_ERR_RELOC, index,
                                               where,
                                               m->desc->guest_base + where,
                                               NULL,
                                               "RELR addend outside the image");
                    }
#ifdef MN_AOT_MUTANT_RELATIVE_NO_BASE
                    st = record_site(loader, index, where,
                                     R_AARCH64_RELATIVE, addend, NULL,
                                     "RELR", err);
#else
                    st = record_site(loader, index, where,
                                     R_AARCH64_RELATIVE,
                                     m->desc->guest_base + addend, NULL,
                                     "RELR", err);
#endif
                    if (st != AOT_LOAD_OK) {
                        return st;
                    }
                }
            }
            base += 8u * 63u;
        }
    }
    return AOT_LOAD_OK;
}

static AotLoadStatus apply_rela_table(AotLoader *loader, uint32_t index,
                                      uint64_t addr, uint64_t size,
                                      const char *table, AotLoadError *err)
{
    AotLoaderModule *m = &loader->modules[index];
    uint64_t count;
    uint64_t i;

    if (size == 0u) {
        return AOT_LOAD_OK;
    }
    if ((size % RELA_ENTRY_BYTES) != 0u) {
        return aot_loader_fail(err, AOT_LOAD_ERR_DYNAMIC, index, addr, 0u,
                               m->desc->name,
                               "RELA table size is not a multiple of 24");
    }
    count = size / RELA_ENTRY_BYTES;
    for (i = 0; i < count; i++) {
        uint64_t entry_off = addr + i * RELA_ENTRY_BYTES;
        const uint8_t *e = image_ptr(m, entry_off, RELA_ENTRY_BYTES);
        uint64_t where;
        uint32_t sym_index;
        uint32_t kind;
        uint64_t addend;
        AotLoadStatus st;

        if (e == NULL) {
            return aot_loader_fail(err, AOT_LOAD_ERR_DYNAMIC, index, entry_off,
                                   0u, m->desc->name,
                                   "relocation table not mapped");
        }
        where = rd64(e);
        sym_index = (uint32_t)(rd64(e + 8) >> 32);
        kind = (uint32_t)(rd64(e + 8) & 0xffffffffu);
        addend = rd64(e + 16);

        if (kind == R_AARCH64_RELATIVE) {
            if (addend >= m->image_size) {
                return aot_loader_fail(err, AOT_LOAD_ERR_RELOC, index, where,
                                       m->desc->guest_base + where, NULL,
                                       "RELATIVE addend outside the image");
            }
#ifdef MN_AOT_MUTANT_RELATIVE_NO_BASE
            /* WRONG: see the RELR case above. */
            st = record_site(loader, index, where, kind, addend, NULL, table,
                             err);
#else
            st = record_site(loader, index, where, kind,
                             m->desc->guest_base + addend, NULL, table, err);
#endif
            if (st != AOT_LOAD_OK) {
                return st;
            }
        } else if (kind == R_AARCH64_ABS64 || kind == R_AARCH64_GLOB_DAT ||
                   kind == R_AARCH64_JUMP_SLOT) {
            Symbol sym;
            Resolution res;
            const char *name;

            if (sym_index >= m->sym_count) {
                return aot_loader_fail(err, AOT_LOAD_ERR_RELOC, index, where,
                                       m->desc->guest_base + where, NULL,
                                       "relocation symbol index out of range");
            }
            st = sym_read(m, sym_index, &sym, err, index);
            if (st != AOT_LOAD_OK) {
                return st;
            }
            if (sym.name == NULL) {
                return aot_loader_fail(err, AOT_LOAD_ERR_RELOC, index, where,
                                       m->desc->guest_base + where, NULL,
                                       "relocation names an empty symbol");
            }
            name = sym.name;
#ifndef MN_AOT_MUTANT_JUMPSLOT_ADDEND_ACCEPT
            if (kind == R_AARCH64_JUMP_SLOT && addend != 0u) {
                return aot_loader_fail(err, AOT_LOAD_ERR_RELOC, index, where,
                                       m->desc->guest_base + where, name,
                                       "JUMP_SLOT with non-zero addend");
            }
#endif
            {
                /* ABS64_NO_ADDEND: the addend is dropped, so R_AARCH64_ABS64
                 * with a non-zero addend points at the symbol, not S+A. */
                uint64_t use_addend = addend;
                if (kind == R_AARCH64_JUMP_SLOT) {
#ifdef MN_AOT_MUTANT_JUMPSLOT_ADDEND_ACCEPT
                    /* WRONG: the addend is honoured instead of rejected. */
                    use_addend = addend;
#else
                    use_addend = 0u;
#endif
                }
#ifdef MN_AOT_MUTANT_ABS64_NO_ADDEND
                if (kind == R_AARCH64_ABS64 || kind == R_AARCH64_GLOB_DAT) {
                    use_addend = 0u; /* WRONG: S+A becomes S */
                }
#endif
                st = resolve_symbol(loader, index, name,
                                    kind == R_AARCH64_JUMP_SLOT, use_addend,
                                    &res, err);
            }
            if (st != AOT_LOAD_OK) {
                return st;
            }
            /* Review fix 16: `cross` counts every relocation whose SYMBOL IS
             * UNDEFINED in this module and whose resolved value S is non-zero
             * -- including override/observer thunk targets. `weak` counts the
             * unresolved weak imports (S == 0). */
            if (sym.shndx == 0u && res.symbol_value != 0u) {
                m->counters.cross++;
            } else if (res.how == 2u) {
                m->counters.weak++;
            }
            st = record_site(loader, index, where, kind, res.value,
                             res.symbol, table, err);
            if (st != AOT_LOAD_OK) {
                return st;
            }
        } else {
            return aot_loader_fail(err, AOT_LOAD_ERR_RELOC, index, where,
                                   m->desc->guest_base + where, NULL,
                                   "unsupported relocation kind");
        }
    }
    return AOT_LOAD_OK;
}

/* Review fix 14: the AOT-time host bindings are MANDATORY (an explicitly empty
 * table is allowed) and must be self-consistent before any relocation runs.
 *   - thunk indices are unique across overrides AND observers, so one symbol
 *     never has two guest VAs and two symbols never share a thunk;
 *   - symbol names are unique across both tables (a name in both tables would
 *     make JUMP_SLOT resolution order-dependent);
 *   - thunk_base lies in [2^32, 2^39) and its whole span stays below 2^39
 *     (the same window the Program validates thunks against). */
static AotLoadStatus bindings_validate(const AotLoader *loader,
                                       AotLoadError *err)
{
    const AotHostBindings *b = loader->bindings;
    const AotHostBinding *tables[2];
    const uint32_t counts[2] = {(b != NULL) ? b->override_count : 0u,
                                (b != NULL) ? b->observer_count : 0u};
    uint64_t max_index = 0u;
    uint64_t span;
    uint32_t t;
    uint32_t i;

    if (b == NULL) {
        return aot_loader_fail(err, AOT_LOAD_ERR_ARG, AOT_LOADER_NO_MODULE,
                               0u, 0u, NULL,
                               "host bindings are required (attach an explicit "
                               "empty table for a module with no host symbols)");
    }
    tables[0] = b->overrides;
    tables[1] = b->observers;
    if (b->thunk_base < AOT_AS_MIN_ADDR || b->thunk_base >= AOT_AS_MAX_ADDR ||
        (b->thunk_base % (uint64_t)AOT_LOADER_THUNK_STRIDE) != 0u) {
        return aot_loader_fail(err, AOT_LOAD_ERR_ARG, AOT_LOADER_NO_MODULE, 0u,
                               b->thunk_base, NULL,
                               "thunk_base is outside [2^32, 2^39) or not "
                               "16-byte aligned");
    }
    for (t = 0; t < 2u; t++) {
        if (counts[t] != 0u && tables[t] == NULL) {
            return aot_loader_fail(err, AOT_LOAD_ERR_ARG,
                                   AOT_LOADER_NO_MODULE, 0u, 0u, NULL,
                                   "binding table is NULL with a non-zero count");
        }
        for (i = 0; i < counts[t]; i++) {
            uint32_t j;
            const AotHostBinding *e = &tables[t][i];

            if (e->name == NULL || e->name[0] == 0) {
                return aot_loader_fail(err, AOT_LOAD_ERR_ARG,
                                       AOT_LOADER_NO_MODULE, 0u, 0u, NULL,
                                       "binding entry has an empty name");
            }
            if (e->thunk > max_index) {
                max_index = e->thunk;
            }
            for (j = 0; j < counts[t]; j++) {
                if (j != i && tables[t][j].thunk == e->thunk) {
                    return aot_loader_fail(err, AOT_LOAD_ERR_ARG,
                                           AOT_LOADER_NO_MODULE, 0u, 0u,
                                           e->name,
                                           "duplicate thunk index in one table");
                }
                if (j != i && strcmp(tables[t][j].name, e->name) == 0) {
                    return aot_loader_fail(err, AOT_LOAD_ERR_ARG,
                                           AOT_LOADER_NO_MODULE, 0u, 0u,
                                           e->name,
                                           "duplicate symbol name in one table");
                }
            }
            if (t == 1u) {
                for (j = 0; j < b->override_count; j++) {
                    if (b->overrides[j].thunk == e->thunk) {
                        return aot_loader_fail(err, AOT_LOAD_ERR_ARG,
                                               AOT_LOADER_NO_MODULE, 0u, 0u,
                                               e->name,
                                               "thunk index shared by an "
                                               "override and an observer");
                    }
                    if (strcmp(b->overrides[j].name, e->name) == 0) {
                        return aot_loader_fail(err, AOT_LOAD_ERR_ARG,
                                               AOT_LOADER_NO_MODULE, 0u, 0u,
                                               e->name,
                                               "symbol is both overridden and "
                                               "observed");
                    }
                }
            }
        }
    }
    if (counts[0] != 0u || counts[1] != 0u) {
        if (max_index > (AOT_AS_MAX_ADDR / AOT_LOADER_THUNK_STRIDE)) {
            return aot_loader_fail(err, AOT_LOAD_ERR_ARG, AOT_LOADER_NO_MODULE,
                                   0u, 0u, NULL,
                                   "thunk index is out of range");
        }
        span = AOT_LOADER_THUNK_STRIDE * (max_index + 1u);
        if (span > AOT_AS_MAX_ADDR - b->thunk_base) {
            return aot_loader_fail(err, AOT_LOAD_ERR_ARG, AOT_LOADER_NO_MODULE,
                                   0u, b->thunk_base, NULL,
                                   "thunk span reaches or passes 2^39");
        }
    }
    return AOT_LOAD_OK;
}

static AotLoadStatus relocate_impl(AotLoader *loader, AotLoadError *err)
{
    DynamicTags tags[AOT_LOADER_MAX_MODULES];
    uint32_t i;

    /* Stage order (mapped, not relocated, not sealed/poisoned) was checked by
     * stage_precheck. */
    {
        AotLoadStatus st = bindings_validate(loader, err);
        if (st != AOT_LOAD_OK) {
            return st;
        }
    }

    /* Phase A: parse MOD0/.dynamic/.dynsym for EVERY module before relocating
     * any of them. A relocation in module 0 may resolve to a symbol defined in
     * module 2, so every module's symbol table must be known first; resolving
     * against a half-parsed module would read a zeroed symtab offset. */
    for (i = 0; i < loader->count; i++) {
        AotLoaderModule *m = &loader->modules[i];
        AotLoadStatus st;
        uint64_t table_len;

        st = parse_dynamic(m, &tags[i], err, i);
        if (st != AOT_LOAD_OK) {
            return st;
        }

        /* Symbol count: DT_HASH's nchain when present (and it must agree with
         * the pinned count), otherwise the descriptor's pinned count. */
        if (tags[i].has_hash) {
            const uint8_t *h = image_ptr(m, tags[i].hash, 8u);
            uint32_t nchain;
            if (h == NULL) {
                return aot_loader_fail(err, AOT_LOAD_ERR_DYNAMIC, i,
                                       tags[i].hash, 0u, m->desc->name,
                                       "DT_HASH is not mapped");
            }
            nchain = rd32(h + 4);
            if (nchain != m->desc->dynsym_count) {
                return aot_loader_fail(err, AOT_LOAD_ERR_DYNAMIC, i,
                                       tags[i].hash, 0u, m->desc->name,
                                       "DT_HASH nchain != pinned dynsym count");
            }
            m->sym_count = nchain;
        } else {
            m->sym_count = m->desc->dynsym_count;
        }
        if (m->sym_count == 0u || !tags[i].has_symtab || !tags[i].has_strtab ||
            !tags[i].has_strsz || tags[i].strsz == 0u) {
            return aot_loader_fail(err, AOT_LOAD_ERR_SYMBOLS, i,
                                   tags[i].symtab, 0u, m->desc->name,
                                   "missing or empty dynsym/dynstr");
        }
        m->symtab_off = tags[i].symtab;
        m->strtab_off = tags[i].strtab;
        m->strsz = tags[i].strsz;
        m->symtab_size = (uint64_t)m->sym_count * SYM_ENTRY_BYTES;
        table_len = m->symtab_size;
        if (image_ptr(m, m->symtab_off, table_len) == NULL ||
            image_ptr(m, m->strtab_off, m->strsz) == NULL) {
            return aot_loader_fail(err, AOT_LOAD_ERR_SYMBOLS, i,
                                   m->symtab_off < m->strtab_off
                                       ? m->symtab_off
                                       : m->strtab_off,
                                   0u, m->desc->name,
                                   "dynsym/dynstr do not fit their segments");
        }
        /* Review fix 4: validate EVERY symbol of EVERY module before any
         * relocation runs (parse-time rejection, not a resolution-time
         * surprise), so a bad definition cannot hide behind an unused path. */
        {
            uint32_t sym_i;
            for (sym_i = 0; sym_i < m->sym_count; sym_i++) {
                AotLoadStatus vst = sym_validate(m, sym_i, err, i);
                if (vst != AOT_LOAD_OK) {
                    return vst;
                }
            }
        }
        /* Minor 5: the tables this module's relocations must stay out of.
         * Registered here, where every extent is known and before ANY site is
         * recorded. gnu.hash is not consumed by this loader (DT_HASH is), so it
         * is not listed; that is deliberate, not an omission. */
        m->table_count = 0u;
        table_add(m, tags[i].dyn_off, tags[i].dyn_size, ".dynamic");
        table_add(m, m->symtab_off, m->symtab_size, ".dynsym");
        table_add(m, m->strtab_off, m->strsz, ".dynstr");
        if (tags[i].has_hash) {
            /* ELF hash: nbucket, nchain, then nbucket+nchain 32-bit words. */
            const uint8_t *h = image_ptr(m, tags[i].hash, 8u);
            if (h != NULL) {
                uint64_t nbucket = rd32(h);
                uint64_t nchain = rd32(h + 4u);
                table_add(m, tags[i].hash, 8u + 4u * (nbucket + nchain),
                          ".hash");
            }
        }
        if (tags[i].has_rela) {
            table_add(m, tags[i].rela,
                      tags[i].has_relasz ? tags[i].relasz : 0u, ".rela");
        }
        if (tags[i].has_jmprel) {
            table_add(m, tags[i].jmprel,
                      tags[i].has_pltrelsz ? tags[i].pltrelsz : 0u,
                      ".jmprel");
        }
        if (tags[i].has_relr) {
            table_add(m, tags[i].relr,
                      tags[i].has_relrsz ? tags[i].relrsz : 0u, ".relr");
        }

        /* Phase A2: build this module's symbol-name index ONCE, now that every
         * symbol and every name is known to be valid. Resolution then costs one
         * hash probe per name instead of a full dynsym scan per site. */
        {
            AotLoadStatus ist = sym_index_build(m, err, i);
            if (ist != AOT_LOAD_OK) {
                return ist;
            }
        }
    }

    /* Phase B: RELR, then RELA, then JMPREL, module by module (the reference
     * linker's order, which fixes the site dump order). */
    for (i = 0; i < loader->count; i++) {
        AotLoadStatus st;

        st = apply_relr(loader, i, &tags[i], err);
        if (st != AOT_LOAD_OK) {
            return st;
        }
        if (tags[i].has_rela) {
            st = apply_rela_table(loader, i, tags[i].rela,
                                  tags[i].has_relasz ? tags[i].relasz : 0u,
                                  "RELA", err);
            if (st != AOT_LOAD_OK) {
                return st;
            }
        }
        if (tags[i].has_jmprel) {
            st = apply_rela_table(loader, i, tags[i].jmprel,
                                  tags[i].has_pltrelsz ? tags[i].pltrelsz : 0u,
                                  "JMPREL", err);
            if (st != AOT_LOAD_OK) {
                return st;
            }
        }
    }

    loader->relocated = 1;
    if (err != NULL) {
        memset(err, 0, sizeof *err);
        err->module = AOT_LOADER_NO_MODULE;
        err->detail = "ok";
    }
    return AOT_LOAD_OK;
}

static AotLoadStatus seal_impl(AotLoader *loader, AotLoadError *err)
{
    AotSha256 digest;
    uint8_t got[AOT_SHA256_DIGEST_BYTES];
    uint8_t want[AOT_SHA256_DIGEST_BYTES];
    uint32_t i;
    AotMemStatus ms;

    /* Stage order (relocated, not sealed, not poisoned) was checked by
     * stage_precheck; seal itself is one-shot by contract. */

    /* Link digest: SHA-256 over the concatenation, in module order, of every
     * module's relocated data segment. bss is excluded. */
    aot_sha256_init(&digest);
    for (i = 0; i < loader->count; i++) {
        const AotLoaderModule *m = &loader->modules[i];
        aot_sha256_update(&digest, m->data.host, (size_t)m->data.image_len);
    }
    aot_sha256_final(&digest, got);

    /* The digest is program-wide, so every descriptor in a set must carry the
     * same expected value; compare against the module's own pinned digest so a
     * mixed-up descriptor set is reported on the module that disagrees. */
    for (i = 0; i < loader->count; i++) {
        memcpy(want, loader->set->modules[i].link_digest,
               AOT_SHA256_DIGEST_BYTES);
        if (memcmp(got, want, AOT_SHA256_DIGEST_BYTES) != 0) {
            return aot_loader_fail(err, AOT_LOAD_ERR_DIGEST, i, 0u, 0u,
                                   loader->modules[i].desc->name,
                                   "link digest does not match the descriptor");
        }
    }
    loader->digest_matched = 1;

    ms = aot_as_seal(loader->as);
    if (ms != AOT_MEM_OK) {
        return aot_loader_fail(err, AOT_LOAD_ERR_SEAL, AOT_LOADER_NO_MODULE,
                               0u, 0u, NULL,
                               "aot_as_seal rejected the address space");
    }
    loader->sealed = 1;
    if (err != NULL) {
        memset(err, 0, sizeof *err);
        err->module = AOT_LOADER_NO_MODULE;
        err->detail = "ok";
    }
    return AOT_LOAD_OK;
}

AotLoadStatus aot_loader_map(AotLoader *loader, const uint8_t *const images[],
                             const uint64_t sizes[], AotLoadError *err)
{
    AotLoadStatus st = stage_precheck(loader, AOT_LOADER_STAGE_MAP, err);

    if (st != AOT_LOAD_OK) {
        /* Out-of-order/repeated stage: nothing was touched, so nothing is
         * poisoned (Major 2). */
        return st;
    }
    st = map_impl(loader, images, sizes, err);
    if (st != AOT_LOAD_OK) {
        aot_loader_poison(loader);
    }
    return st;
}

AotLoadStatus aot_loader_relocate(AotLoader *loader, AotLoadError *err)
{
    AotLoadStatus st = stage_precheck(loader, AOT_LOADER_STAGE_RELOCATE, err);

    if (st != AOT_LOAD_OK) {
        return st;
    }
    st = relocate_impl(loader, err);
    if (st != AOT_LOAD_OK) {
        aot_loader_poison(loader);
    }
    return st;
}

AotLoadStatus aot_loader_seal(AotLoader *loader, AotLoadError *err)
{
    AotLoadStatus st = stage_precheck(loader, AOT_LOADER_STAGE_SEAL, err);

    if (st != AOT_LOAD_OK) {
        return st;
    }
    st = seal_impl(loader, err);
    if (st != AOT_LOAD_OK) {
        aot_loader_poison(loader);
    }
    return st;
}

AotLoadStatus aot_loader_load(AotLoader *loader, const uint8_t *const images[],
                              const uint64_t sizes[], AotLoadError *err)
{
    AotLoadStatus st = aot_loader_map(loader, images, sizes, err);
    if (st != AOT_LOAD_OK) {
        return st;
    }
    st = aot_loader_relocate(loader, err);
    if (st != AOT_LOAD_OK) {
        return st;
    }
    return aot_loader_seal(loader, err);
}

AotLoadStatus aot_loader_symbol(const AotLoader *loader, const char *name,
                                uint64_t *out_va)
{
    uint32_t i;

    /* Review fix 13: resolving against a half-loaded module would report a
     * pre-relocation symbol value, so the gate is the RELOCATED state. */
    if (loader == NULL || name == NULL || out_va == NULL || !loader->mapped ||
        !loader->relocated) {
        return AOT_LOAD_ERR_ARG;
    }
    for (i = 0; i < loader->count; i++) {
        const AotLoaderModule *m = &loader->modules[i];
        uint32_t s;
        for (s = 0; s < m->sym_count; s++) {
            Symbol sym;
            if (sym_read(m, s, &sym, NULL, i) != AOT_LOAD_OK) {
                return AOT_LOAD_ERR_SYMBOLS;
            }
            if (sym_name_is(&sym, name) && sym_defined(m, &sym)) {
                *out_va = m->desc->guest_base + sym.value;
                return AOT_LOAD_OK;
            }
        }
    }
    return AOT_LOAD_ERR_SYMBOL;
}

uint32_t aot_loader_site_count(const AotLoader *loader)
{
    return (loader != NULL) ? loader->site_count : 0u;
}

int aot_loader_site(const AotLoader *loader, uint32_t index, AotLinkSite *out)
{
    if (loader == NULL || out == NULL || index >= loader->site_count) {
        return 0;
    }
    *out = loader->sites[index];
    return 1;
}
