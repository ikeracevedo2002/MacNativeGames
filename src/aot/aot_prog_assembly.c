/*
 * G3 increment 3: Program assembly -- binds translated module images to the
 * loader's sealed, relocated modules.
 *
 * This lives in its own translation unit on purpose: aot_loader.c is a pure
 * loader (it is linked into every link/mutant probe and must not depend on the
 * Program dispatcher), while assembling an AotProgram does. The API is
 * declared in src/aot/aot_loader.h.
 */
#include "aot_loader.h"

#include "aot_runtime.h"

#include <string.h>

/* ======================================================================
 * Program assembly (G3 increment 3)
 *
 * The loader owns the mapped regions and the link results; the translated
 * code is a separate AotImage per module. aot_loader_build_program is the
 * ONLY place where an image is bound to a descriptor, and the binding is the
 * flat SHA-256: an image can never be run against bytes it was not translated
 * from. Everything is checked before a single image is added, and a refusal
 * leaves the caller's Program unfinished (it must be destroyed, not run).
 * ====================================================================== */

static void build_error(AotLoadError *err, int status, uint32_t module,
                        const char *detail)
{
    if (err == NULL) {
        return;
    }
    err->status = status;
    err->module = module;
    err->image_off = 0;
    err->site = 0;
    err->symbol = NULL;
    err->detail = detail;
}

/* Lowercase hex of a 32-byte digest; the translator writes source_sha256 in
 * exactly this form (hashlib.hexdigest()). */
static void hex32(const uint8_t *in, char out[65])
{
    static const char digits[] = "0123456789abcdef";
    uint32_t i;

    for (i = 0u; i < 32u; i++) {
        out[i * 2u] = digits[(in[i] >> 4) & 0x0fu];
        out[i * 2u + 1u] = digits[in[i] & 0x0fu];
    }
    out[64] = '\0';
}

/* Is module `name` declared LINK-ONLY by the caller (see
 * aot_loader_set_link_only)? Only these modules may reach build_program with a
 * NULL image; the check is by NAME so a descriptor mix-up cannot launder a
 * forgotten image into a skipped module. */
static int module_is_link_only(const AotLoader *loader, const char *name)
{
    uint32_t i;

    if (loader->link_only == NULL || name == NULL) {
        return 0;
    }
    for (i = 0u; i < loader->link_only_count; i++) {
        if (loader->link_only[i] != NULL &&
            strcmp(loader->link_only[i], name) == 0) {
            return 1;
        }
    }
    return 0;
}

AotLoadStatus aot_loader_build_program(AotLoader *loader, AotProgram *out,
                                       uint64_t thunk_count,
                                       uint64_t sentinel_base,
                                       uint64_t sentinel_count,
                                       AotLoadError *err)
{
    uint64_t thunk_base = 0u;
    uint32_t i;

    build_error(err, AOT_LOAD_OK, AOT_LOADER_NO_MODULE, "ok");
    if (loader == NULL || out == NULL) {
        build_error(err, AOT_LOAD_ERR_ARG, AOT_LOADER_NO_MODULE,
                    "build_program needs a loader and an empty Program");
        return AOT_LOAD_ERR_ARG;
    }
    /* Minor 4: the Program borrows loader->prog[] and the loader's address
     * space, so a Program built over a DIFFERENT space could dispatch code whose
     * memory is not the memory the descriptors were validated against. The
     * Program must also still be EMPTY and unfinalized: appending to a Program
     * that already carries images (or is frozen) would mix two module sets. */
    if (out->as != loader->as) {
        build_error(err, AOT_LOAD_ERR_ARG, AOT_LOADER_NO_MODULE,
                    "the Program was created over a different address space "
                    "than the loader's");
        return AOT_LOAD_ERR_ARG;
    }
    if (out->finalized || out->image_count != 0u || out->range_count != 0u ||
        out->handler_count != 0u || out->thunk_count != 0u ||
        out->sentinel_count != 0u) {
        build_error(err, AOT_LOAD_ERR_ARG, AOT_LOADER_NO_MODULE,
                    "build_program requires an EMPTY, unfinalized Program "
                    "(no images, ranges, regions, handlers and not finalized)");
        return AOT_LOAD_ERR_ARG;
    }
    if (loader->sealed == 0u || loader->count == 0u) {
        build_error(err, AOT_LOAD_ERR_STATE, AOT_LOADER_NO_MODULE,
                    "build_program requires a sealed load (map+relocate+seal)");
        return AOT_LOAD_ERR_STATE;
    }
    if (loader->program_built != 0u) {
        build_error(err, AOT_LOAD_ERR_STATE, AOT_LOADER_NO_MODULE,
                    "build_program already assembled a Program from this "
                    "loader (the Program borrows loader->prog[], so a second "
                    "one would alias it; init a new loader instead)");
        return AOT_LOAD_ERR_STATE;
    }
    /* The thunk base and the return sentinel are AOT-time facts, so they can
     * only come from the generated host bindings: reconcile the caller's
     * Program geometry against them instead of trusting either side. */
    if (loader->bindings == NULL &&
        (thunk_count != 0u || sentinel_count != 0u)) {
        build_error(err, AOT_LOAD_ERR_ARG, AOT_LOADER_NO_MODULE,
                    "build_program needs the host bindings to place the thunk "
                    "and sentinel regions");
        return AOT_LOAD_ERR_ARG;
    }
    if (loader->bindings != NULL) {
        uint32_t b;
        int have_max = 0;
        uint64_t max_thunk = 0u;
        const AotHostBindings *bd = loader->bindings;

        thunk_base = bd->thunk_base;
        for (b = 0u; b < bd->override_count; b++) {
            if (!have_max || bd->overrides[b].thunk > max_thunk) {
                max_thunk = bd->overrides[b].thunk;
                have_max = 1;
            }
        }
        for (b = 0u; b < bd->observer_count; b++) {
            if (!have_max || bd->observers[b].thunk > max_thunk) {
                max_thunk = bd->observers[b].thunk;
                have_max = 1;
            }
        }
        if (have_max && thunk_count <= max_thunk) {
            build_error(err, AOT_LOAD_ERR_ARG, AOT_LOADER_NO_MODULE,
                        "thunk_count does not cover the highest binding index "
                        "(the bindings place a thunk outside the Program's "
                        "thunk region)");
            return AOT_LOAD_ERR_ARG;
        }
        if (!have_max && thunk_count != 0u) {
            build_error(err, AOT_LOAD_ERR_ARG, AOT_LOADER_NO_MODULE,
                        "the bindings declare no thunks but the Program was "
                        "given a thunk region");
            return AOT_LOAD_ERR_ARG;
        }
        if (thunk_count != 0u && thunk_base == 0u) {
            build_error(err, AOT_LOAD_ERR_ARG, AOT_LOADER_NO_MODULE,
                        "the bindings declare no thunk base but the Program "
                        "was given a thunk region");
            return AOT_LOAD_ERR_ARG;
        }
        /* `sentinel` is carried in the bindings for exactly this check. */
        if (sentinel_count != 0u &&
            (bd->sentinel == 0u || sentinel_base != bd->sentinel)) {
            build_error(err, AOT_LOAD_ERR_ARG, AOT_LOADER_NO_MODULE,
                        "the Program's sentinel base is not the sentinel the "
                        "host bindings were generated with");
            return AOT_LOAD_ERR_ARG;
        }
    }

    for (i = 0u; i < loader->count; i++) {
        const AotLoaderModule *lm = &loader->modules[i];
        const AotModuleDesc *desc = lm->desc;
        const AotImage *img = (desc != NULL) ? desc->image : NULL;
        uint64_t lo;
        uint64_t hi;
        char want[65];
        uint32_t r;

        if (desc == NULL) {
            build_error(err, AOT_LOAD_ERR_ARG, i,
                        "module has no descriptor");
            return AOT_LOAD_ERR_ARG;
        }
        if (img == NULL) {
            /* Link-only module: loaded, relocated and sealed, but no code was
             * translated for it. Allowed ONLY for a module the caller declared
             * link-only by name; it contributes symbols and nothing else. A
             * transfer into it has no block, so dispatch reports
             * AOT_FAULT_UNTRANSLATED (inside a text range of its image) or
             * AOT_FAULT_UNKNOWN_PC (no image range at all). */
            if (!module_is_link_only(loader, desc->name)) {
                build_error(err, AOT_LOAD_ERR_ARG, i,
                            "module has no translated AotImage and was not "
                            "declared link-only (a forgotten image is an "
                            "error)");
                return AOT_LOAD_ERR_ARG;
            }
            continue;
        }
        if (img->subset_id == NULL ||
            strcmp(img->subset_id, AOT_SUBSET_ID_MODULE) != 0) {
            build_error(err, AOT_LOAD_ERR_LAYOUT, i,
                        "image subset id is not " AOT_SUBSET_ID_MODULE);
            return AOT_LOAD_ERR_LAYOUT;
        }
        if (img->abi_version != AOT_ABI_VERSION_PROGRAM ||
            img->state_layout != AOT_STATE_LAYOUT) {
            build_error(err, AOT_LOAD_ERR_LAYOUT, i,
                        "image is not an ABI-v2 Program image");
            return AOT_LOAD_ERR_LAYOUT;
        }
        if (desc->sha256 == NULL) {
            build_error(err, AOT_LOAD_ERR_ARG, i,
                        "descriptor has no flat SHA-256 to bind the image to");
            return AOT_LOAD_ERR_ARG;
        }
#ifndef MN_AOT_MUTANT_IMAGE_UNBOUND
        hex32(desc->sha256, want);
        if (img->source_sha256 == NULL ||
            strcmp(img->source_sha256, want) != 0) {
            build_error(err, AOT_LOAD_ERR_SHA256, i,
                        "image source identity is not the descriptor's flat "
                        "SHA-256 (wrong image/descriptor pairing)");
            return AOT_LOAD_ERR_SHA256;
        }
#else
        /* TEST-ONLY wrong implementation: the image <-> descriptor binding by
         * flat SHA-256 is SKIPPED, so a wrong pairing is accepted. */
        (void)want;
#endif
        lo = desc->guest_base + desc->text.off;
        hi = lo + desc->text.size;
        if (img->ranges == NULL || img->range_count == 0u ||
            img->blocks == NULL) {
            build_error(err, AOT_LOAD_ERR_LAYOUT, i,
                        "image declares no code range or no blocks");
            return AOT_LOAD_ERR_LAYOUT;
        }
        for (r = 0u; r < img->range_count; r++) {
            uint64_t s = img->ranges[r].start;
            uint64_t e = img->ranges[r].end;

            if (s < lo || e > hi || s >= e ||
                ((s | e) & 3u) != 0u) {
                build_error(err, AOT_LOAD_ERR_LAYOUT, i,
                            "image code range is not a 4-byte aligned range "
                            "inside the module's text segment");
                return AOT_LOAD_ERR_LAYOUT;
            }
        }

        /* AotProgImage is the ABI-v2 view of AotImage: the Program has no
         * thunk fields, so the image's own thunk metadata is not copied (a
         * Program owns the thunk region; a v1 image cannot masquerade). */
        loader->prog[i].subset_id = img->subset_id;
        loader->prog[i].abi_version = img->abi_version;
        loader->prog[i].state_layout = img->state_layout;
        loader->prog[i].source_sha256 = img->source_sha256;
        loader->prog[i].fixture_fnv64 = img->fixture_fnv64;
        loader->prog[i].blocks = img->blocks;
        loader->prog[i].block_count = img->block_count;
        loader->prog[i].ranges = img->ranges;
        loader->prog[i].range_count = img->range_count;
        if (aot_program_add_image(out, &loader->prog[i]) != AOT_FAULT_NONE) {
            build_error(err, AOT_LOAD_ERR_LAYOUT, i,
                        "the Program refused the image (overlapping ranges or "
                        "an unsorted block table)");
            return AOT_LOAD_ERR_LAYOUT;
        }
    }

    if (aot_program_set_host_regions(out, thunk_base, thunk_count,
                                     sentinel_base, sentinel_count) !=
        AOT_FAULT_NONE) {
        build_error(err, AOT_LOAD_ERR_LAYOUT, AOT_LOADER_NO_MODULE,
                    "the Program refused the thunk/sentinel regions");
        return AOT_LOAD_ERR_LAYOUT;
    }
    loader->program_built = 1u;
    return AOT_LOAD_OK;
}
