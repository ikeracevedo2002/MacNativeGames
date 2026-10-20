/*
 * G3 AOT module loader -- descriptor ABI and loader API.
 *
 * Increment 2 (T2) defines the descriptor TYPES that the offline reference
 * linker generates; T3 adds the loader that consumes them.
 *
 * The descriptors are the exact-version contract for the loader:
 *   - the SHA-256 of the flat image is verified BEFORE any region is added or
 *     any byte is written;
 *   - together with the pinned layout it identifies the image exactly;
 *   - link_digest is the expected SHA-256 over the concatenation, in module
 *     order, of each module's relocated data segment [data.off, data.off +
 *     data.size) (bss excluded), computed offline by the independent Python
 *     reference linker. The loader recomputes it after relocating and must
 *     match it before it sets permissions and seals the address space.
 *
 * All VAs stored in the descriptors are guest virtual addresses (fixed at AOT
 * time inside [2^32, 2^39)); no host pointers ever appear in guest memory or
 * in a relocated site.
 *
 * Memory shape per module (three regions, because Horizon/NVN permissions are
 * per page and text/rodata/data need different ones):
 *
 *   text   [0, page_up(text.size))                 R-X  state TEXT
 *   ro     [ro.off, page_up(ro.off + ro.size))     R    state TEXT
 *   data   [data.off, page_up(image_size))         RW   state DATA
 *
 * The three ranges must not overlap, so the fixtures' segments must be
 * page-separated (they are: ld places them on 4 KiB boundaries). Regions are
 * created with their FINAL permission; aot_as keeps host pages committed RW
 * until aot_as_seal() applies the declared permissions, so relocation writes
 * are only ever made through the data region's init-only host pointer.
 */
#ifndef MN_AOT_LOADER_H
#define MN_AOT_LOADER_H

/* AotImage / AotProgram / AotProgImage (Program ABI v2). aot_runtime.h does
 * not include this header, so there is no cycle. */
#include "aot_runtime.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* One [offset, size) range inside a module's flat image / memory image. */
typedef struct AotModuleRange {
    uint64_t off;
    uint64_t size;
} AotModuleRange;

/* One module's pinned identity and expected relocation result. */
typedef struct AotModuleDesc {
    const char *name;          /* e.g. "fx_main_v0" */
    uint64_t guest_base;       /* fixed guest VA of image offset 0 */
    uint64_t image_size;       /* flat bytes + bss bytes */
    AotModuleRange text;       /* R-X: [0, text size) */
    AotModuleRange ro;         /* R  */
    AotModuleRange data;       /* RW, file-backed part; bss follows */
    uint64_t bss_size;
    uint32_t dynsym_count;     /* pinned for images without DT_HASH */
    const uint8_t *sha256;     /* 32 bytes: SHA-256 of the flat image */
    uint64_t init_va;          /* DT_INIT guest VA; 0 when the module has none */
    const uint8_t *link_digest;/* 32 bytes: expected relocated-data digest */
    /* G3 increment 3: the translated AotImage for this module. NULL is legal
     * only for link-only fixtures; aot_loader_build_program refuses a NULL
     * image because a Program cannot dispatch untranslated text. */
    const AotImage *image;
} AotModuleDesc;

/* A generated module set for one link variant (module order is significant:
 * it is the global symbol search order). */
typedef struct AotModuleSet {
    const AotModuleDesc *modules;
    uint32_t count;
} AotModuleSet;

/* ======================================================================
 * Loader API (T3)
 *
 * Staged so that no partial failure can leave the guest address space in a
 * state that looks loaded:
 *
 *   verify_images  hash/size/layout only; adds nothing.
 *   map            verifies again, then adds the three regions per module and
 *                  copies the flat bytes + zeroes bss.
 *   relocate       diffs nothing: parses MOD0/dynamic, relocates RELR + RELA +
 *                  JMPREL, resolves symbols, records every site.
 *   seal           compares the link digest, then applies permissions.
 *
 *   aot_loader_load = map + relocate + seal.
 * ====================================================================== */

#define AOT_LOADER_MAX_MODULES 16u
/* Guest thunk stride: thunk VA = thunk_base + 16*index (same value as
 * AOT_THUNK_STRIDE in src/aot/aot_runtime.h). */
#define AOT_LOADER_THUNK_STRIDE 16u
#define AOT_LOADER_NO_MODULE 0xffffffffu

/* Defined in src/aot/aot_as.h (same typedef, repeated harmlessly). */
typedef struct AotAddressSpace AotAddressSpace;

/* Typed loader failure. `module` is the module index the failure belongs to
 * (AOT_LOADER_NO_MODULE when it is a call-level precondition), `image_off` the
 * offset inside that module's flat image, `site` the guest VA involved (0 when
 * not applicable) and `symbol` the symbol name for link errors. */
typedef struct AotLoadError {
    int status;              /* AotLoadStatus */
    uint32_t module;         /* index into AotModuleSet.modules */
    uint64_t image_off;      /* image offset or relocation entry offset */
    uint64_t site;           /* guest VA of the affected site, else 0 */
    const char *symbol;      /* borrowed, may be NULL */
    const char *detail;      /* static explanation, never NULL on failure */
} AotLoadError;

typedef enum {
    AOT_LOAD_OK = 0,
    AOT_LOAD_ERR_ARG,      /* NULL/zeroed argument */
    AOT_LOAD_ERR_COUNT,    /* module count outside 1..AOT_LOADER_MAX_MODULES */
    AOT_LOAD_ERR_LAYOUT,   /* descriptor layout is not a valid image */
    AOT_LOAD_ERR_SIZE,     /* flat size != data.off + data.size */
    AOT_LOAD_ERR_SHA256,   /* image bytes do not match the pinned digest */
    AOT_LOAD_ERR_OVERLAP,  /* two modules claim overlapping guest ranges */
    AOT_LOAD_ERR_STATE,    /* sealed space, or a loader stage out of order */
    AOT_LOAD_ERR_MAP,      /* the address space refused the region */
    AOT_LOAD_ERR_MOD0,     /* bad/missing MOD0 header */
    AOT_LOAD_ERR_DYNAMIC,  /* bad .dynamic / DT_* values */
    AOT_LOAD_ERR_SYMBOLS,  /* bad .dynsym/.dynstr */
    AOT_LOAD_ERR_RELOC,    /* unsupported kind, bad site, duplicate site */
    AOT_LOAD_ERR_DIGEST,   /* link digest != descriptor's expected digest */
    AOT_LOAD_ERR_SEAL,     /* the address space refused to seal */
    AOT_LOAD_ERR_SYMBOL,   /* symbol not found / unresolved import */
    AOT_LOAD_ERR_OOM       /* allocation failure (site table or dup bitmap) */
} AotLoadStatus;

/* Host thunk binding: a symbol name the AOT program replaces with a host
 * function. `thunk` is the program-wide thunk index; its guest VA is
 * thunk_base + 16*index. */
typedef struct AotHostBinding {
    const char *name;
    uint32_t thunk;
} AotHostBinding;

/* Override/observer tables for one generated module set (from link_config.json
 * at AOT time). Overrides apply to every relocation kind; observers apply ONLY
 * to JUMP_SLOT. `sentinel` is carried for the Program link step. */
typedef struct AotHostBindings {
    uint64_t thunk_base;
    uint64_t sentinel;
    const AotHostBinding *overrides;
    uint32_t override_count;
    const AotHostBinding *observers;
    uint32_t observer_count;
} AotHostBindings;

/* Per-module relocation counters (same meaning as the reference linker). */
typedef struct AotLinkCounters {
    uint32_t relative;
    uint32_t symbolic;
    uint32_t cross;
    uint32_t weak;
} AotLinkCounters;

/* One relocated site, in the reference linker's TSV shape. `where` is an image
 * offset; `symbol` is NULL for a RELATIVE site (the TSV prints "-"). */
typedef struct AotLinkSite {
    uint32_t module;
    uint32_t kind;      /* 257 ABS64, 1025 GLOB_DAT, 1026 JUMP_SLOT, 1027 RELATIVE */
    uint64_t where;
    uint64_t value;     /* the 64-bit GUEST VA written */
    const char *symbol;
} AotLinkSite;

/* One mapped region of a module. image_off/image_len are the file-backed part
 * in image offsets; size is the mapped, page-rounded size. */
typedef struct AotLoaderRegion {
    uint64_t image_off;
    uint64_t image_len;
    uint64_t guest_base;
    uint64_t size;
    uint8_t *host;      /* INIT-ONLY host pointer, never a guest address */
} AotLoaderRegion;

/* One slot of a module's symbol-name index (open addressing, power-of-two
 * capacity, load factor <= 0.5). `name == NULL` marks an empty slot. The index
 * keeps TWO symbol indices per name so that resolution order is unchanged:
 * `first` is the first entry with that name (any binding/section), and
 * `first_defined` is the first entry with that name that is DEFINED. */
#define AOT_SYM_INDEX_NONE 0xffffffffu

typedef struct AotSymIndexEntry {
    const char *name;
    uint32_t hash;          /* FNV-1a of the name (informational) */
    uint32_t first;         /* first name match, or AOT_SYM_INDEX_NONE */
    uint32_t first_defined; /* first DEFINED name match, or NONE */
} AotSymIndexEntry;

/* Minor 5: one table the loader CONSUMES, as an [off, off+size) image range.
 * A relocation site may never overlap one. */
#define AOT_LOADER_TABLE_MAX 9

typedef struct AotLoaderTable {
    uint64_t off;
    uint64_t size;
    const char *name;   /* ".dynamic", ".dynsym", ... (static storage) */
} AotLoaderTable;

typedef struct AotLoaderModule {
    const AotModuleDesc *desc;
    AotLoaderRegion text;
    AotLoaderRegion ro;
    AotLoaderRegion data;
    uint64_t image_size;
    uint64_t flat_size;
    uint64_t symtab_off;
    uint64_t strtab_off;
    uint64_t strsz;
    uint64_t symtab_size;  /* bytes of the dynamic symbol table */
    uint32_t sym_count;
    uint32_t major;        /* 0: main-like module (all fixtures are 0) */
    uint64_t init_va;      /* DT_INIT guest VA from the descriptor/image */
    /* Duplicate-site detection: one bit per 8-byte slot of the RELOCATED data
     * segment, i.e. an O(1) test per site instead of a linear scan (review fix
     * 12: real modules carry 10^5..10^6 relocations). Owned by the loader. */
    uint8_t *site_bits;
    uint64_t site_bits_bytes;
    /* Symbol-name index built ONCE after this module's dynsym has been parsed
     * and fully validated (see sym_index_build in aot_loader.c). Before it
     * existed, every relocation name lookup scanned the whole dynsym, which
     * made the real-module link O(sites x dynsym) (~45 s in Debug). */
    AotSymIndexEntry *sym_index;
    uint32_t sym_index_cap; /* power of two, 0 when no index was built */
    AotLinkCounters counters;
    /* Minor 5: the tables this module's relocations must stay out of. Filled
     * once in relocate's phase A (after parse_dynamic, before any site). */
    AotLoaderTable table[AOT_LOADER_TABLE_MAX];
    uint32_t table_count;
} AotLoaderModule;

typedef struct AotLoader {
    AotAddressSpace *as;
    const AotModuleSet *set;
    const AotHostBindings *bindings;  /* borrowed, may be NULL */
    uint32_t count;
    uint32_t verified;
    uint32_t mapped;
    uint32_t relocated;
    uint32_t sealed;
    int digest_matched;
    AotLoaderModule modules[AOT_LOADER_MAX_MODULES];
    AotLinkSite *sites;
    uint32_t site_count;
    uint32_t site_capacity;
    /* Program assembly scratch: one AotProgImage per module, filled by
     * aot_loader_build_program. The Program borrows these pointers, so the
     * loader must outlive the Program (it already owns the mapped regions). */
    AotProgImage prog[AOT_LOADER_MAX_MODULES];
    /* Set once aot_loader_build_program has SUCCEEDED. The Program borrows
     * prog[] AND the descriptor images, so a second build from the same loader
     * would alias the first one's storage: it is refused with a typed error.
     * A FAILED build does not set this, so the caller may retry. */
    uint32_t program_built;
    /* Link-only modules, NAMED BY THE CALLER (array is borrowed; the strings
     * must outlive the loader). aot_loader_build_program accepts a module whose
     * descriptor has image == NULL ONLY when its name appears here, so the
     * caller must state explicitly which modules were never translated. Any
     * other module with a NULL image is still a hard error (a forgotten image
     * can never silently become dead code). A link-only module is loaded,
     * relocated and sealed and can satisfy SYMBOLS, but no code block exists for
     * any of its addresses: a transfer into it faults as
     * AOT_FAULT_UNTRANSLATED inside a declared text range of its own image, or
     * AOT_FAULT_UNKNOWN_PC when it has no image range at all. Off by default. */
    const char *const *link_only;
    uint32_t link_only_count;
} AotLoader;

/* Human-readable status name (never NULL). */
const char *aot_load_status_name(int status);

/* Bind `loader` to an address space and a generated module set. Adds nothing. */
AotLoadStatus aot_loader_init(AotLoader *loader, AotAddressSpace *as,
                              const AotModuleSet *set, AotLoadError *err);

/* Drop every host pointer and the site table (the address space keeps
 * ownership of the backing memory). Safe on a partially loaded loader. */
void aot_loader_release(AotLoader *loader);

/* Attach the AOT-time host bindings (override/observer tables). MANDATORY for
 * a load (review fix 14): aot_loader_relocate() rejects a loader with no
 * bindings attached (AOT_LOAD_ERR_ARG) and validates them, so a forgotten
 * table can never silently change symbol resolution. An EXPLICIT empty table
 * (both counts 0) is allowed and means "no host symbols". The tables are
 * borrowed and must outlive the loader. */
void aot_loader_set_host_bindings(AotLoader *loader,
                                  const AotHostBindings *bindings);

/* Declare which modules are LINK-ONLY: loaded, relocated and sealed, but with
 * no translated code (descriptor image == NULL). `names` is borrowed (its
 * strings are compared by name during aot_loader_build_program) and must
 * outlive the loader. Passing count 0 resets the list. Every module NOT named
 * here must carry a translated image. */
void aot_loader_set_link_only(AotLoader *loader, const char *const *names,
                              uint32_t count);

/* Verify EVERY module's pinned layout, size and SHA-256 BEFORE anything else
 * happens. `sizes[i]` is the byte length of `images[i]` (the flat NSO image).
 * On failure `*err` carries the module index and the failing offset. Adds no
 * region and writes no byte. */
AotLoadStatus aot_loader_verify_images(const AotModuleSet *set,
                                       const uint8_t *const images[],
                                       const uint64_t sizes[],
                                       AotLoadError *err);

/* Map every module: three regions (text R-X, rodata R, data+bss RW) at
 * desc->guest_base, copied from `images[i]` with bss/page tails zero-filled.
 * The address space must be UNSEALED. Verification is repeated first, so an
 * unverified image can never become a mapped region. On failure `*err` names
 * the module; regions already added stay mapped (aot_as_destroy releases them)
 * and the loader must be released before reuse. */
AotLoadStatus aot_loader_map(AotLoader *loader, const uint8_t *const images[],
                             const uint64_t sizes[], AotLoadError *err);

/* Parse MOD0/.dynamic/.dynsym and apply RELR + RELA + JMPREL. Every written
 * value is a 64-bit guest VA. Rejects duplicate sites, sites outside
 * [data.off, data.end-8), unknown kinds, non-zero JUMP_SLOT addends and
 * out-of-image RELATIVE addends. Fills the counters and the site table.
 * Requires the host bindings to be attached and consistent (thunk indices
 * unique across overrides+observers, thunk_base in [2^32, 2^39) with its whole
 * span below 2^39). Duplicate sites are detected through a per-module
 * bitmap over the data segment. A failure leaves the address space POISONED
 * (aot_as_poison) so it can never be sealed. */
AotLoadStatus aot_loader_relocate(AotLoader *loader, AotLoadError *err);

/* Recompute the link digest over each module's relocated data segment and
 * require it to equal the descriptor's expected digest, then seal the address
 * space (which applies the declared text/rodata/data permissions). */
AotLoadStatus aot_loader_seal(AotLoader *loader, AotLoadError *err);

/* map + relocate + seal. */
AotLoadStatus aot_loader_load(AotLoader *loader, const uint8_t *const images[],
                              const uint64_t sizes[], AotLoadError *err);

/* ---- Program assembly (G3 increment 3) --------------------------------
 * After a successful aot_loader_load (verified + mapped + relocated + sealed),
 * add every module's translated image to `out` (created by the caller with
 * aot_program_create over the SAME address space) and set the Program's thunk
 * and sentinel regions. The thunk region base comes from the generated host
 * bindings; handlers are NOT registered here (the caller owns them, and they
 * must be registered before the caller's aot_program_finalize).
 *
 * Fail-closed checks per module:
 *   - desc->image != NULL (a link-only descriptor is not executable);
 *   - image subset == AOT_SUBSET_ID_MODULE and ABI == AOT_ABI_VERSION_PROGRAM;
 *   - image->source_sha256 == lowercase hex of desc->sha256, so an image can
 *     only ever be bound to the exact flat bytes it was translated from
 *     (a wrong variant pairing, e.g. relr descriptors with v0 images, fails
 *     here);
 *   - every image code range lies inside [guest_base + text.off, +text.size)
 *     and is 4-byte aligned (translated text only, never data/rodata).
 * A handled-but-refused condition returns the typed status and never leaves
 * a half-built Program usable. */
AotLoadStatus aot_loader_build_program(AotLoader *loader, AotProgram *out,
                                       uint64_t thunk_count,
                                       uint64_t sentinel_base,
                                       uint64_t sentinel_count,
                                       AotLoadError *err);

/* Resolve a symbol name to its guest VA using the loader's rules: first
 * definition in module order wins. Returns AOT_LOAD_OK or
 * AOT_LOAD_ERR_SYMBOL when nothing defines the name. */
AotLoadStatus aot_loader_symbol(const AotLoader *loader, const char *name,
                                uint64_t *out_va);

/* Per-site dump iterator. Sites are recorded in relocation order (RELR, then
 * RELA, then JMPREL, module by module); callers that need the reference TSV's
 * order sort by (module name, where). */
uint32_t aot_loader_site_count(const AotLoader *loader);
int aot_loader_site(const AotLoader *loader, uint32_t index, AotLinkSite *out);

#ifdef __cplusplus
}
#endif

#endif /* MN_AOT_LOADER_H */
