/*
 * G3 increment 1: the validated, immutable-after-link multi-image Program.
 *
 * This file is pure data/validation: no Win32 calls, no locking, no
 * translation. The dispatcher that consumes a Program lives in aot_runtime.c.
 */
#include "aot_runtime.h"
#include "aot_as.h"

#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------- helpers -- */

static int range_contains(const AotCodeRange *ranges, size_t count, uint64_t pc) {
    for (size_t i = 0; i < count; i++) {
        if (pc >= ranges[i].start && pc < ranges[i].end) return 1;
    }
    return 0;
}

/* base + count * AOT_THUNK_STRIDE without wrapping. Returns 0 on overflow. */
static int region_span_end(uint64_t base, uint64_t count, uint64_t *out_end) {
    if (count > (UINT64_MAX / AOT_THUNK_STRIDE)) return 0;
    uint64_t span = count * AOT_THUNK_STRIDE;
    if (base > UINT64_MAX - span) return 0;
    *out_end = base + span;
    return 1;
}

static int ranges_overlap(uint64_t a0, uint64_t a1, uint64_t b0, uint64_t b1) {
    return a0 < b1 && b0 < a1;
}

/* One image descriptor, validated on its own terms. `is_program` is always 1
 * here: a Program image must be ABI v2 and must not look like a v1 image. */
static uint32_t prog_image_validate(const AotProgImage *img) {
    if (img == NULL) return AOT_FAULT_BAD_STATE;
    if (img->subset_id == NULL || strcmp(img->subset_id, AOT_SUBSET_ID_MODULE) != 0)
        return AOT_FAULT_BAD_STATE;
    if (img->abi_version != AOT_ABI_VERSION_PROGRAM ||
        img->state_layout != AOT_STATE_LAYOUT)
        return AOT_FAULT_BAD_STATE;
    if (img->range_count == 0u || img->ranges == NULL) return AOT_FAULT_BAD_STATE;
    if (img->range_count > AOT_PROGRAM_MAX_RANGES) return AOT_FAULT_BAD_STATE;
    if (img->block_count != 0u && img->blocks == NULL) return AOT_FAULT_BAD_STATE;
    for (size_t i = 0; i < img->range_count; i++) {
        uint64_t s = img->ranges[i].start;
        uint64_t e = img->ranges[i].end;
        if (e <= s) return AOT_FAULT_BAD_STATE;
        if ((s & 3u) != 0u || (e & 3u) != 0u) return AOT_FAULT_BAD_STATE;
        if (s < AOT_AS_MIN_ADDR) return AOT_FAULT_BAD_STATE;
        if (e > AOT_AS_MAX_ADDR) return AOT_FAULT_BAD_STATE;
        if (i != 0 && s < img->ranges[i - 1].end) return AOT_FAULT_BAD_STATE;
    }
    for (size_t i = 0; i < img->block_count; i++) {
        uint64_t pc = img->blocks[i].entry_pc;
        if (img->blocks[i].fn == NULL) return AOT_FAULT_BAD_STATE;
        if ((pc & 3u) != 0u) return AOT_FAULT_BAD_STATE;
        if (i != 0 && pc <= img->blocks[i - 1].entry_pc)
            return AOT_FAULT_BAD_STATE;
        if (!range_contains(img->ranges, img->range_count, pc))
            return AOT_FAULT_BAD_STATE;
    }
    return AOT_FAULT_NONE;
}

/* --------------------------------------------------------------- create -- */

AotProgram *aot_program_create(const AotAddressSpace *as) {
    AotProgram *p = (AotProgram *)calloc(1, sizeof(AotProgram));
    if (p == NULL) return NULL;
    p->as = as;
    return p;
}

void aot_program_destroy(AotProgram *p) {
    if (p == NULL) return;
    free(p->handlers);
    free(p);
}

uint32_t aot_program_add_image(AotProgram *p, const AotProgImage *img) {
    uint32_t rc;
    if (p == NULL || p->finalized) return AOT_FAULT_BAD_STATE;
    rc = prog_image_validate(img);
    if (rc != AOT_FAULT_NONE) return rc;
    if (p->image_count >= AOT_PROGRAM_MAX_IMAGES) return AOT_FAULT_BAD_STATE;
    if (p->range_count + (uint32_t)img->range_count > AOT_PROGRAM_MAX_RANGES)
        return AOT_FAULT_BAD_STATE;
    /* Cross-image text ranges must be disjoint (and images must not share a
     * block entry, which the disjointness implies). */
    for (size_t i = 0; i < img->range_count; i++) {
        for (uint32_t j = 0; j < p->range_count; j++) {
            if (ranges_overlap(img->ranges[i].start, img->ranges[i].end,
                               p->range[j].start, p->range[j].end))
                return AOT_FAULT_BAD_STATE;
        }
    }
    p->image[p->image_count] = img;
    for (size_t i = 0; i < img->range_count; i++) {
        p->range[p->range_count].start = img->ranges[i].start;
        p->range[p->range_count].end = img->ranges[i].end;
        p->range[p->range_count].image = p->image_count;
        p->range_count++;
    }
    p->image_count++;
    /* Keep the merged range table sorted so lookups are a binary search even
     * before finalize (images may be added in any address order). */
    for (uint32_t i = 1; i < p->range_count; i++) {
        AotProgramRange key = p->range[i];
        uint32_t j = i;
        while (j > 0u && p->range[j - 1u].start > key.start) {
            p->range[j] = p->range[j - 1u];
            j--;
        }
        p->range[j] = key;
    }
    return AOT_FAULT_NONE;
}

uint32_t aot_program_set_host_regions(AotProgram *p, uint64_t thunk_base,
                                      uint64_t thunk_count,
                                      uint64_t sentinel_base,
                                      uint64_t sentinel_count) {
    if (p == NULL || p->finalized) return AOT_FAULT_BAD_STATE;
    p->thunk_base = thunk_base;
    p->thunk_count = thunk_count;
    p->sentinel_base = sentinel_base;
    p->sentinel_count = sentinel_count;
    return AOT_FAULT_NONE;
}

int aot_program_set_handler(AotProgram *p, uint32_t kind, uint32_t id,
                            AotProgHandler fn, void *user) {
    if (p == NULL || p->finalized || fn == NULL) return 1;
    for (size_t i = 0; i < p->handler_count; i++) {
        if (p->handlers[i].kind == kind &&
            aot_hle_id_key(kind, p->handlers[i].id) ==
                aot_hle_id_key(kind, id)) {
            return 2;
        }
    }
    if (p->handler_count >= AOT_PROGRAM_MAX_HANDLERS) return 3;
    if (p->handler_count == p->handler_capacity) {
        size_t cap = (p->handler_capacity == 0u) ? 16u : p->handler_capacity * 2u;
        AotProgHandlerEntry *grown;
        if (cap > AOT_PROGRAM_MAX_HANDLERS) cap = AOT_PROGRAM_MAX_HANDLERS;
        grown = (AotProgHandlerEntry *)realloc(
            p->handlers, cap * sizeof(AotProgHandlerEntry));
        if (grown == NULL) return 4;
        p->handlers = grown;
        p->handler_capacity = cap;
    }
    p->handlers[p->handler_count].kind = kind;
    p->handlers[p->handler_count].id = id;
    p->handlers[p->handler_count].fn = fn;
    p->handlers[p->handler_count].user = user;
    p->handler_count++;
    return 0;
}

static int handler_cmp(const void *a, const void *b) {
    const AotProgHandlerEntry *x = (const AotProgHandlerEntry *)a;
    const AotProgHandlerEntry *y = (const AotProgHandlerEntry *)b;
    if (x->kind != y->kind) return (x->kind < y->kind) ? -1 : 1;
    if (x->id != y->id) return (x->id < y->id) ? -1 : 1;
    return 0;
}

uint32_t aot_program_finalize(AotProgram *p) {
    uint64_t thunk_end = 0, sentinel_end = 0;
    if (p == NULL) return AOT_FAULT_BAD_STATE;
    if (p->finalized) return AOT_FAULT_NONE;
    if (p->image_count == 0u || p->range_count == 0u) return AOT_FAULT_BAD_STATE;

    /* Merged range table must be sorted and disjoint across ALL images. */
    for (uint32_t i = 0; i < p->range_count; i++) {
        if (p->range[i].end <= p->range[i].start) return AOT_FAULT_BAD_STATE;
        if (i != 0 && p->range[i].start < p->range[i - 1u].end)
            return AOT_FAULT_BAD_STATE;
    }

    /* Thunk region: 16-byte stride, 16-byte aligned, non-zero. */
    if (p->thunk_count == 0u || p->thunk_base == 0u) return AOT_FAULT_BAD_STATE;
    if ((p->thunk_base & (AOT_THUNK_STRIDE - 1u)) != 0u) return AOT_FAULT_BAD_STATE;
    if (p->thunk_count > 0xffffffffull) return AOT_FAULT_BAD_STATE;
    if (!region_span_end(p->thunk_base, p->thunk_count, &thunk_end))
        return AOT_FAULT_BAD_STATE;
    /* Thunks and sentinels live in the same guest-address window as image text
     * ([2^32, 2^39)), so a forged/stale PC outside it can never be mistaken
     * for a thunk or sentinel and the regions stay inside the address space
     * rules the images obey. */
    if (p->thunk_base < AOT_AS_MIN_ADDR) return AOT_FAULT_BAD_STATE;
    if (thunk_end > AOT_AS_MAX_ADDR) return AOT_FAULT_BAD_STATE;

    /* Sentinel region: at least one slot per call depth. */
    if (p->sentinel_base == 0u) return AOT_FAULT_BAD_STATE;
    if ((p->sentinel_base & (AOT_THUNK_STRIDE - 1u)) != 0u)
        return AOT_FAULT_BAD_STATE;
    if (p->sentinel_count < AOT_MAX_CALL_DEPTH) return AOT_FAULT_BAD_STATE;
    if (p->sentinel_count > 0xffffffffull) return AOT_FAULT_BAD_STATE;
    if (!region_span_end(p->sentinel_base, p->sentinel_count, &sentinel_end))
        return AOT_FAULT_BAD_STATE;
    if (p->sentinel_base < AOT_AS_MIN_ADDR) return AOT_FAULT_BAD_STATE;
    if (sentinel_end > AOT_AS_MAX_ADDR) return AOT_FAULT_BAD_STATE;

    if (ranges_overlap(p->thunk_base, thunk_end, p->sentinel_base, sentinel_end))
        return AOT_FAULT_BAD_STATE;
    for (uint32_t i = 0; i < p->range_count; i++) {
        if (ranges_overlap(p->thunk_base, thunk_end, p->range[i].start,
                           p->range[i].end))
            return AOT_FAULT_BAD_STATE;
        if (ranges_overlap(p->sentinel_base, sentinel_end, p->range[i].start,
                           p->range[i].end))
            return AOT_FAULT_BAD_STATE;
    }
    /* Thunks and sentinels must be UNMAPPED guest data: entering them is a
     * control-flow event, not a load/store, and a mapping would let guest code
     * read or forge them. That check needs the frozen region table, so the
     * address space must already be SEALED when the Program is finalized, and a
     * POISONED space (residue of a failed load) is never usable. */
    if (p->as == NULL || !aot_as_is_sealed(p->as) ||
        aot_as_is_poisoned(p->as))
        return AOT_FAULT_BAD_STATE;
    {
        if (aot_as_range_mapped((AotAddressSpace *)p->as, p->thunk_base,
                                thunk_end - p->thunk_base))
            return AOT_FAULT_BAD_STATE;
        if (aot_as_range_mapped((AotAddressSpace *)p->as, p->sentinel_base,
                                sentinel_end - p->sentinel_base))
            return AOT_FAULT_BAD_STATE;
    }

    if (p->handler_count > 1u) {
        qsort(p->handlers, p->handler_count, sizeof(AotProgHandlerEntry),
              handler_cmp);
        for (size_t i = 1; i < p->handler_count; i++) {
            if (handler_cmp(&p->handlers[i - 1], &p->handlers[i]) == 0)
                return AOT_FAULT_BAD_STATE;
        }
    }
    p->finalized = 1;
    return AOT_FAULT_NONE;
}

/* --------------------------------------------------------------- queries -- */

const AotProgImage *aot_program_image_at(const AotProgram *p, uint64_t pc) {
    if (p == NULL) return NULL;
    uint32_t lo = 0, hi = p->range_count;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2u;
        if (pc < p->range[mid].start) hi = mid;
        else if (pc >= p->range[mid].end) lo = mid + 1u;
        else return p->image[p->range[mid].image];
    }
    return NULL;
}

AotBlockFn aot_program_lookup(const AotProgram *p, uint64_t pc) {
    const AotProgImage *img;
    size_t lo, hi;
    if (p == NULL || (pc & 3u) != 0u) return NULL;
    img = aot_program_image_at(p, pc);
    if (img == NULL || img->blocks == NULL) return NULL;
    lo = 0;
    hi = img->block_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2u;
        uint64_t e = img->blocks[mid].entry_pc;
        if (e == pc) return img->blocks[mid].fn;
        if (e < pc) lo = mid + 1u;
        else hi = mid;
    }
    return NULL;
}

int aot_program_is_entry(const AotProgram *p, uint64_t pc) {
    return aot_program_lookup(p, pc) != NULL;
}

int aot_program_in_thunks(const AotProgram *p, uint64_t pc,
                          uint64_t *off_bytes) {
    uint64_t end = 0;
    if (p == NULL || p->thunk_count == 0u) return 0;
    if (!region_span_end(p->thunk_base, p->thunk_count, &end)) return 0;
    if (pc < p->thunk_base || pc >= end) return 0;
    if (off_bytes != NULL) *off_bytes = pc - p->thunk_base;
    return 1;
}

int aot_program_in_sentinel(const AotProgram *p, uint64_t pc,
                            uint64_t *off_bytes) {
    uint64_t end = 0;
    if (p == NULL || p->sentinel_count == 0u) return 0;
    if (!region_span_end(p->sentinel_base, p->sentinel_count, &end)) return 0;
    if (pc < p->sentinel_base || pc >= end) return 0;
    if (off_bytes != NULL) *off_bytes = pc - p->sentinel_base;
    return 1;
}

const AotProgHandlerEntry *aot_program_handler(const AotProgram *p,
                                               uint32_t kind, uint32_t id) {
    size_t lo, hi;
    if (p == NULL || p->handlers == NULL || !p->finalized) return NULL;
    lo = 0;
    hi = p->handler_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2u;
        const AotProgHandlerEntry *e = &p->handlers[mid];
        if (e->kind == kind &&
            aot_hle_id_key(kind, e->id) == aot_hle_id_key(kind, id)) {
            return e;
        }
        /* Keyed ids stay ordered under the mask, so the binary search is
         * still valid: only the low 5 bits of a SYSREG id are ignored. */
        if (e->kind < kind ||
            (e->kind == kind && aot_hle_id_key(kind, e->id) <
                                    aot_hle_id_key(kind, id))) {
            lo = mid + 1u;
        }
        else hi = mid;
    }
    return NULL;
}
