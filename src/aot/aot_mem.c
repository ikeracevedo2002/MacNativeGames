#include "aot_mem.h"

#include <string.h>

AotMemStatus aot_mem_init(AotMem *m, uint8_t *base, uint64_t size,
                          uint64_t guest_base) {
    m->base = NULL;
    m->size = 0;
    m->guest_base = 0;
    if (base == NULL || size == 0u) return AOT_MEM_ERR_RANGE;
    if (guest_base > UINT64_MAX - size) return AOT_MEM_ERR_RANGE; /* wrap */
    m->base = base;
    m->size = size;
    m->guest_base = guest_base;
    return AOT_MEM_OK;
}

int aot_mem_is_aligned(uint64_t addr, uint64_t align) {
    /* align must be a power of two in 1..16; a zero/non-power-of-two align is
     * treated as "not aligned" rather than silently masked. */
    if (align == 0u || align > 16u || (align & (align - 1u)) != 0u) return 0;
    return (addr & (align - 1u)) == 0u;
}

AotMemStatus aot_mem_check(const AotMem *m, uint64_t addr, uint64_t n) {
    if (m == NULL || m->base == NULL) return AOT_MEM_ERR_RANGE;
    if (addr < m->guest_base) return AOT_MEM_ERR_RANGE;
    uint64_t off = addr - m->guest_base;
    if (off > m->size) return AOT_MEM_ERR_RANGE;
    if (n > m->size - off) return AOT_MEM_ERR_RANGE;
    return AOT_MEM_OK;
}

/* Local byte assembly. All shifts are on unsigned values, so there is no
 * implementation-defined or UB behaviour here. */
static uint16_t le16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8));
}
static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}
static uint64_t le64(const uint8_t *p) {
    return (uint64_t)le32(p) | ((uint64_t)le32(p + 4) << 32);
}
static void st16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
}
static void st32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
    p[2] = (uint8_t)((v >> 16) & 0xffu);
    p[3] = (uint8_t)((v >> 24) & 0xffu);
}
static void st64(uint8_t *p, uint64_t v) {
    st32(p, (uint32_t)(v & 0xffffffffu));
    st32(p + 4, (uint32_t)((v >> 32) & 0xffffffffu));
}

AotMemStatus aot_mem_ld8(const AotMem *m, uint64_t addr, uint8_t *out) {
    AotMemStatus s = aot_mem_check(m, addr, 1);
    if (s != AOT_MEM_OK) return s;
    memcpy(out, m->base + (addr - m->guest_base), 1);
    return AOT_MEM_OK;
}
AotMemStatus aot_mem_ld16(const AotMem *m, uint64_t addr, uint16_t *out) {
    AotMemStatus s = aot_mem_check(m, addr, 2);
    if (s != AOT_MEM_OK) return s;
    if (!aot_mem_is_aligned(addr, 2)) {
        uint8_t b[2];
        memcpy(b, m->base + (addr - m->guest_base), 2);
        *out = le16(b);
    } else {
        memcpy(out, m->base + (addr - m->guest_base), 2);
    }
    return AOT_MEM_OK;
}
AotMemStatus aot_mem_ld32(const AotMem *m, uint64_t addr, uint32_t *out) {
    AotMemStatus s = aot_mem_check(m, addr, 4);
    if (s != AOT_MEM_OK) return s;
    if (!aot_mem_is_aligned(addr, 4)) {
        uint8_t b[4];
        memcpy(b, m->base + (addr - m->guest_base), 4);
        *out = le32(b);
    } else {
        memcpy(out, m->base + (addr - m->guest_base), 4);
    }
    return AOT_MEM_OK;
}
AotMemStatus aot_mem_ld64(const AotMem *m, uint64_t addr, uint64_t *out) {
    AotMemStatus s = aot_mem_check(m, addr, 8);
    if (s != AOT_MEM_OK) return s;
    if (!aot_mem_is_aligned(addr, 8)) {
        uint8_t b[8];
        memcpy(b, m->base + (addr - m->guest_base), 8);
        *out = le64(b);
    } else {
        memcpy(out, m->base + (addr - m->guest_base), 8);
    }
    return AOT_MEM_OK;
}
AotMemStatus aot_mem_ld128(const AotMem *m, uint64_t addr, uint64_t out[2]) {
    AotMemStatus s = aot_mem_check(m, addr, 16);
    if (s != AOT_MEM_OK) return s;
    uint8_t b[16];
    memcpy(b, m->base + (addr - m->guest_base), 16);
    out[0] = le64(b);
    out[1] = le64(b + 8);
    return AOT_MEM_OK;
}

AotMemStatus aot_mem_st8(AotMem *m, uint64_t addr, uint8_t v) {
    AotMemStatus s = aot_mem_check(m, addr, 1);
    if (s != AOT_MEM_OK) return s;
    memcpy(m->base + (addr - m->guest_base), &v, 1);
    return AOT_MEM_OK;
}
AotMemStatus aot_mem_st16(AotMem *m, uint64_t addr, uint16_t v) {
    AotMemStatus s = aot_mem_check(m, addr, 2);
    if (s != AOT_MEM_OK) return s;
    if (!aot_mem_is_aligned(addr, 2)) {
        uint8_t b[2];
        st16(b, v);
        memcpy(m->base + (addr - m->guest_base), b, 2);
    } else {
        memcpy(m->base + (addr - m->guest_base), &v, 2);
    }
    return AOT_MEM_OK;
}
AotMemStatus aot_mem_st32(AotMem *m, uint64_t addr, uint32_t v) {
    AotMemStatus s = aot_mem_check(m, addr, 4);
    if (s != AOT_MEM_OK) return s;
    if (!aot_mem_is_aligned(addr, 4)) {
        uint8_t b[4];
        st32(b, v);
        memcpy(m->base + (addr - m->guest_base), b, 4);
    } else {
        memcpy(m->base + (addr - m->guest_base), &v, 4);
    }
    return AOT_MEM_OK;
}
AotMemStatus aot_mem_st64(AotMem *m, uint64_t addr, uint64_t v) {
    AotMemStatus s = aot_mem_check(m, addr, 8);
    if (s != AOT_MEM_OK) return s;
    if (!aot_mem_is_aligned(addr, 8)) {
        uint8_t b[8];
        st64(b, v);
        memcpy(m->base + (addr - m->guest_base), b, 8);
    } else {
        memcpy(m->base + (addr - m->guest_base), &v, 8);
    }
    return AOT_MEM_OK;
}
AotMemStatus aot_mem_st128(AotMem *m, uint64_t addr, const uint64_t v[2]) {
    AotMemStatus s = aot_mem_check(m, addr, 16);
    if (s != AOT_MEM_OK) return s;
    uint8_t b[16];
    st64(b, v[0]);
    st64(b + 8, v[1]);
    memcpy(m->base + (addr - m->guest_base), b, 16);
    return AOT_MEM_OK;
}

AotMemStatus aot_mem_lds8(const AotMem *m, uint64_t addr, int64_t *out) {
    uint8_t v;
    AotMemStatus s = aot_mem_ld8(m, addr, &v);
    if (s != AOT_MEM_OK) return s;
    *out = (int64_t)(int8_t)v;
    return AOT_MEM_OK;
}
AotMemStatus aot_mem_lds16(const AotMem *m, uint64_t addr, int64_t *out) {
    uint16_t v;
    AotMemStatus s = aot_mem_ld16(m, addr, &v);
    if (s != AOT_MEM_OK) return s;
    *out = (int64_t)(int16_t)v;
    return AOT_MEM_OK;
}
AotMemStatus aot_mem_lds32(const AotMem *m, uint64_t addr, int64_t *out) {
    uint32_t v;
    AotMemStatus s = aot_mem_ld32(m, addr, &v);
    if (s != AOT_MEM_OK) return s;
    *out = (int64_t)(int32_t)v;
    return AOT_MEM_OK;
}

uint64_t aot_mem_fnv1a(const AotMem *m) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (uint64_t i = 0; i < m->size; i++) {
        h ^= (uint64_t)m->base[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}
