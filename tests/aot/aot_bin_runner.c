/*
 * G2 stage-2 data-free native runner: reads a binary input (guest state +
 * arena), runs the AOT image, writes a binary output (final state + HLE
 * events + block-entry trace). No Python/Unicorn/ARM bytes at execution.
 *
 * Binary formats (little-endian; host is x86-64 LE):
 *   input : magic 'AOTI', u32 ver, u64 entry_pc, stop_pc, step_budget,
 *           guest_base, arena_size, u32 trace_enabled, u32 hle_count,
 *           hle_count * (u32 kind, u32 id), AotGuestState, arena bytes
 *   output: magic 'AOTO', u32 ver, u32 exit_reason, u32 fault, u64 fault_src,
 *           fault_target, i64 fault_status, u64 steps, AotGuestState,
 *           u32 event_count, events(4*u64...), u32 trace_count, u64 trace[],
 *           u32 events_overflow, u32 trace_overflow
 */
#include "aot_runtime.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern const AotImage aot_image_diff;

#define IN_MAGIC  0x414F5449u   /* "AOTI" */
#define OUT_MAGIC 0x414F544Fu   /* "AOTO" */
#define FORMAT_VERSION 1u
#define MAX_HANDLERS 32u

static int rd(FILE *f, void *p, size_t n) { return fread(p, 1, n, f) == n; }
static int wr(FILE *f, const void *p, size_t n) { return fwrite(p, 1, n, f) == n; }

/*
 * Deterministic stage-3 HLE mutation contract (mirrored independently by the
 * Python/Unicorn oracle in tools/aot/diff_driver.py; no shared helper).
 * Applied on every SVC / host-thunk HLE entry, then the runtime resumes at
 * req->resume_pc and IGNORES any handler attempt to redirect `s->pc`.
 *
 *   x0  = x0 ^ x1              v8  = v8 ^ v31 (128-bit)
 *   x1  = x1 + 0x11            v31 = v31 + 1   (128-bit)
 *   x18 = x18 ^ 0xA5A5...A5    sp  = sp + 16
 *   x19 = x19 + 1              nzcv = 0xA0000000 (N=1,C=1,Z=0,V=0)
 *   x20 = x20 - 2              fpcr ^= 0x00c00000  (RMode bits)
 *   tpidr = tpidr ^ 0x123456789ABCDEF0   fpsr ^= 0x00000002  (sticky bit)
 *
 * The handler writes `s->pc = 0xDEADull` on purpose; the runtime must discard
 * it and continue at the fixed resume PC.
 */
static void hle_mutate(AotGuestState *s, const AotHleRequest *req, void *user) {
    (void)req; (void)user;
    s->x[0] = s->x[0] ^ s->x[1];
    s->x[1] = s->x[1] + 0x11ull;
    s->x[18] = s->x[18] ^ 0xA5A5A5A5A5A5A5A5ull;
    s->x[19] = s->x[19] + 1ull;
    s->x[20] = s->x[20] - 2ull;
    s->v[8][0] = s->v[8][0] ^ s->v[31][0];
    s->v[8][1] = s->v[8][1] ^ s->v[31][1];
    s->v[31][0] = s->v[31][0] + 1ull;
    if (s->v[31][0] == 0ull) s->v[31][1] = s->v[31][1] + 1ull;   /* 128-bit +1 */
    s->sp = s->sp + 16ull;
    s->nzcv = 0xA0000000ull;
    s->fpcr = s->fpcr ^ 0x00c00000ull;   /* guest-visible RMode write */
    s->fpsr = s->fpsr ^ 0x00000002ull;   /* guest-visible sticky write */
    s->tpidr = s->tpidr ^ 0x123456789ABCDEF0ull;
#ifdef MN_MUTANT_HLE_X18
    s->x[18] = s->x[18] ^ 0x5A5A5A5A5A5A5A5Aull;   /* test-only mutant */
#endif
    s->pc = 0xDEADull;   /* must be ignored by the runtime */
}

static int run_binary(const char *in_path, const char *out_path) {
    FILE *fi = fopen(in_path, "rb");
    if (fi == NULL) { printf("FAIL: open input %s\n", in_path); return 2; }
    uint32_t magic = 0, ver = 0, trace_enabled = 0, hle_count = 0;
    uint64_t entry = 0, stop = 0, budget = 0, guest_base = 0, arena_size = 0;
    AotGuestState state;
    uint8_t *arena = NULL;
    AotRuntime rt;
    memset(&rt, 0, sizeof(rt));
    memset(&state, 0, sizeof(state));

    if (!rd(fi, &magic, 4) || magic != IN_MAGIC) goto bad_input;
    if (!rd(fi, &ver, 4) || ver != FORMAT_VERSION) goto bad_input;
    if (!rd(fi, &entry, 8) || !rd(fi, &stop, 8) || !rd(fi, &budget, 8) ||
        !rd(fi, &guest_base, 8) || !rd(fi, &arena_size, 8)) goto bad_input;
    if (!rd(fi, &trace_enabled, 4) || !rd(fi, &hle_count, 4)) goto bad_input;
    if (hle_count > MAX_HANDLERS) goto bad_input;
    uint32_t hk[MAX_HANDLERS], hid[MAX_HANDLERS];
    for (uint32_t i = 0; i < hle_count; i++) {
        if (!rd(fi, &hk[i], 4) || !rd(fi, &hid[i], 4)) goto bad_input;
    }
    if (!rd(fi, &state, sizeof(state))) goto bad_input;
    arena = (uint8_t *)malloc((size_t)arena_size);
    if (arena == NULL || !rd(fi, arena, (size_t)arena_size)) {
        free(arena);
        goto bad_input;
    }
    fclose(fi);

    AotMem mem;
    if (aot_mem_init(&mem, arena, arena_size, guest_base) != AOT_MEM_OK) {
        printf("FAIL: aot_mem_init\n"); free(arena); return 2;
    }
    if (aot_rt_init(&rt, &aot_image_diff, mem, &state, budget) != AOT_FAULT_NONE) {
        printf("FAIL: aot_rt_init\n"); free(arena); return 2;
    }
    for (uint32_t i = 0; i < hle_count; i++) {
        if (aot_rt_set_handler(&rt, hk[i], hid[i], hle_mutate, NULL) != 0) {
            printf("FAIL: set_handler\n"); free(arena); return 2;
        }
    }
    rt.trace_enabled = trace_enabled ? 1 : 0;
    AotExit e = aot_rt_run(&rt, entry, stop);

    FILE *fo = fopen(out_path, "wb");
    if (fo == NULL) { printf("FAIL: open output %s\n", out_path); free(arena); return 2; }
    uint32_t out_magic = OUT_MAGIC, out_ver = FORMAT_VERSION;
    uint32_t o_exit = (uint32_t)e, o_trace_n = 0, o_ev_n = 0;
    uint32_t eof1 = rt.events_overflow, eof2 = rt.trace_overflow;
    int ok = 1;
    ok &= wr(fo, &out_magic, 4) && wr(fo, &out_ver, 4);
    ok &= wr(fo, &o_exit, 4) && wr(fo, &rt.fault, 4);
    ok &= wr(fo, &rt.fault_src, 8) && wr(fo, &rt.fault_target, 8);
    ok &= wr(fo, &rt.fault_status, 8) && wr(fo, &rt.steps, 8);
    ok &= wr(fo, &state, sizeof(state));
    o_ev_n = (uint32_t)rt.event_count;
    ok &= wr(fo, &o_ev_n, 4);
    for (size_t i = 0; i < rt.event_count; i++) {
        ok &= wr(fo, &rt.events[i].kind, 4) && wr(fo, &rt.events[i].id, 4);
        ok &= wr(fo, &rt.events[i].site_pc, 8) && wr(fo, &rt.events[i].resume_pc, 8);
    }
    o_trace_n = (uint32_t)rt.trace_count;
    ok &= wr(fo, &o_trace_n, 4);
    for (size_t i = 0; i < rt.trace_count; i++) ok &= wr(fo, &rt.trace[i], 8);
    ok &= wr(fo, &eof1, 4) && wr(fo, &eof2, 4);
    ok &= wr(fo, &arena_size, 8) && wr(fo, arena, (size_t)arena_size);
    fclose(fo);
    free(arena);
    if (!ok) { printf("FAIL: write output\n"); return 2; }
    return 0;

bad_input:
    printf("FAIL: bad input format\n");
    return 2;
}

int main(int argc, char **argv) {
    if (argc == 3) return run_binary(argv[1], argv[2]);
    printf("usage: %s <input.bin> <output.bin>\n", argv[0]);
    return 2;
}
