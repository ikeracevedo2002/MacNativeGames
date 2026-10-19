/*
 * G2 stage-1 native runner for the controlled ARM64 fixture.
 *
 * Uses the existing aot_runtime/aot_mem directly (no modifications) to prove
 * the first end-to-end offline-translated integer + flags + branch-loop
 * execution on Windows x64 through generated native C.
 *
 * Exit status only: 0 = the expected scalar result and HLE event were
 * observed, nonzero = a specific mismatch (printed).
 */
#include "aot_runtime.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern const AotImage aot_image_fixture;

#define ARENA_SIZE 4096u
#define GUEST_BASE 0x0000000000100000ull

static int g_svc_seen;
static uint32_t g_svc_id;
static uint64_t g_svc_site;
static uint64_t g_svc_resume;

static void svc_handler(AotGuestState *s, const AotHleRequest *req, void *user) {
    (void)s;
    (void)user;
    g_svc_seen += 1;
    g_svc_id = req->id;
    g_svc_site = req->site_pc;
    g_svc_resume = req->resume_pc;
}

static int fail(const char *what, uint64_t got, uint64_t want) {
    if (got == want) return 0;
    printf("FAIL: %s: got 0x%llx want 0x%llx\n", what,
           (unsigned long long)got, (unsigned long long)want);
    return 1;
}

int main(void) {
    uint8_t *arena = (uint8_t *)malloc(ARENA_SIZE);
    if (arena == NULL) {
        printf("FAIL: arena allocation\n");
        return 1;
    }
    memset(arena, 0, ARENA_SIZE);

    AotMem mem;
    if (aot_mem_init(&mem, arena, ARENA_SIZE, GUEST_BASE) != AOT_MEM_OK) {
        printf("FAIL: aot_mem_init\n");
        free(arena);
        return 1;
    }

    AotGuestState state;
    memset(&state, 0, sizeof(state));
    state.sp = GUEST_BASE + ARENA_SIZE;
    state.x[10] = 0x2000ull;       /* manifest-declared indirect target */
    state.nzcv = AOT_NZCV_PACK(0, 1, 0, 0);

    AotRuntime rt;
    uint32_t rc = aot_rt_init(&rt, &aot_image_fixture, mem, &state, 100000u);
    if (rc != AOT_FAULT_NONE) {
        printf("FAIL: aot_rt_init rc=%u\n", rc);
        free(arena);
        return 1;
    }
    if (aot_rt_set_handler(&rt, AOT_HLE_SVC, 0x40u, svc_handler, NULL) != 0) {
        printf("FAIL: aot_rt_set_handler\n");
        free(arena);
        return 1;
    }

    AotExit e = aot_rt_run(&rt, 0x1000ull, 0ull);
    int bad = 0;
    if (e != AOT_EXIT_STOP) {
        printf("FAIL: exit reason %d fault %u fault_src 0x%llx fault_target 0x%llx\n",
               (int)e, rt.fault, (unsigned long long)rt.fault_src,
               (unsigned long long)rt.fault_target);
        bad = 1;
    }
    if (bad == 0) {
        bad |= fail("x0", state.x[0], 61u);
        bad |= fail("x3", state.x[3], 2u);
        bad |= fail("x5", state.x[5], 0xabcd1234u);
        bad |= fail("x6", state.x[6], 0u);
        bad |= fail("x7", state.x[7], 7u);
        bad |= fail("x9", state.x[9], 15u);
        bad |= fail("x11", state.x[11], 14u);
        bad |= fail("x12", state.x[12], 22u);
        bad |= fail("nzcv masked", state.nzcv & ~0xF0000000ull, 0u);
        if (g_svc_seen != 1) bad |= fail("svc seen", (uint64_t)g_svc_seen, 1u);
        bad |= fail("svc id", g_svc_id, 0x40u);
        bad |= fail("svc site", g_svc_site, 0x1060u);
        bad |= fail("svc resume", g_svc_resume, 0x1064u);
        bad |= fail("rt steps nonzero", (rt.steps != 0u) ? 1u : 0u, 1u);
    }

    if (bad == 0) {
        printf("PASS: fixture x0=%llu x3=%llu x5=0x%llx svc=%llu\n",
               (unsigned long long)state.x[0], (unsigned long long)state.x[3],
               (unsigned long long)state.x[5], (unsigned long long)g_svc_id);
    }
    free(arena);
    return bad ? 1 : 0;
}
