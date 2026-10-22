/* Tiny early-G4 RomFS Start adapter. See g4_romfs_start_hle.h. */

#include "g4_romfs_start_hle.h"

#include <string.h>

static void copy_text(char *dst, size_t cap, const char *src)
{
    if (cap == 0u) return;
    if (src == NULL) {
        dst[0] = '\0';
        return;
    }
    size_t n = strlen(src);
    if (n >= cap) n = cap - 1u;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static void hle_fault(AotRuntime *rt, const AotHleRequest *req,
                      int64_t status)
{
    if (rt == NULL) return;
    rt->fault = AOT_FAULT_BAD_HLE;
    rt->fault_src = req != NULL ? req->site_pc : 0u;
    rt->fault_target = req != NULL ? req->resume_pc : 0u;
    rt->fault_status = status;
}

void g4_romfs_start_hle_init(G4RomfsStartHle *ctx, RomfsProvider *provider,
                             const romfs_provider_config *config)
{
    if (ctx == NULL) return;
    memset(ctx, 0, sizeof(*ctx));
    ctx->provider = provider;
    ctx->config = config;
    ctx->last_provider_status = ROMFS_PROVIDER_ERR_NOT_READY;
}

void g4_romfs_start_hle_handler(AotRuntime *rt, AotGuestState *s,
                                const AotHleRequest *req, void *user)
{
    G4RomfsStartHle *ctx = (G4RomfsStartHle *)user;
    (void)s; /* success and every failure leave the guest state untouched */

    if (ctx == NULL) {
        hle_fault(rt, req, G4_ROMFS_START_HLE_FAULT_CONTEXT);
        return;
    }
    ctx->calls++;
    if (rt == NULL) {
        /* No runtime means there is nowhere to report a typed fault; the
         * caller is a host misconfiguration. Do not report success. */
        ctx->fail++;
        return;
    }
    if (req == NULL || req->kind != AOT_HLE_HOSTCALL) {
        ctx->fail++;
        hle_fault(rt, req, G4_ROMFS_START_HLE_FAULT_KIND);
        return;
    }
    if (s == NULL) {
        /* A valid HOSTCALL always carries guest state. Never publish success
         * over a caller-side ABI violation, and never initialize the provider
         * behind such a request. */
        ctx->fail++;
        hle_fault(rt, req, G4_ROMFS_START_HLE_FAULT_GUEST);
        return;
    }
    if (ctx->provider == NULL || ctx->config == NULL) {
        ctx->fail++;
        hle_fault(rt, req, G4_ROMFS_START_HLE_FAULT_CONFIG);
        return;
    }

    romfs_provider_diag diag;
    memset(&diag, 0, sizeof(diag));
    romfs_provider_status status;
#ifdef MN_G4_ROMFS_MUT_SKIP_INIT
    /* Test-only wrong implementation: never call the real provider init. */
    status = ROMFS_PROVIDER_OK;
    diag.status = ROMFS_PROVIDER_OK;
    diag.stage = "ready";
    diag.detail[0] = '\0';
#else
    /* The ONLY initialization point: a real HOSTCALL invocation. */
    status = romfs_provider_init(ctx->provider, ctx->config, &diag);
#endif
    ctx->last_provider_status = status;
    ctx->last_provider_ready = romfs_provider_is_ready(ctx->provider);
    ctx->last_file_count = romfs_provider_file_count(ctx->provider);
    copy_text(ctx->last_stage, sizeof(ctx->last_stage), diag.stage);
    copy_text(ctx->last_detail, sizeof(ctx->last_detail), diag.detail);

    if (status != ROMFS_PROVIDER_OK) {
        ctx->fail++;
        hle_fault(rt, req,
                  (int64_t)G4_ROMFS_START_HLE_FAULT_PROVIDER_BASE -
                      (int64_t)status);
        return;
    }
    /* A "successful" provider must actually be READY. The index contract
     * permits zero files (strings_offset == 24 with padding), so file_count is
     * deliberately NOT a readiness predicate; READY is the authority. */
    if (!ctx->last_provider_ready) {
        ctx->fail++;
        hle_fault(rt, req,
                  (int64_t)G4_ROMFS_START_HLE_FAULT_PROVIDER_BASE -
                      (int64_t)ROMFS_PROVIDER_ERR_NOT_READY);
        return;
    }
    ctx->success++;
#ifdef MN_G4_ROMFS_MUT_WRITE_X0
    /* Test-only wrong implementation: a void Mac body must not write x0. */
    s->x[0] ^= 1u;
#endif
}
