/*
 * Tiny early-G4 translated adapter for the immutable RomFS provider (D020).
 *
 * SCOPE: ONLY the Mac `_ZN2nn2fs24InitializeForApplicationEv` body
 * (`services.c:175 -> runtime_fs_init -> romfs.c:169-191`) as exercised by the
 * faithful nn::init::Start prefix. This is NOT a general filesystem, mount,
 * save, IPC or graphics adapter, and it is not a second G3 override table.
 *
 * The context BORROWS an owning RomfsProvider and an EXPLICIT
 * romfs_provider_config. The real romfs_provider_init() is called at HOSTCALL
 * invocation time (never before Start runs), and the provider stays READY
 * until the guest run ends; the caller destroys it afterwards.
 *
 * AOT_HLE_HOSTCALL only. The request id is an opaque thunk ordinal; no title
 * ordinal is hardcoded here. On success the handler is exactly Mac's void
 * body: NO guest register, flag or byte is written. READY is the readiness
 * authority; the index contract permits zero files, so file_count is not an
 * extra success predicate. On failure it sets the typed fatal AOT_FAULT_BAD_HLE with a documented negative status, the
 * request's site/resume PCs, and leaves the guest state untouched and the
 * provider EMPTY (provider init is transactional). It never fabricates a
 * guest Result, never writes a host pointer into guest state, and never calls
 * romfs_provider_read().
 */
#ifndef MN_G4_ROMFS_START_HLE_H
#define MN_G4_ROMFS_START_HLE_H

#include "aot_runtime.h"
#include "romfs_provider.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Negative host-side statuses. Provider statuses 1..25 from
 * romfs_provider_status map to G4_ROMFS_START_HLE_FAULT_PROVIDER_BASE -
 * status, i.e. -101..-125. These never collide with the G3 SVC override
 * statuses (-1..-15). */
#define G4_ROMFS_START_HLE_FAULT_CONTEXT (-96)
#define G4_ROMFS_START_HLE_FAULT_KIND (-97)
#define G4_ROMFS_START_HLE_FAULT_CONFIG (-98)
#define G4_ROMFS_START_HLE_FAULT_GUEST (-95)
#define G4_ROMFS_START_HLE_FAULT_PROVIDER_BASE (-100)

typedef struct G4RomfsStartHle {
    RomfsProvider *provider;              /* borrowed owner, may be NULL */
    const romfs_provider_config *config;  /* borrowed explicit config */
    uint64_t calls;
    uint64_t success;
    uint64_t fail;
    /* Last provider state, copied out for host diagnostics. */
    romfs_provider_status last_provider_status;
    int last_provider_ready;
    uint64_t last_file_count;
    char last_stage[64];
    char last_detail[192];
} G4RomfsStartHle;

/* Initialize a HOST-only context. Does not create or initialize a provider. */
void g4_romfs_start_hle_init(G4RomfsStartHle *ctx, RomfsProvider *provider,
                             const romfs_provider_config *config);

/* AotProgHandler for the fs InitializeForApplication thunk. `user` is a
 * G4RomfsStartHle*. */
void g4_romfs_start_hle_handler(AotRuntime *rt, AotGuestState *s,
                                const AotHleRequest *req, void *user);

#ifdef __cplusplus
}
#endif

#endif /* MN_G4_ROMFS_START_HLE_H */
