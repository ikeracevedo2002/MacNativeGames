/*
 * G3 increment 2 (T4): the shape of the generated negative-fixture table.
 *
 * tools/aot/aot_module.py craft-negative emits one entry per case into
 * g_aot_g3_neg_cases[]: a mutated flat image directory, the descriptors for
 * those mutated images (with their own matching SHA-256, so exact-version
 * verification PASSES), the AOT-time host bindings, and the typed loader
 * status the C loader must return for that case.
 */
#ifndef MN_AOT_G3_NEG_CASES_H
#define MN_AOT_G3_NEG_CASES_H

#include "aot_loader.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct AotNegCase {
    const char *name;
    const char *dir;                  /* mutated flats for this case */
    const AotModuleDesc *modules;
    uint32_t count;
    const AotHostBindings *bindings;
    int expected_status;              /* AotLoadStatus, from aot_loader.h */
    uint32_t expected_module;         /* module index, or AOT_LOADER_NO_MODULE */
    /* Review fix 11: the SPECIFIC AotLoadError.detail the loader must report,
     * so a case that fails for the wrong reason fails the test. */
    const char *expected_detail;
} AotNegCase;

extern const AotNegCase g_aot_g3_neg_cases[];
extern const uint32_t g_aot_g3_neg_case_count;

#ifdef __cplusplus
}
#endif

#endif /* MN_AOT_G3_NEG_CASES_H */
