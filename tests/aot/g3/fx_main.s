/*
 * G3 fixture module "main" (guest base 0x10_0000_0000).
 *
 * Covers every relocation shape the loader must implement:
 *   1026 JUMP_SLOT : sdk_add, sub_entry (cross-module), host_hook (override
 *                    thunk), nnMain (observer thunk)
 *   1025 GLOB_DAT  : sdk_data, sdk_vtable, host_hook (thunk identity, same VA
 *                    as "sub" observes), fx_missing_sym (undefined weak -> 0)
 *   257  ABS64     : sdk_data+8 (non-zero addend, cross-module),
 *                    host_hook (thunk VA), nnMain (REAL sdk VA, not the
 *                    observer thunk), fx_missing_sym (weak -> 0)
 *   1027 RELATIVE  : main_vtable[] (hidden targets)
 * plus a DT_INIT (linked with --init=) that walks this module's init_array.
 */
    .section .crt0,"a",%progbits
    .balign 4
    .global _start
_start:
    b       main_entry
    .long   __mod0_off

    .section .mod0,"a",%progbits
    .balign 4
    .type   main_mod0,%object
main_mod0:
    .ascii  "MOD0"
    .long   __dynamic_rel
    .long   __bss_start_rel
    .long   __bss_end_rel
    .long   0
    .long   0
    .long   0

    .text
    .global main_entry
    .type   main_entry,%function
main_entry:
    /* AAPCS64 frame: x29/x30 plus the callee-saved register this body keeps
     * live across the PLT calls (x19 = sdk's data pointer). */
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    stp     x19, x20, [sp, #-16]!

    /* main -> sdk through the PLT. */
    movz    x0, #1
    movz    x1, #2
    bl      sdk_add                     /* JUMP_SLOT -> sdk_add  */

    /* Record sdk_add's result in sdk's data (GLOB_DAT of imported data). */
    adrp    x19, :got:sdk_data
    ldr     x19, [x19, :got_lo12:sdk_data]
    str     x0, [x19, #48]

    /* main -> sub through the PLT. */
    bl      sub_entry                   /* JUMP_SLOT -> sub_entry */

    /* Import overridden by a host thunk, reached as a direct call ... */
    bl      host_hook                   /* JUMP_SLOT -> override thunk */

    /* ... and observed import reached as a direct call. */
    bl      nnMain                      /* JUMP_SLOT -> observer thunk */

    /* Address of the override thunk (must equal sub's GLOB_DAT value). */
    adrp    x4, :got:host_hook
    ldr     x4, [x4, :got_lo12:host_hook]
    str     x4, [x19, #24]

    /* Address of nnMain must stay the REAL module VA (not the observer). */
    adrp    x5, :got:main_nnmain_slot
    ldr     x5, [x5, :got_lo12:main_nnmain_slot]
    ldr     x6, [x5]
    str     x6, [x19, #56]

    /* Undefined WEAK import must resolve to 0. */
    adrp    x7, :got:fx_missing_sym
    ldr     x7, [x7, :got_lo12:fx_missing_sym]
    str     x7, [x19, #16]

    /* ABS64 sdk_data+8: non-zero addend pointing into another module. */
    adrp    x8, :got:main_sdkdata_plus8
    ldr     x8, [x8, :got_lo12:main_sdkdata_plus8]
    ldr     x9, [x8]
    str     x9, [x19, #64]

    /* RELATIVE vtable entry 1: indirect call. */
    adrp    x10, :got:main_vtable
    ldr     x10, [x10, :got_lo12:main_vtable]
    ldr     x11, [x10, #8]
    blr     x11

    /* Duplicated symbol: defined by BOTH sub and sdk. The loader's global
     * search is in module order (main, sub, sdk), and main itself does not
     * define it, so this must resolve to sub's definition. */
    adrp    x12, :got:shared_impl
    ldr     x12, [x12, :got_lo12:shared_impl]
    str     x12, [x19, #72]             /* +72: module-order winner */

    ldp     x19, x20, [sp], #16
    ldp     x29, x30, [sp], #16
    ret

/* =====================================================================
 * G3 increment 3 scenario entry points: host-callable, closed-form results.
 * Every partial is ALSO stored in main_results[] so the probe can check the
 * individual relocation/call shape, not only the folded checksum.
 * ===================================================================== */

/* u64 main_scn_calls(void) */
    .global main_scn_calls
    .type   main_scn_calls,%function
main_scn_calls:
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    stp     x19, x20, [sp, #-16]!

    adrp    x19, :got:main_results
    ldr     x19, [x19, :got_lo12:main_results]

    /* [0] main -> sdk PLT call: 1 + 2 */
    movz    x0, #1
    movz    x1, #2
    bl      sdk_add
    str     x0, [x19]

    /* [1] main -> sub PLT call; sub itself calls sdk through its own PLT */
    bl      sub_entry
    str     x0, [x19, #8]

    /* [2] GLOB_DAT read of sdk's first data word */
    adrp    x2, :got:sdk_data
    ldr     x2, [x2, :got_lo12:sdk_data]
    ldr     x3, [x2]
    str     x3, [x19, #16]

    /* [3] ABS64 (sdk_data + 8) read through main's own data slot */
    adrp    x4, :got:main_sdkdata_plus8
    ldr     x4, [x4, :got_lo12:main_sdkdata_plus8]
    ldr     x5, [x4]                    /* the ABS64 value: sdk_data + 8     */
    ldr     x5, [x5]                    /* ... and the word it points at     */
    str     x5, [x19, #24]

    /* [4] RELATIVE vtable entry 1 -> main_vfn_b */
    adrp    x6, :got:main_vtable
    ldr     x6, [x6, :got_lo12:main_vtable]
    ldr     x7, [x6, #8]
    blr     x7
    str     x0, [x19, #32]

    /* [5] undefined WEAK import == 0 through a cbz path */
    adrp    x8, :got:fx_missing_sym
    ldr     x8, [x8, :got_lo12:fx_missing_sym]
    cbz     x8, 1f
    movz    x9, #0x20
    b       2f
1:
    movz    x9, #0x10
2:
    str     x9, [x19, #40]

    /* [6] duplicated symbol reached from main -> sub's definition */
    bl      shared_impl
    str     x0, [x19, #48]

    /* [7] duplicated symbol reached from sdk -> sdk's own definition */
    bl      sdk_shared_value
    str     x0, [x19, #56]

    /* checksum: the sum of the eight partials */
    ldr     x10, [x19]
    ldr     x11, [x19, #8]
    add     x10, x10, x11
    ldr     x11, [x19, #16]
    add     x10, x10, x11
    ldr     x11, [x19, #24]
    add     x10, x10, x11
    ldr     x11, [x19, #32]
    add     x10, x10, x11
    ldr     x11, [x19, #40]
    add     x10, x10, x11
    ldr     x11, [x19, #48]
    add     x10, x10, x11
    ldr     x11, [x19, #56]
    add     x0, x10, x11

    ldp     x19, x20, [sp], #16
    ldp     x29, x30, [sp], #16
    ret

/* u64 main_scn_identity(void): 1 when main's GOT value for host_hook equals
 * the value sub holds for the same import (both must be the thunk VA). */
    .global main_scn_identity
    .type   main_scn_identity,%function
main_scn_identity:
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    stp     x19, x20, [sp, #-16]!

    adrp    x19, :got:host_hook
    ldr     x19, [x19, :got_lo12:host_hook]
    bl      sub_get_host_hook_got
    cmp     x19, x0
    b.ne    1f
    movz    x0, #1
    b       2f
1:
    movz    x0, #0
2:
    ldp     x19, x20, [sp], #16
    ldp     x29, x30, [sp], #16
    ret

/* u64 main_scn_override(void): call the overridden import through main's PLT
 * stub with x0 = 5; the host handler computes x0*3+1, so this returns
 * (5*3+1) + 100 = 116. */
    .global main_scn_override
    .type   main_scn_override,%function
main_scn_override:
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    movz    x0, #5
    bl      host_hook                   /* PLT: adrp/ldr/add/br x17 */
    add     x0, x0, #100
    ldp     x29, x30, [sp], #16
    ret

/* =====================================================================
 * Scenario 4: OBSERVED import. main calls nnMain through its PLT stub; the
 * loader bound that JUMP_SLOT to the observer thunk, so the host handler runs
 * and calls the REAL nnMain by address through a nested host->guest call.
 * The handler returns real_x0 + 0x4000 (marker: the observer ran).
 * ===================================================================== */
/* u64 main_scn_observer(void) -> 0xB777 + 0x200 = 0xB977 */
    .global main_scn_observer
    .type   main_scn_observer,%function
main_scn_observer:
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    bl      nnMain                      /* JUMP_SLOT -> observer thunk */
    add     x0, x0, #0x200
    ldp     x29, x30, [sp], #16
    ret

/* =====================================================================
 * Scenario 5a: translated -> translated CROSS-MODULE callback. main passes
 * one of its own function VAs (taken from the RELATIVE vtable) to sdk's
 * sdk_apply, which BLRs it. 21 + 0xc1 + 5 = 0xdb.
 * ===================================================================== */
/* u64 main_scn_callback(void) -> 0xdb */
    .global main_scn_callback
    .type   main_scn_callback,%function
main_scn_callback:
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    adrp    x0, :got:main_vtable
    ldr     x0, [x0, :got_lo12:main_vtable]
    ldr     x0, [x0]                    /* fn = main_vfn_a (RELATIVE) */
    movz    x1, #21
    bl      sdk_apply                   /* sdk BLRs the guest callback */
    ldp     x29, x30, [sp], #16
    ret

/* =====================================================================
 * Scenario 5b: HLE -> guest. main calls the overridden import host_invoke
 * with (fn, arg); the handler makes a NESTED host->guest call to fn(arg) and
 * returns x0 + 1000. main also proves x19..x28 survive the round trip:
 * 7 + 0xc1 = 0xc8 = 200, +1000 = 1200, +1 = 1201 = 0x4b1.
 * ===================================================================== */
/* u64 main_scn_invoke(void) -> 0x4b1 when x19..x28 are intact, else 0xdead */
    .global main_scn_invoke
    .type   main_scn_invoke,%function
main_scn_invoke:
    stp     x29, x30, [sp, #-96]!
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x23, x24, [sp, #48]
    stp     x25, x26, [sp, #64]
    stp     x27, x28, [sp, #80]

    movz    x19, #19
    movz    x20, #20
    movz    x21, #21
    movz    x22, #22
    movz    x23, #23
    movz    x24, #24
    movz    x25, #25
    movz    x26, #26
    movz    x27, #27
    movz    x28, #28

    adrp    x0, :got:main_vtable
    ldr     x0, [x0, :got_lo12:main_vtable]
    ldr     x0, [x0]                    /* fn = main_vfn_a */
    movz    x1, #7
    bl      host_invoke                 /* JUMP_SLOT -> host thunk 2 */

    /* sum(x19..x28) must still be 19+...+28 = 235 */
    add     x2, x19, x20
    add     x2, x2, x21
    add     x2, x2, x22
    add     x2, x2, x23
    add     x2, x2, x24
    add     x2, x2, x25
    add     x2, x2, x26
    add     x2, x2, x27
    add     x2, x2, x28
    cmp     x2, #235
    b.ne    1f
    add     x0, x0, #1
    b       2f
1:
    movz    x0, #0xdead
2:
    ldp     x19, x20, [sp, #16]
    ldp     x21, x22, [sp, #32]
    ldp     x23, x24, [sp, #48]
    ldp     x25, x26, [sp, #64]
    ldp     x27, x28, [sp, #80]
    ldp     x29, x30, [sp], #96
    ret

/* u64 main_scn_orr(void) -> 0x2121: ORR (shifted register) with a NON-ZERO
 * shift amount (module-mode translator mutant control). */
    .global main_scn_orr
    .type   main_scn_orr,%function
main_scn_orr:
    movz    x1, #0x21
    orr     x0, x1, x1, lsl #8          /* 0x21 | (0x21 << 8) == 0x2121 */
    ret

/* SYSREG reads (review fix 1): the id carries Rt, ONE handler per register,
 * Rt == 31 discards the value but must still call the handler. */
    .global main_scn_cntpct_rt8
    .type   main_scn_cntpct_rt8,%function
main_scn_cntpct_rt8:
    mrs     x8, cntpct_el0
    mov     x0, x8
    ret

    .global main_scn_cntpct_zr
    .type   main_scn_cntpct_zr,%function
main_scn_cntpct_zr:
    movz    x0, #0x1234
    mrs     xzr, cntpct_el0             /* Rt=31: no register is written */
    ret

    .global main_scn_cntvct
    .type   main_scn_cntvct,%function
main_scn_cntvct:
    movz    x0, #0x4321
    mrs     xzr, cntvct_el0             /* handler runs, x0 untouched */
    mrs     x9, cntvct_el0              /* Rt=9 through its own handler */
    mrs     x10, cntvct_el0
    add     x0, x9, x10
    ret

    .global main_scn_tpidr
    .type   main_scn_tpidr,%function
main_scn_tpidr:
    mrs     x8, tpidr_el0               /* inline from the guest state */
    mrs     x9, tpidrro_el0
    add     x0, x8, x9
    ret

/* =====================================================================
 * Scenario 7: INVALID transfer targets. Each entry performs exactly ONE
 * transfer; emit-desc derives that instruction's guest VA so the probe can
 * require fault_src == the transfer instruction (never hand-coded).
 * ===================================================================== */

/* u64 main_scn_bad_blr_data(u64 target): BLR to a module DATA address
 * (the host passes sdk_data's VA). Expect UNKNOWN_PC. */
    .global main_scn_bad_blr_data
    .type   main_scn_bad_blr_data,%function
main_scn_bad_blr_data:
    blr     x0

/* u64 main_scn_bad_blr_mid(void): BLR to an address INSIDE main_gap_body that
 * no branch ever targets, i.e. not a block entry. Expect UNTRANSLATED. The
 * target is published in main_results[0] so the expected value comes from the
 * module itself. */
    .global main_scn_bad_blr_mid
    .type   main_scn_bad_blr_mid,%function
main_scn_bad_blr_mid:
    adrp    x9, :got:main_gap_body
    ldr     x9, [x9, :got_lo12:main_gap_body]
    add     x9, x9, #8                  /* mid-block instruction */
    adrp    x10, :got:main_results
    ldr     x10, [x10, :got_lo12:main_results]
    str     x9, [x10]                   /* publish the target */
    blr     x9

/* u64 main_scn_bad_blr_align(void): BLR to a misaligned text address.
 * Expect MISALIGNED. Target published in main_results[8]. */
    .global main_scn_bad_blr_align
    .type   main_scn_bad_blr_align,%function
main_scn_bad_blr_align:
    adrp    x10, :got:main_entry
    ldr     x10, [x10, :got_lo12:main_entry]
    add     x9, x10, #2                 /* not 4-byte aligned */
    adrp    x11, :got:main_results
    ldr     x11, [x11, :got_lo12:main_results]
    str     x9, [x11, #8]               /* publish the target */
    blr     x9

/* u64 main_scn_bad_ret_thunk(u64 target): RET into a host thunk VA.
 * Expect BAD_TRANSFER. */
    .global main_scn_bad_ret_thunk
    .type   main_scn_bad_ret_thunk,%function
main_scn_bad_ret_thunk:
    mov     x30, x0
    ret

/* u64 main_scn_bad_br_sentinel(u64 target): BR into the sentinel region.
 * Expect BAD_RETURN. */
    .global main_scn_bad_br_sentinel
    .type   main_scn_bad_br_sentinel,%function
main_scn_bad_br_sentinel:
    br      x0

/* main_gap_body: exported, so +0 is a translated Program entry while +8 is a
 * plain mid-block instruction -- exactly the UNTRANSLATED target above. */
    .global main_gap_body
    .type   main_gap_body,%function
main_gap_body:
    movz    x0, #0x11
    movz    x0, #0x22
    movz    x0, #0x33
    ret

/* =====================================================================
 * Scenario 8: memory permissions (rodata R, text R-X).
 * ===================================================================== */

/* u64 main_scn_store_ro(void): store to main's OWN rodata -> PERM. */
    .global main_scn_store_ro
    .type   main_scn_store_ro,%function
main_scn_store_ro:
    adrp    x9, :got:main_ro_word
    ldr     x9, [x9, :got_lo12:main_ro_word]
    movz    x1, #0x55
    str     x1, [x9]
    ret

/* u64 main_scn_store_text(void): store to main's OWN text -> PERM. */
    .global main_scn_store_text
    .type   main_scn_store_text,%function
main_scn_store_text:
    adrp    x9, :got:main_entry
    ldr     x9, [x9, :got_lo12:main_entry]
    movz    x1, #0x55
    str     x1, [x9]
    ret

/* u64 main_scn_mod0_magic(void) -> 0x30444f4d ("MOD0"): text is READABLE as
 * data, including the MOD0 header the crt0/data-word region of .text keeps. */
    .global main_scn_mod0_magic
    .type   main_scn_mod0_magic,%function
main_scn_mod0_magic:
    adrp    x0, main_mod0
    add     x0, x0, :lo12:main_mod0
    ldr     w0, [x0]
    ret

/* =====================================================================
 * Scenario 9: SYSREG through the PLT (main -> sdk_tick -> mrs cntpct_el0).
 * ===================================================================== */
    .global main_scn_tick
    .type   main_scn_tick,%function
main_scn_tick:
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    bl      sdk_tick
    ldp     x29, x30, [sp], #16
    ret

    .hidden main_vfn_a
    .hidden main_vfn_b
    .type   main_vfn_a,%function
main_vfn_a:
    add     x0, x0, #0xc1               /* depends on its argument */
    ret
    .type   main_vfn_b,%function
main_vfn_b:
    movz    x0, #0xd2
    ret

    .section .rodata,"a",%progbits
    .balign 8
    .global main_ro_word
    .type   main_ro_word,%object
main_ro_word:
    .word   0x11223344

    .data
    .balign 8
    .global main_results
    .type   main_results,%object
main_results:
    .space  0x40                        /* 8 partials, written by scenarios */

    .data
    .balign 8
    .global main_pair_scratch
    .type   main_pair_scratch,%object
main_pair_scratch:
    .space  0x20                        /* Major 1: in-page pair round trip */

    .data
    .balign 8
    .global main_vtable
    .type   main_vtable,%object
main_vtable:
    .xword  main_vfn_a                  /* R_AARCH64_RELATIVE */
    .xword  main_vfn_b                  /* R_AARCH64_RELATIVE */

    .data
    .balign 8
    .global main_sdkdata_plus8
    .type   main_sdkdata_plus8,%object
main_sdkdata_plus8:
    .xword  sdk_data + 8                /* ABS64, addend 8, other module */

    /* Undefined WEAK import: the loader must accept both the GLOB_DAT and the
     * ABS64 site above/below with value 0 (never a link error). */
    .weak   fx_missing_sym
    .global main_weak_slot
    .type   main_weak_slot,%object
main_weak_slot:
    .xword  fx_missing_sym              /* ABS64, undefined weak -> 0   */

    .global main_hosthook_slot
    .type   main_hosthook_slot,%object
main_hosthook_slot:
    .xword  host_hook                   /* ABS64 -> override thunk VA   */

    .global main_nnmain_slot
    .type   main_nnmain_slot,%object
main_nnmain_slot:
    .xword  nnMain                      /* ABS64 -> REAL sdk VA         */

    /* Review fix 5: S+A must hold for a host thunk target and for the 0 of an
     * unresolved weak import, exactly as for a module symbol. */
    .global main_hosthook_plus8
    .type   main_hosthook_plus8,%object
main_hosthook_plus8:
    .xword  host_hook + 8               /* ABS64 -> thunk VA + 8        */

    .global main_weak_plus8
    .type   main_weak_plus8,%object
main_weak_plus8:
    .xword  fx_missing_sym + 8          /* ABS64, undefined weak -> 0+8 */

    /* Review fix 4: `value == image_size` is a VALID definition. Real TotK
     * modules define the linker symbol `end` exactly there, so an ABS64 site
     * naming it must resolve to base + image_size. */
    .global main_sdk_end_slot
    .type   main_sdk_end_slot,%object
main_sdk_end_slot:
    .xword  fx_sdk_end                  /* ABS64 -> sdk base + image_size */

    .global main_ctor_state
main_ctor_state:
    .word   0
    .balign 8
    .global main_init_count
main_init_count:
    .word   0

    .section .bss,"aw",%nobits
    .balign 8
    .global main_bss
    .type   main_bss,%object
main_bss:
    .space  0x20
    .text
    .hidden main_ctor0
    .hidden main_ctor1
    .type   main_ctor0,%function
main_ctor0:
    /* Scenario 6: append this module's marker to sdk's ordered log (PLT call
     * into another module), then bump this module's own init count. */
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    movz    x0, #0
    bl      sdk_log
    adrp    x0, :got:main_init_count
    ldr     x0, [x0, :got_lo12:main_init_count]
    ldr     w1, [x0]
    add     w1, w1, #1
    str     w1, [x0]
    ldp     x29, x30, [sp], #16
    ret
    .type   main_ctor1,%function
main_ctor1:
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    movz    x0, #1
    bl      sdk_log
    adrp    x0, :got:main_init_count
    ldr     x0, [x0, :got_lo12:main_init_count]
    ldr     w1, [x0]
    add     w1, w1, #0x20
    str     w1, [x0]
    ldp     x29, x30, [sp], #16
    ret

    /* DT_INIT: only the loader's exposed DT_INIT VA is ever called, and this
     * body walks the module's own DT_INIT_ARRAY (the loader must NOT). */
    .global main_init
    .type   main_init,%function
main_init:
    /* AAPCS64 frame: this body CALLS its init_array entries, so x30 and the
     * walk cursor/end must live in callee-saved registers across the calls. */
    stp     x29, x30, [sp, #-32]!
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    adrp    x19, __init_array_start
    add     x19, x19, :lo12:__init_array_start
    adrp    x20, __init_array_end
    add     x20, x20, :lo12:__init_array_end
1:
    cmp     x19, x20
    b.hs    2f
    ldr     x9, [x19]
    blr     x9
    add     x19, x19, #8
    b       1b
2:
    adrp    x9, :got:main_ctor_state
    ldr     x9, [x9, :got_lo12:main_ctor_state]
    movz    w10, #2
    str     w10, [x9]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #32
    ret

/* =====================================================================
 * Major 1 (module-mode pair lowering): a POSITIVE in-page STP/LDP round trip
 * in both the X and W forms. The results are folded into one return value so
 * the Unicorn oracle compares them field by field. Everything stays inside
 * this module's own scratch (one 32-byte .data object, one page).
 *
 *    stp x1, x2, [x3]      -> 0xdef09abc56781234, 0x2222
 *    stp w4, w9, [x3, #16] -> 0x0000333300002222 (Rt at the lower address;
 *                             Rt != Rt2 is required by the decoder subset)
 *    ldp x5, x6, [x3]      -> same two values
 *    ldp w7, w8, [x3, #16] -> 0x2222, 0x3333 (W loads zero-extend)
 *    x0 = (x5 ^ x6) + x7 + x8
 * ===================================================================== */
    .global main_scn_pair
    .type   main_scn_pair,%function
main_scn_pair:
    adrp    x3, :got:main_pair_scratch
    ldr     x3, [x3, :got_lo12:main_pair_scratch]
    movz    x1, #0x1234
    movk    x1, #0x5678, lsl #16
    movk    x1, #0x9abc, lsl #32
    movk    x1, #0xdef0, lsl #48
    movz    x2, #0x2222
    movz    w4, #0x2222
    movz    w9, #0x3333
    stp     x1, x2, [x3]
    stp     w4, w9, [x3, #16]
    ldp     x5, x6, [x3]
    ldp     w7, w8, [x3, #16]
    eor     x0, x5, x6
    add     x0, x0, x7
    add     x0, x0, x8
    ret

/* u64 main_scn_pair_straddle(u8 *addr): stores a 64-bit pair whose FIRST half
 * is the last 8 bytes of a RW page and whose SECOND half is in the following
 * page. With the single-access lowering the whole 16-byte range is checked
 * first, so the instruction faults and writes NOTHING; with the old
 * two-store lowering the first half lands. Leaf body: it must not touch the
 * guest stack (the caller protects the page above it). */
    .global main_scn_pair_straddle
    .type   main_scn_pair_straddle,%function
main_scn_pair_straddle:
    movz    x1, #0xaaaa
    movk    x1, #0xbbbb, lsl #16
    movz    x2, #0xcccc
    movk    x2, #0xdddd, lsl #16
    stp     x1, x2, [x0]
    movz    x0, #0
    ret

    .section .init_array,"aw",%init_array
    .balign 8
    .xword  main_ctor0
    .xword  main_ctor1
