/*
 * G3 fixture module "sub" (guest base 0x10_0100_0000).
 *
 * Imports: sdk_add (PLT/JUMP_SLOT, cross-module), sdk_data (GLOB_DAT),
 * host_hook (GLOB_DAT; overridden by a host thunk - the SAME thunk VA that
 * "main" observes), and it DEFINES its own shared_impl so that an intra-module
 * reference resolves to its own definition before any global search (also
 * defined by "sdk", so this pins own-first / module-order resolution).
 */
    .section .crt0,"a",%progbits
    .balign 4
    .global _start
_start:
    b       sub_entry
    .long   __mod0_off

    .section .mod0,"a",%progbits
    .balign 4
    .ascii  "MOD0"
    .long   __dynamic_rel
    .long   __bss_start_rel
    .long   __bss_end_rel
    .long   0
    .long   0
    .long   0

    .text
    .global sub_entry
    .type   sub_entry,%function
sub_entry:
    /* AAPCS64 frame: this body calls through the PLT, so x30 must survive. */
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    stp     x19, x20, [sp, #-16]!
    /* main -> sub -> sdk: PLT call across two module boundaries. */
    movz    x0, #5
    movz    x1, #6
    bl      sdk_add                 /* JUMP_SLOT -> sdk.sdk_add */
    mov     x19, x0                 /* sub_entry returns THIS value */

    /* Own definition of shared_impl must win over sdk's (own-first rule). */
    adrp    x1, :got:shared_impl
    ldr     x1, [x1, :got_lo12:shared_impl]
    blr     x1

    /* Address of the thunk-overridden import (GLOB_DAT, thunk VA). */
    adrp    x2, :got:host_hook
    ldr     x2, [x2, :got_lo12:host_hook]

    /* Publish both values through sdk's data (cross-module GLOB_DAT write). */
    adrp    x3, :got:sdk_data
    ldr     x3, [x3, :got_lo12:sdk_data]
    str     x1, [x3, #32]           /* sub.shared_impl (own) */
    str     x2, [x3, #40]           /* host_hook thunk VA    */
    mov     x0, x19
    ldp     x19, x20, [sp], #16
    ldp     x29, x30, [sp], #16
    ret

/* u64 sub_get_host_hook_got(void): the value sub's GOT holds for host_hook.
 * main compares it with its own GOT value (thunk identity, scenario 2). */
    .global sub_get_host_hook_got
    .type   sub_get_host_hook_got,%function
sub_get_host_hook_got:
    adrp    x0, :got:host_hook
    ldr     x0, [x0, :got_lo12:host_hook]
    ret

    .global shared_impl
    .type   shared_impl,%function
shared_impl:
    movz    x0, #0x1111
    ret

    .text
    .hidden sub_ctor0
    .type   sub_ctor0,%function
sub_ctor0:
    /* Scenario 6: marker into sdk's ordered log via the PLT, then the count. */
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    movz    x0, #2
    bl      sdk_log
    adrp    x0, :got:sub_init_count
    ldr     x0, [x0, :got_lo12:sub_init_count]
    ldr     w1, [x0]
    add     w1, w1, #3
    str     w1, [x0]
    ldp     x29, x30, [sp], #16
    ret

    .global sub_init
    .type   sub_init,%function
sub_init:
    /* AAPCS64 frame: the init_array cursor/end stay in callee-saved x19/x20
     * across the calls to the entries. */
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
    adrp    x9, :got:sub_ctor_state
    ldr     x9, [x9, :got_lo12:sub_ctor_state]
    movz    w10, #2
    str     w10, [x9]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #32
    ret

    .data
    .balign 8
    .global sub_ctor_state
sub_ctor_state:
    .word   0
    .balign 8
    .global sub_init_count
sub_init_count:
    .word   0

    .section .bss,"aw",%nobits
    .balign 8
    .global sub_bss
    .type   sub_bss,%object
sub_bss:
    .space  0x20

    .section .init_array,"aw",%init_array
    .balign 8
    .xword  sub_ctor0
