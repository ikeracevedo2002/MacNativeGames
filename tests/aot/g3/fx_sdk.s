/*
 * G3 fixture module "sdk" (guest base 0x10_0200_0000).
 *
 * Provides: sdk_add (text), sdk_data (RW data), nnMain (JUMP_SLOT observer
 * target, must still be reached by ADDRESS as the real module VA),
 * shared_impl (also defined in "sub": pins own-first/module-order
 * resolution), a RELATIVE vtable, and a DT_INIT function that walks this
 * module's OWN .init_array.
 *
 * Instruction subset deliberately small: adrp/add/ldr/str offset forms,
 * stp/ldp, bl/blr/br/ret/b/cbz/movz/movk/svc.
 */
    .section .crt0,"a",%progbits
    .balign 4
    .global _start
_start:
    b       sdk_entry
    .long   __mod0_off

    .section .mod0,"a",%progbits
    .balign 4
    .ascii  "MOD0"
    .long   __dynamic_rel         /* dynamic_off    (relative to MOD0)   */
    .long   __bss_start_rel       /* bss_start_off  (relative to MOD0)   */
    .long   __bss_end_rel         /* bss_end_off    (relative to MOD0)   */
    .long   0                     /* eh_frame_hdr_start                  */
    .long   0                     /* eh_frame_hdr_end                    */
    .long   0                     /* module_object_off                   */

    .text

/* sdk_entry: exercises this module's own imports (none) and returns a marker. */
    .global sdk_entry
    .type   sdk_entry,%function
sdk_entry:
    movz    x0, #0x1000
    ret

/* u64 sdk_add(u64 a, u64 b) */
    .global sdk_add
    .type   sdk_add,%function
sdk_add:
    add     x0, x0, x1
    ret

/* u64 sdk_shared_value(void): sdk calling shared_impl, which resolves to
 * sdk's OWN definition (own-first), a value distinct from sub's. */
    .global sdk_shared_value
    .type   sdk_shared_value,%function
sdk_shared_value:
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    bl      shared_impl
    ldp     x29, x30, [sp], #16
    ret

/* sdk's definition of the duplicated symbol. */
    .global shared_impl
    .type   shared_impl,%function
shared_impl:
    movz    x0, #0x2222
    ret

/* sdk's OWN reference to shared_impl, which "sub" also defines. The loader
 * must resolve this own-first (sdk), so a global module-order search (which
 * would find sub first) is observable here: it yields a different VA. */
    .global sdk_shared_self
    .type   sdk_shared_self,%function
sdk_shared_self:
    adrp    x0, :got:shared_impl
    ldr     x0, [x0, :got_lo12:shared_impl]
    adrp    x1, :got:sdk_data
    ldr     x1, [x1, :got_lo12:sdk_data]
    str     x0, [x1, #80]
    ret

/* nnMain-like entry: the loader's JUMP_SLOT observer replaces CALLS to it,
 * but address-taken references must keep this real module VA. The side effect
 * proves the REAL body ran (the observer handler invokes it by address). */
    .global nnMain
    .type   nnMain,%function
nnMain:
    adrp    x9, :got:sdk_data
    ldr     x9, [x9, :got_lo12:sdk_data]
    movz    x10, #1
    str     x10, [x9, #88]              /* +88: "real nnMain ran" marker */
    movz    x0, #0x7777
    ret

/* u64 sdk_apply(u64 fn, u64 x): call a GUEST callback supplied by another
 * module through its own PLT, then post-process the result. */
    .global sdk_apply
    .type   sdk_apply,%function
sdk_apply:
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    add     x9, x0, #0                  /* fn   */
    add     x0, x1, #0                  /* arg  */
    blr     x9                          /* translated -> translated cross-module */
    add     x0, x0, #5
    ldp     x29, x30, [sp], #16
    ret

/* Hidden vtable targets: referenced only through .rodata, so the linker
 * emits R_AARCH64_RELATIVE (not ABS64) and no symbol export. */
    .hidden sdk_vfn_a
    .hidden sdk_vfn_b
    .type   sdk_vfn_a,%function
sdk_vfn_a:
    movz    x0, #0xa1
    ret
    .type   sdk_vfn_b,%function
sdk_vfn_b:
    movz    x0, #0xb2
    ret

    .data
    .balign 8
    .global sdk_vtable
    .type   sdk_vtable,%object
sdk_vtable:
    .xword  sdk_vfn_a
    .xword  sdk_vfn_b

    .section .bss,"aw",%nobits
    .balign 8
    .global sdk_bss
    .type   sdk_bss,%object
sdk_bss:
    .space  0x40

    .data
    .balign 8
/* Multi-word RW data imported by "main" (GLOB_DAT) and by "sub". */
    .global sdk_data
    .type   sdk_data,%object
sdk_data:
    .xword  0x1122334455667788
    .xword  0x99aabbccddeeff00
    .xword  0                            /* +16: main writes the weak import  */
    .xword  0                            /* +24: main writes host_hook addr   */
    .xword  0                            /* +32: sub writes own shared_impl   */
    .xword  0                            /* +40: sub writes host_hook addr    */
    .xword  0                            /* +48: sdk_add return value slot    */
    .xword  0                            /* +56: main writes nnMain real VA   */
    .xword  0                            /* +64: main ABS64 sdk_data+8 target */
    .xword  0                            /* +72: main shared_impl (sub wins)  */
    .xword  0                            /* +80: sdk writes own shared_impl   */
    .xword  0                            /* +88: nnMain's marker word. It is
                                          * a REAL sdk_data word so it cannot
                                          * alias sdk_ctor_state (fix 9).     */

    .global sdk_ctor_state
sdk_ctor_state:
    .word   0
    .balign 8
    .global sdk_init_count
sdk_init_count:
    .word   0

/* Scenario 6: the ordered constructor log lives in sdk's data. sdk_log()
 * appends one 32-bit marker at log + cursor and advances the BYTE cursor, so
 * the global ctor order is readable after the init sequence. */
    .balign 8
    .global sdk_log_buf
    .type   sdk_log_buf,%object
sdk_log_buf:
    .space  0x40
    .balign 8
    .global sdk_log_cursor
    .type   sdk_log_cursor,%object
sdk_log_cursor:
    .word   0
    .balign 8

/* The DT_INIT body: walk THIS module's .init_array, call every entry, then
 * publish state 2. The loader must never walk DT_INIT_ARRAY itself. */
    .text
    .hidden sdk_ctor_a
    .hidden sdk_ctor_b
    .type   sdk_ctor_a,%function
sdk_ctor_a:
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    movz    x0, #3
    bl      sdk_log
    adrp    x0, :got:sdk_init_count
    ldr     x0, [x0, :got_lo12:sdk_init_count]
    ldr     w1, [x0]
    add     w1, w1, #1
    str     w1, [x0]
    ldp     x29, x30, [sp], #16
    ret
    .type   sdk_ctor_b,%function
sdk_ctor_b:
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    movz    x0, #4
    bl      sdk_log
    adrp    x0, :got:sdk_init_count
    ldr     x0, [x0, :got_lo12:sdk_init_count]
    ldr     w1, [x0]
    add     w1, w1, #0x10
    str     w1, [x0]
    ldp     x29, x30, [sp], #16
    ret

    .global sdk_init
    .type   sdk_init,%function
sdk_init:
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
    adrp    x9, :got:sdk_ctor_state
    ldr     x9, [x9, :got_lo12:sdk_ctor_state]
    movz    w10, #2
    str     w10, [x9]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #32
    ret

/* u64 sdk_tick(void): CNTPCT_EL0 is a SYSREG HLE id, so this block exits to
 * the host handler and resumes at site_pc + 4 (the ret). */
    .global sdk_tick
    .type   sdk_tick,%function
sdk_tick:
    mrs     x0, cntpct_el0
    ret

/* u64 sdk_log(u64 id): append `id` to this module's ordered ctor log. The
 * cursor is a BYTE offset, so the body needs no variable shift. */
    .global sdk_log
    .type   sdk_log,%function
sdk_log:
    adrp    x1, :got:sdk_log_cursor
    ldr     x1, [x1, :got_lo12:sdk_log_cursor]
    ldr     w2, [x1]                    /* byte cursor (zero-extended) */
    adrp    x3, :got:sdk_log_buf
    ldr     x3, [x3, :got_lo12:sdk_log_buf]
    add     x3, x3, x2                  /* log + cursor */
    str     w0, [x3]
    add     w2, w2, #4
    str     w2, [x1]
    movz    x0, #1
    ret

/* =====================================================================
 * Scenario 6: the nn::init::Start shape. The HOST calls this with the guest
 * VAs of the loader-ready / module-inits / module-finis THUNKS; the body must
 * call ready, then inits, and never finis.
 * ===================================================================== */
/* u64 sdk_start(u64 ready, u64 inits, u64 finis) -> 0x5a5a */
    .global sdk_start
    .type   sdk_start,%function
sdk_start:
    stp     x29, x30, [sp, #-48]!
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    mov     x21, x0                     /* loader ready (thunk VA) */
    mov     x19, x1                     /* module inits (thunk VA) */
    mov     x20, x2                     /* module finis (NEVER called) */

    movz    x0, #7
    blr     x21                         /* BL ready(x0 = 7) */

    mov     x22, x0                     /* keep ready's result */
    mov     x0, x19
    blr     x0                          /* BL module_inits() */

    /* x20 is deliberately still live and is deliberately never called. */
    add     x0, x22, #1                 /* 0x5a59 + 1 = 0x5a5a */
    ldp     x19, x20, [sp, #16]
    ldp     x21, x22, [sp, #32]
    ldp     x29, x30, [sp], #48
    ret

    .section .init_array,"aw",%init_array
    .balign 8
    .xword  sdk_ctor_a
    .xword  sdk_ctor_b

    /* Review fix 4, positive case: a zero-size global symbol at __bss_end,
     * which the linker script makes the image end. Its value is therefore
     * exactly image_size, like the `end` linker symbol of a real module. */
    .section .bss,"aw",%nobits
    .global fx_sdk_end
    .type   fx_sdk_end,%notype
fx_sdk_end:
