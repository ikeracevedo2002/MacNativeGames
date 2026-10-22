/*
 * D024 Stage B fixture: candidate catalog vs current emission (no game data).
 *
 * Four AArch64 functions with DWARF CFI (one FDE each), linked with
 * tests/aot/g3/fde_emit.ld:
 *
 *   fx_entry       protected STT_FUNC  the ONLY admitted root; x0 selects a
 *                                      scenario, x1 is the switch selector,
 *                                      x2 an address chosen by the probe
 *   fx_ctor        protected STT_FUNC  reached by BL from fx_entry
 *   fx_switch      protected STT_FUNC  D022 guarded byte-table switch (owner)
 *   fx_unadmitted  local function      has an FDE and is reachable ONLY
 *                                      through a data pointer + BLR, so it is
 *                                      a catalog body that the CFG closure of
 *                                      the admitted root never contains
 *
 * Scenarios (x0):
 *    0 normal: switch(x1), constructor, SVC #0x21, FDIV by zero, FADD
 *    1 STR to RO                      -> AOT_FAULT_MEMORY
 *    2 STP straddling the image end   -> AOT_FAULT_MEMORY, no partial write
 *    4 x30 altered before RET         -> AOT_FAULT_BAD_RETURN
 *    5 SP altered before RET          -> AOT_FAULT_BAD_RETURN
 *    6 exclusive ABA (LDXR/STR/STR/STXR) -> STXR fails (w2 = 1)
 *    7 exclusive size mismatch (LDXR w / STXR x) -> STXR fails (w2 = 1)
 *    8 BLR to fx_unadmitted           -> AOT_FAULT_UNTRANSLATED
 *    9 STP straddling RO -> RW        -> AOT_FAULT_MEMORY, no partial write
 *   10 LDR from an unmapped address   -> AOT_FAULT_MEMORY
 *   11 BLR x2 with x0 = 0             -> the probe aims x2 at the switch's
 *                                        ADR block (a closure block start),
 *                                        bypassing the bound check: the D022
 *                                        guard faults AOT_FAULT_BAD_STATE
 *   12 an undecodable word (UDF #0)   -> AOT_FAULT_UNSUPPORTED_INSN (partial)
 * (3, a misaligned entry SP, is set up by the probe and runs scenario 0.)
 */
    .section .crt0,"a",%progbits
    .balign 4
    .global _start
_start:
    b       fx_entry
    .long   __mod0_off

    .section .mod0,"a",%progbits
    .balign 4
    .type   fx_mod0,%object
fx_mod0:
    .ascii  "MOD0"
    .long   __dynamic_rel
    .long   __bss_start_rel
    .long   __bss_end_rel
    .long   __eh_hdr_rel
    .long   __eh_hdr_end_rel
    .long   0

    .text
    .balign 16
    .global fx_entry
    .protected fx_entry
    .type   fx_entry,%function
fx_entry:
    .cfi_startproc
    stp     x29, x30, [sp, #-32]!
    .cfi_def_cfa_offset 32
    .cfi_offset 30, -24
    .cfi_offset 29, -32
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    .cfi_offset 20, -8
    .cfi_offset 19, -16
    mov     x19, x0
    mov     x20, x2
    adrp    x9, fx_data
    add     x9, x9, :lo12:fx_data
    cmp     x19, #1
    b.eq    .Lro
    cmp     x19, #2
    b.eq    .Loob_pair
    cmp     x19, #4
    b.eq    .Lbad_lr
    cmp     x19, #5
    b.eq    .Lbad_sp
    cmp     x19, #6
    b.eq    .Laba
    cmp     x19, #7
    b.eq    .Lsize
    cmp     x19, #8
    b.eq    .Lunadmitted
    cmp     x19, #9
    b.eq    .Lro_pair
    cmp     x19, #10
    b.eq    .Loob_load
    cmp     x19, #11
    b.eq    .Lindirect
    cmp     x19, #12
    b.eq    .Lunsup
    mov     x0, x1
    bl      fx_switch
    adrp    x9, fx_data
    add     x9, x9, :lo12:fx_data
    str     x0, [x9, #8]
    bl      fx_ctor
    mov     x0, #0x40
    svc     #0x21
    adrp    x9, fx_data
    add     x9, x9, :lo12:fx_data
    str     x0, [x9, #16]
    ldr     d0, [x9, #24]
    ldr     d1, [x9, #32]
    fdiv    d2, d0, d1
    fadd    d3, d0, d0
    str     d2, [x9, #40]
    str     d3, [x9, #48]
.Lret:
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #32
    ret
.Lro:
    adrp    x10, fx_ro_word
    add     x10, x10, :lo12:fx_ro_word
    str     x19, [x10]
    b       .Lret
.Loob_pair:
    stp     x19, x19, [x20]
    b       .Lret
.Lbad_lr:
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #32
    add     x30, x30, #16
    ret
.Lbad_sp:
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #32
    sub     sp, sp, #16
    ret
.Laba:
    add     x10, x9, #64
    ldxr    x1, [x10]
    mov     x5, #0x55
    str     x5, [x10]
    str     x1, [x10]
    mov     x3, #0x77
    stxr    w2, x3, [x10]
    b       .Lret
.Lsize:
    add     x10, x9, #64
    ldxr    w1, [x10]
    mov     x3, #0x88
    stxr    w2, x3, [x10]
    b       .Lret
.Lunadmitted:
    ldr     x8, [x9, #72]
    blr     x8
    b       .Lret
.Lindirect:
    mov     x0, #0
    blr     x20
    b       .Lret
.Lunsup:
    .inst   0x00000000
.Lro_pair:
    stp     x19, x19, [x20]
    b       .Lret
.Loob_load:                     /* last block: two words, so a window that */
    ldr     x3, [x20]           /* ends 4 bytes early splits it            */
    b       .Lret
    .cfi_endproc
    .size   fx_entry, . - fx_entry

    .balign 16
    .global fx_ctor
    .protected fx_ctor
    .type   fx_ctor,%function
fx_ctor:
    .cfi_startproc
    adrp    x9, fx_data
    add     x9, x9, :lo12:fx_data
    ldr     w10, [x9]
    lsl     w10, w10, #4
    add     w10, w10, #7
    str     w10, [x9]
    ret
    .cfi_endproc
    .size   fx_ctor, . - fx_ctor

    .balign 16
    .global fx_switch
    .protected fx_switch
    .type   fx_switch,%function
fx_switch:
    .cfi_startproc
    adrp    x9, .Ltable
    add     x9, x9, :lo12:.Ltable
    cmp     x0, #3
    b.hi    .Ldefault
    adr     x10, .Lcases
    ldrb    w11, [x9, x0]
    add     x10, x10, x11, lsl #2
    br      x10
.Ldefault:
    mov     x0, #0x99
    ret
.Lcases:
    mov     x0, #10
    ret
    mov     x0, #11
    ret
    mov     x0, #12
    ret
    mov     x0, #13
    ret
    .cfi_endproc
    .size   fx_switch, . - fx_switch

    .balign 16
    .type   fx_unadmitted,%function
fx_unadmitted:
    .cfi_startproc
    mov     x0, #0x5a
    ret
    .cfi_endproc
    .size   fx_unadmitted, . - fx_unadmitted

    .section .rodata,"a",%progbits
    .balign 8
fx_ro_word:
    .quad   0x1122334455667788
.Ltable:                        /* non-zero page offset: a real ADD #lo12 */
    .byte   0, 2, 4, 6

    .data
    .balign 64
fx_data:
    .quad   3                   /* +0  constructor word            */
    .quad   0                   /* +8  switch result               */
    .quad   0                   /* +16 SVC result                  */
    .double 1.0                 /* +24 FDIV dividend               */
    .double 0.0                 /* +32 FDIV divisor                */
    .quad   0                   /* +40 FDIV result                 */
    .quad   0                   /* +48 FADD result                 */
    .quad   0                   /* +56                             */
    .quad   0x1234              /* +64 exclusive word              */
    .quad   fx_unadmitted       /* +72 the only path to the body   */
