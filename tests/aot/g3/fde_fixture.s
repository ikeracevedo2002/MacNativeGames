/*
 * D024 Stage A fixture: .eh_frame / FDE-frontend boundaries (no game data).
 *
 * Four AArch64 functions with DWARF CFI, plus a constructor table whose single
 * slot points at the fourth one.  The interesting properties are the SHAPE of
 * the metadata, not the instructions:
 *
 *   fx_entry  global   STT_FUNC  -> dynsym entry  + FDE  (fde+dynsym_func)
 *   fx_local  local    (no dynsym)                + FDE  (fde only)
 *   fx_hidden global hidden STT_FUNC -> no dynsym + FDE  (fde only)
 *   fx_ctor   local    (no dynsym) + .init_array  + FDE  (fde+dt_init_array)
 *
 * The functions are separated by explicit padding so the module TEXT really
 * contains gaps that no FDE covers: a manifest that silently invented
 * boundaries there would be wrong, and the test asserts the exact gap set.
 *
 * fx_bounds holds the two relocated array-bound words the D023 table
 * derivation requires as corroboration (DT_INIT_ARRAY / +DT_INIT_ARRAYSZ).
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
    .balign 8
    .global fx_entry
    .type   fx_entry,%function
fx_entry:
    .cfi_startproc
    stp     x29, x30, [sp, #-16]!
    .cfi_def_cfa_offset 16
    .cfi_offset 30, -8
    .cfi_offset 29, -16
    mov     x29, sp
    .cfi_def_cfa 29, 16
    mov     x0, #1
    ret
    .cfi_endproc
    .size   fx_entry, . - fx_entry

    .balign 0x40                       /* uncovered gap after fx_entry */
    .type   fx_local,%function
fx_local:
    .cfi_startproc
    mov     x0, #2
    ret
    .cfi_endproc
    .size   fx_local, . - fx_local

    .balign 0x40                       /* uncovered gap after fx_local */
    .global fx_hidden
    .hidden fx_hidden
    .type   fx_hidden,%function
fx_hidden:
    .cfi_startproc
    .cfi_remember_state
    mov     x0, #3
    .cfi_restore_state
    ret
    .cfi_endproc
    .size   fx_hidden, . - fx_hidden

    .balign 0x40                       /* uncovered gap after fx_hidden */
    .type   fx_ctor,%function
fx_ctor:
    .cfi_startproc
    mov     x0, #4
    ret
    .cfi_endproc
    .size   fx_ctor, . - fx_ctor

    .section .init_array,"aw",%init_array
    .balign 8
    .quad   fx_ctor

    .data
    .balign 8
    .type   fx_bounds,%object
fx_bounds:
    .quad   __init_array_start
    .quad   __init_array_end
