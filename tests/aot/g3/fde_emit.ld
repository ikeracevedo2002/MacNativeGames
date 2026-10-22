/*
 * D024 Stage B: NSO-like layout for the candidate-catalog fixture.
 *
 * Same shape as tests/aot/g3/fde.ld with ONE difference: `.rodata` is the
 * FIRST thing in the RO segment.  The D022 local-switch prover excludes the
 * whole read-only suffix that starts at `.eh_frame_hdr` (explicit EH-frame
 * over-approximation), so a switch table must live before the header to be
 * provable at all.
 */
PHDRS {
  text    PT_LOAD FLAGS(5);   /* R-X */
  rodata  PT_LOAD FLAGS(4);   /* R   */
  data    PT_LOAD FLAGS(6);   /* RW  */
  dynamic PT_DYNAMIC FLAGS(6);
}

SECTIONS {
  . = 0;
  PROVIDE_HIDDEN(__image_start = .);

  .crt0 : { KEEP(*(.crt0)) } :text
  .mod0 : { __mod0 = .; KEEP(*(.mod0)) } :text
  .text : { *(.text .text.*) } :text
  .plt  : { *(.plt) *(.plt.*) *(.iplt) } :text

  . = ALIGN(0x1000);
  __text_end = .;

  .rodata : { *(.rodata .rodata.*) } :rodata

  .eh_frame_hdr : {
    __eh_frame_hdr_start = .;
    KEEP(*(.eh_frame_hdr))
    __eh_frame_hdr_end = .;
  } :rodata
  .eh_frame : {
    __eh_frame_start = .;
    KEEP(*(.eh_frame))
    __eh_frame_end = .;
  } :rodata

  .dynsym   : { *(.dynsym) }            :rodata
  .gnu.hash : { *(.gnu.hash) }          :rodata
  .hash     : { *(.hash) }              :rodata
  .dynstr   : { *(.dynstr) }            :rodata
  .rela.dyn : { *(.rela.dyn) }          :rodata
  .rela.plt : { *(.rela.plt) }          :rodata
  .relr.dyn : { *(.relr.dyn) }          :rodata

  . = ALIGN(0x1000);
  __ro_end = .;

  /* .dynamic MUST be first in the RW segment (MOD0 dynamic offset). */
  .dynamic : { __dynamic = .; *(.dynamic) } :data :dynamic
  .got     : { *(.got) *(.got.plt) } :data
  .data.rel.ro : { *(.data.rel.ro .data.rel.ro.*) } :data
  .data    : { *(.data .data.*) } :data
  __data_end = .;

  .bss : {
    PROVIDE_HIDDEN(__bss_start = .);
    *(.bss .bss.*)
    *(COMMON)
    . = ALIGN(8);
    PROVIDE_HIDDEN(__bss_end = .);
  } :data

  PROVIDE_HIDDEN(__mod0_off      = __mod0      - __image_start);
  PROVIDE_HIDDEN(__dynamic_rel   = __dynamic   - __mod0);
  PROVIDE_HIDDEN(__bss_start_rel = __bss_start - __mod0);
  PROVIDE_HIDDEN(__bss_end_rel   = __bss_end   - __mod0);
  PROVIDE_HIDDEN(__eh_hdr_rel     = __eh_frame_hdr_start - __mod0);
  PROVIDE_HIDDEN(__eh_hdr_end_rel = __eh_frame_hdr_end   - __mod0);
}
