/*
 * D024 Stage A: NSO-like layout for the .eh_frame / FDE-frontend fixtures.
 *
 * Same shape as tests/aot/g3/nso.ld (crt0 header, MOD0 in TEXT, R tables,
 * RW data first) plus the two things this fixture must have and the module
 * loader fixtures do not:
 *
 *   .eh_frame_hdr / .eh_frame  placed explicitly in the RO segment, so the
 *                              MOD0 +16/+20 extents are a REAL linker-computed
 *                              interval instead of a guess;
 *   DWARF CFI                  emitted by llvm-mc from `.cfi_*` directives, so
 *                              the header/table/FDE records are produced by the
 *                              same LLVM machinery that produced the real
 *                              modules (linked with `--eh-frame-hdr`).
 *
 * MOD0 offsets are 32-bit ABSOLUTE values (`sym - sym`), fully resolved at
 * link time, exactly like tests/aot/g3/nso.ld.
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

  .rodata : { *(.rodata .rodata.*) } :rodata

  . = ALIGN(0x1000);
  __ro_end = .;

  /* .dynamic MUST be first in the RW segment (MOD0 dynamic offset). */
  .dynamic : { __dynamic = .; *(.dynamic) } :data :dynamic
  .got     : { *(.got) *(.got.plt) } :data
  .data.rel.ro : { *(.data.rel.ro .data.rel.ro.*) } :data
  .data    : { *(.data .data.*) } :data
  .init_array : {
    PROVIDE_HIDDEN(__init_array_start = .);
    KEEP(*(SORT_BY_INIT_PRIORITY(.init_array.*)))
    KEEP(*(.init_array))
    PROVIDE_HIDDEN(__init_array_end = .);
  } :data
  .fini_array : {
    PROVIDE_HIDDEN(__fini_array_start = .);
    KEEP(*(SORT_BY_INIT_PRIORITY(.fini_array.*)))
    KEEP(*(.fini_array))
    PROVIDE_HIDDEN(__fini_array_end = .);
  } :data
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
