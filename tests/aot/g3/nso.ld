/*
 * G3 increment 2: NSO-like layout for the module-loader fixtures.
 *
 * Mirrors the real Nintendo NSO image shape closely enough for the loader
 * work, without any game data:
 *
 *   PT_LOAD #0  R+X  vaddr 0x0     : crt0 header, MOD0, .text, .plt
 *   PT_LOAD #1  R    page aligned  : .dynsym/.hash/.dynstr/.rela*, .rodata
 *   PT_LOAD #2  R+W  page aligned  : .dynamic first, then .got/.data/init arrays/.bss
 *
 * Why the header word is legal here:
 *   Real NSOs replace the ELF header with an 8-byte crt0 header (word0 = entry
 *   branch, word1 = offset of the MOD0 header). We keep that exact byte image:
 *   .crt0 is the first section at vaddr 0, so tools/aot/aot_module.py elf2flat
 *   maps p_offset -> p_vaddr and the resulting .flat file starts with the crt0
 *   header, exactly like an NSO. (The ELF header lives at a different FILE
 *   offset, which is why the tool copies by program header and never assumes
 *   p_offset == p_vaddr.)
 *
 * MOD0 offsets are computed by the linker because they are only known after
 * layout. They are emitted as 32-bit ABSOLUTE values (`sym - __image_start`
 * and address differences) so no dynamic relocation is needed for them: the
 * ABS32 relocation is fully resolved at link time.
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
  /* MOD0 lives in the text segment, directly behind the crt0 header, exactly
   * like a real NSO (word1 of the header is its offset from the image base).
   * It is only READ by the loader, never executed. */
  .mod0 : { __mod0 = .; KEEP(*(.mod0)) } :text
  .text : { *(.text .text.*) } :text
  .plt  : { *(.plt) *(.plt.*) *(.iplt) } :text

  . = ALIGN(0x1000);
  __text_end = .;

  /* Dynamic tables live in the R segment, like a real NSO. They are orphan
   * sections otherwise: lld would append them to the end of the first
   * matching segment, which would silently change the image shape. */
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

  /* .dynamic MUST be first in the RW segment: the loader indexes the whole
   * segment through the MOD0 dynamic offset. */
  .dynamic : { __dynamic = .; *(.dynamic) } :data :dynamic
  .got     : { *(.got) *(.got.plt) } :data
  /* Orphan data sections lld would otherwise append after .bss (which would
   * make them file-backed data past bss_start and break the flat image). */
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

  /* bss starts exactly where the file-backed RW bytes end (real NSO shape):
   * no page padding, so the flat image ends at bss_start. */
  __data_end = .;

  .bss : {
    PROVIDE_HIDDEN(__bss_start = .);
    *(.bss .bss.*)
    *(COMMON)
    . = ALIGN(8);
    PROVIDE_HIDDEN(__bss_end = .);
  } :data

  /* 32-bit values consumed by .crt0/.mod0. Address differences make them
   * ABSOLUTE, so the assembler's R_AARCH64_ABS32 resolves at link time even in
   * a -shared link (a plain address symbol would be preemptible and rejected). */
  PROVIDE_HIDDEN(__mod0_off     = __mod0      - __image_start);
  PROVIDE_HIDDEN(__dynamic_rel  = __dynamic   - __mod0);
  PROVIDE_HIDDEN(__bss_start_rel = __bss_start - __mod0);
  PROVIDE_HIDDEN(__bss_end_rel   = __bss_end   - __mod0);
  PROVIDE_HIDDEN(__data_end_rel  = __data_end  - __mod0);
  PROVIDE_HIDDEN(__image_end_rel = __bss_end   - __image_start);
}
