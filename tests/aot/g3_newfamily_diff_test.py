#!/usr/bin/env python3
"""New integer/memory family differential through EMITTED C + native MSVC x64.

Pipeline (all synthetic, no game data):
  llvm-mc fixture -> raw .text -> aot_translate.py --module (strict, real
  lowering) -> compiled C block functions -> a native runner calls each entry
  block directly and dumps GPR/SP/NZCV/NEXT/FAULT, TPIDR/RO, Q0..31,
  FPCR/FPSR and the data page.
The same words are replayed on a pinned Unicorn A57 from the identical initial
state and compared field by field (state, PC-after-branch, page bytes). A
memory-fault case pins the typed fields (MEMORY, src=site, SP/base writeback
NOT applied) separately.

Compiled translator mutants (tbz_bit, csel_cond, ldst_sign_zero,
imm9_wb_nooff, smulh_unsigned, msub_reverse, madd_no_zeroext,
madd_ignore_ra, div_zero_ones, div_no_zeroext, sdiv_overflow_clamp,
msr_tpidr_*, ccmp_ignore_cond, ccmp_cond_invert, ccmp_w64) are built and must
produce output DIFFERENT from the real image;
a mutant that matches is a survivor. The UDIV/SDIV family covers x/0 == 0,
SDIV(INT_MIN,-1) == INT_MIN without trapping, W-form operand truncation and
zero-extension, Rd aliasing/XZR reads and unchanged NZCV. The CCMP/CCMN
families cover the immediate and register forms at both widths, all 16
condition codes with the taken and not-taken path, the nzcv-field path, XZR
operands, carry/overflow corners and the unchanged-GPR/SP/memory requirement.
Infrastructure
errors are not rejections.

Exit: 0 pass, 2 semantic failure, 1 infrastructure.
"""

import argparse
import glob
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import tempfile

BASE = 0x1000000000
DATA = 0x3000000000
STACK = 0x2000000000
PAGE = 0x1000
MAXWORDS = 512

ASM = r'''
.text
/* ---- non-control families: one straight-line block, state compared ---- */
.global t_alu
t_alu:
    movn    x0, #0x1234
    movn    w1, #0x5678, lsl #16
    cmp     x0, #0x234
    csel    x2, x0, x1, eq
    csinc   w3, w0, w1, ne
    csinv   x4, x0, x1, ne
    csneg   w5, w0, w1, eq
    csel    x6, xzr, x1, lt
    and     x7, x0, #0xff00ff00ff00ff00
    orr     x8, x1, #0xffffffff00000000
    eor     x9, x0, #0x0f0f0f0f0f0f0f0f
    ands    x10, x0, #0xff
    tst     x1, #0xf0
    ands    x11, x0, x1, asr #3
    add     x12, x0, w1, uxtw #1
    sub     w13, w0, w1, sxtb #2
    add     x14, x0, w1, sxtw #3
    movz    x15, #0xffff
    movz    x16, #0xffff
    sbfx    x15, x0, #3, #18
    ubfx    x16, x1, #3, #18
    bfi     x15, x0, #8, #8
    bfxil   x16, x1, #4, #12
    asr     x17, x0, #3
    lsr     w18, w1, #5
    lsl     x19, x0, #7
    sxtw    x20, w1
    add     sp, sp, #0x10
    and     sp, x0, #0xff
    orr     wsp, w1, #0x80000001
    eor     sp, xzr, #1
    ret

/* ---- inverted logical shifted register: BIC/ORN/EON/BICS + MVN alias ----
   Every instruction here keeps its operands in x0/w0 and x1/w1 (the seeded
   values), so the 32-bit forms also prove the upper halves do not leak and
   the shifted forms prove the NOT is applied AFTER the shift. The first CMP
   installs data-dependent NZCV which the whole block must preserve. */
.global t_inv
t_inv:
    cmp     x0, x1
    bic     x2, x0, x1
    bic     w3, w0, w1
    bic     x4, x0, x1, lsl #12
    bic     w5, w0, w1, lsr #7
    bic     x6, x0, x1, asr #63
    bic     w7, w0, w1, ror #11
    orn     x8, x0, x1
    orn     w9, w0, w1, lsl #3
    orn     x10, x0, x1, lsr #1
    orn     w11, w0, w1, asr #31
    orn     x12, x0, x1, ror #32
    eon     x13, x0, x1
    eon     w14, w0, w1, ror #16
    eon     x15, x0, x1, asr #2
    eon     w16, w0, w1, lsl #1
    mvn     x17, x0
    mvn     w18, w1, lsl #9
    mvn     x19, x0, ror #17
    bic     x20, xzr, x1
    bic     x21, x0, xzr
    orn     w22, wzr, w1
    eon     x23, x1, x0, lsl #63
    ret

/* ---- BICS only: flags are SET (N,Z from the result, C/V cleared) ---- */
.global t_inv_flags
t_inv_flags:
    cmp     x0, x1
    bics    x2, x0, x1
    bics    w3, w0, w1
    bics    x4, x0, x1, ror #4
    bics    w5, w0, w1, asr #31
    bics    xzr, x0, x1
    ret

/* ---- signed loads, STP ZR/dup, imm9, reg-offset ---- */
.global t_mem
t_mem:
    movz    x20, #0x30, lsl #32
    add     x20, x20, #0x100
    movz    x21, #8
    movz    x22, #0x8000
    sturh   w22, [x20, #-2]
    ldurh   w23, [x20, #-2]
    ldursh  x24, [x20, #-2]
    ldursh  w25, [x20, #-2]
    sturb   w22, [x20, #2]
    ldursb  x26, [x20, #2]
    movz    w27, #0x80
    sturb   w27, [x20, #3]
    ldrsb   w28, [x20, #3]
    ldrsb   x29, [x20, #3]
    movz    w0, #0x8000, lsl #16
    stur    w0, [x20, #4]
    ldursw  x1, [x20, #4]
    str     wzr, [x20, #8]
    stp     xzr, xzr, [x20, #16]
    ldr     x2, [x20, #16]
    stp     x22, x22, [x20, #32]
    ldr     x3, [x20, #32]
    ldr     x4, [x20, #48]!
    ldr     x5, [x20], #8
    movz    x19, #0x30, lsl #32
    add     x19, x19, #0x100
    ldr     x6, [x19, x21]
    ldr     w7, [x19, w21, uxtw #2]
    ldr     x8, [x19, w21, sxtw #3]
    ldr     x9, [x19, x21, lsl #0]
    ldur    x10, [x19, #-8]
    stur    x10, [x19, #-8]
    ret

/* ---- SMULH: operands are the runner seed values, never overwritten ---- */
.global t_mulh
t_mulh:   smulh x2, x0, x1
          smulh x3, x0, x2
          smulh x4, x1, x3
          smulh x5, x2, x3
          ret

/* ---- UMULH: unsigned high 64 of the x0/x1 seed pair, then chained so the
   later lanes multiply a WIDE product by a fresh operand. ---- */
.global t_umulh
t_umulh:  umulh x2, x0, x1
          umulh x3, x0, x2
          umulh x4, x1, x3
          umulh x5, x2, x3
          ret

/* ---- UMULH: ZERO-register sources, discarded Rd, Rd==Rn==Rm, x18 ---- */
.global t_umulh_alias
t_umulh_alias:
          umulh x2, xzr, x1          /* Rn=31 reads XZR */
          umulh x3, x0, xzr          /* Rm=31 reads XZR */
          umulh xzr, x0, x1          /* Rd=31 discards; x0/x1 survive */
          umulh x4, x1, x1           /* Rn==Rm; distinct Rd */
          umulh x5, x5, x5           /* Rd==Rn==Rm on the canary */
          umulh x18, x18, x1         /* ordinary high GPR destination */
          umulh x6, x18, x18
          ret

/* ---- MUL/MADD/MSUB X/W: modulo-width, Ra=31 MUL alias, NZCV untouched ---- */
.global t_mul
t_mul:    mul   x2, x0, x1
          mul   w3, w0, w1
          madd  x4, x0, x1, x2
          msub  x5, x0, x1, x2
          madd  w6, w0, w1, w2
          msub  w7, w0, w1, w2
          mul   x8, x0, xzr
          movz  x9, #7
          madd  x10, x0, x1, xzr
          ret

/* ---- UDIV/SDIV: x/0==0, INT_MIN/-1 wraps, W zero-extend, no NZCV ---- */
.global t_div
t_div:    udiv  x2, x0, x1
          sdiv  x3, x0, x1
          sdiv  x4, x1, x0
          udiv  x5, x1, x0
          udiv  w6, w0, w1
          sdiv  w7, w0, w1
          sdiv  w8, w1, w0
          ret

/* ---- Rd aliasing Rn/Rm, Rn/Rm=31 reads XZR, Rd=31 discards ---- */
.global t_div_alias
t_div_alias:
          udiv  x0, x0, x2
          sdiv  x1, x0, x1
          udiv  x9, x0, xzr
          sdiv  x10, xzr, x1
          udiv  w11, wzr, w0
          udiv  wzr, w0, w1
          sdiv  w12, w12, w13
          udiv  x14, x15, x14
          ret

/* ---- INT_MIN/-1 for both widths and W-form operand truncation ---- */
.global t_div_overflow
t_div_overflow:
          movz  x20, #0x8000, lsl #48
          movn  x21, #0
          sdiv  x2, x20, x21
          movz  w22, #0x8000, lsl #16
          movn  w23, #0
          sdiv  w3, w22, w23
          udiv  w4, w22, w23
          sdiv  x5, x22, x23
          udiv  x6, x20, x21
          sdiv  x7, x21, x20
          udiv  w8, w21, w20
          ret

/* ---- TBZ/TBNZ: one branch instruction per entry, PC compared ---- */
.global t_tbz31
t_tbz31:  tbz  w0, #31, 1f
          mov  x1, #1
          ret
1:        mov  x1, #2
          ret
.global t_tbz32
t_tbz32:  tbz  x0, #32, 1f
          mov  x1, #3
          ret
1:        mov  x1, #4
          ret
.global t_tbnz63
t_tbnz63: tbnz x0, #63, 1f
          mov  x1, #5
          ret
1:        mov  x1, #6
          ret

/* ---- imm9 pre-index fault: writeback must NOT be applied ---- */
.global t_fault
t_fault:  ldr x0, [x20, #-8]!
          ret

/* ---- MSR TPIDR_EL0: canonical guest tpidr only, Rt=31 is XZR ---- */
.global t_msr
t_msr:    msr tpidr_el0, x0
          ret
.global t_msr8
t_msr8:   msr tpidr_el0, x8
          ret
.global t_msr30
t_msr30:  msr tpidr_el0, x30
          ret
.global t_msr31
t_msr31:  msr tpidr_el0, xzr
          ret

/* ---- CCMP/CCMN (immediate): W and X, imm 0/1/31, condition true and
   condition false for several conditions. Nothing but NZCV may change. ---- */
.global t_ccmp_imm
t_ccmp_imm:
          cmp   w0, #1
          ccmp  w0, #0, #5, eq
          cmp   x0, #1
          ccmp  x0, #31, #10, eq
          cmp   w0, #1
          ccmn  w0, #1, #7, ne
          cmp   x0, #1
          ccmn  x0, #31, #0, ne
          cmp   w0, #2
          ccmp  w0, #1, #15, ls
          cmp   x0, #2
          ccmn  x0, #1, #9, hi
          ret

/* ---- CCMP/CCMN (register): XZR operands, and a ccmp whose condition is
   read from the flags the PREVIOUS ccmp wrote (the condition must be
   evaluated before the guarded comparison overwrites NZCV) ---- */
.global t_ccmp_reg
t_ccmp_reg:
          cmp   w0, #1
          ccmp  w0, w1, #3, eq
          ccmp  w0, w2, #4, ne
          cmp   x0, #1
          ccmp  x0, x1, #6, eq
          ccmp  x0, x2, #12, eq
          cmp   x0, #1
          ccmp  x0, xzr, #7, ne
          cmp   w0, #1
          ccmp  wzr, w1, #11, eq
          cmp   w0, #1
          ccmn  w0, w1, #0, eq
          cmp   x0, #1
          ccmn  x0, x1, #15, ne
          ccmn  x0, x2, #1, gt
          ret

/* ---- every condition code, with flags from cmp w0, w1 so both the taken
   and the not-taken path occur across the scenario corners ---- */
.global t_ccmp_cond
t_ccmp_cond:
          cmp   w0, w1
          ccmp  w0, #1, #6, eq
          cmp   w0, w1
          ccmp  w0, #1, #9, ne
          cmp   w0, w1
          ccmp  w0, #1, #3, cs
          cmp   w0, w1
          ccmp  w0, #1, #12, cc
          cmp   w0, w1
          ccmp  w0, #1, #5, mi
          cmp   w0, w1
          ccmp  w0, #1, #10, pl
          cmp   w0, w1
          ccmp  w0, #1, #1, vs
          cmp   w0, w1
          ccmp  w0, #1, #14, vc
          cmp   w0, w1
          ccmp  w0, #1, #2, hi
          cmp   w0, w1
          ccmp  w0, #1, #13, ls
          cmp   w0, w1
          ccmp  w0, #1, #4, ge
          cmp   w0, w1
          ccmp  w0, #1, #7, lt
          cmp   w0, w1
          ccmp  w0, #1, #8, gt
          cmp   w0, w1
          ccmp  w0, #1, #11, le
          cmp   w0, w1
          ccmp  w0, #1, #0, al
          cmp   w0, w1
          ccmp  w0, #1, #15, nv
          ret

/* ---- carry/overflow corners. The first ccmp reads the ARCHITECTURAL
   incoming NZCV (no cmp first), the rest build Z/C/V edges with x0 - 0,
   x0 + 1, x0 - 31 and x0 + x1 at both widths. ---- */
.global t_ccmp_edge
t_ccmp_edge:
          ccmp  w0, #0, #5, eq
          ccmp  x0, x1, #5, eq
          cmp   w0, #1
          ccmn  w0, #1, #4, ne
          cmp   x0, #1
          ccmn  x0, #1, #4, ne
          cmp   w0, #1
          ccmp  w0, #31, #2, eq
          cmp   x0, #1
          ccmp  x0, #31, #2, eq
          cmp   w0, #1
          ccmp  w0, w1, #13, eq
          cmp   x0, #1
          ccmn  x0, x1, #13, eq
          ret

/* ---- one-source CLZ. Mixed operands, x18, Rn/Rd = 31 (the ZERO register,
   never SP), and Rn == Rd. The high 32 bits of x0/x1 are deliberately live so
   the W lanes can witness a 64-bit count over the low half. ---- */
.global t_clz
t_clz:
          clz   x2, x0
          clz   w3, w0
          clz   x4, x1
          clz   w5, w1
          clz   x6, x18
          clz   w7, w18
          clz   x9, x9          /* alias: Rn == Rd */
          clz   w10, w10        /* alias: Wn == Wd */
          clz   xzr, x0         /* Rd == 31 discards */
          clz   x11, xzr        /* Rn == 31 is XZR (0 -> 64), NOT SP */
          clz   w12, wzr        /* Rn == 31 is WZR (0 -> 32), NOT WSP */
          ret

/* W-only lanes on x0/x1: the edge values where the low 32 bits are zero but
   the high half is not (and vice versa) are the only witnesses for "the W
   form must count within 32 bits only". */
.global t_clz_w
t_clz_w:
          clz   w4, w0
          clz   w5, w1
          ret

/* All-zero operands, including a real register zeroed by MOV: real CLZ must
   yield the operand width (64 / 32 / 64), not 0. */
.global t_clz_zero
t_clz_zero:
          clz   x2, xzr
          clz   w3, wzr
          mov   x22, #0
          clz   x6, x22
          ret

/* CLZ must NOT touch NZCV: a preceding CMP seeds architectural flags and the
   runner's four NZCV seeds change them. */
.global t_clz_flags
t_clz_flags:
          cmp   w0, w1
          clz   x2, x0
          clz   w3, w0
          clz   xzr, x1
          ret

/* ---- one-source RBIT. Mixed operands, x18, Rn/Rd = 31 (the ZERO register,
   never SP), and Rn == Rd. The high 32 bits of x0/x1 are deliberately live so
   the W lanes can witness a 64-bit reversal leaking into the upper half. ---- */
.global t_rbit
t_rbit:
          rbit  x2, x0
          rbit  w3, w0
          rbit  x4, x1
          rbit  w5, w1
          rbit  x6, x18
          rbit  w7, w18
          rbit  x9, x9          /* alias: Rn == Rd */
          rbit  w10, w10        /* alias: Wn == Wd */
          rbit  xzr, x0         /* Rd == 31 discards */
          rbit  x11, xzr        /* Rn == 31 is XZR (0 -> 0), NOT SP */
          rbit  w12, wzr        /* Rn == 31 is WZR, NOT WSP */
          ret

/* W-only lanes on x0/x1: the high-half canaries (0xFFFFFFFF00000000,
   0x00000000FFFFFFFF, ...) are the only witnesses for "the W form reverses
   within 32 bits and zero-extends". */
.global t_rbit_w
t_rbit_w:
          rbit  w4, w0
          rbit  w5, w1
          ret

/* Zero and all-ones operands, including real registers zeroed/filled by MOV:
   RBIT(0) == 0 and RBIT(~0) == ~0 at the operand width. */
.global t_rbit_zero
t_rbit_zero:
          rbit  x2, xzr
          rbit  w3, wzr
          mov   x22, #0
          mov   w23, #0
          rbit  x6, x22
          rbit  w7, w23
          mov   x24, #-1
          rbit  x8, x24
          rbit  w9, w24
          ret

/* RBIT must NOT touch NZCV: a preceding CMP seeds architectural flags and the
   runner's sixteen NZCV seeds change them. */
.global t_rbit_flags
t_rbit_flags:
          cmp   w0, w1
          rbit  x2, x0
          rbit  w3, w0
          rbit  xzr, x1
          ret

/* ---- DMB ISH. Ordinary accesses before and after the barrier, including a
   load of the value a preceding store wrote; x5 is left untouched so a GPR
   clobber is observable. ---- */
.global t_dmb
t_dmb:
          ldr   x2, [x20]
          dmb   ish
          str   x1, [x20, #8]
          dmb   ish
          ldr   x3, [x20, #8]
          ldr   w4, [x20, #16]
          ret

/* DMB ISH must not touch NZCV: all sixteen architectural nibbles seeded. */
.global t_dmb_flags
t_dmb_flags:
          cmp   w0, w1
          dmb   ish
          ret

/* DMB is NOT CLREX: an exclusive pair whose reservation must SURVIVE the
   barrier, so both stxr status words are 0 and both stores land. */
.global t_dmb_excl
t_dmb_excl:
          ldxr  x2, [x20]
          dmb   ish
          stxr  w3, x1, [x20]
          ldxr  w4, [x20]
          dmb   ish
          stxr  w5, w0, [x20]
          ret

/* ---- two-source variable shifts: all four opcodes at both widths, x18,
   Rn/Rm/Rd = 31 (the ZERO register, never SP), and Rn == Rm == Rd overlaps.
   x0 is the shifted value, x1 the amount; the upper 32 bits of both are live
   so the W lanes can witness a 64-bit lowering. ---- */
.global t_vs
t_vs:
          lsl   x2, x0, x1
          lsr   x3, x0, x1
          asr   x4, x0, x1
          ror   x5, x0, x1
          lsl   w6, w0, w1
          lsr   w7, w0, w1
          asr   w8, w0, w1
          ror   w9, w0, w1
          lsl   x18, x18, x1
          ror   w19, w18, w1
          lsl   x10, x10, x10        /* Rn == Rd */
          ror   w11, w11, w11        /* value == amount == dest */
          lsl   xzr, x0, x1          /* Rd == 31 discards */
          lsr   x12, xzr, x1         /* Rn == 31 is XZR */
          asr   w13, w0, wzr         /* Rm == 31 is WZR: amount 0 */
          ror   x14, x0, xzr         /* Rm == 31 is XZR: amount 0 */
          ret

/* Amount edge lanes: x1 carries 0, 1, w-1, w, w+1, 2w-1, UINT64_MAX and
   high-bit-only values, so the modulo-width rule is the only rule that can
   make every lane agree with the hardware. ---- */
.global t_vs_amt
t_vs_amt:
          lsl   x2, x0, x1
          lsr   x3, x0, x1
          asr   x4, x0, x1
          ror   x5, x0, x1
          lsl   w6, w0, w1
          lsr   w7, w0, w1
          asr   w8, w0, w1
          ror   w9, w0, w1
          ret
'''

# Inverted logical (BIC/ORN/EON/BICS) fixture: one instruction per line, in
# this exact order. llvm-mc assembles it and the decoder metadata is compared
# against these architectural field expectations (never hand-encoded words).
INV_ASM = r'''
.text
bic x0, x1, x2
bic w3, w4, w5
bic x6, x7, x8, lsl #7
bic x9, x10, x11, lsr #33
bic x12, x13, x14, asr #63
bic w15, w16, w17, ror #11
orn x0, x1, x2
orn w3, w4, w5, lsl #5
orn x6, x7, x8, lsr #1
orn w9, w10, w11, asr #31
orn x12, x13, x14, ror #32
eon x0, x1, x2
eon w3, w4, w5, lsr #7
eon x6, x7, x8, asr #2
bics x0, x1, x2
bics w3, w4, w5
bics x6, x7, x8, ror #4
bics xzr, x1, x2
mvn x9, x10
mvn w11, w12
mvn x13, x14, lsl #9
bic x15, xzr, x16
bic x17, x18, xzr
'''

#            text                        op width shift imm6  rn  rm  rd  s
INV_ROWS = [("bic x0, x1, x2", 0, 64, 0, 0, 1, 2, 0, 0),
            ("bic w3, w4, w5", 0, 32, 0, 0, 4, 5, 3, 0),
            ("bic x6, x7, x8, lsl #7", 0, 64, 0, 7, 7, 8, 6, 0),
            ("bic x9, x10, x11, lsr #33", 0, 64, 1, 33, 10, 11, 9, 0),
            ("bic x12, x13, x14, asr #63", 0, 64, 2, 63, 13, 14, 12, 0),
            ("bic w15, w16, w17, ror #11", 0, 32, 3, 11, 16, 17, 15, 0),
            ("orn x0, x1, x2", 1, 64, 0, 0, 1, 2, 0, 0),
            ("orn w3, w4, w5, lsl #5", 1, 32, 0, 5, 4, 5, 3, 0),
            ("orn x6, x7, x8, lsr #1", 1, 64, 1, 1, 7, 8, 6, 0),
            ("orn w9, w10, w11, asr #31", 1, 32, 2, 31, 10, 11, 9, 0),
            ("orn x12, x13, x14, ror #32", 1, 64, 3, 32, 13, 14, 12, 0),
            ("eon x0, x1, x2", 2, 64, 0, 0, 1, 2, 0, 0),
            ("eon w3, w4, w5, lsr #7", 2, 32, 1, 7, 4, 5, 3, 0),
            ("eon x6, x7, x8, asr #2", 2, 64, 2, 2, 7, 8, 6, 0),
            ("bics x0, x1, x2", 3, 64, 0, 0, 1, 2, 0, 1),
            ("bics w3, w4, w5", 3, 32, 0, 0, 4, 5, 3, 1),
            ("bics x6, x7, x8, ror #4", 3, 64, 3, 4, 7, 8, 6, 1),
            ("bics xzr, x1, x2", 3, 64, 0, 0, 1, 2, 31, 1),
            ("mvn x9, x10", 1, 64, 0, 0, 31, 10, 9, 0),
            ("mvn w11, w12", 1, 32, 0, 0, 31, 12, 11, 0),
            ("mvn x13, x14, lsl #9", 1, 64, 0, 9, 31, 14, 13, 0),
            ("bic x15, xzr, x16", 0, 64, 0, 0, 31, 16, 15, 0),
            ("bic x17, x18, xzr", 0, 64, 0, 0, 18, 31, 17, 0)]

# One-source CLZ fixture: one instruction per line, in this exact order, so
# llvm-mc is the only encoder involved and the decoder metadata below is
# compared against the assembled words.
CLZ_ASM = r'''
.text
clz x11, x8
clz w11, w8
clz x0, xzr
clz w0, wzr
clz xzr, x0
clz wzr, w0
clz x9, x9
clz w18, w18
clz x19, x18
'''

#            text          sf width rn  rd
CLZ_ROWS = [("clz x11, x8", 64, 8, 11),
            ("clz w11, w8", 32, 8, 11),
            ("clz x0, xzr", 64, 31, 0),
            ("clz w0, wzr", 32, 31, 0),
            ("clz xzr, x0", 64, 0, 31),
            ("clz wzr, w0", 32, 0, 31),
            ("clz x9, x9", 64, 9, 9),
            ("clz w18, w18", 32, 18, 18),
            ("clz x19, x18", 64, 18, 19)]

# One-source RBIT fixture: one instruction per line, in this exact order, so
# llvm-mc is the only encoder involved and the decoder metadata below is
# compared against the assembled words.
RBIT_ASM = r'''
.text
rbit x9, x9
rbit w9, w9
rbit x0, xzr
rbit w0, wzr
rbit xzr, x0
rbit wzr, w0
rbit x11, x8
rbit w18, w18
rbit x19, x18
'''

#            text          width rn  rd
RBIT_ROWS = [("rbit x9, x9", 64, 9, 9),
             ("rbit w9, w9", 32, 9, 9),
             ("rbit x0, xzr", 64, 31, 0),
             ("rbit w0, wzr", 32, 31, 0),
             ("rbit xzr, x0", 64, 0, 31),
             ("rbit wzr, w0", 32, 0, 31),
             ("rbit x11, x8", 64, 8, 11),
             ("rbit w18, w18", 32, 18, 18),
             ("rbit x19, x18", 64, 18, 19)]

# Canonical DMB ISH plus every OTHER DMB/DSB/ISB option llvm-mc can encode,
# one instruction per line in this exact order. Only "dmb ish" is new and
# module-only; "dmb sy"/"dsb sy"/"isb" are the pre-existing SY forms.
DMB_ASM = r'''
.text
dmb ish
dmb ishst
dmb ishld
dmb nsh
dmb nshst
dmb nshld
dmb osh
dmb oshst
dmb oshld
dmb sy
dmb st
dmb ld
dsb ish
dsb sy
isb
'''

#            text        llvm-mc word  mnemonic  Capstone barrier option (None = no operand)
DMB_ROWS = [("dmb ish", 0xD5033BBF, "dmb", 0xB),
            ("dmb ishst", 0xD5033ABF, "dmb", 0xA),
            ("dmb ishld", 0xD50339BF, "dmb", 0x9),
            ("dmb nsh", 0xD50337BF, "dmb", 0x7),
            ("dmb nshst", 0xD50336BF, "dmb", 0x6),
            ("dmb nshld", 0xD50335BF, "dmb", 0x5),
            ("dmb osh", 0xD50333BF, "dmb", 0x3),
            ("dmb oshst", 0xD50332BF, "dmb", 0x2),
            ("dmb oshld", 0xD50331BF, "dmb", 0x1),
            ("dmb sy", 0xD5033FBF, "dmb", 0xF),
            ("dmb st", 0xD5033EBF, "dmb", 0xE),
            ("dmb ld", 0xD5033DBF, "dmb", 0xD),
            ("dsb ish", 0xD5033B9F, "dsb", 0xB),
            ("dsb sy", 0xD5033F9F, "dsb", 0xF),
            ("isb", 0xD5033FDF, "isb", None)]

# Two-source variable shift fixture (LSLV/LSRV/ASRV/RORV), one instruction
# per line in this exact order; llvm-mc assembles it below and each row is
# the architectural field of the mnemonic.
VS_ASM = r'''
.text
lsr x14, x10, x11
lsr w14, w10, w11
lsl x0, x1, x2
lsl w3, w4, w5
asr x6, x7, x8
asr w9, w10, w11
ror x12, x13, x14
ror w15, w16, w17
lsl x18, x18, x18
ror xzr, x0, x1
asr w21, w22, wzr
lsr x24, xzr, x25
lsl x7, x7, x0
'''

#            text                  sh width rm  rn  rd   (Rm, Rn, Rd as architected)
VS_ROWS = [("lsr x14, x10, x11", 1, 64, 11, 10, 14),
           ("lsr w14, w10, w11", 1, 32, 11, 10, 14),
           ("lsl x0, x1, x2", 0, 64, 2, 1, 0),
           ("lsl w3, w4, w5", 0, 32, 5, 4, 3),
           ("asr x6, x7, x8", 2, 64, 8, 7, 6),
           ("asr w9, w10, w11", 2, 32, 11, 10, 9),
           ("ror x12, x13, x14", 3, 64, 14, 13, 12),
           ("ror w15, w16, w17", 3, 32, 17, 16, 15),
           ("lsl x18, x18, x18", 0, 64, 18, 18, 18),
           ("ror xzr, x0, x1", 3, 64, 1, 0, 31),
           ("asr w21, w22, wzr", 2, 32, 31, 22, 21),
           ("lsr x24, xzr, x25", 1, 64, 25, 31, 24),
           ("lsl x7, x7, x0", 0, 64, 0, 7, 7)]

RUNNER = r'''/* generated by tests/aot/g3_newfamily_diff_test.py */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "aot_runtime.h"
#include "aot_mem.h"
#include "__IMG__"

#define DATA_BASE 0x3000000000ull
static uint8_t g_page[0x1000];
static uint64_t g_bad;

static int in_page(uint64_t a, unsigned n)
{
    return a >= DATA_BASE && a + n <= DATA_BASE + sizeof g_page;
}
AotMemStatus aot_mem_ld8(const AotMem *m, uint64_t a, uint8_t *o)
{ (void)m; if (!in_page(a,1)) return AOT_MEM_ERR_RANGE; *o = g_page[a-DATA_BASE]; return AOT_MEM_OK; }
AotMemStatus aot_mem_ld16(const AotMem *m, uint64_t a, uint16_t *o)
{ (void)m; if (!in_page(a,2)) return AOT_MEM_ERR_RANGE; memcpy(o, g_page+(a-DATA_BASE), 2); return AOT_MEM_OK; }
AotMemStatus aot_mem_ld32(const AotMem *m, uint64_t a, uint32_t *o)
{ (void)m; if (!in_page(a,4)) return AOT_MEM_ERR_RANGE; memcpy(o, g_page+(a-DATA_BASE), 4); return AOT_MEM_OK; }
AotMemStatus aot_mem_ld64(const AotMem *m, uint64_t a, uint64_t *o)
{ (void)m; if (!in_page(a,8)) return AOT_MEM_ERR_RANGE; memcpy(o, g_page+(a-DATA_BASE), 8); return AOT_MEM_OK; }
AotMemStatus aot_mem_ld128(const AotMem *m, uint64_t a, uint64_t o[2])
{ (void)m; if (!in_page(a,16)) return AOT_MEM_ERR_RANGE; memcpy(o, g_page+(a-DATA_BASE), 16); return AOT_MEM_OK; }
AotMemStatus aot_mem_st8(AotMem *m, uint64_t a, uint8_t v)
{ (void)m; if (!in_page(a,1)) return AOT_MEM_ERR_RANGE; g_page[a-DATA_BASE] = v; return AOT_MEM_OK; }
AotMemStatus aot_mem_st16(AotMem *m, uint64_t a, uint16_t v)
{ (void)m; if (!in_page(a,2)) return AOT_MEM_ERR_RANGE; memcpy(g_page+(a-DATA_BASE), &v, 2); return AOT_MEM_OK; }
AotMemStatus aot_mem_st32(AotMem *m, uint64_t a, uint32_t v)
{ (void)m; if (!in_page(a,4)) return AOT_MEM_ERR_RANGE; memcpy(g_page+(a-DATA_BASE), &v, 4); return AOT_MEM_OK; }
AotMemStatus aot_mem_st64(AotMem *m, uint64_t a, uint64_t v)
{ (void)m; if (!in_page(a,8)) return AOT_MEM_ERR_RANGE; memcpy(g_page+(a-DATA_BASE), &v, 8); return AOT_MEM_OK; }
AotMemStatus aot_mem_st128(AotMem *m, uint64_t a, const uint64_t v[2])
{ (void)m; if (!in_page(a,16)) return AOT_MEM_ERR_RANGE; memcpy(g_page+(a-DATA_BASE), v, 16); return AOT_MEM_OK; }
AotMemStatus aot_mem_lds8(const AotMem *m, uint64_t a, int64_t *o)
{ uint8_t v; AotMemStatus s = aot_mem_ld8(m,a,&v); *o = (int64_t)(int8_t)v; return s; }
AotMemStatus aot_mem_lds16(const AotMem *m, uint64_t a, int64_t *o)
{ uint16_t v; AotMemStatus s = aot_mem_ld16(m,a,&v); *o = (int64_t)(int16_t)v; return s; }
AotMemStatus aot_mem_lds32(const AotMem *m, uint64_t a, int64_t *o)
{ uint32_t v; AotMemStatus s = aot_mem_ld32(m,a,&v); *o = (int64_t)(int32_t)v; return s; }

/* MODEL-ONLY single-thread monitor for the DMB/exclusive fixture. This is a
   HARNESS MODEL, not the production monitor: it does not register anything
   and the runtime is given a nonzero token by the caller. A reservation is
   live only after a successful ldx; stx succeeds ONLY with a matching live
   reservation (same address and width) and otherwise reports status 1 without
   storing, so no success is fabricated. clrex clears it; DMB must NOT (that
   is the property under test here). The REAL aot_mem.c monitor path is
   exercised separately by the native runtime smoke, not by this stub. */
static struct { int live; uint64_t addr; unsigned width; } g_mon;
AotMemStatus aot_mem_ldx(AotMem *m, uint32_t token, uint64_t a, unsigned w, uint64_t *o)
{
    AotMemStatus s = AOT_MEM_OK;
    (void)token;
    if (w != 1u && w != 2u && w != 4u && w != 8u) return AOT_MEM_ERR_WIDTH;
    if ((a & (uint64_t)(w - 1u)) != 0u) return AOT_MEM_ERR_ALIGN;
    if (w == 8u) s = aot_mem_ld64(m, a, o);
    else if (w == 4u) { uint32_t v = 0; s = aot_mem_ld32(m, a, &v); *o = v; }
    else if (w == 2u) { uint16_t v = 0; s = aot_mem_ld16(m, a, &v); *o = v; }
    else { uint8_t v = 0; s = aot_mem_ld8(m, a, &v); *o = v; }
    if (s != AOT_MEM_OK) return s;
    g_mon.live = 1; g_mon.addr = a; g_mon.width = w;
    return AOT_MEM_OK;
}
AotMemStatus aot_mem_stx(AotMem *m, uint32_t token, uint64_t a, unsigned w,
                         uint64_t val, uint32_t *status)
{
    AotMemStatus s = AOT_MEM_OK;
    (void)token;
    if (w != 1u && w != 2u && w != 4u && w != 8u) return AOT_MEM_ERR_WIDTH;
    if ((a & (uint64_t)(w - 1u)) != 0u) return AOT_MEM_ERR_ALIGN;
    if (!g_mon.live || g_mon.addr != a || g_mon.width != w) {
        *status = 1u;
        return AOT_MEM_OK;
    }
    g_mon.live = 0;
    if (w == 8u) s = aot_mem_st64(m, a, val);
    else if (w == 4u) s = aot_mem_st32(m, a, (uint32_t)val);
    else if (w == 2u) s = aot_mem_st16(m, a, (uint16_t)val);
    else s = aot_mem_st8(m, a, (uint8_t)val);
    if (s != AOT_MEM_OK) return s;
    *status = 0u;
    return AOT_MEM_OK;
}
void aot_mem_clrex(AotMem *m, uint32_t token)
{ (void)m; (void)token; g_mon.live = 0; }
void aot_mem_fence(void) { /* single-threaded harness: ordering not observable */ }

static void dump(const AotGuestState *s, const AotRuntime *rt)
{
    unsigned i;
    unsigned long long h = 14695981039346656037ull;
    printf("X");
    for (i = 0; i < 31; i++) printf(" %016llx", (unsigned long long)s->x[i]);
    for (i = 0; i < sizeof g_page; i++) { h ^= g_page[i]; h *= 1099511628211ull; }
    printf(" SP %016llx NZCV %08llx NEXT %016llx FAULT %u SRC %016llx "
           "TARGET %016llx STATUS %lld PAGE %016llx BYTES ",
           (unsigned long long)s->sp, (unsigned long long)s->nzcv,
           (unsigned long long)rt->next_pc, (unsigned)rt->fault,
           (unsigned long long)rt->fault_src,
           (unsigned long long)rt->fault_target,
           (long long)rt->fault_status, h);
    for (i = 0; i < sizeof g_page; i++) printf("%02x", g_page[i]);
    printf(" TPIDR %016llx TPIDRRO %016llx Q",
           (unsigned long long)s->tpidr, (unsigned long long)s->tpidrro);
    for (i = 0; i < 32; i++)
        printf(" %016llx %016llx", (unsigned long long)s->v[i][0],
               (unsigned long long)s->v[i][1]);
    printf(" FPCR %08llx FPSR %08llx\n", (unsigned long long)s->fpcr,
           (unsigned long long)s->fpsr);
}

int main(int argc, char **argv)
{
    AotGuestState s;
    AotRuntime rt;
    unsigned i;
    unsigned long long seed;

    if (argc != 3 && argc != 4) { printf("usage: runner <entry-index> <seed> [x0]\n"); return 2; }
    seed = strtoull(argv[2], NULL, 0);
    memset(&s, 0, sizeof s);
    memset(&rt, 0, sizeof rt);
    for (i = 0; i < 31; i++) s.x[i] = 0x0101010101010101ull * (i + 1) ^ seed;
    s.sp = 0x2000000000ull + 0x800ull;
    /* HARNESS MODEL ONLY: the stub monitor above ignores tokens; a nonzero
       token just avoids the runtime's BAD_STATE precheck. Nothing is
       registered and no production monitor claim is made here. */
    rt.monitor_token = 0x5a5a5a5au;
    s.nzcv = (uint32_t)((0xA0000000u ^ (unsigned)seed) & 0xF0000000u);
    s.tpidr = 0xa5a5a5a0ull; s.tpidrro = 0x5a5a5a50ull;
    for (i = 0; i < 32; i++) {
        s.v[i][0] = 0x1111000000000000ull + i;
        s.v[i][1] = 0x2222000000000000ull + i;
    }
    s.fpcr = 0x03000000u; /* DN | FZ, supported by the pinned A57 */
    s.fpsr = 0x0800001fu; /* QC plus cumulative exception flags */
    s.x[30] = 0x1000000ff0ull;
    for (i = 0; i < sizeof g_page; i++) g_page[i] = (uint8_t)(i * 7u + 3u);
    s.x[20] = 0x3000000100ull;
    s.x[21] = 8u;
    s.x[0] = seed;
    s.x[1] = ~seed;
    s.x[2] = seed ^ 0xA5A5A5A5A5A5A5A5ull;
    if (argc == 4) s.x[0] = strtoull(argv[3], NULL, 0);
    {
        static const unsigned long long entries[] = { __ENTRIES__ };
        unsigned idx = (unsigned)strtoul(argv[1], NULL, 0);
        if (idx >= sizeof entries / sizeof entries[0]) return 2;
        switch (entries[idx]) {
__CASES__
        default: return 2;
        }
        (void)0;
    }
    dump(&s, &rt);
    fflush(stdout);
    return 0;
}
'''


def fail(msg):
    print("FAIL: " + msg)
    return 2


def infra(msg):
    print("infrastructure: " + msg)
    return 1


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--tools", default="tools/aot")
    ap.add_argument("--repo", default=".")
    ap.add_argument("--llvm", default=None,
                    help="LLVM bin directory (CMake passes its discovered "
                         "AOT_LLVM_BIN_DIR)")
    ap.add_argument("--opt", choices=("Od", "O2"), default="O2",
                    help="native MSVC optimization; always /W4 /WX")
    args = ap.parse_args(argv)
    if not args.llvm:
        args.llvm = os.environ.get("AOT_LLVM_BIN", "")
    if not args.llvm:
        for c in (glob.glob(r"C:/Program Files/LLVM/bin") +
                  glob.glob(os.path.expanduser("~/tools/LLVM/bin"))):
            if os.path.exists(os.path.join(c, "llvm-mc.exe")):
                args.llvm = c
                break
    if not args.llvm:
        return infra("LLVM bin dir not found (pass --llvm)")
    repo = os.path.abspath(args.repo)
    work = tempfile.mkdtemp(prefix="aot_newfam_")
    llvm_mc = os.path.join(args.llvm, "llvm-mc.exe")
    llvm_objcopy = os.path.join(args.llvm, "llvm-objcopy.exe")
    llvm_nm = os.path.join(args.llvm, "llvm-nm.exe")
    for p in (llvm_mc, llvm_objcopy, llvm_nm):
        if not os.path.exists(p):
            return infra("missing " + p)
    vhits = sorted(glob.glob(
        r"C:/Program Files/Microsoft Visual Studio/*/*/VC/Auxiliary/Build/vcvars64.bat"))
    if not vhits:
        return infra("vcvars64.bat not found")
    vcvars = vhits[-1]

    # ---- decode-level claims the emitted C cannot witness ----------------
    # The family is MODULE-ONLY (the G2 single-image subset must keep refusing
    # it) and the decode metadata must name the exact operands. Words are the
    # llvm-mc encodings above, not hand-assembled bit arithmetic.
    sys.path.insert(0, os.path.abspath(args.tools))
    try:
        import aot_translate as T
    except Exception as exc:                                  # noqa: BLE001
        return infra("cannot import aot_translate: %r" % (exc,))
    dec_rows = [("udiv x24,x8,x23", 0x9AD70918, "udiv", 64, 8, 23, 24),
                ("udiv w0,w1,w2", 0x1AC20820, "udiv", 32, 1, 2, 0),
                ("sdiv x3,x4,x5", 0x9AC50C83, "sdiv", 64, 4, 5, 3),
                ("sdiv w6,w7,w8", 0x1AC80CE6, "sdiv", 32, 7, 8, 6),
                ("udiv xzr,x0,x1", 0x9AC1081F, "udiv", 64, 0, 1, 31),
                ("sdiv x9,x9,xzr", 0x9ADF0D29, "sdiv", 64, 9, 31, 9)]
    for why, word, kind, width, rn, rm, rd in dec_rows:
        try:
            ins = T.decode(BASE, word, module=True)
        except T.DecodeError as exc:
            return infra("module decode refused %s: %s" % (why, exc))
        got = (ins["kind"], ins["width"], ins["rn"], ins["rm"], ins["rd"])
        if got != (kind, width, rn, rm, rd):
            return fail("%s: decode metadata %r != %r"
                        % (why, got, (kind, width, rn, rm, rd)))
        try:
            T.decode(BASE, word, module=False)
        except T.DecodeError:
            continue
        return fail("%s (0x%08x) leaked into the G2 single-image subset"
                    % (why, word))
    print("decode: %d UDIV/SDIV words module-only with exact operands"
          % len(dec_rows))

    # CCMP/CCMN: the encodings above were produced by llvm-mc, so the
    # CCMP/CCMN selector (bit 30), the immediate/register selector (bit 11),
    # cond (15:12) and nzcv (3:0) are the assembler's fields, not a sketch.
    # sub==1 means CCMP (compare => subtract), sub==0 CCMN (compare => add).
    cc_rows = [("ccmp w2,w3,#7,gt", 0x7A43C047, 32, 1, 12, 2, 3, None, 7),
               ("ccmn w2,w3,#7,gt", 0x3A43C047, 32, 0, 12, 2, 3, None, 7),
               ("ccmp w2,#7,#7,gt", 0x7A47C847, 32, 1, 12, 2, None, 7, 7),
               ("ccmn w2,#31,#15,gt", 0x3A5FC84F, 32, 0, 12, 2, None, 31, 15),
               ("ccmp x2,x3,#7,gt", 0xFA43C047, 64, 1, 12, 2, 3, None, 7),
               ("ccmn x2,x3,#7,gt", 0xBA43C047, 64, 0, 12, 2, 3, None, 7),
               ("ccmp x2,#31,#15,hi", 0xFA5F884F, 64, 1, 8, 2, None, 31, 15),
               ("ccmp x2,#17,#0,gt", 0xFA51C840, 64, 1, 12, 2, None, 17, 0),
               # the word that stopped the faithful Start prefix at step 382
               ("ccmp w8,#0,#0,eq (start)", 0x7A400900, 32, 1, 0, 8, None, 0, 0)]
    for why, word, width, sub, cond, rn, rm, imm, nzcv in cc_rows:
        try:
            ins = T.decode(BASE, word, module=True)
        except T.DecodeError as exc:
            return infra("module decode refused %s: %s" % (why, exc))
        got = (ins["kind"], ins["width"], ins["sub"], ins["cond"],
               ins["rn"], ins["nzcv"], ins["imm_form"],
               ins.get("rm"), ins.get("imm"))
        want = ("ccmp", width, sub, cond, rn, nzcv,
                1 if imm is not None else 0, rm, imm)
        if got != want:
            return fail("%s: decode metadata %r != %r" % (why, got, want))
        try:
            T.decode(BASE, word, module=False)
        except T.DecodeError:
            continue
        return fail("%s (0x%08x) leaked into the G2 single-image subset"
                    % (why, word))
    # Reserved: bit 4 ("o3") and bit 10 are fixed 0 in the allocated class
    # (llvm-mc reports "invalid instruction encoding" for both when set), so
    # a set bit must fail closed instead of decoding as something.
    for why, word in (("ccmp o3 bit4 set", 0x7A43C057),
                      ("ccmp bit10 set", 0x7A43C447),
                      ("ccmp bit11+10 set", 0x7A43CC47),
                      ("ccmp op bit29 clear", 0x1A43C047)):
        try:
            T.decode(BASE, word, module=True)
        except T.DecodeError:
            continue
        return fail("%s (0x%08x) decoded instead of failing closed"
                    % (why, word))
    print("decode: %d CCMP/CCMN words module-only with exact fields, "
          "4 reserved words refused" % len(cc_rows))

    # ---- inverted logical (BIC/ORN/EON/BICS) decode metadata ------------
    # The words are ASSEMBLED here by llvm-mc: the expectations are the
    # architectural fields of the mnemonic, never hand-encoded bit patterns.
    inv_s = os.path.join(work, "inv.s")
    open(inv_s, "w").write(INV_ASM)
    inv_o = os.path.join(work, "inv.o")
    inv_b = os.path.join(work, "inv.bin")
    if subprocess.run([llvm_mc, "-triple=aarch64-none-elf", "-filetype=obj",
                       "-o", inv_o, inv_s], capture_output=True,
                      text=True).returncode != 0:
        return infra("llvm-mc refused the inverted-logical fixture")
    if subprocess.run([llvm_objcopy, "-O", "binary", "--only-section=.text",
                       inv_o, inv_b], capture_output=True,
                      text=True).returncode != 0:
        return infra("llvm-objcopy failed for the inverted-logical fixture")
    inv_raw = open(inv_b, "rb").read()
    words = struct.unpack("<%dI" % (len(inv_raw) // 4), inv_raw)
    if len(words) != len(INV_ROWS):
        return infra("inverted-logical fixture has %d words, wanted %d"
                     % (len(words), len(INV_ROWS)))
    inv_checked = 0
    for word, row in zip(words, INV_ROWS):
        text, op, width, shift, imm6, rn, rm, rd, s = row
        try:
            ins = T.decode(BASE, word, module=True)
        except T.DecodeError as exc:
            return fail("module decode refused %s (0x%08x): %s"
                        % (text, word, exc))
        got = (ins["kind"], ins["op"], ins["width"], ins["shift"],
               ins["imm6"], ins["rn"], ins["rm"], ins["rd"], ins["s"],
               ins.get("invert"))
        want = ("logic_shift", op, width, shift, imm6, rn, rm, rd, s, 1)
        if got != want:
            return fail("%s (0x%08x): decode metadata %r != %r"
                        % (text, word, got, want))
        try:
            T.decode(BASE, word, module=False)
        except T.DecodeError:
            inv_checked += 1
            continue
        return fail("%s (0x%08x) leaked into the G2 single-image subset"
                    % (text, word))
    # Reserved W encodings: imm6 bit 5 is RESERVED for 32-bit forms, so both
    # widths' "shift amount out of range" refusal must survive for N=1 too.
    for why, word in (("bic w0,w1,w2,lsl#32", 0x0A228020),
                      ("bic w0,w1,w2,ror#32", 0x0AE28020),
                      ("orn w0,w1,w2,lsr#40", 0x2A628020),
                      ("eon w0,w1,w2,asr#63", 0x4A828020),
                      ("bics w0,w1,w2,lsl#32", 0x6A228020)):
        try:
            T.decode(BASE, word, module=True)
        except T.DecodeError:
            continue
        return fail("%s (0x%08x) decoded instead of failing closed"
                    % (why, word))
    print("decode: %d inverted-logical words assembled by llvm-mc, module-only "
          "with exact fields, 5 reserved W words refused" % inv_checked)

    # ---- one-source CLZ decode metadata --------------------------------
    # Every expectation below is the ARCHITECTURAL field of the mnemonic; the
    # words come from llvm-mc. The fixed-field mask is proven on the real boot
    # word 0xdac0110b (clz x11, x8) and the whole adjacent group must refuse.
    clz_s = os.path.join(work, "clz.s")
    open(clz_s, "w").write(CLZ_ASM)
    clz_o = os.path.join(work, "clz.o")
    clz_b = os.path.join(work, "clz.bin")
    if subprocess.run([llvm_mc, "-triple=aarch64-none-elf", "-filetype=obj",
                       "-o", clz_o, clz_s], capture_output=True,
                      text=True).returncode != 0:
        return infra("llvm-mc refused the CLZ fixture")
    if subprocess.run([llvm_objcopy, "-O", "binary", "--only-section=.text",
                       clz_o, clz_b], capture_output=True,
                      text=True).returncode != 0:
        return infra("llvm-objcopy failed for the CLZ fixture")
    clz_raw = open(clz_b, "rb").read()
    clz_words = struct.unpack("<%dI" % (len(clz_raw) // 4), clz_raw)
    if len(clz_words) != len(CLZ_ROWS):
        return infra("CLZ fixture has %d words, wanted %d"
                     % (len(clz_words), len(CLZ_ROWS)))
    for word, (text, width, rn, rd) in zip(clz_words, CLZ_ROWS):
        try:
            ins = T.decode(BASE, word, module=True)
        except T.DecodeError as exc:
            return fail("module decode refused %s (0x%08x): %s"
                        % (text, word, exc))
        got = (ins["kind"], ins["width"], ins["rn"], ins["rd"])
        want = ("clz", width, rn, rd)
        if got != want:
            return fail("%s (0x%08x): decode metadata %r != %r"
                        % (text, word, got, want))
        if (word & 0x7FFFFC00) != 0x5AC01000:
            return fail("%s (0x%08x) escapes the fixed CLZ mask"
                        % (text, word))
        try:
            T.decode(BASE, word, module=False)
        except T.DecodeError:
            continue
        return fail("%s (0x%08x) leaked into the G2 single-image subset"
                    % (text, word))
    # The word that stopped the real G3 boot must decode as CLZ X, Rn=8, Rd=11.
    if clz_words[0] != 0xDAC0110B:
        return fail("clz x11,x8 assembled to 0x%08x, not the boot word "
                    "0xdac0110b" % clz_words[0])
    # Adjacent one-source forms must fail closed (no class widening). CBIT/CLZ
    # share the class mask, so each reserved field value is pinned separately
    # for BOTH operations.
    for why, word in (("rev16 w0,w0", 0x5AC00400),
                      ("rev16 x0,x0", 0xDAC00400),
                      ("rev/rev32 opcode2=2", 0x5AC00800),
                      ("rev opcode2=3", 0xDAC00C00),
                      ("cls x0,x0", 0x5AC01400),
                      ("opcode2=6", 0x5AC01800),
                      ("opcode=1 opcode2=4", 0x5AC11000),
                      ("rbit with S bit set (bit 29)", 0x7AC00000),
                      ("rbit with bit 30 clear", 0x1AC00029),
                      ("rbit with opcode=8", 0x5AC80029),
                      ("clz with sf/bit29 flipped", 0x7AC01000)):
        try:
            T.decode(BASE, word, module=True)
        except T.DecodeError:
            continue
        return fail("%s (0x%08x) decoded instead of failing closed"
                    % (why, word))
    print("decode: %d one-source CLZ words assembled by llvm-mc, module-only "
          "with exact fields (boot word 0xdac0110b in the set), 8 adjacent "
          "one-source words refused" % len(CLZ_ROWS))

    # ---- one-source RBIT decode metadata --------------------------------
    # Same fixed mask as CLZ with opcode2 == 0b000000. The first word is the
    # exact word that stopped the real G3 boot (0xdac00129, rbit x9, x9); the
    # words come from llvm-mc, never from bit arithmetic here.
    rb_s = os.path.join(work, "rb.s")
    open(rb_s, "w").write(RBIT_ASM)
    rb_o = os.path.join(work, "rb.o")
    rb_b = os.path.join(work, "rb.bin")
    if subprocess.run([llvm_mc, "-triple=aarch64-none-elf", "-filetype=obj",
                       "-o", rb_o, rb_s], capture_output=True,
                      text=True).returncode != 0:
        return infra("llvm-mc refused the RBIT fixture")
    if subprocess.run([llvm_objcopy, "-O", "binary", "--only-section=.text",
                       rb_o, rb_b], capture_output=True,
                      text=True).returncode != 0:
        return infra("llvm-objcopy failed for the RBIT fixture")
    rb_raw = open(rb_b, "rb").read()
    rb_words = struct.unpack("<%dI" % (len(rb_raw) // 4), rb_raw)
    if len(rb_words) != len(RBIT_ROWS):
        return infra("RBIT fixture has %d words, wanted %d"
                     % (len(rb_words), len(RBIT_ROWS)))
    if rb_words[0] != 0xDAC00129:
        return fail("rbit x9,x9 assembled to 0x%08x, not the real boot word "
                    "0xdac00129" % rb_words[0])
    for word, (text, width, rn, rd) in zip(rb_words, RBIT_ROWS):
        try:
            ins = T.decode(BASE, word, module=True)
        except T.DecodeError as exc:
            return fail("module decode refused %s (0x%08x): %s"
                        % (text, word, exc))
        got = (ins["kind"], ins["width"], ins["rn"], ins["rd"])
        want = ("rbit", width, rn, rd)
        if got != want:
            return fail("%s (0x%08x): decode metadata %r != %r"
                        % (text, word, got, want))
        if (word & 0x7FFFFC00) != 0x5AC00000:
            return fail("%s (0x%08x) escapes the fixed RBIT mask"
                        % (text, word))
        try:
            T.decode(BASE, word, module=False)
        except T.DecodeError:
            continue
        return fail("%s (0x%08x) leaked into the G2 single-image subset"
                    % (text, word))
    print("decode: %d one-source RBIT words assembled by llvm-mc, module-only "
          "with exact fields (boot word 0xdac00129 in the set)"
          % len(RBIT_ROWS))

    # ---- DMB ISH decode + full DMB/DSB/ISB option grid -------------------
    # llvm-mc assembles every option it can encode; only the canonical
    # zero-register DMB ISH (0xd5033bbf, the exact word that stopped the real
    # G3 boot) may be NEW, and it is module-only. dsb ish/ishst/..., dmb
    # ishst/ishld/nsh*/osh*/st/ld MUST stay refused, while the three legacy SY
    # barrier words keep their pre-existing (both-mode) acceptance.
    dm_s = os.path.join(work, "dmb.s")
    open(dm_s, "w").write(DMB_ASM)
    dm_o = os.path.join(work, "dmb.o")
    dm_b = os.path.join(work, "dmb.bin")
    if subprocess.run([llvm_mc, "-triple=aarch64-none-elf", "-filetype=obj",
                       "-o", dm_o, dm_s], capture_output=True,
                      text=True).returncode != 0:
        return infra("llvm-mc refused a DMB/DSB/ISB option")
    if subprocess.run([llvm_objcopy, "-O", "binary", "--only-section=.text",
                       dm_o, dm_b], capture_output=True,
                      text=True).returncode != 0:
        return infra("llvm-objcopy failed for the DMB fixture")
    dm_raw = open(dm_b, "rb").read()
    dm_words = struct.unpack("<%dI" % (len(dm_raw) // 4), dm_raw)
    if len(dm_words) != len(DMB_ROWS):
        return infra("DMB fixture has %d words, wanted %d"
                     % (len(dm_words), len(DMB_ROWS)))
    try:
        import capstone as _cs
        from capstone import CS_ARCH_ARM64 as _A, CS_MODE_ARM as _M
        from capstone.arm64 import ARM64_OP_BARRIER as _B
        md = _cs.Cs(_A, _M)
        md.detail = True
    except Exception as exc:                                  # noqa: BLE001
        return infra("capstone detail unavailable: %r" % (exc,))
    old_sy = (0xD5033FBF, 0xD5033F9F, 0xD5033FDF)
    for word, (text, want_word, mnem, bopt) in zip(dm_words, DMB_ROWS):
        if word != want_word:
            return fail("%s assembled to 0x%08x, not the pinned 0x%08x"
                        % (text, word, want_word))
        ins_list = list(md.disasm(word.to_bytes(4, "little"), BASE))
        if len(ins_list) != 1:
            return infra("Capstone failed to decode 0x%08x (%s)" % (word, text))
        ci = ins_list[0]
        if ci.mnemonic != mnem:
            return fail("0x%08x: Capstone mnemonic %r != %r"
                        % (word, ci.mnemonic, mnem))
        if mnem == "isb":
            if ci.operands:
                return fail("isb 0x%08x unexpectedly has an operand" % word)
        else:
            if len(ci.operands) != 1 or ci.operands[0].type != _B:
                return fail("0x%08x: Capstone barrier operand missing" % word)
            if ci.operands[0].barrier != bopt:
                return fail("0x%08x: Capstone option %d != %d"
                            % (word, ci.operands[0].barrier, bopt))
        is_new = text == "dmb ish"
        is_old = word in old_sy
        if is_new or is_old:
            try:
                ins = T.decode(BASE, word, module=True)
            except T.DecodeError as exc:
                return fail("module decode refused %s (0x%08x): %s"
                            % (text, word, exc))
            if ins["kind"] != "barrier":
                return fail("%s decoded as %r" % (text, ins["kind"]))
            if is_new:
                if ins.get("option") != "ish":
                    return fail("dmb ish metadata %r lacks option ish" % (ins,))
                try:
                    T.decode(BASE, word, module=False)
                except T.DecodeError:
                    pass
                else:
                    return fail("dmb ish (0x%08x) leaked into the G2 "
                                "single-image subset" % word)
            else:
                if "option" in ins:
                    return fail("legacy SY barrier %s gained an option field"
                                % text)
                if T.decode(BASE, word, module=False)["kind"] != "barrier":
                    return fail("legacy SY barrier %s changed under G2" % text)
        else:
            for mode in (True, False):
                try:
                    T.decode(BASE, word, module=mode)
                except T.DecodeError:
                    continue
                return fail("%s (0x%08x) decoded with module=%r instead of "
                            "failing closed" % (text, word, mode))
    print("decode: %d DMB/DSB/ISB options assembled by llvm-mc, Capstone "
          "mnemonic+option agreed; only dmb ish (0xd5033bbf) is new and "
          "module-only, legacy SY unchanged" % len(DMB_ROWS))

    # ---- two-source variable shift decode metadata -----------------------
    vs_s = os.path.join(work, "vs.s")
    open(vs_s, "w").write(VS_ASM)
    vs_o = os.path.join(work, "vs.o")
    vs_b = os.path.join(work, "vs.bin")
    if subprocess.run([llvm_mc, "-triple=aarch64-none-elf", "-filetype=obj",
                       "-o", vs_o, vs_s], capture_output=True,
                      text=True).returncode != 0:
        return infra("llvm-mc refused the variable-shift fixture")
    if subprocess.run([llvm_objcopy, "-O", "binary", "--only-section=.text",
                       vs_o, vs_b], capture_output=True,
                      text=True).returncode != 0:
        return infra("llvm-objcopy failed for the variable-shift fixture")
    vs_raw = open(vs_b, "rb").read()
    vs_words = struct.unpack("<%dI" % (len(vs_raw) // 4), vs_raw)
    if len(vs_words) != len(VS_ROWS):
        return infra("variable-shift fixture has %d words, wanted %d"
                     % (len(vs_words), len(VS_ROWS)))
    if vs_words[0] != 0x9ACB254E:
        return infra("lsr x14,x10,x11 assembled to 0x%08x, not the real boot "
                     "word 0x9acb254e" % vs_words[0])
    for word, (text, shift, width, rm, rn, rd) in zip(vs_words, VS_ROWS):
        try:
            ins = T.decode(BASE, word, module=True)
        except T.DecodeError as exc:
            return fail("module decode refused %s (0x%08x): %s"
                        % (text, word, exc))
        got = (ins["kind"], ins["shift"], ins["width"], ins["rm"],
               ins["rn"], ins["rd"])
        want = ("varshift", shift, width, rm, rn, rd)
        if got != want:
            return fail("%s (0x%08x): decode metadata %r != %r"
                        % (text, word, got, want))
        if (word & 0x7FE0FC00) not in (0x1AC02000, 0x1AC02400,
                                       0x1AC02800, 0x1AC02C00):
            return fail("%s (0x%08x) escapes the fixed class mask"
                        % (text, word))
        try:
            T.decode(BASE, word, module=False)
        except T.DecodeError:
            continue
        return fail("%s (0x%08x) leaked into the G2 single-image subset"
                    % (text, word))
    for why, word in (("opcode=0b000100 reserved", 0x1AC01000),
                      ("opcode=0b0011xx reserved", 0x1AC03000),
                      ("bit29 (S) set", 0x3AC02000),
                      ("bit30 set", 0x5AC02400)):
        try:
            T.decode(BASE, word, module=True)
        except T.DecodeError:
            continue
        return fail("%s (0x%08x) decoded instead of failing closed"
                    % (why, word))
    print("decode: %d two-source variable-shift words assembled by llvm-mc, "
          "module-only with exact fields (boot word 0x9acb254e in the set), "
          "4 reserved/adjacent words refused" % len(VS_ROWS))

    sp = os.path.join(work, "fx.s")
    open(sp, "w").write(ASM)
    obj = os.path.join(work, "fx.o")
    binp = os.path.join(work, "fx.bin")
    mc = subprocess.run([llvm_mc, "-triple=aarch64-none-elf", "-filetype=obj",
                         "-o", obj, sp], capture_output=True, text=True)
    if mc.returncode != 0:
        return infra("llvm-mc failed: %s" % (mc.stdout + mc.stderr))
    if subprocess.run([llvm_objcopy, "-O", "binary", "--only-section=.text",
                       obj, binp], capture_output=True, text=True
                      ).returncode != 0:
        return infra("llvm-objcopy failed")
    raw = open(binp, "rb").read()
    nm = subprocess.run([llvm_nm, "-n", "--defined-only", obj],
                        capture_output=True, text=True)
    syms = {}
    for line in nm.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] == "T":
            syms[parts[2]] = int(parts[0], 16)
    need = ["t_alu", "t_inv", "t_inv_flags", "t_mem", "t_mulh",
            "t_umulh", "t_umulh_alias", "t_mul",
            "t_div", "t_div_alias",
            "t_div_overflow", "t_tbz31", "t_tbz32",
            "t_tbnz63", "t_fault",
            "t_msr", "t_msr8", "t_msr30", "t_msr31",
            "t_ccmp_imm", "t_ccmp_reg", "t_ccmp_cond", "t_ccmp_edge",
            "t_clz", "t_clz_w", "t_clz_zero", "t_clz_flags",
            "t_rbit", "t_rbit_w", "t_rbit_zero", "t_rbit_flags",
            "t_dmb", "t_dmb_flags", "t_dmb_excl",
            "t_vs", "t_vs_amt"]
    for n in need:
        if n not in syms:
            return infra("symbol %s missing" % n)
    lay = {"name": "fx", "image_size": len(raw), "bss_size": 0,
           "bss_start": len(raw), "bss_end": len(raw), "text": [0, len(raw)],
           "ro": [len(raw), len(raw)], "data": [len(raw), len(raw)],
           "dynsym_count": 0,
           "sha256": hashlib.sha256(raw).hexdigest()}
    lp = os.path.join(work, "fx.layout.json")
    json.dump(lay, open(lp, "w"))
    ep = os.path.join(work, "fx.entries.json")
    json.dump([BASE + syms[n] for n in need], open(ep, "w"))

    entries = [BASE + syms[n] for n in need]
    img = os.path.join(work, "fx_img.c")

    def translate(mutant, out):
        cmd = [sys.executable, os.path.join(os.path.abspath(args.tools),
                                            "aot_translate.py"),
               "--module", "--flat", binp, "--layout", lp,
               "--guest-base", "0x%x" % BASE, "--entries", ep,
               "--name", "fx", "--out", out]
        if mutant:
            cmd[2:2] = ["--mutant", mutant]
        return subprocess.run(cmd, capture_output=True, text=True)

    p = translate(None, img)
    if p.returncode != 0:
        return infra("translation failed: " + p.stderr)

    cases = "\n".join(
        ('        case 0x%xull: s.x[20] = DATA_BASE; (void)aot_blk_%x(&s, &rt); break;'
         if n == "t_fault" else
         '        case 0x%xull: (void)aot_blk_%x(&s, &rt); break;') % (e, e)
        for e, n in zip(entries, need))
    runner = os.path.join(work, "runner.c")
    open(runner, "w").write(
        RUNNER.replace("__IMG__", "fx_img.c").replace(
            "__ENTRIES__", ", ".join("0x%xull" % e for e in entries)
        ).replace("__CASES__", cases))

    def build(cdir, src_img):
        os.makedirs(cdir, exist_ok=True)
        shutil.copy(src_img, os.path.join(cdir, "fx_img.c"))
        shutil.copy(runner, os.path.join(cdir, "runner.c"))
        exe = os.path.join(cdir, "runner.exe")
        bat = os.path.join(cdir, "build.bat")
        with open(bat, "w", encoding="ascii") as f:
            f.write('@call "%s" >nul\r\n' % vcvars.replace("/", "\\"))
            f.write(f'cl /nologo /W4 /WX /{args.opt} /std:c11 /D_CRT_SECURE_NO_WARNINGS '
                    '/Fo:"%s\\\\" /I"%s" /I"%s" /Fe:"%s" "%s"\r\n'
                    % (cdir.replace("/", "\\"),
                       os.path.join(repo, "src", "aot").replace("/", "\\"),
                       os.path.join(repo, "src").replace("/", "\\"),
                       exe.replace("/", "\\"),
                       os.path.join(cdir, "runner.c").replace("/", "\\")))
        cp = subprocess.run([bat], capture_output=True, text=True)
        if cp.returncode != 0:
            print(cp.stdout, cp.stderr, file=sys.stderr)
            return None
        return exe

    import shutil
    real_dir = os.path.join(work, "real")
    os.makedirs(real_dir)
    shutil.copy(img, os.path.join(real_dir, "fx_img.c"))
    exe = build(real_dir, img)
    if exe is None:
        return infra("real image compile failed")

    # ---- Unicorn reference ------------------------------------------------
    try:
        from unicorn import (Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM,
                             UC_PROT_ALL, UC_ERR_READ_UNMAPPED,
                             UC_ERR_WRITE_UNMAPPED)
        from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X29,
                                         UC_ARM64_REG_X30, UC_ARM64_REG_SP,
                                         UC_ARM64_REG_PC, UC_ARM64_REG_NZCV,
                                         UC_ARM64_REG_TPIDR_EL0,
                                         UC_ARM64_REG_TPIDRRO_EL0,
                                         UC_ARM64_REG_Q0, UC_ARM64_REG_FPCR,
                                         UC_ARM64_REG_FPSR,
                                         UC_CPU_ARM64_A57)
    except Exception as exc:
        return infra("unicorn unavailable: %r" % (exc,))
    try:
        probe = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        probe.ctl_set_cpu_model(UC_CPU_ARM64_A57)
    except NameError:
        return infra("Unicorn has no UC_CPU_ARM64_A57; cannot pin the oracle")
    except UcError as exc:
        return infra("ctl_set_cpu_model(ARM64_A57) failed: %r" % (exc,))
    print("oracle: unicorn %s pinned to ARM64_A57"
          % getattr(__import__("unicorn"), "__version__", "unknown"))
    XR = [UC_ARM64_REG_X0 + i for i in range(29)] + [UC_ARM64_REG_X29,
                                                     UC_ARM64_REG_X30]

    def page_pattern():
        return bytes((i * 7 + 3) & 0xff for i in range(PAGE))

    results = {}
    bit_of = {"t_tbz31": 31, "t_tbz32": 32, "t_tbnz63": 63}
    LR = 0x1000000ff0
    MULH_EDGES = [0, 1, 2, 0x7FFFFFFFFFFFFFFF, 0x8000000000000000,
                  0xFFFFFFFFFFFFFFFF, 0xAAAAAAAAAAAAAAAA, 0x5555555555555555,
                  0x0000000100000000, 0x00000000FFFFFFFF, 0xDEADBEEFCAFEBABE,
                  0x0123456789ABCDEF]

    # UMULH operand PAIRS (x0 = a, x1 = b).  The runner maps these to
    # seed = ~b and the x0 override, so both operands are independent (not
    # complements).  Chosen to separate unsigned from signed high halves
    # (MSB-set operands), 32-bit limb carries (`mid` overflow), high-vs-low
    # products and the 2^32 +- 1 / alternating / all-ones edges.
    UMULH_PAIRS = [
        (0, 0), (0, 0xFFFFFFFFFFFFFFFF), (1, 0xFFFFFFFFFFFFFFFF),
        (0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF),
        (0x8000000000000000, 1), (1, 0x8000000000000000),
        (0x8000000000000000, 0x8000000000000000),
        (0x8000000000000000, 0xFFFFFFFFFFFFFFFF),
        (0x7FFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF),
        (0x7FFFFFFFFFFFFFFF, 0x8000000000000000),
        (0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF),
        (0x0000000100000001, 0x0000000100000001),
        (0x00000000FFFFFFFF, 0x0000000100000000),
        (0x0000000100000000, 0x00000000FFFFFFFF),
        (0x0000000100000000, 0x0000000100000000),
        (0xFFFFFFFF00000000, 0xFFFFFFFF00000000),
        (0xFFFFFFFF00000001, 0xFFFFFFFF00000001),
        (0xAAAAAAAAAAAAAAAA, 0x5555555555555555),
        (0x5555555555555555, 0xAAAAAAAAAAAAAAAA),
        (0xDEADBEEFCAFEBABE, 0x0123456789ABCDEF),
        (0x0123456789ABCDEF, 0xFEDCBA9876543210),
        (0x0000000100000000, 0xFFFFFFFFFFFFFFFF),
    ]

    DIV_EDGES = [0, 1, 2, 3, 7, 0x7FFFFFFFFFFFFFFF, 0x8000000000000000,
                 0xFFFFFFFFFFFFFFFF, 0x0000000080000000, 0x00000000FFFFFFFF,
                 0xFFFFFFFF00000000, 0x80000000FFFFFFFF,
                 0xAAAAAAAAAAAAAAAA, 0x5555555555555555]

    # Carry/overflow corners for CCMP/CCMN operands (32- and 64-bit limbs).
    CCMP_EDGES = [0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
                  0x7FFFFFFFFFFFFFFF, 0x8000000000000000,
                  0xFFFFFFFFFFFFFFFF]
    # Seeds whose bits 31:28 select a distinct ARCHITECTURAL incoming NZCV:
    # the runner/Unicorn both seed s->nzcv = (0xA0000000 ^ seed) & 0xF0000000,
    # so 0x0 -> 0xA (N1Z0C1V0), 0x10000000 -> 0xB (N1Z0C1V1),
    # 0x40000000 -> 0xE (N1Z1C1V0), 0xF0000000 -> 0x5 (N0Z1C0V1).
    # x1 = ~seed and x2 = seed ^ 0xA5A5... vary with them as well.
    CCMP_SEEDS = [0x0, 0x10000000, 0x40000000, 0xF0000000]

    def parse_dump(text):
        """Strict field parse. None = malformed (infrastructure, never a
        rejected mutant and never a comparison)."""
        toks = text.strip().split()
        labels = {0: "X", 32: "SP", 34: "NZCV", 36: "NEXT", 38: "FAULT",
                  40: "SRC", 42: "TARGET", 44: "STATUS", 46: "PAGE",
                  48: "BYTES", 50: "TPIDR", 52: "TPIDRRO", 54: "Q",
                  119: "FPCR", 121: "FPSR"}
        if len(toks) != 123 or any(toks[i] != v for i, v in labels.items()):
            return None
        try:
            xs = [int(v, 16) for v in toks[1:32]]
            d = {"SP": int(toks[33], 16), "NZCV": int(toks[35], 16),
                 "NEXT": int(toks[37], 16), "FAULT": int(toks[39]),
                 "SRC": int(toks[41], 16), "TARGET": int(toks[43], 16),
                 "STATUS": int(toks[45]), "PAGE": int(toks[47], 16),
                 "BYTES": toks[49].lower(),
                 "TPIDR": int(toks[51], 16), "TPIDRRO": int(toks[53], 16),
                 "Q": [(int(toks[55+2*i], 16), int(toks[56+2*i], 16))
                       for i in range(32)],
                 "FPCR": int(toks[120], 16), "FPSR": int(toks[122], 16)}
            for i, v in enumerate(xs):
                d["x%d" % i] = v
            if len(d["BYTES"]) != PAGE * 2:
                return None
            bytes.fromhex(d["BYTES"])
        except (ValueError, IndexError):
            return None
        return d

    # CLZ operand edges: zero, MSB set, LSB set, mixed, and the high/low 32
    # halves kept distinct so a 64-bit count on a W form is visible.
    CLZ_EDGES = [0, 1, 2, 0x8000000000000000, 0x7FFFFFFFFFFFFFFF,
                 0x0000000100000000, 0x0000000080000000,
                 0xFFFFFFFF00000000, 0x00000000FFFFFFFF,
                 0x0123456789ABCDEF, 0x5555555555555555]

    # Variable-shift operand edges: zero, MSB, LSB, mixed, and both ways of
    # making the upper and lower halves disagree.
    VS_EDGES = [0, 1, 0x8000000000000000, 0x7FFFFFFFFFFFFFFF,
                0x0000000080000000, 0x0000000100000000,
                0xFFFFFFFF00000000, 0x00000000FFFFFFFF,
                0x0123456789ABCDEF, 0x5555555555555555,
                0x00000000000000FF]
    # Shift-amount edges: 0, 1, w-1, w, w+1, 2w-1 (both widths share the same
    # fixture), UINT64_MAX, and high-bit-only values. Masking the LOW 5/6 bits
    # is the only rule that makes all of them agree with the hardware.
    VS_AMOUNTS = [0, 1, 31, 32, 33, 63, 64, 65, 127, 0xFFFFFFFFFFFFFFFF,
                  0x8000000000000000, 0x0000000100000000,
                  0xFFFFFFFFFFFFFFE0, 0x00000000FFFFFFC1]

    # RBIT operand edges: zero, all ones, every SINGLE bit at both widths and
    # the high/low 32 halves kept distinct so a 64-bit reversal on a W form is
    # visible in the destination's upper half.
    RBIT_EDGES = ([0] + [1 << i for i in range(64)] +
                  [0xFFFFFFFFFFFFFFFF, 0xAAAAAAAAAAAAAAAA,
                   0x5555555555555555, 0xDEADBEEFCAFEBABE,
                   0x0123456789ABCDEF, 0x7FFFFFFFFFFFFFFF,
                   0x8000000000000000, 0x0000000100000000,
                   0xFFFFFFFF00000000, 0x00000000FFFFFFFF,
                   0xFF00FF00FF00FF00, 0x00FF00FF00FF00FF])
    # All SIXTEEN architectural NZCV nibbles (the runner seeds
    # nzcv = (0xA0000000 ^ seed) & 0xF0000000, so seed i << 28 maps 1:1).
    RBIT_NZCV_SEEDS = [i << 28 for i in range(16)]
    RBIT_NZCV_VALUES = [0x0123456789ABCDEF, 0xFFFFFFFF00000000,
                        0x00000000FFFFFFFF, 0xFFFFFFFFFFFFFFFF]

    def scen_for(name):
        if name == "t_dmb":
            # ordinary accesses around the barrier; all 16 NZCV nibbles with
            # one fixed operand per width and a live high half.
            return [(seed, v) for seed in RBIT_NZCV_SEEDS
                    for v in (0x0123456789ABCDEF, 0xFFFFFFFF00000000)]
        if name == "t_dmb_flags":
            return [(seed, v) for seed in RBIT_NZCV_SEEDS
                    for v in (0x0123456789ABCDEF, 0x00000000FFFFFFFF)]
        if name == "t_dmb_excl":
            return [(seed, v) for seed in RBIT_NZCV_SEEDS
                    for v in (0x0123456789ABCDEF, 0xFFFFFFFFFFFFFFFF)]
        if name in ("t_rbit", "t_rbit_w"):
            out = [(seed, v) for seed in (0x0, 0xF0000000)
                   for v in RBIT_EDGES]
            out += [(seed, v) for seed in RBIT_NZCV_SEEDS
                    for v in RBIT_NZCV_VALUES]
            return out
        if name == "t_rbit_zero":
            return [(seed, None) for seed in RBIT_NZCV_SEEDS]
        if name == "t_rbit_flags":
            return [(seed, v) for seed in RBIT_NZCV_SEEDS
                    for v in RBIT_NZCV_VALUES]
        if name in ("t_clz", "t_clz_w", "t_clz_flags"):
            # All four architectural NZCV seeds: CLZ must preserve them.
            return [(seed, v) for seed in CCMP_SEEDS for v in CLZ_EDGES]
        if name == "t_clz_zero":
            return [(seed, None) for seed in CCMP_SEEDS]
        if name == "t_vs":
            # value edges with a fixed in-range amount, all four NZCV seeds.
            return [(seed, v) for seed in CCMP_SEEDS for v in VS_EDGES]
        if name == "t_vs_amt":
            # amount edges (incl. huge / >= width) on one mixed value.
            return [(0x5A5A5A5A ^ a, 0x0123456789ABCDEF)
                    for a in VS_AMOUNTS]
        if name in bit_of:
            return [(0, 0), (0, (1 << bit_of[name]))]
        if name in ("t_mulh", "t_mul"):
            return [(0, v) for v in MULH_EDGES]
        if name in ("t_umulh", "t_umulh_alias"):
            out = [((~b) & 0xFFFFFFFFFFFFFFFF, a) for a, b in UMULH_PAIRS]
            if name == "t_umulh":
                # every architectural NZCV nibble with the seed pair
                # (x0 = seed, x1 = ~seed)
                out += [(seed, None) for seed in RBIT_NZCV_SEEDS]
            return out
        if name.startswith("t_div"):
            # seed == x0 so NZCV/x1 (~x0)/x2 vary with the dividend edge and
            # the divisor is the bitwise complement of the dividend.
            return [(v, v) for v in DIV_EDGES]
        if name.startswith("t_ccmp"):
            # x0 is Rn / the compare operand (both paths per instruction are
            # produced by the preceding cmp of the family body); the seed
            # varies the incoming architectural NZCV and x1/x2.
            return [(seed, v) for seed in CCMP_SEEDS for v in CCMP_EDGES]
        if name == "t_msr":
            return [(0, v) for v in MULH_EDGES]
        if name in ("t_msr8", "t_msr30", "t_msr31"):
            return [(v, None) for v in MULH_EDGES]
        return [(sd, None) for sd in
                (0, 0x5A5A5A5A, 0x8000000000000000, 0x7FFFFFFFFFFFFFFF)]

    for idx, name in enumerate(need):
        for seed, x0ov in scen_for(name):
            rargs = [exe, str(idx), "0x%x" % seed]
            if x0ov is not None:
                rargs.append("0x%x" % x0ov)
            p = subprocess.run(rargs, capture_output=True, text=True,
                               timeout=120)
            if p.returncode != 0:
                return infra("real runner failed (%s seed %x): rc=%d %s %s"
                             % (name, seed, p.returncode, p.stdout, p.stderr))
            d = parse_dump(p.stdout)
            if d is None:
                return infra("%s seed %x: malformed native dump %r"
                             % (name, seed, p.stdout))
            results[(name, seed, x0ov)] = d
            uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
            try:
                uc.ctl_set_cpu_model(UC_CPU_ARM64_A57)
            except UcError as exc:
                return infra("oracle pin failed mid-run: %r" % (exc,))
            uc.mem_map(BASE, 0x4000, UC_PROT_ALL)
            uc.mem_write(BASE, raw)
            uc.mem_map(DATA, PAGE, UC_PROT_ALL)
            uc.mem_write(DATA, page_pattern())
            for i in range(31):
                uc.reg_write(XR[i], (0x0101010101010101 * (i + 1)) ^ seed)
            uc.reg_write(UC_ARM64_REG_SP, STACK + 0x800)
            uc.reg_write(UC_ARM64_REG_NZCV, (0xA0000000 ^ seed) & 0xF0000000)
            uc.reg_write(UC_ARM64_REG_X30, LR)
            uc.reg_write(UC_ARM64_REG_TPIDR_EL0, 0xa5a5a5a0)
            uc.reg_write(UC_ARM64_REG_TPIDRRO_EL0, 0x5a5a5a50)
            for i in range(32):
                uc.reg_write(UC_ARM64_REG_Q0+i, (0x1111000000000000+i) |
                             ((0x2222000000000000+i) << 64))
            uc.reg_write(UC_ARM64_REG_FPCR, 0x03000000)
            uc.reg_write(UC_ARM64_REG_FPSR, 0x0800001f)
            if (uc.reg_read(UC_ARM64_REG_FPCR) != 0x03000000 or
                    uc.reg_read(UC_ARM64_REG_FPSR) != 0x0800001f):
                return infra("oracle masks preservation seeds")
            uc.reg_write(XR[20], DATA if name == "t_fault" else DATA + 0x100)
            uc.reg_write(XR[21], 8)
            uc.reg_write(XR[0], seed if x0ov is None else x0ov)
            uc.reg_write(XR[1], (~seed) & 0xFFFFFFFFFFFFFFFF)
            uc.reg_write(XR[2], seed ^ 0xA5A5A5A5A5A5A5A5)
            entry = entries[idx]
            fault = None
            try:
                if name in bit_of or name == "t_fault":
                    uc.emu_start(entry, entry + 4, count=1)
                else:
                    nxt = (syms[need[idx + 1]] if idx + 1 < len(need)
                           else len(raw))
                    count = (nxt - syms[name]) // 4
                    if count <= 0:
                        return infra("%s: empty instruction slice" % name)
                    uc.emu_start(entry, BASE + len(raw), count=count)
            except UcError as exc:
                fault = exc.errno
            # Preservation includes fault rows and nonzero architectural seeds.
            for field, reg in (("TPIDR", UC_ARM64_REG_TPIDR_EL0),
                               ("TPIDRRO", UC_ARM64_REG_TPIDRRO_EL0),
                               ("FPCR", UC_ARM64_REG_FPCR),
                               ("FPSR", UC_ARM64_REG_FPSR)):
                if d[field] != uc.reg_read(reg):
                    return fail("%s seed %x: %s differs" % (name, seed, field))
            for i in range(32):
                q = uc.reg_read(UC_ARM64_REG_Q0+i)
                if d["Q"][i] != (q & 0xffffffffffffffff, q >> 64):
                    return fail("%s seed %x: Q%d differs" % (name, seed, i))
            if name == "t_fault":
                # Deliberate fault row: exact typed fields and FULL unchanged
                # state/bytes (the ldr faults before any writeback).
                if fault not in (UC_ERR_READ_UNMAPPED, UC_ERR_WRITE_UNMAPPED):
                    return fail("%s seed %x: unicorn did not fault (%r)"
                                % (name, seed, fault))
                if d["FAULT"] != 3:
                    return fail("%s: expected AOT_FAULT_MEMORY (3): %r"
                                % (name, d))
                if d["TARGET"] != DATA - 8:
                    return fail("%s: fault target 0x%x != access address 0x%x"
                                % (name, d["TARGET"], DATA - 8))
                if d["NEXT"] != d["TARGET"]:
                    return fail("%s: fault next_pc 0x%x != target 0x%x"
                                % (name, d["NEXT"], d["TARGET"]))
                if d["SRC"] != entry:
                    return fail("%s: fault src 0x%x != site 0x%x"
                                % (name, d["SRC"], entry))
                if d["STATUS"] != 1:  # AOT_MEM_ERR_RANGE
                    return fail("%s: fault status %d != AOT_MEM_ERR_RANGE (1)"
                                % (name, d["STATUS"]))
                expect = {}
                for i in range(31):
                    expect["x%d" % i] = (0x0101010101010101 * (i + 1)) ^ seed
                expect["x0"] = seed if x0ov is None else x0ov
                expect["x1"] = (~seed) & 0xFFFFFFFFFFFFFFFF
                expect["x2"] = seed ^ 0xA5A5A5A5A5A5A5A5
                expect["x30"] = LR
                expect["x20"] = DATA          # writeback NOT applied
                expect["x21"] = 8
                expect["SP"] = STACK + 0x800
                expect["NZCV"] = (0xA0000000 ^ seed) & 0xF0000000
                for k, v in expect.items():
                    if d[k] != v:
                        return fail("%s seed %x: full-state %s 0x%x != 0x%x"
                                    % (name, seed, k, d[k], v))
                page = page_pattern()
                if d["BYTES"] != page.hex():
                    return fail("%s seed %x: guest page bytes changed on fault"
                                % (name, seed))
                continue
            if fault is not None:
                return fail("%s seed %x: unexpected Unicorn exception %r"
                            % (name, seed, fault))
            # exact GPR/SP/NZCV state
            for i in range(31):
                if d["x%d" % i] != uc.reg_read(XR[i]):
                    return fail("%s seed %x: x%d native 0x%x != unicorn 0x%x"
                                % (name, seed, i, d["x%d" % i],
                                   uc.reg_read(XR[i])))
            if d["SP"] != uc.reg_read(UC_ARM64_REG_SP):
                return fail("%s seed %x: SP mismatch" % (name, seed))
            if d["NZCV"] != uc.reg_read(UC_ARM64_REG_NZCV):
                return fail("%s seed %x: NZCV native 0x%x != unicorn 0x%x"
                            % (name, seed, d["NZCV"],
                               uc.reg_read(UC_ARM64_REG_NZCV)))
            if d["TPIDR"] != uc.reg_read(UC_ARM64_REG_TPIDR_EL0):
                return fail("%s seed %x: TPIDR native 0x%x != unicorn 0x%x"
                            % (name, seed, d["TPIDR"],
                               uc.reg_read(UC_ARM64_REG_TPIDR_EL0)))
            if d["TPIDRRO"] != uc.reg_read(UC_ARM64_REG_TPIDRRO_EL0):
                return fail("%s seed %x: TPIDRRO native 0x%x != unicorn 0x%x"
                            % (name, seed, d["TPIDRRO"],
                               uc.reg_read(UC_ARM64_REG_TPIDRRO_EL0)))
            if name in bit_of:
                if d["NEXT"] != uc.reg_read(UC_ARM64_REG_PC):
                    return fail("%s seed %x: next_pc 0x%x != unicorn pc 0x%x"
                                % (name, seed, d["NEXT"],
                                   uc.reg_read(UC_ARM64_REG_PC)))
            elif d["NEXT"] != LR:
                return fail("%s seed %x: leaf next_pc 0x%x != guest LR 0x%x"
                            % (name, seed, d["NEXT"], LR))
            # raw byte comparison, not just the checksum
            if d["BYTES"] != bytes(uc.mem_read(DATA, PAGE)).hex():
                return fail("%s seed %x: data page differs (raw bytes)"
                            % (name, seed))
            fh = 14695981039346656037
            for b in uc.mem_read(DATA, PAGE):
                fh = ((fh ^ b) * 1099511628211) & 0xFFFFFFFFFFFFFFFF
            if "%016x" % fh != "%016x" % d["PAGE"]:
                return fail("%s seed %x: FNV page checksum differs"
                            % (name, seed))
            if d["FAULT"] != 0:
                return fail("%s seed %x: unexpected fault %d"
                            % (name, seed, d["FAULT"]))
    print("new-family differential (emitted C vs Unicorn): %d scenarios exact"
          % len(results))

    # ---- RBIT: sixteen NZCV seeds, independent of the operand seed --------
    # The same operand (x0 = 0x0123456789abcdef) is run under every one of the
    # SIXTEEN architectural NZCV nibbles (seed i << 28 maps 1:1 through the
    # runner's nzcv = (0xA0000000 ^ seed) & 0xF0000000). RBIT must preserve
    # the nibble exactly, must not move SP, and the Rn=31 / Rd=31 lanes must
    # read the ZERO register -- SP is a non-zero canary in every run, so a
    # lowering that resolved reg31 to SP would leave x11 != 0.
    rbit_nibbles = set()
    rbit_sp = results[("t_rbit", RBIT_NZCV_SEEDS[0],
                       0x0123456789ABCDEF)]["SP"]
    for seed in RBIT_NZCV_SEEDS:
        d = results[("t_rbit", seed, 0x0123456789ABCDEF)]
        want_nzcv = (0xA0000000 ^ seed) & 0xF0000000
        if d["NZCV"] != want_nzcv:
            return fail("RBIT seed 0x%x: NZCV 0x%x != preserved 0x%x"
                        % (seed, d["NZCV"], want_nzcv))
        if d["x11"] != 0:
            return fail("RBIT seed 0x%x: Rn=31 lane x11 = 0x%x (ZERO register, "
                        "not SP=0x%x)" % (seed, d["x11"], d["SP"]))
        if d["x12"] != 0:
            return fail("RBIT seed 0x%x: Wn=31 lane x12 = 0x%x (ZERO register)"
                        % (seed, d["x12"]))
        if d["SP"] != rbit_sp:
            return fail("RBIT seed 0x%x changed SP 0x%x -> 0x%x"
                        % (seed, rbit_sp, d["SP"]))
        rbit_nibbles.add(d["NZCV"] >> 28)
    if rbit_nibbles != set(range(16)):
        return fail("RBIT NZCV coverage %r is not all 16 nibbles"
                    % sorted(rbit_nibbles))
    print("rbit nzcv: all 16 architectural NZCV nibbles preserved with the "
          "same operand, SP 0x%x unchanged, Rn/Rd=31 = ZERO" % rbit_sp)

    # ---- UMULH: unsigned semantics pinned against the A57 oracle ---------
    # The differential above already compares every field, but these direct
    # assertions state the SEMANTIC claims the fixture exists for, so a
    # signed/low-product/missing-carry lowering cannot hide in an uncompared
    # field: umulh(2^63, 1) is 0 (a signed high half would be -1),
    # umulh(2^63, 2^63) is 2^62, umulh(~0, ~0) is ~0 - 1 (only correct when
    # the 32-bit `mid` limb carry is kept), and Rn/Rm=31 read the ZERO
    # register (never SP, which is a non-zero canary in every run).
    umulh_of = {}
    for a, b in UMULH_PAIRS:
        d = results[("t_umulh", (~b) & 0xFFFFFFFFFFFFFFFF, a)]
        umulh_of[(a, b)] = d["x2"]
    for (a, b), want in (
            ((0x8000000000000000, 1), 0),
            ((1, 0x8000000000000000), 0),
            ((0x8000000000000000, 0x8000000000000000), 0x4000000000000000),
            ((0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF),
             0xFFFFFFFFFFFFFFFE),
            ((0x7FFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF),
             0x3FFFFFFFFFFFFFFF),
            ((0x00000000FFFFFFFF, 0x0000000100000000), 0),
            ((0x0000000100000000, 0x0000000100000000), 1),
            ((0xFFFFFFFF00000000, 0xFFFFFFFF00000000),
             0xFFFFFFFE00000001),
            ((0, 0xFFFFFFFFFFFFFFFF), 0),
            ((1, 0xFFFFFFFFFFFFFFFF), 0)):
        if umulh_of[(a, b)] != want:
            return fail("UMULH(0x%x, 0x%x) = 0x%x != 0x%x (native vs the A57 "
                        "oracle's unsigned high half)"
                        % (a, b, umulh_of[(a, b)], want))
    alias_seed, alias_x0 = scen_for("t_umulh_alias")[0]
    alias_first = results[("t_umulh_alias", alias_seed, alias_x0)]
    if alias_first["x2"] != 0 or alias_first["x3"] != 0:
        return fail("UMULH Rn=31 / Rm=31 lanes x2/x3 = 0x%x/0x%x (the ZERO "
                    "register, not SP=0x%x)"
                    % (alias_first["x2"], alias_first["x3"],
                       alias_first["SP"]))
    umulh_sp = results[("t_umulh", RBIT_NZCV_SEEDS[0], None)]["SP"]
    umulh_nibbles = set()
    for seed in RBIT_NZCV_SEEDS:
        d = results[("t_umulh", seed, None)]
        want_nzcv = (0xA0000000 ^ seed) & 0xF0000000
        if d["NZCV"] != want_nzcv:
            return fail("UMULH seed 0x%x: NZCV 0x%x != preserved 0x%x"
                        % (seed, d["NZCV"], want_nzcv))
        if d["SP"] != umulh_sp:
            return fail("UMULH seed 0x%x changed SP 0x%x -> 0x%x"
                        % (seed, umulh_sp, d["SP"]))
        umulh_nibbles.add(d["NZCV"] >> 28)
    if umulh_nibbles != set(range(16)):
        return fail("UMULH NZCV coverage %r is not all 16 nibbles"
                    % sorted(umulh_nibbles))
    print("umulh: unsigned high half, ZERO-register sources and the mid-limb "
          "carry agree with the A57 oracle; all 16 NZCV nibbles preserved "
          "with SP 0x%x unchanged" % umulh_sp)

    # ---- compiled real-lowering mutants ----------------------------------
    mexes = {}
    expected_fields = {
        "tbz_bit": {"NEXT", "x1"},
        # t_alu's conditional destinations (its x9 comes from a later EOR,
        # so it cannot witness this mutant).
        "csel_cond": {"x2", "x3", "x4", "x5", "x6"},
        "ldst_sign_zero": {"x24", "x25", "x26", "x28", "x29"},
        "imm9_wb_nooff": {"x20"},
        "smulh_unsigned": {"x2", "x3", "x4", "x5"},
        # UMULH: a SIGNED high half differs exactly where an operand has its
        # MSB set; a low-product lowering differs everywhere the product
        # exceeds 64 bits; dropping the `mid` limb carry differs on the
        # all-ones / 2^32-crossing pairs.  Named fields are a superset.
        "umulh_signed": {"x2", "x3", "x4", "x5", "x6", "x18"},
        "umulh_lowprod": {"x2", "x3", "x4", "x5", "x6", "x18"},
        "umulh_midcarry": {"x2", "x3", "x4", "x5", "x6", "x18"},
        "msub_reverse": {"x5", "x7"},
        "madd_no_zeroext": {"x6", "x7"},
        "madd_ignore_ra": {"x4", "x5", "x6", "x7"},
        "div_zero_ones": {"x4", "x5"},
        "div_no_zeroext": {"x3", "x4", "x6", "x7", "x8", "x11", "x12"},
        "sdiv_overflow_clamp": {"x2", "x3"},
        # CCMP/CCMN write NZCV and nothing else, so every wrong implementation
        # of the guarded compare, of the condition or of the operand width can
        # only surface as an NZCV divergence (the GPR/SP/Q/page fields are
        # compared too, and must stay identical).
        "ccmp_ignore_cond": {"NZCV"},
        "ccmp_cond_invert": {"NZCV"},
        "ccmp_w64": {"NZCV"},
        # Inverted logical: ignoring N turns BIC/ORN/EON into AND/ORR/EOR and
        # BICS into ANDS, so the GPR results (and, for BICS, NZCV) diverge.
        "logic_inv_ignoren": {"x2", "x3", "x4", "x5", "x6", "x7", "x8",
                              "x9", "x10", "x11", "x12", "x13", "x14",
                              "x15", "x16", "x17", "x18", "x19", "x22",
                              "x23", "NZCV"},
        # Inverting before the shift is WRONG for a nonzero LSL/LSR but is
        # algebraically identical for ASR, ROR and any shift amount 0 (NOT
        # commutes with arithmetic shift and with rotation). Only the nonzero
        # LSL/LSR lanes can therefore discriminate it -- the MVN LSL#0 word
        # that stopped the real boot cannot -- and the ASR/ROR lanes below are
        # asserted NOT to differ, which is what pins that reasoning down.
        "logic_inv_beforeshift": {"x4", "x5", "x9", "x10", "x16", "x18",
                                  "x23"},
        # BICS must set NZCV like ANDS; skipping the flag write is only
        # visible in the flags block (C/V cleared, N/Z from the result).
        "logic_inv_bics_skipflags": {"NZCV"},
        # CLZ: an all-zero operand must yield the OPERAND WIDTH, so the mutant
        # that answers 0 is visible only on the zero lanes (x2/x3 from the zero
        # registers and x6 from the MOV-zeroed x22).
        "clz_zero_wrong": {"x2", "x3", "x6"},
        # A W form that counts over all 64 bits differs exactly on the lanes
        # whose LOW half is zero while the high half is not.
        "clz_W_uses64": {"x4"},
        # CLZ writes no flags: clearing NZCV is only visible in the NZCV field.
        "clz_clobber_flags": {"NZCV"},
        # A non-modulo amount rule answers 0 once the amount reaches the
        # operand width, so the out-of-range amount lanes diverge.
        "varshift_oversize_zero": {"x2", "x3", "x4", "x5", "x6", "x7", "x8",
                                   "x9"},
        # ASRV lowered as LSRV differs only where the shifted value is
        # negative (MSB set) at the operand width.
        "varshift_asr_logical": {"x4", "x8"},
        # A W form acting like the 64-bit form differs on the upper-half
        # canaries at both widths.
        "varshift_W_uses64": {"x6", "x7", "x8", "x9"},
        # RBIT: an identity lowering (source copied, width-truncated and
        # zero-extended) differs on every non-palindromic operand, which is
        # every single-bit edge at both widths and both canary halves.
        "rbit_identity": {"x2", "x3", "x4", "x5", "x6", "x7", "x9",
                          "x10", "x11", "x12"},
        # A BYTE reverse agrees with a BIT reverse only on bit-palindromic
        # values, so the rich edge matrix separates them everywhere else.
        "rbit_byteswap": {"x2", "x3", "x4", "x5", "x6", "x7", "x9",
                          "x10", "x11", "x12"},
        # A W form that reverses all 64 register bits but still zero-extends
        # its 32-bit result is wrong only in the OPERAND width: it answers
        # reverse32(high half) instead of reverse32(low half). The one-hot and
        # high-half-canary edges separate the two halves, so no upper-half
        # garbage is needed to catch it.
        "rbit_W_uses64": {"x3", "x5", "x7", "x10"},
        # RBIT writes no flags: clearing NZCV is only visible in the NZCV field.
        "rbit_clobber_flags": {"NZCV"},
        # A DMB ISH that clears NZCV is visible only in the NZCV field; it is
        # the same wrong-flag lowering pattern as the other families.
        "dmb_ish_clobber_flags": {"NZCV"},
        # DMB is NOT CLREX. Clearing the monitor makes both stxr words report
        # status 1 and leaves the exclusive stores unapplied, so the status
        # registers and the guest page diverge.
        "dmb_ish_clearexclusive": {"x3", "x5", "BYTES", "PAGE"},
        # A barrier never writes a GPR; x5 is untouched by the fixture.
        "dmb_ish_clobber_gpr": {"x5"},
        "msr_tpidr_noop": {"TPIDR"},
        "msr_tpidr_tpidrro": {"TPIDR", "TPIDRRO"},
        "msr_tpidr_xzr_sp": {"TPIDR"},
        "msr_tpidr_skip_xzr": {"TPIDR"},
        "msr_tpidr_clobber_v": {"Q"},
        "msr_tpidr_clobber_fpcr": {"FPCR"},
        "msr_tpidr_clobber_fpsr": {"FPSR"},
    }
    for mutant in ("tbz_bit", "csel_cond", "ldst_sign_zero", "imm9_wb_nooff",
                   "smulh_unsigned", "umulh_signed", "umulh_lowprod",
                   "umulh_midcarry", "msub_reverse", "madd_no_zeroext",
                   "madd_ignore_ra", "div_zero_ones", "div_no_zeroext",
                   "sdiv_overflow_clamp", "msr_tpidr_noop",
                   "msr_tpidr_tpidrro", "msr_tpidr_xzr_sp",
                   "msr_tpidr_skip_xzr", "msr_tpidr_clobber_v",
                   "msr_tpidr_clobber_fpcr", "msr_tpidr_clobber_fpsr",
                   "ccmp_ignore_cond", "ccmp_cond_invert", "ccmp_w64",
                   "logic_inv_ignoren", "logic_inv_beforeshift",
                   "logic_inv_bics_skipflags",
                   "clz_zero_wrong", "clz_W_uses64", "clz_clobber_flags",
                   "varshift_oversize_zero", "varshift_asr_logical",
                   "varshift_W_uses64",
                   "rbit_identity", "rbit_byteswap", "rbit_W_uses64",
                   "rbit_clobber_flags",
                   "dmb_ish_clobber_flags", "dmb_ish_clearexclusive",
                   "dmb_ish_clobber_gpr"):
        mimg = os.path.join(work, "mut_%s.c" % mutant)
        p = translate(mutant, mimg)
        if p.returncode != 0:
            return infra("mutant %s translation failed: %s"
                         % (mutant, p.stderr))
        mdir = os.path.join(work, "mut_" + mutant)
        mex = build(mdir, mimg)
        if mex is None:
            return infra("mutant %s compile failed" % mutant)
        mexes[mutant] = mex
        differed = set()
        first = None
        for idx, name in enumerate(need):
            if mutant.startswith("logic_inv") and \
                    name not in ("t_inv", "t_inv_flags"):
                continue
            if mutant == "logic_inv_bics_skipflags" and name != "t_inv_flags":
                continue
            if (mutant == "tbz_bit" and not name.startswith("t_tb")) and \
               (mutant != "tbz_bit" and name.startswith("t_tb")):
                continue
            if mutant == "csel_cond" and name != "t_alu":
                continue
            if mutant == "ldst_sign_zero" and name != "t_mem":
                continue
            if mutant == "imm9_wb_nooff" and name not in ("t_mem", "t_fault"):
                continue
            if mutant == "smulh_unsigned" and name != "t_mulh":
                continue
            if mutant.startswith("umulh_") and \
                    name not in ("t_umulh", "t_umulh_alias"):
                continue
            if mutant in ("msub_reverse", "madd_no_zeroext",
                          "madd_ignore_ra") and name != "t_mul":
                continue
            if (mutant in ("div_zero_ones", "div_no_zeroext",
                           "sdiv_overflow_clamp")
                    and not name.startswith("t_div")):
                continue
            if mutant.startswith("msr_tpidr_") and not name.startswith("t_msr"):
                continue
            if mutant.startswith("ccmp_") and not name.startswith("t_ccmp"):
                continue
            if mutant.startswith("clz_"):
                allowed = {"clz_zero_wrong": ("t_clz_zero",),
                           "clz_W_uses64": ("t_clz_w",),
                           "clz_clobber_flags": ("t_clz_flags",)}[mutant]
                if name not in allowed:
                    continue
            if mutant.startswith("rbit_"):
                # Every RBIT function carries reversed results; the flags and
                # W-width mutants are pinned to their only witnessing blocks.
                allowed = {"rbit_identity": ("t_rbit", "t_rbit_w",
                                             "t_rbit_zero", "t_rbit_flags"),
                           "rbit_byteswap": ("t_rbit", "t_rbit_w",
                                             "t_rbit_zero", "t_rbit_flags"),
                           "rbit_W_uses64": ("t_rbit", "t_rbit_w"),
                           "rbit_clobber_flags": ("t_rbit_flags",)}[mutant]
                if name not in allowed:
                    continue
            if mutant.startswith("dmb_ish_"):
                # Only the new canonical DMB ISH form is patched; the legacy
                # SY barriers must stay byte-identical.
                allowed = {"dmb_ish_clobber_flags": ("t_dmb", "t_dmb_flags",
                                                     "t_dmb_excl"),
                           "dmb_ish_clearexclusive": ("t_dmb_excl",),
                           "dmb_ish_clobber_gpr": ("t_dmb", "t_dmb_flags")}[
                               mutant]
                if name not in allowed:
                    continue
            if mutant.startswith("varshift_"):
                # The amount-edge function carries the out-of-range amounts;
                # both variable-shift functions carry the upper-half canaries.
                allowed = {"varshift_oversize_zero": ("t_vs_amt", "t_vs"),
                           "varshift_asr_logical": ("t_vs_amt", "t_vs"),
                           "varshift_W_uses64": ("t_vs_amt", "t_vs")}[mutant]
                if name not in allowed:
                    continue
            if mutant in ("msr_tpidr_xzr_sp", "msr_tpidr_skip_xzr") and name != "t_msr31":
                continue
            for seed, x0ov in scen_for(name):
                margs = [mex, str(idx), "0x%x" % seed]
                if x0ov is not None:
                    margs.append("0x%x" % x0ov)
                r = subprocess.run(margs, capture_output=True, text=True,
                                   timeout=120)
                if r.returncode != 0:
                    return infra("mutant %s runner failed (%s seed %x): rc=%d "
                                 "%s %s" % (mutant, name, seed, r.returncode,
                                            r.stdout, r.stderr))
                md = parse_dump(r.stdout)
                if md is None:
                    return infra("mutant %s: malformed native dump %r "
                                 "(never a rejection)" % (mutant, r.stdout))
                real = results[(name, seed, x0ov)]
                for field in real:
                    if md[field] != real[field]:
                        differed.add(field)
                        if first is None:
                            first = (name, seed, field, md[field],
                                     real[field])
                if mutant == "csel_cond" and md["NZCV"] != real["NZCV"]:
                    return fail("csel_cond mutant changed NZCV on %s" % name)
        want = expected_fields[mutant]
        if mutant == "logic_inv_beforeshift":
            # NOT commutes with ASR/ROR, so those lanes MUST stay identical:
            # a divergence there would mean the emitter is wrong in a way this
            # mutant's expected-field set does not describe.
            commutes = {"x6", "x7", "x11", "x12", "x14", "x15", "x19"}
            bad = sorted(differed & commutes)
            if bad:
                return fail("mutant logic_inv_beforeshift changed ASR/ROR "
                            "lane(s) %r; NOT(ASR/ROR) must commute" % bad)
        if not (differed & want):
            return fail("mutant %s SURVIVED (no mismatch in expected fields "
                        "%r; differed=%r)" % (mutant, sorted(want),
                                             sorted(differed)))
        if first is not None:
            # Report the exact first failed comparison, not just the set.
            def show(v):
                if isinstance(v, int):
                    return "0x%x" % v
                return "<%s len %d>" % (type(v).__name__, len(v))
            print("mutant %s first mismatch: %s seed 0x%x %s native %s != "
                  "oracle %s" % (mutant, first[0], first[1], first[2],
                                  show(first[3]), show(first[4])))
        print("mutant %s compiled and rejected on named field(s) %r"
              % (mutant, sorted(differed & want)))
    # The zero-operand mutant must be INVISIBLE on non-zero operands: this is
    # the "a real nonzero boot word cannot catch it" claim, asserted directly
    # on the W-only function with every non-zero edge (x1 == ~0 == all ones).
    mz = mexes["clz_zero_wrong"]
    widx = need.index("t_clz_w")
    clz_zero_nonzero = clz_zero_zero = 0
    for v in CLZ_EDGES:
        if v == 0:
            continue
        r = subprocess.run([mz, str(widx), "0x0", "0x%x" % v],
                           capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            return infra("clz_zero_wrong edge runner failed: %s"
                         % (r.stdout + r.stderr))
        md = parse_dump(r.stdout)
        if md is None:
            return infra("clz_zero_wrong: malformed dump on edge 0x%x" % v)
        same = md == results[("t_clz_w", 0, v)]
        if v & 0xFFFFFFFF:
            # Non-zero at the W operand width: the wrong implementation gives
            # the same answer, i.e. a real (nonzero) boot word CANNOT catch it.
            if not same:
                return fail("clz_zero_wrong altered the NON-ZERO W operand "
                            "edge 0x%x; the mutant must be invisible there" % v)
            clz_zero_nonzero += 1
        else:
            # Low 32 bits zero (high half nonzero) at width 32: the wrong
            # result really is produced here, so this must DIFFER.
            if same:
                return fail("clz_zero_wrong SURVIVED the low-32-zero W "
                            "operand edge 0x%x" % v)
            clz_zero_zero += 1
    print("mutant clz_zero_wrong: invisible on %d non-zero W operands, "
          "visible on %d low-32-zero W operands"
          % (clz_zero_nonzero, clz_zero_zero))
    print("new-family suite PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
