// G2 stage-2 differential fixture (owned original; no game data).
// Fixed .org addresses so the Python differential driver can name entries.
// Every case ends in `ret`; the driver seeds x30 = 0 and stop_pc = 0, so a
// completed case stops cleanly at guest PC 0.
//
// Integer/flags cases are seeded per register by the driver; the expected
// result is produced independently by the Unicorn A57 oracle.

    .text
    .p2align 2

// ---- integer / flags -------------------------------------------------
    .org 0x1000
    adds x1, x0, #1                 // 0x1000 adds_imm
    ret
    .org 0x1010
    subs x1, x0, #2                 // 0x1010 subs_imm
    ret
    .org 0x1020
    add  x1, x0, x2, lsl #3         // 0x1020 add_shift_lsl
    ret
    .org 0x1030
    sub  x1, x0, x2, asr #4         // 0x1030 sub_shift_asr
    ret
    .org 0x1040
    adds w1, w0, w2                 // 0x1040 adds32
    ret
    .org 0x1050
    subs w1, w0, w2                 // 0x1050 subs32
    ret
    .org 0x1060
    movz x1, #0x1234                // 0x1060 movz_movk
    movk x1, #0xabcd, lsl #16
    ret
    .org 0x1070
    subs x1, x0, x2                 // 0x1070 subs_wrap
    ret
    .org 0x1080
    add  x1, sp, #16                // 0x1080 add_sp_imm
    ret
    .org 0x1090
    adds xzr, x0, x1                // 0x1090 adds_xzr_flags_only
    ret
    .org 0x10a0
    add  x1, x1, x1, lsl #1         // 0x10a0 add_overlap
    ret

// ---- all 16 condition codes (b.<cond> taken/not-taken) ---------------
    .org 0x1200
    b.eq 1f                         // 0x1200 cond_eq
    movz x1, #1
    ret
1:  movz x1, #2
    ret
    .org 0x1220
    b.ne 1f                         // 0x1220 cond_ne
    movz x1, #1
    ret
1:  movz x1, #2
    ret
    .org 0x1240
    b.cs 1f                         // 0x1240 cond_cs
    movz x1, #1
    ret
1:  movz x1, #2
    ret
    .org 0x1260
    b.cc 1f                         // 0x1260 cond_cc
    movz x1, #1
    ret
1:  movz x1, #2
    ret
    .org 0x1280
    b.mi 1f                         // 0x1280 cond_mi
    movz x1, #1
    ret
1:  movz x1, #2
    ret
    .org 0x12a0
    b.pl 1f                         // 0x12a0 cond_pl
    movz x1, #1
    ret
1:  movz x1, #2
    ret
    .org 0x12c0
    b.vs 1f                         // 0x12c0 cond_vs
    movz x1, #1
    ret
1:  movz x1, #2
    ret
    .org 0x12e0
    b.vc 1f                         // 0x12e0 cond_vc
    movz x1, #1
    ret
1:  movz x1, #2
    ret
    .org 0x1300
    b.hi 1f                         // 0x1300 cond_hi
    movz x1, #1
    ret
1:  movz x1, #2
    ret
    .org 0x1320
    b.ls 1f                         // 0x1320 cond_ls
    movz x1, #1
    ret
1:  movz x1, #2
    ret
    .org 0x1340
    b.ge 1f                         // 0x1340 cond_ge
    movz x1, #1
    ret
1:  movz x1, #2
    ret
    .org 0x1360
    b.lt 1f                         // 0x1360 cond_lt
    movz x1, #1
    ret
1:  movz x1, #2
    ret
    .org 0x1380
    b.gt 1f                         // 0x1380 cond_gt
    movz x1, #1
    ret
1:  movz x1, #2
    ret
    .org 0x13a0
    b.le 1f                         // 0x13a0 cond_le
    movz x1, #1
    ret
1:  movz x1, #2
    ret
    .org 0x13c0
    b.al 1f                         // 0x13c0 cond_al
    movz x1, #1
    ret
1:  movz x1, #2
    ret
    .org 0x13e0
    b.nv 1f                         // 0x13e0 cond_nv (= AL)
    movz x1, #1
    ret
1:  movz x1, #2
    ret

// ---- memory: LDR/STR 8/16/32/64 and LDP/STP --------------------------
    .org 0x1400
    str  x0, [x1, #8]               // 0x1400 str_ldr64
    ldr  x2, [x1, #8]
    ret
    .org 0x1420
    strb w0, [x1, #3]               // 0x1420 strb_ldrb
    ldrb w2, [x1, #3]
    ret
    .org 0x1440
    strh w0, [x1, #6]               // 0x1440 strh_ldrh
    ldrh w2, [x1, #6]
    ret
    .org 0x1460
    str  w0, [x1, #12]              // 0x1460 str_ldr32
    ldr  w2, [x1, #12]
    ret
    .org 0x1480
    stp  x0, x2, [sp, #-16]!        // 0x1480 stp_pre_ldp_post
    ldp  x3, x4, [sp], #16
    ret
    .org 0x14a0
    stp  x0, x2, [sp, #16]          // 0x14a0 stp_off_ldp_off
    ldp  x3, x4, [sp, #16]
    ret
    .org 0x14c0
    str  x0, [sp, #24]              // 0x14c0 str_sp_ldr_sp
    ldr  x5, [sp, #24]
    ret
    .org 0x14e0
    ldr  x2, [x1, #0]               // 0x14e0 ldr_oob (fault case)
    ret

// ---- SIMD / vector bitwise + integer (stage 3) ----------------------
    .org 0x1500
    fmov d0, d1                     // 0x1500 fmov_d
    ret
    .org 0x1520
    fabs d0, d1                     // 0x1520 fabs_d
    ret
    .org 0x1540
    fneg d0, d1                     // 0x1540 fneg_d
    ret
    .org 0x1560
    and  v0.16b, v1.16b, v2.16b     // 0x1560 vand16b
    ret
    .org 0x1580
    orr  v0.16b, v1.16b, v2.16b     // 0x1580 vorr16b
    ret
    .org 0x15a0
    eor  v0.16b, v1.16b, v2.16b     // 0x15a0 veor16b
    ret
    .org 0x15c0
    add  v0.16b, v1.16b, v2.16b     // 0x15c0 vadd16b
    ret
    .org 0x15e0
    sub  v0.16b, v1.16b, v2.16b     // 0x15e0 vsub16b
    ret

// ---- calls / targets -------------------------------------------------
    .org 0x1600
    stp  x29, x30, [sp, #-16]!      // call_nested_entry: preserve root LR
    bl   f1                         // BL clobbers x30; root frame saves it
    ldp  x29, x30, [sp], #16
    ret
    .org 0x1640
    br   x9                         // 0x1640 br_dynamic
    .org 0x1660
    blr  x9                         // 0x1660 blr_dynamic
    movz x3, #0x6
    movz x30, #0
    ret
    .org 0x1680
    blr  x30                        // 0x1680 blr_x30_capture
    movz x3, #0x7
    movz x30, #0
    ret
    .org 0x16a0
    ret  x9                         // 0x16a0 ret_xN
    .org 0x16c0
    svc  #0x40                      // 0x16c0 svc_case
    movz x3, #0x8
    movz x30, #0
    ret
    .org 0x16e0
    blr  x9                         // 0x16e0 blr_hostthunk (x9 = thunk base)
    movz x3, #0x9
    movz x30, #0
    ret

// f1: guest-saved LR frame with a nested BL
    .org 0x1700
f1:
    stp  x29, x30, [sp, #-16]!
    bl   f2
    ldp  x29, x30, [sp], #16
    ret

    .org 0x1720
f2:
    add  x0, x0, #1
    ret

// pair32 writeback regression (guest arena above 4 GiB) and WSP-only arithmetic
    .org 0x1740
    stp  w0, w2, [x1, #-8]!         // 0x1740 pair32_pre (writeback must stay 64-bit)
    ldp  w3, w4, [x1], #8           // 0x1744 pair32_post
    ret
    .org 0x1760
    add  w1, wsp, #7                // 0x1760 wsp_high (zero-extend, no memory)
    ret

// ---- stage-4 coverage holes: CBZ/CBNZ W vs X -------------------------
    .org 0x1780
    cbz  x0, 1f                     // 0x1780 cbz_x
    movz x1, #1
    ret
1:  movz x1, #2
    ret
    .org 0x17a0
    cbz  w0, 1f                     // 0x17a0 cbz_w
    movz x1, #1
    ret
1:  movz x1, #2
    ret
    .org 0x17c0
    cbnz x0, 1f                     // 0x17c0 cbnz_x
    movz x1, #1
    ret
1:  movz x1, #2
    ret
    .org 0x17e0
    cbnz w0, 1f                     // 0x17e0 cbnz_w
    movz x1, #1
    ret
1:  movz x1, #2
    ret

// dynamic branch / call target
    .org 0x1800
tgt_add:
    add  x0, x0, #7
    ret

// ---- stage-4 coverage holes: ASR32, imm LSL#12, WSP dest, Rd==Rn -----
    .org 0x1810
    add  w1, wzr, w0, asr #31       // 0x1810 asr32_31
    ret
    .org 0x1830
    add  x1, x0, #1, lsl #12        // 0x1830 add_imm_lsl12
    ret
    .org 0x1850
    sub  x1, x0, #1, lsl #12        // 0x1850 sub_imm_lsl12
    ret
    .org 0x1870
    add  wsp, wsp, #7               // 0x1870 wsp_dest_highsp (no memory)
    ret
    .org 0x1890
    fmov d0, d0                     // 0x1890 fmov_d_same (Rd==Rn)
    ret
    .org 0x18b0
    and  v1.16b, v1.16b, v1.16b     // 0x18b0 vand_same (Rd==Rn==Rm)
    ret
    .org 0x18d0
    eor  v2.16b, v2.16b, v1.16b     // 0x18d0 veor_rd_eq_rn
    ret
    .org 0x18f0
    orr  v3.16b, v1.16b, v3.16b     // 0x18f0 vorr_rd_eq_rm
    ret

// ---- stage-5 scalar FP arithmetic and compare ------------------------
// Arithmetic cases are seeded through v[] by the differential driver; every
// case is compared against the Unicorn A57 oracle, including FPSR.
    .org 0x1900
    fadd d0, d1, d2                 // 0x1900 fadd_d
    ret
    .org 0x1920
    fsub d0, d1, d2                 // 0x1920 fsub_d
    ret
    .org 0x1940
    fmul d0, d1, d2                 // 0x1940 fmul_d
    ret
    .org 0x1960
    fdiv d0, d1, d2                 // 0x1960 fdiv_d
    ret
    .org 0x1980
    fadd s0, s1, s2                 // 0x1980 fadd_s
    ret
    .org 0x19a0
    fsub s0, s1, s2                 // 0x19a0 fsub_s
    ret
    .org 0x19c0
    fmul s0, s1, s2                 // 0x19c0 fmul_s
    ret
    .org 0x19e0
    fdiv s0, s1, s2                 // 0x19e0 fdiv_s
    ret
    .org 0x1a00
    fcmp d1, d2                     // 0x1a00 fcmp_d
    ret
    .org 0x1a20
    fcmpe d1, d2                    // 0x1a20 fcmpe_d
    ret
    .org 0x1a40
    fcmp s1, s2                     // 0x1a40 fcmp_s
    ret
    .org 0x1a60
    fcmpe s1, s2                    // 0x1a60 fcmpe_s
    ret
    .org 0x1a80
    fcmp d1, #0.0                   // 0x1a80 fcmp_zero_d
    ret
    .org 0x1aa0
    fcmpe s1, #0.0                  // 0x1aa0 fcmpe_zero_s
    ret

// ---- stage-5 exclusive / ordered scalar + barriers -------------------
    .org 0x1b00
    ldxr x0, [x1]                   // 0x1b00 ldxr_x
    ret
    .org 0x1b10
    ldxr w0, [x1]                   // 0x1b10 ldxr_w
    ret
    .org 0x1b20
    ldxrb w0, [x1]                  // 0x1b20 ldxrb
    ret
    .org 0x1b30
    ldxrh w0, [x1]                  // 0x1b30 ldxrh
    ret
    .org 0x1b40
    stxr w3, x0, [x1]               // 0x1b40 stxr_x (no reservation => fail)
    ret
    .org 0x1b50
    stxr w3, w0, [x1]               // 0x1b50 stxr_w
    ret
    .org 0x1b60
    stxrb w3, w0, [x1]              // 0x1b60 stxrb
    ret
    .org 0x1b70
    stxrh w3, w0, [x1]              // 0x1b70 stxrh
    ret
    .org 0x1b80
    ldar x0, [x1]                   // 0x1b80 ldar_x
    ret
    .org 0x1b90
    ldar w0, [x1]                   // 0x1b90 ldar_w
    ret
    .org 0x1ba0
    ldarb w0, [x1]                  // 0x1ba0 ldarb
    ret
    .org 0x1bb0
    ldarh w0, [x1]                  // 0x1bb0 ldarh
    ret
    .org 0x1bc0
    stlr x0, [x1]                   // 0x1bc0 stlr_x
    ret
    .org 0x1bd0
    stlr w0, [x1]                   // 0x1bd0 stlr_w
    ret
    .org 0x1be0
    stlrb w0, [x1]                  // 0x1be0 stlrb
    ret
    .org 0x1bf0
    stlrh w0, [x1]                  // 0x1bf0 stlrh
    ret
    .org 0x1c00
    ldxr x0, [x1]                   // 0x1c00 ldxr_stxr_ok
    stxr w3, x0, [x1]
    ret
    .org 0x1c20
    ldxr x0, [x1]                   // 0x1c20 ldxr_stxr_other
    add  x1, x1, #8
    stxr w3, x0, [x1]
    ret
    .org 0x1c40
    ldxr x0, [x1]                   // 0x1c40 ldxr_str_stxr (same-value/ABA
    str  x2, [x1]                   //        store must disarm reservation)
    stxr w3, x0, [x1]
    ret
    .org 0x1c60
    ldxr x0, [x1]                   // 0x1c60 ldxr_stlr_stxr
    stlr x2, [x1]
    stxr w3, x0, [x1]
    ret
    .org 0x1c80
    clrex                           // 0x1c80 clrex
    movz x0, #0x5a5a
    ret
    .org 0x1ca0
    dmb sy                          // 0x1ca0 barriers_noop_under_sc
    dsb sy
    isb
    movz x0, #0x5b5b
    ret
    .org 0x1cc0
    svc  #0x40                      // 0x1cc0 post_svc_fdiv: HLE flips FPCR
    fdiv s0, s1, s2
    ret
    .org 0x1ce0
    add  x21, x30, #0               // 0x1ce0 post_hostcall_fdiv: preserve the
    blr  x9                         // RET/STOP sentinel LR across BLR; x21 is
    fdiv s0, s1, s2                 // NOT mutated by the HLE contract
    add  x30, x21, #0
    ret
    .org 0x1d00
    svc  #0x40                      // 0x1d00 post_svc_fdiv_d (double)
    fdiv d0, d1, d2
    ret
    .org 0x1d20
    add  x21, x30, #0               // 0x1d20 post_hostcall_fdiv_d (double)
    blr  x9
    fdiv d0, d1, d2
    add  x30, x21, #0
    ret
