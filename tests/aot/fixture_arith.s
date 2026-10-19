// G2 stage-1 controlled ARM64 fixture. Owned original source (no game data).
// Assembled outside the source tree with LLVM llvm-mc + llvm-objcopy.
//
// Expected results (checked by tests/aot/aot_fixture_runner.c):
//   x0  = 61   (loop sum 10+9+...+1 = 55, +1 via BL, +5 via BLR)
//   x3  = 2    (both compare checks passed)
//   x5  = 0xabcd1234 (MOVZ + MOVK lsl #16)
//   x6  = 0    (CBZ taken, skipped the 0xdead store)
//   x7  = 7    (CBNZ not taken, fell through)
//   x9  = 15   (ADD shifted, lsl #2: 3 + 12)
//   x11 = 14   (SUB shifted, lsr #1: 15 - 1)
//   x12 = 22   (ADD shifted, asr #1: 15 + 7)
//
// The runner seeds x10 = 0x2000 (manifest indirect target) before running.

    .text
    .p2align 2
    .org 0x1000

    .globl aot_fixture
aot_fixture:
    movz x5, #0x1234
    movk x5, #0xabcd, lsl #16
    movz x6, #0
    cbz  x6, aot_cbz_skip
    movz x6, #0xdead
aot_cbz_skip:
    movz x7, #0
    cbnz x6, aot_cbnz_set
    movz x7, #7
aot_cbnz_set:
    movz x8, #3
    add  x9, x8, x8, lsl #2
    sub  x11, x9, x8, lsr #1
    add  x12, x9, x9, asr #1
    movz x0, #0
    movz x1, #10
aot_loop:
    add  x0, x0, x1
    subs x1, x1, #1
    b.ne aot_loop
    bl   aot_sub1
    movz x2, #56
    cmp  x0, x2
    b.ne aot_fail
    movz x3, #1
    b    aot_done
aot_fail:
    movz x3, #0
aot_done:
    svc  #0x40
    blr  x10
    movz x2, #61
    cmp  x0, x2
    b.ne aot_fail2
    movz x3, #2
    b    aot_done2
aot_fail2:
    movz x3, #3
aot_done2:
    movz x30, #0
    ret
aot_sub1:
    add x0, x0, #1
    ret

    .org 0x2000
    .globl aot_via_reg
aot_via_reg:
    add x0, x0, #5
    ret
