// G2 translated-memory concurrency fixture (owned original; no game data).
// Every chunk ends in RET. The runtime's stop sentinel is guest PC 0, so a
// caller can run one chunk, observe guest state, and run another chunk while
// the shared domain keeps the exclusive-monitor reservation alive.
//
// Register conventions used by tests/aot/aot_concurrency_probe.c:
//   x0 = address, x1 = value/result, x2 = STXR status, x3 = loop count/source,
//   x9 = host-thunk target for the HOSTCALL chunk.

    .text
    .p2align 2

    .org 0x1000
    ldxr x1, [x0]                   // 0x1000 ldx_x
    ret
    .org 0x1010
    stxr w2, x1, [x0]               // 0x1010 stx_x
    ret
    .org 0x1020
    str  x1, [x0]                   // 0x1020 str_x
    ret
    .org 0x1030
    ldar x1, [x0]                   // 0x1030 ldar_x
    ret
    .org 0x1040
    stlr x1, [x0]                   // 0x1040 stlr_x
    ret
    .org 0x1050
    clrex                           // 0x1050 clrex
    ret
    .org 0x1060
    svc  #0x40                      // 0x1060 svc_hle
    ret                             // 0x1064
    .org 0x1070
    // BLR clobbers x30 with 0x1078, and the runtime's RET/STOP sentinel is
    // x30==0. Save/restore the incoming LR with supported register/immediate
    // ADDs so the chunk cannot self-loop through its own return address.
    // Test HLE handlers (no-op / shared arena) must not mutate x10.
    add  x10, x30, #0               // 0x1070 save sentinel LR
    blr  x9                         // 0x1074 blr_hostcall
    add  x30, x10, #0               // 0x1078 restore sentinel LR
    ret                             // 0x107c
    .org 0x1080
    add  x1, x1, #1                 // 0x1080 add_x1
    ret
    .org 0x1090
    ldxrb w1, [x0]                  // 0x1090 ldx_byte
    ret
    .org 0x10a0
    stxrb w2, w1, [x0]              // 0x10a0 stx_byte
    ret
    .org 0x10b0
    ldxrh w1, [x0]                  // 0x10b0 ldx_half
    ret
    .org 0x10c0
    stxrh w2, w1, [x0]              // 0x10c0 stx_half
    ret
    .org 0x10d0
    ldxr w1, [x0]                   // 0x10d0 ldx_word
    ret
    .org 0x10e0
    stxr w2, w1, [x0]               // 0x10e0 stx_word
    ret
    .org 0x10f0
    ret                             // 0x10f0 ret_only
    .org 0x1100
1:  ldxr w1, [x0]                   // 0x1100 counter_retry (local label!)
    add  w1, w1, #1
    stxr w2, w1, [x0]
    cbnz w2, 1b                     // retry on failed STXR
    ret                             // 0x1110
    .org 0x1120
    str  x1, [x0]                   // 0x1120 publication payload
    ret
    .org 0x1130
    stlr x1, [x0]                   // 0x1130 publication flag (release)
    ret
    .org 0x1140
    ldar x1, [x0]                   // 0x1140 flag read (acquire)
    ret
    .org 0x1150
    ldr  x1, [x0]                   // 0x1150 payload read (ordinary)
    ret
    .org 0x1160
    ldaxr x1, [x0]                  // 0x1160 ldaxr_x
    ret
    .org 0x1170
    stlxr w2, x1, [x0]              // 0x1170 stlxr_x
    ret
