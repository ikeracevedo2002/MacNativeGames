# Bounded G3 inverted logical shifted-register increment

## Source / scope
Managed successor of w43. Seed exact current source preserving own .git: WT=$(pwd); cd <worktrees>/w43; tar -cf - --exclude=.git . | (cd "$WT" && tar -xf -); cd "$WT". Never edit w43/w33/main, never commit/integrate. Read repo AGENTS, GOAL, DECISIONS, ARCHITECTURE, PORTING_PLAN, PORTING_STATUS, existing translator/proof docs and relevant decode/emitter/test sources. Preserve existing CRLF. New external build outside source only.

w43 has reviewed real early-G4 RomFS provider/adapter/strict config, four native negative controls, plus eighth name-bound trivial CPU-boost override. Source was compiled /W4 /WX /O2 and actually booted with verified external v0 RomFS. It reached 1389 blocks with provider READY/files304207 and CPU hint succeeded. nnosInitialize returned, ready1/inits0/finis0; G3 OPEN. No general FS, mounts, saves, IPC, graphics or unrelated HLE. RFS/G4/CPUHLE files MUST remain frozen.

## Actual blocker and semantics
`start-w43-boost/{run_start.log,result.json}`: code16 UNSUPPORTED_INSN, status24, sdk PC/target0x1020119964 word0xaa2c03e8 `mvn x8,x12` = ORN x8,xzr,x12,LSL0. This is a G3 translation gap, NOT new G4 authorization needed. Mac executes hardware ARM64; preserve instruction semantics in native AOT, no runtime interpreter/JIT.

Implement generic MODULE-ONLY inverted logical shifted-register forms BIC/ORN/EON/BICS (MVN alias), W/X, all legal shifts LSL/LSR/ASR/ROR and registers31-as-ZR. Reuse logical_reg IR/emitter and aot_logic/shift helpers. Shift operand2 FIRST, then invert at width, then apply logical operation. Invert-BEFORE-shift is wrong for nonzero LSL/LSR, yet actual MVN LSL0 would pass it, so discriminative tests mandatory. BICS sets N/Z and clears C/V like ANDS; all others preserve NZCV. W result truncates+zero extends, W shift imm6 bit5 stays RESERVED. Rd31 discards but BICS still flags; Rn/Rm31 readZR, neverSP.

Inspect existing decode/IR/emitter before editing. N1 module-only acceptance must NOT open the G2 single-image subset. Keep all guards. Prefer invert field ONLY on new N1 forms + emitter defaultFalse, so N0/G2 serialized IR shape/output identity remains byte-identical; do not casually update existing goldens to hide drift. Validate masks/fields using actual llvm-mc + independent Capstone, not guessed words.

## Evidence / controls
Existing `g3_newfamily_diff.py` has260scalar/memory/NZCV scenarios and21compiled mutants. Extend that existing harness with rich new matrix for4ops/2widths, aliases, high32 canaries, zero/MSB/pattern operands, LSL/LSR nonzero andwidthmax, ASR/ROR. Use LLVM assembled words and Unicorn independent offline oracle; no runtime ARM decoder/execution. Don't claim vectors/FPCR/FPSR exact if harness omits them (current scalar capture limitation known).

Extend module-decode probe actualwords4ops/2widths/shifts/MVN + reserved refusals; assert G2 still refuses N1. Add meaningful ignoreN, invertBEFOREshift, BICSskipflags wrong-implementation controls (or2if3rd truly redundant), preserving old21 first-mismatch contracts. A mutant only rejected for semantic mismatch, never a compile/setup crash; assert unique replacement sites when patching generated C. Keep /W4 /WX and actual /O2 unchanged. No parser broad rewrite, no single-game-word specialcase.

## Task exit / time
Target bounded7-9min, hard15min watchdog; settle honest checkpoint BEFORE timeout even unfinished. Run targeted moduledecode/newfamily differential + identity/nonidentity tests, not full73 or real17GB boot (lead owns). Use cached external build or new external one, point CMake to OWN source (do not reuse cache bound w43). Reproduce current Python/LLVM/VCVARS flags from <local-work>/build-w43-full/CMakeCache.txt and CTestTestfile.cmake. Build tests only, exact command/evidence and scenario/mutant counts, infra_failures. No code/config/G2 golden weakening. No PORTING_STATUS gate change; add lasting decision only if truly needed (normally simple coverage extension under existing D008).

Deliver changed files, semantics, test counts/first mismatch examples, limits, then STOP/SETTLE. Lead reviews and resumes same FS-enabled Start to next observed blocker. No implementing another ISA/subsystem unobserved.
