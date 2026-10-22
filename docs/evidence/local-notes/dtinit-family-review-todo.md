# Newfamily test review (Haiku w7, lead-confirmed source issues)

Fix before calling suite adequate or integration-ready. Current 12 rows are a useful smoke test, not full differential evidence.

- TBZ/TBNZ all three entries take the branch under both seeds. Explicitly test each site with tested bit clear and set; verify both next PCs. Add always-taken/always-fallthrough compiled mutants or ensure existing bit flip is rejected on both branches.
- t_alu overwrites every consumed input and CMP fixes NZCV; two seeds aren't condition matrix. Add CSEL/CSINC/CSINV/CSNEG X/W all16 conditions over all16 NZCV nibbles, no preceding CMP. Include aliases/ZR and AL/NV.
- Proper logical-immediate SP destinations have Rn GPR/ZR, NOT SP: and sp,x0,#0xff 0x92401c1f; orr wsp,w1,#0x80000001 0x3201043f; eor sp,xzr,#1 0xd24003ff. Test these, SP restore not needed if direct leaf block with no memory-after.
- Fault case currently regex captures SRC/STATUS but asserts only FAULT==3 and x20 unchanged. Require exact src, target and status plus full GPR/SP/NZCV and byte-memory unchanged on fault (except runtime diagnostics). Dump target explicitly.
- Compare next_pc for normal leaf returns too, against guest LR. Fail unexpected Unicorn exceptions; do not silently ignore UcError outside the deliberate fault row. Require positive instruction-count slice instead of max(count,1).
- Dump and compare the 4096 memory bytes, not merely FNV checksum, if claiming byte-exact. Current FNV basis typo 1469598103934665603 vs canonical14695981039346656037; equal custom hashes still useful but not byte-exact.
- Parse and validate native dump BEFORE comparing mutants; empty/truncated stdout exit0 must be infrastructure, not rejected mutant. Same field-level comparator as real vs oracle; require expected named field mismatch for each mutant. Keep translation/compile/crash/timeout/parse as infra.
- Current mutant skip boolean condition is impossible; simplify proper mutant->scenario selection.
- Pass LLVM paths from CMake cache discovery, not IKER hardcoded default. Pin/check dev tool versions and select Unicorn ARM64_A57 explicitly, as existing G2 does. State memory stubs scope honestly (lowering/addressing not product memory permissions/model).
- Current test count12 includes fault rows not fully compared; report exact vs deliberate fault separately with actual dynamic check counts.
- Native partial trap proof also needs valid-prefix instruction preserving its effect before fault + drop-prefix mutant. Current trap-at-entry only is narrower.
