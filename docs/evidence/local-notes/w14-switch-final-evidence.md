# Verified D022 local-switch increment — frozen w14-3

Candidate `<worktrees>/w14-3`, not committed/integrated. G3 OPEN. Scope explicitly authorized by user: MODULE-ONLY bounded local CFG successors, never independent roots or global indirect-target seeding.

## Evidence
- Opus w16 independently reviewed core and native; final H1-R corrective review found no remaining critical issue, conditional on frozen tests/real metadata. Those validation conditions were then met.
- Final frozen full native builds: Debug and Release exit0.
- Full CTest Debug **76/76**, 227.02s; Release **76/76**, 431.07s. Logs `w14-frozen-ctest-{debug,release}.log`.
- Unit policy suite: 31 test functions, including malformed/count/range/RO/source/owner/data/relocation checks, unreachable candidate, forged edges, nonlinear base paths, alternative entries, and strict-final rejection of unvisited branches into ADD/BR after the load.
- Durable native/oracle CTest: actual emitted C over real AotMem domain/attached token, finite direct compiled-BB dev probe, generic N5 fixture. Independent Unicorn A57 comparison of GPR/SP/NZCV/next-PC/memory; normal/default cases; ADR-block guard-bypass case. Three compiled wrong-emit variants distinguish no guard, extra allowed target and first-target-only. Not a full Program/AS-protection probe; no ARM decoder in production.
- G2 identity is part of the full suite: 16 files unchanged except existing two allowed provenance lines.
- Actual readonly SDK: original **213 roots unchanged**, 3421 basic blocks; six distinct site successors; final closure; case-body backedge decoded.
- Same production boot command/profile: `start-w14-switch.log` and `start-w14-switch/{run_start.log,result.json,img/sdk_real.meta.json}`. The original switch BR at `0x102008db10` now executes through local target `0x102008db18`, with no root-follow exception.
- Original fast missing-block witness now passes unchanged when pointed at `start-w14-switch/img/sdk_real.meta.json`.

## New demonstrated blocker (continuing, not stopping here)
At **2096 blocks**, unsupported `UMULH x9,x10,x9`, word `0x9bc97d49`, SDK PC/target `0x102008dc30`, code16/status1. This is another small generic AOT coverage gap, not new HLE/subsystem work. Delegated successor w17 from this exact frozen source, MODULE-ONLY UMULH X with existing correct unsigned-high helper and discriminative tests. No wider ISA authorized ahead of real evidence.

## Explicit limits
No DT_INIT completion, 10700-slot witness, guest return, nnMain execution or G3 closure. Code extent evidence is the pinned defined-FUNC/TEXT metadata plus exclusion checks, not a universal classifier for unannotated literal data. Raw branch-word scanning is negative-only and may conservatively reject DATA-like words; it never introduces code/roots. EH-frame exclusion uses a documented RO-suffix over-approximation. D021's earlier static-reach limitations are unchanged. Native proof variants intentionally bypass the CLI proof gate only inside the synthetic test.
