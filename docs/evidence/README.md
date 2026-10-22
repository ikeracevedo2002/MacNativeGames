# Local evidence notes (imported 2026-10-22)

These are the lead's and workers' working notes from G3 and the early G4 work,
copied from the developer machine (`C:\Users\IKER\mn-g3-local`, `C:\Users\IKER\mn-research`)
so that analysis without that machine has the full history.

How to read them:

- They are **lab notes, not project facts**. Many describe candidates that were later
  corrected, superseded or integrated under a different shape. The authoritative
  record is `DECISIONS.md`, `PORTING_STATUS.md` and `docs/PROJECT_STATE.md`. When a
  note disagrees with them, the note is historical.
- Worker names (`w14-3`, `w21-2`, ...) are harness worktrees under
  `C:\Users\IKER\.pi\agent\harness\worktrees\MacNativeGames-106250b2\`. Everything that
  matters from them has been integrated into `windows-x86-port` (see PROJECT_STATE);
  the worktrees themselves are not in the repository.
- Paths such as `start-w21-ctor/`, `build-*/`, `v0/` refer to local build and run
  directories that hold game-derived data. They are intentionally **not** in the
  repository (D006).
- Redaction: lines with raw game disassembly or byte dumps were replaced by
  `[N line(s) ... omitted ...]`. No keys, NSO/RomFS data or generated game code are
  included. Addresses, instruction mnemonics, counts and hashes are kept.
- Text is as written, often compressed shorthand; a few non-ASCII characters were lost
  in the copy (shown as `�`).

## Index (roughly chronological by topic)

### Reachability / coverage measurements on the real 1.0.0 modules
| File | Content |
|---|---|
| `dtinit-integrated-baseline-coverage.md` | Module-mode decoder coverage on real main/subsdk0/sdk (work item E) |
| `dtinit-reach-1.md` … `dtinit-reach-9.md` | Successive DT_INIT reachable-CFG measurements as ISA families were added |
| `reach-paired-d3.md`, `reach-paired-latest.md`, `reach-w19-lead.md` | Later paired reach measurements |

### ISA increments and their reviews
| File | Content |
|---|---|
| `g3-inverted-logical-brief.md` | Inverted logical shifted-register increment |
| `dtinit-family-review-todo.md`, `dtinit-review-todo.md` | Review queues for the new-family differential tests |
| `g3-msr-review-todo.md`, `msr-note.md` | MSR TPIDR_EL0 handling |
| `g3-checkpoint-w10-before-switch.md` | RBIT + DMB ISH checkpoint before the local-switch decision |

### Memory / SVC services needed by Start (became D018, D019)
| File | Content |
|---|---|
| `g3-heap-design-reviewed.md` | Boot heap design (D018) |
| `g3-alias-map-design.md`, `g3-alias-release-codegen.md` | Physical alias mapping SVC 0x2c/0x2d (D019) and a Release-only codegen issue |
| `g3-query0-reviewed.md` | QueryMemory(0) blocker |
| `g3-budget-review-todo.md` | GetInfo budget review |
| `g3-svc6-thread-review-todo.md` | SVC 6 / thread info review |

### Filesystem boundary and early G4 RomFS provider (became D020)
| File | Content |
|---|---|
| `g3-fs-initialization-boundary.md` | Start blocked at real filesystem init; why a provider was needed |
| `w33-final-validation.md` | Increment validation; faithful Start blocked before FS |
| `g4-romfs-provider-brief.md`, `g4-romfs-provider-review-todo.md` | Provider brief and review |
| `g4-romfs-start-wiring-brief.md` | Wiring the provider into the real Start run |

### Control-flow roots (became D021, D022, D023)
| File | Content |
|---|---|
| `g3-callback-target-investigation.md` | Indirect target `0x1002146110` (allocator veneer) investigation |
| `g3-veneer-root-proof-brief.md`, `g3-veneer-root-wiring-brief.md` | D021 veneer root proof and wiring |
| `g3-local-switch-decision.md`, `w14-switch-final-evidence.md` | D022 local switch in `__nnmusl_init_dso` |
| `g3-ctor-witness-reviewed.md` | Constructor witness design |
| `g3-current-checkpoint.md` | First constructor root blocked at main `0x1520` (pre-D023) |
| `g3-init-array-root-decision.md` | Proposal that became D023 |
| `dtinit-continuation-status-pre-w14.md`, `dtinit-continuation-status.md` | Long running status logs (most detailed, least curated) |

### SavageWind audit probe outputs (supporting `docs/research/savagewind-audit.md`)
| File | Content |
|---|---|
| `sw-test-layout.log` | SavageWind `tools/test_layout.py`: 55/55 |
| `sw-totk-constructors.json`, `sw-totk-generator-boundaries.json`, `sw-totk-readonly-inventory.json` | Their tools on our 1.0.0 modules: FDE/constructor counts |
| `mn-ctor-structural-audit.json` | Our `g3_ctor_roots.derive()` accepts all three tables |

The NVN version-guard disassembly (`totk-nvn-version-guard.txt`) was not imported; its
conclusion (major == 55, minor >= 15) is in the audit.
