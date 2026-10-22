# GetInfo budget review — w19-2

Implementation exists and is validated, not merely a plan. Mac formula family6/21 pool,7/22 used; borrowed immutable pool/image budget wired from actual AOT descriptor sum; ASlogicalheap.size dynamically queried; current alias role immutableRESERVEONLY0committed. Overflow check uses subtraction before addition. G3OPEN.

## Evidence

Latest source w19-2: Debug and Release full CTest61/61 PASS (367.21/369.76s), plus narrowHLE5/5 each /W4/WX. Native `start-w19-budget`:233steps, GetInfo21=1/22=1, budget_fail0; next actual blocker SVC6 QueryMemory0, not accounting. Budgetprobe standalone preserves full state on fault, otherstate on success. New test had unfinished setup: lead fixed unusedvar, rootprintf five missing placeholders, invalid1MiB/1.5MiB heap sizes (now8->4->6MiB), wrong fault snapshot (r1=id set BEFOREsnapshot), missing actual poison+heap fixture, off-by-one info22counter(low32row), forgottenheaprestore afterfault row, and weak mutant setup/fault acceptance. All four wrappers now require normal no-fault expected value-only corruption plus preserved state, same-fixturebaselinegreen. Actualhighwater8MiB differslogical6MiB; overflowrow nonvacuous.

Independent Haiku w20 read-only: no branch correctness bug under scoped profile; confirmed fixes and ABI/printf/counters/lifetime. Review not an execution claim; lead ran tests.

## Pending semantic/doc decisions (do NOT silently choose)

1. Header says image sum page-up applied by caller; root sums descriptor image_size without explicit page-up. Actual current sum0x5ae8000 is pagealigned, so no observed currentnative discrepancy. Future unalignedprofile couldunderreport up to4095; either checkedroundonce andbudgetlimitconsistent oraccuratedoc+profilevalidation. Macpage_up rounds sum.
2. Macruntime_image_bytes sums rewrittenMac `key_off` (0x4000-aligned), not AOTdescriptor.image_size. Host rewrite/keyarea footprint can differ. D018alreadyusesactualAOTpinnedimagebudgetforcommitlimit; doNOTclaim numericMacfootprintparitywithoutcomparison. Document scope orjustify changedaccounting throughreview, not fakezeros/forceMacbytecount blind.
3. Pool6/21 currently require usableAS+heap, thoughMacconstant doesn't. Validnativeprofilealwaysmeetsguard; possibleovergatingonlymalformedhostenvironment. DecidewhetherpurebudgetqueryshouldsucceedwithoutAS; addexplicitrowsifchanged. Not a guest runtime failure observed.

## Remaining low-priority test/code cleanup

- Redundant used>pool branch after `heap<=pool-image` cannotfire; row currentlycoversheap>pool-image, labelaccordingly/removeunreachabledefenseifdesired.
- Factor sharedvaluecomparison forpositive+wrongfieldwrappers so weakeningpositivecomparatorcannotescapecontrols.
- ctx2.budget_failures>=3 canbeexact3; setupreturns shouldsayFATAL.
- G3BUDGETprint usesknownfixtureconstants, NOT independentobservedstate evidence; relyassertions/nativeG3HLE counters.
- Header current-surface doc omitsnewids.

No MapMemory support; aliasbytes0 is only valid for currentimmutable reserve-only profile. General aliasmappingmustextend accounting. No commits/integration/PORTING_STATUSgate change.
