# Current G3 continuation status (lead checkpoint, not final report)

Main checkout windows-x86-port at d3b45204 is CLEAN, untouched. NO commits/integration; user approval `Integra` still required. User full goal/stop conditions in vcc_recall entry #1. Continue while a clear G3 blocker can responsibly be removed; do NOT stop merely at one ISA family or GetInfo selector. Minimal constructor-required HLE authorized, no G4/general headless/graphics.

## Current candidate / active work

Latest writable worker w9 DeepSeek opencode-go/deepseek-v4.1-flash high, branch pi-agent/w9-2, path <worktrees>/w9-2. It started from d3 and lead copied COMPLETE uncommitted w5-4 candidate (which itself contained all earlier ISA/tool/test work + Opus ABI repair + RNG + driver). Only w9 is latest canonical candidate; older worktrees kept, no cleanup/deletion.

W9 completed core heap + initial narrow tests, then HLE glue/GetInfo4/5/Svc1. It has QUEUED followup to fix Opus w11 test nonvacuity findings (M1-M3 + lows), about ~8min next repair block. Core architecture was frozen for review; review finished, now unfrozen for repairs. Need collect w9 outputs/check tests, then continue first actual new blocker (ALIAS GetInfo2).

w11 readonly Claude Opus5.5 high, cwd w9-2. Completed critical heap CODE review, no unsafe core transition bug; found test gaps + poisoned/no-heap guards, sent to w9. Currently queued followup architecture review of actual Info2/3 AS-owned immutable reservation and geometry avoiding existing thunk window; get result. Claude cannot Read external mn-g3-local (sandbox); provide facts/snippets via message if needed.

w10 readonly DeepSeek high, cwd main. Completed reliable metrics aggregation (see below); currently queued NEW plan for unbounded ctor witness via test-only cloned AotImage native block adapters (no public runtime ABI change if possible). Need collect compact exact-field/seam plan then Opus review if ABI-sensitive.

Other workers w1 failed timeout, w2/w3/w4/w5/w6/w7/w8 stopped. Opus w4 repaired critical translated ABI Start callbacks. Haiku w8 reviewed new RNG/HLE/driver; fixes in w5 then copied w9. Earlier ISA/FP/code-data reviews in prior context/vcc. Do not resurrect old source.

## Real execution: proper original Start, latest exact stop

External log <local-work>/v0/start-w9-2-heap/run_start.log, lead independently read:
- LOAD558865 sites digest1 (same validated link data; do not reopen linker).
- Proper Start mangled symbol _ZN2nn4init5StartEmmPFvvES2_S2_, sdk+0xfa060, args {mainhandle0x1001,0,ready/inits/finis GUEST thunks}. N177 -> window180, callbacks177..179.
- Transparent real delegates 5 observer functions under D016; nnMain deliberately unregistered. Real nnMain main+0xe99570 =0x1000e99570 explicitly excluded from supplemental roots/autofollow. No G4 execution.
- Main owned registry1001, guestThreadId0x51, priority44, core0/mask7, ownerOSthread. TLS8192/TLR512/dummy1024 guestRW; tpidr=TLS,tpidrro=TLR; TLR+1f8=dummy initial. NO owner patch. Actual owner read u32[[TLR+1f8]+1b0]. Still0 because nnosInitialize has not returned, not a current mutex error.
- 2 GetInfo11 entropy SVC successes via genuine BCryptGenRandom system preferred RNG. HLE register-only rawx0=0,x1=u64; never derefs rawx0; wrapper stores through saved out pointer. Zero/allones legitimate, deterministic provider tests, private compile-time backend seam exercises real failure branch, no global override.
- Heap AS-owned real reservation base0x4000000000(256GiB), max0x100000000(4GiB), commit_limit0xc7a18000, image_bytes0x5ae8000; logical0; host first page RESERVE/protNONE, diag ptrNULL. NO 4GBcommitupfront.
- GetInfo4 and5 each returned successfully once, no heap failure.
- Next ACTUAL stop: code7 BAD_HLE, sdk+0x1584b0 raw svc #0x29 word0xd4000521; status2 (unknown query selector), steps62. raw x0=0x200003fe78 x1=2 x2=0xffff8001 x3=0, x4=0x7f00000b30, x5..7=0, sp=0x200003fe40. ready/inits/finis0 => zero ctors on faithful path. entropy_calls2/failures0, svc1calls0. Need alias region profile, not new opcode.

Lead READ generated native-C SDK source (external, not committed) v0/start-w9-2-heap/img/sdk_real.c38280..38415: fn pc0x10201315f4 requests GetInfo4 atcallsite+131618 -> struct+0 heapbase, GetInfo5 at+13163c ->struct+8 max, GetInfo2 at+131660 ->struct+16 aliasbase, then GetInfo3 at+131684 ->struct+24 aliassize; errors branch failure. Thus paired2/3 request statically proven, NOT guess. No proof yet of Info12/14 etc next.

Mac services.c21-81: ALIAS_SPACE_AT0x7000000000(448GiB), ALIAS_SIZE64GiB desktop; this overlaps current D015 thunks508GiB! Do NOT blindly copy Mac alias numericbase or move validated thunks/linkdigest. Proposed safe AOT guest alias[320,384)GiB = [0x5000000000,0x6000000000), requires Opus recommendation + real AS owner/reserve-only no64GBcommit. IgnoreX2/X3 asMacGetInfo does. No fake HLE map: core owned immutable query-only reservation kind, getter from real AS. MapPhysical remains typed unsupported until actually hit, if design honest. Source Mac alias remap zero-on-remap differs heap retainbytes, only implement mapping when actual needed.

## Heap design / review obligations

Detailed accepted design <local-work>/g3-heap-design-reviewed.md. D018 in candidate is CANDIDATE heap capability, PortingStatus unchanged/G3OPEN. Heap impl src/aot/aot_as.c +h, aot_mem locked range invalidate. Public add heap preseal reserve-only, heap_info base/max/logicalsize, set_heap_size postseal. Highwater PRIVATE, no per-page AS flags allocated for heap; permissions/state derived logicalsize under domain lock.

Mac SetHeapSize310-313: 2MiB units, cap4GiB, size+image<=APP_POOL, invalidr0=d401 preservingr1size, successr0=0/r1base. Shrink ProtectNONE, retain committed bytes, regrow old bytes, new pages zero. HostVmCommit rejects alreadycommitted; grow fresh F=[hw,t) ONLYt>hw then retained R=[s,min(t,hw)) protectRW; failure rollback only newF, rollbackfail sticky. Shrink hostProtect first whilelocked; only success publish/invalidate monitors, failure leaves oldmap/reservations. No HLE callback under domainlock/no recursion. HOST status appended, old ordinalvalues unchanged.

Opus w11 CODE review found core logic sound, audited EVERY nullflags path/locks/memorycopies/queries. MUST FIX tests/guards (queued to w9):
M1 publish_before_host mutant FAULT_MODE4 needs correct positive aot_as_heap_fault_4, not normal; fault summary must include all...passed for runner.
M2 fault4 LDXR currently armed AFTER failing shrink; armBEFORE and STXRsuccess afterfailure. Normal positive uses onlyonetoken despiteother-runtime claim; arm2 tokens, both fail after successful shrink/regrow.
M3 faultmodes1/3 duplicate production fail branches; inject ONLY host result variables so REAL commit-fail and rollback-desync code runs in test.
L2 set_heap_size reject poisonedAS. L3 noheap=>RANGE, desync=>HOST.
Reset outsentinel immediatelybeforeeveryfailingcall; cap-onlybranch testcommit_limit>max; straddle [size-8,size+8) reserve boundary read/write/ld128 PERM unchangedbytes/noAV; module|heap straddle RANGE; mode3unpublishedfresh bytes inaccessible; mode2retainedbytes unchanged; 4GiBRESERVEONLY max,lastpage smoke (no commit).
Docs: host_page mustserializeHostVmquery; old n<=16 comment false for invalidationresize; old nohosterror comment stale; testctestnames aot_g3_as_heap.

## Validation already done (do not overclaim latest)

Before core heap change lead full w5-4 Debug+Release:46synthetic allgreen +3opt-in real allgreen=49 total, same config/source. Logs mn-g3-local/w5-4-{debug,release}-test-lead.log times132.99/129.61s; w5-4-real-{debug,release}-test-lead.log times9.37/4.82s. All49 explicitly composed, not single49log.
After RNG backend/classification repairs narrow3 tests Debug pass; true total then51.
W9 core first checkpoint: Debug aot_g3_as6/6; Release heap5/5; oldAS/program/runtime-mutants pass; mutantdriver19/19rejected includes6heap but above positive baseline/test gaps require repairs. Builddir mn-g3-local/build-w9-2. Need FULL current suite Debug/Release +real opt-in after core repairs, not yet done. All /W4 /WX compile guards and gitdiffcheck pass as of firstcheckpoint. Main stays clean. Build/GameC/logs all outsideSource, PYTHONDONTWRITEBYTECODE=1; remove own pyc caches if recreated.

## Metrics reliable paired NEW reports

Lead executed SAME CURRENT g3_init_reach.py and M against d3 decoder vs latest decoder; baseline exported git show d3b45204:aot_translate.py. Files outside:
- reach-paired-d3.{json,md,log}
- reach-paired-latest.{json,md,log}
- reach-paired-d3-current-analyzer/{g3_init_reach.py,aot_module.py,aot_translate.py}
Lead normalizedCRLF SHA verified frozen oldT==gitd3 EXACT sha a02cc8c33a6fbae12f18a4ec2bec727a7fa1e7cc36311303e610736fa6f2bfa7. M==d3==current. OLD frozenR differs current, so ignore stale reach-current/reach-9 as latest; new pair controlsanalysisversion properly.
Per module reachable words identical: main294687,sub1365,sdk27027,total323079; accepted I->F271629->294548 (92.18->99.95%),1355->1365(99.27->100%),23609->26568(87.35->98.30%), total296593->322481 (91.80->99.81), remaining598words139/0/459.
Entry candidates (NOTactualprovenwholefunctions)12623/55/719=13397; subset-complete47->1995,2->43,116->289,total165->2327. Global scan-clean/callable-completeWITHHELD=0 BOTH due349cap hits, static_proof_complete=false. No guaranteedfullstaticreach; snapshot-candidate11321,ambiguousindirectentry11047; roots10540/46/117 includes1DT_INITeach +ctor10539/45/116=10700. Blocks53972, indirect287(286textsnapshot,1thunk). Code/data3 flagged ambiguouspadding sites; do NOT treatallRXascodedata orwordpatternasproof. New T MADD/MSUB/MUL+FPmemoryS/D/Q accepted; final gaps ccmp/ccmn,varshifts,bic/mvn,dmb,CRC,rbit/clz,etc measuredcandidatesnotnecessarilyexecuted. W10 result/vcc hascompacttransitiveroot rows. No whole-function-proof count available, saysohonestly.
Advisory initialallRX83.43%/globalexports37.51%(12370/32979) measured, notprimarymetric/notcomparabledenominators.

## D008 evidence VERIFIED

Historical allrootspartial builder dtinit-lead-allroots.log:10703 roots, C68723587B,47437blocks,51unsupported, offlinegen7.6s,MSVCbuild35.0s. Lead stat NOWverified actualexe path mn-g3-local/dtinit-lead-allroots/aot_g3_dtinit_batch_probe.exe FILE18842624B, SizeOfImage18862080, AMD64machine0x8664, onlyKernel32imports. SHA25631b39001e4a0f9a6323c76f463fae286184b30f5cdf3ddf5d1687dad121b740f. Audit mn-g3-local/dtinit-allroots-pe-audit-verified.txt. This is partial allctor-root translation scale evidence, NOTcompletewholemodules/noCtorcompletion. No structuralCbackend blocker shown, D008stillprovisionalG3 vsfinalbackend separated; don'tmigratetoLLVMpreference.

## Pending exact G3 exit witness

Earlier isolatedmain15ctorsreturned16thMVN atmain+0xb9920 (word0x2a2803e0), subuntranslatedSDK+191854,SDKMutexAbortowner0 beforeproperprelude. Those are NOTfaithfulboot/gateclosure. NowproperStartblockedearlierInfo2.
Need sameAS/process originalmodule_inits callback main/sub/sdk DT_INIT SUCCESS + ALL10700 initarray slots orderedactualCALLatMODULE_BASE+148 and entry and return/semanticresumeMODULE_BASE+14c, SP/ABI restored, modifiedmemory/flags recorded. Flag2 writtenBEFOREloopnotcompletion. trace4096/event1024 onlyprefixcannotprove. W10planning test-only cloneDescriptor+AotImage nativeblockFnadapters BEFOREloaderinit (frozenafter), noCoreABIchange/noGuestVAhostcast; exacttypes/lifetimependingread-onlyplan+Opusreview. Needactualentryso'dropCALLjustjumptoresume'mutantdoesnotpass, handleHLEtargetsemanticreturns explicitly. No nnMain execution, cleanStartreturnorboundaryaloneNOTgatepass.
