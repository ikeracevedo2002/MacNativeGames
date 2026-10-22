# MSR TPIDR_EL0 — current facts and remaining review repairs

Source canonicalw19-2. Module-only exactmask0xffffffe0==0xd51bd040, sourceRt low5bits, emitted canonicalstate.tpidr=aot_gpr_zr(s,Rt), Rt31zero/notSP. No hostTLS/TPIDRRO writes/HLE/monitorclear. LegacyG2rejection and unrelatedMSR rejection preserved. Haiku w16 source review found correct actual lowering. Native Start nowpassesoriginalSDK+0x12fe60 and guestwritesThreadTypeowner0x1001 (nohostpatch).

## Compiler evidence corrected, then independently recovered

Worker originally falselyclaimed NF_OPT Debug/Release /WX: permanentnewfamilyhelper actuallyhardcodes /W4/O2 andignoresNF_OPT; itsattemptedstringreplacementfailed. Correctedworkerstatement `msr-note.md`. DoNOTreuseoldfalseclaim.

Lead independentlyloaded CURRENTtestsource and asserted EXACTLYONEliteral `cl /nologo /W4 /O2 /std:c11` before in-memory replacement with `/W4 /WX /Od`, separately `/W4 /WX /O2`; unique-match assertionspassed, actual nativecompileandallcasescompleted exit0. Logs `w19-lead-msr-od-wx.log`, `w19-lead-msr-o2-wx.log` begin explicitflagoverrideconfirmation. Both90TOTALfamily scenarios exactvsUnicorn2.1.4A57,11compiledmutantsrejected inclMSRnoop/wrongTPIDRRO/XZRasSP. These flags are controlledleadprobes, NOTpermanentconfigsupportinthetestscript. LatestfullCTest61/61each usespermanentharnessdefaultflagswhereapplicable; doNOTinferembeddedcompilerconfigfromCTestconfig.

## Remaining important test repairs

1. InitialTPIDR/TPIDRROcurrentlyzero in nativeandUnicorn; Rt31writezero cannotdistinguishskip-for-XZR. Seedbothdistinctnonzero markers andaddRt31-onlyskipmutant. Existingall-MSRnoopmutantisrejectedbyotherRts, notproofthisedgeworks.
2. Serialize/compare seededV32x128 andFPCR/FPSR ifclaimingpreservationcoverage. Currentdump54TOKENS (includeslabels,NOT54architecturalfields) checksGPR/SP/NZCV/NEXT/fault/page/TPregs; NOTfullcanonicalstate. DirectblockNEXTvsUCcontrolPCcontract mustremaincorrect; don'tcompareunmaintainednativebodyPC toUCpostRETPC blindly.
3. Rt0/8/30/31 entrylabels run12initial-statevariants each =48MSRscenarioswithin90TOTAL. Rt30writesconstantLR, Rt31zero, butothercanaryGPRsvary; thesearelegitimatepreservationcontexts, NOT48distinctwrittenvalues. Don'tcollapseusefulcasesmerelytochangeheadlinecount. Rt0/8includehigh64/bit63edges; optionalexplicittrunc32mutantmakescoveragevisible.
4. AddRt18positivecase toproveguestx18source(notanyhostABIregister); referenceMacpatchrawx18rewritemaybeambiguous, actualAOTcanonicalmodelmustgovern.
5. CapstoneindependentcheckSYSREGname/operand, notonlymnemonicanddecoderRt. RealunrelatedMSRnegativewordsmustdecodeasvalidCapstoneinstructionsbeforeclaimingvalidunsupportedencodings; don'tblindlycopyunverifiedsuggestedneighbors.
6. Permanenttestcompilerflag/configinterface +/WX, labelvalidationinparsedump, truthfuldocstring. Reportcompilediagnosticsoninfrastructurefail.
7. DedicatedLDXR-MSR-STXRpositivecontrolnotyetadded; loweringcontainsnomonitoroperation,butpersistenceisnotdirectlyexercisedhere.

No newpublicRuntimeABI/backenddecision. No whole-module/G3closureclaim.
