# D024 Stage C — first Windows validation and measurement (2026-10-23)

Machine: the developer's Windows x64 box (VS 18 / MSVC 19.51, LLVM, local TotK 1.0.0 data).
Source: `windows-x86-port` at `1eba8cd` (cloud Stage C work) plus `69b973e` (Windows path fix).
Only numbers, addresses already in DECISIONS.md, and hashes; no game bytes.

## 1. CTest battery (EXECUTION_PLAN §9 step 1)

- 84 tests registered with `MN_TOTK_V0_DIR` and `MN_TOTK_ROOTS_DIR`, as the plan predicted.
  The 79 without data is not separately run.
- At `1eba8cd`: 83/84 in Debug and in Release, 0 build warnings. The failure was
  `aot_g3_start_prefix_classification`:
  - `build()` spelled the `CORE` sources with mixed separators (`repo\src/aot/x.c`);
  - the object cache key includes the path, so one TU could get two keys;
  - this is Linux-invisible.
  - Fixed in `69b973e` (`os.path.normpath`). The test passes after the fix (run directly; the
    test is configuration independent). The full battery was not re-run after the one-line fix.

## 2. Legacy baseline (step 2, plan 1.1.5)

Command: `g3_start_prefix.py --backend legacy --max-iterations 6 --romfs-config <v0>/romfs-init/romfs_config.h --timing-out …`.

| it | t_total | translate (main/sdk/sub) | compile | link | run | admitted |
|---:|---:|---|---:|---:|---:|---|
| 0 | 66.0 | 4.5 / 4.4 / 0.4 | 5.6 | 1.1 | 44.7 | veneer 0x1002146110 |
| 1 | 54.2 | 4.4 / 4.3 / 0.4 | 1.1 | 1.0 | 40.8 | main#0 0x1000001520 |
| 2 | 53.2 | 4.5 / 4.3 / 0.4 | 1.1 | 1.0 | 40.8 | main#1 0x1000016830 |
| 3 | 53.6 | 4.3 / 4.4 / 0.4 | 1.1 | 1.1 | 41.3 | main#2 0x100001ba50 |
| 4 | 53.5 | 4.4 / 4.4 / 0.4 | 1.1 | 1.0 | 41.1 | main#3 0x1000034b70 |
| 5 | 53.9 | 4.5 / 4.3 / 0.4 | 1.1 | 1.2 | 41.3 | main#4 0x1000034bd0 |

Steady-state median: 53.6 s per iteration.

The object cache works in legacy too: `BUILD compiled=23 reused=0`, then `compiled=1 reused=22`.
The concerns noted by the cloud agent did not cause problems: `/Fo:` and `/OUT:` quoting, `link`
resolution after vcvars, and the `cl` banner as compiler id. The pruning of `work/obj` is still open.

## 3. Catalog backend with equivalence (step 3, plan 1.2.9)

Command: `--backend catalog --equivalence-check --max-iterations 8`.

- **8/8 `EQUIV ok`, 0 REFUSED, 0 partition mismatches.**
- Admission order identical to legacy and to the historical `start-w21-ctor` run:
  veneer `0x1002146110`, then main#0 … main#6 (`0x1520`, `0x16830`, `0x1ba50`, `0x34b70`,
  `0x34bd0`, `0x361c0`, `0x36220`).
- One-time catalog preparation: main 59 windows / 5.0 s, subsdk0 34 / 0.4 s, sdk 246 / 1.8 s
  (32 next constructors each).
- Steady state per iteration (iterations 1–7):

| phase | legacy | catalog |
|---|---:|---:|
| translate / table | 9.3 s | 4.5–4.7 s |
| compile + link | 2.1 s | 2.1 s |
| run | 41.2 s | 41.2 s |
| total without the equivalence re-run | 53.6 s | ≈ 48.9 s (−9 %) |
| equivalence re-run (legacy build + run) | — | 52.6 s |

## 4. Where the time goes

- `run` is 77 % of a legacy iteration. The probe reruns Start from the beginning:
  - About 1.26 M translated block dispatches, which take little time.
  - The D020 RomFS provider's mandatory full verification: SHA-256 of the 17,069,139,640-byte
    `romfs.bin` with the portable `aot_sha256` (`src/romfs_provider.c` `hash_image`).
- Throughput check: an optimized SHA-256 (Python `hashlib`, OpenSSL with SHA extensions) hashes
  the same file in 8.2 s (≈ 2.1 GB/s), file in the OS cache. So I/O is not the limit; the 41 s
  is consistent with about 415 MB/s software SHA-256 plus guest execution. This is inferred
  from arithmetic; the probe was not instrumented per phase.
- The catalog `table` step still costs about 4.5 s. It recomputes the full admitted closure of
  main with `module_cfg`; the emission itself is small.

## 5. Consequence for the 1.6 gate

Criterion (c) requires ≥ 50 % lower median `t_total` than legacy.

- Measured: about 9 %.
- Upper bound even with translate, compile and link at zero: about 21 %, because `run` dominates.
- Criteria (a), 0 equivalence mismatches, and (b), negatives rejected, hold for what was run.

Stage C as specified cannot pass gate (c); a decision is needed (see PROJECT_STATE / the lead's report).
Steps 1.5 (40-iteration measurement) and 1.6 were not run.

## 6. After the RomFS hash change (2026-10-23, user decisions 1 and 2a)

Change: image/overlay hashing through the host CNG SHA-256 (`src/host_sha256.c`); full
verification is still mandatory on every init (D020 amendment). Battery: 86/86 in Debug and
Release, 0 warnings (adds `host_sha256`, `host_sha256_mutants`).

Legacy, 6 iterations (`start-c3-legacy`): same admissions as before.

| it | t_total | translate | compile | link | run |
|---:|---:|---:|---:|---:|---:|
| 0 | 33.7 | 9.6 | 5.6 | 1.1 | 12.3 |
| 1 | 22.6 | 9.1 | 1.1 | 1.0 | 9.1 |
| 2 | 21.6 | 9.2 | 1.1 | 1.0 | 9.2 |
| 3 | 21.4 | 9.1 | 1.1 | 1.0 | 9.1 |
| 4 | 24.7 | 9.3 | 1.3 | 1.2 | 11.8 |
| 5 | 24.5 | 9.2 | 1.1 | 1.1 | 11.9 |

Steady median 22.6 s (was 53.6 s).

Catalog + `--equivalence-check`, 8 iterations (`start-c3-catalog`): **8/8 EQUIV ok**, 0 REFUSED,
same admissions (veneer, main#0 … main#6). Steady state (iterations 1–7): table 4.4–4.7 s,
compile + link 2.3 s, run 12.3–12.8 s, equivalence re-run 23.7–24.9 s. Excluding the
equivalence re-run, the time per admission is 20.1–22.2 s, median 20.8 s.

Result under the restated gate (absolute time per admitted constructor):

| backend | per admission (median) |
|---|---:|
| legacy, before hash change | 53.6 s |
| legacy, after | 22.6 s |
| catalog, after (no equivalence) | 20.8 s (≈ −8 % vs legacy) |

Notes:
- The catalog's Start run is consistently ~1.5–3 s slower than legacy's (12.6 vs 9.1–11.9 s).
  Not explained; possibly the larger executable or file-cache interaction with the
  interleaved equivalence run. Not investigated.
- Remaining costs per admission: Start rerun (~10–12 s) and the main closure recomputation in
  the table step (~4.5 s). Making the table incremental (option b) or resuming without a
  restart (option c, needs a new decision) are the only further levers.
- Not run: step 1.5's 40-iteration measurement and the D008 generated-code microbench.
