#!/usr/bin/env python3
"""G3 increment 4, work item A: pin the Mac observer/override derivation.

Runs tools/aot/extract_mac_bindings.py over this repository's Mac sources and
checks the result is the documented one:

  * exactly 6 observers, in services.c source order;
  * exactly 171 overrides in the default Mac desktop configuration
    (6 + 171 = 177 thunk slots; the brief's "~173" counts the two inverted
    Get*Handles probes, which are NOT overrides while rumble/gyro are on);
  * the two inverted hid probes are reported as excluded, with their flags;
  * the movie::Decoder table (22 names: 20 + 2 aliases) is present, because
    libvpx is available in that configuration;
  * observers and overrides are disjoint and the output is deterministic.

No game data is involved: the input is C source text from games/totk/runtime
and games/totk/third_party.  Two negative controls prove the configuration is
really consulted (a parser that ignored the conditions could not pass them):
  * gyro off  -> exactly the 4 gyro-flagged detail records leave, the inverted
    GetSixAxisSensorHandles probe becomes an override, observers unchanged;
  * libvpx off -> exactly the 22 movie::Decoder names leave.

Usage: g3_mac_bindings_test.py --tools <dir with extract_mac_bindings.py>
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile

OBSERVERS = [
    "_ZN2nn2os21AllocateAddressRegionEPmm",
    "_ZN2nn2os19AllocateMemoryPagesEmm",
    "nnosInitialize",
    "nninitInitializeSdkModule",
    "nninitStartup",
    "nnMain",
]
OVERRIDE_COUNT = 171
MOVIE_COUNT = 22
GYRO_RECORDS = 4          # {..., true} records in hid_feedback.c
RUMBLE_RECORDS = 7        # {..., false} records
INVERTED = 2              # hid strcmp probes that return NULL when on


def run(tools, out, config=None):
    cmd = [sys.executable, os.path.join(tools, "extract_mac_bindings.py"),
           "--out", out, "--quiet"]
    if config is not None:
        cmd.extend(["--config", config])
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit("g3_mac_bindings_test: extractor failed: %s%s"
                         % (proc.stdout, proc.stderr))
    with open(out, encoding="utf-8") as f:
        return json.load(f)


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--tools", required=True)
    args = ap.parse_args(argv[1:])
    failures = []

    def check(cond, what):
        if not cond:
            failures.append(what)

    with tempfile.TemporaryDirectory() as tmp:
        a_path = os.path.join(tmp, "a.json")
        b_path = os.path.join(tmp, "b.json")
        doc = run(args.tools, a_path)
        run(args.tools, b_path)
        with open(a_path, "rb") as f:
            first = f.read()
        with open(b_path, "rb") as f:
            second = f.read()
        check(first == second, "the extractor output is deterministic")

        check(doc["counts"]["observers"] == 6,
              "6 observers (got %d)" % doc["counts"]["observers"])
        check(doc["observers"] == OBSERVERS,
              "observer list and order match services.c")
        check(doc["counts"]["overrides"] == OVERRIDE_COUNT,
              "%d overrides (got %d)"
              % (OVERRIDE_COUNT, doc["counts"]["overrides"]))
        check(not set(doc["observers"]) & set(doc["overrides"]),
              "observers and overrides are disjoint")
        check(len(set(doc["overrides"])) == len(doc["overrides"]),
              "override names are unique")
        check("nnMain" in doc["observers"], "nnMain is an observer")
        check("nvnBootstrapLoader" in doc["overrides"],
              "nvnBootstrapLoader is an override (HLE_FORCE)")
        movie = [n for n in doc["overrides"]
                 if n.startswith("_ZN5movie7Decoder")]
        check(len(movie) == MOVIE_COUNT,
              "%d movie::Decoder overrides (got %d)"
              % (MOVIE_COUNT, len(movie)))
        excluded = doc["excluded"]
        check(len(excluded) == INVERTED,
              "%d inverted hid probes excluded (got %d)"
              % (INVERTED, len(excluded)))
        check(any("GetVibrationDeviceHandles" in n for n in excluded),
              "GetVibrationDeviceHandles is excluded (rumble on)")
        check(any("GetSixAxisSensorHandles" in n for n in excluded),
              "GetSixAxisSensorHandles is excluded (gyro on)")
        hid = [n for n in doc["overrides"] if n.startswith("_ZN2nn3hid6detail")]
        check(len(hid) == GYRO_RECORDS + RUMBLE_RECORDS,
              "all %d hid detail records are overrides (got %d)"
              % (GYRO_RECORDS + RUMBLE_RECORDS, len(hid)))

        # Negative control 1: gyro off.
        cfg = os.path.join(tmp, "gyro_off.json")
        with open(cfg, "w", encoding="utf-8") as f:
            json.dump({"runtime_flags": {"gyro": False}}, f)
        gyro = run(args.tools, os.path.join(tmp, "gyro.json"), cfg)
        lost = set(doc["overrides"]) - set(gyro["overrides"])
        gained = set(gyro["overrides"]) - set(doc["overrides"])
        check(len(lost) == GYRO_RECORDS,
              "gyro off removes exactly %d records (removed %d: %s)"
              % (GYRO_RECORDS, len(lost), sorted(lost)))
        check(all(n.startswith("_ZN2nn3hid6detail") for n in lost),
              "only hid detail records depend on gyro")
        check(len(gained) == 1 and
              any("GetSixAxisSensorHandles" in n for n in gained),
              "gyro off makes the inverted six-axis probe an override")
        check(gyro["counts"]["observers"] == 6,
              "the observer table does not depend on the hid flags")
        check(gyro["counts"]["overrides"] ==
              OVERRIDE_COUNT - GYRO_RECORDS + 1,
              "gyro-off override count is %d (got %d)"
              % (OVERRIDE_COUNT - GYRO_RECORDS + 1,
                 gyro["counts"]["overrides"]))

        # Negative control 2: no libvpx (the iPhone/no-video configuration).
        cfg = os.path.join(tmp, "novpx.json")
        with open(cfg, "w", encoding="utf-8") as f:
            json.dump({"macros": {"TOTK_MOVIE_HOST": 0}}, f)
        novpx = run(args.tools, os.path.join(tmp, "novpx.json"), cfg)
        lost = set(doc["overrides"]) - set(novpx["overrides"])
        check(len(lost) == MOVIE_COUNT,
              "no libvpx removes exactly %d movie names (removed %d)"
              % (MOVIE_COUNT, len(lost)))
        check(all(n.startswith("_ZN5movie7Decoder") for n in lost),
              "only movie::Decoder names depend on libvpx")
        check(novpx["counts"]["overrides"] == OVERRIDE_COUNT - MOVIE_COUNT,
              "no-libvpx override count is %d (got %d)"
              % (OVERRIDE_COUNT - MOVIE_COUNT, novpx["counts"]["overrides"]))

    if failures:
        for what in failures:
            print("FAIL: %s" % what)
        print("g3_mac_bindings_test: FAILED")
        return 2
    print("g3_mac_bindings_test: 6 observers, %d overrides; configuration "
          "controls verified" % OVERRIDE_COUNT)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
