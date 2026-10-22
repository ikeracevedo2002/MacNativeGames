#!/usr/bin/env python3
"""Game-data-free tests for the strict G4 RomFS config parser/emitter."""

import sys

sys.dont_write_bytecode = True

import json
import os
import tempfile
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO, "tools", "aot"))

import g4_romfs_config as G  # noqa: E402

EXPECTED = os.path.join(REPO, "games", "totk", "assets", "expected-v1.0.0.json")


def _octal_literal(value):
    return "".join("\\%03o" % byte for byte in value.encode("utf-8"))


def check(name, got, want):
    if got != want:
        print("FAIL: %s: got %r want %r" % (name, got, want))
        return 1
    return 0


def expect_error(name, fn):
    try:
        fn()
    except G.ConfigError:
        return 0
    print("FAIL: %s: expected ConfigError" % name)
    return 1


def good_config(expected):
    return (
        "#define ROMFS_IMAGE_SIZE %dULL\n"
        '#define ROMFS_IMAGE_SHA256 "%s"\n'
        '#define ROMFS_INDEX_SHA256 "%s"\n'
        % (expected["size"], expected["sha256"], "a" * 64)
    )


def main():
    failures = 0
    expected = G.load_expected(EXPECTED)
    failures += check("expected version/size", expected["size"], 17069139640)
    failures += check(
        "expected sha",
        expected["sha256"],
        "4751542f544d8c3406cb63ccfc68b42690ff0387228d1f0af021d1f0037dafcf",
    )

    parsed = G.parse_romfs_config(good_config(expected))
    failures += check("parsed size", parsed["ROMFS_IMAGE_SIZE"], expected["size"])
    failures += check(
        "parsed image sha", parsed["ROMFS_IMAGE_SHA256"], expected["sha256"]
    )
    failures += check("parsed index sha", parsed["ROMFS_INDEX_SHA256"], "a" * 64)
    failures += check(
        "blank lines allowed",
        G.parse_romfs_config("\n" + good_config(expected) + "\n")[
            "ROMFS_IMAGE_SIZE"
        ],
        expected["size"],
    )

    for label, text in [
        ("include", '#include "x.h"\n' + good_config(expected)),
        ("unknown macro", good_config(expected) + "#define TITLE_ID 1\n"),
        ("duplicate", good_config(expected) + good_config(expected)),
        (
            "uppercase sha",
            good_config(expected).replace(expected["sha256"], "A" * 64),
        ),
        (
            "malformed size",
            good_config(expected).replace(str(expected["size"]), "17GB"),
        ),
        (
            "missing macro",
            '#define ROMFS_IMAGE_SIZE %dULL\n' % expected["size"],
        ),
        (
            "code after define",
            good_config(expected).replace(
                "ULL\n", "ULL; system(\"x\");\n", 1
            ),
        ),
        ("nul", good_config(expected).replace("\n", "\x00\n", 1)),
        ("comment", "/* x */\n" + good_config(expected)),
    ]:
        failures += expect_error("parse rejects " + label,
                                 lambda t=text: G.parse_romfs_config(t))

    failures += expect_error(
        "pin wrong size",
        lambda: G.pin_config(
            {"ROMFS_IMAGE_SIZE": 1, "ROMFS_IMAGE_SHA256": expected["sha256"]},
            expected,
        ),
    )
    failures += expect_error(
        "pin wrong sha",
        lambda: G.pin_config(
            {"ROMFS_IMAGE_SIZE": expected["size"], "ROMFS_IMAGE_SHA256": "b" * 64},
            expected,
        ),
    )

    with tempfile.TemporaryDirectory() as tmp:
        profile = Path(tmp) / "v0"
        config_dir = profile / "romfs-init"
        config_dir.mkdir(parents=True)
        cfg_path = config_dir / "romfs_config.h"
        cfg_path.write_text(good_config(expected), encoding="utf-8")

        g4 = G.resolve_start_config(cfg_path, EXPECTED, environ={})
        failures += check("default resource", g4["resource_dir"],
                          str(config_dir.resolve()))
        failures += check(
            "default optional sibling",
            g4["overlays"],
            [{"dir": str(profile / "romfs-patches"), "required": 0}],
        )

        g4 = G.resolve_start_config(
            cfg_path, EXPECTED, environ={"TOTK_ROMFS": str(profile / "custom-romfs")}
        )
        failures += check("env resource", g4["resource_dir"],
                          str(profile / "custom-romfs"))
        failures += check(
            "env resource overlay sibling",
            g4["overlays"],
            [{"dir": str(profile / "romfs-patches"), "required": 0}],
        )

        g4 = G.resolve_start_config(
            cfg_path, EXPECTED, no_overlays=True, environ={}
        )
        failures += check("no overlays", g4["overlays"], [])
        failures += expect_error(
            "no-overlays conflict",
            lambda: G.resolve_start_config(
                cfg_path, EXPECTED, no_overlays=True,
                overlay_dir=str(profile / "p"), environ={}
            ),
        )

        g4 = G.resolve_start_config(
            cfg_path, EXPECTED,
            overlay_dir=str(profile / "opt"),
            required_overlay_dir=str(profile / "req"),
            environ={},
        )
        failures += check(
            "explicit optional+required",
            g4["overlays"],
            [
                {"dir": str(profile / "opt"), "required": 0},
                {"dir": str(profile / "req"), "required": 1},
            ],
        )
        failures += expect_error(
            "duplicate roots",
            lambda: G.resolve_start_config(
                cfg_path, EXPECTED,
                overlay_dir=str(profile / "same"),
                required_overlay_dir=str(profile / "same"),
                environ={},
            ),
        )
        failures += expect_error(
            "unsupported resolution env",
            lambda: G.resolve_start_config(
                cfg_path, EXPECTED,
                environ={"TOTK_ROMFS_PATCHES_OUT": "1920x1080"},
            ),
        )
        failures += expect_error(
            "TOTK_OUTPUT_RES=2560x1440 auto-select refused",
            lambda: G.resolve_start_config(
                cfg_path, EXPECTED,
                environ={"TOTK_OUTPUT_RES": "2560x1440"},
            ),
        )
        failures += expect_error(
            "TOTK_OUTPUT_RES=auto refused",
            lambda: G.resolve_start_config(
                cfg_path, EXPECTED, environ={"TOTK_OUTPUT_RES": "auto"}
            ),
        )
        g4 = G.resolve_start_config(
            cfg_path, EXPECTED, environ={"TOTK_OUTPUT_RES": "0"}
        )
        failures += check("TOTK_OUTPUT_RES=0 headless", g4["output_res"], "0")
        g4 = G.resolve_start_config(
            cfg_path, EXPECTED,
            required_overlay_dir=str(profile / "req"),
            environ={"TOTK_OUTPUT_RES": "2560x1440"},
        )
        failures += check(
            "explicit required root allows output res",
            [o["required"] for o in g4["overlays"]],
            [0, 1],
        )
        failures += check(
            "explicit required root records canonical WxH",
            g4["output_res"],
            "2560x1440",
        )
        # The resolution REQUEST is validated even when a required root is
        # supplied: malformed or out-of-range values are caller errors, never a
        # silent downgrade or a fabricated resolution answer.
        for label, value in [
            ("malformed", "banana"),
            ("zero dimension", "0x1080"),
            ("below range", "320x240"),
            ("above range", "7681x4320"),
            ("short form", "1920"),
            ("nonsense size", "axb"),
        ]:
            failures += expect_error(
                "required root rejects bad TOTK_OUTPUT_RES " + label,
                lambda v=value: G.resolve_start_config(
                    cfg_path, EXPECTED,
                    required_overlay_dir=str(profile / "req"),
                    environ={"TOTK_OUTPUT_RES": v},
                ),
            )
        g4 = G.resolve_start_config(
            cfg_path, EXPECTED,
            required_overlay_dir=str(profile / "req"),
            environ={"TOTK_OUTPUT_RES": "640x360"},
        )
        failures += check(
            "required root accepts range minimum",
            g4["output_res"],
            "640x360",
        )
        for label, kwargs in [
            ("empty resource", {"resource_dir": ""}),
            ("empty overlay", {"overlay_dir": ""}),
            ("empty required overlay", {"required_overlay_dir": ""}),
        ]:
            failures += expect_error(
                "explicit " + label + " rejected",
                lambda kw=kwargs: G.resolve_start_config(
                    cfg_path, EXPECTED, environ={}, **kw
                ),
            )
        g4 = G.resolve_start_config(
            cfg_path, EXPECTED,
            required_overlay_dir=str(profile / "req"),
            environ={"TOTK_ROMFS_PATCHES": "0"},
        )
        failures += check(
            "patches=0 disables optional only",
            g4["overlays"],
            [{"dir": str(profile / "req"), "required": 1}],
        )

        failures += check(
            "disabled config",
            G.resolve_start_config(None, EXPECTED, environ={"TOTK_ROMFS": "x"}),
            None,
        )
        # Default stays disabled even with ambient selection variables; ambient
        # environment alone must neither enable G4 nor turn into an error.
        failures += check(
            "disabled ignores ambient selection vars",
            G.resolve_start_config(
                None, EXPECTED,
                environ={
                    "TOTK_ROMFS": "x",
                    "TOTK_ROMFS_PATCHES": "y",
                    "TOTK_ROMFS_PATCHES_OUT": "1920x1080",
                    "TOTK_OUTPUT_RES": "1920x1080",
                },
            ),
            None,
        )
        # Explicit CLI options WITHOUT a config are caller errors, not a silent
        # disable and not a fallthrough to the default.
        for label, kwargs in [
            ("resource", {"resource_dir": str(profile / "r")}),
            ("empty resource", {"resource_dir": ""}),
            ("overlay", {"overlay_dir": str(profile / "o")}),
            ("empty overlay", {"overlay_dir": ""}),
            ("required overlay", {"required_overlay_dir": str(profile / "q")}),
            ("empty required overlay", {"required_overlay_dir": ""}),
            ("no-overlays", {"no_overlays": True}),
        ]:
            failures += expect_error(
                "explicit %s without config rejected" % label,
                lambda kw=kwargs: G.resolve_start_config(
                    None, EXPECTED, environ={}, **kw
                ),
            )

        # Relative CLI roots are frozen to absolute paths at resolution time,
        # against the CALLER's cwd. This is serialized-profile invariance: the
        # emitted profile must not depend on whatever cwd a later consumer runs
        # with. Defensive robustness, not a known misresolution.
        caller = Path(tmp) / "caller-cwd"
        (caller / "res").mkdir(parents=True)
        (caller / "ovl").mkdir(parents=True)
        (caller / "req").mkdir(parents=True)
        work = Path(tmp) / "work"
        work.mkdir()
        previous_cwd = os.getcwd()
        try:
            os.chdir(caller)
            rel = G.resolve_start_config(
                cfg_path, EXPECTED,
                resource_dir="res",
                overlay_dir="ovl",
                required_overlay_dir="req",
                environ={},
            )
            want_res = str((caller / "res").resolve())
            want_dirs = [
                str((caller / "ovl").resolve()),
                str((caller / "req").resolve()),
            ]
            failures += check(
                "relative resource frozen absolute", rel["resource_dir"], want_res
            )
            failures += check(
                "relative overlay roots frozen absolute",
                [o["dir"] for o in rel["overlays"]],
                want_dirs,
            )
            failures += check(
                "frozen roots are absolute paths",
                all(
                    os.path.isabs(p)
                    for p in [rel["resource_dir"]]
                    + [o["dir"] for o in rel["overlays"]]
                ),
                True,
            )
            # Simulate the child's cwd (= --work) and re-check + emit there.
            os.chdir(work)
            failures += check(
                "frozen root unchanged after cwd change",
                rel["resource_dir"],
                want_res,
            )
            rel_c = Path(tmp) / "gen-relative.c"
            G.emit_config_c(rel, rel_c)
            rel_text = rel_c.read_text(encoding="ascii")
            failures += check(
                "emitted relative root is the frozen absolute path",
                _octal_literal(want_res) in rel_text,
                True,
            )
            failures += check(
                "emitted overlay dirs are frozen absolute paths",
                all(_octal_literal(d) in rel_text for d in want_dirs),
                True,
            )
        finally:
            os.chdir(previous_cwd)

        disabled_c = Path(tmp) / "gen-disabled.c"
        G.emit_config_c(None, disabled_c)
        disabled_text = disabled_c.read_text(encoding="ascii")
        failures += check(
            "disabled emits NULL",
            "g_g4_romfs_start_config = 0;" in disabled_text,
            True,
        )

        weird = dict(g4)
        weird["resource_dir"] = "C:\\röm\\romfs"
        weird["overlays"] = [{"dir": "C:\\påtch", "required": 1}]
        weird["image_size"] = expected["size"]
        weird["image_sha256"] = expected["sha256"]
        weird["index_sha256"] = "a" * 64
        enabled_c = Path(tmp) / "gen-enabled.c"
        G.emit_config_c(weird, enabled_c)
        enabled_text = enabled_c.read_text(encoding="ascii")
        failures += check(
            "utf8 path emitted as octal",
            "\\103\\072\\134\\162\\303\\266\\155" in enabled_text,
            True,
        )
        failures += check(
            "no raw non-ascii",
            all(ord(ch) < 128 for ch in enabled_text),
            True,
        )
        failures += expect_error(
            "emit rejects NUL path",
            lambda: G.emit_config_c(
                {**weird, "resource_dir": "a\x00b"}, Path(tmp) / "bad.c"
            ),
        )
        failures += expect_error(
            "emit rejects >4096-byte path",
            lambda: G.emit_config_c(
                {**weird, "resource_dir": "a" * 4097}, Path(tmp) / "long.c"
            ),
        )

        # Hermetic only: the real prepared v0 header is validated by the actual
        # Start driver run (lead), never by this repo test with a private
        # absolute user path.

    if failures:
        print("FAIL: %d G4 config check(s)" % failures)
        return 2
    print("PASS: strict G4 RomFS config parse/pin/emit/overlay selection")
    return 0


if __name__ == "__main__":
    sys.exit(main())
