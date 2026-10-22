"""Strict, non-executing RomFS Start config handling for the G4 driver.

The external `romfs_config.h` is DATA, not C to be compiled. It is parsed here
with a deliberately tiny grammar (exactly three `#define`s), pinned against the
repo's genuine v1.0.0 expected hashes, and then re-emitted as a generated C
literal into the external work directory. No `#include` or arbitrary C ever
reaches the compiler from the external profile.

Only the Python standard library is used.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Mapping, Optional

MACROS = ("ROMFS_IMAGE_SIZE", "ROMFS_IMAGE_SHA256", "ROMFS_INDEX_SHA256")
# Fixed-octal emission is 4 source bytes per UTF-8 byte. 4096 keeps every
# generated C string well below MSVC's 64 KiB literal limit while covering
# the Mac profile's long paths.
MAX_C_PATH_BYTES = 4096
_SIZE_RE = re.compile(r"^([0-9]+)(?:ULL|LLU|UL|LU|LL|U|L)?$", re.IGNORECASE)
_SHA_RE = re.compile(r'^"([0-9a-f]{64})"$')
# TOTK_OUTPUT_RES: empty/0 (headless), Mac `auto`, or a canonical WxH inside
# the Mac-supported range. Anything else is a caller error, never a silent
# fallback to the headless profile.
_OUTPUT_RES_RE = re.compile(r"^([0-9]{1,5})x([0-9]{1,5})$")
OUTPUT_RES_MIN = (640, 360)
OUTPUT_RES_MAX = (7680, 4320)
_DEFINE_RE = re.compile(
    r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_][A-Za-z0-9_]*)[ \t]+(.+?)[ \t]*$"
)


class ConfigError(Exception):
    """The external config/profile is malformed, unpinned, or unsupported."""


def parse_romfs_config(text: str) -> dict[str, object]:
    """Parse exactly three defines. Reject includes, code, comments, duplicates."""
    if "\x00" in text:
        raise ConfigError("config contains NUL")
    if text.startswith("\ufeff"):
        raise ConfigError("config must be UTF-8 without a BOM")
    values: dict[str, object] = {}
    for lineno, line in enumerate(text.splitlines(), 1):
        if line.strip() == "":
            continue
        match = _DEFINE_RE.match(line)
        if not match:
            raise ConfigError(
                f"line {lineno}: only '#define NAME VALUE' is allowed"
            )
        name, raw = match.group(1), match.group(2)
        if name not in MACROS:
            raise ConfigError(f"line {lineno}: unknown macro {name}")
        if name in values:
            raise ConfigError(f"line {lineno}: duplicate macro {name}")
        if name == "ROMFS_IMAGE_SIZE":
            size_match = _SIZE_RE.match(raw)
            if not size_match:
                raise ConfigError(f"line {lineno}: malformed image size")
            value = int(size_match.group(1), 10)
            if value <= 0 or value > 0xFFFFFFFFFFFFFFFF:
                raise ConfigError(f"line {lineno}: image size out of range")
            values[name] = value
        else:
            sha_match = _SHA_RE.match(raw)
            if not sha_match:
                raise ConfigError(
                    f"line {lineno}: {name} must be 64 lowercase hex in quotes"
                )
            values[name] = sha_match.group(1)
    missing = [name for name in MACROS if name not in values]
    if missing:
        raise ConfigError("missing macro(s): " + ", ".join(missing))
    return values


def read_romfs_config(path: os.PathLike[str] | str) -> dict[str, object]:
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise ConfigError(f"cannot read config: {exc}") from exc
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigError("config is not valid UTF-8") from exc
    return parse_romfs_config(text)


def load_expected(path: os.PathLike[str] | str, version: int = 0) -> dict[str, object]:
    try:
        obj = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConfigError(f"cannot read expected profile: {exc}") from exc
    if not isinstance(obj, dict):
        raise ConfigError("expected profile is not an object")
    if obj.get("version") != version:
        raise ConfigError(
            f"expected profile version {obj.get('version')!r} is not {version}"
        )
    romfs = obj.get("romfs")
    if not isinstance(romfs, dict):
        raise ConfigError("expected profile has no romfs object")
    size = romfs.get("size")
    sha = romfs.get("sha256")
    if not isinstance(size, int) or size <= 0:
        raise ConfigError("expected profile romfs.size is invalid")
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
        raise ConfigError("expected profile romfs.sha256 is invalid")
    return {"size": size, "sha256": sha}


def pin_config(
    cfg: Mapping[str, object],
    expected: Mapping[str, object],
    expected_label: str = "expected-v1.0.0.json",
) -> None:
    """Require the external profile to describe the genuine v1.0.0 image."""
    if cfg.get("ROMFS_IMAGE_SIZE") != expected["size"]:
        raise ConfigError(
            f"ROMFS_IMAGE_SIZE {cfg.get('ROMFS_IMAGE_SIZE')} != "
            f"{expected_label} romfs.size {expected['size']}"
        )
    if cfg.get("ROMFS_IMAGE_SHA256") != expected["sha256"]:
        raise ConfigError(
            f"ROMFS_IMAGE_SHA256 does not match {expected_label} romfs.sha256"
        )


def _check_path(path: str, what: str) -> str:
    if not isinstance(path, str) or path == "":
        raise ConfigError(f"{what} is empty")
    if "\x00" in path:
        raise ConfigError(f"{what} contains NUL")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in path):
        raise ConfigError(f"{what} contains a control character")
    try:
        path.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ConfigError(f"{what} is not encodable as UTF-8") from exc
    return path


def _key(path: str) -> str:
    return os.path.normcase(os.path.abspath(path))


def _freeze(path: str, what: str) -> str:
    """Make a selected root absolute, resolved against the CALLER's cwd.

    DEFENSIVE INVARIANCE, not a fix for an observed misresolution: the emitted
    profile is serialized C, so freezing every root here makes it resolve
    identically regardless of the cwd a later consumer (or a reused caller
    config) runs with. No current driver path is known to rebase these paths.
    The UTF-8 length bound in `_c_literal()` is checked on the frozen spelling,
    which is what actually ships.
    """
    return str(Path(_check_path(path, what)).resolve())


def _validate_output_res(value: str) -> str:
    """Accept only '', '0', 'auto' or canonical WxH in the Mac range.

    This validates the PROFILE REQUEST only. It does not select resolution
    overlays or any graphics behavior; the Windows driver keeps the explicit
    profile the caller chose.
    """
    if value in ("", "0", "auto"):
        return value
    match = _OUTPUT_RES_RE.match(value)
    if not match:
        raise ConfigError(
            f"TOTK_OUTPUT_RES={value!r} is malformed; expected 0, auto or WxH"
        )
    width, height = int(match.group(1)), int(match.group(2))
    if not (OUTPUT_RES_MIN[0] <= width <= OUTPUT_RES_MAX[0]
            and OUTPUT_RES_MIN[1] <= height <= OUTPUT_RES_MAX[1]):
        raise ConfigError(
            f"TOTK_OUTPUT_RES={value!r} is outside the supported Mac range "
            f"{OUTPUT_RES_MIN[0]}x{OUTPUT_RES_MIN[1]}.."
            f"{OUTPUT_RES_MAX[0]}x{OUTPUT_RES_MAX[1]}"
        )
    return f"{width}x{height}"


def resolve_start_config(
    config_path: Optional[os.PathLike[str] | str],
    expected_path: os.PathLike[str] | str,
    *,
    resource_dir: Optional[str] = None,
    overlay_dir: Optional[str] = None,
    required_overlay_dir: Optional[str] = None,
    no_overlays: bool = False,
    environ: Optional[Mapping[str, str]] = None,
) -> Optional[dict[str, object]]:
    """Resolve a v0 profile. `config_path is None` means G4 stays disabled.

    Disabled returns None even if unrelated TOTK_* variables exist elsewhere in
    the environment. Enabled defaults mirror the Mac layout: resource dir from
    --romfs-dir/TOTK_ROMFS (else the config's own directory, where the prepared
    v0 image/index live) and an OPTIONAL sibling `romfs-patches` of the resource
    dir's parent. TOTK_ROMFS_PATCHES=0 disables that optional root; a non-empty
    value selects it. A required explicit root is the second root and is
    enforced by the provider.

    The default is the native/headless profile (output resolution 0). Mac
    auto-selects resolution patches from TOTK_OUTPUT_RES; this Windows driver
    does not port that graphics selection, so TOTK_OUTPUT_RES is only VALIDATED
    (0, auto or canonical WxH in the Mac range) and RECORDED: a nonzero request
    is refused unless the caller supplies an explicit required overlay root.
    Empty CLI path overrides are errors, never fallthrough. Explicit options
    without an explicit config are errors too: ambient TOTK_* variables alone
    never enable, and never fail, the default-disabled path.
    """
    if config_path is None:
        if (resource_dir is not None
                or overlay_dir is not None
                or required_overlay_dir is not None
                or no_overlays):
            raise ConfigError(
                "explicit RomFS options require an explicit --romfs-config; "
                "the default stays disabled"
            )
        return None
    env = dict(os.environ if environ is None else environ)
    cfg = read_romfs_config(config_path)
    expected = load_expected(expected_path, version=0)
    pin_config(cfg, expected)

    # An explicit empty CLI path is a caller error, never "use the default".
    # Every selected root is frozen to an absolute path resolved against THIS
    # process's cwd. This is profile serialization invariance (a generated
    # profile no longer depends on the consumer's cwd); it is not a fix for an
    # observed rebase, since no current driver path sets a different cwd.
    if resource_dir is not None:
        resource_dir = _freeze(resource_dir, "resource directory")
    if overlay_dir is not None:
        overlay_dir = _freeze(overlay_dir, "overlay directory")
    if required_overlay_dir is not None:
        required_overlay_dir = _freeze(
            required_overlay_dir, "required overlay directory"
        )
    if no_overlays and (overlay_dir is not None or required_overlay_dir is not None):
        raise ConfigError("--romfs-no-overlays conflicts with an explicit root")

    output_res = _validate_output_res(
        (env.get("TOTK_OUTPUT_RES") or "").strip()
    )
    if output_res not in ("", "0") and required_overlay_dir is None:
        raise ConfigError(
            f"TOTK_OUTPUT_RES={output_res!r} requests a Mac resolution overlay "
            "profile; this driver uses the native/headless profile and does not "
            "auto-select graphics overlays. Pass --romfs-required-overlay-dir "
            "explicitly."
        )
    if env.get("TOTK_ROMFS_PATCHES_OUT", "") and required_overlay_dir is None:
        raise ConfigError(
            "resolution overlay profile requested by TOTK_ROMFS_PATCHES_OUT "
            "is unsupported; pass --romfs-required-overlay-dir explicitly"
        )

    resource = resource_dir or env.get("TOTK_ROMFS") or str(
        Path(config_path).resolve().parent
    )
    resource = _freeze(resource, "resource directory")

    overlays: list[dict[str, object]] = []
    if no_overlays:
        base = None
    elif overlay_dir is not None:
        base = overlay_dir
    elif env.get("TOTK_ROMFS_PATCHES") == "0":
        base = None
    elif env.get("TOTK_ROMFS_PATCHES"):
        base = env["TOTK_ROMFS_PATCHES"]
    else:
        base = str(Path(resource).resolve().parent / "romfs-patches")
    if base is not None:
        overlays.append(
            {"dir": _freeze(base, "overlay directory"), "required": 0}
        )
    if required_overlay_dir is not None:
        overlays.append({"dir": required_overlay_dir, "required": 1})

    seen: dict[str, str] = {}
    if _key(resource) in {_key(str(o["dir"])) for o in overlays}:
        raise ConfigError("an overlay root aliases the resource directory")
    for overlay in overlays:
        key = _key(str(overlay["dir"]))
        if key in seen:
            raise ConfigError(
                "duplicate overlay roots: "
                f"{seen[key]} and {overlay['dir']} are the same directory"
            )
        seen[key] = str(overlay["dir"])

    return {
        "resource_dir": resource,
        "index_sha256": cfg["ROMFS_INDEX_SHA256"],
        "image_size": cfg["ROMFS_IMAGE_SIZE"],
        "image_sha256": cfg["ROMFS_IMAGE_SHA256"],
        "overlays": overlays,
        "output_res": output_res or "0",
        "config_path": str(Path(config_path).resolve()),
    }


def _c_literal(value: str) -> str:
    """Encode every UTF-8 byte with fixed three-digit octal escapes.

    This avoids hex-escape run-on (`\\xNNf`), embedded quotes/backslashes and
    source-encoding assumptions. The string is bounded and NUL-free.
    """
    raw = value.encode("utf-8")
    if not raw or b"\x00" in raw:
        raise ConfigError("cannot emit an empty or NUL-containing C string")
    if len(raw) > MAX_C_PATH_BYTES:
        raise ConfigError(
            f"C string is {len(raw)} UTF-8 bytes; the supported profile limit is "
            f"{MAX_C_PATH_BYTES}"
        )
    return '"' + "".join(f"\\{byte:03o}" for byte in raw) + '"'


def emit_config_c(cfg: Optional[Mapping[str, object]], out_path: os.PathLike[str] | str) -> None:
    """Emit the generated external config C file (NULL pointer when disabled)."""
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "/* GENERATED OUTSIDE THE SOURCE TREE by tools/aot/g4_romfs_config.py. */",
        '#include "romfs_provider.h"',
        "",
    ]
    if cfg is None:
        lines.append(
            "const romfs_provider_config *const g_g4_romfs_start_config = 0;"
        )
    else:
        overlays = list(cfg.get("overlays") or [])
        if len(overlays) > 2:
            raise ConfigError("provider supports at most two overlay roots")
        dirs = [str(o["dir"]) for o in overlays] + [None] * (2 - len(overlays))
        required = [int(o["required"]) for o in overlays] + [0] * (2 - len(overlays))
        if any(v not in (0, 1) for v in required):
            raise ConfigError("overlay required flags must be 0 or 1")
        dir_literals = ", ".join(
            _c_literal(d) if d is not None else "0" for d in dirs
        )
        lines.extend(
            [
                "static const romfs_provider_config g_g4_romfs_config_storage = {",
                f"    {_c_literal(str(cfg['resource_dir']))},",
                f"    {_c_literal(str(cfg['index_sha256']))},",
                f"    {int(cfg['image_size'])}ULL,",
                f"    {_c_literal(str(cfg['image_sha256']))},",
                f"    {len(overlays)}u,",
                f"    {{ {dir_literals} }},",
                f"    {{ {required[0]}u, {required[1]}u }}",
                "};",
                "",
                "const romfs_provider_config *const g_g4_romfs_start_config =",
                "    &g_g4_romfs_config_storage;",
            ]
        )
    out.write_text("\n".join(lines) + "\n", encoding="ascii", newline="\n")
