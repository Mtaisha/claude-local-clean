"""Windows-local Claude Desktop privacy cleanup.

This module intentionally stays separate from the portable Claude Code cleaner.
It only touches allowlisted Claude Desktop cache files, the applied managed
configuration, and one content-verified embedded Claude Code release.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
from pathlib import Path


DESKTOP_RESIDUE_NAMES = (
    "ant-device-registry.json",
    "ant-did",
    "sentry",
    "Crashpad",
    "Code Cache",
    "logs",
)

MANAGED_PRIVACY_VALUES = {
    "disableAutoUpdates": True,
    "disableFeatureDiscovery": True,
    "coworkScheduledTasksEnabled": False,
    "ccdScheduledTasksEnabled": False,
    "disableNonessentialTelemetry": True,
    "disableEssentialTelemetry": True,
}

SUPPORTED_EMBEDDED_VERSION = "2.1.281"
SUPPORTED_EMBEDDED_SIZE = 240_767_648
SUPPORTED_EMBEDDED_ORIGINAL_SHA256 = (
    "39be063c2512b43347fe7b0ab18c46f1596141701c9c5fc895ddfca9a051067c"
)
SUPPORTED_EMBEDDED_CLEAN_SHA256 = (
    "721de6b078db998d0e7dca8559e56a8c8e71c12057d31e62f4111d1008d01aea"
)

MODEL_REGEX_START = b"ark-code|astron|command-r|deepseek|"
MODEL_REGEX_END = b"|\\bds-|dpsk"
MODEL_REGEX_LENGTH = 393
MODEL_DISABLED_BLOCK = b"(?!)" + (b"x" * (MODEL_REGEX_LENGTH - 4))

PROJECT_SOURCE_RE = re.compile(
    rb"has_xcode_project:(?P<x>[A-Za-z_$][A-Za-z0-9_$]*\.hasXcodeProject),"
    rb"has_ios_app_project:(?P<i>[A-Za-z_$][A-Za-z0-9_$]*\.hasIosAppProject),"
    rb"has_android_project:(?P<a>[A-Za-z_$][A-Za-z0-9_$]*\.hasAndroidProject),"
    rb"has_android_app_project:(?P<aa>[A-Za-z_$][A-Za-z0-9_$]*\.hasAndroidAppProject),"
)
PROJECT_DISABLED_BLOCK = (
    b"has_xcode_project:!1" + (b" " * 15)
    + b",has_ios_app_project:!1" + (b" " * 16)
    + b",has_android_project:!1" + (b" " * 17)
    + b",has_android_app_project:!1" + (b" " * 20)
    + b","
)

NARRATION_ERROR = b"narration_classifier_error"
NARRATION_DISABLED = b"narration_disabled".ljust(len(NARRATION_ERROR), b"_")
NARRATION_FUNCTION_RE = re.compile(
    rb"function (?P<name>[A-Za-z_$][A-Za-z0-9_$]*)"
    rb"\((?P<arg>[A-Za-z_$][A-Za-z0-9_$]*)\)\{try\{if\("
    rb"(?P<condition>[^)]{1,256})\)return!1;"
)


class DesktopPrivacyError(RuntimeError):
    """Raised when a destructive Desktop operation cannot be verified."""


def _environment_path(name: str) -> Path | None:
    value = os.environ.get(name)
    return Path(value) if value else None


def _path_size(path: Path) -> int:
    try:
        if path.is_file() or path.is_symlink():
            return path.stat().st_size
        return sum(item.stat().st_size for item in path.rglob("*") if item.is_file())
    except OSError:
        return 0


def _remove_exact_path(path: Path) -> tuple[int, int]:
    if not path.exists() and not path.is_symlink():
        return 0, 0
    size = _path_size(path)
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)
    else:
        raise DesktopPrivacyError(f"Unsupported Desktop residue type: {path}")
    return 1, size


def desktop_roaming_roots(
    *, appdata: Path | None = None, local_appdata: Path | None = None
) -> list[Path]:
    if platform.system() != "Windows" and appdata is None and local_appdata is None:
        return []

    appdata = appdata or _environment_path("APPDATA")
    local_appdata = local_appdata or _environment_path("LOCALAPPDATA")
    roots: list[Path] = []
    if appdata is not None:
        roots.append(appdata / "Claude")
    packages = local_appdata / "Packages" if local_appdata is not None else None
    if packages is not None and packages.is_dir():
        for package in packages.glob("Claude_*"):
            roots.append(package / "LocalCache" / "Roaming" / "Claude")

    unique: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        identity = str(root.resolve(strict=False)).casefold()
        if identity not in seen:
            seen.add(identity)
            unique.append(root)
    return unique


def clean_desktop_privacy_residue(
    *, appdata: Path | None = None, local_appdata: Path | None = None
) -> dict[str, object]:
    """Delete only known, regenerable Desktop identifiers and telemetry caches."""

    if appdata is None and local_appdata is None and _claude_process_running():
        return {"status": "blocked", "removed": [], "removed_count": 0, "removed_bytes": 0}

    removed: list[str] = []
    removed_bytes = 0
    for root in desktop_roaming_roots(appdata=appdata, local_appdata=local_appdata):
        for name in DESKTOP_RESIDUE_NAMES:
            candidate = root / name
            count, size = _remove_exact_path(candidate)
            if count:
                removed.append(str(candidate))
                removed_bytes += size

    local_appdata = local_appdata or _environment_path("LOCALAPPDATA")
    if local_appdata is not None:
        meta_backup = local_appdata / "Claude-3p" / "configLibrary" / "_meta.json.bak"
        count, size = _remove_exact_path(meta_backup)
        if count:
            removed.append(str(meta_backup))
            removed_bytes += size

    return {
        "status": "updated" if removed else "current",
        "removed": removed,
        "removed_count": len(removed),
        "removed_bytes": removed_bytes,
    }


def _write_json_atomic(path: Path, value: dict) -> None:
    tmp = path.with_name(path.name + ".tmp-clean")
    try:
        with tmp.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def apply_desktop_managed_privacy(
    *, local_appdata: Path | None = None
) -> dict[str, object]:
    """Merge Desktop privacy values into Claude-3p's currently applied config."""

    local_appdata = local_appdata or _environment_path("LOCALAPPDATA")
    if local_appdata is None:
        return {"status": "unavailable", "changed": [], "reason": "LOCALAPPDATA is absent"}
    library = local_appdata / "Claude-3p" / "configLibrary"
    meta_path = library / "_meta.json"
    if not meta_path.is_file():
        return {"status": "unavailable", "changed": [], "reason": "managed config is absent"}

    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DesktopPrivacyError(f"Managed config metadata is unreadable: {exc}") from exc
    applied_id = meta.get("appliedId") if isinstance(meta, dict) else None
    if not isinstance(applied_id, str) or not re.fullmatch(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        applied_id,
    ):
        raise DesktopPrivacyError("Managed config appliedId is invalid")

    config_path = library / f"{applied_id}.json"
    if config_path.parent.resolve(strict=False) != library.resolve(strict=False):
        raise DesktopPrivacyError("Managed config path escaped configLibrary")
    if not config_path.is_file():
        return {"status": "unavailable", "changed": [], "reason": "applied config is absent"}

    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DesktopPrivacyError(f"Applied managed config is unreadable: {exc}") from exc
    if not isinstance(config, dict):
        raise DesktopPrivacyError("Applied managed config must be a JSON object")

    changed: list[str] = []
    for key, value in MANAGED_PRIVACY_VALUES.items():
        if config.get(key) is not value:
            config[key] = value
            changed.append(key)
    if changed:
        _write_json_atomic(config_path, config)
    return {"status": "updated" if changed else "current", "changed": changed}


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _model_regex_regions(payload: bytes) -> list[tuple[int, int]]:
    regions: list[tuple[int, int]] = []
    offset = 0
    while True:
        start = payload.find(MODEL_REGEX_START, offset)
        if start < 0:
            break
        end_marker = payload.find(MODEL_REGEX_END, start)
        if end_marker < 0:
            raise DesktopPrivacyError("Model classifier end marker is missing")
        end = end_marker + len(MODEL_REGEX_END)
        if end - start != MODEL_REGEX_LENGTH:
            raise DesktopPrivacyError("Model classifier length drifted")
        regions.append((start, end))
        offset = end
    return regions


def _patch_project_source(payload: bytearray) -> None:
    matches = list(PROJECT_SOURCE_RE.finditer(payload))
    if len(matches) != 1:
        raise DesktopPrivacyError(
            f"Expected one project-intent source object, found {len(matches)}"
        )
    match = matches[0]
    for group in ("x", "i", "a", "aa"):
        start, end = match.span(group)
        payload[start:end] = b"!1" + (b" " * ((end - start) - 2))


def _patch_narration(payload: bytearray) -> None:
    marker = bytes(payload).find(NARRATION_ERROR)
    if marker < 0 or bytes(payload).find(NARRATION_ERROR, marker + 1) >= 0:
        raise DesktopPrivacyError("Expected one narration classifier marker")

    window_start = max(0, marker - 16_384)
    window = bytes(payload[window_start:marker])
    candidates = []
    for match in NARRATION_FUNCTION_RE.finditer(window):
        arg = match.group("arg")
        expected = arg + b'.type!=="thinking"||!' + arg + b".signature"
        if match.group("condition") == expected:
            candidates.append(match)
    if len(candidates) != 1:
        raise DesktopPrivacyError(
            f"Expected one narration parser condition, found {len(candidates)}"
        )

    match = candidates[0]
    start, end = match.span("condition")
    absolute_start = window_start + start
    absolute_end = window_start + end
    payload[absolute_start:absolute_end] = b"!0" + (b" " * ((absolute_end - absolute_start) - 2))
    payload[marker : marker + len(NARRATION_ERROR)] = NARRATION_DISABLED


def patch_supported_embedded_payload(payload: bytes) -> bytes:
    """Return an equal-length patched 2.1.281 payload or raise on any drift."""

    regions = _model_regex_regions(payload)
    if len(regions) != 2:
        raise DesktopPrivacyError(f"Expected two model classifiers, found {len(regions)}")

    patched = bytearray(payload)
    for start, end in regions:
        patched[start:end] = MODEL_DISABLED_BLOCK
    _patch_project_source(patched)
    _patch_narration(patched)

    result = bytes(patched)
    if len(result) != len(payload):
        raise DesktopPrivacyError("Embedded Claude Code length changed")
    return result


def embedded_payload_is_clean(payload: bytes) -> bool:
    return (
        payload.count(MODEL_REGEX_START) == 0
        and payload.count(MODEL_DISABLED_BLOCK) == 2
        and payload.count(PROJECT_DISABLED_BLOCK) == 1
        and payload.count(NARRATION_ERROR) == 0
        and payload.count(NARRATION_DISABLED) == 1
    )


def _version_key(value: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in value.split("."))
    except ValueError:
        return (0,)


def latest_embedded_binary(*, local_appdata: Path | None = None) -> tuple[str, Path] | None:
    local_appdata = local_appdata or _environment_path("LOCALAPPDATA")
    if local_appdata is None:
        return None
    packages = local_appdata / "Packages"
    if not packages.is_dir():
        return None

    package_roots = list(packages.glob("Claude_*"))
    preferred = packages / "Claude_pzs8sxrjxfjjc"
    package_roots.sort(key=lambda path: (path != preferred, path.name.casefold()))

    preferred_candidates: list[tuple[str, Path]] = []
    fallback_candidates: list[tuple[str, Path]] = []
    for package in package_roots:
        root = package / "LocalCache" / "Roaming" / "Claude" / "claude-code"
        if not root.is_dir():
            continue
        for child in root.iterdir():
            binary = child / "claude.exe"
            if child.is_dir() and binary.is_file() and re.fullmatch(r"\d+\.\d+\.\d+", child.name):
                target = preferred_candidates if package == preferred else fallback_candidates
                target.append((child.name, binary))
    candidates = preferred_candidates or fallback_candidates
    return max(candidates, key=lambda item: _version_key(item[0])) if candidates else None


def _claude_process_running() -> bool:
    if platform.system() != "Windows":
        return False
    try:
        result = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq Claude.exe", "/FO", "CSV", "/NH"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise DesktopPrivacyError(f"Claude process detection failed: {exc}") from exc
    if result.returncode != 0:
        raise DesktopPrivacyError("Claude process detection returned an error")
    return '"claude.exe"' in result.stdout.casefold()


def _write_binary_atomic(path: Path, payload: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp-clean")
    try:
        with tmp.open("wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        shutil.copystat(path, tmp)
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def _smoke_embedded_binary(path: Path) -> tuple[bool, str]:
    creationflags = subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0
    version = subprocess.run(
        [str(path), "--version"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=20,
        creationflags=creationflags,
    )
    help_result = subprocess.run(
        [str(path), "--help"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=20,
        creationflags=creationflags,
    )
    version_text = version.stdout.strip() or version.stderr.strip()
    ok = (
        version.returncode == 0
        and help_result.returncode == 0
        and SUPPORTED_EMBEDDED_VERSION in version_text
    )
    return ok, version_text


def harden_current_embedded_claude_code(
    *, local_appdata: Path | None = None
) -> dict[str, object]:
    """Patch only the exact supported embedded release; never guess on drift."""

    candidate = latest_embedded_binary(local_appdata=local_appdata)
    if candidate is None:
        return {"status": "unavailable", "reason": "embedded Claude Code was not found"}
    version, path = candidate
    if version != SUPPORTED_EMBEDDED_VERSION:
        return {"status": "unsupported", "version": version, "reason": "content review required"}

    original = path.read_bytes()
    digest = _sha256(original)
    if len(original) != SUPPORTED_EMBEDDED_SIZE:
        return {"status": "unsupported", "version": version, "reason": "binary size drifted"}
    if embedded_payload_is_clean(original):
        if digest != SUPPORTED_EMBEDDED_CLEAN_SHA256:
            return {
                "status": "unsupported",
                "version": version,
                "reason": "clean-looking binary hash is unknown",
            }
        ok, version_text = _smoke_embedded_binary(path)
        if not ok:
            raise DesktopPrivacyError("Embedded Claude Code smoke test failed")
        return {
            "status": "current",
            "version": version,
            "sha256": digest,
            "version_text": version_text,
        }
    if digest != SUPPORTED_EMBEDDED_ORIGINAL_SHA256:
        return {"status": "unsupported", "version": version, "reason": "binary hash is unknown"}
    if _claude_process_running():
        return {"status": "blocked", "version": version, "reason": "Claude is running"}

    patched = patch_supported_embedded_payload(original)
    patched_digest = _sha256(patched)
    if patched_digest != SUPPORTED_EMBEDDED_CLEAN_SHA256:
        raise DesktopPrivacyError("Embedded Claude Code patched hash is unexpected")
    _write_binary_atomic(path, patched)
    try:
        written = path.read_bytes()
        if (
            written != patched
            or _sha256(written) != SUPPORTED_EMBEDDED_CLEAN_SHA256
            or not embedded_payload_is_clean(written)
        ):
            raise DesktopPrivacyError("Embedded Claude Code verification failed")
        ok, version_text = _smoke_embedded_binary(path)
        if not ok:
            raise DesktopPrivacyError("Embedded Claude Code smoke test failed")
    except Exception:
        _write_binary_atomic(path, original)
        raise

    return {
        "status": "updated",
        "version": version,
        "sha256": patched_digest,
        "version_text": version_text,
    }
