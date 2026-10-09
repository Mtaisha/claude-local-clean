from __future__ import annotations

import copy
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable


UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
ACCOUNT_MAP_KEYS = {
    "bypassPermissionsOptInByAccount",
    "bypassPermissionsGateByAccount",
    "coworkModelAutoFallbackByAccount",
}
ACCOUNT_IDENTITY_KEYS = {
    "accountUuid",
    "accountUUID",
    "accountId",
    "accountID",
    "lastKnownAccountUuid",
    "account_uuid",
    "ownerAccountId",
}
ORGANIZATION_IDENTITY_KEYS = {
    "organizationUuid",
    "organizationUUID",
    "organizationId",
    "organizationID",
    "organization_uuid",
    "orgUuid",
    "orgUUID",
    "orgId",
    "orgID",
    "primaryOrganizationUuid",
}
LOGIN_METADATA_KEYS = {
    "oauthAccount",
    "oauthAccountId",
    "oauthOrganization",
    "cachedExtraUsageDisabledReason",
    "passesEligibilityCache",
    "hasAvailableSubscription",
    "subscriptionType",
}
LOGIN_STORAGE_NAMES = (
    "Local Storage",
    "Session Storage",
    "IndexedDB",
    "Network",
    "WebStorage",
    "blob_storage",
    "DIPS",
    "SharedStorage",
    "SharedStorage-wal",
    "InterestGroups",
    "Shared Dictionary",
    "Partitions",
    "Cookies",
    "Cookies-journal",
)
PACKAGE_LOGIN_STATE_NAMES = (
    "LocalState",
    "RoamingState",
    "Settings",
    "SystemAppData",
)
PROTECTED_LOGIN_NAMES = (
    "config.json",
    "claude_desktop_config.json",
    "cowork-enabled-cli-ops.json",
    "Local Storage",
    "Session Storage",
    "IndexedDB",
    "Network",
    "WebStorage",
    "blob_storage",
    "DIPS",
    "SharedStorage",
    "SharedStorage-wal",
    "InterestGroups",
    "Shared Dictionary",
    "Preferences",
    "Local State",
    "Partitions",
    "Cache",
    "Code Cache",
    "GPUCache",
    "DawnWebGPUCache",
    "DawnGraphiteCache",
    "Crashpad",
    "sentry",
    "logs",
)
APP_STATE_NAMES = (
    "plan-usage-history.json",
    "buddy-tokens.json",
    "extensions-blocklist.json",
    "session-migration-backups",
)
PRESERVED_HOME_NAMES = (
    "projects",
    "CLAUDE.md",
    "settings.json",
    "settings.local.json",
    "file-history",
    "plugins",
    "skills",
    "agents",
    "plans",
    "tasks",
    "sessions",
    "session-env",
    "backups",
)


class ClaudeAccountCleanupError(RuntimeError):
    pass


class ClaudeAccountPartialCleanupError(ClaudeAccountCleanupError):
    def __init__(self, message: str, result: dict[str, object]):
        super().__init__(message)
        self.result = result


@dataclass(frozen=True)
class ClaudeAccountPaths:
    msix_root: Path
    home_root: Path
    legacy_root: Path
    primary_anchor: Path

    @property
    def config_path(self) -> Path:
        return self.msix_root / "config.json"

    @property
    def package_root(self) -> Path:
        if tuple(part.casefold() for part in self.msix_root.parts[-3:]) == (
            "localcache",
            "roaming",
            "claude",
        ):
            return self.msix_root.parents[2]
        return self.msix_root.parent

    @property
    def home_config_path(self) -> Path:
        return self.home_root.parent / ".claude.json"

    @property
    def desktop_config_path(self) -> Path:
        return self.msix_root / "claude_desktop_config.json"

    @property
    def cowork_ops_path(self) -> Path:
        return self.msix_root / "cowork-enabled-cli-ops.json"

    @property
    def code_sessions_root(self) -> Path:
        return self.msix_root / "claude-code-sessions"

    @property
    def agent_sessions_root(self) -> Path:
        return self.msix_root / "local-agent-mode-sessions"


def default_paths() -> ClaudeAccountPaths:
    home = Path.home()
    packages = home / "AppData" / "Local" / "Packages"
    preferred = packages / "Claude_pzs8sxrjxfjjc" / "LocalCache" / "Roaming" / "Claude"
    msix_root = preferred
    if not preferred.exists():
        for package in sorted(packages.glob("Claude_*")):
            candidate = package / "LocalCache" / "Roaming" / "Claude"
            if candidate.exists():
                msix_root = candidate
                break
    return ClaudeAccountPaths(
        msix_root=msix_root,
        home_root=home / ".claude",
        legacy_root=home / "AppData" / "Roaming" / "Claude",
        # Optional local anchor used only when a user creates it themselves.
        # Keeping it inside Claude's own configuration root avoids coupling the
        # public cleaner to a private tool or a personal Documents layout.
        primary_anchor=home / ".claude" / "primary-account.json",
    )


def _is_uuid(value: object) -> bool:
    return isinstance(value, str) and bool(UUID_RE.fullmatch(value))


def _is_reparse(path: Path) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    attributes = getattr(info, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return path.is_symlink() or bool(attributes & reparse_flag)


def _require_direct_child(root: Path, child: Path) -> None:
    if child.parent != root or not _is_uuid(child.name):
        raise ClaudeAccountCleanupError("账号目录不在允许的固定根目录内。")
    if _is_reparse(root) or _is_reparse(child):
        raise ClaudeAccountCleanupError("账号目录是链接或重解析点，拒绝处理。")


def _require_owned_child(root: Path, child: Path) -> None:
    if child.parent != root:
        raise ClaudeAccountCleanupError("登录存储不在允许的 Claude 根目录内。")
    if _is_reparse(root) or _is_reparse(child):
        raise ClaudeAccountCleanupError("登录存储是链接或重解析点，拒绝处理。")


def _is_claude_credential_target(target: object) -> bool:
    if not isinstance(target, str):
        return False
    lowered = target.casefold()
    return "claude" in lowered or "anthropic" in lowered


def _default_credential_target_provider() -> list[str]:
    if os.name != "nt":
        return []
    try:
        result = subprocess.run(
            ["cmdkey.exe", "/list"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=8,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ClaudeAccountCleanupError(f"Windows 凭据扫描失败：{exc}") from exc
    if result.returncode != 0:
        raise ClaudeAccountCleanupError("Windows 凭据扫描失败，拒绝声称登录层已清空。")

    targets: list[str] = []
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if ":" not in line:
            continue
        label, value = line.split(":", 1)
        if label.casefold() not in {"target", "目标"}:
            continue
        target = value.strip()
        if _is_claude_credential_target(target):
            targets.append(target)
    return sorted(set(targets), key=str.casefold)


def _default_credential_target_deleter(target: str) -> None:
    if not _is_claude_credential_target(target):
        raise ClaudeAccountCleanupError("拒绝删除非 Claude/Anthropic 的 Windows 凭据。")
    try:
        result = subprocess.run(
            ["cmdkey.exe", f"/delete:{target}"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=8,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ClaudeAccountCleanupError(f"Windows 凭据删除失败：{exc}") from exc
    if result.returncode != 0:
        raise ClaudeAccountCleanupError("Windows 凭据删除失败。")


def _read_json(path: Path, *, strict: bool) -> dict:
    if not path.exists():
        return {}
    if _is_reparse(path) or not path.is_file():
        if strict:
            raise ClaudeAccountCleanupError(f"拒绝读取异常 JSON 路径：{path.name}")
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        if strict:
            raise ClaudeAccountCleanupError(f"{path.name} 无法安全解析，未执行任何清理。") from exc
        return {}
    if not isinstance(value, dict):
        if strict:
            raise ClaudeAccountCleanupError(f"{path.name} 顶层不是对象，未执行任何清理。")
        return {}
    return value


def _write_json_atomic(path: Path, value: dict) -> None:
    if _is_reparse(path) or _is_reparse(path.parent):
        raise ClaudeAccountCleanupError(f"拒绝写入链接或重解析路径：{path.name}")
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def _write_bytes_atomic(path: Path, payload: bytes) -> None:
    if _is_reparse(path) or _is_reparse(path.parent):
        raise ClaudeAccountCleanupError(f"拒绝恢复链接或重解析路径：{path.name}")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def _write_json_batch_with_rollback(changes: list[tuple[Path, dict]]) -> None:
    originals: dict[Path, bytes | None] = {}
    applied: list[Path] = []
    for path, _ in changes:
        originals[path] = path.read_bytes() if path.exists() else None
    try:
        for path, value in changes:
            _write_json_atomic(path, value)
            applied.append(path)
    except Exception as exc:
        rollback_failures: list[str] = []
        for path in reversed(applied):
            try:
                original = originals[path]
                if original is None:
                    path.unlink(missing_ok=True)
                else:
                    _write_bytes_atomic(path, original)
            except Exception:
                rollback_failures.append(path.name)
        suffix = f"；回滚失败：{', '.join(rollback_failures)}" if rollback_failures else "；已恢复本轮 JSON 写入"
        raise ClaudeAccountCleanupError(f"账号 JSON 批量写入失败{suffix}") from exc


def _path_size(path: Path) -> int:
    if not path.exists() or _is_reparse(path):
        return 0
    if path.is_file():
        try:
            return path.stat().st_size
        except OSError:
            return 0
    total = 0
    for child in path.rglob("*"):
        if child.is_file() and not _is_reparse(child):
            try:
                total += child.stat().st_size
            except OSError:
                pass
    return total


def _default_process_checker() -> list[dict[str, object]]:
    if os.name != "nt":
        return []
    script = (
        "$p=Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object { "
        "$_.Name -ieq 'claude.exe' -or $_.Name -ieq 'claude-code.exe' -or "
        "$_.ExecutablePath -like '*Claude_pzs8sxrjxfjjc*' }; "
        "$p | Select-Object Name,ProcessId | ConvertTo-Json -Compress"
    )
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=8,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ClaudeAccountCleanupError(f"Claude 进程检测失败：{exc}") from exc
    if result.returncode != 0:
        raise ClaudeAccountCleanupError("Claude 进程检测失败，拒绝账号清理。")
    if not result.stdout.strip():
        return []
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ClaudeAccountCleanupError("Claude 进程检测结果异常，拒绝账号清理。") from exc
    return value if isinstance(value, list) else [value]


def _account_sources(paths: ClaudeAccountPaths, desktop_config: dict | None = None) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for label, root in (
        ("claude-code-sessions", paths.code_sessions_root),
        ("local-agent-mode-sessions", paths.agent_sessions_root),
    ):
        if not root.is_dir() or _is_reparse(root):
            continue
        for child in root.iterdir():
            if child.is_dir() and not _is_reparse(child) and _is_uuid(child.name):
                found.setdefault(child.name.lower(), set()).add(label)

    desktop = desktop_config if desktop_config is not None else _read_json(paths.desktop_config_path, strict=False)

    def visit(value: object) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if key in ACCOUNT_MAP_KEYS and isinstance(child, dict):
                    for candidate in child:
                        if _is_uuid(candidate):
                            found.setdefault(candidate.lower(), set()).add(f"account-map:{key}")
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(desktop)
    anchor = _read_json(paths.primary_anchor, strict=False)
    anchor_uuid = anchor.get("account_uuid")
    if _is_uuid(anchor_uuid):
        found.setdefault(str(anchor_uuid).lower(), set()).add("猫主账号锚点")
    return found


def _identity_uuids(value: object) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if key in ACCOUNT_IDENTITY_KEYS and _is_uuid(child):
                found.add(str(child).lower())
            else:
                found.update(_identity_uuids(child))
    elif isinstance(value, list):
        for child in value:
            found.update(_identity_uuids(child))
    return found


def _current_uuids(
    paths: ClaudeAccountPaths,
    config: dict | None = None,
    home_config: dict | None = None,
) -> set[str]:
    desktop_state = config if config is not None else _read_json(paths.config_path, strict=False)
    cli_state = home_config if home_config is not None else _read_json(paths.home_config_path, strict=False)
    return _identity_uuids(desktop_state) | _identity_uuids(cli_state)


def _current_uuid(
    paths: ClaudeAccountPaths,
    config: dict | None = None,
    home_config: dict | None = None,
) -> str:
    current = _current_uuids(paths, config, home_config)
    return sorted(current)[0] if current else ""


def _orgs_for_account(paths: ClaudeAccountPaths, account_uuid: str) -> set[str]:
    orgs: set[str] = set()
    for root in (paths.code_sessions_root, paths.agent_sessions_root):
        account = root / account_uuid
        if not account.is_dir() or _is_reparse(account):
            continue
        _require_direct_child(root, account)
        for child in account.iterdir():
            if child.is_dir() and not _is_reparse(child) and _is_uuid(child.name):
                orgs.add(child.name.lower())
    return orgs


def _transcript_ids(paths: ClaudeAccountPaths) -> set[str]:
    projects = paths.home_root / "projects"
    if not projects.is_dir() or _is_reparse(projects):
        return set()
    return {path.stem for path in projects.rglob("*.jsonl") if path.is_file() and not _is_reparse(path)}


def _manual_review(paths: ClaudeAccountPaths) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []

    def add(kind: str, label: str, path: Path, policy: str = "仅展示，绝不自动删除") -> None:
        if path.exists():
            candidates.append(
                {"kind": kind, "label": label, "path": str(path), "bytes": _path_size(path), "policy": policy}
            )

    if paths.legacy_root.exists() and paths.legacy_root != paths.msix_root:
        add("legacy", "旧版 Claude Roaming", paths.legacy_root)
    for name in APP_STATE_NAMES:
        add("app-state", f"应用状态：{name}", paths.msix_root / name)
    for name in ("Cache", "Code Cache", "GPUCache", "Crashpad", "sentry", "logs"):
        add("cache-log", f"缓存或日志：{name}", paths.msix_root / name)
    add("device-state", "设备级状态 ant-did", paths.msix_root / "ant-did", "设备级状态，必须单独决定")

    transcripts = _transcript_ids(paths)
    for root in (paths.code_sessions_root, paths.agent_sessions_root):
        if not root.is_dir() or _is_reparse(root):
            continue
        for child in root.iterdir():
            if child.is_dir() and not _is_reparse(child) and not _is_uuid(child.name):
                add("unknown-session-state", "非 UUID 的 Desktop Session 状态目录", child)
        for metadata in root.glob("*/*/local_*.json"):
            if _is_reparse(metadata) or not metadata.is_file():
                continue
            data = _read_json(metadata, strict=False)
            cli_id = str(data.get("cliSessionId", ""))
            session_id = str(data.get("sessionId", ""))
            if not cli_id or not session_id or cli_id not in transcripts:
                add("orphan-metadata", "无正文的 Desktop Session metadata", metadata)
    return candidates


def _login_storage_paths(paths: ClaudeAccountPaths) -> list[Path]:
    found: list[Path] = []
    seen: set[str] = set()
    for root in (paths.msix_root, paths.legacy_root):
        root_key = str(root.resolve(strict=False)).casefold()
        if root_key in seen:
            continue
        seen.add(root_key)
        for name in LOGIN_STORAGE_NAMES:
            candidate = root / name
            if candidate.exists():
                found.append(candidate)
    package_root_key = str(paths.package_root.resolve(strict=False)).casefold()
    if package_root_key not in seen:
        for name in PACKAGE_LOGIN_STATE_NAMES:
            candidate = paths.package_root / name
            if candidate.exists():
                found.append(candidate)
    credentials = paths.home_root / ".credentials.json"
    if credentials.exists():
        found.append(credentials)
    return found


def _credential_targets(provider: Callable[[], list[str]]) -> list[str]:
    return sorted(
        {target for target in provider() if _is_claude_credential_target(target)},
        key=str.casefold,
    )


def collect_account_status(
    paths: ClaudeAccountPaths | None = None,
    *,
    process_checker: Callable[[], list[dict[str, object]]] | None = None,
    credential_target_provider: Callable[[], list[str]] | None = None,
) -> dict:
    paths = paths or default_paths()
    config = _read_json(paths.config_path, strict=False)
    desktop = _read_json(paths.desktop_config_path, strict=False)
    home_config = _read_json(paths.home_config_path, strict=False)
    current_uuids = _current_uuids(paths, config, home_config)
    current = sorted(current_uuids)[0] if current_uuids else ""
    anchor = _read_json(paths.primary_anchor, strict=False)
    bound = str(anchor.get("account_uuid", "")).lower() if _is_uuid(anchor.get("account_uuid")) else ""
    sources = _account_sources(paths, desktop)
    accounts = []
    for account_uuid in sorted(sources):
        size = sum(
            _path_size(root / account_uuid)
            for root in (paths.code_sessions_root, paths.agent_sessions_root)
        )
        accounts.append(
            {
                "uuid": account_uuid,
                "retireable": account_uuid not in current_uuids,
                "sources": sorted(sources[account_uuid]),
                "bytes": size,
            }
        )

    protected = [paths.msix_root / name for name in PROTECTED_LOGIN_NAMES]
    protected = [path for path in protected if path.exists()]
    for path in _login_storage_paths(paths):
        if path not in protected:
            protected.append(path)
    if paths.home_config_path.exists():
        protected.append(paths.home_config_path)
    credentials = paths.home_root / ".credentials.json"
    if credentials.exists() and credentials not in protected:
        protected.append(credentials)
    checker = process_checker or _default_process_checker
    processes = checker()
    provider = credential_target_provider or _default_credential_target_provider
    credential_scan_error = ""
    try:
        credential_targets = _credential_targets(provider)
    except ClaudeAccountCleanupError as exc:
        credential_targets = []
        credential_scan_error = str(exc)
    return {
        "current_account_uuid": current,
        "current_account_uuids": sorted(current_uuids),
        "bound_account_uuid": bound,
        "detected_accounts": accounts,
        "protected_login": {
            "paths": [str(path) for path in protected],
            "credentials_present": credentials.exists(),
            "policy": "当前账号登录层永久保护，不参与自动清理。",
        },
        "full_reset": {
            "login_paths": [str(path) for path in _login_storage_paths(paths)],
            "credential_target_count": len(credential_targets),
            "credential_scan_error": credential_scan_error,
            "policy": "仅在已退出全部账号且 Claude 完全关闭后，由用户单独执行；完成后必须通过残留复查。",
        },
        "preserved": [str(paths.home_root / name) for name in PRESERVED_HOME_NAMES],
        "manual_review": _manual_review(paths),
        "claude_running": bool(processes),
        "msix_root": str(paths.msix_root),
    }


def _remove_account_map_entries(value: object, account_uuid: str) -> int:
    removed = 0
    if isinstance(value, dict):
        for key, child in list(value.items()):
            if key in ACCOUNT_MAP_KEYS and isinstance(child, dict):
                for candidate in list(child):
                    if candidate.lower() == account_uuid:
                        del child[candidate]
                        removed += 1
            removed += _remove_account_map_entries(child, account_uuid)
    elif isinstance(value, list):
        for child in value:
            removed += _remove_account_map_entries(child, account_uuid)
    return removed


def _retire_residuals(
    paths: ClaudeAccountPaths,
    account_uuid: str,
    organization_uuids: set[str],
) -> dict[str, int]:
    sources = _account_sources(paths)
    config = _read_json(paths.config_path, strict=False)
    allowlists = sum(
        1
        for key in config
        if key.startswith("dxt:allowlist") and key.rsplit(":", 1)[-1].lower() in organization_uuids
    )
    identity_fields = int(account_uuid in _identity_uuids(config))
    account_directories = sum(
        1
        for root in (paths.code_sessions_root, paths.agent_sessions_root)
        if (root / account_uuid).exists()
    )
    return {
        "account_sources": int(account_uuid in sources),
        "account_directories": account_directories,
        "identity_fields": identity_fields,
        "organization_allowlists": allowlists,
    }


def retire_stale_account(
    account_uuid: str,
    confirmation: str,
    paths: ClaudeAccountPaths | None = None,
    *,
    process_checker: Callable[[], list[dict[str, object]]] | None = None,
) -> dict:
    paths = paths or default_paths()
    account_uuid = str(account_uuid).lower()
    if not _is_uuid(account_uuid):
        raise ClaudeAccountCleanupError("账号 UUID 格式无效。")
    if confirmation != f"RETIRE_ACCOUNT:{account_uuid}":
        raise ClaudeAccountCleanupError("缺少与目标账号匹配的废弃确认。")

    checker = process_checker or _default_process_checker
    if checker():
        raise ClaudeAccountCleanupError("请先完全退出 Claude 与 Claude Code，再清理旧账号。")

    # Parse every potentially mutated JSON before deleting or writing anything.
    config = _read_json(paths.config_path, strict=True)
    desktop = _read_json(paths.desktop_config_path, strict=True)
    cowork = _read_json(paths.cowork_ops_path, strict=True)
    anchor = _read_json(paths.primary_anchor, strict=True)
    home_config = _read_json(paths.home_config_path, strict=True)

    current_uuids = _current_uuids(paths, config, home_config)
    if account_uuid in current_uuids:
        raise ClaudeAccountCleanupError("当前账号属于永久保护层，拒绝清理。")
    sources = _account_sources(paths, desktop)
    if account_uuid not in sources:
        raise ClaudeAccountCleanupError("目标 UUID 不在本次扫描识别的账号对象中。")

    account_paths = [root / account_uuid for root in (paths.code_sessions_root, paths.agent_sessions_root)]
    for root, account_path in zip((paths.code_sessions_root, paths.agent_sessions_root), account_paths):
        if account_path.exists():
            _require_direct_child(root, account_path)
    orgs = _orgs_for_account(paths, account_uuid)

    config_removed = 0
    for key in list(config):
        value = config[key]
        if key in ACCOUNT_IDENTITY_KEYS and isinstance(value, str) and value.lower() == account_uuid:
            del config[key]
            config_removed += 1
        elif key.startswith("dxt:allowlist") and ":" in key:
            suffix = key.rsplit(":", 1)[-1].lower()
            if suffix in orgs:
                del config[key]
                config_removed += 1

    map_removed = _remove_account_map_entries(desktop, account_uuid)
    cowork_removed = 0
    owner = cowork.get("ownerAccountId")
    if isinstance(owner, str) and owner.lower() == account_uuid:
        del cowork["ownerAccountId"]
        cowork_removed = 1
    anchor_removed = 0
    anchor_uuid = anchor.get("account_uuid")
    if isinstance(anchor_uuid, str) and anchor_uuid.lower() == account_uuid:
        anchor = {}
        anchor_removed = 1

    mutations = (
        (paths.config_path, config, config_removed),
        (paths.desktop_config_path, desktop, map_removed),
        (paths.cowork_ops_path, cowork, cowork_removed),
        (paths.primary_anchor, anchor, anchor_removed),
    )
    result: dict[str, object] = {
        "status": "partial",
        "account_uuid": account_uuid,
        "directories_removed": 0,
        "config_fields_removed": config_removed,
        "account_map_entries_removed": map_removed,
        "cowork_owner_removed": cowork_removed,
        "primary_anchor_removed": anchor_removed,
        "bytes_removed": 0,
        "protected_login_touched": False,
        "project_assets_touched": False,
    }
    for account_path in account_paths:
        if account_path.exists():
            size = _path_size(account_path)
            try:
                shutil.rmtree(account_path)
            except Exception as exc:
                residuals = _retire_residuals(paths, account_uuid, orgs)
                partial = _partial_result(result, phase="account-directories", error=exc, residuals=residuals)
                raise ClaudeAccountPartialCleanupError("旧账号目录只完成了部分清理，可以安全重试。", partial) from exc
            result["bytes_removed"] = int(result["bytes_removed"]) + size
            result["directories_removed"] = int(result["directories_removed"]) + 1

    if any(account_path.exists() for account_path in account_paths):
        residuals = _retire_residuals(paths, account_uuid, orgs)
        partial = _partial_result(
            result,
            phase="deletion-postcondition",
            error="账号目录删除后仍然存在",
            residuals=residuals,
        )
        raise ClaudeAccountPartialCleanupError("旧账号目录仍有残留，JSON 尚未提交，可以安全重试。", partial)

    changes = [(path, value) for path, value, changed in mutations if changed]
    try:
        _write_json_batch_with_rollback(changes)
    except Exception as exc:
        residuals = _retire_residuals(paths, account_uuid, orgs)
        partial = _partial_result(result, phase="json-commit", error=exc, residuals=residuals)
        raise ClaudeAccountPartialCleanupError("旧账号配置只完成了部分清理，可以安全重试。", partial) from exc

    residuals = _retire_residuals(paths, account_uuid, orgs)
    if _has_residuals(residuals):
        partial = _partial_result(result, phase="postcondition", error="仍检测到目标账号残留", residuals=residuals)
        raise ClaudeAccountPartialCleanupError("旧账号仍有残留，结果标记为部分完成，可以安全重试。", partial)

    result.update(
        {
            "status": "completed",
            "residuals": residuals,
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }
    )
    return result


def _remove_all_account_login_fields(value: object) -> dict[str, int]:
    counts = {"account": 0, "organization": 0, "maps": 0, "login_metadata": 0}

    def visit(node: object) -> None:
        if isinstance(node, dict):
            for key, child in list(node.items()):
                if key in ACCOUNT_IDENTITY_KEYS:
                    del node[key]
                    counts["account"] += 1
                    continue
                if key in ORGANIZATION_IDENTITY_KEYS:
                    del node[key]
                    counts["organization"] += 1
                    continue
                if key in LOGIN_METADATA_KEYS or key.startswith("oauth:"):
                    del node[key]
                    counts["login_metadata"] += 1
                    continue
                if key.startswith("dxt:allowlist") and _is_uuid(key.rsplit(":", 1)[-1]):
                    del node[key]
                    counts["organization"] += 1
                    continue
                if key in ACCOUNT_MAP_KEYS and isinstance(child, dict):
                    for candidate in list(child):
                        if _is_uuid(candidate):
                            del child[candidate]
                            counts["maps"] += 1
                visit(child)
        elif isinstance(node, list):
            for child in node:
                visit(child)

    visit(value)
    return counts


def _known_identity_field_counts(paths: ClaudeAccountPaths) -> dict[str, int]:
    totals = {"account": 0, "organization": 0, "maps": 0, "login_metadata": 0}
    for value in (
        _read_json(paths.config_path, strict=False),
        _read_json(paths.desktop_config_path, strict=False),
        _read_json(paths.cowork_ops_path, strict=False),
        _read_json(paths.primary_anchor, strict=False),
        _read_json(paths.home_config_path, strict=False),
    ):
        counts = _remove_all_account_login_fields(copy.deepcopy(value))
        for key in totals:
            totals[key] += counts[key]
    return totals


def _reset_residuals(
    paths: ClaudeAccountPaths,
    credential_target_provider: Callable[[], list[str]],
) -> dict[str, int]:
    field_counts = _known_identity_field_counts(paths)
    account_directories = 0
    for root in (paths.code_sessions_root, paths.agent_sessions_root):
        if root.is_dir() and not _is_reparse(root):
            account_directories += sum(
                1
                for child in root.iterdir()
                if child.is_dir() and not _is_reparse(child) and _is_uuid(child.name)
            )
    try:
        credential_target_count = len(_credential_targets(credential_target_provider))
        credential_scan_failures = 0
    except ClaudeAccountCleanupError:
        credential_target_count = 0
        credential_scan_failures = 1
    return {
        "account_directories": account_directories,
        "account_fields": field_counts["account"],
        "organization_links": field_counts["organization"],
        "account_map_entries": field_counts["maps"],
        "login_metadata": field_counts["login_metadata"],
        "login_paths": len(_login_storage_paths(paths)),
        "credential_targets": credential_target_count,
        "credential_scan_failures": credential_scan_failures,
    }


def _deletion_residuals(
    paths: ClaudeAccountPaths,
    credential_target_provider: Callable[[], list[str]],
) -> dict[str, int]:
    account_directories = 0
    for root in (paths.code_sessions_root, paths.agent_sessions_root):
        if root.is_dir() and not _is_reparse(root):
            account_directories += sum(
                1
                for child in root.iterdir()
                if child.is_dir() and not _is_reparse(child) and _is_uuid(child.name)
            )
    try:
        credential_target_count = len(_credential_targets(credential_target_provider))
        credential_scan_failures = 0
    except ClaudeAccountCleanupError:
        credential_target_count = 0
        credential_scan_failures = 1
    return {
        "account_directories": account_directories,
        "login_paths": len(_login_storage_paths(paths)),
        "credential_targets": credential_target_count,
        "credential_scan_failures": credential_scan_failures,
    }


def _has_residuals(residuals: dict[str, int]) -> bool:
    return any(value > 0 for value in residuals.values())


def _partial_result(
    result: dict[str, object],
    *,
    phase: str,
    error: Exception | str,
    residuals: dict[str, int],
) -> dict[str, object]:
    result.update(
        {
            "status": "partial",
            "failed_phase": phase,
            "failure": str(error),
            "residuals": residuals,
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }
    )
    return result


def reset_all_accounts_and_login(
    confirmation: str,
    logged_out_acknowledged: bool,
    paths: ClaudeAccountPaths | None = None,
    *,
    process_checker: Callable[[], list[dict[str, object]]] | None = None,
    credential_target_provider: Callable[[], list[str]] | None = None,
    credential_target_deleter: Callable[[str], None] | None = None,
) -> dict:
    paths = paths or default_paths()
    if confirmation != "RESET_ALL_CLAUDE_ACCOUNTS":
        raise ClaudeAccountCleanupError("缺少清空全部账号与登录层的精确确认。")
    if logged_out_acknowledged is not True:
        raise ClaudeAccountCleanupError("请先确认当前已经退出全部 Claude 账号。")

    checker = process_checker or _default_process_checker
    if checker():
        raise ClaudeAccountCleanupError("请先完全退出 Claude 与 Claude Code，再清空账号与登录层。")
    provider = credential_target_provider or _default_credential_target_provider
    credential_deleter = credential_target_deleter or _default_credential_target_deleter
    credential_targets = _credential_targets(provider)

    # Parse every JSON that may be changed before mutating or deleting anything.
    config = _read_json(paths.config_path, strict=True)
    desktop = _read_json(paths.desktop_config_path, strict=True)
    cowork = _read_json(paths.cowork_ops_path, strict=True)
    anchor = _read_json(paths.primary_anchor, strict=True)
    home_config = _read_json(paths.home_config_path, strict=True)

    account_paths: list[Path] = []
    for root in (paths.code_sessions_root, paths.agent_sessions_root):
        if root.exists() and _is_reparse(root):
            raise ClaudeAccountCleanupError("账号会话根目录是链接或重解析点，拒绝处理。")
        if root.is_dir():
            for child in root.iterdir():
                if child.is_dir() and _is_uuid(child.name):
                    _require_direct_child(root, child)
                    account_paths.append(child)

    login_paths = _login_storage_paths(paths)
    credentials = paths.home_root / ".credentials.json"
    for path in login_paths:
        if path == credentials:
            _require_owned_child(paths.home_root, path)
            continue
        if path.parent == paths.msix_root:
            owner_root = paths.msix_root
        elif path.parent == paths.legacy_root:
            owner_root = paths.legacy_root
        elif path.parent == paths.package_root:
            owner_root = paths.package_root
        else:
            raise ClaudeAccountCleanupError("登录存储不在允许的 Claude 根目录内。")
        _require_owned_child(owner_root, path)

    totals = {"account": 0, "organization": 0, "maps": 0, "login_metadata": 0}
    mutations: list[tuple[Path, dict, dict[str, int]]] = []
    for path, value in (
        (paths.config_path, config),
        (paths.desktop_config_path, desktop),
        (paths.cowork_ops_path, cowork),
        (paths.home_config_path, home_config),
    ):
        counts = _remove_all_account_login_fields(value)
        for key in totals:
            totals[key] += counts[key]
        mutations.append((path, value, counts))

    anchor_counts = _remove_all_account_login_fields(anchor)
    for key in totals:
        totals[key] += anchor_counts[key]
    anchor_changed = bool(anchor)
    if anchor_changed:
        anchor = {}

    result: dict[str, object] = {
        "status": "partial",
        "directories_removed": 0,
        "account_fields_removed": totals["account"],
        "organization_links_removed": totals["organization"],
        "account_map_entries_removed": totals["maps"],
        "login_metadata_removed": totals["login_metadata"],
        "login_paths_removed": 0,
        "credential_targets_removed": 0,
        "bytes_removed": 0,
        "project_assets_touched": False,
        "machine_id_touched": False,
    }

    for account_path in account_paths:
        size = _path_size(account_path)
        try:
            shutil.rmtree(account_path)
        except Exception as exc:
            residuals = _reset_residuals(paths, provider)
            partial = _partial_result(result, phase="account-directories", error=exc, residuals=residuals)
            raise ClaudeAccountPartialCleanupError("账号目录只完成了部分清理，可以安全重试。", partial) from exc
        result["bytes_removed"] = int(result["bytes_removed"]) + size
        result["directories_removed"] = int(result["directories_removed"]) + 1

    for path in login_paths:
        size = _path_size(path)
        try:
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
        except Exception as exc:
            residuals = _reset_residuals(paths, provider)
            partial = _partial_result(result, phase="login-paths", error=exc, residuals=residuals)
            raise ClaudeAccountPartialCleanupError("登录存储只完成了部分清理，可以安全重试。", partial) from exc
        result["bytes_removed"] = int(result["bytes_removed"]) + size
        result["login_paths_removed"] = int(result["login_paths_removed"]) + 1

    for target in credential_targets:
        try:
            credential_deleter(target)
        except Exception as exc:
            residuals = _reset_residuals(paths, provider)
            partial = _partial_result(result, phase="credential-manager", error=exc, residuals=residuals)
            raise ClaudeAccountPartialCleanupError("Windows 凭据只完成了部分清理，可以安全重试。", partial) from exc
        result["credential_targets_removed"] = int(result["credential_targets_removed"]) + 1

    deletion_residuals = _deletion_residuals(paths, provider)
    if _has_residuals(deletion_residuals):
        partial = _partial_result(
            result,
            phase="deletion-postcondition",
            error="删除阶段仍检测到账号目录、登录存储或 Windows 凭据",
            residuals=deletion_residuals,
        )
        raise ClaudeAccountPartialCleanupError("删除阶段仍有残留，JSON 尚未提交，可以安全重试。", partial)

    changes = [
        (path, value)
        for path, value, counts in mutations
        if path.exists() and any(counts.values())
    ]
    if paths.primary_anchor.exists() and anchor_changed:
        changes.append((paths.primary_anchor, anchor))
    try:
        _write_json_batch_with_rollback(changes)
    except Exception as exc:
        residuals = _reset_residuals(paths, provider)
        partial = _partial_result(result, phase="json-commit", error=exc, residuals=residuals)
        raise ClaudeAccountPartialCleanupError("账号配置只完成了部分清理，可以安全重试。", partial) from exc

    residuals = _reset_residuals(paths, provider)
    if _has_residuals(residuals):
        partial = _partial_result(result, phase="postcondition", error="仍检测到账号或登录层残留", residuals=residuals)
        raise ClaudeAccountPartialCleanupError("仍检测到账号或登录层残留，结果标记为部分完成，可以安全重试。", partial)

    result.update(
        {
            "status": "completed",
            "residuals": residuals,
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }
    )
    return result
