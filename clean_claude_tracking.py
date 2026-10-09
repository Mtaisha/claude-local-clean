#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Claude Code 追踪数据清理脚本
支持 Windows 11, macOS, Linux
"""
import json
import os
import platform
import shutil
import stat
import sys
import tempfile
from pathlib import Path

DEVICE_LINK_KEYS = [
    'machineID',
    'machineId',
    'userID',
    'userId',
    'anonymousId',
    'firstStartTime',
    'claudeCodeFirstTokenDate',
]

STRUCTURED_NOTICE_ENV = 'CLAUDE_LOCAL_CLEAN_STRUCTURED_NOTICES'
STRUCTURED_NOTICE_PREFIX = '@@CLAUDE_LOCAL_CLEAN_NOTICE@@'


class CleanupSafetyError(RuntimeError):
    """Raised when an allowlisted cleanup target is redirected through a link."""

# 隐私加固：写入 ~/.claude/settings.json 的 env 变量。
# 不同 Claude 版本可能只识别其中一部分；不识别的键会作为普通环境变量保留。
# apply_privacy_hardening() 只强制管理以下隐私键；其他 env 不会被覆盖。
PRIVACY_ENV = {
    # 一键关所有非必要流量（推荐第一道防线）
    'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC': 'true',
    # 显式关 telemetry
    'CLAUDE_CODE_ENABLE_TELEMETRY': 'false',
    'DISABLE_TELEMETRY': '1',
    # 关错误上报（Sentry / Datadog）
    'DISABLE_ERROR_REPORTING': '1',
    # 关反馈命令（避免误触发上报）
    'DISABLE_FEEDBACK_COMMAND': '1',
    # 通用不追踪协议
    'DO_NOT_TRACK': '1',
    # 关 GrowthBook（feature flag CDN）
    'DISABLE_GROWTHBOOK': '1',
    # 关自动更新（避免升级后 patch 丢失，也避免自动更新流量）
    'CLAUDE_CODE_PACKAGE_MANAGER_AUTO_UPDATE': 'false',
    'DISABLE_AUTOUPDATER': '1',
    # OTEL 内容上报默认已关，这里显式关闭以防被 admin 或其他配置打开
    'OTEL_LOG_USER_PROMPTS': '0',
    'OTEL_LOG_TOOL_CONTENT': '0',
    'OTEL_LOG_TOOL_DETAILS': '0',
    'OTEL_LOG_RAW_API_BODIES': '0',
}

# 修复 Windows 编码
if platform.system() == "Windows":
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

def get_home():
    return Path.home()

def get_claude_json():
    return get_home() / ".claude.json"

def get_claude_dir():
    return get_home() / ".claude"


def emit_structured_notice(notice):
    """Emit a server-only result marker without cluttering direct CLI runs."""
    if os.environ.get(STRUCTURED_NOTICE_ENV) == '1':
        print(
            STRUCTURED_NOTICE_PREFIX
            + json.dumps(notice, ensure_ascii=False, separators=(',', ':'))
        )


def _is_reparse(path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    attributes = getattr(info, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return path.is_symlink() or bool(attributes & reparse_flag)


def _require_plain_child(root, path):
    if path.parent != root:
        raise CleanupSafetyError(f"清理目标不在固定根目录内: {path}")
    if _is_reparse(root) or _is_reparse(path):
        raise CleanupSafetyError(f"清理目标是链接或重解析点，拒绝处理: {path}")


def save_claude_json(path, data):
    """Atomically replace Claude's JSON file without creating a backup copy."""
    if _is_reparse(path):
        raise CleanupSafetyError(f"配置文件是链接或重解析点，拒绝处理: {path}")
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp-clean", dir=path.parent)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, path)
    finally:
        temp_path.unlink(missing_ok=True)

def clean_tracking_ids():
    """清除追踪标识（保留其他配置）"""
    claude_json = get_claude_json()
    if not claude_json.exists():
        print("✓ ~/.claude.json 不存在")
        return
    if _is_reparse(claude_json):
        raise CleanupSafetyError(f"配置文件是链接或重解析点，拒绝处理: {claude_json}")

    with open(claude_json, 'r', encoding='utf-8') as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise CleanupSafetyError("~/.claude.json 顶层不是对象，拒绝修改")

    removed = []
    for key in DEVICE_LINK_KEYS:
        if key in data:
            removed.append(key)
            del data[key]

    if removed:
        save_claude_json(claude_json, data)
        print(f"✓ 已删除追踪 ID: {', '.join(removed)}")
    else:
        print("✓ 无追踪 ID 需要删除")

def clean_telemetry():
    """清除遥测和分析数据"""
    dirs = [
        get_claude_dir() / "telemetry",
        get_claude_dir() / "statsig",
    ]
    files = [
        get_claude_dir() / "stats-cache.json",
    ]

    for target in [*dirs, *files]:
        _require_plain_child(get_claude_dir(), target)

    for d in dirs:
        if d.exists():
            shutil.rmtree(d)
            print(f"✓ 已删除: {d}")

    for f in files:
        if f.exists():
            f.unlink()
            print(f"✓ 已删除: {f}")

def get_desktop_audit_roots():
    """Return only known Claude Desktop local-agent audit roots on Windows."""
    if platform.system() != "Windows":
        return []

    roots = []
    appdata = os.environ.get("APPDATA")
    if appdata:
        roots.append(Path(appdata) / "Claude" / "local-agent-mode-sessions")

    local_appdata = os.environ.get("LOCALAPPDATA")
    if local_appdata:
        packages = Path(local_appdata) / "Packages"
        for package in packages.glob("Claude_*"):
            roots.append(
                package / "LocalCache" / "Roaming" / "Claude" /
                "local-agent-mode-sessions"
            )

    return roots

def clean_desktop_audit_logs():
    """Delete Claude Desktop local-agent audit transcripts from known roots."""
    removed = 0
    removed_bytes = 0
    seen = set()

    for root in get_desktop_audit_roots():
        if not root.is_dir():
            continue
        if _is_reparse(root):
            raise CleanupSafetyError(f"Desktop 审计根目录是链接或重解析点，拒绝处理: {root}")
        for audit_log in root.rglob("audit.jsonl"):
            if _is_reparse(audit_log):
                raise CleanupSafetyError(f"Desktop 审计记录是链接或重解析点，拒绝处理: {audit_log}")
            if not audit_log.is_file() and not audit_log.is_symlink():
                continue
            identity = str(audit_log.resolve(strict=False)).casefold()
            if identity in seen:
                continue
            seen.add(identity)
            try:
                removed_bytes += audit_log.stat().st_size
            except OSError:
                pass
            audit_log.unlink()
            removed += 1
            print(f"✓ 已删除 Desktop 审计记录: {audit_log}")

    print(f"✓ Desktop 审计记录清理: {removed} 个文件，{removed_bytes} 字节")

def clean_safe_cache():
    """清除可重建缓存，保留登录、会话环境、备份和全部工作资产。"""
    items = [
        get_claude_dir() / "paste-cache",
        get_claude_dir() / "shell-snapshots",
        get_claude_dir() / "debug",
    ]

    for item in items:
        _require_plain_child(get_claude_dir(), item)

    for item in items:
        if item.exists():
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()
            print(f"✓ 已删除可重建缓存: {item}")


def verify_tracking_ids_clean():
    """Return device-link fields that remain after cleanup."""
    claude_json = get_claude_json()
    if not claude_json.exists():
        return []
    if _is_reparse(claude_json):
        raise CleanupSafetyError(f"配置文件是链接或重解析点，拒绝复查: {claude_json}")
    with open(claude_json, 'r', encoding='utf-8') as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise CleanupSafetyError("~/.claude.json 顶层不是对象，无法安全复查")
    remaining = [key for key in DEVICE_LINK_KEYS if key in data]
    return [f"设备关联字段仍存在: {', '.join(remaining)}"] if remaining else []


def verify_telemetry_clean():
    """Return allowlisted telemetry targets that still exist."""
    targets = [
        get_claude_dir() / "telemetry",
        get_claude_dir() / "statsig",
        get_claude_dir() / "stats-cache.json",
    ]
    remaining = []
    for target in targets:
        _require_plain_child(get_claude_dir(), target)
        if target.exists() or target.is_symlink():
            remaining.append(target.name)
    return [f"遥测缓存仍存在: {', '.join(remaining)}"] if remaining else []


def verify_desktop_audit_clean():
    """Return a bounded summary of Desktop audit logs that remain."""
    remaining = 0
    for root in get_desktop_audit_roots():
        if not root.is_dir():
            continue
        if _is_reparse(root):
            raise CleanupSafetyError(f"Desktop 审计根目录是链接或重解析点，拒绝复查: {root}")
        for audit_log in root.rglob("audit.jsonl"):
            if _is_reparse(audit_log):
                raise CleanupSafetyError(
                    f"Desktop 审计记录是链接或重解析点，拒绝复查: {audit_log}"
                )
            if audit_log.is_file() or audit_log.is_symlink():
                remaining += 1
    return [f"Desktop audit.jsonl 仍存在: {remaining} 个"] if remaining else []


def verify_safe_cache_clean():
    """Return allowlisted rebuildable caches that still exist."""
    targets = [
        get_claude_dir() / "paste-cache",
        get_claude_dir() / "shell-snapshots",
        get_claude_dir() / "debug",
    ]
    remaining = []
    for target in targets:
        _require_plain_child(get_claude_dir(), target)
        if target.exists() or target.is_symlink():
            remaining.append(target.name)
    return [f"可重建缓存仍存在: {', '.join(remaining)}"] if remaining else []


def verify_privacy_hardening():
    """Return local Claude Code privacy values that failed read-back."""
    settings_path = get_claude_dir() / 'settings.json'
    if _is_reparse(settings_path.parent) or _is_reparse(settings_path):
        raise CleanupSafetyError("settings.json 或其 Claude 根目录是链接/重解析点")
    if not settings_path.is_file():
        return ["settings.json 不存在"]
    with open(settings_path, 'r', encoding='utf-8') as f:
        settings = json.load(f)
    if not isinstance(settings, dict):
        raise CleanupSafetyError("settings.json 顶层不是对象，无法安全复查")
    env = settings.get('env')
    if not isinstance(env, dict):
        raise CleanupSafetyError("settings.json 的 env 不是对象，无法安全复查")
    remaining = [key for key, value in PRIVACY_ENV.items() if env.get(key) != value]
    if settings.get('autoUpdates') is not False:
        remaining.append('autoUpdates')
    return [f"隐私配置回读不一致: {', '.join(remaining)}"] if remaining else []


def _one_line(value):
    return " ".join(str(value).split())[:1200]


def _status_problems(result):
    if not isinstance(result, dict):
        return []
    if result.get("status") not in {"partial", "blocked", "unavailable", "failed"}:
        return []
    return [_one_line(result.get("reason") or "步骤返回未完成状态")]


def _merge_notices(*results):
    merged = []
    seen = set()
    for result in results:
        if not isinstance(result, dict):
            continue
        for notice in result.get("notices", []):
            if not isinstance(notice, dict):
                continue
            identity = json.dumps(notice, ensure_ascii=False, sort_keys=True)
            if identity not in seen:
                seen.add(identity)
                merged.append(notice)
    return merged


def _stage_attempt(action, verifier=None, inspect_result=None):
    """Run one bounded attempt and return result, problems, and retry safety."""
    try:
        raw_result = action()
    except (CleanupSafetyError, json.JSONDecodeError, UnicodeError) as exc:
        return {"status": "partial"}, [_one_line(exc)], False
    except OSError as exc:
        return {"status": "partial"}, [_one_line(exc)], True

    result = dict(raw_result) if isinstance(raw_result, dict) else {"status": "success"}
    problems = list(inspect_result(result) if inspect_result else [])
    if verifier is None:
        return result, problems, True
    try:
        problems.extend(verifier())
    except (CleanupSafetyError, json.JSONDecodeError, UnicodeError) as exc:
        return result, [*problems, _one_line(exc)], False
    except OSError as exc:
        return result, [*problems, _one_line(exc)], True
    return result, [_one_line(problem) for problem in problems if problem], True


def run_self_healing_stage(label, action, verifier=None, inspect_result=None):
    """Run, verify, retry once when safe, and report a bounded final failure."""
    first, problems, repairable = _stage_attempt(action, verifier, inspect_result)
    if not problems:
        print(f"✓ 自检通过: {label}")
        return first

    initial = "；".join(problems)
    if not repairable:
        detail = f"{label} 无法安全自动修复: {initial}"
        print(f"✗ 自动修复失败: {detail}")
        emit_structured_notice(
            {"code": "cleanup-auto-repair-failed", "stage": label, "reason": detail}
        )
        return {"status": "partial", "reason": detail, "notices": _merge_notices(first)}

    print(f"⚠ 自检发现问题，正在自动修复 {label}: {initial}")
    second, remaining, _second_repairable = _stage_attempt(action, verifier, inspect_result)
    notices = _merge_notices(first, second)
    if remaining:
        detail = f"{label} 自动修复后仍未通过: {'；'.join(remaining)}"
        print(f"✗ 自动修复失败: {detail}")
        emit_structured_notice(
            {"code": "cleanup-auto-repair-failed", "stage": label, "reason": detail}
        )
        return {"status": "partial", "reason": detail, "notices": notices}

    print(f"✓ 自动修复成功: {label}")
    second["status"] = "success"
    second["notices"] = notices
    return second


def clean_local_desktop_privacy():
    """Clean Windows-local Desktop residue and content-verified embedded CC markers."""
    if platform.system() != "Windows":
        return {"status": "success"}

    try:
        from local_desktop_privacy import (
            DesktopPrivacyError,
            SUPPORTED_EMBEDDED_VERSION,
            clean_desktop_privacy_residue,
            harden_current_embedded_claude_code,
        )
    except ImportError:
        print("⚠ 本机 Desktop 清理模块不存在，已跳过")
        return {"status": "partial", "reason": "Desktop cleanup module is missing"}

    incomplete = False
    problems = []
    notices = []
    try:
        residue = clean_desktop_privacy_residue()
        if residue.get("status") == "blocked":
            incomplete = True
            problems.append("Claude 正在运行，Desktop 缓存与设备注册残留未处理")
            print("⚠ Claude 正在运行，未删除 Desktop 缓存与设备注册残留")
        elif residue.get("removed_count"):
            print(
                f"✓ 已删除 Desktop 可重建残留: {residue['removed_count']} 项，"
                f"{residue['removed_bytes']} 字节"
            )
        else:
            print("✓ Desktop 可重建残留已是干净状态")

        embedded = harden_current_embedded_claude_code()
        status = embedded.get("status")
        if status == "updated":
            print(f"✓ 已按内容校验清理内置 Claude Code {embedded['version']}")
        elif status == "current":
            print(f"✓ 内置 Claude Code {embedded['version']} 已是清理状态")
        elif status == "blocked":
            incomplete = True
            problems.append("Claude 正在运行，内置 Claude Code 未处理")
            print("⚠ Claude 正在运行，未修改内置 Claude Code")
        elif status == "unsupported":
            version = str(embedded.get('version', '未知版本'))
            if embedded.get("newer_than_supported") is True:
                notices.append(
                    {
                        "code": "embedded-cc-newer",
                        "version": version,
                        "supported_version": str(
                            embedded.get("supported_version", SUPPORTED_EMBEDDED_VERSION)
                        ),
                    }
                )
                print(
                    f"⚠ 内置 Claude Code {version} 高于当前已复核版本 "
                    f"{embedded.get('supported_version', SUPPORTED_EMBEDDED_VERSION)}；"
                    "常规清理已继续，深度二进制处理已跳过，建议自行扫描新版文件后再深度清理"
                )
            else:
                incomplete = True
                problems.append(f"内置 Claude Code {version} 尚未通过内容复核")
                print(
                    f"⚠ 内置 Claude Code {version} 未在支持清单中；"
                    "为避免误改已跳过，需先重新审查该版本内容"
                )
        else:
            print("  未发现可处理的 Desktop 内置 Claude Code")
    except DesktopPrivacyError as exc:
        incomplete = True
        problems.append(str(exc))
        print(f"⚠ Desktop 本机清理未通过内容校验，已停止该步骤: {exc}")
    return {
        "status": "partial" if incomplete else "success",
        "reason": "；".join(problems),
        "notices": notices,
    }


def apply_local_desktop_privacy_hardening():
    """Apply the persistent Windows Desktop managed privacy configuration."""
    if platform.system() != "Windows":
        return {"status": "success"}

    try:
        from local_desktop_privacy import DesktopPrivacyError, apply_desktop_managed_privacy
    except ImportError:
        print("⚠ 本机 Desktop 隐私模块不存在，已跳过")
        return {"status": "partial", "reason": "Desktop privacy module is missing"}

    try:
        result = apply_desktop_managed_privacy()
        if result.get("status") == "updated":
            print(f"✓ 已写入 Desktop 托管隐私配置: {', '.join(result['changed'])}")
        elif result.get("status") == "current":
            print("✓ Desktop 托管隐私配置已是最新状态")
        else:
            reason = result.get('reason', 'unknown')
            print(f"⚠ Desktop 托管配置不可用，已跳过: {reason}")
            return {"status": "partial", "reason": str(reason)}
        return {"status": "success"}
    except DesktopPrivacyError as exc:
        print(f"⚠ Desktop 托管隐私配置未通过校验，已跳过: {exc}")
        return {"status": "partial", "reason": str(exc)}

def apply_privacy_hardening():
    """在 ~/.claude/settings.json 中启用隐私加固 env 变量。

    - 保留现有字段（enabledPlugins/theme/hooks 等一律不动）
    - 只 merge 到 env 子字段
    - 只强制管理 PRIVACY_ENV 中的隐私键，其他 env 与顶层字段不动
    - 顶层 autoUpdates 强制设为 false
    """
    settings_path = get_claude_dir() / 'settings.json'
    if _is_reparse(settings_path.parent) or _is_reparse(settings_path):
        print('⚠ settings.json 或其 Claude 根目录是链接/重解析点；不做任何修改')
        return {"status": "partial", "reason": "settings.json path is redirected"}
    if settings_path.exists():
        try:
            with open(settings_path, 'r', encoding='utf-8') as f:
                settings = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            print(f'⚠ settings.json 读取失败: {exc}；不做任何修改')
            apply_local_desktop_privacy_hardening()
            return {"status": "partial", "reason": "settings.json is unreadable"}
    else:
        settings = {}

    if not isinstance(settings, dict):
        print('⚠ settings.json 顶层不是对象；不做任何修改')
        apply_local_desktop_privacy_hardening()
        return {"status": "partial", "reason": "settings.json root is invalid"}

    env = settings.get('env')
    if env is None:
        env = {}
    elif not isinstance(env, dict):
        print('⚠ settings.json 的 env 不是对象；不做任何修改')
        apply_local_desktop_privacy_hardening()
        return {"status": "partial", "reason": "settings.json env is invalid"}

    changed = []
    for key, value in PRIVACY_ENV.items():
        if env.get(key) != value:
            env[key] = value
            changed.append(key)

    settings['env'] = env

    top_level_changed = settings.get('autoUpdates') is not False
    if top_level_changed:
        settings['autoUpdates'] = False

    if changed or top_level_changed or not settings_path.exists():
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(
            prefix=f'.{settings_path.name}.', suffix='.tmp-clean', dir=settings_path.parent
        )
        tmp = Path(temp_name)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(settings, f, indent=2, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, settings_path)
        finally:
            tmp.unlink(missing_ok=True)

    if changed:
        print(f'✓ 已强制设置隐私加固 env: {", ".join(changed)}')
    if top_level_changed:
        print('✓ 已强制设置 autoUpdates=false（顶层）')
    if not changed and not top_level_changed:
        print('✓ 隐私加固已是最新状态，无需改动')

    return apply_local_desktop_privacy_hardening()


def clean_device_links_only(include_desktop_audit=False):
    """Remove Claude-owned device links without touching login or session data."""
    print("=== Claude Code 设备关联清理 ===\n")
    print(f"平台: {platform.system()} {platform.release()}\n")

    total_steps = 3 if include_desktop_audit else 2
    print(f"[1/{total_steps}] 清除 Claude Code 本地设备标识...")
    tracking_result = run_self_healing_stage(
        "Claude Code 设备关联字段",
        clean_tracking_ids,
        verify_tracking_ids_clean,
    )

    print(f"\n[2/{total_steps}] 清除遥测与 Statsig 缓存...")
    telemetry_result = run_self_healing_stage(
        "遥测与 Statsig 缓存",
        clean_telemetry,
        verify_telemetry_clean,
    )

    results = [tracking_result, telemetry_result]

    if include_desktop_audit:
        print("\n[3/3] 清除 Claude Desktop 本地代理审计记录...")
        results.append(
            run_self_healing_stage(
                "Claude Desktop 审计记录",
                clean_desktop_audit_logs,
                verify_desktop_audit_clean,
            )
        )

    audit_note = "；已删除 Desktop 本地代理审计回放记录" if include_desktop_audit else ""
    incomplete = any(result.get("status") == "partial" for result in results)
    if incomplete:
        print("\n⚠ 设备关联清理部分完成；无法自动修复的项目已在上方列明。")
    else:
        print(f"\n✓ 设备关联清理完成；未修改系统 Machine ID，未删除登录、普通 Claude Code 项目对话或文件回退数据{audit_note}。")
    return {"status": "partial" if incomplete else "success"}

def main() -> int:
    allowed_flags = {'--device-links-only', '--desktop-audit', '--privacy-harden'}
    unknown_args = [arg for arg in sys.argv[1:] if arg not in allowed_flags]
    if unknown_args:
        print(f'✗ 未知参数: {", ".join(unknown_args)}', file=sys.stderr)
        return 1
    if '--desktop-audit' in sys.argv and '--device-links-only' not in sys.argv:
        print('✗ --desktop-audit 必须与 --device-links-only 一起使用', file=sys.stderr)
        return 1

    apply_privacy = '--privacy-harden' in sys.argv

    if '--device-links-only' in sys.argv:
        cleanup_result = clean_device_links_only(
            include_desktop_audit='--desktop-audit' in sys.argv
        )
        incomplete = cleanup_result.get("status") == "partial"
        if apply_privacy:
            print('\n[附加] 应用隐私加固 env...')
            result = run_self_healing_stage(
                "隐私加固配置",
                apply_privacy_hardening,
                verify_privacy_hardening,
                _status_problems,
            )
            incomplete = incomplete or result.get("status") == "partial"
        return 2 if incomplete else 0

    # 仅隐私加固（不清任何东西）
    if apply_privacy and len([a for a in sys.argv[1:] if not a.startswith('-')]) == 0 \
            and set(sys.argv[1:]).issubset({'--privacy-harden'}):
        print('=== Claude 隐私加固（写入 Code env 与本机 Desktop 托管配置，不清理数据）===\n')
        print(f'平台: {platform.system()} {platform.release()}\n')
        print('[1/1] 应用隐私加固配置...')
        result = run_self_healing_stage(
            "隐私加固配置",
            apply_privacy_hardening,
            verify_privacy_hardening,
            _status_problems,
        )
        if result.get("status") == "partial":
            print('\n⚠ 隐私加固自动修复失败；请查看上方具体错误。')
            return 2
        return 0

    print('=== Claude 一键完整清理 ===\n')
    print(f'平台: {platform.system()} {platform.release()}\n')

    include_local_desktop = platform.system() == "Windows"
    total_steps = 5 if include_local_desktop else 4

    print(f'[1/{total_steps}] 清除追踪标识...')
    tracking_result = run_self_healing_stage(
        "Claude Code 设备关联字段",
        clean_tracking_ids,
        verify_tracking_ids_clean,
    )

    print(f'\n[2/{total_steps}] 清除遥测数据...')
    telemetry_result = run_self_healing_stage(
        "遥测与 Statsig 缓存",
        clean_telemetry,
        verify_telemetry_clean,
    )

    next_step = 3
    incomplete = any(
        result.get("status") == "partial"
        for result in (tracking_result, telemetry_result)
    )
    if include_local_desktop:
        print(f'\n[{next_step}/{total_steps}] 清除本机 Desktop 残留并核验内置 CC...')
        desktop_result = run_self_healing_stage(
            "Claude Desktop 残留与内置 Claude Code",
            clean_local_desktop_privacy,
            inspect_result=_status_problems,
        )
        incomplete = incomplete or desktop_result.get("status") == "partial"
        for notice in desktop_result.get("notices", []):
            if isinstance(notice, dict):
                emit_structured_notice(notice)
        next_step += 1

    print(f'\n[{next_step}/{total_steps}] 清除 Claude Desktop 本地代理审计记录...')
    audit_result = run_self_healing_stage(
        "Claude Desktop 审计记录",
        clean_desktop_audit_logs,
        verify_desktop_audit_clean,
    )
    incomplete = incomplete or audit_result.get("status") == "partial"

    print(f'\n[{next_step + 1}/{total_steps}] 清除可重建缓存...')
    cache_result = run_self_healing_stage(
        "可重建缓存",
        clean_safe_cache,
        verify_safe_cache_clean,
    )
    incomplete = incomplete or cache_result.get("status") == "partial"

    if apply_privacy:
        print('\n[附加] 应用隐私加固 env...')
        privacy_result = run_self_healing_stage(
            "隐私加固配置",
            apply_privacy_hardening,
            verify_privacy_hardening,
            _status_problems,
        )
        incomplete = incomplete or privacy_result.get("status") == "partial"

    if incomplete:
        print('\n⚠ 一键完整清理部分完成；自动修复失败的项目及原因已在上方列明。')
        return 2
    print('\n✓ 一键完整清理完成；登录凭据、账号资料、sessions、session-env、backups 与工作资产均已保留。')
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
