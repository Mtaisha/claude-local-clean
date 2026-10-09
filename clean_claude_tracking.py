#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Claude Code 追踪数据清理脚本
支持 Windows 11, macOS, Linux
"""
import json
import os
import shutil
import platform
import sys
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

def save_claude_json(path, data):
    """Atomically replace Claude's JSON file without creating a backup copy."""
    temp_path = path.with_name(path.name + ".tmp-clean")
    try:
        with open(temp_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        os.replace(temp_path, path)
    finally:
        temp_path.unlink(missing_ok=True)

def clean_tracking_ids():
    """清除追踪标识（保留其他配置）"""
    claude_json = get_claude_json()
    if not claude_json.exists():
        print("✓ ~/.claude.json 不存在")
        return

    with open(claude_json, 'r', encoding='utf-8') as f:
        data = json.load(f)

    removed = []
    for key in DEVICE_LINK_KEYS:
        if key in data:
            removed.append(key)
            del data[key]

    save_claude_json(claude_json, data)

    if removed:
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

    preserve_parent = get_home() / "Documents" / "Claude"
    for preserve in preserve_parent.glob("ClaudeDesktop-session-preserve-*"):
        roots.append(preserve / "package-roaming" / "local-agent-mode-sessions")

    return roots

def clean_desktop_audit_logs():
    """Delete Claude Desktop local-agent audit transcripts from known roots."""
    removed = 0
    removed_bytes = 0
    seen = set()

    for root in get_desktop_audit_roots():
        if not root.is_dir():
            continue
        for audit_log in root.rglob("audit.jsonl"):
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
        if item.exists():
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()
            print(f"✓ 已删除可重建缓存: {item}")


def clean_local_desktop_privacy():
    """Clean Windows-local Desktop residue and content-verified embedded CC markers."""
    if platform.system() != "Windows":
        return {"status": "success"}

    try:
        from local_desktop_privacy import (
            DesktopPrivacyError,
            clean_desktop_privacy_residue,
            harden_current_embedded_claude_code,
        )
    except ImportError:
        print("⚠ 本机 Desktop 清理模块不存在，已跳过")
        return {"status": "partial", "reason": "Desktop cleanup module is missing"}

    incomplete = False
    try:
        residue = clean_desktop_privacy_residue()
        if residue.get("status") == "blocked":
            incomplete = True
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
            print("⚠ Claude 正在运行，未修改内置 Claude Code")
        elif status == "unsupported":
            incomplete = True
            print(
                f"⚠ 内置 Claude Code {embedded.get('version', '未知版本')} 未在支持清单中；"
                "为避免误改已跳过，需先重新审查新版内容"
            )
        else:
            print("  未发现可处理的 Desktop 内置 Claude Code")
    except DesktopPrivacyError as exc:
        incomplete = True
        print(f"⚠ Desktop 本机清理未通过内容校验，已停止该步骤: {exc}")
    return {"status": "partial" if incomplete else "success"}


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
            print(f"  Desktop 托管配置不可用，已跳过: {result.get('reason', 'unknown')}")
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
    if not isinstance(env, dict):
        env = {}

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
        tmp = settings_path.with_name(settings_path.name + '.tmp-clean')
        try:
            settings_path.parent.mkdir(parents=True, exist_ok=True)
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump(settings, f, indent=2, ensure_ascii=False)
            os.replace(tmp, settings_path)
        finally:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass

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
    clean_tracking_ids()

    print(f"\n[2/{total_steps}] 清除遥测与 Statsig 缓存...")
    clean_telemetry()

    if include_desktop_audit:
        print("\n[3/3] 清除 Claude Desktop 本地代理审计记录...")
        clean_desktop_audit_logs()

    audit_note = "；已删除 Desktop 本地代理审计回放记录" if include_desktop_audit else ""
    print(f"\n✓ 设备关联清理完成；未修改系统 Machine ID，未删除登录、普通 Claude Code 项目对话或文件回退数据{audit_note}。")

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
        clean_device_links_only(include_desktop_audit='--desktop-audit' in sys.argv)
        if apply_privacy:
            print('\n[附加] 应用隐私加固 env...')
            result = apply_privacy_hardening()
            if result.get("status") == "partial":
                print('\n⚠ 清理已完成，但隐私加固部分完成；请查看上方警告后重试。')
                return 2
        return 0

    # 仅隐私加固（不清任何东西）
    if apply_privacy and len([a for a in sys.argv[1:] if not a.startswith('-')]) == 0 \
            and set(sys.argv[1:]).issubset({'--privacy-harden'}):
        print('=== Claude 隐私加固（写入 Code env 与本机 Desktop 托管配置，不清理数据）===\n')
        print(f'平台: {platform.system()} {platform.release()}\n')
        print('[1/1] 应用隐私加固配置...')
        result = apply_privacy_hardening()
        if result.get("status") == "partial":
            print('\n⚠ 隐私加固部分完成；请查看上方警告后重试。')
            return 2
        return 0

    print('=== Claude 一键完整清理 ===\n')
    print(f'平台: {platform.system()} {platform.release()}\n')

    include_local_desktop = platform.system() == "Windows"
    total_steps = 5 if include_local_desktop else 4

    print(f'[1/{total_steps}] 清除追踪标识...')
    clean_tracking_ids()

    print(f'\n[2/{total_steps}] 清除遥测数据...')
    clean_telemetry()

    next_step = 3
    incomplete = False
    if include_local_desktop:
        print(f'\n[{next_step}/{total_steps}] 清除本机 Desktop 残留并核验内置 CC...')
        desktop_result = clean_local_desktop_privacy()
        incomplete = desktop_result.get("status") == "partial"
        next_step += 1

    print(f'\n[{next_step}/{total_steps}] 清除 Claude Desktop 本地代理审计记录...')
    clean_desktop_audit_logs()

    print(f'\n[{next_step + 1}/{total_steps}] 清除可重建缓存...')
    clean_safe_cache()

    if apply_privacy:
        print('\n[附加] 应用隐私加固 env...')
        privacy_result = apply_privacy_hardening()
        incomplete = incomplete or privacy_result.get("status") == "partial"

    if incomplete:
        print('\n⚠ 一键完整清理部分完成；已完成的安全清理保留，未完成项目请按上方提示处理后重试。')
        return 2
    print('\n✓ 一键完整清理完成；登录凭据、账号资料、sessions、session-env、backups 与工作资产均已保留。')
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
