#!/usr/bin/env python3
"""Local-only HTTP control panel for Claude Local Clean.

The server deliberately binds to the IPv4 loopback interface and exposes no
remote-device features. Mutating requests require a per-process CSRF token.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import platform
import re
import secrets
import signal
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from claude_account_cleanup import (
    ClaudeAccountCleanupError,
    ClaudeAccountPartialCleanupError,
    collect_account_status,
    reset_all_accounts_and_login,
    retire_stale_account,
)


if platform.system() == "Windows":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

BASE_DIR = Path(__file__).resolve().parent
INDEX_PATH = BASE_DIR / "index.html"
SCRIPT_PATH = BASE_DIR / "clean_claude_tracking.py"
PID_PATH = BASE_DIR / "server.pid"
HOST = "127.0.0.1"
DEFAULT_PORT = 8190
APP_ID = "claude-local-clean"
API_VERSION = 1
INSTANCE_ID = secrets.token_urlsafe(18)
CSRF_TOKEN = secrets.token_urlsafe(32)
MACHINE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
STRUCTURED_NOTICE_ENV = "CLAUDE_LOCAL_CLEAN_STRUCTURED_NOTICES"
STRUCTURED_NOTICE_PREFIX = "@@CLAUDE_LOCAL_CLEAN_NOTICE@@"

CLEANUP_MODES = {
    "device-links": {
        "id": "device-links",
        "label": "设备关联清理",
        "description": "删除 Claude 自有的本机设备关联字段及遥测缓存，保留登录、对话和文件历史。",
        "args": ["--device-links-only"],
    },
    "device-links-audit": {
        "id": "device-links-audit",
        "label": "设备关联与审计记录",
        "description": "在设备关联清理基础上，删除 Desktop 本地代理的 audit.jsonl。",
        "args": ["--device-links-only", "--desktop-audit"],
    },
    "full": {
        "id": "full",
        "label": "完整本机清理",
        "description": "再清理可重建缓存和受支持 Desktop 残留；保留登录、会话与工作资产。",
        "args": [],
    },
    "privacy-harden": {
        "id": "privacy-harden",
        "label": "隐私加固",
        "description": "写入关闭非必要遥测、错误上报、反馈命令和自动更新的本机配置。",
        "args": ["--privacy-harden"],
    },
}

RUN_LOCK = threading.Lock()
MACHINE_ID_LOCK = threading.Lock()
RUNNING = False


def claim_mutation_slot() -> bool:
    global RUNNING
    with RUN_LOCK:
        if RUNNING:
            return False
        RUNNING = True
        return True


def release_mutation_slot() -> None:
    global RUNNING
    with RUN_LOCK:
        RUNNING = False


def cleanup_status_from_exit_code(code: int) -> str:
    if code == 0:
        return "success"
    if code == 2:
        return "partial"
    return "failed"


def parse_steps(output: str) -> list[dict[str, str]]:
    steps: list[dict[str, str]] = []
    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("✓"):
            status = "success"
        elif line.startswith("⚠"):
            status = "warning"
        elif line.startswith("✗"):
            status = "failed"
        else:
            continue
        steps.append({"status": status, "text": line.lstrip("✓⚠✗ ")})
    return steps


def parse_cleanup_output(output: str) -> tuple[str, list[dict[str, str]]]:
    """Separate validated structured notices from human-readable CLI output."""
    visible_lines: list[str] = []
    notices: list[dict[str, str]] = []
    for raw in output.splitlines(keepends=True):
        marker = raw.strip()
        if not marker.startswith(STRUCTURED_NOTICE_PREFIX):
            visible_lines.append(raw)
            continue
        try:
            value = json.loads(marker[len(STRUCTURED_NOTICE_PREFIX):])
        except json.JSONDecodeError:
            visible_lines.append(raw)
            continue
        if not isinstance(value, dict) or not isinstance(value.get("code"), str):
            visible_lines.append(raw)
            continue
        notice = {
            key: item[:1200]
            for key, item in value.items()
            if key in {
                "code",
                "version",
                "supported_version",
                "stage",
                "reason",
            }
            and isinstance(item, str)
        }
        notices.append(notice)
    return "".join(visible_lines), notices


def run_cleanup(mode: str) -> dict[str, object]:
    if mode not in CLEANUP_MODES:
        raise ValueError("未知清理模式")

    start = time.monotonic()
    command = [sys.executable, str(SCRIPT_PATH), *CLEANUP_MODES[mode]["args"]]
    child_env = os.environ.copy()
    child_env[STRUCTURED_NOTICE_ENV] = "1"
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=180,
            env=child_env,
            creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0,
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "failed",
            "duration_ms": int((time.monotonic() - start) * 1000),
            "steps": [],
            "output": "",
            "error": "清理超过 180 秒，已停止等待。",
        }
    except OSError as exc:
        return {
            "status": "failed",
            "duration_ms": int((time.monotonic() - start) * 1000),
            "steps": [],
            "output": "",
            "error": f"无法启动本机清理脚本：{exc}",
        }

    status = cleanup_status_from_exit_code(result.returncode)
    visible_output, notices = parse_cleanup_output(result.stdout)
    return {
        "status": status,
        "duration_ms": int((time.monotonic() - start) * 1000),
        "steps": parse_steps(visible_output),
        "output": visible_output,
        "notices": notices,
        "error": result.stderr.strip() or (
            "清理只完成了一部分，请查看输出并在处理阻塞项后重试。"
            if status == "partial"
            else ""
        ),
    }


def normalize_machine_id(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("Machine ID 必须是文本")
    normalized = value.strip().lower().replace("-", "")
    if not MACHINE_ID_RE.fullmatch(normalized):
        raise ValueError("Machine ID 必须是 32 个十六进制字符或标准 GUID")
    if normalized == "0" * 32:
        raise ValueError("Machine ID 不能全部为 0")
    return normalized


def format_windows_guid(machine_id: str) -> str:
    return (
        f"{machine_id[:8]}-{machine_id[8:12]}-{machine_id[12:16]}-"
        f"{machine_id[16:20]}-{machine_id[20:]}"
    )


def read_machine_id() -> str:
    if platform.system() != "Windows":
        raise RuntimeError("Machine ID 面板仅支持 Windows")
    import winreg

    access = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)
    with winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Cryptography",
        0,
        access,
    ) as key:
        value, _ = winreg.QueryValueEx(key, "MachineGuid")
    return normalize_machine_id(value)


def _is_windows_admin() -> bool:
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _run_windows_elevated(script: str, timeout: int = 180) -> None:
    encoded_script = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    launcher = rf"""$ErrorActionPreference = 'Stop'
$p = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ArgumentList @('-NoProfile','-NonInteractive','-EncodedCommand','{encoded_script}')
exit $p.ExitCode
"""
    encoded_launcher = base64.b64encode(launcher.encode("utf-16le")).decode("ascii")
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded_launcher],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    if result.returncode != 0:
        raise PermissionError("未获得管理员权限，或管理员操作执行失败")


def _write_windows_machine_id(machine_id: str) -> None:
    import winreg

    guid = format_windows_guid(machine_id)
    if _is_windows_admin():
        access = winreg.KEY_SET_VALUE | getattr(winreg, "KEY_WOW64_64KEY", 0)
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
            0,
            access,
        ) as key:
            winreg.SetValueEx(key, "MachineGuid", 0, winreg.REG_SZ, guid)
        return

    script = (
        "$ErrorActionPreference = 'Stop'\n"
        "Set-ItemProperty -LiteralPath 'HKLM:\\SOFTWARE\\Microsoft\\Cryptography' "
        f"-Name 'MachineGuid' -Value '{guid}'\n"
    )
    _run_windows_elevated(script)


def change_machine_id(value: object) -> dict[str, object]:
    machine_id = normalize_machine_id(value)
    with MACHINE_ID_LOCK:
        current = read_machine_id()
        if current == machine_id:
            raise ValueError("新 ID 与当前 ID 相同")
        _write_windows_machine_id(machine_id)
        verified = read_machine_id()
        if verified != machine_id:
            raise RuntimeError("写入后的 Machine ID 校验失败")
    return {
        "success": True,
        "machine_id": machine_id,
        "display_id": format_windows_guid(machine_id),
        "reboot_required": True,
        "message": "Machine ID 已写入，重启 Windows 后完全生效。",
    }


def request_reboot() -> dict[str, object]:
    if platform.system() != "Windows":
        raise RuntimeError("重启按钮仅支持 Windows")
    command = [
        "shutdown.exe",
        "/r",
        "/t",
        "20",
        "/d",
        "p:0:0",
        "/c",
        "Claude Local Clean requested reboot",
    ]
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=15,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    if result.returncode != 0:
        script = (
            "$ErrorActionPreference = 'Stop'\n"
            "shutdown.exe /r /t 20 /d p:0:0 /c 'Claude Local Clean requested reboot'\n"
        )
        _run_windows_elevated(script, timeout=60)
    return {"success": True, "delay_seconds": 20, "message": "已安排在 20 秒后重启。"}


class LocalHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class RequestHandler(BaseHTTPRequestHandler):
    server_version = "ClaudeLocalClean/1.0"

    def log_message(self, format: str, *args: object) -> None:
        pass

    def _host_allowed(self) -> bool:
        host = self.headers.get("Host", "").rsplit(":", 1)[0].strip("[]").lower()
        return host in {"127.0.0.1", "localhost", "::1"}

    def _send_headers(self, content_type: str, length: int, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()

    def _send_json(self, value: dict[str, object], status: int = 200) -> None:
        payload = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self._send_headers("application/json; charset=utf-8", len(payload), status)
        self.wfile.write(payload)

    def _read_body(self) -> dict[str, object]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Content-Length 无效") from exc
        if length < 0 or length > 65_536:
            raise ValueError("请求体大小无效")
        if length == 0:
            return {}
        value = json.loads(self.rfile.read(length).decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("JSON 请求体必须是对象")
        return value

    def _authorize_mutation(self) -> bool:
        if not self._host_allowed():
            self._send_json({"success": False, "error": "Host 不受信任"}, 403)
            return False
        supplied = self.headers.get("X-Cleanup-Token", "")
        if supplied and secrets.compare_digest(supplied, CSRF_TOKEN):
            return True
        self._send_json({"success": False, "error": "请求令牌无效"}, 403)
        return False

    def do_GET(self) -> None:
        if not self._host_allowed():
            self._send_json({"success": False, "error": "Host 不受信任"}, 403)
            return
        path = urlparse(self.path).path
        if path == "/":
            self._serve_index()
        elif path == "/api/config":
            with RUN_LOCK:
                running = RUNNING
            self._send_json(
                {
                    "success": True,
                    "app_id": APP_ID,
                    "api_version": API_VERSION,
                    "instance_id": INSTANCE_ID,
                    "csrf_token": CSRF_TOKEN,
                    "platform": platform.system(),
                    "cleanup_modes": list(CLEANUP_MODES.values()),
                    "running": running,
                }
            )
        elif path == "/api/claude-account/status":
            self._get_account_status()
        elif path == "/api/machine-id":
            self._get_machine_id()
        else:
            self._send_json({"success": False, "error": "Not found"}, 404)

    def do_POST(self) -> None:
        if not self._authorize_mutation():
            return
        path = urlparse(self.path).path
        if path == "/api/run":
            self._post_run()
        elif path == "/api/claude-account/retire":
            self._post_account_retire()
        elif path == "/api/claude-account/reset-all":
            self._post_account_reset_all()
        elif path == "/api/machine-id":
            self._post_machine_id()
        elif path == "/api/reboot":
            self._post_reboot()
        elif path == "/api/shutdown":
            self._post_shutdown()
        else:
            self._send_json({"success": False, "error": "Not found"}, 404)

    def _serve_index(self) -> None:
        if not INDEX_PATH.is_file():
            self._send_json({"success": False, "error": "index.html 不存在"}, 404)
            return
        payload = INDEX_PATH.read_bytes()
        self._send_headers("text/html; charset=utf-8", len(payload))
        self.wfile.write(payload)

    def _get_account_status(self) -> None:
        try:
            status = collect_account_status()
        except ClaudeAccountCleanupError as exc:
            self._send_json({"success": False, "error": str(exc)}, 409)
            return
        except Exception:
            self._send_json({"success": False, "error": "Claude 账号扫描失败"}, 500)
            return
        self._send_json({"success": True, "status": status})

    def _get_machine_id(self) -> None:
        try:
            machine_id = read_machine_id()
        except Exception as exc:
            self._send_json({"success": False, "error": str(exc)}, 500)
            return
        self._send_json(
            {
                "success": True,
                "machine_id": machine_id,
                "display_id": format_windows_guid(machine_id),
                "storage": r"HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid",
            }
        )

    def _post_run(self) -> None:
        try:
            body = self._read_body()
        except (ValueError, json.JSONDecodeError):
            self._send_json({"success": False, "error": "JSON 请求无效"}, 400)
            return
        mode = body.get("mode")
        if mode not in CLEANUP_MODES:
            self._send_json({"success": False, "error": "清理模式无效"}, 400)
            return
        if body.get("confirmation") != "RUN_LOCAL_CLEANUP":
            self._send_json({"success": False, "error": "缺少本机清理确认"}, 400)
            return
        if not claim_mutation_slot():
            self._send_json({"success": False, "error": "已有修改任务正在运行"}, 409)
            return
        cleanup_failed = False
        try:
            result = run_cleanup(str(mode))
        except Exception:
            cleanup_failed = True
        finally:
            release_mutation_slot()
        if cleanup_failed:
            self._send_json({"success": False, "error": "本机清理进程异常终止"}, 500)
            return
        self._send_json({"success": result["status"] == "success", "result": result})

    def _post_account_retire(self) -> None:
        try:
            body = self._read_body()
        except (ValueError, json.JSONDecodeError):
            self._send_json({"success": False, "error": "JSON 请求无效"}, 400)
            return
        if not claim_mutation_slot():
            self._send_json({"success": False, "error": "已有修改任务正在运行"}, 409)
            return
        try:
            result = retire_stale_account(
                str(body.get("account_uuid", "")),
                str(body.get("confirmation", "")),
            )
            status = collect_account_status()
        except ClaudeAccountPartialCleanupError as exc:
            self._send_account_partial(exc)
            return
        except ClaudeAccountCleanupError as exc:
            self._send_json({"success": False, "error": str(exc)}, 409)
            return
        except Exception:
            self._send_json({"success": False, "error": "旧账号清理失败"}, 500)
            return
        finally:
            release_mutation_slot()
        self._send_json({"success": True, "result": result, "status": status})

    def _post_account_reset_all(self) -> None:
        try:
            body = self._read_body()
        except (ValueError, json.JSONDecodeError):
            self._send_json({"success": False, "error": "JSON 请求无效"}, 400)
            return
        if not claim_mutation_slot():
            self._send_json({"success": False, "error": "已有修改任务正在运行"}, 409)
            return
        try:
            result = reset_all_accounts_and_login(
                str(body.get("confirmation", "")),
                body.get("logged_out_acknowledged") is True,
            )
            status = collect_account_status()
        except ClaudeAccountPartialCleanupError as exc:
            self._send_account_partial(exc)
            return
        except ClaudeAccountCleanupError as exc:
            self._send_json({"success": False, "error": str(exc)}, 409)
            return
        except Exception:
            self._send_json({"success": False, "error": "全部账号与登录层清理失败"}, 500)
            return
        finally:
            release_mutation_slot()
        self._send_json({"success": True, "result": result, "status": status})

    def _send_account_partial(self, exc: ClaudeAccountPartialCleanupError) -> None:
        payload: dict[str, object] = {
            "success": False,
            "partial": True,
            "error": str(exc),
            "result": exc.result,
        }
        try:
            payload["status"] = collect_account_status()
        except Exception:
            payload["status_refresh_failed"] = True
        self._send_json(payload, 409)

    def _post_machine_id(self) -> None:
        try:
            body = self._read_body()
            if body.get("confirmation") != "CHANGE_MACHINE_ID":
                raise ValueError("缺少 Machine ID 修改确认")
        except (ValueError, json.JSONDecodeError) as exc:
            self._send_json({"success": False, "error": str(exc)}, 400)
            return
        if not claim_mutation_slot():
            self._send_json({"success": False, "error": "已有修改任务正在运行"}, 409)
            return
        try:
            result = change_machine_id(body.get("machine_id"))
        except PermissionError as exc:
            self._send_json({"success": False, "error": str(exc)}, 403)
            return
        except ValueError as exc:
            self._send_json({"success": False, "error": str(exc)}, 400)
            return
        except Exception as exc:
            self._send_json({"success": False, "error": str(exc)}, 500)
            return
        finally:
            release_mutation_slot()
        self._send_json(result)

    def _post_reboot(self) -> None:
        try:
            body = self._read_body()
            if body.get("confirmation") != "REBOOT_LOCAL":
                raise ValueError("缺少本机重启确认")
        except (ValueError, json.JSONDecodeError) as exc:
            self._send_json({"success": False, "error": str(exc)}, 400)
            return
        if not claim_mutation_slot():
            self._send_json({"success": False, "error": "已有修改任务正在运行"}, 409)
            return
        try:
            result = request_reboot()
        except Exception as exc:
            self._send_json({"success": False, "error": str(exc)}, 500)
            return
        finally:
            release_mutation_slot()
        self._send_json(result)

    def _post_shutdown(self) -> None:
        try:
            body = self._read_body()
        except (ValueError, json.JSONDecodeError):
            self._send_json({"success": False, "error": "JSON 请求无效"}, 400)
            return
        if body.get("confirmation") != "STOP_LOCAL_SERVER":
            self._send_json({"success": False, "error": "缺少停止确认"}, 400)
            return
        with RUN_LOCK:
            busy = RUNNING
        if busy:
            self._send_json({"success": False, "error": "修改任务运行期间不能停止服务"}, 409)
            return
        self._send_json({"success": True})
        threading.Thread(target=self.server.shutdown, daemon=True).start()


def write_pid() -> None:
    PID_PATH.write_text(str(os.getpid()), encoding="ascii")


def remove_pid() -> None:
    try:
        if PID_PATH.is_file() and PID_PATH.read_text(encoding="ascii").strip() == str(os.getpid()):
            PID_PATH.unlink()
    except OSError:
        pass


def serve(port: int) -> None:
    server = LocalHTTPServer((HOST, port), RequestHandler)
    write_pid()
    print(f"Claude Local Clean running at http://{HOST}:{port}")
    print("Close this window or press Ctrl+C to stop.")

    def stop_server(signum: int, frame: object) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, stop_server)
    signal.signal(signal.SIGTERM, stop_server)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        remove_pid()


def main() -> int:
    parser = argparse.ArgumentParser(description="Local-only Claude cleanup console")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()
    if platform.system() != "Windows":
        parser.error("the public control panel currently supports Windows only")
    if not 1024 <= args.port <= 65535:
        parser.error("port must be between 1024 and 65535")
    serve(args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
