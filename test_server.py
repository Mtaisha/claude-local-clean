from __future__ import annotations

import json
import os
import subprocess
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import server


class MachineIdTests(unittest.TestCase):
    def test_normalize_machine_id_accepts_guid(self) -> None:
        value = server.normalize_machine_id("00112233-4455-6677-8899-AABBCCDDEEFF")
        self.assertEqual(value, "00112233445566778899aabbccddeeff")

    def test_normalize_machine_id_rejects_zero(self) -> None:
        with self.assertRaisesRegex(ValueError, "不能全部为 0"):
            server.normalize_machine_id("0" * 32)

    def test_cleanup_exit_status(self) -> None:
        self.assertEqual(server.cleanup_status_from_exit_code(0), "success")
        self.assertEqual(server.cleanup_status_from_exit_code(2), "partial")
        self.assertEqual(server.cleanup_status_from_exit_code(1), "failed")

    def test_structured_cleanup_notice_is_removed_from_visible_output(self) -> None:
        marker = server.STRUCTURED_NOTICE_PREFIX + json.dumps(
            {
                "code": "embedded-cc-newer",
                "version": "2.1.999",
                "supported_version": "2.1.281",
                "ignored": {"not": "a string"},
            }
        )
        visible, notices = server.parse_cleanup_output(
            f"✓ 常规清理完成\n{marker}\n⚠ 深度处理已跳过\n"
        )

        self.assertEqual(visible, "✓ 常规清理完成\n⚠ 深度处理已跳过\n")
        self.assertEqual(
            notices,
            [
                {
                    "code": "embedded-cc-newer",
                    "version": "2.1.999",
                    "supported_version": "2.1.281",
                }
            ],
        )


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.httpd = server.LocalHTTPServer((server.HOST, 0), server.RequestHandler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=5)

    def setUp(self) -> None:
        server.release_mutation_slot()

    def request(self, path: str, *, body: dict | None = None, token: bool = True):
        headers = {}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
            if token:
                headers["X-Cleanup-Token"] = server.CSRF_TOKEN
        request = Request(
            f"http://{server.HOST}:{self.port}{path}",
            data=data,
            headers=headers,
            method="POST" if body is not None else "GET",
        )
        with urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read().decode("utf-8"))

    def request_error(self, path: str, *, body: dict, token: bool = True):
        with self.assertRaises(HTTPError) as raised:
            self.request(path, body=body, token=token)
        payload = json.loads(raised.exception.read().decode("utf-8"))
        return raised.exception.code, payload

    def test_config_exposes_only_local_modes(self) -> None:
        status, body = self.request("/api/config")
        self.assertEqual(status, 200)
        self.assertEqual(body["app_id"], "claude-local-clean")
        self.assertEqual(body["api_version"], 1)
        self.assertTrue(body["instance_id"])
        self.assertEqual(
            {item["id"] for item in body["cleanup_modes"]},
            {"device-links", "device-links-audit", "full", "privacy-harden"},
        )
        self.assertNotIn("targets", body)
        for mode in body["cleanup_modes"]:
            self.assertNotIn("supported_targets", mode)

    def test_mutation_requires_token(self) -> None:
        with self.assertRaises(HTTPError) as raised:
            self.request(
                "/api/run",
                body={"mode": "device-links", "confirmation": "RUN_LOCAL_CLEANUP"},
                token=False,
            )
        self.assertEqual(raised.exception.code, 403)

    @patch("server.run_cleanup")
    def test_local_cleanup_contract(self, run_cleanup) -> None:
        run_cleanup.return_value = {
            "status": "success",
            "duration_ms": 1,
            "steps": [],
            "output": "ok",
            "error": "",
        }
        status, body = self.request(
            "/api/run",
            body={"mode": "privacy-harden", "confirmation": "RUN_LOCAL_CLEANUP"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(body["success"])
        run_cleanup.assert_called_once_with("privacy-harden")

    @patch("server.read_machine_id", return_value="00112233445566778899aabbccddeeff")
    def test_machine_id_response(self, _read_machine_id) -> None:
        status, body = self.request("/api/machine-id")
        self.assertEqual(status, 200)
        self.assertEqual(body["display_id"], "00112233-4455-6677-8899-aabbccddeeff")

    @patch("server.collect_account_status", return_value={"detected_accounts": []})
    @patch("server.retire_stale_account")
    def test_account_partial_response_includes_result_and_refreshed_status(
        self, retire_stale_account, _collect_account_status
    ) -> None:
        partial = server.ClaudeAccountPartialCleanupError(
            "旧账号目录只完成了部分清理，可以安全重试。",
            {
                "status": "partial",
                "failed_phase": "account-directories",
                "failure": "injected failure",
                "residuals": {"directories": 1},
            },
        )
        retire_stale_account.side_effect = partial

        status, body = self.request_error(
            "/api/claude-account/retire",
            body={"account_uuid": "11111111-2222-4333-8444-555555555555", "confirmation": "x"},
        )

        self.assertEqual(status, 409)
        self.assertTrue(body["partial"])
        self.assertEqual(body["result"]["failed_phase"], "account-directories")
        self.assertEqual(body["result"]["residuals"], {"directories": 1})
        self.assertEqual(body["status"], {"detected_accounts": []})

    @patch("server.collect_account_status", return_value={"detected_accounts": []})
    @patch("server.reset_all_accounts_and_login")
    def test_account_reset_success_contract(
        self, reset_all_accounts_and_login, _collect_account_status
    ) -> None:
        reset_all_accounts_and_login.return_value = {"status": "completed"}

        status, body = self.request(
            "/api/claude-account/reset-all",
            body={
                "confirmation": "RESET_ALL_CLAUDE_ACCOUNTS",
                "logged_out_acknowledged": True,
            },
        )

        self.assertEqual(status, 200)
        self.assertTrue(body["success"])
        reset_all_accounts_and_login.assert_called_once_with(
            "RESET_ALL_CLAUDE_ACCOUNTS", True
        )

    @patch("server.collect_account_status", return_value={"detected_accounts": []})
    @patch("server.retire_stale_account")
    def test_account_operation_holds_shared_mutation_slot(
        self, retire_stale_account, _collect_account_status
    ) -> None:
        observed_running: list[bool] = []

        def retire(_uuid: str, _confirmation: str) -> dict:
            observed_running.append(server.RUNNING)
            return {"status": "completed"}

        retire_stale_account.side_effect = retire
        status, _body = self.request(
            "/api/claude-account/retire",
            body={"account_uuid": "11111111-2222-4333-8444-555555555555", "confirmation": "x"},
        )

        self.assertEqual(status, 200)
        self.assertEqual(observed_running, [True])
        self.assertFalse(server.RUNNING)

    @patch("server.retire_stale_account")
    def test_account_operation_rejects_while_another_mutation_runs(
        self, retire_stale_account
    ) -> None:
        self.assertTrue(server.claim_mutation_slot())
        try:
            status, body = self.request_error(
                "/api/claude-account/retire",
                body={"account_uuid": "11111111-2222-4333-8444-555555555555", "confirmation": "x"},
            )
        finally:
            server.release_mutation_slot()

        self.assertEqual(status, 409)
        self.assertIn("修改任务", body["error"])
        retire_stale_account.assert_not_called()

    @patch("server.change_machine_id")
    def test_machine_id_write_requires_confirmation(self, change_machine_id) -> None:
        status, body = self.request_error(
            "/api/machine-id",
            body={"machine_id": "00112233445566778899aabbccddeeff", "confirmation": "wrong"},
        )
        self.assertEqual(status, 400)
        self.assertIn("确认", body["error"])
        change_machine_id.assert_not_called()

    @patch("server.change_machine_id")
    def test_machine_id_write_rejects_while_another_mutation_runs(
        self, change_machine_id
    ) -> None:
        self.assertTrue(server.claim_mutation_slot())
        try:
            status, body = self.request_error(
                "/api/machine-id",
                body={
                    "machine_id": "00112233445566778899aabbccddeeff",
                    "confirmation": "CHANGE_MACHINE_ID",
                },
            )
        finally:
            server.release_mutation_slot()

        self.assertEqual(status, 409)
        self.assertIn("修改任务", body["error"])
        change_machine_id.assert_not_called()

    @patch("server.request_reboot")
    def test_reboot_requires_confirmation(self, request_reboot) -> None:
        status, body = self.request_error(
            "/api/reboot", body={"confirmation": "wrong"}
        )
        self.assertEqual(status, 400)
        self.assertIn("确认", body["error"])
        request_reboot.assert_not_called()

    def test_shutdown_rejects_while_mutation_runs(self) -> None:
        self.assertTrue(server.claim_mutation_slot())
        try:
            status, body = self.request_error(
                "/api/shutdown", body={"confirmation": "STOP_LOCAL_SERVER"}
            )
        finally:
            server.release_mutation_slot()

        self.assertEqual(status, 409)
        self.assertIn("不能停止", body["error"])

    @patch("server.run_cleanup", side_effect=RuntimeError("injected"))
    def test_cleanup_internal_failure_returns_json_and_releases_busy_state(
        self, _run_cleanup
    ) -> None:
        status, body = self.request_error(
            "/api/run",
            body={"mode": "device-links", "confirmation": "RUN_LOCAL_CLEANUP"},
        )
        self.assertEqual(status, 500)
        self.assertFalse(server.RUNNING)
        self.assertIn("异常终止", body["error"])


class WrongServiceHandler(BaseHTTPRequestHandler):
    post_count = 0

    def log_message(self, format: str, *args: object) -> None:
        pass

    def do_GET(self) -> None:
        payload = json.dumps({"success": True, "csrf_token": "foreign-token"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self) -> None:
        type(self).post_count += 1
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()


@unittest.skipUnless(os.name == "nt", "PowerShell launcher tests require Windows")
class LauncherIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        WrongServiceHandler.post_count = 0
        self.httpd = ThreadingHTTPServer((server.HOST, 0), WrongServiceHandler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.root = Path(__file__).resolve().parent

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)

    def run_script(self, name: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(self.root / name),
                "-Port",
                str(self.port),
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
        )

    def test_launcher_rejects_foreign_service_on_same_port(self) -> None:
        result = self.run_script("start_console.ps1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already used", result.stdout + result.stderr)

    def test_stopper_rejects_foreign_service_without_posting(self) -> None:
        result = self.run_script("stop_console.ps1")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(WrongServiceHandler.post_count, 0)


if __name__ == "__main__":
    unittest.main()
