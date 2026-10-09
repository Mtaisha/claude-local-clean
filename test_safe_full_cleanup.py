from __future__ import annotations

import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import Mock, patch

import clean_claude_tracking as clean


class SafeFullCleanupTests(unittest.TestCase):
    def test_default_full_mode_preserves_login_and_work_assets(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            claude = home / ".claude"
            claude.mkdir()
            (home / ".claude.json").write_text(
                json.dumps(
                    {
                        "machineID": "remove",
                        "anonymousId": "remove",
                        "oauthAccount": {"keep": True},
                        "passesEligibilityCache": {"keep": True},
                        "theme": "keep",
                    }
                ),
                encoding="utf-8",
            )
            protected = {
                claude / ".credentials.json": b"credential",
                claude / "projects" / "p" / "dialogue.jsonl": b"dialogue\n",
                claude / "history.jsonl": b"history\n",
                claude / "file-history" / "rewind": b"rewind",
                claude / "settings.json": b'{"theme":"keep"}',
                claude / "sessions" / "state": b"session",
                claude / "session-env" / "env": b"env",
                claude / "backups" / ".claude.json.backup.1": b"backup",
                claude / "skills" / "skill.md": b"skill",
            }
            for path, content in protected.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
            for relative in (
                "telemetry/event.json",
                "statsig/state.json",
                "stats-cache.json",
                "paste-cache/paste.txt",
                "shell-snapshots/shell.txt",
                "debug/debug.txt",
            ):
                path = claude / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("remove", encoding="utf-8")
            appdata = home / "AppData" / "Roaming"
            local_appdata = home / "AppData" / "Local"
            desktop_audit = appdata / "Claude" / "local-agent-mode-sessions" / "one" / "audit.jsonl"
            desktop_audit.parent.mkdir(parents=True, exist_ok=True)
            desktop_audit.write_text("remove", encoding="utf-8")
            preserved_audit = (
                home
                / "Documents"
                / "Claude"
                / "ClaudeDesktop-session-preserve-test"
                / "package-roaming"
                / "local-agent-mode-sessions"
                / "one"
                / "audit.jsonl"
            )
            preserved_audit.parent.mkdir(parents=True, exist_ok=True)
            preserved_audit.write_text("keep", encoding="utf-8")
            desktop_root = (
                local_appdata
                / "Packages"
                / "Claude_test"
                / "LocalCache"
                / "Roaming"
                / "Claude"
            )
            desktop_residue = desktop_root / "ant-device-registry.json"
            desktop_residue.parent.mkdir(parents=True, exist_ok=True)
            desktop_residue.write_text("remove", encoding="utf-8")
            before = {path: path.read_bytes() for path in protected}

            with patch.object(clean, "get_home", return_value=home), patch.object(
                clean.sys, "argv", ["clean_claude_tracking.py"]
            ), patch(
                "local_desktop_privacy._claude_process_running", return_value=False
            ), patch.dict(
                os.environ,
                {"APPDATA": str(appdata), "LOCALAPPDATA": str(local_appdata)},
                clear=False,
            ), redirect_stdout(StringIO()) as output:
                exit_code = clean.main()

            data = json.loads((home / ".claude.json").read_text(encoding="utf-8"))
            self.assertNotIn("machineID", data)
            self.assertNotIn("anonymousId", data)
            self.assertEqual(data["oauthAccount"], {"keep": True})
            self.assertEqual(data["passesEligibilityCache"], {"keep": True})
            self.assertEqual({path: path.read_bytes() for path in protected}, before)
            for relative in ("telemetry", "statsig", "stats-cache.json", "paste-cache", "shell-snapshots", "debug"):
                self.assertFalse((claude / relative).exists(), relative)
            self.assertFalse(desktop_audit.exists())
            self.assertEqual(preserved_audit.read_text(encoding="utf-8"), "keep")
            self.assertFalse(desktop_residue.exists())
            self.assertEqual(exit_code, 0)
            self.assertIn("一键完整清理完成", output.getvalue())

    def test_desktop_skip_makes_full_cleanup_partial(self) -> None:
        with patch.object(clean.platform, "system", return_value="Windows"), patch.object(
            clean.sys, "argv", ["clean_claude_tracking.py"]
        ), patch.object(clean, "clean_tracking_ids"), patch.object(
            clean, "clean_telemetry"
        ), patch.object(
            clean, "clean_local_desktop_privacy", return_value={"status": "partial"}
        ), patch.object(clean, "clean_desktop_audit_logs"), patch.object(
            clean, "clean_safe_cache"
        ), redirect_stdout(StringIO()) as output:
            exit_code = clean.main()

        self.assertEqual(exit_code, 2)
        self.assertIn("部分完成", output.getvalue())
        self.assertNotIn("✓ 一键完整清理完成", output.getvalue())

    def test_newer_desktop_code_is_a_notice_not_a_cleanup_failure(self) -> None:
        with patch.object(clean.platform, "system", return_value="Windows"), patch(
            "local_desktop_privacy.clean_desktop_privacy_residue",
            return_value={"status": "current", "removed_count": 0, "removed_bytes": 0},
        ), patch(
            "local_desktop_privacy.harden_current_embedded_claude_code",
            return_value={
                "status": "unsupported",
                "version": "2.1.999",
                "supported_version": "2.1.281",
                "newer_than_supported": True,
            },
        ), redirect_stdout(StringIO()) as output:
            result = clean.clean_local_desktop_privacy()

        self.assertEqual(result["status"], "success")
        self.assertEqual(
            result["notices"],
            [
                {
                    "code": "embedded-cc-newer",
                    "version": "2.1.999",
                    "supported_version": "2.1.281",
                }
            ],
        )
        self.assertIn("常规清理已继续", output.getvalue())

    def test_full_cleanup_emits_newer_version_notice_for_console_server(self) -> None:
        notice = {
            "code": "embedded-cc-newer",
            "version": "2.1.999",
            "supported_version": "2.1.281",
        }
        with patch.object(clean.platform, "system", return_value="Windows"), patch.object(
            clean.sys, "argv", ["clean_claude_tracking.py"]
        ), patch.object(clean, "clean_tracking_ids"), patch.object(
            clean, "clean_telemetry"
        ), patch.object(
            clean,
            "clean_local_desktop_privacy",
            return_value={"status": "success", "notices": [notice]},
        ), patch.object(clean, "clean_desktop_audit_logs"), patch.object(
            clean, "clean_safe_cache"
        ), patch.object(
            clean, "verify_tracking_ids_clean", return_value=[]
        ), patch.object(
            clean, "verify_telemetry_clean", return_value=[]
        ), patch.object(
            clean, "verify_desktop_audit_clean", return_value=[]
        ), patch.object(
            clean, "verify_safe_cache_clean", return_value=[]
        ), patch.dict(
            os.environ, {clean.STRUCTURED_NOTICE_ENV: "1"}, clear=False
        ), redirect_stdout(StringIO()) as output:
            exit_code = clean.main()

        self.assertEqual(exit_code, 0)
        self.assertIn(clean.STRUCTURED_NOTICE_PREFIX, output.getvalue())
        self.assertIn('"code":"embedded-cc-newer"', output.getvalue())

    def test_self_check_repairs_one_residual_and_rechecks(self) -> None:
        action = Mock()
        verifier = Mock(side_effect=[["遥测缓存仍存在: statsig"], []])

        with redirect_stdout(StringIO()) as output:
            result = clean.run_self_healing_stage("遥测缓存", action, verifier)

        self.assertEqual(result["status"], "success")
        self.assertEqual(action.call_count, 2)
        self.assertEqual(verifier.call_count, 2)
        self.assertIn("自动修复成功", output.getvalue())

    def test_self_check_reports_bounded_failure_after_one_retry(self) -> None:
        action = Mock()
        verifier = Mock(return_value=["遥测缓存仍存在: statsig"])

        with patch.dict(
            os.environ, {clean.STRUCTURED_NOTICE_ENV: "1"}, clear=False
        ), redirect_stdout(StringIO()) as output:
            result = clean.run_self_healing_stage("遥测缓存", action, verifier)

        self.assertEqual(result["status"], "partial")
        self.assertEqual(action.call_count, 2)
        self.assertIn("自动修复失败", output.getvalue())
        self.assertIn('"code":"cleanup-auto-repair-failed"', output.getvalue())

    def test_self_check_does_not_retry_a_safety_refusal(self) -> None:
        action = Mock(side_effect=clean.CleanupSafetyError("路径被重定向"))

        with redirect_stdout(StringIO()) as output:
            result = clean.run_self_healing_stage("设备关联字段", action)

        self.assertEqual(result["status"], "partial")
        action.assert_called_once_with()
        self.assertIn("无法安全自动修复", output.getvalue())

    def test_privacy_hardening_overrides_only_managed_values(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            settings_path = home / ".claude" / "settings.json"
            settings_path.parent.mkdir()
            settings_path.write_text(
                json.dumps(
                    {
                        "env": {
                            "CLAUDE_CODE_ENABLE_TELEMETRY": "true",
                            "UNRELATED_VALUE": "keep",
                        },
                        "autoUpdates": True,
                        "theme": "keep",
                    }
                ),
                encoding="utf-8",
            )

            with patch.object(clean, "get_home", return_value=home), patch.object(
                clean.platform, "system", return_value="Linux"
            ), redirect_stdout(StringIO()):
                result = clean.apply_privacy_hardening()

            settings = json.loads(settings_path.read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "success")
            self.assertEqual(settings["env"]["CLAUDE_CODE_ENABLE_TELEMETRY"], "false")
            self.assertEqual(settings["env"]["UNRELATED_VALUE"], "keep")
            self.assertIs(settings["autoUpdates"], False)
            self.assertEqual(settings["theme"], "keep")

    def test_privacy_hardening_reports_partial_when_desktop_config_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.object(
            clean, "get_home", return_value=Path(temp)
        ), patch.object(clean.platform, "system", return_value="Windows"), patch(
            "local_desktop_privacy.apply_desktop_managed_privacy",
            return_value={
                "status": "unavailable",
                "changed": [],
                "reason": "managed config is absent",
            },
        ), redirect_stdout(StringIO()):
            result = clean.apply_privacy_hardening()

        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["reason"], "managed config is absent")

    def test_device_link_cleanup_does_not_rewrite_unchanged_config(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            config = home / ".claude.json"
            original = b'{"theme":"keep"}\r\n'
            config.write_bytes(original)

            with patch.object(clean, "get_home", return_value=home), redirect_stdout(StringIO()):
                clean.clean_tracking_ids()

            self.assertEqual(config.read_bytes(), original)

    def test_device_link_cleanup_refuses_non_object_config_without_rewrite(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            config = home / ".claude.json"
            original = b'["machineID"]\r\n'
            config.write_bytes(original)

            with patch.object(clean, "get_home", return_value=home), redirect_stdout(StringIO()):
                with self.assertRaises(clean.CleanupSafetyError):
                    clean.clean_tracking_ids()

            self.assertEqual(config.read_bytes(), original)

    def test_privacy_hardening_refuses_invalid_env_without_rewrite(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            settings_path = home / ".claude" / "settings.json"
            settings_path.parent.mkdir()
            original = b'{"env":"broken","theme":"keep"}\r\n'
            settings_path.write_bytes(original)

            with patch.object(clean, "get_home", return_value=home), patch.object(
                clean.platform, "system", return_value="Linux"
            ), redirect_stdout(StringIO()):
                result = clean.apply_privacy_hardening()

            self.assertEqual(result["status"], "partial")
            self.assertEqual(settings_path.read_bytes(), original)

    def test_cleanup_refuses_redirected_allowlisted_target_before_delete(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            claude = home / ".claude"
            telemetry = claude / "telemetry"
            statsig = claude / "statsig"
            telemetry.mkdir(parents=True)
            statsig.mkdir()
            (telemetry / "event.json").write_text("keep", encoding="utf-8")
            (statsig / "state.json").write_text("keep", encoding="utf-8")

            real_is_reparse = clean._is_reparse

            def redirected(path: Path) -> bool:
                return path == statsig or real_is_reparse(path)

            with patch.object(clean, "get_home", return_value=home), patch.object(
                clean, "_is_reparse", side_effect=redirected
            ):
                with self.assertRaises(clean.CleanupSafetyError):
                    clean.clean_telemetry()

            self.assertTrue((telemetry / "event.json").exists())
            self.assertTrue((statsig / "state.json").exists())

    def test_unknown_or_unbound_flags_cannot_fall_through_to_full_cleanup(self) -> None:
        for argv in (
            ["clean_claude_tracking.py", "--privacy-hardn"],
            ["clean_claude_tracking.py", "--desktop-audit"],
        ):
            with self.subTest(argv=argv), patch.object(
                clean.sys, "argv", argv
            ), patch.object(clean, "clean_tracking_ids") as tracking, patch.object(
                clean, "clean_telemetry"
            ) as telemetry, redirect_stderr(StringIO()) as error:
                exit_code = clean.main()

            self.assertEqual(exit_code, 1)
            self.assertTrue(error.getvalue().strip())
            tracking.assert_not_called()
            telemetry.assert_not_called()


if __name__ == "__main__":
    unittest.main()
