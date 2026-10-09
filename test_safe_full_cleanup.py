from __future__ import annotations

import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

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
