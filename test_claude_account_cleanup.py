from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import claude_account_cleanup as cleanup


CURRENT = "11111111-1111-4111-8111-111111111111"
STALE = "33333333-3333-4333-8333-333333333333"
STALE_ORG = "44444444-4444-4444-8444-444444444444"
OTHER = "55555555-5555-4555-8555-555555555555"


class ClaudeAccountCleanupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.__enter__())
        self.paths = cleanup.ClaudeAccountPaths(
            msix_root=root / "msix" / "Claude_pzs8sxrjxfjjc" / "LocalCache" / "Roaming" / "Claude",
            home_root=root / "home" / ".claude",
            legacy_root=root / "legacy" / "Claude",
            primary_anchor=root / "cat" / "claude_primary_account.json",
        )
        self.paths.msix_root.mkdir(parents=True)
        self.paths.home_root.mkdir(parents=True)

    def tearDown(self) -> None:
        self.temp.__exit__(None, None, None)

    def write_json(self, path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")

    def seed(self) -> None:
        self.write_json(
            self.paths.config_path,
            {
                "lastKnownAccountUuid": CURRENT,
                "theme": "keep",
                f"dxt:allowlistEnabled:{STALE_ORG}": True,
                f"dxt:allowlistCache:{OTHER}": {"keep": True},
                "oauth:tokenCache": "protected-current-login",
            },
        )
        self.write_json(
            self.paths.desktop_config_path,
            {
                "mcpServers": {"keep": {"command": "x"}},
                "preferences": {
                    "bypassPermissionsOptInByAccount": {STALE: True, CURRENT: False},
                    "bypassPermissionsGateByAccount": {STALE: True},
                    "coworkModelAutoFallbackByAccount": {STALE: False},
                    "theme": "keep",
                },
            },
        )
        self.write_json(self.paths.cowork_ops_path, {"ownerAccountId": STALE, "keep": True})
        self.write_json(
            self.paths.primary_anchor,
            {"account_uuid": STALE, "organization_uuid": STALE_ORG, "bound_at": "old"},
        )
        stale_code = self.paths.code_sessions_root / STALE / STALE_ORG
        stale_agent = self.paths.agent_sessions_root / STALE / STALE_ORG
        stale_code.mkdir(parents=True)
        stale_agent.mkdir(parents=True)
        self.write_json(stale_code / "local_one.json", {"sessionId": "one", "cliSessionId": "missing"})
        (stale_agent / "audit.jsonl").write_text("private", encoding="utf-8")
        (self.paths.code_sessions_root / CURRENT / OTHER).mkdir(parents=True)
        (self.paths.agent_sessions_root / "unknown-state").mkdir(parents=True)

        protected = {
            self.paths.home_root / ".credentials.json": b"credential-keep",
            self.paths.home_root / "projects" / "p" / "dialogue.jsonl": b"dialogue-keep\n",
            self.paths.home_root / "settings.json": b'{"keep":true}',
            self.paths.home_root / "file-history" / "history.jsonl": b"file-history-keep\n",
            self.paths.home_root / "sessions" / "state": b"session-keep",
            self.paths.home_root / "session-env" / "env": b"env-keep",
            self.paths.home_root / "backups" / "backup": b"backup-keep",
            self.paths.msix_root / "Local Storage" / "login.ldb": b"login-keep",
            self.paths.msix_root / "ant-did": b"device-state-keep",
        }
        for path, content in protected.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        self.protected = protected

    def identity_snapshot(self) -> dict[Path, bytes | None]:
        paths = (
            self.paths.config_path,
            self.paths.desktop_config_path,
            self.paths.cowork_ops_path,
            self.paths.home_config_path,
            self.paths.primary_anchor,
        )
        return {path: path.read_bytes() if path.exists() else None for path in paths}

    def reset_all(self, **kwargs: object) -> dict:
        kwargs.setdefault("process_checker", lambda: [])
        kwargs.setdefault("credential_target_provider", lambda: [])
        return cleanup.reset_all_accounts_and_login(
            "RESET_ALL_CLAUDE_ACCOUNTS",
            True,
            self.paths,
            **kwargs,
        )

    def seed_reset_state(self) -> None:
        self.seed()
        self.write_json(
            self.paths.home_config_path,
            {
                "oauthAccount": {"accountUuid": CURRENT, "organizationUuid": OTHER},
                "passesEligibilityCache": {"keep": False},
                "theme": "keep",
            },
        )

    def retire(self, account: str = STALE) -> dict:
        return cleanup.retire_stale_account(
            account,
            f"RETIRE_ACCOUNT:{account}",
            self.paths,
            process_checker=lambda: [],
        )

    def test_scan_is_read_only_and_lists_protected_and_manual_items(self) -> None:
        self.seed()
        before = {path: path.read_bytes() for path in self.protected}
        config_before = self.paths.config_path.read_bytes()

        status = cleanup.collect_account_status(self.paths, process_checker=lambda: [])

        accounts = {item["uuid"]: item for item in status["detected_accounts"]}
        self.assertFalse(accounts[CURRENT]["retireable"])
        self.assertTrue(accounts[STALE]["retireable"])
        self.assertTrue(any("Local Storage" in path for path in status["protected_login"]["paths"]))
        self.assertTrue(any(item["kind"] == "device-state" for item in status["manual_review"]))
        self.assertTrue(any(item["kind"] == "unknown-session-state" for item in status["manual_review"]))
        self.assertEqual(self.paths.config_path.read_bytes(), config_before)
        self.assertEqual({path: path.read_bytes() for path in self.protected}, before)

    def test_current_account_is_always_refused(self) -> None:
        self.seed()
        with self.assertRaisesRegex(cleanup.ClaudeAccountCleanupError, "当前账号"):
            self.retire(CURRENT)

    def test_cli_oauth_account_is_also_current_and_protected(self) -> None:
        self.seed()
        self.write_json(self.paths.home_config_path, {"oauthAccount": {"accountUuid": OTHER}})
        (self.paths.agent_sessions_root / OTHER).mkdir(parents=True)

        status = cleanup.collect_account_status(self.paths, process_checker=lambda: [])
        self.assertEqual(set(status["current_account_uuids"]), {CURRENT, OTHER})
        accounts = {item["uuid"]: item for item in status["detected_accounts"]}
        self.assertFalse(accounts[OTHER]["retireable"])
        with self.assertRaisesRegex(cleanup.ClaudeAccountCleanupError, "当前账号"):
            self.retire(OTHER)

    def test_retire_requires_exact_confirmation_and_detected_uuid(self) -> None:
        self.seed()
        with self.assertRaisesRegex(cleanup.ClaudeAccountCleanupError, "废弃确认"):
            cleanup.retire_stale_account(STALE, "RETIRE_ACCOUNT:wrong", self.paths, process_checker=lambda: [])
        with self.assertRaisesRegex(cleanup.ClaudeAccountCleanupError, "不在本次扫描"):
            self.retire(OTHER)

    def test_exact_retire_mutates_only_target_identity(self) -> None:
        self.seed()
        before = {path: path.read_bytes() for path in self.protected}

        result = self.retire()

        self.assertEqual(result["directories_removed"], 2)
        self.assertFalse((self.paths.code_sessions_root / STALE).exists())
        self.assertFalse((self.paths.agent_sessions_root / STALE).exists())
        self.assertTrue((self.paths.code_sessions_root / CURRENT).exists())
        config = json.loads(self.paths.config_path.read_text(encoding="utf-8"))
        self.assertEqual(config["lastKnownAccountUuid"], CURRENT)
        self.assertEqual(config["theme"], "keep")
        self.assertEqual(config["oauth:tokenCache"], "protected-current-login")
        self.assertNotIn(f"dxt:allowlistEnabled:{STALE_ORG}", config)
        self.assertIn(f"dxt:allowlistCache:{OTHER}", config)
        desktop = json.loads(self.paths.desktop_config_path.read_text(encoding="utf-8"))
        prefs = desktop["preferences"]
        self.assertNotIn(STALE, prefs["bypassPermissionsOptInByAccount"])
        self.assertIn(CURRENT, prefs["bypassPermissionsOptInByAccount"])
        self.assertEqual(desktop["mcpServers"], {"keep": {"command": "x"}})
        self.assertEqual(json.loads(self.paths.cowork_ops_path.read_text(encoding="utf-8")), {"keep": True})
        self.assertEqual(
            json.loads(self.paths.primary_anchor.read_text(encoding="utf-8")),
            {"bound_at": "old"},
        )
        self.assertEqual({path: path.read_bytes() for path in self.protected}, before)

    def test_malformed_json_fails_before_any_deletion(self) -> None:
        self.seed()
        self.paths.desktop_config_path.write_text("{broken", encoding="utf-8")
        stale_dir = self.paths.code_sessions_root / STALE

        with self.assertRaisesRegex(cleanup.ClaudeAccountCleanupError, "未执行任何清理"):
            self.retire()

        self.assertTrue(stale_dir.exists())
        self.assertIn(STALE, self.paths.primary_anchor.read_text(encoding="utf-8"))

    def test_running_process_refuses_before_read_or_delete(self) -> None:
        self.seed()
        with self.assertRaisesRegex(cleanup.ClaudeAccountCleanupError, "完全退出"):
            cleanup.retire_stale_account(
                STALE,
                f"RETIRE_ACCOUNT:{STALE}",
                self.paths,
                process_checker=lambda: [{"Name": "Claude.exe", "ProcessId": 1}],
            )
        self.assertTrue((self.paths.code_sessions_root / STALE).exists())

    def test_retire_directory_failure_is_partial_and_retryable(self) -> None:
        self.seed()
        identity_before = self.identity_snapshot()
        failing_path = self.paths.agent_sessions_root / STALE
        original_rmtree = cleanup.shutil.rmtree

        def fail_for_agent_directory(path: str | Path, *args: object, **kwargs: object) -> None:
            if Path(path) == failing_path:
                raise OSError("injected stale-account directory failure")
            original_rmtree(path, *args, **kwargs)

        with patch.object(cleanup.shutil, "rmtree", side_effect=fail_for_agent_directory):
            with self.assertRaises(cleanup.ClaudeAccountPartialCleanupError) as raised:
                self.retire()

        self.assertEqual(raised.exception.result.get("status"), "partial")
        self.assertEqual(self.identity_snapshot(), identity_before)
        self.assertTrue(failing_path.exists())

        result = self.retire()
        self.assertEqual(result.get("status"), "completed")
        self.assertFalse(failing_path.exists())

    def test_symlink_account_directory_is_refused_when_supported(self) -> None:
        self.seed()
        target = self.paths.agent_sessions_root / STALE
        for child in sorted(target.rglob("*"), reverse=True):
            if child.is_file():
                child.unlink()
            else:
                child.rmdir()
        target.rmdir()
        outside = self.paths.msix_root.parent / "outside"
        outside.mkdir()
        try:
            target.symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest("symlink creation is unavailable")

        with self.assertRaisesRegex(cleanup.ClaudeAccountCleanupError, "链接|重解析"):
            self.retire()
        self.assertTrue(outside.exists())

    def test_nested_or_traversal_account_path_is_not_a_direct_child(self) -> None:
        nested = self.paths.code_sessions_root / "nested" / STALE
        nested.mkdir(parents=True)
        with self.assertRaisesRegex(cleanup.ClaudeAccountCleanupError, "固定根目录"):
            cleanup._require_direct_child(self.paths.code_sessions_root, nested)

    def test_reset_all_removes_account_org_and_login_but_preserves_work(self) -> None:
        self.seed()
        self.write_json(
            self.paths.home_config_path,
            {
                "oauthAccount": {"accountUuid": CURRENT, "organizationUuid": OTHER},
                "passesEligibilityCache": {"keep": False},
                "theme": "keep",
            },
        )
        legacy_network = self.paths.legacy_root / "Network" / "Cookies"
        legacy_network.parent.mkdir(parents=True, exist_ok=True)
        legacy_network.write_bytes(b"legacy-login")
        work_paths = {
            path: path.read_bytes()
            for path in self.protected
            if ".credentials.json" not in str(path) and "Local Storage" not in str(path)
        }

        result = cleanup.reset_all_accounts_and_login(
            "RESET_ALL_CLAUDE_ACCOUNTS",
            True,
            self.paths,
            process_checker=lambda: [],
        )

        self.assertEqual(result["directories_removed"], 3)
        self.assertFalse((self.paths.code_sessions_root / STALE).exists())
        self.assertFalse((self.paths.agent_sessions_root / STALE).exists())
        self.assertFalse((self.paths.code_sessions_root / CURRENT).exists())
        self.assertTrue((self.paths.agent_sessions_root / "unknown-state").exists())
        config = json.loads(self.paths.config_path.read_text(encoding="utf-8"))
        self.assertEqual(config, {"theme": "keep"})
        desktop = json.loads(self.paths.desktop_config_path.read_text(encoding="utf-8"))
        self.assertEqual(desktop["mcpServers"], {"keep": {"command": "x"}})
        self.assertEqual(desktop["preferences"]["theme"], "keep")
        self.assertTrue(all(not value for key, value in desktop["preferences"].items() if key in cleanup.ACCOUNT_MAP_KEYS))
        self.assertEqual(json.loads(self.paths.cowork_ops_path.read_text(encoding="utf-8")), {"keep": True})
        self.assertEqual(
            json.loads(self.paths.primary_anchor.read_text(encoding="utf-8")),
            {"bound_at": "old"},
        )
        self.assertEqual(json.loads(self.paths.home_config_path.read_text(encoding="utf-8")), {"theme": "keep"})
        self.assertFalse((self.paths.home_root / ".credentials.json").exists())
        self.assertFalse((self.paths.msix_root / "Local Storage").exists())
        self.assertFalse((self.paths.legacy_root / "Network").exists())
        self.assertEqual({path: path.read_bytes() for path in work_paths}, work_paths)
        self.assertGreaterEqual(result["organization_links_removed"], 3)
        self.assertGreaterEqual(result["login_metadata_removed"], 3)

    def test_reset_all_requires_logged_out_confirmation_and_closed_processes(self) -> None:
        self.seed()
        stale_dir = self.paths.code_sessions_root / STALE
        with self.assertRaisesRegex(cleanup.ClaudeAccountCleanupError, "精确确认"):
            cleanup.reset_all_accounts_and_login("wrong", True, self.paths, process_checker=lambda: [])
        with self.assertRaisesRegex(cleanup.ClaudeAccountCleanupError, "退出全部"):
            cleanup.reset_all_accounts_and_login(
                "RESET_ALL_CLAUDE_ACCOUNTS", False, self.paths, process_checker=lambda: []
            )
        with self.assertRaisesRegex(cleanup.ClaudeAccountCleanupError, "完全退出"):
            cleanup.reset_all_accounts_and_login(
                "RESET_ALL_CLAUDE_ACCOUNTS",
                True,
                self.paths,
                process_checker=lambda: [{"Name": "Claude.exe", "ProcessId": 1}],
            )
        self.assertTrue(stale_dir.exists())

    def test_reset_all_directory_failure_is_partial_and_retry_is_idempotent(self) -> None:
        self.seed_reset_state()
        identity_before = self.identity_snapshot()
        failing_path = self.paths.agent_sessions_root / STALE
        original_rmtree = cleanup.shutil.rmtree

        def fail_for_one_directory(path: str | Path, *args: object, **kwargs: object) -> None:
            if Path(path) == failing_path:
                raise OSError("injected account-directory deletion failure")
            original_rmtree(path, *args, **kwargs)

        with patch.object(cleanup.shutil, "rmtree", side_effect=fail_for_one_directory):
            with self.assertRaises(cleanup.ClaudeAccountPartialCleanupError) as raised:
                self.reset_all()

        self.assertEqual(raised.exception.result.get("status"), "partial")
        self.assertEqual(self.identity_snapshot(), identity_before)
        self.assertTrue(failing_path.exists())

        result = self.reset_all()

        self.assertEqual(result.get("status"), "completed")
        self.assertFalse(failing_path.exists())

    def test_reset_all_login_storage_failure_is_partial_and_retry_is_idempotent(self) -> None:
        self.seed_reset_state()
        identity_before = self.identity_snapshot()
        failing_path = self.paths.msix_root / "Local Storage"
        original_rmtree = cleanup.shutil.rmtree

        def fail_for_one_login_path(path: str | Path, *args: object, **kwargs: object) -> None:
            if Path(path) == failing_path:
                raise OSError("injected login-storage deletion failure")
            original_rmtree(path, *args, **kwargs)

        with patch.object(cleanup.shutil, "rmtree", side_effect=fail_for_one_login_path):
            with self.assertRaises(cleanup.ClaudeAccountPartialCleanupError) as raised:
                self.reset_all()

        self.assertEqual(raised.exception.result.get("status"), "partial")
        self.assertEqual(self.identity_snapshot(), identity_before)
        self.assertTrue(failing_path.exists())

        result = self.reset_all()

        self.assertEqual(result.get("status"), "completed")
        self.assertFalse(failing_path.exists())

    def test_reset_all_removes_msix_package_login_state_but_preserves_work_assets(self) -> None:
        self.seed_reset_state()
        package_state = {
            "LocalState": b"local-state",
            "RoamingState": b"roaming-state",
            "Settings": b"settings-state",
            "SystemAppData": b"system-app-data",
        }
        for name, content in package_state.items():
            path = self.paths.package_root / name
            path.mkdir(parents=True)
            (path / "state.bin").write_bytes(content)

        work_paths = {
            self.paths.home_root / "projects" / "p" / "dialogue.jsonl",
            self.paths.home_root / "settings.json",
            self.paths.home_root / "file-history" / "history.jsonl",
            self.paths.home_root / "sessions" / "state",
        }
        work_before = {path: path.read_bytes() for path in work_paths}

        result = self.reset_all()

        self.assertEqual(result.get("status"), "completed")
        for name in package_state:
            self.assertFalse((self.paths.package_root / name).exists())
        self.assertEqual({path: path.read_bytes() for path in work_paths}, work_before)

    def test_reset_all_credential_injection_deletes_only_provider_claude_targets(self) -> None:
        self.seed_reset_state()
        provider_targets = [
            "LegacyGeneric:target=Anthropic API",
            "LegacyGeneric:target=Claude Code",
            "LegacyGeneric:target=my-claude-notes",
            "LegacyGeneric:target=anthropic-unrelated",
            "LegacyGeneric:target=Microsoft Account",
            "LegacyGeneric:target=github.com",
        ]
        remaining = list(provider_targets)
        provider_calls: list[bool] = []
        deleted: list[str] = []

        def provider() -> list[str]:
            provider_calls.append(True)
            return list(remaining)

        def deleter(target: str) -> None:
            deleted.append(target)
            remaining.remove(target)

        result = self.reset_all(
            credential_target_provider=provider,
            credential_target_deleter=deleter,
        )

        self.assertTrue(provider_calls)
        self.assertEqual(
            deleted,
            ["LegacyGeneric:target=Anthropic API", "LegacyGeneric:target=Claude Code"],
        )
        self.assertNotIn("LegacyGeneric:target=Microsoft Account", deleted)
        self.assertNotIn("LegacyGeneric:target=github.com", deleted)
        self.assertNotIn("LegacyGeneric:target=my-claude-notes", deleted)
        self.assertNotIn("LegacyGeneric:target=anthropic-unrelated", deleted)
        self.assertEqual(result.get("status"), "completed")

    def test_reset_all_credential_deleter_failure_is_partial_and_retryable(self) -> None:
        self.seed_reset_state()
        identity_before = self.identity_snapshot()
        anthropic_target = "LegacyGeneric:target=Anthropic API"
        claude_target = "LegacyGeneric:target=Claude Code"
        unrelated_target = "LegacyGeneric:target=Microsoft Account"
        remaining = [anthropic_target, claude_target, unrelated_target]
        deleted: list[str] = []
        fail_once = True

        def provider() -> list[str]:
            return list(remaining)

        def deleter(target: str) -> None:
            nonlocal fail_once
            deleted.append(target)
            if target == claude_target and fail_once:
                fail_once = False
                raise OSError("injected Windows Credential Manager deletion failure")
            remaining.remove(target)

        with self.assertRaises(cleanup.ClaudeAccountPartialCleanupError) as raised:
            self.reset_all(
                credential_target_provider=provider,
                credential_target_deleter=deleter,
            )

        self.assertEqual(raised.exception.result.get("status"), "partial")
        self.assertEqual(self.identity_snapshot(), identity_before)
        self.assertEqual(deleted, [anthropic_target, claude_target])
        self.assertNotIn(unrelated_target, deleted)

        retry_deleted: list[str] = []

        def retry_deleter(target: str) -> None:
            retry_deleted.append(target)
            remaining.remove(target)

        result = self.reset_all(
            credential_target_provider=provider,
            credential_target_deleter=retry_deleter,
        )

        self.assertEqual(result.get("status"), "completed")
        self.assertEqual(retry_deleted, [claude_target])
        self.assertEqual(remaining, [unrelated_target])

    def test_reset_all_residual_postcondition_cannot_report_completed(self) -> None:
        self.seed_reset_state()
        identity_before = self.identity_snapshot()
        residual_path = self.paths.msix_root / "Local Storage"
        original_rmtree = cleanup.shutil.rmtree

        def leave_one_login_path(path: str | Path, *args: object, **kwargs: object) -> None:
            if Path(path) == residual_path:
                return
            original_rmtree(path, *args, **kwargs)

        with patch.object(cleanup.shutil, "rmtree", side_effect=leave_one_login_path):
            with self.assertRaises(cleanup.ClaudeAccountPartialCleanupError) as raised:
                self.reset_all()

        self.assertEqual(raised.exception.result.get("status"), "partial")
        self.assertNotEqual(raised.exception.result.get("status"), "completed")
        self.assertEqual(self.identity_snapshot(), identity_before)
        self.assertTrue(residual_path.exists())

        result = self.reset_all()

        self.assertEqual(result.get("status"), "completed")
        self.assertFalse(residual_path.exists())

    def test_reset_all_json_commit_failure_rolls_back_and_retry_completes(self) -> None:
        self.seed_reset_state()
        identity_before = self.identity_snapshot()
        original_write = cleanup._write_json_atomic
        calls = 0

        def fail_second_write(path: Path, value: dict) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected JSON commit failure")
            original_write(path, value)

        with patch.object(cleanup, "_write_json_atomic", side_effect=fail_second_write):
            with self.assertRaises(cleanup.ClaudeAccountPartialCleanupError) as raised:
                self.reset_all()

        self.assertEqual(raised.exception.result.get("failed_phase"), "json-commit")
        self.assertEqual(self.identity_snapshot(), identity_before)

        result = self.reset_all()
        self.assertEqual(result.get("status"), "completed")
        self.assertFalse(any(result["residuals"].values()))


if __name__ == "__main__":
    unittest.main()
