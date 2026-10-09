from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import local_desktop_privacy as privacy


class LocalDesktopPrivacyTests(unittest.TestCase):
    def test_residue_cleanup_is_allowlisted(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            appdata = root / "Roaming"
            local_appdata = root / "Local"
            roots = [
                appdata / "Claude",
                local_appdata
                / "Packages"
                / "Claude_test"
                / "LocalCache"
                / "Roaming"
                / "Claude",
            ]
            for desktop_root in roots:
                for name in privacy.DESKTOP_RESIDUE_NAMES:
                    target = desktop_root / name
                    if "." in name:
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_text("remove", encoding="utf-8")
                    else:
                        target.mkdir(parents=True, exist_ok=True)
                        (target / "entry").write_text("remove", encoding="utf-8")
                (desktop_root / "config.json").write_text("keep", encoding="utf-8")

            library = local_appdata / "Claude-3p" / "configLibrary"
            library.mkdir(parents=True)
            (library / "_meta.json.bak").write_text("remove", encoding="utf-8")
            (library / "_meta.json").write_text("keep", encoding="utf-8")

            result = privacy.clean_desktop_privacy_residue(
                appdata=appdata, local_appdata=local_appdata
            )

            self.assertEqual(result["status"], "updated")
            self.assertEqual(result["removed_count"], len(roots) * 6 + 1)
            for desktop_root in roots:
                for name in privacy.DESKTOP_RESIDUE_NAMES:
                    self.assertFalse((desktop_root / name).exists(), name)
                self.assertEqual((desktop_root / "config.json").read_text(), "keep")
            self.assertFalse((library / "_meta.json.bak").exists())
            self.assertEqual((library / "_meta.json").read_text(), "keep")

    def test_residue_cleanup_refuses_reparse_before_any_delete(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            appdata = root / "Roaming"
            local_appdata = root / "Local"
            desktop_root = appdata / "Claude"
            ant_did = desktop_root / "ant-did"
            sentry = desktop_root / "sentry"
            ant_did.mkdir(parents=True)
            sentry.mkdir()
            (ant_did / "keep").write_text("keep", encoding="utf-8")
            (sentry / "keep").write_text("keep", encoding="utf-8")

            real_is_reparse = privacy._is_reparse

            def redirected(path: Path) -> bool:
                return path == sentry or real_is_reparse(path)

            with patch.object(privacy, "_is_reparse", side_effect=redirected):
                with self.assertRaises(privacy.DesktopPrivacyError):
                    privacy.clean_desktop_privacy_residue(
                        appdata=appdata, local_appdata=local_appdata
                    )

            self.assertTrue((ant_did / "keep").exists())
            self.assertTrue((sentry / "keep").exists())

    def test_managed_privacy_merge_preserves_other_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            local_appdata = Path(temp)
            library = local_appdata / "Claude-3p" / "configLibrary"
            library.mkdir(parents=True)
            applied_id = "11111111-2222-4333-8444-555555555555"
            (library / "_meta.json").write_text(
                json.dumps({"appliedId": applied_id, "entries": []}), encoding="utf-8"
            )
            config_path = library / f"{applied_id}.json"
            config_path.write_text(
                json.dumps({"theme": "keep", "disableEssentialTelemetry": False}),
                encoding="utf-8",
            )

            result = privacy.apply_desktop_managed_privacy(local_appdata=local_appdata)
            config = json.loads(config_path.read_text(encoding="utf-8"))

            self.assertEqual(result["status"], "updated")
            self.assertEqual(config["theme"], "keep")
            for key, value in privacy.MANAGED_PRIVACY_VALUES.items():
                self.assertIs(config[key], value)
            self.assertFalse(config_path.with_name(config_path.name + ".tmp-clean").exists())

    def test_supported_payload_patch_is_equal_length_and_idempotent(self) -> None:
        middle_length = (
            privacy.MODEL_REGEX_LENGTH
            - len(privacy.MODEL_REGEX_START)
            - len(privacy.MODEL_REGEX_END)
        )
        model = (
            privacy.MODEL_REGEX_START
            + (b"m" * middle_length)
            + privacy.MODEL_REGEX_END
        )
        project = (
            b"has_xcode_project:u.hasXcodeProject,"
            b"has_ios_app_project:u.hasIosAppProject,"
            b"has_android_project:u.hasAndroidProject,"
            b"has_android_app_project:u.hasAndroidAppProject,"
        )
        narration = (
            b'function ab(c){try{if(c.type!=="thinking"||!c.signature)return!1;'
            b'work()}catch(e){report("narration_classifier_error")}}'
        )
        original = b"prefix" + model + b"gap" + model + project + narration + b"suffix"

        patched = privacy.patch_supported_embedded_payload(original)

        self.assertEqual(len(patched), len(original))
        self.assertTrue(privacy.embedded_payload_is_clean(patched))
        self.assertEqual(patched.count(privacy.MODEL_REGEX_START), 0)
        self.assertEqual(patched.count(privacy.PROJECT_DISABLED_BLOCK), 1)
        self.assertEqual(patched.count(privacy.NARRATION_DISABLED), 1)

    def test_payload_drift_is_refused(self) -> None:
        with self.assertRaises(privacy.DesktopPrivacyError):
            privacy.patch_supported_embedded_payload(b"not-a-supported-payload")

    def test_clean_looking_unknown_hash_is_refused_without_smoke(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            binary = Path(temp) / "claude.exe"
            binary.write_bytes(b"x")
            with patch.object(
                privacy,
                "latest_embedded_binary",
                return_value=(privacy.SUPPORTED_EMBEDDED_VERSION, binary),
            ), patch.object(privacy, "SUPPORTED_EMBEDDED_SIZE", 1), patch.object(
                privacy, "embedded_payload_is_clean", return_value=True
            ), patch.object(privacy, "_sha256", return_value="unknown"), patch.object(
                privacy, "_smoke_embedded_binary"
            ) as smoke:
                result = privacy.harden_current_embedded_claude_code(
                    local_appdata=Path(temp)
                )

        self.assertEqual(result["status"], "unsupported")
        self.assertIn("hash", result["reason"])
        smoke.assert_not_called()

    def test_known_clean_hash_requires_successful_smoke(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            binary = Path(temp) / "claude.exe"
            binary.write_bytes(b"x")
            with patch.object(
                privacy,
                "latest_embedded_binary",
                return_value=(privacy.SUPPORTED_EMBEDDED_VERSION, binary),
            ), patch.object(privacy, "SUPPORTED_EMBEDDED_SIZE", 1), patch.object(
                privacy, "embedded_payload_is_clean", return_value=True
            ), patch.object(
                privacy, "_sha256", return_value=privacy.SUPPORTED_EMBEDDED_CLEAN_SHA256
            ), patch.object(
                privacy,
                "_smoke_embedded_binary",
                return_value=(True, "2.1.281 (Claude Code)"),
            ) as smoke:
                result = privacy.harden_current_embedded_claude_code(
                    local_appdata=Path(temp)
                )

        self.assertEqual(result["status"], "current")
        smoke.assert_called_once_with(binary)

    def test_unexpected_patched_hash_is_refused_before_write(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            binary = Path(temp) / "claude.exe"
            binary.write_bytes(b"x")
            with patch.object(
                privacy,
                "latest_embedded_binary",
                return_value=(privacy.SUPPORTED_EMBEDDED_VERSION, binary),
            ), patch.object(privacy, "SUPPORTED_EMBEDDED_SIZE", 1), patch.object(
                privacy, "embedded_payload_is_clean", return_value=False
            ), patch.object(
                privacy,
                "_sha256",
                side_effect=[privacy.SUPPORTED_EMBEDDED_ORIGINAL_SHA256, "unexpected"],
            ), patch.object(
                privacy, "patch_supported_embedded_payload", return_value=b"y"
            ):
                with self.assertRaisesRegex(
                    privacy.DesktopPrivacyError, "patched hash"
                ):
                    privacy.harden_current_embedded_claude_code(
                        local_appdata=Path(temp)
                    )

            self.assertEqual(binary.read_bytes(), b"x")

    def test_process_detection_failure_is_not_treated_as_closed(self) -> None:
        failed = Mock(returncode=1, stdout="", stderr="failed")
        with patch.object(privacy.platform, "system", return_value="Windows"), patch.object(
            privacy.subprocess, "run", return_value=failed
        ):
            with self.assertRaisesRegex(privacy.DesktopPrivacyError, "returned an error"):
                privacy._claude_process_running()

    def test_embedded_lookup_prefers_current_package_and_falls_back(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            local_appdata = Path(temp)
            packages = local_appdata / "Packages"
            preferred = (
                packages
                / "Claude_pzs8sxrjxfjjc"
                / "LocalCache"
                / "Roaming"
                / "Claude"
                / "claude-code"
                / "2.1.281"
                / "claude.exe"
            )
            fallback = (
                packages
                / "Claude_other"
                / "LocalCache"
                / "Roaming"
                / "Claude"
                / "claude-code"
                / "9.9.9"
                / "claude.exe"
            )
            preferred.parent.mkdir(parents=True)
            fallback.parent.mkdir(parents=True)
            preferred.write_bytes(b"preferred")
            fallback.write_bytes(b"fallback")

            self.assertEqual(
                privacy.latest_embedded_binary(local_appdata=local_appdata),
                ("2.1.281", preferred),
            )
            preferred.unlink()
            self.assertEqual(
                privacy.latest_embedded_binary(local_appdata=local_appdata),
                ("9.9.9", fallback),
            )


if __name__ == "__main__":
    unittest.main()
