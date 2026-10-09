from __future__ import annotations

import json
import threading
import unittest
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

    def test_config_exposes_only_local_modes(self) -> None:
        status, body = self.request("/api/config")
        self.assertEqual(status, 200)
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


if __name__ == "__main__":
    unittest.main()
