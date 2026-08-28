from http.client import HTTPConnection
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest

from paramguard.assisted import AssistedWorkspace
from paramguard.assisted_web import AssistedServer, COMMAND_LIMIT, UPLOAD_LIMIT
from assisted_fixtures import Reader


class AssistedHttpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.work = AssistedWorkspace(
            Path(self.temp.name) / "workspace", reader=Reader()
        )
        self.server = AssistedServer(("127.0.0.1", 0), self.work)
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.01}
        )
        self.thread.start()
        self.port = self.server.server_port

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(2)
        self.server.server_close()
        self.work.close()
        self.temp.cleanup()

    def request(self, method="GET", path="/api/jobs", body=None, headers=None):
        conn = HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            response = conn.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            conn.close()

    def raw_request(self, lines, body=b""):
        with socket.create_connection(("127.0.0.1", self.port), timeout=3) as conn:
            conn.sendall(("\r\n".join(lines) + "\r\n\r\n").encode() + body)
            conn.shutdown(socket.SHUT_WR)
            result = b""
            while chunk := conn.recv(8192):
                result += chunk
            return int(result.split(b" ")[1]), result

    def test_page_security_headers_and_explicit_mode(self):
        status, headers, page = self.request(path="/")
        self.assertEqual(status, 200)
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertNotIn("unsafe-inline", headers["Content-Security-Policy"])
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["Cross-Origin-Resource-Policy"], "same-origin")
        self.assertNotIn(b"__PG_CSRF__", page)
        self.assertIn("不属于独立人工首审".encode(), page)

    def test_cross_site_and_wrong_host_rejected(self):
        for headers in (
            {"Host": "evil.test"},
            {"Host": "127.0.0.1:1"},
            {"Origin": "https://evil.test"},
            {"Origin": "null"},
            {"Sec-Fetch-Site": "cross-site"},
        ):
            with self.subTest(headers=headers):
                self.assertEqual(self.request(headers=headers)[0], 403)
        self.assertEqual(self.work.jobs(), [])

    def test_missing_wrong_or_duplicate_csrf(self):
        for headers in (
            {"Content-Type": "application/json"},
            {"Content-Type": "application/json", "X-ParamGuard-CSRF": "wrong"},
        ):
            with self.subTest(headers=headers):
                self.assertIn(
                    self.request("POST", body=b"{}", headers=headers)[0], (400, 403)
                )
        lines = [
            "POST /api/jobs HTTP/1.0",
            f"Host: 127.0.0.1:{self.port}",
            "Content-Type: application/json",
            "Content-Length: 2",
            f"X-ParamGuard-CSRF: {self.server.csrf}",
            f"X-ParamGuard-CSRF: {self.server.csrf}",
        ]
        self.assertEqual(self.raw_request(lines, b"{}")[0], 400)
        self.assertEqual(self.work.jobs(), [])

    def test_duplicate_headers_and_transfer_encoding(self):
        base = [
            "POST /api/jobs HTTP/1.0",
            f"Host: 127.0.0.1:{self.port}",
            "Content-Type: application/json",
            "Content-Length: 2",
            f"X-ParamGuard-CSRF: {self.server.csrf}",
        ]
        for extra in (
            f"Host: 127.0.0.1:{self.port}",
            "Content-Length: 2",
            "Transfer-Encoding: chunked",
            "Content-Encoding: gzip",
        ):
            with self.subTest(extra=extra):
                self.assertEqual(self.raw_request([*base, extra], b"{}")[0], 400)

    def test_length_limits_before_body_read(self):
        job = "a" * 32
        for route, cap in (
            (f"/api/jobs/{job}/images", UPLOAD_LIMIT),
            (f"/api/jobs/{job}/review", COMMAND_LIMIT),
        ):
            lines = [
                f"POST {route} HTTP/1.0",
                f"Host: 127.0.0.1:{self.port}",
                "Content-Type: application/json",
                f"Content-Length: {cap+1}",
                f"X-ParamGuard-CSRF: {self.server.csrf}",
            ]
            self.assertEqual(self.raw_request(lines)[0], 413)

    def test_json_schema_and_encoding_rejections_have_no_effect(self):
        headers = {
            "Content-Type": "application/json",
            "X-ParamGuard-CSRF": self.server.csrf,
        }
        for body in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":"\\ud800"}', b"[]", b"{}"):
            with self.subTest(body=body):
                self.assertEqual(
                    self.request("POST", body=body, headers=headers)[0], 400
                )
        self.assertEqual(self.work.jobs(), [])

    def test_truncated_body_rejected(self):
        lines = [
            "POST /api/jobs HTTP/1.0",
            f"Host: 127.0.0.1:{self.port}",
            "Content-Type: application/json",
            "Content-Length: 9",
            f"X-ParamGuard-CSRF: {self.server.csrf}",
        ]
        self.assertEqual(self.raw_request(lines, b"{}")[0], 400)

    def test_unsupported_paths_and_query_fields(self):
        for path in (
            "/api/jobs/../../etc/passwd",
            "/api/jobs/%2e%2e/secret",
            "/api/approve",
            "/api/jobs/" + "a" * 32 + "?offset=0&offset=1",
        ):
            with self.subTest(path=path):
                self.assertIn(self.request(path=path)[0], (400, 404))

    def test_valid_create_retry_and_state(self):
        body = {
            "label": "SYNTHETIC HTTP TEST",
            "targets": "P1\nP2",
            "command_id": "test-http-create",
            "acknowledge_assisted": True,
            "confirm_local_test_data": True,
            "confirm_single_column": True,
        }
        headers = {
            "Content-Type": "application/json",
            "X-ParamGuard-CSRF": self.server.csrf,
        }
        first = self.request("POST", body=json.dumps(body), headers=headers)
        again = self.request("POST", body=json.dumps(body), headers=headers)
        self.assertEqual(first[0], 200)
        self.assertEqual(first[2], again[2])
        job = json.loads(first[2])["job_id"]
        status, _, data = self.request(path=f"/api/jobs/{job}?offset=0&limit=1")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["total"], 2)
        self.assertEqual(len(json.loads(data)["items"]), 1)

    def test_non_loopback_server_is_not_allowed(self):
        with self.assertRaises(ValueError):
            AssistedServer(("0.0.0.0", 0), self.work)


if __name__ == "__main__":
    unittest.main()
