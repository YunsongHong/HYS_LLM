"""Local-only, opt-in assisted workbench. This is not the default R1 server."""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import secrets
import socket
import threading
from urllib.parse import parse_qs, urlsplit

from .assisted import AssistedWorkspace
from .assisted_input import AssistedError, canonical, strict_json


UUID = r"[a-f0-9]{32}"
JOB_PATH = re.compile(rf"/api/jobs/({UUID})(?:/(.*))?\Z")
UPLOAD_LIMIT = 12 * 1024 * 1024
CREATE_LIMIT = 512 * 1024
COMMAND_LIMIT = 16 * 1024


class AssistedServer(ThreadingHTTPServer):
    """Four bounded requests and one workspace-owned OCR worker at a time."""

    daemon_threads = False
    block_on_close = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], workspace: AssistedWorkspace):
        if address[0] != "127.0.0.1":
            raise ValueError("The assisted prototype may only bind 127.0.0.1")
        self.workspace = workspace
        self.csrf = secrets.token_hex(32)
        self._slots = threading.BoundedSemaphore(4)
        super().__init__(address, AssistedHandler)

    def process_request(self, request: socket.socket, client_address) -> None:
        if not self._slots.acquire(blocking=False):
            try:
                request.settimeout(1)
                request.sendall(
                    b"HTTP/1.0 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


class AssistedHandler(BaseHTTPRequestHandler):
    server: AssistedServer
    server_version = "ParamGuardLocal/1"
    protocol_version = "HTTP/1.0"

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(35)

    def log_message(self, fmt, *args) -> None:
        # Parameter IDs, filenames and submitted values do not enter stdout.
        return

    def _one(self, name: str, *, required: bool = False) -> str | None:
        values = self.headers.get_all(name, [])
        if len(values) > 1 or (required and len(values) != 1):
            raise AssistedError("INVALID_HEADERS", "请求头无效。", 400)
        return values[0] if values else None

    def _boundary(self, *, mutation: bool = False) -> tuple[str, dict[str, str]]:
        host = self._one("Host", required=True)
        port = self.server.server_port
        if host not in {f"127.0.0.1:{port}", f"localhost:{port}"}:
            raise AssistedError("HOST_REJECTED", "仅允许本机工作区请求。", 403)
        origin = self._one("Origin")
        if origin is not None and origin != f"http://{host}":
            raise AssistedError("ORIGIN_REJECTED", "不接受其他网站的请求。", 403)
        site = self._one("Sec-Fetch-Site")
        if site is not None and site not in {"same-origin", "none"}:
            raise AssistedError("ORIGIN_REJECTED", "不接受跨站请求。", 403)
        if (
            self._one("Transfer-Encoding") is not None
            or self._one("Content-Encoding") is not None
        ):
            raise AssistedError("INVALID_HEADERS", "不接受分块或压缩请求。", 400)
        if mutation:
            token = self._one("X-ParamGuard-CSRF", required=True)
            if token is None or not secrets.compare_digest(token, self.server.csrf):
                raise AssistedError("CSRF_REJECTED", "页面会话已失效，请刷新。", 403)
        if len(self.path) > 2048:
            raise AssistedError("INVALID_URL", "请求地址过长。", 400)
        parts = urlsplit(self.path)
        if parts.scheme or parts.netloc or parts.fragment or "%" in parts.path:
            raise AssistedError("INVALID_URL", "无效的工作区地址。", 400)
        try:
            raw_query = parse_qs(
                parts.query,
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=4,
            )
        except ValueError as exc:
            raise AssistedError("INVALID_QUERY", "查询参数无效。") from exc
        if any(len(values) != 1 for values in raw_query.values()):
            raise AssistedError("INVALID_QUERY", "查询参数重复。")
        return parts.path, {key: values[0] for key, values in raw_query.items()}

    def _send(
        self,
        status: int,
        data: bytes,
        mime: str,
        *,
        nonce: str | None = None,
        download: bool = False,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Connection", "close")
        self.send_header(
            "Content-Security-Policy",
            (
                "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'; "
                "connect-src 'self'; img-src 'self' blob:; font-src 'self'; "
                + (
                    f"script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'"
                    if nonce
                    else "script-src 'none'; style-src 'none'"
                )
            ),
        )
        if download:
            self.send_header(
                "Content-Disposition",
                'attachment; filename="paramguard-assisted-report.json"',
            )
        self.end_headers()
        self.close_connection = True
        self.wfile.write(data)

    def _json(self, data: object, status: int = 200, *, download: bool = False) -> None:
        self._send(
            status,
            canonical(data).encode(),
            "application/json; charset=utf-8",
            download=download,
        )

    def _error(self, error: AssistedError) -> None:
        self._json({"error": error.code, "message": error.message}, error.status)

    @staticmethod
    def _number(value: str) -> int:
        if not re.fullmatch(r"[0-9]{1,4}", value):
            raise AssistedError("INVALID_QUERY", "分页参数必须是整数。")
        return int(value)

    def do_GET(self) -> None:
        try:
            path, query = self._boundary()
            if self._one("Content-Length") not in (None, "0"):
                raise AssistedError("INVALID_HEADERS", "GET 不接受请求内容。")
            if path == "/" and not query:
                nonce = secrets.token_hex(16)
                page = (Path(__file__).parent / "static" / "assisted.html").read_text(
                    "utf-8"
                )
                page = page.replace("__PG_NONCE__", nonce).replace(
                    "__PG_CSRF__", self.server.csrf
                )
                self._send(200, page.encode(), "text/html; charset=utf-8", nonce=nonce)
                return
            workspace = self.server.workspace
            if path == "/api/jobs" and not query:
                self._json({"jobs": workspace.jobs()})
                return
            match = JOB_PATH.fullmatch(path)
            if match is None:
                raise AssistedError("NOT_FOUND", "未找到页面。", 404)
            job, route = match.groups()
            if route is None:
                if set(query) - {"offset", "limit", "filter", "query"}:
                    raise AssistedError("INVALID_QUERY", "不支持此查询条件。")
                self._json(
                    workspace.state(
                        job,
                        offset=self._number(query.get("offset", "0")),
                        limit=self._number(query.get("limit", "25")),
                        filter_by=query.get("filter", "all"),
                        query=query.get("query", ""),
                    )
                )
            elif query:
                raise AssistedError("INVALID_QUERY", "此地址不接受查询参数。")
            elif route == "export":
                self._json(workspace.export(job), download=True)
            elif item := re.fullmatch(r"items/([0-9]{1,4})", route):
                self._json(workspace.item(job, int(item[1])))
            elif page := re.fullmatch(rf"pages/({UUID})\.png", route):
                self._send(200, workspace.image(job, page[1]), "image/png")
            elif crop := re.fullmatch(
                r"crops/([0-9]{1,4})/(left|right)/([0-9]{1,2})\.png", route
            ):
                self._send(
                    200,
                    workspace.crop(job, int(crop[1]), crop[2], int(crop[3])),
                    "image/png",
                )
            else:
                raise AssistedError("NOT_FOUND", "未找到页面。", 404)
        except AssistedError as exc:
            self._error(exc)
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            self.close_connection = True
        except Exception:
            self._error(
                AssistedError("INTERNAL_ERROR", "读取失败，未确认当前状态。请刷新或保留工作区检查。", 500)
            )

    def do_POST(self) -> None:
        try:
            path, query = self._boundary(mutation=True)
            if query:
                raise AssistedError("INVALID_QUERY", "操作地址不接受查询参数。")
            match = JOB_PATH.fullmatch(path)
            create = path == "/api/jobs"
            action = match[2] if match else None
            actions = {
                "images": "upload",
                "start": "start",
                "cancel": "cancel",
                "choose": "choose",
                "region": "region",
                "review": "review",
                "finish": "finish",
            }
            if not create and (match is None or action not in actions):
                raise AssistedError("NOT_FOUND", "未找到操作。", 404)
            if self._one("Content-Type", required=True) != "application/json":
                raise AssistedError("CONTENT_TYPE_REJECTED", "仅接受 JSON 请求。", 415)
            length = self._one("Content-Length", required=True)
            if length is None or not re.fullmatch(r"[0-9]{1,9}", length):
                raise AssistedError("INVALID_LENGTH", "请求长度无效。")
            cap = (
                CREATE_LIMIT
                if create
                else UPLOAD_LIMIT
                if action == "images"
                else COMMAND_LIMIT
            )
            if not 0 < int(length) <= cap:
                raise AssistedError("BODY_TOO_LARGE", "请求超过此操作的大小上限。", 413)
            raw = self.rfile.read(int(length))
            if len(raw) != int(length):
                raise AssistedError("INCOMPLETE_REQUEST", "请求未传输完整。")
            body = strict_json(raw)
            workspace = self.server.workspace
            result = (
                workspace.create(body)
                if create
                else getattr(workspace, actions[action])(match[1], body)
            )
            self._json(result)
        except AssistedError as exc:
            self._error(exc)
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            self.close_connection = True
        except Exception:
            self._error(AssistedError("INTERNAL_ERROR", "操作未确认成功。请刷新检查，勿重复新建任务。", 500))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Local AI-assisted review; not independent R1"
    )
    parser.add_argument("--host", choices=["127.0.0.1"], default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument(
        "--workspace", type=Path, default=Path("artifacts/assisted-workspace")
    )
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    workspace = AssistedWorkspace(args.workspace)
    server = None
    try:
        server = AssistedServer((args.host, args.port), workspace)
        print(
            f"ASSISTED_REVIEW_V1 — local, non-blind, no approval\nhttp://{args.host}:{server.server_port}/",
            flush=True,
        )
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        return 0
    finally:
        if server is not None:
            server.server_close()
        workspace.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
