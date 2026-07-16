"""Loopback-only standard-library web server for the Mnemoir operator cockpit."""

from __future__ import annotations

import hmac
import json
import secrets
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from .local_ui_adapter import LocalUIAdapter, LocalUIError

MAX_JSON_BYTES = 64 * 1024
CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
_ASSETS = {"/": ("index.html", "text/html; charset=utf-8"), "/index.html": ("index.html", "text/html; charset=utf-8"), "/app.css": ("app.css", "text/css; charset=utf-8"), "/app.js": ("app.js", "text/javascript; charset=utf-8")}


class LocalUIServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, server_address: tuple[str, int], adapter: LocalUIAdapter):
        host = server_address[0]
        if host not in {"127.0.0.1", "::1"}:
            raise ValueError("local_ui_requires_loopback")
        self.adapter = adapter
        self.mutation_token = secrets.token_urlsafe(32)
        super().__init__(server_address, LocalUIRequestHandler)

    @property
    def origin(self) -> str:
        host, port = self.server_address[:2]
        bracketed = f"[{host}]" if ":" in host else host
        return f"http://{bracketed}:{port}"


class LocalUIRequestHandler(BaseHTTPRequestHandler):
    server: LocalUIServer
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        # Request paths and the mutation token are deliberately not logged.
        return

    def _security_headers(self, *, content_type: str, length: int, cache: str = "no-store") -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", cache)
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

    def _host_valid(self) -> bool:
        supplied = self.headers.get("Host", "")
        expected = urlsplit(self.server.origin).netloc
        return hmac.compare_digest(supplied.lower(), expected.lower())

    def _origin_valid(self) -> bool:
        supplied = self.headers.get("Origin", "")
        return hmac.compare_digest(supplied, self.server.origin)

    def _send_bytes(self, status: int, data: bytes, content_type: str, *, cache: str = "no-store", head_only: bool = False) -> None:
        self.send_response(status)
        self._security_headers(content_type=content_type, length=len(data), cache=cache)
        self.end_headers()
        if not head_only:
            self.wfile.write(data)

    def _send_json(self, status: int, payload: dict[str, Any], *, head_only: bool = False) -> None:
        data = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self._send_bytes(status, data, "application/json; charset=utf-8", head_only=head_only)

    def _error(self, status: int, code: str, *, head_only: bool = False) -> None:
        self._send_json(status, {"status": "error", "error": code}, head_only=head_only)

    def _guard_host(self) -> bool:
        if not self._host_valid():
            self._error(HTTPStatus.BAD_REQUEST, "invalid_host")
            return False
        return True

    def do_OPTIONS(self) -> None:  # noqa: N802
        if not self._guard_host():
            return
        self._error(HTTPStatus.METHOD_NOT_ALLOWED, "method_not_allowed")

    def do_HEAD(self) -> None:  # noqa: N802
        self._get(head_only=True)

    def do_GET(self) -> None:  # noqa: N802
        self._get(head_only=False)

    def _get(self, *, head_only: bool) -> None:
        if not self._guard_host():
            return
        parsed = urlsplit(self.path)
        path = parsed.path
        if path in _ASSETS:
            name, mime = _ASSETS[path]
            try:
                data = resources.files("mnemoir_provenance.ui").joinpath(name).read_bytes()
            except (OSError, FileNotFoundError):
                self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "asset_unavailable", head_only=head_only)
                return
            self._send_bytes(HTTPStatus.OK, data, mime, cache="no-cache", head_only=head_only)
            return
        if path == "/api/session":
            self._send_json(HTTPStatus.OK, {"status": "ok", "mutation_token": self.server.mutation_token}, head_only=head_only)
            return
        if path.startswith("/api/view/"):
            destination = unquote(path.removeprefix("/api/view/"))
            params = parse_qs(parsed.query, keep_blank_values=True)
            query = params.get("query", ["Council memory"])[0]
            try:
                payload = self.server.adapter.view(destination, query=query)
            except LocalUIError as error:
                self._error(error.status, error.code, head_only=head_only)
                return
            self._send_json(HTTPStatus.OK, payload, head_only=head_only)
            return
        if path.startswith("/api/detail/"):
            parts = path.split("/")
            if len(parts) != 5:
                self._error(HTTPStatus.NOT_FOUND, "not_found", head_only=head_only)
                return
            try:
                payload = self.server.adapter.detail(unquote(parts[3]), unquote(parts[4]))
            except LocalUIError as error:
                self._error(error.status, error.code, head_only=head_only)
                return
            self._send_json(HTTPStatus.OK, payload, head_only=head_only)
            return
        self._error(HTTPStatus.NOT_FOUND, "not_found", head_only=head_only)

    def do_POST(self) -> None:  # noqa: N802
        if not self._guard_host():
            self.close_connection = True
            return
        if not self._origin_valid():
            self.close_connection = True
            self._error(HTTPStatus.FORBIDDEN, "invalid_origin")
            return
        supplied_token = self.headers.get("X-Mnemoir-Mutation-Token", "")
        if not supplied_token or not hmac.compare_digest(supplied_token, self.server.mutation_token):
            self.close_connection = True
            self._error(HTTPStatus.FORBIDDEN, "invalid_mutation_token")
            return
        parsed = urlsplit(self.path)
        if not parsed.path.startswith("/api/action/"):
            self.close_connection = True
            self._error(HTTPStatus.NOT_FOUND, "not_found")
            return
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            self.close_connection = True
            self._error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "json_content_type_required")
            return
        raw_length = self.headers.get("Content-Length")
        try:
            length = int(raw_length or "-1")
        except ValueError:
            length = -1
        if length < 0 or length > MAX_JSON_BYTES:
            self.close_connection = True
            self._error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "request_body_size_invalid")
            return
        try:
            body = self.rfile.read(length)
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._error(HTTPStatus.BAD_REQUEST, "invalid_json")
            return
        if not isinstance(payload, dict):
            self._error(HTTPStatus.BAD_REQUEST, "json_object_required")
            return
        action = unquote(parsed.path.removeprefix("/api/action/"))
        try:
            response = self.server.adapter.mutate(action, payload)
        except LocalUIError as error:
            self._error(error.status, error.code)
            return
        self._send_json(HTTPStatus.OK, response)


def build_server(*, db_path: str | Path | None = None, port: int = 0, adapter: LocalUIAdapter | None = None) -> LocalUIServer:
    if not isinstance(port, int) or not 0 <= port <= 65535:
        raise ValueError("invalid_port")
    return LocalUIServer(("127.0.0.1", port), adapter or LocalUIAdapter(db_path))


def serve_ui(*, db_path: str | Path | None = None, port: int = 8765, open_browser: bool = True) -> int:
    """Serve until interrupted. The URL is safe to print because it contains no token."""
    server = build_server(db_path=db_path, port=port)
    print(f"Mnemoir Provenance UI: {server.origin} (loopback only)", flush=True)
    if open_browser:
        threading.Timer(0.2, lambda: webbrowser.open(server.origin, new=2)).start()
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
