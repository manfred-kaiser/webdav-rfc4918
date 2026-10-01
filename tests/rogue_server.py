"""A deliberately misbehaving/adversarial WebDAV-ish server, for security tests.

Unlike ``tests/server.py`` (a real, RFC-compliant server via wsgidav), this
one intentionally does the *wrong* thing - the kind of thing a compromised,
buggy, or actively malicious server might do. It exists to give the security
regression tests in ``tests/test_security_edge_cases.py`` something to run
against, since a compliant server never triggers these code paths.

Each behavior is opt-in via ``RogueBehavior`` so a test only enables the one
it's exercising.
"""

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable


@dataclass
class RogueBehavior:
    """Captured requests plus the misbehavior to trigger."""

    #: If set, any request to this path answers with a redirect (307, so the
    #: method and body are preserved) to ``redirect_target``.
    redirect_from: str | None = None
    redirect_target: str | None = None
    redirect_status: int = 307

    #: If set, any PROPFIND is answered with a 207 whose body is this
    #: deliberately not-well-formed XML instead of a real multistatus body.
    malformed_multistatus_body: bytes | None = None

    #: Every request this server received: (method, path, body bytes).
    requests: list[tuple[str, str, bytes]] = field(default_factory=list)


def _make_handler(behavior: RogueBehavior) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            """Keep test output quiet; inspect ``behavior.requests`` instead."""

        def _read_body(self) -> bytes:
            length = int(self.headers.get("Content-Length", 0) or 0)
            return self.rfile.read(length) if length else b""

        def _dispatch(self) -> None:
            body = self._read_body()
            behavior.requests.append((self.command, self.path, body))

            if behavior.redirect_from and self.path == behavior.redirect_from:
                self.send_response(behavior.redirect_status)
                self.send_header("Location", behavior.redirect_target or "/")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            if self.command == "PROPFIND" and behavior.malformed_multistatus_body:
                payload = behavior.malformed_multistatus_body
                self.send_response(207)
                self.send_header("Content-Type", "application/xml")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return

            self.send_response(201 if self.command in ("PUT", "MKCOL") else 204)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def __getattr__(self, name: str) -> "Callable[[], None]":
            # BaseHTTPRequestHandler dispatches a request by looking up an
            # attribute named "do_" followed by the HTTP method (GET, PUT,
            # PROPFIND, ...) - route every one of those to the same
            # handler instead of naming each out as its own mixedCase
            # method/assignment (which linting flags either way).
            if name.startswith("do_"):
                return self._dispatch
            raise AttributeError(name)

    return Handler


@contextmanager
def rogue_server(behavior: RogueBehavior) -> Iterator[str]:
    """Run the rogue server for the duration of the block; yields its base URL."""
    server = HTTPServer(("127.0.0.1", 0), _make_handler(behavior))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
