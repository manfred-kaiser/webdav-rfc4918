"""A tiny scriptable HTTP server: answers every method from a callback.

Where ``rogue_server.py`` bundles a few fixed misbehaviours, this lets a
test say exactly what the server answers per request, and records every
request it received (method, path, lower-cased headers, body).
"""

import socket
import ssl
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from tests.certificates import Certificates

Reply = tuple[int, dict[str, str], bytes]

#: Put this key in a reply's headers to send no ``Content-Length`` (the body then ends
#: when the connection closes, as with a chunked or endless response).
NO_CONTENT_LENGTH = "!no-content-length"

#: Put this key in a reply's headers (value: seconds) to send the body one byte at a time,
#: pausing that long between bytes - a slow-drip response.
DRIP = "!drip"


@dataclass
class Seen:
    """One request as the server received it."""

    method: str
    path: str
    headers: dict[str, str]
    body: bytes


@dataclass
class Recorder:
    """Everything a scripted server received."""

    requests: list[Seen] = field(default_factory=list)

    def to(self, path: str) -> list[Seen]:
        """Requests received for exactly ``path``."""
        return [r for r in self.requests if r.path == path]


def _make_handler(
    respond: Callable[[Seen], Reply], recorder: Recorder
) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        """Answers every request through the responder."""

        def log_message(self, *_args: object) -> None:
            """Keep test output quiet."""

        def _dispatch(self) -> None:
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length) if length else b""
            seen = Seen(
                self.command,
                self.path,
                {k.lower(): v for k, v in self.headers.items()},
                body,
            )
            recorder.requests.append(seen)
            status, headers, payload = respond(seen)
            self.send_response(status)
            for name, value in headers.items():
                if name not in (NO_CONTENT_LENGTH, DRIP):
                    self.send_header(name, value)
            if NO_CONTENT_LENGTH not in headers:
                self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if DRIP in headers:
                for i in range(len(payload)):
                    self.wfile.write(payload[i : i + 1])
                    self.wfile.flush()
                    time.sleep(float(headers[DRIP]))
            else:
                self.wfile.write(payload)

        def __getattr__(self, name: str) -> Callable[[], None]:
            if name.startswith("do_"):
                return self._dispatch
            raise AttributeError(name)

    return Handler


@contextmanager
def scripted_server(respond: Callable[[Seen], Reply]) -> Iterator[tuple[str, Recorder]]:
    """Serve ``respond`` on a free port; yields ``(base URL, recorder)``."""
    recorder = Recorder()
    server = HTTPServer(("127.0.0.1", 0), _make_handler(respond, recorder))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", recorder
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def redirect(status: int, location: str) -> Reply:
    """A redirect reply."""
    return status, {"Location": location}, b""


OK: Reply = (204, {}, b"")


def always(reply: Reply) -> Callable[[Seen], Reply]:
    """A responder that answers every request with ``reply``."""
    return lambda _seen: reply


MULTISTATUS_EMPTY = (
    b'<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"></d:multistatus>'
)


def record_server() -> Any:
    """A scripted server that answers a ``PROPFIND`` with 404 and everything else with 204."""

    def respond(seen: Seen) -> Reply:
        return (404, {}, b"") if seen.method == "PROPFIND" else (204, {}, b"")

    return scripted_server(respond)


def closed_port() -> int:
    """A port on 127.0.0.1 that nothing listens on."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class QuietServer(HTTPServer):
    """An ``HTTPServer`` that does not report a client that gave up."""

    def handle_error(self, request: Any, client_address: Any) -> None:
        """A client that gives up the handshake is the point of some tests, not news."""


@contextmanager
def tls_server(
    certs: Certificates, respond: Any, *, max_version: "ssl.TLSVersion | None" = None
) -> Iterator[tuple[str, Recorder]]:
    """A scripted server speaking TLS with the certificate of ``certs`` (valid for 127.0.0.1)."""
    recorder = Recorder()
    server = QuietServer(("127.0.0.1", 0), _make_handler(respond, recorder))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(certs.server_cert), str(certs.server_key))
    if max_version is not None:
        context.maximum_version = max_version
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"https://127.0.0.1:{server.server_address[1]}", recorder
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
