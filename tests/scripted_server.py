"""A tiny scriptable HTTP server: answers every method from a callback.

Where ``rogue_server.py`` bundles a few fixed misbehaviours, this lets a
test say exactly what the server answers per request, and records every
request it received (method, path, lower-cased headers, body).
"""

import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer

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
        def log_message(self, fmt: str, *args: object) -> None:
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
