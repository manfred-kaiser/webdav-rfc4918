"""A TCP proxy that cuts one response in the middle, to see what a client does about a dropped connection.

It sits between the client and a real server, forwards everything, and the first response that
is longer than ``cut`` bytes is dropped after ``pause`` seconds: both sockets are shut down,
the client sees the connection end in the middle of the body. The proxy records the heads of
the requests it forwarded, so a test can tell that the client came back with a ``Range``.
"""

import re
import socket
import threading
import time
from types import TracebackType

_METHODS = (b"GET ", b"HEAD ", b"PROPFIND ", b"PUT ", b"DELETE ", b"MKCOL ", b"LOCK ")


class CutProxy:
    """Forward to ``target`` (host, port); cut the first response over ``cut`` bytes after ``pause`` seconds."""

    def __init__(self, target: "tuple[str, int]", *, cut: int, pause: float) -> None:
        """Listen on a free port of 127.0.0.1; use it as a context manager."""
        self._target = target
        self._cut = cut
        self._pause = pause
        self._stop = threading.Event()
        self._listener = socket.create_server(("127.0.0.1", 0))
        self._listener.settimeout(0.2)
        #: The request heads (request line and headers) that went through, in order.
        self.heads: list[str] = []
        #: The ETag of the first 200 answer, as the client got it.
        self.first_etag: "str | None" = None
        #: Whether a response has been cut.
        self.cut_happened = False
        self._lock = threading.Lock()
        self._acceptor = threading.Thread(target=self._accept, daemon=True)

    @property
    def url(self) -> str:
        """The base URL of the proxy."""
        return f"http://127.0.0.1:{self._listener.getsockname()[1]}"

    def __enter__(self) -> "CutProxy":
        self._acceptor.start()
        return self

    def __exit__(
        self,
        exc_type: "type[BaseException] | None",
        exc: "BaseException | None",
        traceback: "TracebackType | None",
    ) -> None:
        self._stop.set()
        self._acceptor.join(2)
        self._listener.close()

    def _accept(self) -> None:
        while not self._stop.is_set():
            try:
                client, _ = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            threading.Thread(target=self._handle, args=(client,), daemon=True).start()

    def _forward_requests(self, client: socket.socket, upstream: socket.socket) -> None:
        try:
            while data := client.recv(65536):
                if data.startswith(_METHODS) and b"\r\n\r\n" in data:
                    head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1")
                    with self._lock:
                        self.heads.append(head)
                upstream.sendall(data)
        except OSError:
            pass

    def _handle(self, client: socket.socket) -> None:
        upstream = socket.create_connection(self._target)
        threading.Thread(
            target=self._forward_requests, args=(client, upstream), daemon=True
        ).start()
        sent = 0
        try:
            while data := upstream.recv(65536):
                if self.first_etag is None and data.startswith(b"HTTP/1.1 200"):
                    match = re.search(rb"\r\nETag: ([^\r]*)", data)
                    if match:
                        self.first_etag = match.group(1).decode("latin-1")
                sent += len(data)
                with self._lock:
                    cut_now = sent > self._cut and not self.cut_happened
                    if cut_now:
                        self.cut_happened = True
                if cut_now:
                    time.sleep(self._pause)
                    for sock in (client, upstream):
                        try:
                            sock.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                    return
                client.sendall(data)
        except OSError:
            pass
        finally:
            for sock in (client, upstream):
                try:
                    sock.close()
                except OSError:
                    pass
