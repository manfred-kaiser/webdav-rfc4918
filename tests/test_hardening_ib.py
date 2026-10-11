"""Hardening of the transport, the streams and the download path.

One block per behaviour; each has a test of the misbehaviour and one of the behaviour that
has always been right and must stay so.
"""

import gzip
import socket
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from tests.scripted_server import (
    NO_CONTENT_LENGTH,
    Reply,
    Seen,
    scripted_server,
)
from webdav import FileSystem, Session
from webdav.exceptions import ClientError
from webdav.fsspec import WebdavFileSystem

_PROPFIND = (
    b'<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response><d:href>/f</d:href>'
    b"<d:propstat><d:prop><d:resourcetype/><d:getcontentlength>%d</d:getcontentlength>"
    b"</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
    b"</d:multistatus>"
)


def file_server(
    size: int, on_get: "Callable[[Seen], Reply]"
) -> "Callable[[Seen], Reply]":
    """A responder for a resource ``/f`` of ``size`` bytes: PROPFIND is answered, GET is ``on_get``."""

    def respond(seen: Seen) -> Reply:
        if seen.method == "PROPFIND":
            return 207, {"Content-Type": "application/xml"}, _PROPFIND % size
        return on_get(seen)

    return respond


def serves(data: bytes, **extra: str) -> "Callable[[Seen], Reply]":
    """A GET answered like a server that knows ranges (and an ETag) answers it."""

    def respond(seen: Seen) -> Reply:
        headers = {"ETag": '"v1"', "Accept-Ranges": "bytes", **extra}
        requested = seen.headers.get("range")
        if requested is None:
            return 200, headers, data
        first, _, last = requested.removeprefix("bytes=").partition("-")
        start = int(first)
        stop = min(int(last) if last else len(data) - 1, len(data) - 1)
        headers["Content-Range"] = f"bytes {start}-{stop}/{len(data)}"
        return 206, headers, data[start : stop + 1]

    return respond


class RawServer:
    """A keep-alive HTTP server that answers with exactly the bytes a handler sends."""

    def __init__(
        self, handler: "Callable[[RawServer, socket.socket, Seen], str | None]"
    ):
        self.handler = handler
        self.requests: list[Seen] = []
        self.connections = 0
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(20)
        self.url = f"http://127.0.0.1:{self._sock.getsockname()[1]}"
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            self.connections += 1
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        try:
            while True:
                data = b""
                while b"\r\n\r\n" not in data:
                    more = conn.recv(65536)
                    if not more:
                        return
                    data += more
                head, _, rest = data.partition(b"\r\n\r\n")
                lines = head.decode("latin1").split("\r\n")
                method, path, _ = lines[0].split(" ", 2)
                headers = {
                    k.lower(): v.strip()
                    for k, _, v in (line.partition(":") for line in lines[1:])
                }
                length = int(headers.get("content-length", 0))
                while len(rest) < length:
                    rest += conn.recv(65536)
                seen = Seen(method, path, headers, rest[:length])
                self.requests.append(seen)
                if self.handler(self, conn, seen) == "close":
                    return
        except OSError:
            pass
        finally:
            conn.close()

    def close(self) -> None:
        self._sock.close()


@contextmanager
def raw_server(
    handler: "Callable[[RawServer, socket.socket, Seen], str | None]",
) -> Iterator[RawServer]:
    server = RawServer(handler)
    try:
        yield server
    finally:
        server.close()


def _propfind_reply(conn: socket.socket, size: int) -> None:
    body = _PROPFIND % size
    conn.sendall(
        b"HTTP/1.1 207 Multi-Status\r\nContent-Type: application/xml\r\n"
        b"Content-Length: %d\r\n\r\n" % len(body) + body
    )


class Sink:
    """A file object that collects what is written."""

    def __init__(self) -> None:
        self.data = b""

    def write(self, chunk: bytes) -> int:
        self.data += chunk
        return len(chunk)


_BODY = bytes(range(256)) * 40  # 10 KiB


# ---------------------------------------------------------------------------
# a Content-Encoding on a streamed body is refused
# ---------------------------------------------------------------------------


_GZIPPED = gzip.compress(b"A" * 100_000)


def _gzip_server(*, with_length: bool) -> "Callable[[Seen], Reply]":
    headers = {"Content-Encoding": "gzip"}
    if not with_length:
        headers[NO_CONTENT_LENGTH] = "1"
    return file_server(len(_GZIPPED), lambda _seen: (200, headers, _GZIPPED))


@pytest.mark.parametrize("with_length", [True, False])
@pytest.mark.parametrize("how", ["download_fileobj", "download_file", "open", "cat"])
def test_a_content_encoding_is_refused_where_a_body_is_streamed(
    with_length: bool, how: str, tmp_path: Path
) -> None:
    with scripted_server(_gzip_server(with_length=with_length)) as (url, _rec):
        fs = FileSystem(url)
        sink = Sink()
        with pytest.raises(ClientError, match="Content-Encoding: gzip"):
            if how == "download_fileobj":
                fs.download_fileobj("/f", sink)  # type: ignore[arg-type]
            elif how == "download_file":
                fs.download_file("/f", tmp_path / "out")
            elif how == "open":
                with fs.open("/f", "rb") as f:
                    f.read()
            else:
                WebdavFileSystem(url).cat_file("/f", 0, 10)
        assert sink.data == b""
        assert not (tmp_path / "out").exists()
        fs.close()


def test_a_content_encoding_is_refused_for_a_whole_file_read_of_fsspec() -> None:
    with scripted_server(_gzip_server(with_length=False)) as (url, _rec):
        with pytest.raises(ClientError, match="Content-Encoding"):
            WebdavFileSystem(url).cat_file("/f")


def test_identity_is_no_content_encoding() -> None:
    with scripted_server(
        file_server(5, lambda _seen: (200, {"Content-Encoding": "identity"}, b"hello"))
    ) as (url, _rec):
        sink = Sink()
        FileSystem(url).download_fileobj("/f", sink)  # type: ignore[arg-type]
        assert sink.data == b"hello"


# ---------------------------------------------------------------------------
# a held bodyless response does not poison the connection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("method", ["put", "delete", "head"])
def test_a_held_bodyless_response_does_not_break_the_next_request(method: str) -> None:
    def handler(_server: RawServer, conn: socket.socket, seen: Seen) -> None:
        if seen.method == "HEAD":
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n")
        elif seen.method in ("PUT", "DELETE"):
            conn.sendall(b"HTTP/1.1 204 No Content\r\n\r\n")
        else:
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

    with raw_server(handler) as server:
        session = Session(server.url, retry=False)
        held = []
        for call in (method, "put", "head", "delete", "get", "put", "get"):
            kwargs = {"data": b"x"} if call == "put" else {}
            held.append(getattr(session, call)("/f", **kwargs))
        assert [r.status_code for r in held] == [
            204 if m in ("put", "delete") else 200
            for m in (method, "put", "head", "delete", "get", "put", "get")
        ]
        assert held[-1].text == "ok"
        assert server.connections == 1  # and the connection was kept alive, not dropped
