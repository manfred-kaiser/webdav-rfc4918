"""Reading and writing response bodies: streams, content codings, ``Content-Range`` and resuming."""

import contextlib
import gzip
import io
import socket
import threading
import tracemalloc
import zlib
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
import requests

from tests.scripted_server import (
    NO_CONTENT_LENGTH,
    Reply,
    Seen,
    always,
    scripted_server,
)
from webdav import FileSystem, Session
from webdav._fsspec_ranges import fetch_range
from webdav.exceptions import ClientError, WebDAVError
from webdav.fs.streams import IterStream
from webdav.fsspec import WebdavFileSystem
from webdav.transport.parse_utils import parse_content_range

if TYPE_CHECKING:
    from collections.abc import Callable


@pytest.mark.parametrize("length", ["²", "9" * 5000, "-5", "1e3", "\uff10"])
def test_a_hostile_content_length_never_raises_a_bare_valueerror(length: str) -> None:
    reply = (200, {"Content-Length": length, NO_CONTENT_LENGTH: "1"}, b"hello")
    # Refusing the response is fine, and so is a network-level error;
    # a bare ValueError (or anything else) escaping is what must not happen.
    with (
        scripted_server(always(reply)) as (url, _rec),
        contextlib.suppress(WebDAVError, requests.RequestException),
    ):
        Session(retry=False).get(f"{url}/f")


def test_send_reads_a_no_length_body_normally() -> None:
    with scripted_server(always((200, {NO_CONTENT_LENGTH: "1"}, b"abc"))) as (
        url,
        _rec,
    ):
        session = Session(retry=False)
        assert (
            session.send(
                session.prepare_request(requests.Request("GET", f"{url}/a"))
            ).content
            == b"abc"
        )


def test_stacked_content_codings_are_refused() -> None:
    body = gzip.compress(gzip.compress(gzip.compress(b"0" * 1_000_000)))
    with (
        scripted_server(
            always((207, {"Content-Encoding": "gzip, gzip, gzip"}, body))
        ) as (url, _r),
        pytest.raises(ClientError, match="stacked"),
    ):
        Session(retry=False).propfind(url, depth=0)


def test_a_head_reply_is_not_refused_for_the_length_of_the_body_it_does_not_carry() -> (
    None
):
    reply: tuple[int, dict[str, str], bytes] = (
        200,
        {"Content-Length": "200000000", NO_CONTENT_LENGTH: "1"},
        b"",
    )
    with scripted_server(always(reply)) as (url, _rec):
        response = Session(retry=False, max_response_size=1024).head(f"{url}/big")
        assert response.status_code == 200
        assert response.headers["Content-Length"] == "200000000"
        assert response.content == b""
    not_modified = (304, {"Content-Length": "999999999", NO_CONTENT_LENGTH: "1"}, b"")
    with scripted_server(always(not_modified)) as (url, _rec):
        assert (
            Session(retry=False, max_response_size=1024).get(f"{url}/x").status_code
            == 304
        )


@pytest.mark.parametrize("unit", ["bytes", "Bytes", "BYTES"])
def test_the_range_unit_is_case_insensitive(unit: str) -> None:
    assert parse_content_range(f"{unit} 0-9/10") == (0, 9, 10)


def test_another_unit_is_not_a_byte_range() -> None:
    assert parse_content_range("items 0-9/10") is None


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


class Sink:
    """A file object that collects what is written."""

    def __init__(self) -> None:
        """Start empty."""
        self.data = b""

    def write(self, chunk: bytes) -> int:
        """Keep ``chunk``."""
        self.data += chunk
        return len(chunk)


_GZIPPED = gzip.compress(b"A" * 100_000)


def _gzip_server(*, with_length: bool) -> "Callable[[Seen], Reply]":
    headers = {"Content-Encoding": "x-gzip"}
    if not with_length:
        headers[NO_CONTENT_LENGTH] = "1"
    return file_server(len(_GZIPPED), lambda _seen: (200, headers, _GZIPPED))


@pytest.mark.parametrize("with_length", [True, False])
@pytest.mark.parametrize("how", ["download_fileobj", "download_file", "open", "cat"])
def test_a_stored_gzip_file_is_downloaded_as_stored(
    with_length: bool, how: str, tmp_path: Path
) -> None:
    """Apache with ``AddEncoding x-gzip .gz``: the file is the gzip bytes, not what is in it."""
    with scripted_server(_gzip_server(with_length=with_length)) as (url, _rec):
        fs = FileSystem(url)
        sink = Sink()
        if how == "download_fileobj":
            fs.download_fileobj("/f", sink)  # type: ignore[arg-type]
            got = sink.data
        elif how == "download_file":
            fs.download_file("/f", tmp_path / "out")
            got = (tmp_path / "out").read_bytes()
        elif how == "open":
            with fs.open("/f", "rb") as f:
                got = f.read()
        else:
            got = WebdavFileSystem(url).cat_file("/f", 0, len(_GZIPPED))
        assert got == _GZIPPED
        fs.close()


def test_a_stored_gzip_file_is_read_whole_by_fsspec() -> None:
    with scripted_server(_gzip_server(with_length=False)) as (url, _rec):
        assert WebdavFileSystem(url).cat_file("/f") == _GZIPPED


def test_identity_is_no_content_encoding() -> None:
    with scripted_server(
        file_server(5, lambda _seen: (200, {"Content-Encoding": "identity"}, b"hello"))
    ) as (url, _rec):
        sink = Sink()
        FileSystem(url).download_fileobj("/f", sink)  # type: ignore[arg-type]
        assert sink.data == b"hello"


@pytest.mark.parametrize("method", ["PUT", "DELETE", "MKCOL", "PROPFIND"])
def test_an_answer_labelled_gzip_that_is_not_gzip_is_taken_as_it_came(
    method: str,
) -> None:
    """Apache labels the answers for ``a.gz`` ``x-gzip``: the 201 of a PUT is HTML, a PROPFIND's XML."""
    reply = (201, {"Content-Encoding": "x-gzip"}, b"<html>Created</html>")
    with scripted_server(always(reply)) as (url, _rec), Session(url, retry=False) as s:
        response = s.request(method, "/a.gz", data=b"x" if method == "PUT" else None)
    assert response.status_code == 201
    assert response.content == b"<html>Created</html>"


@pytest.mark.parametrize("coding", ["gzip", "x-gzip", "deflate"])
def test_a_real_gzip_or_deflate_answer_is_inflated(coding: str) -> None:
    body = b"<d:multistatus xmlns:d='DAV:'/>" * 20
    packed = gzip.compress(body) if "gzip" in coding else zlib.compress(body)
    reply = (200, {"Content-Encoding": coding}, packed)
    with scripted_server(always(reply)) as (url, _rec), Session(url, retry=False) as s:
        assert s.get("/x").content == body


def test_an_answer_that_inflates_past_the_limit_is_refused() -> None:
    reply = (200, {"Content-Encoding": "gzip"}, gzip.compress(b"A" * 1_000_000))
    with (
        scripted_server(always(reply)) as (url, _rec),
        Session(url, retry=False, max_response_size=10_000) as s,
        pytest.raises(ClientError, match="exceeds"),
    ):
        s.get("/x")


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


def test_a_forward_seek_does_not_hold_what_it_skips() -> None:
    size = 24 * 2**20
    data = b"\0" * size
    with scripted_server(file_server(size, serves(data))) as (url, _rec):
        session = Session(url)
        with IterStream(session, f"{url}/f", chunk_size=64 * 1024) as stream:
            tracemalloc.start()
            try:
                tracemalloc.reset_peak()
                stream.seek(size - 100, 1)
                _, peak = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
            assert stream.tell() == size - 100
            assert len(stream.read()) == 100
        assert peak < 6 * 2**20


class RawServer:
    """A keep-alive HTTP server that answers with exactly the bytes a handler sends."""

    def __init__(
        self, handler: "Callable[[RawServer, socket.socket, Seen], str | None]"
    ) -> None:
        """Listen on a free port; ``handler`` answers each request."""
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
        """Stop listening."""
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


def _stream(url: str, session: Session) -> IterStream:
    return IterStream(session, f"{url}/f", chunk_size=100)


def test_seeking_to_the_end_of_an_empty_file_is_position_zero() -> None:
    with (
        scripted_server(file_server(0, serves(b""))) as (url, _rec),
        _stream(url, Session(url)) as stream,
    ):
        assert stream.seek(0, 2) == 0
        assert stream.read() == b""


_BODY = bytes(range(256)) * 40  # 10 KiB


def test_read_none_reads_everything() -> None:
    with (
        scripted_server(file_server(len(_BODY), serves(_BODY))) as (url, _rec),
        _stream(url, Session(url)) as stream,
    ):
        assert stream.read(None) == _BODY  # type: ignore[arg-type]


def test_reading_a_closed_stream_is_a_value_error() -> None:
    with scripted_server(file_server(len(_BODY), serves(_BODY))) as (url, _rec):
        stream = _stream(url, Session(url))
        with stream:
            pass
        for call in (stream.read, stream.read1, stream.readall):
            with pytest.raises(ValueError, match="closed file"):
                call()


def test_a_seek_on_a_closed_stream_does_not_open_it_again() -> None:
    with scripted_server(file_server(len(_BODY), serves(_BODY))) as (url, rec):
        stream = _stream(url, Session(url))
        with stream:
            stream.read(10)
        gets = len([r for r in rec.requests if r.method == "GET"])
        with pytest.raises(ValueError, match="closed file"):
            stream.seek(5)
        assert stream.closed
        assert len([r for r in rec.requests if r.method == "GET"]) == gets


def test_seeking_and_reading_an_open_stream_still_works() -> None:
    with (
        scripted_server(file_server(len(_BODY), serves(_BODY))) as (url, _rec),
        _stream(url, Session(url)) as stream,
    ):
        assert stream.seek(10) == 10
        assert stream.read(5) == _BODY[10:15]
        assert stream.seek(5, 1) == 20
        assert stream.read(5) == _BODY[20:25]
        assert stream.seek(-10, 2) == len(_BODY) - 10
        assert stream.read() == _BODY[-10:]
        assert stream.seek(3) == 3
        assert stream.read(2) == _BODY[3:5]


class Raw:
    """A raw stream: ``write`` takes at most ``limit`` bytes at a time and says how many."""

    def __init__(self, limit: int) -> None:
        """Take at most ``limit`` bytes per ``write``."""
        self.limit = limit
        self.data = b""

    def write(self, chunk: bytes) -> int:
        """Keep what fits and say how much that was."""
        taken = chunk[: self.limit]
        self.data += taken
        return len(taken)


def test_a_partial_write_is_written_to_the_end() -> None:
    with scripted_server(file_server(len(_BODY), serves(_BODY))) as (url, _rec):
        raw = Raw(limit=1000)
        FileSystem(url).download_fileobj("/f", raw, chunk_size=4096)  # type: ignore[arg-type]
        assert raw.data == _BODY


class Silent:
    """A file object whose ``write`` returns nothing (many wrappers)."""

    def __init__(self) -> None:
        """Start empty."""
        self.data = b""

    def write(self, chunk: bytes) -> None:
        """Keep ``chunk`` and return nothing."""
        self.data += chunk


def test_a_write_that_returns_none_counts_as_complete() -> None:
    with scripted_server(file_server(len(_BODY), serves(_BODY))) as (url, _rec):
        silent = Silent()
        FileSystem(url).download_fileobj("/f", silent)  # type: ignore[arg-type]
        assert silent.data == _BODY


def test_a_file_object_that_takes_nothing_is_an_error_not_an_endless_loop() -> None:
    with (
        scripted_server(file_server(len(_BODY), serves(_BODY))) as (url, _rec),
        pytest.raises(OSError, match="accepted no more data"),
    ):
        FileSystem(url).download_fileobj("/f", Raw(limit=0))  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("bytes 0-9/20", (0, 9, 20)),
        ("bytes 10-19/*", (10, 19, None)),
        ("bytes 5-5/6", (5, 5, 6)),
        ("bytes 0-9/5", None),  # last beyond the total
        ("bytes 10-99999/1", None),
        ("bytes 10-5/20", None),
        ("bytes 10-/20", None),
        ("bytes -5/20", None),
        ("bytes 10-19", None),
        ("bytes */20", None),
        ("items 0-9/20", None),
        ("bytes  0-9/20", None),
        ("bytes 0 -9/20", None),
        ("bytes +0-9/20", None),
        ("bytes 0-9/2x", None),
        ("", None),
        (None, None),
    ],
)
def test_content_range_is_parsed_whole(
    value: "str | None", expected: "tuple[int, int, int | None] | None"
) -> None:
    assert parse_content_range(value) == expected


def _resumed_with(content_range: str) -> "Callable[[Seen], Reply]":
    """A first answer cut off after 10 of 20 bytes, and a resumed one with ``content_range``."""
    data = bytes(range(20))

    def on_get(seen: Seen) -> Reply:
        if "range" not in seen.headers:
            headers = {
                "ETag": '"v"',
                "Accept-Ranges": "bytes",
                NO_CONTENT_LENGTH: "1",
                "Content-Length": "20",
            }
            return 200, headers, data[:10]
        return 206, {"ETag": '"v"', "Content-Range": content_range}, data[10:]

    return file_server(20, on_get)


@pytest.mark.parametrize(
    "content_range",
    ["bytes 10-99999/1", "bytes 10-19/5", "bytes 10-5/20", "bytes 10-/20"],
)
def test_a_resumed_response_with_a_wrong_content_range_is_refused(
    content_range: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("webdav.fs.streams.RESUME_BACKOFF_SECONDS", 0.01)
    with (
        scripted_server(_resumed_with(content_range)) as (url, _rec),
        pytest.raises(ClientError, match="Content-Range"),
    ):
        FileSystem(url).download_fileobj("/f", io.BytesIO())


@pytest.mark.parametrize("content_range", ["bytes 10-19/20", "bytes 10-19/*"])
def test_a_resumed_response_with_a_right_content_range_is_taken(
    content_range: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("webdav.fs.streams.RESUME_BACKOFF_SECONDS", 0.01)
    with scripted_server(_resumed_with(content_range)) as (url, _rec):
        sink = Sink()
        FileSystem(url).download_fileobj("/f", sink)  # type: ignore[arg-type]
        assert sink.data == bytes(range(20))


@pytest.mark.parametrize(
    "content_range",
    ["bytes 0-9/5", "bytes 0-9/20", "bytes 0-4/x", "bytes 1-4/20", "0-4/20"],
)
def test_a_block_with_a_wrong_content_range_is_refused(content_range: str) -> None:
    reply = (206, {"Content-Range": content_range}, b"abcde")
    with (
        scripted_server(file_server(20, lambda _s: reply)) as (url, _rec),
        pytest.raises(ClientError, match="Content-Range"),
    ):
        fetch_range(Session(url, retry=False), "/f", 0, 5, total=20)


def test_a_block_with_the_right_content_range_is_taken() -> None:
    reply = (206, {"Content-Range": "bytes 0-4/20"}, b"abcde")
    with scripted_server(file_server(20, lambda _s: reply)) as (url, _rec):
        assert (
            fetch_range(Session(url, retry=False), "/f", 0, 5, total=20).data
            == b"abcde"
        )
