"""Hardening of the transport, the streams and the download path.

One block per behaviour; each has a test of the misbehaviour and one of the behaviour that
has always been right and must stay so.
"""

import gzip
import io
import socket
import threading
import tracemalloc
import types
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
from webdav import FileSystem, RedirectPolicy, Session
from webdav.exceptions import ClientError
from webdav.fs.streams import IterStream
from webdav.fsspec import WebdavFileSystem
from webdav.transport import retry as retry_module
from webdav.transport.deadline import DeadlineAdapter

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
# the headers of a response have a size limit
# ---------------------------------------------------------------------------


def _with_headers(
    count: int, size: int
) -> "Callable[[RawServer, socket.socket, Seen], None]":
    def handler(_server: RawServer, conn: socket.socket, _seen: Seen) -> None:
        lines = b"".join(b"X-%d: %s\r\n" % (i, b"a" * size) for i in range(count))
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n" + lines + b"\r\nok")

    return handler


def test_headers_of_two_megabytes_are_refused() -> None:
    with raw_server(_with_headers(30, 65_000)) as server:
        with pytest.raises(ClientError, match="response headers are larger"):
            Session().get(f"{server.url}/x")


@pytest.mark.parametrize(("count", "size"), [(1, 16_000), (14, 64_000)])
def test_large_but_reasonable_headers_go_through(count: int, size: int) -> None:
    with raw_server(_with_headers(count, size)) as server:
        assert Session().get(f"{server.url}/x").text == "ok"


# ---------------------------------------------------------------------------
# skipping forward does not buffer what is skipped
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# an address urllib3 cannot parse is an InvalidURL
# ---------------------------------------------------------------------------


def test_a_redirect_to_an_unparseable_host_is_an_invalid_url() -> None:
    with scripted_server(lambda _s: (302, {"Location": "http://a..b/"}, b"")) as (
        url,
        _rec,
    ):
        session = Session(redirect_policy=RedirectPolicy.ALL, retry=False)
        with pytest.raises(requests.exceptions.InvalidURL) as excinfo:
            session.get(f"{url}/x")
    assert isinstance(excinfo.value, ValueError)


def test_the_adapter_turns_a_location_error_into_an_invalid_url() -> None:
    prepared = requests.Request("GET", "http://a..b/").prepare()
    with pytest.raises(requests.exceptions.InvalidURL):
        DeadlineAdapter().send(prepared, timeout=1)


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


# ---------------------------------------------------------------------------
# the corners of IterStream
# ---------------------------------------------------------------------------


def _stream(url: str, session: Session) -> IterStream:
    return IterStream(session, f"{url}/f", chunk_size=100)


def test_seeking_and_reading_an_open_stream_still_works() -> None:
    with scripted_server(file_server(len(_BODY), serves(_BODY))) as (url, _rec):
        with _stream(url, Session(url)) as stream:
            assert stream.seek(10) == 10
            assert stream.read(5) == _BODY[10:15]
            assert stream.seek(5, 1) == 20
            assert stream.read(5) == _BODY[20:25]
            assert stream.seek(-10, 2) == len(_BODY) - 10
            assert stream.read() == _BODY[-10:]
            assert stream.seek(3) == 3
            assert stream.read(2) == _BODY[3:5]


# ---------------------------------------------------------------------------
# Content-Range is checked as a whole
# ---------------------------------------------------------------------------


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
    from webdav.transport.parse_utils import parse_content_range  # noqa: PLC0415

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
    with scripted_server(_resumed_with(content_range)) as (url, _rec):
        with pytest.raises(ClientError, match="Content-Range"):
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
    from webdav._fsspec_ranges import fetch_range  # noqa: PLC0415

    reply = (206, {"Content-Range": content_range}, b"abcde")
    with scripted_server(file_server(20, lambda _s: reply)) as (url, _rec):
        with pytest.raises(ClientError, match="Content-Range"):
            fetch_range(Session(url, retry=False), "/f", 0, 5, total=20)


def test_a_block_with_the_right_content_range_is_taken() -> None:
    from webdav._fsspec_ranges import fetch_range  # noqa: PLC0415

    reply = (206, {"Content-Range": "bytes 0-4/20"}, b"abcde")
    with scripted_server(file_server(20, lambda _s: reply)) as (url, _rec):
        assert (
            fetch_range(Session(url, retry=False), "/f", 0, 5, total=20).data
            == b"abcde"
        )


# ---------------------------------------------------------------------------
# a certificate that fails verification is not tried again
# ---------------------------------------------------------------------------


def _verification_error() -> requests.exceptions.SSLError:
    cause = ssl.SSLCertVerificationError(
        1, "certificate verify failed: self-signed certificate"
    )
    low = urllib3.exceptions.SSLError(cause)
    pool = urllib3.exceptions.MaxRetryError(None, "https://x/", low)  # type: ignore[arg-type]
    return requests.exceptions.SSLError(pool)


def _handshake_cut_off() -> requests.exceptions.SSLError:
    cause = ssl.SSLEOFError(8, "EOF occurred in violation of protocol")
    return requests.exceptions.SSLError(urllib3.exceptions.SSLError(cause))


@pytest.mark.parametrize(
    ("error", "calls"),
    [(_verification_error, 1), (_handshake_cut_off, 3)],
)
def test_only_a_failed_certificate_check_is_not_retried(
    error: "Callable[[], Exception]", calls: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        retry_module, "time", types.SimpleNamespace(sleep=lambda _s: None)
    )
    count = 0

    def attempt() -> None:
        nonlocal count
        count += 1
        raise error()

    with pytest.raises(requests.exceptions.SSLError):
        retry_module.retry(enabled=True)(attempt)
    assert count == calls


def test_an_untrusted_server_certificate_is_one_handshake_not_three(
    tmp_path: Path,
) -> None:
    from tests.certificates import Certificates  # noqa: PLC0415

    certs = Certificates(tmp_path)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(certs.server_cert), str(certs.server_key))
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(10)
    accepted = 0

    def serve() -> None:
        nonlocal accepted
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            accepted += 1
            try:
                context.wrap_socket(conn, server_side=True).close()
            except OSError:
                conn.close()

    threading.Thread(target=serve, daemon=True).start()
    try:
        with pytest.raises(requests.exceptions.SSLError):
            Session(f"https://127.0.0.1:{listener.getsockname()[1]}").get("/x")
    finally:
        listener.close()
    assert accepted == 1
