"""The whole-request deadline against servers that stretch a request out on purpose.

Every server here keeps each single socket operation well inside the
per-read ``timeout=``; only the deadline over the whole request stops it.
"""

import contextlib
import socket
import ssl
import threading
import time
from typing import TYPE_CHECKING

import pytest
import requests

from tests.certificates import Certificates
from webdav import Session
from webdav.exceptions import ClientError

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator


@contextlib.contextmanager
def raw_server(handler: "Callable[[socket.socket], None]") -> "Iterator[str]":
    """A TCP server that hands every accepted connection to ``handler``."""
    listener = socket.create_server(("127.0.0.1", 0))
    listener.settimeout(0.2)
    stop = threading.Event()
    workers: list[threading.Thread] = []

    def serve() -> None:
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return

            def run(c: socket.socket = conn) -> None:
                with contextlib.suppress(OSError), c:
                    handler(c)

            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            workers.append(worker)

    acceptor = threading.Thread(target=serve, daemon=True)
    acceptor.start()
    try:
        yield f"http://127.0.0.1:{listener.getsockname()[1]}"
    finally:
        stop.set()
        acceptor.join(2)
        listener.close()


def _read_request_head(conn: socket.socket) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(65536)
        if not chunk:
            break
        data += chunk
    return data


def _drip(conn: socket.socket, data: bytes, pause: float, limit: float = 10) -> None:
    """Send ``data`` one byte per ``pause`` seconds, for at most ``limit`` seconds."""
    end = time.monotonic() + limit
    for i in range(len(data)):
        if time.monotonic() > end:
            return
        conn.sendall(data[i : i + 1])
        time.sleep(pause)


def _session(max_time: float) -> Session:
    session = Session(retry=False, timeout=2)
    session.max_response_time = max_time
    return session


def _assert_cut_off(call: "Callable[[], object]", max_time: float) -> None:
    started = time.monotonic()
    with pytest.raises(ClientError, match="did not complete within"):
        call()
    assert time.monotonic() - started < max_time + 1.0


# ---------------------------------------------------------------------------
# Every part of an exchange is held to the deadline
# ---------------------------------------------------------------------------


def test_header_lines_that_trickle_in_are_cut_off() -> None:
    def handler(conn: socket.socket) -> None:
        _read_request_head(conn)
        conn.sendall(b"HTTP/1.1 200 OK\r\n")
        _drip(conn, b"X-Slow: " + b"a" * 500 + b"\r\n", 0.05)

    with raw_server(handler) as url:
        _assert_cut_off(lambda: _session(0.5).get(f"{url}/x"), 0.5)


def test_an_endless_run_of_100_continue_is_cut_off() -> None:
    def handler(conn: socket.socket) -> None:
        _read_request_head(conn)
        end = time.monotonic() + 10
        while time.monotonic() < end:
            conn.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
            time.sleep(0.05)

    with raw_server(handler) as url:
        _assert_cut_off(lambda: _session(0.5).get(f"{url}/x"), 0.5)


def test_chunked_trailers_that_never_end_are_cut_off() -> None:
    def handler(conn: socket.socket) -> None:
        _read_request_head(conn)
        conn.sendall(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n"
        )
        end = time.monotonic() + 10
        while time.monotonic() < end:
            conn.sendall(b"X-Trailer: 1\r\n")
            time.sleep(0.05)

    with raw_server(handler) as url:
        _assert_cut_off(lambda: _session(0.5).get(f"{url}/x"), 0.5)


def test_a_status_line_that_trickles_in_is_cut_off() -> None:
    def handler(conn: socket.socket) -> None:
        _read_request_head(conn)
        _drip(conn, b"HTTP/1.1 200 OK" + b" " * 2000, 0.05)

    with raw_server(handler) as url:
        _assert_cut_off(lambda: _session(0.5).get(f"{url}/x"), 0.5)


def test_an_upload_the_server_reads_slowly_is_cut_off() -> None:
    """Each piece goes through well inside the read timeout; all of them together do not."""

    def handler(conn: socket.socket) -> None:
        end = time.monotonic() + 10
        while time.monotonic() < end:
            if not conn.recv(4096):
                return
            time.sleep(0.02)

    def body() -> "Iterator[bytes]":
        for _ in range(1000):
            yield b"x" * 65536

    with raw_server(handler) as url:
        _assert_cut_off(lambda: _session(0.8).put(f"{url}/x", data=body()), 0.8)


def test_a_single_large_upload_the_server_reads_slowly_is_cut_off() -> None:
    def handler(conn: socket.socket) -> None:
        end = time.monotonic() + 10
        while time.monotonic() < end:
            if not conn.recv(4096):
                return
            time.sleep(0.02)

    with raw_server(handler) as url:
        _assert_cut_off(
            lambda: _session(0.8).put(f"{url}/x", data=b"x" * (64 * 1024 * 1024)), 0.8
        )


def test_a_stalled_tls_handshake_is_cut_off() -> None:
    def handler(conn: socket.socket) -> None:
        conn.recv(65536)  # the ClientHello; no ServerHello ever comes
        time.sleep(10)

    with raw_server(handler) as url:
        https = url.replace("http://", "https://")
        session = Session(retry=False, timeout=5)
        session.max_response_time = 0.5
        _assert_cut_off(lambda: session.get(f"{https}/x"), 0.5)


def test_a_proxy_that_trickles_its_answer_to_connect_is_cut_off() -> None:
    def handler(conn: socket.socket) -> None:
        head = _read_request_head(conn)
        assert head.startswith(b"CONNECT ")
        conn.sendall(b"HTTP/1.1 200 Connection established\r\n")
        _drip(conn, b"X-Slow: " + b"a" * 500 + b"\r\n", 0.05)

    with raw_server(handler) as proxy:
        session = _session(0.5)
        session.trust_env = False
        _assert_cut_off(
            lambda: session.get("https://webdav.invalid/x", proxies={"https": proxy}),
            0.5,
        )


def test_the_deadline_covers_a_body_read_by_request_and_not_streamed() -> None:
    def handler(conn: socket.socket) -> None:
        _read_request_head(conn)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n")
        _drip(conn, b"x" * 1000, 0.05)

    with raw_server(handler) as url:
        _assert_cut_off(lambda: _session(0.5).get(f"{url}/x"), 0.5)


# ---------------------------------------------------------------------------
# What the deadline leaves alone
# ---------------------------------------------------------------------------


def test_a_streamed_body_read_after_the_request_returned_uses_the_read_timeout() -> (
    None
):
    """The deadline covers getting the headers; reading on is the caller's business."""

    def handler(conn: socket.socket) -> None:
        _read_request_head(conn)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n")
        _drip(conn, b"y" * 20, 0.05)

    with raw_server(handler) as url:
        session = _session(0.3)
        response = session.get(f"{url}/x", stream=True)
        assert response.raw.read() == b"y" * 20  # ~1 s, well past the deadline


def test_a_pooled_connection_is_usable_after_a_request_close_to_its_deadline() -> None:
    def handler(conn: socket.socket) -> None:
        for delay in (0.4, 0.0, 0.0):
            _read_request_head(conn)
            time.sleep(delay)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

    with raw_server(handler) as url:
        session = _session(0.5)
        for _ in range(3):
            assert session.get(f"{url}/x").content == b"ok"


def test_a_slow_but_steady_streamed_response_is_not_affected_by_a_stale_cap() -> None:
    """A capped socket timeout from inside the deadline must not shorten a later read."""

    def handler(conn: socket.socket) -> None:
        _read_request_head(conn)
        time.sleep(0.25)  # the headers come late: the cap is tiny by then
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n")
        time.sleep(0.6)  # longer than what was left, shorter than timeout=2
        conn.sendall(b"ok")

    with raw_server(handler) as url:
        response = _session(0.3).get(f"{url}/x", stream=True)
        assert response.raw.read() == b"ok"


def test_an_ordinary_network_error_is_not_reported_as_the_deadline() -> None:
    with socket.create_server(("127.0.0.1", 0)) as s:
        port = s.getsockname()[1]
    with pytest.raises(requests.exceptions.ConnectionError):
        _session(30).get(f"http://127.0.0.1:{port}/x")


def test_a_large_upload_and_download_within_the_deadline_arrive_intact() -> None:
    payload = bytes(range(256)) * 40000  # ~10 MB

    def handler(conn: socket.socket) -> None:
        head = _read_request_head(conn)
        header, _, rest = head.partition(b"\r\n\r\n")
        length = int(
            next(
                line.split(b":")[1]
                for line in header.split(b"\r\n")
                if line.lower().startswith(b"content-length")
            )
        )
        got = bytearray(rest)
        while len(got) < length:
            got += conn.recv(65536)
        conn.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(got) + bytes(got)
        )

    with raw_server(handler) as url:
        session = _session(30)
        session.max_response_size = None
        assert session.put(f"{url}/x", data=payload).content == payload


def test_no_thread_is_started_for_the_deadline() -> None:
    def handler(conn: socket.socket) -> None:
        _read_request_head(conn)
        conn.sendall(
            b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok"
        )

    with raw_server(handler) as url:
        session = _session(5)
        client = threading.current_thread()
        started_here: list[threading.Thread] = []
        original = threading.Thread.start

        def spy(self: threading.Thread) -> None:
            if threading.current_thread() is client:
                started_here.append(self)
            original(self)

        threading.Thread.start = spy  # type: ignore[method-assign]
        try:
            assert session.get(f"{url}/x").content == b"ok"
            assert session.put(f"{url}/x", data=b"abc").content == b"ok"
        finally:
            threading.Thread.start = original  # type: ignore[method-assign]
        assert [(t.name, getattr(t, "_target", None)) for t in started_here] == []


# ---------------------------------------------------------------------------
# TLS, and TLS inside TLS (an https:// proxy to an https:// origin)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def certs(tmp_path_factory: pytest.TempPathFactory) -> Certificates:
    return Certificates(tmp_path_factory.mktemp("deadline-certs"))


def _server_context(certs: Certificates) -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(certs.server_cert, certs.server_key)
    return ctx


def test_https_within_the_deadline_works(certs: Certificates) -> None:
    ctx = _server_context(certs)

    def handler(conn: socket.socket) -> None:
        with ctx.wrap_socket(conn, server_side=True) as tls:
            for _ in range(2):
                _read_request_head(tls)
                tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

    with raw_server(handler) as url:
        session = _session(5)
        https = url.replace("http://", "https://")
        for _ in range(2):
            got = session.get(f"{https}/x", verify=str(certs.ca_cert))
            assert got.content == b"ok"


def test_a_trickled_body_over_https_is_cut_off(certs: Certificates) -> None:
    ctx = _server_context(certs)

    def handler(conn: socket.socket) -> None:
        with ctx.wrap_socket(conn, server_side=True) as tls:
            _read_request_head(tls)
            tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n")
            _drip(tls, b"x" * 1000, 0.05)

    with raw_server(handler) as url:
        session = _session(0.5)
        https = url.replace("http://", "https://")
        _assert_cut_off(
            lambda: session.get(f"{https}/x", verify=str(certs.ca_cert)), 0.5
        )


def _tls_proxy(
    certs: Certificates, after_connect: "Callable[[ssl.SSLSocket], None]"
) -> "Callable[[socket.socket], None]":
    """An https:// proxy that answers CONNECT and then hands over to ``after_connect``."""
    ctx = _server_context(certs)

    def handler(conn: socket.socket) -> None:
        with ctx.wrap_socket(conn, server_side=True) as outer:
            head = _read_request_head(outer)  # type: ignore[arg-type]
            assert head.startswith(b"CONNECT ")
            outer.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            after_connect(outer)

    return handler


def test_an_inner_tls_handshake_trickled_through_an_https_proxy_is_cut_off(
    certs: Certificates,
) -> None:
    """``urllib3`` runs TLS inside TLS in Python, one ``recv()`` after another."""
    ctx = _server_context(certs)

    def origin(outer: ssl.SSLSocket) -> None:
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        inner = ctx.wrap_bio(incoming, outgoing, server_side=True)
        incoming.write(outer.recv(65536))  # the ClientHello
        with contextlib.suppress(ssl.SSLWantReadError):
            inner.do_handshake()
        _drip(outer, outgoing.read(), 0.05)  # ServerHello etc., byte by byte

    with raw_server(_tls_proxy(certs, origin)) as proxy:
        session = _session(0.8)
        session.trust_env = False
        https_proxy = proxy.replace("http://", "https://")
        _assert_cut_off(
            lambda: session.get(
                "https://127.0.0.1:9/x",
                proxies={"https": https_proxy},
                verify=str(certs.ca_cert),
            ),
            0.8,
        )


def test_a_body_trickled_through_an_https_proxy_tunnel_is_cut_off(
    certs: Certificates,
) -> None:
    ctx = _server_context(certs)

    def origin(outer: ssl.SSLSocket) -> None:
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        inner = ctx.wrap_bio(incoming, outgoing, server_side=True)

        def pump() -> None:
            out = outgoing.read()
            if out:
                outer.sendall(out)

        while True:
            try:
                inner.do_handshake()
                break
            except ssl.SSLWantReadError:
                pump()
                incoming.write(outer.recv(65536))
        pump()
        data = b""
        while b"\r\n\r\n" not in data:
            try:
                data += inner.read(65536)
            except ssl.SSLWantReadError:
                pump()
                incoming.write(outer.recv(65536))
        inner.write(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n")
        pump()
        end = time.monotonic() + 10
        for _ in range(1000):
            if time.monotonic() > end:
                return
            inner.write(b"x")
            pump()
            time.sleep(0.05)

    with raw_server(_tls_proxy(certs, origin)) as proxy:
        session = _session(1.0)
        session.trust_env = False
        https_proxy = proxy.replace("http://", "https://")
        _assert_cut_off(
            lambda: session.get(
                "https://127.0.0.1:9/x",
                proxies={"https": https_proxy},
                verify=str(certs.ca_cert),
            ),
            1.0,
        )
