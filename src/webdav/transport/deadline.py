"""One deadline for a whole request - headers, body and trailers included.

``timeout=`` in ``requests`` limits each single socket operation, so a server
that sends one byte just inside it - a trickle of header lines, an endless
run of ``100 Continue`` interim responses, chunked-body trailers that never
end - keeps a request alive for as long as it likes.

This module closes that gap without a thread of its own. The connections of
the adapters in this package (:class:`DeadlineAdapter`) look at the
:func:`watch` that is active in the calling context before every blocking
socket operation, and cap that socket's timeout to what is left of the
deadline. Every single wait then ends at the deadline at the latest, so the
sum of them does too. Three places cover every byte of an exchange:

- the TCP connect and (on ``https://``) the TLS handshake of a new
  connection (:meth:`_TrackedConnectionMixin._new_conn`),
- every piece of the request that is sent (:meth:`_TrackedConnectionMixin.send`),
- every read of the response - status line, headers, interim responses,
  body and trailers, and the answer of a proxy to ``CONNECT`` - through
  the file object ``http.client`` reads them from (:class:`_DeadlineReader`).

Through an ``https://`` proxy to an ``https://`` origin, ``urllib3`` runs
the inner TLS connection in Python (``SSLTransport``), looping over many
``recv()``/``sendall()`` calls for one read or write; :class:`_HeldSocket`
holds each of those to the deadline as well.
"""

import contextvars
import http.client
import io
import socket
import time
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, cast

from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool

from webdav.exceptions import ClientError
from webdav.response import Response

if TYPE_CHECKING:
    from collections.abc import Iterator

    from requests import PreparedRequest

_ACTIVE: "contextvars.ContextVar[_Watch | None]" = contextvars.ContextVar(
    "webdav_deadline_watch", default=None
)


class _Watch:
    """A point in time by which every socket operation in its block must be done."""

    def __init__(self, seconds: float) -> None:
        self._deadline = time.monotonic() + seconds

    @property
    def expired(self) -> bool:
        """Whether the time is up."""
        return time.monotonic() >= self._deadline

    def capped(self, timeout: object) -> float:
        """``timeout`` (``None``: no limit), but never past the deadline.

        Raises :class:`TimeoutError` - what a socket that timed out raises -
        when nothing is left: a timeout of ``0`` would not wait, it would
        switch the socket to non-blocking mode, and a read from that would
        report "no data yet" instead of failing.
        """
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            msg = "the deadline for this request has passed"
            raise TimeoutError(msg)
        if isinstance(timeout, int | float):
            return min(timeout, remaining)
        return remaining

    def bound(self, sock: Any, timeout: object) -> None:
        """Set ``sock``'s timeout to ``timeout``, but no later than the deadline."""
        sock.settimeout(self.capped(timeout))


def _bound(sock: Any, timeout: object) -> None:
    """Give ``sock`` ``timeout``, capped by the :func:`watch` active here (if any)."""
    watcher = _ACTIVE.get()
    if watcher is None:
        sock.settimeout(timeout)
    else:
        watcher.bound(sock, timeout)


@contextmanager
def watch(seconds: "float | None") -> "Iterator[_Watch | None]":
    """Hold every connection used inside the block to a deadline ``seconds`` from now.

    ``None`` means no deadline. Yields the watch (``.expired`` says whether
    the time is up, to tell a timed-out connection from an ordinary network
    error), or ``None`` when there is none - and also when one is already
    active in this context, so the outermost, longest-lived deadline is the
    one that counts.
    """
    if seconds is None or _ACTIVE.get() is not None:
        yield None
        return
    token = _ACTIVE.set(_Watch(seconds))
    try:
        yield _ACTIVE.get()
    finally:
        _ACTIVE.reset(token)


@contextmanager
def enforce(seconds: "float | None") -> "Iterator[None]":
    """:func:`watch` the block, and turn a missed deadline into a :class:`~webdav.exceptions.ClientError`.

    Two things must not be left to the caller to remember. An exception that
    escapes while the time is up is the deadline talking, not a network
    error - say so. And a block that *returns* after the time is up has
    not met the deadline either, whatever it read.

    Nested, the outermost deadline is the one that counts (see :func:`watch`).
    """
    with watch(seconds) as watcher:
        try:
            yield
        except BaseException:
            if watcher is not None and watcher.expired:
                raise _deadline_error(seconds) from None
            raise
        if watcher is not None and watcher.expired:
            raise _deadline_error(seconds)


def _deadline_error(seconds: "float | None") -> ClientError:
    return ClientError(
        f"the request did not complete within the configured time of {seconds} seconds"
    )


class _DeadlineReader(io.RawIOBase):
    """The socket reader ``http.client`` reads a response from, held to :func:`watch`.

    Each read first sets the socket's timeout: the one ``urllib3`` gave it
    for reading, capped by the deadline active at that moment. Outside a
    :func:`watch` (a streamed body read after the request returned) that is
    the plain read timeout again.
    """

    def __init__(self, raw: io.RawIOBase, sock: Any) -> None:
        super().__init__()
        self._raw = raw
        self._sock = sock
        self._timeout = sock.gettimeout()

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> "int | None":
        _bound(self._sock, self._timeout)
        return self._raw.readinto(buffer)

    def fileno(self) -> int:
        return self._raw.fileno()

    def close(self) -> None:
        try:
            self._raw.close()
        finally:
            super().close()


class _DeadlineHTTPResponse(http.client.HTTPResponse):
    """An ``http.client`` response whose every read is held to :func:`watch`."""

    def __init__(self, sock: Any, *args: Any, **kwargs: Any) -> None:
        super().__init__(sock, *args, **kwargs)
        # Nothing has been read yet, so the buffer is empty and can be
        # replaced; its raw reader carries over (and with it, the socket's
        # reference count that closing it gives back).
        raw = self.fp.detach()
        self.fp = io.BufferedReader(_DeadlineReader(raw, sock))


def _hold(sock: Any) -> None:
    """Cap ``sock``'s current timeout to the active :func:`watch` (if any)."""
    watcher = _ACTIVE.get()
    if watcher is not None:
        watcher.bound(sock, sock.gettimeout())


class _HeldSocket:
    """The socket under ``urllib3``'s ``SSLTransport`` (TLS inside TLS), held to :func:`watch`.

    ``SSLTransport`` calls ``recv()`` and ``sendall()`` on it in a loop for
    a single read, write or handshake; each call is capped here. Within one
    deadline, a timeout capped by an earlier call is never shorter than
    what is left now, so capping the socket's current timeout is enough;
    the read timeout itself is set again through ``settimeout()`` (passed
    on unchanged) by ``urllib3`` and :class:`_DeadlineReader`.
    """

    def __init__(self, sock: Any) -> None:
        self._sock = sock

    def __getattr__(self, name: str) -> Any:
        return getattr(self._sock, name)

    def recv(self, bufsize: int, flags: int = 0) -> bytes:
        """``recv()`` on the wrapped socket, within what is left of the deadline."""
        _hold(self._sock)
        return cast("bytes", self._sock.recv(bufsize, flags))

    def sendall(self, data: Any, flags: int = 0) -> None:
        """Send all of ``data``, each ``send()`` within what is left of the deadline."""
        with memoryview(data) as view, view.cast("B") as octets:
            sent = 0
            while sent < len(octets):
                _hold(self._sock)
                sent += self._sock.send(octets[sent:], flags)


class _TrackedConnectionMixin:
    """Holds every blocking operation of a connection to the active :func:`watch`."""

    def send(self, data: Any) -> None:
        """Send ``data``, each piece within what is left of the deadline.

        ``sendall()`` would apply one timeout per call (and an
        ``SSLSocket``'s, one per internal ``send()``), so a server that
        accepts one byte at a time could stretch it out. ``urllib3`` only
        ever hands bytes here; anything else goes to ``http.client`` as is.
        """
        sock = getattr(self, "sock", None)
        if (
            sock is None
            or _ACTIVE.get() is None
            or not isinstance(data, bytes | bytearray | memoryview)
        ):
            super().send(data)  # type: ignore[misc]
            return
        timeout = getattr(self, "timeout", None)
        with memoryview(data) as view, view.cast("B") as octets:
            sent = 0
            while sent < len(octets):
                _bound(sock, timeout)
                sent += sock.send(octets[sent:])

    def _new_conn(self) -> socket.socket:
        """Open the socket, the TCP connect and TLS handshake held to the deadline.

        ``urllib3`` connects inside this call, with ``self.timeout`` - capped
        here for that. The TLS handshake follows on the returned socket in
        a single ``wrap_socket()`` call; :class:`ssl.SSLSocket` copies the
        wrapped socket's timeout when it is created, so capping that one
        again (time has passed) holds the handshake to the deadline too.
        """
        watcher = _ACTIVE.get()
        if watcher is None:
            return cast("socket.socket", super()._new_conn())  # type: ignore[misc]
        connection: Any = self
        timeout = connection.timeout
        connection.timeout = watcher.capped(timeout)
        try:
            sock = cast("socket.socket", super()._new_conn())  # type: ignore[misc]
        finally:
            connection.timeout = timeout
        watcher.bound(sock, sock.gettimeout())
        return sock


class _TrackedHTTPConnection(_TrackedConnectionMixin, HTTPConnection):
    response_class = _DeadlineHTTPResponse


class _TrackedHTTPSConnection(_TrackedConnectionMixin, HTTPSConnection):
    response_class = _DeadlineHTTPResponse

    def _connect_tls_proxy(self, hostname: str, sock: socket.socket) -> Any:
        """Connect to an ``https://`` proxy; the result carries the TLS connection to the origin."""
        return _HeldSocket(super()._connect_tls_proxy(hostname, sock))


class _HTTPPool(HTTPConnectionPool):
    ConnectionCls = _TrackedHTTPConnection


class _HTTPSPool(HTTPSConnectionPool):
    ConnectionCls = _TrackedHTTPSConnection


_POOL_CLASSES: dict[str, Any] = {"http": _HTTPPool, "https": _HTTPSPool}


class DeadlineAdapter(HTTPAdapter):
    """An ``HTTPAdapter`` whose connections answer to :func:`watch`.

    Every adapter this library ever mounts or uses standalone
    (:class:`~webdav.transport.tls.SSLContextAdapter`, the credential-stripped
    cross-origin adapter a :class:`~webdav.session.Session` keeps for
    redirects) is one of these, so :meth:`build_response` is the one place a
    :class:`~webdav.response.Response` - not a bare :class:`requests.Response`
    - comes from, for every request this library ever sends.
    """

    def __init__(
        self, *args: Any, response_class: type[Response] = Response, **kwargs: Any
    ) -> None:
        """Store which :class:`~webdav.response.Response` (sub)class to build - see :meth:`build_response`."""
        self._response_class = response_class
        super().__init__(*args, **kwargs)

    def build_response(self, req: "PreparedRequest", resp: Any) -> Response:
        """Build a :class:`~webdav.response.Response`, not a plain :class:`requests.Response`.

        Overriding this - not reclassifying afterwards - is what
        :class:`~requests.adapters.HTTPAdapter` itself documents as the way
        to customise the response type; see its own docstring ("only
        exposed for use when subclassing"). Delegates to ``requests``' own
        population logic first (status, headers, encoding, cookies, ...) so
        a future ``requests`` version's improvements to it are not silently
        missed, and only changes the resulting object's class - in place,
        so the connection/stream it holds is unaffected.
        """
        response = super().build_response(req, resp)
        response.__class__ = self._response_class
        return cast("Response", response)

    def init_poolmanager(self, *args: Any, **kwargs: Any) -> None:
        """Build the pool manager, with tracked connections."""
        super().init_poolmanager(*args, **kwargs)
        self.poolmanager.pool_classes_by_scheme = dict(_POOL_CLASSES)

    def proxy_manager_for(self, *args: Any, **kwargs: Any) -> Any:
        """Build a proxy pool manager, with tracked connections."""
        manager = super().proxy_manager_for(*args, **kwargs)
        manager.pool_classes_by_scheme = dict(_POOL_CLASSES)
        return manager
