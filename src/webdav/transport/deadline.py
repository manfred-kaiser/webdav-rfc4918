"""One deadline for a whole request - headers, body and trailers included.

``timeout=`` in ``requests`` limits each single socket operation, so a server
that sends one byte just inside it - a trickle of header lines, an endless
run of ``100 Continue`` interim responses, chunked-body trailers that never
end - keeps a request alive for as long as it likes. The only thing that
stops that is somebody else looking at the clock and pulling the plug.

That is what this module does. The connections of the adapters in this package
(:class:`DeadlineAdapter`) report themselves to the :func:`watch` that is
active in the calling context when they start an exchange; when the time is up
the watchdog shuts their sockets down, which wakes whatever read is blocked
on them - wherever inside ``http.client`` it is.
"""

import contextvars
import socket
import threading
from contextlib import contextmanager, suppress
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
    """A timer that shuts down every socket registered with it when it expires."""

    def __init__(self, seconds: float) -> None:
        self.expired = threading.Event()
        self._sockets: list[socket.socket] = []
        self._mutex = threading.Lock()
        self._timer = threading.Timer(seconds, self._expire)
        self._timer.daemon = True

    def start(self) -> None:
        """Start the clock."""
        self._timer.start()

    def cancel(self) -> None:
        """Stop the clock; the request finished in time."""
        self._timer.cancel()

    def track(self, connection: Any) -> None:
        """Watch the socket of ``connection`` from now on (cut it at once if the time is up).

        The *socket* is what is kept, not the connection: once a response
        that closes the connection has been read, ``http.client`` lets go of
        ``connection.sock`` while the response still reads from it.
        """
        sock = getattr(connection, "sock", None)
        if sock is None:
            return  # not connected yet; tracked again when it is (getresponse)
        with self._mutex:
            if all(s is not sock for s in self._sockets):
                self._sockets.append(sock)
            expired = self.expired.is_set()
        if expired:
            _cut_off(sock)

    def _expire(self) -> None:
        self.expired.set()
        with self._mutex:
            sockets = list(self._sockets)
        for sock in sockets:
            _cut_off(sock)


def _cut_off(sock: socket.socket) -> None:
    """Shut ``sock`` down, waking any thread blocked reading it."""
    with suppress(OSError):  # already closed: nothing left to wake
        sock.shutdown(socket.SHUT_RDWR)


@contextmanager
def watch(seconds: "float | None") -> "Iterator[_Watch | None]":
    """Cut off every connection used inside the block once ``seconds`` have passed.

    ``None`` means no deadline. Yields the watch (``.expired`` says whether it
    fired, to tell a cut-off connection from an ordinary network error), or
    ``None`` when there is none - and also when one is already active in this
    context, so the outermost, longest-lived deadline is the one that counts.
    """
    if seconds is None or _ACTIVE.get() is not None:
        yield None
        return
    watcher = _Watch(seconds)
    token = _ACTIVE.set(watcher)
    watcher.start()
    try:
        yield watcher
    finally:
        watcher.cancel()
        _ACTIVE.reset(token)


@contextmanager
def enforce(seconds: "float | None") -> "Iterator[None]":
    """:func:`watch` the block, and turn a cut-off into a :class:`~webdav.exceptions.ClientError`.

    Two things must not be left to the caller to remember. An exception that
    escapes while the time is up is the cut-off connection talking, not a
    network error - say so. And a socket shut down in the middle of a body
    can look like a clean end of the data (EOF): a block that *returns* after
    the time is up must never hand back what it read as complete.

    Nested, the outermost deadline is the one that counts (see :func:`watch`).
    """
    with watch(seconds) as watcher:
        try:
            yield
        except BaseException:
            if watcher is not None and watcher.expired.is_set():
                raise _deadline_error(seconds) from None
            raise
        if watcher is not None and watcher.expired.is_set():
            raise _deadline_error(seconds)


def _deadline_error(seconds: "float | None") -> ClientError:
    return ClientError(
        f"the request did not complete within the configured time of {seconds} seconds"
    )


def _register(connection: Any) -> None:
    watcher = _ACTIVE.get()
    if watcher is not None:
        watcher.track(connection)


class _TrackedHTTPConnection(HTTPConnection):
    def request(self, *args: Any, **kwargs: Any) -> None:
        _register(self)  # also a connection reused from the pool
        super().request(*args, **kwargs)

    def getresponse(self, *args: Any, **kwargs: Any) -> Any:
        _register(self)
        return super().getresponse(*args, **kwargs)


class _TrackedHTTPSConnection(HTTPSConnection):
    def request(self, *args: Any, **kwargs: Any) -> None:
        _register(self)
        super().request(*args, **kwargs)

    def getresponse(self, *args: Any, **kwargs: Any) -> Any:
        _register(self)
        return super().getresponse(*args, **kwargs)


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
