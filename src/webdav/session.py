"""HTTP transport: a :class:`requests.Session` extended with WebDAV verbs.

Deliberately thin: no base-url concept, no kwarg translation layer - every
``requests.Session`` feature (auth, adapters, hooks, cookies, connection
pooling, ``timeout=``, ``allow_redirects=``, ...) keeps working exactly as
documented in ``requests`` itself. Callers needing a base URL do the
joining themselves via :mod:`webdav.urls` before calling into this
session, same as the high level :class:`webdav.client.Client` does.
"""

from typing import TYPE_CHECKING, Any

import requests

if TYPE_CHECKING:
    from collections.abc import Callable

#: Applied whenever a call site doesn't set its own ``timeout=`` -
#: ``requests`` itself defaults to *no* timeout, which lets a stalled
#: connection hang a program forever. (connect, read) seconds.
DEFAULT_TIMEOUT = (10, 60)


class Method:
    """HTTP/WebDAV method name constants, to avoid typos in call sites."""

    GET = "GET"
    HEAD = "HEAD"
    PUT = "PUT"
    DELETE = "DELETE"
    OPTIONS = "OPTIONS"
    PROPFIND = "PROPFIND"
    PROPPATCH = "PROPPATCH"
    MKCOL = "MKCOL"
    COPY = "COPY"
    MOVE = "MOVE"
    LOCK = "LOCK"
    UNLOCK = "UNLOCK"


def _verb(method: str) -> "Callable[..., requests.Response]":
    """Build a ``Session`` method for a WebDAV verb.

    Mirrors the shape of ``requests.Session.get``/``.post``/... so the new
    verbs feel native rather than bolted on.
    """

    def caller(self: "WebDAVSession", url: str, **kwargs: Any) -> requests.Response:
        return self.request(method, url, **kwargs)

    caller.__name__ = method.lower()
    caller.__doc__ = f"Sends a {method} request. Returns a :class:`requests.Response`."
    return caller


class WebDAVSession(requests.Session):
    """A :class:`requests.Session` extended with the WebDAV verbs.

    Subclassing ``requests.Session`` for new HTTP verbs is the same
    pattern used by e.g. ``requests_toolbelt`` - every ``requests``
    feature keeps working unmodified for the new verbs too.

    Applies :data:`DEFAULT_TIMEOUT` whenever a call doesn't set its own
    ``timeout=``, on both :meth:`request` and :meth:`send` - streaming
    downloads (:mod:`webdav.streaming`) call ``send()`` directly, bypassing
    ``request()``, so both need the same default to actually be effective
    everywhere.
    """

    propfind = _verb(Method.PROPFIND)
    proppatch = _verb(Method.PROPPATCH)
    mkcol = _verb(Method.MKCOL)
    copy = _verb(Method.COPY)
    move = _verb(Method.MOVE)
    lock = _verb(Method.LOCK)
    unlock = _verb(Method.UNLOCK)

    def __init__(
        self, timeout: "float | tuple[float, float] | None" = DEFAULT_TIMEOUT
    ) -> None:
        """Instantiate with a default request timeout.

        Args:
            timeout: Default ``(connect, read)`` timeout (or a single
                value for both) applied when a request doesn't set its
                own. ``None`` restores ``requests``' own no-timeout
                default - not recommended, see :data:`DEFAULT_TIMEOUT`.

        """
        super().__init__()
        self.timeout = timeout

    def request(self, *args: Any, **kwargs: Any) -> requests.Response:
        """Send a request, applying the default timeout if unset."""
        kwargs.setdefault("timeout", self.timeout)
        return super().request(*args, **kwargs)

    def send(self, *args: Any, **kwargs: Any) -> requests.Response:
        """Send a prepared request, applying the default timeout if unset."""
        kwargs.setdefault("timeout", self.timeout)
        return super().send(*args, **kwargs)
