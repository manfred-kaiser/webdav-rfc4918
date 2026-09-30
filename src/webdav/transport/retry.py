"""Retry wrapper for transient WebDAV/HTTP failures.

Deliberately not delegated to ``urllib3``'s/``requests``' own adapter-level
retries: this needs to retry on *WebDAV*-domain conditions (423 Locked,
507, ...) that only become visible after this library's own
:func:`~webdav.exceptions.raise_for_status` has run, which an adapter
sitting below ``requests`` never sees.
"""

import time
from collections.abc import Callable
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Protocol, TypeVar

import requests.exceptions

from webdav.exceptions import HTTPStatusError
from webdav.transport.parse_utils import parse_uint

_T = TypeVar("_T")

BACKOFF: float = 1

#: The longest ``Retry-After`` (RFC 9110 sec. 10.2.3) that is waited for, in
#: seconds. A server that asks for more is not waited for: the failure is
#: raised instead - a server must not be able to park a client for as long as
#: it likes.
MAX_RETRY_AFTER: float = 30.0
_TRANSIENT_TRANSPORT_ERRORS = (
    requests.exceptions.Timeout,
    requests.exceptions.ConnectionError,
)


class RetryFunc(Protocol):
    """Retry function protocol."""

    def __call__(self, f: Callable[[], _T], /) -> _T:
        """Call ``f``, retrying it per the wrapper's policy."""


def _retry_after(exc: HTTPStatusError) -> "float | None":
    """How many seconds the server asked to wait (``Retry-After``: seconds or an HTTP-date), or ``None``."""
    value = (
        exc.response.headers.get("Retry-After", "") if exc.response is not None else ""
    )
    seconds = parse_uint(value)
    if seconds is not None:
        return float(seconds)
    try:
        when = parsedate_to_datetime(value.strip())
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return max(0.0, (when - datetime.now(UTC)).total_seconds())


def retry(enabled: bool = False, tries: int = 3) -> RetryFunc:
    """Build a retry wrapper.

    Args:
        enabled: If falsy, the wrapper calls through once, with no retry.
        tries: Maximum attempts when ``enabled``.

    Retries :class:`~webdav.exceptions.HTTPStatusError` subclasses marked
    ``retryable = True`` (429, 5xx, ...) and transient
    transport errors (timeouts, connection errors) - not, e.g., 404 or 403,
    which retrying cannot fix. A ``Retry-After`` the server sent (RFC 9110
    sec. 10.2.3) is waited for if it is longer than the backoff - but not if
    it is longer than :data:`MAX_RETRY_AFTER`.

    """
    retries = tries if enabled else 1

    def wrapper(func: Callable[[], _T]) -> _T:
        for attempt in range(retries):
            delay = BACKOFF * 2**attempt
            try:
                return func()
            except HTTPStatusError as exc:
                if not exc.retryable or attempt + 1 == retries:
                    raise
                asked = _retry_after(exc)
                if asked is not None:
                    if asked > MAX_RETRY_AFTER:
                        raise
                    delay = max(delay, asked)
            except _TRANSIENT_TRANSPORT_ERRORS:
                if attempt + 1 == retries:
                    raise
            time.sleep(delay)
        msg = "unreachable"
        raise AssertionError(msg)  # pragma: no cover

    return wrapper
