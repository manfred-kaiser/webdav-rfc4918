"""Retry wrapper for transient WebDAV/HTTP failures.

Deliberately not delegated to ``urllib3``'s/``requests``' own adapter-level
retries: this needs to retry on *WebDAV*-domain conditions (423 Locked,
507, ...) that only become visible after this library's own
:func:`~webdav.exceptions.raise_for_status` has run, which an adapter
sitting below ``requests`` never sees.
"""

import time
from collections.abc import Callable
from typing import Protocol, TypeVar

import requests.exceptions

from webdav.exceptions import HTTPStatusError

_T = TypeVar("_T")

BACKOFF: float = 1
_TRANSIENT_TRANSPORT_ERRORS = (
    requests.exceptions.Timeout,
    requests.exceptions.ConnectionError,
)


class RetryFunc(Protocol):
    """Retry function protocol."""

    def __call__(self, f: Callable[[], _T], /) -> _T:
        """Call ``f``, retrying it per the wrapper's policy."""


def retry(enabled: bool = False, tries: int = 3) -> RetryFunc:
    """Build a retry wrapper.

    Args:
        enabled: If falsy, the wrapper calls through once, with no retry.
        tries: Maximum attempts when ``enabled``.

    Retries :class:`~webdav.exceptions.HTTPStatusError` subclasses marked
    ``retryable = True`` (429, 5xx, ...) and transient
    transport errors (timeouts, connection errors) - not, e.g., 404 or 403,
    which retrying cannot fix.

    """
    retries = tries if enabled else 1

    def wrapper(func: Callable[[], _T]) -> _T:
        for attempt in range(retries):
            try:
                return func()
            except HTTPStatusError as exc:
                if not exc.retryable or attempt + 1 == retries:
                    raise
            except _TRANSIENT_TRANSPORT_ERRORS:
                if attempt + 1 == retries:
                    raise
            time.sleep(BACKOFF * 2**attempt)
        msg = "unreachable"
        raise AssertionError(msg)  # pragma: no cover

    return wrapper
