"""The two exception classes a lower-level module may need to raise.

Split out of :mod:`webdav.exceptions` so a module ``webdav.exceptions``
itself needs something from (e.g. :mod:`webdav.transport.body`, for the
bounded read :func:`~webdav.exceptions.HTTPStatusError.error_codes` uses)
can import :class:`ClientError` without a cycle - :mod:`webdav.exceptions`
re-exports both names, so everything else keeps importing them from there.
"""

import requests.exceptions


class WebDAVError(requests.exceptions.RequestException):
    """Base class for every exception raised by this library."""


class ClientError(WebDAVError):
    """Raised for client-side errors that are not a failed HTTP response."""

    def __init__(self, msg: str) -> None:
        """Instantiate with a human-readable message."""
        self.msg = msg
        super().__init__(msg)

    def __str__(self) -> str:
        """Return the message."""
        return self.msg


__all__ = ["ClientError", "WebDAVError"]
