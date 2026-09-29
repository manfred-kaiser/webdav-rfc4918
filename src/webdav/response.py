"""A :class:`requests.Response` that also understands WebDAV.

Deliberately a *subclass*, not a wrapper: every ``requests`` attribute and
method keeps working unmodified, so code written against ``requests`` can
consume it as-is. What it adds is the WebDAV-domain view of the same
response - its multistatus body, its lock - plus a
:meth:`~Response.raise_for_status` that raises the specific
:mod:`webdav.exceptions` (which are :class:`requests.HTTPError` too).
"""

from functools import cached_property
from typing import TYPE_CHECKING, cast
from urllib.parse import unquote, urlsplit

import requests

from webdav.exceptions import raise_for_status as _raise_for_status
from webdav.locks import parse_lock_response
from webdav.multistatus import parse_multistatus_response

if TYPE_CHECKING:
    from webdav.locks import ActiveLock
    from webdav.multistatus import MultiStatusResponse


class Response(requests.Response):
    """A :class:`requests.Response` with WebDAV-aware helpers."""

    #: Why a redirect this response answered with was *not* followed, or
    #: ``None``. Set by :class:`~webdav.session.Session`.
    redirect_refusal: "str | None" = None

    @cached_property
    def multistatus(self) -> "MultiStatusResponse":
        """The parsed ``207 Multi-Status`` body (RFC 4918 sec. 13).

        Raises:
            webdav.exceptions.MalformedResponseError: The body is not a
                well-formed multistatus document.

        """
        return parse_multistatus_response(self)

    @cached_property
    def active_lock(self) -> "ActiveLock":
        """The lock a successful ``LOCK`` response granted (RFC 4918 sec. 9.10)."""
        return parse_lock_response(self)

    def _error_path(self) -> "str | None":
        """The path the error message names: the resource - and, for a COPY/MOVE, where it was going."""
        path = unquote(urlsplit(self.url).path) or None
        destination = (
            self.request.headers.get("Destination")
            if self.request is not None
            else None
        )
        if (
            path
            and destination
            and self.request is not None
            and self.request.method in ("COPY", "MOVE")
        ):
            return f"{path} -> {unquote(urlsplit(destination).path)}"
        return path

    def raise_for_status(self) -> None:
        """Raise the matching :class:`~webdav.exceptions.HTTPStatusError`, if any.

        Differs from :meth:`requests.Response.raise_for_status` in three
        ways, all deliberate:

        - a 3xx that was *not* followed raises
          :class:`~webdav.exceptions.RedirectNotFollowedError` (``requests``
          treats it as "ok"), since for a WebDAV write a silently
          unfollowed redirect means the write did not happen;
        - the raised exception is the specific one for the status (e.g.
          :class:`~webdav.exceptions.ResourceNotFoundError`), and is still a
          :class:`requests.HTTPError`;
        - a ``207 Multi-Status`` that reports a failure for any individual
          resource raises too - except for ``PROPFIND``, where a per-property
          404 inside a 207 is the normal way to say "no such property".
        """
        _raise_for_status(self, path=self._error_path())
        method = self.request.method if self.request is not None else None
        if self.status_code == requests.codes.multi_status and method != "PROPFIND":
            self.multistatus.raise_for_status()


def adopt(response: requests.Response) -> Response:
    """Turn a plain ``requests`` response into a :class:`Response`, in place.

    Done in place (not by copying) so the connection, ``history`` and
    streaming state stay attached to the one object the caller holds.
    """
    # Exactly this class - not a subclass, which has been adopted already.
    if response.__class__ is requests.Response:
        response.__class__ = Response
    return cast("Response", response)
