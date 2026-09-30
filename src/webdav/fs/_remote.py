"""How :class:`~webdav.fs.client.FileSystem` talks to a :class:`~webdav.session.Session`.

A ``Session`` answers with responses and leaves it to the caller to look at
them; a ``FileSystem`` wants plain values and, on failure, a
:class:`~webdav.exceptions.WebDAVError` that names the path it was asked
about. :class:`Remote` is that translation - built on nothing but the
session's public API, so the file-system layer has no private door into it.
"""

from http import HTTPStatus
from typing import TYPE_CHECKING, Any, NamedTuple

from webdav.dav.multistatus import parse_multistatus_response
from webdav.dav.urls import URL, relative_url_to
from webdav.exceptions import ClientError, raise_for_status
from webdav.methods import Method
from webdav.url_safety import display_url, is_url

if TYPE_CHECKING:
    from webdav.dav.multistatus import MultiStatusResponse
    from webdav.response import Response
    from webdav.session import Session
    from webdav.transport.redirects import RedirectPolicy


class Located(NamedTuple):
    """Where a path is: the URL to request, and how it relates to the session's base."""

    #: The full URL.
    url: str
    #: The ``base_url`` of the session - or, without one, the server's root.
    base: URL
    #: The path relative to ``base``.
    rel: str


class Remote:
    """A session as the file-system layer uses it: paths in, plain values or exceptions out.

    ``path`` is relative to the session's ``base_url``; without a
    ``base_url`` it is a full URL.
    """

    def __init__(self, session: "Session") -> None:
        """Wrap ``session``."""
        self._session = session

    def locate(self, path: str, *, add_trailing_slash: bool = False) -> Located:
        """Resolve ``path`` to its full URL, the base it is under, and its path relative to that.

        Raises:
            ClientError: ``path`` is outside the ``base_url``, or is not a
                full URL and there is no ``base_url``.

        """
        base_url = self._session.base_url
        if base_url is not None:
            url = self._session.resolve_url(path, add_trailing_slash=add_trailing_slash)
            base = URL(base_url)
            if is_url(path):
                try:
                    return Located(url, base, relative_url_to(base, URL(url).path))
                except ValueError as exc:
                    raise ClientError(str(exc)) from exc
            return Located(url, base, path)
        parsed = URL(path)
        if not parsed.is_absolute_url:
            msg = f"{path!r} is not a full http(s) URL and this session has no base_url"
            raise ClientError(msg)
        base = parsed.copy_with(path="/", query="")
        suffix = "/" if add_trailing_slash and not parsed.path.endswith("/") else ""
        return Located(
            str(parsed.copy_with(path=parsed.path + suffix)), base, parsed.path
        )

    def send(
        self,
        method: str,
        path: str,
        *,
        add_trailing_slash: bool = False,
        error_path: "str | None" = None,
        multistatus: bool = True,
        **kwargs: Any,
    ) -> "Response":
        """Send ``method`` for ``path``, raising the matching exception on failure.

        With ``multistatus`` (the default) a ``207`` reporting a failure
        for any individual resource raises too; a ``PROPFIND`` turns
        that off, since a per-property 404 there is just data.

        Whatever ``raise_on_error`` the session has is overridden: the error
        raised here is the one that names ``path`` (or ``error_path``).
        """
        url = self.locate(path, add_trailing_slash=add_trailing_slash).url
        response = self._session.request(method, url, raise_on_error=False, **kwargs)
        raise_for_status(response, path=display_url(error_path or path))
        if multistatus and response.status_code == HTTPStatus.MULTI_STATUS:
            parse_multistatus_response(response).raise_for_status()
        return response

    def propfind(
        self,
        path: str,
        *,
        data: "str | None" = None,
        headers: "dict[str, str] | None" = None,
        redirect_policy: "RedirectPolicy | None" = None,
    ) -> "MultiStatusResponse":
        """Send a ``PROPFIND`` and parse the multistatus response."""
        extra: dict[str, Any] = {}
        if redirect_policy is not None:
            extra["redirect_policy"] = redirect_policy
        response = self.send(
            Method.PROPFIND,
            path,
            multistatus=False,
            data=data,
            headers=headers,
            **extra,
        )
        return parse_multistatus_response(response)
