"""How :class:`~webdav.fs.client.FileSystem` talks to a :class:`~webdav.session.Session`.

A ``Session`` answers with responses and leaves it to the caller to look at
them; a ``FileSystem`` wants plain values and, on failure, a
:class:`~webdav.exceptions.WebDAVError` that names the path it was asked
about. :class:`Remote` is that translation - built on nothing but the
session's public API, so the file-system layer has no private door into it.
"""

from http import HTTPStatus
from typing import TYPE_CHECKING, Any, NamedTuple
from urllib.parse import urlsplit, urlunsplit

from webdav.dav.multistatus import multistatus_failure
from webdav.dav.urls import URL, relative_url_to
from webdav.exceptions import (
    ClientError,
    ResourceNotFoundError,
    WebDAVError,
    raise_for_member_status,
    raise_for_status,
)
from webdav.methods import Method
from webdav.url_safety import display_url, is_url

if TYPE_CHECKING:
    from webdav.dav.multistatus import MultiStatusResponse, ResourceResponse
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
        # A full URL is used as it is written, as ``Session.resolve_url`` does: ``parsed`` is
        # for comparing only - encoding its decoded path again would turn ``a%2Fb`` into
        # ``a/b`` and ``caf%E9`` into ``caf%EF%BF%BD``, another object on the server.
        split = urlsplit(path)
        raw_path = split.path
        if add_trailing_slash and not raw_path.endswith("/"):
            raw_path += "/"
        return Located(urlunsplit(split._replace(path=raw_path)), base, parsed.path)

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
        that off, since a per-property 404 there is just data. The same
        flag also covers a server that wraps that per-resource detail
        under a different top-level error status instead of 207 (confirmed
        on a real Apache instance: 424 Failed Dependency, for a collection
        DELETE one locked member blocked) - see
        :func:`~webdav.dav.multistatus.multistatus_failure`.

        Whatever ``raise_on_error`` the session has is overridden: the error
        raised here is the one that names ``path`` (or ``error_path``).
        """
        url = self.locate(path, add_trailing_slash=add_trailing_slash).url
        response = self._session.request(method, url, raise_on_error=False, **kwargs)
        if multistatus and 400 <= response.status_code < 600:
            failure = multistatus_failure(response)
            if failure is not None:
                failure.raise_for_status()
        raise_for_status(response, path=display_url(error_path or path))
        if multistatus and response.status_code == HTTPStatus.MULTI_STATUS:
            # Via .multistatus, not parse_multistatus_response() directly,
            # so a custom Response.multistatus_class (see Session's
            # response_class) is honoured here too.
            response.multistatus.raise_for_status()
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
        # Via .multistatus, not parse_multistatus_response() directly, so a
        # custom Response.multistatus_class (see Session's response_class)
        # is honoured here too.
        return response.multistatus

    def raise_for_resource(self, path: str, resource: "ResourceResponse") -> None:
        """Raise what the status says that a multistatus gives for ``resource``, if it is not a success.

        A server may answer a ``PROPFIND`` with a ``207`` whose ``<response>`` for ``path``
        holds a ``<status>`` and no properties (RFC 4918 sec. 13): a ``404`` there is as good
        as an HTTP ``404``.
        """
        if resource.status_code is not None:
            raise_for_member_status(
                resource.status_code,
                url=self.locate(path).url,
                path=display_url(path),
            )

    def raise_for_own_response(self, path: str, result: "MultiStatusResponse") -> None:
        """:meth:`raise_for_resource` for the answer to a depth-0 ``PROPFIND`` on ``path``.

        Looks at the response for ``path``, or at the only one there is (a server may spell
        the path another way). Nothing is raised if neither can be told.
        """
        _url, base, rel = self.locate(path)
        try:
            own = result.get_response_for_path(base.path, rel)
        except ClientError:
            if len(result.entries) != 1:
                return
            own = result.entries[0]
        self.raise_for_resource(path, own)

    def is_missing(self, path: str) -> bool:
        """Whether a ``PROPFIND`` (depth 0) says ``path`` is not there: a ``404``, and nothing less.

        A server that cannot answer (``401``, ``403``, a ``PROPFIND`` it refuses) has not said so.
        """
        try:
            self.raise_for_own_response(
                path, self.propfind(path, headers={"Depth": "0"})
            )
        except ResourceNotFoundError:
            return True
        except WebDAVError:
            return False
        return False

    def exists_quietly(self, path: str) -> bool:
        """Whether a ``PROPFIND`` (depth 0) finds ``path`` - ``False`` for any failure, not only a 404.

        For a caller that already holds an error of its own and only wants to
        know whether the resource is there: a server error answering this
        question must not replace the one it holds.
        """
        try:
            self.raise_for_own_response(
                path, self.propfind(path, headers={"Depth": "0"})
            )
        except WebDAVError:
            return False
        return True
