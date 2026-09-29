"""High-level WebDAV client (RFC 4918), built on :mod:`requests`."""

import dataclasses
import locale
import os
import pathlib
import threading
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from functools import partial
from http import HTTPStatus
from io import TextIOWrapper
from typing import (
    TYPE_CHECKING,
    Any,
    BinaryIO,
    Literal,
    Self,
    TextIO,
    cast,
    overload,
)
from urllib.parse import urljoin, urlsplit

import requests

from webdav.conditional import (
    Condition,
    build_if_header_single,
    merge_if_headers,
    token_condition,
)
from webdav.exceptions import (
    ClientError,
    HTTPStatusError,
    IsACollectionError,
    IsAResourceError,
    MalformedResponseError,
    ResourceAlreadyExistsError,
    ResourceNotFoundError,
    raise_for_status,
)
from webdav.fs_utils import peek_filelike_length
from webdav.locks import (
    EXCLUSIVE,
    ActiveLock,
    build_lock_body,
    format_timeout,
    parse_lock_response,
)
from webdav.multistatus import Response, parse_multistatus_response
from webdav.properties import (
    CONVENIENCE_PROPS,
    build_propfind_body,
    build_proppatch_body,
)
from webdav.retry import retry as _retry
from webdav.session import Method, WebDAVSession
from webdav.streaming import DEFAULT_CHUNK_SIZE, IterStream, SizedIterator
from webdav.tls import TLSOptions, mount_mtls_adapter
from webdav.urls import URL, join_url, normalize_path
from webdav.xml_utils import DAV_NAMESPACE

#: Default cap on a single response body this client will buffer/parse
#: (PROPFIND/PROPPATCH/LOCK responses - not GET downloads, which stream
#: through webdav.streaming regardless of this setting). A malicious or
#: compromised server has no other way to force this client to allocate an
#: unbounded amount of memory for a single request; ``None`` disables the
#: check for deployments that legitimately need a bigger tree in one
#: PROPFIND. Only actually caps responses that send a (truthful)
#: Content-Length - a chunked-encoded response with no Content-Length isn't
#: covered without a deeper streaming rewrite of the request path.
DEFAULT_MAX_RESPONSE_SIZE = 64 * 1024 * 1024  # 64 MiB

#: How many redirects a single request will follow automatically before
#: giving up - guards against a redirect loop between trusted origins.
_MAX_REDIRECTS = 5

#: Default port per scheme, used so "https://host" and "https://host:443"
#: compare equal when deciding whether a redirect stays within one origin.
_DEFAULT_PORTS = {"http": 80, "https": 443}

#: Sentinel distinguishing "no such attribute" from a legitimate falsy
#: attribute value (``0``, ``""``, ``False``, ``None``) in get_property().
_MISSING = object()


def _origin(url: str) -> tuple[str, str | None, int | None]:
    """``(scheme, hostname, port)`` with the scheme's default port filled in.

    An RFC 6454-style origin tuple - two URLs compare equal here iff a
    redirect between them can't cross a trust boundary a caller didn't
    explicitly sanction (see ``Client.__init__``'s ``trusted_redirect_origins``).
    """
    parts = urlsplit(url)
    return (parts.scheme, parts.hostname, parts.port or _DEFAULT_PORTS.get(parts.scheme))

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable
    from datetime import datetime
    from os import PathLike
    from typing import AnyStr
    from xml.etree.ElementTree import Element

    from requests import Response as HTTPResponse
    from requests.auth import AuthBase

    from webdav.multistatus import MultiStatusResponse
    from webdav.properties import DAVProperties, PropName
    from webdav.retry import RetryFunc

    AuthTypes = AuthBase | tuple[str, str] | None
    CertTypes = str | tuple[str, str] | None


def _build_redirect_trust_check(
    trusted_redirect_origins: "Iterable[str] | Callable[[str], bool] | None",
) -> "Callable[[str], bool]":
    """Build the predicate :meth:`Client._request` uses for a cross-origin redirect.

    Accepts either shape :class:`Client`'s ``trusted_redirect_origins``
    documents: a caller-supplied predicate is used as-is; an iterable of
    origin strings is turned into one exact-origin-membership check.
    """
    if trusted_redirect_origins is None:
        return lambda _url: False
    if callable(trusted_redirect_origins):
        return trusted_redirect_origins
    origins = frozenset(_origin(o) for o in trusted_redirect_origins)
    return lambda url: _origin(url) in origins


def _has_replayable_body(data: object) -> bool:
    """Whether a request ``data=`` payload is safe to send a second time.

    ``None``/``str``/``bytes`` are (a lack of a body is trivially
    replayable, and a string/bytes body is read fresh from memory every
    time). Anything else (a generator, an already-partially-read file
    object, :class:`~webdav.streaming.SizedIterator`, ...) may have
    already been exhausted by a first attempt - resending it would
    silently send a truncated/empty body instead of raising, which is
    worse than not retrying at all.
    """
    return data is None or isinstance(data, str | bytes)


def _check_response_size(response: "HTTPResponse", max_size: "int | None") -> None:
    """Reject a response whose declared ``Content-Length`` exceeds ``max_size``.

    Only catches a response that (truthfully) declares its size upfront -
    see :data:`DEFAULT_MAX_RESPONSE_SIZE`.
    """
    if max_size is None:
        return
    content_length = response.headers.get("Content-Length", "")
    if content_length.isdigit() and int(content_length) > max_size:
        response.close()
        msg = (
            f"response declared Content-Length {content_length} bytes, "
            f"exceeding the configured limit of {max_size} bytes"
        )
        raise ClientError(msg)


def _prepare_result_info(
    response: Response,
    base_url: URL,
    detail: bool = True,
) -> str | dict[str, Any]:
    """Transform a multistatus response entry to a str/dict for ls()/info()."""
    rel = response.path_relative_to(base_url)
    if not detail:
        return rel
    return {
        "name": rel,
        "href": response.href,
        **response.properties.as_dict(),
    }


class FeatureDetection:
    """Server features detected via an OPTIONS request.

    Mostly used for detecting ``Accept-Ranges`` support, since some
    servers (e.g. ownCloud/Nextcloud) don't advertise it on GET responses.
    """

    supports_ranges: bool
    dav_compliances: set[str]

    def __init__(self, options_response: "HTTPResponse | None" = None) -> None:
        """Build from an OPTIONS response, or an empty/unknown state if ``None``."""
        dav_compliances = set()
        supports_ranges = False
        if options_response is not None:
            dav_header = options_response.headers.get("dav", "")
            dav_compliances = _parse_dav_header(dav_header)
            supports_ranges = options_response.headers.get("accept-ranges") == "bytes"

        self.dav_compliances = dav_compliances
        self.supports_ranges = supports_ranges


def _parse_dav_header(value: str) -> set[str]:
    """Split a ``DAV`` compliance-class header into its tokens (RFC 4918 §18).

    ``compliance-class = ("1" | "2" | "3" | extend)``, and ``extend`` can
    be a bare token (``"bind"``) or a ``Coded-URL`` (``<absolute-URI>``) -
    a comma inside the URI (legal per RFC 3986, unencoded, as a path/query
    sub-delim) is part of it, not a token separator, so this tracks
    bracket depth instead of blindly splitting on every comma.
    """
    tokens = []
    depth = 0
    current: list[str] = []
    for char in value:
        if char == "<":
            depth += 1
            current.append(char)
        elif char == ">":
            depth = max(0, depth - 1)
            current.append(char)
        elif char == "," and depth == 0:
            tokens.append("".join(current))
            current = []
        else:
            current.append(char)
    tokens.append("".join(current))
    return {t.strip() for t in tokens if t.strip()}


def _configure_tls(
    session: WebDAVSession,
    *,
    cert: "CertTypes",
    verify: "bool | str",
    tls: "TLSOptions | None",
) -> None:
    """Wire up ``cert``/``verify`` - via plain ``requests`` attrs, or a hardened adapter.

    The hardened :mod:`webdav.tls` adapter is only needed for what plain
    ``requests`` cannot express (``tls=...``); everything else uses
    ``requests``' own, well-known ``cert=``/``verify=`` attributes.
    """
    if tls is None:
        session.cert = cert
        session.verify = verify
        return

    certfile: str | None
    keyfile: str | None
    if cert is None:
        certfile, keyfile = None, None
    elif isinstance(cert, str):
        certfile, keyfile = cert, None
    else:
        certfile, keyfile = cert[0], cert[1]

    if tls.ca_files is None and isinstance(verify, str):
        tls = dataclasses.replace(tls, ca_files=verify)
    mount_mtls_adapter(session, certfile=certfile, keyfile=keyfile, options=tls)


class Client:
    """High-level WebDAV client.

    Every WebDAV-specific detail (property parsing, locking, multistatus,
    resumable streaming) sits here or in the modules it composes; the
    underlying :class:`~webdav.session.WebDAVSession` stays a thin,
    standard :class:`requests.Session` subclass.
    """

    def __init__(
        self,
        base_url: str,
        *,
        auth: "AuthTypes" = None,
        session: WebDAVSession | None = None,
        retry: "RetryFunc | bool" = True,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        cert: "CertTypes" = None,
        verify: "bool | str" = True,
        tls: TLSOptions | None = None,
        headers: dict[str, str] | None = None,
        max_response_size: "int | None" = DEFAULT_MAX_RESPONSE_SIZE,
        allow_redirects: bool = True,
        trusted_redirect_origins: "Iterable[str] | Callable[[str], bool] | None" = None,
    ) -> None:
        """Instantiate a client for a WebDAV server.

        Examples:
            >>> client = Client("https://webdav.example.org")
            >>> client.ls("/")

        Args:
            base_url: Base URL of the WebDAV server.
            auth: Passed straight through to ``requests`` - a
                ``(user, password)`` tuple, a
                :class:`requests.auth.AuthBase` instance, or ``None``.
            session: A pre-built :class:`~webdav.session.WebDAVSession` to
                use instead (e.g. for mocking in tests). When given, the
                TLS/auth/header parameters below are ignored - configure
                the session directly instead.
            retry: Disable/enable retrying retryable failures (423 Locked,
                5xx, transient network errors), or pass a callable
                implementing :class:`~webdav.retry.RetryFunc` directly.
            chunk_size: Default chunk size for streaming reads/writes.
            cert: Client certificate for mTLS - a path to a combined
                cert+key PEM, or a ``(certfile, keyfile)`` tuple.
            verify: Server certificate verification - ``True`` (system
                trust store), or a path to a CA bundle.
            tls: Advanced TLS knobs (encrypted private key, CRL checking,
                explicit cipher restriction) that plain ``cert=``/
                ``verify=`` cannot express - see
                :class:`~webdav.tls.TLSOptions`. Triggers the hardened
                :mod:`webdav.tls` adapter when given.
            headers: Default headers sent with every request.
            max_response_size: Reject a PROPFIND/PROPPATCH/LOCK response
                whose (truthful) ``Content-Length`` exceeds this many
                bytes, rather than buffering and parsing it - a server has
                no other way to make this client allocate unbounded
                memory for a single request. ``None`` disables the check.
                Does not apply to GET downloads, which always stream
                through :mod:`webdav.streaming` regardless of this
                setting.
            allow_redirects: This client's default redirect policy - the
                three tiers this and ``trusted_redirect_origins`` together
                form (deliberately mirroring the browser ``fetch()``
                ``redirect``/``credentials`` options for a familiar
                mental model):

                - ``False``: never follow any redirect, from any call on
                  this client - the strictest tier (``fetch``'s
                  ``redirect: "error"``), for a caller that wants zero
                  surprises about where a request ends up.
                - ``True`` (the default): follow a same-origin redirect
                  automatically, refuse (``RedirectNotFollowedError``)
                  anything else - safe by construction, since a
                  same-origin redirect can't move a request or its body
                  outside the server the caller already chose to trust.
                - Additionally set ``trusted_redirect_origins`` to also
                  follow specific other origins (e.g. a signed-upload
                  gateway) - this client's own credentials are never
                  forwarded there, only to its own origin (see
                  :meth:`_send_without_credentials`).

                Overridable per call on the methods that expose their own
                ``allow_redirects`` (e.g. :meth:`propfind`).
            trusted_redirect_origins: Beyond this client's own origin
                (always implicitly trusted), which redirect targets to
                also follow. HTTP permits a server to redirect a request
                anywhere, including to a completely different host - a
                real, legitimate pattern (e.g. a cloud-storage gateway
                redirecting PUT to a signed upload URL on a separate
                origin) - but blindly trusting whatever origin a server
                names at request time is exactly how a malicious or
                compromised server could exfiltrate a request body
                cross-origin. This keeps that decision with whoever
                configures the client, not the server, in one of two
                shapes:

                - An iterable of exact origins (``"https://host"`` or
                  ``"https://host:port"``) - the straightforward case
                  when the redirect target is fixed and known ahead of
                  time.
                - A ``Callable[[str], bool]`` receiving the full target
                  URL, for when it isn't - e.g. a signed-upload gateway
                  whose exact hostname varies per bucket/region/tenant,
                  where only the *provider's* domain is stable::

                      trusted_redirect_origins=lambda url: (
                          urlsplit(url).hostname or ""
                      ).endswith(".amazonaws.com")

                  Note this trusts an entire domain (and everything
                  DNS-delegated under it), not one exact host - scope it
                  as tightly as the actual deployment allows.

                A redirect to any origin neither this client's own nor
                covered by this parameter is always refused
                (``RedirectNotFollowedError``); same-origin redirects are
                always allowed regardless of this setting.

        """
        self.session: WebDAVSession = session or WebDAVSession()
        if session is None:
            self.session.auth = auth
            if headers:
                self.session.headers.update(headers)
            _configure_tls(self.session, cert=cert, verify=verify, tls=tls)

        self.base_url = URL(base_url)
        self.with_retry = retry if callable(retry) else _retry(retry)
        self.chunk_size = chunk_size
        self.max_response_size = max_response_size
        self.allow_redirects = allow_redirects
        self._is_trusted_redirect_target = _build_redirect_trust_check(
            trusted_redirect_origins
        )
        self._detected_features: FeatureDetection | None = None
        self._detect_feature_lock = threading.RLock()
        # path (normalized, leading slash) -> [(lock token, lock Depth), ...]
        # a list, not a single tuple, since RFC 4918 §6.2 allows several
        # (e.g. shared) locks on the same resource to coexist.
        self._locks: dict[str, list[tuple[str, str]]] = {}
        self._locks_lock = threading.RLock()

    def __enter__(self) -> Self:
        """Support use as a context manager, closing the session on exit."""
        return self

    def __exit__(self, *args: object) -> None:
        """Close the underlying session."""
        self.close()

    def close(self) -> None:
        """Close the underlying session and its connection pool."""
        self.session.close()

    @property
    def detected_features(self) -> FeatureDetection:
        """Feature detection for the server (cached, lazily probed)."""
        if not self._detected_features:
            with self._detect_feature_lock:
                if self._detected_features:  # pragma: no cover
                    return self._detected_features
                resp = None
                with suppress(Exception):
                    resp = self.session.request(Method.OPTIONS, str(self.base_url))
                self._detected_features = FeatureDetection(resp)
        return self._detected_features

    def options(self, path: str = "") -> set[str]:
        """Return the ``DAV:`` compliance classes the server advertises."""
        resp = self.session.request(Method.OPTIONS, str(self.join_url(path)))
        return FeatureDetection(resp).dav_compliances

    def join_url(self, path: str, add_trailing_slash: bool = False) -> URL:
        """Join a resource path with the client's base URL.

        Raises:
            ClientError: ``path`` contains enough ``..`` segments that the
                resolved path would climb outside of this client's
                ``base_url`` - almost always unsanitized input reaching
                this call, never a legitimate WebDAV request.

        """
        try:
            return join_url(self.base_url, path, add_trailing_slash=add_trailing_slash)
        except ValueError as exc:
            raise ClientError(str(exc)) from exc

    def _find_lock_token(self, path: str) -> str | None:
        """Return a held lock's token covering ``path``, if any.

        A Depth:0 lock only covers its own exact path; a Depth:infinity
        lock covers everything under it, including not-yet-existing
        children (RFC 4918 §6.1: a write lock on a collection also
        affects adding/removing members) - matched purely on the path
        string, not on whether anything exists there yet.
        """
        if not self._locks:
            return None
        norm_path = normalize_path("/" + path.strip("/"))
        with self._locks_lock:
            for locked_path, entries in self._locks.items():
                # The root ("/") needs no extra separator before its
                # children; every other path does, so "/a" doesn't also
                # match "/ab".
                prefix = locked_path if locked_path == "/" else locked_path + "/"
                for token, depth in entries:
                    if norm_path == locked_path or (
                        depth == "infinity" and norm_path.startswith(prefix)
                    ):
                        return token
        return None

    def _if_header_for(self, path: str) -> str | None:
        """Return an ``If`` header value for ``path``, if a held lock covers it."""
        token = self._find_lock_token(path)
        return token_condition(token) if token else None

    def _request(
        self,
        method: str,
        path: str,
        add_trailing_slash: bool = False,
        error_path: str | None = None,
        **kwargs: Any,
    ) -> "HTTPResponse":
        """Send a request, joining ``path`` and mapping HTTP errors.

        HTTP permits a server to answer *any* method with a redirect (RFC
        9110 sec. 15.4; RFC 7238 defines 308 specifically to preserve the
        method/body across one) - nothing requires a client to *follow*
        one, though, and blindly doing so is unsafe for a general-purpose
        client: a malicious or compromised server could otherwise
        redirect a write to a different resource, or - via 307/308 - to
        a completely different host while fully replaying the request
        body, with no error raised to the caller.

        This method never delegates redirect-following to ``requests``
        itself; instead, a same-origin redirect (or one to an origin
        ``trusted_redirect_origins`` at :class:`Client` construction
        approves) is followed automatically, up to :data:`_MAX_REDIRECTS`
        hops, and only when the request body is one that's safe to resend
        (see :func:`_has_replayable_body`). A redirect to any other
        origin, or one that can't be safely replayed, raises
        :class:`~webdav.exceptions.RedirectNotFollowedError` instead.
        Passing ``allow_redirects=False`` explicitly disables even
        same-origin following, for a caller that wants zero surprises
        about where a request ends up.

        A redirect that crosses into a *different* (trusted) origin never
        carries this session's credentials there - same rationale, and
        same mechanism, as ``requests``' own ``Session.rebuild_auth()``
        for its native redirect-following, which following redirects via
        our own loop instead of delegating to ``requests`` bypasses
        otherwise: see :meth:`_send_without_credentials`.
        """
        url = str(self.join_url(path, add_trailing_slash=add_trailing_slash))
        follow = kwargs.pop("allow_redirects", self.allow_redirects)
        kwargs["allow_redirects"] = False

        if_header = self._if_header_for(path)
        if if_header:
            headers = dict(kwargs.get("headers") or {})
            headers.setdefault("If", if_header)
            kwargs["headers"] = headers

        http_resp = self.session.request(method, url, **kwargs)

        hops = 0
        while (
            follow
            and (http_resp.is_redirect or http_resp.is_permanent_redirect)
            and hops < _MAX_REDIRECTS
        ):
            location = http_resp.headers.get("Location")
            if not location:
                break
            target = urljoin(http_resp.url, location)
            same_origin = _origin(target) == _origin(url)
            if not same_origin and not self._is_trusted_redirect_target(target):
                break
            if not _has_replayable_body(kwargs.get("data")):
                break
            http_resp.close()
            hops += 1
            url = target
            http_resp = (
                self.session.request(method, url, **kwargs)
                if same_origin
                else self._send_without_credentials(method, url, **kwargs)
            )

        _check_response_size(http_resp, self.max_response_size)
        raise_for_status(http_resp, path=error_path or path)
        return http_resp

    def _send_without_credentials(
        self, method: str, url: str, **kwargs: Any
    ) -> "HTTPResponse":
        """Send one request through this client's session, minus its credentials.

        Used only for a redirect retry that crosses into a different
        (explicitly trusted) origin. Being trusted enough to receive this
        request's body doesn't make an origin trusted with this client's
        separate WebDAV-server credentials too - a signed-upload gateway
        needs neither the ``Authorization`` header this session would
        otherwise attach nor any ``self.session.headers`` default that
        looks like one, since its own authorization is meant to already
        be embedded in the URL/query string it handed back.

        Manually replays what ``Session.request()`` itself does
        internally (build → prepare → send), stripping the credential
        headers from the already-*prepared* request in between - the
        same point ``requests``' own ``Session.rebuild_auth()`` intervenes
        at for its native redirect-following, and the reason this can't
        simply pass ``auth=None``: ``Session.prepare_request()`` merges a
        falsy per-call ``auth`` right back into ``self.session.auth``
        (see ``requests.sessions.merge_setting``), so the only place that
        reliably removes it is post-preparation, on the built header
        dict. Deliberately doesn't do this by temporarily clearing
        ``self.session.auth`` instead, which would race with any other
        request concurrently in flight on the same (possibly shared)
        session.

        Custom, non-credential-shaped headers configured via
        ``Client(headers=...)`` are *not* stripped - this can't generally
        tell those apart from an unrelated default header, so a
        deployment authenticating via a custom header instead of
        ``Authorization`` should avoid ``trusted_redirect_origins``, or
        use a separate :class:`Client` per origin instead.
        """
        request = requests.Request(
            method=method,
            url=url,
            headers=kwargs.get("headers"),
            data=kwargs.get("data"),
            params=kwargs.get("params"),
            cookies=kwargs.get("cookies"),
            hooks=kwargs.get("hooks"),
        )
        prepared = self.session.prepare_request(request)
        for header in ("Authorization", "Proxy-Authorization"):
            prepared.headers.pop(header, None)
        settings = self.session.merge_environment_settings(
            prepared.url,
            kwargs.get("proxies") or {},
            kwargs.get("stream"),
            kwargs.get("verify"),
            kwargs.get("cert"),
        )
        send_kwargs: dict[str, Any] = {"allow_redirects": False}
        send_kwargs.update(settings)
        if "timeout" in kwargs:
            send_kwargs["timeout"] = kwargs["timeout"]
        return self.session.send(prepared, **send_kwargs)

    def request(self, method: str, path: str, **kwargs: Any) -> "HTTPResponse":
        """Send a request, also raising on a 207 response with per-resource failures."""
        http_resp = self._request(method, path, **kwargs)
        if http_resp.status_code == HTTPStatus.MULTI_STATUS:
            result = parse_multistatus_response(http_resp)
            result.raise_for_status()
        return http_resp

    # -- properties -----------------------------------------------------

    def propfind(
        self,
        path: str,
        data: str | None = None,
        headers: dict[str, str] | None = None,
        allow_redirects: bool | None = None,
    ) -> "MultiStatusResponse":
        """Send a PROPFIND request and parse the multistatus response.

        ``allow_redirects`` defaults to this client's own
        ``allow_redirects`` policy (see :class:`Client`) when left unset -
        pass it explicitly only to override that policy for this one call.
        """
        redirect_kwargs: dict[str, Any] = (
            {} if allow_redirects is None else {"allow_redirects": allow_redirects}
        )
        call = partial(
            self._request,
            Method.PROPFIND,
            path,
            data=data,
            headers=headers,
            **redirect_kwargs,
        )
        http_resp = self.with_retry(call)
        return parse_multistatus_response(http_resp)

    def get_props(
        self,
        path: str,
        names: "Iterable[str | PropName] | None" = None,
        all_prop: bool = False,
        include: "Iterable[str | PropName] | None" = None,
    ) -> "DAVProperties":
        """Return properties of a resource via PROPFIND.

        Args:
            path: Resource path.
            names: Specific property names to request - see
                :func:`~webdav.properties.build_propfind_body`. Requests
                all properties when omitted (and ``all_prop`` is falsy).
            all_prop: Explicitly request ``<d:allprop/>``.
            include: Additional named properties to request alongside
                ``all_prop`` - see
                :func:`~webdav.properties.build_propfind_body`.

        """
        data = build_propfind_body(names, all_prop=all_prop or not names, include=include)
        # Depth: 0 - this is a single-resource lookup, not a traversal.
        # Left unset, RFC 4918 §9.1 says servers SHOULD default a missing
        # Depth to infinity, which would make a lookup against a
        # collection trigger a full recursive PROPFIND for one property.
        headers = {"Content-Type": "application/xml; charset=utf-8", "Depth": "0"}
        result = self.propfind(path, headers=headers, data=data)
        response = result.get_response_for_path(self.base_url.path, path)
        return response.properties

    def get_property(self, path: str, name: "str | PropName") -> Any:
        """Return a single property's value (text, or an Element for complex values)."""
        props = self.get_props(path, names=[name])
        if isinstance(name, tuple):
            return props.get(*name)
        value = getattr(props, name, _MISSING)
        if value is not _MISSING:
            # A legitimate falsy value (e.g. content_length == 0 for an
            # empty file) must be returned as-is, not treated as "missing".
            return value
        return props.get(DAV_NAMESPACE, CONVENIENCE_PROPS.get(name, name))

    def set_props(
        self,
        path: str,
        set_props: "dict[str | PropName, Any] | None" = None,
        remove_props: "Iterable[str | PropName] | None" = None,
    ) -> None:
        """Set and/or remove properties via PROPPATCH (RFC 4918 §9.2)."""
        data = build_proppatch_body(set_props, remove_props)
        headers = {"Content-Type": "application/xml; charset=utf-8"}
        call = partial(
            self._request, Method.PROPPATCH, path, data=data, headers=headers
        )
        http_resp = self.with_retry(call)
        result = parse_multistatus_response(http_resp)
        result.raise_for_status()

    # -- locking (RFC 4918 Class 2) --------------------------------------

    def _lock_bookkeeping_path(self, active_lock: ActiveLock, requested_path: str) -> str:
        """Resolve the path to key ``self._locks`` under for a newly granted lock.

        Deliberately always the *requested* path, never the server-supplied
        ``lock_root`` (§14.1's ``<lockroot>``), despite ``lock_root`` being
        the more RFC-literal choice for the rare case where a server
        reports a differently-spelled (but equivalent) canonical root.
        Trusting it turned out to be a real bookkeeping-integrity issue,
        not just a conformance nicety: a server's ``<lockroot>`` for a
        successful LOCK response was found to accept an entirely
        unrelated href - even on a different host, since only the path
        component is read - with nothing to cross-check it against. A
        malicious/compromised server could use that to make this client
        silently key its own lock bookkeeping under a path the caller
        never asked to lock, so a later write to *that* path would
        unexpectedly carry a token the caller has no idea it's holding -
        while the path the caller actually locked would carry no token at
        all. Requiring an exact match against the requested path before
        trusting ``lock_root`` would close that hole, but also makes the
        RFC-conformance upside moot (a match yields the same path the
        requested-path fallback already gives), so there is no accuracy
        gained by consulting it at all - only re-verify this if a concrete
        case actually needs it, with a real cross-check, not blind trust.
        ``active_lock`` is kept as a parameter (unused) so the method's
        shape survives if that need ever arises.
        """
        return normalize_path("/" + requested_path.strip("/"))

    @contextmanager
    def lock(
        self,
        path: str,
        scope: str = EXCLUSIVE,
        depth: str = "infinity",
        timeout: "int | Iterable[int | None] | None" = None,
        owner: "str | Element | None" = None,
    ) -> Iterator[ActiveLock]:
        """Hold a WebDAV lock on ``path`` for the duration of the ``with`` block.

        Writes made through this same client to ``path`` (or, with
        ``depth="infinity"``, anything under it) automatically carry the
        held lock's token in an ``If`` header. The lock is released on
        exit, even if the block raised.

        Args:
            path: Resource to lock.
            scope: :data:`~webdav.locks.EXCLUSIVE` or
                :data:`~webdav.locks.SHARED`.
            depth: ``"0"`` or ``"infinity"`` - no other value is legal on
                a LOCK request (RFC 4918 §9.10.4).
            timeout: A single seconds value, ``None`` for infinite, or an
                ordered preference list - see
                :func:`~webdav.locks.format_timeout`.
            owner: Plain text, or a pre-built
                :class:`~xml.etree.ElementTree.Element` for a structured
                owner identity - see
                :func:`~webdav.locks.build_lock_body`.

        Raises:
            ValueError: ``depth`` is neither ``"0"`` nor ``"infinity"``.

        """
        if depth not in ("0", "infinity"):
            msg = f"LOCK Depth must be '0' or 'infinity' (RFC 4918 §9.10.4), got {depth!r}"
            raise ValueError(msg)

        data = build_lock_body(scope, owner)
        headers = {
            "Depth": depth,
            "Timeout": format_timeout(timeout),
            "Content-Type": "application/xml; charset=utf-8",
        }
        http_resp = self._request(Method.LOCK, path, data=data, headers=headers)
        active_lock = parse_lock_response(http_resp)

        norm_path = self._lock_bookkeeping_path(active_lock, path)
        entry = (active_lock.token, depth)
        with self._locks_lock:
            self._locks.setdefault(norm_path, []).append(entry)
        try:
            yield active_lock
        finally:
            with self._locks_lock:
                entries = self._locks.get(norm_path)
                if entries:
                    with suppress(ValueError):
                        entries.remove(entry)
                    if not entries:
                        del self._locks[norm_path]
            with suppress(HTTPStatusError):
                self.unlock(path, active_lock.token)

    def refresh_lock(
        self,
        path: str,
        token: str,
        timeout: "int | Iterable[int | None] | None" = None,
    ) -> ActiveLock:
        """Refresh a held lock's timeout (RFC 4918 §9.10.2).

        Sends a bodyless LOCK request carrying the lock's token in the
        ``If`` header - the RFC's mechanism for extending a lock's
        timeout without releasing and re-acquiring it, which would risk
        another client taking the lock in the gap between the two. No
        ``Depth`` header is sent, since the lock's depth was already
        fixed when it was created and can't change on refresh.

        Updates this client's own bookkeeping so a still-open ``lock()``
        block for the same lock keeps attaching the right token; the
        returned :class:`~webdav.locks.ActiveLock` reflects the refreshed
        timeout (the one an open ``lock()`` block is already holding does
        not update itself - use this method's return value instead).
        """
        headers = {"If": token_condition(token), "Timeout": format_timeout(timeout)}
        http_resp = self._request(Method.LOCK, path, headers=headers)
        active_lock = parse_lock_response(http_resp)

        with self._locks_lock:
            for entries in self._locks.values():
                for i, (tok, depth) in enumerate(entries):
                    if tok == token:
                        entries[i] = (active_lock.token, depth)
        return active_lock

    def unlock(self, path: str, token: str) -> None:
        """Release a lock by its token (RFC 4918 §9.11)."""
        self._request(Method.UNLOCK, path, headers={"Lock-Token": f"<{token}>"})

    # -- structural operations --------------------------------------------

    def move(self, from_path: str, to_path: str, overwrite: bool = False) -> None:
        """Move a resource (with or without overwriting the destination)."""
        self._transfer(Method.MOVE, from_path, to_path, overwrite=overwrite)

    def copy(
        self,
        from_path: str,
        to_path: str,
        depth: "int | str" = "infinity",
        overwrite: bool = False,
    ) -> None:
        """Copy a resource.

        Raises:
            ValueError: ``depth`` is neither ``"0"``/``0`` nor
                ``"infinity"`` - no other value is legal on a COPY request
                (RFC 4918 §9.8.3).

        """
        self._transfer(
            Method.COPY, from_path, to_path, depth=depth, overwrite=overwrite
        )

    def _locks_if_header_for_transfer(self, from_path: str, to_path: str) -> str | None:
        """Build an ``If`` header covering both sides of a COPY/MOVE.

        RFC 4918 §10.2: "If a source or destination resource within the
        scope of the Depth header is locked in such a way as to prevent
        the successful execution of the method, then the lock token for
        that resource MUST be submitted with the request in the If
        request header." An untagged (``No-tag-list``) token only
        unambiguously identifies a single resource, so once the
        destination needs one too, each token is scoped to its own
        resource via a ``Tagged-list`` instead.
        """
        from_token = self._find_lock_token(from_path)
        to_token = self._find_lock_token(to_path)
        if not to_token:
            return token_condition(from_token) if from_token else None

        parts = [
            build_if_header_single(
                [Condition(token=to_token)], resource=str(self.join_url(to_path))
            )
        ]
        if from_token:
            parts.append(
                build_if_header_single(
                    [Condition(token=from_token)],
                    resource=str(self.join_url(from_path)),
                )
            )
        return merge_if_headers(*parts)

    def _transfer(
        self,
        operation: str,
        from_path: str,
        to_path: str,
        overwrite: bool,
        depth: "int | str" = "infinity",
    ) -> None:
        if operation == Method.COPY and str(depth) not in ("0", "infinity"):
            msg = f"COPY Depth must be '0' or 'infinity' (RFC 4918 §9.8.3), got {depth!r}"
            raise ValueError(msg)

        to_url = self.join_url(to_path)
        headers = {
            "Destination": str(to_url),
            "Overwrite": "T" if overwrite else "F",
            "Depth": str(depth),
        }
        if_header = self._locks_if_header_for_transfer(from_path, to_path)
        if if_header:
            headers["If"] = if_header
        call = partial(
            self.request,
            operation,
            from_path,
            headers=headers,
            error_path=to_path,
        )
        self.with_retry(call)

    def mkdir(self, path: str, body: str | None = None) -> None:
        """Create a collection.

        Args:
            path: Collection path.
            body: Optional Extended MKCOL request body (RFC 5689) to set
                a non-default resourcetype and/or properties at creation
                time. Sent with ``Content-Type: application/xml`` when given.

        """
        headers = {"Content-Type": "application/xml; charset=utf-8"} if body else None
        call = partial(
            self.request,
            Method.MKCOL,
            path,
            add_trailing_slash=True,
            data=body,
            headers=headers,
        )
        try:
            http_resp = self.with_retry(call)
        except HTTPStatusError as exc:
            if exc.status_code == HTTPStatus.METHOD_NOT_ALLOWED:
                raise ResourceAlreadyExistsError(exc.response, path) from exc
            raise

        if http_resp.status_code not in (HTTPStatus.OK, HTTPStatus.CREATED):
            msg = f"unexpected status {http_resp.status_code} from MKCOL"
            raise MalformedResponseError(msg)

    def remove(self, path: str) -> None:
        """Remove a resource (or collection, recursively)."""
        self.with_retry(partial(self.request, Method.DELETE, path))

    # -- listing / metadata -------------------------------------------------

    @overload
    def ls(
        self,
        path: str,
        detail: Literal[True] = ...,
        allow_listing_resource: bool = ...,
    ) -> "list[dict[str, Any]]": ...

    @overload
    def ls(
        self,
        path: str,
        detail: Literal[False],
        allow_listing_resource: bool = ...,
    ) -> "list[str]": ...

    def ls(
        self,
        path: str,
        detail: bool = True,
        allow_listing_resource: bool = True,
    ) -> "list[str] | list[dict[str, Any]]":
        """List members of a collection.

        Args:
            path: Path to the resource.
            detail: If True, return a dict of properties per entry instead
                of just its relative path.
            allow_listing_resource: If True and ``path`` is a resource
                (not a collection), return its own entry rather than
                raising.

        """
        result = self.propfind(path, headers={"Depth": "1"})
        responses = result.responses

        url = self.join_url(path)
        response = responses.get(url.path)

        if response:
            typ = response.properties.resource_type
            if typ == "file" and not allow_listing_resource:
                raise IsAResourceError(path, "cannot list from a resource itself")
            if typ == "directory":
                responses.pop(url.path)

        return cast(
            "list[str] | list[dict[str, Any]]",
            [
                _prepare_result_info(resp, self.base_url, detail)
                for resp in responses.values()
            ],
        )

    def info(self, path: str) -> dict[str, Any]:
        """Return properties of ``path`` itself, as a dict."""
        result = self.propfind(path, headers={"Depth": "0"})
        response = result.get_response_for_path(self.base_url.path, path)
        details = _prepare_result_info(response, self.base_url, detail=True)
        assert not isinstance(details, str)
        return details

    def exists(self, path: str) -> bool:
        """Check whether a resource exists."""
        try:
            self.propfind(path)
        except ResourceNotFoundError:
            return False
        return True

    def isdir(self, path: str) -> bool:
        """Check whether a resource is a collection."""
        return bool(self.get_props(path, names=["resourcetype"]).collection)

    def isfile(self, path: str) -> bool:
        """Check whether a resource is not a collection."""
        return not self.isdir(path)

    def content_length(self, path: str) -> "int | None":
        """Return the ``getcontentlength`` property."""
        return self.get_props(path, names=["content_length"]).content_length

    def created(self, path: str) -> "datetime | None":
        """Return the ``creationdate`` property."""
        return self.get_props(path, names=["created"]).created

    def modified(self, path: str) -> "datetime | None":
        """Return the ``getlastmodified`` property."""
        return self.get_props(path, names=["modified"]).modified

    def etag(self, path: str) -> "str | None":
        """Return the ``getetag`` property."""
        return self.get_props(path, names=["etag"]).etag

    def content_type(self, path: str) -> "str | None":
        """Return the ``getcontenttype`` property."""
        return self.get_props(path, names=["content_type"]).content_type

    def content_language(self, path: str) -> "str | None":
        """Return the ``getcontentlanguage`` property."""
        return self.get_props(path, names=["content_language"]).content_language

    # -- streaming I/O -----------------------------------------------------

    @overload
    @contextmanager
    def open(
        self,
        path: str,
        mode: Literal["rb"],
        encoding: str | None = ...,
        chunk_size: int | None = ...,
    ) -> Iterator[BinaryIO]: ...

    @overload
    @contextmanager
    def open(
        self,
        path: str,
        mode: Literal["r", "rt"] = ...,
        encoding: str | None = ...,
        chunk_size: int | None = ...,
    ) -> Iterator[TextIO]: ...

    @contextmanager
    def open(
        self,
        path: str,
        mode: str = "r",
        encoding: str | None = None,
        chunk_size: int | None = None,
    ) -> "Iterator[TextIO | BinaryIO]":
        """Open a resource for streaming reads."""
        if self.isdir(path):
            raise IsACollectionError(path, "cannot open a collection")
        if mode not in {"r", "rt", "rb"}:
            msg = f"unsupported mode {mode!r}"
            raise ValueError(msg)

        with IterStream(
            self,
            str(self.join_url(path)),
            chunk_size=chunk_size or self.chunk_size,
        ) as buffer:
            buff = cast("BinaryIO", buffer)
            if mode == "rb":
                yield buff
            else:
                enc = encoding or buffer.encoding or locale.getpreferredencoding(False)
                yield TextIOWrapper(buff, encoding=enc)

    def download_fileobj(
        self,
        from_path: str,
        file_obj: BinaryIO,
        callback: "Callable[[int], Any] | None" = None,
        chunk_size: int | None = None,
    ) -> None:
        """Write a resource's contents to an open, writable file object."""
        with self.open(from_path, mode="rb", chunk_size=chunk_size) as remote_obj:
            while data := remote_obj.read(chunk_size or self.chunk_size):
                file_obj.write(data)
                if callback:
                    callback(len(data))

    def download_file(
        self,
        from_path: str,
        to_path: "PathLike[AnyStr]",
        chunk_size: int | None = None,
        callback: "Callable[[int], Any] | None" = None,
    ) -> None:
        """Download a resource to a local file.

        Refuses to follow a symlink at ``to_path``, so a pre-planted
        symlink can't redirect the write to an unintended local file (the
        same class of attack OpenSSH's ``sftp`` client hardened against
        for downloads).
        """
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(to_path, flags, 0o666)
        with os.fdopen(fd, mode="wb") as fobj:
            self.download_fileobj(
                from_path, fobj, callback=callback, chunk_size=chunk_size
            )

    def upload_file(
        self,
        from_path: "str | PathLike[str]",
        to_path: str,
        overwrite: bool = False,
        chunk_size: int | None = None,
        callback: "Callable[[int], Any] | None" = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        """Upload a local file to a remote path."""
        with pathlib.Path(from_path).open(mode="rb") as fobj:
            self.upload_fileobj(
                fobj,
                to_path,
                overwrite=overwrite,
                chunk_size=chunk_size,
                callback=callback,
                headers=headers,
            )

    def upload_fileobj(
        self,
        file_obj: BinaryIO,
        to_path: str,
        overwrite: bool = False,
        callback: "Callable[[int], Any] | None" = None,
        chunk_size: int | None = None,
        size: int | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        """Upload an open, readable file object to a remote path."""
        headers = dict(headers or {})

        # We try to avoid chunked transfer as much as possible, so we try
        # to use size as a hint if provided, else find it out from the
        # file object, else gracefully fall back to chunked encoding.
        if size is None:
            size = peek_filelike_length(file_obj)

        if not overwrite:
            # An `exists()` pre-check followed by a separate PUT would be a
            # TOCTOU race (another client could create the resource in
            # between); `If-None-Match: *` (RFC 7232 §3.2) makes the
            # not-already-there check atomic on the server, which maps a
            # conflicting PUT to 412 Precondition Failed -
            # ResourceAlreadyExistsError via the usual status-code table.
            headers.setdefault("If-None-Match", "*")

        def chunks() -> Iterator[bytes]:
            while data := file_obj.read(chunk_size or self.chunk_size):
                yield data
                if callback is not None:
                    callback(len(data))

        # SizedIterator lets `requests` learn the real length itself and
        # keep the upload streamed with a plain Content-Length - passing
        # size via our own header instead doesn't work, see its docstring.
        body: Iterator[bytes] | SizedIterator = (
            SizedIterator(chunks(), size) if size is not None else chunks()
        )
        self.request(
            Method.PUT, to_path, data=body, headers=headers, error_path=to_path
        )
