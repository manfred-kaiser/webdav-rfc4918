"""Exception hierarchy for the WebDAV client.

Every exception raised by this library derives from :class:`WebDAVError`,
which itself derives from :class:`requests.exceptions.RequestException`.
Code that already broadly catches requests' own exception hierarchy (a
common pattern in projects built on top of ``requests``) therefore also
catches everything this library raises, without needing to know about it
specifically.

HTTP-status-driven exceptions are looked up through ``STATUS_CODE_EXCEPTIONS``
by :func:`raise_for_status`, covering the status codes RFC 4918 gives
WebDAV-specific meaning to (207, 422, 423, 424, 507) in addition to the
regular HTTP 4xx/5xx codes a WebDAV server commonly returns.
"""

import inspect
import warnings
import xml.etree.ElementTree as ET
from http import HTTPStatus
from types import MappingProxyType
from typing import TYPE_CHECKING, ClassVar

import requests.exceptions

from webdav.url_safety import redact_url

if TYPE_CHECKING:
    import types
    from collections.abc import Mapping

    from requests import Response

#: RFC 4918 §16's <error> element lives in the DAV: namespace, same as
#: everything else this library parses off the wire.
_DAV_NAMESPACE = "DAV:"

# Non-standard status used by cPanel-based shared hosting (its bandwidth
# limit module, not Apache's own - httpd has no name for 509) to signal
# that a customer's bandwidth allotment was exceeded.
BANDWIDTH_LIMIT_EXCEEDED = 509


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


class IsACollectionError(ClientError):
    """Raised when a resource is a collection, but was expected not to be."""

    def __init__(self, path: str, msg: str = "") -> None:
        """Initialize with the path and an optional extra message."""
        self.path = path
        super().__init__(f"{path} is a collection. {msg}".rstrip())


class IsAResourceError(ClientError):
    """Raised when a resource is not a collection, but was expected to be."""

    def __init__(self, path: str, msg: str = "") -> None:
        """Initialize with the path and an optional extra message."""
        self.path = path
        super().__init__(f"{path} is not a collection. {msg}".rstrip())


class TLSConfigError(ClientError):
    """Raised when a client/CA certificate or key could not be loaded.

    Wraps the notoriously undifferentiated failures :mod:`ssl` itself
    raises (e.g. a bare ``ssl.SSLError: [SSL] PEM lib`` that doesn't say
    *which* of possibly several configured files was the culprit) with
    the path that was actually being loaded.
    """


class LockError(ClientError):
    """Raised for lock-token/`If`-header related failures.

    Covers cases the server never gets to reject, such as refreshing a
    lock without holding its token, or writing through a stale lock.
    """


class MalformedResponseError(ClientError):
    """Raised when a server response's body could not be parsed/understood.

    Covers non-well-formed XML in a 207 Multi-Status or LOCK response body,
    a multistatus reply missing an expected ``<d:response>`` entry, and a
    ``<d:response>``/``<d:activelock>`` whose ``href``/lock token doesn't
    make sense (e.g. points outside the requested subtree, or contains
    control characters). The HTTP exchange itself succeeded - this is
    specifically about the response body not being what RFC 4918 promises.
    """


class MultiStatusError(WebDAVError):
    """Raised when a 207 Multi-Status response contains per-resource errors."""

    def __init__(
        self,
        statuses: dict[str, str],
        error_codes: "dict[str, frozenset[str]] | None" = None,
    ) -> None:
        """Instantiate with a mapping of ``href`` to failure reason.

        Args:
            statuses: ``href`` (or ``"href (property)"`` for a PROPPATCH
                per-property failure) to a human-readable reason.
            error_codes: The same keys, mapped to the RFC 4918 §16
                precondition/postcondition codes (e.g.
                ``{"no-conflicting-lock"}``) the server's ``<d:error>``
                carried for that failure, if any.

        """
        self.statuses = statuses
        self.error_codes = error_codes or {}
        if len(statuses) > 1:
            msg = f"multiple errors received: {statuses}"
        else:
            href, status = next(iter(statuses.items()))
            msg = f"The resource {href} is {status.lower()}"
        self.msg = msg
        super().__init__(msg)


#: Request headers redacted on every raised :class:`HTTPStatusError` (see
#: ``_redact_request_headers``) - a calling application logging or
#: serializing the exception's ``.response`` (an APM/error tracker that
#: captures it by default, a bare ``logger.error("%r", exc.response)``)
#: must not put real credentials into storage it does not control.
_SENSITIVE_REQUEST_HEADERS = frozenset({"authorization", "cookie", "proxy-authorization"})


def _redact_request_headers(response: "Response") -> None:
    request = getattr(response, "request", None)
    headers = getattr(request, "headers", None)
    if not headers:
        return
    for name in list(headers):
        if name.lower() in _SENSITIVE_REQUEST_HEADERS:
            headers[name] = "[redacted]"


class HTTPStatusError(WebDAVError, requests.exceptions.HTTPError):
    """Raised when the server returned an unexpected/error HTTP status.

    A subclass registered in ``STATUS_CODE_EXCEPTIONS`` is raised instead
    whenever the status code is one this library gives special meaning to.
    """

    #: Class-level default used only to populate ``STATUS_CODE_EXCEPTIONS``
    #: (see ``_register``) - not read after that. The actual status of
    #: a raised instance is always ``self.status_code``, set in
    #: ``__init__`` from the real response, since a base ``HTTPStatusError``
    #: (an unregistered status code) has no fixed status of its own.
    default_status_code: ClassVar[int | None] = None
    #: Whether ``webdav.transport.retry`` should retry a request that failed with
    #: this status - i.e. the failure is plausibly transient.
    retryable: ClassVar[bool] = False

    def __init__(
        self,
        response: "Response",
        path: str | None = None,
        msg: str | None = None,
    ) -> None:
        """Instantiate with the failed response and the request path."""
        _redact_request_headers(response)
        self.response: Response = response
        self.path = path
        self.status_code: int = response.status_code
        self._error_codes: frozenset[str] | None = None
        reason = response.reason or _phrase_for(response.status_code)
        default = f"received {self.status_code} ({reason})"
        if path:
            default += f" for {path!r}"
        super().__init__(msg or default, response=response)

    @property
    def error_codes(self) -> "frozenset[str]":
        """RFC 4918 §16 precondition/postcondition codes from the response body.

        E.g. ``{"no-conflicting-lock"}`` for a 423 from
        :meth:`~webdav.fs.client.FileSystem.locked`,
        or ``{"lock-token-submitted"}`` for a write through a stale token -
        lets a caller distinguish *why* without re-parsing the response
        body itself. Lazily parsed and cached: most callers never need
        this, and most error responses carry no body (or a non-XML one) at
        all - either case is treated as "no codes", never an exception.
        """
        if self._error_codes is None:
            self._error_codes = _parse_error_codes(self.response)
        return self._error_codes


#: Cap for the lazy read in :func:`_bounded_error_body`. A real RFC 4918
#: ``<d:error>`` body is a handful of empty precondition/postcondition
#: elements - this is generous while still refusing to buffer an attacker's
#: multi-gigabyte error body in memory just because a caller checked
#: ``error_codes`` on a streamed response.
_MAX_ERROR_BODY_SIZE = 1 * 1024 * 1024


def _parse_error_codes(response: "Response") -> "frozenset[str]":
    # Local import, not at top-level: webdav.transport.body imports this module.
    # pylint: disable-next=import-outside-toplevel
    from webdav.transport.body import content_within  # noqa: PLC0415

    content = content_within(response, max_size=_MAX_ERROR_BODY_SIZE)
    if not content:
        return frozenset()
    try:
        # See webdav.dav.xml_utils's module docstring: stdlib expat never resolves
        # external entities and rejects entity-amplification by default.
        tree = ET.fromstring(content)  # noqa: S314 # nosec B314
    except (ET.ParseError, LookupError, ValueError, UnicodeError):
        return frozenset()
    tag = tree.tag
    local_name = tag.rpartition("}")[2] if tag.startswith("{") else tag
    if local_name == "mkcol-response":
        # RFC 5689 sec. 3: an Extended MKCOL failure's <error> sits inside
        # the <propstat> of the property that could not be set, not at the
        # document root or directly under it like every other method's.
        error_els = [
            el
            for propstat in tree.findall(f"{{{_DAV_NAMESPACE}}}propstat")
            if (el := propstat.find(f"{{{_DAV_NAMESPACE}}}error")) is not None
        ]
    else:
        single = (
            tree if local_name == "error" else tree.find(f"{{{_DAV_NAMESPACE}}}error")
        )
        error_els = [single] if single is not None else []
    codes = set()
    for error_el in error_els:
        for child in error_el:
            child_tag = child.tag
            codes.add(
                child_tag.rpartition("}")[2] if child_tag.startswith("{") else child_tag
            )
    return frozenset(codes)


def _phrase_for(status_code: int) -> str:
    try:
        return HTTPStatus(status_code).phrase
    except ValueError:
        return ""


_STATUS_CODE_EXCEPTIONS: dict[int, type[HTTPStatusError]] = {}

#: Which exception a status code raises (see :func:`raise_for_status`) - also
#: which ones a retry repeats (``retryable``). Read-only: a mapping that any
#: import could add to would let it change what every session in the process
#: raises and retries.
STATUS_CODE_EXCEPTIONS: "Mapping[int, type[HTTPStatusError]]" = MappingProxyType(
    _STATUS_CODE_EXCEPTIONS
)


def _register(exc_cls: type[HTTPStatusError]) -> type[HTTPStatusError]:
    assert exc_cls.default_status_code is not None
    _STATUS_CODE_EXCEPTIONS[exc_cls.default_status_code] = exc_cls
    return exc_cls


@_register
class ForbiddenError(HTTPStatusError):
    """Raised when the operation was forbidden (403)."""

    default_status_code = HTTPStatus.FORBIDDEN


@_register
class ResourceNotFoundError(HTTPStatusError):
    """Raised when the resource does not exist on the server (404)."""

    default_status_code = HTTPStatus.NOT_FOUND

    def __init__(self, response: "Response", path: str | None = None) -> None:
        """Instantiate with the failed response and the missing path."""
        msg = f"The resource {path} could not be found on the server" if path else None
        super().__init__(response, path=path, msg=msg)


@_register
class ResourceConflictError(HTTPStatusError):
    """Raised when there was a conflict during the operation (409)."""

    default_status_code = HTTPStatus.CONFLICT


@_register
class PreconditionFailedError(HTTPStatusError):
    """Raised when a condition the request set did not hold (412).

    ``If-Match``/``If-None-Match`` (a lost update, or a resource that is
    already there), ``Overwrite: F`` on a destination that exists, an ``If``
    header naming a lock token that is not (or no longer) held. The cause is
    in :attr:`~HTTPStatusError.error_codes` when the server gave one; where
    the library knows which condition it set, it raises the more specific
    :class:`ResourceAlreadyExistsError` instead.
    """

    default_status_code = HTTPStatus.PRECONDITION_FAILED

    def __init__(
        self,
        response: "Response",
        path: str | None = None,
        msg: str | None = None,
    ) -> None:
        """Instantiate with the failed response and the request path."""
        default = (
            f"A condition of the request was not met (412) for {path!r}"
            if path
            else None
        )
        super().__init__(response, path=path, msg=msg or default)


class ResourceAlreadyExistsError(PreconditionFailedError):
    """Raised when the resource that was to be created already exists.

    Not what a bare 412 turns into - a 412 can mean other things (see
    :class:`PreconditionFailedError`) - but what an operation that asked for
    "create, do not replace" raises when the server refuses: an upload with
    ``overwrite=False`` (``If-None-Match: *``) or ``mkdir`` on an existing
    collection.
    """

    def __init__(self, response: "Response", path: str | None = None) -> None:
        """Instantiate with the failed response and the existing path."""
        msg = f"The resource {path} already exists" if path else None
        super().__init__(response, path=path, msg=msg)


@_register
class UnprocessableEntityError(HTTPStatusError):
    """Raised when the request body was well-formed but semantically invalid (422)."""

    default_status_code = HTTPStatus.UNPROCESSABLE_ENTITY


@_register
class UnsupportedMediaTypeError(HTTPStatusError):
    """Raised when the request body's media type wasn't acceptable (415).

    For MKCOL (RFC 4918 §9.3.1), this means a non-empty request body that
    wasn't a valid Extended MKCOL body (RFC 5689).
    """

    default_status_code = HTTPStatus.UNSUPPORTED_MEDIA_TYPE


@_register
class ResourceLockedError(HTTPStatusError):
    """Raised when the resource is locked (423)."""

    default_status_code = HTTPStatus.LOCKED
    retryable = False  # a lock does not go away in the seconds a retry would wait


@_register
class FailedDependencyError(HTTPStatusError):
    """Raised when a method could not proceed because another action failed (424)."""

    default_status_code = HTTPStatus.FAILED_DEPENDENCY


@_register
class PreconditionRequiredError(HTTPStatusError):
    """Raised when the server requires the request to be conditional (428)."""

    default_status_code = HTTPStatus.PRECONDITION_REQUIRED


@_register
class TooManyRequestsError(HTTPStatusError):
    """Raised when the client is rate-limited (429)."""

    default_status_code = HTTPStatus.TOO_MANY_REQUESTS
    retryable = True


@_register
class InternalServerError(HTTPStatusError):
    """Raised on a generic server-side failure (500)."""

    default_status_code = HTTPStatus.INTERNAL_SERVER_ERROR
    retryable = True


@_register
class BadGatewayError(HTTPStatusError):
    """Raised when an upstream/proxy server refused the request (502)."""

    default_status_code = HTTPStatus.BAD_GATEWAY
    retryable = True

    def __init__(self, response: "Response", path: str | None = None) -> None:
        """Instantiate with the failed response."""
        msg = "the destination server may have refused to accept the resource"
        super().__init__(response, path=path, msg=msg)


@_register
class ServiceUnavailableError(HTTPStatusError):
    """Raised when the server is temporarily unable to handle the request (503)."""

    default_status_code = HTTPStatus.SERVICE_UNAVAILABLE
    retryable = True


@_register
class GatewayTimeoutError(HTTPStatusError):
    """Raised when an upstream/proxy server timed out (504)."""

    default_status_code = HTTPStatus.GATEWAY_TIMEOUT
    retryable = True


@_register
class InsufficientStorageError(HTTPStatusError):
    """Raised when the server has run out of storage space (507)."""

    default_status_code = HTTPStatus.INSUFFICIENT_STORAGE

    def __init__(self, response: "Response", path: str | None = None) -> None:
        """Instantiate with the failed response and the request path."""
        msg = "Insufficient Storage on the server"
        super().__init__(response, path=path, msg=msg)


@_register
class BandwidthLimitExceededError(HTTPStatusError):
    """Raised for the non-standard 509 Bandwidth Limit Exceeded status."""

    default_status_code = BANDWIDTH_LIMIT_EXCEEDED
    retryable = True


class RedirectNotFollowedError(HTTPStatusError):
    """Raised when the server answered with a redirect this request didn't follow.

    A :class:`~webdav.session.Session` only follows the redirects its
    :class:`~webdav.transport.redirects.RedirectPolicy` allows, so a malicious or
    compromised server can't silently redirect a write's body to an
    unintended resource or a different host - HTTP permits a 3xx response
    to any method (RFC 9110 sec. 15.4), so this can happen legitimately
    too, e.g. a cloud-storage gateway redirecting a PUT to a signed upload
    URL. The server's requested target is on the response:
    ``exc.response.headers.get("Location")``. Use
    ``RedirectPolicy.WHITELIST`` (or pass ``redirect_policy=`` on a call)
    if your server relies on this pattern.

    Not registered in ``STATUS_CODE_EXCEPTIONS`` (unlike every other
    subclass here) since it applies to a whole class of status codes
    (301/302/303/307/308), not one specific code.
    """

    retryable = False

    def __init__(self, response: "Response", path: str | None = None) -> None:
        """Instantiate with the unfollowed redirect and the request path."""
        reason = getattr(response, "redirect_refusal", None)
        location = response.headers.get("Location")
        msg = f"received {response.status_code} ({_phrase_for(response.status_code)})"
        if path:
            msg += f" for {path!r}"
        if location:
            msg += f", redirecting to {redact_url(location)!r}"
        msg += f" - not followed: {reason}" if reason else " - not followed"
        super().__init__(response, path=path, msg=msg)

    @property
    def reason(self) -> "str | None":
        """Why the redirect was not followed (``None`` if not recorded)."""
        reason: str | None = getattr(self.response, "redirect_refusal", None)
        return reason


class InsecureTransportWarning(UserWarning):
    """Credentials are about to be sent over plain ``http`` to a non-local host."""


class TLSHardeningDisabledWarning(UserWarning):
    """A TLS hardening measure was explicitly turned off for this session.

    Certificate verification, the 1.2 floor or strict chain checking.
    Deliberately its own class, not a subclass of anything ``urllib3``/``requests``
    already define (``urllib3.exceptions.InsecureRequestWarning`` and its
    ``HTTPWarning`` base) - ``urllib3.disable_warnings()`` filters on that
    hierarchy, a one-liner common enough in ``requests``-based code that relying
    on it would risk this warning being silenced by the same call that silenced
    the unrelated warning someone was actually trying to quiet. Also logged
    (``logging.getLogger("webdav")``), not just raised as a Python warning - and
    unlike a plain ``warnings.warn``, exempted below from the default filter's
    once-per-(message, category, module, line) deduplication, so a repeated
    insecure call keeps warning every time, not just the first.
    """


# See the class docstring: without this, Python's default warnings filter
# would print this warning only once per call site per process - which
# would quietly undersell what every other call to it does: the log line
# still fires each time either way, but the Python warning should too.
warnings.filterwarnings("always", category=TLSHardeningDisabledWarning)


class DeadlineDisabledWarning(UserWarning):
    """``max_response_time`` was set to ``None`` for this session.

    Without it, a server that answers one byte at a time - a trickle of
    header lines, an endless run of ``100 Continue``, chunked-body trailers
    that never end - can keep a request alive for as long as it likes (see
    :mod:`webdav.transport.deadline`); nothing else here stops it (a
    ``timeout=`` of ``requests``' own only bounds a single socket read).
    Deliberately a one-off warning at the point ``max_response_time`` is
    set, not repeated on every request the way
    :class:`TLSHardeningDisabledWarning` is: unlike disabling certificate
    verification, this does not hand anything to a network attacker on
    each individual exchange - it is one standing choice about how long a
    stuck request may run, worth seeing once, not on every call.
    """


def _in_this_package(frame: "types.FrameType") -> bool:
    """Whether ``frame`` belongs to this library (or is plumbing ``contextlib`` adds between its frames)."""
    name = frame.f_globals.get("__name__", "")
    return name in {"webdav", "contextlib"} or name.startswith("webdav.")


def warn_at_caller(message: str, category: type[Warning]) -> None:
    """``warnings.warn``, attributed to the first frame outside this library.

    A fixed ``stacklevel`` counts the library's own frames (a verb calls
    ``request``, which calls the retry wrapper, which calls ...) and is wrong
    as soon as one of them changes. Here the level is worked out on every call,
    so the warning always names the line of the caller's code that made the
    request - which is what the default warning filter deduplicates on and
    what a ``-W error`` or a ``filterwarnings`` entry has to be able to match.
    """
    frame = inspect.currentframe()
    level = 1
    while frame is not None and _in_this_package(frame):
        frame = frame.f_back
        level += 1
    warnings.warn(message, category, stacklevel=level)


def raise_for_status(response: "Response", path: str | None = None) -> None:
    """Raise the appropriate :class:`HTTPStatusError` subclass, if any.

    A 207 Multi-Status response is left alone - its body may contain
    per-resource failures, which :mod:`webdav.dav.multistatus` inspects
    separately, since the overall HTTP exchange itself succeeded.

    Raises:
        RedirectNotFollowedError: The response is a 3xx redirect that
            ``requests`` did not follow (``allow_redirects=False``).
            Checked before ``response.ok`` - a 3xx status is otherwise
            "ok" by ``requests``' own definition, which would otherwise
            let it through to a caller expecting e.g. a 207 body.

    """
    if response.is_redirect or response.is_permanent_redirect:
        raise RedirectNotFollowedError(response, path=path)
    # Not ``response.ok``: on a :class:`webdav.response.Response` that calls
    # back into ``raise_for_status()``, i.e. into this function.
    if not 400 <= response.status_code < 600:
        return
    exc_cls = STATUS_CODE_EXCEPTIONS.get(response.status_code, HTTPStatusError)
    raise exc_cls(response, path=path)
