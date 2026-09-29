# pylint: disable=too-many-lines  # one Session class is the single entry point; see pyproject
"""A :class:`requests.Session` that speaks WebDAV.

Everything ``requests.Session`` does keeps working exactly as documented
in ``requests`` itself (auth, adapters, hooks, cookies, connection pooling,
``timeout=``, ``verify=``, ``cert=``, ``stream=``, ...); this subclass adds
what WebDAV needs on top, in two groups that follow one naming rule:

- **HTTP/WebDAV verbs** - ``get``, ``put``, ``delete``, ``head``,
  ``options``, ``propfind``, ``proppatch``, ``mkcol``, ``copy``, ``move``,
  ``lock``, ``unlock`` - shaped like ``Session.get``/``.put``: they return
  a :class:`webdav.response.Response` and, like ``requests``, do not raise
  for an error status unless asked to (``raise_for_status()``, or
  ``raise_on_error=True``);
- **file-system operations** - ``ls``, ``info``, ``exists``, ``isdir``,
  ``open``, ``upload_file``, ``download_file``, ``mkdir``, ``remove``,
  ``locked``, ... - which return plain Python values and raise a
  :class:`~webdav.exceptions.WebDAVError` on failure.

Both take a full URL, or a path if the session has a ``base_url``.

It also brings a redirect policy that is safe for methods other than
``GET`` (see :mod:`webdav.redirects` - ``requests`` itself re-sends a
redirected ``PROPFIND`` as a bodiless request or turns it into a ``GET``),
automatic ``If`` headers for locks the session holds, retries of transient
failures, and a cap on how large a response body may be declared.
"""

import codecs
import dataclasses
import errno
import ipaddress
import logging
import math
import os
import pathlib
import re
import secrets
import shutil
import tempfile
import threading
import time
import warnings
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from datetime import timedelta
from http import HTTPStatus
from io import TextIOWrapper
from typing import (
    TYPE_CHECKING,
    Any,
    BinaryIO,
    Literal,
    TextIO,
    cast,
    overload,
)
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

import requests
import requests.auth
import urllib3.exceptions
import urllib3.response
from requests.cookies import extract_cookies_to_jar
from requests.hooks import dispatch_hook
from requests.structures import CaseInsensitiveDict
from requests.utils import default_headers, requote_uri, resolve_proxies

from webdav.conditional import (
    entity_tag,
    token_condition,
)
from webdav.deadline import DeadlineAdapter, watch
from webdav.exceptions import (
    STATUS_CODE_EXCEPTIONS,
    ClientError,
    HTTPStatusError,
    InsecureConfigurationError,
    InsecureTransportWarning,
    IsACollectionError,
    IsAResourceError,
    MalformedResponseError,
    PreconditionFailedError,
    ResourceAlreadyExistsError,
    ResourceNotFoundError,
    raise_for_status,
)
from webdav.fs_utils import peek_filelike_length
from webdav.locks import (
    _TOKEN_RE,
    DEFAULT_LOCK_TIMEOUT,
    EXCLUSIVE,
    ActiveLock,
    LockRegistry,
    build_lock_body,
    check_token,
    format_timeout,
    parse_lock_response,
)
from webdav.methods import Method
from webdav.multistatus import parse_multistatus_response
from webdav.parse_utils import parse_uint
from webdav.properties import (
    build_propfind_body,
    build_proppatch_body,
)
from webdav.redirects import (
    MAX_REDIRECTS,
    RedirectPolicy,
    build_trust_check,
    effective_origin,
    has_replayable_body,
    redact_url,
    validate_policy,
)
from webdav.resource import Resource
from webdav.response import Response, adopt
from webdav.retry import retry as _retry
from webdav.streaming import DEFAULT_CHUNK_SIZE, IterStream, SizedIterator
from webdav.tls import mount_mtls_adapter
from webdav.urls import URL, join_url, path_key, relative_url_to

if TYPE_CHECKING:
    import urllib.parse
    from collections.abc import Callable, Iterable, Mapping, MutableMapping
    from datetime import datetime
    from os import PathLike
    from xml.etree.ElementTree import Element

    from requests.auth import AuthBase

    from webdav.multistatus import MultiStatusResponse
    from webdav.multistatus import Response as ResourceResponse
    from webdav.properties import DAVProperties, PropName
    from webdav.redirects import Origin
    from webdav.retry import RetryFunc
    from webdav.tls import TLSOptions

    AuthTypes = AuthBase | tuple[str, str] | None
    CertTypes = str | tuple[str, str] | None

#: Applied whenever a call site doesn't set its own ``timeout=`` -
#: ``requests`` itself defaults to *no* timeout, which lets a stalled
#: connection hang a program forever. (connect, read) seconds.
DEFAULT_TIMEOUT = (10, 60)

#: Default cap on a single response body this session will accept when it
#: is not streamed (PROPFIND/PROPPATCH/LOCK responses, ... - not
#: ``stream=True`` downloads). A malicious or compromised server has no
#: other way to force the client to allocate an unbounded amount of memory
#: for a single request; ``None`` disables the check for deployments that
#: legitimately need a bigger tree in one PROPFIND. Only actually caps
#: responses that send a (truthful) Content-Length.
DEFAULT_MAX_RESPONSE_SIZE = 64 * 1024 * 1024  # 64 MiB

#: Default deadline for the whole body of a non-streamed response, in
#: seconds. Generous for a big PROPFIND on a slow line; finite, because
#: ``timeout`` alone lets a server that drips bytes hold a request forever.
DEFAULT_MAX_RESPONSE_TIME = 300.0

#: The positional parameters of ``requests.Session.request`` after
#: ``method`` and ``url``, in order - kept so positional calls still work.
_REQUEST_PARAMS = (
    "params",
    "data",
    "headers",
    "cookies",
    "files",
    "auth",
    "timeout",
    "allow_redirects",
    "proxies",
    "hooks",
    "stream",
    "verify",
    "cert",
    "json",
)

#: Headers that are credentials or capabilities of *this* server and so
#: must never be forwarded to another origin a redirect lands on: login
#: credentials, session cookies, a lock token (``If``/``Lock-Token``, a
#: bearer capability for one resource), and ``Destination`` (which names
#: a resource on the *original* server).
_NEVER_FORWARD = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "if",
        "lock-token",
        "destination",
    }
)

#: The only per-call headers a cross-origin redirect keeps: the ones that
#: describe the representation being sent or the conditions of the request.
#: Everything else - a custom ``X-Api-Key``, a bearer token in a header the
#: library cannot recognise as one - is dropped, because a whitelisted
#: origin is trusted with the *body*, not with whatever else the caller
#: attached. Extend with ``Session.redirect_forward_headers``.
_FORWARD_HEADERS = frozenset(
    {
        "content-type",
        "content-encoding",
        "content-language",
        "content-md5",
        "accept",
        "accept-language",
        "range",
        "if-match",
        "if-none-match",
        "if-modified-since",
        "if-unmodified-since",
    }
)

#: Methods that change something: only these carry the ``If`` header of a held
#: lock. A read has no use for a lock token, and sending one anyway would
#: only put a capability on the wire for nothing.
_WRITE_METHODS = frozenset(
    {
        Method.PUT,
        Method.DELETE,
        Method.PROPPATCH,
        Method.MKCOL,
        Method.COPY,
        Method.MOVE,
        "POST",
        "PATCH",
    }
)

#: Methods whose request body is an XML document (RFC 4918).
_XML_BODY_METHODS = frozenset(
    {Method.PROPFIND, Method.PROPPATCH, Method.MKCOL, Method.LOCK}
)


class _NoAuth(requests.auth.AuthBase):
    """Authentication that adds nothing.

    Passing this as ``auth`` when the caller gave none stops ``requests``
    from looking the host up in ``~/.netrc`` and silently authenticating with
    whatever it finds there: credentials are only ever the ones asked for.
    """

    def __call__(self, r: requests.PreparedRequest) -> requests.PreparedRequest:
        return r


_NO_AUTH = _NoAuth()

#: Marks a reason string (rather than a URL) returned by ``Session._hop_target``.
_REASON_PREFIX = "\x00reason:"

_URL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")

#: The attributes (beyond ``requests.Session.__attrs__``) a pickled
#: session keeps; see ``Session._init_derived`` for what is rebuilt.
_PICKLED = (
    "base_url",
    "timeout",
    "redirect_policy",
    "max_response_size",
    "raise_on_error",
    "chunk_size",
    "max_response_time",
    "redirect_forward_headers",
    "_retry_arg",
    "_trusted_arg",
)

#: The modes :meth:`Session.open` understands.
_OPEN_MODES = frozenset({"r", "rt", "rb", "w", "wt", "wb", "x", "xt", "xb"})

#: ``walk`` refuses to go deeper / visit more collections than this, however
#: the caller set ``max_depth`` - see ``Session.walk``.
_WALK_MAX_DEPTH = 256
_WALK_MAX_DIRS = 100_000

#: A write-mode ``open`` keeps this many bytes in memory before spilling to disk.
_SPOOL_SIZE = 8 * 1024 * 1024

_DEPTHS = ("0", "1", "infinity")


def _check_depth(depth: "int | str", allowed: "Iterable[str]", method: str) -> str:
    value = str(depth)
    if value not in allowed:
        msg = f"{method} Depth must be one of {', '.join(allowed)}, got {depth!r}"
        raise ValueError(msg)
    return value


#: How much of a redirect's own body is kept for ``response.history``.
_MAX_REDIRECT_BODY = 1024 * 1024

#: Read granularity of :func:`_read_bounded`.
_READ_CHUNK = 64 * 1024

_LOOPBACK_NAMES = frozenset({"localhost", "localhost.localdomain"})

_LOGGER = logging.getLogger("webdav")


def _refuse(response: requests.Response, reason: str) -> None:
    """Record (and log) why a redirect was not followed."""
    if isinstance(response, Response):
        response.redirect_refusal = reason
    _LOGGER.warning(
        "not following the %s redirect from %s to %s: %s",
        response.status_code,
        redact_url(response.url),
        redact_url(response.headers.get("Location", "")),
        reason,
    )


def _iter_body(response: requests.Response) -> "Iterator[bytes]":
    """Yield a streamed body in whatever pieces arrive, without waiting to fill a buffer.

    ``iter_content(n)`` blocks until ``n`` bytes have arrived, so a server
    sending one byte just inside the read timeout keeps it waiting for days;
    ``read1`` hands back what is there, and gives the caller a chance to look
    at the clock after every read.
    """
    raw = response.raw
    read1 = getattr(raw, "read1", None)
    if not isinstance(raw, urllib3.response.BaseHTTPResponse) or read1 is None:
        # A body that is not urllib3's (a custom adapter's, a test double).
        yield from response.iter_content(chunk_size=_READ_CHUNK)
        return
    try:
        while chunk := read1(_READ_CHUNK, decode_content=True):
            yield chunk
    except urllib3.exceptions.ProtocolError as exc:
        raise requests.exceptions.ChunkedEncodingError(exc, response=response) from exc
    except urllib3.exceptions.DecodeError as exc:
        raise requests.exceptions.ContentDecodingError(exc) from exc
    except urllib3.exceptions.ReadTimeoutError as exc:
        raise requests.exceptions.ConnectionError(exc, response=response) from exc
    except urllib3.exceptions.SSLError as exc:
        raise requests.exceptions.SSLError(exc, response=response) from exc


def _read_bounded(
    response: requests.Response,
    max_size: "int | None",
    max_time: "float | None" = None,
) -> None:
    """Read the body of a streamed ``response`` into memory - within a size and a time budget.

    Counts the bytes *after* decoding (``Content-Encoding``), so a small
    gzip body that inflates to gigabytes is stopped as surely as a chunked
    response that never ends; a declared ``Content-Length`` over the cap
    is rejected without reading anything. ``max_time`` is a deadline for the
    *whole* body: the timeouts of ``requests`` apply to each single read, so
    on their own they let a server that drips one byte at a time keep a
    request alive indefinitely. ``None`` for either means no limit.

    Raises:
        ClientError: The body is larger than ``max_size`` or takes longer
            than ``max_time`` seconds.

    """
    if max_size is None and max_time is None:
        _ = response.content
        return
    codings = [
        c for c in response.headers.get("Content-Encoding", "").split(",") if c.strip()
    ]
    if len(codings) > 1:
        # ``gzip, gzip, gzip``: each layer multiplies what a few kilobytes
        # inflate to, and (before urllib3 2.6) is undone in one piece before
        # the size cap can look at it. No legitimate server stacks codings.
        response.close()
        msg = f"refusing a response with stacked content-codings ({', '.join(c.strip() for c in codings)})"
        raise ClientError(msg)
    declared = parse_uint(response.headers.get("Content-Length"))
    if max_size is not None and declared is not None and declared > max_size:
        response.close()
        msg = (
            f"response declared Content-Length {declared} bytes, "
            f"exceeding the configured limit of {max_size} bytes"
        )
        raise ClientError(msg)
    deadline = None if max_time is None else time.monotonic() + max_time
    chunks: list[bytes] = []
    total = 0
    for chunk in _iter_body(response):
        total += len(chunk)
        if max_size is not None and total > max_size:
            response.close()
            msg = f"response body exceeds the configured limit of {max_size} bytes"
            raise ClientError(msg)
        if deadline is not None and time.monotonic() > deadline:
            response.close()
            msg = f"response body did not arrive within the configured time of {max_time} seconds"
            raise ClientError(msg)
        chunks.append(chunk)
    # What ``response.content`` would have stored, minus the unbounded read.
    body = b"".join(chunks)
    _set_body(response, body)


def _set_body(response: requests.Response, body: bytes) -> None:
    """Store ``body`` as what ``response.content`` returns (requests has no public way)."""
    # pylint: disable=protected-access
    response._content = body  # noqa: SLF001
    response._content_consumed = True  # type: ignore[attr-defined]  # noqa: SLF001


def _read_response(
    response: requests.Response,
    method: str,
    max_size: "int | None",
    max_time: "float | None",
) -> None:
    """Read the body of a streamed ``response`` - if it has one - within the size and time budget.

    A ``HEAD`` reply, a ``1xx``/``204``/``304`` carries no body whatever its
    ``Content-Length`` says (the length of what a ``GET`` would have sent):
    nothing is read, and that length is no reason to refuse it.
    """
    status = response.status_code
    if method.upper() == "HEAD" or status in (204, 304) or 100 <= status < 200:
        _set_body(response, b"")
        response.close()
        return
    _read_bounded(response, max_size, max_time)


def _prepare_body(method: str, kwargs: dict[str, Any]) -> None:
    """Give a request body its final form: XML gets its type, text becomes UTF-8 bytes."""
    if method in _XML_BODY_METHODS and kwargs.get("data") is not None:
        _prepare_xml_body(kwargs)
    if isinstance(kwargs.get("data"), str):
        # Text is sent as UTF-8 whatever ``requests`` version is installed
        # (older ones leave it to ``http.client``, which encodes Latin-1 and
        # declares a Content-Length that no longer matches the bytes).
        kwargs["data"] = kwargs["data"].encode("utf-8")


def _prepare_xml_body(kwargs: dict[str, Any]) -> None:
    """Give an XML request body its ``Content-Type`` and, if text, encode it as UTF-8.

    ``requests`` (before 2.32) leaves a ``str`` body to ``http.client``,
    which encodes it as ISO-8859-1 and fails on anything outside that
    range - while the body is XML, whose default encoding is UTF-8.
    """
    headers = CaseInsensitiveDict(kwargs.get("headers") or {})
    content_type = headers.get("Content-Type")
    if content_type is None:
        headers["Content-Type"] = "application/xml; charset=utf-8"
    data = kwargs["data"]
    declares_other_charset = (
        content_type is not None
        and "charset" in content_type.lower()
        and "utf-8" not in content_type.lower()
    )
    if isinstance(data, str) and not declares_other_charset:
        kwargs["data"] = data.encode("utf-8")
    kwargs["headers"] = dict(headers)


def _deadline_error(seconds: "float | None") -> ClientError:
    return ClientError(
        f"the request did not complete within the configured time of {seconds} seconds"
    )


def _bounded_chunks(
    fileobj: BinaryIO,
    size: "int | None",
    chunk_size: int,
    callback: "Callable[[int], Any] | None",
    problem: list[str],
) -> "Iterator[bytes]":
    """The chunks of ``fileobj``, exactly ``size`` bytes of them (any length if ``size`` is ``None``).

    A file that is longer or shorter than declared ends the upload with a
    :class:`~webdav.exceptions.ClientError` (its message is also put in ``problem``,
    for the caller to raise when the request itself breaks in consequence).
    """
    sent = 0
    while True:
        want = chunk_size if size is None else min(chunk_size, size - sent)
        if want <= 0:
            if fileobj.read(1):
                problem.append(
                    f"the file is longer than the {size} bytes it was declared to be"
                )
                raise ClientError(problem[0])
            return
        data = fileobj.read(want)
        if not data:
            if size is not None and sent != size:
                problem.append(
                    f"the file ended after {sent} of the {size} bytes it was declared to be"
                )
                raise ClientError(problem[0])
            return
        sent += len(data)
        yield data
        if callback is not None:
            callback(len(data))


def _split(url: str) -> "urllib.parse.SplitResult":
    """``urlsplit`` that reports an unparseable URL as the library's own error."""
    try:
        return urlsplit(url)
    except ValueError as exc:
        msg = f"not a valid URL: {redact_url(url)!r}"
        raise ClientError(msg) from exc


def _verification_on(verify: object) -> bool:
    """Whether ``verify`` means "check the server's certificate" (to ``requests``, anything falsy does not)."""
    return verify is True or (
        isinstance(verify, str | os.PathLike) and bool(os.fspath(verify))
    )


def _check_chunk_size(value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        msg = f"chunk_size must be a positive integer, got {value!r}"
        raise ValueError(msg)


def _display(path: str) -> str:
    """``path`` for a message: a URL loses its userinfo, query and fragment."""
    return redact_url(path) if _URL_RE.match(path) else path


#: The character sets a server's ``Content-Type`` may select for text reads.
_TEXT_CHARSETS = frozenset(
    {
        "utf-8",
        "utf_8",
        "ascii",
        "iso8859-1",
        "latin-1",
        "cp1252",
        "utf-16",
        "utf-16-le",
        "utf-16-be",
        "utf-32",
    }
)


def _text_charset(name: "str | None") -> "str | None":
    """``name`` if it is a text encoding worth trusting from a server, else ``None``."""
    if not name:
        return None
    try:
        canonical = codecs.lookup(name).name
    except LookupError:
        return None
    return canonical if canonical in _TEXT_CHARSETS else None


def _strong_etag(value: str) -> str:
    """``value`` as the entity-tag ``If-Match`` needs (RFC 9110 sec. 13.1.1: strong comparison only).

    A server's own spelling (``"abc"``) and a bare value (``abc``, as some
    WebDAV servers report ``getetag``) are both written as ``"abc"``;
    ``*`` is passed through.

    Raises:
        ValueError: The ETag is weak, or not a valid entity-tag.

    """
    if value.startswith("W/"):
        msg = (
            f"a weak ETag cannot be used in If-Match (RFC 9110 sec. 13.1.1): {value!r}"
        )
        raise ValueError(msg)
    return value if value == "*" else entity_tag(value)


def _is_loopback(host: str) -> bool:
    if host.lower() in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _direct_members(
    responses: "list[ResourceResponse]", own: "ResourceResponse | None", own_key: str
) -> "list[ResourceResponse]":
    """The entries of a ``Depth: 1`` listing that are direct members of the collection asked for.

    An entry outside the collection is a lie or a bug - refused, never
    followed (``walk`` and anything built on ``ls`` would walk out of the
    subtree); one deeper down means the server ignored ``Depth: 1``, and is
    left out.
    """
    prefix = own_key.rstrip("/") + "/"
    members = []
    for resp in responses:
        if resp is own:
            continue
        key = path_key(resp.path)
        if not key.startswith(prefix):
            msg = f"server response href {resp.href!r} is outside the listed collection"
            raise MalformedResponseError(msg)
        if "/" not in key[len(prefix) :]:
            members.append(resp)
    return members


def _resource(response: "ResourceResponse", base_url: URL) -> Resource:
    """The :class:`~webdav.resource.Resource` a multistatus entry describes."""
    props = response.properties
    return Resource(
        response.path_relative_to(base_url),
        href=response.href,
        is_dir=props.resource_type == "directory",
        size=props.content_length,
        created=props.created,
        modified=props.modified,
        etag=props.etag,
        content_type=props.content_type,
        content_language=props.content_language,
        display_name=props.display_name,
    )


class FeatureDetection:
    """Server features detected via an OPTIONS request.

    Mostly used for detecting ``Accept-Ranges`` support, since some
    servers (e.g. ownCloud/Nextcloud) don't advertise it on GET responses.
    """

    supports_ranges: bool
    dav_compliances: set[str]

    def __init__(self, options_response: "requests.Response | None" = None) -> None:
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
    session: "Session",
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


#: Methods a transient failure (429, 5xx, a dropped connection) is retried
#: for: the *safe* ones (RFC 9110 sec. 9.2.1) - ``PROPFIND`` is a read. Never a
#: write: when the connection drops after the server acted, the retry finds
#: the work already done and reports the opposite of what happened (MKCOL
#: "exists", DELETE "not found", COPY "precondition failed"), and a lost
#: LOCK reply would leave an orphaned lock. Whoever knows a particular
#: write is safe to repeat can repeat it.
_RETRY_METHODS = frozenset({Method.GET, Method.HEAD, Method.OPTIONS, Method.PROPFIND})


class Session(requests.Session):
    """A :class:`requests.Session` extended with WebDAV.

    Examples:
        >>> session = Session("https://webdav.example.org", auth=("user", "password"))
        >>> session.ls("/", detail=False)
        >>> response = session.propfind("/dir/", depth=1)
        >>> response.multistatus.responses

    """

    def __init__(
        self,
        base_url: "str | None" = None,
        *,
        auth: "AuthTypes" = None,
        headers: "dict[str, str] | None" = None,
        cert: "CertTypes" = None,
        verify: "Literal[True] | str" = True,
        tls: "TLSOptions | None" = None,
        timeout: "float | tuple[float, float] | None" = DEFAULT_TIMEOUT,
        redirect_policy: RedirectPolicy = RedirectPolicy.SAME_ORIGIN,
        trusted_redirect_origins: "Iterable[str] | Callable[[str], bool] | None" = None,
        max_response_size: "int | None" = DEFAULT_MAX_RESPONSE_SIZE,
        retry: "RetryFunc | bool" = True,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        raise_on_error: bool = False,
    ) -> None:
        """Instantiate a session.

        Everything ``requests`` sets as an attribute after construction
        (``auth``, ``headers``, ``cert``, ``verify``) may also be given
        here, and can still be changed afterwards.

        Args:
            base_url: If given, request URLs may be paths relative to it
                (``session.get("/a.txt")``); a full URL is then only
                accepted for the same origin, so a stray absolute URL can
                never carry this session's credentials elsewhere. Left
                unset, every URL must be a full ``http(s)`` URL, and the
                names ``ls`` returns are relative to the server root.
            auth: A ``(user, password)`` tuple or a
                :class:`requests.auth.AuthBase` instance.
            headers: Default headers sent with every request to this
                session's own origin (never to another one a redirect
                lands on).
            cert: Client certificate for mTLS - a path to a combined
                cert+key PEM, or a ``(certfile, keyfile)`` tuple.
            verify: Server certificate verification - ``True`` (system
                trust store), or a path to a CA bundle. ``False`` is
                refused: there is deliberately no constructor parameter
                that turns verification off (``requests`` itself still lets
                you assign ``session.verify = False``, and ``urllib3`` warns
                when you do).
            tls: Advanced TLS knobs (encrypted private key, CRL checking,
                explicit cipher restriction) that plain ``cert=``/
                ``verify=`` cannot express - see
                :class:`~webdav.tls.TLSOptions`. Triggers the hardened
                :mod:`webdav.tls` adapter when given.
            timeout: Default ``(connect, read)`` timeout (or a single
                value for both) applied when a request doesn't set its
                own. ``None`` restores ``requests``' own no-timeout
                default - not recommended, see :data:`DEFAULT_TIMEOUT`.
            redirect_policy: Which redirects to follow - see
                :class:`~webdav.redirects.RedirectPolicy`. Overridable
                per call with ``redirect_policy=``; ``allow_redirects=False``
                on a call still means "never".
            trusted_redirect_origins: Which redirect targets
                :data:`RedirectPolicy.WHITELIST` follows, beyond this
                session's own origin. Either an iterable of exact origins
                (``"https://host"``) or a ``Callable[[str], bool]`` given
                the full target URL. Required with ``WHITELIST`` and
                rejected with any other policy.
            max_response_size: Reject a non-streamed response whose
                (truthful) ``Content-Length`` exceeds this many bytes.
                ``None`` disables the check.
            retry: Retry transient failures (429, 5xx,
                timeouts, dropped connections) of the safe and idempotent
                methods - or pass a callable implementing
                :class:`~webdav.retry.RetryFunc` directly.
            chunk_size: Default chunk size for streaming reads/writes.
            raise_on_error: Call :meth:`Response.raise_for_status` on every
                response before returning it (``requests`` itself never
                raises for a status code unless asked to).

        Raises:
            ValueError: ``trusted_redirect_origins`` and ``redirect_policy``
                disagree - see :func:`~webdav.redirects.validate_policy` -
                or ``verify`` is ``False``.

        """
        validate_policy(redirect_policy, trusted_redirect_origins)
        if not _verification_on(verify):
            msg = (
                f"verify={verify!r} is not accepted: server certificate verification "
                "cannot be switched off through the constructor - not with False, "
                "and not with anything else that requests reads as False (None, 0, "
                "an empty string). Give True, or the path of the CA bundle that "
                "signed the server's certificate."
            )
            raise InsecureConfigurationError(msg)
        _check_chunk_size(chunk_size)
        if max_response_size is not None and (
            isinstance(max_response_size, bool)
            or not isinstance(max_response_size, int)
            or max_response_size <= 0
        ):
            msg = f"max_response_size must be a positive integer or None, got {max_response_size!r}"
            raise ValueError(msg)
        super().__init__()
        # Adapters whose connections answer to the whole-request deadline
        # (see webdav.deadline); ``tls=`` below replaces the https one with
        # the mTLS adapter, which has the same property.
        self.mount("https://", DeadlineAdapter())
        self.mount("http://", DeadlineAdapter())
        self.auth = auth
        if headers:
            self.headers.update(headers)
        _configure_tls(self, cert=cert, verify=verify, tls=tls)
        self.base_url = base_url
        self.timeout = timeout
        self.redirect_policy = redirect_policy
        self.max_response_size = max_response_size
        self.raise_on_error = raise_on_error
        self.chunk_size = chunk_size
        #: Deadline, in seconds, for the whole body of a response that is not
        #: streamed (``None``: none). ``timeout`` only limits each single read.
        self._max_response_time: float | None = None
        self.max_response_time = DEFAULT_MAX_RESPONSE_TIME
        #: Names (lower case) of extra per-call headers a redirect to a
        #: trusted *other* origin may carry, beyond the representation and
        #: conditional headers it always keeps - e.g. ``{"x-amz-meta-owner"}``
        #: for a signed upload that has to repeat them.
        self._redirect_forward_headers: frozenset[str] = frozenset()
        self._retry_arg = retry
        self._trusted_arg = trusted_redirect_origins
        self._init_derived()

    def _init_derived(self) -> None:
        """(Re)build the state that follows from the constructor arguments.

        Kept apart from ``__init__`` because none of it can be pickled (a
        closure, a mutex): a copy or unpickled session gets fresh ones -
        which also means it holds none of the original's locks, as it
        must: a lock belongs to the server, not to a copy of an object.
        """
        self.with_retry = (
            self._retry_arg if callable(self._retry_arg) else _retry(self._retry_arg)
        )
        self.locks = LockRegistry()
        self._is_trusted_redirect_target = build_trust_check(self._trusted_arg)
        self._features: dict[Origin | str, FeatureDetection] = {}
        self._features_lock = threading.RLock()
        self._insecure_warned: set[str] = set()
        # What a redirect to another origin is sent through: a plain adapter,
        # so that neither a client certificate (mTLS) nor any transport
        # setting meant for *this* server goes with it.
        self._foreign_adapter = DeadlineAdapter()

    @property
    def max_response_time(self) -> "float | None":
        """Deadline in seconds for the whole body of a non-streamed response (``None``: none).

        Covers the *body*: the time to receive headers is limited only by
        ``timeout`` for each single read, as with any ``requests`` client - a
        server that drips header bytes just inside it can hold a request
        open. Keep the read timeout short where that matters.
        """
        return self._max_response_time

    @max_response_time.setter
    def max_response_time(self, seconds: "float | None") -> None:
        if seconds is not None and (
            isinstance(seconds, bool)
            or not isinstance(seconds, int | float)
            or not math.isfinite(seconds)
            or seconds <= 0
        ):
            msg = f"max_response_time must be a positive number of seconds or None, got {seconds!r}"
            raise ValueError(msg)
        self._max_response_time = seconds

    @property
    def redirect_forward_headers(self) -> "frozenset[str]":
        """Names of extra per-call headers a redirect to a trusted *other* origin may carry.

        Beyond the representation and conditional headers it always keeps -
        e.g. ``{"x-amz-meta-owner"}`` for a signed upload that has to repeat
        them. Any iterable of names, in any case, is accepted; stored lower-case.
        """
        return self._redirect_forward_headers

    @redirect_forward_headers.setter
    def redirect_forward_headers(self, names: "Iterable[str]") -> None:
        if isinstance(names, str):
            names = [names]
        self._redirect_forward_headers = frozenset(n.strip().lower() for n in names)

    def close(self) -> None:
        """Close the session and every connection pool it opened."""
        super().close()
        self._foreign_adapter.close()

    def merge_environment_settings(
        self,
        url: "str | bytes | None",
        proxies: "MutableMapping[str, str] | None",
        stream: "bool | None",
        verify: "bool | str | None",
        cert: "str | tuple[str, str] | None",
    ) -> Any:
        """Like ``requests``, but a CA bundle is only ever the one configured.

        ``requests`` lets ``REQUESTS_CA_BUNDLE``/``CURL_CA_BUNDLE`` from the
        environment replace ``verify=True`` - and so replace, or widen, the
        CA a caller pinned. Proxies from the environment are kept.
        """
        settings = super().merge_environment_settings(
            url, proxies, stream, verify, cert
        )
        settings["verify"] = verify if verify is not None else self.verify
        return settings

    def __getstate__(self) -> dict[str, Any]:
        """Pickle the configuration (``requests``' own attributes plus ours)."""
        return {
            name: getattr(self, name, None) for name in (*self.__attrs__, *_PICKLED)
        }

    def __setstate__(self, state: dict[str, Any]) -> None:
        """Restore from :meth:`__getstate__`, with fresh locks/caches."""
        for name, value in state.items():
            setattr(self, name, value)
        self._init_derived()

    # -- URL handling ---------------------------------------------------

    def resolve_url(self, url: str, add_trailing_slash: bool = False) -> str:
        """Turn ``url`` (a path relative to ``base_url``, or a full URL) into a full URL.

        A *full* URL (``scheme://...``) is used as it is written, and with a
        ``base_url`` must be on the same origin. A *path* is a plain path -
        what you would call the name, not its percent-encoded form: ``a%20b``
        is a file called "a%20b" - and is percent-encoded here, entirely
        (``%``, ``?``, ``#``, ``;`` and ``+`` included), exactly once. It is
        never split into a query or fragment; pass a query as ``params=``.
        A trailing ``/`` is kept: it says "this is a collection" (RFC 4918
        sec. 5.2).

        Raises:
            ClientError: ``url`` climbs out of ``base_url`` with ``..``, or
                is a full URL for a different origin than ``base_url``.

        """
        if self.base_url is None:
            return url
        if _URL_RE.match(url):
            if effective_origin(url) is None or effective_origin(
                url
            ) != effective_origin(self.base_url):
                msg = f"{redact_url(url)!r} is not on this session's base_url {redact_url(self.base_url)!r}"
                raise ClientError(msg)
            return url
        keep_slash = url.endswith("/") and bool(url.strip("/"))
        try:
            joined = join_url(
                URL(self.base_url),
                url,
                add_trailing_slash=add_trailing_slash or keep_slash,
            )
        except ValueError as exc:
            raise ClientError(str(exc)) from exc
        return str(joined.copy_with(query=""))

    # -- sending --------------------------------------------------------

    def request(  # type: ignore[override]
        self,
        method: str,
        url: str,
        *args: Any,
        redirect_policy: "RedirectPolicy | None" = None,
        **kwargs: Any,
    ) -> Response:
        """Send a request, exactly like :meth:`requests.Session.request`.

        Differences: the URL may be relative to ``base_url``; redirects
        follow this session's :class:`~webdav.redirects.RedirectPolicy`
        (``allow_redirects=False`` still disables them, and
        ``redirect_policy=`` overrides the policy for this one call); a
        held lock's token is attached as an ``If`` header; transient
        failures of safe/idempotent methods are retried; and the default
        ``timeout`` and ``max_response_size`` apply.
        """
        response = self._fetch(
            method, url, *args, redirect_policy=redirect_policy, **kwargs
        )
        if self.raise_on_error:
            response.raise_for_status()
        return response

    def _fetch(
        self,
        method: str,
        url: str,
        *args: Any,
        redirect_policy: "RedirectPolicy | None" = None,
        absolute: bool = False,
        **kwargs: Any,
    ) -> Response:
        """:meth:`request` without the ``raise_on_error`` step.

        ``absolute`` says ``url`` is already a full URL the library itself worked
        out (not something to resolve against ``base_url`` again).
        """
        if len(args) > len(_REQUEST_PARAMS):
            msg = f"request() takes at most {len(_REQUEST_PARAMS) + 2} positional arguments"
            raise TypeError(msg)
        for name, value in zip(_REQUEST_PARAMS, args, strict=False):
            if name in kwargs:
                msg = f"request() got multiple values for argument {name!r}"
                raise TypeError(msg)
            kwargs[name] = value

        if not absolute:
            url = self.resolve_url(url)
        self._require_full_url(url)
        _prepare_body(method, kwargs)
        allow = kwargs.pop("allow_redirects", None)
        policy = (
            RedirectPolicy.NEVER
            if allow is False
            else (redirect_policy or self.redirect_policy)
        )
        kwargs.setdefault("timeout", self.timeout)
        self._require_verification(kwargs.get("verify"))

        def attempt() -> Response:
            return self._fetch_once(method, url, policy, dict(kwargs))

        if method not in _RETRY_METHODS or not has_replayable_body(kwargs):
            return attempt()

        def checked() -> Response:
            response = attempt()
            exc_cls = STATUS_CODE_EXCEPTIONS.get(response.status_code)
            if exc_cls is not None and exc_cls.retryable:
                raise exc_cls(response)
            return response

        try:
            return self.with_retry(checked)
        except HTTPStatusError as exc:
            # Out of attempts: hand back the last response, as ``requests`` would.
            return cast("Response", exc.response)

    def _require_full_url(self, url: str) -> None:
        """Refuse a URL that is not one full, credential-free ``http(s)`` URL - with one error of ours.

        Unparseable, not http(s), ambiguous, or relative without a ``base_url``: not
        whichever error ``requests`` (or ``urlsplit``) would raise. Credentials
        belong in ``auth=``, not in a URL, which ends up in logs and messages.
        """
        if _URL_RE.match(url) and urlsplit(url).username is not None:
            msg = "a URL with credentials in it is refused: pass auth=(user, password) instead"
            raise ClientError(msg)
        if effective_origin(url) is None:
            msg = f"not a full http(s) URL: {redact_url(url)!r}" + (
                "" if self.base_url is not None else " (this session has no base_url)"
            )
            raise ClientError(msg)

    def _require_verification(self, verify: object) -> None:
        """Refuse to talk to a server whose certificate would not be checked.

        ``requests`` reads any falsy ``verify`` as "do not check", per call and
        as a session attribute; the constructor already refuses those, and this
        closes the other two doors. There is no way to switch this off: a session
        that talks to a server it does not authenticate hands the password to
        whoever answers - name the CA that signed the server's certificate
        (``verify="ca.pem"``) instead.
        """
        effective = self.verify if verify is None else verify
        if not _verification_on(effective):
            msg = (
                f"verify={effective!r}: this session does not talk to a server whose "
                "certificate is not verified. Use verify=True, or the path of the CA "
                "bundle that signed the server's certificate."
            )
            raise InsecureConfigurationError(msg)
        if (
            isinstance(effective, str | os.PathLike)
            and not pathlib.Path(effective).exists()
        ):
            msg = f"the CA bundle {os.fspath(effective)!r} (verify=) does not exist"
            raise ClientError(msg)

    def _headers_with_locks(
        self, method: str, url: str, caller_headers: "dict[str, str]"
    ) -> "dict[str, str]":
        """``caller_headers`` plus the ``If`` header of any held lock a write to ``url`` needs."""
        if method not in _WRITE_METHODS or any(
            k.lower() == "if" for k in caller_headers
        ):
            return dict(caller_headers)
        below = (url,) if method == Method.DELETE else ()
        header = self.locks.if_header(url, include_below=below)
        return {**caller_headers, "If": header} if header else dict(caller_headers)

    def _fetch_once(
        self, method: str, url: str, policy: RedirectPolicy, kwargs: dict[str, Any]
    ) -> Response:
        self._warn_if_insecure(url, kwargs)
        caller_headers: dict[str, str] = dict(kwargs.get("headers") or {})

        def kwargs_for(target: str) -> dict[str, Any]:
            """The arguments for a request to ``target`` on the origin we started at."""
            hop = {k: v for k, v in kwargs.items() if k != "params"}
            hop["headers"] = self._headers_with_locks(method, target, caller_headers)
            return hop

        # Always sent as a stream, so that no body (the answer itself, or a
        # redirect's) is read into memory before this session has had its
        # say on how big it may get - see _read_bounded.
        caller_streams = kwargs.get("stream")
        if caller_streams is None:
            caller_streams = self.stream
        kwargs["stream"] = True
        first = dict(kwargs)
        first["headers"] = self._headers_with_locks(method, url, caller_headers)

        budget = self.max_response_time
        # One deadline for the whole exchange - every hop, the headers, the
        # body and its trailers - unless the caller streams: then it covers
        # getting the response (headers) and the caller reads the rest.
        with watch(budget) as watcher:
            try:
                response = super().request(method, url, allow_redirects=False, **first)
                response = self._follow_redirects(
                    response, method, policy, kwargs, kwargs_for
                )
                if not caller_streams:
                    _read_response(response, method, self.max_response_size, None)
            except BaseException:
                if watcher is not None and watcher.expired.is_set():
                    raise _deadline_error(budget) from None
                raise
            if watcher is not None and watcher.expired.is_set():
                # A socket shut down mid-body can look like a clean end of the
                # data (EOF): never hand that back as a complete response.
                raise _deadline_error(budget)
        return cast("Response", response)

    def prepare_request(self, request: requests.Request) -> requests.PreparedRequest:
        """Prepare ``request``; with no credentials configured, none are looked up.

        ``requests`` would otherwise search ``~/.netrc`` for the host and
        authenticate with whatever it finds (see :class:`_NoAuth`).
        """
        if request.auth is None and self.auth is None:
            request.auth = _NO_AUTH
        return super().prepare_request(request)

    def send(self, request: requests.PreparedRequest, **kwargs: Any) -> Response:
        """Send one prepared request and return its response - never following a redirect.

        Replaces ``requests``' own, whose redirect handling (``resolve_redirects``:
        wrong methods and bodies for WebDAV, credentials and session headers
        carried along, a redirect's whole body read into memory, an
        unparseable ``Location`` raising a bare ``ValueError``) is exactly
        what this class exists to keep out of the picture. Redirects are
        followed - under this session's :class:`~webdav.redirects.RedirectPolicy` -
        by :meth:`request`; a 3xx that reaches the caller of ``send`` is
        returned as it is, with ``redirect_refusal`` set. The timeout,
        certificate-verification and body-size rules apply as they do to
        every request.
        """
        kwargs.setdefault("timeout", self.timeout)
        allow_redirects = kwargs.pop("allow_redirects", True)
        kwargs.setdefault("stream", self.stream)
        kwargs.setdefault("verify", self.verify)
        kwargs.setdefault("cert", self.cert)
        if "proxies" not in kwargs:
            kwargs["proxies"] = resolve_proxies(
                request, dict(self.proxies), self.trust_env
            )
        self._require_verification(kwargs["verify"])

        started = time.perf_counter()
        method = request.method or ""
        adapter = self.get_adapter(url=request.url or "")
        with watch(self.max_response_time) as watcher:
            try:
                response = adapter.send(request, **kwargs)
                response.elapsed = timedelta(seconds=time.perf_counter() - started)
                # Before any response hook runs: ``HTTPDigestAuth`` (and any
                # hook of the caller's) reads ``.content`` of a 401 to answer
                # it - which would be an unbounded, deadline-free read.
                hooks = request.hooks.get("response") if request.hooks else None
                if not kwargs["stream"] or (
                    hooks and response.status_code in (401, 407)
                ):
                    _read_response(response, method, self.max_response_size, None)
                response = dispatch_hook("response", request.hooks, response, **kwargs)  # type: ignore[no-untyped-call]
                extract_cookies_to_jar(self.cookies, request, response.raw)  # type: ignore[no-untyped-call]
            except BaseException:
                if watcher is not None and watcher.expired.is_set():
                    raise _deadline_error(self.max_response_time) from None
                raise
            if watcher is not None and watcher.expired.is_set():
                raise _deadline_error(self.max_response_time)
        result = adopt(response)
        if allow_redirects and (result.is_redirect or result.is_permanent_redirect):
            _refuse(
                result,
                "send() sends one request and never follows redirects; use request()",
            )
        return result

    def _warn_if_insecure(self, url: str, kwargs: dict[str, Any]) -> None:
        """Warn (once per host) when credentials are about to go out over plain ``http``."""
        parts = _split(url)
        if (
            parts.scheme.lower() != "http"
            or not parts.hostname
            or _is_loopback(parts.hostname)
        ):
            return
        credential_headers = {"authorization", "proxy-authorization", "cookie"}
        names = {k.lower() for k in (kwargs.get("headers") or {})} | {
            k.lower() for k in self.headers
        }
        per_call_auth = kwargs.get("auth")
        if not (
            (per_call_auth is not None and per_call_auth is not _NO_AUTH)
            or self.auth
            or parts.username is not None
            or names & credential_headers
        ):
            return
        # Host and port only: the netloc may carry the very password being warned about.
        host = (
            f"{parts.hostname.lower()}:{parts.port}"
            if parts.port
            else parts.hostname.lower()
        )
        with self._features_lock:
            if host in self._insecure_warned:
                return
            self._insecure_warned.add(host)
        warnings.warn(
            f"sending credentials to {host} over plain http - anyone on the network "
            "path can read them; use an https URL",
            InsecureTransportWarning,
            stacklevel=6,
        )

    # -- redirects ------------------------------------------------------

    def _follow_redirects(
        self,
        response: requests.Response,
        method: str,
        policy: RedirectPolicy,
        kwargs: dict[str, Any],
        kwargs_for: "Callable[[str], dict[str, Any]] | None" = None,
    ) -> requests.Response:
        """Follow redirects per ``policy``; stop (leaving the 3xx) on any doubt.

        Never delegated to ``requests``' own redirect-following, which for
        every status but 307/308 drops the body of the redirected request
        and for 302/303 turns any method into ``GET`` - wrong for WebDAV
        (a ``PROPFIND`` on a collection missing its trailing slash is
        commonly answered with a 301). A redirect this doesn't follow is
        returned as-is, with the reason on ``response.redirect_refusal``;
        :meth:`Response.raise_for_status` then reports it as
        :class:`~webdav.exceptions.RedirectNotFollowedError`.

        Every hop is judged against the origin the *request started at*, not
        against the page that redirected: after A sends us to B, a further
        redirect to another path on B is still "another origin" as far as
        our credentials are concerned, and gets the same stripped request.
        """
        origin_url = response.url
        seen = {origin_url}
        hops = 0
        while response.is_redirect or response.is_permanent_redirect:
            if policy == RedirectPolicy.NEVER:
                _refuse(response, "redirects are disabled for this request")
                break
            if hops >= MAX_REDIRECTS:
                _refuse(response, f"more than {MAX_REDIRECTS} redirects in a row")
                break
            hop = self._plan_hop(response, method, policy, kwargs, seen, origin_url)
            if isinstance(hop, str):
                _refuse(response, hop)
                break
            target, same_origin = hop
            previous = response
            # Keep the (small) body of a redirect for ``history``, but never
            # let it be an unbounded read.
            with suppress(ClientError):
                _read_bounded(previous, _MAX_REDIRECT_BODY, self.max_response_time)
            previous.close()
            hops += 1
            seen.add(target)
            if same_origin:
                # ``params`` were already merged into the original URL; the
                # Location is complete, and must not get them appended again.
                # The lock header is worked out again for *this* URL.
                hop_kwargs = (
                    kwargs_for(target)
                    if kwargs_for is not None
                    else {k: v for k, v in kwargs.items() if k != "params"}
                )
                response = super().request(
                    method, target, allow_redirects=False, **hop_kwargs
                )
            else:
                response = self._send_stripped(method, target, kwargs)
            response.history = [*previous.history, previous]
        return response

    def _plan_hop(
        self,
        response: requests.Response,
        method: str,
        policy: RedirectPolicy,
        kwargs: dict[str, Any],
        seen: "set[str]",
        origin_url: "str | None" = None,
    ) -> "tuple[str, bool] | str":
        """Decide whether ``response``'s redirect may be followed.

        Returns ``(target URL, stays on the origin the request started at)``,
        or - if it may not be followed - a sentence saying why.
        """
        target = self._hop_target(response, method)
        if target.startswith(_REASON_PREFIX):
            return target.removeprefix(_REASON_PREFIX)
        if target in seen:
            return "the redirect leads back to a URL already visited (a loop)"
        if not has_replayable_body(kwargs):
            return "the request body cannot be sent a second time"
        same_origin = self._may_follow(origin_url or response.url, target, policy)
        if isinstance(same_origin, str):
            return same_origin
        return target, same_origin

    def _hop_target(self, response: requests.Response, method: str) -> str:
        """The absolute URL ``response`` redirects to - or ``_REASON_PREFIX`` plus why it can't be used."""
        # RFC 9110 sec. 15.4.4: 303 means "retrieve the result with GET".
        # Re-sending a write (or a PROPFIND) to it would be wrong, and
        # silently turning it into a GET would report a write as done.
        if response.status_code == requests.codes.see_other and method not in (
            "GET",
            "HEAD",
        ):
            return (
                _REASON_PREFIX
                + "a 303 is only followed for GET/HEAD (RFC 9110 sec. 15.4.4)"
            )
        try:
            location = self.get_redirect_target(response)
            target = urljoin(response.url, location) if location else ""
        except (UnicodeError, ValueError):
            return _REASON_PREFIX + "the Location header is malformed"
        return target or _REASON_PREFIX + "the redirect has no Location"

    def _may_follow(
        self, source: str, target: str, policy: RedirectPolicy
    ) -> "bool | str":
        """Whether ``policy`` lets a request for ``source`` be redirected to ``target``.

        ``True``: yes, same origin. ``False``: yes, but to another origin
        (so nothing of ours may go along). A string: no, and why.
        """
        source_origin = effective_origin(source)
        target_origin = effective_origin(target)
        if source_origin is None or target_origin is None:
            return "the target is not one unambiguous http(s) URL"
        if source_origin == target_origin:
            return True
        trusted = (
            policy == RedirectPolicy.WHITELIST
            and self._is_trusted_redirect_target(target)
        )
        # Never step down from https to http on the strength of a policy
        # alone (even ALL): the body would cross the network in clear text.
        if source_origin[0] == "https" and target_origin[0] == "http" and not trusted:
            return "the redirect would downgrade https to http"
        if policy == RedirectPolicy.ALL or trusted:
            return False
        return "the target is on another origin and redirect_policy does not allow that"

    def _send_stripped(
        self, method: str, url: str, kwargs: dict[str, Any]
    ) -> requests.Response:
        """Send one request to another origin, carrying nothing that is ours.

        Built from scratch and sent through a plain adapter of its own, so
        that none of the session exists on it: no ``auth`` (and no netrc),
        no cookies - and none set by the answer, no default headers (which
        may include a custom API-key header this can't recognise as a
        credential), no client certificate, no hooks. Of the caller's own
        per-call headers only the representation/conditional ones in
        :data:`_FORWARD_HEADERS` (plus ``redirect_forward_headers``) are kept.
        """
        allowed = (_FORWARD_HEADERS | self._redirect_forward_headers) - _NEVER_FORWARD
        headers = default_headers()
        for name, value in (kwargs.get("headers") or {}).items():
            if name.lower() in allowed:
                headers[name] = value
        prepared = requests.PreparedRequest()
        prepared.prepare(
            method=method,
            url=url,
            headers=headers,
            data=kwargs.get("data"),
            json=kwargs.get("json"),
        )
        settings = self.merge_environment_settings(
            prepared.url or url,
            kwargs.get("proxies") or {},
            True,
            kwargs.get("verify"),
            None,
        )
        self._require_verification(settings["verify"])
        response = self._foreign_adapter.send(
            prepared,
            stream=True,
            timeout=kwargs.get("timeout"),
            verify=settings["verify"],
            cert=None,
            proxies=settings["proxies"],
        )
        return adopt(response)

    # -- HTTP verbs, typed to return a webdav Response --------------------

    def get(self, url: str, params: Any = None, **kwargs: Any) -> Response:  # type: ignore[override]
        """Send a ``GET``; like :meth:`requests.Session.get`."""
        kwargs.setdefault("allow_redirects", True)
        return self.request(Method.GET, url, params=params, **kwargs)

    def head(self, url: str, **kwargs: Any) -> Response:  # type: ignore[override]
        """Send a ``HEAD``; like :meth:`requests.Session.head` (redirects off by default)."""
        kwargs.setdefault("allow_redirects", False)
        return self.request(Method.HEAD, url, **kwargs)

    def options(self, url: str, **kwargs: Any) -> Response:  # type: ignore[override]
        """Send an ``OPTIONS``; like :meth:`requests.Session.options`."""
        kwargs.setdefault("allow_redirects", True)
        return self.request(Method.OPTIONS, url, **kwargs)

    def put(  # type: ignore[override]
        self,
        url: str,
        data: Any = None,
        *,
        if_match: "str | None" = None,
        overwrite: "bool | None" = None,
        **kwargs: Any,
    ) -> Response:
        """Send a ``PUT``; like :meth:`requests.Session.put`.

        Args:
            url: The resource.
            data: The body.
            if_match: Only replace the resource if its current ETag is this
                one (``If-Match``) - protection against a lost update. A
                weak ETag is refused (RFC 9110 sec. 13.1.1).
            overwrite: ``False`` only creates the resource, and fails with
                412 if it already exists (``If-None-Match: *``), atomically
                on the server - unlike an ``exists()`` check followed by a
                ``PUT``. Left unset, the ``PUT`` replaces what is there.
            **kwargs: Anything :meth:`requests.Session.request` takes.

        Raises:
            ValueError: ``if_match`` is a weak ETag, or is combined with
                ``overwrite=False`` (one requires the resource to exist,
                the other forbids it).

        """
        extra: dict[str, str | None] = {}
        if if_match is not None:
            if overwrite is False:
                msg = "if_match requires the resource to exist, overwrite=False forbids it"
                raise ValueError(msg)
            extra["If-Match"] = _strong_etag(if_match)
        if overwrite is False:
            extra["If-None-Match"] = "*"
        return self._with_headers(Method.PUT, url, kwargs, extra, data=data)

    def delete(  # type: ignore[override]
        self, url: str, *, if_match: "str | None" = None, **kwargs: Any
    ) -> Response:
        """Send a ``DELETE``; like :meth:`requests.Session.delete`.

        ``if_match`` only deletes the resource if its current ETag is this
        one - see :meth:`put`.
        """
        extra: dict[str, str | None] = {}
        if if_match is not None:
            extra["If-Match"] = _strong_etag(if_match)
        return self._with_headers(Method.DELETE, url, kwargs, extra)

    # -- WebDAV verbs ---------------------------------------------------

    def propfind(
        self,
        url: str,
        data: "str | bytes | None" = None,
        *,
        depth: "int | str | None",
        props: "Iterable[str | PropName] | None" = None,
        all_prop: bool = False,
        include: "Iterable[str | PropName] | None" = None,
        **kwargs: Any,
    ) -> Response:
        """Send a ``PROPFIND`` (RFC 4918 sec. 9.1).

        ``depth`` has no default, on purpose: an omitted ``Depth`` header
        means ``infinity`` to the server (sec. 9.1), a request for the
        whole tree that is a denial-of-service vector many servers refuse
        (Apache mod_dav by default; sabre/dav answers as if it were ``1``),
        while any default this library picked would silently return either
        too little or too much. Say what you want.

        Args:
            url: The resource.
            data: The request body. Without one (and without ``props``),
                the server treats it as ``allprop`` (sec. 9.1).
            props: Property names to request instead of writing the body
                yourself - see :func:`~webdav.properties.build_propfind_body`.
            all_prop: Request ``<d:allprop/>`` explicitly.
            include: Additional named properties to request alongside
                ``all_prop``.
            depth: Required, by keyword. ``0``: the resource itself. ``1``:
                the resource and its direct members (a directory listing).
                ``"infinity"``: the whole tree below it - often refused by
                the server. ``None``: send no ``Depth`` header at all and
                let the server apply its own default (``infinity`` per the
                RFC).
            **kwargs: Anything :meth:`requests.Session.request` takes.

        Raises:
            ValueError: ``data`` is combined with ``props``/``all_prop``/
                ``include``, or ``depth`` is not ``0``, ``1`` or ``infinity``.

        """
        if props is not None or all_prop or include is not None:
            if data is not None:
                msg = "pass either data or props/all_prop/include, not both"
                raise ValueError(msg)
            data = build_propfind_body(
                props, all_prop=all_prop or props is None, include=include
            )
        return self._with_headers(
            Method.PROPFIND,
            url,
            kwargs,
            {
                "Depth": (
                    _check_depth(depth, _DEPTHS, "PROPFIND")
                    if depth is not None
                    else None
                )
            },
            data=data,
        )

    def proppatch(
        self,
        url: str,
        data: "str | bytes | None" = None,
        *,
        set_props: "dict[str | PropName, Any] | None" = None,
        remove_props: "Iterable[str | PropName] | None" = None,
        **kwargs: Any,
    ) -> Response:
        """Send a ``PROPPATCH`` (RFC 4918 sec. 9.2).

        Either ``data`` (the body) or ``set_props``/``remove_props`` (which
        build it - see :func:`~webdav.properties.build_proppatch_body`).
        """
        if set_props is not None or remove_props is not None:
            if data is not None:
                msg = "pass either data or set_props/remove_props, not both"
                raise ValueError(msg)
            data = build_proppatch_body(set_props, remove_props)
        elif data is None:
            msg = "a PROPPATCH needs a body: data, or set_props/remove_props"
            raise ValueError(msg)
        return self.request(Method.PROPPATCH, url, data=data, **kwargs)

    def mkcol(
        self, url: str, data: "str | bytes | None" = None, **kwargs: Any
    ) -> Response:
        """Send a ``MKCOL`` (RFC 4918 sec. 9.3; RFC 5689 for a ``data`` body).

        A collection's URL should end in ``/`` (sec. 5.2); one is added if
        it is missing, rather than having the server redirect.
        """
        full = self.resolve_url(url)
        parts = urlsplit(full)
        if parts.path and not parts.path.endswith("/"):
            full = urlunsplit(parts._replace(path=parts.path + "/"))
        return self.request(Method.MKCOL, full, data=data, **kwargs)

    def copy(
        self,
        url: str,
        destination: str,
        *,
        overwrite: "bool | None" = False,
        depth: "int | str | None" = None,
        **kwargs: Any,
    ) -> Response:
        """Send a ``COPY`` (RFC 4918 sec. 9.8).

        Args:
            url: The source.
            destination: Where to copy to - a full URL, or a path relative
                to ``base_url``. Sent as the ``Destination`` header.
            overwrite: By keyword. ``False`` (the default) sends
                ``Overwrite: F``: an existing destination makes the server
                answer 412 instead of being silently replaced - the RFC's
                own default (``T``) loses data without a word. ``True``
                replaces it explicitly; ``None`` sends no header at all and
                leaves it to the server (``T``).
            depth: ``0`` or ``"infinity"`` - no other value is legal on a
                COPY (sec. 9.8.3). Left unset, the whole collection is
                copied, which is what copying a collection means.
            **kwargs: Anything :meth:`requests.Session.request` takes.

        """
        return self._transfer(Method.COPY, url, destination, overwrite, depth, kwargs)

    def move(
        self,
        url: str,
        destination: str,
        *,
        overwrite: "bool | None" = False,
        **kwargs: Any,
    ) -> Response:
        """Send a ``MOVE`` (RFC 4918 sec. 9.9); see :meth:`copy` for the arguments."""
        return self._transfer(Method.MOVE, url, destination, overwrite, None, kwargs)

    def lock(
        self,
        url: str,
        *,
        scope: str = EXCLUSIVE,
        owner: "str | Element | None" = None,
        depth: "int | str" = "infinity",
        lock_timeout: "int | Iterable[int | None] | None" = DEFAULT_LOCK_TIMEOUT,
        refresh: "str | None" = None,
        **kwargs: Any,
    ) -> Response:
        """Send a ``LOCK`` (RFC 4918 sec. 9.10).

        Returns the raw response; ``response.active_lock`` is the parsed
        lock. This does *not* record the lock for automatic ``If``
        headers - add it to :attr:`locks` for that.

        Args:
            url: The resource.
            scope: ``"exclusive"`` or ``"shared"``.
            owner: Plain text, or a pre-built element - see
                :func:`~webdav.locks.build_lock_body`.
            depth: ``"0"`` or ``"infinity"`` (sec. 9.10.4).
            lock_timeout: The ``Timeout`` header - seconds, ``None`` for
                infinite, or a preference list (the name avoids clashing
                with ``requests``' own network ``timeout=``).
            refresh: A lock token; sends a bodiless refresh request
                instead of creating a lock (sec. 9.10.2).
            **kwargs: Anything :meth:`requests.Session.request` takes.

        """
        headers = {"Timeout": format_timeout(lock_timeout)}
        if refresh is not None:
            headers["If"] = f"(<{check_token(refresh)}>)"
            return self._with_headers(Method.LOCK, url, kwargs, headers)
        headers["Depth"] = _check_depth(depth, ("0", "infinity"), "LOCK")
        headers["Content-Type"] = "application/xml; charset=utf-8"
        return self._with_headers(
            Method.LOCK, url, kwargs, headers, data=build_lock_body(scope, owner)
        )

    def unlock(self, url: str, token: str, **kwargs: Any) -> Response:
        """Send an ``UNLOCK`` for ``token`` (RFC 4918 sec. 9.11)."""
        check_token(token.strip("<>"))
        return self._with_headers(
            Method.UNLOCK, url, kwargs, {"Lock-Token": f"<{token.strip('<>')}>"}
        )

    # -- file-system operations: plain values, errors raised -----------------
    #
    # ``path`` is relative to ``base_url``; without a ``base_url`` it is a
    # full URL. Every operation raises a WebDAVError on failure, with the
    # ``path`` in its message.

    def _locate(
        self, path: str, add_trailing_slash: bool = False
    ) -> "tuple[str, URL, str]":
        """Resolve ``path`` to ``(full URL, base URL, path relative to that base)``."""
        if self.base_url is not None:
            url = self.resolve_url(path, add_trailing_slash=add_trailing_slash)
            base = URL(self.base_url)
            if _URL_RE.match(path):
                try:
                    return url, base, relative_url_to(base, URL(url).path)
                except ValueError as exc:
                    raise ClientError(str(exc)) from exc
            return url, base, path
        parsed = URL(path)
        if not parsed.is_absolute_url:
            msg = f"{path!r} is not a full http(s) URL and this session has no base_url"
            raise ClientError(msg)
        base = parsed.copy_with(path="/", query="")
        suffix = "/" if add_trailing_slash and not parsed.path.endswith("/") else ""
        return str(parsed.copy_with(path=parsed.path + suffix)), base, parsed.path

    def _send(
        self,
        method: str,
        path: str,
        *,
        add_trailing_slash: bool = False,
        error_path: "str | None" = None,
        multistatus: bool = True,
        **kwargs: Any,
    ) -> Response:
        """Send ``method`` for ``path``, raising the matching exception on failure.

        With ``multistatus`` (the default) a ``207`` reporting a failure
        for any individual resource raises too; a ``PROPFIND`` turns
        that off, since a per-property 404 there is just data.
        """
        url = self._locate(path, add_trailing_slash)[0]
        response = self._fetch(method, url, **kwargs)
        raise_for_status(response, path=_display(error_path or path))
        if multistatus and response.status_code == HTTPStatus.MULTI_STATUS:
            parse_multistatus_response(response).raise_for_status()
        return response

    def _propfind_parsed(
        self,
        path: str,
        data: "str | None" = None,
        headers: "dict[str, str] | None" = None,
        redirect_policy: "RedirectPolicy | None" = None,
    ) -> "MultiStatusResponse":
        """Send a ``PROPFIND`` and parse the multistatus response."""
        extra: dict[str, Any] = {}
        if redirect_policy is not None:
            extra["redirect_policy"] = redirect_policy
        response = self._send(
            Method.PROPFIND,
            path,
            multistatus=False,
            data=data,
            headers=headers,
            **extra,
        )
        return parse_multistatus_response(response)

    def features_for(self, path: str = "") -> FeatureDetection:
        """Features of the server ``path`` is on (cached per origin once a probe has answered)."""
        url = self._locate(path)[0]
        key: Origin | str = effective_origin(url) or url
        with self._features_lock:
            cached = self._features.get(key)
        if cached is not None:
            return cached
        # Probed outside the lock (a slow server must not block every other
        # thread's lookup); a failed probe is not remembered.
        try:
            response = self._fetch(Method.OPTIONS, url)
        except requests.RequestException:
            return FeatureDetection(None)
        detected = FeatureDetection(response)
        with self._features_lock:
            return self._features.setdefault(key, detected)

    def dav_compliance(self, path: str = "") -> set[str]:
        """Return the ``DAV:`` compliance classes the server advertises."""
        response = self._fetch(Method.OPTIONS, self._locate(path)[0])
        return FeatureDetection(response).dav_compliances

    def get_props(
        self,
        path: str,
        *,
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
        _url, base, rel = self._locate(path)
        data = build_propfind_body(
            names, all_prop=all_prop or not names, include=include
        )
        # Depth: 0 - this is a single-resource lookup, not a traversal.
        # Left unset, RFC 4918 sec. 9.1 says servers SHOULD default a
        # missing Depth to infinity, which would make a lookup against a
        # collection trigger a full recursive PROPFIND for one property.
        headers = {"Content-Type": "application/xml; charset=utf-8", "Depth": "0"}
        result = self._propfind_parsed(path, headers=headers, data=data)
        return result.get_response_for_path(base.path, rel).properties

    def set_props(
        self,
        path: str,
        *,
        set_props: "dict[str | PropName, Any] | None" = None,
        remove_props: "Iterable[str | PropName] | None" = None,
    ) -> None:
        """Set and/or remove properties via PROPPATCH (RFC 4918 sec. 9.2)."""
        data = build_proppatch_body(set_props, remove_props)
        headers = {"Content-Type": "application/xml; charset=utf-8"}
        self._send(Method.PROPPATCH, path, data=data, headers=headers)

    @contextmanager
    def locked(
        self,
        path: str,
        *,
        scope: str = EXCLUSIVE,
        depth: str = "infinity",
        lock_timeout: "int | Iterable[int | None] | None" = DEFAULT_LOCK_TIMEOUT,
        owner: "str | Element | None" = None,
    ) -> "Iterator[ActiveLock]":
        """Hold a WebDAV lock on ``path`` for the duration of the ``with`` block.

        Writes made through this same session to ``path`` (or, with
        ``depth="infinity"``, anything under it) automatically carry the
        held lock's token in an ``If`` header. The lock is released on
        exit, even if the block raised.

        Args:
            path: Resource to lock.
            scope: :data:`~webdav.locks.EXCLUSIVE` or
                :data:`~webdav.locks.SHARED`.
            depth: ``"0"`` or ``"infinity"`` - no other value is legal on
                a LOCK request (RFC 4918 sec. 9.10.4).
            lock_timeout: A single seconds value, ``None`` for infinite, or
                an ordered preference list - see
                :func:`~webdav.locks.format_timeout`.
            owner: Plain text, or a pre-built
                :class:`~xml.etree.ElementTree.Element` for a structured
                owner identity - see :func:`~webdav.locks.build_lock_body`.

        Raises:
            ValueError: ``depth`` is neither ``"0"`` nor ``"infinity"``.
            ClientError: The server did not grant the lock.
            MalformedResponseError: The server sent an unusable lock answer.

        """
        depth = _check_depth(depth, ("0", "infinity"), "LOCK")
        headers = {
            "Depth": depth,
            "Timeout": format_timeout(lock_timeout),
            "Content-Type": "application/xml; charset=utf-8",
        }
        # The URL that is locked - fixed now, so that whatever happens to the
        # session (a changed base_url, ...) the UNLOCK goes to the same place.
        url = self._locate(path)[0]
        response = self._send(
            Method.LOCK,
            path,
            multistatus=False,
            data=build_lock_body(scope, owner),
            headers=headers,
        )
        try:
            active_lock = parse_lock_response(response)
            # Always keyed by the *requested* URL, never by the server-supplied
            # <lockroot>: a malicious server could name an unrelated resource
            # there and make this session attach the token somewhere the
            # caller never asked to lock (see LockRegistry).
            self.locks.add(url, active_lock.token, depth)
        except (MalformedResponseError, ClientError):
            # The server granted a lock this side cannot use: release it (with
            # the token of the Lock-Token header, if that is a usable one)
            # instead of leaving it there until it times out.
            header_token = response.headers.get("Lock-Token", "").strip().strip("<>")
            if _TOKEN_RE.fullmatch(header_token):
                self._unlock_quietly(url, header_token)
            raise
        try:
            yield active_lock
        finally:
            self.locks.discard(url, active_lock.token, depth)
            self._unlock_quietly(url, active_lock.token)

    def _unlock_quietly(self, url: str, token: str) -> None:
        """Release the lock ``token`` on ``url``, never raising (and never hiding that it failed)."""
        try:
            self._fetch(
                Method.UNLOCK, url, absolute=True, headers={"Lock-Token": f"<{token}>"}
            )
        except requests.RequestException as exc:
            # A failed UNLOCK (a dropped connection, a refusal) must not
            # replace whatever the ``with`` body raised - nor hide that the
            # lock is still there: say so, and go on.
            _LOGGER.warning(
                "could not release the lock on %s: %s", redact_url(url), exc
            )

    def refresh_lock(
        self,
        path: str,
        token: str,
        *,
        lock_timeout: "int | Iterable[int | None] | None" = DEFAULT_LOCK_TIMEOUT,
    ) -> ActiveLock:
        """Refresh a held lock's timeout (RFC 4918 sec. 9.10.2).

        Sends a bodyless LOCK request carrying the lock's token in the
        ``If`` header - the RFC's mechanism for extending a lock's
        timeout without releasing and re-acquiring it, which would risk
        another client taking the lock in the gap between the two. No
        ``Depth`` header is sent, since the lock's depth was already
        fixed when it was created and can't change on refresh.

        Updates this session's own bookkeeping so a still-open
        :meth:`locked` block for the same lock keeps attaching the right
        token; the returned :class:`~webdav.locks.ActiveLock` reflects the
        refreshed timeout (the one an open block is already holding does
        not update itself - use this method's return value instead).
        """
        check_token(token)
        headers = {
            "If": token_condition(token),
            "Timeout": format_timeout(lock_timeout),
        }
        response = self._send(Method.LOCK, path, multistatus=False, headers=headers)
        active_lock = parse_lock_response(response, expected_token=token)
        self.locks.replace_token(token, active_lock.token)
        return active_lock

    def mkdir(self, path: str, *, data: str | None = None) -> None:
        """Create a collection.

        Args:
            path: Collection path.
            data: Optional Extended MKCOL request body (RFC 5689) to set
                a non-default resourcetype and/or properties at creation
                time. Sent with ``Content-Type: application/xml`` when given.

        """
        headers = {"Content-Type": "application/xml; charset=utf-8"} if data else None
        try:
            response = self._send(
                Method.MKCOL, path, add_trailing_slash=True, data=data, headers=headers
            )
        except HTTPStatusError as exc:
            if exc.status_code == HTTPStatus.METHOD_NOT_ALLOWED:
                raise ResourceAlreadyExistsError(exc.response, path) from exc
            raise

        if response.status_code not in (HTTPStatus.OK, HTTPStatus.CREATED):
            msg = f"unexpected status {response.status_code} from MKCOL"
            raise MalformedResponseError(msg)

    def remove(self, path: str) -> None:
        """Remove a resource (or a collection, with everything in it).

        Raises:
            ClientError: ``path`` is the root of the session (its ``base_url``, or
                the server's root) - deleting that is not something a slip of an
                empty string should be able to do.

        """
        url, base, _rel = self._locate(path)
        if path_key(URL(url).path) == path_key(base.path):
            msg = "refusing to remove the root of the session (its base_url): name what to remove"
            raise ClientError(msg)
        self._send(Method.DELETE, path)

    def ls(self, path: str) -> list[Resource]:
        """List the members of a collection.

        Always a list of :class:`~webdav.resource.Resource` - each is its own name
        (relative to ``base_url``, or to the server root without one) and carries
        what the server reported (``.size``, ``.is_dir``, ``.modified``, ...).

        Raises:
            IsAResourceError: ``path`` is not a collection (:meth:`info` describes one resource).
            ResourceNotFoundError: There is nothing at ``path``.

        """
        url, base, _rel = self._locate(path)
        result = self._propfind_parsed(path, headers={"Depth": "1"})
        responses = result.responses

        own_key = path_key(URL(url).path)
        own = responses.get(own_key)
        if own is None:
            # A case-insensitive server (IIS, SharePoint) may spell the
            # collection's own href differently from the request.
            folded = own_key.casefold()
            own = next(
                (r for k, r in responses.items() if k.casefold() == folded), None
            )
            if own is not None:
                own_key = path_key(own.path)
        if own is not None and own.properties.resource_type == "file":
            raise IsAResourceError(_display(path), "not a collection: use info()")
        members = _direct_members(result.entries, own, own_key)
        return [_resource(resp, base) for resp in members]

    def info(self, path: str) -> Resource:
        """Describe one resource (a file or a collection - not its members).

        The same :class:`~webdav.resource.Resource` :meth:`ls` returns for each member.
        """
        _url, base, rel = self._locate(path)
        result = self._propfind_parsed(path, headers={"Depth": "0"})
        return _resource(result.get_response_for_path(base.path, rel), base)

    def exists(self, path: str) -> bool:
        """Check whether a resource exists."""
        try:
            self._propfind_parsed(path, headers={"Depth": "0"})
        except ResourceNotFoundError:
            return False
        return True

    def _is_collection(self, path: str) -> "bool | None":
        """``True`` for a collection, ``False`` for anything else, ``None`` if there is nothing."""
        try:
            return bool(self.get_props(path, names=["resourcetype"]).collection)
        except ResourceNotFoundError:
            return None

    def isdir(self, path: str) -> bool:
        """Check whether a resource is a collection (``False`` if it does not exist)."""
        return self._is_collection(path) is True

    def isfile(self, path: str) -> bool:
        """Check whether a resource exists and is not a collection."""
        return self._is_collection(path) is False

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

    @overload
    @contextmanager
    def open(
        self,
        path: str,
        mode: Literal["rb", "wb", "xb"],
        *,
        encoding: str | None = ...,
        chunk_size: int | None = ...,
    ) -> Iterator[BinaryIO]: ...

    @overload
    @contextmanager
    def open(
        self,
        path: str,
        mode: Literal["r", "rt", "w", "wt", "x", "xt"] = ...,
        *,
        encoding: str | None = ...,
        chunk_size: int | None = ...,
    ) -> Iterator[TextIO]: ...

    @contextmanager
    def open(
        self,
        path: str,
        mode: str = "r",
        *,
        encoding: str | None = None,
        chunk_size: int | None = None,
    ) -> "Iterator[TextIO | BinaryIO]":
        """Open a resource for reading or writing, like the builtin ``open``.

        Modes ``r``/``rt``/``rb`` stream the resource down (resuming after
        a dropped connection). Modes ``w``/``wb`` collect what is written -
        in memory up to a threshold, on disk beyond it - and ``PUT`` it,
        replacing the resource, when the ``with`` block ends *without* an
        exception; ``x``/``xb`` do the same but fail if the resource
        already exists (``If-None-Match: *``, atomic on the server).
        Add ``t`` (or nothing) for text, ``b`` for bytes.
        """
        if mode not in _OPEN_MODES:
            msg = f"unsupported mode {mode!r}"
            raise ValueError(msg)
        if mode[0] == "r":
            yield from self._open_read(path, mode, encoding, chunk_size)
        else:
            yield from self._open_write(path, mode, encoding, chunk_size)

    def _open_read(
        self, path: str, mode: str, encoding: "str | None", chunk_size: "int | None"
    ) -> "Iterator[TextIO | BinaryIO]":
        if self.isdir(path):
            raise IsACollectionError(path, "cannot open a collection")

        with IterStream(
            self, self._locate(path)[0], chunk_size=chunk_size or self.chunk_size
        ) as buffer:
            buff = cast("BinaryIO", buffer)
            if mode == "rb":
                yield buff
            else:
                # The server does not get to pick the codec: only well-known text
                # encodings are taken from its Content-Type, anything else is UTF-8.
                enc = encoding or _text_charset(buffer.encoding) or "utf-8"
                yield TextIOWrapper(buff, encoding=enc)

    def _open_write(
        self, path: str, mode: str, encoding: "str | None", chunk_size: "int | None"
    ) -> "Iterator[TextIO | BinaryIO]":
        with tempfile.SpooledTemporaryFile(max_size=_SPOOL_SIZE, mode="w+b") as spool:
            if "b" in mode:
                yield cast("BinaryIO", spool)
            else:
                text = TextIOWrapper(spool, encoding=encoding or "utf-8")
                yield text
                text.flush()
                text.detach()  # leave ``spool`` open for the upload below
            # Reached only if the block raised nothing: a failed write must
            # never replace the remote resource with a half-written one.
            size = spool.seek(0, os.SEEK_END)
            spool.seek(0)
            self.upload_fileobj(
                cast("BinaryIO", spool),
                path,
                overwrite=mode[0] == "w",
                chunk_size=chunk_size,
                size=size,
            )

    def walk(
        self, path: str, *, max_depth: "int | None" = None
    ) -> "Iterator[tuple[str, list[Resource], list[Resource]]]":
        """Walk a collection tree top-down, like :func:`os.walk`.

        Yields ``(path, directories, files)`` for ``path`` and every collection
        below it. The members are the same :class:`~webdav.resource.Resource`
        objects :meth:`ls` returns - full names, usable as they are - not bare
        basenames as in :func:`os.walk`. Each collection costs one ``Depth: 1``
        PROPFIND - never ``Depth: infinity``, which servers commonly
        refuse and which would make one request return a whole tree.
        Remove a directory from the list to skip that subtree. A
        collection reachable a second time (RFC 5842 bindings can make a
        tree cyclic) is visited only once.

        Args:
            path: The collection to start at.
            max_depth: How many levels below ``path`` to descend; ``None``
                for no limit.

        """
        seen: set[str] = set()
        stack: list[tuple[str, int]] = [(path, 0)]
        while stack:
            current, depth = stack.pop()
            key = path_key(URL(self._locate(current)[0]).path)
            if key in seen:
                continue
            if depth > _WALK_MAX_DEPTH or len(seen) >= _WALK_MAX_DIRS:
                msg = (
                    f"walk gave up at {_display(current)!r}: more than {_WALK_MAX_DEPTH} levels "
                    f"deep or {_WALK_MAX_DIRS} collections - a server that invents directories "
                    "as you go never ends. Pass max_depth to bound it deliberately."
                )
                raise ClientError(msg)
            seen.add(key)
            entries = self.ls(current)
            dirnames = [e for e in entries if e.is_dir]
            files = [e for e in entries if not e.is_dir]
            subdirs = {e.name for e in dirnames}
            yield current, dirnames, files
            if max_depth is not None and depth >= max_depth:
                continue
            # Honours names the caller removed from ``dirnames``.
            stack.extend(
                (self._from_name(current, name.name), depth + 1)
                for name in reversed(dirnames)
                if name.name in subdirs
            )
            if len(seen) + len(stack) > _WALK_MAX_DIRS:
                # The queue counts too: one listing can announce a hundred
                # thousand subdirectories, and each waits in memory.
                msg = f"walk gave up: more than {_WALK_MAX_DIRS} collections found or queued"
                raise ClientError(msg)

    def _from_name(self, current: str, name: str) -> str:
        """The path (or, without a ``base_url``, URL) an ``ls`` entry ``name`` stands for."""
        if self.base_url is not None:
            return name
        return str(URL(current).copy_with(path="/" + name.lstrip("/"), query=""))

    def download_fileobj(
        self,
        path: str,
        fileobj: BinaryIO,
        *,
        chunk_size: int | None = None,
        callback: "Callable[[int], Any] | None" = None,
    ) -> None:
        """Write a resource's contents to an open, writable file object.

        Raises if the transfer does not complete - whatever was written to
        ``fileobj`` before then is a partial file, not a download.
        """
        if chunk_size is not None:
            _check_chunk_size(chunk_size)
        with self.open(path, mode="rb", chunk_size=chunk_size) as remote_obj:
            size = chunk_size or self.chunk_size
            # (pylint takes the @contextmanager result for a generator)
            while data := remote_obj.read(size):
                fileobj.write(data)
                if callback:
                    callback(len(data))

    def download_file(
        self,
        path: str,
        local_path: "str | PathLike[str]",
        *,
        overwrite: bool = False,
        chunk_size: int | None = None,
        callback: "Callable[[int], Any] | None" = None,
    ) -> None:
        """Download a resource to a local file.

        The data goes to a temporary file next to ``local_path`` first, and only
        a complete download is moved into place: a failed or interrupted one
        leaves neither a partial file nor - with ``overwrite=True`` - a
        destroyed old one behind. Without ``overwrite`` an existing
        ``local_path`` is an error (``FileExistsError``), checked again
        atomically at the moment of the move, like ``upload_file``'s
        ``overwrite=False``.

        Never writes through a symlink: one at ``local_path`` is refused
        (``OSError``, or ``FileExistsError`` without ``overwrite``), so a
        pre-planted link can't redirect the write to an unintended local file
        (the same class of attack OpenSSH's ``sftp`` client hardened against).
        """
        if chunk_size is not None:
            _check_chunk_size(chunk_size)
        target = pathlib.Path(local_path)
        directory = target.absolute().parent
        if not directory.is_dir():
            raise FileNotFoundError(errno.ENOENT, "no such directory", str(directory))
        if (target.is_symlink() or target.exists()) and not overwrite:
            raise FileExistsError(
                errno.EEXIST,
                "file exists (pass overwrite=True to replace it)",
                str(target),
            )
        if target.is_symlink():
            raise OSError(
                errno.ELOOP, "refusing to write through a symlink", str(target)
            )
        # The kernel applies the umask when it creates the file, exclusively
        # (O_EXCL) and without following a link; nothing here reads or changes
        # the process-wide umask, which another thread may be relying on.
        temp = directory / f".webdav-{secrets.token_hex(8)}.part"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(temp, flags, 0o666)
        claimed = False
        try:
            with os.fdopen(fd, mode="wb") as fobj:
                self.download_fileobj(
                    path, fobj, callback=callback, chunk_size=chunk_size
                )
            if overwrite:
                if target.exists():
                    shutil.copymode(
                        target, temp
                    )  # keep the permissions of what is replaced
            else:
                # Claim the name first: O_EXCL is atomic on every file system
                # (a hard link is not available on some), and only a complete
                # download gets this far, so no half-written file is ever visible.
                os.close(os.open(target, flags, 0o666))
                claimed = True
            temp.replace(target)
        except BaseException:
            temp.unlink(missing_ok=True)
            if claimed and target.exists() and target.stat().st_size == 0:
                target.unlink(missing_ok=True)  # our own, still empty claim
            raise

    def upload_file(
        self,
        local_path: "str | PathLike[str]",
        path: str,
        *,
        overwrite: bool = False,
        chunk_size: int | None = None,
        callback: "Callable[[int], Any] | None" = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        """Upload a local file to a remote path."""
        with pathlib.Path(local_path).open(mode="rb") as fobj:
            self.upload_fileobj(
                fobj,
                path,
                overwrite=overwrite,
                chunk_size=chunk_size,
                callback=callback,
                headers=headers,
            )

    def upload_fileobj(
        self,
        fileobj: BinaryIO,
        path: str,
        *,
        overwrite: bool = False,
        chunk_size: int | None = None,
        callback: "Callable[[int], Any] | None" = None,
        size: int | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        """Upload an open, readable file object to a remote path.

        The body is exactly ``size`` bytes (measured from the file object unless
        given): a file that turns out longer or shorter while it is read is an
        error - never sent as a silently truncated copy, and never allowed to
        leave surplus bytes on the connection for the server to read as the
        start of another request.

        Raises:
            ClientError: The file object did not hold as many bytes as ``size``.
            ResourceAlreadyExistsError: ``overwrite`` is false and ``path`` exists.
            PreconditionFailedError: A precondition of the upload failed.
            requests.RequestException: The transport failed.

        """
        if chunk_size is not None:
            _check_chunk_size(chunk_size)
        headers = dict(headers or {})

        # We try to avoid chunked transfer as much as possible, so we try
        # to use size as a hint if provided, else find it out from the
        # file object, else gracefully fall back to chunked encoding.
        if size is None:
            size = peek_filelike_length(fileobj)

        if not overwrite:
            # An `exists()` pre-check followed by a separate PUT would be a
            # TOCTOU race (another client could create the resource in
            # between); `If-None-Match: *` (RFC 7232 §3.2) makes the
            # not-already-there check atomic on the server, which maps a
            # conflicting PUT to 412 Precondition Failed.
            headers.setdefault("If-None-Match", "*")

        problem: list[str] = []
        chunks = _bounded_chunks(
            fileobj, size, chunk_size or self.chunk_size, callback, problem
        )

        # SizedIterator lets `requests` learn the real length itself and
        # keep the upload streamed with a plain Content-Length - passing
        # size via our own header instead doesn't work, see its docstring.
        body: Iterator[bytes] | SizedIterator = (
            SizedIterator(chunks, size) if size is not None else chunks
        )
        try:
            self._send(Method.PUT, path, data=body, headers=headers, error_path=path)
        except PreconditionFailedError as exc:
            if not overwrite and not isinstance(exc, ResourceAlreadyExistsError):
                # We set ``If-None-Match: *``: a 412 here means "it exists".
                raise ResourceAlreadyExistsError(exc.response, _display(path)) from exc
            raise
        except requests.RequestException as exc:
            if problem:  # the request broke because the body could not be completed
                raise ClientError(problem[0]) from exc
            raise

    # -- helpers --------------------------------------------------------

    def _with_headers(
        self,
        method: str,
        url: str,
        kwargs: dict[str, Any],
        extra: "Mapping[str, str | None]",
        **rest: Any,
    ) -> Response:
        """Send ``method`` with ``extra`` headers, the caller's own headers taking precedence."""
        headers = {k: v for k, v in extra.items() if v is not None}
        headers.update(kwargs.pop("headers", None) or {})
        return self.request(method, url, headers=headers, **rest, **kwargs)

    def _transfer(
        self,
        method: str,
        url: str,
        destination: str,
        overwrite: "bool | None",
        depth: "int | str | None",
        kwargs: dict[str, Any],
    ) -> Response:
        source_url = self.resolve_url(url)
        destination_header = self._destination(destination)
        extra: dict[str, str | None] = {"Destination": destination_header}
        if overwrite is not None:
            extra["Overwrite"] = "T" if overwrite else "F"
        if depth is not None:
            extra["Depth"] = _check_depth(depth, ("0", "infinity"), method)
        # A path-absolute Destination names a resource on the source's server.
        destination_url = urljoin(source_url, destination_header)
        extra["If"] = self._if_for_transfer(
            source_url, destination_url, moves=method == Method.MOVE
        )
        return self._with_headers(method, url, kwargs, extra)

    def _if_for_transfer(
        self, from_url: str, to_url: str, *, moves: bool = False
    ) -> "str | None":
        """Build an ``If`` header covering both sides of a COPY/MOVE.

        RFC 4918 sec. 10.2: "If a source or destination resource within
        the scope of the Depth header is locked in such a way as to
        prevent the successful execution of the method, then the lock
        token for that resource MUST be submitted with the request in the
        If request header." That includes a lock on the *parent* of either
        (sec. 7.4: a lock on a collection covers its membership: the
        source's parent loses a member on a MOVE, the destination's gains
        one), and - for a MOVE, which takes the source and all it holds away -
        locks on members of the source. Every lock touched is presented as a
        tagged list of its own resource - a plain token would only speak about
        the request's.
        """
        return self.locks.if_header(
            from_url, to_url, include_below=(from_url,) if moves else ()
        )

    def _destination(self, destination: str) -> str:
        """The ``Destination`` header value: an absolute URI or path-absolute (RFC 4918 sec. 10.3).

        A path is a plain path (encoded here, like every path); a full URL is
        made a valid URI (a space or a lone ``%`` in it is encoded) and, with
        a ``base_url``, must be on that server: a ``Destination`` on another
        origin is a cross-server COPY/MOVE nobody has asked for.
        """
        if destination.startswith("//"):
            msg = "a scheme-relative Destination is not allowed (RFC 4918 sec. 10.3)"
            raise ClientError(msg)
        if _URL_RE.match(destination):
            parts = _split(destination)
            if parts.query or parts.fragment or "\\" in destination:
                # Not part of a resource's address here - and exactly where a
                # parser that reads the URL differently would find another host.
                msg = f"a Destination has no query, fragment or backslash: {redact_url(destination)!r}"
                raise ClientError(msg)
            origin = effective_origin(destination)
            if origin is None or (
                self.base_url is not None and origin != effective_origin(self.base_url)
            ):
                msg = f"Destination {redact_url(destination)!r} is not on this session's base_url"
                raise ClientError(msg)
            # ``requote_uri`` leaves a "%" that is not a valid escape as it is;
            # in a URI it can only mean a literal percent sign.
            return str(requote_uri(re.sub(r"%(?![0-9A-Fa-f]{2})", "%25", destination)))
        if self.base_url is not None:
            return self.resolve_url(destination)
        if destination.startswith("/"):
            return quote(destination, safe="/")
        msg = "a Destination is a full URL, or - with a base_url - a path"
        raise ClientError(msg)


__all__ = [
    "DEFAULT_MAX_RESPONSE_SIZE",
    "DEFAULT_TIMEOUT",
    "Method",
    "Session",
]
