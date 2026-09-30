# pylint: disable=too-many-lines  # one documented entry point: about a quarter of this file is docstrings
"""A :class:`requests.Session` that speaks WebDAV verbs directly.

Everything ``requests.Session`` does keeps working exactly as documented
in ``requests`` itself (auth, adapters, hooks, cookies, connection pooling,
``timeout=``, ``verify=``, ``cert=``, ``stream=``, ...); this subclass adds
the WebDAV verbs on top - ``get``, ``put``, ``delete``, ``head``, ``options``,
``propfind``, ``proppatch``, ``mkcol``, ``copy``, ``move``, ``lock``,
``unlock`` - shaped like ``Session.get``/``.put``: they return a
:class:`webdav.response.Response` and, like ``requests``, do not raise for an
error status unless asked to (``raise_for_status()``, or
``raise_on_error=True``).

For filesystem-shaped access to a server (``ls``, ``open``, ``upload_file``,
``mkdir``, ``remove``, ... - plain return values, raising a
:class:`~webdav.exceptions.WebDAVError` on failure) see
:class:`~webdav.fs.FileSystem`, a peer class built on top of a ``Session``
rather than a part of it (``FileSystem.from_session(session)`` shares one).

A verb takes a full URL, or a path if the session has a ``base_url``.

It also brings a redirect policy that is safe for methods other than
``GET`` (see :mod:`webdav.transport.redirects` - ``requests`` itself re-sends a
redirected ``PROPFIND`` as a bodiless request or turns it into a ``GET``),
automatic ``If`` headers for locks the session holds, retries of transient
failures, and a cap on how large a response body may be declared.
"""

import difflib
import threading
import time
from contextlib import suppress
from datetime import timedelta
from http import HTTPStatus
from typing import (
    TYPE_CHECKING,
    Any,
    TypedDict,
    cast,
)
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests
import requests.adapters
import requests.auth
from requests.cookies import extract_cookies_to_jar
from requests.hooks import dispatch_hook
from requests.utils import default_headers, resolve_proxies

from webdav.dav.body import prepare_body
from webdav.dav.features import FeatureDetection
from webdav.dav.headers import depth_header, destination_header, strong_etag
from webdav.dav.locks import (
    DEFAULT_LOCK_TIMEOUT,
    EXCLUSIVE,
    LockRegistry,
    build_lock_body,
    format_timeout,
    validate_token,
)
from webdav.dav.properties import build_propfind_body, build_proppatch_body
from webdav.dav.urls import URL, join_url
from webdav.exceptions import (
    STATUS_CODE_EXCEPTIONS,
    ClientError,
    HTTPStatusError,
)
from webdav.methods import RETRYABLE_METHODS, Method
from webdav.response import Response
from webdav.transport.body import read_bounded, read_response
from webdav.transport.deadline import DeadlineAdapter, enforce
from webdav.transport.guards import (
    NO_AUTH,
    CleartextWarner,
    check_base_url,
    check_verify,
    require_full_url,
)
from webdav.transport.limits import (
    DEFAULT_CHUNK_SIZE,
    check_chunk_size,
    check_flag,
    check_max_redirects,
    check_max_size,
    check_max_time,
    check_timeout,
)
from webdav.transport.redirects import (
    MAX_REDIRECT_BODY,
    MAX_REDIRECTS,
    RedirectPolicy,
    Refuse,
    build_trust_check,
    check_redirect_policy,
    cross_origin_headers,
    has_replayable_body,
    plan_hop,
    refuse,
    validate_policy,
)
from webdav.transport.retry import retry as _retry
from webdav.transport.tls import (
    configure_tls,
)
from webdav.url_safety import effective_origin, is_url, redact_url

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping, MutableMapping
    from typing import Self
    from xml.etree.ElementTree import Element

    from requests.auth import AuthBase
    from requests.cookies import RequestsCookieJar
    from requests.structures import CaseInsensitiveDict

    from webdav.dav.properties import PropName
    from webdav.transport.retry import RetryFunc
    from webdav.transport.tls import CertTypes, TLSOptions
    from webdav.url_safety import Origin

    AuthTypes = AuthBase | tuple[str, str] | None

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

#: The WebDAV-specific attributes a pickled session keeps, beyond the plain
#: ``requests`` ones in ``_TRANSPORT_PICKLED`` below; see
#: ``Session._init_derived`` for what is rebuilt fresh instead.
_PICKLED = (
    "base_url",
    "timeout",
    "redirect_policy",
    "max_response_size",
    "raise_on_error",
    "chunk_size",
    "max_response_time",
    "max_redirects",
    "redirect_forward_headers",
    "_retry_arg",
    "_trusted_arg",
    # The raw TLS arguments, not the adapter/SSLContext they build: unlike
    # those, they are plain, picklable values, and _init_derived() rebuilds
    # the adapter fresh from them - the same way it already rebuilds locks
    # and other live state a copy must never share with the original.
    "_cert_arg",
    "_verify_arg",
    "_tls_arg",
)

#: The plain ``requests.Session`` attributes this class forwards to
#: ``self._transport`` - see the properties below - and so pickles/copies
#: the same way the rest of :data:`_PICKLED` does.
_TRANSPORT_PICKLED = (
    "headers",
    "cookies",
    "auth",
    "proxies",
    "hooks",
    "params",
    "stream",
    "trust_env",
)


def _merge_arguments(args: "tuple[Any, ...]", kwargs: "dict[str, Any]") -> None:
    """Fold the positional arguments of ``request()`` into ``kwargs``, and refuse any name it does not know.

    ``requests`` refuses an unknown keyword argument; so does this. Silently
    ignoring one would turn a typo in an option that matters
    (``allow_redirect=False``, ``verfiy=True``, ``timout=5``) into a request
    that quietly does the opposite of what was asked.

    Raises:
        TypeError: Too many positional arguments, one given twice, an
            unknown keyword argument, or ``allow_redirects``/``stream`` that
            is not a ``bool``.

    """
    if len(args) > len(_REQUEST_PARAMS):
        msg = f"request() takes at most {len(_REQUEST_PARAMS) + 2} positional arguments"
        raise TypeError(msg)
    for name, value in zip(_REQUEST_PARAMS, args, strict=False):
        if name in kwargs:
            msg = f"request() got multiple values for argument {name!r}"
            raise TypeError(msg)
        kwargs[name] = value
    for flag in ("allow_redirects", "stream"):
        if kwargs.get(flag) is not None:
            check_flag(flag, kwargs[flag])
    for name in kwargs:
        if name not in _REQUEST_PARAMS:
            msg = f"request() got an unexpected keyword argument {name!r}"
            close = difflib.get_close_matches(
                name, [*_REQUEST_PARAMS, "redirect_policy", "raise_on_error"], n=1
            )
            if close:
                msg += f". Did you mean {close[0]!r}?"
            raise TypeError(msg)


class ConnectionOptions(TypedDict, total=False):
    """The options of :class:`Session` that say how a server is reached and trusted.

    What every file-system function takes beside its own arguments; the keys
    are exactly ``Session``'s keyword-only constructor arguments (a test
    compares them), so there is one list of options, not one per entry point.
    """

    auth: "AuthTypes"
    cert: "CertTypes"
    verify: "bool | str"
    tls: "TLSOptions | None"
    timeout: "float | tuple[float | None, float | None] | None"
    redirect_policy: RedirectPolicy
    trusted_redirect_origins: "Iterable[str] | Callable[[str], bool] | None"
    max_response_size: "int | None"
    max_response_time: "float | None"
    max_redirects: int
    retry: "RetryFunc | bool"
    raise_on_error: bool


class SessionOptions(ConnectionOptions, total=False):
    """Every keyword-only option of :class:`Session` - what ``FileSystem(base_url, **options)`` takes."""

    headers: "dict[str, str] | None"
    chunk_size: int


class Session:
    """A WebDAV client built on ``requests``, with the API you already know from it.

    Not a :class:`requests.Session` subclass - it holds one (``auth``,
    ``headers``, ``cookies``, ``verify``, ``cert``, ``proxies``, ``hooks``,
    ``params``, ``stream`` and ``trust_env`` all work exactly
    as documented in ``requests``, forwarded to it) rather than *being* one.
    That is deliberate: ``requests.Session``'s own redirect-following and
    response construction are exactly what this class needs to replace, not
    inherit and then fight - see :meth:`send` and :meth:`request`.

    Examples:
        >>> session = Session("https://webdav.example.org", auth=("user", "password"))
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
        verify: bool | str = True,
        tls: "TLSOptions | None" = None,
        timeout: "float | tuple[float | None, float | None] | None" = DEFAULT_TIMEOUT,
        redirect_policy: RedirectPolicy = RedirectPolicy.SAME_ORIGIN,
        trusted_redirect_origins: "Iterable[str] | Callable[[str], bool] | None" = None,
        max_response_size: "int | None" = DEFAULT_MAX_RESPONSE_SIZE,
        max_response_time: "float | None" = DEFAULT_MAX_RESPONSE_TIME,
        max_redirects: int = MAX_REDIRECTS,
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
                trust store, the default), a path to a CA bundle, or
                ``False``. Disabling it is a deliberate, explicit choice a
                developer is free to make - it is not this library's place
                to forbid it - but it raises and logs a
                :class:`~webdav.exceptions.TLSHardeningDisabledWarning`
                every time, loud and independent of ``urllib3``'s own
                warning category (a common ``urllib3.disable_warnings()``
                cannot silence it). Prefer naming the CA
                (``verify="ca.pem"``) over disabling verification when the
                server certificate simply isn't in the system trust store.
            tls: Advanced TLS knobs (encrypted private key, CRL checking,
                explicit cipher restriction) that plain ``cert=``/
                ``verify=`` cannot express - see
                :class:`~webdav.transport.tls.TLSOptions`. Triggers the hardened
                :mod:`webdav.transport.tls` adapter when given.
            timeout: Default ``(connect, read)`` timeout (or a single
                value for both) applied when a request doesn't set its
                own. ``None`` restores ``requests``' own no-timeout
                default - not recommended, see :data:`DEFAULT_TIMEOUT`.
            redirect_policy: Which redirects to follow - see
                :class:`~webdav.transport.redirects.RedirectPolicy`. Overridable
                per call with ``redirect_policy=``; ``allow_redirects=False``
                on a call still means "never".
            trusted_redirect_origins: Which redirect targets
                :data:`RedirectPolicy.WHITELIST` follows, beyond this
                session's own origin. Either an iterable of exact origins
                (``"https://host"``) or a ``Callable[[str], bool]`` given
                the full target URL. Required with ``WHITELIST`` and
                rejected with any other policy.
            max_response_size: Reject a non-streamed response whose body
                exceeds this many bytes (declared ``Content-Length``, and the
                bytes actually read after decoding). ``None`` disables the
                check.
            max_response_time: Deadline, in seconds, for the whole exchange
                of a request that is not streamed - every redirect hop, the
                headers, the body. ``timeout`` only limits each single read.
                ``None`` disables the deadline.
            max_redirects: How many redirects in a row one request follows
                before it is refused as a loop.
            retry: Retry transient failures (429, 5xx,
                timeouts, dropped connections) of the safe and idempotent
                methods - or pass a callable implementing
                :class:`~webdav.transport.retry.RetryFunc` directly.
            chunk_size: Default chunk size for streaming reads/writes.
            raise_on_error: Call :meth:`Response.raise_for_status` on every
                response before returning it (``requests`` itself never
                raises for a status code unless asked to).

        Raises:
            TypeError: ``redirect_policy`` is not a
                :class:`~webdav.transport.redirects.RedirectPolicy`.
            ValueError: ``trusted_redirect_origins`` and ``redirect_policy``
                disagree - see :func:`~webdav.transport.redirects.validate_policy` -
                or ``base_url``, ``timeout``, ``max_response_size``,
                ``max_response_time``, ``max_redirects`` or ``chunk_size`` is
                not a usable value.

        """
        validate_policy(redirect_policy, trusted_redirect_origins)
        self._transport = requests.Session()
        self.auth = auth
        if headers:
            self.headers.update(headers)
        self._trusted_arg = trusted_redirect_origins
        self._base_url: str | None = None
        self.base_url = base_url
        self._timeout: float | tuple[float | None, float | None] | None = None
        self.timeout = timeout
        self._redirect_policy = redirect_policy
        self._max_redirects = MAX_REDIRECTS
        self.max_redirects = max_redirects
        self._max_response_size: int | None = None
        self.max_response_size = max_response_size
        self._raise_on_error = False
        self.raise_on_error = raise_on_error
        self._chunk_size = DEFAULT_CHUNK_SIZE
        self.chunk_size = chunk_size
        #: Deadline, in seconds, for the whole body of a response that is not
        #: streamed (``None``: none). ``timeout`` only limits each single read.
        self._max_response_time: float | None = None
        self.max_response_time = max_response_time
        #: Names (lower case) of extra per-call headers a redirect to a
        #: trusted *other* origin may carry, beyond the representation and
        #: conditional headers it always keeps - e.g. ``{"x-amz-meta-owner"}``
        #: for a signed upload that has to repeat them.
        self._redirect_forward_headers: frozenset[str] = frozenset()
        self._retry_arg = retry
        self._with_retry: RetryFunc
        self.retry = retry
        self._cert_arg = cert
        self._verify_arg = verify
        self._tls_arg = tls
        self._init_derived()

    def _init_derived(self) -> None:
        """(Re)build the state that follows from the constructor arguments.

        Kept apart from the rest of ``__init__`` because none of it can be
        pickled (a closure, a mutex, a live TLS adapter) - a copy or
        unpickled session gets everything here freshly rebuilt from the
        stored arguments, including its locks: it must hold none of the
        original's, since a lock belongs to the server, not to a copy of an
        object holding it.
        """
        # Adapters whose connections answer to the whole-request deadline
        # (see webdav.transport.deadline); ``_tls_arg`` below replaces the
        # https one with the mTLS adapter, which has the same property.
        self.mount("https://", DeadlineAdapter())
        self.mount("http://", DeadlineAdapter())
        configure_tls(
            self._transport,
            cert=self._cert_arg,
            verify=self._verify_arg,
            tls=self._tls_arg,
        )
        self._with_retry = (
            self._retry_arg if callable(self._retry_arg) else _retry(self._retry_arg)
        )
        self.locks = LockRegistry()
        self._is_trusted_redirect_target = build_trust_check(self._trusted_arg)
        self._features: dict[Origin | str, FeatureDetection] = {}
        self._features_lock = threading.RLock()
        self._cleartext = CleartextWarner()
        # What a redirect to another origin is sent through: a plain adapter,
        # so that neither a client certificate (mTLS) nor any transport
        # setting meant for *this* server goes with it.
        self._foreign_adapter = DeadlineAdapter()

    # -- forwarded to self._transport, exactly like plain requests.Session --

    @property
    def headers(self) -> "CaseInsensitiveDict[str]":
        """Default headers sent with every request - see :attr:`requests.Session.headers`."""
        return cast("CaseInsensitiveDict[str]", self._transport.headers)

    @headers.setter
    def headers(self, value: "MutableMapping[str, str]") -> None:
        self._transport.headers = value  # type: ignore[assignment]

    @property
    def cookies(self) -> "RequestsCookieJar":
        """See :attr:`requests.Session.cookies`."""
        return self._transport.cookies

    @cookies.setter
    def cookies(self, value: Any) -> None:
        self._transport.cookies = value

    @property
    def auth(self) -> "AuthTypes":
        """See :attr:`requests.Session.auth`."""
        return cast("AuthTypes", self._transport.auth)

    @auth.setter
    def auth(self, value: "AuthTypes") -> None:
        self._transport.auth = value

    @property
    def proxies(self) -> "MutableMapping[str, str]":
        """See :attr:`requests.Session.proxies`."""
        return self._transport.proxies

    @proxies.setter
    def proxies(self, value: "MutableMapping[str, str]") -> None:
        self._transport.proxies = value

    @property
    def hooks(self) -> Any:
        """See :attr:`requests.Session.hooks`."""
        return self._transport.hooks

    @hooks.setter
    def hooks(self, value: Any) -> None:
        self._transport.hooks = value

    @property
    def params(self) -> Any:
        """See :attr:`requests.Session.params`."""
        return self._transport.params

    @params.setter
    def params(self, value: Any) -> None:
        self._transport.params = value

    @property
    def stream(self) -> bool:
        """See :attr:`requests.Session.stream`."""
        return self._transport.stream

    @stream.setter
    def stream(self, value: bool) -> None:
        self._transport.stream = check_flag("stream", value)

    @property
    def verify(self) -> "bool | str | None":
        """See :attr:`requests.Session.verify`."""
        return self._transport.verify

    @verify.setter
    def verify(self, value: "bool | str | None") -> None:
        self._transport.verify = value

    @property
    def cert(self) -> "CertTypes":
        """See :attr:`requests.Session.cert`."""
        return self._transport.cert

    @cert.setter
    def cert(self, value: "CertTypes") -> None:
        self._transport.cert = value

    @property
    def trust_env(self) -> bool:
        """See :attr:`requests.Session.trust_env`."""
        return self._transport.trust_env

    @trust_env.setter
    def trust_env(self, value: bool) -> None:
        self._transport.trust_env = check_flag("trust_env", value)

    def mount(self, prefix: str, adapter: requests.adapters.BaseAdapter) -> None:
        """Mount a transport adapter - see :meth:`requests.Session.mount`."""
        self._transport.mount(prefix, adapter)

    def get_adapter(self, url: str) -> requests.adapters.BaseAdapter:
        """The adapter mounted for ``url`` - see :meth:`requests.Session.get_adapter`."""
        return self._transport.get_adapter(url)

    def _redirect_location(self, response: requests.Response) -> "str | None":
        """The ``Location`` header's value, decoded - what :meth:`requests.Session.get_redirect_target` reads."""
        return self._transport.get_redirect_target(response)

    @property
    def raise_on_error(self) -> bool:
        """Whether every response is passed to :meth:`Response.raise_for_status` before it is returned.

        Raises:
            TypeError: When set to anything but ``True`` or ``False``.

        """
        return self._raise_on_error

    @raise_on_error.setter
    def raise_on_error(self, value: bool) -> None:
        self._raise_on_error = check_flag("raise_on_error", value)

    @property
    def retry(self) -> "RetryFunc":
        """The wrapper that retries a transient failure of a safe method (see :class:`~webdav.transport.retry.RetryFunc`).

        Set it to ``False`` (no retries), ``True`` (the default policy) or
        your own :class:`~webdav.transport.retry.RetryFunc`.

        Raises:
            TypeError: When set to anything else.

        """
        return self._with_retry

    @retry.setter
    def retry(self, value: "RetryFunc | bool") -> None:
        if not (isinstance(value, bool) or callable(value)):
            msg = f"retry must be True, False or a RetryFunc, got {value!r}"
            raise TypeError(msg)
        self._retry_arg = value
        self._with_retry = value if callable(value) else _retry(value)

    @property
    def base_url(self) -> "str | None":
        """The URL that request paths are relative to (``None``: every URL is a full one).

        Raises:
            ValueError: When set to anything but ``None`` or one full
                ``http(s)`` URL without credentials, a query or a fragment.

        """
        return self._base_url

    @base_url.setter
    def base_url(self, url: "str | None") -> None:
        self._base_url = check_base_url(url)

    @property
    def timeout(self) -> "float | tuple[float | None, float | None] | None":
        """Default ``timeout`` of a request that does not set its own - see :data:`DEFAULT_TIMEOUT`.

        Raises:
            ValueError: When set to anything but ``None``, a positive number
                of seconds, or a ``(connect, read)`` pair of those.

        """
        return self._timeout

    @timeout.setter
    def timeout(
        self, value: "float | tuple[float | None, float | None] | None"
    ) -> None:
        self._timeout = check_timeout(value)

    @property
    def redirect_policy(self) -> RedirectPolicy:
        """Which redirects to follow - see :class:`~webdav.transport.redirects.RedirectPolicy`.

        Raises:
            TypeError: When set to anything but a ``RedirectPolicy``.
            ValueError: When set to ``WHITELIST`` and the session has no
                ``trusted_redirect_origins``.

        """
        return self._redirect_policy

    @redirect_policy.setter
    def redirect_policy(self, policy: RedirectPolicy) -> None:
        self._redirect_policy = check_redirect_policy(
            policy, trusted=self._trusted_arg is not None
        )

    @property
    def trusted_redirect_origins(
        self,
    ) -> "Iterable[str] | Callable[[str], bool] | None":
        """The redirect targets :data:`RedirectPolicy.WHITELIST` follows - as given to the constructor."""
        return self._trusted_arg

    @property
    def max_redirects(self) -> int:
        """How many redirects in a row one request follows before it is refused as a loop.

        Raises:
            ValueError: When set to anything but an integer of at least 0.

        """
        return self._max_redirects

    @max_redirects.setter
    def max_redirects(self, count: int) -> None:
        self._max_redirects = check_max_redirects(count)

    @property
    def chunk_size(self) -> int:
        """Default chunk size, in bytes, for streaming reads and writes.

        Raises:
            ValueError: When set to anything but a positive integer.

        """
        return self._chunk_size

    @chunk_size.setter
    def chunk_size(self, size: int) -> None:
        self._chunk_size = check_chunk_size(size)

    @property
    def max_response_size(self) -> "int | None":
        """Reject a non-streamed response whose body is larger than this many bytes (``None``: no limit).

        Checked against the declared ``Content-Length`` and, for a body that
        arrives in pieces, against the bytes actually read after decoding.

        Raises:
            ValueError: When set to anything but ``None`` or a positive integer.

        """
        return self._max_response_size

    @max_response_size.setter
    def max_response_size(self, size: "int | None") -> None:
        self._max_response_size = check_max_size(size)

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
        self._max_response_time = check_max_time(seconds)

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

    def __enter__(self) -> "Self":
        """Usable as a context manager, exactly like :class:`requests.Session`."""
        return self

    def __exit__(self, *exc_info: object) -> None:
        """Close the session on exit."""
        self.close()

    def close(self) -> None:
        """Close the session and every connection pool it opened."""
        self._transport.close()
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
        settings = self._transport.merge_environment_settings(
            url, proxies, stream, verify, cert
        )
        settings["verify"] = verify if verify is not None else self.verify
        return settings

    def __getstate__(self) -> dict[str, Any]:
        """Pickle the configuration - ``requests``' own attributes (forwarded) plus ours."""
        return {
            name: getattr(self, name, None) for name in (*_TRANSPORT_PICKLED, *_PICKLED)
        }

    def __setstate__(self, state: dict[str, Any]) -> None:
        """Restore from :meth:`__getstate__`.

        ``self._transport`` and every derived, unpicklable piece of state
        (locks, caches, adapters) are rebuilt fresh - see :meth:`_init_derived`.
        """
        self._transport = requests.Session()
        # The private arguments first: a setter (``redirect_policy``) may need one.
        for name in sorted(state, key=lambda n: not n.startswith("_")):
            setattr(self, name, state[name])
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
        if is_url(url):
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

    def request(
        self,
        method: str,
        url: str,
        *args: Any,
        redirect_policy: "RedirectPolicy | None" = None,
        raise_on_error: "bool | None" = None,
        **kwargs: Any,
    ) -> Response:
        """Send a request, exactly like :meth:`requests.Session.request`.

        Differences: the URL may be relative to ``base_url``; redirects
        follow this session's :class:`~webdav.transport.redirects.RedirectPolicy`
        (``allow_redirects=False`` still disables them, and
        ``redirect_policy=`` overrides the policy for this one call); a
        held lock's token is attached as an ``If`` header; transient
        failures of safe/idempotent methods are retried; the default
        ``timeout`` and ``max_response_size`` apply; and
        :meth:`Response.raise_for_status` is called on the response if the
        session's ``raise_on_error`` says so (``raise_on_error=`` overrides
        that for this one call).
        """
        if raise_on_error is not None:
            check_flag("raise_on_error", raise_on_error)
        response = self._fetch(
            method, url, *args, redirect_policy=redirect_policy, **kwargs
        )
        if self.raise_on_error if raise_on_error is None else raise_on_error:
            response.raise_for_status()
        return response

    def _fetch(
        self,
        method: str,
        url: str,
        *args: Any,
        redirect_policy: "RedirectPolicy | None" = None,
        **kwargs: Any,
    ) -> Response:
        """:meth:`request` without the ``raise_on_error`` step."""
        _merge_arguments(args, kwargs)
        url = self.resolve_url(url)
        require_full_url(url, has_base_url=self.base_url is not None)
        kwargs["data"], kwargs["headers"] = prepare_body(
            method, kwargs.get("data"), kwargs.get("headers")
        )
        policy = self._policy_for(kwargs.pop("allow_redirects", None), redirect_policy)
        kwargs.setdefault("timeout", self.timeout)
        self._require_verification(kwargs.get("verify"))

        def attempt() -> Response:
            return self._fetch_once(method, url, policy, dict(kwargs))

        if method not in RETRYABLE_METHODS or not has_replayable_body(kwargs):
            return attempt()

        def checked() -> Response:
            response = attempt()
            exc_cls = STATUS_CODE_EXCEPTIONS.get(response.status_code)
            if exc_cls is not None and exc_cls.retryable:
                raise exc_cls(response)
            return response

        try:
            return self._with_retry(checked)
        except HTTPStatusError as exc:
            # Out of attempts: hand back the last response, as ``requests`` would.
            return cast("Response", exc.response)

    def _policy_for(
        self, allow_redirects: object, override: "RedirectPolicy | None"
    ) -> RedirectPolicy:
        """The redirect policy one request runs under: ``allow_redirects=False`` is "never", then the call's own, then the session's."""
        if allow_redirects is False:
            return RedirectPolicy.NEVER
        if override is None:
            return self.redirect_policy
        return check_redirect_policy(override, trusted=self._trusted_arg is not None)

    def _require_verification(self, verify: object) -> None:
        """Check (and warn about) the certificate verification a request will use."""
        check_verify(self.verify if verify is None else verify)

    def _fetch_once(
        self, method: str, url: str, policy: RedirectPolicy, kwargs: dict[str, Any]
    ) -> Response:
        self._warn_if_insecure(url, kwargs)
        caller_headers: dict[str, str] = dict(kwargs.get("headers") or {})

        def kwargs_for(target: str) -> dict[str, Any]:
            """The arguments for a request to ``target`` on the origin we started at."""
            hop = {k: v for k, v in kwargs.items() if k != "params"}
            hop["headers"] = self.locks.headers_for(method, target, caller_headers)
            return hop

        # Always sent as a stream, so that no body (the answer itself, or a
        # redirect's) is read into memory before this session has had its
        # say on how big it may get - see read_bounded.
        caller_streams = kwargs.get("stream")
        if caller_streams is None:
            caller_streams = self.stream
        kwargs["stream"] = True
        first = dict(kwargs)
        first["headers"] = self.locks.headers_for(method, url, caller_headers)

        # One deadline for the whole exchange - every hop, the headers, the
        # body and its trailers - unless the caller streams: then it covers
        # getting the response (headers) and the caller reads the rest.
        with enforce(self.max_response_time):
            response = self._dispatch(method, url, allow_redirects=False, **first)
            response = self._follow_redirects(
                response, method, policy, kwargs, kwargs_for
            )
            if not caller_streams:
                read_response(
                    response, method, max_size=self.max_response_size, max_time=None
                )
        return response

    def prepare_request(self, request: requests.Request) -> requests.PreparedRequest:
        """Prepare ``request``; with no credentials configured, none are looked up.

        ``requests`` would otherwise search ``~/.netrc`` for the host and
        authenticate with whatever it finds (see :data:`~webdav.transport.guards.NO_AUTH`).
        """
        if request.auth is None and self.auth is None:
            request.auth = NO_AUTH
        return self._transport.prepare_request(request)

    def _dispatch(self, method: str, url: str, **kwargs: Any) -> Response:
        """Build a request exactly like :meth:`requests.Session.request` does, then :meth:`send` it.

        Not inherited, because ``requests.Session.request()`` always ends by
        calling *its own* ``send()`` - reused here up to that point
        (``self._transport`` builds and merges the ``PreparedRequest``
        exactly as ``requests`` documents), but the actual dispatch always
        goes through this class's own :meth:`send`, which is what enforces
        verification, the deadline and bounded reading - none of which
        ``self._transport`` knows anything about. Every same-origin redirect
        hop goes through here too (see :meth:`_follow_redirects`), so none
        of that is only applied to the first and last response of a chain.
        """
        allow_redirects = kwargs.pop("allow_redirects", True)
        prepared = self.prepare_request(
            requests.Request(
                method=method.upper(),
                url=url,
                headers=kwargs.get("headers"),
                files=kwargs.get("files"),
                data=kwargs.get("data") or {},
                json=kwargs.get("json"),
                params=kwargs.get("params") or {},
                auth=kwargs.get("auth"),
                cookies=kwargs.get("cookies"),
                hooks=kwargs.get("hooks"),
            )
        )
        settings = self.merge_environment_settings(
            prepared.url,
            kwargs.get("proxies") or {},
            kwargs.get("stream"),
            kwargs.get("verify"),
            kwargs.get("cert"),
        )
        send_kwargs: dict[str, Any] = {
            "timeout": kwargs.get("timeout"),
            "allow_redirects": allow_redirects,
        }
        send_kwargs.update(settings)
        return self.send(prepared, **send_kwargs)

    def send(self, request: requests.PreparedRequest, **kwargs: Any) -> Response:
        """Send one prepared request and return its response - never following a redirect.

        Replaces ``requests``' own, whose redirect handling (``resolve_redirects``:
        wrong methods and bodies for WebDAV, credentials and session headers
        carried along, a redirect's whole body read into memory, an
        unparseable ``Location`` raising a bare ``ValueError``) is exactly
        what this class exists to keep out of the picture. Redirects are
        followed - under this session's :class:`~webdav.transport.redirects.RedirectPolicy` -
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
        with enforce(self.max_response_time):
            response = adapter.send(request, **kwargs)
            response.elapsed = timedelta(seconds=time.perf_counter() - started)
            # Before any response hook runs: ``HTTPDigestAuth`` (and any
            # hook of the caller's) reads ``.content`` of a 401 to answer
            # it - which would be an unbounded, deadline-free read.
            hooks = request.hooks.get("response") if request.hooks else None
            if not kwargs["stream"] or (hooks and response.status_code in (401, 407)):
                read_response(
                    response, method, max_size=self.max_response_size, max_time=None
                )
            response = dispatch_hook("response", request.hooks, response, **kwargs)  # type: ignore[no-untyped-call]
            extract_cookies_to_jar(self.cookies, request, response.raw)  # type: ignore[no-untyped-call]
        # Nearly always a webdav.Response already (the adapters this library
        # mounts build one); an adapter a caller mounted may not have.
        result = Response.adopt(response)
        if allow_redirects and (result.is_redirect or result.is_permanent_redirect):
            refuse(
                result,
                "send() sends one request and never follows redirects; use request()",
            )
        return result

    def _warn_if_insecure(self, url: str, kwargs: dict[str, Any]) -> None:
        """Warn (once per host) when credentials are about to go out over plain ``http``."""
        per_call_auth = kwargs.get("auth")
        self._cleartext.check(
            url,
            call_headers=kwargs.get("headers"),
            session_headers=self.headers,
            has_auth=(per_call_auth is not None and per_call_auth is not NO_AUTH)
            or bool(self.auth),
        )

    # -- redirects ------------------------------------------------------

    def _follow_redirects(
        self,
        response: Response,
        method: str,
        policy: RedirectPolicy,
        kwargs: dict[str, Any],
        kwargs_for: "Callable[[str], dict[str, Any]] | None" = None,
    ) -> Response:
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
                refuse(response, "redirects are disabled for this request")
                break
            if hops >= self.max_redirects:
                refuse(response, f"more than {self.max_redirects} redirects in a row")
                break
            decision = plan_hop(
                response,
                method,
                policy,
                body_replayable=has_replayable_body(kwargs),
                seen=seen,
                origin_url=origin_url,
                is_trusted=self._is_trusted_redirect_target,
                get_location=self._redirect_location,
            )
            if isinstance(decision, Refuse):
                refuse(response, decision.reason)
                break
            target, same_origin = decision.target, decision.same_origin
            previous = response
            # Keep the (small) body of a redirect for ``history``, but never
            # let it be an unbounded read.
            with suppress(ClientError):
                read_bounded(
                    previous,
                    max_size=MAX_REDIRECT_BODY,
                    max_time=self.max_response_time,
                )
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
                response = self._dispatch(
                    method, target, allow_redirects=False, **hop_kwargs
                )
            else:
                response = self._send_stripped(method, target, kwargs)
            response.history = [*previous.history, previous]
        return response

    def _send_stripped(self, method: str, url: str, kwargs: dict[str, Any]) -> Response:
        """Send one request to another origin, carrying nothing that is ours.

        Built from scratch and sent through a plain adapter of its own, so
        that none of the session exists on it: no ``auth`` (and no netrc),
        no cookies - and none set by the answer, no default headers (which
        may include a custom API-key header this can't recognise as a
        credential), no client certificate, no hooks. Of the caller's own
        per-call headers only the representation/conditional ones in
        :data:`~webdav.transport.redirects.FORWARD_HEADERS` (plus ``redirect_forward_headers``) are kept.
        """
        headers = default_headers()
        headers.update(
            cross_origin_headers(kwargs.get("headers"), self._redirect_forward_headers)
        )
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
        # Already a webdav.Response: _foreign_adapter is a DeadlineAdapter too.
        return cast(
            "Response",
            self._foreign_adapter.send(
                prepared,
                stream=True,
                timeout=kwargs.get("timeout"),
                verify=settings["verify"],
                cert=None,
                proxies=settings["proxies"],
            ),
        )

    # -- HTTP verbs, typed to return a webdav Response --------------------

    def get(self, url: str, params: Any = None, **kwargs: Any) -> Response:
        """Send a ``GET``; like :meth:`requests.Session.get`."""
        kwargs.setdefault("allow_redirects", True)
        return self.request(Method.GET, url, params=params, **kwargs)

    def head(self, url: str, **kwargs: Any) -> Response:
        """Send a ``HEAD``; like :meth:`requests.Session.head` (redirects off by default)."""
        kwargs.setdefault("allow_redirects", False)
        return self.request(Method.HEAD, url, **kwargs)

    def options(self, url: str, **kwargs: Any) -> Response:
        """Send an ``OPTIONS``; like :meth:`requests.Session.options`."""
        kwargs.setdefault("allow_redirects", True)
        return self.request(Method.OPTIONS, url, **kwargs)

    def put(
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
            extra["If-Match"] = strong_etag(if_match)
        if overwrite is False:
            extra["If-None-Match"] = "*"
        return self._with_headers(Method.PUT, url, kwargs, extra, data=data)

    def delete(
        self, url: str, *, if_match: "str | None" = None, **kwargs: Any
    ) -> Response:
        """Send a ``DELETE``; like :meth:`requests.Session.delete`.

        ``if_match`` only deletes the resource if its current ETag is this
        one - see :meth:`put`.
        """
        extra: dict[str, str | None] = {}
        if if_match is not None:
            extra["If-Match"] = strong_etag(if_match)
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
        prop_name: bool = False,
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
                yourself - see :func:`~webdav.dav.properties.build_propfind_body`.
            all_prop: Request ``<d:allprop/>`` explicitly.
            prop_name: Request ``<d:propname/>``: the *names* of the
                properties the resource has, without their values.
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
                ``prop_name``/``include``, more than one of ``props``,
                ``all_prop`` and ``prop_name`` is given, or ``depth`` is not
                ``0``, ``1`` or ``infinity``.

        """
        if props is not None or all_prop or prop_name or include is not None:
            if data is not None:
                msg = "pass either data or props/all_prop/prop_name/include, not both"
                raise ValueError(msg)
            if (props is not None) + all_prop + prop_name > 1:
                msg = "pass only one of props, all_prop and prop_name"
                raise ValueError(msg)
            data = build_propfind_body(
                props,
                all_prop=all_prop or (props is None and not prop_name),
                prop_name=prop_name,
                include=include,
            )
        return self._with_headers(
            Method.PROPFIND,
            url,
            kwargs,
            {
                "Depth": (
                    depth_header(depth, Method.PROPFIND) if depth is not None else None
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
        build it - see :func:`~webdav.dav.properties.build_proppatch_body`).
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
                :func:`~webdav.dav.locks.build_lock_body`.
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
            headers["If"] = f"(<{validate_token(refresh)}>)"
            return self._with_headers(Method.LOCK, url, kwargs, headers)
        headers["Depth"] = depth_header(depth, Method.LOCK)
        headers["Content-Type"] = "application/xml; charset=utf-8"
        return self._with_headers(
            Method.LOCK, url, kwargs, headers, data=build_lock_body(scope, owner)
        )

    def unlock(self, url: str, token: str, **kwargs: Any) -> Response:
        """Send an ``UNLOCK`` for ``token`` (RFC 4918 sec. 9.11).

        A token in :attr:`locks` is dropped from it once the server has
        released the lock: a released token must not go on being attached to
        the writes that follow.

        RFC 4918 sec. 9.11: the lock is named by the ``Lock-Token`` header
        alone (no ``If`` header is needed), ``url`` must be within the scope of
        the lock, and ``204`` is the normal answer. A ``403`` means the
        principal may not remove the lock, a ``409`` that the resource was not
        locked (the lock may have timed out) or that ``url`` is outside the
        lock's scope. A ``404``/``409`` for the very URL a lock was recorded
        for means the lock is gone (it may have timed out) and drops it from
        :attr:`locks` too - a dead token must not go on making every later write
        fail with ``412`` - while anywhere else, or on ``403``, the token stays,
        since the lock may still exist. An UNLOCK is idempotent but never retried
        here: the repeat of one whose answer was lost would be answered ``409``.

        Raises:
            ValueError: ``token`` is not a usable lock token.

        """
        token = validate_token(token.strip("<>"))
        response = self._with_headers(
            Method.UNLOCK, url, kwargs, {"Lock-Token": f"<{token}>"}
        )
        status = response.status_code
        if HTTPStatus.OK <= status < HTTPStatus.MULTIPLE_CHOICES:
            self.locks.discard_token(token)
        elif status in (HTTPStatus.NOT_FOUND, HTTPStatus.CONFLICT):
            with suppress(ClientError):
                self.locks.discard_token(token, url=self.resolve_url(url))
        return response

    def features_for(self, path: str = "") -> FeatureDetection:
        """Features of the server ``path`` is on (cached per origin once a probe has answered).

        A server that cannot be reached - or that does not answer ``OPTIONS`` -
        is "nothing known" (``FeatureDetection()``), not an error, and is not
        remembered; a ``path`` that cannot be requested at all *is* an error.
        :meth:`FileSystem.dav_compliance <webdav.fs.client.FileSystem.dav_compliance>`
        asks afresh and raises instead.
        """
        url = self.resolve_url(path)
        require_full_url(url, has_base_url=self.base_url is not None)
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
            return FeatureDetection()
        detected = FeatureDetection.from_response(response)
        with self._features_lock:
            return self._features.setdefault(key, detected)

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
        destination_value = destination_header(
            destination, base_url=self.base_url, resolve=self.resolve_url
        )
        extra: dict[str, str | None] = {"Destination": destination_value}
        if overwrite is not None:
            extra["Overwrite"] = "T" if overwrite else "F"
        if depth is not None:
            extra["Depth"] = depth_header(depth, method)
        # A path-absolute Destination names a resource on the source's server.
        destination_url = urljoin(source_url, destination_value)
        extra["If"] = self.locks.if_header_for_transfer(
            source_url, destination_url, moves=method == Method.MOVE
        )
        return self._with_headers(method, url, kwargs, extra)


__all__ = [
    "DEFAULT_MAX_RESPONSE_SIZE",
    "DEFAULT_MAX_RESPONSE_TIME",
    "DEFAULT_TIMEOUT",
    "ConnectionOptions",
    "Session",
    "SessionOptions",
]
