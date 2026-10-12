"""The checks a request passes before it leaves, and the defaults that keep stray credentials out.

Each one either refuses the request (with the library's own
:class:`~webdav.exceptions.ClientError`, never whatever ``requests`` or
``urllib`` would have raised) or says, loudly, what it is about to do:

- :func:`require_full_url` - one full, credential-free ``http(s)`` URL;
- :func:`check_verify` - a server whose certificate will not be checked, or a
  CA bundle that is not there;
- :class:`CleartextWarner` - credentials about to go out over plain ``http``
  (refused, warned about or allowed - ``insecure_transport=``);
- :data:`NO_AUTH` - no credentials looked up behind the caller's back;
- :func:`scrub_exception` - the query of a signed URL taken out of a transport error.
"""

import contextlib
import ipaddress
import logging
import pathlib
import threading
from enum import StrEnum
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

import requests.auth

from webdav.exceptions import ClientError, InsecureTransportWarning, warn_at_caller
from webdav.transport.basic_auth import as_basic
from webdav.transport.tls import (
    check_verify_type,
    verification_on,
    warn_hardening_disabled,
)
from webdav.url_safety import effective_origin, is_url, redact_url

if TYPE_CHECKING:
    import urllib.parse
    from collections.abc import Callable, Mapping

_LOGGER = logging.getLogger("webdav")


class InsecureTransport(StrEnum):
    """What a session does with credentials that would go over plain ``http://``.

    RFC 4918 section 20.1: "Basic authentication MUST NOT be used to authenticate a
    WebDAV client to a server unless the connection is secure" (TLS is its example of a
    secure connection). So the default is :data:`ERROR`; a trusted network that has no TLS
    is a decision to make on purpose, with :data:`WARN` or :data:`ALLOW`. Members are
    strings: ``"warn"`` works wherever ``InsecureTransport.WARN`` does.

    - :data:`ERROR` (the default): refuse the request with a
      :class:`~webdav.exceptions.ClientError`.
    - :data:`WARN`: send it, with an :class:`~webdav.exceptions.InsecureTransportWarning`
      (once per host, also logged). ``dav --allow-insecure``.
    - :data:`ALLOW`: send it without a word.

    Loopback (``127.0.0.1``, ``::1``, ``localhost``) is not affected, unless a proxy would
    carry the request. A request without credentials is not either.
    """

    ERROR = "error"
    WARN = "warn"
    ALLOW = "allow"


_CREDENTIAL_HEADERS = frozenset({"authorization", "proxy-authorization", "cookie"})

_LOOPBACK_NAMES = frozenset({"localhost", "localhost.localdomain"})


class _NoAuth(requests.auth.AuthBase):
    """Authentication that adds nothing.

    Passing this as ``auth`` when the caller gave none stops ``requests``
    from looking the host up in ``~/.netrc`` and silently authenticating with
    whatever it finds there: credentials are only ever the ones asked for.
    """

    def __call__(self, r: requests.PreparedRequest) -> requests.PreparedRequest:
        return r


#: Use as ``auth`` when the caller gave none.
NO_AUTH = _NoAuth()


def check_auth(auth: object) -> None:
    """Refuse ``requests.auth.HTTPDigestAuth``, and Basic credentials that cannot be sent.

    Digest authentication is not supported.

    It is MD5 unless the server offers more, does not authenticate the server, does not
    protect the content and allows guessing the password offline; and a request with a
    body cannot be answered to its challenge, because the body is a stream (see the
    Digest section of ``docs/reference/session.md``).

    Raises:
        ClientError: ``auth`` is an ``HTTPDigestAuth``, or a user name with a colon, or
            credentials that cannot be encoded.

    """
    if isinstance(auth, requests.auth.HTTPDigestAuth):
        msg = (
            "Digest authentication is not supported: it is weak (MD5, the server is not "
            "authenticated, the content is not protected). Use Basic authentication "
            "over https, or a client certificate (docs/reference/session.md, "
            '"Digest authentication")'
        )
        raise ClientError(msg)
    # Now, not at the first request: a user name with a colon, a name that cannot be encoded.
    as_basic(auth)


def split_url(url: str) -> "urllib.parse.SplitResult":
    """``urlsplit`` that reports an unparseable URL as the library's own error.

    Raises:
        ClientError: ``url`` cannot be parsed (e.g. ``http://[bad``).

    """
    try:
        return urlsplit(url)
    except ValueError as exc:
        msg = f"not a valid URL: {redact_url(url)!r}"
        raise ClientError(msg) from exc


def require_full_url(url: str, *, has_base_url: bool) -> None:
    """Refuse a URL that is not one full, credential-free ``http(s)`` URL - with one error of ours.

    Unparseable, not http(s), ambiguous, or relative without a ``base_url``: not
    whichever error ``requests`` (or ``urlsplit``) would raise. Credentials
    belong in ``auth=``, not in a URL, which ends up in logs and messages.

    Raises:
        ClientError: For any of the above.

    """
    if is_url(url) and split_url(url).username is not None:
        msg = "a URL with credentials in it is refused: pass auth=(user, password) instead"
        raise ClientError(msg)
    if effective_origin(url) is None:
        msg = f"not a full http(s) URL: {redact_url(url)!r}" + (
            "" if has_base_url else " (this session has no base_url)"
        )
        raise ClientError(msg)


def check_base_url(value: "str | None") -> "str | None":
    """Return ``value`` if it can be the ``base_url`` of a session.

    Raises:
        ValueError: It is neither ``None`` nor one full ``http(s)`` URL
            without credentials, a query or a fragment.

    """
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or effective_origin(value) is None
        or urlsplit(value).query
        or urlsplit(value).fragment
    ):
        msg = (
            "base_url must be a full http(s) URL without credentials, query or "
            f"fragment, got {redact_url(str(value))!r}"
        )
        raise ValueError(msg)
    return value


def check_verify(verify: object) -> None:
    """Warn loudly when talking to a server whose certificate will not be checked.

    ``verify=False`` is an explicit choice, not refused - see
    :class:`~webdav.exceptions.TLSHardeningDisabledWarning` - but a session
    that talks to a server it does not authenticate hands the password to
    whoever answers, so every occurrence is loud and logged. Prefer naming
    the CA that signed the server's certificate (``verify="ca.pem"``)
    over disabling verification when it's just not in the trust store.
    Anything that is not ``True``, ``False`` or a path is refused: ``requests``
    would read ``""``, ``None`` or ``0`` as "do not check".

    Raises:
        TypeError: ``verify`` is not ``True``, ``False`` or a path.
        ClientError: ``verify`` names a CA bundle that does not exist.

    """
    verify = check_verify_type(verify)
    if not verification_on(verify):
        warn_hardening_disabled(
            f"TLS server certificate verification is off (verify={verify!r})"
        )
        return
    if isinstance(verify, str) and not pathlib.Path(verify).exists():
        msg = f"the CA bundle {verify!r} (verify=) does not exist"
        raise ClientError(msg)


def _is_loopback(host: str) -> bool:
    if host.lower() in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check_insecure_transport(value: object) -> InsecureTransport:
    """``value`` as an :class:`InsecureTransport` - a member, or one of ``"warn"``, ``"error"``, ``"allow"``.

    Raises:
        ValueError: It is anything else - a typo here would silently pick the wrong one.

    """
    if isinstance(value, str):
        with contextlib.suppress(ValueError):
            return InsecureTransport(value)
    msg = (
        "insecure_transport must be an InsecureTransport or one of "
        f"{[mode.value for mode in InsecureTransport]}, got {value!r}"
    )
    raise ValueError(msg)


class CleartextWarner:
    """Credentials about to go out over plain ``http``: refuse, warn once per host, or let them.

    Holds what it has already warned about, so it belongs to one session: a
    copy of a session starts with a fresh one (see ``Session._init_derived``).
    """

    def __init__(self) -> None:
        """Start with nothing warned about."""
        self._warned: set[str] = set()
        self._lock = threading.Lock()

    def check(
        self,
        url: str,
        *,
        mode: "InsecureTransport | str" = InsecureTransport.WARN,
        call_headers: "Mapping[str, str] | None",
        session_headers: "Mapping[str, str]",
        has_auth: bool,
        basic: bool = False,
        has_cookies: "Callable[[], bool]" = lambda: False,
        proxied: "Callable[[], bool]" = lambda: False,
    ) -> None:
        """Deal with a request to ``url`` that would send credentials in clear text.

        Args:
            url: Where the request goes.
            mode: What to do (see :class:`InsecureTransport`).
            call_headers: The headers this request carries on top of the
                session's own.
            session_headers: The session's default headers.
            has_auth: The request or the session has ``auth`` set.
            basic: The credentials are HTTP Basic (an ``auth`` pair, a ``BasicAuth``, an
                ``Authorization: Basic`` header): what RFC 4918 section 20.1 forbids.
            has_cookies: Whether a cookie the caller set goes along (asked
                only when nothing else already said so).
            proxied: Whether the request goes through a proxy (asked only for
                a loopback host: it is the proxy that sees such a request, not
                the machine).

        Raises:
            ClientError: ``url`` cannot be parsed - or ``mode`` is ``"error"``
                and credentials would be sent in clear text.

        """
        mode = InsecureTransport(mode)
        if mode is InsecureTransport.ALLOW:
            return
        parts = split_url(url)
        if parts.scheme.lower() != "http" or not parts.hostname:
            return
        if _is_loopback(parts.hostname) and not proxied():
            return
        names = {k.lower() for k in (call_headers or {})} | {
            k.lower() for k in session_headers
        }
        if not (
            has_auth
            or parts.username is not None
            or names & _CREDENTIAL_HEADERS
            or has_cookies()
        ):
            return
        # Host and port only: the netloc may carry the very password being warned about.
        host = (
            f"{parts.hostname.lower()}:{parts.port}"
            if parts.port
            else parts.hostname.lower()
        )
        rfc = (
            "RFC 4918 section 20.1: Basic authentication MUST NOT be used unless the "
            "connection is secure"
        )
        if mode is InsecureTransport.ERROR:
            why = (
                f"{rfc}, and anyone on the network path can read it"
                if basic
                else ("anyone on the network path can read them")
            )
            msg = (
                f"refusing to send credentials to {host} over plain http ({why}). Use an "
                "https URL; or, for a network you trust, pass "
                'insecure_transport=InsecureTransport.WARN ("warn": send, with a warning; '
                'dav: --allow-insecure) or InsecureTransport.ALLOW ("allow": send, silently)'
            )
            raise ClientError(msg)
        with self._lock:
            if host in self._warned:
                return
            self._warned.add(host)
        message = (
            f"sending credentials to {host} over plain http - anyone on the network "
            "path can read them; use an https URL" + (f" ({rfc})" if basic else "")
        )
        _LOGGER.warning(message)
        warn_at_caller(message, InsecureTransportWarning)


def scrub_exception(exc: BaseException, url: str) -> None:
    """Take the query of ``url`` out of ``exc``'s text and of every cause it has - in place.

    ``requests`` builds the message of a connection error from the URL it
    was sending to ("Max retries exceeded with url: /dl/f?X-Amz-Signature=...
    (Caused by ...)"), and the query of a signed URL is the credential.
    The exception types, ``__cause__`` and ``.reason`` stay as they are, so
    that code that looks at them keeps working; only the text changes. The
    live :class:`~requests.PreparedRequest` on ``exc.request`` is not touched.
    """
    try:
        query = urlsplit(url).query
    except ValueError:
        return
    if not query:
        return
    marker, blanked = f"?{query}", "?<redacted>"
    seen: set[int] = set()
    stack: list[object] = [exc]
    while stack:
        current = stack.pop()
        if not isinstance(current, BaseException) or id(current) in seen:
            continue
        seen.add(id(current))
        current.args = tuple(
            a.replace(marker, blanked) if isinstance(a, str) else a
            for a in current.args
        )
        for name in ("url", "_message"):
            value = getattr(current, name, None)
            if isinstance(value, str) and marker in value:
                setattr(current, name, value.replace(marker, blanked))
        stack.extend(
            [
                current.__cause__,
                current.__context__,
                getattr(current, "reason", None),
                *current.args,
            ]
        )


__all__ = [
    "NO_AUTH",
    "CleartextWarner",
    "InsecureTransport",
    "check_auth",
    "check_base_url",
    "check_insecure_transport",
    "check_verify",
    "require_full_url",
    "scrub_exception",
    "split_url",
]
