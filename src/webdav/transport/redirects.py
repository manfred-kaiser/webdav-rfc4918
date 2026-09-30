"""Redirect policy and the URL checks that back it.

HTTP permits a server to answer *any* method with a redirect (RFC 9110
sec. 15.4); nothing requires a client to *follow* one, and blindly doing
so is unsafe for a general-purpose client - a malicious or compromised
server could otherwise redirect a write to a different resource, or
(307/308) to a completely different host while fully replaying the
request body, with no error raised to the caller.

Everything here is about deciding *whether* a redirect target may be
followed; :class:`webdav.session.Session` does the following itself.
"""

import re
from enum import Enum
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

import requests
import urllib3.util

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

#: How many redirects a single request will follow automatically before
#: giving up - guards against a redirect loop between trusted origins.
MAX_REDIRECTS = 5

#: Default port per scheme, so "https://host" and "https://host:443"
#: compare equal when deciding whether a redirect stays within one origin.
_DEFAULT_PORTS = {"http": 80, "https": 443}

#: Anything a redirect ``Location`` must never contain: control characters
#: (header/URL smuggling) and backslashes (which some URL parsers treat as
#: a path separator and others as part of the authority - a classic
#: parser-differential vector for making a check and the connection see
#: two different hosts).
_FORBIDDEN_URL_CHARS = re.compile(r"[\x00-\x1f\x7f\\]")

Origin = tuple[str, str, int]


class RedirectPolicy(Enum):
    """How a :class:`~webdav.session.Session` decides whether to follow a 3xx redirect.

    Four explicit, named tiers, deliberately mirroring the browser
    ``fetch()`` ``redirect``/``credentials`` options for a familiar mental
    model - there is no implicit "trust everything" default; :data:`ALL`
    exists, but has to be chosen on purpose:

    - :data:`NEVER`: never follow any redirect - ``fetch``'s
      ``redirect: "error"``. The strictest tier, for a caller that wants
      zero surprises about where a request ends up.
    - :data:`SAME_ORIGIN` (the default): follow a same-origin redirect
      automatically, refuse (``RedirectNotFollowedError``) anything else
      - safe by construction, since a same-origin redirect can't move a
      request or its body outside the server the caller already chose
      to trust. An origin is scheme + host + port (RFC 6454), so an
      ``http`` -> ``https`` upgrade on the same host is a *different*
      origin and is refused too: the request that produced it already
      sent its credentials in clear text, and following the redirect
      would only hide that from the caller. Use an ``https`` URL.
    - :data:`WHITELIST`: additionally follow a redirect to an origin
      ``trusted_redirect_origins`` names - e.g. a signed-upload gateway
      on a separate origin. Requires ``trusted_redirect_origins`` to
      actually be set; using ``WHITELIST`` without it (or setting
      ``trusted_redirect_origins`` under a different policy) is rejected
      at construction as a likely mistake rather than silently doing
      nothing.
    - :data:`ALL`: follow a redirect to any origin at all - except an
      ``https`` -> ``http`` downgrade, which is never followed. The
      unrestricted tier - only ever appropriate when the caller has
      independently decided every redirect this server could possibly
      issue is fine to follow.

    Regardless of tier, credentials, cookies and lock tokens are never
    forwarded to a *different* origin a redirect lands on - nor is any
    header the session sets by default, since a custom API-key header
    can't be told apart from an unrelated one.
    """

    NEVER = "never"
    SAME_ORIGIN = "same-origin"
    WHITELIST = "whitelist"
    ALL = "all"


def origin(url: str) -> "tuple[str, str | None, int | None]":
    """``(scheme, hostname, port)`` with the scheme's default port filled in.

    An RFC 6454-style origin tuple - two URLs compare equal here iff a
    redirect between them can't cross a trust boundary a caller didn't
    explicitly sanction.
    """
    parts = urlsplit(url)
    return (
        parts.scheme,
        parts.hostname,
        parts.port or _DEFAULT_PORTS.get(parts.scheme),
    )


def effective_origin(url: str) -> "Origin | None":
    r"""The origin a connection to ``url`` would *actually* go to, or ``None``.

    ``None`` means "don't trust this URL for anything": it isn't plain
    ``http``/``https``, carries userinfo, contains control characters or
    backslashes, or - the point of the exercise - two URL parsers disagree
    about which host it names. The check parses the URL the way
    ``requests`` will prepare it and then with both :mod:`urllib.parse`
    (what the policy compares) and :mod:`urllib3` (what opens the
    connection); a Location such as ``https://good.example\@evil.example/``
    that one reads as ``good.example`` and the other as ``evil.example``
    yields ``None`` instead of an origin an attacker chose.
    """
    try:
        return _checked_origin(url)
    except (ValueError, requests.exceptions.RequestException):
        return None


def _checked_origin(url: str) -> Origin:
    """:func:`effective_origin`, raising ``ValueError`` where that returns ``None``."""
    msg = f"{url!r} does not name one unambiguous http(s) origin"
    # Checked on the URL as given *and* as prepared: preparing normalises,
    # e.g. drops an empty userinfo, and an authority with an "@" in it is
    # never something a redirect target has a legitimate reason to have.
    raw = urlsplit(url)
    # ``raw.port`` raises ValueError for anything above 65535. Port 0 is no
    # port a connection is made to - and preparing the URL below would drop
    # it silently and turn ``host:0`` into the default port.
    if _FORBIDDEN_URL_CHARS.search(url) or "@" in raw.netloc or raw.port == 0:
        raise ValueError(msg)
    prepared = requests.models.PreparedRequest()
    prepared.prepare_url(url, None)
    final = prepared.url or ""
    parts = urlsplit(final)
    wire = urllib3.util.parse_url(final)
    scheme, host = parts.scheme, parts.hostname
    explicit_port = parts.port  # ValueError above 65535
    if explicit_port == 0:
        raise ValueError(msg)  # port 0 is no port a connection is made to
    port = explicit_port if explicit_port is not None else _DEFAULT_PORTS.get(scheme, 0)
    # urllib3 keeps the brackets of an IPv6 literal; urllib.parse drops them.
    wire_origin = (
        wire.scheme,
        (wire.hostname or "").strip("[]").lower(),
        wire.port or port,
    )
    problems = (
        _FORBIDDEN_URL_CHARS.search(final),
        scheme not in _DEFAULT_PORTS,
        not host,
        parts.username is not None or parts.password is not None or "@" in parts.netloc,
        wire_origin != (scheme, host, port),
    )
    if any(problems) or host is None:
        raise ValueError(msg)
    return (scheme, host, port)


def redact_url(url: str) -> str:
    """``url`` without userinfo, query and fragment, for log lines and error messages.

    A redirect target is often a signed URL whose query string *is* the
    credential; it must not end up in a log or an exception message.
    """
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        port = f":{parts.port}" if parts.port else ""
    except ValueError:
        return "<unparseable URL>"
    if not parts.scheme and not host:
        return _FORBIDDEN_URL_CHARS.sub("?", parts.path)[:200]
    return _FORBIDDEN_URL_CHARS.sub("?", f"{parts.scheme}://{host}{port}{parts.path}")[
        :200
    ]


def validate_policy(
    policy: RedirectPolicy,
    trusted_redirect_origins: "Iterable[str] | Callable[[str], bool] | None",
) -> None:
    """Reject an inconsistent ``policy`` / ``trusted_redirect_origins`` pair.

    Raises:
        ValueError: ``WHITELIST`` without trusted origins, or trusted
            origins under any other policy - almost certainly a mistake,
            and silently doing nothing would be the unsafe way to fail.

    """
    if policy == RedirectPolicy.WHITELIST and trusted_redirect_origins is None:
        msg = (
            "redirect_policy=RedirectPolicy.WHITELIST requires "
            "trusted_redirect_origins to be set"
        )
        raise ValueError(msg)
    if policy != RedirectPolicy.WHITELIST and trusted_redirect_origins is not None:
        msg = (
            "trusted_redirect_origins has no effect without "
            "redirect_policy=RedirectPolicy.WHITELIST"
        )
        raise ValueError(msg)


def build_trust_check(
    trusted_redirect_origins: "Iterable[str] | Callable[[str], bool] | None",
) -> "Callable[[str], bool]":
    """Build the predicate deciding whether a cross-origin target is trusted.

    Accepts either shape ``trusted_redirect_origins`` documents: a
    caller-supplied predicate is used as-is; an iterable of origin strings
    is turned into one exact-origin-membership check.
    """
    if trusted_redirect_origins is None:
        return lambda _url: False
    if callable(trusted_redirect_origins):
        return trusted_redirect_origins
    trusted = frozenset(o for o in map(effective_origin, trusted_redirect_origins) if o)
    return lambda url: effective_origin(url) in trusted


def has_replayable_body(kwargs: "dict[str, object]") -> bool:
    """Whether a request's payload is safe to send a second time.

    ``None``/``str``/``bytes`` (and a ``json=`` value) are - a lack of a
    body is trivially replayable, and a string/bytes body is read fresh
    from memory every time. Anything else (a generator, an
    already-partially-read file object, :class:`~webdav.transport.streaming.SizedIterator`,
    ``files=``, ...) may already have been exhausted by a first attempt -
    resending it would silently send a truncated/empty body instead of
    raising, which is worse than not following at all.
    """
    data = kwargs.get("data")
    return kwargs.get("files") is None and (
        data is None or isinstance(data, str | bytes)
    )
