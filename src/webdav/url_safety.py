"""What a URL names, and how to show it without leaking what is in it.

The primitives every other part of the library leans on when it has to decide
whether two URLs are the same server (:func:`effective_origin`) or has to put
a URL into a log line or an error message (:func:`redact_url`). Internal, and
deliberately a leaf: it imports nothing from :mod:`webdav`, so the exception
classes, the lock registry, the redirect policy and the session can all use
it without importing each other.
"""

import re
from urllib.parse import urlsplit

import requests
import urllib3.util

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

    An origin is scheme, host and port (RFC 6454), with the scheme's default
    port filled in: two URLs compare equal here iff a request to one can't
    cross a trust boundary a caller didn't explicitly sanction by going to
    the other.
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


__all__ = ["Origin", "effective_origin", "redact_url"]
