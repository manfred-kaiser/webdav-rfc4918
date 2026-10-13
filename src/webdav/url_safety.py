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
DEFAULT_PORTS = {"http": 80, "https": 443}

#: Anything a redirect ``Location`` must never contain: control characters
#: (header/URL smuggling) and backslashes (which some URL parsers treat as
#: a path separator and others as part of the authority - a classic
#: parser-differential vector for making a check and the connection see
#: two different hosts).
_FORBIDDEN_URL_CHARS = re.compile(r"[\x00-\x1f\x7f\\]")

#: What must never reach a terminal or a log line as itself, whatever else a name
#: may hold: control characters (C0, DEL, C1 - an ``ESC`` sequence rewrites the
#: screen, ``NEL`` and the line/paragraph separators end a log line), and the
#: bidirectional overrides and isolates that make ``gpj.exe`` read as ``exe.jpg``.
#: Deliberately no more than that: no-break and narrow spaces, joiners and the
#: left-to-right/right-to-left marks are ordinary parts of real file names.
_UNSAFE_TEXT = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069]")

Origin = tuple[str, str, int]

_URL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")


def is_url(value: str) -> bool:
    """Whether ``value`` is written as a URL (``scheme://...``) rather than a plain path."""
    return _URL_RE.match(value) is not None


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
    port = explicit_port if explicit_port is not None else DEFAULT_PORTS.get(scheme, 0)
    # urllib3 keeps the brackets of an IPv6 literal; urllib.parse drops them.
    wire_origin = (
        wire.scheme,
        (wire.hostname or "").strip("[]").lower(),
        wire.port or port,
    )
    problems = (
        _FORBIDDEN_URL_CHARS.search(final),
        scheme not in DEFAULT_PORTS,
        not host,
        parts.username is not None or parts.password is not None or "@" in parts.netloc,
        wire_origin != (scheme, host, port),
    )
    if any(problems) or host is None:
        raise ValueError(msg)
    return (scheme, host, port)


def escape_text(text: str) -> str:
    r"""``text`` with the characters of ``_UNSAFE_TEXT`` written as ``\xNN``/``\uNNNN``, for a message or a log line.

    Only for showing: a name from a server is data and stays as it is.
    """
    return _UNSAFE_TEXT.sub(
        lambda m: (
            f"\\x{ord(m.group()):02x}"
            if ord(m.group()) < 0x100
            else f"\\u{ord(m.group()):04x}"
        ),
        text,
    )


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
        return escape_text(_FORBIDDEN_URL_CHARS.sub("?", parts.path)[:200])
    return escape_text(
        _FORBIDDEN_URL_CHARS.sub("?", f"{parts.scheme}://{host}{port}{parts.path}")[
            :200
        ]
    )


def display_url(path: str) -> str:
    """``path`` for a message: a URL loses its userinfo, query and fragment, and no name carries a control character into it."""
    return redact_url(path) if is_url(path) else escape_text(path)


__all__ = [
    "Origin",
    "display_url",
    "effective_origin",
    "escape_text",
    "is_url",
    "redact_url",
]
