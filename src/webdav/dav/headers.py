"""Building and checking the WebDAV request headers that carry a decision."""

import re
from typing import TYPE_CHECKING
from urllib.parse import quote

from requests.utils import requote_uri

from webdav.dav.conditional import entity_tag
from webdav.exceptions import ClientError
from webdav.methods import Method
from webdav.transport.guards import split_url
from webdav.url_safety import effective_origin, is_url, redact_url

if TYPE_CHECKING:
    from collections.abc import Callable

#: The ``Depth`` values each method accepts (RFC 4918 sec. 9.1, 9.8, 9.9, 9.10).
_ALLOWED_DEPTHS = {
    Method.PROPFIND: ("0", "1", "infinity"),
    Method.COPY: ("0", "infinity"),
    Method.MOVE: ("0", "infinity"),
    Method.LOCK: ("0", "infinity"),
}


def depth_header(depth: "int | str", method: str) -> str:
    """The ``Depth`` header value for ``depth`` on a ``method`` request.

    Raises:
        ValueError: ``depth`` is not one ``method`` accepts.

    """
    try:
        allowed = _ALLOWED_DEPTHS[Method(method)]
    except (KeyError, ValueError):
        msg = f"{method} takes no Depth header"
        raise ValueError(msg) from None
    value = str(depth)
    if value not in allowed:
        msg = f"{method} Depth must be one of {', '.join(allowed)}, got {depth!r}"
        raise ValueError(msg)
    return value


def strong_etag(value: str) -> str:
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


def destination_header(
    destination: str,
    *,
    base_url: "str | None",
    resolve: "Callable[[str], str]",
) -> str:
    """The ``Destination`` header value: an absolute URI or path-absolute (RFC 4918 sec. 10.3).

    A path is a plain path (encoded here, like every path); a full URL is
    made a valid URI (a space or a lone ``%`` in it is encoded) and, with
    a ``base_url``, must be on that server: a ``Destination`` on another
    origin is a cross-server COPY/MOVE nobody has asked for.

    Args:
        destination: A full URL, or a path.
        base_url: The session's ``base_url``, if it has one.
        resolve: Turns a path into a full URL under ``base_url``.

    Raises:
        ClientError: The destination is scheme-relative, carries a query,
            a fragment or a backslash, is on another origin than ``base_url``,
            or is a relative path and there is no ``base_url``.

    """
    if destination.startswith("//"):
        msg = "a scheme-relative Destination is not allowed (RFC 4918 sec. 10.3)"
        raise ClientError(msg)
    if is_url(destination):
        parts = split_url(destination)
        if parts.query or parts.fragment or "\\" in destination:
            # Not part of a resource's address here - and exactly where a
            # parser that reads the URL differently would find another host.
            msg = f"a Destination has no query, fragment or backslash: {redact_url(destination)!r}"
            raise ClientError(msg)
        origin = effective_origin(destination)
        if origin is None or (
            base_url is not None and origin != effective_origin(base_url)
        ):
            msg = f"Destination {redact_url(destination)!r} is not on this session's base_url"
            raise ClientError(msg)
        # ``requote_uri`` leaves a "%" that is not a valid escape as it is;
        # in a URI it can only mean a literal percent sign.
        return str(requote_uri(re.sub(r"%(?![0-9A-Fa-f]{2})", "%25", destination)))
    if base_url is not None:
        return resolve(destination)
    if destination.startswith("/"):
        return quote(destination, safe="/")
    msg = "a Destination is a full URL, or - with a base_url - a path"
    raise ClientError(msg)
