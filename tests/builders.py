"""The XML answers and responses the tests hand to the library, built in one place."""

import requests
from requests.structures import CaseInsensitiveDict

from webdav import Response

DAV = 'xmlns:d="DAV:"'

MULTISTATUS_TEMPLATE = (
    '<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">{}</d:multistatus>'
)


def ms(*entries: str, root: str = f"d:multistatus {DAV}") -> bytes:
    """A multistatus document around ``entries``."""
    name = root.split(maxsplit=1)[0]
    return f"<{root}>{''.join(entries)}</{name}>".encode()


def entry(href: str, *, collection: bool = False, extra: str = "") -> str:
    """A ``<d:response>`` with one 200 propstat."""
    rtype = (
        "<d:resourcetype><d:collection/></d:resourcetype>"
        if collection
        else "<d:resourcetype/>"
    )
    return (
        f"<d:response><d:href>{href}</d:href><d:propstat><d:prop>{rtype}{extra}"
        "</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
    )


def sized_entry(href: str, is_dir: bool, size: "int | None" = None) -> str:
    """A ``<d:response>`` with a 200 propstat for the type and, if given, the size."""
    kind = (
        "<d:resourcetype><d:collection/></d:resourcetype>"
        if is_dir
        else "<d:resourcetype/>"
    )
    length = (
        f"<d:getcontentlength>{size}</d:getcontentlength>" if size is not None else ""
    )
    return (
        f"<d:response><d:href>{href}</d:href><d:propstat><d:prop>{kind}{length}</d:prop>"
        "<d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
    )


def status_entry(href: str, status: str) -> str:
    """A ``<d:response>`` that has only a status (no propstat)."""
    return (
        f"<d:response><d:href>{href}</d:href><d:status>{status}</d:status></d:response>"
    )


def multistatus_doc(*responses: str) -> bytes:
    """A multistatus document, with its XML declaration, around ``responses``."""
    return (
        f'<?xml version="1.0"?><d:multistatus {DAV}>{"".join(responses)}</d:multistatus>'
    ).encode()


def multistatus_of_hrefs(*hrefs: str, collection: bool = True) -> bytes:
    """A multistatus with one 200 propstat per href, all collections or all files."""
    kind = "<d:collection/>" if collection else ""
    responses = "".join(
        f"<d:response><d:href>{h}</d:href><d:propstat><d:prop><d:resourcetype>{kind}"
        "</d:resourcetype></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
        for h in hrefs
    )
    return MULTISTATUS_TEMPLATE.format(responses).encode()


def multistatus_ls(*hrefs: str) -> bytes:
    """A listing: an href ending in ``/`` is a collection, any other is a file."""
    rows = "".join(
        f"<d:response><d:href>{h}</d:href><d:propstat><d:prop><d:resourcetype>"
        f"{'<d:collection/>' if h.endswith('/') else ''}</d:resourcetype></d:prop>"
        f"<d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
        for h in hrefs
    )
    return MULTISTATUS_TEMPLATE.format(rows).encode()


def make_response(
    status: int = 200,
    body: bytes = b"",
    *,
    method: str = "PUT",
    url: str = "http://dav.example/f",
    headers: "dict[str, str] | None" = None,
    request_headers: "dict[str, str] | None" = None,
    reason: "str | None" = None,
) -> Response:
    """A fully read :class:`~webdav.Response` for ``method`` on ``url``."""
    response = Response()
    response.status_code = status
    response.url = url
    response.reason = reason  # type: ignore[assignment]
    response.headers.update(headers or {})
    response._content = body
    response._content_consumed = True  # type: ignore[attr-defined]
    request = requests.PreparedRequest()
    request.method = method
    request.url = url
    request.headers = CaseInsensitiveDict(request_headers or {})
    response.request = request
    return response
