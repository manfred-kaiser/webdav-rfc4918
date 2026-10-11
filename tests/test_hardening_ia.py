"""1.3.0 hardening of the DAV wire layer, exceptions and responses.

One block per finding (see the ids in the test names): a test that shows the
misbehaviour, and one that pins the behaviour that has to stay.
"""

import copy
import inspect
import logging
import pickle
import time
import unicodedata
from concurrent.futures import ProcessPoolExecutor
from multiprocessing import get_context
from datetime import UTC, datetime, timedelta
from io import BytesIO
from typing import Any

import pytest
import requests
from requests.structures import CaseInsensitiveDict

import webdav.dav.locks as locks_module
from webdav.dav import xml_utils
import webdav.exceptions as exceptions_module
from tests.scripted_server import Seen, scripted_server
from webdav import FileSystem, Response, Session
from webdav.dav import multistatus, properties
from webdav.dav.conditional import entity_tag
from webdav.dav.date_utils import fromisoformat, from_rfc1123
from webdav.dav.locks import ActiveLock, HeldLock, LockRegistry
from webdav.dav.multistatus import (
    MultiStatusResponse,
    multistatus_failure,
    parse_multistatus_response,
)
from webdav.dav.properties import build_proppatch_body
from webdav.dav.xml_utils import parse_xml, to_xml_string
from webdav.exceptions import (
    ClientError,
    HTTPStatusError,
    MalformedResponseError,
    MultiStatusError,
    RedirectNotFollowedError,
    ResourceLockedError,
    ResourceNotFoundError,
    WebDAVError,
    raise_for_status,
)
from webdav.url_safety import redact_url

DAV = 'xmlns:d="DAV:"'


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


# -- DOS-01: entity declarations ---------------------------------------------

BOMB = (
    '<?xml version="1.0"?><!DOCTYPE d [<!ENTITY big "'
    + "&#60;a/>" * 400
    + '">]><d:multistatus xmlns:d="DAV:">'
    + "&big;" * 99
    + "</d:multistatus>"
).encode()


def test_dos01_an_entity_declaration_is_refused_before_anything_expands() -> None:
    started = time.perf_counter()
    with pytest.raises(MalformedResponseError, match="entity"):
        parse_xml(BOMB)
    assert time.perf_counter() - started < 0.5


def test_dos01_a_small_harmless_entity_is_refused_too() -> None:
    body = b'<!DOCTYPE x [<!ENTITY e "v">]><d:multistatus xmlns:d="DAV:">&e;</d:multistatus>'
    with pytest.raises(MalformedResponseError, match="entity"):
        parse_xml(body)


def test_dos01_a_parameter_entity_is_refused_too() -> None:
    body = b'<!DOCTYPE x [<!ENTITY % p "v">]><d:multistatus xmlns:d="DAV:"/>'
    with pytest.raises(MalformedResponseError, match="entity"):
        parse_xml(body)


def test_dos01_the_error_body_parser_does_not_expand_an_entity_either() -> None:
    body = (
        b'<!DOCTYPE x [<!ENTITY e "v">]><d:error xmlns:d="DAV:">'
        b"<d:no-conflicting-lock/>&e;</d:error>"
    )
    exc = ResourceLockedError(make_response(423, body))
    assert exc.error_codes == frozenset()


def test_dos01_the_error_body_bomb_costs_nothing() -> None:
    body = BOMB.replace(b"d:multistatus", b"d:error")
    exc = ResourceLockedError(make_response(423, body))
    started = time.perf_counter()
    assert exc.error_codes == frozenset()
    assert time.perf_counter() - started < 0.5


@pytest.mark.parametrize(
    "doctype",
    [
        "<!DOCTYPE html>",
        '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0//EN" "http://x/x.dtd">',
        "<!DOCTYPE d:multistatus [<!ATTLIST d:multistatus a CDATA #IMPLIED>]>",
    ],
)
def test_dos01_a_doctype_without_entities_stays_readable(doctype: str) -> None:
    body = f'{doctype}<d:multistatus xmlns:d="DAV:"/>'.encode()
    assert parse_xml(body).tag == "{DAV:}multistatus"


def test_dos01_an_html_error_page_with_a_doctype_is_still_no_multistatus() -> None:
    page = b"<!DOCTYPE html><html><body>Forbidden</body></html>"
    assert multistatus_failure(make_response(403, page)) is None
    assert ResourceLockedError(make_response(423, page)).error_codes == frozenset()


@pytest.mark.parametrize(
    "body",
    [
        b"\xef\xbb\xbf" + ms(entry("/a")),
        b'<?xml version="1.0" encoding="ISO-8859-1"?>' + ms(entry("/a")),
        b'<?xml version="1.0"?>\n' + ms("\n  ", entry("/a"), "\n"),
    ],
)
def test_dos01_ordinary_documents_parse_as_before(body: bytes) -> None:
    assert list(MultiStatusResponse(body).responses) == ["/a"]


# -- DOS-09: the cost of one document ----------------------------------------


def test_dos09_the_default_limit_lies_above_what_max_responses_carry() -> None:
    # 200 000 Nextcloud-style allprop entries carry ~68 '<' each (13.6 M).
    assert xml_utils.MAX_MARKUP is not None
    assert xml_utils.MAX_MARKUP > multistatus.MAX_RESPONSES * 68


def test_dos09_a_document_over_the_limit_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(xml_utils, "MAX_MARKUP", 1000)
    with pytest.raises(MalformedResponseError, match="MAX_MARKUP"):
        parse_xml(b"<a>" + b"<b/>" * 1000 + b"</a>")
    assert parse_xml(b"<a>" + b"<b/>" * 100 + b"</a>").tag == "a"
    monkeypatch.setattr(xml_utils, "MAX_MARKUP", None)
    assert parse_xml(b"<a>" + b"<b/>" * 5000 + b"</a>").tag == "a"


def test_dos09_a_big_ordinary_listing_is_not_touched() -> None:
    entries = [
        entry(f"/d/file{n}.txt", extra="<d:getcontentlength>1</d:getcontentlength>")
        for n in range(20_000)
    ]
    assert len(MultiStatusResponse(ms(*entries)).entries) == 20_000
