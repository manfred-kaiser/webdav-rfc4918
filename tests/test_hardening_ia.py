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


# -- DOS-05: one log line, not one per element -------------------------------


def test_dos05_defective_activelocks_log_once_without_a_traceback(
    caplog: pytest.LogCaptureFixture,
) -> None:
    prop = "<d:lockdiscovery>" + "<d:activelock/>" * 5000 + "</d:lockdiscovery>"
    with caplog.at_level(logging.WARNING, logger="webdav.dav.properties"):
        response = MultiStatusResponse(ms(entry("/a", extra=prop)))
    assert response.responses["/a"].properties.active_locks == []
    records = [r for r in caplog.records if r.name == "webdav.dav.properties"]
    assert 1 <= len(records) <= 2
    assert all(r.exc_info is None for r in records)
    assert "5000" in records[0].getMessage()


def test_dos05_good_activelocks_are_still_read_and_silent(
    caplog: pytest.LogCaptureFixture,
) -> None:
    prop = (
        "<d:lockdiscovery><d:activelock><d:locktoken><d:href>opaquelocktoken:x</d:href>"
        "</d:locktoken></d:activelock></d:lockdiscovery>"
    )
    with caplog.at_level(logging.WARNING, logger="webdav.dav.properties"):
        response = MultiStatusResponse(ms(entry("/a", extra=prop)))
    assert [
        lock.token for lock in response.responses["/a"].properties.active_locks
    ] == ["opaquelocktoken:x"]
    assert not caplog.records


# -- DOS-06: depth of a property value ---------------------------------------


def _nested(levels: int) -> str:
    return "<d:p>" * levels + "x" + "</d:p>" * levels


def test_dos06_a_property_nested_absurdly_deep_is_refused() -> None:
    body = ms(entry("/a", extra=f'<x:prop xmlns:x="urn:x">{_nested(3000)}</x:prop>'))
    with pytest.raises(MalformedResponseError, match="MAX_PROPERTY_DEPTH"):
        MultiStatusResponse(body)


def test_dos06_a_realistically_nested_property_is_read() -> None:
    body = ms(entry("/a", extra=f'<x:prop xmlns:x="urn:x">{_nested(40)}</x:prop>'))
    props = MultiStatusResponse(body).responses["/a"].properties
    assert props.element("urn:x", "prop") is not None


def test_dos06_the_limit_can_be_lifted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(properties, "MAX_PROPERTY_DEPTH", None)
    body = ms(entry("/a", extra=f'<x:prop xmlns:x="urn:x">{_nested(500)}</x:prop>'))
    assert MultiStatusResponse(body).responses["/a"].properties.elements


def _deep_element(levels: int) -> Any:
    from xml.etree.ElementTree import Element, SubElement

    root = node = Element("{urn:x}p")
    for _ in range(levels):
        node = SubElement(node, "{urn:x}p")
    return root


def test_dos06_serialising_a_too_deep_tree_is_a_value_error() -> None:
    with pytest.raises(ValueError, match="nested too deeply"):
        to_xml_string(_deep_element(5000))
    with pytest.raises(ValueError, match="nested too deeply"):
        build_proppatch_body({("urn:x", "p"): _deep_element(5000)})


# -- DOS-07: the message of a MultiStatusError stays small -------------------


def test_dos07_a_flood_of_failures_gives_a_short_message_and_full_statuses() -> None:
    statuses = {f"/{i}-" + "x" * 8000: "Locked" for i in range(3000)}
    exc = MultiStatusError(statuses)
    assert len(str(exc)) < 10_000
    assert "more" in str(exc)
    assert len(exc.statuses) == 3000


def test_dos07_a_few_short_failures_keep_their_message() -> None:
    assert str(MultiStatusError({"/a": "Locked"})) == "The resource /a is locked"
    two = {"/a": "Locked", "/b": "Not Found"}
    assert str(MultiStatusError(two)) == f"multiple errors received: {two}"


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


# -- DOS-13: parsing a streamed answer is bound to max_response_size ---------


def _multistatus_of(size: int) -> bytes:
    return ms(*(entry(f"/d/{n}") for n in range(size)))


def test_dos13_a_streamed_multistatus_over_the_limit_is_refused() -> None:
    body = _multistatus_of(500)
    with scripted_server(lambda _s: (207, {}, body)) as (url, _rec):
        with Session(url, max_response_size=2000, retry=False) as session:
            response = session.propfind("/d", depth=1, stream=True)
            with pytest.raises(ClientError, match="configured limit"):
                _ = response.multistatus


def test_dos13_a_streamed_multistatus_within_the_limit_is_parsed() -> None:
    body = _multistatus_of(5)
    with scripted_server(lambda _s: (207, {}, body)) as (url, _rec):
        with Session(url, retry=False) as session:
            response = session.propfind("/d", depth=1, stream=True)
            assert len(response.multistatus.entries) == 5


def test_dos13_without_a_limit_a_streamed_multistatus_is_read_whole() -> None:
    body = _multistatus_of(500)
    with scripted_server(lambda _s: (207, {}, body)) as (url, _rec):
        with Session(url, max_response_size=None, retry=False) as session:
            response = session.propfind("/d", depth=1, stream=True)
            assert len(response.multistatus.entries) == 500


def test_dos13_a_streamed_lock_answer_over_the_limit_is_refused() -> None:
    body = b"<d:prop " + DAV.encode() + b">" + b"<d:x/>" * 2000 + b"</d:prop>"
    with scripted_server(lambda _s: (200, {"Lock-Token": "<urn:a>"}, body)) as (
        url,
        _rec,
    ):
        with Session(url, max_response_size=500, retry=False) as session:
            response = session.lock("/f", stream=True, track=False)
            with pytest.raises(ClientError, match="configured limit"):
                _ = response.active_lock


def test_dos13_the_caller_s_own_read_of_a_stream_stays_unbounded() -> None:
    body = b"x" * 100_000
    with scripted_server(lambda _s: (200, {}, body)) as (url, _rec):
        with Session(url, max_response_size=1000, retry=False) as session:
            assert session.get("/big", stream=True).content == body


# -- EXC-01: every href is validated inside the constructor's try ------------

BAD_SECOND_HREF = ms(
    "<d:response><d:href>/d/</d:href><d:href>http://[::1</d:href>"
    "<d:status>HTTP/1.1 423 Locked</d:status></d:response>"
)


def test_exc01_a_second_unparseable_href_is_a_malformed_response() -> None:
    with pytest.raises(MalformedResponseError, match="unusable"):
        MultiStatusResponse(BAD_SECOND_HREF)


def test_exc01_a_423_with_such_a_body_is_still_a_locked_error() -> None:
    response = make_response(423, BAD_SECOND_HREF, method="DELETE")
    with pytest.raises(ResourceLockedError):
        response.raise_for_status()


def test_exc01_a_207_with_such_a_body_is_a_malformed_response() -> None:
    response = make_response(207, BAD_SECOND_HREF, method="DELETE")
    with pytest.raises(MalformedResponseError):
        response.raise_for_status()


def test_exc01_info_through_the_file_system_stays_in_the_hierarchy() -> None:
    with scripted_server(lambda _s: (207, {}, BAD_SECOND_HREF)) as (url, _rec):
        with pytest.raises(WebDAVError):
            FileSystem(url, retry=False).info("/d")


def test_exc01_several_valid_hrefs_of_one_response_still_work() -> None:
    body = ms(
        "<d:response><d:href>/a</d:href><d:href>/a/</d:href>"
        "<d:status>HTTP/1.1 423 Locked</d:status></d:response>"
    )
    parsed = MultiStatusResponse(body)
    assert parsed.entries[0].hrefs == ["/a", "/a/"]
    assert set(parsed.responses) == {"/a", "/a/"} or "/a" in parsed.responses


# -- PROTO-05: the root element of a multistatus -------------------------------


@pytest.mark.parametrize(
    "body",
    [
        b"<multistatus><response><href>/a</href><status>HTTP/1.1 423 Locked</status></response></multistatus>",
        b'<m:multistatus xmlns:m="urn:x"/>',
        b"<html><body>hello</body></html>",
    ],
)
def test_proto05_a_207_with_another_root_is_refused(body: bytes) -> None:
    with pytest.raises(MalformedResponseError, match="multistatus"):
        parse_multistatus_response(make_response(207, body, method="DELETE"))
    with pytest.raises(MalformedResponseError):
        make_response(207, body, method="DELETE").raise_for_status()


def test_proto05_an_empty_correct_multistatus_is_still_empty() -> None:
    parsed = parse_multistatus_response(make_response(207, ms(), method="PROPFIND"))
    assert parsed.entries == []


def test_proto05_the_public_constructor_takes_any_root_as_before() -> None:
    assert MultiStatusResponse(b"<anything/>").entries == []


# -- PROTO-07: a 3xx that carried nothing out --------------------------------


@pytest.mark.parametrize("status", [300, 301, 304, 305, 306])
@pytest.mark.parametrize("method", ["PUT", "DELETE", "MKCOL", "MOVE", "PROPPATCH"])
def test_proto07_a_write_answered_by_an_unfollowable_3xx_is_an_error(
    status: int, method: str
) -> None:
    response = make_response(status, method=method)
    with pytest.raises(RedirectNotFollowedError):
        response.raise_for_status()
    with pytest.raises(RedirectNotFollowedError):
        raise_for_status(response)


@pytest.mark.parametrize("method", ["GET", "HEAD", "PROPFIND", "OPTIONS"])
def test_proto07_a_conditional_read_answered_304_stays_fine(method: str) -> None:
    make_response(304, method=method).raise_for_status()


def test_proto07_the_message_says_nothing_was_carried_out() -> None:
    with pytest.raises(RedirectNotFollowedError, match="no Location"):
        make_response(304, method="PUT").raise_for_status()


# -- BUG-09: whitespace around an href or an ETag ----------------------------


def test_bug09_a_pretty_printed_href_and_etag_are_read() -> None:
    body = ms(
        entry(
            "\n    /d/a.txt\n  ",
            extra='<d:getetag>\n  "abc"\n </d:getetag>',
        )
    )
    parsed = MultiStatusResponse(body)
    response = parsed.entries[0]
    assert response.href == "/d/a.txt"
    assert response.properties.etag == '"abc"'
    assert entity_tag(response.properties.etag or "") == '"abc"'


def test_bug09_an_href_of_nothing_but_whitespace_is_still_missing() -> None:
    with pytest.raises(MalformedResponseError, match="missing a required"):
        MultiStatusResponse(ms(entry(" \n ")))


def test_bug09_a_control_character_inside_an_href_is_still_refused() -> None:
    with pytest.raises(MalformedResponseError, match="control character"):
        MultiStatusResponse(ms(entry("/d/a\tb")))


def test_bug09_display_name_keeps_its_edge_spaces() -> None:
    body = ms(entry("/a", extra="<d:displayname> a </d:displayname>"))
    assert MultiStatusResponse(body).entries[0].properties.display_name == " a "


# -- FS-05: what a message may carry -----------------------------------------

NASTY = "x\n2026 ERROR forged\x1b[2J\x85\u2028\u202eexe.jpg"


def test_fs05_redact_url_neutralises_every_control_class() -> None:
    shown = redact_url(f"https://h.example/{NASTY}?token=secret")
    assert "secret" not in shown
    assert not any(c in shown for c in "\n\x1b\x85\u2028\u202e")


def test_fs05_a_reason_phrase_cannot_forge_a_log_line() -> None:
    exc = HTTPStatusError(
        make_response(403, reason="Forbidden\x1b]0;pwned\x07\r\nforged")
    )
    assert not any(c in str(exc) for c in "\x1b\x07\r\n")
    assert "Forbidden" in str(exc)


def test_fs05_a_path_in_a_not_found_message_cannot_forge_a_log_line() -> None:
    exc = ResourceNotFoundError(make_response(404), path=NASTY)
    assert not any(c in str(exc) for c in "\n\x1b\x85\u2028\u202e")
    assert exc.path == NASTY  # the data itself is not altered


def test_fs05_a_failing_href_in_a_multistatus_message_cannot_forge_a_log_line() -> None:
    exc = MultiStatusError({NASTY: "Locked"})
    assert not any(c in str(exc) for c in "\n\x1b\x85\u2028\u202e")


def test_fs05_the_error_path_of_a_redirected_request_is_safe() -> None:
    response = make_response(
        404, url="http://dav.example/gone%0a2026-10-11%20ERROR%20x%1b%5b2J"
    )
    with pytest.raises(ResourceNotFoundError) as caught:
        response.raise_for_status()
    assert "\n" not in str(caught.value)
    assert "\x1b" not in str(caught.value)


@pytest.mark.parametrize(
    "name",
    [
        "Screenshot 10.00.00\u202fAM.png",
        "a\u00a0b",
        "family \U0001f468\u200d\U0001f469\u200d\U0001f467",
        "\u6f22\u5b57.txt",
        "\u05e9\u200f\u05dc\u05d5\u05dd",
        "back\\slash",
    ],
)
def test_fs05_ordinary_unicode_names_are_neither_rejected_nor_changed(
    name: str,
) -> None:
    exc = ResourceNotFoundError(make_response(404), path=name)
    assert name in str(exc)
    assert redact_url(f"https://h/{name}").endswith(name.replace("\\", "?"))


def test_fs05_names_with_control_characters_are_still_listed() -> None:
    parsed = MultiStatusResponse(ms(entry("/d/a%0Ab"), entry("/d/%E2%80%AEgpj.exe")))
    assert [r.path for r in parsed.entries] == ["/d/a\nb", "/d/\u202egpj.exe"]


# -- FS-09: two answers for one resource --------------------------------------


def _info_of(*entries: str) -> Any:
    with scripted_server(lambda _s: (207, {}, ms(*entries))) as (url, _rec):
        return FileSystem(url, retry=False).info("/d")


def test_fs09_a_hidden_collection_is_not_silently_replaced_by_a_file() -> None:
    with pytest.raises(MalformedResponseError, match="several"):
        _info_of(entry("/d/", collection=True), entry("/d/."))


def test_fs09_get_props_refuses_the_same_ambiguity() -> None:
    with scripted_server(
        lambda _s: (207, {}, ms(entry("/d/", collection=True), entry("/d/.")))
    ) as (url, _rec):
        with pytest.raises(MalformedResponseError, match="several"):
            FileSystem(url, retry=False).get_props("/d")


def test_fs09_a_plain_info_is_untouched() -> None:
    assert _info_of(entry("/d/", collection=True)).is_dir


def test_fs09_nfc_and_nfd_twins_are_both_listed() -> None:
    nfc = unicodedata.normalize("NFC", "/d/\u00e9.txt")
    nfd = unicodedata.normalize("NFD", "/d/\u00e9.txt")
    assert nfc != nfd
    body = ms(entry("/d/", collection=True), entry(nfc), entry(nfd))
    with scripted_server(lambda _s: (207, {}, body)) as (url, _rec):
        names = [str(r) for r in FileSystem(url, retry=False).ls("/d")]
    assert len(names) == 2
    assert MultiStatusResponse(
        body
    ).ambiguous_keys  # the lookup is ambiguous, the listing is not


def test_fs09_one_response_with_two_hrefs_is_not_a_duplicate() -> None:
    parsed = MultiStatusResponse(
        ms(
            "<d:response><d:href>/a</d:href><d:href>/a/</d:href>"
            "<d:status>HTTP/1.1 423 Locked</d:status></d:response>"
        )
    )
    assert not parsed.ambiguous_keys


def test_fs09_the_same_member_listed_twice_is_listed_twice() -> None:
    body = ms(entry("/d/", collection=True), entry("/d/a"), entry("/d/a"))
    with scripted_server(lambda _s: (207, {}, body)) as (url, _rec):
        assert len(FileSystem(url, retry=False).ls("/d")) == 2
