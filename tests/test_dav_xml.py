"""The XML the library builds and reads.

Property names, bodies, dates, error bodies, and entities it refuses.
"""

import logging
import pyexpat
import time
from datetime import UTC, datetime, timedelta
from xml.etree.ElementTree import Element, fromstring

import pytest
import requests

from tests.builders import entry, make_response, ms
from tests.scripted_server import always, scripted_server
from webdav import FileSystem, Session, _xml_guard
from webdav.dav.date_utils import from_rfc1123, fromisoformat
from webdav.dav.multistatus import MultiStatusResponse, multistatus_failure
from webdav.dav.properties import build_propfind_body, build_proppatch_body
from webdav.dav.xml_utils import parse_xml
from webdav.exceptions import (
    _MAX_ERROR_BODY_SIZE,
    HTTPStatusError,
    MalformedResponseError,
    ResourceLockedError,
    _parse_error_codes,
)


@pytest.mark.parametrize("encoding", ["x-bogus", "utf-16", "idna", "punycode", "rot13"])
def test_a_bogus_xml_encoding_declaration_is_a_webdav_error(encoding: str) -> None:
    body = f'<?xml version="1.0" encoding="{encoding}"?><d:multistatus xmlns:d="DAV:"/>'.encode()
    with scripted_server(always((207, {}, body))) as (url, _rec):
        with pytest.raises(MalformedResponseError):
            FileSystem(retry=False).ls(f"{url}/dir")
        response = Session(retry=False).get(f"{url}/x")
        assert response.status_code == 207  # and an error response's <error> body:
    with scripted_server(always((409, {}, body))) as (url, _rec):
        with pytest.raises(HTTPStatusError) as excinfo:
            FileSystem(retry=False).mkdir(f"{url}/d")
        assert excinfo.value.error_codes == frozenset()


def _consumed(body: bytes) -> requests.Response:
    response = requests.Response()
    response.status_code = 423
    response._content = body
    response._content_consumed = True  # type: ignore[attr-defined]
    return response


def test_an_error_body_within_the_limit_is_read() -> None:
    body = b'<D:error xmlns:D="DAV:"><D:no-conflicting-lock/></D:error>'
    assert _parse_error_codes(_consumed(body)) == {"no-conflicting-lock"}


def test_an_error_body_already_read_but_over_the_limit_is_not_parsed() -> None:
    padding = b"<!--" + b"x" * _MAX_ERROR_BODY_SIZE + b"-->"
    body = b'<D:error xmlns:D="DAV:"><D:no-conflicting-lock/></D:error>' + padding
    assert _parse_error_codes(_consumed(body)) == frozenset()


def test_an_entity_in_an_error_body_is_logged_not_silent(
    caplog: pytest.LogCaptureFixture,
) -> None:
    body = b'<!DOCTYPE e [<!ENTITY a "x">]><D:error xmlns:D="DAV:"><D:no-conflicting-lock/></D:error>'
    with caplog.at_level(logging.WARNING, logger="webdav"):
        assert _parse_error_codes(_consumed(body)) == frozenset()
    assert "declares an entity" in caplog.text
    assert "423" in caplog.text


def test_an_old_expat_is_logged_once(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(pyexpat, "version_info", (2, 6, 0))
    monkeypatch.setattr(pyexpat, "EXPAT_VERSION", "expat_2.6.0")
    _xml_guard._warned.clear()
    try:
        with caplog.at_level(logging.WARNING, logger="webdav"):
            _xml_guard.check_xml(b"<a/>")
            _xml_guard.check_xml(b"<a/>")
        assert caplog.text.count("expat_2.6.0") == 1
        assert "2.7.2" in caplog.text
    finally:
        _xml_guard._warned.clear()


def test_a_current_expat_is_not_logged(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(pyexpat, "version_info", (2, 7, 2))
    _xml_guard._warned.clear()
    with caplog.at_level(logging.WARNING, logger="webdav"):
        _xml_guard.check_xml(b"<a/>")
    assert "expat" not in caplog.text


def test_a_proppatch_value_can_be_a_list_of_elements() -> None:
    body = build_proppatch_body(
        {("urn:x", "kinds"): [Element("{urn:x}a"), Element("{urn:x}b")]}
    )
    assert body.index("<ns1:a />") < body.index("<ns1:b />")
    assert body.count("kinds") == 2


def test_a_proppatch_value_must_be_text_or_elements() -> None:
    with pytest.raises(TypeError, match="str or Element"):
        build_proppatch_body({"displayname": ["text"]})  # type: ignore[list-item]


INJECTIONS = [
    'a/><ns0:evil xmlns:ns0="urn:x"',
    'x xmlns:e="urn:e" e:a="1"',
    "x><evil/><y",
    "with space",
    "",
    "nul\x00",
    "1starts-with-digit",
    "a:b",
    "a b>",
]


@pytest.mark.parametrize("name", INJECTIONS)
def test_a_property_name_that_is_not_a_name_is_refused(name: str) -> None:
    with pytest.raises(ValueError, match="property name"):
        build_proppatch_body(remove_props=[name])
    with pytest.raises(ValueError, match="property name"):
        build_propfind_body([name])
    with pytest.raises(ValueError, match="property name"):
        build_proppatch_body(set_props={name: "v"})


@pytest.mark.parametrize(
    "name",
    [
        ("urn:q", "x}y"),
        ("ur}n", "x"),
        ("urn:\x00", "x"),
        (None, "x"),
        ("a", "b", "c"),
        5,
        b"x",
        ("urn:q", 5),
    ],
)
def test_a_malformed_qualified_name_is_refused(name: object) -> None:
    with pytest.raises((ValueError, TypeError)):
        build_propfind_body([name])  # type: ignore[list-item]


def test_an_empty_namespace_means_no_namespace_and_never_an_undeclaration() -> None:
    body = build_propfind_body([("", "custom")])
    assert 'xmlns:ns1=""' not in body
    prop = fromstring(body)[0]
    assert [child.tag for child in prop] == ["custom"]


def test_a_single_string_is_not_a_list_of_characters() -> None:
    with pytest.raises(TypeError, match="not a single"):
        build_propfind_body("etag")
    with pytest.raises(TypeError, match="not a single"):
        FileSystem("http://unused.invalid").get_props("/a", props="etag")


def test_ordinary_names_still_work() -> None:
    body = build_propfind_body(
        ["etag", "getcontentlength", ("urn:my", "custom-prop_1.x")]
    )
    tags = [child.tag for child in fromstring(body)[0]]
    assert tags == [
        "{DAV:}getetag",
        "{DAV:}getcontentlength",
        "{urn:my}custom-prop_1.x",
    ]


@pytest.mark.parametrize("value", ["a\x00b", "a\x01b", "a\x0bb", "a\ud800b", "￾", "￿"])
def test_characters_xml_cannot_carry_are_refused_not_sent(value: str) -> None:
    with pytest.raises(ValueError, match="XML"):
        build_proppatch_body(set_props={"displayname": value})
    with pytest.raises(ValueError, match="XML"):
        Session().lock("http://unused.invalid/a", owner=value)


def test_a_carriage_return_survives_the_round_trip() -> None:
    body = build_proppatch_body(set_props={"displayname": "a\r\nb\rc"})
    assert "&#13;" in body
    assert fromstring(body).findtext(".//{DAV:}displayname") == "a\r\nb\rc"


def test_tabs_newlines_and_unicode_are_fine() -> None:
    body = build_proppatch_body(set_props={"displayname": "tab\tnewline\nünï 😀"})
    assert fromstring(body).findtext(".//{DAV:}displayname") == "tab\tnewline\nünï 😀"


@pytest.mark.parametrize(
    "text",
    [
        "2024-01-01T00:00:00+99:99",
        "9999-12-31T23:59:59-23:59",
        "1",
        "2024",
        "Mon",
        "0000",
        "T",
        "24:00",
    ],
)
def test_a_garbage_or_unusable_date_is_none(text: str) -> None:
    assert fromisoformat(text) is None
    assert from_rfc1123(text) is None


@pytest.mark.parametrize(
    "text",
    [
        "Wed, 21 Oct 2015 07:28:00 GMT",
        "Sunday, 06-Nov-94 08:49:37 GMT",
        "Sun Nov  6 08:49:37 1994",
        "2015-10-21T07:28:00Z",
        "2015-10-21T07:28:00.5+01:00",
        "2015-10-21 07:28:00",
    ],
)
def test_real_dates_still_parse_and_are_usable(text: str) -> None:
    for parse in (from_rfc1123, fromisoformat):
        value = parse(text)
        if value is not None:
            value.astimezone(UTC)
            value.isoformat()
            str(value)
    assert (from_rfc1123(text) or fromisoformat(text)) is not None


def test_a_missing_field_is_not_filled_from_todays_date() -> None:
    assert fromisoformat("2024") is None
    assert from_rfc1123("Wed, 21 Oct 2015 07:28:00 GMT") == datetime(
        2015, 10, 21, 7, 28, tzinfo=UTC
    )


def test_an_empty_proppatch_is_refused() -> None:
    with pytest.raises(ValueError, match="at least one"):
        build_proppatch_body()
    with pytest.raises(ValueError, match="at least one"):
        build_proppatch_body(set_props={}, remove_props=[])
    with pytest.raises(TypeError, match="str or Element"):
        build_proppatch_body(set_props={"displayname": 5})  # type: ignore[dict-item]


def test_an_empty_proppatch_on_the_session_is_refused() -> None:
    with pytest.raises(ValueError, match="needs a body"):
        Session().proppatch("http://unused.invalid/a")


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


@pytest.mark.parametrize(
    "text",
    [
        "Sun, 06 Nov 1994 08:49:37 GMT",
        "Sun, 06 Nov 1994 08:49:37 -0000",
        "Sun Nov  6 08:49:37 1994",
        "Sun, 06 Nov 1994 08:49:37",
        "Sunday, 06-Nov-94 08:49:37 GMT",
    ],
)
def test_bug08_every_http_date_is_aware_utc(text: str) -> None:
    value = from_rfc1123(text)
    assert value is not None
    assert value.utcoffset() == timedelta(0)
    assert value == datetime(1994, 11, 6, 8, 49, 37, tzinfo=UTC)


def test_bug08_http_dates_in_any_form_sort_together() -> None:
    values = [
        from_rfc1123("Sun, 06 Nov 1994 08:49:37 GMT"),
        from_rfc1123("Sun Nov  6 08:49:38 1994"),
        from_rfc1123("Sun, 06 Nov 1994 08:49:39 -0000"),
    ]
    assert sorted(v for v in values if v) == [v for v in values if v]


@pytest.mark.parametrize("text", ["2024-01-01", "2024-01-01T00:00:00"])
def test_bug08_an_iso_date_without_a_zone_stays_as_it_is(text: str) -> None:
    value = fromisoformat(text)
    assert value is not None
    assert value.tzinfo is None
    other = from_rfc1123(text)  # the ISO fallback of from_rfc1123
    assert other is not None
    assert other.tzinfo is None


def test_bug08_an_iso_date_with_a_zone_keeps_it() -> None:
    value = fromisoformat("2024-01-01T00:00:00+02:00")
    assert value is not None
    assert value.utcoffset() == timedelta(hours=2)
