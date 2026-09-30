"""Round 3, protocol level: XML we build, dates we parse, locks we present - pinned."""

# ruff: noqa: SIM117, S105
import re
from datetime import UTC, datetime
from xml.etree.ElementTree import fromstring

import pytest

from tests.scripted_server import OK, Seen, always, scripted_server
from webdav import FileSystem, Session
from webdav.date_utils import from_rfc1123, fromisoformat
from webdav.exceptions import MalformedResponseError
from webdav.locks import LockRegistry
from webdav.properties import build_propfind_body, build_proppatch_body

# ---------------------------------------------------------------------------
# Property names and values cannot change the shape of the XML
# ---------------------------------------------------------------------------

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
        build_propfind_body("etag")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="not a single"):
        FileSystem("http://unused.invalid").get_props("/a", names="etag")  # type: ignore[arg-type]


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


# ---------------------------------------------------------------------------
# Dates from a server are either right or None - never a value that raises later
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Locks: a lock is never leaked, the token goes where it was taken, tags are valid URIs
# ---------------------------------------------------------------------------

LOCK_BODY = (
    '<?xml version="1.0"?><d:prop xmlns:d="DAV:"><d:lockdiscovery><d:activelock>'
    "<d:locktype><d:write/></d:locktype><d:lockscope><d:exclusive/></d:lockscope>"
    "<d:depth>infinity</d:depth><d:locktoken><d:href>{token}</d:href></d:locktoken>"
    "</d:activelock></d:lockdiscovery></d:prop>"
)


def _lock_server(token_text: str, header: str = "<opaquelocktoken:abc>"):  # type: ignore[no-untyped-def]
    def respond(seen: Seen) -> tuple[int, dict[str, str], bytes]:
        if seen.method == "LOCK":
            return (
                200,
                {"Lock-Token": header},
                LOCK_BODY.format(token=token_text).encode(),
            )
        return 204, {}, b""

    return respond


def test_a_pretty_printed_token_is_accepted() -> None:
    with scripted_server(_lock_server("\n   opaquelocktoken:abc\n  ")) as (url, _rec):
        with FileSystem(retry=False).locked(f"{url}/f") as lock:
            assert lock.token == "opaquelocktoken:abc"


def test_a_lock_the_client_cannot_use_is_released_anyway() -> None:
    with scripted_server(_lock_server("bad token with spaces")) as (url, rec):
        with pytest.raises(MalformedResponseError):
            with FileSystem(retry=False).locked(f"{url}/f"):
                pass
    assert [r.method for r in rec.requests] == ["LOCK", "UNLOCK"]
    assert rec.requests[1].headers["lock-token"] == "<opaquelocktoken:abc>"


def test_unlock_goes_to_the_url_that_was_locked() -> None:
    with scripted_server(_lock_server("opaquelocktoken:abc")) as (url_a, rec_a):
        with scripted_server(always(OK)) as (url_b, rec_b):
            session = Session(url_a, retry=False)
            fs = FileSystem.from_session(session)
            with fs.locked("f"):
                session.base_url = url_b
    assert [r.method for r in rec_a.requests] == ["LOCK", "UNLOCK"]
    assert rec_b.requests == []


def test_a_tag_url_is_always_a_valid_uri() -> None:
    registry = LockRegistry()
    for raw in (
        "https://dav.example/d e/",
        "https://dav.example/d>e/",
        "https://dav.example/日本/",
        "https://dav.example/dir/#frag",
    ):
        registry.add(raw, "tok", "0")
    header = registry.if_header("https://dav.example/d%20e/x")
    assert header is not None
    tags = re.findall(r"<([^>]*)>", header)
    for tag in tags:
        assert re.fullmatch(r"[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+", tag), tag
        assert "#" not in tag


def test_a_locked_url_with_a_space_is_presented_with_a_valid_tag() -> None:
    with scripted_server(always(OK)) as (url, rec):
        session = Session(retry=False)
        session.locks.add(f"{url}/d e/", "opaquelocktoken:abc", "0")
        session.put(f"{url}/d%20e/new.txt", data=b"x")
    header = rec.requests[0].headers["if"]
    assert " (" in header  # the list separator, not a space inside the tag
    assert header.startswith(f"<{url}/d%20e/> ")


def test_a_path_absolute_destination_still_presents_the_lock_of_its_parent() -> None:
    with scripted_server(always(OK)) as (url, rec):
        session = Session(retry=False)
        session.locks.add(f"{url}/dest/", "opaquelocktoken:abc", "0")
        session.move(f"{url}/src", destination="/dest/f")
    assert "opaquelocktoken:abc" in rec.requests[0].headers["if"]


def test_a_delete_or_move_of_an_ancestor_presents_the_locks_below_it() -> None:
    with scripted_server(always(OK)) as (url, rec):
        session = Session(retry=False)
        session.locks.add(f"{url}/d/f", "opaquelocktoken:abc", "0")
        session.delete(f"{url}/d")
        session.move(f"{url}/d", destination=f"{url}/e")
        session.copy(f"{url}/d", destination=f"{url}/e2")
    delete, move, copy = rec.requests
    assert f"<{url}/d/f> (<opaquelocktoken:abc>)" in delete.headers["if"]
    assert f"<{url}/d/f> (<opaquelocktoken:abc>)" in move.headers["if"]
    assert "if" not in copy.headers  # a copy does not touch the source
