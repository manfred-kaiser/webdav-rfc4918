"""Multistatus answers: statuses, hrefs and the shapes a server may answer in, also hostile ones."""

# ruff: noqa: SIM117, PLC0415, PTH208, S105, RUF001

import unicodedata
from typing import Any

import pytest
import requests
from requests.structures import CaseInsensitiveDict

from tests.scripted_server import Reply, Seen, always, scripted_server
from webdav import FileSystem, Response, exceptions
from webdav.dav.multistatus import MultiStatusResponse, parse_multistatus_response
from webdav.exceptions import (
    MalformedResponseError,
    MultiStatusError,
    ResourceLockedError,
    WebDAVError,
)


def _multistatus(*hrefs: str, collection: bool = True) -> bytes:
    kind = "<d:collection/>" if collection else ""
    responses = "".join(
        f"<d:response><d:href>{h}</d:href><d:propstat><d:prop><d:resourcetype>{kind}"
        "</d:resourcetype></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
        for h in hrefs
    )
    return f'<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">{responses}</d:multistatus>'.encode()


def test_ls_refuses_entries_outside_the_listed_directory() -> None:
    body = _multistatus("/a/b/", "/a/", "/", "/secret/", "/a/b/ok.txt")
    with scripted_server(always((207, {}, body))) as (url, _rec):
        with pytest.raises(MalformedResponseError, match="outside"):
            FileSystem(retry=False).ls(f"{url}/a/b")


def test_an_encoded_slash_in_an_href_is_refused_not_turned_into_a_path_separator() -> (
    None
):
    body = _multistatus("/a/", "/a/x%2fy/")
    with (
        scripted_server(always((207, {}, body))) as (url, _rec),
        pytest.raises(MalformedResponseError, match="encoded path separator"),
    ):
        FileSystem(retry=False).ls(f"{url}/a")


def test_a_control_character_in_an_href_is_refused() -> None:
    """``\\x7f`` (and most other control characters) survive well-formed XML
    untouched - unlike a redirect Location, nothing upstream already refuses
    them for an href, so _check_href must."""
    body = _multistatus("/a/", "/a/x\x7fy.txt")
    with (
        scripted_server(always((207, {}, body))) as (url, _rec),
        pytest.raises(MalformedResponseError, match="control character"),
    ):
        FileSystem(retry=False).ls(f"{url}/a")


def test_a_backslash_in_an_href_is_still_an_ordinary_character() -> None:
    """Unlike the control-character check above, a backslash is deliberately
    still accepted here - an ordinary POSIX file-name character, not part of
    an authority a parser could misread (see test_get_names.py's
    test_a_backslash_in_a_name_is_an_ordinary_character_on_posix)."""
    body = _multistatus("/a/", "/a/x\\y.txt")
    with scripted_server(always((207, {}, body))) as (url, _rec):
        assert FileSystem(retry=False).ls(f"{url}/a") == ["a/x\\y.txt"]


def test_a_multistatus_with_absurdly_many_responses_is_refused() -> None:
    body = _multistatus(*[f"/d/{i}" for i in range(300)])
    from webdav.dav import multistatus

    old = multistatus.MAX_RESPONSES
    multistatus.MAX_RESPONSES = 100
    try:
        with scripted_server(always((207, {}, body))) as (url, _rec):
            with pytest.raises(MalformedResponseError, match="too many"):
                FileSystem(retry=False).ls(f"{url}/d")
    finally:
        multistatus.MAX_RESPONSES = old


_NS = 'xmlns:d="DAV:"'


def _multistatus_of(*responses: str) -> bytes:
    return (
        f'<?xml version="1.0"?><d:multistatus {_NS}>{"".join(responses)}</d:multistatus>'
    ).encode()


@pytest.mark.parametrize("prop", ["<d:prop/>", "", "<d:prop>text</d:prop>"])
def test_a_failed_propstat_without_a_property_still_fails(prop: str) -> None:
    ms = MultiStatusResponse(
        _multistatus_of(
            "<d:response><d:href>/a</d:href><d:propstat>"
            f"{prop}<d:status>HTTP/1.1 403 Forbidden</d:status>"
            "</d:propstat></d:response>"
        )
    )
    with pytest.raises(exceptions.MultiStatusError) as excinfo:
        ms.raise_for_status()
    assert excinfo.value.statuses == {"/a": "Forbidden"}


def _answers(body: bytes) -> "Reply":
    return 207, {"Content-Type": "application/xml"}, body


def test_set_props_reports_a_failure_the_server_gives_without_a_property() -> None:
    body = _multistatus_of(
        "<d:response><d:href>/f</d:href><d:propstat><d:prop/>"
        "<d:status>HTTP/1.1 409 Conflict</d:status></d:propstat></d:response>"
    )
    with scripted_server(always(_answers(body))) as (url, _rec):
        fs = FileSystem(url, retry=False)
        with pytest.raises(exceptions.MultiStatusError):
            fs.set_props("f", set_props={"displayname": "x"})


def _status_only(href: str, status: str) -> str:
    return f"<d:response><d:href>{href}</d:href><d:status>HTTP/1.1 {status}</d:status></d:response>"


def test_info_and_exists_follow_a_404_given_in_the_body() -> None:
    body = _multistatus_of(_status_only("/gone", "404 Not Found"))
    with scripted_server(always(_answers(body))) as (url, _rec):
        fs = FileSystem(url, retry=False)
        assert fs.exists("gone") is False
        assert fs.isdir("gone") is False
        assert fs.isfile("gone") is False
        with pytest.raises(exceptions.ResourceNotFoundError):
            fs.info("gone")
        with pytest.raises(exceptions.ResourceNotFoundError):
            fs.get_props("gone")


def test_a_403_given_in_the_body_is_not_an_answer_to_exists() -> None:
    body = _multistatus_of(_status_only("/secret", "403 Forbidden"))
    with scripted_server(always(_answers(body))) as (url, _rec):
        fs = FileSystem(url, retry=False)
        with pytest.raises(exceptions.ForbiddenError):
            fs.exists("secret")
        with pytest.raises(exceptions.ForbiddenError):
            fs.info("secret")


def test_a_redirect_given_in_the_body_is_not_a_resource() -> None:
    body = _multistatus_of(_status_only("/moved", "301 Moved Permanently"))
    with scripted_server(always(_answers(body))) as (url, _rec):
        fs = FileSystem(url, retry=False)
        with pytest.raises(exceptions.RedirectNotFollowedError):
            fs.info("moved")


def _props(href: str, *, directory: bool = False, size: int = 3) -> str:
    kind = "<d:collection/>" if directory else ""
    return (
        f"<d:response><d:href>{href}</d:href><d:propstat><d:prop>"
        f"<d:resourcetype>{kind}</d:resourcetype><d:getcontentlength>{size}</d:getcontentlength>"
        "</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
    )


def test_ls_keeps_a_member_the_account_may_not_read_and_drops_one_that_is_gone() -> (
    None
):
    body = _multistatus_of(
        _props("/d/", directory=True),
        _props("/d/ok.txt", size=7),
        _status_only("/d/secret", "403 Forbidden"),
        _status_only("/d/gone", "404 Not Found"),
    )
    with scripted_server(always(_answers(body))) as (url, _rec):
        listing = FileSystem(url, retry=False).ls("d")
    assert sorted(listing) == ["d/ok.txt", "d/secret"]
    by_name = {r.name: r for r in listing}
    assert by_name["d/ok.txt"].status is None
    assert by_name["d/ok.txt"].size == 7
    secret = by_name["d/secret"]
    assert secret.status == 403
    assert secret.size is None
    assert secret.is_dir is False


def test_ls_of_a_collection_the_body_calls_missing_raises() -> None:
    body = _multistatus_of(_status_only("/d/", "404 Not Found"))
    with scripted_server(always(_answers(body))) as (url, _rec):
        with pytest.raises(exceptions.ResourceNotFoundError):
            FileSystem(url, retry=False).ls("d")


def test_a_resource_has_a_status_field_in_its_dict() -> None:
    body = _multistatus_of(_props("/f.txt"))
    with scripted_server(always(_answers(body))) as (url, _rec):
        info = FileSystem(url, retry=False).info("f.txt")
    assert info.status is None
    assert info.as_dict()["status"] is None


_MS = '<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">{}</d:multistatus>'


def _entry(href: str, status: str) -> str:
    return (
        f"<d:response><d:href>{href}</d:href><d:status>{status}</d:status></d:response>"
    )


def _delete_reply(*entries: str) -> tuple[int, dict[str, str], bytes]:
    return (
        207,
        {"Content-Type": "application/xml"},
        _MS.format("".join(entries)).encode(),
    )


def test_a_failure_is_not_hidden_by_a_later_entry_for_the_same_href() -> None:
    reply = _delete_reply(
        _entry("/d/x", "HTTP/1.1 423 Locked"), _entry("/d/x", "HTTP/1.1 204 No Content")
    )
    with scripted_server(always(reply)) as (url, _rec):
        with pytest.raises(exceptions.MultiStatusError):
            FileSystem(retry=False).remove(f"{url}/d")


@pytest.mark.parametrize(
    "status", ["HTTP/1.1 302 Found", "HTTP/1.1 999 Odd", "HTTP/1.1 100 Continue"]
)
def test_any_member_status_outside_2xx_is_a_failure(status: str) -> None:
    with scripted_server(always(_delete_reply(_entry("/d/x", status)))) as (url, _rec):
        with pytest.raises(exceptions.MultiStatusError):
            FileSystem(retry=False).remove(f"{url}/d")


def test_an_unparseable_member_status_is_an_error_not_a_success() -> None:
    with scripted_server(always(_delete_reply(_entry("/d/x", "garbage")))) as (
        url,
        _rec,
    ):
        with pytest.raises(MalformedResponseError):
            FileSystem(retry=False).remove(f"{url}/d")


def test_a_2xx_member_status_is_fine() -> None:
    reply = _delete_reply(
        _entry("/d/x", "HTTP/1.1 200 OK"), _entry("/d/y", "HTTP/1.1 204 No Content")
    )
    with scripted_server(always(reply)) as (url, _rec):
        FileSystem(retry=False).remove(f"{url}/d")


def _multistatus_ls(*hrefs: str) -> bytes:
    rows = "".join(
        f"<d:response><d:href>{h}</d:href><d:propstat><d:prop><d:resourcetype>"
        f"{'<d:collection/>' if h.endswith('/') else ''}</d:resourcetype></d:prop>"
        f"<d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
        for h in hrefs
    )
    return _MS.format(rows).encode()


def test_nfc_and_nfd_twins_are_both_listed() -> None:

    nfc = unicodedata.normalize("NFC", "é")
    nfd = unicodedata.normalize("NFD", "é")
    body = _multistatus_ls("/d/", f"/d/{nfc}", f"/d/{nfd}", "/d/x")
    with scripted_server(always((207, {}, body))) as (url, _rec):
        names = FileSystem(retry=False).ls(f"{url}/d")
    assert sorted(names) == sorted([f"d/{nfc}", f"d/{nfd}", "d/x"])


def test_an_absolute_href_for_the_same_server_is_fine() -> None:
    def respond(seen: Seen) -> tuple[int, dict[str, str], bytes]:
        host = seen.headers["host"]
        return 207, {}, _multistatus_ls(f"http://{host}/d/", f"http://{host}/d/x.txt")

    with scripted_server(respond) as (url, _rec):
        assert FileSystem(retry=False).ls(f"{url}/d") == ["d/x.txt"]


def test_a_plain_web_server_answering_a_propfind_is_a_webdav_error_not_a_valueerror() -> (
    None
):
    with scripted_server(always((200, {}, b"<html>hello</html>"))) as (url, _rec):
        fs = FileSystem(retry=False)
        for call in (
            lambda: fs.ls(f"{url}/d"),
            lambda: fs.info(f"{url}/d"),
            lambda: fs.exists(f"{url}/d"),
            lambda: fs.isdir(f"{url}/d"),
            lambda: fs.content_length(f"{url}/d"),
        ):
            with pytest.raises(MalformedResponseError, match="207"):
                call()


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


def test_dos09_a_big_ordinary_listing_is_not_touched() -> None:
    entries = [
        entry(f"/d/file{n}.txt", extra="<d:getcontentlength>1</d:getcontentlength>")
        for n in range(20_000)
    ]
    assert len(MultiStatusResponse(ms(*entries)).entries) == 20_000


BAD_SECOND_HREF = ms(
    "<d:response><d:href>/d/</d:href><d:href>http://[::1</d:href>"
    "<d:status>HTTP/1.1 423 Locked</d:status></d:response>"
)


def test_exc01_a_second_unparseable_href_is_a_malformed_response() -> None:
    with pytest.raises(MalformedResponseError, match="unusable"):
        MultiStatusResponse(BAD_SECOND_HREF)


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


def test_bug09_an_href_padded_with_a_line_break_is_refused() -> None:
    with pytest.raises(MalformedResponseError, match="control character"):
        MultiStatusResponse(ms(entry("\n    /d/a.txt\n  ")))


def test_bug09_an_href_of_nothing_but_whitespace_is_missing() -> None:
    with pytest.raises(MalformedResponseError):
        MultiStatusResponse(ms(entry(" \n ")))


def test_bug09_a_control_character_inside_an_href_is_still_refused() -> None:
    with pytest.raises(MalformedResponseError, match="control character"):
        MultiStatusResponse(ms(entry("/d/a\tb")))


def test_bug09_display_name_keeps_its_edge_spaces() -> None:
    body = ms(entry("/a", extra="<d:displayname> a </d:displayname>"))
    assert MultiStatusResponse(body).entries[0].properties.display_name == " a "


def _info_of(*entries: str) -> Any:
    with scripted_server(lambda _s: (207, {}, ms(*entries))) as (url, _rec):
        return FileSystem(url, retry=False).info("/d")


def test_fs09_a_plain_info_is_untouched() -> None:
    assert _info_of(entry("/d/", collection=True)).is_dir


def test_fs09_the_same_member_listed_twice_is_listed_twice() -> None:
    body = ms(entry("/d/", collection=True), entry("/d/a"), entry("/d/a"))
    with scripted_server(lambda _s: (207, {}, body)) as (url, _rec):
        assert len(FileSystem(url, retry=False).ls("/d")) == 2
