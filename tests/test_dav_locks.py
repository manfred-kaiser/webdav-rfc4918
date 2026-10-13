"""Locks: the registry, the ``If`` header they end up in, lock discovery, and what a server may do to them."""

# ruff: noqa: SIM117, S105, PLC0415, S108, PTH208, RUF001

import logging
import re
from typing import Any
from xml.etree.ElementTree import fromstring

import pytest
import requests

from tests.builders import DAV, entry, ms, multistatus_doc
from tests.credentials import AUTH
from tests.scripted_server import OK, Reply, Seen, always, scripted_server
from webdav import FileSystem, Response, Session
from webdav.dav.conditional import Condition
from webdav.dav.locks import ActiveLock, LockRegistry
from webdav.dav.multistatus import MultiStatusResponse
from webdav.exceptions import (
    STATUS_CODE_EXCEPTIONS,
    MalformedResponseError,
    MultiStatusError,
    ResourceNotFoundError,
    WebDAVError,
)


def test_a_depth_zero_lock_on_a_collection_covers_adding_a_member(
    server_url: str,
) -> None:
    with Session(server_url, auth=AUTH, retry=False) as session:
        fs = FileSystem.from_session(session)
        fs.mkdir("dir")
        with fs.locked("dir", depth="0"):
            assert session.put("dir/new.txt", b"x").status_code == 201
            assert session.mkcol("dir/sub").status_code == 201
            assert session.delete("dir/new.txt").status_code == 204


def test_a_depth_zero_lock_does_not_cover_grandchildren(server_url: str) -> None:
    with Session(server_url, auth=AUTH, retry=False) as session:
        fs = FileSystem.from_session(session)
        fs.mkdir("dir")
        fs.mkdir("dir/sub")
        with fs.locked("dir", depth="0"):
            url = session.resolve_url("dir/sub/deep.txt")
            assert session.locks.token_for(url) is None


@pytest.mark.parametrize(
    "timeout", ["Second-²", "Second-" + "9" * 5000, "Second--1", "Bogus"]
)
def test_a_hostile_lock_timeout_header_does_not_break_locking(timeout: str) -> None:
    body = (
        b'<?xml version="1.0"?><d:prop xmlns:d="DAV:"><d:lockdiscovery><d:activelock>'
        b"<d:locktype><d:write/></d:locktype><d:lockscope><d:exclusive/></d:lockscope>"
        b"<d:depth>infinity</d:depth><d:locktoken><d:href>opaquelocktoken:ok</d:href></d:locktoken>"
        b"</d:activelock></d:lockdiscovery></d:prop>"
    )

    def respond(seen: Seen) -> tuple[int, dict[str, str], bytes]:
        if seen.method == "LOCK":
            return 200, {"Timeout": timeout, "Lock-Token": "<opaquelocktoken:ok>"}, body
        return 204, {}, b""

    with (
        scripted_server(respond) as (url, _rec),
        FileSystem(retry=False).locked(f"{url}/f") as lock,
    ):
        assert lock.token == "opaquelocktoken:ok"


@pytest.mark.parametrize(
    "token", ["x>) (<y> Not <z", "tok en", "täg", "aĀb", 'a"b', "a<b", "a\\b"]
)
def test_a_lock_token_that_could_change_the_if_header_is_refused(token: str) -> None:
    body = (
        '<?xml version="1.0"?><d:prop xmlns:d="DAV:"><d:lockdiscovery><d:activelock>'
        "<d:locktype><d:write/></d:locktype><d:lockscope><d:exclusive/></d:lockscope>"
        f"<d:depth>infinity</d:depth><d:locktoken><d:href>{token}</d:href></d:locktoken>"
        "</d:activelock></d:lockdiscovery></d:prop>"
    ).encode()
    with scripted_server(always((200, {}, body))) as (url, _rec):
        with pytest.raises(WebDAVError), FileSystem(retry=False).locked(f"{url}/f"):
            pass


TOKEN = "opaquelocktoken:abc"  # noqa: S105


LOCK_BODY = f"""<?xml version="1.0"?>
<d:prop xmlns:d="DAV:"><d:lockdiscovery><d:activelock>
<d:locktype><d:write/></d:locktype><d:lockscope><d:exclusive/></d:lockscope>
<d:depth>0</d:depth><d:timeout>Second-60</d:timeout>
<d:locktoken><d:href>{TOKEN}</d:href></d:locktoken>
</d:activelock></d:lockdiscovery></d:prop>""".encode()


def _server(unlock_status: int = 204) -> Any:
    def respond(seen: Seen) -> tuple[int, dict[str, str], bytes]:
        if seen.method == "LOCK":
            return 200, {"Lock-Token": f"<{TOKEN}>"}, LOCK_BODY
        if seen.method == "UNLOCK":
            return unlock_status, {}, b""
        return 204, {}, b""

    return respond


@pytest.mark.parametrize("status", [403, 423, 500])
def test_a_lock_the_server_refused_to_release_stays_recorded(status: int) -> None:
    with scripted_server(_server(unlock_status=status)) as (url, _rec):
        session = Session(retry=False)
        session.locks.add(f"{url}/f", TOKEN, "infinity")
        assert session.unlock(f"{url}/f", f"<{TOKEN}>").status_code == status
    assert session.locks.token_for(f"{url}/f") == TOKEN


@pytest.mark.parametrize("status", [404, 409])
def test_a_lock_the_server_says_is_gone_is_forgotten_for_that_url_only(
    status: int,
) -> None:
    # RFC 4918 sec. 9.11.1: 409 - not locked, or the URL is outside the lock's
    # scope. For the URL the lock was recorded for that means it is gone (timed
    # out); a dead token must not make every later write fail with 412.
    with scripted_server(_server(unlock_status=status)) as (url, _rec):
        session = Session(retry=False)
        session.locks.add(f"{url}/f", TOKEN, "infinity")
        session.locks.add(f"{url}/other", TOKEN, "0")
        session.unlock(f"{url}/f", TOKEN)
    assert session.locks.token_for(f"{url}/f") is None
    assert session.locks.token_for(f"{url}/other") == TOKEN  # maybe another lock: kept


def test_a_409_for_another_url_than_the_recorded_one_keeps_the_lock() -> None:
    with scripted_server(_server(unlock_status=409)) as (url, _rec):
        session = Session(retry=False)
        session.locks.add(f"{url}/dir/", TOKEN, "infinity")
        session.unlock(f"{url}/elsewhere", TOKEN)  # outside the lock's scope
    assert session.locks.token_for(f"{url}/dir/") == TOKEN


@pytest.mark.parametrize("token", ["x y", "a>b", "", "x" * 2000])
def test_a_token_the_caller_gives_that_is_unusable_is_a_value_error(token: str) -> None:
    session = Session("http://dav.example", retry=False)
    with pytest.raises(ValueError, match="not a usable lock token"):
        session.unlock("/f", token)
    with pytest.raises(ValueError, match="not a usable lock token"):
        session.lock("/f", refresh=token)
    with pytest.raises(ValueError, match="not a usable lock token"):
        FileSystem("http://dav.example").refresh_lock("/f", token)


def test_unlock_discards_the_token_wherever_it_was_recorded() -> None:
    with scripted_server(_server()) as (url, _rec):
        session = Session(retry=False)
        session.locks.add(f"{url}/a", TOKEN, "0")
        session.locks.add(f"{url}/b/", TOKEN, "infinity")
        session.locks.add(f"{url}/c", "opaquelocktoken:other", "0")
        session.unlock(f"{url}/a", TOKEN)
    assert session.locks.token_for(f"{url}/a") is None
    assert session.locks.token_for(f"{url}/b/x") is None
    assert session.locks.token_for(f"{url}/c") == "opaquelocktoken:other"


def test_the_status_code_table_cannot_be_changed_from_outside() -> None:
    with pytest.raises(TypeError):
        STATUS_CODE_EXCEPTIONS[404] = ValueError  # type: ignore[index]
    with pytest.raises(TypeError):
        STATUS_CODE_EXCEPTIONS[999] = ValueError  # type: ignore[index]
    assert STATUS_CODE_EXCEPTIONS[404] is ResourceNotFoundError


def test_send_hands_back_a_webdav_response_even_from_an_adapter_the_caller_mounted() -> (
    None
):
    with scripted_server(_server()) as (url, _rec):
        session = Session(retry=False)
        session.mount("http://", requests.adapters.HTTPAdapter())
        prepared = session.prepare_request(
            requests.Request("PUT", f"{url}/f", data=b"x")
        )
        response = session.send(prepared)
    assert type(response) is Response
    assert response.redirect_refusal is None


@pytest.mark.parametrize("status", [403, 423, 500])
def test_a_lock_the_server_would_not_release_is_reported_not_swallowed(
    caplog: pytest.LogCaptureFixture, status: int
) -> None:
    # RFC 4918 sec. 9.11.1: 403 - the principal may not remove the lock.
    with scripted_server(_server(unlock_status=status)) as (url, rec):
        with caplog.at_level("WARNING", logger="webdav"):
            with FileSystem(retry=False).locked(f"{url}/f"):
                pass
    assert [r.method for r in rec.requests] == ["LOCK", "UNLOCK"]
    assert (
        f"could not release the lock on {url}/f: the server answered {status}"
        in caplog.text
    )


@pytest.mark.parametrize("status", [404, 409, 400])  # 400: what Apache answers
def test_a_lock_that_was_already_gone_is_reported_as_that(
    caplog: pytest.LogCaptureFixture, status: int
) -> None:
    with scripted_server(_server(unlock_status=status)) as (url, _rec):
        with caplog.at_level("WARNING", logger="webdav"):
            with FileSystem(retry=False).locked(f"{url}/f"):
                pass
    assert "was already gone when it was released" in caplog.text
    assert f"answered {status}" in caplog.text
    assert "may have timed out" in caplog.text


def test_a_released_lock_is_not_reported(caplog: pytest.LogCaptureFixture) -> None:
    with scripted_server(_server()) as (url, rec):
        with caplog.at_level("WARNING", logger="webdav"):
            with FileSystem(retry=False).locked(f"{url}/f"):
                pass
    assert rec.requests[1].headers["lock-token"] == f"<{TOKEN}>"
    assert "if" not in rec.requests[1].headers  # sec. 9.11: no If header is needed
    assert caplog.text == ""


def test_unlock_is_never_retried() -> None:
    with scripted_server(_server(unlock_status=503)) as (url, rec):
        assert Session().unlock(f"{url}/f", TOKEN).status_code == 503
    assert [r.method for r in rec.requests] == ["UNLOCK"]


_MEMBER_LOCKED = b"""<?xml version="1.0"?><D:multistatus xmlns:D="DAV:">
<D:response><D:href>/dir/member</D:href><D:status>HTTP/1.1 423 Locked</D:status></D:response>
<D:response><D:href>/dir/</D:href><D:propstat><D:prop><D:lockdiscovery/></D:prop>
<D:status>HTTP/1.1 424 Failed Dependency</D:status></D:propstat></D:response>
</D:multistatus>"""


def test_a_lock_that_could_not_cover_every_member_is_an_error_naming_the_member() -> (
    None
):
    # Sec. 9.10.6/7.4: a 207 for a Depth: infinity LOCK is a failure, not a lock.
    with scripted_server(lambda _s: (207, {}, _MEMBER_LOCKED)) as (url, rec):
        fs = FileSystem(retry=False)
        with pytest.raises(MultiStatusError, match="member"):
            with fs.locked(f"{url}/dir/"):
                pytest.fail("no lock was granted")
        with pytest.raises(MultiStatusError, match="member"):
            fs.refresh_lock(f"{url}/dir/", TOKEN)
    assert [r.method for r in rec.requests] == ["LOCK", "LOCK"]  # nothing to unlock


def _answer_with_owner(owner_xml: str) -> bytes:
    return LOCK_BODY.replace(b"</d:activelock>", f"{owner_xml}</d:activelock>".encode())


@pytest.mark.parametrize(
    ("owner_xml", "expected"),
    [
        ("<d:owner>me</d:owner>", "me"),
        (
            "<d:owner><d:href>mailto:me@example.org</d:href></d:owner>",
            "mailto:me@example.org",
        ),
        (
            "<d:owner>  <d:href>http://example.org/~me</d:href>  </d:owner>",
            "http://example.org/~me",
        ),
        ("<d:owner/>", None),
        ("", None),
    ],
)
def test_the_owner_of_a_lock_is_read_whatever_it_holds(
    owner_xml: str, expected: "str | None"
) -> None:
    body = _answer_with_owner(owner_xml)
    with scripted_server(lambda _s: (200, {"Lock-Token": f"<{TOKEN}>"}, body)) as (
        url,
        _rec,
    ):
        assert Session(retry=False).lock(f"{url}/f").active_lock.owner == expected


def test_a_granted_lock_is_recorded_so_writes_carry_its_token_until_unlock() -> None:
    with scripted_server(_server()) as (url, rec):
        session = Session(retry=False)
        assert session.lock(f"{url}/f").status_code == 200
        assert session.locks.token_for(f"{url}/f") == TOKEN
        session.put(f"{url}/f", data=b"x")
        session.unlock(f"{url}/f", TOKEN)
        session.put(f"{url}/f", data=b"y")
    puts = [r for r in rec.requests if r.method == "PUT"]
    assert puts[0].headers["if"] == f"(<{TOKEN}>)"
    assert "if" not in puts[1].headers
    assert not session.locks


def test_recording_a_lock_is_not_repeated_when_the_caller_also_adds_it() -> None:
    with scripted_server(_server()) as (url, rec):
        session = Session(retry=False)
        session.lock(f"{url}/f")
        session.locks.add(f"{url}/f", TOKEN, "infinity")
        session.put(f"{url}/f", data=b"x")
        session.unlock(f"{url}/f", TOKEN)
    assert rec.requests[1].headers["if"] == f"(<{TOKEN}>)"
    assert not session.locks


def test_track_false_records_nothing_and_does_not_even_read_the_answer() -> None:
    with scripted_server(
        lambda _s: (200, {"Lock-Token": f"<{TOKEN}>"}, b"not xml")
    ) as (url, _rec):
        response = Session(retry=False).lock(f"{url}/f", track=False)
        session = Session(retry=False)
        session.lock(f"{url}/f", track=False)
    assert response.status_code == 200
    assert not session.locks


def test_the_lock_is_recorded_for_the_url_asked_for_not_the_one_the_server_names() -> (
    None
):
    body = LOCK_BODY.replace(
        b"</d:activelock>",
        b"<d:lockroot><d:href>/elsewhere/</d:href></d:lockroot></d:activelock>",
    )
    with scripted_server(lambda _s: (200, {"Lock-Token": f"<{TOKEN}>"}, body)) as (
        url,
        _rec,
    ):
        session = Session(retry=False)
        session.lock(f"{url}/f")
    assert session.locks.token_for(f"{url}/f") == TOKEN
    assert session.locks.token_for(f"{url}/elsewhere/x") is None


@pytest.mark.parametrize("status", [207, 409, 423, 500])
def test_an_answer_that_is_no_granted_lock_records_nothing(status: int) -> None:
    with scripted_server(lambda _s: (status, {}, _MEMBER_LOCKED)) as (url, _rec):
        session = Session(retry=False)
        assert session.lock(f"{url}/f").status_code == status
    assert not session.locks


def test_a_refused_lock_raises_and_records_nothing_when_the_session_raises() -> None:
    with scripted_server(lambda _s: (423, {}, b"")) as (url, _rec):
        session = Session(retry=False, raise_on_error=True)
        with pytest.raises(Exception, match="423"):
            session.lock(f"{url}/f")
    assert not session.locks


def test_a_granted_lock_that_cannot_be_read_is_released_again_and_raised() -> None:
    def respond(seen: Seen) -> "tuple[int, dict[str, str], bytes]":
        if seen.method == "LOCK":
            return 200, {"Lock-Token": f"<{TOKEN}>"}, b"<not-a-lock/>"
        return 204, {}, b""

    with scripted_server(respond) as (url, rec):
        session = Session(retry=False)
        with pytest.raises(MalformedResponseError):
            session.lock(f"{url}/f")
    assert [r.method for r in rec.requests] == ["LOCK", "UNLOCK"]
    assert rec.requests[1].headers["lock-token"] == f"<{TOKEN}>"
    assert not session.locks


def test_a_lock_with_no_usable_token_anywhere_raises_and_has_nothing_to_release() -> (
    None
):
    with scripted_server(
        lambda _s: (200, {"Lock-Token": "<bad token>"}, b"<not-a-lock/>")
    ) as (url, rec):
        with pytest.raises(MalformedResponseError):
            Session(retry=False).lock(f"{url}/f")
    assert [r.method for r in rec.requests] == ["LOCK"]


def test_a_refresh_leaves_the_recorded_lock_alone() -> None:
    def respond(seen: Seen) -> "tuple[int, dict[str, str], bytes]":
        headers = {} if "if" in seen.headers else {"Lock-Token": f"<{TOKEN}>"}
        return 200, headers, LOCK_BODY

    with scripted_server(respond) as (url, _rec):
        session = Session(retry=False)
        session.lock(f"{url}/f")
        session.lock(f"{url}/f", refresh=TOKEN)
    assert session.locks.token_for(f"{url}/f") == TOKEN
    assert len(session.locks.covering(f"{url}/f")) == 1


_DEEP = "http://h/dav"


@pytest.mark.parametrize("moves", [False, True])
def test_a_transfer_presents_the_locks_below_the_destination(moves: bool) -> None:
    registry = LockRegistry()
    registry.add(f"{_DEEP}/dest/sub/f.txt", "urn:uuid:aaa", "0")
    header = registry.if_header_for_transfer(
        f"{_DEEP}/src", f"{_DEEP}/dest", moves=moves
    )
    assert header is not None
    assert f"<{_DEEP}/dest/sub/f.txt> (<urn:uuid:aaa>)" in header


def test_a_copy_over_a_collection_sends_the_token_of_a_locked_member() -> None:
    with scripted_server(always(OK)) as (url, rec):
        session = Session(retry=False)
        session.locks.add(f"{url}/dest/inner.txt", "urn:uuid:bbb", "0")
        session.copy(f"{url}/src", f"{url}/dest", overwrite=True)
    assert "urn:uuid:bbb" in rec.requests[0].headers["if"]


def test_the_registry_forgets_everything_within_a_url() -> None:
    registry = LockRegistry()
    registry.add(f"{_DEEP}/a", "t1", "0")
    registry.add(f"{_DEEP}/a/b", "t2", "0")
    registry.add(f"{_DEEP}/ab", "t3", "0")
    registry.add(f"{_DEEP}", "t4", "infinity")
    registry.add("http://other/dav/a", "t5", "0")
    registry.discard_within(f"{_DEEP}/a")
    assert {h.token for h in registry.held()} == {"t3", "t4", "t5"}


@pytest.mark.parametrize("method", ["delete", "move"])
def test_a_deleted_or_moved_resource_takes_its_locks_along(method: str) -> None:
    with scripted_server(always(OK)) as (url, rec):
        session = Session(retry=False)
        session.locks.add(f"{url}/d/f", "opaquelocktoken:abc", "0")
        session.locks.add(f"{url}/other", "opaquelocktoken:def", "0")
        if method == "delete":
            session.delete(f"{url}/d")
        else:
            session.move(f"{url}/d", f"{url}/e")
        session.put(f"{url}/d/f", data=b"x")
    assert {h.token for h in session.locks.held()} == {"opaquelocktoken:def"}
    assert "if" not in rec.requests[-1].headers


def test_a_failed_delete_keeps_the_locks() -> None:
    with scripted_server(always((423, {}, b""))) as (url, _rec):
        session = Session(retry=False)
        session.locks.add(f"{url}/d", "opaquelocktoken:abc", "0")
        session.delete(f"{url}/d", raise_on_error=False)
    assert len(session.locks.held()) == 1


def _answers(body: bytes) -> "Reply":
    return 207, {"Content-Type": "application/xml"}, body


_LOCK_TOKEN = "opaquelocktoken:abc"


def _lock_discovery(body_of_lockdiscovery: "str | None") -> bytes:
    if body_of_lockdiscovery is None:
        return multistatus_doc(
            "<d:response><d:href>/f</d:href><d:propstat><d:prop><d:lockdiscovery/></d:prop>"
            "<d:status>HTTP/1.1 403 Forbidden</d:status></d:propstat></d:response>"
        )
    return multistatus_doc(
        "<d:response><d:href>/f</d:href><d:propstat><d:prop><d:lockdiscovery>"
        f"{body_of_lockdiscovery}</d:lockdiscovery></d:prop>"
        "<d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
    )


def _kept_after_a_412(discovery: bytes) -> bool:
    def respond(seen: Seen) -> Reply:
        if seen.method == "PROPFIND":
            return _answers(discovery)
        return 412, {}, b""

    with scripted_server(respond) as (url, _rec):
        session = Session(retry=False)
        session.locks.add(f"{url}/f", _LOCK_TOKEN, "0")
        session.put(f"{url}/f", data=b"x", raise_on_error=False)
        return bool(session.locks.held())


def test_a_lock_that_the_server_no_longer_lists_is_forgotten() -> None:
    assert not _kept_after_a_412(_lock_discovery(""))


_ACTIVELOCK = (
    "<d:activelock><d:locktype><d:write/></d:locktype><d:lockscope><d:exclusive/></d:lockscope>"
    "<d:depth>0</d:depth>{token}</d:activelock>"
)


def test_a_lock_that_the_server_still_lists_is_kept() -> None:
    token = f"<d:locktoken><d:href>{_LOCK_TOKEN}</d:href></d:locktoken>"
    assert _kept_after_a_412(_lock_discovery(_ACTIVELOCK.format(token=token)))


def test_a_lock_listed_without_its_token_is_kept() -> None:
    assert _kept_after_a_412(_lock_discovery(_ACTIVELOCK.format(token="")))


def test_an_answer_without_lockdiscovery_keeps_the_lock() -> None:
    assert _kept_after_a_412(_lock_discovery(None))


LOCK_ANSWER = (
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
                LOCK_ANSWER.format(token=token_text).encode(),
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


def test_a_lock_already_gone_on_release_is_logged_without_the_token(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``base_url`` is immutable (see test_session_settings.py), so a held lock's
    UNLOCK on cleanup always goes to the resource it was acquired on - the server
    answering that it is already gone (timed out, or removed) is the one other
    way ``_unlock_quietly`` warns instead of silently succeeding."""

    def respond(seen: Seen) -> tuple[int, dict[str, str], bytes]:
        if seen.method == "UNLOCK":
            return 404, {}, b""
        result: tuple[int, dict[str, str], bytes] = _lock_server("opaquelocktoken:abc")(
            seen
        )
        return result

    with scripted_server(respond) as (url, rec):
        with caplog.at_level("WARNING", logger="webdav"):
            with FileSystem(retry=False).locked(f"{url}/f"):
                pass
    assert [r.method for r in rec.requests] == ["LOCK", "UNLOCK"]
    assert "was already gone" in caplog.text
    assert "may have timed out" in caplog.text
    assert (
        "opaquelocktoken:abc" not in caplog.text
    )  # the token is a capability: never logged


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
        # The delete took the lock with it; hold it again for the next request.
        session.locks.add(f"{url}/d/f", "opaquelocktoken:abc", "0")
        session.move(f"{url}/d", destination=f"{url}/e")
        session.locks.add(f"{url}/d/f", "opaquelocktoken:abc", "0")
        session.copy(f"{url}/d", destination=f"{url}/e2")
    delete, move, copy = rec.requests
    assert f"<{url}/d/f> (<opaquelocktoken:abc>)" in delete.headers["if"]
    assert f"<{url}/d/f> (<opaquelocktoken:abc>)" in move.headers["if"]
    assert "if" not in copy.headers  # a copy does not touch the source


def test_reads_never_carry_a_lock_token() -> None:
    with scripted_server(always(OK)) as (url, rec):
        session = Session(retry=False)
        session.locks.add(f"{url}/f", "opaquelocktoken:t", "infinity")
        session.get(f"{url}/f")
        session.propfind(f"{url}/f", depth=0)
        session.head(f"{url}/f")
        session.put(f"{url}/f", data=b"x")
    assert [("if" in r.headers) for r in rec.requests] == [False, False, False, True]


@pytest.mark.parametrize("token", ["a>b", "a b", 'a"b', "tä"])
def test_a_token_that_would_break_out_of_its_brackets_is_refused(token: str) -> None:
    with pytest.raises(ValueError, match="Coded-URL"):
        Condition(token=token).render()


def test_lock_arguments_are_validated_before_anything_is_sent() -> None:
    session = Session()
    with pytest.raises(ValueError, match="scope"):
        session.lock("http://unused.invalid/a", scope="bogus")
    bad_timeouts: list[Any] = [True, -1, 2**40, "5", []]
    for bad in bad_timeouts:
        with pytest.raises(ValueError, match=r"timeout|empty"):
            session.lock("http://unused.invalid/a", lock_timeout=bad)  # type: ignore[arg-type]


def test_unlock_strips_angle_brackets_and_validates() -> None:
    with scripted_server(always(OK)) as (url, rec):
        session = Session(retry=False)
        session.unlock(f"{url}/a", "<opaquelocktoken:t>")
        with pytest.raises(ValueError, match="not a usable lock token"):
            session.unlock(f"{url}/a", "x>) (<y")
    assert rec.requests[0].headers["lock-token"] == "<opaquelocktoken:t>"
    assert len(rec.requests) == 1


def test_lock_registry_direct_children_and_grandchildren() -> None:
    registry = LockRegistry()
    registry.add("https://dav.example/dir", "tok", "0")
    assert registry.covering("https://dav.example/dir")
    assert registry.covering("https://dav.example/dir/child.txt")
    assert not registry.covering("https://dav.example/dir/sub/deep.txt")
    assert not registry.covering("https://dav.example/dirty")
    assert not registry.covering("https://other.example/dir/child.txt")
    header = registry.if_header("https://dav.example/dir/child.txt")
    assert header == "<https://dav.example/dir> (<tok>)"
    assert registry.if_header("https://dav.example/dir") == "(<tok>)"


def test_a_shared_lock_response_selects_the_lock_that_was_asked_about() -> None:
    body = (
        '<?xml version="1.0"?><d:prop xmlns:d="DAV:"><d:lockdiscovery>'
        + "".join(
            f"<d:activelock><d:locktype><d:write/></d:locktype>"
            f"<d:lockscope><d:shared/></d:lockscope><d:depth>0</d:depth>"
            f"<d:owner>{owner}</d:owner><d:locktoken><d:href>{tok}</d:href></d:locktoken>"
            f"</d:activelock>"
            for owner, tok in (
                ("someone-else", "opaquelocktoken:other"),
                ("me", "opaquelocktoken:mine"),
            )
        )
        + "</d:lockdiscovery></d:prop>"
    ).encode()

    def respond(seen: Seen) -> tuple[int, dict[str, str], bytes]:
        if seen.method == "LOCK":
            return 200, {"Lock-Token": "<opaquelocktoken:mine>"}, body
        return 204, {}, b""

    with scripted_server(respond) as (url, _rec):
        with FileSystem(retry=False).locked(f"{url}/f", scope="shared") as lock:
            assert lock.owner == "me"
            assert lock.token == "opaquelocktoken:mine"
        refreshed = FileSystem(retry=False).refresh_lock(
            f"{url}/f", "opaquelocktoken:mine"
        )
        assert refreshed.owner == "me"


def test_a_lock_refresh_token_is_validated_like_every_other_token() -> None:
    session = Session()
    with pytest.raises(ValueError, match="not a usable lock token"):
        session.lock("http://unused.invalid/a", refresh="x>) (<y")


def test_copy_and_move_into_a_depth_zero_locked_collection(server_url: str) -> None:
    with Session(server_url, auth=AUTH, retry=False) as session:
        fs = FileSystem.from_session(session)
        fs.mkdir("dir")
        session.put("out.txt", b"x")
        with fs.locked("dir", depth="0"):
            assert session.copy("out.txt", destination="dir/c.txt").status_code == 201
            assert session.move("out.txt", destination="dir/m.txt").status_code == 201
            assert session.move("dir/c.txt", destination="c.txt").status_code == 201


def test_a_transfer_presents_every_lock_it_touches_as_one_tagged_list() -> None:
    from webdav.dav.locks import LockRegistry

    registry = LockRegistry()
    registry.add("https://dav.example/src", "tokI", "infinity")
    registry.add("https://dav.example/dst", "tokD", "0")
    header = registry.if_header(
        "https://dav.example/src/a.txt", "https://dav.example/dst/b.txt"
    )
    assert header is not None
    assert header.startswith("<https://dav.example/")
    assert "(<tokI>)" in header
    assert "(<tokD>)" in header
    assert not header.startswith("(")  # tagged lists and untagged ones cannot be mixed


def test_a_transfer_of_a_locked_source_alone_is_still_tagged() -> None:
    from webdav.dav.locks import LockRegistry

    registry = LockRegistry()
    registry.add("https://dav.example/a.txt", "tok", "0")
    assert registry.if_header(
        "https://dav.example/a.txt", "https://dav.example/b.txt"
    ) == ("<https://dav.example/a.txt> (<tok>)")


def test_a_failed_unlock_never_replaces_the_callers_own_exception() -> None:
    body = (
        b'<?xml version="1.0"?><d:prop xmlns:d="DAV:"><d:lockdiscovery><d:activelock>'
        b"<d:locktype><d:write/></d:locktype><d:lockscope><d:exclusive/></d:lockscope>"
        b"<d:depth>infinity</d:depth><d:locktoken><d:href>opaquelocktoken:t</d:href></d:locktoken>"
        b"</d:activelock></d:lockdiscovery></d:prop>"
    )
    unlocks = {"n": 0}

    def respond(seen: Seen) -> tuple[int, dict[str, str], bytes]:
        if seen.method == "LOCK":
            return 200, {"Lock-Token": "<opaquelocktoken:t>"}, body
        unlocks["n"] += 1
        raise ConnectionResetError

    class BoomError(Exception):
        pass

    with scripted_server(respond) as (url, _rec):
        with pytest.raises(BoomError):
            with FileSystem(retry=False).locked(f"{url}/f"):
                raise BoomError
    assert unlocks["n"] >= 1


DISCOVERED_TOKEN = "opaquelocktoken:1234-abcd"


ACTIVE = (
    "<d:activelock><d:locktype><d:write/></d:locktype><d:lockscope><d:exclusive/></d:lockscope>"
    f"<d:depth>0</d:depth><d:timeout>Second-600</d:timeout><d:locktoken><d:href>{DISCOVERED_TOKEN}</d:href>"
    "</d:locktoken></d:activelock>"
)


DISCOVERY_BODY = (
    f'<?xml version="1.0"?><d:prop xmlns:d="DAV:"><d:lockdiscovery>{ACTIVE}</d:lockdiscovery></d:prop>'
).encode()


def _propfind(*, alive: bool) -> bytes:
    discovery = ACTIVE if alive else ""
    return (
        '<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response><d:href>/f.txt</d:href>'
        f"<d:propstat><d:prop><d:lockdiscovery>{discovery}</d:lockdiscovery></d:prop>"
        "<d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"
    ).encode()


class Server:
    """A server whose lock may be gone, whose PUT answers 412 while a token is sent for it."""

    def __init__(
        self,
        *,
        alive: bool,
        propfind_status: int = 207,
        put_412_with_live_lock: bool = False,
    ) -> None:
        self.alive = alive
        self.propfind_status = propfind_status
        self.put_412_with_live_lock = put_412_with_live_lock

    def __call__(self, seen: Seen) -> Reply:
        if seen.method == "LOCK":
            return (
                200,
                {
                    "Lock-Token": f"<{DISCOVERED_TOKEN}>",
                    "Content-Type": "application/xml",
                },
                DISCOVERY_BODY,
            )
        if seen.method == "PROPFIND":
            if self.propfind_status != 207:
                return self.propfind_status, {}, b""
            return 207, {"Content-Type": "application/xml"}, _propfind(alive=self.alive)
        if seen.method == "PUT":
            carries = DISCOVERED_TOKEN in seen.headers.get("if", "")
            if carries and (not self.alive or self.put_412_with_live_lock):
                return 412, {}, b""
            return 204, {}, b""
        return 404, {}, b""


def _puts(recorder: "list[Seen]") -> "list[Seen]":
    return [seen for seen in recorder if seen.method == "PUT"]


def test_a_token_the_server_no_longer_has_is_forgotten_after_the_412() -> None:
    server = Server(alive=False)
    with scripted_server(server) as (url, recorder):
        with Session(url, retry=False) as session:
            session.lock("/f.txt")
            assert session.locks
            first = session.put("/f.txt", data=b"one")
            assert (
                first.status_code == 412
            )  # not repeated: without the lock it may be someone else's turn
            assert not session.locks
            second = session.put("/f.txt", data=b"two")
    assert second.status_code == 204
    puts = _puts(recorder.requests)
    assert DISCOVERED_TOKEN in puts[0].headers["if"]
    assert "if" not in puts[1].headers
    assert len([s for s in recorder.requests if s.method == "PUT"]) == 2


def test_a_token_the_server_still_has_is_kept_after_a_412_for_another_reason() -> None:
    server = Server(alive=True, put_412_with_live_lock=True)
    with scripted_server(server) as (url, recorder):
        with Session(url, retry=False) as session:
            session.lock("/f.txt")
            assert session.put("/f.txt", data=b"x").status_code == 412
            assert session.locks
            session.put("/f.txt", data=b"y")
    assert all(
        DISCOVERED_TOKEN in put.headers["if"] for put in _puts(recorder.requests)
    )


@pytest.mark.parametrize("status", [401, 403, 500, 405])
def test_a_token_is_kept_when_the_server_cannot_say(status: int) -> None:
    server = Server(alive=False, propfind_status=status)
    with scripted_server(server) as (url, _):
        with Session(url, retry=False) as session:
            session.lock("/f.txt")
            assert session.put("/f.txt", data=b"x").status_code == 412
            assert session.locks


def test_a_412_for_a_write_without_a_token_asks_nothing() -> None:
    def respond(seen: Seen) -> Reply:
        return (412, {}, b"") if seen.method == "PUT" else (404, {}, b"")

    with scripted_server(respond) as (url, recorder):
        with Session(url, retry=False) as session:
            assert (
                session.put(
                    "/g.txt", data=b"x", headers={"If-Match": '"e"'}
                ).status_code
                == 412
            )
    assert [seen.method for seen in recorder.requests] == ["PUT"]


def test_only_the_tokens_the_request_carried_are_asked_about() -> None:
    server = Server(alive=False)
    with scripted_server(server) as (url, recorder):
        with Session(url, retry=False) as session:
            session.lock("/f.txt")
            session.put("/other.txt", data=b"x")  # no token for this path: 204
            assert session.locks
    assert not [seen for seen in recorder.requests if seen.method == "PROPFIND"]


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


@pytest.mark.parametrize(
    ("text", "timeout", "raw"),
    [
        ("Infinite", None, None),
        ("Second-600", 600, None),
        ("Second-1, Infinite", 1, None),
        ("Second-99999999999999999999", None, "Second-99999999999999999999"),
        ("garbage", None, "garbage"),
        ("Second--5", None, "Second--5"),
        ("Second-1000000000000000000", None, "Second-1000000000000000000"),
    ],
)
def test_proto02_timeout_raw_tells_infinite_from_unreadable(
    text: str, timeout: "int | None", raw: "str | None"
) -> None:
    body = f"""<d:activelock {DAV}><d:locktoken><d:href>urn:a</d:href></d:locktoken>
    <d:timeout>{text}</d:timeout></d:activelock>"""

    lock = ActiveLock.from_element(fromstring(body))
    assert lock.timeout == timeout
    assert lock.timeout_raw == raw


def test_proto02_an_unreadable_timeout_is_never_an_error() -> None:
    body = f"""<d:activelock {DAV}><d:locktoken><d:href>urn:a</d:href></d:locktoken>
    <d:timeout>garbage</d:timeout></d:activelock>"""

    assert ActiveLock.from_element(fromstring(body)).token == "urn:a"


def test_proto06_two_locks_on_one_resource_both_go_into_the_if_header() -> None:
    registry = LockRegistry()
    registry.add("http://h/f", "urn:a", "0")
    registry.add("http://h/f", "urn:b", "0")
    assert registry.if_header("http://h/f") == "(<urn:a>) (<urn:b>)"


def test_proto06_one_lock_keeps_its_header() -> None:
    registry = LockRegistry()
    registry.add("http://h/f", "urn:a", "0")
    assert registry.if_header("http://h/f") == "(<urn:a>)"
