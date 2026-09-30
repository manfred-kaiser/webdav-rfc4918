"""Locks used through ``Session`` directly, and what ``send`` hands back."""

from typing import Any

import pytest
import requests
import requests.adapters

from tests.scripted_server import Seen, scripted_server
from webdav import FileSystem, Response, Session
from webdav.exceptions import (
    STATUS_CODE_EXCEPTIONS,
    MalformedResponseError,
    MultiStatusError,
    ResourceNotFoundError,
)

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


@pytest.mark.parametrize("status", [404, 409])
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


# ---------------------------------------------------------------------------
# LOCK (RFC 4918 sec. 9.10)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Session.lock() records what it was granted
# ---------------------------------------------------------------------------


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
