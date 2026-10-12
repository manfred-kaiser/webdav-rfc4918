"""RFC 4918 section 6.6: locks can disappear at any time. A 412 for a write that carried a token asks the server."""

import pytest

from tests.scripted_server import Reply, Seen, scripted_server
from webdav import Session

TOKEN = "opaquelocktoken:1234-abcd"
ACTIVE = (
    "<d:activelock><d:locktype><d:write/></d:locktype><d:lockscope><d:exclusive/></d:lockscope>"
    f"<d:depth>0</d:depth><d:timeout>Second-600</d:timeout><d:locktoken><d:href>{TOKEN}</d:href>"
    "</d:locktoken></d:activelock>"
)
LOCK_BODY = (
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
                {"Lock-Token": f"<{TOKEN}>", "Content-Type": "application/xml"},
                LOCK_BODY,
            )
        if seen.method == "PROPFIND":
            if self.propfind_status != 207:
                return self.propfind_status, {}, b""
            return 207, {"Content-Type": "application/xml"}, _propfind(alive=self.alive)
        if seen.method == "PUT":
            carries = TOKEN in seen.headers.get("if", "")
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
    assert TOKEN in puts[0].headers["if"]
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
    assert all(TOKEN in put.headers["if"] for put in _puts(recorder.requests))


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
