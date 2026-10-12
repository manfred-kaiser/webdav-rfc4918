"""Basic authentication sends non-ASCII credentials as UTF-8 (RFC 7617), the way curl and browsers do."""

import base64

import pytest
from requests.auth import HTTPBasicAuth, HTTPProxyAuth, _basic_auth_str

from tests.scripted_server import Reply, Seen, scripted_server
from webdav import BasicAuth, ClientError, FileSystem, Session
from webdav.fsspec import WebdavFileSystem
from webdav.transport.basic_auth import as_basic


def _decoded(header: str) -> bytes:
    assert header.startswith("Basic ")
    return base64.b64decode(header.removeprefix("Basic "))


def test_ascii_credentials_are_what_requests_sends() -> None:
    assert BasicAuth("user", "pass").header() == _basic_auth_str("user", "pass")


@pytest.mark.parametrize(
    ("user", "password"),
    [("üser", "päss"), ("名前", "пароль"), ("u", "€uro"), ("ünï", "")],
)
def test_utf8_is_the_default(user: str, password: str) -> None:
    assert _decoded(BasicAuth(user, password).header()) == f"{user}:{password}".encode()


def test_latin1_can_be_asked_for() -> None:
    header = BasicAuth("üser", "päss", encoding="latin-1").header()
    assert _decoded(header) == "üser:päss".encode("latin-1")
    assert header == _basic_auth_str("üser", "päss")


def test_latin1_cannot_carry_what_it_has_no_character_for() -> None:
    with pytest.raises(ClientError, match="cannot be encoded as latin-1"):
        BasicAuth("名前", "pw", encoding="latin-1")
    with pytest.raises(ClientError, match="password cannot be encoded"):
        BasicAuth("user", "пароль", encoding="latin-1")


def test_bytes_are_sent_as_they_are() -> None:
    header = BasicAuth(b"u\xfcser", b"p\xe4ss").header()
    assert _decoded(header) == b"u\xfcser:p\xe4ss"


def test_a_user_name_with_a_colon_is_refused() -> None:
    with pytest.raises(ClientError, match="colon"):
        BasicAuth("a:b", "pw")
    with pytest.raises(ClientError, match="colon"):
        Session(auth=("a:b", "pw"))
    with pytest.raises(ClientError, match="colon"):
        BasicAuth(b"a:b", "pw")


def test_a_password_may_contain_a_colon() -> None:
    assert _decoded(BasicAuth("user", "a:b:c").header()) == b"user:a:b:c"


def test_the_representation_hides_the_password() -> None:
    assert "secret" not in repr(BasicAuth("user", "secret"))


def test_as_basic_converts_a_pair_and_a_plain_http_basic_auth() -> None:
    assert isinstance(as_basic(("u", "p")), BasicAuth)
    converted = as_basic(HTTPBasicAuth("u", "p"))
    assert isinstance(converted, BasicAuth)
    assert (converted.username, converted.password) == ("u", "p")


def test_as_basic_leaves_everything_else_alone() -> None:
    proxy = HTTPProxyAuth("u", "p")
    token = lambda request: request  # noqa: E731
    mine = BasicAuth("u", "p", encoding="latin-1")
    for other in (proxy, token, mine, ("a", "b", "c"), None, False, ("a", 1)):
        assert as_basic(other) is other


def _record(authorizations: "list[str | None]"):  # noqa: ANN202
    def respond(seen: Seen) -> Reply:
        authorizations.append(seen.headers.get("authorization"))
        return 404, {}, b""

    return respond


def test_a_session_sends_its_pair_as_utf8() -> None:
    seen: list["str | None"] = []
    with scripted_server(_record(seen)) as (url, _):
        with Session(auth=("üser", "päss"), retry=False) as session:
            assert session.get(f"{url}/x").status_code == 404
            assert session.auth == (
                "üser",
                "päss",
            )  # what was given is what is read back
    assert _decoded(seen[0] or "") == "üser:päss".encode()


def test_a_call_sends_its_pair_as_utf8_and_a_cjk_name_does_not_raise() -> None:
    seen: list["str | None"] = []
    with scripted_server(_record(seen)) as (url, _), Session(retry=False) as session:
        session.get(f"{url}/x", auth=("名前", "пароль"))
    assert _decoded(seen[0] or "") == "名前:пароль".encode()


def test_a_call_with_auth_false_still_beats_the_sessions() -> None:
    seen: list["str | None"] = []
    with scripted_server(_record(seen)) as (url, _):
        with Session(auth=("üser", "päss"), retry=False) as session:
            session.get(f"{url}/x", auth=False)  # type: ignore[arg-type]
    assert seen == [None]


def test_latin1_is_used_when_basic_auth_says_so() -> None:
    seen: list["str | None"] = []
    with scripted_server(_record(seen)) as (url, _):
        with Session(auth=BasicAuth("üser", "päss", "latin-1"), retry=False) as session:
            session.get(f"{url}/x")
    assert _decoded(seen[0] or "") == "üser:päss".encode("latin-1")


def test_the_file_system_and_fsspec_send_utf8() -> None:
    seen: list["str | None"] = []
    with scripted_server(_record(seen)) as (url, _):
        with FileSystem(url, auth=("üser", "päss"), retry=False) as fs:
            assert not fs.exists("/x")
        WebdavFileSystem(url, auth=("名前", "пароль")).exists("/y")
    assert _decoded(seen[0] or "") == "üser:päss".encode()
    assert _decoded(seen[-1] or "") == "名前:пароль".encode()
