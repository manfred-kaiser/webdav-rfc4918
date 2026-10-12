"""Digest authentication is refused, with a message that says why; Basic is not."""

import pytest
import requests
from requests.auth import HTTPBasicAuth, HTTPDigestAuth

from tests.scripted_server import always, scripted_server
from webdav import ClientError, FileSystem, Session
from webdav.fsspec import WebdavFileSystem

DIGEST = HTTPDigestAuth("user", "secret")


def test_the_constructor_refuses_digest() -> None:
    with pytest.raises(ClientError, match="Digest authentication is not supported"):
        Session(auth=DIGEST)


def test_the_attribute_refuses_digest() -> None:
    session = Session()
    with pytest.raises(ClientError, match="not supported"):
        session.auth = DIGEST
    assert session.auth is None


def test_a_call_refuses_digest_and_sends_nothing() -> None:
    with scripted_server(always((200, {}, b""))) as (url, recorder):
        with Session(retry=False) as session:
            with pytest.raises(ClientError, match="not supported"):
                session.get(f"{url}/x", auth=DIGEST)
    assert recorder.requests == []


def test_prepare_request_refuses_digest() -> None:
    with pytest.raises(ClientError, match="not supported"):
        Session().prepare_request(
            requests.Request("GET", "http://127.0.0.1/", auth=DIGEST)
        )


def test_the_file_system_and_fsspec_refuse_digest() -> None:
    with pytest.raises(ClientError, match="not supported"):
        FileSystem("https://dav.example", auth=DIGEST)
    with pytest.raises(ClientError, match="not supported"):
        WebdavFileSystem(host="dav.example", auth=DIGEST)


def test_a_subclass_of_digest_is_refused_too() -> None:
    class Mine(HTTPDigestAuth):
        """A digest handler of the caller's own."""

    with pytest.raises(ClientError, match="not supported"):
        Session(auth=Mine("u", "p"))


@pytest.mark.parametrize("auth", [("user", "secret"), HTTPBasicAuth("u", "p"), None])
def test_other_auth_is_accepted(auth: object) -> None:
    assert Session(auth=auth).auth == auth  # type: ignore[arg-type]


def test_the_message_names_the_way_out() -> None:
    with pytest.raises(ClientError) as caught:
        Session(auth=DIGEST)
    assert "Basic" in str(caught.value)
    assert "client certificate" in str(caught.value)
    assert "secret" not in str(caught.value)
