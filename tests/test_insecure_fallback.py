"""http:// works: with credentials it needs one explicit switch, and every entry point has it."""

from collections.abc import Callable
from typing import Any

import fsspec
import pytest
import requests

import webdav
from webdav import ClientError, FileSystem, Session
from webdav.fsspec import WebdavFileSystem

#: TEST-NET-1: never answers. With the switch the request is sent and fails to connect; without
#: it, it is refused before anything leaves the machine.
HOST = "192.0.2.1:9"
AUTH = ("user", "secret")
SHORT: dict[str, Any] = {"retry": False, "timeout": (0.05, 0.05)}

Call = Callable[[str], Any]

pytestmark = pytest.mark.filterwarnings(
    "ignore::webdav.exceptions.InsecureTransportWarning"
)


def _get_with_mode(mode: str) -> Any:
    kwargs: dict[str, Any] = {"insecure_transport": mode} if mode else {}
    return Session(f"http://{HOST}", auth=AUTH, **SHORT, **kwargs).get("/x")


def _filesystem(mode: str) -> Any:
    kwargs: dict[str, Any] = {"insecure_transport": mode} if mode else {}
    return FileSystem(f"http://{HOST}", auth=AUTH, **SHORT, **kwargs).ls("/")


def _short_form(mode: str) -> Any:
    kwargs: dict[str, Any] = {"insecure_transport": mode} if mode else {}
    return webdav.ls(f"http://{HOST}/", auth=AUTH, **SHORT, **kwargs)


def _fsspec_class(mode: str) -> Any:
    kwargs: dict[str, Any] = {"insecure_transport": mode} if mode else {}
    return WebdavFileSystem(f"http://{HOST}", auth=AUTH, **SHORT, **kwargs).ls("/")


def _fsspec_url(mode: str) -> Any:
    options: dict[str, Any] = {"insecure_transport": mode} if mode else {}
    return (
        fsspec.open(f"webdav://{HOST}/x", auth=AUTH, **SHORT, **options).open().read()
    )


ENTRY_POINTS = [_get_with_mode, _filesystem, _short_form, _fsspec_class, _fsspec_url]


@pytest.mark.parametrize("call", ENTRY_POINTS)
def test_credentials_over_http_are_refused_with_the_way_out_in_the_message(
    call: Call,
) -> None:
    with pytest.raises(ClientError, match="insecure_transport") as caught:
        call("")
    assert "https" in str(caught.value)
    assert "--allow-insecure" in str(caught.value)
    assert "secret" not in str(caught.value)


@pytest.mark.parametrize("mode", ["warn", "allow"])
@pytest.mark.parametrize("call", ENTRY_POINTS)
def test_the_switch_lets_the_request_go_out(call: Call, mode: str) -> None:
    """The error is now the connection's (nothing answers there), not the refusal."""
    with pytest.raises(requests.RequestException):
        call(mode)


def test_http_without_credentials_needs_no_switch() -> None:
    with pytest.raises(requests.RequestException):
        FileSystem(f"http://{HOST}", **SHORT).ls("/")


def test_the_command_line_has_the_switch(capsys: pytest.CaptureFixture[str]) -> None:
    from webdav import cli  # noqa: PLC0415

    url = f"webdav://user:secret@{HOST}/"
    base = ["--timeout", "0.05", "--no-retry"]
    assert cli.main(["ls", *base, url]) == 1
    err = capsys.readouterr().err
    assert "--allow-insecure" in err
    assert "secret" not in err
    assert cli.main(["ls", "--allow-insecure", *base, url]) == 1
    err = capsys.readouterr().err
    assert "refusing to send credentials" not in err
