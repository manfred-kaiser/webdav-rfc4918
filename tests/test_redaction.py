"""Secrets and control characters never reach a message, a log line or a traceback."""

# ruff: noqa: SIM117, PLC0415, S105, S108, S301, PT031, EM101

import logging
import traceback

import pytest
import requests

from tests.builders import entry, make_response, ms
from tests.scripted_server import Seen, always, closed_port, redirect, scripted_server
from webdav import FileSystem, RedirectPolicy, Session
from webdav.dav.multistatus import MultiStatusResponse
from webdav.exceptions import (
    ClientError,
    HTTPStatusError,
    MultiStatusError,
    ResourceNotFoundError,
)
from webdav.url_safety import redact_url


def test_credentials_in_a_url_do_not_reach_messages_or_warnings() -> None:
    session = Session("http://dav.example")
    with pytest.raises(ClientError) as excinfo:
        session.get("http://bob:PWD1@other.example/x")
    assert "PWD1" not in str(excinfo.value)

    with scripted_server(always((404, {}, b""))) as (url, rec):
        host = url.removeprefix("http://")
        with pytest.raises(ClientError, match="auth") as refused:
            FileSystem(retry=False).ls(f"http://bob:PWD4@{host}/dir")
    assert "PWD4" not in str(refused.value)
    assert (
        rec.requests == []
    )  # credentials in a URL are refused before anything is sent


_SIGNATURE = "SECRETSIG-0123"


def _whole(exc: BaseException) -> str:
    return "".join(traceback.format_exception(exc)) + repr(exc.args)


def test_a_connection_error_after_a_redirect_does_not_show_the_signed_query() -> None:
    target = f"http://127.0.0.1:{closed_port()}/dl/file?X-Amz-Signature={_SIGNATURE}&token=TOK"
    with scripted_server(lambda _r: redirect(302, target)) as (url, _rec):
        session = Session(redirect_policy=RedirectPolicy.ALL, retry=False)
        with pytest.raises(requests.exceptions.ConnectionError) as caught:
            session.get(f"{url}/x")
    assert _SIGNATURE not in _whole(caught.value)
    assert "TOK" not in str(caught.value)
    assert "<redacted>" in str(caught.value)


def test_a_connection_error_for_the_callers_own_query_does_not_show_it() -> None:
    url = f"http://127.0.0.1:{closed_port()}/dl?sig={_SIGNATURE}"
    with pytest.raises(requests.exceptions.ConnectionError) as caught:
        Session(retry=False).get(url)
    assert _SIGNATURE not in _whole(caught.value)


def test_a_failed_unlock_logs_no_query(caplog: pytest.LogCaptureFixture) -> None:
    client = FileSystem(retry=False)
    with caplog.at_level(logging.WARNING, logger="webdav"):
        client._unlock_quietly(
            f"http://127.0.0.1:{closed_port()}/a?sig={_SIGNATURE}",
            "opaquelocktoken:1",
        )
    assert caplog.records
    assert _SIGNATURE not in caplog.text


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


def test_cred05_the_live_request_is_not_mutated() -> None:
    response = make_response(500, request_headers={"Authorization": "Basic c2VjcmV0"})
    live = response.request
    exc = HTTPStatusError(response)
    assert live.headers["Authorization"] == "Basic c2VjcmV0"
    assert exc.response.request.headers["Authorization"] == "[redacted]"


def test_cred05_a_prepared_request_can_be_sent_again_after_the_failure() -> None:
    seen: list[str] = []

    def respond(request: Seen) -> "tuple[int, dict[str, str], bytes]":
        seen.append(request.headers.get("authorization", ""))
        return 500, {}, b""

    with scripted_server(respond) as (url, _rec):
        with Session(auth=("user", "pw"), retry=False) as session:
            prepared = session.prepare_request(requests.Request("GET", f"{url}/x"))
            with pytest.raises(HTTPStatusError):
                session.send(prepared).raise_for_status()
            session.send(prepared)
    assert seen[0] == seen[1] != "[redacted]"
    assert seen[1].startswith("Basic ")


def test_cred05_the_history_is_redacted_too() -> None:
    hop = make_response(
        302, request_headers={"Authorization": "Basic c2VjcmV0", "Cookie": "s=1"}
    )
    final = make_response(500, request_headers={"Authorization": "Basic c2VjcmV0"})
    final.history = [hop]
    original_hop_request = hop.request
    HTTPStatusError(final)
    assert hop.request.headers["Authorization"] == "[redacted]"
    assert hop.request.headers["Cookie"] == "[redacted]"
    assert original_hop_request.headers["Authorization"] == "Basic c2VjcmV0"


def test_cred05_a_request_without_secrets_is_left_alone() -> None:
    response = make_response(500, request_headers={"Accept": "*/*"})
    request = response.request
    HTTPStatusError(response)
    assert response.request is request


def test_cred05_redacting_twice_is_stable() -> None:
    response = make_response(500, request_headers={"Authorization": "Basic c2VjcmV0"})
    HTTPStatusError(response)
    HTTPStatusError(response)
    assert response.request.headers["Authorization"] == "[redacted]"
