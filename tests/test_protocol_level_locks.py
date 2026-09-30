"""Locks used through ``Session`` directly, and what ``send`` hands back."""

from typing import Any

import pytest
import requests
import requests.adapters

from tests.scripted_server import Seen, scripted_server
from webdav import Response, Session
from webdav.exceptions import STATUS_CODE_EXCEPTIONS, ResourceNotFoundError

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


def test_a_released_lock_is_no_longer_attached_to_writes() -> None:
    with scripted_server(_server()) as (url, rec):
        session = Session(retry=False)
        response = session.lock(f"{url}/f")
        session.locks.add(f"{url}/f", response.active_lock.token, "infinity")
        session.put(f"{url}/f", data=b"x")
        assert session.unlock(f"{url}/f", response.active_lock.token).status_code == 204
        session.put(f"{url}/f", data=b"y")
    puts = [r for r in rec.requests if r.method == "PUT"]
    assert puts[0].headers["if"] == f"(<{TOKEN}>)"
    assert "if" not in puts[1].headers
    assert not session.locks


def test_a_lock_the_server_did_not_release_stays_recorded() -> None:
    with scripted_server(_server(unlock_status=409)) as (url, _rec):
        session = Session(retry=False)
        session.locks.add(f"{url}/f", TOKEN, "infinity")
        assert session.unlock(f"{url}/f", f"<{TOKEN}>").status_code == 409
    assert session.locks.token_for(f"{url}/f") == TOKEN


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
