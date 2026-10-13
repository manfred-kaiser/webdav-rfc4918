"""Credentials: which ones are sent, where they may go, and what never reads them from the environment."""

import os
from pathlib import Path

import pytest
import requests

from tests.scripted_server import OK, Seen, always, redirect, scripted_server
from webdav import RedirectPolicy, Session


@pytest.mark.parametrize("policy", ["all", "whitelist"])
def test_credentials_do_not_reach_a_foreign_origin_on_its_second_hop(
    policy: str,
) -> None:
    with (
        scripted_server(
            lambda r: redirect(307, "/final") if r.path == "/hop" else OK
        ) as (b_url, b_rec),
        scripted_server(lambda _r: redirect(307, f"{b_url}/hop")) as (
            a_url,
            _a_rec,
        ),
    ):
        if policy == "all":
            session = Session(redirect_policy=RedirectPolicy.ALL, retry=False)
        else:
            session = Session(
                redirect_policy=RedirectPolicy.WHITELIST,
                trusted_redirect_origins=[b_url],
                retry=False,
            )
        session.auth = ("u", "SECRET")
        session.headers["X-Api-Key"] = "K"
        session.cookies.set("sid", "cookie-secret", domain="127.0.0.1")
        session.locks.add(f"{a_url}/f", "opaquelocktoken:t", "0")
        response = session.put(
            f"{a_url}/f", data=b"x", headers={"Authorization": "Bearer T"}
        )

    assert response.status_code == 204
    assert [r.path for r in b_rec.requests] == ["/hop", "/final"]
    for seen in b_rec.requests:
        for leaked in ("authorization", "x-api-key", "if"):
            assert (
                leaked not in seen.headers
            ), f"{leaked} reached the foreign origin at {seen.path}"


def test_credentials_do_not_reach_a_third_origin_either() -> None:
    with (
        scripted_server(always(OK)) as (a_url, a_rec),
        scripted_server(lambda _r: redirect(307, f"{a_url}/back")) as (
            b_url,
            _b_rec,
        ),
    ):
        session = Session(redirect_policy=RedirectPolicy.ALL, retry=False)
        session.auth = ("u", "SECRET")
        with scripted_server(lambda _r: redirect(307, f"{b_url}/x")) as (
            start_url,
            _s_rec,
        ):
            # start -> b (foreign) -> a (foreign to start): nothing may go to a.
            session.put(f"{start_url}/f", data=b"x")
    assert all("authorization" not in r.headers for r in a_rec.requests)


def test_netrc_is_not_consulted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    netrc = tmp_path / "netrc"
    netrc.write_text("machine 127.0.0.1 login netrcuser password netrcpass\n")
    netrc.chmod(0o600)
    monkeypatch.setenv("NETRC", str(netrc))
    monkeypatch.setenv("HOME", str(tmp_path))
    with scripted_server(always(OK)) as (url, rec):
        Session(retry=False).get(f"{url}/a")
        Session(retry=False).propfind(f"{url}/a", depth=0)
    assert all("authorization" not in r.headers for r in rec.requests)


def test_explicit_credentials_still_work() -> None:
    with scripted_server(always(OK)) as (url, rec):
        Session(auth=("u", "p"), retry=False).get(f"{url}/a")
        Session(retry=False).get(f"{url}/b", auth=("u", "p"))
    assert all(r.headers["authorization"].startswith("Basic ") for r in rec.requests)


def test_a_cross_origin_answer_cannot_set_cookies_in_the_session() -> None:
    def storage(_r: Seen) -> tuple[int, dict[str, str], bytes]:
        return 204, {"Set-Cookie": "sid=attacker; Path=/"}, b""

    with (
        scripted_server(storage) as (storage_url, _s),
        scripted_server(lambda _r: redirect(307, f"{storage_url}/t")) as (
            gateway_url,
            _g,
        ),
    ):
        session = Session(redirect_policy=RedirectPolicy.ALL, retry=False)
        session.put(f"{gateway_url}/f", data=b"x")
        assert len(session.cookies) == 0


def test_the_documented_environment_is_what_tests_run_in() -> None:
    assert "NETRC" not in os.environ or os.environ["NETRC"]


def test_send_does_not_consult_netrc(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    netrc = tmp_path / "netrc"
    netrc.write_text("machine 127.0.0.1 login netrcuser password netrcpass\n")
    netrc.chmod(0o600)
    monkeypatch.setenv("NETRC", str(netrc))
    with scripted_server(always(OK)) as (url, rec):
        session = Session(retry=False)
        session.send(session.prepare_request(requests.Request("GET", f"{url}/a")))
    assert "authorization" not in rec.requests[0].headers


@pytest.mark.parametrize("falsy", [False, (), ""])
def test_a_falsy_auth_does_not_read_netrc(
    falsy: object, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    netrc = tmp_path / "netrc"
    netrc.write_text("machine 127.0.0.1 login netrcuser password netrcpass\n")
    netrc.chmod(0o600)
    monkeypatch.setenv("NETRC", str(netrc))
    monkeypatch.setenv("HOME", str(tmp_path))
    with scripted_server(always(OK)) as (url, rec):
        Session(retry=False).get(f"{url}/a", auth=falsy)
        Session(retry=False).propfind(f"{url}/a", depth=0, auth=falsy)
        Session(auth=falsy, retry=False).get(f"{url}/a")  # type: ignore[arg-type]
    assert len(rec.requests) == 3
    assert all("authorization" not in r.headers for r in rec.requests)


def test_a_per_call_false_auth_still_beats_the_sessions() -> None:
    with scripted_server(always(OK)) as (url, rec):
        Session(auth=("u", "p"), retry=False).get(f"{url}/a", auth=False)
        Session(auth=("u", "p"), retry=False).get(f"{url}/a")
    assert "authorization" not in rec.requests[0].headers
    assert rec.requests[1].headers["authorization"].startswith("Basic ")
