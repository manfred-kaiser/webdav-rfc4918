"""The settings of a session: what is accepted, when it is refused, and that it survives a pickle."""

# ruff: noqa: SIM117, PLC0415, PTH208, S105, RUF001, S301, PT031, EM101

import base64
import copy
import logging
import pickle
from typing import Any

import pytest
import requests

import webdav
from tests import previous_release_pickles as old
from tests.scripted_server import (
    NO_CONTENT_LENGTH,
    OK,
    always,
    redirect,
    scripted_server,
)
from webdav import FileSystem, RedirectPolicy, Session
from webdav.transport.tls import TLSOptions


@pytest.mark.parametrize(
    "timeout",
    [0, -1, float("inf"), float("nan"), True, "5", (1,), (1, 2, 3), (0, 5), (1, "x")],
)
def test_a_timeout_that_cannot_work_is_refused_when_it_is_set(timeout: object) -> None:
    session = Session()
    before = session.timeout
    with pytest.raises(ValueError, match="timeout"):
        session.timeout = timeout  # type: ignore[assignment]
    assert session.timeout == before
    with pytest.raises(ValueError, match="timeout"):
        Session(timeout=timeout)  # type: ignore[arg-type]


@pytest.mark.parametrize("timeout", [None, 5, 0.5, (3.05, 27), (3, None), (None, 7)])
def test_the_timeouts_requests_understands_are_accepted(timeout: Any) -> None:
    session = Session(timeout=timeout)
    assert session.timeout == timeout


@pytest.mark.parametrize(
    "base_url",
    [
        "dav.example/base",
        "/base",
        "ftp://dav.example/",
        "http://user:pw@dav.example/",
        "http://dav.example/?x=1",
        "http://dav.example/#frag",
        "http://[bad",
        "",
        42,
    ],
)
def test_a_base_url_that_is_no_full_http_url_is_refused(base_url: object) -> None:
    with pytest.raises(ValueError, match="base_url"):
        Session(base_url)  # type: ignore[arg-type]


def test_a_base_url_is_never_shown_with_its_credentials_in_the_error() -> None:
    with pytest.raises(ValueError, match="base_url") as excinfo:
        Session("http://user:SECRET@dav.example/")
    assert "SECRET" not in str(excinfo.value)


def test_base_url_is_immutable_after_construction() -> None:
    """Internal code (releasing a lock on cleanup, ...) replays an absolute URL it
    captured earlier, trusting it was already checked against this session's
    origin - a base_url that could later point elsewhere would silently
    invalidate that check. A session for a different server is a new Session."""
    session = Session("http://dav.example/base")
    with pytest.raises(AttributeError):
        session.base_url = "https://other.example:8443/x/"  # type: ignore[misc]
    assert session.base_url == "http://dav.example/base"


@pytest.mark.parametrize("policy", ["all", "same-origin", None, 1, RedirectPolicy])
def test_a_redirect_policy_has_to_be_a_redirect_policy(policy: object) -> None:
    with pytest.raises(TypeError, match="RedirectPolicy"):
        Session(redirect_policy=policy)  # type: ignore[arg-type]
    session = Session()
    with pytest.raises(TypeError, match="RedirectPolicy"):
        session.redirect_policy = policy  # type: ignore[assignment]
    assert session.redirect_policy is RedirectPolicy.SAME_ORIGIN


def test_the_whitelist_policy_needs_trusted_origins_also_when_set_later() -> None:
    session = Session()
    with pytest.raises(ValueError, match="trusted_redirect_origins"):
        session.redirect_policy = RedirectPolicy.WHITELIST
    trusting = Session(
        redirect_policy=RedirectPolicy.WHITELIST,
        trusted_redirect_origins=["https://store.example"],
    )
    trusting.redirect_policy = RedirectPolicy.NEVER
    trusting.redirect_policy = RedirectPolicy.WHITELIST
    assert trusting.trusted_redirect_origins == ["https://store.example"]


def test_a_redirect_policy_given_for_one_call_is_checked_too() -> None:
    session = Session("http://dav.example", retry=False)
    with pytest.raises(TypeError, match="RedirectPolicy"):
        session.get("/x", redirect_policy="all")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="trusted_redirect_origins"):
        session.get("/x", redirect_policy=RedirectPolicy.WHITELIST)


def _chain(box: "dict[str, str]") -> Any:
    def respond(seen: Any) -> Any:
        return redirect(307, f"{box['url']}/{int(seen.path.lstrip('/')) + 1}")

    return respond


@pytest.mark.parametrize(("limit", "requests_made"), [(0, 1), (2, 3), (5, 6)])
def test_max_redirects_is_how_many_hops_in_a_row_are_followed(
    limit: int, requests_made: int
) -> None:
    box: dict[str, str] = {}
    with scripted_server(_chain(box)) as (url, rec):
        box["url"] = url
        session = Session(retry=False, max_redirects=limit)
        response = session.get(f"{url}/0")
    assert len(rec.requests) == requests_made
    assert response.redirect_refusal == f"more than {limit} redirects in a row"


def test_max_redirects_is_five_unless_changed_and_can_be_changed_later() -> None:
    session = Session()
    assert session.max_redirects == 5
    session.max_redirects = 1
    assert session.max_redirects == 1


@pytest.mark.parametrize("count", [-1, 1.5, True, "5", None])
def test_a_max_redirects_that_is_no_count_is_refused(count: object) -> None:
    with pytest.raises(ValueError, match="max_redirects"):
        Session(max_redirects=count)  # type: ignore[arg-type]


def test_max_response_time_is_a_constructor_argument_everywhere() -> None:
    assert Session(max_response_time=7).max_response_time == 7
    assert Session(max_response_time=None).max_response_time is None
    assert FileSystem(max_response_time=7)._session.max_response_time == 7
    with scripted_server(always(OK)) as (url, _rec):
        # The one-off functions take it too (it reaches the session they open):
        # removing the root is refused by the library before anything is sent.
        with pytest.raises(webdav.ClientError, match="root"):
            webdav.remove(f"{url}/", max_response_time=3)


def _configured() -> Session:
    session = Session(
        "https://dav.example/base",
        auth=("user", "pw"),
        headers={"X-A": "1"},
        timeout=(3, 7),
        redirect_policy=RedirectPolicy.WHITELIST,
        trusted_redirect_origins=["https://store.example"],
        max_response_size=1234,
        max_response_time=11,
        max_redirects=2,
        chunk_size=4096,
        raise_on_error=True,
        retry=False,
        tls=TLSOptions(key_password="k", ciphers="ECDHE+AESGCM"),
    )
    session.redirect_forward_headers = ["x-amz-meta-owner"]
    session.locks.add("https://dav.example/base/f", "opaquelocktoken:1", "0")
    return session


_SETTINGS = (
    "base_url",
    "timeout",
    "redirect_policy",
    "trusted_redirect_origins",
    "max_response_size",
    "max_response_time",
    "max_redirects",
    "chunk_size",
    "raise_on_error",
    "redirect_forward_headers",
    "auth",
)


@pytest.mark.parametrize(
    "duplicate", [copy.copy, copy.deepcopy, lambda s: pickle.loads(pickle.dumps(s))]
)
def test_a_duplicate_has_the_settings_but_none_of_the_live_state(
    duplicate: Any,
) -> None:
    original = _configured()
    clone = duplicate(original)
    assert [getattr(clone, name) for name in _SETTINGS] == [
        getattr(original, name) for name in _SETTINGS
    ]
    assert clone.headers["X-A"] == "1"
    assert not clone.locks  # a lock belongs to the server, not to a copy
    assert clone.locks is not original.locks
    assert (
        clone.get_adapter("https://dav.example/").__class__.__name__
        == "SSLContextAdapter"
    )
    assert clone._is_trusted_redirect_target("https://store.example/x")
    assert not clone._is_trusted_redirect_target("https://evil.example/x")


def test_a_filesystem_survives_a_pickle_and_keeps_owning_its_session() -> None:
    clone = pickle.loads(
        pickle.dumps(FileSystem("https://dav.example/base", auth=("u", "p")))
    )
    assert clone._session.base_url == "https://dav.example/base"
    assert clone._owns_session is True
    shared = pickle.loads(
        pickle.dumps(FileSystem.from_session(Session("https://dav.example")))
    )
    assert shared._owns_session is False


def test_what_cannot_be_pickled_says_so() -> None:
    with pytest.raises((pickle.PicklingError, AttributeError)):
        pickle.dumps(
            Session(
                redirect_policy=RedirectPolicy.WHITELIST,
                trusted_redirect_origins=lambda _url: True,
            )
        )


def test_retry_can_be_switched_and_replaced_after_construction() -> None:
    calls: list[str] = []

    def mine(attempt: Any) -> Any:
        calls.append("mine")
        return attempt()

    with scripted_server(always(OK)) as (url, _rec):
        session = Session(retry=False)
        session.get(f"{url}/x")
        assert calls == []
        session.retry = mine
        assert session.retry is mine
        session.get(f"{url}/x")
        assert calls == ["mine"]
        session.retry = True
        assert session.retry is not mine


@pytest.mark.parametrize("value", ["yes", 1, None])
def test_a_retry_that_is_neither_a_bool_nor_callable_is_refused(value: object) -> None:
    with pytest.raises(TypeError, match="retry"):
        Session(retry=value)  # type: ignore[arg-type]
    session = Session(retry=False)
    with pytest.raises(TypeError, match="retry"):
        session.retry = value  # type: ignore[assignment]


def test_a_changed_retry_survives_a_copy() -> None:
    session = Session(retry=True)
    session.retry = False
    assert copy.copy(session).retry is not session.retry  # rebuilt, not shared
    assert copy.copy(session)._retry_arg is False


@pytest.mark.parametrize("bad", [0, -1, 1.5, "8", True])
def test_chunk_size_must_be_a_positive_integer(bad: object) -> None:
    with pytest.raises(ValueError, match="chunk_size"):
        Session(chunk_size=bad)  # type: ignore[arg-type]


@pytest.mark.parametrize("bad", [0, -1, "5", True, float("nan"), float("inf")])
def test_response_limits_are_validated(bad: object) -> None:
    session = Session()
    with pytest.raises(ValueError, match="max_response_time"):
        session.max_response_time = bad  # type: ignore[assignment]
    with pytest.raises(ValueError, match="max_response_size"):
        Session(max_response_size=bad)  # type: ignore[arg-type]


def test_valid_response_limits_are_accepted() -> None:
    session = Session(max_response_size=10)
    session.max_response_time = None
    session.max_response_time = 12.5
    assert session.max_response_time == 12.5


def test_a_session_takes_max_response_time_after_construction() -> None:
    with scripted_server(always((200, {NO_CONTENT_LENGTH: "1"}, b"x" * 100))) as (
        url,
        _rec,
    ):
        session = Session()
        session.max_response_time = 30
        assert session.get(f"{url}/f").content == b"x" * 100


def test_pickles_of_the_previous_release_still_load() -> None:
    plain = pickle.loads(base64.b64decode("".join(old.PLAIN)))
    assert plain.base_url == "https://dav.example.org/base/"
    assert plain.auth == ("alice", "s3cret")
    assert plain.headers["X-Test"] == "1"
    assert plain.cookies.get("sid") == "abc"
    assert plain.verify is True
    # ... and the loaded session works like a new one.
    with scripted_server(always(OK)) as (url, rec):
        clone = pickle.loads(base64.b64decode("".join(old.PLAIN)))
        clone._base_url = None  # pytest-only: point it at the local server
        clone.get(f"{url}/x")
    assert rec.requests[0].headers["authorization"].startswith("Basic ")


def test_a_filesystem_pickle_of_the_previous_release_loads() -> None:
    client = pickle.loads(base64.b64decode("".join(old.FILESYSTEM)))
    assert client.session.auth == ("bob", "pw")


def test_a_copy_does_not_share_its_containers() -> None:
    session = Session(headers={"X-A": "1"})
    session.params = {"a": "1"}
    session.proxies = {"http": "http://proxy.example:3128"}
    session.cookies.set("c", "1", domain="h.example")
    clone = copy.copy(session)
    clone.headers["X-B"] = "2"
    clone.params["b"] = "2"
    clone.proxies["https"] = "http://other.example:3128"
    clone.cookies.set("d", "2", domain="h.example")
    clone.hooks["response"].append(lambda r, **_k: r)
    assert "X-B" not in session.headers
    assert session.params == {"a": "1"}
    assert "https" not in session.proxies
    assert session.cookies.get("d") is None
    assert session.hooks["response"] == []
    assert clone.headers["X-A"] == "1"
    assert clone.cookies.get("c") == "1"


def test_a_pickle_roundtrip_is_unchanged() -> None:
    session = Session("https://h.example", auth=("u", "p"), headers={"X-A": "1"})
    clone = pickle.loads(pickle.dumps(session))
    assert clone.auth == ("u", "p")
    assert clone.headers["X-A"] == "1"


def test_trust_env_false_ignores_the_environment_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with scripted_server(always(OK)) as (proxy, proxy_rec):
        monkeypatch.setenv("HTTP_PROXY", proxy)
        monkeypatch.setenv("http_proxy", proxy)
        monkeypatch.delenv("NO_PROXY", raising=False)
        monkeypatch.delenv("no_proxy", raising=False)
        Session(retry=False).get(
            "http://dav.invalid/x"
        )  # the default: through the proxy
        assert len(proxy_rec.requests) == 1
        with pytest.raises(requests.exceptions.ConnectionError):
            Session(retry=False, trust_env=False, timeout=(0.5, 0.5)).get(
                "http://dav.invalid/x"
            )
        assert len(proxy_rec.requests) == 1


def test_trust_env_is_a_bool_and_an_option_everywhere() -> None:
    with pytest.raises(TypeError):
        Session(trust_env=0)  # type: ignore[arg-type]
    assert Session().trust_env is True
    assert FileSystem("http://dav.example", trust_env=False).session.trust_env is False
    assert pickle.loads(pickle.dumps(Session(trust_env=False))).trust_env is False


def _closed_port() -> int:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def test_a_connection_error_through_an_environment_proxy_says_so(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    dead = f"http://proxyuser:proxypw@127.0.0.1:{_closed_port()}"
    monkeypatch.setenv("HTTP_PROXY", dead)
    monkeypatch.setenv("http_proxy", dead)
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    with caplog.at_level(logging.WARNING, logger="webdav"):
        with pytest.raises(requests.exceptions.ConnectionError) as caught:
            Session(retry=False).get("http://dav.invalid/x")
    notes = " ".join(getattr(caught.value, "__notes__", []))
    assert "trust_env=False" in notes
    assert "trust_env=False" in caplog.text
    assert "proxypw" not in notes + caplog.text
