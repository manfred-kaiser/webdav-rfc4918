"""Redirect handling in ``webdav.Session``: what is followed, and what never leaves.

Every test here pins a decision of the redirect handling in ``Session`` (see
``webdav/redirects.py``), against
servers that answer exactly what a hostile or merely odd server might.
"""

import pytest
import requests

from tests.scripted_server import (
    MULTISTATUS_EMPTY,
    OK,
    Seen,
    always,
    redirect,
    scripted_server,
)
from webdav import (
    RedirectNotFollowedError,
    RedirectPolicy,
    Session,
)
from webdav.exceptions import ClientError
from webdav.locks import LockRegistry
from webdav.redirects import effective_origin, redact_url

# ---------------------------------------------------------------------------
# effective_origin: the one place that decides "same server or not"
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://Example.com/x", ("https", "example.com", 443)),
        ("https://example.com:443/x", ("https", "example.com", 443)),
        ("http://example.com:8080/x", ("http", "example.com", 8080)),
        ("http://[::1]:8080/x", ("http", "::1", 8080)),
    ],
)
def test_effective_origin_normalizes(url: str, expected: tuple[str, str, int]) -> None:
    assert effective_origin(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com/x",
        "file:///etc/passwd",
        "https://user:pw@example.com/x",
        "https://user@example.com/x",
        "https://good.example\\@evil.example/x",
        "https://example.com/x\r\nInjected: 1",
        "https://example.com/\x00",
        "//example.com/x",
        "/relative",
        "",
    ],
)
def test_effective_origin_rejects_anything_ambiguous(url: str) -> None:
    assert effective_origin(url) is None


def test_http_and_https_on_the_same_host_are_different_origins() -> None:
    assert effective_origin("http://example.com/x") != effective_origin(
        "https://example.com/x"
    )


# ---------------------------------------------------------------------------
# Which redirects are followed
# ---------------------------------------------------------------------------


def test_303_is_not_replayed_for_a_write() -> None:
    """RFC 9110 15.4.4: 303 means "GET the result" - never re-send a PUT to it."""
    with scripted_server(
        lambda r: redirect(303, "/elsewhere") if r.path == "/f" else OK
    ) as (
        url,
        rec,
    ):
        response = Session().put(f"{url}/f", data=b"payload")

    assert response.status_code == 303
    assert not rec.to("/elsewhere")
    with pytest.raises(RedirectNotFollowedError):
        response.raise_for_status()


def test_303_is_followed_for_a_get() -> None:
    with scripted_server(
        lambda r: redirect(303, "/result") if r.path == "/f" else (200, {}, b"hello")
    ) as (url, rec):
        response = Session().get(f"{url}/f")

    assert response.content == b"hello"
    assert [r.method for r in rec.to("/result")] == ["GET"]


def test_same_origin_redirect_keeps_method_and_body() -> None:
    """requests would re-send this PROPFIND without its body, or as a GET."""
    with scripted_server(
        lambda r: (
            redirect(301, "/dir/") if r.path == "/dir" else (207, {}, MULTISTATUS_EMPTY)
        )
    ) as (url, rec):
        response = Session().propfind(f"{url}/dir", data=b"<propfind/>", depth=0)

    assert response.status_code == 207
    (second,) = rec.to("/dir/")
    assert second.method == "PROPFIND"
    assert second.body == b"<propfind/>"
    assert second.headers["depth"] == "0"
    assert response.history[0].status_code == 301


def test_redirect_loop_is_not_followed() -> None:
    with scripted_server(lambda r: redirect(302, r.path)) as (url, rec):
        response = Session().get(f"{url}/loop")

    assert len(rec.requests) == 1
    assert response.status_code == 302


def test_allow_redirects_false_means_never() -> None:
    with scripted_server(lambda r: redirect(301, "/b") if r.path == "/a" else OK) as (
        url,
        rec,
    ):
        response = Session().get(f"{url}/a", allow_redirects=False)

    assert response.status_code == 301
    assert not rec.to("/b")


def test_per_call_policy_overrides_the_session() -> None:
    with scripted_server(lambda r: redirect(301, "/b") if r.path == "/a" else OK) as (
        url,
        rec,
    ):
        response = Session().get(f"{url}/a", redirect_policy=RedirectPolicy.NEVER)

    assert response.status_code == 301
    assert not rec.to("/b")


@pytest.mark.parametrize(
    "location",
    [
        "http://user:pw@127.0.0.1:1/x",
        "http://127.0.0.1:1\\@127.0.0.1:2/x",
        "ftp://127.0.0.1/x",
        "file:///etc/passwd",
    ],
)
def test_ambiguous_or_non_http_targets_are_never_followed_even_under_all(
    location: str,
) -> None:
    with scripted_server(always(redirect(307, location))) as (url, rec):
        session = Session(redirect_policy=RedirectPolicy.ALL)
        response = session.put(f"{url}/f", data=b"secret")

    assert response.status_code == 307
    assert len(rec.requests) == 1


def test_a_non_replayable_body_is_not_replayed_to_a_redirect_target() -> None:
    with scripted_server(lambda r: redirect(307, "/b") if r.path == "/a" else OK) as (
        url,
        rec,
    ):
        response = Session().put(f"{url}/a", data=iter([b"a", b"b"]))

    assert response.status_code == 307
    assert not rec.to("/b")


def test_redirects_cap() -> None:
    counter = {"n": 0}

    def respond(_seen: Seen) -> tuple[int, dict[str, str], bytes]:
        counter["n"] += 1
        return redirect(302, f"/hop{counter['n']}")

    with scripted_server(respond) as (url, rec):
        response = Session().get(f"{url}/start")

    assert response.status_code == 302
    assert len(rec.requests) == 6  # the original request + 5 hops


# ---------------------------------------------------------------------------
# What never leaves for another origin
# ---------------------------------------------------------------------------


def test_trusted_cross_origin_redirect_forwards_nothing_that_is_ours() -> None:
    with scripted_server(always(OK)) as (storage_url, storage):
        gateway = scripted_server(lambda _seen: redirect(307, f"{storage_url}/target"))
        with gateway as (gateway_url, _gateway):
            session = Session(
                redirect_policy=RedirectPolicy.WHITELIST,
                trusted_redirect_origins=[storage_url],
            )
            session.auth = ("user", "password")
            session.headers["X-Api-Key"] = "session-wide-secret"
            session.cookies.set("sid", "cookie-secret")
            session.locks.add(f"{gateway_url}/f", "opaquelocktoken:abc", "0")
            response = session.put(
                f"{gateway_url}/f",
                data=b"payload",
                headers={
                    "Content-Type": "text/plain",
                    "Destination": f"{gateway_url}/x",
                },
            )

    assert response.status_code == 204
    (seen,) = storage.to("/target")
    assert seen.body == b"payload"
    assert seen.headers["content-type"] == "text/plain"
    for leaked in (
        "authorization",
        "x-api-key",
        "cookie",
        "if",
        "lock-token",
        "destination",
    ):
        assert leaked not in seen.headers, f"{leaked} was forwarded to another origin"


def test_lock_token_is_sent_on_the_locked_origin_only() -> None:
    with scripted_server(always(OK)) as (url, rec):
        session = Session()
        session.locks.add(f"{url}/locked.txt", "opaquelocktoken:abc", "0")
        session.put(f"{url}/locked.txt", data=b"x")
        session.put(f"{url}/other.txt", data=b"x")

    assert rec.to("/locked.txt")[0].headers["if"] == "(<opaquelocktoken:abc>)"
    assert "if" not in rec.to("/other.txt")[0].headers


def test_a_callers_own_if_header_wins() -> None:
    with scripted_server(always(OK)) as (url, rec):
        session = Session()
        session.locks.add(f"{url}/f", "opaquelocktoken:abc", "0")
        session.put(f"{url}/f", data=b"x", headers={"if": "(<opaquelocktoken:mine>)"})

    assert rec.requests[0].headers["if"] == "(<opaquelocktoken:mine>)"


def test_lock_registry_is_keyed_by_origin_too() -> None:
    registry = LockRegistry()
    registry.add("https://a.example/dir", "tok", "infinity")
    assert registry.token_for("https://a.example/dir/child") == "tok"
    assert registry.token_for("https://b.example/dir/child") is None
    assert registry.token_for("http://a.example/dir/child") is None
    assert registry.token_for("https://a.example/dirty") is None


# ---------------------------------------------------------------------------
# Downgrades and http -> https, decided without needing a TLS server
# ---------------------------------------------------------------------------


def _redirect_response(url: str, location: str, status: int = 307) -> requests.Response:
    response = requests.Response()
    response.status_code = status
    response.url = url
    response.headers["Location"] = location
    return response


@pytest.mark.parametrize("policy", [RedirectPolicy.ALL, RedirectPolicy.SAME_ORIGIN])
def test_https_to_http_downgrade_is_never_followed(policy: RedirectPolicy) -> None:
    session = Session(redirect_policy=policy)
    response = _redirect_response("https://dav.example/f", "http://dav.example/f")
    hop = session._plan_hop(response, "PUT", policy, {"data": b"x"}, set())
    assert isinstance(hop, str)
    assert "downgrade" in hop


def test_https_to_http_downgrade_needs_an_explicit_whitelist_entry() -> None:
    session = Session(
        redirect_policy=RedirectPolicy.WHITELIST,
        trusted_redirect_origins=["http://gateway.example"],
    )
    response = _redirect_response("https://dav.example/f", "http://gateway.example/f")
    hop = session._plan_hop(
        response, "PUT", RedirectPolicy.WHITELIST, {"data": b"x"}, set()
    )
    assert hop == ("http://gateway.example/f", False)


def test_http_to_https_upgrade_on_the_same_host_is_a_different_origin() -> None:
    """Refused by default: the credentials already went out over plain http."""
    session = Session()
    response = _redirect_response("http://dav.example/f", "https://dav.example/f", 301)
    hop = session._plan_hop(response, "PROPFIND", RedirectPolicy.SAME_ORIGIN, {}, set())
    assert isinstance(hop, str)
    assert "another origin" in hop


def test_a_different_port_is_a_different_origin() -> None:
    session = Session()
    response = _redirect_response("https://dav.example/f", "https://dav.example:8443/f")
    hop = session._plan_hop(response, "GET", RedirectPolicy.SAME_ORIGIN, {}, set())
    assert isinstance(hop, str)


def test_an_explicit_default_port_is_the_same_origin() -> None:
    session = Session()
    response = _redirect_response("https://dav.example/f", "https://DAV.example:443/g")
    assert session._plan_hop(
        response, "GET", RedirectPolicy.SAME_ORIGIN, {}, set()
    ) == (
        "https://DAV.example:443/g",
        True,
    )


# ---------------------------------------------------------------------------
# Configuration mistakes fail loudly
# ---------------------------------------------------------------------------


def test_whitelist_needs_origins_and_vice_versa() -> None:
    with pytest.raises(ValueError, match="requires"):
        Session(redirect_policy=RedirectPolicy.WHITELIST)
    with pytest.raises(ValueError, match="no effect"):
        Session(trusted_redirect_origins=["https://a.example"])


def test_base_url_refuses_a_full_url_for_another_origin() -> None:
    session = Session(base_url="https://dav.example/root")
    with pytest.raises(ClientError, match="base_url"):
        session.get("https://evil.example/root/x")
    with pytest.raises(ClientError):
        session.get("/../escape")


def test_response_size_cap() -> None:
    with scripted_server(always((207, {}, b"x" * 100))) as (url, _rec):
        with pytest.raises(ClientError, match="Content-Length"):
            Session(max_response_size=10).propfind(url, depth=0)
        assert Session(max_response_size=None).propfind(url, depth=0).status_code == 207


# ---------------------------------------------------------------------------
# Why a redirect was refused - and nothing secret in the message
# ---------------------------------------------------------------------------


def test_a_refused_redirect_says_why_without_leaking_the_signed_query(
    caplog: pytest.LogCaptureFixture,
) -> None:
    signed = "https://storage.example/upload?X-Signature=SUPERSECRET&user:pw=1"
    with scripted_server(always(redirect(307, signed))) as (url, _rec):
        response = Session().put(f"{url}/f", data=b"x")

    assert response.redirect_refusal is not None
    assert "another origin" in response.redirect_refusal
    with pytest.raises(RedirectNotFollowedError) as excinfo:
        response.raise_for_status()

    message = str(excinfo.value)
    assert "storage.example/upload" in message
    assert "another origin" in message
    assert excinfo.value.reason == response.redirect_refusal
    assert "SUPERSECRET" not in message
    assert "SUPERSECRET" not in caplog.text
    assert "another origin" in caplog.text


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        (
            "https://user:pw@host.example:8443/a/b?token=x#frag",
            "https://host.example:8443/a/b",
        ),
        ("http://[::1]:80/x?y", "http://[::1]:80/x"),
        ("/relative?token=x", "/relative"),
        ("", ""),
    ],
)
def test_redact_url(url: str, expected: str) -> None:
    assert redact_url(url) == expected


def test_redact_url_survives_garbage() -> None:
    assert redact_url("http://[bad") == "<unparseable URL>"
    assert "\n" not in redact_url("http://host/a\nb")
