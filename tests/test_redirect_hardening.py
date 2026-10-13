"""Redirect handling in ``webdav.Session``: what is followed, and what never leaves.

Every test here pins a decision of the redirect handling in ``Session`` (see
``webdav/transport/redirects.py``), against
servers that answer exactly what a hostile or merely odd server might.
"""

import tracemalloc
from typing import Any

import pytest
import requests
import urllib3.exceptions

from tests.builders import make_response
from tests.certificates import Certificates
from tests.scripted_server import (
    MULTISTATUS_EMPTY,
    OK,
    Seen,
    always,
    closed_port,
    redirect,
    scripted_server,
    tls_server,
)
from webdav import RedirectNotFollowedError, RedirectPolicy, Session
from webdav.dav.locks import LockRegistry
from webdav.exceptions import ClientError, WebDAVError, raise_for_status
from webdav.response import Response
from webdav.transport.deadline import DeadlineAdapter
from webdav.transport.redirects import (
    NEVER_FORWARD,
    Follow,
    Refuse,
    build_trust_check,
    cross_origin_headers,
    has_replayable_body,
    plan_hop,
    refuse,
)
from webdav.url_safety import effective_origin, redact_url


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
    """``requests`` would re-send this PROPFIND without its body, or as a GET."""
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


def test_a_300_or_a_304_is_never_treated_as_a_redirect_to_follow_or_refuse() -> None:
    """RFC 9110 §15.4.1/§15.4.5: 300 and 304 are 3xx, but outside the followable-redirect set."""
    with scripted_server(always((300, {"Location": "/elsewhere"}, b""))) as (url, rec):
        response = Session(redirect_policy=RedirectPolicy.NEVER).get(f"{url}/f")
    assert response.status_code == 300
    assert len(rec.requests) == 1
    assert (
        response.redirect_refusal is None
    )  # not "refused" either - never redirect-handled at all
    response.raise_for_status()  # must not raise RedirectNotFollowedError

    with scripted_server(always((304, {}, b""))) as (url, rec):
        response = Session(redirect_policy=RedirectPolicy.NEVER).get(f"{url}/f")
    assert response.status_code == 304
    assert len(rec.requests) == 1
    assert response.redirect_refusal is None


def test_a_308_preserves_method_and_body_same_as_307() -> None:
    """RFC 9110 §15.4.9: 308, like 307, MUST NOT change the request method."""
    with scripted_server(
        lambda r: (
            redirect(308, "/dir/") if r.path == "/dir" else (207, {}, MULTISTATUS_EMPTY)
        )
    ) as (url, rec):
        response = Session().propfind(f"{url}/dir", data=b"<propfind/>", depth=0)
    assert response.status_code == 207
    (second,) = rec.to("/dir/")
    assert second.method == "PROPFIND"
    assert second.body == b"<propfind/>"
    assert response.history[0].status_code == 308


def test_a_redirect_with_no_location_header_at_all_is_returned_as_is() -> None:
    """Not a ``requests``-classified redirect at all (is_redirect needs a Location).

    Reaches the caller untouched.
    """
    with scripted_server(always((301, {}, b""))) as (url, rec):
        response = Session().get(f"{url}/f")
    assert response.status_code == 301
    assert len(rec.requests) == 1
    assert response.redirect_refusal is None
    response.raise_for_status()  # must not raise


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


def _redirect_response(url: str, location: str, status: int = 307) -> requests.Response:
    response = requests.Response()
    response.status_code = status
    response.url = url
    response.headers["Location"] = location
    return response


def _plan(
    response: requests.Response,
    method: str,
    policy: RedirectPolicy,
    *,
    kwargs: "dict[str, object] | None" = None,
    seen: "set[str] | None" = None,
    trusted: "list[str] | None" = None,
) -> "Follow | Refuse":
    return plan_hop(
        response,
        method,
        policy,
        body_replayable=has_replayable_body(kwargs or {}),
        seen=seen if seen is not None else set(),
        is_trusted=build_trust_check(trusted),
        get_location=requests.Session().get_redirect_target,
    )


@pytest.mark.parametrize("policy", [RedirectPolicy.ALL, RedirectPolicy.SAME_ORIGIN])
def test_https_to_http_downgrade_is_never_followed(policy: RedirectPolicy) -> None:
    response = _redirect_response("https://dav.example/f", "http://dav.example/f")
    hop = _plan(response, "PUT", policy, kwargs={"data": b"x"})
    assert isinstance(hop, Refuse)
    assert "downgrade" in hop.reason


def test_https_to_http_downgrade_is_never_followed_even_whitelisted() -> None:
    """Trusting an origin with credentials is a different question from accepting that the same bytes cross the network in clear text - no policy allows it."""
    response = _redirect_response("https://dav.example/f", "http://gateway.example/f")
    hop = _plan(
        response,
        "PUT",
        RedirectPolicy.WHITELIST,
        kwargs={"data": b"x"},
        trusted=["http://gateway.example"],
    )
    assert isinstance(hop, Refuse)
    assert "downgrade" in hop.reason


def test_http_to_https_upgrade_on_the_same_host_is_a_different_origin() -> None:
    """Refused by default: the credentials already went out over plain http."""
    response = _redirect_response("http://dav.example/f", "https://dav.example/f", 301)
    hop = _plan(response, "PROPFIND", RedirectPolicy.SAME_ORIGIN)
    assert isinstance(hop, Refuse)
    assert "another origin" in hop.reason


def test_a_different_port_is_a_different_origin() -> None:
    response = _redirect_response("https://dav.example/f", "https://dav.example:8443/f")
    assert isinstance(_plan(response, "GET", RedirectPolicy.SAME_ORIGIN), Refuse)


def test_an_explicit_default_port_is_the_same_origin() -> None:
    response = _redirect_response("https://dav.example/f", "https://DAV.example:443/g")
    assert _plan(response, "GET", RedirectPolicy.SAME_ORIGIN) == Follow(
        "https://DAV.example:443/g", same_origin=True
    )


def test_a_whitelisted_other_origin_is_followed_as_another_origin() -> None:
    response = _redirect_response("https://dav.example/f", "https://store.example/f")
    assert _plan(
        response,
        "PUT",
        RedirectPolicy.WHITELIST,
        kwargs={"data": b"x"},
        trusted=["https://store.example"],
    ) == Follow("https://store.example/f", same_origin=False)


def test_a_redirect_is_judged_against_where_the_request_started() -> None:
    response = _redirect_response("https://b.example/x", "https://b.example/y")
    decision = plan_hop(
        response,
        "GET",
        RedirectPolicy.SAME_ORIGIN,
        body_replayable=True,
        seen=set(),
        origin_url="https://a.example/start",
        is_trusted=build_trust_check(None),
        get_location=requests.Session().get_redirect_target,
    )
    assert isinstance(decision, Refuse)
    assert "another origin" in decision.reason


@pytest.mark.parametrize(
    ("status", "method", "refused"),
    [
        (303, "PUT", True),
        (303, "PROPFIND", True),
        (303, "GET", False),
        (303, "HEAD", False),
        (307, "PUT", False),
    ],
)
def test_a_303_is_only_followed_for_get_and_head(
    status: int, method: str, refused: bool
) -> None:
    response = _redirect_response("https://dav.example/f", "/g", status)
    hop = _plan(response, method, RedirectPolicy.SAME_ORIGIN, kwargs={"data": b"x"})
    assert isinstance(hop, Refuse) is refused


def test_a_redirect_without_a_location_or_with_a_broken_one_is_refused() -> None:
    bare = requests.Response()
    bare.status_code, bare.url = 301, "https://dav.example/f"
    hop = _plan(bare, "GET", RedirectPolicy.SAME_ORIGIN)
    assert hop == Refuse("the redirect has no Location")

    def broken(_response: requests.Response) -> "str | None":
        raise UnicodeError

    assert plan_hop(
        _redirect_response("https://dav.example/f", "/g"),
        "GET",
        RedirectPolicy.SAME_ORIGIN,
        body_replayable=True,
        seen=set(),
        is_trusted=build_trust_check(None),
        get_location=broken,
    ) == Refuse("the Location header is malformed")


def test_a_loop_and_a_body_that_cannot_be_replayed_are_refused() -> None:
    response = _redirect_response("https://dav.example/f", "/g")
    looped = _plan(
        response, "GET", RedirectPolicy.SAME_ORIGIN, seen={"https://dav.example/g"}
    )
    assert isinstance(looped, Refuse)
    assert "loop" in looped.reason
    stream = _plan(
        response, "PUT", RedirectPolicy.SAME_ORIGIN, kwargs={"data": iter([b"x"])}
    )
    assert isinstance(stream, Refuse)
    assert "second time" in stream.reason


def test_only_representation_and_condition_headers_go_to_another_origin() -> None:
    sent = cross_origin_headers(
        {
            "Content-Type": "text/plain",
            "If-Match": '"e"',
            "X-Api-Key": "SECRET",
            "Authorization": "B",
        }
    )
    assert sent == {"Content-Type": "text/plain", "If-Match": '"e"'}


def test_an_extra_allowed_header_goes_along_in_any_case() -> None:
    sent = cross_origin_headers({"X-Amz-Meta-Owner": "me"}, ["x-AMZ-meta-owner"])
    assert sent == {"X-Amz-Meta-Owner": "me"}


def test_what_is_never_forwarded_stays_home_even_when_named_as_allowed() -> None:
    headers = dict.fromkeys(NEVER_FORWARD, "v")
    assert cross_origin_headers(headers, NEVER_FORWARD) == {}
    assert cross_origin_headers(None) == {}


def test_a_refusal_is_recorded_on_the_response() -> None:
    response = Response.adopt(_redirect_response("https://dav.example/f", "/g"))
    refuse(response, "because")
    assert response.redirect_refusal == "because"


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


def test_per_call_custom_headers_do_not_follow_a_redirect_to_another_origin() -> None:
    with (
        scripted_server(always(OK)) as (storage_url, storage),
        scripted_server(lambda _r: redirect(307, f"{storage_url}/t")) as (
            gateway_url,
            _g,
        ),
    ):
        session = Session(redirect_policy=RedirectPolicy.ALL, retry=False)
        session.put(
            f"{gateway_url}/f",
            data=b"x",
            headers={
                "Content-Type": "text/plain",
                "X-Api-Key": "SECRET",
                "X-Token": "T",
            },
        )
    (seen,) = storage.requests
    assert seen.headers["content-type"] == "text/plain"
    assert "x-api-key" not in seen.headers
    assert "x-token" not in seen.headers


def test_extra_forwarded_headers_are_an_explicit_opt_in() -> None:
    with (
        scripted_server(always(OK)) as (storage_url, storage),
        scripted_server(lambda _r: redirect(307, f"{storage_url}/t")) as (
            gateway_url,
            _g,
        ),
    ):
        session = Session(redirect_policy=RedirectPolicy.ALL, retry=False)
        session.redirect_forward_headers = frozenset({"x-amz-meta-owner"})
        session.put(
            f"{gateway_url}/f",
            data=b"x",
            headers={
                "X-Amz-Meta-Owner": "me",
                "X-Api-Key": "SECRET",
                "Authorization": "B",
            },
        )
    (seen,) = storage.requests
    assert seen.headers["x-amz-meta-owner"] == "me"
    assert "x-api-key" not in seen.headers
    assert "authorization" not in seen.headers


def test_the_lock_header_is_worked_out_again_for_a_redirect_target_on_the_same_origin() -> (
    None
):
    def respond(seen: Seen) -> tuple[int, dict[str, str], bytes]:
        return redirect(307, "/other.txt") if seen.path == "/locked.txt" else OK

    with scripted_server(respond) as (url, rec):
        session = Session(retry=False)
        session.locks.add(f"{url}/locked.txt", "opaquelocktoken:t", "0")
        session.put(f"{url}/locked.txt", data=b"x")
    first, second = rec.requests
    assert first.headers["if"] == "(<opaquelocktoken:t>)"
    assert "if" not in second.headers


def test_a_port_zero_is_never_an_origin() -> None:
    assert effective_origin("https://dav.example:0/x") is None
    assert effective_origin("http://dav.example:65536/x") is None
    assert effective_origin("https://dav.example:443/x") == (
        "https",
        "dav.example",
        443,
    )


def test_send_does_not_follow_a_redirect_across_origins() -> None:
    with (
        scripted_server(always(OK)) as (b_url, b_rec),
        scripted_server(lambda _r: redirect(307, f"{b_url}/steal")) as (a_url, _a),
    ):
        session = Session(retry=False)
        session.headers["X-Api-Key"] = "SECRET"
        prepared = session.prepare_request(
            requests.Request("PUT", f"{a_url}/f", data=b"BODY")
        )
        response = session.send(prepared)
    assert response.status_code == 307
    assert b_rec.requests == []
    assert response.redirect_refusal


def test_send_does_not_follow_redirects_on_the_same_origin_either() -> None:
    with scripted_server(lambda r: redirect(307, "/b") if r.path == "/a" else OK) as (
        url,
        rec,
    ):
        session = Session(retry=False)
        response = session.send(
            session.prepare_request(requests.Request("GET", f"{url}/a"))
        )
    assert response.status_code == 307
    assert [r.path for r in rec.requests] == ["/a"]


def test_the_body_of_a_redirect_is_not_read_into_memory_unbounded() -> None:
    big = b"x" * (20 * 1024 * 1024)
    with scripted_server(always((302, {"Location": "/elsewhere"}, big))) as (url, _rec):
        session = Session(
            retry=False,
            max_response_size=1024 * 1024,
            redirect_policy=RedirectPolicy.NEVER,
        )
        tracemalloc.start()
        try:
            with pytest.raises(ClientError):
                session.get(f"{url}/a")
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
    assert peak < 8 * 1024 * 1024, f"read {peak} bytes of a redirect body into memory"


@pytest.mark.parametrize(
    "location",
    [
        "http://[::1/x",
        "http://B%2f.A/",
        "http://host:99999/",
        "http://exa mple.invalid/",
        "//",
    ],
)
def test_a_malformed_location_is_a_refused_redirect_not_a_crash(location: str) -> None:
    with scripted_server(always(redirect(302, location))) as (url, _rec):
        try:
            response = Session(retry=False).get(f"{url}/a")
        except (WebDAVError, requests.RequestException):
            return
    assert response.status_code == 302  # returned as it is, not followed


def test_a_location_with_invalid_utf8_is_a_refused_redirect_not_a_crash() -> None:
    with scripted_server(always((302, {"Location": "http://x/\xff\xfe"}, b""))) as (
        url,
        _rec,
    ):
        try:
            response = Session(retry=False).get(f"{url}/a")
        except (WebDAVError, requests.RequestException):
            return
    assert response.status_code == 302


def test_redirect_forward_headers_accepts_any_iterable_and_any_case() -> None:
    with (
        scripted_server(always(OK)) as (storage_url, storage),
        scripted_server(lambda _r: redirect(307, f"{storage_url}/t")) as (
            gateway_url,
            _g,
        ),
    ):
        session = Session(redirect_policy=RedirectPolicy.ALL, retry=False)
        session.redirect_forward_headers = ["X-Amz-Meta-Owner"]
        session.put(
            f"{gateway_url}/f",
            data=b"x",
            headers={"x-amz-meta-owner": "me", "X-Other": "no"},
        )
    (seen,) = storage.requests
    assert seen.headers["x-amz-meta-owner"] == "me"
    assert "x-other" not in seen.headers
    assert isinstance(session.redirect_forward_headers, frozenset)


def test_a_chain_that_returns_to_the_start_origin_returns_without_credentials() -> None:
    with (
        scripted_server(
            lambda r: redirect(307, f"{b_url}/gateway") if r.path == "/upload" else OK
        ) as (a_url, a_rec),
        scripted_server(lambda _r: redirect(307, f"{a_url}/victim")) as (
            b_url,
            b_rec,
        ),
    ):
        session = Session(
            a_url,
            auth=("alice", "s3cret"),
            headers={"X-Api-Key": "KEY"},
            redirect_policy=RedirectPolicy.WHITELIST,
            trusted_redirect_origins=[b_url],
            retry=False,
        )
        session.cookies.set("sid", "S3CRET", domain="127.0.0.1")
        response = session.put("/upload", data=b"payload", headers={"If-Match": '"e"'})
    assert response.status_code == 204
    first = a_rec.to("/upload")[0]
    assert first.headers["authorization"].startswith("Basic ")
    assert "sid=S3CRET" in first.headers["cookie"]
    (back,) = a_rec.to("/victim")
    assert back.body == b"payload"
    for header in ("authorization", "cookie", "x-api-key", "if"):
        assert header not in back.headers
    assert back.headers["if-match"] == '"e"'  # what describes the body still goes
    (gateway,) = b_rec.to("/gateway")
    assert "authorization" not in gateway.headers


def test_a_same_origin_chain_that_never_left_keeps_its_credentials() -> None:
    def respond(seen: Seen) -> tuple[int, dict[str, str], bytes]:
        return redirect(307, f"{url}/b") if seen.path == "/a" else OK

    with scripted_server(respond) as (url, rec):
        Session(url, auth=("u", "p"), retry=False).put("/a", data=b"x")
    assert rec.to("/b")[0].headers["authorization"].startswith("Basic ")


@pytest.fixture(scope="module")
def certs(tmp_path_factory: pytest.TempPathFactory) -> Certificates:
    return Certificates(tmp_path_factory.mktemp("ic-certs"))


def test_a_chain_from_http_over_https_back_to_http_is_not_followed(
    certs: Certificates,
) -> None:
    with (
        scripted_server(
            lambda r: redirect(307, f"{b_url}/mid") if r.path == "/start" else OK
        ) as (a_url, a_rec),
        tls_server(certs, lambda _r: redirect(307, f"{a_url}/final")) as (
            b_url,
            _b,
        ),
    ):
        session = Session(redirect_policy=RedirectPolicy.ALL, retry=False)
        response = session.get(f"{a_url}/start", verify=str(certs.ca_cert))
    assert response.status_code == 307
    assert "downgrade" in (response.redirect_refusal or "")
    assert a_rec.to("/final") == []


def test_http_to_https_with_all_still_follows(certs: Certificates) -> None:
    with (
        tls_server(certs, always(OK)) as (b_url, b_rec),
        scripted_server(lambda _r: redirect(307, f"{b_url}/t")) as (a_url, _a),
    ):
        session = Session(redirect_policy=RedirectPolicy.ALL, retry=False)
        response = session.get(f"{a_url}/start", verify=str(certs.ca_cert))
    assert response.status_code == 204
    assert len(b_rec.requests) == 1


_SIGNATURE = "SECRETSIG-0123"


def test_the_cause_chain_is_cleaned_in_place_not_cut() -> None:
    url = f"http://127.0.0.1:{closed_port()}/dl?sig={_SIGNATURE}"
    with pytest.raises(requests.exceptions.ConnectionError) as caught:
        Session(retry=False).get(url)
    inner = caught.value.args[0]
    assert isinstance(inner, urllib3.exceptions.MaxRetryError)
    assert isinstance(inner.reason, urllib3.exceptions.NewConnectionError)
    assert caught.value.request is not None
    assert caught.value.__cause__ is None or isinstance(
        caught.value.__cause__, BaseException
    )


def _redirecting_to(location: str) -> Any:
    def respond(seen: Seen) -> tuple[int, dict[str, str], bytes]:
        return redirect(301, location) if seen.path.startswith("/start") else OK

    return respond


def test_a_session_param_the_location_already_has_is_not_added_twice() -> None:
    with scripted_server(_redirecting_to("/dir/?a=1")) as (url, rec):
        session = Session(retry=False)
        session.params = {"a": "1"}
        session.get(f"{url}/start")
    assert [r.path for r in rec.requests][-1] == "/dir/?a=1"


def test_a_session_param_the_location_lacks_is_still_added() -> None:
    with scripted_server(_redirecting_to("/dir/")) as (url, rec):
        session = Session(retry=False)
        session.params = {"token": "T"}
        session.get(f"{url}/start")
    assert [r.path for r in rec.requests][-1] == "/dir/?token=T"


def test_the_location_wins_over_a_session_param_of_the_same_key() -> None:
    with scripted_server(_redirecting_to("/dir/?a=2")) as (url, rec):
        session = Session(retry=False)
        session.params = {"a": "1", "b": "x"}
        session.get(f"{url}/start")
    assert [r.path for r in rec.requests][-1] == "/dir/?a=2&b=x"


def test_a_redirect_to_an_unparseable_host_is_an_invalid_url() -> None:
    with scripted_server(lambda _s: (302, {"Location": "http://a..b/"}, b"")) as (
        url,
        _rec,
    ):
        session = Session(redirect_policy=RedirectPolicy.ALL, retry=False)
        with pytest.raises(requests.exceptions.InvalidURL) as excinfo:
            session.get(f"{url}/x")
    assert isinstance(excinfo.value, ValueError)


def test_the_adapter_turns_a_location_error_into_an_invalid_url() -> None:
    prepared = requests.Request("GET", "http://a..b/").prepare()
    with pytest.raises(requests.exceptions.InvalidURL):
        DeadlineAdapter().send(prepared, timeout=1)


@pytest.mark.parametrize("status", [300, 301, 304, 305, 306])
@pytest.mark.parametrize("method", ["PUT", "DELETE", "MKCOL", "MOVE", "PROPPATCH"])
def test_proto07_a_write_answered_by_an_unfollowable_3xx_is_an_error(
    status: int, method: str
) -> None:
    response = make_response(status, method=method)
    with pytest.raises(RedirectNotFollowedError):
        response.raise_for_status()
    with pytest.raises(RedirectNotFollowedError):
        raise_for_status(response)


@pytest.mark.parametrize("method", ["GET", "HEAD", "PROPFIND", "OPTIONS"])
def test_proto07_a_conditional_read_answered_304_stays_fine(method: str) -> None:
    make_response(304, method=method).raise_for_status()


def test_proto07_the_message_says_nothing_was_carried_out() -> None:
    with pytest.raises(RedirectNotFollowedError, match="no Location"):
        make_response(304, method="PUT").raise_for_status()
