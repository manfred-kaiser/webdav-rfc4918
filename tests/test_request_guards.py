"""The checks a request passes before it leaves: what URL, where to, with which headers."""

# ruff: noqa: SIM117

import contextlib
import copy
import warnings
from pathlib import Path
from typing import Any

import pytest
import requests

from tests.scripted_server import OK, always, redirect, scripted_server
from webdav import FileSystem, RedirectPolicy, Session
from webdav.exceptions import (
    ClientError,
    InsecureTransportWarning,
    ResourceNotFoundError,
    TLSHardeningDisabledWarning,
)

# ---------------------------------------------------------------------------
# Only full http(s) URLs are ever requested
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url", ["ftp://dav.example/x", "file:///etc/passwd", "/relative", "dav.example/x"]
)
def test_a_url_that_is_not_http_is_refused_with_our_own_error(url: str) -> None:
    with pytest.raises(ClientError, match="not a full http"):
        Session(retry=False).get(url)


@pytest.mark.parametrize("url", ["http://[bad", "http://[bad/x", "https://u:p@[bad"])
def test_an_unparseable_url_is_our_own_error_not_a_bare_valueerror(url: str) -> None:
    with pytest.raises(ClientError, match="not a valid URL"):
        Session(retry=False).get(url)


def test_the_refusal_says_when_a_base_url_would_have_helped() -> None:
    with pytest.raises(ClientError, match="no base_url"):
        Session(retry=False).get("/relative")


def test_a_full_url_on_another_origin_is_refused_with_a_base_url() -> None:
    with pytest.raises(ClientError, match="not on this session's base_url"):
        Session("http://dav.example", retry=False).get("ftp://dav.example/x")


def test_a_full_url_outside_the_base_url_is_a_client_error_for_the_filesystem() -> None:
    with pytest.raises(ClientError):
        FileSystem("http://dav.example/base", retry=False).info(
            "http://dav.example/elsewhere/x"
        )


# ---------------------------------------------------------------------------
# request() keeps requests' positional calling convention
# ---------------------------------------------------------------------------


def test_request_takes_requests_positional_arguments() -> None:
    with scripted_server(always(OK)) as (url, rec):
        Session(retry=False).request("GET", f"{url}/p", {"a": "1"})
    assert rec.requests[0].path == "/p?a=1"


def test_request_refuses_too_many_positional_arguments() -> None:
    with pytest.raises(TypeError, match="at most"):
        Session("http://dav.example").request("GET", "/x", *range(20))


def test_request_refuses_an_argument_given_twice() -> None:
    with pytest.raises(TypeError, match="multiple values"):
        Session("http://dav.example").request(
            "GET", "/x", {"a": "1"}, params={"b": "2"}
        )


# ---------------------------------------------------------------------------
# What is sent
# ---------------------------------------------------------------------------


def test_a_text_body_is_sent_as_utf8_whatever_the_method() -> None:
    with scripted_server(always(OK)) as (url, rec):
        Session(retry=False).put(f"{url}/f", data="ü")
    assert rec.requests[0].body == "ü".encode()


def test_a_single_string_is_one_forwarded_header_name() -> None:
    session = Session()
    session.redirect_forward_headers = "X-Amz-Meta-Owner"  # type: ignore[assignment]
    assert session.redirect_forward_headers == frozenset({"x-amz-meta-owner"})


def test_a_header_that_is_never_forwarded_stays_home_even_when_whitelisted() -> None:
    never = {
        "authorization",
        "proxy-authorization",
        "cookie",
        "if",
        "lock-token",
        "destination",
    }
    with scripted_server(always(OK)) as (storage_url, storage):
        with scripted_server(lambda _r: redirect(307, f"{storage_url}/t")) as (
            gateway_url,
            _g,
        ):
            session = Session(
                redirect_policy=RedirectPolicy.ALL,
                auth=("user", "secret"),
                retry=False,
            )
            session.redirect_forward_headers = frozenset(never)
            session.put(
                f"{gateway_url}/f",
                data=b"x",
                headers={
                    "Authorization": "B",
                    "Proxy-Authorization": "P",
                    "Cookie": "c=1",
                    "If": "(<opaquelocktoken:x>)",
                    "Lock-Token": "<opaquelocktoken:x>",
                    "Destination": "http://elsewhere.example/y",
                },
            )
    (seen,) = storage.requests
    assert never.isdisjoint(seen.headers)


# ---------------------------------------------------------------------------
# COPY/MOVE Destination
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "destination",
    [
        "http://dav.example/b?x=1",
        "http://dav.example/b#frag",
        "http://dav.example/b\\c",
    ],
)
def test_a_destination_with_a_query_a_fragment_or_a_backslash_is_refused(
    destination: str,
) -> None:
    with pytest.raises(ClientError, match="no query, fragment or backslash"):
        Session("http://dav.example", retry=False).move("/a", destination)


def test_an_unparseable_destination_is_our_own_error() -> None:
    with pytest.raises(ClientError, match="not a valid URL"):
        Session("http://dav.example", retry=False).move("/a", "http://[bad")


def test_a_relative_destination_needs_a_base_url() -> None:
    with pytest.raises(ClientError, match="full URL"):
        Session(retry=False).move("http://dav.example/a", "b")


# ---------------------------------------------------------------------------
# Server features
# ---------------------------------------------------------------------------


def test_a_failed_feature_probe_gives_empty_features_and_is_not_remembered() -> None:
    session = Session(retry=False, timeout=(0.2, 0.2))
    features = session.features_for("http://127.0.0.1:1/")
    assert features.supports_ranges is False
    assert features.dav_compliances == set()
    assert session._features == {}


# ---------------------------------------------------------------------------
# Warnings point at the code that made the call
# ---------------------------------------------------------------------------


def _is_this_file(warning: warnings.WarningMessage) -> bool:
    return Path(warning.filename).resolve() == Path(__file__).resolve()


def test_the_warnings_of_a_disabled_certificate_check_point_at_the_caller() -> None:
    with scripted_server(always(OK)) as (url, _rec):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            session = Session(verify=False, retry=False)
            session.get(f"{url}/a")
            session.put(f"{url}/b", data=b"x")
            FileSystem.from_session(session).remove(f"{url}/c")
    ours = [w for w in caught if issubclass(w.category, TLSHardeningDisabledWarning)]
    assert len(ours) >= 4  # one for the session, and every request repeats it
    assert all(_is_this_file(w) for w in ours)


def test_the_cleartext_credentials_warning_points_at_the_caller() -> None:
    session = Session(auth=("user", "secret"), retry=False, timeout=(0.05, 0.05))
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        with contextlib.suppress(requests.RequestException):
            session.get("http://192.0.2.1:9/x")
        with contextlib.suppress(requests.RequestException):
            session.put("http://192.0.2.2:9/x", data=b"x")
    ours = [w for w in caught if issubclass(w.category, InsecureTransportWarning)]
    assert len(ours) == 2  # once per host
    assert all(_is_this_file(w) for w in ours)


def test_a_copy_of_a_session_does_not_share_what_was_warned_about() -> None:
    session = Session(auth=("user", "secret"), retry=False, timeout=(0.05, 0.05))
    duplicate = copy.copy(session)
    for each in (session, duplicate):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            with contextlib.suppress(requests.RequestException):
                each.get("http://192.0.2.1:9/x")
        assert [w.category for w in caught] == [InsecureTransportWarning]


def test_features_of_a_url_that_cannot_be_requested_are_an_error_not_unknown() -> None:
    with pytest.raises(ClientError, match="no base_url"):
        Session(retry=False).features_for("/relative")
    with pytest.raises(ClientError, match="not a valid URL"):
        Session(retry=False).features_for("http://[bad")


# ---------------------------------------------------------------------------
# raise_on_error per call
# ---------------------------------------------------------------------------


def test_raise_on_error_can_be_overridden_for_one_call() -> None:
    with scripted_server(always((404, {}, b""))) as (url, _rec):
        strict = Session(retry=False, raise_on_error=True)
        lax = Session(retry=False)
        with pytest.raises(ResourceNotFoundError):
            strict.get(f"{url}/x")
        assert strict.get(f"{url}/x", raise_on_error=False).status_code == 404
        assert lax.get(f"{url}/x").status_code == 404
        with pytest.raises(ResourceNotFoundError):
            lax.get(f"{url}/x", raise_on_error=True)
        with pytest.raises(ResourceNotFoundError):
            lax.request("GET", f"{url}/x", raise_on_error=True)


# ---------------------------------------------------------------------------
# A typo in an option is an error, never a request that does the opposite
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("typo", "meant"),
    [
        ("allow_redirect", "allow_redirects"),
        ("verfiy", "verify"),
        ("timout", "timeout"),
        ("raise_on_eror", "raise_on_error"),
        ("redirect_polcy", "redirect_policy"),
    ],
)
def test_an_unknown_keyword_argument_is_refused_and_nothing_is_sent(
    typo: str, meant: str
) -> None:
    options: dict[str, Any] = {typo: False}
    with scripted_server(always(OK)) as (url, rec):
        session = Session(retry=False)
        with pytest.raises(
            TypeError, match=f"unexpected keyword argument '{typo}'.*{meant}"
        ):
            session.get(f"{url}/x", **options)
        with pytest.raises(TypeError, match="unexpected keyword argument"):
            session.put(f"{url}/x", data=b"x", **options)
        with pytest.raises(TypeError, match="unexpected keyword argument"):
            session.request("PROPFIND", f"{url}/x", **options)
    assert rec.requests == []


def test_a_name_that_resembles_nothing_is_refused_without_a_suggestion() -> None:
    with pytest.raises(TypeError, match="unexpected keyword argument 'zzz'$"):
        Session("http://dav.example").get("/x", zzz=1)


@pytest.mark.parametrize("falsy", [False, 0, None])
def test_any_false_allow_redirects_means_never(falsy: object) -> None:
    with scripted_server(always(OK)) as (b_url, b_rec):
        with scripted_server(lambda _r: redirect(307, f"{b_url}/x")) as (a_url, _a):
            session = Session(retry=False, redirect_policy=RedirectPolicy.ALL)
            response = session.get(f"{a_url}/x", allow_redirects=falsy)
    if falsy is None:  # not given: the session's policy applies
        assert b_rec.requests
    else:
        assert response.status_code == 307
        assert b_rec.requests == []


# ---------------------------------------------------------------------------
# PROPFIND request kinds (RFC 4918 sec. 9.1)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("options", "element"),
    [
        ({"prop_name": True}, "propname"),
        ({"all_prop": True}, "allprop"),
        ({"props": ["etag"]}, "prop"),
        ({}, None),  # no body at all is an allprop request (sec. 9.1)
    ],
)
def test_propfind_sends_the_kind_of_request_that_was_asked_for(
    options: "dict[str, Any]", element: "str | None"
) -> None:
    with scripted_server(always(OK)) as (url, rec):
        Session(retry=False).propfind(f"{url}/x", depth=0, **options)
    body = rec.requests[0].body.decode()
    if element is None:
        assert body == ""
    else:
        assert f":{element}" in body or f"<{element}" in body
    assert rec.requests[0].headers["depth"] == "0"


@pytest.mark.parametrize(
    "options",
    [
        {"prop_name": True, "all_prop": True},
        {"prop_name": True, "props": ["etag"]},
        {"all_prop": True, "props": ["etag"]},
        {"prop_name": True, "data": b"<x/>"},
    ],
)
def test_propfind_refuses_to_mix_request_kinds(options: "dict[str, Any]") -> None:
    with pytest.raises(ValueError, match="only one|either data"):
        Session("http://dav.example").propfind("/x", depth=0, **options)
