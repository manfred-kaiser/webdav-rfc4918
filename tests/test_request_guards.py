"""The checks a request passes before it leaves: what URL, where to, with which headers."""

# ruff: noqa: SIM117

import warnings
from pathlib import Path

import pytest

from tests.scripted_server import OK, always, redirect, scripted_server
from webdav import FileSystem, RedirectPolicy, Session
from webdav.exceptions import ClientError, TLSHardeningDisabledWarning

# ---------------------------------------------------------------------------
# Only full http(s) URLs are ever requested
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url", ["ftp://dav.example/x", "file:///etc/passwd", "/relative", "dav.example/x"]
)
def test_a_url_that_is_not_http_is_refused_with_our_own_error(url: str) -> None:
    with pytest.raises(ClientError, match="not a full http"):
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
