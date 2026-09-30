"""The settings of a session: what is accepted, when it is refused, and that it survives a pickle."""

import copy
import pickle
from typing import Any

import pytest

import webdav
from tests.scripted_server import OK, always, redirect, scripted_server
from webdav import FileSystem, RedirectPolicy, Session
from webdav.transport.tls import TLSOptions

# ---------------------------------------------------------------------------
# Every setting is checked where it is set
# ---------------------------------------------------------------------------


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
    session = Session("http://dav.example")
    with pytest.raises(ValueError, match="base_url"):
        session.base_url = base_url  # type: ignore[assignment]
    assert session.base_url == "http://dav.example"


def test_a_base_url_is_never_shown_with_its_credentials_in_the_error() -> None:
    with pytest.raises(ValueError, match="base_url") as excinfo:
        Session("http://user:SECRET@dav.example/")
    assert "SECRET" not in str(excinfo.value)


def test_the_base_url_can_be_lifted_and_set_again() -> None:
    session = Session("http://dav.example/base")
    session.base_url = None
    assert session.base_url is None
    session.base_url = "https://other.example:8443/x/"
    assert session.resolve_url("a") == "https://other.example:8443/x/a"


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


# ---------------------------------------------------------------------------
# max_redirects is a real limit
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# max_response_time is given to the constructor like every other limit
# ---------------------------------------------------------------------------


def test_max_response_time_is_a_constructor_argument_everywhere() -> None:
    assert Session(max_response_time=7).max_response_time == 7
    assert Session(max_response_time=None).max_response_time is None
    assert FileSystem(max_response_time=7)._session.max_response_time == 7
    with scripted_server(always(OK)) as (url, _rec):
        # The one-off functions take it too (it reaches the session they open):
        # removing the root is refused by the library before anything is sent.
        with pytest.raises(webdav.ClientError, match="root"):
            webdav.remove(f"{url}/", max_response_time=3)


# ---------------------------------------------------------------------------
# A session can be copied and pickled (fsspec needs it) - credentials included
# ---------------------------------------------------------------------------


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
