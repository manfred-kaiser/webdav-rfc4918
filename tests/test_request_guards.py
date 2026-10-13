"""The checks a request passes before it leaves: what URL, where to, with which headers."""

import contextlib
import copy
import io
import warnings
from pathlib import Path
from typing import Any

import pytest
import requests

from tests.credentials import AUTH
from tests.scripted_server import (
    NO_CONTENT_LENGTH,
    OK,
    Seen,
    always,
    record_server,
    redirect,
    scripted_server,
)
from webdav import FileSystem, RedirectPolicy, Session
from webdav.dav.conditional import Condition, build_if_header_single
from webdav.exceptions import (
    ClientError,
    InsecureTransportWarning,
    ResourceNotFoundError,
    TLSHardeningDisabledWarning,
    WebDAVError,
)
from webdav.url_safety import effective_origin


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


def test_a_text_body_is_sent_as_utf8_whatever_the_method() -> None:
    with scripted_server(always(OK)) as (url, rec):
        Session(retry=False).put(f"{url}/f", data="ü")
    assert rec.requests[0].body == "ü".encode()


def test_a_single_string_is_one_forwarded_header_name() -> None:
    session = Session()
    session.redirect_forward_headers = "X-Amz-Meta-Owner"
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
    with (
        scripted_server(always(OK)) as (storage_url, storage),
        scripted_server(lambda _r: redirect(307, f"{storage_url}/t")) as (
            gateway_url,
            _g,
        ),
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


def test_a_cross_origin_destination_is_refused() -> None:
    """RFC 6454: two origins are the same iff scheme, host and port all match.

    A COPY/MOVE across them is refused.
    """
    with pytest.raises(ClientError, match="not on this session's base_url"):
        Session("http://dav.example", retry=False).move("/a", "http://evil.example/b")


def test_an_explicit_default_http_port_is_the_same_origin_as_none() -> None:
    """RFC 6454 §4 step 6: fill in the scheme's default port before comparing.

    Http's is 80, not just https' 443.
    """
    assert effective_origin("http://dav.example:80/x") == effective_origin(
        "http://dav.example/x"
    )


def test_a_scheme_relative_destination_is_refused() -> None:
    """A "//host/path" Destination resolves relative to the request's own scheme.

    The same confusion RFC 6454 origin comparison exists to close.
    """
    with pytest.raises(ClientError, match="scheme-relative"):
        Session("http://dav.example", retry=False).move("/a", "//dav.example/b")


def test_a_relative_destination_resolves_to_the_expected_absolute_url() -> None:
    with scripted_server(always((201, {}, b""))) as (url, rec):
        Session(url, retry=False).move("/a", "b")
    assert rec.requests[0].headers["destination"] == f"{url}/b"


def test_a_failed_feature_probe_gives_empty_features_and_is_not_remembered() -> None:
    session = Session(retry=False, timeout=(0.2, 0.2))
    features = session.features_for("http://127.0.0.1:1/")
    assert features.supports_ranges is False
    assert features.dav_compliances == set()
    assert session._features == {}


def _is_this_file(warning: warnings.WarningMessage) -> bool:
    return Path(warning.filename).resolve() == Path(__file__).resolve()


def test_the_warnings_of_a_disabled_certificate_check_point_at_the_caller() -> None:
    with (
        scripted_server(always(OK)) as (url, _rec),
        warnings.catch_warnings(record=True) as caught,
    ):
        warnings.simplefilter("always")
        session = Session(verify=False, retry=False)
        session.get(f"{url}/a")
        session.put(f"{url}/b", data=b"x")
        FileSystem.from_session(session).remove(f"{url}/c")
    ours = [w for w in caught if issubclass(w.category, TLSHardeningDisabledWarning)]
    assert len(ours) >= 4  # one for the session, and every request repeats it
    assert all(_is_this_file(w) for w in ours)


def test_the_cleartext_credentials_warning_points_at_the_caller() -> None:
    session = Session(
        auth=("user", "secret"),
        retry=False,
        timeout=(0.05, 0.05),
        insecure_transport="warn",
    )
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
    session = Session(
        auth=("user", "secret"),
        retry=False,
        timeout=(0.05, 0.05),
        insecure_transport="warn",
    )
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
    with pytest.raises(TypeError, match=r"unexpected keyword argument 'zzz'$"):
        Session("http://dav.example").get("/x", zzz=1)


def test_allow_redirects_false_means_never_and_true_or_absent_means_the_policy() -> (
    None
):
    with (
        scripted_server(always(OK)) as (b_url, b_rec),
        scripted_server(lambda _r: redirect(307, f"{b_url}/x")) as (a_url, _a),
    ):
        session = Session(retry=False, redirect_policy=RedirectPolicy.ALL)
        assert session.get(f"{a_url}/x", allow_redirects=False).status_code == 307
        assert b_rec.requests == []
        for given in (True, None):
            assert session.get(f"{a_url}/x", allow_redirects=given).status_code == 204
        assert len(b_rec.requests) == 2


@pytest.mark.parametrize("value", [0, 1, "", "no", "False", [], object()])
@pytest.mark.parametrize("option", ["allow_redirects", "stream", "raise_on_error"])
def test_a_flag_that_is_not_a_bool_is_refused_and_nothing_is_sent(
    option: str, value: object
) -> None:
    options: dict[str, Any] = {option: value}
    with (
        scripted_server(always(OK)) as (url, rec),
        pytest.raises(TypeError, match=f"{option} must be True or False"),
    ):
        Session(retry=False).get(f"{url}/x", **options)
    assert rec.requests == []


@pytest.mark.parametrize("value", [0, 1, "", "no", None])
@pytest.mark.parametrize("option", ["raise_on_error", "stream", "trust_env"])
def test_a_flag_of_the_session_has_to_be_a_bool_too(option: str, value: object) -> None:
    session = Session()
    before = getattr(session, option)
    with pytest.raises(TypeError, match=f"{option} must be True or False"):
        setattr(session, option, value)
    assert getattr(session, option) == before
    if option == "raise_on_error":
        with pytest.raises(TypeError, match=option):
            Session(raise_on_error=value)  # type: ignore[arg-type]


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
    with pytest.raises(ValueError, match=r"only one|either data"):
        Session("http://dav.example").propfind("/x", depth=0, **options)


@pytest.mark.parametrize(
    "name", ["a%20b.txt", "100%.txt", "sp ace.txt", "ünï.txt", "h#x.txt"]
)
def test_move_and_copy_destinations_are_encoded_like_paths(
    server_url: str, storage_dir: Path, name: str
) -> None:
    """Names with ``?`` or ``;`` are left out only because wsgidav re-splits a decoded Destination."""
    with Session(server_url, auth=AUTH, retry=False) as session:
        session.put(name, b"data")
        assert session.copy(name, destination="copy-" + name).status_code == 201
        assert session.move(name, destination="moved-" + name).status_code == 201
        assert sorted(p.name for p in storage_dir.iterdir()) == sorted(
            ["copy-" + name, "moved-" + name]
        )


@pytest.mark.parametrize(
    "given",
    [
        "/dir/a%2Fb.txt",
        "/dir/caf%E9.txt",
        "/dir/x%2fy/",
        "/dir/a%20b.txt",
        "/dir/caf%C3%A9.txt",
        "/dir/100%25.txt",
    ],
)
def test_bug03_full_url_is_sent_as_written_without_base_url(given: str) -> None:
    with record_server() as (url, rec):
        FileSystem(retry=False).remove(url + given)
    # ``requests`` itself spells the hex digits of an escape in capitals: the same bytes
    assert rec.requests[0].path.upper() == given.upper()


@pytest.mark.parametrize("given", ["/dir/a%2Fb.txt", "/dir/caf%E9.txt"])
def test_bug03_guard_full_url_with_base_url_is_sent_as_written(given: str) -> None:
    with record_server() as (url, rec):
        FileSystem(url, retry=False).remove(url + given)
    assert rec.requests[0].path == given


def test_bug03_guard_unencoded_space_and_unicode_are_encoded() -> None:
    with record_server() as (url, rec):
        FileSystem(retry=False).remove(url + "/a b/café.txt")
    assert rec.requests[0].path == "/a%20b/caf%C3%A9.txt"


def test_bug03_guard_mkdir_adds_the_slash_to_the_raw_path() -> None:
    with scripted_server(always((201, {}, b""))) as (url, rec):
        FileSystem(retry=False).mkdir(url + "/d%2Fx")
    assert rec.requests[0].path == "/d%2Fx/"


@pytest.mark.parametrize(
    ("destination", "sent"),
    [
        ("{url}/t2/x/../file2.txt", "{url}/t2/file2.txt"),
        ("{url}/t2/./file2.txt", "{url}/t2/file2.txt"),
        ("{url}/t2/x/%2e%2e/file2.txt", "{url}/t2/file2.txt"),
        ("{url}/a/b/..", "{url}/a/"),
        ("{url}/../x", "{url}/x"),
        ("/t2/x/../file2.txt", "/t2/file2.txt"),
    ],
)
def test_a_destination_has_no_dot_segments(destination: str, sent: str) -> None:
    with scripted_server(always((201, {}, b""))) as (url, rec):
        Session(retry=False).copy(f"{url}/t2/file.txt", destination.format(url=url))
    assert rec.requests[0].headers["destination"] == sent.format(url=url)


@pytest.mark.parametrize(
    ("given", "rendered"),
    [
        ('"abc"', '["abc"]'),
        ("abc", '["abc"]'),
        ('W/"abc"', '[W/"abc"]'),
    ],
)
def test_an_etag_in_an_if_header_is_quoted_exactly_once(
    given: str, rendered: str
) -> None:
    assert Condition(etag=given).render() == rendered
    assert build_if_header_single([Condition(etag=given)]) == f"({rendered})"


@pytest.mark.parametrize("bad", ['a"b', "a\nb", "a\x00b", '"a"b"', '"a b"', "a b"])
def test_an_etag_that_would_break_out_of_its_brackets_is_refused(bad: str) -> None:
    with pytest.raises(ValueError, match="entity-tag"):
        Condition(etag=bad).render()


def test_send_still_sends_and_returns_a_webdav_response() -> None:
    with scripted_server(always((200, {}, b"hello"))) as (url, _rec):
        session = Session(retry=False)
        response = session.send(
            session.prepare_request(requests.Request("GET", f"{url}/a"))
        )
    assert response.content == b"hello"
    assert response.__class__.__module__ == "webdav.response"


def test_an_absolute_destination_is_percent_encoded_once(server_url: str) -> None:
    with Session(auth=AUTH, retry=False) as session:
        session.put(f"{server_url}/a.txt", b"x")
        response = session.move(
            f"{server_url}/a.txt", destination=f"{server_url}/ünï code.txt"
        )
        assert response.status_code == 201
        assert FileSystem.from_session(session).exists(
            f"{server_url}/%C3%BCn%C3%AF%20code.txt"
        )


def test_a_bare_etag_is_quoted_for_if_match() -> None:
    with scripted_server(always(OK)) as (url, rec):
        session = Session(retry=False)
        session.put(f"{url}/a", b"x", if_match="35256-abc-1")
        session.put(f"{url}/b", b"x", if_match='"quoted"')
        session.delete(f"{url}/c", if_match="bare")
    assert [r.headers["if-match"] for r in rec.requests] == [
        '"35256-abc-1"',
        '"quoted"',
        '"bare"',
    ]


def test_a_scheme_relative_or_foreign_destination_is_refused() -> None:
    with pytest.raises(ClientError):
        Session("http://dav.example").move("/a", destination="//evil.example/x")
    with pytest.raises(ClientError):
        Session("http://dav.example").move("/a", destination="http://evil.example/x")


def test_an_absolute_destination_with_a_space_or_percent_is_made_valid() -> None:
    with scripted_server(always(OK)) as (url, rec):
        session = Session(retry=False)
        session.move(f"{url}/a", destination=f"{url}/a b/100%.txt")
    destination = rec.requests[0].headers["destination"]
    assert " " not in destination
    assert destination.endswith("/a%20b/100%25.txt")


def test_dotdot_past_the_root_is_an_error_even_with_a_root_base_url() -> None:
    session = Session("http://dav.example")
    for path in ("../x", "a/../../x", "..", "/../x"):
        with pytest.raises(ClientError):
            session.resolve_url(path)
    assert session.resolve_url("a/../b") == "http://dav.example/b"


_MS = '<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">{}</d:multistatus>'


def test_a_weak_etag_is_not_a_validator_for_resuming_a_download() -> None:
    calls = {"n": 0}

    def respond(seen: Seen) -> tuple[int, dict[str, str], bytes]:
        if seen.method == "PROPFIND":
            return (
                207,
                {"Content-Type": "application/xml"},
                _MS.format(
                    "<d:response><d:href>/f</d:href><d:propstat><d:prop><d:resourcetype/></d:prop>"
                    "<d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
                ).encode(),
            )
        calls["n"] += 1
        if calls["n"] == 1:
            return (
                200,
                {
                    "Content-Length": "1000",
                    "ETag": 'W/"weak"',
                    "Accept-Ranges": "bytes",
                    NO_CONTENT_LENGTH: "1",
                },
                b"x" * 100,
            )
        return (
            206,
            {"Content-Range": "bytes 100-999/1000", "ETag": 'W/"weak"'},
            b"y" * 900,
        )

    out = io.BytesIO()
    with (
        scripted_server(respond) as (url, _rec),
        pytest.raises((WebDAVError, requests.RequestException)),
    ):
        FileSystem(retry=False).download_fileobj(f"{url}/f", out)


def test_send_refuses_another_origin_than_the_base_url() -> None:
    with (
        scripted_server(always(OK)) as (other, other_rec),
        scripted_server(always(OK)) as (url, rec),
    ):
        session = Session(url, auth=("u", "p"), headers={"X-Api-Key": "K"}, retry=False)
        prepared = session.prepare_request(requests.Request("GET", f"{other}/x"))
        assert prepared.headers["Authorization"]  # prepare_request prepares as asked
        with pytest.raises(ClientError, match="base_url"):
            session.send(prepared)
        ok = session.prepare_request(requests.Request("GET", f"{url}/y"))
        assert session.send(ok).status_code == 204
    assert other_rec.requests == []
    assert len(rec.requests) == 1


def test_send_refuses_a_url_with_credentials_in_it() -> None:
    with scripted_server(always(OK)) as (url, rec):
        host = url.removeprefix("http://")
        session = Session(retry=False)
        prepared = session.prepare_request(
            requests.Request("GET", f"http://u:p@{host}/x")
        )
        with pytest.raises(ClientError, match="credentials"):
            session.send(prepared)
    assert rec.requests == []


def test_send_without_a_base_url_still_sends_to_any_http_url() -> None:
    with scripted_server(always(OK)) as (url, _rec):
        session = Session(retry=False)
        assert (
            session.send(
                session.prepare_request(requests.Request("GET", f"{url}/x"))
            ).status_code
            == 204
        )
