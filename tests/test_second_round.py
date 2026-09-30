"""Second-round audit: the last doors into ``requests``' own redirect and TLS handling."""

# ruff: noqa: SIM117, PLC0415
import tracemalloc
from pathlib import Path

import pytest
import requests

from tests.scripted_server import (
    NO_CONTENT_LENGTH,
    OK,
    Seen,
    always,
    redirect,
    scripted_server,
)
from tests.server import AUTH
from webdav import FileSystem, RedirectPolicy, Session, exceptions
from webdav.exceptions import ClientError, MalformedResponseError, WebDAVError

# ---------------------------------------------------------------------------
# Session.send() is one request - never a way around the policy
# ---------------------------------------------------------------------------


def test_send_does_not_follow_a_redirect_across_origins() -> None:
    with scripted_server(always(OK)) as (b_url, b_rec):
        with scripted_server(lambda _r: redirect(307, f"{b_url}/steal")) as (a_url, _a):
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


def test_send_checks_tls_verification_like_request_does() -> None:
    with scripted_server(always(OK)) as (url, _rec):
        session = Session(retry=False)
        prepared = session.prepare_request(requests.Request("GET", f"{url}/a"))
        with pytest.raises(ClientError, match="not verified"):
            session.send(prepared, verify=False)
        session.verify = False
        with pytest.raises(ClientError, match="not verified"):
            session.send(prepared)


def test_send_still_sends_and_returns_a_webdav_response() -> None:
    with scripted_server(always((200, {}, b"hello"))) as (url, _rec):
        session = Session(retry=False)
        response = session.send(
            session.prepare_request(requests.Request("GET", f"{url}/a"))
        )
    assert response.content == b"hello"
    assert response.__class__.__module__ == "webdav.response"


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


# ---------------------------------------------------------------------------
# What a redirect response brings with it is bounded, and never crashes the caller
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Loose ends
# ---------------------------------------------------------------------------


def test_redirect_forward_headers_accepts_any_iterable_and_any_case() -> None:
    with scripted_server(always(OK)) as (storage_url, storage):
        with scripted_server(lambda _r: redirect(307, f"{storage_url}/t")) as (
            gateway_url,
            _g,
        ):
            session = Session(redirect_policy=RedirectPolicy.ALL, retry=False)
            session.redirect_forward_headers = ["X-Amz-Meta-Owner"]  # type: ignore[assignment]
            session.put(
                f"{gateway_url}/f",
                data=b"x",
                headers={"x-amz-meta-owner": "me", "X-Other": "no"},
            )
    (seen,) = storage.requests
    assert seen.headers["x-amz-meta-owner"] == "me"
    assert "x-other" not in seen.headers
    assert isinstance(session.redirect_forward_headers, frozenset)


def test_a_lock_refresh_token_is_validated_like_every_other_token() -> None:
    session = Session()
    with pytest.raises(MalformedResponseError):
        session.lock("http://unused.invalid/a", refresh="x>) (<y")


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


def test_send_reads_a_no_length_body_normally() -> None:
    with scripted_server(always((200, {NO_CONTENT_LENGTH: "1"}, b"abc"))) as (
        url,
        _rec,
    ):
        session = Session(retry=False)
        assert (
            session.send(
                session.prepare_request(requests.Request("GET", f"{url}/a"))
            ).content
            == b"abc"
        )


# ---------------------------------------------------------------------------
# RFC 4918 s7.4 / s10.4 for COPY and MOVE: every lock a transfer touches is presented
# ---------------------------------------------------------------------------


def test_copy_and_move_into_a_depth_zero_locked_collection(server_url: str) -> None:
    with Session(server_url, auth=AUTH, retry=False) as session:
        fs = FileSystem.from_session(session)
        fs.mkdir("dir")
        session.put("out.txt", b"x")
        with fs.locked("dir", depth="0"):
            assert session.copy("out.txt", destination="dir/c.txt").status_code == 201
            assert session.move("out.txt", destination="dir/m.txt").status_code == 201
            assert session.move("dir/c.txt", destination="c.txt").status_code == 201


def test_a_transfer_presents_every_lock_it_touches_as_one_tagged_list() -> None:
    from webdav.locks import LockRegistry

    registry = LockRegistry()
    registry.add("https://dav.example/src", "tokI", "infinity")
    registry.add("https://dav.example/dst", "tokD", "0")
    header = registry.if_header(
        "https://dav.example/src/a.txt", "https://dav.example/dst/b.txt"
    )
    assert header is not None
    assert header.startswith("<https://dav.example/")
    assert "(<tokI>)" in header
    assert "(<tokD>)" in header
    assert not header.startswith("(")  # tagged lists and untagged ones cannot be mixed


def test_a_transfer_of_a_locked_source_alone_is_still_tagged() -> None:
    from webdav.locks import LockRegistry

    registry = LockRegistry()
    registry.add("https://dav.example/a.txt", "tok", "0")
    assert registry.if_header(
        "https://dav.example/a.txt", "https://dav.example/b.txt"
    ) == ("<https://dav.example/a.txt> (<tok>)")


# ---------------------------------------------------------------------------
# A multistatus is read in full: nothing hides in a duplicate, a odd status or a foreign href
# ---------------------------------------------------------------------------

_MS = '<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">{}</d:multistatus>'


def _entry(href: str, status: str) -> str:
    return (
        f"<d:response><d:href>{href}</d:href><d:status>{status}</d:status></d:response>"
    )


def _delete_reply(*entries: str) -> tuple[int, dict[str, str], bytes]:
    return (
        207,
        {"Content-Type": "application/xml"},
        _MS.format("".join(entries)).encode(),
    )


def test_a_failure_is_not_hidden_by_a_later_entry_for_the_same_href() -> None:
    reply = _delete_reply(
        _entry("/d/x", "HTTP/1.1 423 Locked"), _entry("/d/x", "HTTP/1.1 204 No Content")
    )
    with scripted_server(always(reply)) as (url, _rec):
        with pytest.raises(exceptions.MultiStatusError):
            FileSystem(retry=False).remove(f"{url}/d")


@pytest.mark.parametrize(
    "status", ["HTTP/1.1 302 Found", "HTTP/1.1 999 Odd", "HTTP/1.1 100 Continue"]
)
def test_any_member_status_outside_2xx_is_a_failure(status: str) -> None:
    with scripted_server(always(_delete_reply(_entry("/d/x", status)))) as (url, _rec):
        with pytest.raises(exceptions.MultiStatusError):
            FileSystem(retry=False).remove(f"{url}/d")


def test_an_unparseable_member_status_is_an_error_not_a_success() -> None:
    with scripted_server(always(_delete_reply(_entry("/d/x", "garbage")))) as (
        url,
        _rec,
    ):
        with pytest.raises(MalformedResponseError):
            FileSystem(retry=False).remove(f"{url}/d")


def test_a_2xx_member_status_is_fine() -> None:
    reply = _delete_reply(
        _entry("/d/x", "HTTP/1.1 200 OK"), _entry("/d/y", "HTTP/1.1 204 No Content")
    )
    with scripted_server(always(reply)) as (url, _rec):
        FileSystem(retry=False).remove(f"{url}/d")


def test_nfc_and_nfd_twins_are_both_listed() -> None:
    import unicodedata

    nfc = unicodedata.normalize("NFC", "é")
    nfd = unicodedata.normalize("NFD", "é")
    body = _multistatus_ls("/d/", f"/d/{nfc}", f"/d/{nfd}", "/d/x")
    with scripted_server(always((207, {}, body))) as (url, _rec):
        names = FileSystem(retry=False).ls(f"{url}/d")
    assert sorted(names) == sorted([f"d/{nfc}", f"d/{nfd}", "d/x"])


def _multistatus_ls(*hrefs: str) -> bytes:
    rows = "".join(
        f"<d:response><d:href>{h}</d:href><d:propstat><d:prop><d:resourcetype>"
        f"{'<d:collection/>' if h.endswith('/') else ''}</d:resourcetype></d:prop>"
        f"<d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
        for h in hrefs
    )
    return _MS.format(rows).encode()


def test_an_absolute_href_for_the_same_server_is_fine() -> None:
    def respond(seen: Seen) -> tuple[int, dict[str, str], bytes]:
        host = seen.headers["host"]
        return 207, {}, _multistatus_ls(f"http://{host}/d/", f"http://{host}/d/x.txt")

    with scripted_server(respond) as (url, _rec):
        assert FileSystem(retry=False).ls(f"{url}/d") == ["d/x.txt"]


# ---------------------------------------------------------------------------
# Small things
# ---------------------------------------------------------------------------


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


def test_download_does_not_touch_the_process_umask(
    server_url: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os

    def forbidden(_mask: int) -> int:
        msg = "the process-wide umask must not be changed"
        raise AssertionError(msg)

    monkeypatch.setattr(os, "umask", forbidden)
    with Session(server_url, auth=AUTH, retry=False) as session:
        fs = FileSystem.from_session(session)
        session.put("a.txt", b"x")
        (tmp_path / "local").mkdir()
        fs.download_file("a.txt", tmp_path / "local" / "a.txt")
    assert (tmp_path / "local" / "a.txt").read_bytes() == b"x"


def test_download_keeps_the_permissions_of_the_file_it_replaces(
    server_url: str, tmp_path: Path
) -> None:
    target = tmp_path / "secret.txt"
    target.write_bytes(b"old")
    target.chmod(0o600)
    with Session(server_url, auth=AUTH, retry=False) as session:
        fs = FileSystem.from_session(session)
        session.put("a.txt", b"new")
        fs.download_file("a.txt", target, overwrite=True)
    assert target.read_bytes() == b"new"
    assert target.stat().st_mode & 0o777 == 0o600


def test_a_new_download_gets_the_umask_permissions(
    server_url: str, tmp_path: Path
) -> None:
    import os

    previous = os.umask(0o022)
    try:
        with Session(server_url, auth=AUTH, retry=False) as session:
            fs = FileSystem.from_session(session)
            session.put("a.txt", b"x")
            fs.download_file("a.txt", tmp_path / "new.txt")
    finally:
        os.umask(previous)
    assert (tmp_path / "new.txt").stat().st_mode & 0o777 == 0o644


def test_an_empty_proppatch_is_refused() -> None:
    with pytest.raises(ValueError, match="needs a body"):
        Session().proppatch("http://unused.invalid/a")


def test_dotdot_past_the_root_is_an_error_even_with_a_root_base_url() -> None:
    session = Session("http://dav.example")
    for path in ("../x", "a/../../x", "..", "/../x"):
        with pytest.raises(ClientError):
            session.resolve_url(path)
    assert session.resolve_url("a/../b") == "http://dav.example/b"


def test_a_failed_unlock_never_replaces_the_callers_own_exception() -> None:
    body = (
        b'<?xml version="1.0"?><d:prop xmlns:d="DAV:"><d:lockdiscovery><d:activelock>'
        b"<d:locktype><d:write/></d:locktype><d:lockscope><d:exclusive/></d:lockscope>"
        b"<d:depth>infinity</d:depth><d:locktoken><d:href>opaquelocktoken:t</d:href></d:locktoken>"
        b"</d:activelock></d:lockdiscovery></d:prop>"
    )
    unlocks = {"n": 0}

    def respond(seen: Seen) -> tuple[int, dict[str, str], bytes]:
        if seen.method == "LOCK":
            return 200, {"Lock-Token": "<opaquelocktoken:t>"}, body
        unlocks["n"] += 1
        raise ConnectionResetError

    class BoomError(Exception):
        pass

    with scripted_server(respond) as (url, _rec):
        with pytest.raises(BoomError):
            with FileSystem(retry=False).locked(f"{url}/f"):
                raise BoomError
    assert unlocks["n"] >= 1


def test_a_weak_etag_is_not_a_validator_for_resuming_a_download() -> None:
    import io

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
    with scripted_server(respond) as (url, _rec):
        with pytest.raises((WebDAVError, requests.RequestException)):
            FileSystem(retry=False).download_fileobj(f"{url}/f", out)


# ---------------------------------------------------------------------------
# Untrusted answers, part two
# ---------------------------------------------------------------------------


def test_stacked_content_codings_are_refused() -> None:
    import gzip

    body = gzip.compress(gzip.compress(gzip.compress(b"0" * 1_000_000)))
    with scripted_server(
        always((207, {"Content-Encoding": "gzip, gzip, gzip"}, body))
    ) as (url, _r):
        with pytest.raises(ClientError, match="stacked"):
            Session(retry=False).propfind(url, depth=0)


def test_a_head_reply_is_not_refused_for_the_length_of_the_body_it_does_not_carry() -> (
    None
):
    reply: tuple[int, dict[str, str], bytes] = (
        200,
        {"Content-Length": "200000000", NO_CONTENT_LENGTH: "1"},
        b"",
    )
    with scripted_server(always(reply)) as (url, _rec):
        response = Session(retry=False, max_response_size=1024).head(f"{url}/big")
        assert response.status_code == 200
        assert response.headers["Content-Length"] == "200000000"
        assert response.content == b""
    not_modified = (304, {"Content-Length": "999999999", NO_CONTENT_LENGTH: "1"}, b"")
    with scripted_server(always(not_modified)) as (url, _rec):
        assert (
            Session(retry=False, max_response_size=1024).get(f"{url}/x").status_code
            == 304
        )


def test_a_plain_web_server_answering_a_propfind_is_a_webdav_error_not_a_valueerror() -> (
    None
):
    with scripted_server(always((200, {}, b"<html>hello</html>"))) as (url, _rec):
        fs = FileSystem(retry=False)
        for call in (
            lambda: fs.ls(f"{url}/d"),
            lambda: fs.info(f"{url}/d"),
            lambda: fs.exists(f"{url}/d"),
            lambda: fs.isdir(f"{url}/d"),
            lambda: fs.content_length(f"{url}/d"),
        ):
            with pytest.raises(MalformedResponseError, match="207"):
                call()


def test_a_case_insensitive_server_spelling_the_collection_differently_is_fine() -> (
    None
):
    def respond(seen: Seen) -> tuple[int, dict[str, str], bytes]:
        upper = seen.path.upper().rstrip("/")
        return 207, {}, _multistatus_ls(f"{upper}/", f"{upper}/File.txt")

    with scripted_server(respond) as (url, _rec):
        assert FileSystem(retry=False).ls(f"{url}/dav/dir") == ["DAV/DIR/File.txt"]


def test_a_backslash_in_a_name_is_an_ordinary_character_on_posix() -> None:
    import os

    if os.name == "nt":
        pytest.skip("a backslash separates paths on Windows")
    body = _multistatus_ls("/d/", "/d/a%5Cb.txt", "/d/c\\d.txt")
    with scripted_server(always((207, {}, body))) as (url, _rec):
        assert sorted(FileSystem(retry=False).ls(f"{url}/d")) == [
            "d/a\\b.txt",
            "d/c\\d.txt",
        ]


def test_walk_counts_queued_collections(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("webdav.fs._WALK_MAX_DIRS", 50)

    def respond(seen: Seen) -> tuple[int, dict[str, str], bytes]:
        base = seen.path.rstrip("/")
        return (
            207,
            {},
            _multistatus_ls(f"{base}/", *[f"{base}/sub{i}/" for i in range(200)]),
        )

    with scripted_server(respond) as (url, rec):
        with pytest.raises(ClientError, match="walk gave up"):
            list(FileSystem(retry=False).walk(url))
    assert len(rec.requests) == 1


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


def test_the_module_level_functions_take_max_response_time_and_reject_typos_at_the_call() -> (
    None
):
    import webdav

    with scripted_server(always((200, {NO_CONTENT_LENGTH: "1"}, b"x" * 100))) as (
        url,
        _rec,
    ):
        assert webdav.get(f"{url}/f", max_response_time=30).content == b"x" * 100
    with pytest.raises(TypeError, match="bogus"):
        webdav.walk("http://unused.invalid/", bogus=1)  # type: ignore[call-arg]


def test_cli_urls_are_percent_decoded_and_ipv6_hosts_keep_their_brackets() -> None:
    from webdav.cli import _split_url

    assert (
        _split_url("webdav://h.example/Photos/a%20b.txt", user=None, password=None)[1]
        == "/Photos/a b.txt"
    )
    assert (
        _split_url("webdav://h.example/100%25.txt", user=None, password=None)[1]
        == "/100%.txt"
    )
    base, path, _auth = _split_url("webdav://[::1]:8080/x", user=None, password=None)
    assert base == "http://[::1]:8080"
    assert path == "/x"
    assert Session(base).resolve_url(path) == "http://[::1]:8080/x"


def test_cli_error_output_is_escaped(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    from webdav import cli

    def hostile(_args: object) -> None:
        msg = "received 500 (\x1b]0;PWNED\x07\x1b[2J)\nforged: line"
        raise cli.CLIError(msg)

    monkeypatch.setattr(cli, "_cmd_ls", hostile)
    assert cli.main(["ls", "http://h.example/x"]) == 1
    err = capsys.readouterr().err
    assert "\x1b" not in err.replace("\\x1b", "")
    assert err.count("\n") == 1  # one line, not two
    assert "\\x1b" in err
