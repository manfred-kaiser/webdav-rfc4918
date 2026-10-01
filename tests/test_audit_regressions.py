"""Regressions for bugs an independent audit found (each was reproduced before it was fixed)."""

# ruff: noqa: SIM117, PLC0415, PTH208, S105, RUF001
# (These tests deliberately nest several servers in one ``with``, import lazily, use made-up
# secrets and a full-width digit as attack input, and list directories the way the code under test does.)

import contextlib
import os
import unicodedata
from pathlib import Path

import pytest
import requests

import webdav
from tests.credentials import AUTH
from tests.scripted_server import OK, redirect, scripted_server
from webdav import FileSystem, RedirectPolicy, Session

# ---------------------------------------------------------------------------
# A redirect chain must never bring credentials to a foreign origin, not even on
# the second hop, which is "same origin" only relative to the foreign one.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("policy", ["all", "whitelist"])
def test_credentials_do_not_reach_a_foreign_origin_on_its_second_hop(
    policy: str,
) -> None:
    with scripted_server(
        lambda r: redirect(307, "/final") if r.path == "/hop" else OK
    ) as (b_url, b_rec):
        with scripted_server(lambda _r: redirect(307, f"{b_url}/hop")) as (
            a_url,
            _a_rec,
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
    with scripted_server(always(OK)) as (a_url, a_rec):
        with scripted_server(lambda _r: redirect(307, f"{a_url}/back")) as (
            b_url,
            _b_rec,
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


# ---------------------------------------------------------------------------
# RFC 4918 sec. 7.4: a write lock on a collection - Depth 0 or infinity - also
# protects its direct membership.
# ---------------------------------------------------------------------------


def test_a_depth_zero_lock_on_a_collection_covers_adding_a_member(
    server_url: str,
) -> None:
    with Session(server_url, auth=AUTH, retry=False) as session:
        fs = FileSystem.from_session(session)
        fs.mkdir("dir")
        with fs.locked("dir", depth="0"):
            assert session.put("dir/new.txt", b"x").status_code == 201
            assert session.mkcol("dir/sub").status_code == 201
            assert session.delete("dir/new.txt").status_code == 204


def test_a_depth_zero_lock_does_not_cover_grandchildren(server_url: str) -> None:
    with Session(server_url, auth=AUTH, retry=False) as session:
        fs = FileSystem.from_session(session)
        fs.mkdir("dir")
        fs.mkdir("dir/sub")
        with fs.locked("dir", depth="0"):
            url = session.resolve_url("dir/sub/deep.txt")
            assert session.locks.token_for(url) is None


# ---------------------------------------------------------------------------
# Names round-trip: what ``ls`` returns is what ``get``/``walk``/... accept.
# ---------------------------------------------------------------------------

AWKWARD_NAMES = [
    "a%20b.txt",
    "100%.txt",
    "q?x.txt",
    "h#x.txt",
    "sp ace.txt",
    "plus+and&amp;.txt",
    "ünï.txt",
    "semi;colon,comma.txt",
]


@pytest.mark.parametrize("name", AWKWARD_NAMES)
def test_awkward_names_are_written_where_they_were_asked_for(
    server_url: str, storage_dir: Path, name: str
) -> None:
    with Session(server_url, auth=AUTH, retry=False) as session:
        fs = FileSystem.from_session(session)
        assert session.put(name, b"data").status_code == 201
        assert name in os.listdir(storage_dir)
        assert session.get(name).content == b"data"
        assert fs.exists(name)
        assert fs.ls("/") == [name]
        assert fs.info(name).name == name
        with fs.open(name, "rb") as fobj:
            assert fobj.read() == b"data"
        session.delete(name).raise_for_status()
        assert os.listdir(storage_dir) == []


def test_walk_finds_awkward_directories(server_url: str, storage_dir: Path) -> None:
    with Session(server_url, auth=AUTH, retry=False) as session:
        fs = FileSystem.from_session(session)
        fs.mkdir("a%20b")
        fs.mkdir("q?x")
        session.put("a%20b/f#1.txt", b"x")
        walked = {p: sorted(f) for p, _d, f in fs.walk("/")}
        assert walked == {"/": [], "a%20b": ["a%20b/f#1.txt"], "q?x": []}
        assert sorted(os.listdir(storage_dir)) == ["a%20b", "q?x"]


def test_full_urls_are_used_as_given(server_url: str, storage_dir: Path) -> None:
    (storage_dir / "a b.txt").write_bytes(b"x")
    with Session(auth=AUTH) as session:
        assert session.get(f"{server_url}/a%20b.txt").content == b"x"
        assert FileSystem.from_session(session).exists(f"{server_url}/a%20b.txt")


def test_unicode_normalisation_of_names_is_not_changed_on_the_wire(
    server_url: str, storage_dir: Path
) -> None:
    """A macOS-style NFD name must be requested as the server stores it, not as NFC."""
    nfd = unicodedata.normalize("NFD", "café.txt")
    nfc = unicodedata.normalize("NFC", "café.txt")
    assert nfd != nfc
    (storage_dir / nfd).write_bytes(b"decomposed")
    with Session(server_url, auth=AUTH, retry=False) as session:
        fs = FileSystem.from_session(session)
        (name,) = fs.ls("/")
        assert session.get(name).content == b"decomposed"
        assert fs.exists(name)
        # and the caller's own NFC spelling is also just what it says it is:
        assert not fs.exists(nfc)


# ---------------------------------------------------------------------------
# ls/walk on a full URL with a trailing slash must not list the collection in itself
# ---------------------------------------------------------------------------


def test_ls_with_a_trailing_slash_does_not_list_the_collection_itself(
    server_url: str,
) -> None:
    with Session(auth=AUTH, retry=False) as session:
        fs = FileSystem.from_session(session)
        fs.mkdir(f"{server_url}/Full")
        session.put(f"{server_url}/Full/f.txt", b"x")
        fs.mkdir(f"{server_url}/Empty")
        assert fs.ls(f"{server_url}/Full/") == ["Full/f.txt"]
        assert fs.ls(f"{server_url}/Full") == ["Full/f.txt"]
        assert fs.ls(f"{server_url}/Empty/") == []
        assert [p for p, _d, _f in fs.walk(f"{server_url}/Full/")] == [
            f"{server_url}/Full/"
        ]
    with FileSystem(server_url, auth=AUTH, retry=False) as based:
        assert based.ls("Full/") == ["Full/f.txt"]
        assert based.ls(f"{server_url}/Full/") == ["Full/f.txt"]


def test_isdir_and_isfile_are_false_for_something_that_does_not_exist(
    server_url: str,
) -> None:
    with FileSystem(server_url, auth=AUTH, retry=False) as fs:
        assert fs.isdir("nope") is False
        assert fs.isfile("nope") is False
        assert fs.exists("nope") is False


# ---------------------------------------------------------------------------
# Downloads never destroy a local file that they then fail to replace
# ---------------------------------------------------------------------------


def test_a_failed_download_leaves_an_existing_local_file_alone(
    server_url: str, tmp_path: Path
) -> None:
    target = tmp_path / "keep.txt"
    target.write_bytes(b"precious")
    with FileSystem(server_url, auth=AUTH, retry=False) as fs:
        with pytest.raises(webdav.ResourceNotFoundError):
            fs.download_file("missing.txt", target, overwrite=True)
    assert target.read_bytes() == b"precious"
    assert [p.name for p in tmp_path.iterdir()] == ["keep.txt"]  # no stray partial file


def test_download_does_not_replace_an_existing_file_unless_told_to(
    server_url: str, tmp_path: Path
) -> None:
    target = tmp_path / "there.txt"
    target.write_bytes(b"local")
    with Session(server_url, auth=AUTH, retry=False) as session:
        fs = FileSystem.from_session(session)
        session.put("remote.txt", b"remote")
        with pytest.raises(FileExistsError):
            fs.download_file("remote.txt", target)
        assert target.read_bytes() == b"local"
        fs.download_file("remote.txt", target, overwrite=True)
        assert target.read_bytes() == b"remote"
        fresh = tmp_path / "fresh.txt"
        fs.download_file("remote.txt", fresh)
        assert fresh.read_bytes() == b"remote"


def test_a_download_does_not_follow_a_symlink_at_the_target(
    server_url: str, tmp_path: Path
) -> None:
    victim = tmp_path / "victim.txt"
    victim.write_bytes(b"do not touch")
    link = tmp_path / "link.txt"
    link.symlink_to(victim)
    with Session(server_url, auth=AUTH, retry=False) as session:
        fs = FileSystem.from_session(session)
        session.put("remote.txt", b"remote")
        with pytest.raises((FileExistsError, OSError)):
            fs.download_file("remote.txt", link, overwrite=True)
    assert victim.read_bytes() == b"do not touch"


@pytest.mark.parametrize("bad", [0, -1, 1.5, "8", True])
def test_chunk_size_must_be_a_positive_integer(bad: object) -> None:
    with pytest.raises(ValueError, match="chunk_size"):
        Session(chunk_size=bad)  # type: ignore[arg-type]


def test_a_per_call_chunk_size_is_validated_too(
    server_url: str, tmp_path: Path
) -> None:
    with Session(server_url, auth=AUTH, retry=False) as session:
        session.put("a.txt", b"x")
        with pytest.raises(ValueError, match="chunk_size"):
            FileSystem.from_session(session).download_file(
                "a.txt", tmp_path / "o.txt", chunk_size=0
            )


@pytest.mark.parametrize("mode", ["rb", "wb"])
def test_open_validates_chunk_size_up_front_like_the_other_transfers(
    server_url: str, mode: str
) -> None:
    """Unlike download_file/download_fileobj/upload_fileobj, open() used to pass
    chunk_size straight through unchecked - a read never validated it at all,
    and a write only found out after the whole body had been spooled."""
    with Session(server_url, auth=AUTH, retry=False) as session:
        session.put("a.txt", b"x")
        with pytest.raises(ValueError, match="chunk_size"):
            with FileSystem.from_session(session).open(  # type: ignore[call-overload]
                "a.txt", mode, chunk_size=0
            ):
                pass


def test_module_level_transfers_reject_unknown_arguments_and_forward_known_ones(
    server_url: str, tmp_path: Path
) -> None:
    source = tmp_path / "in.txt"
    source.write_bytes(b"payload")
    seen: list[int] = []
    webdav.upload_file(source, f"{server_url}/f.txt", auth=AUTH, callback=seen.append)
    assert sum(seen) == 7
    seen.clear()
    webdav.download_file(
        f"{server_url}/f.txt", tmp_path / "out.txt", auth=AUTH, callback=seen.append
    )
    assert sum(seen) == 7
    with pytest.raises(TypeError):
        webdav.download_file(f"{server_url}/f.txt", tmp_path / "x", auth=AUTH, bogus_kw=1)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        webdav.upload_file(source, f"{server_url}/g.txt", auth=AUTH, bogus=1)  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# A hostile server must not make the client raise anything but a WebDAVError, hand
# back a truncated download as a success, or walk it out of the requested subtree
# ---------------------------------------------------------------------------

from tests.scripted_server import DRIP, NO_CONTENT_LENGTH, Seen, always  # noqa: E402
from webdav.exceptions import (  # noqa: E402
    HTTPStatusError,
    MalformedResponseError,
    WebDAVError,
)

_FILE_PROPS = (
    b'<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response><d:href>/f</d:href>'
    b"<d:propstat><d:prop><d:resourcetype/></d:prop><d:status>HTTP/1.1 200 OK</d:status>"
    b"</d:propstat></d:response></d:multistatus>"
)


def _multistatus(*hrefs: str, collection: bool = True) -> bytes:
    kind = "<d:collection/>" if collection else ""
    responses = "".join(
        f"<d:response><d:href>{h}</d:href><d:propstat><d:prop><d:resourcetype>{kind}"
        "</d:resourcetype></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
        for h in hrefs
    )
    return f'<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">{responses}</d:multistatus>'.encode()


def _file_server(get_reply: "tuple[int, dict[str, str], bytes]"):  # type: ignore[no-untyped-def]
    def respond(seen: Seen) -> tuple[int, dict[str, str], bytes]:
        if seen.method == "PROPFIND":
            return 207, {"Content-Type": "application/xml"}, _FILE_PROPS
        return get_reply

    return respond


def test_a_416_on_the_first_get_is_an_error_not_an_empty_download() -> None:
    import io

    with scripted_server(_file_server((416, {}, b""))) as (url, _rec):
        with pytest.raises(HTTPStatusError):
            FileSystem(retry=False).download_fileobj(f"{url}/f", io.BytesIO())


@pytest.mark.parametrize("status", [403, 404])
def test_a_failed_download_gives_its_connection_back(status: int) -> None:
    """The error response of a streamed GET is not read; nothing may keep its connection checked out."""
    import io

    with scripted_server(_file_server((status, {}, b"not for you"))) as (url, _rec):
        with pytest.raises(HTTPStatusError) as caught:
            FileSystem(retry=False).download_fileobj(f"{url}/f", io.BytesIO())
    assert caught.value.status_code == status
    assert caught.value.response.raw.closed
    assert caught.value.error_codes == frozenset()  # still usable: no error body, no codes


def test_a_truncated_download_is_never_reported_as_complete() -> None:
    """Server promises 1000 bytes, sends 100, then answers the resume with 416."""
    import io

    calls = {"n": 0}

    def respond(seen: Seen) -> tuple[int, dict[str, str], bytes]:
        if seen.method == "PROPFIND":
            return 207, {"Content-Type": "application/xml"}, _FILE_PROPS
        calls["n"] += 1
        if calls["n"] == 1:
            return (
                200,
                {"Content-Length": "1000", "ETag": '"e"', NO_CONTENT_LENGTH: "1"},
                b"x" * 100,
            )
        return 416, {"Content-Range": "bytes */1000"}, b""

    out = io.BytesIO()
    with (
        scripted_server(respond) as (url, _rec),
        pytest.raises((WebDAVError, requests.RequestException)),
    ):
        FileSystem(retry=False).download_fileobj(f"{url}/f", out)
    assert len(out.getvalue()) < 1000


@pytest.mark.parametrize("length", ["²", "9" * 5000, "-5", "1e3", "０"])
def test_a_hostile_content_length_never_raises_a_bare_valueerror(length: str) -> None:
    reply = (200, {"Content-Length": length, NO_CONTENT_LENGTH: "1"}, b"hello")
    with scripted_server(always(reply)) as (url, _rec):
        # Refusing the response is fine, and so is a network-level error;
        # a bare ValueError (or anything else) escaping is what must not happen.
        with contextlib.suppress(WebDAVError, requests.RequestException):
            Session(retry=False).get(f"{url}/f")


@pytest.mark.parametrize(
    "timeout", ["Second-²", "Second-" + "9" * 5000, "Second--1", "Bogus"]
)
def test_a_hostile_lock_timeout_header_does_not_break_locking(timeout: str) -> None:
    body = (
        b'<?xml version="1.0"?><d:prop xmlns:d="DAV:"><d:lockdiscovery><d:activelock>'
        b"<d:locktype><d:write/></d:locktype><d:lockscope><d:exclusive/></d:lockscope>"
        b"<d:depth>infinity</d:depth><d:locktoken><d:href>opaquelocktoken:ok</d:href></d:locktoken>"
        b"</d:activelock></d:lockdiscovery></d:prop>"
    )

    def respond(seen: Seen) -> tuple[int, dict[str, str], bytes]:
        if seen.method == "LOCK":
            return 200, {"Timeout": timeout, "Lock-Token": "<opaquelocktoken:ok>"}, body
        return 204, {}, b""

    with (
        scripted_server(respond) as (url, _rec),
        FileSystem(retry=False).locked(f"{url}/f") as lock,
    ):
        assert lock.token == "opaquelocktoken:ok"


@pytest.mark.parametrize(
    "token", ["x>) (<y> Not <z", "tok en", "täg", "aĀb", 'a"b', "a<b", "a\\b"]
)
def test_a_lock_token_that_could_change_the_if_header_is_refused(token: str) -> None:
    body = (
        '<?xml version="1.0"?><d:prop xmlns:d="DAV:"><d:lockdiscovery><d:activelock>'
        "<d:locktype><d:write/></d:locktype><d:lockscope><d:exclusive/></d:lockscope>"
        f"<d:depth>infinity</d:depth><d:locktoken><d:href>{token}</d:href></d:locktoken>"
        "</d:activelock></d:lockdiscovery></d:prop>"
    ).encode()
    with scripted_server(always((200, {}, body))) as (url, _rec):
        with pytest.raises(WebDAVError), FileSystem(retry=False).locked(f"{url}/f"):
            pass


@pytest.mark.parametrize("encoding", ["x-bogus", "utf-16", "idna", "punycode", "rot13"])
def test_a_bogus_xml_encoding_declaration_is_a_webdav_error(encoding: str) -> None:
    body = f'<?xml version="1.0" encoding="{encoding}"?><d:multistatus xmlns:d="DAV:"/>'.encode()
    with scripted_server(always((207, {}, body))) as (url, _rec):
        with pytest.raises(MalformedResponseError):
            FileSystem(retry=False).ls(f"{url}/dir")
        response = Session(retry=False).get(f"{url}/x")
        assert response.status_code == 207  # and an error response's <error> body:
    with scripted_server(always((409, {}, body))) as (url, _rec):
        with pytest.raises(HTTPStatusError) as excinfo:
            FileSystem(retry=False).mkdir(f"{url}/d")
        assert excinfo.value.error_codes == frozenset()


def test_ls_refuses_entries_outside_the_listed_directory() -> None:
    body = _multistatus("/a/b/", "/a/", "/", "/secret/", "/a/b/ok.txt")
    with scripted_server(always((207, {}, body))) as (url, _rec):
        with pytest.raises(MalformedResponseError, match="outside"):
            FileSystem(retry=False).ls(f"{url}/a/b")


def test_an_encoded_slash_in_an_href_is_refused_not_turned_into_a_path_separator() -> (
    None
):
    body = _multistatus("/a/", "/a/x%2fy/")
    with (
        scripted_server(always((207, {}, body))) as (url, _rec),
        pytest.raises(MalformedResponseError, match="encoded path separator"),
    ):
        FileSystem(retry=False).ls(f"{url}/a")


def test_a_control_character_in_an_href_is_refused() -> None:
    """``\\x7f`` (and most other control characters) survive well-formed XML
    untouched - unlike a redirect Location, nothing upstream already refuses
    them for an href, so _check_href must."""
    body = _multistatus("/a/", "/a/x\x7fy.txt")
    with (
        scripted_server(always((207, {}, body))) as (url, _rec),
        pytest.raises(MalformedResponseError, match="control character"),
    ):
        FileSystem(retry=False).ls(f"{url}/a")


def test_a_backslash_in_an_href_is_still_an_ordinary_character() -> None:
    """Unlike the control-character check above, a backslash is deliberately
    still accepted here - an ordinary POSIX file-name character, not part of
    an authority a parser could misread (see test_second_round.py's
    test_a_backslash_in_a_name_is_an_ordinary_character_on_posix)."""
    body = _multistatus("/a/", "/a/x\\y.txt")
    with scripted_server(always((207, {}, body))) as (url, _rec):
        assert FileSystem(retry=False).ls(f"{url}/a") == ["a/x\\y.txt"]


def test_walk_stops_a_server_that_invents_a_new_directory_at_every_level() -> None:
    def respond(seen: Seen) -> tuple[int, dict[str, str], bytes]:
        path = seen.path.rstrip("/")
        return 207, {}, _multistatus(f"{path}/", f"{path}/d/")

    with scripted_server(respond) as (url, rec):
        with pytest.raises(webdav.ClientError, match="walk"):
            for _ in FileSystem(retry=False).walk(url):
                pass
    assert len(rec.requests) < 1000


def test_a_response_that_drips_forever_hits_a_total_deadline() -> None:
    import time

    reply = (200, {DRIP: "0.05", NO_CONTENT_LENGTH: "1"}, b"x" * 400)
    with scripted_server(always(reply)) as (url, _rec):
        session = Session(retry=False)
        session.max_response_time = 0.5
        started = time.monotonic()
        with pytest.raises(webdav.ClientError, match="time"):
            session.get(f"{url}/f")
        assert time.monotonic() - started < 5


def test_a_multistatus_with_absurdly_many_responses_is_refused() -> None:
    body = _multistatus(*[f"/d/{i}" for i in range(300)])
    from webdav.dav import multistatus

    old = multistatus.MAX_RESPONSES
    multistatus.MAX_RESPONSES = 100
    try:
        with scripted_server(always((207, {}, body))) as (url, _rec):
            with pytest.raises(MalformedResponseError, match="too many"):
                FileSystem(retry=False).ls(f"{url}/d")
    finally:
        multistatus.MAX_RESPONSES = old


@pytest.mark.parametrize(
    "name", ["a%20b.txt", "100%.txt", "sp ace.txt", "ünï.txt", "h#x.txt"]
)
def test_move_and_copy_destinations_are_encoded_like_paths(
    server_url: str, storage_dir: Path, name: str
) -> None:
    """(Names with ``?``/``;`` are left out only because wsgidav re-splits a decoded Destination.)"""
    with Session(server_url, auth=AUTH, retry=False) as session:
        session.put(name, b"data")
        assert session.copy(name, destination="copy-" + name).status_code == 201
        assert session.move(name, destination="moved-" + name).status_code == 201
        assert sorted(os.listdir(storage_dir)) == sorted(
            ["copy-" + name, "moved-" + name]
        )
