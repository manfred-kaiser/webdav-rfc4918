"""The requests-shaped API: ``Session``, ``Response`` - against a real server."""

import copy
import gzip
import pickle
import warnings
from pathlib import Path
from typing import Any

import pytest
import requests

import webdav
from tests.scripted_server import NO_CONTENT_LENGTH, OK, Seen, always, scripted_server
from tests.server import AUTH
from webdav import (
    FileSystem,
    RedirectPolicy,
    Resource,
    ResourceNotFoundError,
    Response,
    Session,
    exceptions,
)
from webdav.exceptions import InsecureTransportWarning, MultiStatusError


def test_session_verbs_roundtrip(server_url: str) -> None:
    # No module-level one-off for any of these: a Session is what gives you
    # the raw Response, for all of them, not just move/copy - see webdav.fs.api.
    verbs = Session(auth=AUTH)
    assert verbs.mkcol(f"{server_url}/docs/").status_code == 201
    assert verbs.put(f"{server_url}/docs/a.txt", data=b"hello").status_code == 201
    assert verbs.get(f"{server_url}/docs/a.txt").content == b"hello"
    assert verbs.head(f"{server_url}/docs/a.txt").headers["Content-Length"] == "5"

    moved = verbs.move(
        f"{server_url}/docs/a.txt",
        destination=f"{server_url}/docs/b.txt",
        overwrite=False,
    )
    assert moved.status_code == 201
    copied = verbs.copy(
        f"{server_url}/docs/b.txt",
        destination=f"{server_url}/docs/c.txt",
        depth=0,
    )
    assert copied.status_code == 201

    listing = verbs.propfind(f"{server_url}/docs/", depth=1)
    assert listing.status_code == 207
    hrefs = {r.href for r in listing.multistatus.responses.values()}
    assert {"/docs/b.txt", "/docs/c.txt"} <= hrefs

    assert verbs.delete(f"{server_url}/docs/").status_code == 204
    assert "DAV" in verbs.options(server_url).headers
    verbs.close()


def test_module_level_convenience_matches_the_verbs(server_url: str) -> None:
    auth: dict[str, Any] = {"auth": AUTH}
    webdav.mkdir(f"{server_url}/docs", **auth)
    with webdav.open(f"{server_url}/docs/a.txt", "wb", **auth) as fobj:
        fobj.write(b"hello")

    assert webdav.exists(f"{server_url}/docs/a.txt", **auth)
    assert not webdav.exists(f"{server_url}/docs/nope.txt", **auth)
    assert webdav.isdir(f"{server_url}/docs", **auth)
    assert webdav.isfile(f"{server_url}/docs/a.txt", **auth)
    assert webdav.ls(f"{server_url}/docs", **auth) == ["docs/a.txt"]
    assert webdav.info(f"{server_url}/docs/a.txt", **auth).size == 5
    with webdav.open(f"{server_url}/docs/a.txt", "rb", **auth) as fobj:
        assert fobj.read() == b"hello"

    webdav.remove(f"{server_url}/docs", **auth)
    assert not webdav.exists(f"{server_url}/docs", **auth)


def test_upload_and_download_file(server_url: str, tmp_path: Path) -> None:
    source = tmp_path / "in.txt"
    source.write_bytes(b"payload")
    target = tmp_path / "out.txt"
    webdav.upload_file(source, f"{server_url}/f.txt", auth=AUTH)
    webdav.download_file(f"{server_url}/f.txt", target, auth=AUTH)
    assert target.read_bytes() == b"payload"


def test_response_is_a_requests_response_and_its_errors_are_requests_errors(
    server_url: str,
) -> None:
    response = Session(auth=AUTH).get(f"{server_url}/missing.txt")
    assert isinstance(response, requests.Response)
    assert isinstance(response, Response)
    assert response.status_code == 404
    assert response.ok is False

    with pytest.raises(ResourceNotFoundError) as excinfo:
        response.raise_for_status()
    assert isinstance(excinfo.value, requests.HTTPError)
    assert excinfo.value.response is response


def test_raise_on_error_option(server_url: str) -> None:
    with pytest.raises(requests.HTTPError):
        Session(auth=AUTH, raise_on_error=True).get(f"{server_url}/missing.txt")


def test_session_with_base_url_takes_paths(server_url: str) -> None:
    with Session(base_url=server_url) as session:
        session.auth = AUTH
        assert session.mkcol("/docs").status_code == 201
        assert session.put("/docs/a.txt", data=b"x").status_code == 201
        assert session.get("docs/a.txt").content == b"x"
        session.move("/docs/a.txt", destination="/docs/b.txt", overwrite=True)
        assert session.get("/docs/b.txt").status_code == 200
        assert session.get(f"{server_url}/docs/b.txt").status_code == 200


def test_session_locks_and_unlocks(server_url: str) -> None:
    with Session(base_url=server_url) as session:
        session.auth = AUTH
        session.put("/f.txt", data=b"x")
        response = session.lock("/f.txt", owner="me", lock_timeout=60)
        assert response.status_code == 200
        lock = response.active_lock
        assert lock.token.startswith("opaquelocktoken:")

        # Without the token the resource is locked for everyone else...
        assert session.put("/f.txt", data=b"y").status_code == 423
        # ...with it (registered, so it is attached automatically) it is not.
        session.locks.add(session.resolve_url("/f.txt"), lock.token, "infinity")
        assert session.put("/f.txt", data=b"y").status_code in (200, 204)
        session.locks.discard(session.resolve_url("/f.txt"), lock.token, "infinity")
        assert session.unlock("/f.txt", lock.token).status_code == 204


def test_invalid_depths_are_rejected_before_anything_is_sent() -> None:
    session = Session()
    with pytest.raises(ValueError, match="Depth"):
        session.propfind("http://unused.invalid/", depth=2)
    with pytest.raises(ValueError, match="Depth"):
        session.copy("http://unused.invalid/a", destination="/b", depth=1)
    with pytest.raises(ValueError, match="Depth"):
        session.lock("http://unused.invalid/a", depth=1)


def test_verb_headers_on_the_wire() -> None:
    with scripted_server(always(OK)) as (url, rec):
        session = Session()
        session.copy(f"{url}/a", destination=f"{url}/b", overwrite=False, depth=0)
        session.move(f"{url}/a", destination=f"{url}/b")
        session.propfind(f"{url}/a", depth=None)
        session.propfind(f"{url}/a", depth=1)
        session.unlock(f"{url}/a", "opaquelocktoken:t")
        session.lock(f"{url}/a", refresh="opaquelocktoken:t", lock_timeout=30)

    copy, move, propfind, propfind_one, unlock, refresh = rec.requests
    assert copy.headers["destination"] == f"{url}/b"
    assert copy.headers["overwrite"] == "F"
    assert copy.headers["depth"] == "0"
    # Overwrite defaults to F: RFC 4918's own default (T) replaces a destination without a word.
    assert move.headers["overwrite"] == "F"
    # depth=None sends no Depth header at all: RFC 4918 9.1's "infinity" default is then the server's call.
    assert "depth" not in propfind.headers
    assert propfind_one.headers["depth"] == "1"
    assert unlock.headers["lock-token"] == "<opaquelocktoken:t>"
    assert refresh.headers["if"] == "(<opaquelocktoken:t>)"
    assert refresh.headers["timeout"] == "Second-30"
    assert refresh.body == b""


def test_a_callers_headers_take_precedence_over_the_convenience_kwargs() -> None:
    with scripted_server(always(OK)) as (url, rec):
        Session().copy(
            f"{url}/a",
            destination=f"{url}/b",
            overwrite=False,
            headers={"Overwrite": "T"},
        )

    assert rec.requests[0].headers["overwrite"] == "T"


def test_multistatus_failure_raises_for_writes_but_not_for_propfind() -> None:
    body = (
        b'<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response>'
        b"<d:href>/dir/locked.txt</d:href><d:status>HTTP/1.1 423 Locked</d:status>"
        b"</d:response></d:multistatus>"
    )

    def respond(_r: Seen) -> tuple[int, dict[str, str], bytes]:
        return 207, {"Content-Type": "application/xml"}, body

    with scripted_server(respond) as (url, _rec):
        session = Session()
        with pytest.raises(MultiStatusError):
            session.delete(f"{url}/dir/").raise_for_status()
        propfind = session.propfind(f"{url}/dir/", depth=1)
        propfind.raise_for_status()  # a per-resource status in a PROPFIND is data
        assert propfind.multistatus.responses


def test_history_of_a_followed_redirect_is_kept() -> None:
    def respond(r: Seen) -> tuple[int, dict[str, str], bytes]:
        if r.path == "/a":
            return 301, {"Location": "/b"}, b""
        return 200, {}, b"done"

    with scripted_server(respond) as (url, _rec):
        response = Session().get(f"{url}/a")

    assert response.content == b"done"
    assert [r.status_code for r in response.history] == [301]
    assert isinstance(response.history[0], Response)


# ---------------------------------------------------------------------------
# Retry, Depth and the URL mode of the file-system operations
# ---------------------------------------------------------------------------


def _flaky(failures: int, status: int = 503) -> "tuple[Any, dict[str, int]]":
    counter = {"n": 0}

    def respond(_seen: Seen) -> tuple[int, dict[str, str], bytes]:
        counter["n"] += 1
        if counter["n"] <= failures:
            return status, {}, b""
        return 204, {}, b""

    return respond, counter


def test_transient_failures_of_safe_verbs_are_retried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("webdav.transport.retry.BACKOFF", 0)
    respond, counter = _flaky(2)
    with scripted_server(respond) as (url, _rec):
        response = Session().propfind(f"{url}/a", depth=0)

    assert response.status_code == 204
    assert counter["n"] == 3


def test_a_put_is_never_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("webdav.transport.retry.BACKOFF", 0)
    respond, counter = _flaky(1)
    with scripted_server(respond) as (url, _rec):
        response = Session().put(f"{url}/a", data=b"x")

    assert response.status_code == 503
    assert counter["n"] == 1


def test_lock_and_unlock_are_never_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    """A lost LOCK response that is retried would leave an orphaned lock behind."""
    monkeypatch.setattr("webdav.transport.retry.BACKOFF", 0)
    respond, counter = _flaky(1)
    with scripted_server(respond) as (url, _rec):
        assert Session().lock(f"{url}/a").status_code == 503
    assert counter["n"] == 1


@pytest.mark.parametrize("verb", ["delete", "mkcol", "proppatch"])
def test_a_write_is_never_retried(monkeypatch: pytest.MonkeyPatch, verb: str) -> None:
    """If the server acted before the connection broke, the retry reports the opposite."""
    monkeypatch.setattr("webdav.transport.retry.BACKOFF", 0)
    respond, counter = _flaky(1)
    with scripted_server(respond) as (url, _rec):
        extra = {"set_props": {"displayname": "x"}} if verb == "proppatch" else {}
        response = getattr(Session(), verb)(f"{url}/a", **extra)

    assert response.status_code == 503
    assert counter["n"] == 1


def test_running_out_of_retries_returns_the_last_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("webdav.transport.retry.BACKOFF", 0)
    respond, counter = _flaky(99)
    with scripted_server(respond) as (url, _rec):
        response = Session().get(f"{url}/a")

    assert response.status_code == 503
    assert counter["n"] == 3
    with pytest.raises(requests.HTTPError):
        response.raise_for_status()


def test_retry_can_be_disabled() -> None:
    respond, counter = _flaky(1)
    with scripted_server(respond) as (url, _rec):
        assert Session(retry=False).delete(f"{url}/a").status_code == 503
    assert counter["n"] == 1


def test_exists_and_info_send_depth_zero() -> None:
    """Without it a server treats the PROPFIND as Depth: infinity (RFC 4918 9.1)."""
    body = (
        b'<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response>'
        b"<d:href>/dir/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/>"
        b"</d:resourcetype></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>"
        b"</d:response></d:multistatus>"
    )
    with scripted_server(always((207, {}, body))) as (url, rec):
        fs = FileSystem()
        assert fs.exists(f"{url}/dir/")
        fs.info(f"{url}/dir/")
        fs.get_props(f"{url}/dir/")

    assert [r.headers["depth"] for r in rec.requests] == ["0", "0", "0"]


def test_operations_take_full_urls_without_a_base_url(server_url: str) -> None:
    with FileSystem(auth=AUTH) as fs:
        fs.mkdir(f"{server_url}/docs")
        assert fs.isdir(f"{server_url}/docs")
        assert fs.ls(f"{server_url}/docs") == []
        with pytest.raises(webdav.ClientError, match="full http"):
            fs.exists("docs")


def test_base_url_and_full_url_give_the_same_names(server_url: str) -> None:
    with (
        Session(auth=AUTH) as plain_session,
        Session(server_url, auth=AUTH) as based_session,
    ):
        plain, based = FileSystem.from_session(plain_session), FileSystem.from_session(
            based_session
        )
        plain.mkdir(f"{server_url}/docs")
        plain_session.put(f"{server_url}/docs/a.txt", data=b"x")
        assert plain.ls(f"{server_url}/docs") == ["docs/a.txt"]
        assert based.ls("docs") == ["docs/a.txt"]
        assert based.ls(f"{server_url}/docs") == ["docs/a.txt"]


def test_features_are_probed_once_per_origin() -> None:
    with scripted_server(
        always((200, {"DAV": "1, 2", "Accept-Ranges": "bytes"}, b""))
    ) as (
        url,
        rec,
    ):
        session = Session()
        assert session.features_for(f"{url}/a").supports_ranges
        assert "2" in session.features_for(f"{url}/b").dav_compliances

    assert [r.method for r in rec.requests] == ["OPTIONS"]


# ---------------------------------------------------------------------------
# Bounded reads, XML bodies, conditional writes, pickling, walk, open("w")
# ---------------------------------------------------------------------------


def test_a_response_without_content_length_is_still_bounded() -> None:
    reply = (207, {NO_CONTENT_LENGTH: "1"}, b"x" * 5000)
    with scripted_server(always(reply)) as (url, _rec):
        with pytest.raises(webdav.ClientError, match="exceeds the configured limit"):
            Session(max_response_size=1000).propfind(url, depth=0)
        assert (
            Session(max_response_size=10_000).propfind(url, depth=0).content
            == b"x" * 5000
        )


def test_a_gzip_bomb_is_stopped_by_its_decoded_size() -> None:
    bomb = gzip.compress(b"0" * 5_000_000)
    assert len(bomb) < 10_000
    reply = (207, {"Content-Encoding": "gzip"}, bomb)
    with (
        scripted_server(always(reply)) as (url, _rec),
        pytest.raises(webdav.ClientError, match="exceeds the configured limit"),
    ):
        Session(max_response_size=1_000_000).propfind(url, depth=0)


def test_a_streamed_response_is_not_read_or_capped() -> None:
    reply = (200, {NO_CONTENT_LENGTH: "1"}, b"x" * 5000)
    with scripted_server(always(reply)) as (url, _rec):
        response = Session(max_response_size=10).get(f"{url}/f", stream=True)
        assert b"".join(response.iter_content(1024)) == b"x" * 5000


def test_xml_bodies_get_a_content_type_and_are_sent_as_utf8() -> None:
    with scripted_server(always(OK)) as (url, rec):
        session = Session(retry=False)
        session.lock(f"{url}/a", owner="Jürgen 🙂")
        session.propfind(url, props=["etag"], depth=0)
        session.proppatch(url, set_props={"displayname": "ü"})
        session.mkcol(f"{url}/dir", data="<x>ü</x>")

    lock, propfind, proppatch, mkcol = rec.requests
    for seen in (lock, propfind, proppatch, mkcol):
        assert seen.headers["content-type"] == "application/xml; charset=utf-8"
    assert "Jürgen 🙂".encode() in lock.body
    assert b"getetag" in propfind.body
    assert b"displayname" in proppatch.body
    assert mkcol.path == "/dir/"


def test_a_callers_content_type_is_kept() -> None:
    with scripted_server(always(OK)) as (url, rec):
        Session().propfind(url, b"<a/>", depth=0, headers={"Content-Type": "text/xml"})

    assert rec.requests[0].headers["content-type"] == "text/xml"
    assert rec.requests[0].body == b"<a/>"


def test_propfind_and_proppatch_bodies_are_exclusive_with_their_builders() -> None:
    session = Session()
    with pytest.raises(ValueError, match="not both"):
        session.propfind("http://unused.invalid/", b"<x/>", depth=0, props=["etag"])
    with pytest.raises(ValueError, match="not both"):
        session.proppatch("http://unused.invalid/", b"<x/>", set_props={"a": "b"})


def test_conditional_writes() -> None:
    with scripted_server(always(OK)) as (url, rec):
        session = Session()
        session.put(f"{url}/a", b"x", if_match='"abc"')
        session.put(f"{url}/b", b"x", overwrite=False)
        session.put(f"{url}/c", b"x")
        session.delete(f"{url}/d", if_match='"abc"')

    a, b, c, d = rec.requests
    assert a.headers["if-match"] == '"abc"'
    assert b.headers["if-none-match"] == "*"
    assert "if-match" not in c.headers
    assert "if-none-match" not in c.headers
    assert d.headers["if-match"] == '"abc"'


def test_weak_etags_and_contradictory_conditions_are_refused() -> None:
    session = Session()
    with pytest.raises(ValueError, match="weak"):
        session.put("http://unused.invalid/a", b"x", if_match='W/"abc"')
    with pytest.raises(ValueError, match="weak"):
        session.delete("http://unused.invalid/a", if_match='W/"abc"')
    with pytest.raises(ValueError, match="forbids"):
        session.put("http://unused.invalid/a", b"x", if_match='"a"', overwrite=False)


def test_put_overwrite_false_is_atomic_on_a_real_server(server_url: str) -> None:
    with Session(server_url, auth=AUTH) as session:
        assert session.put("/a.txt", b"one", overwrite=False).status_code == 201
        assert session.put("/a.txt", b"two", overwrite=False).status_code == 412
        assert session.get("/a.txt").content == b"one"


def test_a_session_survives_pickling_and_copying() -> None:
    session = Session(
        "https://dav.example/root",
        auth=("u", "p"),
        redirect_policy=RedirectPolicy.WHITELIST,
        trusted_redirect_origins=["https://storage.example"],
        max_response_size=123,
        chunk_size=456,
        retry=False,
        raise_on_error=True,
        headers={"X-Team": "a"},
    )
    session.locks.add("https://dav.example/root/f", "opaquelocktoken:t", "0")

    for clone in (
        pickle.loads(pickle.dumps(session)),  # noqa: S301
        copy.copy(session),
    ):
        assert clone.base_url == "https://dav.example/root"
        assert clone.auth == ("u", "p")
        assert clone.redirect_policy is RedirectPolicy.WHITELIST
        assert clone.max_response_size == 123
        assert clone.chunk_size == 456
        assert clone.raise_on_error is True
        assert clone.headers["X-Team"] == "a"
        assert clone._is_trusted_redirect_target("https://storage.example/x")
        assert not clone._is_trusted_redirect_target("https://evil.example/x")
        # A lock belongs to the server, not to a copy of the object.
        assert not clone.locks


def test_a_pickled_session_still_works(server_url: str) -> None:
    clone = pickle.loads(pickle.dumps(Session(server_url, auth=AUTH)))  # noqa: S301
    assert clone.put("/a.txt", b"x").status_code == 201
    assert FileSystem.from_session(clone).ls("/") == ["a.txt"]


def test_walk(server_url: str) -> None:
    with Session(server_url, auth=AUTH) as session:
        fs = FileSystem.from_session(session)
        fs.mkdir("a")
        fs.mkdir("a/b")
        fs.mkdir("c")
        session.put("/top.txt", b"x")
        session.put("/a/one.txt", b"x")
        session.put("/a/b/two.txt", b"x")

        walked = {p: (sorted(d), sorted(f)) for p, d, f in fs.walk("/")}
        assert walked == {
            "/": (["a", "c"], ["top.txt"]),
            "a": (["a/b"], ["a/one.txt"]),
            "a/b": ([], ["a/b/two.txt"]),
            "c": ([], []),
        }

        assert [p for p, _d, _f in fs.walk("/", max_depth=0)] == ["/"]

        pruned = []
        for path, dirs, _files in fs.walk("/"):
            pruned.append(path)
            dirs[:] = [d for d in dirs if d != "a"]
            assert all(isinstance(d, Resource) for d in dirs)
        assert sorted(pruned) == ["/", "c"]


def test_walk_members_are_what_ls_returns(server_url: str) -> None:
    with Session(server_url, auth=AUTH) as session:
        fs = FileSystem.from_session(session)
        fs.mkdir("/a")
        session.put("/a/one.txt", b"x")
        fs.mkdir("/a/b")
        (path, dirs, files), *_ = fs.walk("/a")
        listed = fs.ls("/a")
        assert (path, dirs + files) == ("/a", listed)
        assert [r.as_dict() for r in dirs + files] == [r.as_dict() for r in listed]


def test_walk_with_full_urls(server_url: str) -> None:
    with Session(auth=AUTH) as session:
        fs = FileSystem.from_session(session)
        fs.mkdir(f"{server_url}/a")
        session.put(f"{server_url}/a/one.txt", b"x")
        paths = [p for p, _d, _f in fs.walk(server_url)]
        assert paths == [server_url, f"{server_url}/a"]


def test_open_for_writing(server_url: str) -> None:
    with Session(server_url, auth=AUTH) as session:
        fs = FileSystem.from_session(session)
        with fs.open("t.txt", "w") as fobj:
            fobj.write("héllo ")
            fobj.write("wörld")
        with fs.open("b.bin", "wb") as bobj:
            bobj.write(b"\x00\x01")
        assert session.get("/t.txt").content == "héllo wörld".encode()
        assert session.get("/b.bin").content == b"\x00\x01"

        with (
            pytest.raises(webdav.ResourceAlreadyExistsError),
            fs.open("t.txt", "x") as fobj,
        ):
            fobj.write("nope")
        assert session.get("/t.txt").content == "héllo wörld".encode()

        with fs.open("new.txt", "xb") as bobj:
            bobj.write(b"fresh")
        assert session.get("/new.txt").content == b"fresh"


def _write_then_fail(fs: FileSystem) -> None:
    with fs.open("keep.txt", "wb") as bobj:
        bobj.write(b"half")
        raise RuntimeError


def test_a_failed_write_does_not_replace_the_resource(server_url: str) -> None:
    with Session(server_url, auth=AUTH) as session:
        session.put("/keep.txt", b"original")
        with pytest.raises(RuntimeError):
            _write_then_fail(FileSystem.from_session(session))
        assert session.get("/keep.txt").content == b"original"


def test_open_rejects_unknown_modes() -> None:
    fs = FileSystem("http://x.invalid")
    with (
        pytest.raises(ValueError, match="unsupported mode"),
        fs.open("a", "rw"),  # type: ignore[call-overload]
    ):
        pass


def test_ls_entries_have_the_documented_keys(server_url: str) -> None:
    with Session(server_url, auth=AUTH) as session:
        fs = FileSystem.from_session(session)
        session.put("/a.txt", b"12345")
        (entry,) = fs.ls("/")
        assert entry == "a.txt"
        assert entry.name == "a.txt"
        assert entry.size == 5
        assert entry.is_dir is False
        assert fs.info("a.txt").as_dict() == entry.as_dict()


def test_credentials_over_plain_http_to_a_remote_host_warn_once() -> None:
    session = Session(auth=("u", "p"), retry=False)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        session._warn_if_insecure("http://dav.example.org/a", {})
        session._warn_if_insecure("http://dav.example.org/b", {})
    assert [w.category for w in caught] == [InsecureTransportWarning]
    assert "plain http" in str(caught[0].message)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/a",
        "http://localhost/a",
        "http://[::1]/a",
        "https://dav.example.org/a",
    ],
)
def test_no_warning_for_loopback_or_https(url: str) -> None:
    session = Session(auth=("u", "p"))
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        session._warn_if_insecure(url, {})


def test_no_warning_without_credentials() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        Session()._warn_if_insecure("http://dav.example.org/a", {})


def test_response_errors_carry_the_path() -> None:
    with scripted_server(always((404, {}, b""))) as (url, _rec):
        response = Session().get(f"{url}/some/missing%20file.txt")
    with pytest.raises(ResourceNotFoundError, match=r"some/missing file\.txt"):
        response.raise_for_status()


# ---------------------------------------------------------------------------
# Secure, explicit defaults: nothing dangerous happens because an argument was left out
# ---------------------------------------------------------------------------


def test_propfind_makes_you_say_which_depth() -> None:
    with pytest.raises(TypeError, match="depth"):
        Session().propfind("http://unused.invalid/")  # type: ignore[call-arg]


def test_depth_none_is_the_only_way_to_send_no_depth_header() -> None:
    with scripted_server(always(OK)) as (url, rec):
        Session().propfind(url, depth=None)
        Session().propfind(url, depth="infinity")
        Session().propfind(url, depth=0)

    assert [r.headers.get("depth") for r in rec.requests] == [None, "infinity", "0"]


def test_copy_and_move_do_not_overwrite_unless_told_to() -> None:
    with scripted_server(always(OK)) as (url, rec):
        session = Session()
        session.copy(f"{url}/a", destination=f"{url}/b")
        session.move(f"{url}/a", destination=f"{url}/b")
        session.copy(f"{url}/a", destination=f"{url}/b", overwrite=True)
        session.move(f"{url}/a", destination=f"{url}/b", overwrite=None)

    assert [r.headers.get("overwrite") for r in rec.requests] == ["F", "F", "T", None]


def test_copy_onto_an_existing_destination_fails_by_default(server_url: str) -> None:
    with Session(server_url, auth=AUTH) as session:
        session.put("/a.txt", b"a")
        session.put("/b.txt", b"b")
        assert session.copy("/a.txt", destination="/b.txt").status_code == 412
        assert session.get("/b.txt").content == b"b"
        assert (
            session.copy("/a.txt", destination="/b.txt", overwrite=True).status_code
            == 204
        )
        assert session.get("/b.txt").content == b"a"


def test_a_lock_is_finite_unless_you_ask_for_infinite() -> None:
    with scripted_server(always(OK)) as (url, rec):
        session = Session()
        session.lock(f"{url}/a")
        session.lock(f"{url}/a", lock_timeout=None)
        session.lock(f"{url}/a", lock_timeout=30)

    assert [r.headers["timeout"] for r in rec.requests] == [
        "Second-600",
        "Infinite",
        "Second-30",
    ]


def test_secondary_parameters_must_be_named() -> None:
    """A bare ``True``/``False`` (or a number) in a call says nothing: name it."""
    fs = FileSystem("http://unused.invalid")
    with pytest.raises(TypeError):
        fs.ls("/", False)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        fs.upload_file("a", "b", True)  # type: ignore[misc]
    with pytest.raises(TypeError):
        fs.upload_fileobj(None, "b", True)  # type: ignore[arg-type,misc]
    with pytest.raises(TypeError):
        fs.locked("/a", "shared")  # type: ignore[misc]
    with pytest.raises(TypeError):
        fs.refresh_lock("/a", "tok", 30)  # type: ignore[misc]
    with pytest.raises(TypeError):
        list(fs.walk("/", 1))  # type: ignore[misc]
    with pytest.raises(TypeError):
        fs.get_props("/a", None, True)  # type: ignore[misc]


def test_disabling_certificate_verification_in_the_constructor_warns_loudly() -> None:
    with pytest.warns(exceptions.TLSHardeningDisabledWarning, match="verify=False"):
        assert Session(verify=False).verify is False  # type: ignore[arg-type]
    assert Session(verify=True).verify is True
    assert Session(verify="/etc/ssl/ca.pem").verify == "/etc/ssl/ca.pem"


def test_a_locked_resource_is_not_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    """A lock does not disappear in the seconds a retry would wait."""
    monkeypatch.setattr("webdav.transport.retry.BACKOFF", 0)
    respond, counter = _flaky(99, status=423)
    with scripted_server(respond) as (url, _rec):
        assert Session().delete(f"{url}/a").status_code == 423
    assert counter["n"] == 1
