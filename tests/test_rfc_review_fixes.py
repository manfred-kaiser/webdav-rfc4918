"""Regression tests for the findings of the RFC 4918 review of 2026-10-13."""

import io

import pytest

from tests.scripted_server import OK, Reply, Seen, always, scripted_server
from webdav import FileSystem, Session, exceptions
from webdav.dav.locks import LockRegistry
from webdav.dav.multistatus import MultiStatusResponse
from webdav.dav.properties import build_proppatch_body

_NS = 'xmlns:d="DAV:"'
_DEEP = "http://h/dav"


def _multistatus(*responses: str) -> bytes:
    return (
        f'<?xml version="1.0"?><d:multistatus {_NS}>{"".join(responses)}</d:multistatus>'
    ).encode()


def _status_only(href: str, status: str) -> str:
    return f"<d:response><d:href>{href}</d:href><d:status>HTTP/1.1 {status}</d:status></d:response>"


def _props(href: str, *, directory: bool = False, size: int = 3) -> str:
    kind = "<d:collection/>" if directory else ""
    return (
        f"<d:response><d:href>{href}</d:href><d:propstat><d:prop>"
        f"<d:resourcetype>{kind}</d:resourcetype><d:getcontentlength>{size}</d:getcontentlength>"
        "</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
    )


def _answers(body: bytes) -> "Reply":
    return 207, {"Content-Type": "application/xml"}, body


# ---------------------------------------------------------------------------
# A3: a failed propstat that names no property is a failure
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("prop", ["<d:prop/>", "", "<d:prop>text</d:prop>"])
def test_a_failed_propstat_without_a_property_still_fails(prop: str) -> None:
    ms = MultiStatusResponse(
        _multistatus(
            "<d:response><d:href>/a</d:href><d:propstat>"
            f"{prop}<d:status>HTTP/1.1 403 Forbidden</d:status>"
            "</d:propstat></d:response>"
        )
    )
    with pytest.raises(exceptions.MultiStatusError) as excinfo:
        ms.raise_for_status()
    assert excinfo.value.statuses == {"/a": "Forbidden"}


def test_set_props_reports_a_failure_the_server_gives_without_a_property() -> None:
    body = _multistatus(
        "<d:response><d:href>/f</d:href><d:propstat><d:prop/>"
        "<d:status>HTTP/1.1 409 Conflict</d:status></d:propstat></d:response>"
    )
    with scripted_server(always(_answers(body))) as (url, _rec):
        fs = FileSystem(url, retry=False)
        with pytest.raises(exceptions.MultiStatusError):
            fs.set_props("f", set_props={"displayname": "x"})


# ---------------------------------------------------------------------------
# A4: the status of a resource inside a PROPFIND multistatus
# ---------------------------------------------------------------------------


def test_info_and_exists_follow_a_404_given_in_the_body() -> None:
    body = _multistatus(_status_only("/gone", "404 Not Found"))
    with scripted_server(always(_answers(body))) as (url, _rec):
        fs = FileSystem(url, retry=False)
        assert fs.exists("gone") is False
        assert fs.isdir("gone") is False
        assert fs.isfile("gone") is False
        with pytest.raises(exceptions.ResourceNotFoundError):
            fs.info("gone")
        with pytest.raises(exceptions.ResourceNotFoundError):
            fs.get_props("gone")


def test_a_403_given_in_the_body_is_not_an_answer_to_exists() -> None:
    body = _multistatus(_status_only("/secret", "403 Forbidden"))
    with scripted_server(always(_answers(body))) as (url, _rec):
        fs = FileSystem(url, retry=False)
        with pytest.raises(exceptions.ForbiddenError):
            fs.exists("secret")
        with pytest.raises(exceptions.ForbiddenError):
            fs.info("secret")


def test_a_redirect_given_in_the_body_is_not_a_resource() -> None:
    body = _multistatus(_status_only("/moved", "301 Moved Permanently"))
    with scripted_server(always(_answers(body))) as (url, _rec):
        fs = FileSystem(url, retry=False)
        with pytest.raises(exceptions.RedirectNotFollowedError):
            fs.info("moved")


def test_ls_keeps_a_member_the_account_may_not_read_and_drops_one_that_is_gone() -> (
    None
):
    body = _multistatus(
        _props("/d/", directory=True),
        _props("/d/ok.txt", size=7),
        _status_only("/d/secret", "403 Forbidden"),
        _status_only("/d/gone", "404 Not Found"),
    )
    with scripted_server(always(_answers(body))) as (url, _rec):
        listing = FileSystem(url, retry=False).ls("d")
    assert sorted(listing) == ["d/ok.txt", "d/secret"]
    by_name = {r.name: r for r in listing}
    assert by_name["d/ok.txt"].status is None
    assert by_name["d/ok.txt"].size == 7
    secret = by_name["d/secret"]
    assert secret.status == 403
    assert secret.size is None
    assert secret.is_dir is False


def test_ls_of_a_collection_the_body_calls_missing_raises() -> None:
    body = _multistatus(_status_only("/d/", "404 Not Found"))
    with scripted_server(always(_answers(body))) as (url, _rec):
        with pytest.raises(exceptions.ResourceNotFoundError):
            FileSystem(url, retry=False).ls("d")


def test_a_resource_has_a_status_field_in_its_dict() -> None:
    body = _multistatus(_props("/f.txt"))
    with scripted_server(always(_answers(body))) as (url, _rec):
        info = FileSystem(url, retry=False).info("f.txt")
    assert info.status is None
    assert info.as_dict()["status"] is None


# ---------------------------------------------------------------------------
# A6: a failed OPTIONS probe is asked again
# ---------------------------------------------------------------------------


def test_an_options_error_is_not_remembered() -> None:
    answers = iter(
        [(503, {}, b""), (200, {"Accept-Ranges": "bytes", "DAV": "1, 2"}, b"")]
    )
    with scripted_server(lambda _seen: next(answers)) as (url, rec):
        session = Session(url, retry=False)
        assert not session.features_for("").supports_ranges
        features = session.features_for("")
        assert features.supports_ranges
        assert features.dav_compliances == {"1", "2"}
        # ...and the answer that did come is remembered.
        assert session.features_for("") is features
    assert len(rec.requests) == 2


# ---------------------------------------------------------------------------
# A1: locks below the destination
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("moves", [False, True])
def test_a_transfer_presents_the_locks_below_the_destination(moves: bool) -> None:
    registry = LockRegistry()
    registry.add(f"{_DEEP}/dest/sub/f.txt", "urn:uuid:aaa", "0")
    header = registry.if_header_for_transfer(
        f"{_DEEP}/src", f"{_DEEP}/dest", moves=moves
    )
    assert header is not None
    assert f"<{_DEEP}/dest/sub/f.txt> (<urn:uuid:aaa>)" in header


def test_a_copy_over_a_collection_sends_the_token_of_a_locked_member() -> None:
    with scripted_server(always(OK)) as (url, rec):
        session = Session(retry=False)
        session.locks.add(f"{url}/dest/inner.txt", "urn:uuid:bbb", "0")
        session.copy(f"{url}/src", f"{url}/dest", overwrite=True)
    assert "urn:uuid:bbb" in rec.requests[0].headers["if"]


# ---------------------------------------------------------------------------
# A2: a lock does not outlive the resource
# ---------------------------------------------------------------------------


def test_the_registry_forgets_everything_within_a_url() -> None:
    registry = LockRegistry()
    registry.add(f"{_DEEP}/a", "t1", "0")
    registry.add(f"{_DEEP}/a/b", "t2", "0")
    registry.add(f"{_DEEP}/ab", "t3", "0")
    registry.add(f"{_DEEP}", "t4", "infinity")
    registry.add("http://other/dav/a", "t5", "0")
    registry.discard_within(f"{_DEEP}/a")
    assert {h.token for h in registry.held()} == {"t3", "t4", "t5"}


@pytest.mark.parametrize("method", ["delete", "move"])
def test_a_deleted_or_moved_resource_takes_its_locks_along(method: str) -> None:
    with scripted_server(always(OK)) as (url, rec):
        session = Session(retry=False)
        session.locks.add(f"{url}/d/f", "opaquelocktoken:abc", "0")
        session.locks.add(f"{url}/other", "opaquelocktoken:def", "0")
        if method == "delete":
            session.delete(f"{url}/d")
        else:
            session.move(f"{url}/d", f"{url}/e")
        session.put(f"{url}/d/f", data=b"x")
    assert {h.token for h in session.locks.held()} == {"opaquelocktoken:def"}
    assert "if" not in rec.requests[-1].headers


def test_a_failed_delete_keeps_the_locks() -> None:
    with scripted_server(always((423, {}, b""))) as (url, _rec):
        session = Session(retry=False)
        session.locks.add(f"{url}/d", "opaquelocktoken:abc", "0")
        session.delete(f"{url}/d", raise_on_error=False)
    assert len(session.locks.held()) == 1


# ---------------------------------------------------------------------------
# B1: a lock the server lists without its token is not "gone"
# ---------------------------------------------------------------------------

_LOCK_TOKEN = "opaquelocktoken:abc"


def _lock_discovery(body_of_lockdiscovery: "str | None") -> bytes:
    if body_of_lockdiscovery is None:
        return _multistatus(
            "<d:response><d:href>/f</d:href><d:propstat><d:prop><d:lockdiscovery/></d:prop>"
            "<d:status>HTTP/1.1 403 Forbidden</d:status></d:propstat></d:response>"
        )
    return _multistatus(
        "<d:response><d:href>/f</d:href><d:propstat><d:prop><d:lockdiscovery>"
        f"{body_of_lockdiscovery}</d:lockdiscovery></d:prop>"
        "<d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
    )


_ACTIVELOCK = (
    "<d:activelock><d:locktype><d:write/></d:locktype><d:lockscope><d:exclusive/></d:lockscope>"
    "<d:depth>0</d:depth>{token}</d:activelock>"
)


def _kept_after_a_412(discovery: bytes) -> bool:
    def respond(seen: Seen) -> Reply:
        if seen.method == "PROPFIND":
            return _answers(discovery)
        return 412, {}, b""

    with scripted_server(respond) as (url, _rec):
        session = Session(retry=False)
        session.locks.add(f"{url}/f", _LOCK_TOKEN, "0")
        session.put(f"{url}/f", data=b"x", raise_on_error=False)
        return bool(session.locks.held())


def test_a_lock_that_the_server_no_longer_lists_is_forgotten() -> None:
    assert not _kept_after_a_412(_lock_discovery(""))


def test_a_lock_that_the_server_still_lists_is_kept() -> None:
    token = f"<d:locktoken><d:href>{_LOCK_TOKEN}</d:href></d:locktoken>"
    assert _kept_after_a_412(_lock_discovery(_ACTIVELOCK.format(token=token)))


def test_a_lock_listed_without_its_token_is_kept() -> None:
    assert _kept_after_a_412(_lock_discovery(_ACTIVELOCK.format(token="")))


def test_an_answer_without_lockdiscovery_keeps_the_lock() -> None:
    assert _kept_after_a_412(_lock_discovery(None))


# ---------------------------------------------------------------------------
# B7: a 412 is "already exists" only for a resource that is there
# ---------------------------------------------------------------------------


def test_a_412_on_an_upload_for_a_missing_resource_is_a_precondition_failure() -> None:
    def respond(seen: Seen) -> Reply:
        if seen.method == "PROPFIND":
            return 404, {}, b""
        return 412, {}, b""

    with scripted_server(respond) as (url, _rec):
        fs = FileSystem(url, retry=False)
        with pytest.raises(exceptions.PreconditionFailedError) as excinfo:
            fs.upload_fileobj(io.BytesIO(b"x"), "a")
    assert not isinstance(excinfo.value, exceptions.ResourceAlreadyExistsError)


# ---------------------------------------------------------------------------
# B11 / B12: what goes on the wire
# ---------------------------------------------------------------------------


def test_mkdir_with_a_full_url_adds_the_trailing_slash() -> None:
    with scripted_server(always((201, {}, b""))) as (url, rec):
        FileSystem(url, retry=False).mkdir(f"{url}/new")
        FileSystem(retry=False).mkdir(f"{url}/other")
    assert [r.path for r in rec.requests] == ["/new/", "/other/"]


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


# ---------------------------------------------------------------------------
# A7: an Extended MKCOL with several resource types
# ---------------------------------------------------------------------------


def test_a_proppatch_value_can_be_a_list_of_elements() -> None:
    from xml.etree.ElementTree import Element  # noqa: PLC0415

    body = build_proppatch_body(
        {("urn:x", "kinds"): [Element("{urn:x}a"), Element("{urn:x}b")]}
    )
    assert body.index("<ns1:a />") < body.index("<ns1:b />")
    assert body.count("kinds") == 2


def test_a_proppatch_value_must_be_text_or_elements() -> None:
    with pytest.raises(TypeError, match="str or Element"):
        build_proppatch_body({"displayname": ["text"]})  # type: ignore[list-item]
