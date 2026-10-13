"""``FileSystem`` on the server's tree: listing, walking, ``mkdir``, ``copy``, ``move``, ``info`` and ``exists``."""

# ruff: noqa: SIM117, PLC0415, PTH208, S105, RUF001

import io
import os
import unicodedata
from pathlib import Path
from typing import Any

import pytest

import webdav
from tests.builders import (
    multistatus_doc,
    multistatus_ls,
    multistatus_of_hrefs,
    sized_entry,
)
from tests.credentials import AUTH
from tests.scripted_server import Reply, Seen, always, scripted_server
from webdav import FileSystem, Session
from webdav.exceptions import (
    ClientError,
    ForbiddenError,
    HTTPStatusError,
    PreconditionFailedError,
    ResourceAlreadyExistsError,
    WebDAVError,
)
from webdav.fsspec import WebdavFileSystem

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


def test_walk_stops_a_server_that_invents_a_new_directory_at_every_level() -> None:
    def respond(seen: Seen) -> tuple[int, dict[str, str], bytes]:
        path = seen.path.rstrip("/")
        return 207, {}, multistatus_of_hrefs(f"{path}/", f"{path}/d/")

    with scripted_server(respond) as (url, rec):
        with pytest.raises(webdav.ClientError, match="walk"):
            for _ in FileSystem(retry=False).walk(url):
                pass
    assert len(rec.requests) < 1000


@pytest.mark.parametrize("status", [202, 204])
def test_BUG10_mkdir_accepts_any_success_status(status: int) -> None:
    with scripted_server(always((status, {}, b""))) as (url, _):
        FileSystem(retry=False).mkdir(url + "/d")


def test_BUG10_mkdir_405_is_only_exists_if_the_resource_is_there() -> None:
    def respond(seen: Seen) -> tuple[int, dict[str, str], bytes]:
        if seen.method == "PROPFIND":
            return 404, {}, b""
        return 405, {"Allow": "GET, PUT"}, b""

    with scripted_server(respond) as (url, _):
        with pytest.raises(WebDAVError) as caught:
            FileSystem(retry=False).mkdir(url + "/d")
    assert not isinstance(caught.value, ResourceAlreadyExistsError)


def test_BUG10_guard_mkdir_on_something_that_exists(fs: FileSystem) -> None:
    fs.mkdir("/d")
    with pytest.raises(ResourceAlreadyExistsError):
        fs.mkdir("/d")


def test_BUG10_copy_412_from_the_if_header_is_not_exists() -> None:
    def respond(seen: Seen) -> tuple[int, dict[str, str], bytes]:
        return (404, {}, b"") if seen.method == "PROPFIND" else (412, {}, b"")

    with scripted_server(respond) as (url, _):
        with pytest.raises(PreconditionFailedError) as caught:
            FileSystem(url, retry=False).copy("/a", "/b")
        with pytest.raises(PreconditionFailedError) as caught_move:
            FileSystem(url, retry=False).move("/a", "/b")
    assert not isinstance(caught.value, ResourceAlreadyExistsError)
    assert not isinstance(caught_move.value, ResourceAlreadyExistsError)


def test_BUG10_guard_copy_and_move_onto_an_existing_destination(fs: FileSystem) -> None:
    fs.upload_fileobj(io.BytesIO(b"1"), "/a")
    fs.upload_fileobj(io.BytesIO(b"2"), "/b")
    with pytest.raises(ResourceAlreadyExistsError):
        fs.copy("/a", "/b")
    with pytest.raises(ResourceAlreadyExistsError):
        fs.move("/a", "/b")


XML = {"Content-Type": "application/xml"}


def _tree_server(forbidden: "set[str]") -> Any:
    def respond(seen: Seen) -> tuple[int, dict[str, str], bytes]:
        base = seen.path.rstrip("/")
        if base in forbidden:
            return 403, {}, b""
        if base == "":
            return (
                207,
                XML,
                multistatus_doc(
                    sized_entry("/", True),
                    sized_entry("/a/", True),
                    sized_entry("/b/", True),
                ),
            )
        return (
            207,
            XML,
            multistatus_doc(
                sized_entry(f"{base}/", True), sized_entry(f"{base}/f.txt", False, 1)
            ),
        )

    return respond


def test_BUG12_walk_raises_on_the_first_unlistable_directory_by_default() -> None:
    with scripted_server(_tree_server({"/a"})) as (url, _):
        with pytest.raises(ForbiddenError):
            list(FileSystem(retry=False).walk(url))


def test_BUG12_walk_onerror_reports_and_skips() -> None:
    errors: list[WebDAVError] = []
    with scripted_server(_tree_server({"/a"})) as (url, _):
        seen = [
            path
            for path, _d, _f in FileSystem(retry=False).walk(url, onerror=errors.append)
        ]
    assert [type(e) for e in errors] == [ForbiddenError]
    assert len(seen) == 2
    assert seen[1].endswith("/b")
    assert not any(p.endswith("/a") for p in seen)


def test_BUG12_module_function_takes_onerror() -> None:
    import webdav

    errors: list[WebDAVError] = []
    with scripted_server(_tree_server({"/b"})) as (url, _):
        paths = [
            p for p, _d, _f in webdav.walk(url, onerror=errors.append, retry=False)
        ]
    assert len(errors) == 1
    assert any(p.endswith("/a") for p in paths)


def _endless_server(counter: list[int]) -> Any:
    def respond(seen: Seen) -> tuple[int, dict[str, str], bytes]:
        if seen.method == "PROPFIND":
            counter[0] += 1
            base = seen.path.rstrip("/")
            entries = [sized_entry(base + "/", True)]
            if seen.headers.get("depth") == "1":
                entries += [
                    sized_entry(base + "/d/", True),
                    sized_entry(base + "/f", False, 3),
                ]
            return 207, XML, multistatus_doc(*entries)
        return 200, {"Content-Length": "3"}, b"abc"

    return respond


@pytest.mark.parametrize("call", ["find", "walk", "du", "glob", "expand_path"])
def test_DOS04_an_endless_tree_is_a_client_error_not_a_recursion_error(
    call: str,
) -> None:
    counter = [0]
    with scripted_server(_endless_server(counter)) as (url, _):
        filesystem = WebdavFileSystem(url)
        operations: dict[str, Any] = {
            "find": lambda: filesystem.find("/"),
            "walk": lambda: list(filesystem.walk("/")),
            "du": lambda: filesystem.du("/"),
            "glob": lambda: filesystem.glob("/**"),
            "expand_path": lambda: filesystem.expand_path("/", recursive=True),
        }
        with pytest.raises(ClientError, match="too deep"):
            operations[call]()
    assert counter[0] < 2000


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


def test_mkdir_with_a_full_url_adds_the_trailing_slash() -> None:
    with scripted_server(always((201, {}, b""))) as (url, rec):
        FileSystem(url, retry=False).mkdir(f"{url}/new")
        FileSystem(retry=False).mkdir(f"{url}/other")
    assert [r.path for r in rec.requests] == ["/new/", "/other/"]


def test_a_case_insensitive_server_spelling_the_collection_differently_is_fine() -> (
    None
):
    def respond(seen: Seen) -> tuple[int, dict[str, str], bytes]:
        upper = seen.path.upper().rstrip("/")
        return 207, {}, multistatus_ls(f"{upper}/", f"{upper}/File.txt")

    with scripted_server(respond) as (url, _rec):
        assert FileSystem(retry=False).ls(f"{url}/dav/dir") == ["DAV/DIR/File.txt"]


def test_walk_counts_queued_collections(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("webdav.fs.client._WALK_MAX_DIRS", 50)

    def respond(seen: Seen) -> tuple[int, dict[str, str], bytes]:
        base = seen.path.rstrip("/")
        return (
            207,
            {},
            multistatus_ls(f"{base}/", *[f"{base}/sub{i}/" for i in range(200)]),
        )

    with scripted_server(respond) as (url, rec):
        with pytest.raises(ClientError, match="walk gave up"):
            list(FileSystem(retry=False).walk(url))
    assert len(rec.requests) == 1


_MULTISTATUS = (
    b'<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response><d:href>/d/</d:href>'
    b"<d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop>"
    b"<d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"
)


def _mkcol_405(propfind: Reply):  # noqa: ANN202
    def respond(seen: Seen) -> Reply:
        if seen.method == "MKCOL":
            return 405, {}, b""
        return propfind

    return respond


def test_mkcol_405_is_already_exists_when_the_resource_is_there() -> None:
    reply = (207, {"Content-Type": "application/xml"}, _MULTISTATUS)
    with (
        scripted_server(_mkcol_405(reply)) as (url, _),
        FileSystem(url, retry=False) as fs,
    ):
        with pytest.raises(ResourceAlreadyExistsError):
            fs.mkdir("/d")


@pytest.mark.parametrize("status", [401, 403, 500])
def test_mkcol_405_stays_already_exists_when_the_server_will_not_say(
    status: int,
) -> None:
    """A server that answers MKCOL 405 (it is mapped) and refuses PROPFIND: ``exist_ok`` must still work."""
    with scripted_server(_mkcol_405((status, {}, b""))) as (url, _):
        with (
            FileSystem(url, retry=False) as fs,
            pytest.raises(ResourceAlreadyExistsError),
        ):
            fs.mkdir("/d")


def test_mkcol_405_is_not_already_exists_when_the_resource_is_missing() -> None:
    """A read-only server answers 405 for everything."""
    with scripted_server(_mkcol_405((404, {}, b""))) as (url, _):
        with (
            FileSystem(url, retry=False) as fs,
            pytest.raises(HTTPStatusError) as caught,
        ):
            fs.mkdir("/d")
    assert caught.value.status_code == 405
