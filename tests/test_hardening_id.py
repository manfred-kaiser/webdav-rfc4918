"""Regression tests for the file-system / fsspec hardening: the misbehaviour, and what stays legitimate.

One group per finding (``FS-01``, ``BUG-05``, ...). A ``test_<ID>_...`` test fails without the fix; a
``test_<ID>_guard_...`` test pins behaviour that worked before and has to keep working.
"""

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import fsspec
import pytest

from tests.credentials import AUTH
from tests.scripted_server import Seen, scripted_server
from webdav import FileSystem
from webdav.exceptions import (
    ClientError,
    ForbiddenError,
    WebDAVError,
)
from webdav.fsspec import WebdavFileSystem

XML = {"Content-Type": "application/xml"}


def _entry(href: str, is_dir: bool, size: "int | None" = None) -> str:
    kind = (
        "<d:resourcetype><d:collection/></d:resourcetype>"
        if is_dir
        else "<d:resourcetype/>"
    )
    length = (
        f"<d:getcontentlength>{size}</d:getcontentlength>" if size is not None else ""
    )
    return (
        f"<d:response><d:href>{href}</d:href><d:propstat><d:prop>{kind}{length}</d:prop>"
        "<d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
    )


def _multistatus(*entries: str) -> bytes:
    return (
        '<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">'
        + "".join(entries)
        + "</d:multistatus>"
    ).encode()


PROPFIND_FILE = _multistatus(_entry("/f", False))


@pytest.fixture
def ffs(server_url: str) -> Iterator[WebdavFileSystem]:
    filesystem = WebdavFileSystem(server_url, auth=AUTH)
    yield filesystem
    filesystem.filesystem.close()


# ------------------------------------------------------------------ BUG-12
def _tree_server(forbidden: "set[str]") -> Any:
    def respond(seen: Seen) -> tuple[int, dict[str, str], bytes]:
        base = seen.path.rstrip("/")
        if base in forbidden:
            return 403, {}, b""
        if base == "":
            return (
                207,
                XML,
                _multistatus(
                    _entry("/", True), _entry("/a/", True), _entry("/b/", True)
                ),
            )
        return (
            207,
            XML,
            _multistatus(_entry(f"{base}/", True), _entry(f"{base}/f.txt", False, 1)),
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


# ------------------------------------------------------------------ DOS-04
def _endless_server(counter: list[int]) -> Any:
    def respond(seen: Seen) -> tuple[int, dict[str, str], bytes]:
        if seen.method == "PROPFIND":
            counter[0] += 1
            base = seen.path.rstrip("/")
            entries = [_entry(base + "/", True)]
            if seen.headers.get("depth") == "1":
                entries += [_entry(base + "/d/", True), _entry(base + "/f", False, 3)]
            return 207, XML, _multistatus(*entries)
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
        with pytest.raises(ClientError, match="walk_max_depth"):
            operations[call]()
    assert counter[0] < 400


def test_DOS04_the_limits_can_be_raised() -> None:
    counter = [0]
    with scripted_server(_endless_server(counter)) as (url, _):
        filesystem = WebdavFileSystem(url, walk_max_depth=20)
        with pytest.raises(ClientError):
            filesystem.find("/")
    assert 18 <= counter[0] <= 24
    counter[0] = 0
    with scripted_server(_endless_server(counter)) as (url, _):
        filesystem = WebdavFileSystem(url, walk_max_depth=None, walk_max_dirs=30)
        with pytest.raises(ClientError, match="walk_max_dirs"):
            filesystem.find("/")
    assert counter[0] <= 34


def test_DOS04_a_deep_but_finite_tree_is_walked(ffs: WebdavFileSystem) -> None:
    path = "/" + "/".join(f"l{i}" for i in range(40))
    ffs.pipe_file(path + "/leaf.txt", b"x")
    assert ffs.find("/") == [path + "/leaf.txt"]


def test_DOS04_guard_the_fsspec_contract_of_walk(ffs: WebdavFileSystem) -> None:
    ffs.pipe_file("/d/a/1.txt", b"1")
    ffs.pipe_file("/d/b/2.txt", b"2")
    ffs.pipe_file("/d/top.txt", b"t")
    top_down = list(ffs.walk("/d"))
    assert top_down[0][0] == "/d"
    assert sorted(top_down[0][1]) == ["a", "b"]
    assert top_down[0][2] == ["top.txt"]
    bottom_up = list(ffs.walk("/d", topdown=False))
    assert bottom_up[-1][0] == "/d"
    assert [p for p, _, _ in ffs.walk("/d", maxdepth=1)] == ["/d"]
    pruned = []
    for path, dirs, _files in ffs.walk("/d"):
        pruned.append(path)
        if path == "/d":
            dirs.remove("a")
    assert "/d/a" not in pruned
    assert sorted(ffs.find("/d")) == ["/d/a/1.txt", "/d/b/2.txt", "/d/top.txt"]
    assert sorted(ffs.glob("/d/**/*.txt")) == ["/d/a/1.txt", "/d/b/2.txt", "/d/top.txt"]


# ------------------------------------------------------------------ EXC-06
@pytest.mark.parametrize(
    "authority", ["h:²", "h:٣٠", "[::1]:٨٠", "h:1_0", "h:+80", "h:8 0"]
)
def test_EXC06_a_port_is_ascii_digits(authority: str) -> None:
    from webdav._webdavs_url import host_and_port

    with pytest.raises(ValueError, match="host"):
        host_and_port(authority)


@pytest.mark.parametrize(
    ("authority", "expected"),
    [("h:80", ("h", 80)), ("[::1]:8080", ("::1", 8080)), ("h", ("h", None))],
)
def test_EXC06_guard_ordinary_authorities(
    authority: str, expected: "tuple[str, int | None]"
) -> None:
    from webdav._webdavs_url import host_and_port

    assert host_and_port(authority) == expected


# ------------------------------------------------------------------ FS-06
def test_FS06_webdavs_url_against_a_plain_http_base_url_is_refused() -> None:
    with pytest.raises(ValueError, match="webdav://"):
        WebdavFileSystem(
            base_url="http://files.example/dav", host="files.example", transport="https"
        )


def test_FS06_the_same_through_fsspec() -> None:
    with pytest.raises(ValueError, match="plain http"):
        fsspec.core.url_to_fs(
            "webdavs://files.example/d", base_url="http://files.example/dav"
        )


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
def test_FS06_guard_loopback_stays_possible(host: str) -> None:
    name = f"[{host}]" if ":" in host else host
    WebdavFileSystem(
        base_url=f"http://{name}:8080/dav", host=host, transport="https"
    ).filesystem.close()


def test_FS06_guard_other_combinations() -> None:
    WebdavFileSystem(
        base_url="https://files.example/dav", host="files.example", transport="https"
    ).filesystem.close()
    WebdavFileSystem(
        base_url="http://files.example/dav", host="files.example", transport="http"
    ).filesystem.close()
    WebdavFileSystem(
        base_url="http://files.example/dav"
    ).filesystem.close()  # no URL host: nothing to compare


# ------------------------------------------------------------------ FS-07
FOREIGN = "webdavs://other.example/secret.txt"


@pytest.fixture
def seeded(ffs: WebdavFileSystem) -> WebdavFileSystem:
    ffs.pipe_file("/secret.txt", b"S")
    return ffs


@pytest.mark.parametrize(
    "call",
    [
        lambda fs: fs.cat_file(FOREIGN),
        lambda fs: fs.cat(FOREIGN),
        lambda fs: fs.open(FOREIGN, "rb"),
        lambda fs: fs.info(FOREIGN),
        lambda fs: fs.ls("webdavs://other.example/"),
        lambda fs: fs.exists(FOREIGN),
        lambda fs: fs.isdir("webdavs://other.example/d"),
        lambda fs: fs.isfile(FOREIGN),
        lambda fs: fs.rm(FOREIGN),
        lambda fs: fs.find("webdavs://other.example/"),
        lambda fs: fs.glob("webdavs://other.example/*"),
        lambda fs: fs.expand_path(FOREIGN),
        lambda fs: list(fs.walk("webdavs://other.example/")),
        lambda fs: fs.du("webdavs://other.example/"),
        lambda fs: fs.pipe_file("webdavs://other.example/new", b"x"),
        lambda fs: fs.pipe("webdavs://other.example/new", b"x"),
        lambda fs: fs.copy(FOREIGN, "/copy.txt"),
        lambda fs: fs.copy("/secret.txt", "webdavs://other.example/copy.txt"),
        lambda fs: fs.mv("/secret.txt", "webdavs://other.example/moved.txt"),
        lambda fs: fs.makedirs("webdavs://other.example/dir"),
        lambda fs: fs.size(FOREIGN),
        lambda fs: fs.head(FOREIGN),
        lambda fs: fs.read_text(FOREIGN),
    ],
)
def test_FS07_a_url_for_another_server_is_refused_at_every_entry_point(
    seeded: WebdavFileSystem, call: Any, tmp_path: Path
) -> None:
    with pytest.raises(ValueError, match="bound to one server"):
        call(seeded)
    assert not (tmp_path / "new").exists()
    assert not (tmp_path / "copy.txt").exists()


def test_FS07_guard_the_servers_own_host_works_everywhere(
    seeded: WebdavFileSystem, server_url: str
) -> None:
    from urllib.parse import urlsplit

    netloc = urlsplit(server_url).netloc
    url = f"webdavs://{netloc}/secret.txt"
    assert seeded.cat_file(url) == b"S"
    assert seeded.cat(url) == b"S"
    assert seeded.exists(url)
    assert seeded.info(url)["size"] == 1
    assert seeded.find(f"webdavs://{netloc}/") == ["/secret.txt"]
    assert seeded.glob(f"webdavs://{netloc.upper()}/*.txt") == ["/secret.txt"]
    with seeded.open(url, "rb") as f:
        assert f.read() == b"S"
    assert (
        seeded.cat_file("webdavs:///secret.txt") == b"S"
    )  # no host: the base_url's server


def test_FS07_the_class_level_strip_protocol_is_untouched() -> None:
    assert WebdavFileSystem._strip_protocol("webdavs://other.example/a/b") == "/a/b"
    assert WebdavFileSystem._strip_protocol(["webdav://h/a", "/b"]) == ["/a", "/b"]


def test_FS07_guard_fsspec_front_doors(server_url: str) -> None:
    from urllib.parse import urlsplit

    netloc = urlsplit(server_url).netloc
    options = {"base_url": server_url, "auth": AUTH}
    filesystem = fsspec.filesystem("webdavs", **options)
    filesystem.pipe_file("/d/a.txt", b"A")
    with fsspec.open(f"webdavs://{netloc}/d/a.txt", "rb", **options) as f:
        assert f.read() == b"A"
    assert [
        x.path
        for x in fsspec.open_files(f"webdavs://{netloc}/d/*.txt", "rb", **options)
    ] == ["/d/a.txt"]
    filesystem.filesystem.close()


def test_DOS04_the_limits_survive_pickling_and_json(server_url: str) -> None:
    import pickle

    filesystem = WebdavFileSystem(
        server_url, auth=AUTH, walk_max_depth=7, walk_max_dirs=None
    )
    restored = pickle.loads(pickle.dumps(filesystem))  # noqa: S301
    assert (restored.walk_max_depth, restored.walk_max_dirs) == (7, None)
    restored.filesystem.close()
    filesystem.filesystem.close()
    filesystem = WebdavFileSystem(
        server_url, auth=AUTH, walk_max_depth=7, walk_max_dirs=9
    )
    restored = fsspec.AbstractFileSystem.from_json(
        filesystem.to_json()
    )  # None is fsspec's limit
    assert (restored.walk_max_depth, restored.walk_max_dirs) == (7, 9)
    restored.filesystem.close()
    filesystem.filesystem.close()
