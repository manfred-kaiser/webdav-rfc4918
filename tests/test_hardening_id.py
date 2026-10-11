"""Regression tests for the file-system / fsspec hardening: the misbehaviour, and what stays legitimate.

One group per finding (``FS-01``, ``BUG-05``, ...). A ``test_<ID>_...`` test fails without the fix; a
``test_<ID>_guard_...`` test pins behaviour that worked before and has to keep working.
"""

from collections.abc import Iterator
from typing import Any

import pytest

from tests.credentials import AUTH
from tests.scripted_server import Seen, scripted_server
from webdav import FileSystem
from webdav.exceptions import (
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
