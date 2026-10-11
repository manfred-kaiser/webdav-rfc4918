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
