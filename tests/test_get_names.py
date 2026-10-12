"""What ``get`` writes from the names a server lists: Windows names and names that are one file."""

import errno
import os
from pathlib import Path

import pytest

from tests.scripted_server import Reply, Seen, scripted_server
from webdav import _fsspec_guards
from webdav.fsspec import WebdavFileSystem


def _listing(*names: str) -> bytes:
    entries = "".join(
        f"<d:response><d:href>/dir/{n}</d:href><d:propstat><d:prop><d:resourcetype/>"
        "<d:getcontentlength>2</d:getcontentlength></d:prop><d:status>HTTP/1.1 200 OK"
        "</d:status></d:propstat></d:response>"
        for n in names
    )
    return (
        '<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response><d:href>/dir/</d:href>'
        "<d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop>"
        f"<d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>{entries}</d:multistatus>"
    ).encode()


def _server(*names: str):  # noqa: ANN202
    def respond(seen: Seen) -> Reply:
        if seen.method == "PROPFIND":
            return 207, {"Content-Type": "application/xml"}, _listing(*names)
        if seen.method == "GET":
            return 200, {}, b"hi"
        return 404, {}, b""

    return scripted_server(respond)


@pytest.mark.parametrize("name", ["CON", "nul.txt", "a:b", "trail.", "COM1"])
def test_windows_refuses_what_is_not_a_windows_file_name(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_fsspec_guards, "_on_windows", lambda: True)
    with _server(name) as (url, _):
        with pytest.raises(OSError, match="Windows") as caught:
            WebdavFileSystem(url).get("/dir", str(tmp_path / "dst"), recursive=True)
    assert caught.value.errno == errno.EINVAL
    assert (
        not list((tmp_path / "dst").rglob("*")) if (tmp_path / "dst").exists() else True
    )


def test_windows_accepts_a_plain_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_fsspec_guards, "_on_windows", lambda: True)
    with _server("ok.txt") as (url, _):
        WebdavFileSystem(url).get("/dir", str(tmp_path / "dst"), recursive=True)
    assert (tmp_path / "dst" / "ok.txt").read_bytes() == b"hi"


@pytest.mark.parametrize("name", ["CON", "a:b", "back\\slash"])
def test_other_platforms_keep_these_names(name: str, tmp_path: Path) -> None:
    """On Linux and macOS a colon or a backslash is an ordinary character; ``CON`` a name."""
    if os.name == "nt":
        pytest.skip("Windows")
    with _server(name) as (url, _):
        WebdavFileSystem(url).get("/dir", str(tmp_path / "dst"), recursive=True)
    assert (tmp_path / "dst" / name).read_bytes() == b"hi"


def test_two_names_that_are_one_file_are_not_written_over_each_other(
    tmp_path: Path,
) -> None:
    """A hard link stands in for a case-insensitive file system: ``B`` is the file ``A``."""
    dst = tmp_path / "dst"
    dst.mkdir()
    first = dst / "a.txt"
    tree = _fsspec_guards.GetTree(str(dst), contained=True)
    first.write_bytes(b"first")
    tree.record(str(first))
    (dst / "A.TXT").hardlink_to(first)
    with pytest.raises(OSError, match="same file") as caught:
        tree.check(str(dst / "A.TXT"))
    assert caught.value.errno == errno.EEXIST
    tree.check(str(dst / "other.txt"))
