"""End-to-end tests for the fsspec filesystem, against a real WebDAV server."""

from collections.abc import Iterator

import pytest

from tests.credentials import AUTH
from webdav.fsspec import WebdavFileSystem


@pytest.fixture
def fs(server_url: str) -> Iterator[WebdavFileSystem]:
    filesystem = WebdavFileSystem(server_url, auth=AUTH)
    yield filesystem
    filesystem.filesystem.close()


def test_pipe_and_cat_roundtrip(fs: WebdavFileSystem) -> None:
    fs.pipe_file("a.txt", b"hello fsspec")
    assert fs.cat_file("a.txt") == b"hello fsspec"


def test_ls_and_info(fs: WebdavFileSystem) -> None:
    fs.pipe_file("dir/one.txt", b"1")
    names = sorted(fs.ls("dir", detail=False))
    assert names == ["dir/one.txt"]

    info = fs.info("dir/one.txt")
    assert info["name"] == "dir/one.txt"
    assert info["size"] == 1
    assert info["type"] == "file"


def test_open_read_mode(fs: WebdavFileSystem) -> None:
    fs.pipe_file("t.txt", b"streamed content")
    with fs.open("t.txt", "rb") as f:
        assert f.read() == b"streamed content"


def test_put_file(
    fs: WebdavFileSystem, tmp_path_factory: pytest.TempPathFactory
) -> None:
    # A separate temp dir from `storage_dir` (the served WebDAV root) -
    # `tmp_path` would otherwise alias it, planting the upload source
    # inside the very tree being served.
    local = tmp_path_factory.mktemp("upload-src") / "local.txt"
    local.write_bytes(b"from disk")
    fs.put_file(local, "remote.txt")
    assert fs.cat_file("remote.txt") == b"from disk"


def test_mkdir_and_exists(fs: WebdavFileSystem) -> None:
    fs.mkdir("newdir")
    assert fs.exists("newdir")
    assert fs.isdir("newdir")


def test_rm_and_mv(fs: WebdavFileSystem) -> None:
    fs.pipe_file("src.txt", b"x")
    fs.mv("src.txt", "dst.txt")
    assert not fs.exists("src.txt")
    assert fs.exists("dst.txt")

    fs.rm("dst.txt")
    assert not fs.exists("dst.txt")


def test_write_mode_upload_file(fs: WebdavFileSystem) -> None:
    with fs.open("written.txt", "wb") as f:
        f.write(b"buffered upload")
    assert fs.cat_file("written.txt") == b"buffered upload"


def test_self_registers_webdavs_scheme() -> None:
    """Importing webdav.fsspec is enough for fsspec to resolve "webdavs" to it."""
    import fsspec  # noqa: PLC0415

    assert fsspec.get_filesystem_class("webdavs") is WebdavFileSystem
