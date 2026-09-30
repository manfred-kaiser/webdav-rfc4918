"""End-to-end tests against a real WebDAV server (wsgidav)."""

import io

import pytest

from tests.server import AUTH
from webdav import (
    FileSystem,
    ResourceAlreadyExistsError,
    ResourceLockedError,
    ResourceNotFoundError,
)
from webdav.dav.locks import EXCLUSIVE


def test_mkdir_and_ls(fs: FileSystem) -> None:
    fs.mkdir("docs")
    assert fs.isdir("docs")
    assert fs.exists("docs")
    assert fs.ls("docs") == []


def test_mkdir_conflict_on_existing_collection(fs: FileSystem) -> None:
    fs.mkdir("docs")
    with pytest.raises(ResourceAlreadyExistsError):
        fs.mkdir("docs")


def test_upload_and_download_roundtrip(fs: FileSystem) -> None:
    fs.mkdir("docs")
    fs.upload_fileobj(io.BytesIO(b"hello world"), "docs/a.txt")

    assert fs.isfile("docs/a.txt")
    assert fs.content_length("docs/a.txt") == len(b"hello world")

    buf = io.BytesIO()
    fs.download_fileobj("docs/a.txt", buf)
    assert buf.getvalue() == b"hello world"


def test_upload_overwrite_protection(fs: FileSystem) -> None:
    fs.upload_fileobj(io.BytesIO(b"v1"), "a.txt")
    with pytest.raises(ResourceAlreadyExistsError):
        fs.upload_fileobj(io.BytesIO(b"v2"), "a.txt", overwrite=False)

    fs.upload_fileobj(io.BytesIO(b"v2"), "a.txt", overwrite=True)
    buf = io.BytesIO()
    fs.download_fileobj("a.txt", buf)
    assert buf.getvalue() == b"v2"


def test_open_read_text_and_binary(fs: FileSystem) -> None:
    fs.upload_fileobj(io.BytesIO("héllo".encode()), "t.txt")

    with fs.open("t.txt", mode="rb") as f:
        assert f.read() == "héllo".encode()

    with fs.open("t.txt", mode="r", encoding="utf-8") as f:
        assert f.read() == "héllo"


def test_move_and_copy(fs: FileSystem) -> None:
    fs.upload_fileobj(io.BytesIO(b"content"), "src.txt")

    fs.copy("src.txt", "copy.txt")
    assert fs.exists("src.txt")
    assert fs.exists("copy.txt")

    fs.move("src.txt", "moved.txt")
    assert not fs.exists("src.txt")
    assert fs.exists("moved.txt")


def test_remove(fs: FileSystem) -> None:
    fs.upload_fileobj(io.BytesIO(b"x"), "gone.txt")
    assert fs.exists("gone.txt")
    fs.remove("gone.txt")
    assert not fs.exists("gone.txt")


def test_not_found(fs: FileSystem) -> None:
    with pytest.raises(ResourceNotFoundError):
        fs.info("does-not-exist.txt")


def test_get_props_and_etag(fs: FileSystem) -> None:
    fs.upload_fileobj(io.BytesIO(b"data"), "e.txt")
    props = fs.get_props("e.txt")
    assert props.content_length == 4
    assert props.etag
    assert fs.etag("e.txt") == props.etag


def test_ls_lists_members(fs: FileSystem) -> None:
    fs.mkdir("dir")
    fs.upload_fileobj(io.BytesIO(b"1"), "dir/one.txt")
    fs.upload_fileobj(io.BytesIO(b"2"), "dir/two.txt")

    # Root-relative, matching os.walk's own full-path convention for
    # directories reachable from the walk root.
    names = sorted(fs.ls("dir"))
    assert names == ["dir/one.txt", "dir/two.txt"]


def test_lock_and_write_with_held_token(fs: FileSystem) -> None:
    fs.upload_fileobj(io.BytesIO(b"v1"), "locked.txt")

    with fs.locked("locked.txt", scope=EXCLUSIVE) as active_lock:
        assert active_lock.token
        # A write through the same shared session automatically carries the
        # lock token via the `If` header - must succeed.
        fs.upload_fileobj(io.BytesIO(b"v2"), "locked.txt", overwrite=True)

    buf = io.BytesIO()
    fs.download_fileobj("locked.txt", buf)
    assert buf.getvalue() == b"v2"


def test_lock_blocks_a_second_client(fs: FileSystem, server_url: str) -> None:
    fs.upload_fileobj(io.BytesIO(b"v1"), "locked2.txt")

    other = FileSystem(server_url, auth=AUTH)
    try:
        with (
            fs.locked("locked2.txt", scope=EXCLUSIVE),
            pytest.raises(ResourceLockedError),
        ):
            other.upload_fileobj(io.BytesIO(b"v2"), "locked2.txt", overwrite=True)
    finally:
        other.close()


def test_set_and_get_custom_property(fs: FileSystem) -> None:
    fs.upload_fileobj(io.BytesIO(b"x"), "p.txt")
    fs.set_props("p.txt", set_props={("https://example.org/ns", "color"): "blue"})

    props = fs.get_props("p.txt", names=[("https://example.org/ns", "color")])
    assert props.text("https://example.org/ns", "color") == "blue"
