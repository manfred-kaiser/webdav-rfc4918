"""End-to-end tests against a real WebDAV server (wsgidav)."""

import io

import pytest

from tests.server import AUTH
from webdav import (
    Client,
    ResourceAlreadyExistsError,
    ResourceLockedError,
    ResourceNotFoundError,
)
from webdav.locks import EXCLUSIVE


def test_mkdir_and_ls(client: Client) -> None:
    client.mkdir("docs")
    assert client.isdir("docs")
    assert client.exists("docs")
    assert client.ls("docs", detail=False) == []


def test_mkdir_conflict_on_existing_collection(client: Client) -> None:
    client.mkdir("docs")
    with pytest.raises(ResourceAlreadyExistsError):
        client.mkdir("docs")


def test_upload_and_download_roundtrip(client: Client) -> None:
    client.mkdir("docs")
    client.upload_fileobj(io.BytesIO(b"hello world"), "docs/a.txt")

    assert client.isfile("docs/a.txt")
    assert client.content_length("docs/a.txt") == len(b"hello world")

    buf = io.BytesIO()
    client.download_fileobj("docs/a.txt", buf)
    assert buf.getvalue() == b"hello world"


def test_upload_overwrite_protection(client: Client) -> None:
    client.upload_fileobj(io.BytesIO(b"v1"), "a.txt")
    with pytest.raises(ResourceAlreadyExistsError):
        client.upload_fileobj(io.BytesIO(b"v2"), "a.txt", overwrite=False)

    client.upload_fileobj(io.BytesIO(b"v2"), "a.txt", overwrite=True)
    buf = io.BytesIO()
    client.download_fileobj("a.txt", buf)
    assert buf.getvalue() == b"v2"


def test_open_read_text_and_binary(client: Client) -> None:
    client.upload_fileobj(io.BytesIO("héllo".encode()), "t.txt")

    with client.open("t.txt", mode="rb") as f:
        assert f.read() == "héllo".encode()

    with client.open("t.txt", mode="r", encoding="utf-8") as f:
        assert f.read() == "héllo"


def test_move_and_copy(client: Client) -> None:
    client.upload_fileobj(io.BytesIO(b"content"), "src.txt")

    client.copy("src.txt", "copy.txt")
    assert client.exists("src.txt")
    assert client.exists("copy.txt")

    client.move("src.txt", "moved.txt")
    assert not client.exists("src.txt")
    assert client.exists("moved.txt")


def test_remove(client: Client) -> None:
    client.upload_fileobj(io.BytesIO(b"x"), "gone.txt")
    assert client.exists("gone.txt")
    client.remove("gone.txt")
    assert not client.exists("gone.txt")


def test_not_found(client: Client) -> None:
    with pytest.raises(ResourceNotFoundError):
        client.info("does-not-exist.txt")


def test_get_props_and_etag(client: Client) -> None:
    client.upload_fileobj(io.BytesIO(b"data"), "e.txt")
    props = client.get_props("e.txt")
    assert props.content_length == 4
    assert props.etag
    assert client.etag("e.txt") == props.etag


def test_ls_lists_members(client: Client) -> None:
    client.mkdir("dir")
    client.upload_fileobj(io.BytesIO(b"1"), "dir/one.txt")
    client.upload_fileobj(io.BytesIO(b"2"), "dir/two.txt")

    # Root-relative, matching fsspec's own AbstractFileSystem.ls() convention
    # (this client's whole reason to expose a `detail=False` mode).
    names = sorted(client.ls("dir", detail=False))
    assert names == ["dir/one.txt", "dir/two.txt"]


def test_lock_and_write_with_held_token(client: Client) -> None:
    client.upload_fileobj(io.BytesIO(b"v1"), "locked.txt")

    with client.lock("locked.txt", scope=EXCLUSIVE) as active_lock:
        assert active_lock.token
        # A write through the same client automatically carries the
        # lock token via the `If` header - must succeed.
        client.upload_fileobj(io.BytesIO(b"v2"), "locked.txt", overwrite=True)

    buf = io.BytesIO()
    client.download_fileobj("locked.txt", buf)
    assert buf.getvalue() == b"v2"


def test_lock_blocks_a_second_client(client: Client, server_url: str) -> None:
    client.upload_fileobj(io.BytesIO(b"v1"), "locked2.txt")

    other = Client(server_url, auth=AUTH)
    try:
        with (
            client.lock("locked2.txt", scope=EXCLUSIVE),
            pytest.raises(ResourceLockedError),
        ):
            other.upload_fileobj(io.BytesIO(b"v2"), "locked2.txt", overwrite=True)
    finally:
        other.close()


def test_set_and_get_custom_property(client: Client) -> None:
    client.upload_fileobj(io.BytesIO(b"x"), "p.txt")
    client.set_props("p.txt", set_props={("https://example.org/ns", "color"): "blue"})

    props = client.get_props("p.txt", names=[("https://example.org/ns", "color")])
    assert props.get("https://example.org/ns", "color") == "blue"
