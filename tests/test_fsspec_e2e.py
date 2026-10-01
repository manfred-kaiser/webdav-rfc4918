"""End-to-end tests for the fsspec filesystem, against a real WebDAV server."""

from collections.abc import Iterator

import pytest

from tests.credentials import AUTH
from webdav.exceptions import ClientError
from webdav.fsspec import WebdavFileSystem
from webdav.session import Session


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
    assert names == ["/dir/one.txt"]

    info = fs.info("dir/one.txt")
    assert info["name"] == "/dir/one.txt"
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


# ---------------------------------------------------------------------------
# Paths start at the root: root_marker == "/" (fsspec/filesystem_spec#2215)
# ---------------------------------------------------------------------------


def test_every_path_is_absolute() -> None:
    assert WebdavFileSystem.root_marker == "/"
    strip = WebdavFileSystem._strip_protocol
    assert strip("a/b") == "/a/b"
    assert strip("/a/b") == "/a/b"
    assert strip("//a/b/") == "/a/b"
    assert strip("webdavs://a/b") == "/a/b"
    assert strip("") == "/"
    assert strip("/") == "/"
    assert strip(["a", "/b"]) == ["/a", "/b"]


def test_a_name_that_ls_returns_goes_back_into_every_other_call(
    fs: WebdavFileSystem,
) -> None:
    fs.pipe_file("d/x.txt", b"1")
    (top,) = fs.ls("/", detail=False)
    assert top == "/d"
    (member,) = fs.ls(top, detail=False)
    assert member == "/d/x.txt"
    assert fs.cat_file(member) == b"1"
    assert [i["name"] for i in fs.ls("/", detail=True)] == ["/d"]
    assert fs.info("/")["type"] == "directory"
    assert sorted(fs.find("/")) == ["/d/x.txt"]


def test_the_root_cannot_be_removed(fs: WebdavFileSystem) -> None:
    fs.pipe_file("keep.txt", b"1")
    for root in ("/", "", "//", "/a/..", "a/.."):
        with pytest.raises((ValueError, OSError)):
            fs.rm(root, recursive=True)
        with pytest.raises((ValueError, OSError)):
            fs.rmdir(root)
    assert fs.exists("/keep.txt")


def test_a_directory_at_the_top_level_nests_into_an_existing_destination(
    fs: WebdavFileSystem, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """The case fsspec.utils.other_paths() gets wrong for a path without any "/" in it.

    ``src`` sits at the top level of the server, and a second ``get`` into the
    (now existing) target has to put it *inside*, as ``cp -r`` does.
    """
    fs.pipe_file("src/a.txt", b"a")
    fs.pipe_file("src/sub/b.txt", b"b")
    target = tmp_path_factory.mktemp("target")
    fs.get("/src", str(target) + "/", recursive=True)
    fs.get("/src", str(target) + "/", recursive=True)
    assert sorted(
        p.relative_to(target).as_posix() for p in target.rglob("*") if p.is_file()
    ) == [
        "src/a.txt",
        "src/sub/b.txt",
    ]


# ---------------------------------------------------------------------------
# A filesystem is bound to one server
# ---------------------------------------------------------------------------


def test_a_filesystem_without_a_base_url_is_refused_with_a_clear_error() -> None:
    with pytest.raises(ValueError, match="bound to one server"):
        WebdavFileSystem()
    with pytest.raises(ValueError, match="bound to one server"):
        WebdavFileSystem(auth=AUTH)
    with pytest.raises(ValueError, match="bound to one server"):
        WebdavFileSystem(session=Session())


def test_a_session_that_has_a_base_url_is_enough() -> None:
    with Session("http://dav.example") as session:
        filesystem = WebdavFileSystem(session=session)
        assert filesystem.filesystem.session is session


def test_fsspec_opens_a_url_without_a_host_against_the_given_base_url(
    server_url: str,
) -> None:
    import fsspec  # noqa: PLC0415

    fsspec.filesystem("webdavs", base_url=server_url, auth=AUTH).pipe_file(
        "/top.txt", b"T"
    )
    with fsspec.open("webdavs:///top.txt", "rb", base_url=server_url, auth=AUTH) as f:
        assert f.read() == b"T"
    _fs, path = fsspec.core.url_to_fs(
        "webdavs:///top.txt", base_url=server_url, auth=AUTH
    )
    assert path == "/top.txt"


def test_the_web_root_is_the_path_of_the_base_url(server_url: str) -> None:
    root = WebdavFileSystem(server_url, auth=AUTH)
    root.pipe_file("sub/a.txt", b"A")
    root.pipe_file("top.txt", b"T")
    sub = WebdavFileSystem(f"{server_url}/sub", auth=AUTH)
    assert sub.ls("/", detail=False) == ["/a.txt"]
    assert sub.cat_file("/a.txt") == b"A"
    assert sub.info("/")["name"] == "/"
    assert sorted(root.ls("/", detail=False)) == ["/sub", "/top.txt"]


@pytest.mark.parametrize("path", ["/../top.txt", "../top.txt", "a/../../top.txt"])
def test_a_path_cannot_leave_the_base_url(server_url: str, path: str) -> None:
    root = WebdavFileSystem(server_url, auth=AUTH)
    root.pipe_file("top.txt", b"T")
    sub = WebdavFileSystem(f"{server_url}/sub", auth=AUTH)
    sub.mkdir("/")
    with pytest.raises(ClientError, match="climbs out"):
        sub.cat_file(path)


def test_dots_and_double_slashes_are_resolved_inside_the_root(server_url: str) -> None:
    filesystem = WebdavFileSystem(server_url, auth=AUTH)
    filesystem.pipe_file("sub/a.txt", b"A")
    for path in ("./sub/a.txt", "sub//a.txt", "sub/../sub/a.txt", "/sub/./a.txt"):
        assert filesystem.cat_file(path) == b"A"


@pytest.mark.parametrize(
    "spelling",
    ["./d", "d/.", "x/../d", "d/sub/..", "a/b/../../d", "/d//", "d/sub/../../d/./"],
)
def test_one_directory_has_one_name_whatever_its_spelling(
    fs: WebdavFileSystem, spelling: str
) -> None:
    """``find``/``walk`` build their names from the path they are given."""
    fs.pipe_file("d/sub/x.txt", b"1")
    assert WebdavFileSystem._strip_protocol(spelling) == "/d"
    assert sorted(fs.find(spelling, withdirs=True)) == ["/d", "/d/sub", "/d/sub/x.txt"]
    assert [root for root, _dirs, _files in fs.walk(spelling)] == ["/d", "/d/sub"]
    assert sorted(fs.expand_path(spelling, recursive=True)) == [
        "/d",
        "/d/sub",
        "/d/sub/x.txt",
    ]


def test_a_path_that_climbs_out_of_the_root_is_left_for_the_session_to_refuse() -> None:
    for path in ("..", "/../a", "a/../..", "a/../../b"):
        assert ".." in WebdavFileSystem._strip_protocol(path)


def test_every_name_a_listing_returns_is_a_fixed_point_of_strip_protocol(
    fs: WebdavFileSystem,
) -> None:
    fs.pipe_file("d/deep/x.txt", b"1")
    fs.pipe_file("top.txt", b"2")
    names = sorted(fs.find("/", withdirs=True))
    assert names == ["/", "/d", "/d/deep", "/d/deep/x.txt", "/top.txt"]
    assert all(WebdavFileSystem._strip_protocol(n) == n for n in names)
    assert next(root for root, _dirs, _files in fs.walk("/")) == "/"
