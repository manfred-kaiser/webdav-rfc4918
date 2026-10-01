"""End-to-end tests for the fsspec filesystem, against a real WebDAV server."""

import pickle
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlsplit

import fsspec
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
    assert strip("webdavs:///a/b") == "/a/b"
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


# ---------------------------------------------------------------------------
# A host in the URL names the server: webdavs://host[:port]/path
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "path", "options"),
    [
        ("webdavs://host/d/f", "/d/f", {"host": "host"}),
        ("webdavs://host:8443/d/f", "/d/f", {"host": "host", "port": 8443}),
        ("webdavs://HOST", "/", {"host": "HOST"}),
        ("webdavs://host/", "/", {"host": "host"}),
        ("webdavs://[::1]:8443/x", "/x", {"host": "::1", "port": 8443}),
        ("webdavs://host/a/../b/./c", "/b/c", {"host": "host"}),
        ("webdavs:///d/f", "/d/f", {}),
        ("webdavs:///", "/", {}),
        # without the scheme there is no authority: a leading "//" is a path
        ("//a/b/", "/a/b", {}),
        ("a/b", "/a/b", {}),
    ],
)
def test_the_host_of_a_url_is_an_option_and_not_part_of_the_path(
    url: str, path: str, options: dict[str, object]
) -> None:
    assert WebdavFileSystem._strip_protocol(url) == path
    assert WebdavFileSystem._get_kwargs_from_urls(url) == options


@pytest.mark.parametrize(
    "url", ["webdavs://user:secret@host/d", "webdavs://user@host/d"]
)
def test_credentials_in_a_url_are_refused_and_never_echoed(url: str) -> None:
    for call in (
        WebdavFileSystem._strip_protocol,
        WebdavFileSystem._get_kwargs_from_urls,
    ):
        with pytest.raises(ValueError, match="pass auth") as caught:
            call(url)
        assert "secret" not in str(caught.value)


def test_a_port_that_is_no_number_is_refused() -> None:
    with pytest.raises(ValueError, match="host"):
        WebdavFileSystem._get_kwargs_from_urls("webdavs://host:eighty/d")


def test_without_a_base_url_the_host_of_the_url_is_the_server_over_tls() -> None:
    for host, port, expected in [
        ("dav.example", None, "https://dav.example"),
        ("dav.example", 8443, "https://dav.example:8443"),
        ("::1", 8443, "https://[::1]:8443"),
    ]:
        filesystem = WebdavFileSystem(host=host, port=port)
        assert filesystem.filesystem.session.base_url == expected
        filesystem.filesystem.close()
    filesystem, path = fsspec.core.url_to_fs("webdavs://dav.example:8443/d/f")
    assert filesystem.filesystem.session.base_url == "https://dav.example:8443"
    assert path == "/d/f"
    filesystem.filesystem.close()


def test_the_host_of_a_url_is_the_server_of_the_base_url(server_url: str) -> None:
    """Plain http is reached through ``base_url``; the URL only has to name the same server."""
    netloc = urlsplit(server_url).netloc
    fsspec.filesystem("webdavs", base_url=server_url, auth=AUTH).pipe_file(
        "/top.txt", b"T"
    )
    with fsspec.open(
        f"webdavs://{netloc}/top.txt", "rb", base_url=server_url, auth=AUTH
    ) as f:
        assert f.read() == b"T"
    with fsspec.open(
        f"webdavs://{netloc.upper()}/top.txt", "rb", base_url=server_url, auth=AUTH
    ) as f:
        assert f.read() == b"T"
    _fs, path = fsspec.core.url_to_fs(
        f"webdavs://{netloc}/top.txt", base_url=server_url, auth=AUTH
    )
    assert path == "/top.txt"


def test_a_host_never_becomes_a_directory_on_the_server(server_url: str) -> None:
    """It used to: ``webdavs://127.0.0.1:1234/p/f`` was written to ``/127.0.0.1:1234/p/f``."""
    netloc = urlsplit(server_url).netloc
    with fsspec.open(
        f"webdavs://{netloc}/p/f.txt", "wb", base_url=server_url, auth=AUTH
    ) as f:
        f.write(b"x")
    filesystem = fsspec.filesystem("webdavs", base_url=server_url, auth=AUTH)
    assert filesystem.find("/") == ["/p/f.txt"]


def test_the_base_url_may_have_a_path_the_host_is_still_the_servers(
    server_url: str,
) -> None:
    netloc = urlsplit(server_url).netloc
    root = WebdavFileSystem(server_url, auth=AUTH)
    root.pipe_file("/sub/a.txt", b"A")
    with fsspec.open(
        f"webdavs://{netloc}/a.txt", "rb", base_url=f"{server_url}/sub", auth=AUTH
    ) as f:
        assert f.read() == b"A"


@pytest.mark.parametrize(
    "url",
    [
        "webdavs://evil.example/top.txt",
        "webdavs://127.0.0.1:1/top.txt",  # the right host, another port
    ],
)
def test_a_url_cannot_send_a_filesystem_to_another_server(
    server_url: str, url: str
) -> None:
    """The ``base_url`` wins; a URL that names another server is an error, not a redirect."""
    with pytest.raises(ValueError, match="bound to one server"):
        fsspec.open(url, "rb", base_url=server_url, auth=AUTH).open()
    with pytest.raises(ValueError, match="bound to one server"):
        WebdavFileSystem(
            server_url, auth=AUTH, host=(urlsplit(url).hostname or "") + "x"
        )


def test_the_host_of_a_url_works_through_every_front_door(
    server_url: str, tmp_path: Path
) -> None:
    netloc = urlsplit(server_url).netloc
    options = {"base_url": server_url, "auth": AUTH}
    filesystem = fsspec.filesystem("webdavs", **options)
    filesystem.pipe_file("/d/a.txt", b"A")
    filesystem.pipe_file("/d/b.txt", b"B")
    base = f"webdavs://{netloc}/d"

    files = fsspec.open_files(f"{base}/*.txt", "rb", **options)
    assert [f.path for f in files] == ["/d/a.txt", "/d/b.txt"]
    assert sorted(fsspec.get_mapper(base, **options)) == ["a.txt", "b.txt"]
    with fsspec.open(
        f"simplecache::{base}/a.txt",
        "rb",
        webdavs=options,
        simplecache={"cache_storage": str(tmp_path)},
    ) as f:
        assert f.read() == b"A"


def test_a_filesystem_made_from_a_url_survives_serialisation(server_url: str) -> None:
    netloc = urlsplit(server_url).netloc
    filesystem, _path = fsspec.core.url_to_fs(
        f"webdavs://{netloc}/d", base_url=server_url, auth=AUTH
    )
    filesystem.pipe_file("/d/a.txt", b"A")
    for restored in (
        # our own bytes
        pickle.loads(pickle.dumps(filesystem)),  # noqa: S301
        fsspec.AbstractFileSystem.from_json(filesystem.to_json()),
    ):
        assert restored.cat_file("/d/a.txt") == b"A"
        restored.filesystem.close()
    filesystem.filesystem.close()


@pytest.mark.parametrize("name", ["a/b", "/a/b", "./a/../a/b", "//a//b"])
def test_a_url_is_made_of_the_absolute_path(fs: WebdavFileSystem, name: str) -> None:
    """``webdavs://a/b`` would name the host ``a``: the round trip has to keep the root."""
    url = fs.unstrip_protocol(name)
    assert url == "webdavs:///a/b"
    assert fs._strip_protocol(url) == "/a/b"
    assert fs.unstrip_protocol(url) == url


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
