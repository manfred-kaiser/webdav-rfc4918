"""Every path method fsspec has refuses a URL for another server - also one a later fsspec adds.

The check sits in ``_strip_protocol`` (see ``server_aware``), which fsspec's methods call on the
instance. If a release of fsspec adds a method that takes a path and does not go through it, this
fails, and the method needs a check of its own in ``GuardedFileSystem``.
"""

import inspect
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import fsspec
import pytest
from fsspec.spec import AbstractFileSystem

from tests.credentials import AUTH
from webdav.fsspec import WebdavFileSystem

FOREIGN = "webdavs://other.example/secret.txt"


FIRST_ARGUMENTS = ("path", "rpath", "path1", "root", "urlpath")


#: Take a path but never touch a server with it, or need more than a path.
NOT_CHECKED = {"invalidate_cache", "sign", "get_file", "cat_file_ranges"}


def test_every_path_method_of_fsspec_refuses_another_server() -> None:
    fs = WebdavFileSystem("http://127.0.0.1:9", retry=False, timeout=(0.05, 0.05))
    not_refused = []
    tried = 0
    for name, member in inspect.getmembers(
        AbstractFileSystem, predicate=inspect.isfunction
    ):
        if name.startswith("_") or name in NOT_CHECKED:
            continue
        params = list(inspect.signature(member).parameters.values())[1:]
        if not params or params[0].name not in FIRST_ARGUMENTS:
            continue
        if any(
            p.default is p.empty
            and p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
            for p in params[1:]
        ):
            continue  # needs more than a path
        tried += 1
        try:
            result = getattr(fs, name)(FOREIGN)
            if inspect.isgenerator(result):
                list(result)
        except ValueError as exc:
            if "bound to one server" not in str(exc):
                not_refused.append(name)
        except (
            Exception
        ):  # noqa: BLE001 - anything else means it went on towards the server
            not_refused.append(name)
        else:
            not_refused.append(name)
    assert (
        tried >= 25
    ), "the canary found hardly any methods: has fsspec changed its signatures?"
    assert not_refused == []


@pytest.fixture
def ffs(server_url: str) -> Iterator[WebdavFileSystem]:
    filesystem = WebdavFileSystem(server_url, auth=AUTH)
    yield filesystem
    filesystem.filesystem.close()


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
        lambda fs: fs.get(FOREIGN, "/nonexistent/dst"),
        lambda fs: fs.put(__file__, "webdavs://other.example/new"),
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
