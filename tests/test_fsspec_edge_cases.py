# pylint: disable=too-many-lines  # one file per server or per topic: the length is the number of checks
"""Edge cases of the fsspec filesystem that fsspec's own conformance suite does not reach.

``tests/test_fsspec_abstract.py`` runs the official suite, which checks what *every* backend
has to do for ``cp``/``get``/``put``/``pipe``/``open``. This module is ours: it pins what is
particular to WebDAV and to this implementation - which exception a failing call raises, what a
half-finished write leaves behind, which file names survive the trip through a URL, how the
filesystem is serialised, what a server that misbehaves cannot make it do.

Most tests run against a real WsgiDAV server (``server_url``); the few that need a server to
answer something specific use ``scripted_server``.
"""

import copy
import errno
import gc
import io
import os
import pickle
import re
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, TypeVar, cast

import fsspec
import pytest
from fsspec.callbacks import Callback

from tests.builders import multistatus_doc, sized_entry
from tests.certificates import Certificates
from tests.credentials import AUTH
from tests.mtls_server import mtls_webdav_server
from tests.scripted_server import DRIP, Reply, Seen, scripted_server
from webdav.exceptions import (
    ClientError,
    HTTPStatusError,
    InternalServerError,
    ResourceLockedError,
)
from webdav.fsspec import WebdavFileSystem

if TYPE_CHECKING:
    from collections.abc import Callable


_T = TypeVar("_T")


@pytest.fixture
def fs(server_url: str) -> Iterator[WebdavFileSystem]:
    filesystem = WebdavFileSystem(server_url, auth=AUTH)
    yield filesystem
    filesystem.filesystem.close()


@pytest.mark.parametrize(
    "method", ["ls", "info", "size", "modified", "created", "checksum", "cat_file"]
)
def test_a_missing_path_is_a_file_not_found_error(
    fs: WebdavFileSystem, method: str
) -> None:
    with pytest.raises(FileNotFoundError):
        getattr(fs, method)("/nope")


@pytest.mark.parametrize(
    "write",
    [
        lambda fs: fs.open("/d", "wb").close(),
        lambda fs: fs.pipe_file("/d", b"x"),
        lambda fs: fs.touch("/d", truncate=True),
    ],
    ids=["open", "pipe_file", "touch"],
)
def test_writing_to_a_directory_is_an_is_a_directory_error(
    fs: WebdavFileSystem, write: "Callable[[WebdavFileSystem], object]"
) -> None:
    fs.pipe_file("/d/f", b"1")
    with pytest.raises(IsADirectoryError):
        write(fs)
    assert fs.find("/d") == ["/d/f"]


def test_a_missing_path_is_not_an_error_for_exists_and_the_type_checks(
    fs: WebdavFileSystem,
) -> None:
    assert not fs.exists("/nope")
    assert not fs.isdir("/nope")
    assert not fs.isfile("/nope")


@pytest.mark.parametrize("method", ["exists", "isdir", "isfile"])
@pytest.mark.parametrize(
    ("status", "error"),
    [(403, PermissionError), (500, InternalServerError)],
)
def test_exists_and_the_type_checks_raise_what_is_not_a_missing_path(
    method: str, status: int, error: type[Exception]
) -> None:
    """A server that fails is not a server without the path."""
    with scripted_server(lambda _seen: (status, {}, b"")) as (url, _recorder):
        fs = WebdavFileSystem(url)
        with pytest.raises(error):
            getattr(fs, method)("/f")
        fs.filesystem.close()


@pytest.mark.parametrize("method", ["exists", "isdir", "isfile"])
def test_exists_and_the_type_checks_raise_a_connection_error(method: str) -> None:
    """Nobody listens on the port: the answer is the error, not "no"."""
    with scripted_server(lambda _seen: (200, {}, b"")) as (url, _recorder):
        pass  # the server is shut down again, so the port is closed
    fs = WebdavFileSystem(url)
    with pytest.raises(OSError):  # noqa: PT011
        getattr(fs, method)("/f")
    fs.filesystem.close()


@pytest.mark.parametrize("method", ["exists", "isdir", "isfile"])
def test_exists_and_the_type_checks_raise_a_tls_error(
    method: str, tmp_path: Path
) -> None:
    """An untrusted certificate is not a missing path."""
    (tmp_path / "certs").mkdir()
    certs = Certificates(tmp_path / "certs")
    with mtls_webdav_server(str(tmp_path), certs) as url:
        fs = WebdavFileSystem(url)
        with pytest.raises(OSError, match="CERTIFICATE_VERIFY_FAILED"):
            getattr(fs, method)("/f")
        fs.filesystem.close()


def test_reading_a_directory_as_a_file_is_an_is_a_directory_error(
    fs: WebdavFileSystem,
) -> None:
    fs.mkdir("/d")
    with pytest.raises(IsADirectoryError):
        fs.cat_file("/d")
    with pytest.raises(IsADirectoryError):
        fs.open("/d", "rb")


def test_a_path_below_a_file_does_not_exist(fs: WebdavFileSystem) -> None:
    fs.pipe_file("/f", b"x")
    assert not fs.exists("/f/below")
    assert not fs.isdir("/f/")
    assert fs.isfile("/f")


def test_mkdir_over_a_file_and_below_a_file(fs: WebdavFileSystem) -> None:
    fs.pipe_file("/f", b"x")
    with pytest.raises(FileExistsError):
        fs.mkdir("/f")
    with pytest.raises(NotADirectoryError):
        fs.mkdir("/f/sub")
    assert fs.cat_file("/f") == b"x"


def test_mkdir_creates_parents_unless_told_not_to(fs: WebdavFileSystem) -> None:
    with pytest.raises(FileNotFoundError):
        fs.mkdir("/a/b", create_parents=False)
    assert not fs.exists("/a")
    fs.mkdir("/a/b")
    assert fs.isdir("/a/b")
    fs.mkdir("/a/b")  # `mkdir -p`: a directory that is already there is fine


def test_makedirs_exist_ok_decides_whether_an_existing_directory_is_an_error(
    fs: WebdavFileSystem,
) -> None:
    fs.makedirs("/d/e")
    fs.makedirs("/d/e", exist_ok=True)
    with pytest.raises(FileExistsError):
        fs.makedirs("/d/e", exist_ok=False)


def test_rmdir_refuses_a_directory_that_has_content(fs: WebdavFileSystem) -> None:
    fs.pipe_file("/d/a", b"x")
    with pytest.raises(OSError, match="not empty") as caught:
        fs.rmdir("/d")
    assert caught.value.errno == errno.ENOTEMPTY
    assert fs.exists("/d/a")


def test_rmdir_of_a_file_is_a_not_a_directory_error(fs: WebdavFileSystem) -> None:
    fs.pipe_file("/f", b"x")
    with pytest.raises(NotADirectoryError):
        fs.rmdir("/f")
    assert fs.exists("/f")


def test_rm_of_a_directory_with_content_needs_recursive(fs: WebdavFileSystem) -> None:
    fs.pipe_file("/d/sub/a", b"x")
    with pytest.raises(OSError, match="not empty"):
        fs.rm("/d")
    with pytest.raises(OSError, match="not empty"):
        fs.rm("/d", recursive=False)
    assert fs.exists("/d/sub/a")
    fs.rm("/d", recursive=True)
    assert not fs.exists("/d")


def test_rm_of_an_empty_directory_needs_no_recursive(fs: WebdavFileSystem) -> None:
    fs.mkdir("/d")
    fs.rm("/d")
    assert not fs.exists("/d")


def test_rm_of_a_missing_path_is_a_file_not_found_error(fs: WebdavFileSystem) -> None:
    with pytest.raises(FileNotFoundError):
        fs.rm("/nope")
    with pytest.raises(FileNotFoundError):
        fs.rm_file("/nope")


def test_rm_takes_a_list_and_removes_what_it_names(fs: WebdavFileSystem) -> None:
    fs.pipe({"/a": b"1", "/b": b"2", "/keep": b"3"})
    fs.rm(["/a", "/b"])
    assert fs.ls("/", detail=False) == ["/keep"]


def test_sign_is_not_supported(fs: WebdavFileSystem) -> None:
    fs.pipe_file("/a", b"1")
    with pytest.raises(NotImplementedError):
        fs.sign("/a")


def _write_and_fail(fs: WebdavFileSystem, path: str) -> None:
    """Write to ``path`` and raise before the file is closed cleanly."""
    with fs.open(path, "wb") as f:
        f.write(b"new")
        msg = "boom"
        raise RuntimeError(msg)


def test_a_write_that_raises_leaves_the_old_content_untouched(
    fs: WebdavFileSystem,
) -> None:
    fs.pipe_file("/w", b"old")
    with pytest.raises(RuntimeError, match="boom"):
        _write_and_fail(fs, "/w")
    assert fs.cat_file("/w") == b"old"


def test_a_write_that_raises_creates_nothing(fs: WebdavFileSystem) -> None:
    with pytest.raises(RuntimeError, match="boom"):
        _write_and_fail(fs, "/new/w")
    assert not fs.exists("/new/w")


def test_a_write_creates_the_missing_parent_collections(fs: WebdavFileSystem) -> None:
    with fs.open("/p/q/w", "wb") as f:
        f.write(b"abc")
    assert fs.cat_file("/p/q/w") == b"abc"
    assert fs.isdir("/p/q")


def test_a_write_with_nothing_written_creates_an_empty_file(
    fs: WebdavFileSystem,
) -> None:
    with fs.open("/empty", "wb"):
        pass
    assert fs.size("/empty") == 0
    assert fs.cat_file("/empty") == b""


def test_a_file_can_be_closed_twice(fs: WebdavFileSystem) -> None:
    f = fs.open("/w", "wb")
    f.write(b"once")
    f.close()
    f.close()
    assert fs.cat_file("/w") == b"once"


def test_exclusive_create_does_not_touch_what_is_there(fs: WebdavFileSystem) -> None:
    fs.pipe_file("/w", b"first")
    with pytest.raises(FileExistsError):
        fs.open("/w", "xb")
    with pytest.raises(FileExistsError):
        fs.pipe_file("/w", b"second", mode="create")
    assert fs.cat_file("/w") == b"first"
    fs.pipe_file("/fresh", b"x", mode="create")
    assert fs.cat_file("/fresh") == b"x"


def test_append_is_refused_everywhere(fs: WebdavFileSystem) -> None:
    """WebDAV's PUT always replaces the whole resource - append would have to read, modify, write."""
    fs.pipe_file("/w", b"1")
    with pytest.raises(ValueError, match="append"):
        fs.open("/w", "ab")
    with pytest.raises(NotImplementedError, match="append"):
        fs.pipe_file("/w", b"2", mode="append")
    assert fs.cat_file("/w") == b"1"


def test_pipe_file_wants_bytes(fs: WebdavFileSystem) -> None:
    with pytest.raises(TypeError):
        fs.pipe_file("/s", "text")  # type: ignore[arg-type]
    assert not fs.exists("/s")


def test_text_mode_encodes_and_decodes(fs: WebdavFileSystem) -> None:
    with fs.open("/t", "w", encoding="utf-16") as f:
        f.write("héllo")
    assert fs.cat_file("/t") == "héllo".encode("utf-16")
    with fs.open("/t", "r", encoding="utf-16") as f:
        assert f.read() == "héllo"
    fs.pipe_file("/l1", "é".encode("latin-1"))
    with fs.open("/l1", "r", encoding="latin-1") as f:
        assert f.read() == "é"


def test_a_large_file_survives_the_round_trip(fs: WebdavFileSystem) -> None:
    payload = bytes(range(256)) * (
        3 * 4096 + 1
    )  # ~3 MB, not a multiple of any block size
    with fs.open("/big.bin", "wb") as f:
        for start in range(0, len(payload), 500_000):
            f.write(payload[start : start + 500_000])
    assert fs.size("/big.bin") == len(payload)
    assert fs.cat_file("/big.bin") == payload

    chunks = []
    with fs.open("/big.bin", "rb", block_size=64 * 1024) as f:
        while chunk := f.read(100_000):
            chunks.append(chunk)
    assert b"".join(chunks) == payload


@pytest.mark.parametrize(
    ("start", "end", "expected"),
    [
        (2, 5, b"234"),
        (None, 3, b"012"),
        (-3, None, b"789"),
        (0, -2, b"01234567"),
        (8, 100, b"89"),
        (10, None, b""),
        (5, 5, b""),
    ],
)
def test_cat_file_ranges(
    fs: WebdavFileSystem, start: "int | None", end: "int | None", expected: bytes
) -> None:
    fs.pipe_file("/f", b"0123456789")
    assert fs.cat_file("/f", start, end) == expected


def test_seek_and_read_follow_the_file_position(fs: WebdavFileSystem) -> None:
    fs.pipe_file("/s", b"0123456789")
    with fs.open("/s", "rb") as f:
        assert f.tell() == 0
        f.seek(3)
        assert f.read(2) == b"34"
        assert f.tell() == 5
        f.seek(2, 1)
        assert f.read(1) == b"7"
        f.seek(-2, 2)
        assert f.read() == b"89"
        f.seek(0)
        assert f.read(0) == b""
        assert f.tell() == 0
        assert f.read(3) == b"012"


def test_lines_and_iteration(fs: WebdavFileSystem) -> None:
    fs.pipe_file("/l", b"a\nbb\nccc")
    with fs.open("/l", "rb") as f:
        assert f.readline() == b"a\n"
        assert list(f) == [b"bb\n", b"ccc"]
    with fs.open("/l", "r") as f:
        assert f.read().splitlines() == ["a", "bb", "ccc"]


def test_an_empty_file(fs: WebdavFileSystem) -> None:
    fs.pipe_file("/e", b"")
    assert fs.cat_file("/e") == b""
    assert fs.size("/e") == 0
    assert fs.info("/e")["size"] == 0
    assert fs.ls("/", detail=False) == ["/e"]
    with fs.open("/e", "rb") as f:
        assert f.read() == b""
        assert f.read(10) == b""


@pytest.mark.parametrize(("start", "end"), [(20, None), (20, 30), (10, 20), (11, 12)])
def test_reading_from_beyond_the_end_gives_nothing(
    fs: WebdavFileSystem, start: int, end: "int | None"
) -> None:
    """Like a local file; a range request for it would be refused with 416."""
    fs.pipe_file("/f", b"0123456789")
    assert fs.cat_file("/f", start, end) == b""


def test_seeking_beyond_the_end_reads_nothing_and_can_come_back(
    fs: WebdavFileSystem,
) -> None:
    fs.pipe_file("/f", b"0123456789")
    with fs.open("/f", "rb") as f:
        f.seek(20)
        assert f.tell() == 20
        assert f.read(5) == b""
        assert f.read() == b""
        f.seek(2)
        assert f.read(2) == b"23"


def test_nothing_can_be_read_beyond_an_empty_file(fs: WebdavFileSystem) -> None:
    fs.pipe_file("/e", b"")
    assert fs.cat_file("/e", 1) == b""
    with fs.open("/e", "rb") as f:
        f.seek(5)
        assert f.read() == b""


def test_a_closed_file_cannot_be_read(fs: WebdavFileSystem) -> None:
    fs.pipe_file("/f", b"x")
    f = fs.open("/f", "rb")
    f.close()
    assert f.closed
    with pytest.raises(ValueError, match="closed file"):
        f.read()
    with pytest.raises(ValueError, match="closed file"):
        f.read(1)


def test_a_directory_has_no_size_and_no_checksum(fs: WebdavFileSystem) -> None:
    fs.mkdir("/d")
    assert fs.size("/d") is None
    assert fs.checksum("/d") is None
    assert fs.info("/d")["type"] == "directory"


def test_the_checksum_is_stable_and_differs_between_resources(
    fs: WebdavFileSystem,
) -> None:
    fs.pipe_file("/a", b"1")
    fs.pipe_file("/b", b"1")
    first = fs.checksum("/a")
    assert first
    assert fs.checksum("/a") == first
    assert fs.checksum("/b") != first


def test_modified_and_created_are_timezone_aware(fs: WebdavFileSystem) -> None:
    fs.pipe_file("/m", b"1")
    modified = fs.modified("/m")
    assert modified is not None
    assert modified.tzinfo is not None


AWKWARD_NAMES = [
    "sp ace.txt",
    "per%cent.txt",
    "%41.txt",
    "100%",
    "a%2Fb",
    "hash#tag",
    "q?uery",
    "plus+sign",
    "amp&er",
    "semi;colon",
    "a=b",
    "colon:name",
    "a,b",
    "quo'te",
    "ünï.txt",
    "日本語.txt",
    "emoji-😀.txt",
    ".hidden",
    "~tilde",
    "at@sign",
    "(parens)",
    "[brackets]",
]


@pytest.mark.parametrize("name", AWKWARD_NAMES)
def test_an_awkward_name_is_the_same_name_on_the_way_back(
    fs: WebdavFileSystem, name: str
) -> None:
    path = f"/dir with space#1/{name}"
    fs.pipe_file(path, name.encode())
    assert fs.cat_file(path) == name.encode()
    assert fs.ls("/dir with space#1", detail=False) == [path]
    assert fs.info(path)["name"] == path
    assert fs.exists(path)
    assert not fs.exists(path + "x")
    # rm_file, not rm: rm() expands its argument as a glob first, so "[brackets]" would
    # mean "one of the characters b, r, a, ..." - for every fsspec backend, not just this one.
    fs.rm_file(path)
    assert not fs.exists(path)


def test_a_name_that_looks_percent_encoded_is_not_decoded(
    fs: WebdavFileSystem,
) -> None:
    fs.pipe_file("/%41", b"literal")
    fs.pipe_file("/A", b"decoded")
    assert fs.cat_file("/%41") == b"literal"
    assert fs.cat_file("/A") == b"decoded"
    assert sorted(fs.ls("/", detail=False)) == ["/%41", "/A"]


def test_find_glob_du_and_walk_agree(fs: WebdavFileSystem) -> None:
    fs.pipe_file("/a/x.txt", b"1")
    fs.pipe_file("/a/b/y.txt", b"22")
    fs.pipe_file("/z.log", b"333")
    assert sorted(fs.find("/")) == ["/a/b/y.txt", "/a/x.txt", "/z.log"]
    assert sorted(fs.find("/", maxdepth=1)) == ["/z.log"]
    assert sorted(fs.find("/", withdirs=True)) == [
        "/",
        "/a",
        "/a/b",
        "/a/b/y.txt",
        "/a/x.txt",
        "/z.log",
    ]
    assert sorted(fs.glob("/**/*.txt")) == ["/a/b/y.txt", "/a/x.txt"]
    assert sorted(fs.glob("/a/*")) == ["/a/b", "/a/x.txt"]
    assert fs.du("/") == 6
    assert sorted(fs.du("/a", total=False).items()) == [
        ("/a/b/y.txt", 2),
        ("/a/x.txt", 1),
    ]
    root, dirs, files = next(iter(fs.walk("/")))
    assert (root, sorted(dirs), sorted(files)) == ("/", ["a"], ["z.log"])


def test_glob_wildcards(fs: WebdavFileSystem) -> None:
    for name in ("a1", "a2", "b1"):
        fs.pipe_file(f"/{name}", b"")
    assert sorted(fs.glob("/a?")) == ["/a1", "/a2"]
    assert sorted(fs.glob("/[ab]1")) == ["/a1", "/b1"]
    assert sorted(fs.glob("/*")) == ["/a1", "/a2", "/b1"]
    assert fs.glob("/nothing*") == []


def test_listing_an_empty_directory(fs: WebdavFileSystem) -> None:
    fs.mkdir("/d")
    assert fs.ls("/d", detail=False) == []
    assert fs.ls("/d") == []
    assert fs.find("/d") == []


def test_listing_a_file_lists_that_file(fs: WebdavFileSystem) -> None:
    """As for a local file or an S3 key - fsspec's ``walk`` and ``find`` rely on it."""
    fs.pipe_file("/d/f.txt", b"abc")
    assert fs.ls("/d/f.txt", detail=False) == ["/d/f.txt"]
    (entry,) = fs.ls("/d/f.txt")
    assert (entry["name"], entry["type"], entry["size"]) == ("/d/f.txt", "file", 3)
    with pytest.raises(FileNotFoundError):
        fs.ls("/d/nope.txt")


def test_a_file_is_what_find_walk_glob_and_du_make_of_it(fs: WebdavFileSystem) -> None:
    fs.pipe_file("/f", b"abc")
    assert fs.find("/f") == ["/f"]
    assert fs.glob("/f") == ["/f"]
    assert fs.du("/f") == 3
    assert list(fs.walk("/f")) == [("/f", [], [""])]  # the same as LocalFileSystem


def test_info_of_the_root(fs: WebdavFileSystem) -> None:
    info = fs.info("/")
    assert (info["name"], info["type"]) == ("/", "directory")
    assert fs.exists("")
    assert fs.isdir("/")
    assert not fs.isfile("/")


def test_cat_takes_a_glob_a_list_and_keeps_going_on_request(
    fs: WebdavFileSystem,
) -> None:
    fs.pipe({"/d/1": b"one", "/d/2": b"two"})
    assert fs.cat("/d/*") == {"/d/1": b"one", "/d/2": b"two"}
    result = fs.cat(["/d/1", "/nope"], on_error="return")
    assert result["/d/1"] == b"one"
    assert isinstance(result["/nope"], FileNotFoundError)
    with pytest.raises(FileNotFoundError):
        fs.cat(["/d/1", "/nope"])


def test_touch_creates_a_file_but_cannot_only_update_its_timestamp(
    fs: WebdavFileSystem,
) -> None:
    """``getlastmodified`` is a protected property: no WebDAV request sets it."""
    fs.touch("/t")
    assert fs.size("/t") == 0
    fs.pipe_file("/t", b"abc")
    with pytest.raises(NotImplementedError):
        fs.touch("/t", truncate=False)
    assert fs.cat_file("/t") == b"abc"
    fs.touch("/t")  # truncate=True, the default, is a rewrite
    assert fs.cat_file("/t") == b""


def test_copy_and_move_replace_an_existing_file(fs: WebdavFileSystem) -> None:
    """As ``LocalFileSystem`` does, and as ``pipe_file`` and ``open("wb")`` do here."""
    fs.pipe_file("/a", b"1")
    fs.pipe_file("/b", b"2")
    fs.pipe_file("/c", b"3")
    fs.cp("/a", "/b")
    assert fs.cat_file("/a") == fs.cat_file("/b") == b"1"
    fs.mv("/a", "/c")
    assert not fs.exists("/a")
    assert fs.cat_file("/c") == b"1"


def test_copy_replaces_an_existing_file_in_a_new_parent_too(
    fs: WebdavFileSystem,
) -> None:
    """``cp_file`` creates the parents first, then the COPY meets the file that is there."""
    fs.pipe_file("/a", b"new")
    fs.pipe_file("/x/y", b"old")
    fs.cp_file("/a", "/x/y")
    assert fs.cat_file("/x/y") == b"new"
    fs.cp_file("/a", "/p/q/r")
    assert fs.cat_file("/p/q/r") == b"new"


def test_a_directory_is_never_replaced_by_a_copy(fs: WebdavFileSystem) -> None:
    """COPY with ``Overwrite: T`` deletes the destination with ``Depth: infinity``."""
    fs.pipe_file("/a", b"1")
    fs.pipe_file("/d/f", b"2")
    for destination in ("/d", "/d/"):
        with pytest.raises(FileExistsError):
            fs.cp_file("/a", destination)
    assert fs.cat_file("/a") == b"1"
    assert sorted(fs.find("/d")) == ["/d/f"]
    assert fs.cat_file("/d/f") == b"2"


def test_a_file_moved_onto_a_directory_goes_into_it(fs: WebdavFileSystem) -> None:
    fs.pipe_file("/a", b"1")
    fs.pipe_file("/d/f", b"2")
    fs.mv("/a", "/d")
    assert sorted(fs.find("/")) == ["/d/a", "/d/f"]


@pytest.mark.parametrize(
    ("destination", "error"),
    [("/f", FileExistsError), ("/f/", NotADirectoryError)],
)
def test_a_directory_copied_onto_a_file_leaves_the_file_alone(
    fs: WebdavFileSystem, destination: str, error: type[OSError]
) -> None:
    fs.pipe_file("/f", b"1")
    fs.pipe_file("/d/x", b"2")
    with pytest.raises(error):
        fs.cp("/d", destination, recursive=True)
    assert fs.cat_file("/f") == b"1"
    assert fs.cat_file("/d/x") == b"2"


def test_copy_and_move_of_a_missing_source(fs: WebdavFileSystem) -> None:
    with pytest.raises(FileNotFoundError):
        fs.cp("/nope", "/b")
    with pytest.raises(FileNotFoundError):
        fs.mv("/nope", "/b")
    assert not fs.exists("/b")


def test_copying_onto_itself_or_into_itself_is_a_permission_error(
    fs: WebdavFileSystem,
) -> None:
    """RFC 4918 forbids it (403); callers get the stdlib error, and nothing is lost."""
    fs.pipe_file("/a", b"1")
    fs.pipe_file("/d/x", b"1")
    with pytest.raises(PermissionError):
        fs.cp("/a", "/a")
    with pytest.raises(PermissionError):
        fs.cp("/d", "/d/inner", recursive=True)
    with pytest.raises(PermissionError):
        fs.mv("/d", "/d/inner", recursive=True)
    assert fs.cat_file("/a") == b"1"
    assert sorted(fs.find("/d")) == ["/d/x"]


def test_moving_a_file_onto_itself_keeps_the_file(fs: WebdavFileSystem) -> None:
    fs.pipe_file("/a", b"1")
    fs.mv("/a", "/a")
    assert fs.cat_file("/a") == b"1"


@pytest.mark.parametrize("destination", ["/d", "d", "d/", "./d", "/x/../d"])
def test_moving_a_path_onto_itself_is_a_no_op_whatever_its_spelling(
    fs: WebdavFileSystem, destination: str
) -> None:
    """``fsspec`` compares the strings; ``mv("/d", "d")`` would copy ``d`` into itself, then delete it."""
    fs.pipe_file("/d/f", b"1")
    fs.pipe_file("/d/sub/g", b"2")
    fs.mv("/d", destination, recursive=True)
    assert sorted(fs.find("/")) == ["/d/f", "/d/sub/g"]


@pytest.mark.parametrize("destination", ["/d/sub", "/d/sub/", "d/sub", "/d/new"])
@pytest.mark.parametrize("operation", ["cp", "mv"])
def test_a_directory_is_never_copied_or_moved_into_itself(
    fs: WebdavFileSystem, operation: str, destination: str
) -> None:
    """Into an *existing* directory below it the work is done entry by entry, and ``mv`` ends by deleting the source - the whole tree, with the copy in it."""
    fs.pipe_file("/d/f", b"1")
    fs.pipe_file("/d/sub/g", b"2")
    with pytest.raises(PermissionError):
        getattr(fs, operation)("/d", destination, recursive=True)
    assert sorted(fs.find("/")) == ["/d/f", "/d/sub/g"]


def test_a_directory_is_never_copied_onto_itself(fs: WebdavFileSystem) -> None:
    """``fsspec`` would nest it: ``cp("/d", "/d")`` is a copy into the existing directory ``/d``."""
    fs.pipe_file("/d/f", b"1")
    for destination in ("/d", "d/", "./d"):
        with pytest.raises(PermissionError):
            fs.cp("/d", destination, recursive=True)
    assert sorted(fs.find("/")) == ["/d/f"]


@pytest.mark.parametrize("destination", ["/x", "x", "/e/", "/e"])
@pytest.mark.parametrize("operation", ["cp", "mv"])
def test_the_root_is_never_copied_or_moved(
    fs: WebdavFileSystem, operation: str, destination: str
) -> None:
    """Every destination is below the root; the server answers a root COPY/MOVE with a 500."""
    fs.pipe_file("/d/f", b"1")
    fs.mkdir("/e")
    for root in ("/", "", "/d/..", "."):
        with pytest.raises(PermissionError):
            getattr(fs, operation)(root, destination, recursive=True)
    assert sorted(fs.find("/", withdirs=True)) == ["/", "/d", "/d/f", "/e"]


def test_a_non_recursive_copy_into_a_directory_below_it_is_not_refused(
    fs: WebdavFileSystem,
) -> None:
    """Without ``recursive`` a directory is not taken along at all: nothing to refuse, nothing copied."""
    fs.pipe_file("/d/f", b"1")
    fs.mkdir("/d/sub")
    fs.cp("/d", "/d/sub")
    assert sorted(fs.find("/")) == ["/d/f"]


def test_copy_creates_the_missing_parents_of_the_destination(
    fs: WebdavFileSystem,
) -> None:
    fs.pipe_file("/a", b"1")
    fs.cp("/a", "/new/deep/b")
    assert fs.cat_file("/new/deep/b") == b"1"
    assert fs.cat_file("/a") == b"1"


def test_copy_into_an_existing_directory_by_trailing_slash(
    fs: WebdavFileSystem,
) -> None:
    fs.pipe_file("/a", b"1")
    fs.pipe_file("/b", b"2")
    fs.mkdir("/d")
    fs.cp(["/a", "/b"], "/d/")
    assert sorted(fs.ls("/d", detail=False)) == ["/d/a", "/d/b"]
    fs.pipe_file("/a", b"changed")
    fs.cp("/a", "/d/")  # the copy that is already there is replaced, like a file
    assert fs.cat_file("/d/a") == b"changed"


@pytest.mark.parametrize("operation", ["cp", "mv"])
@pytest.mark.parametrize("destination", ["/e", "/e/", "e/"])
def test_a_directory_goes_into_a_destination_with_a_trailing_slash(
    fs: WebdavFileSystem, operation: str, destination: str
) -> None:
    """``cp("d", "e/")`` is "into e", also when ``e`` does not exist yet - as ``cp -r d e/``."""
    fs.pipe_file("/d/f", b"1")
    fs.pipe_file("/d/sub/g", b"2")
    getattr(fs, operation)("/d", destination, recursive=True)
    expected = (
        ["/e/d/f", "/e/d/sub/g"] if destination.endswith("/") else ["/e/f", "/e/sub/g"]
    )
    kept = [] if operation == "mv" else ["/d/f", "/d/sub/g"]
    assert sorted(fs.find("/")) == sorted(expected + kept)


@pytest.mark.parametrize("destination", ["/t", "/t/", "t"])
def test_a_directory_is_moved_whole_without_recursive(
    fs: WebdavFileSystem, destination: str
) -> None:
    """A MOVE takes the tree along; fsspec's base class would skip the copy and delete the source."""
    fs.pipe_file("/s/f", b"1")
    fs.mkdir("/s/empty")
    fs.mv("/s", destination)
    assert not fs.exists("/s")
    assert sorted(fs.find("/", withdirs=True)) == (
        ["/", "/t", "/t/empty", "/t/f"]
        if not destination.endswith("/")
        else ["/", "/t", "/t/s", "/t/s/empty", "/t/s/f"]
    )


def test_an_empty_directory_is_not_lost_by_a_move_without_recursive(
    fs: WebdavFileSystem,
) -> None:
    fs.mkdir("/e")
    fs.mv("/e", "/x")
    assert fs.isdir("/x")
    assert not fs.exists("/e")


def test_moving_a_tree_takes_its_empty_directories_along(fs: WebdavFileSystem) -> None:
    fs.pipe_file("/s/f", b"1")
    fs.mkdir("/s/empty/deeper")
    fs.mv("/s", "/t", recursive=True)
    assert sorted(fs.find("/", withdirs=True)) == [
        "/",
        "/t",
        "/t/empty",
        "/t/empty/deeper",
        "/t/f",
    ]


def test_copying_a_tree_leaves_the_source_alone(fs: WebdavFileSystem) -> None:
    fs.pipe_file("/s/f", b"1")
    fs.pipe_file("/s/sub/g", b"2")
    fs.cp("/s", "/c", recursive=True)
    assert sorted(fs.find("/")) == ["/c/f", "/c/sub/g", "/s/f", "/s/sub/g"]


def test_a_non_recursive_copy_of_a_directory_copies_nothing(
    fs: WebdavFileSystem,
) -> None:
    fs.pipe_file("/s/f", b"1")
    fs.cp("/s", "/c")
    assert not fs.exists("/c")


def test_put_and_get_keep_empty_directories_and_empty_files(
    fs: WebdavFileSystem, tmp_path_factory: pytest.TempPathFactory
) -> None:
    source = tmp_path_factory.mktemp("source")
    (source / "empty-dir").mkdir()
    (source / "empty-file").write_bytes(b"")
    (source / "f").write_bytes(b"f")
    fs.put(str(source), "/up", recursive=True)
    assert sorted(fs.find("/up", withdirs=True)) == [
        "/up",
        "/up/empty-dir",
        "/up/empty-file",
        "/up/f",
    ]
    assert fs.size("/up/empty-file") == 0

    target = tmp_path_factory.mktemp("target")
    fs.get("/up", str(target / "down"), recursive=True)
    assert sorted(
        p.relative_to(target / "down").as_posix() for p in (target / "down").rglob("*")
    ) == ["empty-dir", "empty-file", "f"]


def test_a_failed_get_leaves_no_local_file(
    fs: WebdavFileSystem, tmp_path_factory: pytest.TempPathFactory
) -> None:
    local = tmp_path_factory.mktemp("target") / "gone"
    with pytest.raises(FileNotFoundError):
        fs.get_file("/nope", str(local))
    assert not local.exists()


def test_get_refuses_to_write_through_a_symlink(
    fs: WebdavFileSystem, tmp_path_factory: pytest.TempPathFactory
) -> None:
    fs.pipe_file("/r", b"remote")
    folder = tmp_path_factory.mktemp("target")
    victim = folder / "victim"
    victim.write_bytes(b"precious")
    link = folder / "link"
    link.symlink_to(victim)
    with pytest.raises(OSError, match="symlink") as caught:
        fs.get_file("/r", str(link))
    assert caught.value.errno == errno.ELOOP
    assert victim.read_bytes() == b"precious"
    assert link.is_symlink()


def test_get_over_an_existing_local_file_replaces_it(
    fs: WebdavFileSystem, tmp_path_factory: pytest.TempPathFactory
) -> None:
    fs.pipe_file("/r", b"new")
    local = tmp_path_factory.mktemp("target") / "f"
    local.write_bytes(b"old content that is longer")
    fs.get_file("/r", str(local))
    assert local.read_bytes() == b"new"


def test_put_file_replaces_what_is_there(
    fs: WebdavFileSystem, tmp_path_factory: pytest.TempPathFactory
) -> None:
    fs.pipe_file("/r", b"old content that is longer")
    local = tmp_path_factory.mktemp("source") / "f"
    local.write_bytes(b"new")
    fs.put_file(str(local), "/r")
    assert fs.cat_file("/r") == b"new"


def _through_pickle(value: _T) -> _T:
    """What a process boundary does to ``value``: serialise, then restore."""
    return cast("_T", pickle.loads(pickle.dumps(value)))


def test_a_pickled_filesystem_keeps_its_credentials(
    fs: WebdavFileSystem,
) -> None:
    fs.pipe_file("/a", b"1")
    for clone in (_through_pickle(fs), copy.deepcopy(fs)):
        assert clone.cat_file("/a") == b"1"
        clone.filesystem.close()


def test_an_open_file_survives_pickling_and_continues_where_it_was(
    fs: WebdavFileSystem,
) -> None:
    """What dask or multiprocessing do with a file they hand to a worker."""
    fs.pipe_file("/f", b"0123456789")
    with fs.open("/f", "rb") as original:
        assert original.read(2) == b"01"
        original.seek(4)
        with _through_pickle(original) as clone:
            assert clone.tell() == 4
            assert clone.read() == b"456789"
            assert clone.size == 10
        assert original.read(2) == b"45"  # the original does not notice
    with fs.open("/f", "rb") as fresh, _through_pickle(fresh) as clone:
        assert clone.tell() == 0
        assert clone.read() == b"0123456789"


def test_a_filesystem_survives_a_json_round_trip(
    server_url: str, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """JSON has no tuples: ``("user", "password")`` and ``(connect, read)`` come back as lists."""
    folder = tmp_path_factory.mktemp("cert")
    certfile, keyfile = str(folder / "client.pem"), str(folder / "client.key")
    for name in (certfile, keyfile):  # never used: the test server speaks plain HTTP
        Path(name).write_text("", encoding="utf-8")
    original = WebdavFileSystem(
        server_url, auth=AUTH, timeout=(5, 30), cert=(certfile, keyfile)
    )
    original.pipe_file("/a", b"1")
    for restored in (
        fsspec.AbstractFileSystem.from_json(original.to_json()),
        fsspec.AbstractFileSystem.from_dict(original.to_dict()),
    ):
        assert isinstance(restored, WebdavFileSystem)
        session = restored.filesystem.session
        assert session.auth == AUTH
        assert session.timeout == (5, 30)
        assert session.cert == (certfile, keyfile)
        assert restored.cat_file("/a") == b"1"
        restored.filesystem.close()
    original.filesystem.close()


def test_the_password_is_not_in_the_repr(fs: WebdavFileSystem) -> None:
    assert AUTH[1] not in repr(fs)
    assert AUTH[1] not in str(fs)


def test_filesystems_with_the_same_arguments_are_separate_instances(
    server_url: str,
) -> None:
    first = WebdavFileSystem(server_url, auth=AUTH)
    second = WebdavFileSystem(server_url, auth=AUTH)
    assert first is not second
    assert first.filesystem.session is not second.filesystem.session


def test_the_core_client_shares_the_session_and_its_locks(
    fs: WebdavFileSystem, server_url: str
) -> None:
    fs.pipe_file("/a", b"1")
    other = WebdavFileSystem(server_url, auth=AUTH)
    with fs.filesystem.locked("/a"):
        fs.pipe_file("/a", b"mine")  # the lock belongs to this session
        with pytest.raises(ResourceLockedError):
            other.pipe_file("/a", b"theirs")
    assert fs.cat_file("/a") == b"mine"
    other.pipe_file("/a", b"theirs")  # released
    assert fs.cat_file("/a") == b"theirs"
    other.filesystem.close()


def test_one_filesystem_serves_several_threads(fs: WebdavFileSystem) -> None:
    errors: list[BaseException] = []

    def work(number: int) -> None:
        try:
            payload = bytes([number]) * 100
            for index in range(5):
                path = f"/thread{number}/{index}.bin"
                fs.pipe_file(path, payload)
                assert fs.cat_file(path) == payload
            assert len(fs.ls(f"/thread{number}", detail=False)) == 5
        # pylint: disable-next=broad-exception-caught
        except BaseException as exc:  # noqa: BLE001 - the main thread reports it
            errors.append(exc)

    threads = [threading.Thread(target=work, args=(n,)) for n in range(5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []


def test_the_first_writes_into_one_new_directory_race_without_failing(
    server_url: str,
) -> None:
    """``dask`` and zarr write many files into a directory that does not exist yet, at once.

    WsgiDAV answers the MKCOL that loses the race with a 500, not the 405 of "exists already".
    """
    filesystem = WebdavFileSystem(server_url, auth=AUTH)
    errors: list[BaseException] = []

    def work(number: int, directory: str, barrier: threading.Barrier) -> None:
        try:
            barrier.wait()
            filesystem.pipe_file(f"{directory}/{number}.bin", b"x")
        # pylint: disable-next=broad-exception-caught
        except BaseException as exc:  # noqa: BLE001 - the main thread reports it
            errors.append(exc)

    for attempt in range(10):
        barrier = threading.Barrier(16)
        directory = f"/race{attempt}/deep"
        threads = [
            threading.Thread(target=work, args=(n, directory, barrier))
            for n in range(16)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    assert errors == []
    assert len(filesystem.ls("/race9/deep", detail=False)) == 16
    filesystem.filesystem.close()


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("asynchronous", True),
        ("asynchronous", False),
        ("loop", None),
        ("use_listings_cache", False),
        ("listings_expiry_time", 5),
        ("max_paths", 10),
    ],
)
def test_the_options_fsspec_hands_every_filesystem_are_accepted(
    server_url: str, option: str, value: object
) -> None:
    """``zarr`` and xarray open ``webdavs:///...`` with ``asynchronous=True``."""
    filesystem = fsspec.filesystem(
        "webdavs", base_url=server_url, auth=AUTH, **{option: value}
    )
    filesystem.pipe_file("/a", b"1")
    assert filesystem.cat_file("/a") == b"1"
    filesystem.filesystem.close()


def test_an_option_nobody_knows_is_still_refused(server_url: str) -> None:
    """Only fsspec's own options are let through: a typo in a session option is an error."""
    with pytest.raises(TypeError, match="timeuot"):
        WebdavFileSystem(server_url, auth=AUTH, timeuot=5)


def test_open_files_expands_a_glob(server_url: str) -> None:
    filesystem = fsspec.filesystem("webdavs", base_url=server_url, auth=AUTH)
    filesystem.pipe({"/d/a.txt": b"A", "/d/b.txt": b"B", "/d/c.log": b"C"})
    files = fsspec.open_files(
        "webdavs:///d/*.txt", "rb", base_url=server_url, auth=AUTH
    )
    assert sorted(f.path for f in files) == ["/d/a.txt", "/d/b.txt"]
    contents = []
    for f in files:
        with f as handle:
            contents.append(handle.read())
    assert sorted(contents) == [b"A", b"B"]


def test_fsspec_open_writes_text(server_url: str) -> None:
    with fsspec.open(
        "webdavs:///notes/today.txt", "wt", base_url=server_url, auth=AUTH
    ) as f:
        f.write("grüße\nzweite Zeile\n")
    with fsspec.open(
        "webdavs:///notes/today.txt", "rt", base_url=server_url, auth=AUTH
    ) as f:
        assert f.read() == "grüße\nzweite Zeile\n"


def test_unstrip_protocol_is_what_the_url_front_door_accepts(
    fs: WebdavFileSystem,
) -> None:
    # The `fs` fixture's test server is plain HTTP, so the round trip uses
    # "webdav://", not "webdavs://" - unstrip_protocol() matches the server's
    # actual transport, not a fixed scheme.
    url = fs.unstrip_protocol("/a/b")
    assert url == "webdav:///a/b"
    assert fs._strip_protocol(url) == "/a/b"


#: What a PROPFIND on ``/f`` answers: a 10 byte file.
_FILE_PROPERTIES = (
    b'<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response><d:href>/f</d:href>'
    b"<d:propstat><d:prop><d:resourcetype/><d:getcontentlength>10</d:getcontentlength>"
    b"</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
    b"</d:multistatus>"
)


#: What a PROPFIND on ``/d`` answers: a collection.
_COLLECTION_PROPERTIES = (
    b'<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response><d:href>/d/</d:href>'
    b"<d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype>"
    b"</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
    b"</d:multistatus>"
)


def _mkcol_fails(status: int, *, collection_exists: bool) -> "Callable[[Seen], Reply]":
    def respond(seen: Seen) -> Reply:
        if seen.method == "MKCOL":
            return status, {"Content-Type": "text/plain"}, b"mkdir failed"
        if (
            seen.method == "PROPFIND"
            and collection_exists
            and seen.path.startswith("/d")
        ):
            return 207, {"Content-Type": "application/xml"}, _COLLECTION_PROPERTIES
        return 404, {"Content-Type": "text/plain"}, b""

    return respond


#: How the loser of a race to create a collection is answered: WsgiDAV 500, Apache 403 (some of them).
_LOST_RACE = [(500, InternalServerError), (403, PermissionError)]


@pytest.mark.parametrize(("status", "error"), _LOST_RACE)
def test_a_failed_mkcol_is_fine_if_the_collection_is_there_afterwards(
    status: int, error: type[Exception]
) -> None:
    """The loser of a race to create ``/d`` - and only for ``exist_ok``."""
    respond = _mkcol_fails(status, collection_exists=True)
    with scripted_server(respond) as (url, _):
        fs = WebdavFileSystem(url)
        fs.makedirs("/d", exist_ok=True)
        fs.mkdir("/d")  # create_parents=True is makedirs(exist_ok=True)
        with pytest.raises(error):
            fs.makedirs("/d", exist_ok=False)
        fs.filesystem.close()


@pytest.mark.parametrize(("status", "error"), _LOST_RACE)
def test_a_failed_mkcol_is_an_error_if_there_is_no_collection(
    status: int, error: type[Exception]
) -> None:
    respond = _mkcol_fails(status, collection_exists=False)
    with scripted_server(respond) as (url, _):
        fs = WebdavFileSystem(url)
        with pytest.raises(error):
            fs.makedirs("/d", exist_ok=True)
        fs.filesystem.close()


@pytest.mark.parametrize(
    "call",
    [
        lambda fs: fs.info("/f"),
        lambda fs: fs.ls("/"),
        lambda fs: fs.cat_file("/f"),
        lambda fs: fs.pipe_file("/f", b"x"),
        lambda fs: fs.rm_file("/f"),
        lambda fs: fs.mkdir("/d", create_parents=False),
        lambda fs: fs.mkdir("/d"),
        lambda fs: fs.cp_file("/f", "/g"),
        lambda fs: fs.open("/f", "wb").close(),
    ],
    ids=[
        "info",
        "ls",
        "cat_file",
        "pipe_file",
        "rm_file",
        "mkdir",
        "mkdir-p",
        "cp_file",
        "open-wb",
    ],
)
def test_a_server_that_forbids_everything_is_a_permission_error(
    call: "Callable[[WebdavFileSystem], object]",
) -> None:
    with scripted_server(lambda _seen: (403, {}, b"")) as (url, _recorder):
        fs = WebdavFileSystem(url)
        with pytest.raises(PermissionError):
            call(fs)
        fs.filesystem.close()


def test_a_405_for_a_write_is_a_directory_only_if_there_is_one() -> None:
    """A read-only resource answers a PUT with 405 as well."""

    def respond(seen: Seen) -> Reply:
        if seen.method == "PROPFIND":
            return 207, {"Content-Type": "application/xml"}, _FILE_PROPERTIES
        return 405, {"Allow": "GET, PROPFIND"}, b""

    with scripted_server(respond) as (url, _recorder):
        fs = WebdavFileSystem(url)
        with pytest.raises(HTTPStatusError) as caught:
            fs.pipe_file("/f", b"x")
        assert caught.value.status_code == 405
        fs.filesystem.close()


def test_a_failed_upload_still_closes_the_file() -> None:
    """Like ``io``: close() that fails has closed all the same - the buffer is not left behind."""
    with scripted_server(lambda _seen: (403, {}, b"")) as (url, _recorder):
        fs = WebdavFileSystem(url)
        f = fs.open("/f", "wb")
        f.write(b"data")
        with pytest.raises(PermissionError):
            f.close()
        assert f.closed
        f.close()  # closing again is quiet
        fs.filesystem.close()


def test_a_server_without_ranges_cannot_be_seeked() -> None:
    """A server that does not offer ranges is refused at ``seek``, before anything is requested."""

    def respond(seen: Seen) -> Reply:
        if seen.method == "PROPFIND":
            return 207, {"Content-Type": "application/xml"}, _FILE_PROPERTIES
        return 200, {"Content-Type": "application/octet-stream"}, b"0123456789"

    with scripted_server(respond) as (url, recorder):
        fs = WebdavFileSystem(url)
        with fs.open("/f", "rb") as f:
            assert f.read(2) == b"01"
            with pytest.raises(ValueError, match="does not support ranges"):
                f.seek(5)
        fs.filesystem.close()
    assert not any("range" in r.headers for r in recorder.requests)


def test_a_server_that_ignores_range_never_yields_the_wrong_bytes() -> None:
    """A partial range needs a 206; a server that answers 200 with the whole body is refused."""
    body = b"0123456789"

    def respond(seen: Seen) -> Reply:
        if seen.method == "PROPFIND":
            return 207, {"Content-Type": "application/xml"}, _FILE_PROPERTIES
        # Claims to serve ranges, then ignores the Range header.
        headers = {"Content-Type": "application/octet-stream", "Accept-Ranges": "bytes"}
        return 200, headers, body

    with scripted_server(respond) as (url, recorder):
        fs = WebdavFileSystem(url)
        with fs.open("/f", "rb", cache_type="none") as f:
            f.seek(5)
            with pytest.raises(ClientError, match="206"):
                f.read(2)
        fs.filesystem.close()
    assert any(r.headers.get("range") == "bytes=5-6" for r in recorder.requests)


_BIG = 1_000_000


def _big_file(on_get: "Callable[[Seen], Reply]") -> "Callable[[Seen], Reply]":
    properties = _FILE_PROPERTIES.replace(
        b"<d:getcontentlength>10<", b"<d:getcontentlength>%d<" % _BIG
    )

    def respond(seen: Seen) -> Reply:
        if seen.method == "PROPFIND":
            return 207, {"Content-Type": "application/xml"}, properties
        return on_get(seen)

    return respond


def _serves_ranges(seen: Seen, *, etag: str = '"v1"') -> Reply:
    """A GET answered the way a server that knows ranges answers it."""
    data = bytes(range(256)) * (_BIG // 256 + 1)
    requested = seen.headers.get("range")
    headers = {"Content-Type": "application/octet-stream", "ETag": etag}
    if requested is None:
        return 200, headers, data[:_BIG]
    first, _, last = requested.removeprefix("bytes=").partition("-")
    start, stop = int(first), min(int(last) if last else _BIG - 1, _BIG - 1)
    headers["Content-Range"] = f"bytes {start}-{stop}/{_BIG}"
    return 206, headers, data[start : stop + 1]


def test_every_read_is_a_bounded_range_and_no_response_is_cut_off() -> None:
    """A Parquet reader seeks all the time: each block is one request that is read to its end."""
    with scripted_server(_big_file(_serves_ranges)) as (url, recorder):
        fs = WebdavFileSystem(url)
        with fs.open("/f", "rb", block_size=1000) as f:
            for position in (900_000, 5, 500_000, 123_456, 0):
                f.seek(position)
                assert f.read(10) == bytes((position + i) % 256 for i in range(10))
        assert fs.cat_file("/f", 1000, 1010) == bytes(
            (1000 + i) % 256 for i in range(10)
        )
        fs.filesystem.close()
    gets = [r for r in recorder.requests if r.method == "GET"]
    assert len(gets) == 6
    assert all(re.fullmatch(r"bytes=\d+-\d+", r.headers.get("range", "")) for r in gets)
    assert gets[-1].headers["range"] == "bytes=1000-1009"  # exactly what was asked for


def test_reading_a_whole_file_sends_no_range_at_all() -> None:
    """The one request a server that does not know ranges can answer too."""
    body = bytes(range(100)) * 10

    def respond(seen: Seen) -> Reply:
        if seen.method == "PROPFIND":
            properties = _FILE_PROPERTIES.replace(
                b"<d:getcontentlength>10<", b"<d:getcontentlength>1000<"
            )
            return 207, {"Content-Type": "application/xml"}, properties
        return 200, {"Content-Type": "application/octet-stream"}, body

    with scripted_server(respond) as (url, recorder):
        fs = WebdavFileSystem(url)
        assert fs.cat_file("/f") == body
        with fs.open("/f", "rb") as f:
            assert f.read() == body
        fs.filesystem.close()
    assert not any("range" in r.headers for r in recorder.requests if r.method == "GET")


def test_a_file_that_changes_between_two_blocks_is_an_error() -> None:
    versions = iter(['"v1"', '"v2"'])

    def respond(seen: Seen) -> Reply:
        return _serves_ranges(seen, etag=next(versions))

    with scripted_server(_big_file(respond)) as (url, _recorder):
        fs = WebdavFileSystem(url)
        with fs.open("/f", "rb", cache_type="none") as f:
            assert len(f.read(10)) == 10
            with pytest.raises(ClientError, match="changed"):
                f.read(10)
        fs.filesystem.close()


@pytest.mark.parametrize("extra", [b"more", b""])
def test_a_response_that_is_not_the_size_asked_for_is_an_error(extra: bytes) -> None:
    def respond(seen: Seen) -> Reply:
        status, headers, data = _serves_ranges(seen)
        return status, headers, data + extra if extra else data[:-1]

    with scripted_server(_big_file(respond)) as (url, _recorder):
        fs = WebdavFileSystem(url)
        with (
            fs.open("/f", "rb", cache_type="none") as f,
            pytest.raises(ClientError, match="10 bytes"),
        ):
            f.read(10)
        fs.filesystem.close()


def test_a_resource_without_a_size_cannot_be_opened_for_reading() -> None:
    def respond(_seen: Seen) -> Reply:
        no_length = _FILE_PROPERTIES.replace(
            b"<d:getcontentlength>10</d:getcontentlength>", b""
        )
        return 207, {"Content-Type": "application/xml"}, no_length

    with scripted_server(respond) as (url, _recorder):
        fs = WebdavFileSystem(url)
        with pytest.raises(OSError, match="how big"):
            fs.open("/f", "rb")
        fs.filesystem.close()


def test_bug04_ls_keeps_a_trailing_space(ffs: WebdavFileSystem, tmp_path: Path) -> None:
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "plain.txt").write_text("1")
    (tmp_path / "data ").mkdir()
    (tmp_path / "data " / "spaced.txt").write_text("2")
    assert ffs.ls("/data ", detail=False) == ["/data /spaced.txt"]
    assert ffs.ls("/data", detail=False) == ["/data/plain.txt"]
    assert "/data /spaced.txt" in ffs.find("/")


def test_bug04_file_with_a_trailing_space(
    ffs: WebdavFileSystem, tmp_path: Path
) -> None:
    (tmp_path / "trail ").write_text("x")
    assert ffs.ls("/trail ", detail=False) == ["/trail "]


def test_bug04_guard_plain_paths(ffs: WebdavFileSystem, tmp_path: Path) -> None:
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "a").write_text("1")
    assert ffs.ls("d", detail=False) == ["/d/a"]
    assert ffs.ls("/d/", detail=False) == ["/d/a"]
    assert ffs.ls("webdavs:///d", detail=False) == ["/d/a"]
    assert ffs.ls("", detail=False) == ["/d"]


def test_bug05_transaction_defers_the_put_until_commit(
    ffs: WebdavFileSystem, tmp_path: Path
) -> None:
    with ffs.transaction:
        with ffs.open("/tx1.txt", "wb") as f:
            f.write(b"abc")
        assert not (tmp_path / "tx1.txt").exists()
    assert (tmp_path / "tx1.txt").read_bytes() == b"abc"


def test_bug05_transaction_rolls_back_on_an_error(
    ffs: WebdavFileSystem, tmp_path: Path
) -> None:
    def fail_inside_a_transaction() -> None:
        with ffs.transaction:
            with ffs.open("/tx2.txt", "wb") as f:
                f.write(b"abc")
            message = "boom"
            raise RuntimeError(message)

    with pytest.raises(RuntimeError):
        fail_inside_a_transaction()
    assert not (tmp_path / "tx2.txt").exists()


def test_bug05_transaction_two_files_and_text_mode(
    ffs: WebdavFileSystem, tmp_path: Path
) -> None:
    with ffs.transaction:
        with ffs.open("/a.txt", "w") as f:
            f.write("a")
        with ffs.open("/b.txt", "wb") as f:
            f.write(b"b")
    assert (tmp_path / "a.txt").read_text() == "a"
    assert (tmp_path / "b.txt").read_text() == "b"


def test_bug05_transaction_does_not_hold_a_big_file_in_memory(
    ffs: WebdavFileSystem, tmp_path: Path
) -> None:
    data = os.urandom(20 * 1024 * 1024)
    with (
        ffs.transaction,
        ffs.open("/big.bin", "wb") as f,
    ):
        f.write(data)
        assert f._rolled  # on disk, not in RAM
    assert (tmp_path / "big.bin").read_bytes() == data


def test_bug05_a_failing_commit_leaves_no_open_file(
    ffs: WebdavFileSystem, tmp_path: Path
) -> None:
    (
        tmp_path / "taken"
    ).mkdir()  # a collection where the PUT goes: the server refuses it
    held = []

    def write_in_a_transaction(path: str, *, then_fail: bool) -> None:
        with ffs.transaction:
            f = ffs.open(path, "wb")
            f.write(b"1")
            f.close()
            held.append(f)
            if then_fail:
                raise RuntimeError

    with pytest.raises(IsADirectoryError):
        write_in_a_transaction("/taken", then_fail=False)
    assert all(f.closed for f in held)
    with pytest.raises(RuntimeError):
        write_in_a_transaction("/other.txt", then_fail=True)
    assert all(f.closed for f in held)
    assert not (tmp_path / "other.txt").exists()


def test_bug05_guard_plain_open_uploads_on_close(
    ffs: WebdavFileSystem, tmp_path: Path
) -> None:
    with ffs.open("/plain.txt", "wb") as f:
        f.write(b"x")
    assert (tmp_path / "plain.txt").read_bytes() == b"x"
    f2 = ffs.open("/plain2.txt", "wb")
    f2.write(b"y")
    f2.close()
    assert (tmp_path / "plain2.txt").read_bytes() == b"y"
    assert f2.closed


def test_bug05_guard_an_exception_in_a_plain_with_discards(
    ffs: WebdavFileSystem, tmp_path: Path
) -> None:
    def write_and_fail() -> None:
        with ffs.open("/nope.txt", "wb") as f:
            f.write(b"x")
            raise RuntimeError

    with pytest.raises(RuntimeError):
        write_and_fail()
    assert not (tmp_path / "nope.txt").exists()


def test_bug06_the_fsspec_front_doors(ffs: WebdavFileSystem, tmp_path: Path) -> None:
    buf = io.BytesIO(b"HEADER:payload")
    buf.seek(7)
    ffs.upload_fileobj(buf, "/a.bin")
    r, w = os.pipe()
    os.write(w, b"piped")
    os.close(w)
    with os.fdopen(r, "rb") as fobj:
        ffs.upload_fileobj(fobj, "/b.bin")
    assert (tmp_path / "a.bin").read_bytes() == b"payload"
    assert (tmp_path / "b.bin").read_bytes() == b"piped"


def test_bug10_guard_fsspec_makedirs_exist_ok(ffs: WebdavFileSystem) -> None:
    ffs.makedirs("/a/b", exist_ok=True)
    ffs.makedirs("/a/b", exist_ok=True)


def test_bug11_guard_an_unclosed_upload_file_still_uploads_and_warns(
    ffs: WebdavFileSystem, tmp_path: Path
) -> None:
    def open_and_forget() -> None:
        f = ffs.open("/gc.txt", "wb")
        f.write(b"x")
        del f
        gc.collect()

    with pytest.warns(ResourceWarning):
        open_and_forget()
    assert (tmp_path / "gc.txt").read_bytes() == b"x"


def test_bug11_an_unclosed_transaction_file_is_not_uploaded_by_the_collector(
    ffs: WebdavFileSystem, tmp_path: Path
) -> None:
    with ffs.transaction:
        f = ffs.open("/held.txt", "wb")
        f.write(b"x")
        f.close()
        del f
        gc.collect()
        assert not (tmp_path / "held.txt").exists()
    assert (tmp_path / "held.txt").read_bytes() == b"x"


def test_dos04_a_deep_but_finite_tree_is_walked(ffs: WebdavFileSystem) -> None:
    path = "/" + "/".join(f"l{i}" for i in range(40))
    ffs.pipe_file(path + "/leaf.txt", b"x")
    assert ffs.find("/") == [path + "/leaf.txt"]


def test_dos04_guard_the_fsspec_contract_of_walk(ffs: WebdavFileSystem) -> None:
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


def _two_dirs(
    tmp_path_factory: pytest.TempPathFactory, name: str
) -> "tuple[Path, Path, Path]":
    base = tmp_path_factory.mktemp(name)
    outside = base / "outside"
    outside.mkdir()
    dst = base / "dst"
    dst.mkdir()
    return base, outside, dst


@pytest.mark.parametrize("source", ["/d/", "/d"])
def test_fs01_recursive_get_does_not_follow_a_symlink_out_of_the_destination(
    ffs: WebdavFileSystem, tmp_path_factory: pytest.TempPathFactory, source: str
) -> None:
    ffs.pipe_file("/d/sub/f.txt", b"REMOTE")
    ffs.pipe_file("/d/top.txt", b"top")
    _base, outside, dst = _two_dirs(tmp_path_factory, "get")
    (dst / ("sub" if source.endswith("/") else "d")).symlink_to(outside)
    with pytest.raises(OSError, match="follow_symlinks=True"):
        ffs.get(source, str(dst), recursive=True)
    assert not list(outside.iterdir())


def test_fs01_follow_symlinks_restores_the_old_behaviour(
    ffs: WebdavFileSystem, tmp_path_factory: pytest.TempPathFactory
) -> None:
    ffs.pipe_file("/d/photos/f.txt", b"REMOTE")
    _base, big, dst = _two_dirs(tmp_path_factory, "get")
    (dst / "photos").symlink_to(big)
    ffs.get("/d/", str(dst), recursive=True, follow_symlinks=True)
    assert (big / "f.txt").read_bytes() == b"REMOTE"


def test_fs01_guard_the_destination_root_may_be_a_symlink(
    ffs: WebdavFileSystem, tmp_path_factory: pytest.TempPathFactory
) -> None:
    ffs.pipe_file("/d/sub/f.txt", b"REMOTE")
    base = tmp_path_factory.mktemp("get")
    (base / "mnt").mkdir()
    (base / "data").symlink_to(base / "mnt")
    ffs.get("/d/", str(base / "data"), recursive=True)
    assert (base / "mnt" / "sub" / "f.txt").read_bytes() == b"REMOTE"


def test_fs01_guard_a_symlink_inside_the_tree_that_points_inside(
    ffs: WebdavFileSystem, tmp_path_factory: pytest.TempPathFactory
) -> None:
    ffs.pipe_file("/d/sub/f.txt", b"REMOTE")
    dst = tmp_path_factory.mktemp("get") / "dst"
    (dst / "real").mkdir(parents=True)
    (dst / "sub").symlink_to(dst / "real")
    ffs.get("/d/", str(dst), recursive=True)
    assert (dst / "real" / "f.txt").read_bytes() == b"REMOTE"


def test_fs01_guard_a_single_file_and_lists_follow_the_callers_paths(
    ffs: WebdavFileSystem, tmp_path_factory: pytest.TempPathFactory
) -> None:
    ffs.pipe_file("/one.txt", b"1")
    ffs.pipe_file("/two.txt", b"2")
    base = tmp_path_factory.mktemp("get")
    real = base / "real.txt"
    (base / "link.txt").symlink_to(real)
    real.write_bytes(b"old")
    # the caller named the file itself; the download replaces the link's *name* only if it is
    # a plain file - download_file refuses to write through a symlink at the target
    with pytest.raises(OSError, match="symlink"):
        ffs.get("/one.txt", str(base / "link.txt"))
    outside = base / "outside"
    outside.mkdir()
    ffs.get(["/one.txt", "/two.txt"], [str(outside / "a"), str(outside / "b")])
    assert (outside / "a").read_bytes() == b"1"


def test_fs01_guard_a_plain_recursive_get(
    ffs: WebdavFileSystem, tmp_path_factory: pytest.TempPathFactory
) -> None:
    ffs.pipe_file("/d/a/1.txt", b"1")
    ffs.pipe_file("/d/2.txt", b"2")
    dst = tmp_path_factory.mktemp("get") / "dst"
    ffs.get("/d/", str(dst), recursive=True)
    assert (dst / "a" / "1.txt").read_bytes() == b"1"
    assert (dst / "2.txt").read_bytes() == b"2"


def test_fs02_recursive_put_refuses_a_symlink_out_of_the_tree(
    ffs: WebdavFileSystem, tmp_path: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    base = tmp_path_factory.mktemp("up")
    (base / "src").mkdir()
    (base / "src" / "ok.txt").write_text("ok")
    (base / "secret.txt").write_text("TOP-SECRET")
    (base / "src" / "innocent.txt").symlink_to(base / "secret.txt")
    with pytest.raises(OSError, match="follow_symlinks=True"):
        ffs.put(str(base / "src") + "/", "/dest/", recursive=True)
    assert not (tmp_path / "dest" / "innocent.txt").exists()


def test_fs02_a_glob_put_checks_against_the_directory_before_the_glob(
    ffs: WebdavFileSystem, tmp_path: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    base = tmp_path_factory.mktemp("up")
    (base / "src").mkdir()
    (base / "secret.txt").write_text("TOP-SECRET")
    (base / "src" / "innocent.txt").symlink_to(base / "secret.txt")
    with pytest.raises(OSError, match="outside the source tree"):
        ffs.put(str(base / "src" / "*.txt"), "/dest/")
    assert not (tmp_path / "dest" / "innocent.txt").exists()


def test_fs02_follow_symlinks_restores_the_old_behaviour(
    ffs: WebdavFileSystem, tmp_path: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    base = tmp_path_factory.mktemp("up")
    (base / "src").mkdir()
    (base / "secret.txt").write_text("DATA")
    (base / "src" / "link.txt").symlink_to(base / "secret.txt")
    ffs.put(str(base / "src") + "/", "/dest/", recursive=True, follow_symlinks=True)
    assert (tmp_path / "dest" / "link.txt").read_text() == "DATA"


def test_fs02_guard_symlinks_inside_the_tree_and_a_named_symlink_work(
    ffs: WebdavFileSystem, tmp_path: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    base = tmp_path_factory.mktemp("up")
    (base / "src").mkdir()
    (base / "src" / "real.txt").write_text("data")
    (base / "src" / "link.txt").symlink_to(base / "src" / "real.txt")
    ffs.put(str(base / "src") + "/", "/dest/", recursive=True)
    assert (tmp_path / "dest" / "link.txt").read_text() == "data"
    ffs.put(str(base / "src" / "link.txt"), "/named.txt")  # the caller's own choice
    assert (tmp_path / "named.txt").read_text() == "data"
    (base / "elsewhere.txt").write_text("e")
    ffs.put(
        [str(base / "elsewhere.txt")], ["/listed.txt"]
    )  # a list: every path is the caller's
    assert (tmp_path / "listed.txt").read_text() == "e"


def test_fs02_guard_the_source_root_may_be_a_symlink(
    ffs: WebdavFileSystem, tmp_path: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    base = tmp_path_factory.mktemp("up")
    (base / "real").mkdir()
    (base / "real" / "a.txt").write_text("a")
    (base / "link").symlink_to(base / "real")
    ffs.put(str(base / "link") + "/", "/dest/", recursive=True)
    assert (tmp_path / "dest" / "a.txt").read_text() == "a"


# A callback that raises is how a streamed download is bounded: neither
# max_response_size nor max_response_time applies to it.


class _TooSlowError(Exception):
    """What the callbacks below raise."""


class _Within(Callback):
    """A callback that raises once the transfer has taken longer than ``seconds``."""

    def __init__(self, seconds: float) -> None:
        super().__init__()
        self.seconds = seconds
        self.started = time.monotonic()

    def relative_update(self, inc: int = 1) -> None:
        if time.monotonic() - self.started > self.seconds:
            raise _TooSlowError
        super().relative_update(inc)


class _WithinForChildren(_Within):
    """The same, handed on to the transfers ``get`` starts (fsspec gives them no-op callbacks otherwise)."""

    def branched(self, path_1: str, path_2: str, **kwargs: object) -> "Callback":
        return self


def _dripping_file(seen: Seen) -> Reply:
    if seen.method == "PROPFIND":
        entry = sized_entry("/f", is_dir=False, size=400)
        return 207, {"Content-Type": "application/xml"}, multistatus_doc(entry)
    return 200, {DRIP: "0.05"}, b"x" * 400  # 20 bytes a second, for twenty seconds


def test_get_file_stops_when_the_callback_raises(tmp_path: Path) -> None:
    with scripted_server(_dripping_file) as (url, _rec):
        filesystem = WebdavFileSystem(url, retry=False, timeout=2)
        with pytest.raises(_TooSlowError):
            filesystem.get_file("f", str(tmp_path / "out"), callback=_Within(0.5))
    assert list(tmp_path.iterdir()) == []


def test_get_stops_when_a_callback_that_hands_itself_on_raises(tmp_path: Path) -> None:
    with scripted_server(_dripping_file) as (url, _rec):
        filesystem = WebdavFileSystem(url, retry=False, timeout=2)
        with pytest.raises(_TooSlowError):
            filesystem.get("f", str(tmp_path / "out"), callback=_WithinForChildren(0.5))
    assert list(tmp_path.iterdir()) == []


def test_get_of_several_files_stops_when_the_callback_raises(tmp_path: Path) -> None:
    with scripted_server(_dripping_file) as (url, _rec):
        filesystem = WebdavFileSystem(url, retry=False, timeout=2)
        with pytest.raises(_TooSlowError):
            filesystem.get(
                ["f", "f"],
                [str(tmp_path / "one"), str(tmp_path / "two")],
                callback=_WithinForChildren(0.5),
            )
    assert list(tmp_path.iterdir()) == []
