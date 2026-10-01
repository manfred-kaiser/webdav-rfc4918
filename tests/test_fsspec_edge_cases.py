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
import pickle
import threading
from collections.abc import Iterator
from typing import TypeVar, cast

import fsspec
import pytest

from tests.credentials import AUTH
from tests.scripted_server import Reply, Seen, scripted_server
from webdav.exceptions import ClientError, ResourceLockedError
from webdav.fsspec import WebdavFileSystem

_T = TypeVar("_T")


@pytest.fixture
def fs(server_url: str) -> Iterator[WebdavFileSystem]:
    filesystem = WebdavFileSystem(server_url, auth=AUTH)
    yield filesystem
    filesystem.filesystem.close()


# ---------------------------------------------------------------------------
# Errors are the stdlib ones fsspec callers catch
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "method", ["ls", "info", "size", "modified", "created", "checksum", "cat_file"]
)
def test_a_missing_path_is_a_file_not_found_error(
    fs: WebdavFileSystem, method: str
) -> None:
    with pytest.raises(FileNotFoundError):
        getattr(fs, method)("/nope")


def test_a_missing_path_is_not_an_error_for_exists_and_the_type_checks(
    fs: WebdavFileSystem,
) -> None:
    assert not fs.exists("/nope")
    assert not fs.isdir("/nope")
    assert not fs.isfile("/nope")


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


# ---------------------------------------------------------------------------
# Writing: what a write that goes wrong leaves behind
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Reading: ranges, seeking, the empty file
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Names: what survives the trip through a URL
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Listing and walking
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Copy and move
# ---------------------------------------------------------------------------


def test_copy_does_not_overwrite_an_existing_file(fs: WebdavFileSystem) -> None:
    """``Overwrite: F`` on every COPY/MOVE, deliberately: the destination is never replaced silently."""
    fs.pipe_file("/a", b"1")
    fs.pipe_file("/b", b"2")
    with pytest.raises(FileExistsError):
        fs.cp("/a", "/b")
    with pytest.raises(FileExistsError):
        fs.mv("/a", "/b")
    assert fs.cat_file("/a") == b"1"
    assert fs.cat_file("/b") == b"2"


def test_copy_and_move_of_a_missing_source(fs: WebdavFileSystem) -> None:
    with pytest.raises(FileNotFoundError):
        fs.cp("/nope", "/b")
    with pytest.raises(FileNotFoundError):
        fs.mv("/nope", "/b")
    assert not fs.exists("/b")


def test_moving_a_file_onto_itself_keeps_the_file(fs: WebdavFileSystem) -> None:
    fs.pipe_file("/a", b"1")
    fs.mv("/a", "/a")
    assert fs.cat_file("/a") == b"1"


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
    with pytest.raises(
        FileExistsError
    ):  # the copy that is already there is not replaced
        fs.cp("/a", "/d/")
    assert fs.cat_file("/d/a") == b"1"


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


# ---------------------------------------------------------------------------
# get / put
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# One filesystem, serialised, shared, several at once
# ---------------------------------------------------------------------------


def _through_pickle(value: _T) -> _T:
    """What a process boundary does to ``value``: serialise, then restore."""
    return cast("_T", pickle.loads(pickle.dumps(value)))  # noqa: S301 - our own bytes


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
        except BaseException as exc:  # noqa: BLE001 - the main thread reports it
            errors.append(exc)

    threads = [threading.Thread(target=work, args=(n,)) for n in range(5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []


# ---------------------------------------------------------------------------
# Through fsspec's own front doors
# ---------------------------------------------------------------------------


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
    url = fs.unstrip_protocol("/a/b")
    assert url == "webdavs:///a/b"
    assert fs._strip_protocol(url) == "/a/b"


# ---------------------------------------------------------------------------
# A server that misbehaves must not make the filesystem lie
# ---------------------------------------------------------------------------

#: What a PROPFIND on ``/f`` answers: a 10 byte file.
_FILE_PROPERTIES = (
    b'<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response><d:href>/f</d:href>'
    b"<d:propstat><d:prop><d:resourcetype/><d:getcontentlength>10</d:getcontentlength>"
    b"</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
    b"</d:multistatus>"
)


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
    """Seeking needs a 206; a server that answers 200 with the whole body is refused, not believed."""
    body = b"0123456789"

    def respond(seen: Seen) -> Reply:
        if seen.method == "PROPFIND":
            return 207, {"Content-Type": "application/xml"}, _FILE_PROPERTIES
        # Claims to serve ranges, then ignores the Range header.
        headers = {"Content-Type": "application/octet-stream", "Accept-Ranges": "bytes"}
        return 200, headers, body

    with scripted_server(respond) as (url, recorder):
        fs = WebdavFileSystem(url)
        with fs.open("/f", "rb") as f:
            assert f.read(2) == b"01"
            f.seek(5)
            with pytest.raises(ClientError, match="206"):
                f.read(2)
        fs.filesystem.close()
    assert any(r.headers.get("range") == "bytes=5-" for r in recorder.requests)
