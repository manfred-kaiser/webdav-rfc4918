"""Regression tests for the file-system / fsspec hardening: the misbehaviour, and what stays legitimate.

One group per finding (``FS-01``, ``BUG-05``, ...). A ``test_<ID>_...`` test fails without the fix; a
``test_<ID>_guard_...`` test pins behaviour that worked before and has to keep working.
"""

import errno
import gc
import io
import os
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import fsspec
import pytest

from tests.credentials import AUTH
from tests.scripted_server import Seen, always, scripted_server
from webdav import FileSystem
from webdav.exceptions import (
    ClientError,
    ForbiddenError,
    PreconditionFailedError,
    ResourceAlreadyExistsError,
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


# ------------------------------------------------------------------ BUG-02
def _text_server(content_type: "str | None", body: bytes) -> Any:
    def respond(seen: Seen) -> tuple[int, dict[str, str], bytes]:
        if seen.method == "PROPFIND":
            return 207, {}, PROPFIND_FILE
        return (
            200,
            ({} if content_type is None else {"Content-Type": content_type}),
            body,
        )

    return respond


def _read_text(content_type: "str | None", body: bytes, **options: Any) -> str:
    with scripted_server(_text_server(content_type, body)) as (url, _):
        with FileSystem(retry=False).open(f"{url}/f", **options) as f:
            return str(f.read())


def test_BUG02_text_without_charset_is_utf8() -> None:
    assert _read_text("text/plain", "héllo wörld €".encode()) == "héllo wörld €"


def test_BUG02_no_content_type_is_utf8() -> None:
    assert _read_text(None, "héllo €".encode()) == "héllo €"


def test_BUG02_guard_declared_latin1_is_honoured() -> None:
    assert (
        _read_text("text/plain; charset=iso-8859-1", "héllo".encode("latin-1"))
        == "héllo"
    )


def test_BUG02_guard_quoted_and_uppercase_charset() -> None:
    assert _read_text('text/plain; Charset="UTF-8"', "héllo".encode()) == "héllo"


def test_BUG02_guard_explicit_encoding_wins() -> None:
    assert (
        _read_text("text/plain", "héllo".encode("latin-1"), encoding="iso-8859-1")
        == "héllo"
    )


def test_BUG02_legacy_latin1_without_charset_needs_encoding() -> None:
    with pytest.raises(UnicodeDecodeError):
        _read_text("text/plain", "héllo".encode("latin-1"))


def test_BUG02_guard_hostile_charset_is_not_used() -> None:
    assert _read_text("text/plain; charset=rot13", "héllo".encode()) == "héllo"


# ------------------------------------------------------------------ BUG-03
def _record_server() -> Any:
    def respond(seen: Seen) -> tuple[int, dict[str, str], bytes]:
        return (404, {}, b"") if seen.method == "PROPFIND" else (204, {}, b"")

    return scripted_server(respond)


@pytest.mark.parametrize(
    "given",
    [
        "/dir/a%2Fb.txt",
        "/dir/caf%E9.txt",
        "/dir/x%2fy/",
        "/dir/a%20b.txt",
        "/dir/caf%C3%A9.txt",
        "/dir/100%25.txt",
    ],
)
def test_BUG03_full_url_is_sent_as_written_without_base_url(given: str) -> None:
    with _record_server() as (url, rec):
        FileSystem(retry=False).remove(url + given)
    # ``requests`` itself spells the hex digits of an escape in capitals: the same bytes
    assert rec.requests[0].path.upper() == given.upper()


@pytest.mark.parametrize("given", ["/dir/a%2Fb.txt", "/dir/caf%E9.txt"])
def test_BUG03_guard_full_url_with_base_url_is_sent_as_written(given: str) -> None:
    with _record_server() as (url, rec):
        FileSystem(url, retry=False).remove(url + given)
    assert rec.requests[0].path == given


def test_BUG03_guard_unencoded_space_and_unicode_are_encoded() -> None:
    with _record_server() as (url, rec):
        FileSystem(retry=False).remove(url + "/a b/café.txt")
    assert rec.requests[0].path == "/a%20b/caf%C3%A9.txt"


def test_BUG03_guard_mkdir_adds_the_slash_to_the_raw_path() -> None:
    with scripted_server(always((201, {}, b""))) as (url, rec):
        FileSystem(retry=False).mkdir(url + "/d%2Fx")
    assert rec.requests[0].path == "/d%2Fx/"


# ------------------------------------------------------------------ BUG-04
def test_BUG04_ls_keeps_a_trailing_space(ffs: WebdavFileSystem, tmp_path: Path) -> None:
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "plain.txt").write_text("1")
    (tmp_path / "data ").mkdir()
    (tmp_path / "data " / "spaced.txt").write_text("2")
    assert ffs.ls("/data ", detail=False) == ["/data /spaced.txt"]
    assert ffs.ls("/data", detail=False) == ["/data/plain.txt"]
    assert "/data /spaced.txt" in ffs.find("/")


def test_BUG04_file_with_a_trailing_space(
    ffs: WebdavFileSystem, tmp_path: Path
) -> None:
    (tmp_path / "trail ").write_text("x")
    assert ffs.ls("/trail ", detail=False) == ["/trail "]


def test_BUG04_guard_plain_paths(ffs: WebdavFileSystem, tmp_path: Path) -> None:
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "a").write_text("1")
    assert ffs.ls("d", detail=False) == ["/d/a"]
    assert ffs.ls("/d/", detail=False) == ["/d/a"]
    assert ffs.ls("webdavs:///d", detail=False) == ["/d/a"]
    assert ffs.ls("", detail=False) == ["/d"]


# ------------------------------------------------------------------ BUG-05
def test_BUG05_transaction_defers_the_put_until_commit(
    ffs: WebdavFileSystem, tmp_path: Path
) -> None:
    with ffs.transaction:
        with ffs.open("/tx1.txt", "wb") as f:
            f.write(b"abc")
        assert not (tmp_path / "tx1.txt").exists()
    assert (tmp_path / "tx1.txt").read_bytes() == b"abc"


def test_BUG05_transaction_rolls_back_on_an_error(
    ffs: WebdavFileSystem, tmp_path: Path
) -> None:
    with pytest.raises(RuntimeError):
        with ffs.transaction:
            with ffs.open("/tx2.txt", "wb") as f:
                f.write(b"abc")
            raise RuntimeError("boom")
    assert not (tmp_path / "tx2.txt").exists()


def test_BUG05_transaction_two_files_and_text_mode(
    ffs: WebdavFileSystem, tmp_path: Path
) -> None:
    with ffs.transaction:
        with ffs.open("/a.txt", "w") as f:
            f.write("a")
        with ffs.open("/b.txt", "wb") as f:
            f.write(b"b")
    assert (tmp_path / "a.txt").read_text() == "a"
    assert (tmp_path / "b.txt").read_text() == "b"


def test_BUG05_transaction_does_not_hold_a_big_file_in_memory(
    ffs: WebdavFileSystem, tmp_path: Path
) -> None:
    data = os.urandom(20 * 1024 * 1024)
    with ffs.transaction:
        with ffs.open("/big.bin", "wb") as f:
            f.write(data)
            assert f._rolled  # type: ignore[attr-defined]  # on disk, not in RAM
    assert (tmp_path / "big.bin").read_bytes() == data


def test_BUG05_a_failing_commit_leaves_no_open_file(
    ffs: WebdavFileSystem, tmp_path: Path
) -> None:
    (
        tmp_path / "taken"
    ).mkdir()  # a collection where the PUT goes: the server refuses it
    held = []
    with pytest.raises(IsADirectoryError):
        with ffs.transaction:
            f = ffs.open("/taken", "wb")
            f.write(b"1")
            f.close()
            held.append(f)
    assert all(f.closed for f in held)
    with pytest.raises(RuntimeError):
        with ffs.transaction:
            g = ffs.open("/other.txt", "wb")
            g.write(b"1")
            g.close()
            held.append(g)
            raise RuntimeError
    assert all(f.closed for f in held)
    assert not (tmp_path / "other.txt").exists()


def test_BUG05_guard_plain_open_uploads_on_close(
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


def test_BUG05_guard_an_exception_in_a_plain_with_discards(
    ffs: WebdavFileSystem, tmp_path: Path
) -> None:
    with pytest.raises(RuntimeError):
        with ffs.open("/nope.txt", "wb") as f:
            f.write(b"x")
            raise RuntimeError
    assert not (tmp_path / "nope.txt").exists()


# ------------------------------------------------------------------ BUG-06
def test_BUG06_fileobj_not_at_offset_zero(fs: FileSystem, tmp_path: Path) -> None:
    buf = io.BytesIO(b"HEADER:payload-bytes")
    buf.seek(7)
    fs.upload_fileobj(buf, "/off.bin")
    assert (tmp_path / "off.bin").read_bytes() == b"payload-bytes"


def test_BUG06_real_file_at_an_offset(fs: FileSystem, tmp_path: Path) -> None:
    src = tmp_path / "s.bin"
    src.write_bytes(b"HEADER:payload-bytes")
    with src.open("rb") as fobj:
        fobj.seek(7)
        fs.upload_fileobj(fobj, "/off2.bin")
    assert (tmp_path / "off2.bin").read_bytes() == b"payload-bytes"


def test_BUG06_pipe(fs: FileSystem, tmp_path: Path) -> None:
    r, w = os.pipe()
    os.write(w, b"from a pipe")
    os.close(w)
    with os.fdopen(r, "rb") as fobj:
        fs.upload_fileobj(fobj, "/pipe.bin")
    assert (tmp_path / "pipe.bin").read_bytes() == b"from a pipe"


def test_BUG06_fifo(fs: FileSystem, tmp_path: Path) -> None:
    import threading

    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)

    def feed() -> None:
        with fifo.open("wb") as out:
            out.write(b"through a fifo")

    thread = threading.Thread(target=feed)
    thread.start()
    with fifo.open("rb") as fobj:
        fs.upload_fileobj(fobj, "/fifo.bin")
    thread.join()
    assert (tmp_path / "fifo.bin").read_bytes() == b"through a fifo"


def test_BUG06_a_pipe_is_sent_chunked() -> None:
    with _record_server() as (url, rec):
        r, w = os.pipe()
        os.write(w, b"x")
        os.close(w)
        with os.fdopen(r, "rb") as fobj:
            try:
                FileSystem(retry=False).upload_fileobj(fobj, url + "/p", overwrite=True)
            except Exception:  # the scripted server does not de-chunk  # noqa: BLE001
                pass
    assert rec.requests
    assert "content-length" not in rec.requests[0].headers
    assert rec.requests[0].headers.get("transfer-encoding") == "chunked"


def test_BUG06_the_fsspec_front_doors(ffs: WebdavFileSystem, tmp_path: Path) -> None:
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


def test_BUG06_guard_sizes(fs: FileSystem, tmp_path: Path) -> None:
    fs.upload_fileobj(io.BytesIO(b""), "/empty")
    fs.upload_fileobj(io.BytesIO(b"abc"), "/abc")
    assert (tmp_path / "empty").read_bytes() == b""
    assert (tmp_path / "abc").read_bytes() == b"abc"


def test_BUG06_guard_a_longer_file_than_declared_still_errors(fs: FileSystem) -> None:
    with pytest.raises(ClientError):
        fs.upload_fileobj(io.BytesIO(b"abcdef"), "/x", size=3)


# ------------------------------------------------------------------ BUG-10
@pytest.mark.parametrize("status", [202, 204])
def test_BUG10_mkdir_accepts_any_success_status(status: int) -> None:
    with scripted_server(always((status, {}, b""))) as (url, _):
        FileSystem(retry=False).mkdir(url + "/d")


def test_BUG10_mkdir_405_is_only_exists_if_the_resource_is_there() -> None:
    def respond(seen: Seen) -> tuple[int, dict[str, str], bytes]:
        if seen.method == "PROPFIND":
            return 404, {}, b""
        return 405, {"Allow": "GET, PUT"}, b""

    with scripted_server(respond) as (url, _):
        with pytest.raises(WebDAVError) as caught:
            FileSystem(retry=False).mkdir(url + "/d")
    assert not isinstance(caught.value, ResourceAlreadyExistsError)


def test_BUG10_guard_mkdir_on_something_that_exists(fs: FileSystem) -> None:
    fs.mkdir("/d")
    with pytest.raises(ResourceAlreadyExistsError):
        fs.mkdir("/d")


def test_BUG10_guard_fsspec_makedirs_exist_ok(ffs: WebdavFileSystem) -> None:
    ffs.makedirs("/a/b", exist_ok=True)
    ffs.makedirs("/a/b", exist_ok=True)


def test_BUG10_copy_412_from_the_if_header_is_not_exists() -> None:
    def respond(seen: Seen) -> tuple[int, dict[str, str], bytes]:
        return (404, {}, b"") if seen.method == "PROPFIND" else (412, {}, b"")

    with scripted_server(respond) as (url, _):
        with pytest.raises(PreconditionFailedError) as caught:
            FileSystem(url, retry=False).copy("/a", "/b")
        with pytest.raises(PreconditionFailedError) as caught_move:
            FileSystem(url, retry=False).move("/a", "/b")
    assert not isinstance(caught.value, ResourceAlreadyExistsError)
    assert not isinstance(caught_move.value, ResourceAlreadyExistsError)


def test_BUG10_guard_copy_and_move_onto_an_existing_destination(fs: FileSystem) -> None:
    fs.upload_fileobj(io.BytesIO(b"1"), "/a")
    fs.upload_fileobj(io.BytesIO(b"2"), "/b")
    with pytest.raises(ResourceAlreadyExistsError):
        fs.copy("/a", "/b")
    with pytest.raises(ResourceAlreadyExistsError):
        fs.move("/a", "/b")


# ------------------------------------------------------------------ BUG-11
def test_BUG11_guard_an_unclosed_upload_file_still_uploads_and_warns(
    ffs: WebdavFileSystem, tmp_path: Path
) -> None:
    with pytest.warns(ResourceWarning):
        f = ffs.open("/gc.txt", "wb")
        f.write(b"x")
        del f
        gc.collect()
    assert (tmp_path / "gc.txt").read_bytes() == b"x"


def test_BUG11_an_unclosed_transaction_file_is_not_uploaded_by_the_collector(
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


# ------------------------------------------------------------------ DOS-04
def _endless_server(counter: list[int]) -> Any:
    def respond(seen: Seen) -> tuple[int, dict[str, str], bytes]:
        if seen.method == "PROPFIND":
            counter[0] += 1
            base = seen.path.rstrip("/")
            entries = [_entry(base + "/", True)]
            if seen.headers.get("depth") == "1":
                entries += [_entry(base + "/d/", True), _entry(base + "/f", False, 3)]
            return 207, XML, _multistatus(*entries)
        return 200, {"Content-Length": "3"}, b"abc"

    return respond


@pytest.mark.parametrize("call", ["find", "walk", "du", "glob", "expand_path"])
def test_DOS04_an_endless_tree_is_a_client_error_not_a_recursion_error(
    call: str,
) -> None:
    counter = [0]
    with scripted_server(_endless_server(counter)) as (url, _):
        filesystem = WebdavFileSystem(url)
        operations: dict[str, Any] = {
            "find": lambda: filesystem.find("/"),
            "walk": lambda: list(filesystem.walk("/")),
            "du": lambda: filesystem.du("/"),
            "glob": lambda: filesystem.glob("/**"),
            "expand_path": lambda: filesystem.expand_path("/", recursive=True),
        }
        with pytest.raises(ClientError, match="too deep"):
            operations[call]()
    assert counter[0] < 2000


def test_DOS04_a_deep_but_finite_tree_is_walked(ffs: WebdavFileSystem) -> None:
    path = "/" + "/".join(f"l{i}" for i in range(40))
    ffs.pipe_file(path + "/leaf.txt", b"x")
    assert ffs.find("/") == [path + "/leaf.txt"]


def test_DOS04_guard_the_fsspec_contract_of_walk(ffs: WebdavFileSystem) -> None:
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


# ------------------------------------------------------------------ EXC-06
@pytest.mark.parametrize(
    "authority", ["h:²", "h:٣٠", "[::1]:٨٠", "h:1_0", "h:+80", "h:8 0"]
)
def test_EXC06_a_port_is_ascii_digits(authority: str) -> None:
    from webdav._webdavs_url import host_and_port

    with pytest.raises(ValueError, match="host"):
        host_and_port(authority)


@pytest.mark.parametrize(
    ("authority", "expected"),
    [("h:80", ("h", 80)), ("[::1]:8080", ("::1", 8080)), ("h", ("h", None))],
)
def test_EXC06_guard_ordinary_authorities(
    authority: str, expected: "tuple[str, int | None]"
) -> None:
    from webdav._webdavs_url import host_and_port

    assert host_and_port(authority) == expected


# ------------------------------------------------------------------ FS-01 (recursive get)
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
def test_FS01_recursive_get_does_not_follow_a_symlink_out_of_the_destination(
    ffs: WebdavFileSystem, tmp_path_factory: pytest.TempPathFactory, source: str
) -> None:
    ffs.pipe_file("/d/sub/f.txt", b"REMOTE")
    ffs.pipe_file("/d/top.txt", b"top")
    _base, outside, dst = _two_dirs(tmp_path_factory, "get")
    (dst / ("sub" if source.endswith("/") else "d")).symlink_to(outside)
    with pytest.raises(OSError, match="follow_symlinks=True"):
        ffs.get(source, str(dst), recursive=True)
    assert not list(outside.iterdir())


def test_FS01_follow_symlinks_restores_the_old_behaviour(
    ffs: WebdavFileSystem, tmp_path_factory: pytest.TempPathFactory
) -> None:
    ffs.pipe_file("/d/photos/f.txt", b"REMOTE")
    _base, big, dst = _two_dirs(tmp_path_factory, "get")
    (dst / "photos").symlink_to(big)
    ffs.get("/d/", str(dst), recursive=True, follow_symlinks=True)
    assert (big / "f.txt").read_bytes() == b"REMOTE"


def test_FS01_guard_the_destination_root_may_be_a_symlink(
    ffs: WebdavFileSystem, tmp_path_factory: pytest.TempPathFactory
) -> None:
    ffs.pipe_file("/d/sub/f.txt", b"REMOTE")
    base = tmp_path_factory.mktemp("get")
    (base / "mnt").mkdir()
    (base / "data").symlink_to(base / "mnt")
    ffs.get("/d/", str(base / "data"), recursive=True)
    assert (base / "mnt" / "sub" / "f.txt").read_bytes() == b"REMOTE"


def test_FS01_guard_a_symlink_inside_the_tree_that_points_inside(
    ffs: WebdavFileSystem, tmp_path_factory: pytest.TempPathFactory
) -> None:
    ffs.pipe_file("/d/sub/f.txt", b"REMOTE")
    dst = tmp_path_factory.mktemp("get") / "dst"
    (dst / "real").mkdir(parents=True)
    (dst / "sub").symlink_to(dst / "real")
    ffs.get("/d/", str(dst), recursive=True)
    assert (dst / "real" / "f.txt").read_bytes() == b"REMOTE"


def test_FS01_guard_a_single_file_and_lists_follow_the_callers_paths(
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
    with pytest.raises(OSError):
        ffs.get("/one.txt", str(base / "link.txt"))
    outside = base / "outside"
    outside.mkdir()
    ffs.get(["/one.txt", "/two.txt"], [str(outside / "a"), str(outside / "b")])
    assert (outside / "a").read_bytes() == b"1"


def test_FS01_guard_a_plain_recursive_get(
    ffs: WebdavFileSystem, tmp_path_factory: pytest.TempPathFactory
) -> None:
    ffs.pipe_file("/d/a/1.txt", b"1")
    ffs.pipe_file("/d/2.txt", b"2")
    dst = tmp_path_factory.mktemp("get") / "dst"
    ffs.get("/d/", str(dst), recursive=True)
    assert (dst / "a" / "1.txt").read_bytes() == b"1"
    assert (dst / "2.txt").read_bytes() == b"2"


# ------------------------------------------------------------------ FS-02 (put, upload_file)
def test_FS02_upload_file_can_refuse_a_symlink(
    fs: FileSystem, tmp_path_factory: pytest.TempPathFactory
) -> None:
    base = tmp_path_factory.mktemp("up")
    (base / "secret.txt").write_text("TOP-SECRET")
    (base / "innocent.txt").symlink_to(base / "secret.txt")
    with pytest.raises(OSError):
        fs.upload_file(base / "innocent.txt", "/innocent.txt", follow_symlinks=False)


def test_FS02_guard_upload_file_follows_a_symlink_by_default(
    fs: FileSystem, tmp_path: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    base = tmp_path_factory.mktemp("up")
    (base / "real.txt").write_text("data")
    (base / "link.txt").symlink_to(base / "real.txt")
    fs.upload_file(base / "link.txt", "/link.txt")
    assert (tmp_path / "link.txt").read_text() == "data"


def test_FS02_the_module_function_has_the_parameter(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    import inspect

    import webdav

    assert "follow_symlinks" in inspect.signature(webdav.upload_file).parameters


def test_FS02_recursive_put_refuses_a_symlink_out_of_the_tree(
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


def test_FS02_a_glob_put_checks_against_the_directory_before_the_glob(
    ffs: WebdavFileSystem, tmp_path: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    base = tmp_path_factory.mktemp("up")
    (base / "src").mkdir()
    (base / "secret.txt").write_text("TOP-SECRET")
    (base / "src" / "innocent.txt").symlink_to(base / "secret.txt")
    with pytest.raises(OSError):
        ffs.put(str(base / "src" / "*.txt"), "/dest/")
    assert not (tmp_path / "dest" / "innocent.txt").exists()


def test_FS02_follow_symlinks_restores_the_old_behaviour(
    ffs: WebdavFileSystem, tmp_path: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    base = tmp_path_factory.mktemp("up")
    (base / "src").mkdir()
    (base / "secret.txt").write_text("DATA")
    (base / "src" / "link.txt").symlink_to(base / "secret.txt")
    ffs.put(str(base / "src") + "/", "/dest/", recursive=True, follow_symlinks=True)
    assert (tmp_path / "dest" / "link.txt").read_text() == "DATA"


def test_FS02_guard_symlinks_inside_the_tree_and_a_named_symlink_work(
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


def test_FS02_guard_the_source_root_may_be_a_symlink(
    ffs: WebdavFileSystem, tmp_path: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    base = tmp_path_factory.mktemp("up")
    (base / "real").mkdir()
    (base / "real" / "a.txt").write_text("a")
    (base / "link").symlink_to(base / "real")
    ffs.put(str(base / "link") + "/", "/dest/", recursive=True)
    assert (tmp_path / "dest" / "a.txt").read_text() == "a"


# ------------------------------------------------------------------ FS-03
def test_FS03_safe_local_name_on_posix() -> None:
    from webdav.resource import safe_local_name

    assert safe_local_name("dir/sub/file.txt") == "file.txt"
    assert safe_local_name("dir/sub/") == "sub"
    # a backslash, a colon and a leading dash are ordinary POSIX names
    for name in ("a\\b.txt", "a:b", "-rf", "~", ".bashrc"):
        assert safe_local_name(name) == name


@pytest.mark.parametrize(
    "name", ["", "/", ".", "..", "a\x00b", "x\ny", "\x1b[31mred", "a\x7fb"]
)
def test_FS03_safe_local_name_refuses_what_no_platform_can_use(name: str) -> None:
    from webdav.resource import safe_local_name

    with pytest.raises(ValueError, match="not usable"):
        safe_local_name(name)


@pytest.mark.parametrize(
    "name",
    [
        "CON",
        "con.txt",
        "NUL",
        "com1",
        "LPT9.log",
        "a:evil",
        "a\\b",
        "trail.",
        "trail ",
        'a"b',
        "a*b",
        "a?b",
    ],
)
def test_FS03_safe_local_name_on_windows(name: str) -> None:
    from webdav.resource import safe_local_name

    with pytest.raises(ValueError, match="not usable on Windows"):
        safe_local_name(name, windows=True)


def test_FS03_guard_ordinary_names_on_windows() -> None:
    from webdav.resource import safe_local_name

    for name in ("report.txt", "Straße.txt", "console.txt", "日本語.md", "a b.txt"):
        assert safe_local_name(name, windows=True) == name


def test_FS03_the_message_escapes_the_server_name() -> None:
    from webdav.resource import safe_local_name

    with pytest.raises(ValueError) as caught:
        safe_local_name("\x1b[2Jfake\x00", windows=False)
    assert "\x1b" not in str(caught.value)


def test_FS03_resource_basename() -> None:
    from webdav import Resource

    r = Resource("dir/sub/a\\b.txt", href="/dir/sub/a%5Cb.txt", is_dir=False)
    assert r.basename == "a\\b.txt"
    assert Resource("dir/sub", href="/dir/sub/", is_dir=True).basename == "sub"


def test_FS03_windows_rules_are_not_on_by_themselves() -> None:
    from webdav.resource import safe_local_name

    assert (
        safe_local_name("CON") == "CON"
    )  # only windows=True refuses it, whatever os.name is
    assert safe_local_name("trail.") == "trail."


def test_FS03_prepared_windows_name_check(tmp_path: Path) -> None:
    from webdav._fsspec_guards import GetTree

    tree = GetTree(str(tmp_path), contained=True)
    tree.check_windows_names(str(tmp_path / "ok" / "a.txt"))
    with pytest.raises(OSError, match="not usable on Windows"):
        tree.check_windows_names(str(tmp_path / "d" / "CON"))


def test_FS03_prepared_collision_check(tmp_path: Path) -> None:
    from webdav._fsspec_guards import GetTree

    (tmp_path / "a.txt").write_bytes(b"x")
    os.link(
        tmp_path / "a.txt", tmp_path / "A.TXT"
    )  # what the two are where case is folded
    tree = GetTree(str(tmp_path), contained=True)
    tree.record(str(tmp_path / "a.txt"))
    with pytest.raises(OSError, match="same file"):
        tree.check_collision(str(tmp_path / "A.TXT"))
    tree.check_collision(
        str(tmp_path / "a.txt")
    )  # the same name again is not a collision


def test_FS03_get_does_not_enforce_platform_name_rules(
    ffs: WebdavFileSystem, tmp_path_factory: pytest.TempPathFactory
) -> None:
    ffs.pipe_file("/d/CON", b"x")
    ffs.pipe_file("/d/Case.TXT", b"4")
    ffs.pipe_file("/d/case.txt", b"5")
    dst = tmp_path_factory.mktemp("get") / "dst"
    ffs.get("/d/", str(dst), recursive=True)
    assert sorted(p.name for p in dst.iterdir()) == ["CON", "Case.TXT", "case.txt"]


def test_FS03_guard_posix_names_download_as_they_are(
    ffs: WebdavFileSystem, tmp_path_factory: pytest.TempPathFactory
) -> None:
    ffs.pipe_file("/d/a\\b.txt", b"1")
    ffs.pipe_file("/d/c:d", b"2")
    ffs.pipe_file("/d/-rf", b"3")
    ffs.pipe_file("/d/Case.TXT", b"4")
    ffs.pipe_file("/d/case.txt", b"5")
    dst = tmp_path_factory.mktemp("get") / "dst"
    ffs.get("/d/", str(dst), recursive=True)
    assert sorted(p.name for p in dst.iterdir()) == sorted(
        ["a\\b.txt", "c:d", "-rf", "Case.TXT", "case.txt"]
    )


# ------------------------------------------------------------------ FS-04
def test_FS04_the_part_file_is_private_while_it_is_written(
    fs: FileSystem, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fs.upload_fileobj(io.BytesIO(b"x" * 1000), "/a.txt")
    modes: list[int] = []
    real_fdopen = os.fdopen

    def spy(fd: int, *args: Any, **kwargs: Any) -> Any:
        modes.append(stat.S_IMODE(os.fstat(fd).st_mode))
        return real_fdopen(fd, *args, **kwargs)

    monkeypatch.setattr(os, "fdopen", spy)
    target = tmp_path / "out" / "n.txt"
    target.parent.mkdir()
    fs.download_file("/a.txt", target)
    assert modes[0] == 0o600


def test_FS04_guard_the_final_mode_follows_the_umask(
    fs: FileSystem, tmp_path: Path
) -> None:
    fs.upload_fileobj(io.BytesIO(b"x"), "/a.txt")
    previous = os.umask(0o027)
    try:
        fs.download_file("/a.txt", tmp_path / "n.txt")
        fs.download_file("/a.txt", tmp_path / "o.txt", overwrite=True)
        (tmp_path / "p.txt").write_text("old")
        (tmp_path / "p.txt").chmod(0o600)
        fs.download_file("/a.txt", tmp_path / "p.txt", overwrite=True)
    finally:
        os.umask(previous)
    assert stat.S_IMODE((tmp_path / "n.txt").stat().st_mode) == 0o640
    assert stat.S_IMODE((tmp_path / "o.txt").stat().st_mode) == 0o640
    assert (
        stat.S_IMODE((tmp_path / "p.txt").stat().st_mode) == 0o600
    )  # what is replaced keeps its own


def test_FS04_a_file_system_that_refuses_chmod_still_gets_the_download(
    fs: FileSystem, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import shutil

    fs.upload_fileobj(io.BytesIO(b"x"), "/a.txt")

    def refuse(*_args: Any, **_kwargs: Any) -> None:
        raise PermissionError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(shutil, "copymode", refuse)
    fs.download_file("/a.txt", tmp_path / "n.txt")
    assert (tmp_path / "n.txt").read_bytes() == b"x"


def test_FS04_a_failed_download_leaves_no_part_file(
    fs: FileSystem, tmp_path: Path
) -> None:
    fs.upload_fileobj(io.BytesIO(b"x" * 100), "/a.txt")

    def boom(_n: int) -> None:
        raise KeyboardInterrupt

    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(KeyboardInterrupt):
        fs.download_file("/a.txt", out / "n.txt", callback=boom)
    assert list(out.iterdir()) == []
    with pytest.raises(KeyboardInterrupt):
        fs.download_file("/a.txt", out / "n.txt", overwrite=True, callback=boom)
    assert list(out.iterdir()) == []


# ------------------------------------------------------------------ FS-06


# ------------------------------------------------------------------ FS-07
FOREIGN = "webdavs://other.example/secret.txt"


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


