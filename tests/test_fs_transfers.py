"""Moving content between the server and local files or file objects.

Uploads, downloads, ``open()``, text decoding, symlinks, part files and local names.
"""

import contextlib
import errno
import inspect
import io
import os
import shutil
import stat
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import pytest
import requests

import webdav
from tests.builders import multistatus_doc, sized_entry
from tests.credentials import AUTH
from tests.scripted_server import (
    DRIP,
    NO_CONTENT_LENGTH,
    OK,
    Reply,
    Seen,
    always,
    record_server,
    scripted_server,
)
from webdav import FileSystem, Session, exceptions
from webdav.exceptions import (
    ClientError,
    HTTPStatusError,
    WebDAVError,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import BinaryIO


def test_a_failed_download_leaves_an_existing_local_file_alone(
    server_url: str, tmp_path: Path
) -> None:
    target = tmp_path / "keep.txt"
    target.write_bytes(b"precious")
    with (
        FileSystem(server_url, auth=AUTH, retry=False) as fs,
        pytest.raises(webdav.ResourceNotFoundError),
    ):
        fs.download_file("missing.txt", target, overwrite=True)
    assert target.read_bytes() == b"precious"
    assert [p.name for p in tmp_path.iterdir()] == ["keep.txt"]  # no stray partial file


def test_download_does_not_replace_an_existing_file_unless_told_to(
    server_url: str, tmp_path: Path
) -> None:
    target = tmp_path / "there.txt"
    target.write_bytes(b"local")
    with Session(server_url, auth=AUTH, retry=False) as session:
        fs = FileSystem.from_session(session)
        session.put("remote.txt", b"remote")
        with pytest.raises(FileExistsError):
            fs.download_file("remote.txt", target)
        assert target.read_bytes() == b"local"
        fs.download_file("remote.txt", target, overwrite=True)
        assert target.read_bytes() == b"remote"
        fresh = tmp_path / "fresh.txt"
        fs.download_file("remote.txt", fresh)
        assert fresh.read_bytes() == b"remote"


def test_a_download_does_not_follow_a_symlink_at_the_target(
    server_url: str, tmp_path: Path
) -> None:
    victim = tmp_path / "victim.txt"
    victim.write_bytes(b"do not touch")
    link = tmp_path / "link.txt"
    link.symlink_to(victim)
    with Session(server_url, auth=AUTH, retry=False) as session:
        fs = FileSystem.from_session(session)
        session.put("remote.txt", b"remote")
        with pytest.raises((FileExistsError, OSError)):
            fs.download_file("remote.txt", link, overwrite=True)
    assert victim.read_bytes() == b"do not touch"


def test_a_per_call_chunk_size_is_validated_too(
    server_url: str, tmp_path: Path
) -> None:
    with Session(server_url, auth=AUTH, retry=False) as session:
        session.put("a.txt", b"x")
        with pytest.raises(ValueError, match="chunk_size"):
            FileSystem.from_session(session).download_file(
                "a.txt", tmp_path / "o.txt", chunk_size=0
            )


@pytest.mark.parametrize("mode", ["rb", "wb"])
def test_open_validates_chunk_size_up_front_like_the_other_transfers(
    server_url: str, mode: str
) -> None:
    """Unlike download_file/download_fileobj/upload_fileobj, open() used to pass chunk_size straight through unchecked - a read never validated it at all, and a write only found out after the whole body had been spooled."""
    with Session(server_url, auth=AUTH, retry=False) as session:
        session.put("a.txt", b"x")
        with (
            pytest.raises(ValueError, match="chunk_size"),
            FileSystem.from_session(session).open(  # type: ignore[call-overload]
                "a.txt", mode, chunk_size=0
            ),
        ):
            pass


def test_module_level_transfers_reject_unknown_arguments_and_forward_known_ones(
    server_url: str, tmp_path: Path
) -> None:
    source = tmp_path / "in.txt"
    source.write_bytes(b"payload")
    seen: list[int] = []
    webdav.upload_file(source, f"{server_url}/f.txt", auth=AUTH, callback=seen.append)
    assert sum(seen) == 7
    seen.clear()
    webdav.download_file(
        f"{server_url}/f.txt", tmp_path / "out.txt", auth=AUTH, callback=seen.append
    )
    assert sum(seen) == 7
    with pytest.raises(TypeError):
        webdav.download_file(f"{server_url}/f.txt", tmp_path / "x", auth=AUTH, bogus_kw=1)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        webdav.upload_file(source, f"{server_url}/g.txt", auth=AUTH, bogus=1)  # type: ignore[call-arg]


_FILE_PROPS = (
    b'<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response><d:href>/f</d:href>'
    b"<d:propstat><d:prop><d:resourcetype/></d:prop><d:status>HTTP/1.1 200 OK</d:status>"
    b"</d:propstat></d:response></d:multistatus>"
)


def _file_server(get_reply: "tuple[int, dict[str, str], bytes]") -> Any:
    def respond(seen: Seen) -> tuple[int, dict[str, str], bytes]:
        if seen.method == "PROPFIND":
            return 207, {"Content-Type": "application/xml"}, _FILE_PROPS
        return get_reply

    return respond


def test_a_416_on_the_first_get_is_an_error_not_an_empty_download() -> None:
    with (
        scripted_server(_file_server((416, {}, b""))) as (url, _rec),
        pytest.raises(HTTPStatusError),
    ):
        FileSystem(retry=False).download_fileobj(f"{url}/f", io.BytesIO())


@pytest.mark.parametrize("status", [403, 404])
def test_a_failed_download_gives_its_connection_back(status: int) -> None:
    """The error response of a streamed GET is not read; nothing may keep its connection checked out."""
    with (
        scripted_server(_file_server((status, {}, b"not for you"))) as (url, _rec),
        pytest.raises(HTTPStatusError) as caught,
    ):
        FileSystem(retry=False).download_fileobj(f"{url}/f", io.BytesIO())
    assert caught.value.status_code == status
    assert caught.value.response.raw.closed
    assert (
        caught.value.error_codes == frozenset()
    )  # still usable: no error body, no codes


def test_a_truncated_download_is_never_reported_as_complete() -> None:
    """Server promises 1000 bytes, sends 100, then answers the resume with 416."""
    calls = {"n": 0}

    def respond(seen: Seen) -> tuple[int, dict[str, str], bytes]:
        if seen.method == "PROPFIND":
            return 207, {"Content-Type": "application/xml"}, _FILE_PROPS
        calls["n"] += 1
        if calls["n"] == 1:
            return (
                200,
                {"Content-Length": "1000", "ETag": '"e"', NO_CONTENT_LENGTH: "1"},
                b"x" * 100,
            )
        return 416, {"Content-Range": "bytes */1000"}, b""

    out = io.BytesIO()
    with (
        scripted_server(respond) as (url, _rec),
        pytest.raises((WebDAVError, requests.RequestException)),
    ):
        FileSystem(retry=False).download_fileobj(f"{url}/f", out)
    assert len(out.getvalue()) < 1000


PROPFIND_FILE = multistatus_doc(sized_entry("/f", False))


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
    with (
        scripted_server(_text_server(content_type, body)) as (url, _),
        FileSystem(retry=False).open(f"{url}/f", **options) as f,
    ):
        return str(f.read())


def test_bug02_text_without_charset_is_utf8() -> None:
    assert _read_text("text/plain", "héllo wörld €".encode()) == "héllo wörld €"


def test_bug02_no_content_type_is_utf8() -> None:
    assert _read_text(None, "héllo €".encode()) == "héllo €"


def test_bug02_guard_declared_latin1_is_honoured() -> None:
    assert (
        _read_text("text/plain; charset=iso-8859-1", "héllo".encode("latin-1"))
        == "héllo"
    )


def test_bug02_guard_quoted_and_uppercase_charset() -> None:
    assert _read_text('text/plain; Charset="UTF-8"', "héllo".encode()) == "héllo"


def test_bug02_guard_explicit_encoding_wins() -> None:
    assert (
        _read_text("text/plain", "héllo".encode("latin-1"), encoding="iso-8859-1")
        == "héllo"
    )


def test_bug02_legacy_latin1_without_charset_needs_encoding() -> None:
    with pytest.raises(UnicodeDecodeError):
        _read_text("text/plain", "héllo".encode("latin-1"))


def test_bug02_guard_hostile_charset_is_not_used() -> None:
    assert _read_text("text/plain; charset=rot13", "héllo".encode()) == "héllo"


def test_bug06_fileobj_not_at_offset_zero(fs: FileSystem, tmp_path: Path) -> None:
    buf = io.BytesIO(b"HEADER:payload-bytes")
    buf.seek(7)
    fs.upload_fileobj(buf, "/off.bin")
    assert (tmp_path / "off.bin").read_bytes() == b"payload-bytes"


def test_bug06_real_file_at_an_offset(fs: FileSystem, tmp_path: Path) -> None:
    src = tmp_path / "s.bin"
    src.write_bytes(b"HEADER:payload-bytes")
    with src.open("rb") as fobj:
        fobj.seek(7)
        fs.upload_fileobj(fobj, "/off2.bin")
    assert (tmp_path / "off2.bin").read_bytes() == b"payload-bytes"


def test_bug06_pipe(fs: FileSystem, tmp_path: Path) -> None:
    r, w = os.pipe()
    os.write(w, b"from a pipe")
    os.close(w)
    with os.fdopen(r, "rb") as fobj:
        fs.upload_fileobj(fobj, "/pipe.bin")
    assert (tmp_path / "pipe.bin").read_bytes() == b"from a pipe"


def test_bug06_fifo(fs: FileSystem, tmp_path: Path) -> None:
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


def test_bug06_a_pipe_is_sent_chunked() -> None:
    with record_server() as (url, rec):
        r, w = os.pipe()
        os.write(w, b"x")
        os.close(w)
        with (
            os.fdopen(r, "rb") as fobj,
            # the scripted server does not de-chunk, so the upload itself may fail
            contextlib.suppress(Exception),
        ):
            FileSystem(retry=False).upload_fileobj(fobj, url + "/p", overwrite=True)
    assert rec.requests
    assert "content-length" not in rec.requests[0].headers
    assert rec.requests[0].headers.get("transfer-encoding") == "chunked"


def test_bug06_guard_sizes(fs: FileSystem, tmp_path: Path) -> None:
    fs.upload_fileobj(io.BytesIO(b""), "/empty")
    fs.upload_fileobj(io.BytesIO(b"abc"), "/abc")
    assert (tmp_path / "empty").read_bytes() == b""
    assert (tmp_path / "abc").read_bytes() == b"abc"


def test_bug06_guard_a_longer_file_than_declared_still_errors(fs: FileSystem) -> None:
    with pytest.raises(ClientError):
        fs.upload_fileobj(io.BytesIO(b"abcdef"), "/x", size=3)


def test_fs02_upload_file_can_refuse_a_symlink(
    fs: FileSystem, tmp_path_factory: pytest.TempPathFactory
) -> None:
    base = tmp_path_factory.mktemp("up")
    (base / "secret.txt").write_text("TOP-SECRET")
    (base / "innocent.txt").symlink_to(base / "secret.txt")
    with pytest.raises(OSError, match="symbolic links"):
        fs.upload_file(base / "innocent.txt", "/innocent.txt", follow_symlinks=False)


def test_fs02_guard_upload_file_follows_a_symlink_by_default(
    fs: FileSystem, tmp_path: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    base = tmp_path_factory.mktemp("up")
    (base / "real.txt").write_text("data")
    (base / "link.txt").symlink_to(base / "real.txt")
    fs.upload_file(base / "link.txt", "/link.txt")
    assert (tmp_path / "link.txt").read_text() == "data"


def test_fs02_the_module_function_has_the_parameter() -> None:
    assert "follow_symlinks" in inspect.signature(webdav.upload_file).parameters


def test_fs04_the_part_file_is_private_while_it_is_written(
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


def test_fs04_guard_the_final_mode_follows_the_umask(
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


def test_fs04_a_file_system_that_refuses_chmod_still_gets_the_download(
    fs: FileSystem, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fs.upload_fileobj(io.BytesIO(b"x"), "/a.txt")

    def refuse(*_args: Any, **_kwargs: Any) -> None:
        raise PermissionError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(shutil, "copymode", refuse)
    fs.download_file("/a.txt", tmp_path / "n.txt")
    assert (tmp_path / "n.txt").read_bytes() == b"x"


def test_fs04_a_failed_download_leaves_no_part_file(
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


def test_a_412_on_an_upload_for_a_missing_resource_is_a_precondition_failure() -> None:
    def respond(seen: Seen) -> Reply:
        if seen.method == "PROPFIND":
            return 404, {}, b""
        return 412, {}, b""

    with scripted_server(respond) as (url, _rec):
        fs = FileSystem(url, retry=False)
        with pytest.raises(exceptions.PreconditionFailedError) as excinfo:
            fs.upload_fileobj(io.BytesIO(b"x"), "a")
    assert not isinstance(excinfo.value, exceptions.ResourceAlreadyExistsError)


def test_an_interrupted_download_does_not_leave_a_claimed_empty_target(
    server_url: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "out"
    out.mkdir()
    with Session(server_url, auth=AUTH, retry=False) as session:
        fs = FileSystem.from_session(session)
        session.put("a.txt", b"x")

        def interrupted(_self: Path, _target: object) -> None:
            raise KeyboardInterrupt

        monkeypatch.setattr(Path, "replace", interrupted)
        with pytest.raises(KeyboardInterrupt):
            fs.download_file("a.txt", out / "a.txt")
        monkeypatch.undo()
        assert list(out.iterdir()) == []
        fs.download_file("a.txt", out / "a.txt")  # and a retry just works
        assert (out / "a.txt").read_bytes() == b"x"


class _Liar(io.RawIOBase):
    """A file that says it holds ``declared`` bytes and actually yields ``actual``."""

    def __init__(self, declared: int, actual: int) -> None:
        self.declared, self.remaining = declared, actual

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        take = min(len(buffer), self.remaining)
        buffer[:take] = b"x" * take
        self.remaining -= take
        return take


def test_a_file_that_grows_during_upload_is_an_error_and_never_sent_truncated() -> None:
    with (
        scripted_server(always(OK)) as (url, rec),
        pytest.raises(ClientError, match="longer"),
    ):
        FileSystem(retry=False).upload_fileobj(
            cast("BinaryIO", _Liar(100, 5000)),
            f"{url}/f",
            overwrite=True,
            size=100,
            chunk_size=64,
        )
    assert len(rec.requests) <= 1  # no surplus bytes parsed as a second request


@pytest.mark.parametrize("size", [3, 10])
def test_a_body_that_does_not_match_its_declared_size_is_refused(size: int) -> None:
    with (
        scripted_server(always(OK)) as (url, _rec),
        pytest.raises(ClientError, match="declared"),
    ):
        FileSystem(retry=False, timeout=5).upload_fileobj(
            io.BytesIO(b"abcdef" if size == 3 else b"abc"),
            f"{url}/f",
            overwrite=True,
            size=size,
        )


def test_a_file_that_shrinks_during_upload_is_an_error_not_a_hang() -> None:
    with scripted_server(always(OK)) as (url, _rec):
        started = time.monotonic()
        with pytest.raises((ClientError, requests.RequestException)):
            FileSystem(retry=False, timeout=5).upload_fileobj(
                cast("BinaryIO", _Liar(1000, 10)),
                f"{url}/f",
                overwrite=True,
                size=1000,
                chunk_size=64,
            )
        assert time.monotonic() - started < 4


@pytest.mark.parametrize(
    "charset", ["bogus", "x-user-defined", "rot13", "punycode", "idna"]
)
def test_a_hostile_charset_never_picks_the_text_codec(charset: str) -> None:
    def respond(seen: Seen) -> tuple[int, dict[str, str], bytes]:
        if seen.method == "PROPFIND":
            body = (
                b'<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response><d:href>/f</d:href>'
                b"<d:propstat><d:prop><d:resourcetype/></d:prop><d:status>HTTP/1.1 200 OK</d:status>"
                b"</d:propstat></d:response></d:multistatus>"
            )
            return 207, {}, body
        return 200, {"Content-Type": f"text/plain; charset={charset}"}, "héllo".encode()

    with (
        scripted_server(respond) as (url, _rec),
        FileSystem(retry=False).open(f"{url}/f") as fobj,
    ):
        assert fobj.read() == "héllo"


_FOUND = (
    b'<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response><d:href>/a</d:href>'
    b"<d:propstat><d:prop><d:resourcetype/></d:prop><d:status>HTTP/1.1 200 OK</d:status>"
    b"</d:propstat></d:response></d:multistatus>"
)


def test_a_412_is_a_precondition_failure_not_necessarily_an_existing_resource() -> None:
    def respond(seen: Seen) -> Reply:
        # A 412 for the upload; the resource is there (a PROPFIND finds it).
        if seen.method == "PROPFIND":
            return 207, {}, _FOUND
        return 412, {}, b""

    with scripted_server(respond) as (url, _rec):
        session = Session(retry=False, raise_on_error=True)
        fs = FileSystem.from_session(session)
        with pytest.raises(exceptions.PreconditionFailedError) as excinfo:
            session.put(f"{url}/a", data=b"x")
        assert not isinstance(excinfo.value, exceptions.ResourceAlreadyExistsError)
        assert "already exists" not in str(excinfo.value)
        # ...while an upload that asked for "create only" knows what a 412 means:

        with pytest.raises(exceptions.ResourceAlreadyExistsError):
            fs.upload_fileobj(io.BytesIO(b"x"), f"{url}/a")
    assert issubclass(
        exceptions.ResourceAlreadyExistsError, exceptions.PreconditionFailedError
    )


def test_download_does_not_touch_the_process_umask(
    server_url: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(_mask: int) -> int:
        msg = "the process-wide umask must not be changed"
        raise AssertionError(msg)

    monkeypatch.setattr(os, "umask", forbidden)
    with Session(server_url, auth=AUTH, retry=False) as session:
        fs = FileSystem.from_session(session)
        session.put("a.txt", b"x")
        (tmp_path / "local").mkdir()
        fs.download_file("a.txt", tmp_path / "local" / "a.txt")
    assert (tmp_path / "local" / "a.txt").read_bytes() == b"x"


def test_download_keeps_the_permissions_of_the_file_it_replaces(
    server_url: str, tmp_path: Path
) -> None:
    target = tmp_path / "secret.txt"
    target.write_bytes(b"old")
    target.chmod(0o600)
    with Session(server_url, auth=AUTH, retry=False) as session:
        fs = FileSystem.from_session(session)
        session.put("a.txt", b"new")
        fs.download_file("a.txt", target, overwrite=True)
    assert target.read_bytes() == b"new"
    assert target.stat().st_mode & 0o777 == 0o600


def test_a_new_download_gets_the_umask_permissions(
    server_url: str, tmp_path: Path
) -> None:
    previous = os.umask(0o022)
    try:
        with Session(server_url, auth=AUTH, retry=False) as session:
            fs = FileSystem.from_session(session)
            session.put("a.txt", b"x")
            fs.download_file("a.txt", tmp_path / "new.txt")
    finally:
        os.umask(previous)
    assert (tmp_path / "new.txt").stat().st_mode & 0o777 == 0o644


# A callback that raises is how a streamed download is bounded: neither
# max_response_size nor max_response_time applies to it.


class _TooSlowError(Exception):
    """What the callbacks below raise."""


def _within(seconds: float) -> "Callable[[int], None]":
    """A callback that raises once the transfer has taken longer than ``seconds``."""
    started = time.monotonic()

    def callback(_nbytes: int) -> None:
        if time.monotonic() - started > seconds:
            raise _TooSlowError

    return callback


def _at_least(bytes_per_second: float, window: float) -> "Callable[[int], None]":
    """A callback that raises when fewer than ``bytes_per_second`` arrive over ``window`` seconds."""
    window_start = time.monotonic()
    received = 0

    def callback(nbytes: int) -> None:
        nonlocal window_start, received
        received += nbytes
        elapsed = time.monotonic() - window_start
        if elapsed >= window:
            if received / elapsed < bytes_per_second:
                raise _TooSlowError
            window_start, received = time.monotonic(), 0

    return callback


def _dripping_file() -> "Callable[[Seen], Reply]":
    """A server that answers the download with 20 bytes a second, for twenty seconds."""
    return cast(
        "Callable[[Seen], Reply]", _file_server((200, {DRIP: "0.05"}, b"x" * 400))
    )


def test_a_raising_callback_stops_a_download_that_drips(tmp_path: Path) -> None:
    target = tmp_path / "out.bin"
    with (
        scripted_server(_dripping_file()) as (url, _rec),
        FileSystem(url, retry=False, timeout=2) as fs,
    ):
        started = time.monotonic()
        with pytest.raises(_TooSlowError):
            fs.download_file("f", target, callback=_within(0.5))
        assert time.monotonic() - started < 3
    assert list(tmp_path.iterdir()) == []  # no target, no .part file


def test_a_stopped_download_leaves_the_file_it_would_have_replaced(
    tmp_path: Path,
) -> None:
    target = tmp_path / "keep.bin"
    target.write_bytes(b"precious")
    with (
        scripted_server(_dripping_file()) as (url, _rec),
        FileSystem(url, retry=False, timeout=2) as fs,
        pytest.raises(_TooSlowError),
    ):
        fs.download_file("f", target, overwrite=True, callback=_within(0.5))
    assert target.read_bytes() == b"precious"
    assert [p.name for p in tmp_path.iterdir()] == ["keep.bin"]


def test_a_minimum_rate_callback_stops_a_download_that_drips(tmp_path: Path) -> None:
    with (
        scripted_server(_dripping_file()) as (url, _rec),
        FileSystem(url, retry=False, timeout=2) as fs,
        pytest.raises(_TooSlowError),
    ):
        fs.download_file("f", tmp_path / "out.bin", callback=_at_least(100, 0.5))


def test_a_raising_callback_stops_download_fileobj() -> None:
    with (
        scripted_server(_dripping_file()) as (url, _rec),
        FileSystem(url, retry=False, timeout=2) as fs,
        pytest.raises(_TooSlowError),
    ):
        fs.download_fileobj("f", io.BytesIO(), callback=_within(0.5))


def test_a_raising_callback_stops_the_short_form_download(tmp_path: Path) -> None:
    with (
        scripted_server(_dripping_file()) as (url, _rec),
        pytest.raises(_TooSlowError),
    ):
        webdav.download_file(
            f"{url}/f", tmp_path / "out.bin", callback=_within(0.5), retry=False
        )


def test_the_session_is_usable_after_a_download_was_stopped(tmp_path: Path) -> None:
    with (
        scripted_server(_dripping_file()) as (url, _rec),
        FileSystem(url, retry=False, timeout=2) as fs,
    ):
        with pytest.raises(_TooSlowError):
            fs.download_file("f", tmp_path / "out.bin", callback=_within(0.5))
        assert fs.isdir("f") is False
