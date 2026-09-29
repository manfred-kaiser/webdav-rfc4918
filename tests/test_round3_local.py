"""Round 3, local side: fsspec, uploads, downloads and the CLI, against what an audit found."""

# ruff: noqa: SIM117, PLC0415, S105
import io
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any, BinaryIO, cast

import pytest
import requests
from requests.auth import AuthBase

from tests.scripted_server import OK, Seen, always, scripted_server
from tests.server import AUTH
from webdav import Session
from webdav.exceptions import ClientError
from webdav.fsspec import WebdavFileSystem


@pytest.fixture
def fs(server_url: str) -> Iterator[WebdavFileSystem]:
    filesystem = WebdavFileSystem(server_url, auth=AUTH, skip_instance_cache=True)
    yield filesystem
    filesystem.session.close()


# ---------------------------------------------------------------------------
# fsspec writes
# ---------------------------------------------------------------------------


def test_a_failed_fsspec_write_does_not_replace_the_remote_file(
    fs: WebdavFileSystem,
) -> None:
    fs.pipe_file("precious", b"ORIGINAL IMPORTANT DATA")
    with pytest.raises(RuntimeError):  # noqa: PT012 - the raise inside is the point
        with fs.open("precious", "wb") as fobj:
            fobj.write(b"half-writ")
            raise RuntimeError
    assert fs.cat_file("precious") == b"ORIGINAL IMPORTANT DATA"


def test_a_clean_fsspec_write_still_commits(fs: WebdavFileSystem) -> None:
    with fs.open("new.txt", "wb") as fobj:
        fobj.write(b"hello")
    assert fs.cat_file("new.txt") == b"hello"


def test_exclusive_fsspec_open_is_atomic_on_the_server(
    fs: WebdavFileSystem, monkeypatch: pytest.MonkeyPatch
) -> None:
    fs.pipe_file("race", b"theirs")
    monkeypatch.setattr(fs, "exists", lambda *_a, **_k: False)  # the check that races
    with pytest.raises(FileExistsError):
        with fs.open("race", "xb") as fobj:
            fobj.write(b"mine")
    assert fs.cat_file("race") == b"theirs"


def test_fs_get_uses_the_hardened_download(
    fs: WebdavFileSystem, tmp_path: Path
) -> None:
    fs.pipe_file("f", b"remote")
    victim = tmp_path / "victim.txt"
    victim.write_bytes(b"do not touch")
    link = tmp_path / "link.txt"
    link.symlink_to(victim)
    with pytest.raises(OSError, match=r"."):
        fs.get("f", str(link))
    assert victim.read_bytes() == b"do not touch"

    existing = tmp_path / "existing.txt"
    existing.write_bytes(b"old")
    fs.get("f", str(existing))
    assert existing.read_bytes() == b"remote"
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".webdav-")] == []


def test_a_failed_fs_get_keeps_the_old_local_file(
    fs: WebdavFileSystem, tmp_path: Path
) -> None:
    keep = tmp_path / "keep.txt"
    keep.write_bytes(b"old")
    with pytest.raises((OSError, FileNotFoundError)):
        fs.get("missing", str(keep))
    assert keep.read_bytes() == b"old"


@pytest.mark.parametrize("root", ["", "/", ".", "//", "./"])
def test_rm_never_removes_the_root_of_the_file_system(
    fs: WebdavFileSystem, root: str
) -> None:
    fs.pipe_file("keep.txt", b"x")
    with pytest.raises(ValueError, match="root"):
        fs.rm(root, recursive=True)
    assert fs.exists("keep.txt")


def test_instances_with_different_credentials_are_never_shared(server_url: str) -> None:
    class Bearer(AuthBase):
        def __init__(self, token: str) -> None:
            self.token = token

        def __repr__(
            self,
        ) -> str:  # a repr that omits the secret, as a careful one does
            return "Bearer()"

        def __call__(self, r: Any) -> Any:
            return r

    alice = WebdavFileSystem(server_url, auth=Bearer("alice-token"))
    bob = WebdavFileSystem(server_url, auth=Bearer("bob-token"))
    assert alice is not bob
    assert bob.session.auth.token == "bob-token"  # type: ignore[union-attr]


def test_leading_slashes_in_fsspec_paths_are_the_same_paths(
    fs: WebdavFileSystem, tmp_path: Path
) -> None:
    fs.pipe_file("d/a", b"1")
    fs.pipe_file("d/sub/b", b"2")
    assert sorted(fs.ls("/d", detail=False)) == sorted(fs.ls("d", detail=False))
    assert sorted(fs.glob("/d/*")) == sorted(fs.glob("d/*")) != []
    fs.get("/d", str(tmp_path / "out"), recursive=True)
    assert (tmp_path / "out" / "a").read_bytes() == b"1"


# ---------------------------------------------------------------------------
# download_file: an interrupted claim leaves nothing behind
# ---------------------------------------------------------------------------


def test_an_interrupted_download_does_not_leave_a_claimed_empty_target(
    server_url: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "out"
    out.mkdir()
    with Session(server_url, auth=AUTH, retry=False) as session:
        session.put("a.txt", b"x")

        def interrupted(_self: Path, _target: object) -> None:
            raise KeyboardInterrupt

        monkeypatch.setattr(Path, "replace", interrupted)
        with pytest.raises(KeyboardInterrupt):
            session.download_file("a.txt", out / "a.txt")
        monkeypatch.undo()
        assert list(out.iterdir()) == []
        session.download_file("a.txt", out / "a.txt")  # and a retry just works
        assert (out / "a.txt").read_bytes() == b"x"


# ---------------------------------------------------------------------------
# upload_fileobj: the body is exactly as long as it was declared to be
# ---------------------------------------------------------------------------


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
    with scripted_server(always(OK)) as (url, rec):
        with pytest.raises(ClientError, match="longer"):
            Session(retry=False).upload_fileobj(
                cast("BinaryIO", _Liar(100, 5000)),
                f"{url}/f",
                overwrite=True,
                size=100,
                chunk_size=64,
            )
    assert len(rec.requests) <= 1  # no surplus bytes parsed as a second request


@pytest.mark.parametrize("size", [3, 10])
def test_a_body_that_does_not_match_its_declared_size_is_refused(size: int) -> None:
    with scripted_server(always(OK)) as (url, _rec):
        with pytest.raises(ClientError, match="declared"):
            Session(retry=False, timeout=5).upload_fileobj(
                io.BytesIO(b"abcdef" if size == 3 else b"abc"),
                f"{url}/f",
                overwrite=True,
                size=size,
            )


def test_a_file_that_shrinks_during_upload_is_an_error_not_a_hang() -> None:
    import time

    with scripted_server(always(OK)) as (url, _rec):
        started = time.monotonic()
        with pytest.raises((ClientError, requests.RequestException)):
            Session(retry=False, timeout=5).upload_fileobj(
                cast("BinaryIO", _Liar(1000, 10)),
                f"{url}/f",
                overwrite=True,
                size=1000,
                chunk_size=64,
            )
        assert time.monotonic() - started < 4


# ---------------------------------------------------------------------------
# open("r") text mode: the server does not pick the codec
# ---------------------------------------------------------------------------


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

    with scripted_server(respond) as (url, _rec):
        with Session(retry=False).open(f"{url}/f") as fobj:
            assert fobj.read() == "héllo"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_a_closed_pipe_ends_the_cli_quietly(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    from webdav import cli

    def broken(_args: object) -> None:
        raise BrokenPipeError

    monkeypatch.setattr(cli, "_cmd_ls", broken)
    assert cli.main(["ls", "http://h.example/x"]) == 0
    assert "Broken pipe" not in capsys.readouterr().err
    assert os.fstat(1)  # stdout was redirected, not closed
