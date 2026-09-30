"""Round 3, local side: uploads, downloads and the CLI, against what an audit found."""

# ruff: noqa: SIM117, PLC0415
import io
import os
from pathlib import Path
from typing import Any, BinaryIO, cast

import pytest
import requests

from tests.scripted_server import OK, Seen, always, scripted_server
from tests.server import AUTH
from webdav import FileSystem, Session
from webdav.exceptions import ClientError

# ---------------------------------------------------------------------------
# download_file: an interrupted claim leaves nothing behind
# ---------------------------------------------------------------------------


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
    with scripted_server(always(OK)) as (url, _rec):
        with pytest.raises(ClientError, match="declared"):
            FileSystem(retry=False, timeout=5).upload_fileobj(
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
            FileSystem(retry=False, timeout=5).upload_fileobj(
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
        with FileSystem(retry=False).open(f"{url}/f") as fobj:
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
