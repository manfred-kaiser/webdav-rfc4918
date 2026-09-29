"""End-to-end tests for the `dav` CLI, against a real WebDAV server."""

from pathlib import Path

import pytest

from webdav import cli


def _url(server_url: str, path: str) -> str:
    return f"webdav://user1:password1@{server_url.removeprefix('http://')}/{path}"


def test_put_ls_cat_rm_roundtrip(
    server_url: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    local = tmp_path / "local.txt"
    local.write_text("hello cli")

    assert cli.main(["put", str(local), _url(server_url, "a.txt")]) == 0
    assert cli.main(["ls", _url(server_url, "")]) == 0
    assert "a.txt" in capsys.readouterr().out

    assert cli.main(["cat", _url(server_url, "a.txt")]) == 0
    assert capsys.readouterr().out == "hello cli"

    assert cli.main(["rm", _url(server_url, "a.txt")]) == 0
    assert cli.main(["info", _url(server_url, "a.txt")]) == 1
    assert "could not be found" in capsys.readouterr().err


def test_mv_cross_server_is_rejected(
    server_url: str, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = cli.main(["mv", _url(server_url, "a.txt"), "webdav://other-host/b.txt"])
    assert exit_code == 1
    assert "same server" in capsys.readouterr().err
