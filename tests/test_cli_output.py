"""What the ``dav`` command prints and how it treats its input."""

import os

import pytest

from webdav import Session, cli
from webdav.cli import _split_url


def test_a_closed_pipe_ends_the_cli_quietly(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(_args: object) -> None:
        raise BrokenPipeError

    monkeypatch.setattr(cli, "_cmd_ls", broken)
    assert cli.main(["ls", "http://h.example/x"]) == 0
    assert "Broken pipe" not in capsys.readouterr().err
    assert os.fstat(1)  # stdout was redirected, not closed


def test_cli_urls_are_percent_decoded_and_ipv6_hosts_keep_their_brackets() -> None:
    assert (
        _split_url("webdav://h.example/Photos/a%20b.txt", user=None, password=None)[1]
        == "/Photos/a b.txt"
    )
    assert (
        _split_url("webdav://h.example/100%25.txt", user=None, password=None)[1]
        == "/100%.txt"
    )
    base, path, _auth = _split_url("webdav://[::1]:8080/x", user=None, password=None)
    assert base == "http://[::1]:8080"
    assert path == "/x"
    assert Session(base).resolve_url(path) == "http://[::1]:8080/x"


def test_cli_error_output_is_escaped(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def hostile(_args: object) -> None:
        msg = "received 500 (\x1b]0;PWNED\x07\x1b[2J)\nforged: line"
        raise cli.CLIError(msg)

    monkeypatch.setattr(cli, "_cmd_ls", hostile)
    assert cli.main(["ls", "http://h.example/x"]) == 1
    err = capsys.readouterr().err
    assert "\x1b" not in err.replace("\\x1b", "")
    assert err.count("\n") == 1  # one line, not two
    assert "\\x1b" in err
