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


@pytest.mark.parametrize("command", ["mv", "cp"])
def test_the_root_is_neither_moved_nor_copied(
    server_url: str, capsys: pytest.CaptureFixture[str], command: str
) -> None:
    assert cli.main([command, _url(server_url, ""), _url(server_url, "x")]) == 1
    assert "root of the session" in capsys.readouterr().err
    assert cli.main(["info", _url(server_url, "x")]) == 1
    capsys.readouterr()


def test_redirect_policy_flag_is_honored(
    server_url: str, capsys: pytest.CaptureFixture[str]
) -> None:
    for policy in ("never", "same-origin", "all"):
        assert cli.main(["ls", _url(server_url, ""), "--redirect-policy", policy]) == 0
    capsys.readouterr()


def test_whitelist_without_trusted_origin_is_a_clean_cli_error(
    server_url: str, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = cli.main(["ls", _url(server_url, ""), "--redirect-policy", "whitelist"])
    assert exit_code == 1
    assert "trusted_redirect_origins" in capsys.readouterr().err


def test_max_response_size_none_disables_the_cap(
    server_url: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["ls", _url(server_url, ""), "--max-response-size", "none"]) == 0
    capsys.readouterr()


def test_invalid_redirect_policy_is_a_clean_argparse_error(
    server_url: str, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["ls", _url(server_url, ""), "--redirect-policy", "bogus"])
    assert exc_info.value.code == 2
    assert "invalid" in capsys.readouterr().err.lower()


def test_max_response_time_and_max_redirects_are_taken(
    server_url: str, capsys: pytest.CaptureFixture[str]
) -> None:
    args = ["ls", _url(server_url, "")]
    assert cli.main([*args, "--max-response-time", "30", "--max-redirects", "0"]) == 0
    assert cli.main([*args, "--max-response-time", "none"]) == 0
    capsys.readouterr()


@pytest.mark.parametrize(
    "flags",
    [
        ["--max-response-time", "0"],
        ["--max-response-time", "inf"],
        ["--max-response-time", "soon"],
        ["--max-redirects", "-1"],
        ["--max-redirects", "many"],
        ["--timeout", "nan"],
    ],
)
def test_a_limit_that_cannot_work_is_a_clean_argparse_error(
    server_url: str, capsys: pytest.CaptureFixture[str], flags: list[str]
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["ls", _url(server_url, ""), *flags])
    assert exc_info.value.code == 2
    capsys.readouterr()
