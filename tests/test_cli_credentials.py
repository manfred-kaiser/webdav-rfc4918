"""CLI credential handling: sources, precedence, secrets off the command line."""

import base64
import getpass
import io
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from webdav import cli

if TYPE_CHECKING:
    from collections.abc import Callable

from .scripted_server import Recorder, Reply, always, scripted_server

_CREATED: Reply = (201, {}, b"")


class _Tty(io.StringIO):
    """A StringIO that claims to be a terminal (or not)."""

    def __init__(self, text: str = "", *, tty: bool = False) -> None:
        super().__init__(text)
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("WEBDAV_USER", "WEBDAV_PASSWORD", "WEBDAV_KEY_PASSWORD"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def _never_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    """A test that reaches a real prompt must fail instead of hanging."""

    def refuse(prompt: str = "") -> str:
        msg = f"unexpected prompt {prompt!r}"
        raise AssertionError(msg)

    monkeypatch.setattr(getpass, "getpass", refuse)


@contextmanager
def _created_server() -> Iterator[tuple[str, Recorder]]:
    with scripted_server(always(_CREATED)) as (url, recorder):
        yield url.removeprefix("http://"), recorder


def _sent(recorder: Recorder) -> set[str | None]:
    """The decoded Basic credentials of every request (None: no Authorization)."""
    result: set[str | None] = set()
    for seen in recorder.requests:
        header = seen.headers.get("authorization")
        result.add(
            base64.b64decode(header.split()[1]).decode("utf-8") if header else None
        )
    return result


#: The recorder of the server the last ``_run`` talked to.
_last: list[Recorder] = []


def _run(
    argv: list[str], monkeypatch: pytest.MonkeyPatch, *, stdin: str = ""
) -> tuple[int, str]:
    """Run ``dav`` with ``HOST`` in ``argv`` replaced by the live server; (exit code, stderr)."""
    monkeypatch.setattr(sys, "stdin", _Tty(stdin))
    err = _Tty()
    monkeypatch.setattr(sys, "stderr", err)
    with _created_server() as (host, recorder):
        code = cli.main([a.replace("HOST", host) for a in argv])
        _last[:] = [recorder]
    return code, err.getvalue()


def _credentials() -> set[str | None]:
    return _sent(_last[0])


# --- what has always worked keeps working ---------------------------------------------


def test_the_url_user_takes_its_password_from_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``dav ls https://alice@host/`` with ``$WEBDAV_PASSWORD`` is the documented cron setup."""
    monkeypatch.setenv("WEBDAV_PASSWORD", "ENVPW")
    code, _ = _run(["mkdir", "webdav://bob@HOST/x"], monkeypatch)
    assert code == 0
    assert _credentials() == {"bob:ENVPW"}


def test_the_environment_user_and_password_apply_together(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEBDAV_USER", "alice")
    monkeypatch.setenv("WEBDAV_PASSWORD", "ENVPW")
    code, _ = _run(["mkdir", "webdav://HOST/x"], monkeypatch)
    assert code == 0
    assert _credentials() == {"alice:ENVPW"}
    code, _ = _run(["mkdir", "webdav://alice@HOST/x"], monkeypatch)
    assert code == 0
    assert _credentials() == {"alice:ENVPW"}


def test_an_exported_password_alone_does_not_break_an_anonymous_server(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``$WEBDAV_PASSWORD`` in a shell profile must not turn public servers into errors."""
    monkeypatch.setenv("WEBDAV_PASSWORD", "ENVPW")
    code, err = _run(["mkdir", "webdav://HOST/x"], monkeypatch)
    assert code == 0, err
    assert _credentials() == {None}


def test_flags_beat_the_url_and_the_url_beats_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEBDAV_PASSWORD", "ENVPW")
    code, _ = _run(["mkdir", "webdav://u:urlpw@HOST/x"], monkeypatch)
    assert code == 0
    assert _credentials() == {"u:urlpw"}
    code, _ = _run(
        ["mkdir", "webdav://u:urlpw@HOST/x", "--user", "f", "--password", "flagpw"],
        monkeypatch,
    )
    assert code == 0
    assert _credentials() == {"f:flagpw"}


@pytest.mark.parametrize(
    ("userinfo", "expected"),
    [
        ("u:a+b", "u:a+b"),  # '+' is not a space in a userinfo
        ("u:50%off", "u:50%off"),  # not a valid escape: stays literal
        ("u:p@ss", "u:p@ss"),  # urlsplit splits at the last '@'
        ("u:a:b", "u:a:b"),
        ("u:", "u:"),
    ],
)
def test_userinfo_that_was_never_encoded_is_unchanged(
    monkeypatch: pytest.MonkeyPatch, userinfo: str, expected: str
) -> None:
    code, _ = _run(["mkdir", f"webdav://{userinfo}@HOST/x"], monkeypatch)
    assert code == 0
    assert _credentials() == {expected}


# --- credentials a URL spells with percent-encoding ----------------------------------


def test_the_userinfo_of_a_url_is_percent_decoded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RFC 3986 requires ``@ : / %`` in a userinfo to be encoded; the CLI must decode them."""
    code, _ = _run(["mkdir", "webdav://al%40ice:p%40ss%3Aw%25rd@HOST/x"], monkeypatch)
    assert code == 0
    assert _credentials() == {"al@ice:p@ss:w%rd"}


def test_a_literal_percent_escape_in_a_password_is_decoded_on_purpose(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``pa%41ss`` used to be sent as typed (by accident); it is now ``paAss``.

    The way out is writing ``%25`` for the ``%``, or ``--password-stdin``.
    """
    code, _ = _run(["mkdir", "webdav://u:pa%41ss@HOST/x"], monkeypatch)
    assert code == 0
    assert _credentials() == {"u:paAss"}
    code, _ = _run(["mkdir", "webdav://u:pa%2541ss@HOST/x"], monkeypatch)
    assert code == 0
    assert _credentials() == {"u:pa%41ss"}
    code, _ = _run(
        ["mkdir", "webdav://u@HOST/x", "--password-stdin"],
        monkeypatch,
        stdin="pa%41ss\n",
    )
    assert code == 0
    assert _credentials() == {"u:pa%41ss"}


# --- a password without a user, a password for another user ---------------------------


@pytest.mark.parametrize(
    "argv",
    [
        ["mkdir", "webdav://HOST/x", "--password", "pw"],
        ["mkdir", "webdav://:pw@HOST/x"],
    ],
)
def test_an_explicit_password_without_a_user_is_an_error(
    monkeypatch: pytest.MonkeyPatch, argv: list[str]
) -> None:
    """It used to be dropped silently and the request went out anonymously."""
    code, err = _run(argv, monkeypatch)
    assert code == 1
    assert "no user name" in err
    assert not _last[0].requests


def test_the_environment_password_does_not_go_to_another_user(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEBDAV_USER", "alice")
    monkeypatch.setenv("WEBDAV_PASSWORD", "ENVPW")
    code, err = _run(["mkdir", "webdav://bob@HOST/x"], monkeypatch)
    assert code == 1
    assert "WEBDAV_PASSWORD" in err
    assert "alice" in err
    assert "--password-stdin" in err  # names the way out
    assert not _last[0].requests


def test_an_explicit_password_for_another_user_is_not_a_conflict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEBDAV_USER", "alice")
    monkeypatch.setenv("WEBDAV_PASSWORD", "ENVPW")
    code, err = _run(["mkdir", "webdav://bob:own@HOST/x"], monkeypatch)
    assert code == 0, err
    assert _credentials() == {"bob:own"}


# --- the password off the command line ------------------------------------------------


def test_password_stdin(monkeypatch: pytest.MonkeyPatch) -> None:
    code, _ = _run(
        ["mkdir", "webdav://u@HOST/x", "--password-stdin"],
        monkeypatch,
        stdin="sekret\n",
    )
    assert code == 0
    assert _credentials() == {"u:sekret"}


def test_password_stdin_removes_only_the_line_ending(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    code, _ = _run(
        ["mkdir", "webdav://u@HOST/x", "--password-stdin"],
        monkeypatch,
        stdin=" sekret \r\n",
    )
    assert code == 0
    assert _credentials() == {"u: sekret "}


def test_password_stdin_without_input_is_an_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    code, err = _run(["mkdir", "webdav://u@HOST/x", "--password-stdin"], monkeypatch)
    assert code == 1
    assert "stdin" in err
    assert not _last[0].requests


def test_an_empty_line_on_stdin_is_an_explicit_empty_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEBDAV_PASSWORD", "ENVPW")
    code, _ = _run(
        ["mkdir", "webdav://u@HOST/x", "--password-stdin"], monkeypatch, stdin="\n"
    )
    assert code == 0
    assert _credentials() == {"u:"}


@pytest.mark.parametrize("command", ["mv", "cp"])
def test_mv_and_cp_read_the_stdin_password_once(
    monkeypatch: pytest.MonkeyPatch, command: str
) -> None:
    """Both URLs are split; a second read of stdin would find EOF."""
    code, err = _run(
        [command, "webdav://u@HOST/a", "webdav://u@HOST/b", "--password-stdin"],
        monkeypatch,
        stdin="sekret\n",
    )
    assert code == 0, err
    assert _credentials() == {"u:sekret"}


@pytest.mark.parametrize("source", ["/dev/stdin", "/dev/fd/0"])
def test_password_stdin_and_an_upload_from_stdin_collide_cleanly(
    monkeypatch: pytest.MonkeyPatch, source: str
) -> None:
    code, err = _run(
        ["put", source, "webdav://u@HOST/b", "--password-stdin"],
        monkeypatch,
        stdin="sekret\n",
    )
    assert code == 1
    assert "stdin" in err
    assert not _last[0].requests


def test_password_file_needs_no_particular_permissions(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Kubernetes and Docker secrets are mounted 0644."""
    secret = tmp_path / "password"
    secret.write_text("filepw\n", encoding="utf-8")
    secret.chmod(0o644)
    code, _ = _run(
        ["mkdir", "webdav://u@HOST/x", "--password-file", str(secret)], monkeypatch
    )
    assert code == 0
    assert _credentials() == {"u:filepw"}


def test_password_file_without_a_trailing_newline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    secret = tmp_path / "password"
    secret.write_text("filepw", encoding="utf-8")
    code, _ = _run(
        [
            "mv",
            "webdav://u@HOST/a",
            "webdav://u@HOST/b",
            "--password-file",
            str(secret),
        ],
        monkeypatch,
    )
    assert code == 0
    assert _credentials() == {"u:filepw"}


def test_a_missing_password_file_is_a_clean_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    code, err = _run(
        ["mkdir", "webdav://u@HOST/x", "--password-file", str(tmp_path / "nope")],
        monkeypatch,
    )
    assert code == 1
    assert "nope" in err


def test_a_password_file_beats_the_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    secret = tmp_path / "password"
    secret.write_text("filepw", encoding="utf-8")
    monkeypatch.setenv("WEBDAV_PASSWORD", "ENVPW")
    code, _ = _run(
        ["mkdir", "webdav://u@HOST/x", "--password-file", str(secret)], monkeypatch
    )
    assert code == 0
    assert _credentials() == {"u:filepw"}


def test_the_password_sources_exclude_each_other(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "stdin", _Tty(""))
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["ls", "webdav://h/x", "--password", "a", "--password-stdin"])
    assert exc_info.value.code == 2
    assert "not allowed with" in capsys.readouterr().err


# --- the prompt: only on a terminal, only for a bare --user ---------------------------


def _prompting(
    monkeypatch: pytest.MonkeyPatch, answer: str, *, stdin_tty: bool, stderr_tty: bool
) -> list[str]:
    prompts: list[str] = []

    def ask(prompt: str = "") -> str:
        prompts.append(prompt)
        return answer

    monkeypatch.setattr(getpass, "getpass", ask)
    monkeypatch.setattr(sys, "stdin", _Tty("", tty=stdin_tty))
    monkeypatch.setattr(sys, "stderr", _Tty("", tty=stderr_tty))
    return prompts


def _main_against_server(argv: list[str]) -> tuple[int, set[str | None]]:
    with _created_server() as (host, recorder):
        code = cli.main([a.replace("HOST", host) for a in argv])
    return code, _sent(recorder)


def test_a_bare_user_on_a_terminal_is_asked_for_the_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prompts = _prompting(monkeypatch, "typed", stdin_tty=True, stderr_tty=True)
    code, sent = _main_against_server(["mkdir", "webdav://HOST/x", "--user", "alice"])
    assert code == 0
    assert sent == {"alice:typed"}
    assert prompts == ["Password for alice: "]


def test_mv_prompts_only_once(monkeypatch: pytest.MonkeyPatch) -> None:
    prompts = _prompting(monkeypatch, "typed", stdin_tty=True, stderr_tty=True)
    code, sent = _main_against_server(
        ["mv", "webdav://HOST/a", "webdav://HOST/b", "--user", "alice"]
    )
    assert code == 0
    assert sent == {"alice:typed"}
    assert len(prompts) == 1


@pytest.mark.parametrize(
    ("stdin_tty", "stderr_tty"), [(False, False), (True, False), (False, True)]
)
def test_without_a_terminal_nothing_is_asked_and_nothing_changes(
    monkeypatch: pytest.MonkeyPatch, stdin_tty: bool, stderr_tty: bool
) -> None:
    """Cron, CI and pipes keep sending ``alice:`` - they must never hang on a prompt."""
    _prompting(monkeypatch, "typed", stdin_tty=stdin_tty, stderr_tty=stderr_tty)
    code, sent = _main_against_server(["mkdir", "webdav://HOST/x", "--user", "alice"])
    assert code == 0
    assert sent == {"alice:"}


@pytest.mark.parametrize(
    "argv",
    [
        ["mkdir", "webdav://HOST/x", "--user", "alice", "--password", ""],
        ["mkdir", "webdav://alice:@HOST/x", "--user", "alice"],
        ["mkdir", "webdav://HOST/x", "--user", "alice", "--password", "given"],
    ],
)
def test_a_given_password_is_never_prompted_for(
    monkeypatch: pytest.MonkeyPatch, argv: list[str]
) -> None:
    prompts = _prompting(monkeypatch, "typed", stdin_tty=True, stderr_tty=True)
    code, _sent_credentials = _main_against_server(argv)
    assert code == 0
    assert not prompts


def test_the_environment_password_is_not_prompted_over(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prompts = _prompting(monkeypatch, "typed", stdin_tty=True, stderr_tty=True)
    monkeypatch.setenv("WEBDAV_PASSWORD", "ENVPW")
    code, sent = _main_against_server(["mkdir", "webdav://HOST/x", "--user", "alice"])
    assert code == 0
    assert sent == {"alice:ENVPW"}
    assert not prompts


def test_a_bare_url_user_is_not_prompted_for(monkeypatch: pytest.MonkeyPatch) -> None:
    """Only ``--user`` asks; ``alice@host`` behaves as before."""
    prompts = _prompting(monkeypatch, "typed", stdin_tty=True, stderr_tty=True)
    code, sent = _main_against_server(["mkdir", "webdav://alice@HOST/x"])
    assert code == 0
    assert sent == {"alice:"}
    assert not prompts


# --- the warning about a password on the command line ---------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        ["mkdir", "webdav://HOST/x", "--user", "u", "--password", "pw"],
        ["mkdir", "webdav://u:pw@HOST/x"],
    ],
)
def test_a_password_on_the_command_line_is_warned_about_on_a_terminal(
    monkeypatch: pytest.MonkeyPatch, argv: list[str]
) -> None:
    monkeypatch.setattr(sys, "stdin", _Tty(""))
    err = _Tty("", tty=True)
    monkeypatch.setattr(sys, "stderr", err)
    code, _sent_credentials = _main_against_server(argv)
    assert code == 0
    assert "visible to other local users" in err.getvalue()
    assert "--password-stdin" in err.getvalue()
    assert "pw" not in err.getvalue().replace("password", "").replace("--", "")


def test_the_warning_stays_off_a_stderr_that_is_not_a_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scripts that treat any stderr output as failure keep working."""
    code, err = _run(
        ["mkdir", "webdav://HOST/x", "--user", "u", "--password", "pw"], monkeypatch
    )
    assert code == 0
    assert err == ""


def test_no_warning_for_the_safe_sources(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    secret = tmp_path / "password"
    secret.write_text("pw", encoding="utf-8")
    monkeypatch.setattr(sys, "stdin", _Tty(""))
    err = _Tty("", tty=True)
    monkeypatch.setattr(sys, "stderr", err)
    monkeypatch.setenv("WEBDAV_PASSWORD", "ENVPW")
    code, _sent_credentials = _main_against_server(
        ["mkdir", "webdav://u@HOST/x", "--password-file", str(secret)]
    )
    assert code == 0
    assert err.getvalue() == ""


def test_the_split_url_signature_is_stable() -> None:
    """Callers (and tests) use ``_split_url(url, user=, password=)`` -> ``(base, path, auth)``."""
    split: Callable[..., tuple[str, str, tuple[str, str] | None]] = cli._split_url
    assert split("webdav://u:p@h.example:8080/a%20b", user=None, password=None) == (
        "http://h.example:8080",
        "/a b",
        ("u", "p"),
    )
