"""``insecure_transport`` is an ``InsecureTransport``; the refusal cites RFC 4918 section 20.1 for Basic."""

# ruff: noqa: SIM117, PLC0415, S105, S108, S301, PT031, EM101

import base64
import contextlib
import copy
import logging
import pickle
import warnings
from typing import Any

import pytest
import requests
from requests.auth import HTTPBasicAuth

from tests import previous_release_pickles as old
from tests.scripted_server import OK, always, scripted_server
from webdav import (
    BasicAuth,
    ClientError,
    FileSystem,
    InsecureTransport,
    Session,
    exceptions,
)
from webdav.exceptions import InsecureTransportWarning

REMOTE = "http://192.0.2.1:9/x"  # TEST-NET: never answers; the decision comes before a connection


QUICK: dict[str, Any] = {"retry": False, "timeout": (0.05, 0.05)}


def test_the_members_are_strings() -> None:
    assert InsecureTransport.ERROR == "error"
    assert InsecureTransport("warn") is InsecureTransport.WARN
    assert [mode.value for mode in InsecureTransport] == ["error", "warn", "allow"]


def test_the_default_is_error_and_a_string_is_turned_into_the_member() -> None:
    assert Session().insecure_transport is InsecureTransport.ERROR
    assert (
        Session(insecure_transport="warn").insecure_transport is InsecureTransport.WARN
    )
    assert (
        Session(insecure_transport=InsecureTransport.ALLOW).insecure_transport
        is InsecureTransport.ALLOW
    )
    session = Session()
    session.insecure_transport = "allow"
    assert session.insecure_transport is InsecureTransport.ALLOW


@pytest.mark.parametrize("value", ["WARN", "yes", "", None, True, 1, b"warn"])
def test_anything_else_is_a_value_error(value: object) -> None:
    with pytest.raises(ValueError, match="insecure_transport must be"):
        Session(insecure_transport=value)  # type: ignore[arg-type]


def test_the_mode_survives_a_pickle_and_a_copy() -> None:
    session = Session(insecure_transport=InsecureTransport.WARN)
    assert (
        pickle.loads(pickle.dumps(session)).insecure_transport is InsecureTransport.WARN
    )
    assert copy.copy(session).insecure_transport is InsecureTransport.WARN


@pytest.mark.parametrize(
    "auth",
    [("user", "secret"), HTTPBasicAuth("user", "secret"), BasicAuth("user", "secret")],
)
def test_the_refusal_of_basic_cites_the_rfc(auth: object) -> None:
    with pytest.raises(ClientError) as caught:
        Session(auth=auth, **QUICK).get(REMOTE)  # type: ignore[arg-type]
    text = str(caught.value)
    assert "RFC 4918 section 20.1" in text
    assert (
        "Basic authentication MUST NOT be used unless the connection is secure" in text
    )
    assert "InsecureTransport.WARN" in text
    assert "--allow-insecure" in text
    assert "secret" not in text


def test_an_authorization_basic_header_counts_as_basic() -> None:
    with pytest.raises(ClientError, match="RFC 4918 section 20.1"):
        Session(**QUICK).get(REMOTE, headers={"Authorization": "Basic dXNlcjpwdw=="})


@pytest.mark.parametrize(
    "headers", [{"Authorization": "Bearer token"}, {"Cookie": "sid=1"}]
)
def test_the_refusal_of_other_credentials_does_not_claim_the_rfc_forbids_them(
    headers: dict[str, str],
) -> None:
    with pytest.raises(ClientError) as caught:
        Session(**QUICK).get(REMOTE, headers=headers)
    assert "RFC 4918" not in str(caught.value)
    assert "anyone on the network path can read them" in str(caught.value)


@pytest.mark.parametrize("mode", ["warn", InsecureTransport.WARN])
def test_the_warning_for_basic_cites_the_rfc(mode: object) -> None:
    session = Session(auth=("user", "secret"), insecure_transport=mode, **QUICK)  # type: ignore[arg-type]
    with pytest.warns(InsecureTransportWarning, match="RFC 4918 section 20.1"):
        with pytest.raises(Exception, match=r"192\.0\.2\.1"):
            session.get(REMOTE)


def test_the_insecure_transport_warning_names_no_password_and_sees_url_credentials() -> (
    None
):
    session = Session(retry=False, insecure_transport="warn")
    with pytest.warns(exceptions.InsecureTransportWarning) as caught:
        session._warn_if_insecure("http://bob:PWD2@192.0.2.1:9/x", {})
    assert "PWD2" not in str(caught[0].message)
    assert "192.0.2.1:9" in str(caught[0].message)


def test_a_cookie_header_counts_as_a_credential_for_the_warning() -> None:
    session = Session(retry=False, insecure_transport="warn")
    with pytest.warns(exceptions.InsecureTransportWarning):
        session._warn_if_insecure(
            "http://192.0.2.1/x", {"headers": {"Cookie": "sid=1"}}
        )


_REMOTE = "http://192.0.2.1:9/x"  # TEST-NET: never answers; the error must come before a connection


def test_credentials_over_plain_http_to_a_remote_host_are_refused_by_default() -> None:
    session = Session(auth=("u", "p"), retry=False, timeout=(0.05, 0.05))
    with pytest.raises(ClientError) as caught:
        session.get(_REMOTE)
    text = str(caught.value)
    assert "insecure_transport" in text
    assert '"allow"' in text
    assert '"warn"' in text
    assert "192.0.2.1:9" in text


def test_the_refusal_is_the_same_for_a_filesystem() -> None:
    client = FileSystem("http://192.0.2.1:9", auth=("u", "p"), retry=False)
    with pytest.raises(ClientError, match="insecure_transport"):
        client.ls("/")


@pytest.mark.parametrize(
    "setup",
    [
        lambda s: s.headers.update({"Authorization": "Bearer x"}),
        lambda s: s.headers.update({"Cookie": "a=b"}),
        lambda s: setattr(s, "auth", ("u", "p")),
    ],
)
def test_every_kind_of_credential_counts(setup: Any) -> None:
    session = Session(retry=False, timeout=(0.05, 0.05))
    setup(session)
    with pytest.raises(ClientError, match="insecure_transport"):
        session.get(_REMOTE)


def test_without_credentials_there_is_nothing_to_refuse() -> None:
    session = Session(retry=False, timeout=(0.05, 0.05))
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        session._warn_if_insecure(_REMOTE, {})


def test_warn_sends_with_a_warning_once_and_logs_it(
    caplog: pytest.LogCaptureFixture,
) -> None:
    session = Session(
        auth=("u", "p"), retry=False, timeout=(0.05, 0.05), insecure_transport="warn"
    )
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        with caplog.at_level(logging.WARNING, logger="webdav"):
            for _ in range(2):
                with contextlib.suppress(requests.RequestException):
                    session.get(_REMOTE)
    assert [w.category for w in caught] == [exceptions.InsecureTransportWarning]
    assert "plain http" in caplog.text


def test_allow_is_silent() -> None:
    session = Session(
        auth=("u", "p"), retry=False, timeout=(0.05, 0.05), insecure_transport="allow"
    )
    with warnings.catch_warnings():
        warnings.simplefilter("error", exceptions.InsecureTransportWarning)
        with contextlib.suppress(requests.RequestException):
            session.get(_REMOTE)


def test_a_pickle_of_the_previous_release_gets_the_default_mode() -> None:
    session = pickle.loads(base64.b64decode("".join(old.PLAIN)))
    assert session.insecure_transport == "error"


def test_the_mode_is_validated_and_can_be_changed() -> None:
    with pytest.raises(ValueError, match="insecure_transport"):
        Session(insecure_transport="yes")
    session = Session()
    assert session.insecure_transport == "error"
    session.insecure_transport = "warn"
    assert pickle.loads(pickle.dumps(session)).insecure_transport == "warn"


def test_loopback_http_with_credentials_is_untouched() -> None:
    with scripted_server(always(OK)) as (url, rec):
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            Session(url, auth=("u", "p"), retry=False).get("/x")
    assert len(rec.requests) == 1


def test_loopback_does_not_count_when_a_proxy_would_carry_it() -> None:
    session = Session(auth=("u", "p"), retry=False, timeout=(0.05, 0.05))
    session.proxies = {"http": "http://127.0.0.1:9"}
    with pytest.raises(ClientError, match="insecure_transport"):
        session.get("http://127.0.0.1:12345/x")


def test_loopback_does_not_count_for_an_environment_proxy_either(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:9")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    with pytest.raises(ClientError, match="insecure_transport"):
        Session(auth=("u", "p"), retry=False, timeout=(0.05, 0.05)).get(
            "http://localhost:12345/x"
        )
    # trust_env=False: no proxy, so loopback is loopback again
    with scripted_server(always(OK)) as (url, _rec):
        Session(auth=("u", "p"), retry=False, trust_env=False).get(f"{url}/x")


def test_the_cli_flag_allows_what_the_default_refuses(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from webdav import cli

    args = ["ls", "http://u:p@192.0.2.1:9/", "--timeout", "0.05", "--no-retry"]
    assert cli.main(args) == 1
    assert "refusing to send credentials" in capsys.readouterr().err
    assert cli.main([*args, "--allow-insecure"]) == 1
    assert "refusing to send credentials" not in capsys.readouterr().err
