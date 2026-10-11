"""TLS state, redirect chains, credentials and origins: what the hardening of ``Session`` has to keep true.

Most tests here failed against the code before the hardening; the ones that
only pin what has to stay as it was say so in their names.
"""

# ruff: noqa: SIM117, PLC0415, S301, PT031, EM101
# (Nested servers in one ``with``, lazy imports and made-up secrets are the point of these tests.)

import base64
import contextlib
import copy
import logging
import pickle
import ssl
import threading
import traceback
import warnings
from collections.abc import Iterator
from http.server import HTTPServer
from pathlib import Path
from typing import Any

import pytest
import requests

from tests import previous_release_pickles as old
from tests.certificates import Certificates
from tests.scripted_server import (
    OK,
    Recorder,
    _make_handler,
    always,
    redirect,
    scripted_server,
)
from webdav import FileSystem, RedirectPolicy, Session, exceptions
from webdav.exceptions import ClientError, TLSConfigError
from webdav.transport.tls import TLSOptions

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def certs(tmp_path_factory: pytest.TempPathFactory) -> Certificates:
    return Certificates(tmp_path_factory.mktemp("ic-certs"))


@pytest.fixture(scope="module")
def other_ca(certs: Certificates) -> str:
    """The certificate file of a CA that signed nothing the servers here present."""
    return str(certs.issue_other_ca().with_suffix(".crt"))


class _QuietServer(HTTPServer):
    def handle_error(self, request: Any, client_address: Any) -> None:
        """A client that gives up the handshake is the point of some tests, not news."""


@contextlib.contextmanager
def tls_server(
    certs: Certificates, respond: Any, *, max_version: "ssl.TLSVersion | None" = None
) -> Iterator[tuple[str, Recorder]]:
    """A scripted server speaking TLS with the certificate of ``certs`` (valid for 127.0.0.1)."""
    recorder = Recorder()
    server = _QuietServer(("127.0.0.1", 0), _make_handler(respond, recorder))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(certs.server_cert), str(certs.server_key))
    if max_version is not None:
        context.maximum_version = max_version
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"https://127.0.0.1:{server.server_address[1]}", recorder
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def _closed_port() -> int:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


# ---------------------------------------------------------------------------
# A copy or a pickle keeps what was set after construction
# ---------------------------------------------------------------------------


def test_a_clone_keeps_a_verify_that_was_set_after_construction(
    certs: Certificates, other_ca: str
) -> None:
    with tls_server(certs, always(OK)) as (url, _rec):
        with pytest.warns(exceptions.TLSHardeningDisabledWarning):
            session = Session(verify=False, retry=False)
        session.verify = other_ca  # a CA that did not sign this server
        for clone in (copy.copy(session), pickle.loads(pickle.dumps(session))):
            assert clone.verify == other_ca
            with pytest.raises(requests.exceptions.SSLError):
                clone.get(f"{url}/x")


def test_a_clone_keeps_a_cert_that_was_set_after_construction(tmp_path: Path) -> None:
    cert, key = Certificates(tmp_path).issue_client_cert("client")
    session = Session()
    session.cert = (str(cert), str(key))
    for clone in (copy.copy(session), pickle.loads(pickle.dumps(session))):
        assert clone.cert == (str(cert), str(key))


def test_a_clone_with_tls_keeps_verify_and_cert_changes_too(
    certs: Certificates, other_ca: str
) -> None:
    with tls_server(certs, always(OK)) as (url, _rec):
        session = Session(verify=str(certs.ca_cert), tls=TLSOptions(), retry=False)
        assert session.get(f"{url}/x").status_code == 204
        session.verify = other_ca
        clone = copy.copy(session)
        assert clone.verify == other_ca
        with pytest.raises(requests.exceptions.SSLError):
            clone.get(f"{url}/x")


def test_pickles_of_the_previous_release_still_load() -> None:
    plain = pickle.loads(base64.b64decode("".join(old.PLAIN)))
    assert plain.base_url == "https://dav.example.org/base/"
    assert plain.auth == ("alice", "s3cret")
    assert plain.headers["X-Test"] == "1"
    assert plain.cookies.get("sid") == "abc"
    assert plain.verify is True
    # ... and the loaded session works like a new one.
    with scripted_server(always(OK)) as (url, rec):
        clone = pickle.loads(base64.b64decode("".join(old.PLAIN)))
        clone._base_url = None  # pytest-only: point it at the local server
        clone.get(f"{url}/x")
    assert rec.requests[0].headers["authorization"].startswith("Basic ")


def test_a_tls_session_pickle_of_the_previous_release_loads() -> None:
    session = pickle.loads(base64.b64decode("".join(old.TLS)))
    assert session.verify is True
    assert session.get_adapter("https://x").verifies  # type: ignore[attr-defined]


def test_a_filesystem_pickle_of_the_previous_release_loads() -> None:
    client = pickle.loads(base64.b64decode("".join(old.FILESYSTEM)))
    assert client.session.auth == ("bob", "pw")


# ---------------------------------------------------------------------------
# Setters rebuild a hardened adapter; the getter says what is in force
# ---------------------------------------------------------------------------


def test_verify_set_later_applies_with_tls(certs: Certificates, other_ca: str) -> None:
    with tls_server(certs, always(OK)) as (url, _rec):
        with pytest.warns(exceptions.TLSHardeningDisabledWarning):
            session = Session(verify=False, tls=TLSOptions(), retry=False)
            assert session.get(f"{url}/x").status_code == 204
        session.verify = other_ca
        assert session.verify == other_ca
        with pytest.raises(requests.exceptions.SSLError):
            session.get(f"{url}/x")
        session.verify = str(certs.ca_cert)
        assert session.get(f"{url}/x").status_code == 204
        with pytest.warns(exceptions.TLSHardeningDisabledWarning):
            session.verify = False
            assert session.get(f"{url}/x").status_code == 204


def test_the_verify_getter_of_a_tls_session_is_the_real_value(
    certs: Certificates,
) -> None:
    with pytest.warns(exceptions.TLSHardeningDisabledWarning):
        assert Session(verify=False, tls=TLSOptions()).verify is False
    assert Session(tls=TLSOptions()).verify is True
    assert Session(verify=str(certs.ca_cert), tls=TLSOptions()).verify == str(
        certs.ca_cert
    )


def test_verify_false_for_one_call_does_not_switch_a_verifying_tls_session_off(
    certs: Certificates, other_ca: str, caplog: pytest.LogCaptureFixture
) -> None:
    with tls_server(certs, always(OK)) as (url, _rec):
        session = Session(verify=other_ca, tls=TLSOptions(), retry=False)
        with warnings.catch_warnings():
            warnings.simplefilter("error")  # no "verification is off" - it is not
            with caplog.at_level(logging.WARNING, logger="webdav"):
                with pytest.raises(requests.exceptions.SSLError):
                    session.get(f"{url}/x", verify=False)
    assert any("ignored" in r.message for r in caplog.records)


def test_verify_true_for_one_call_is_refused_where_the_context_does_not_verify(
    certs: Certificates,
) -> None:
    with tls_server(certs, always(OK)) as (url, rec):
        with pytest.warns(exceptions.TLSHardeningDisabledWarning):
            session = Session(verify=False, tls=TLSOptions(), retry=False)
            with pytest.raises(ClientError, match=r"session\.verify"):
                session.get(f"{url}/x", verify=True)
            with pytest.raises(ClientError, match=r"session\.verify"):
                session.get(f"{url}/x", verify=str(certs.ca_cert))
            # per call None, and False (what the session does anyway), stay as they were
            assert session.get(f"{url}/x", verify=None).status_code == 204
            assert session.get(f"{url}/x", verify=False).status_code == 204
    assert len(rec.requests) == 2


def test_a_verify_that_cannot_be_applied_leaves_the_session_as_it_was(
    certs: Certificates, tmp_path: Path
) -> None:
    with tls_server(certs, always(OK)) as (url, _rec):
        session = Session(verify=str(certs.ca_cert), tls=TLSOptions(), retry=False)
        broken = tmp_path / "not-a-ca.pem"
        broken.write_text("this is not a certificate")
        with pytest.raises(TLSConfigError):
            session.verify = str(broken)
        assert session.verify == str(certs.ca_cert)
        assert session.get(f"{url}/x").status_code == 204


def test_changing_verify_while_other_threads_send_breaks_nothing(
    certs: Certificates,
) -> None:
    errors: list[BaseException] = []
    with tls_server(certs, always(OK)) as (url, _rec):
        session = Session(
            verify=str(certs.ca_cert),
            tls=TLSOptions(),
            retry=False,
            pool_maxsize=4,
        )
        stop = threading.Event()

        def sender() -> None:
            while not stop.is_set():
                try:
                    session.get(f"{url}/x")
                except requests.exceptions.RequestException:
                    pass  # a request that met a swap may fail; it must not crash
                except BaseException as exc:  # noqa: BLE001
                    errors.append(exc)

        threads = [threading.Thread(target=sender) for _ in range(3)]
        for thread in threads:
            thread.start()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            for index in range(20):
                session.verify = str(certs.ca_cert) if index % 2 else False
        stop.set()
        for thread in threads:
            thread.join()
    assert errors == []


# ---------------------------------------------------------------------------
# verify is a bool or a path
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("verify", [None, 0, "", b"", 0.0, [], 1, object()])
def test_the_setter_refuses_what_is_no_bool_and_no_path(verify: object) -> None:
    session = Session()
    with pytest.raises(TypeError, match=r"True, False or the path"):
        session.verify = verify  # type: ignore[assignment]
    assert session.verify is True


def test_a_path_object_is_a_ca_bundle_without_and_with_tls(
    certs: Certificates, other_ca: str
) -> None:
    ca = certs.ca_cert
    with tls_server(certs, always(OK)) as (url, _rec):
        for tls in (None, TLSOptions()):
            session = Session(verify=ca, tls=tls, retry=False)
            assert session.get(f"{url}/x").status_code == 204
            assert session.verify == str(ca)
            # the private CA is the pin: it does not fall back to the system store
            wrong = Session(verify=Path(other_ca), tls=tls, retry=False)
            with pytest.raises(requests.exceptions.SSLError):
                wrong.get(f"{url}/x")


def test_a_falsy_verify_in_an_old_pickle_stays_what_it_meant() -> None:
    """The pickled session ran unverified (loudly); loading it must not turn that into an error or into verification."""
    with pytest.warns(exceptions.TLSHardeningDisabledWarning):
        session = pickle.loads(base64.b64decode("".join(old.FALSY_VERIFY)))
    assert session.verify is False


def test_a_refused_verify_leaves_the_session_as_it_was(certs: Certificates) -> None:
    with tls_server(certs, always(OK)) as (url, _rec):
        session = Session(verify=str(certs.ca_cert), tls=TLSOptions(), retry=False)
        with pytest.raises(TypeError):
            session.verify = ""  # type: ignore[assignment]
        assert session.verify == str(certs.ca_cert)
        assert session.get(f"{url}/x").status_code == 204


def test_verify_none_for_one_call_means_the_sessions_own() -> None:
    with scripted_server(always(OK)) as (url, rec):
        Session(retry=False).get(f"{url}/x", verify=None)
    assert len(rec.requests) == 1


# ---------------------------------------------------------------------------
# The query of a signed URL is not in a transport error
# ---------------------------------------------------------------------------

_SIGNATURE = "SECRETSIG-0123"


def _whole(exc: BaseException) -> str:
    return "".join(traceback.format_exception(exc)) + repr(exc.args)


def test_a_connection_error_after_a_redirect_does_not_show_the_signed_query() -> None:
    target = f"http://127.0.0.1:{_closed_port()}/dl/file?X-Amz-Signature={_SIGNATURE}&token=TOK"
    with scripted_server(lambda _r: redirect(302, target)) as (url, _rec):
        session = Session(redirect_policy=RedirectPolicy.ALL, retry=False)
        with pytest.raises(requests.exceptions.ConnectionError) as caught:
            session.get(f"{url}/x")
    assert _SIGNATURE not in _whole(caught.value)
    assert "TOK" not in str(caught.value)
    assert "<redacted>" in str(caught.value)


def test_a_connection_error_for_the_callers_own_query_does_not_show_it() -> None:
    url = f"http://127.0.0.1:{_closed_port()}/dl?sig={_SIGNATURE}"
    with pytest.raises(requests.exceptions.ConnectionError) as caught:
        Session(retry=False).get(url)
    assert _SIGNATURE not in _whole(caught.value)


def test_the_cause_chain_is_cleaned_in_place_not_cut() -> None:
    import urllib3.exceptions

    url = f"http://127.0.0.1:{_closed_port()}/dl?sig={_SIGNATURE}"
    with pytest.raises(requests.exceptions.ConnectionError) as caught:
        Session(retry=False).get(url)
    inner = caught.value.args[0]
    assert isinstance(inner, urllib3.exceptions.MaxRetryError)
    assert isinstance(inner.reason, urllib3.exceptions.NewConnectionError)
    assert caught.value.request is not None
    assert caught.value.__cause__ is None or isinstance(
        caught.value.__cause__, BaseException
    )


def test_a_failed_unlock_logs_no_query(caplog: pytest.LogCaptureFixture) -> None:
    client = FileSystem(retry=False)
    with caplog.at_level(logging.WARNING, logger="webdav"):
        client._unlock_quietly(
            f"http://127.0.0.1:{_closed_port()}/a?sig={_SIGNATURE}",
            "opaquelocktoken:1",
        )
    assert caplog.records
    assert _SIGNATURE not in caplog.text


# ---------------------------------------------------------------------------
# No netrc behind an auth that is falsy
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("falsy", [False, (), ""])
def test_a_falsy_auth_does_not_read_netrc(
    falsy: object, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    netrc = tmp_path / "netrc"
    netrc.write_text("machine 127.0.0.1 login netrcuser password netrcpass\n")
    netrc.chmod(0o600)
    monkeypatch.setenv("NETRC", str(netrc))
    monkeypatch.setenv("HOME", str(tmp_path))
    with scripted_server(always(OK)) as (url, rec):
        Session(retry=False).get(f"{url}/a", auth=falsy)
        Session(retry=False).propfind(f"{url}/a", depth=0, auth=falsy)
        Session(auth=falsy, retry=False).get(f"{url}/a")  # type: ignore[arg-type]
    assert len(rec.requests) == 3
    assert all("authorization" not in r.headers for r in rec.requests)


def test_a_per_call_false_auth_still_beats_the_sessions() -> None:
    with scripted_server(always(OK)) as (url, rec):
        Session(auth=("u", "p"), retry=False).get(f"{url}/a", auth=False)
        Session(auth=("u", "p"), retry=False).get(f"{url}/a")
    assert "authorization" not in rec.requests[0].headers
    assert rec.requests[1].headers["authorization"].startswith("Basic ")
