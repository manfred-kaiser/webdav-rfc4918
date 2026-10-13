"""How ``cert=``/``verify=``/``tls=`` end up on a session."""

# ruff: noqa: SIM117, PLC0415, S105, S108, S301, PT031, EM101

import base64
import copy
import logging
import pickle
import ssl
import threading
import warnings
from pathlib import Path
from typing import Any

import pytest
import requests

from tests import previous_release_pickles as old
from tests.certificates import Certificates
from tests.scripted_server import (
    OK,
    always,
    redirect,
    scripted_server,
    tls_server,
)
from webdav import RedirectPolicy, Session, exceptions
from webdav.exceptions import ClientError, TLSConfigError
from webdav.transport.tls import SSLContextAdapter, TLSOptions, build_ssl_context


def _adapter(session: Session) -> SSLContextAdapter:
    adapter = session.get_adapter("https://dav.example/")
    assert isinstance(adapter, SSLContextAdapter)
    return adapter


def test_tls_options_without_a_client_certificate_build_a_hardened_adapter() -> None:
    _adapter(Session(tls=TLSOptions()))


def test_a_single_pem_path_is_the_client_certificate_and_its_key(
    tmp_path: Path,
) -> None:
    cert, key = Certificates(tmp_path).issue_client_cert("client")
    combined = tmp_path / "client.pem"
    combined.write_text(cert.read_text() + key.read_text())
    _adapter(Session(cert=str(combined), tls=TLSOptions()))


def test_a_ca_bundle_given_as_verify_is_the_only_trust_anchor(tmp_path: Path) -> None:
    certs = Certificates(tmp_path)
    context = _adapter(
        Session(verify=str(certs.ca_cert), tls=TLSOptions())
    )._ssl_context
    assert context.cert_store_stats()["x509_ca"] == 1


def test_verification_can_be_named_and_left_on_without_tls_options(
    tmp_path: Path,
) -> None:
    certs = Certificates(tmp_path)
    session = Session(cert=None, verify=str(certs.ca_cert))
    assert session.verify == str(certs.ca_cert)
    assert session.cert is None


def test_the_constructor_warns_loudly_for_verify_false() -> None:
    with pytest.warns(exceptions.TLSHardeningDisabledWarning, match="verification"):
        Session(verify=False)


@pytest.mark.parametrize("verify", [None, 0, "", b"", 0.0, [], 1, object()])
def test_the_constructor_refuses_what_only_requests_reads_as_no_verification(
    verify: object,
) -> None:
    """``None``/``0``/``""`` used to switch verification off (with a warning); that is a ``TypeError`` now.

    ``verify=os.environ.get("CA_BUNDLE", "")`` must not turn TLS off by
    accident - ``verify=False`` is the way to say it on purpose.
    """
    with pytest.raises(TypeError, match=r"verify=False"):
        Session(verify=verify)  # type: ignore[arg-type]


def test_a_per_call_or_attribute_verify_false_still_sends_the_request() -> None:
    with scripted_server(always(OK)) as (url, rec):
        session = Session(retry=False)
        with pytest.warns(exceptions.TLSHardeningDisabledWarning):
            session.get(f"{url}/a", verify=False)
        session.verify = False
        with pytest.warns(exceptions.TLSHardeningDisabledWarning):
            session.get(f"{url}/a")
        with pytest.warns(exceptions.TLSHardeningDisabledWarning):
            session.propfind(f"{url}/a", depth=0)
    assert len(rec.requests) == 3


def test_disabling_verification_is_logged_too_not_only_a_python_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Not only ``warnings.warn`` - a blanket warnings filter must not erase every trace."""

    def connect_insecurely(url: str) -> None:
        Session(retry=False, verify=False).get(f"{url}/a")

    with scripted_server(always(OK)) as (url, _rec):
        with pytest.warns(exceptions.TLSHardeningDisabledWarning):
            connect_insecurely(url)
    assert any(
        "TLS hardening disabled" in r.message and "verification" in r.message
        for r in caplog.records
    )


def test_a_missing_ca_bundle_is_both_a_webdav_error_and_a_value_error(
    tmp_path: Path,
) -> None:
    with pytest.raises(ClientError) as excinfo:
        Session(verify=str(tmp_path / "nope.pem"), retry=False).get(
            "http://unused.invalid/a"
        )
    assert isinstance(excinfo.value, requests.RequestException)


def test_a_missing_ca_bundle_is_a_webdav_error_not_an_oserror(tmp_path: Path) -> None:
    session = Session(verify=str(tmp_path / "nope.pem"), retry=False)
    with pytest.raises(ClientError, match="does not exist"):
        session.get("http://unused.invalid/a")


def test_verification_false_warns_per_call_and_the_rest_is_refused() -> None:
    with scripted_server(always(OK)) as (url, rec):
        session = Session(retry=False)
        session.verify = False
        with pytest.warns(exceptions.TLSHardeningDisabledWarning):
            session.get(f"{url}/a")
        for falsy in (0, "", None):
            with pytest.raises(TypeError, match=r"verify=False"):
                session.verify = falsy  # type: ignore[assignment]
            if falsy is not None:
                with pytest.raises(TypeError, match=r"verify=False"):
                    session.get(f"{url}/a", verify=falsy)
        with pytest.warns(exceptions.TLSHardeningDisabledWarning):
            session.get(
                f"{url}/a", verify=None
            )  # per call, None is "the session's own"
        assert len(rec.requests) == 2


def test_the_environment_cannot_replace_the_configured_ca(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    other = tmp_path / "other-ca.pem"
    other.write_text("not really a ca")
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(other))
    monkeypatch.setenv("CURL_CA_BUNDLE", str(other))
    session = Session()
    settings = session.merge_environment_settings(
        "https://dav.example/", {}, None, None, None
    )
    assert settings["verify"] is True
    pinned = Session(verify="/etc/ssl/pinned.pem")
    settings = pinned.merge_environment_settings(
        "https://dav.example/", {}, None, None, None
    )
    assert settings["verify"] == "/etc/ssl/pinned.pem"


def test_a_foreign_hop_uses_its_own_adapter_and_no_client_certificate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cert, key = Certificates(tmp_path).issue_client_cert("client")
    seen: dict[str, Any] = {}
    with scripted_server(always(OK)) as (storage_url, _storage):
        with scripted_server(lambda _r: redirect(307, f"{storage_url}/t")) as (
            gateway_url,
            _g,
        ):
            session = Session(
                redirect_policy=RedirectPolicy.ALL,
                cert=(str(cert), str(key)),
                retry=False,
            )
            real = session._foreign_adapter.send

            def spy(request: Any, **kwargs: Any) -> Any:
                seen.update(kwargs)
                return real(request, **kwargs)

            monkeypatch.setattr(session._foreign_adapter, "send", spy)
            response = session.put(f"{gateway_url}/f", data=b"x")
    assert response.status_code == 204
    assert seen["cert"] is None


def test_the_key_password_is_not_in_the_repr() -> None:
    assert "TOPSECRET" not in repr(TLSOptions(key_password="TOPSECRET"))


@pytest.mark.parametrize("field", ["ca_files", "crl_files"])
@pytest.mark.parametrize("empty", [[], (), ""])
def test_an_empty_ca_or_crl_list_is_an_error_not_a_weaker_setup(
    field: str, empty: object
) -> None:
    options: dict[str, Any] = {field: empty}
    with pytest.raises(TLSConfigError, match="empty"):
        build_ssl_context(options=TLSOptions(**options))


# Lowering the floor to TLSv1 is what this test is about; CPython itself calls that
# version deprecated and says so when it is set on a context.
@pytest.mark.filterwarnings(
    "ignore:ssl.TLSVersion.TLSv1 is deprecated:DeprecationWarning"
)
def test_the_tls_floor_is_secure_by_default_but_can_be_lowered_loudly() -> None:
    context = build_ssl_context()
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
    assert context.verify_flags & ssl.VERIFY_X509_STRICT

    with pytest.warns(exceptions.TLSHardeningDisabledWarning, match="floor"):
        context = build_ssl_context(
            options=TLSOptions(minimum_version=ssl.TLSVersion.TLSv1)
        )
    assert context.minimum_version == ssl.TLSVersion.TLSv1


def test_strict_chain_checking_is_on_by_default_but_can_be_turned_off_loudly() -> None:
    context = build_ssl_context()
    assert context.verify_flags & ssl.VERIFY_X509_STRICT

    with pytest.warns(exceptions.TLSHardeningDisabledWarning, match="strict"):
        context = build_ssl_context(options=TLSOptions(strict_chain_checking=False))
    assert not context.verify_flags & ssl.VERIFY_X509_STRICT


def test_verification_is_on_by_default_but_can_be_turned_off_loudly() -> None:
    context = build_ssl_context()
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True

    with pytest.warns(exceptions.TLSHardeningDisabledWarning, match="verify"):
        context = build_ssl_context(verify=False)
    assert context.verify_mode == ssl.CERT_NONE
    assert context.check_hostname is False


def test_the_adapter_leaves_verification_to_its_context_alone() -> None:
    adapter = SSLContextAdapter(build_ssl_context())

    class Conn:
        cert_reqs = None
        ca_certs = "/certifi/cacert.pem"
        ca_cert_dir = "/somewhere"
        cert_file = "/tmp/other.pem"
        key_file = "/tmp/other.key"

    conn = Conn()
    adapter.cert_verify(conn, "https://dav.example/", False, ("/a", "/b"))
    assert conn.cert_reqs == "CERT_REQUIRED"
    assert conn.ca_certs is None
    assert conn.cert_file is None
    assert conn.key_file is None


def test_the_adapter_carries_verify_false_through_to_the_connection() -> None:
    with pytest.warns(exceptions.TLSHardeningDisabledWarning):
        adapter = SSLContextAdapter(build_ssl_context(verify=False), verify=False)

    class Conn:
        cert_reqs = None
        ca_certs = "/certifi/cacert.pem"
        ca_cert_dir = "/somewhere"
        cert_file = "/tmp/other.pem"
        key_file = "/tmp/other.key"

    conn = Conn()
    adapter.cert_verify(conn, "https://dav.example/", False, ("/a", "/b"))
    assert conn.cert_reqs == "CERT_NONE"


def test_a_pinned_ca_is_not_widened_by_the_public_ones(tmp_path: Path) -> None:
    certs = Certificates(tmp_path)
    context = build_ssl_context(options=TLSOptions(ca_files=[str(certs.ca_cert)]))
    before = len(context.get_ca_certs())
    adapter = SSLContextAdapter(context)
    adapter.cert_verify(type("C", (), {})(), "https://dav.example/", True, None)
    assert len(context.get_ca_certs()) == before == 1


def test_an_encrypted_key_without_a_password_fails_instead_of_prompting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    certs = Certificates(tmp_path)
    cert, key = certs.issue_client_cert("client")
    encrypted = certs.encrypt_key(key, "secret-pw")
    prompts: list[int] = []

    def fake_input(*_a: object) -> str:
        prompts.append(1)
        return ""

    monkeypatch.setattr("builtins.input", fake_input)
    with pytest.raises(TLSConfigError):
        build_ssl_context(certfile=cert, keyfile=encrypted, options=TLSOptions())
    assert prompts == []


def test_an_ssl_adapter_refuses_to_be_pickled() -> None:
    import pickle

    with pytest.raises(TypeError, match="cannot be pickled"):
        pickle.dumps(SSLContextAdapter(build_ssl_context()))


def test_send_checks_tls_verification_like_request_does() -> None:
    with scripted_server(always(OK)) as (url, _rec):
        session = Session(retry=False)
        prepared = session.prepare_request(requests.Request("GET", f"{url}/a"))
        with pytest.warns(exceptions.TLSHardeningDisabledWarning):
            session.send(prepared, verify=False)
        session.verify = False
        with pytest.warns(exceptions.TLSHardeningDisabledWarning):
            session.send(prepared)


@pytest.fixture(scope="module")
def certs(tmp_path_factory: pytest.TempPathFactory) -> Certificates:
    return Certificates(tmp_path_factory.mktemp("ic-certs"))


@pytest.fixture(scope="module")
def other_ca(certs: Certificates) -> str:
    """The certificate file of a CA that signed nothing the servers here present."""
    return str(certs.issue_other_ca().with_suffix(".crt"))


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


def test_a_tls_session_pickle_of_the_previous_release_loads() -> None:
    session = pickle.loads(base64.b64decode("".join(old.TLS)))
    assert session.verify is True
    assert session.get_adapter("https://x").verifies  # type: ignore[attr-defined]


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


def test_the_tls_path_reads_ssl_cert_file_and_the_plain_path_does_not(
    certs: Certificates, other_ca: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SSL_CERT_FILE", str(certs.ca_cert))
    with tls_server(certs, always(OK)) as (url, _rec):
        with pytest.raises(requests.exceptions.SSLError):
            Session(retry=False).get(f"{url}/x")
        assert Session(tls=TLSOptions(), retry=False).get(f"{url}/x").status_code == 204
        # naming the CA is what no environment variable can widen
        with pytest.raises(requests.exceptions.SSLError):
            Session(tls=TLSOptions(ca_files=other_ca), retry=False).get(f"{url}/x")
        with pytest.raises(requests.exceptions.SSLError):
            Session(verify=other_ca, tls=TLSOptions(), retry=False).get(f"{url}/x")


def test_a_redirect_target_that_cannot_meet_the_tls_policy_is_not_reached(
    certs: Certificates, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SSL_CERT_FILE", str(certs.ca_cert))  # the foreign hop's trust
    with tls_server(certs, always(OK), max_version=ssl.TLSVersion.TLSv1_2) as (
        old_url,
        old_rec,
    ):
        with tls_server(certs, lambda _r: redirect(307, f"{old_url}/t")) as (
            gateway,
            _g,
        ):
            strict = Session(
                redirect_policy=RedirectPolicy.ALL,
                tls=TLSOptions(
                    ca_files=str(certs.ca_cert),
                    minimum_version=ssl.TLSVersion.TLSv1_3,
                ),
                retry=False,
            )
            with pytest.raises(requests.exceptions.SSLError):
                strict.get(f"{gateway}/x")
            assert old_rec.requests == []
            # the same without the floor: the hop works, as it always did
            relaxed = Session(
                redirect_policy=RedirectPolicy.ALL,
                tls=TLSOptions(ca_files=str(certs.ca_cert)),
                retry=False,
            )
            assert relaxed.get(f"{gateway}/x").status_code == 204
            assert len(old_rec.requests) == 1


def test_the_foreign_context_takes_policy_and_nothing_of_the_origins_own(
    certs: Certificates,
) -> None:
    session = Session(
        tls=TLSOptions(
            ca_files=str(certs.ca_cert),
            crl_files=str(certs.ca_cert),
            ciphers="ECDHE+AESGCM",
            minimum_version=ssl.TLSVersion.TLSv1_3,
            strict_chain_checking=False,
            key_password="pw",
        )
    )
    main = session.get_adapter("https://x")._ssl_context  # type: ignore[attr-defined]
    foreign = session._foreign_adapter._ssl_context  # type: ignore[attr-defined]
    assert main.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF
    assert not foreign.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF
    assert foreign.minimum_version == ssl.TLSVersion.TLSv1_3
    assert not foreign.verify_flags & ssl.VERIFY_X509_STRICT
    assert foreign.verify_mode == ssl.CERT_REQUIRED


def test_the_foreign_adapter_follows_verify_false_and_a_changed_verify(
    certs: Certificates,
) -> None:
    with pytest.warns(exceptions.TLSHardeningDisabledWarning):
        session = Session(verify=False, tls=TLSOptions())
    adapter = session._foreign_adapter
    assert adapter.verifies is False  # type: ignore[attr-defined]
    session.verify = str(certs.ca_cert)
    assert session._foreign_adapter is adapter
    assert adapter.verifies is True  # type: ignore[attr-defined]


def test_without_tls_the_foreign_adapter_is_the_plain_one() -> None:
    from webdav.transport.deadline import DeadlineAdapter

    assert type(Session()._foreign_adapter) is DeadlineAdapter
