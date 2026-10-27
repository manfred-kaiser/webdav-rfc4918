"""``SSL_CERT_FILE``/``SSL_CERT_DIR`` name the CA of a default session - and nothing else does."""

import subprocess  # nosec B404 -- fixed argv below, local test fixture only
from collections.abc import Iterator
from pathlib import Path

import pytest
import requests

from tests.certificates import Certificates
from tests.scripted_server import OK, always, redirect, tls_server
from webdav import Session
from webdav.exceptions import TLSHardeningDisabledWarning
from webdav.transport.tls import TLSOptions


@pytest.fixture(scope="module")
def certs(tmp_path_factory: pytest.TempPathFactory) -> Certificates:
    return Certificates(tmp_path_factory.mktemp("env-ca"))


@pytest.fixture(scope="module")
def other_certs(tmp_path_factory: pytest.TempPathFactory) -> Certificates:
    return Certificates(tmp_path_factory.mktemp("env-ca-other"))


@pytest.fixture
def server(certs: Certificates) -> Iterator[str]:
    with tls_server(certs, always(OK)) as (url, _recorder):
        yield url


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
    ):
        monkeypatch.delenv(name, raising=False)


def _ca_dir(ca_cert: Path, directory: Path) -> Path:
    """A directory OpenSSL can look a CA up in: ``<subject hash>.0``."""
    name = subprocess.run(  # noqa: S603  # nosec B603
        ["openssl", "x509", "-hash", "-noout", "-in", str(ca_cert)],  # noqa: S607  # nosec B607
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    directory.mkdir()
    (directory / f"{name}.0").write_bytes(ca_cert.read_bytes())
    return directory


def test_without_the_variables_a_private_ca_is_not_trusted(server: str) -> None:
    with pytest.raises(requests.exceptions.SSLError):
        Session(retry=False).get(f"{server}/x")


def test_ssl_cert_file_names_the_ca(
    server: str, certs: Certificates, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SSL_CERT_FILE", str(certs.ca_cert))
    assert Session(retry=False).get(f"{server}/x").status_code == 204


def test_ssl_cert_dir_names_the_ca(
    server: str, certs: Certificates, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SSL_CERT_DIR", str(_ca_dir(certs.ca_cert, tmp_path / "ca")))
    assert Session(retry=False).get(f"{server}/x").status_code == 204


def test_a_ca_named_in_the_code_wins_over_the_environment(
    server: str,
    certs: Certificates,
    other_certs: Certificates,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The right CA in the environment does not rescue the wrong one in the code."""
    monkeypatch.setenv("SSL_CERT_FILE", str(certs.ca_cert))
    session = Session(verify=str(other_certs.ca_cert), retry=False)
    with pytest.raises(requests.exceptions.SSLError):
        session.get(f"{server}/x")
    # ... and the right one in the code works with the wrong one in the environment.
    monkeypatch.setenv("SSL_CERT_FILE", str(other_certs.ca_cert))
    assert (
        Session(verify=str(certs.ca_cert), retry=False).get(f"{server}/x").status_code
        == 204
    )


def test_ca_files_of_tls_win_over_the_environment(
    server: str,
    certs: Certificates,
    other_certs: Certificates,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SSL_CERT_FILE", str(other_certs.ca_cert))
    session = Session(tls=TLSOptions(ca_files=str(certs.ca_cert)), retry=False)
    assert session.get(f"{server}/x").status_code == 204


def test_verify_false_stays_off(
    server: str, other_certs: Certificates, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SSL_CERT_FILE", str(other_certs.ca_cert))
    with pytest.warns(TLSHardeningDisabledWarning, match="verification is off"):
        session = Session(verify=False, retry=False)
    assert session.get(f"{server}/x").status_code == 204


def test_trust_env_false_ignores_the_variables(
    server: str, certs: Certificates, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SSL_CERT_FILE", str(certs.ca_cert))
    with pytest.raises(requests.exceptions.SSLError):
        Session(trust_env=False, retry=False).get(f"{server}/x")


@pytest.mark.parametrize("name", ["REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"])
def test_the_bundles_of_requests_and_curl_are_still_ignored(
    server: str, certs: Certificates, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    monkeypatch.setenv(name, str(certs.ca_cert))
    with pytest.raises(requests.exceptions.SSLError):
        Session(retry=False).get(f"{server}/x")


def test_an_empty_variable_is_the_default(
    server: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unset variable that a shell exported as ``""`` is not a path."""
    monkeypatch.setenv("SSL_CERT_FILE", "")
    with pytest.raises(requests.exceptions.SSLError):
        Session(retry=False).get(f"{server}/x")


def test_a_path_that_does_not_exist_is_an_error(
    server: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Not a quiet fall back to the bundle of ``certifi``."""
    monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "missing.pem"))
    with pytest.raises(OSError):  # noqa: PT011
        Session(retry=False).get(f"{server}/x")


def test_every_hop_and_every_method_sees_the_variable(
    certs: Certificates, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SSL_CERT_FILE", str(certs.ca_cert))
    with tls_server(
        certs, lambda seen: redirect(307, "/there") if seen.path == "/here" else OK
    ) as (url, _recorder):
        session = Session(retry=False)
        assert session.request("PROPFIND", f"{url}/here").status_code == 204
        assert session.put(f"{url}/here", data=b"x").status_code == 204
