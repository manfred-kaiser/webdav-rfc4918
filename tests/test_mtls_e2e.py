"""End-to-end mTLS tests, against a real WebDAV server requiring client certs."""

from collections.abc import Iterator
from pathlib import Path

import pytest
import requests.exceptions

from tests.mtls_server import Certificates, mtls_webdav_server
from webdav import FileSystem
from webdav.exceptions import TLSConfigError
from webdav.transport.tls import TLSOptions


@pytest.fixture
def certs(tmp_path_factory: pytest.TempPathFactory) -> Certificates:
    return Certificates(tmp_path_factory.mktemp("mtls-certs"))


@pytest.fixture
def mtls_url(tmp_path: Path, certs: Certificates) -> Iterator[str]:
    with mtls_webdav_server(str(tmp_path), certs) as url:
        yield url


def test_valid_client_cert_is_accepted(mtls_url: str, certs: Certificates) -> None:
    cert, key = certs.issue_client_cert("client")
    with FileSystem(
        mtls_url, cert=(str(cert), str(key)), verify=str(certs.ca_cert)
    ) as client:
        client.mkdir("docs")
        assert client.exists("docs")


def test_encrypted_client_key_with_correct_password(
    mtls_url: str, certs: Certificates
) -> None:
    cert, key = certs.issue_client_cert("client")
    encrypted_key = certs.encrypt_key(key, "correct-horse-battery-staple")
    tls = TLSOptions(key_password="correct-horse-battery-staple")
    with FileSystem(
        mtls_url,
        cert=(str(cert), str(encrypted_key)),
        verify=str(certs.ca_cert),
        tls=tls,
    ) as client:
        client.mkdir("docs")
        assert client.exists("docs")


def test_encrypted_client_key_with_wrong_password_fails_cleanly(
    mtls_url: str, certs: Certificates
) -> None:
    cert, key = certs.issue_client_cert("client")
    encrypted_key = certs.encrypt_key(key, "correct-horse-battery-staple")
    tls = TLSOptions(key_password="wrong-password")
    with pytest.raises(TLSConfigError):
        FileSystem(
            mtls_url,
            cert=(str(cert), str(encrypted_key)),
            verify=str(certs.ca_cert),
            tls=tls,
        )


def test_certificate_from_untrusted_ca_is_rejected(
    mtls_url: str, certs: Certificates
) -> None:
    other_ca_key = certs.issue_other_ca()
    cert, key = certs.issue_client_cert("rogue", ca_key=other_ca_key)
    with (
        FileSystem(
            mtls_url, cert=(str(cert), str(key)), verify=str(certs.ca_cert)
        ) as client,
        pytest.raises(requests.exceptions.SSLError),
    ):
        client.exists("docs")


def test_missing_client_cert_is_rejected(mtls_url: str, certs: Certificates) -> None:
    with (
        FileSystem(mtls_url, verify=str(certs.ca_cert)) as client,
        pytest.raises(requests.exceptions.SSLError),
    ):
        client.exists("docs")
