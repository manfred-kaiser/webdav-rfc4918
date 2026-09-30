"""How ``cert=``/``verify=``/``tls=`` end up on a session."""

from pathlib import Path

from tests.certificates import Certificates
from webdav import Session
from webdav.transport.tls import SSLContextAdapter, TLSOptions


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
