"""Throwaway certificates for tests, generated with the system ``openssl`` binary.

Matching this project's own convention for throwaway dev/test certs rather
than adding a ``cryptography`` dependency just for tests. Needs no server
package: tests that only *use* certificates do not need ``cheroot``/``wsgidav``.
"""

import subprocess  # nosec B404 -- fixed argv below, local test fixture only
from pathlib import Path


def _openssl(*args: str) -> None:
    argv = ["openssl", *args]  # nosec B607 -- fixed executable, not attacker-controlled
    subprocess.run(argv, check=True, capture_output=True)  # noqa: S603 # nosec B603


class Certificates:
    """A throwaway CA, server cert, and one or more client certs, for one test."""

    def __init__(self, directory: Path) -> None:
        """Generate the certificate set into ``directory``."""
        self.dir = directory
        self.ca_key = directory / "ca.key"
        self.ca_cert = directory / "ca.crt"
        self.server_key = directory / "server.key"
        self.server_cert = directory / "server.crt"

        _openssl(
            "ecparam",
            "-name",
            "prime256v1",
            "-genkey",
            "-noout",
            "-out",
            str(self.ca_key),
        )
        _openssl(
            "req",
            "-x509",
            "-new",
            "-key",
            str(self.ca_key),
            "-sha256",
            "-days",
            "1",
            "-subj",
            "/CN=Test CA",
            "-out",
            str(self.ca_cert),
            "-addext",
            "basicConstraints=critical,CA:true",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        )

        _openssl(
            "ecparam",
            "-name",
            "prime256v1",
            "-genkey",
            "-noout",
            "-out",
            str(self.server_key),
        )
        csr = directory / "server.csr"
        _openssl(
            "req",
            "-new",
            "-key",
            str(self.server_key),
            "-subj",
            "/CN=127.0.0.1",
            "-out",
            str(csr),
        )
        extfile = directory / "server.ext"
        extfile.write_text(
            "subjectAltName=IP:127.0.0.1\n"
            "basicConstraints=CA:false\n"
            "keyUsage=digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n"
        )
        _openssl(
            "x509",
            "-req",
            "-in",
            str(csr),
            "-CA",
            str(self.ca_cert),
            "-CAkey",
            str(self.ca_key),
            "-CAcreateserial",
            "-days",
            "1",
            "-out",
            str(self.server_cert),
            "-extfile",
            str(extfile),
        )

    def issue_client_cert(
        self, name: str, ca_key: "Path | None" = None
    ) -> tuple[Path, Path]:
        """Issue a client cert/key pair, signed by this CA (or a different one, for negative tests)."""
        key = self.dir / f"{name}.key"
        cert = self.dir / f"{name}.crt"
        csr = self.dir / f"{name}.csr"
        signing_ca_cert = self.ca_cert if ca_key is None else ca_key.with_suffix(".crt")
        signing_ca_key = ca_key or self.ca_key

        _openssl(
            "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key)
        )
        _openssl(
            "req", "-new", "-key", str(key), "-subj", f"/CN={name}", "-out", str(csr)
        )
        extfile = self.dir / f"{name}.ext"
        extfile.write_text(
            "basicConstraints=CA:false\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n"
        )
        _openssl(
            "x509",
            "-req",
            "-in",
            str(csr),
            "-CA",
            str(signing_ca_cert),
            "-CAkey",
            str(signing_ca_key),
            "-CAcreateserial",
            "-days",
            "1",
            "-out",
            str(cert),
            "-extfile",
            str(extfile),
        )
        return cert, key

    def encrypt_key(self, key: Path, password: str) -> Path:
        """Return a password-encrypted copy of ``key``."""
        encrypted = key.with_name(key.stem + "-encrypted.key")
        _openssl(
            "ec",
            "-in",
            str(key),
            "-out",
            str(encrypted),
            "-passout",
            f"pass:{password}",
            "-aes256",
        )
        return encrypted

    def issue_other_ca(self, name: str = "other-ca") -> Path:
        """Issue a second, unrelated CA (for a client cert the server must reject)."""
        key = self.dir / f"{name}.key"
        cert = self.dir / f"{name}.crt"
        _openssl(
            "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key)
        )
        _openssl(
            "req",
            "-x509",
            "-new",
            "-key",
            str(key),
            "-sha256",
            "-days",
            "1",
            "-subj",
            f"/CN={name}",
            "-out",
            str(cert),
            "-addext",
            "basicConstraints=critical,CA:true",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        )
        return key
