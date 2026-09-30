"""A real mTLS-enabled WebDAV server (wsgidav + cheroot) for tests.

The certificates it needs come from :mod:`tests.certificates`.
"""

import ssl
from collections.abc import Iterator
from contextlib import contextmanager

from cheroot import wsgi
from cheroot.ssl.builtin import BuiltinSSLAdapter

from tests.certificates import Certificates
from tests.server import create_wsgidav_app, get_server_address, run_server_on_thread


class _MTLSAdapter(BuiltinSSLAdapter):
    """Requires and verifies a client certificate against ``ca_cert``."""

    def __init__(self, certificate: str, private_key: str, ca_cert: str) -> None:
        """Build a server-side SSL adapter requiring client certs signed by ``ca_cert``."""
        super().__init__(certificate, private_key, certificate_chain=ca_cert)
        self.context.verify_mode = ssl.CERT_REQUIRED


@contextmanager
def mtls_webdav_server(directory: str, certs: Certificates) -> Iterator[str]:
    """Run a real WebDAV server requiring mTLS, for the duration of the block."""
    app = create_wsgidav_app(directory, require_auth=False)
    server = wsgi.Server(("127.0.0.1", 0), app)
    server.ssl_adapter = _MTLSAdapter(
        str(certs.server_cert), str(certs.server_key), str(certs.ca_cert)
    )
    with run_server_on_thread(server):
        yield get_server_address(server).replace("http://", "https://")
