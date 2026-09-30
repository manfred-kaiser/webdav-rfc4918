# TLS and mTLS

The common case - a client certificate with an unencrypted private key,
verified against the system trust store or a custom CA bundle - works
with `requests`' own, well-known attributes:

```python
session = Session(
    "https://webdav.example.org",
    cert=("client.crt", "client.key"),
    verify="ca-bundle.pem",
)
```

Server certificate verification is on by default - the constructor, a
single call and `session.verify` all accept `False` (like `None`, `0` and
`""`, which `requests` reads the same way), but every use raises and logs
a `TLSHardeningDisabledWarning`, loud and independent of `urllib3`'s own
warning category (a plain `urllib3.disable_warnings()` cannot silence it).
Prefer `verify=<path to a CA bundle>` for a private CA or a test setup -
that keeps verification on.

`REQUESTS_CA_BUNDLE`/`CURL_CA_BUNDLE` from the environment are ignored (they
would replace the CA you configured), and so is `~/.netrc`.

## Encrypted keys, CRL checking, cipher restriction

Plain `requests` cannot express a password-protected private key, CRL
checking, or explicit cipher restriction. Pass `tls=TLSOptions(...)` for
these - it builds a hardened `ssl.SSLContext` (TLS 1.2 floor, TLS
compression disabled) instead:

```python
from webdav import Session
from webdav.transport.tls import TLSOptions

session = Session(
    "https://webdav.example.org",
    cert=("client.crt", "client.key"),
    tls=TLSOptions(key_password="secret"),
)
```

```{eval-rst}
.. autoclass:: webdav.transport.tls.TLSOptions
   :members:

.. autofunction:: webdav.transport.tls.build_ssl_context
```
