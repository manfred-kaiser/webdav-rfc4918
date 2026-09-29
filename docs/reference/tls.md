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

Server certificate verification is always on: there is no constructor
parameter to disable it, and `Session(verify=False)` - like `None`, `0` and
`""`, which `requests` reads the same way - is refused. So is `verify=False`
on a single call, or set as `session.verify`. There is no opt-out (a
`InsecureConfigurationError` is raised): use `verify=<path to a CA bundle>`
for a private CA or a test setup instead.

`REQUESTS_CA_BUNDLE`/`CURL_CA_BUNDLE` from the environment are ignored (they
would replace the CA you configured), and so is `~/.netrc`.

## Encrypted keys, CRL checking, cipher restriction

Plain `requests` cannot express a password-protected private key, CRL
checking, or explicit cipher restriction. Pass `tls=TLSOptions(...)` for
these - it builds a hardened `ssl.SSLContext` (TLS 1.2 floor, TLS
compression disabled) instead:

```python
from webdav import Session
from webdav.tls import TLSOptions

session = Session(
    "https://webdav.example.org",
    cert=("client.crt", "client.key"),
    tls=TLSOptions(key_password="secret"),
)
```

```{eval-rst}
.. autoclass:: webdav.tls.TLSOptions
   :members:

.. autofunction:: webdav.tls.build_ssl_context
```
