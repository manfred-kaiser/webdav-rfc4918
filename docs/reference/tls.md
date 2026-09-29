# TLS and mTLS

The common case - a client certificate with an unencrypted private key,
verified against the system trust store or a custom CA bundle - works
with `requests`' own, well-known attributes:

```python
client = Client(
    "https://webdav.example.org",
    cert=("client.crt", "client.key"),
    verify="ca-bundle.pem",
)
```

Server certificate verification is always on: there is no parameter to
disable it. Use `verify=<path to a CA bundle>` for a private CA instead.

## Encrypted keys, CRL checking, cipher restriction

Plain `requests` cannot express a password-protected private key, CRL
checking, or explicit cipher restriction. Pass `tls=TLSOptions(...)` for
these - it builds a hardened `ssl.SSLContext` (TLS 1.2 floor, TLS
compression disabled) instead:

```python
from webdav import Client
from webdav.tls import TLSOptions

client = Client(
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
