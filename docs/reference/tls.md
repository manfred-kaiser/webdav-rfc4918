# TLS and mTLS

The common case is a client certificate with an unencrypted private key,
and a server verified against the system trust store or a custom CA
bundle. That needs only the usual `requests` arguments:

```python
from webdav import Session

session = Session(
    "https://webdav.example.org",
    cert=("client.crt", "client.key"),
    verify="ca-bundle.pem",
)
```

Server certificate verification is on by default. The constructor, a
single call and `session.verify` all accept `False`, and also `None`, `0`
and `""`, which `requests` reads the same way.

```{warning}
Every use of `verify=False` (or anything else `requests` reads as false)
emits and logs a `TLSHardeningDisabledWarning` (a Python warning, not an
exception). It is separate from
`urllib3`'s warning category, so `urllib3.disable_warnings()` does not
silence it. For a private CA or a test setup, use
`verify=<path to a CA bundle>` instead, which keeps verification on.
```

All security defaults, TLS and otherwise, are listed in the
[README](https://github.com/manfred-kaiser/webdav-rfc4918#security).

`REQUESTS_CA_BUNDLE`/`CURL_CA_BUNDLE` from the environment are ignored (they
would replace the CA you configured), and so is `~/.netrc`.

```{warning}
All of this needs an `https://` `base_url`. Over plain `http://` there is
no TLS to verify, and `auth=` sends the username and password in clear
text with every request, see
[Session: Limits on what a server can make the client
do](session.md#limits-on-what-a-server-can-make-the-client-do).
```

## Encrypted keys, CRL checking, cipher restriction

Plain `requests` cannot express a password-protected private key, CRL
checking, or explicit cipher restriction. For these, pass
`tls=TLSOptions(...)`. It builds a hardened `ssl.SSLContext` instead (TLS
1.2 minimum, TLS compression disabled):

```python
from webdav import Session
from webdav.transport.tls import TLSOptions

session = Session(
    "https://webdav.example.org",
    cert=("client.crt", "client-encrypted.key"),
    tls=TLSOptions(key_password="secret"),
)
```

A wrong password, a missing file or an invalid cipher string raises
`TLSConfigError` when the session is created, not on the first request.

## All `TLSOptions` fields

| Field | Default | What it does |
|---|---|---|
| `key_password` | `None` | Password of an encrypted private key. Never shown by `repr`. |
| `ca_files` | `None` | CA bundle(s) to trust instead of the system trust store |
| `crl_files` | `None` | CRL file(s); turns on revocation checking of the server certificate |
| `ciphers` | `None` | OpenSSL cipher string |
| `minimum_version` | `TLSVersion.TLSv1_2` | Lowest TLS version |
| `maximum_version` | `None` | Highest TLS version (no limit) |
| `strict_chain_checking` | `True` | Rejects malformed certificates in the chain that OpenSSL's lenient default would accept |

`ca_files` and `crl_files` take one path or a list. An empty value (`[]`
or `""`) raises `TLSConfigError` instead of quietly falling back to a
weaker setup.

With `tls=`, the `SSLContext` is the whole configuration. A per-call
`verify=` or `cert=` does not change it, and the `certifi` bundle that
`requests` would add is not used.

### `key_password`

The password of the key in `cert=`, as in the example
[above](#encrypted-keys-crl-checking-cipher-restriction). Without `key_password`, an encrypted key fails with `TLSConfigError`. It
never makes OpenSSL prompt on the terminal.

### `ca_files`

```python
from webdav import Session
from webdav.transport.tls import TLSOptions

tls = TLSOptions(ca_files="company-ca.pem")
tls = TLSOptions(ca_files=["company-ca.pem", "partner-ca.pem"])
session = Session("https://webdav.example.org", tls=tls)
```

Only these CAs are trusted. Without `ca_files`, a path given as
`verify="ca-bundle.pem"` is used the same way, and without either, the
system trust store.

### `crl_files`

```python
tls = TLSOptions(ca_files="company-ca.pem", crl_files="company-ca.crl")
session = Session("https://webdav.example.org", tls=tls)
```

Checks the server certificate (not the rest of the chain) against the
CRLs. OpenSSL then needs a CRL from the CA that issued the server
certificate; without one, the handshake fails.

### `ciphers`

```python
tls = TLSOptions(ciphers="ECDHE+AESGCM")
session = Session("https://webdav.example.org", tls=tls)
```

The string goes to `SSLContext.set_ciphers` and applies to TLS 1.2 and
older. Python's `ssl` module does not restrict TLS 1.3 cipher suites this
way.

### `minimum_version` and `maximum_version`

```python
import ssl

tls = TLSOptions(minimum_version=ssl.TLSVersion.TLSv1_3)
tls = TLSOptions(maximum_version=ssl.TLSVersion.TLSv1_2)
tls = TLSOptions(minimum_version=ssl.TLSVersion.TLSv1_1)  # warns, see below
```

A `minimum_version` below TLS 1.2 is possible for a legacy server. Creating
the session with it emits and logs a `TLSHardeningDisabledWarning`.

### `strict_chain_checking`

```python
tls = TLSOptions(strict_chain_checking=False)
```

By default the chain is checked with OpenSSL's strict X.509 mode
(`ssl.VERIFY_X509_STRICT`, as in `ssl.create_default_context()`). It
refuses certificates that break the X.509 profile but that OpenSSL would
otherwise tolerate, for example a CA certificate whose Basic Constraints
extension is not marked critical. `False` accepts such chains, which some
legacy or internal CAs produce. Like a low `minimum_version`, it emits the warning when
the session is created.

## `build_ssl_context`

`build_ssl_context` returns the hardened `ssl.SSLContext` that `tls=`
uses, for code outside this library:

```python
import ssl
import urllib.request

from webdav.transport.tls import TLSOptions, build_ssl_context

context = build_ssl_context(
    certfile="client.crt",
    keyfile="client.key",   # leave out if the key is in client.crt
    options=TLSOptions(ca_files="company-ca.pem"),
)
urllib.request.urlopen("https://webdav.example.org/", context=context)
```

| Argument | Default | What it does |
|---|---|---|
| `certfile` | `None` | Client certificate (PEM) for mTLS; `None` for plain TLS |
| `keyfile` | `None` | Its private key, if not in `certfile` |
| `options` | `TLSOptions()` | The fields above |
| `verify` | `True` | `False` turns off certificate and hostname checking, with a `TLSHardeningDisabledWarning` |

All arguments are keyword-only. Every signature is also in the
[API reference](api.md#tls).
