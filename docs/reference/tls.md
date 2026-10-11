# TLS and mTLS

The common case is a client certificate with an unencrypted private key,
and a server verified against the default trust store (see
[Where the trust comes from](#where-the-trust-comes-from)) or a custom CA
bundle. That needs only the usual `requests` arguments:

```python
from webdav import Session

session = Session(
    "https://webdav.example.org",
    cert=("client.crt", "client.key"),
    verify="ca-bundle.pem",
)
```

Server certificate verification is on by default. `verify` is `True`,
`False` or the path of a CA bundle (a `str` or a path-like object), in the
constructor, on `session.verify` and on a single call. Nothing else is
accepted: `requests` reads `None`, `0` and `""` as "do not verify", so
`verify=os.environ.get("CA_BUNDLE", "")` would silently turn verification off
whenever the variable is unset. Those values raise a `TypeError` that says
`verify=False` is how to ask for it. On a single call, `verify=None` still
means "the session's own setting".

```{warning}
Every use of `verify=False` emits and logs a `TLSHardeningDisabledWarning`
(a Python warning, not an exception). It is separate from
`urllib3`'s warning category, so `urllib3.disable_warnings()` does not
silence it. For a private CA or a test setup, use
`verify=<path to a CA bundle>` instead, which keeps verification on.
```

All security defaults, TLS and otherwise, are listed in the
[README](https://github.com/manfred-kaiser/webdav-rfc4918#security).

`REQUESTS_CA_BUNDLE`/`CURL_CA_BUNDLE` from the environment are ignored (they
would replace the CA you configured), and so is `~/.netrc`. Proxies from the
environment (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`) are used, as in
`requests`; `trust_env=False` (`dav --no-proxy`) turns that off.

## Where the trust comes from

It is not "the system trust store" on every path:

| Configuration | Trusted CAs |
|---|---|
| `verify=True` (no `tls=`) | What `requests` uses: the `certifi` bundle (or your distribution's own, where it patches `certifi`) |
| `verify="ca.pem"` (no `tls=`) | Only that bundle |
| `tls=TLSOptions()` | OpenSSL's default locations: the operating system's store, **plus** whatever `SSL_CERT_FILE`/`SSL_CERT_DIR` name |
| `tls=TLSOptions(ca_files=...)` or `verify="ca.pem"` with `tls=` | Only those files (`ca_files` wins if both are given) |

`SSL_CERT_FILE`/`SSL_CERT_DIR` therefore widen the trust of a session with
`tls=` and no CA of its own, but not of one without `tls=`. A company CA in the
operating system's store works with `tls=`, and only there. Naming the CA is
the one way to a trust anchor that no environment variable can widen. A
redirect to another origin is verified against the default locations in the
`tls=` case, never against `ca_files` (see [Redirects to another
origin](#redirects-to-another-origin)).

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

With `tls=`, the `SSLContext` is the whole configuration, and the `certifi`
bundle that `requests` would add is not used. `session.verify` and
`session.cert` are part of it: setting one rebuilds the context (the new one
is built first, so a value that cannot be applied raises and leaves the old
configuration as it was), and `session.verify` returns what is in force.
`ca_files` takes precedence over a `verify=` path. A per-call `verify=`
cannot change it: `verify=False` is ignored (and logged as ignored), and
`verify=True` or a path where the session does not verify is refused with a
`ClientError`: set `session.verify` instead. A per-call `cert=` is ignored.

### Redirects to another origin

What a redirect to another origin is sent through gets the policy of how to
talk TLS: `minimum_version`, `maximum_version`, `ciphers`,
`strict_chain_checking` and whether to verify. It does not get what belongs to
your server: no `ca_files`, no `crl_files` (the storage host has no CRL from
your CA), no client certificate or key password. A target that
cannot meet the policy (a storage host that speaks TLS 1.2 where you require
1.3) makes the request fail with an `SSLError`; `RedirectPolicy.SAME_ORIGIN`
(the default) is the way not to follow it.

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
default locations of OpenSSL (see [Where the trust comes
from](#where-the-trust-comes-from)).

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

### `pin_sha256`

```python
tls = TLSOptions(ca_files="company-ca.pem", pin_sha256="3f:..:9a")  # 64 hex digits
```

The SHA-256 fingerprint of the server's certificate (DER form; colons and
case do not matter). A connection to a server with another certificate fails
with an `SSLError` that says so. It is checked on top of verification, not
instead of it, and it takes the place of the host name check: the pinned
certificate is the identity. It applies to your server only, never to another
origin a redirect leads to. A pin breaks at every renewal of the certificate:
change it together with the certificate. A single certificate in `ca_files` is
the other way to pin, and survives a renewal with the same key if the CA is
the same.

## Which limits can be turned off, and what warns

| What | Turned off by | Says so |
|---|---|---|
| Certificate verification | `verify=False` | `TLSHardeningDisabledWarning`, logged, on every request |
| TLS 1.2 floor, strict chain checking | `TLSOptions` | `TLSHardeningDisabledWarning` when the session is created |
| Weak ciphers | `TLSOptions(ciphers=...)` | `TLSHardeningDisabledWarning` when the session is created |
| Whole-exchange deadline | `max_response_time=None` | `DeadlineDisabledWarning` |
| Per-read timeout, response size cap | `timeout=None`, `max_response_size=None` | nothing: no network attacker gains from it, and large downloads need them |
| Redirect restrictions | `RedirectPolicy.ALL`, `WHITELIST` with a predicate that is always true | nothing |
| Cleartext credentials | `insecure_transport="warn"` or `"allow"` | `InsecureTransportWarning` (`"warn"`) |

There is deliberately no single switch that turns all of these into errors:
the Python warning filters (`-W error::webdav.exceptions.TLSHardeningDisabledWarning`)
do that per category. The warning for `verify=False` is repeated on purpose,
and `webdav` sets its filter to `always` for that category when it is
imported.

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
| `warn` | `True` | `False` leaves out the hardening warnings (for a second context of a configuration already warned about) |

All arguments are keyword-only. Every signature is also in the
[API reference](api.md#tls).
