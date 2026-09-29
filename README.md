# webdav-rfc4918

An [RFC 4918](https://www.rfc-editor.org/rfc/rfc4918) compliant WebDAV
client for Python, built on [`requests`](https://requests.readthedocs.io/),
with an optional [`fsspec`](https://filesystem-spec.readthedocs.io)
filesystem and a CLI.

## Installation

```console
$ pip install webdav-rfc4918
```

## Usage

```python
from webdav import Client

client = Client("https://webdav.example.org", auth=("username", "password"))
client.exists("Documents/Readme.md")

client.ls("Photos", detail=False)
client.upload_file("Gorilla.jpg", "Photos/Gorilla.jpg")
```

### Locking (RFC 4918 Class 2)

```python
with client.lock("Documents/report.docx") as active_lock:
    # writes made through this client to the locked path automatically
    # carry the lock token in an `If` header
    client.upload_file("report.docx", "Documents/report.docx", overwrite=True)
    client.refresh_lock("Documents/report.docx", active_lock.token, timeout=300)
# lock released on exit, even if the block raised
```

### Redirects

A WebDAV server may answer any request with a redirect - a real,
legitimate pattern (e.g. a cloud-storage gateway redirecting `PUT` to a
signed upload URL), but blindly following one is how a compromised
server could redirect a write to a different resource, or a different
host entirely, and exfiltrate the body. By default, this client only
follows a same-origin redirect automatically (`RedirectPolicy.SAME_ORIGIN`)
and refuses anything else with `RedirectNotFollowedError`:

```python
from webdav import Client, RedirectPolicy

# Trust specific additional origins, e.g. a signed-upload gateway -
# credentials are never forwarded there, only to this client's own origin.
client = Client(
    "https://webdav.example.org",
    redirect_policy=RedirectPolicy.WHITELIST,
    trusted_redirect_origins=["https://storage.example.com"],
)
```

`RedirectPolicy.NEVER` refuses every redirect; `RedirectPolicy.ALL` follows
any redirect target - only for a server you fully trust.

### mTLS

```python
client = Client(
    "https://webdav.example.org",
    cert=("client.crt", "client.key"),
    verify="ca-bundle.pem",
)
```

An encrypted private key (a password-protected `cert`), CRL checking, or
explicit cipher/TLS-version restriction need the extra `key_password`/
`crl_files`/`ciphers`/`minimum_version`/`maximum_version` parameters on
`TLSOptions` - see `Client.__init__`.

### fsspec

```console
$ pip install webdav-rfc4918[fsspec]
```

```python
from webdav.fsspec import WebdavFileSystem

fs = WebdavFileSystem("https://webdav.example.org", auth=("username", "password"))
fs.exists("Documents/Readme.md")
fs.ls("Photos", detail=False)
```

### CLI

```console
$ pip install webdav-rfc4918[cli]
$ dav ls webdav://webdav.example.org/Photos
$ dav get webdav://webdav.example.org/report.pdf ./report.pdf
```

Every `Client` constructor option has a matching flag - authentication
(`--user`/`--password`, or `$WEBDAV_USER`/`$WEBDAV_PASSWORD`), mTLS
(`--cert`/`--key`/`--ca-cert`/`--crl-cert`/`--ciphers`/`--tls-min-version`),
redirect handling (`--redirect-policy`/`--trusted-redirect-origin`), and
connection tuning (`--max-response-size`/`--chunk-size`/`--no-retry`).
Run `dav <command> --help` for the full list.

## Development

```console
$ hatch run lint:check
$ hatch run hatch-test:run
```

See [CHANGELOG.md](CHANGELOG.md) for release history.
