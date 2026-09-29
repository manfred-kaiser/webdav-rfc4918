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
# lock released on exit, even if the block raised
```

### mTLS

```python
client = Client(
    "https://webdav.example.org",
    cert=("client.crt", "client.key"),
    verify="ca-bundle.pem",
)
```

An encrypted private key (a password-protected `cert`), CRL checking, or
explicit cipher restriction need the extra `key_password`/`crl_files`/
`ciphers`/`ciphersuites` parameters - see `Client.__init__`.

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
```

## Development

```console
$ hatch run lint:check
$ hatch run hatch-test:run
```

See [CHANGELOG.md](CHANGELOG.md) for release history.
