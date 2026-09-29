<h1 align="center">webdav-rfc4918</h1>

<p align="center">
  <strong>WebDAV with the API you already know from <code>requests</code>.</strong><br>
  RFC 4918 compliant, secure by default - with an fsspec filesystem and a <code>dav</code> command.
</p>

<p align="center">
  <a href="https://pypi.org/project/webdav-rfc4918"><img src="https://img.shields.io/pypi/v/webdav-rfc4918" alt="PyPI"></a>
  <a href="https://pypi.org/project/webdav-rfc4918"><img src="https://img.shields.io/pypi/pyversions/webdav-rfc4918" alt="Python versions"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/manfred-kaiser/webdav-rfc4918" alt="License"></a>
  <a href="https://github.com/psf/black"><img src="https://img.shields.io/badge/code%20style-black-000000.svg" alt="Code style: black"></a>
  <a href="https://github.com/manfred-kaiser/webdav-rfc4918/issues"><img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs Welcome"></a>
</p>

---

`webdav-rfc4918` is a WebDAV client ([RFC 4918](https://www.rfc-editor.org/rfc/rfc4918)) built *on* [`requests`](https://requests.readthedocs.io/), not next to it: `webdav.Session` **is** a `requests.Session`, `webdav.get(url)` works like `requests.get(url)`, and everything you know - `auth=`, `verify=`, adapters, hooks - keeps working. On top of that it speaks the WebDAV vocabulary (`propfind`, `mkcol`, `copy`, `move`, `lock`, ...) and adds a file-system layer (`ls`, `open`, `walk`, `upload_file`, ...).

- **One API, two ways to call it**: module-level functions for a single request, a `Session` for several - same names, same arguments, same return values (a test compares the signatures)
- **Secure by default**: a malicious server is the attacker this library is written against - TLS verification cannot be switched off, redirects never carry your credentials to another origin, responses are bounded in size and time ([details below](#security))
- **RFC 4918 to the letter**: multistatus parsing, `Depth`, `Overwrite`, class 2 locking with `If` headers, conditional writes, extended MKCOL
- **Consistent return types**: the verbs return a `Response`, the file-system operations return plain values and raise a `WebDAVError` - no call changes its result type depending on its arguments


## Quick Start

```sh
pip install webdav-rfc4918
```

```python
import webdav

auth = ("username", "password")

# One-off calls, like requests.get()
response = webdav.get("https://webdav.example.org/a.txt", auth=auth)
response = webdav.propfind("https://webdav.example.org/Photos/", depth=1, auth=auth)
response.multistatus.responses            # the parsed 207 body
webdav.mkcol("https://webdav.example.org/New/", auth=auth)

# Several calls: a Session keeps the connection open
with webdav.Session("https://webdav.example.org", auth=auth) as session:
    session.put("/a.txt", data=b"hello")
    session.exists("Documents/Readme.md")
    session.ls("Photos")                   # a list of Resource objects
    session.upload_file("Gorilla.jpg", "Photos/Gorilla.jpg")
    session.download_file("Photos/Gorilla.jpg", "copy.jpg")
```


## Verbs and file-system operations

Two kinds of names, one rule each:

| | Names | Returns | On an error status |
|---|---|---|---|
| **Verbs** | `get` `put` `delete` `head` `options` `propfind` `proppatch` `mkcol` `copy` `move` `lock` `unlock` `request` | a `webdav.Response` (a `requests.Response`) | nothing is raised, like `requests` - call `raise_for_status()` or pass `raise_on_error=True` |
| **File-system operations** | `ls` `info` `exists` `isdir` `isfile` `get_props` `set_props` `mkdir` `remove` `open` `walk` `upload_file` `download_file` `locked` ... | plain values | a `WebDAVError` is raised (also an `HTTPError`, where a status caused it) |

`ls` returns a list of `Resource` objects and `info` returns one. A `Resource` **is** its name (a `str`), so it can be handed to any other method unchanged, and it carries what the server reported:

```python
for entry in session.ls("Photos"):
    print(entry, entry.is_dir, entry.size, entry.modified)
```

More of the same vocabulary:

```python
for path, dirs, files in session.walk("Photos"):        # like os.walk: one Depth: 1 request per collection;
    dirs[:] = [d for d in dirs if d != "Photos/tmp"]    # the members are the Resources ls() returns

with session.open("notes.txt", "w") as f:               # uploaded when the block ends cleanly
    f.write("hello")

session.put("/a.txt", data=b"new", if_match=etag)       # only replace what you last saw
session.put("/b.txt", data=b"x", overwrite=False)       # only create (If-None-Match: *)
session.copy("/a.txt", "/c.txt", overwrite=True)        # copy and replace (the default is Overwrite: F)
```

Paths are plain names, percent-encoded for you exactly once: `session.put("100%.txt", ...)` writes a file called `100%.txt`. A full URL (`https://...`) is used as written; a query goes in `params=`, not in the path. Secondary arguments are keyword-only, and the ones that matter for safety are required (`propfind(url, depth=1)`).


## Locking

Class 2 locking (RFC 4918 §7) with the `If` header handled for you:

```python
with session.locked("Documents/report.docx") as lock:
    # writes through this session to the locked path (or, for a locked
    # collection, to its members) carry the lock token automatically
    session.upload_file("report.docx", "Documents/report.docx", overwrite=True)
    session.refresh_lock("Documents/report.docx", lock.token, lock_timeout=300)
# released on exit, even if the block raised
```


## Security

A WebDAV server - or a redirect to one - can be hostile. The defaults assume so:

- **TLS verification cannot be disabled.** `verify=False` (and `None`, `0`, `""`) is refused - in the constructor, per call and as `session.verify`. There is no opt-out: use a CA file for a private CA. `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` and `~/.netrc` are ignored - credentials are only the ones you pass.
- **Redirects are yours to allow.** Only same-origin redirects are followed by default (`RedirectPolicy.SAME_ORIGIN`). A hop to another origin never carries credentials, cookies, session headers, a client certificate or a lock token; `https` → `http` is never followed. `NEVER`, `WHITELIST` and `ALL` are there when you need them - see [Redirects](docs/reference/redirects.md).
- **Bounded responses.** `max_response_size` (64 MiB after decompression; stacked content-codings are refused), `max_response_time` (a 300 s deadline for the whole request, headers included), 200 000 `<response>` elements per multistatus, limits on `walk`. All can be tightened. A streamed download is bounded per read, not in size.
- **Safe defaults.** `copy`/`move` do not overwrite unless told to, `download_file` writes a temporary file and moves it into place when complete (never through a symlink), writes are never retried, credentials in a URL (`https://user:pw@host/`) are refused.
- **Credentials do not leak** into exception messages, warnings or logs.

A pickled `Session` (and an fsspec filesystem's `to_json()`) contains its credentials in clear text: do not store or send one anywhere untrusted. See [SECURITY.md](SECURITY.md) for how to report a vulnerability, and the [CHANGELOG](CHANGELOG.md) for the full list of decisions.

```python
from webdav import RedirectPolicy, Session

# Trust a signed-upload gateway - your credentials still go only to your own origin.
session = Session(
    "https://webdav.example.org",
    redirect_policy=RedirectPolicy.WHITELIST,
    trusted_redirect_origins=["https://storage.example.com"],
)

# mTLS with a private CA
session = Session(
    "https://webdav.example.org",
    cert=("client.crt", "client.key"),
    verify="ca-bundle.pem",
)
```

Encrypted private keys, CRL checking and cipher/TLS-version restriction are configured with `TLSOptions` - see [TLS](docs/reference/tls.md).


## fsspec

```sh
pip install webdav-rfc4918[fsspec]
```

```python
from webdav.fsspec import WebdavFileSystem

fs = WebdavFileSystem("https://webdav.example.org", auth=("username", "password"))
fs.exists("Documents/Readme.md")
fs.ls("Photos", detail=False)
```

pandas, dask & co. can then read and write a WebDAV server without knowing anything WebDAV-specific.


## Command line

The `dav` command is part of the package:

```sh
dav ls webdav://webdav.example.org/Photos
dav get webdav://webdav.example.org/report.pdf ./report.pdf
dav put ./report.pdf webdav://webdav.example.org/report.pdf
```

Also `info`, `cat`, `mkdir`, `rm`, `mv` and `cp`. Authentication is `--user` and `--password` (or `$WEBDAV_USER` / `$WEBDAV_PASSWORD`), and the connection options - mTLS, redirect policy, size limits - have flags too. See the [CLI reference](docs/reference/cli.md), or `dav <command> --help`.


## Documentation

[Session and module-level API](docs/reference/session.md) · [Locking](docs/reference/locking.md) · [Redirects](docs/reference/redirects.md) · [TLS](docs/reference/tls.md) · [fsspec](docs/reference/fsspec.md) · [CLI](docs/reference/cli.md)

Build the docs yourself with `hatch run docs:build`.


## Development

```sh
hatch run lint:check
hatch run hatch-test:run
```

See [CHANGELOG.md](CHANGELOG.md) for the release history. Licensed under the [MIT License](LICENSE).
