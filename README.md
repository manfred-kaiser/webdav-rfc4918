<h1 align="center">webdav-rfc4918</h1>

<p align="center">
  <strong>A secure-by-default WebDAV client for Python, built on RFC 4918.</strong><br>
  Filesystem-style API, the raw protocol when you need it, a <code>dav</code> command, and TLS/mTLS support.
</p>

<p align="center">
  <a href="https://pypi.org/project/webdav-rfc4918"><img src="https://img.shields.io/pypi/v/webdav-rfc4918" alt="PyPI"></a>
  <a href="https://pypi.org/project/webdav-rfc4918"><img src="https://img.shields.io/pypi/pyversions/webdav-rfc4918" alt="Python versions"></a>
  <a href="https://github.com/manfred-kaiser/webdav-rfc4918/actions/workflows/ci.yml"><img src="https://github.com/manfred-kaiser/webdav-rfc4918/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/manfred-kaiser/webdav-rfc4918/actions/workflows/apache-compliance.yml"><img src="https://github.com/manfred-kaiser/webdav-rfc4918/actions/workflows/apache-compliance.yml/badge.svg" alt="Apache compliance"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/manfred-kaiser/webdav-rfc4918" alt="License"></a>
  <a href="https://github.com/psf/black"><img src="https://img.shields.io/badge/code%20style-black-000000.svg" alt="Code style: black"></a>
  <a href="https://github.com/manfred-kaiser/webdav-rfc4918/issues"><img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs Welcome"></a>
</p>

---

`webdav-rfc4918` implements [RFC 4918](https://www.rfc-editor.org/rfc/rfc4918) for Python. `webdav.FileSystem` gives file-system-shaped access to a server (`ls`, `open`, `walk`, `upload_file`, ...); `webdav.Session` gives protocol-level access (the WebDAV verbs, raw responses, status codes) for when you need it.

- **The whole protocol**: every WebDAV method, multistatus parsing, `Depth` and `Overwrite`, `propname`/`allprop`/`include`, extended MKCOL (RFC 5689), class 2 locking with `If` headers, conditional writes. Tested on Python 3.11 to 3.14 against a real [WsgiDAV](https://wsgidav.readthedocs.io/) server and against a real Apache `mod_dav` instance (an independent implementation, cross-checked separately - [known Apache-specific behavior](docs/apache-compliance-check.md#known-differences-from-the-rfc-text--from-wsgidav) is documented, not silently papered over), and against the oldest `requests`/`urllib3` it supports.
- **Secure by default**: a malicious server is the attacker this library is written against - TLS verification, safe redirect handling and bounded responses are all on by default, and turning any of them off is loud, never silent ([details below](#security)).
- **One filesystem API, two ways to call it**: module-level functions for a single request, `FileSystem` for several - same names, same arguments, same return values (a test compares the signatures).
- **Consistent return types**: `FileSystem` operations return plain values and raise a `WebDAVError`; `Session` verbs return a `Response` and never raise unless asked - no call changes its result type depending on its arguments.

Requires Python 3.11 or newer. It is built on [`requests`](https://requests.readthedocs.io/) and [`urllib3`](https://urllib3.readthedocs.io/).


## Quick Start

```sh
pip install webdav-rfc4918
```

```python
import webdav

auth = ("username", "password")

# One-off calls
webdav.mkdir("https://webdav.example.org/New/", auth=auth)
webdav.upload_file("Gorilla.jpg", "https://webdav.example.org/Photos/Gorilla.jpg", auth=auth)
webdav.ls("https://webdav.example.org/Photos/", auth=auth)   # a list of Resource objects

# Several calls: a FileSystem keeps the connection open
with webdav.FileSystem("https://webdav.example.org", auth=auth) as fs:
    fs.exists("Documents/Readme.md")
    fs.ls("Photos")
    fs.upload_file("Gorilla.jpg", "Photos/Gorilla.jpg")
    fs.download_file("Photos/Gorilla.jpg", "copy.jpg")

# Protocol-level control: the raw WebDAV verbs, raw responses
with webdav.Session("https://webdav.example.org", auth=auth) as session:
    response = session.propfind("/Photos/", depth=1)
    response.multistatus.responses            # the parsed 207 body
```


## `Session` and `FileSystem`

Two peer classes, one rule each - neither lives inside the other:

| | Names | Returns | On an error status |
|---|---|---|---|
| **`Session`** (verbs) | `get` `put` `delete` `head` `options` `propfind` `proppatch` `mkcol` `copy` `move` `lock` `unlock` `request` | a `webdav.Response` (a `requests.Response`) | nothing is raised, like `requests` - call `raise_for_status()`, or pass `raise_on_error=True` (per call, or to the `Session`) |
| **`FileSystem`** | `ls` `info` `exists` `isdir` `isfile` `get_props` `set_props` `mkdir` `remove` `copy` `move` `open` `walk` `upload_file` `download_file` `locked` ... | plain values | a `WebDAVError` is raised (also an `HTTPError`, where a status caused it) |

Default to `FileSystem` (or its module-level mirror) - it reads like ordinary Python filesystem code. Reach for `Session` directly only when you need the raw `Response`/status code, or there is no file-system operation for what you want - there is no module-level one-off for it, open one explicitly. Use both together, sharing one connection (and its locks), with `FileSystem.from_session(session)`; `fs.session` is the session a `FileSystem` uses.

`ls` returns a list of `Resource` objects and `info` returns one. A `Resource` **is** its name (a `str`), so it can be handed to any other method unchanged, and it carries what the server reported:

```python
for entry in fs.ls("Photos"):
    print(entry, entry.is_dir, entry.size, entry.modified)
```

More of the same vocabulary:

```python
for path, dirs, files in fs.walk("Photos"):             # like os.walk: one Depth: 1 request per collection;
    dirs[:] = [d for d in dirs if d != "Photos/tmp"]    # the members are the Resources ls() returns

with fs.open("notes.txt", "w") as f:                    # uploaded when the block ends cleanly
    f.write("hello")

session.put("/a.txt", data=b"new", if_match=etag)       # only replace what you last saw
session.put("/b.txt", data=b"x", overwrite=False)       # only create (If-None-Match: *)
fs.copy("/a.txt", "/c.txt", overwrite=True)             # copy and replace (the default is Overwrite: F)
session.propfind("/a.txt", depth=0, prop_name=True)     # the names of the properties, without values
```

Paths are plain names, percent-encoded for you exactly once: `fs.upload_file(local, "100%.txt")` writes a file called `100%.txt`. A full URL (`https://...`) is used as written; a query goes in `params=`, not in the path. Secondary arguments are keyword-only, and the ones that matter for safety are required (`propfind(url, depth=1)`).


## Errors

Everything the library raises is a `WebDAVError`, which is also a `requests.RequestException` - code that already catches `requests`' errors catches these too. An error status raises the exception for that status:

```python
try:
    fs.info("missing.txt")
except webdav.ResourceNotFoundError:          # 404
    ...
except webdav.ResourceLockedError:            # 423
    ...
except webdav.HTTPStatusError as exc:         # any other status; exc.status_code, exc.response
    ...
except webdav.WebDAVError:                    # anything else the library refuses or cannot read
    ...
```

`ResourceAlreadyExistsError` (an upload or `mkdir` that must not replace), `PreconditionFailedError` (412), `MultiStatusError` (a `207` that reports a failure for some resource), `RedirectNotFollowedError` and `MalformedResponseError` (an answer that is not what RFC 4918 promises) are there too. A wrong argument is a `ValueError` or `TypeError`, as usual.


## Configuration

`Session(...)`, `FileSystem(...)` and every one-off function take the same options, and all but `tls` and `trusted_redirect_origins` can be changed on a session afterwards. A value that cannot work is refused when it is set:

| Option | Default | |
|---|---|---|
| `auth`, `headers` | none | credentials (never put them in a URL) and default headers - sent to your own origin only |
| `verify`, `cert`, `tls` | `True`, none, none | server verification, client certificate, [`TLSOptions`](docs/reference/tls.md) |
| `timeout` | `(10, 60)` | connect and read timeout, in seconds |
| `max_response_time` | `300` | a deadline for the whole request, in seconds |
| `max_response_size` | 64 MiB | body size after decompression; `None` lifts it |
| `redirect_policy`, `trusted_redirect_origins` | `SAME_ORIGIN`, none | see [Redirects](docs/reference/redirects.md) |
| `max_redirects` | `5` | redirects in a row before a request is refused as a loop |
| `retry` | `True` | retries safe requests on 429/5xx and dropped connections; `False`, or your own |
| `chunk_size` | 4 MiB | for streamed uploads and downloads |
| `raise_on_error` | `False` | raise on an error status (`Session` verbs) |

See [Session and FileSystem](docs/reference/session.md) for all of them.


## Locking

Class 2 locking (RFC 4918 §7) with the `If` header handled for you:

```python
with webdav.Session("https://webdav.example.org", auth=auth) as session:
    fs = webdav.FileSystem.from_session(session)
    with fs.locked("Documents/report.docx", lock_timeout=300) as lock:
        # writes through this session to the locked path (or, for a locked
        # collection, to its members) carry the lock token automatically
        fs.upload_file("report.docx", "Documents/report.docx", overwrite=True)
        fs.refresh_lock("Documents/report.docx", lock.token, lock_timeout=300)
    # released on exit, even if the block raised
```

A lock times out, and nothing refreshes it for you: writes after that fail with `412`, which is how you learn the lock is gone. Locking a path that does not exist yet creates an empty resource there, as the RFC requires. At the protocol level, `session.lock(url)` records what the server granted - so the writes that follow carry its token - and `session.unlock(url, token)` releases it. See [Locking](docs/reference/locking.md).


## Security

A WebDAV server - or a redirect to one - can be hostile. The defaults assume so:

- **TLS verification is on by default, and turning it off is never quiet.** `verify=False` (and `None`, `0`, `""`) is accepted - it's your call to make, not this library's to forbid - but every use raises *and* logs a `TLSHardeningDisabledWarning`: its own warning class, not a subclass of anything `urllib3`/`requests` define, so a plain `urllib3.disable_warnings()` can't silence it as a side effect. The TLS 1.2 floor and strict certificate-chain checking (`TLSOptions`) get the same treatment. Prefer a CA file for a private CA over disabling verification. `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` and `~/.netrc` are ignored either way.
- **Redirects are yours to allow.** Only same-origin redirects are followed by default (`RedirectPolicy.SAME_ORIGIN`). A hop to another origin never carries credentials, cookies, session headers, a client certificate or a lock token; `https` → `http` is never followed, under any policy, not even for an explicitly trusted target. `NEVER`, `WHITELIST` and `ALL` are there when you need them - see [Redirects](docs/reference/redirects.md).
- **Bounded responses.** `max_response_size` (stacked content-codings are refused), `max_response_time` (headers included), `max_redirects`, a `Retry-After` waited for at most 30 s, 200 000 `<response>` elements per multistatus, limits on `walk`. All can be tightened. A streamed download is bounded per read, not in size.
- **No accidental overwrites, no accidental retries.** `copy`/`move`/uploads don't overwrite unless told to; `download_file` writes to a temporary file and moves it into place only once complete, never through a symlink; a write is never retried (a retried `mkdir` would report "exists", a retried `remove` "not found" - the opposite of what happened).
- **A mistake fails loudly.** A typo in an option (`allow_redirect=False`) is a `TypeError`, not a request that quietly does the opposite; a flag has to be a real `bool`; every limit is checked when it is set.

Credentials are never logged, never appear in exception messages, and a URL carrying them (`https://user:pw@host/`) is refused in favor of `auth=`. A `Session` can be copied and pickled (to hand it to another process, for example); a pickle contains its credentials in clear text, so do not store or send one anywhere untrusted. See [SECURITY.md](SECURITY.md) for how to report a vulnerability, and the [CHANGELOG](CHANGELOG.md) for the full list of decisions.

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


## Command line

The `dav` command is part of the package:

```sh
dav ls webdav://webdav.example.org/Photos
dav get webdav://webdav.example.org/report.pdf ./report.pdf
dav put ./report.pdf webdav://webdav.example.org/report.pdf
```

Also `info`, `cat`, `mkdir`, `rm`, `mv` and `cp`. Authentication is `--user` and `--password` (or `$WEBDAV_USER` / `$WEBDAV_PASSWORD`), and the connection options - mTLS, redirect policy, limits - have flags too. See the [CLI reference](docs/reference/cli.md), or `dav <command> --help`.


## fsspec

An optional [`fsspec`](https://filesystem-spec.readthedocs.io) filesystem, for projects (pandas, dask, ...) that want a WebDAV server behind the standard storage-backend interface instead of this library's own API:

```sh
pip install webdav-rfc4918[fsspec]
```

```python
from webdav.fsspec import WebdavFileSystem

fs = WebdavFileSystem("https://webdav.example.org", auth=auth)
fs.ls("Photos", detail=False)        # ['/Photos/Gorilla.jpg', ...]
```

Importing it registers `"webdavs"` with fsspec (not `"webdav"` - already mapped by fsspec to [`webdav4`](https://pypi.org/project/webdav4/) by default; see [fsspec](docs/reference/fsspec.md) for why). Paths start at the root of the `base_url` (`/Photos/Gorilla.jpg`), as fsspec expects of a filesystem with a root. Checked against fsspec's own conformance test suite.


## Documentation

[Session and FileSystem](docs/reference/session.md) · [Locking](docs/reference/locking.md) · [Redirects](docs/reference/redirects.md) · [TLS](docs/reference/tls.md) · [CLI](docs/reference/cli.md) · [fsspec](docs/reference/fsspec.md)

Build the docs yourself with `hatch run docs:build`.


## Development

```sh
hatch run lint:check    # formatting, linting, type checks, tests
hatch test              # the tests, against a real WsgiDAV server
```

An opt-in compliance check against Apache `mod_dav` is described in [docs/apache-compliance-check.md](docs/apache-compliance-check.md). See [CHANGELOG.md](CHANGELOG.md) for the release history. Licensed under the [MIT License](LICENSE).
