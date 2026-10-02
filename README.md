<p align="center">
  <img src="https://raw.githubusercontent.com/manfred-kaiser/webdav-rfc4918/main/docs/_static/icon.svg" width="96" height="96" alt="webdav-rfc4918">
</p>

<h1 align="center">webdav-rfc4918</h1>

<p align="center">
  <strong>A secure-by-default WebDAV client for Python, built on RFC 4918 and RFC 5689.</strong><br>
  Filesystem-style API, the raw protocol when you need it, a <code>dav</code> command, and TLS/mTLS support.
</p>

<p align="center">
  <strong>Full documentation:</strong> <a href="https://webdav.readthedocs.io">webdav.readthedocs.io</a>
</p>

<p align="center">
  <a href="https://pypi.org/project/webdav-rfc4918"><img src="https://img.shields.io/pypi/v/webdav-rfc4918" alt="PyPI"></a>
  <a href="https://pypi.org/project/webdav-rfc4918"><img src="https://img.shields.io/pypi/pyversions/webdav-rfc4918" alt="Python versions"></a>
  <a href="https://github.com/manfred-kaiser/webdav-rfc4918/actions/workflows/ci.yml"><img src="https://github.com/manfred-kaiser/webdav-rfc4918/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/manfred-kaiser/webdav-rfc4918/actions/workflows/apache-compliance.yml"><img src="https://github.com/manfred-kaiser/webdav-rfc4918/actions/workflows/apache-compliance.yml/badge.svg" alt="Apache compliance"></a>
  <a href="https://github.com/manfred-kaiser/webdav-rfc4918/actions/workflows/nginx-compliance.yml"><img src="https://github.com/manfred-kaiser/webdav-rfc4918/actions/workflows/nginx-compliance.yml/badge.svg" alt="nginx compliance"></a>
  <a href="https://github.com/manfred-kaiser/webdav-rfc4918/actions/workflows/nextcloud-compliance.yml"><img src="https://github.com/manfred-kaiser/webdav-rfc4918/actions/workflows/nextcloud-compliance.yml/badge.svg" alt="Nextcloud compliance"></a>
  <a href="https://webdav.readthedocs.io"><img src="https://readthedocs.org/projects/webdav/badge/?version=latest" alt="Documentation Status"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/manfred-kaiser/webdav-rfc4918" alt="License"></a>
  <a href="https://github.com/psf/black"><img src="https://img.shields.io/badge/code%20style-black-000000.svg" alt="Code style: black"></a>
  <a href="https://github.com/manfred-kaiser/webdav-rfc4918/issues"><img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs Welcome"></a>
</p>

---

`webdav-rfc4918` is a WebDAV client for Python - WebDAV lets you read and
write files on a server over HTTP, like a network drive reachable by URL.
A file-system-style API, and the raw protocol underneath when you need it.

Three things to know before anything else:

- **Verified against three real servers** in CI every commit - Nextcloud,
  Apache `mod_dav`, nginx `dav-ext` - each documented separately; the rest
  runs against WsgiDAV, the no-server Python backend. See
  [Tested against real servers](#tested-against-real-servers).
- **Built to resist real attacks**, the kind file-transfer clients have
  shipped with: credential leakage via a malicious redirect, memory
  exhaustion from an oversized or malformed server response, credentials
  or arguments smuggled in a URL. See [Security](#security).
- **Works with pandas, dask, and anything else built on fsspec** - read and
  write a WebDAV server the same way those tools already read S3 or a local
  disk. See [fsspec](#fsspec).

## Quick Start

Requires Python 3.11+.

```sh
pip install webdav-rfc4918
```

A single call, nothing to open or close:

```python
import webdav

auth = ("username", "password")  # HTTP Basic auth

webdav.mkdir("https://webdav.example.org/New/", auth=auth)
webdav.upload_file("Gorilla.jpg", "https://webdav.example.org/Photos/Gorilla.jpg", auth=auth)
webdav.ls("https://webdav.example.org/Photos/", auth=auth)   # a list of Resource objects
```

Several calls to the same server: a `FileSystem` keeps the connection open.

```python
with webdav.FileSystem("https://webdav.example.org", auth=auth) as fs:
    fs.exists("Documents/Readme.md")
    fs.ls("Photos")
    fs.upload_file("Gorilla.jpg", "Photos/Gorilla.jpg")
    fs.download_file("Photos/Gorilla.jpg", "copy.jpg")  # to a file

    with fs.open("Photos/Gorilla.jpg", "rb") as f:       # or straight into memory
        image_bytes = f.read()
```

Need the raw protocol - status codes, headers, the `207` (multi-status)
body itself? Use a `Session` directly.

```python
with webdav.Session("https://webdav.example.org", auth=auth) as session:
    response = session.propfind("/Photos/", depth=1)
    response.multistatus.responses            # the parsed 207 body
```

mTLS (if your server requires a client certificate instead of just a
password), with a private CA:

```python
with webdav.Session(
    "https://webdav.example.org",
    cert=("client.crt", "client.key"),
    verify="ca-bundle.pem",
) as session:
    ...
```


## Tested against real servers

Nextcloud, Apache `mod_dav`, and nginx `dav-ext` each get their own CI job,
because each reads the RFC differently: Apache's weak `getetag`, nginx's
missing PROPPATCH and overwrite protection, Nextcloud's version-dependent
locking and strong etag - each documented separately.

| Server | Tests | Docs |
|---|---|---|
| Nextcloud | 43 | [docs](docs/nextcloud-compliance-check.md) |
| Apache `mod_dav` | 42 | [docs](docs/apache-compliance-check.md) |
| nginx + `dav-ext` | 26 | [docs](docs/nginx-compliance-check.md) |

As of 2026-10-02: Apache 2.4.58, nginx 1.24.0 on GitHub's stock runner, not
pinned; Nextcloud pinned to `35.0.1`.

The whole suite - 1404 tests - runs continuously; most of it against
WsgiDAV, the Python backend that needs no server. That includes fsspec's
own 137-test conformance suite, 134 tests checking one RFC 4918 clause
each, and 72 targeting security hardening specifically. Counted with
pytest's own test collection, not a source grep, so parametrized cases
are included. 93% code coverage, every CI run.


## Security

A WebDAV server, or a redirect to one, can be hostile. Each default below
answers a known vulnerability class:

- **TLS verification stays on for every request, deliberately re-checked,
  not just set once** - a stale, reused connection never carries a
  verification setting from an earlier, different call. Disabling it logs
  a dedicated `TLSHardeningDisabledWarning` that the usual
  `urllib3.disable_warnings()` can't silence.
- Only same-origin redirects are followed by default
  (`RedirectPolicy.SAME_ORIGIN`), so **credentials never cross an origin
  boundary** on a redirect, even to an explicitly trusted target.
- Responses, redirects, and multistatus size are all capped, **to prevent
  memory- and resource-exhaustion attacks** - XXE (malicious XML) and
  entity-bomb style payloads included. Exact limits:
  [docs/reference/session.md](docs/reference/session.md#limits-on-what-a-server-can-make-the-client-do).
- **Downloads never write outside the destination, or through a symlink**
  - the same bug class as "Zip Slip" (a crafted path overwriting a file
  outside the intended directory), generalized to any server-supplied
  name. `download_file` writes to a temporary file and moves it into
  place only once complete.

Credentials are never logged or allowed in a URL. **72 tests** specifically
target these defenses
([`tests/test_security_hardening.py`](tests/test_security_hardening.py),
[`tests/test_security_edge_cases.py`](tests/test_security_edge_cases.py)),
same CI run as everything else. Report a vulnerability:
[SECURITY.md](SECURITY.md).


## fsspec

[`fsspec`](https://filesystem-spec.readthedocs.io) is the storage-backend
interface **pandas**, **dask**, and most of the Python data ecosystem
already use for S3, GCS, local disk, and more - one API, regardless of
where the data lives. This package adds a WebDAV backend for it, so those
tools can read and write a WebDAV server the same way, without knowing
anything WebDAV-specific.

**Passes all 137 tests in fsspec's own official conformance suite.**

```sh
pip install webdav-rfc4918[fsspec]
```

```python
import fsspec
import pandas as pd

auth = ("username", "password")

fs = fsspec.filesystem("webdav", base_url="https://webdav.example.org", auth=auth)
fs.ls("Photos", detail=False)        # ['/Photos/Gorilla.jpg', ...]

with fsspec.open("webdavs://webdav.example.org/Photos/Gorilla.jpg", auth=auth) as f:
    f.read()

df = pd.read_csv("webdav:///data.csv", storage_options={
    "base_url": "https://webdav.example.org", "auth": auth,
})
```

Installing the package registers both `"webdav"` and `"webdavs"` with fsspec
through its `fsspec.specs` entry point - no import needed, explicit or
otherwise. Paths start at the root of the `base_url`
(`/Photos/Gorilla.jpg`), as fsspec expects of a filesystem with a root. See
[fsspec](docs/reference/fsspec.md) for the full picture (URL schemes,
credentials, path semantics).


## Locking

Lock a file so no one else can overwrite it while you're editing it - class
2 locking (RFC 4918 §7), with the `If` header handled for you:

```python
auth = ("username", "password")

with webdav.Session("https://webdav.example.org", auth=auth) as session:
    fs = webdav.FileSystem.from_session(session)
    with fs.locked("Documents/report.docx", lock_timeout=300) as lock:
        # writes through this session to the locked path (or, for a locked
        # collection, to its members) carry the lock token automatically
        fs.upload_file("report.docx", "Documents/report.docx", overwrite=True)
        fs.refresh_lock("Documents/report.docx", lock.token, lock_timeout=300)
    # released on exit, even if the block raised
```

A lock times out, and nothing refreshes it for you: writes after that fail
with `412`, which is how you learn the lock is gone. See
[Locking](docs/reference/locking.md) for the protocol-level calls.


## Command line

The `dav` command is part of the package:

```sh
dav ls webdav://webdav.example.org/Photos
dav get webdav://webdav.example.org/report.pdf ./report.pdf
dav put ./report.pdf webdav://webdav.example.org/report.pdf
```

Also `info`, `cat`, `mkdir`, `rm`, `mv` and `cp`. Authentication is `--user`
and `--password` (or `$WEBDAV_USER` / `$WEBDAV_PASSWORD`), and the
connection options - mTLS, redirect policy, limits - have flags too. See the
[CLI reference](docs/reference/cli.md), or `dav <command> --help`.


See [CHANGELOG.md](CHANGELOG.md) for the release history. Licensed under the
[MIT License](LICENSE).
