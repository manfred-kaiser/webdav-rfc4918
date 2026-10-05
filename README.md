<p align="center">
  <img src="https://raw.githubusercontent.com/manfred-kaiser/webdav-rfc4918/main/docs/_static/icon.svg" width="96" height="96" alt="webdav-rfc4918">
</p>

<h1 align="center">webdav-rfc4918</h1>

<p align="center">
  <strong>A secure-by-default WebDAV client for Python, built on RFC 4918 and RFC 5689.</strong><br>
  Filesystem-style API, the raw protocol when you need it, a <code>dav</code> command, and protection against known attacks.
</p>

<p align="center">
  <strong>Full documentation:</strong> <a href="https://webdav.readthedocs.io">webdav.readthedocs.io</a>
</p>

<p align="center">
  <a href="https://pypi.org/project/webdav-rfc4918"><img src="https://img.shields.io/pypi/v/webdav-rfc4918" alt="PyPI"></a>
  <a href="https://pypi.org/project/webdav-rfc4918"><img src="https://img.shields.io/pypi/pyversions/webdav-rfc4918" alt="Python versions"></a>
  <a href="https://webdav.readthedocs.io"><img src="https://readthedocs.org/projects/webdav/badge/?version=latest" alt="Documentation Status"></a>
  <a href="https://github.com/manfred-kaiser/webdav-rfc4918/blob/main/LICENSE"><img src="https://img.shields.io/github/license/manfred-kaiser/webdav-rfc4918" alt="License"></a>
</p>

---

`webdav-rfc4918` is a WebDAV client for Python. WebDAV lets you read and
write files on a server over HTTP, like a network drive reachable by URL.

- Tested in CI on every commit against Nextcloud, Apache (mod_dav), nginx
  (dav-ext) and WsgiDAV. See
  [Tested against four servers](#tested-against-four-servers).
- Secure defaults: TLS verification, same-origin redirects, size limits on
  buffered responses. See [Security](#security).
- Works with pandas, dask and anything else built on fsspec. See
  [fsspec](#fsspec).

## Quick Start

Requires Python 3.11+. Built on `requests`.

```sh
pip install webdav-rfc4918
```

A single call, nothing to open or close:

```python
import webdav

auth = ("user", "password")  # HTTP Basic auth

webdav.mkdir("https://webdav.example.org/Photos/", auth=auth)
webdav.upload_file("Gorilla.jpg", "https://webdav.example.org/Photos/Gorilla.jpg", auth=auth)
webdav.ls("https://webdav.example.org/Photos/", auth=auth)   # a list of Resource objects
```

Several calls to the same server: a `FileSystem` keeps the connection open.

```python
with webdav.FileSystem("https://webdav.example.org", auth=auth) as fs:
    fs.upload_file("Gorilla.jpg", "Photos/Gorilla.jpg")
    print(fs.ls("Photos"))
    fs.download_file("Photos/Gorilla.jpg", "copy.jpg")

    with fs.open("Photos/Gorilla.jpg", "rb") as f:   # a file-like object
        image_bytes = f.read()
```

Need the raw protocol: status codes, headers, the multi-status body? Use a
`Session` directly.

```python
with webdav.Session("https://webdav.example.org", auth=auth) as session:
    response = session.propfind("/Photos/", depth=1)
    print(response.status_code, list(response.multistatus.responses))
```

A client certificate (mTLS) and a private CA:

```python
with webdav.Session(
    "https://webdav.example.org",
    cert=("client.crt", "client.key"),
    verify="ca-bundle.pem",
) as session:
    session.propfind("/", depth=0)
```


## Tested against four servers

Nextcloud, Apache `mod_dav`, and nginx `dav-ext` each get their own CI job,
because each reads the RFC differently, and each is documented separately.
WsgiDAV runs the rest of the test suite.

| Server | CI (main) | Tests | Docs |
|---|---|---|---|
| Nextcloud | [![Nextcloud](https://github.com/manfred-kaiser/webdav-rfc4918/actions/workflows/nextcloud-compliance.yml/badge.svg?branch=main)](https://github.com/manfred-kaiser/webdav-rfc4918/actions/workflows/nextcloud-compliance.yml) | 40+ | [docs](https://webdav.readthedocs.io/en/latest/nextcloud-compliance-check.html) |
| Apache `mod_dav` | [![Apache](https://github.com/manfred-kaiser/webdav-rfc4918/actions/workflows/apache-compliance.yml/badge.svg?branch=main)](https://github.com/manfred-kaiser/webdav-rfc4918/actions/workflows/apache-compliance.yml) | 100+ | [docs](https://webdav.readthedocs.io/en/latest/apache-compliance-check.html) |
| nginx + `dav-ext` | [![nginx](https://github.com/manfred-kaiser/webdav-rfc4918/actions/workflows/nginx-compliance.yml/badge.svg?branch=main)](https://github.com/manfred-kaiser/webdav-rfc4918/actions/workflows/nginx-compliance.yml) | 25+ | [docs](https://webdav.readthedocs.io/en/latest/nginx-compliance-check.html) |
| WsgiDAV | [![WsgiDAV](https://github.com/manfred-kaiser/webdav-rfc4918/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/manfred-kaiser/webdav-rfc4918/actions/workflows/ci.yml) | rest of the suite | - |

The test suite runs on every commit: 1500+ tests with over 90% code coverage. It
includes:

- fsspec's own conformance suite (130+ tests)
- 130+ tests that each check one clause of RFC 4918
- 70+ tests for the security defaults described below


## Security

A WebDAV server, or a redirect to one, can be hostile. This is the complete
list of defaults:

- TLS verification is on. Turning it off (`verify=False`, or anything
  `requests` reads as false) emits and logs a `TLSHardeningDisabledWarning`
  that `urllib3.disable_warnings()` does not silence. So does a
  `TLSOptions` with a TLS version below 1.2 or with strict chain checking off.
- `REQUESTS_CA_BUNDLE` and `CURL_CA_BUNDLE` are ignored, so the environment
  cannot replace the CA you configured. `~/.netrc` is ignored too: without
  `auth=`, no credentials are sent.
- A URL with credentials in it (`https://user:pw@host/`) is refused. Pass
  `auth=` instead.
- Credentials sent over plain `http` to a host other than localhost trigger
  an `InsecureTransportWarning`, once per host.
- Only same-origin redirects are followed
  (`RedirectPolicy.SAME_ORIGIN`). Credentials and cookies are never sent to
  another origin, even a trusted one.
- A redirect from `https` to `http` is never followed, under any policy.
- Buffered responses, including multistatus XML, are size-capped, and so are
  redirect chains. Exact limits:
  [Session reference](https://webdav.readthedocs.io/en/latest/reference/session.html#limits-on-what-a-server-can-make-the-client-do).
- A request that is not streamed has a deadline for the whole exchange
  (`max_response_time`, default 300 s): connecting, every redirect hop,
  headers and body. `timeout` only limits each single read.
- A streamed download (`stream=True`, `download_file`) is bounded per read
  only. Neither `max_response_size` nor `max_response_time` applies to it.
- XML from the server is parsed with the standard library's expat parser.
  External entities are never resolved, and expat 2.4.0 or newer rejects
  entity expansion attacks such as "billion laughs". A multistatus or lock
  response that tries either raises `MalformedResponseError`.
- Credentials do not end up in exception messages, warnings or logs: the
  userinfo of a URL and the query of a signed URL are redacted.
- `download_file` writes only to the path you give, through a temporary
  file, and refuses a symlink at that path.

**Report a vulnerability:**
[SECURITY.md](https://github.com/manfred-kaiser/webdav-rfc4918/blob/main/SECURITY.md).


## fsspec

[`fsspec`](https://filesystem-spec.readthedocs.io) is the storage interface
behind pandas, dask and most of the Python data ecosystem. This package adds
a WebDAV backend, so those tools can read and write a WebDAV server like any
other storage. It passes fsspec's own conformance suite (130+ tests).

```sh
pip install webdav-rfc4918[fsspec]
```

```python
import fsspec
import pandas as pd

auth = ("user", "password")

df = pd.read_csv("webdavs://webdav.example.org/data.csv", storage_options={"auth": auth})

with fsspec.open("webdavs://webdav.example.org/Photos/Gorilla.jpg", auth=auth) as f:
    f.read()
```

Installing the package registers the `webdav` and `webdavs` schemes with
fsspec. Paths start at the root of the server (`/Photos/Gorilla.jpg`). See
[fsspec](https://webdav.readthedocs.io/en/latest/reference/fsspec.html) for URL schemes, credentials and path
semantics.


## Locking

Lock a file while you edit it, so no one else can overwrite it (class 2
locking, RFC 4918 §7). The `If` header is handled for you:

```python
import webdav

auth = ("user", "password")

with webdav.FileSystem("https://webdav.example.org", auth=auth) as fs:
    with fs.locked("Documents/report.docx") as lock:
        # writes to the locked path carry the lock token automatically
        fs.upload_file("report.docx", "Documents/report.docx", overwrite=True)
        fs.refresh_lock("Documents/report.docx", lock.token)
```

A lock times out, and nothing refreshes it for you: writes after that fail
with `412`. See
[Locking](https://webdav.readthedocs.io/en/latest/reference/locking.html) for the details.


## Command line

The `dav` command is part of the package:

```sh
dav ls webdavs://webdav.example.org/Photos
dav get webdavs://webdav.example.org/report.pdf ./report.pdf
dav put ./report.pdf webdavs://webdav.example.org/report.pdf --overwrite
```

`webdavs://` is WebDAV over HTTPS, `webdav://` plain HTTP.

Also `info`, `cat`, `mkdir`, `rm`, `mv` and `cp`. Credentials via `--user` and
`--password`, or `$WEBDAV_USER` and `$WEBDAV_PASSWORD`. See the
[CLI reference](https://webdav.readthedocs.io/en/latest/reference/cli.html), or `dav <command> --help`.


## More

The [documentation](https://webdav.readthedocs.io) has a
[quickstart](https://webdav.readthedocs.io/en/latest/quickstart.html),
reference pages for
[sessions](https://webdav.readthedocs.io/en/latest/reference/session.html),
[TLS](https://webdav.readthedocs.io/en/latest/reference/tls.html) and
[redirects](https://webdav.readthedocs.io/en/latest/reference/redirects.html),
and migration guides from
[webdav4](https://webdav.readthedocs.io/en/latest/migration-webdav4.html),
[webdavclient3](https://webdav.readthedocs.io/en/latest/migration-webdavclient3.html)
and [other WebDAV clients](https://webdav.readthedocs.io/en/latest/migration.html).
Release history:
[CHANGELOG.md](https://github.com/manfred-kaiser/webdav-rfc4918/blob/main/CHANGELOG.md).
Licensed under the
[MIT License](https://github.com/manfred-kaiser/webdav-rfc4918/blob/main/LICENSE).
