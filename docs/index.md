# webdav-rfc4918

A secure-by-default WebDAV client for Python, built on
[RFC 4918](https://www.rfc-editor.org/rfc/rfc4918). It offers a
filesystem-style API, the raw protocol when you need it, an
[`fsspec`](https://filesystem-spec.readthedocs.io) backend for pandas and
Dask, and a `dav` command.

[![PyPI](https://img.shields.io/pypi/v/webdav-rfc4918)](https://pypi.org/project/webdav-rfc4918)
[![Python versions](https://img.shields.io/pypi/pyversions/webdav-rfc4918)](https://pypi.org/project/webdav-rfc4918)
[![License](https://img.shields.io/github/license/manfred-kaiser/webdav-rfc4918)](https://github.com/manfred-kaiser/webdav-rfc4918/blob/main/LICENSE)

## Installation

```console
$ pip install webdav-rfc4918
```

Requires Python 3.11+. Built on [`requests`](https://requests.readthedocs.io/).
MIT licensed.

## First call

```python
import webdav

for resource in webdav.ls("https://webdav.example.org/Photos", auth=("user", "password")):
    print(resource, resource.size)
```

One call, one connection. For several calls against the same server,
open a [`FileSystem`](reference/filesystem.md) instead.

## Works with pandas and Dask

Installing the package registers the `webdav` and `webdavs` schemes with
fsspec. pandas, Dask and other fsspec-based tools then read a WebDAV
server like any other storage:

```python
import fsspec
import pandas as pd

auth = ("user", "password")

df = pd.read_csv("webdavs://webdav.example.org/data.csv", storage_options={"auth": auth})

with fsspec.open("webdavs://webdav.example.org/Photos/Gorilla.jpg", auth=auth) as f:
    f.read()
```

It passes fsspec's own conformance suite (130+ tests). Install with
`pip install webdav-rfc4918[fsspec]`, details in [fsspec](reference/fsspec.md).

## Tested against four servers

Each server reads the RFC a little differently. Nextcloud, Apache and
nginx each get their own CI job and their own page:

| Server | Tests | Scope | Details |
|---|---|---|---|
| Nextcloud | 40+ | Core RFC 4918 only, no `oc:`/`nc:` properties | [Nextcloud](nextcloud-compliance-check.md) |
| Apache `mod_dav` | 100+ | The primary deployment target | [Apache](apache-compliance-check.md) |
| nginx + `dav-ext` | 25+ | Includes the module's known limitations | [nginx](nginx-compliance-check.md) |
| WsgiDAV | 1200+ | All other tests, on every commit, no system dependency | - |

## Safe by default

- 1500+ tests on every commit, over 90% code coverage. 70+ of them
  cover the security defaults.
- Follows [RFC 4918](https://www.rfc-editor.org/rfc/rfc4918), checked
  clause by clause in 130+ tests.
- TLS verification is on by default. Turning it off always warns.
- Redirects never carry credentials or cookies to another origin.
- Buffered responses, including multistatus XML, are size-capped, and so
  are redirect chains. Exact limits in
  [Session](reference/session.md#limits-on-what-a-server-can-make-the-client-do).
- `download_file` writes only to the path you give, through a temporary
  file, and refuses a symlink at that path.

The full list is in the
[README](https://github.com/manfred-kaiser/webdav-rfc4918#security).

## Next steps

- New here: the [Quickstart](quickstart.md) covers single calls,
  `FileSystem`, errors, fsspec and the CLI on one page.
- Three ways to call a server: the [short form](reference/short-form.md),
  [`FileSystem`](reference/filesystem.md) and
  [`Session`](reference/session.md).
  [Which form to use](quickstart.md#which-form-to-use) compares them.
- Looking something up: [API reference](reference/api.md) and
  [Exceptions](reference/exceptions.md).
- Coming from another Python WebDAV client:
  [from webdav4](migration-webdav4.md),
  [from webdavclient3](migration-webdavclient3.md), or the general
  [Migrating](migration.md) page.

## Help and feedback

Bugs and questions:
[GitHub Issues](https://github.com/manfred-kaiser/webdav-rfc4918/issues).
To report a vulnerability, follow
[SECURITY.md](https://github.com/manfred-kaiser/webdav-rfc4918/blob/main/SECURITY.md).
Please do not open a public issue for it.

```{toctree}
:hidden:
:maxdepth: 1

quickstart
```

```{toctree}
:hidden:
:maxdepth: 1
:caption: User guide

reference/short-form
reference/filesystem
reference/session
reference/locking
reference/fsspec
reference/cli
```

```{toctree}
:hidden:
:maxdepth: 1
:caption: Security & transport

reference/tls
reference/redirects
reference/url-credentials
```

```{toctree}
:hidden:
:maxdepth: 1
:caption: Reference

reference/api
reference/exceptions
```

```{toctree}
:hidden:
:maxdepth: 1
:caption: Migration

migration-webdav4
migration-webdavclient3
migration
```

```{toctree}
:hidden:
:maxdepth: 1
:caption: Server notes

nextcloud-compliance-check
apache-compliance-check
nginx-compliance-check
```

