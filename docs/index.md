# webdav-rfc4918

A WebDAV client for Python, built on
[`requests`](https://requests.readthedocs.io/), with an
[`fsspec`](https://filesystem-spec.readthedocs.io) filesystem and a `dav`
command.

```python
import webdav

for resource in webdav.ls("https://webdav.example.org/Photos", auth=("user", "password")):
    print(resource, resource.size)
```

## Installation

```console
$ pip install webdav-rfc4918
```

## Tested against four servers

Each server reads the RFC a little differently. Nextcloud, Apache and
nginx each get their own CI job and their own page:

| Server | Tests | Scope | Details |
|---|---|---|---|
| Nextcloud | 40+ | Core RFC 4918 only, no `oc:`/`nc:` properties | [Nextcloud](nextcloud-compliance-check.md) |
| Apache `mod_dav` | 100+ | The primary deployment target | [Apache](apache-compliance-check.md) |
| nginx + `dav-ext` | 25+ | Includes the module's known limitations | [nginx](nginx-compliance-check.md) |
| WsgiDAV | rest of the suite | Runs on every commit, no system dependency | - |

## Safe by default

- 1500+ tests on every commit, over 90% code coverage.
- Follows [RFC 4918](https://www.rfc-editor.org/rfc/rfc4918), checked
  clause by clause in 130+ tests.
- TLS verification is on by default. Turning it off always warns.
- Redirects never carry credentials to another origin.

The full list of security defaults is in the
[README](https://github.com/manfred-kaiser/webdav-rfc4918#security).

## Next steps

Start with the [Quickstart](quickstart.md): single calls, `FileSystem`,
error handling, fsspec and the CLI on one page. The library has three
ways to call a server: the [short form](reference/short-form.md) above for
single calls, [`FileSystem`](reference/filesystem.md) for several calls on
one server, and [`Session`](reference/session.md) for raw HTTP and WebDAV
requests. [Which form to use](reference/short-form.md#which-form-to-use)
compares them. If a call fails, [Exceptions](reference/exceptions.md)
explains each error. Every class and function is listed in the
[API reference](reference/api.md). Coming from another Python WebDAV
client, read [Migrating](migration.md).

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
reference/performance
```

```{toctree}
:hidden:
:maxdepth: 1
:caption: Security & transport

reference/tls
reference/redirects
```

```{toctree}
:hidden:
:maxdepth: 1
:caption: Reference

reference/api
reference/exceptions
migration
```

```{toctree}
:hidden:
:maxdepth: 1
:caption: Server compatibility

apache-compliance-check
nginx-compliance-check
nextcloud-compliance-check
```
