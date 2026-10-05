# webdav-rfc4918

An [RFC 4918](https://www.rfc-editor.org/rfc/rfc4918) compliant WebDAV
client for Python, built on [`requests`](https://requests.readthedocs.io/),
with an optional [`fsspec`](https://filesystem-spec.readthedocs.io)
filesystem and a `dav` CLI.

The test suite runs 1500+ tests on every commit, with over 90% code
coverage, against four real servers (Nextcloud, Apache `mod_dav`, nginx
`dav-ext`, WsgiDAV). TLS verification is on by default, turning it off is
never silent, and redirects never carry credentials to another origin. The
full test and CI breakdown, and the complete list of security defaults, are
in the
[README](https://github.com/manfred-kaiser/webdav-rfc4918#readme).

## Installation

```console
$ pip install webdav-rfc4918
```

## Quick start

```python
import webdav

# One-off call, like os.path.exists()
webdav.exists("https://webdav.example.org/a.txt", auth=("username", "password"))

# Several calls: a FileSystem - same names, same arguments, same results
with webdav.FileSystem("https://webdav.example.org", auth=("username", "password")) as fs:
    fs.exists("Documents/Readme.md")
    fs.ls("Photos")                   # a list of Resource objects
    fs.upload_file("Gorilla.jpg", "Photos/Gorilla.jpg")
```

Any of the calls above can raise a `webdav.exceptions.WebDAVError` (or one
of its subclasses) if the server rejects the request or the connection
fails:

```python
try:
    fs.upload_file("Gorilla.jpg", "Photos/Gorilla.jpg")
except webdav.exceptions.WebDAVError as exc:
    print(exc)
```

See [Exceptions](reference/exceptions.md) for the full hierarchy and which
errors are safe to retry.

```{toctree}
:maxdepth: 2
:caption: For switchers

migration
```

```{toctree}
:maxdepth: 2
:caption: Core concepts

reference/session
reference/locking
```

```{toctree}
:maxdepth: 2
:caption: Error handling & troubleshooting

reference/exceptions
```

```{toctree}
:maxdepth: 2
:caption: Security & transport

reference/tls
reference/redirects
```

```{toctree}
:maxdepth: 2
:caption: Features in depth

reference/fsspec
reference/cli
reference/performance
```

```{toctree}
:maxdepth: 2
:caption: Operations & compliance

apache-compliance-check
nginx-compliance-check
nextcloud-compliance-check
```
