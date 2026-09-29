# webdav-rfc4918

An [RFC 4918](https://www.rfc-editor.org/rfc/rfc4918) compliant WebDAV
client for Python, built on [`requests`](https://requests.readthedocs.io/),
with an optional [`fsspec`](https://filesystem-spec.readthedocs.io)
filesystem and a `dav` CLI. TLS verification cannot be disabled, redirects never
carry your credentials to another origin, and responses are bounded in size and time.

## Installation

```console
$ pip install webdav-rfc4918
```

## Quick start

```python
import webdav

# One-off call, like requests.get()
webdav.get("https://webdav.example.org/a.txt", auth=("username", "password"))

# Several calls: a Session - same names, same arguments, same results
with webdav.Session("https://webdav.example.org", auth=("username", "password")) as session:
    session.exists("Documents/Readme.md")
    session.ls("Photos")                   # a list of Resource objects
    session.upload_file("Gorilla.jpg", "Photos/Gorilla.jpg")
```

```{toctree}
:maxdepth: 2
:caption: Contents

reference/session
reference/locking
reference/redirects
reference/tls
reference/fsspec
reference/cli
apache-compliance-check
```
