# webdav-rfc4918

An [RFC 4918](https://www.rfc-editor.org/rfc/rfc4918) compliant WebDAV
client for Python, built on [`requests`](https://requests.readthedocs.io/),
with a `dav` CLI. TLS verification is on by default and disabling it is
never quiet, redirects never carry your credentials to another origin, and
responses are bounded in size and time.

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

```{toctree}
:maxdepth: 2
:caption: Contents

reference/session
reference/locking
reference/redirects
reference/tls
reference/cli
apache-compliance-check
```
