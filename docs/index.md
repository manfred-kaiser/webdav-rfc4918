# webdav-rfc4918

An [RFC 4918](https://www.rfc-editor.org/rfc/rfc4918) compliant WebDAV
client for Python, built on [`requests`](https://requests.readthedocs.io/),
with an optional [`fsspec`](https://filesystem-spec.readthedocs.io)
filesystem and a `dav` CLI.

## Installation

```console
$ pip install webdav-rfc4918
```

## Quick start

```python
from webdav import Client

client = Client("https://webdav.example.org", auth=("username", "password"))
client.exists("Documents/Readme.md")

client.ls("Photos", detail=False)
client.upload_file("Gorilla.jpg", "Photos/Gorilla.jpg")
```

```{toctree}
:maxdepth: 2
:caption: Contents

reference/client
reference/locking
reference/redirects
reference/tls
reference/fsspec
reference/cli
apache-compliance-check
```
