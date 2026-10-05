# Quickstart

The common tasks, one short example each. Replace the URL and the
credentials with your own.

## Install

```console
$ pip install webdav-rfc4918
```

This also installs the `dav` command. For the fsspec filesystem, install
`webdav-rfc4918[fsspec]` instead.

## A single call

```python
import webdav

webdav.exists("https://webdav.example.org/Documents/Readme.md", auth=("user", "password"))
```

`webdav.ls`, `webdav.upload_file`, `webdav.download_file` and the other
file operations work the same way: they take a full URL, connect, do one
thing and close the connection again. See [Short form](reference/short-form.md).

## Several calls on one server

```python
with webdav.FileSystem("https://webdav.example.org", auth=("user", "password")) as fs:
    for resource in fs.ls("Photos"):
        print(resource, resource.size, resource.is_dir)

    fs.upload_file("Gorilla.jpg", "Photos/Gorilla.jpg")
    fs.download_file("Documents/Readme.md", "Readme.md")
```

A `FileSystem` keeps one connection open, and paths are relative to the
URL you gave it. `ls` returns {class}`~webdav.resource.Resource` objects:
each one is a string with the resource's name, so you can pass it straight
to `download_file` or `remove`. See [FileSystem](reference/filesystem.md).

## Handling errors

```python
from webdav import ResourceNotFoundError, WebDAVError

with webdav.FileSystem("https://webdav.example.org", auth=("user", "password")) as fs:
    try:
        fs.download_file("Documents/Report.pdf", "Report.pdf")
    except ResourceNotFoundError:
        print("Report.pdf is not on the server")
    except WebDAVError as exc:
        print(f"download failed: {exc}")
```

A refused request raises a `WebDAVError` subclass. A network failure
raises the usual `requests` exception, and
`except requests.RequestException` catches both kinds. Uploads and downloads
never replace an existing file unless you pass `overwrite=True`.

## fsspec and pandas

```python
import fsspec
import pandas as pd

with fsspec.open("webdavs://webdav.example.org/Documents/Readme.md", auth=("user", "password")) as f:
    print(f.read())

df = pd.read_csv(
    "webdavs://webdav.example.org/Data/events.csv",
    storage_options={"auth": ("user", "password")},
)
```

`webdavs://` means WebDAV over HTTPS, `webdav://` plain HTTP. Any library
that accepts fsspec URLs can read and write the server this way.

## From the shell

```console
$ export WEBDAV_USER=user WEBDAV_PASSWORD=password
$ dav ls webdavs://webdav.example.org/Photos
```

`dav` also has `get`, `put`, `cat`, `info`, `mkdir`, `rm`, `cp` and `mv`.

## Read next

- [Short form](reference/short-form.md),
  [FileSystem](reference/filesystem.md) and [Session](reference/session.md):
  the three ways to call a server, and when to use which.
- [Exceptions](reference/exceptions.md): which error means what, and
  which ones are retried.
- [Locking](reference/locking.md), [TLS and mTLS](reference/tls.md),
  [Redirects](reference/redirects.md),
  [Performance](reference/performance.md).
- [fsspec](reference/fsspec.md) and [CLI](reference/cli.md) in detail.
