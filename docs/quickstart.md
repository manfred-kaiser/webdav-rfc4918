# Quickstart

The common tasks, one short example each. Replace the URL and the
credentials with your own.

## Install

```console
$ pip install webdav-rfc4918
```

This also installs the `dav` command. For the fsspec filesystem, install
`webdav-rfc4918[fsspec]` instead.

## Which form to use

The library offers three ways to talk to a server. They are three layers
of one implementation, each built on the one below:

```text
short form  →  FileSystem  →  Session  →  HTTP
```

`Session` sends the HTTP and WebDAV requests and returns the server's
answers as they are. `FileSystem` sends its requests through a `Session`.
It takes paths instead of URLs, returns Python values instead of responses
and raises an exception for an error status. Each short-form function
opens a `FileSystem`, makes one call and closes it again. So the options
(`auth=`, `timeout=`, limits, retries) and the behaviour of a file
operation are the same in all three. Going up a layer means less code per
call. Going down means more control over the requests.

| You want to | Use |
|---|---|
| Make one or two calls, for example in a script or a health check | The [short form](reference/short-form.md) |
| Make several calls against the same server | [`FileSystem`](reference/filesystem.md) |
| See status codes and headers, read the raw multistatus, or send a request the file operations do not cover | [`Session`](reference/session.md) |

The short form takes a full URL, a `FileSystem` a path relative to its
base URL. `Session` has no short form.

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
import webdav

with webdav.FileSystem("https://webdav.example.org", auth=("user", "password")) as fs:
    for resource in fs.ls("Photos"):
        print(resource, resource.size, resource.is_dir)

    fs.upload_file("Gorilla.jpg", "Photos/Gorilla.jpg")
    fs.download_file("Documents/Readme.md", "Readme.md")
```

This is the form to use in most programs. A `FileSystem` keeps one
connection open, and paths are relative to the URL you gave it. `ls`
returns {class}`~webdav.resource.Resource` objects: each one is a string
with the resource's name, so you can pass it straight to `download_file`
or `remove`. See [FileSystem](reference/filesystem.md).

## Handling errors

```python
import webdav
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

auth = ("user", "password")

df = pd.read_csv("webdavs://webdav.example.org/data.csv", storage_options={"auth": auth})

with fsspec.open("webdavs://webdav.example.org/Photos/Gorilla.jpg", auth=auth) as f:
    f.read()
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
  [Redirects](reference/redirects.md).
- [fsspec](reference/fsspec.md) and [CLI](reference/cli.md) in detail.
- [Migration](migration.md): coming from another WebDAV client.

## Common problems

| Problem | What to do |
|---|---|
| `HTTPStatusError` with `status_code` 401 | Wrong username or password. See [Exceptions](reference/exceptions.md). |
| `requests.exceptions.SSLError` on a server with a self-signed certificate | Pass the CA: `verify="ca.pem"`. See [TLS and mTLS](reference/tls.md). |
| `InsecureTransportWarning` | The URL is `http://`/`webdav://`, so the password goes out in clear text. See [Session](reference/session.md#limits-on-what-a-server-can-make-the-client-do). |
| Which URL for Nextcloud? | The WebDAV URL is `https://<host>/remote.php/dav/files/<user>`. See [Nextcloud](nextcloud-compliance-check.md). |
| `ResourceConflictError` (409) on upload or `mkdir` | The parent folder does not exist. Create it with `mkdir` first. |
| `ResourceAlreadyExistsError` on upload | The file exists. Pass `overwrite=True` to replace it. |
