# Migrating from webdav4

This page is for code that uses `webdav4` today. It shows the same tasks
with both libraries and maps the `webdav4` names to the ones here. The
examples were checked against `webdav4` 0.11.0. For other clients, see
[Migrating from other clients](migration.md). For a first
introduction, see the [Quickstart](quickstart.md).

Three things change everywhere:

- The import name is `webdav`, the package name `webdav-rfc4918`.
- The HTTP layer is `requests`. `webdav4` uses `httpx`. Options such as
  `timeout`, `verify` and `cert` keep their names. Network errors are
  `requests` exceptions.
- Optional arguments such as `overwrite` are keyword-only.

## Before and after

### List and download

```python
# webdav4
from webdav4.client import Client

client = Client("https://webdav.example.org", auth=("user", "password"))
for entry in client.ls("Documents"):
    print(entry["name"], entry["content_length"], entry["type"])
client.download_file("Documents/Report.pdf", "Report.pdf")
client.http.close()
```

```python
import webdav

with webdav.FileSystem("https://webdav.example.org", auth=("user", "password")) as fs:
    for resource in fs.ls("Documents"):
        print(resource, resource.size, resource.is_dir)
    fs.download_file("Documents/Report.pdf", "Report.pdf", overwrite=True)
```

`webdav4`'s `ls` returns dicts, or names with `detail=False`. Here `ls`
returns {class}`~webdav.resource.Resource` objects. Each is a string (its
name) with attributes: `size` for `content_length`, `is_dir` for
`type == "directory"`, and `modified`, `etag`, `content_type` and the
others under their `webdav4` names.

`download_file` here does not replace a local file that already exists.
It raises `FileExistsError` unless you pass `overwrite=True`. `webdav4`
always writes the local file.

`ls` on a file raises `IsAResourceError` here. `webdav4` returns the file's
own entry unless you pass `allow_listing_resource=False`. Use `info` for a
single resource.

### Upload without overwriting

```python
# webdav4
from webdav4.client import Client, ResourceAlreadyExists

client = Client("https://webdav.example.org", auth=("user", "password"))
try:
    client.upload_file("Report.pdf", "Documents/Report.pdf")
except ResourceAlreadyExists:
    print("already there, skipped")
```

```python
import webdav

with webdav.FileSystem("https://webdav.example.org", auth=("user", "password")) as fs:
    try:
        fs.upload_file("Report.pdf", "Documents/Report.pdf")
    except webdav.ResourceAlreadyExistsError:
        print("already there, skipped")
```

Both refuse to overwrite by default. `webdav4` sends a `PROPFIND` first and
then the `PUT`. Here the server does the check in the `PUT` itself
(`If-None-Match: *`).

### Handling errors

```python
# webdav4
import httpx
from webdav4.client import Client, HTTPError, ResourceNotFound

client = Client("https://webdav.example.org", auth=("user", "password"))
try:
    info = client.info("Documents/Report.pdf")
except ResourceNotFound as exc:
    print("missing:", exc.path)
except HTTPError as exc:
    print("failed:", exc.status_code)
except httpx.ConnectError:
    print("server not reachable")
```

```python
import requests
import webdav

with webdav.FileSystem("https://webdav.example.org", auth=("user", "password")) as fs:
    try:
        info = fs.info("Documents/Report.pdf")
    except webdav.ResourceNotFoundError as exc:
        print("missing:", exc.path)
    except webdav.HTTPStatusError as exc:
        print("failed:", exc.status_code)
    except requests.exceptions.ConnectionError:
        print("server not reachable")
```

`HTTPStatusError` is the base class of every status error here, like
`HTTPError` in `webdav4`. Most statuses have a subclass of their own, for
example `ResourceLockedError` for 423 and `PreconditionFailedError` for
412. The full list is in [Exceptions](reference/exceptions.md). Every
exception here also derives from `requests.exceptions.RequestException`.

### fsspec

Without this library installed, fsspec resolves `webdav` to `webdav4`.
The URL carries only the path. The server always comes from `base_url`:

```python
# webdav4
import pandas as pd

options = {"base_url": "https://webdav.example.org", "auth": ("user", "password")}
df = pd.read_csv("webdav://Data/events.csv", storage_options=options)
```

:::{note}
The common fsspec pattern of naming the server in the URL itself does not
work with `webdav4`:

```python
pd.read_csv("webdav://webdav.example.org/Data/events.csv", storage_options={"auth": ("user", "password")})
# TypeError: WebdavFileSystem.__init__() missing 1 required
# positional argument: 'base_url'
```

`webdav4.fsspec.WebdavFileSystem` does not implement
`_get_kwargs_from_urls()`, the method fsspec uses to pull a host out of a
URL (reproduced against `webdav4` 0.11.0). `base_url` in `storage_options`
is the only way to point it at a server.
:::

This library registers `webdavs` and `webdav`. The URL can name the
server:

```python
import pandas as pd

options = {"auth": ("user", "password")}
df = pd.read_csv("webdavs://webdav.example.org/Data/events.csv", storage_options=options)
```

To keep `base_url` in `storage_options`, leave the host out of the URL.
That takes a third slash:

```python
options = {"base_url": "https://webdav.example.org", "auth": ("user", "password")}
df = pd.read_csv("webdav:///Data/events.csv", storage_options=options)
```

Without the third slash, `Data` is read as a host name. It does not match
`base_url`, and the call raises `ValueError`. Paths in listings start with
`/` here (`/Data/events.csv`). `webdav4` lists them without it.

When both libraries are installed, `webdav://` resolves to this library.
See [fsspec](reference/fsspec.md) for the constructor keywords.

## Concept mapping

| `webdav4` | Here |
|---|---|
| `webdav4.client.Client(base_url, auth=...)` | {class}`~webdav.fs.client.FileSystem` `(base_url, auth=...)` |
| `httpx` options: `timeout`, `verify`, `cert`, `headers` | The same keywords, passed to `requests`, see [Session options](reference/session.md#session-options) |
| `retry=True`, `retry=False` | `retry=True`, `retry=False`. What is retried is listed under [Retries](reference/session.md#retries) |
| `client.http.close()` | `with FileSystem(...) as fs:` or `fs.close()` |
| `client.ls(path)`, a list of dicts | `fs.ls(path)`, a list of `Resource` objects |
| `client.ls(path, detail=False)` | `fs.ls(path)`. A `Resource` is already a `str` |
| `entry["content_length"]`, `entry["type"]` | `resource.size`, `resource.is_dir` |
| `client.info(path)` | `fs.info(path)` |
| `exists`, `isdir`, `isfile` | Same names |
| `content_length`, `created`, `modified`, `etag`, `content_type`, `content_language` | Same names |
| `client.get_props(path, name=...)` | `fs.get_props(path, props=[...])`, see [Properties](reference/filesystem.md#properties) |
| `client.options()` | `fs.dav_compliance()` |
| `client.mkdir(path)`, `client.remove(path)` | `fs.mkdir(path)`, `fs.remove(path)` |
| `client.copy(from_path, to_path, depth, overwrite)` | `fs.copy(path, destination, overwrite=..., depth=...)` |
| `client.move(from_path, to_path, overwrite)` | `fs.move(path, destination, overwrite=...)` |
| `client.open(path, "rb")` (read only) | `fs.open(path, "rb")`, also `"wb"` and `"xb"` |
| `upload_file`, `upload_fileobj`, `download_file`, `download_fileobj` | Same names. `overwrite` is keyword-only. `download_file` also has it for the local file |
| `client.http.propfind(...)`, `client.request(...)` | {class}`~webdav.session.Session` verbs: `session.propfind(path, depth=1)`, `session.request(...)`. They return the response and raise nothing by default |
| `client.http.lock(...)`, `client.http.unlock(...)` | `with fs.locked(path):`, see [Locking](reference/locking.md) |
| `ClientError` | `WebDAVError` |
| `HTTPError` | `HTTPStatusError` |
| `ResourceNotFound`, `ResourceAlreadyExists`, `ResourceLocked`, `ResourceConflict` | `ResourceNotFoundError`, `ResourceAlreadyExistsError`, `ResourceLockedError`, `ResourceConflictError` |
| `ForbiddenOperation`, `InsufficientStorage`, `BadGatewayError` | `ForbiddenError`, `InsufficientStorageError`, `BadGatewayError` |
| `IsACollectionError`, `IsAResourceError`, `MultiStatusError` | Same names |
| `httpx.ConnectError`, `httpx.TimeoutException` | `requests.exceptions.ConnectionError`, `requests.exceptions.Timeout` |
| `webdav4.fsspec.WebdavFileSystem(base_url, auth=...)` | `webdav.fsspec.WebdavFileSystem(base_url, auth=...)` |
| `webdav://path` with `base_url` | `webdav:///path` with `base_url`, or `webdavs://host/path` |
| `dav --endpoint-url https://host ls dav://Documents` | `dav ls webdavs://host/Documents`, see [CLI](reference/cli.md) |

## Installing both side by side

Both packages install a command called `dav`. The one installed last wins.

`webdav4` does not register an fsspec entry point itself. fsspec's own
`fsspec/registry.py` has a built-in fallback that maps the `webdav`
protocol to `webdav4.fsspec.WebdavFileSystem` when nothing else claims it.
This library registers `webdav` and `webdavs` through an
`fsspec.specs` entry point (`clobber=True`), which takes precedence over
that fallback. With both packages installed, `webdav://` resolves to this
library. Python imports do not collide: `webdav4` and
`webdav` are different module names. To keep both `dav` commands, install
the packages in separate environments.

## Checks to run on your current setup

See [Checks to run on your current setup](migration.md#checks-to-run-on-your-current-setup) - same four criteria.

For fsspec conformance, run fsspec's own suite, `fsspec.tests.abstract`,
against `webdav4.fsspec.WebdavFileSystem` if you use `webdav4` through
fsspec.
