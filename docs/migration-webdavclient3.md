# Migrating from webdavclient3

This page is for code that uses `webdavclient3` (`from webdav3.client
import Client`). It shows the same tasks in both libraries. The
`webdavclient3` examples were run against version 3.14.7. For other
clients, see [Migrating from other clients](migration.md). For a first
introduction, see the [Quickstart](quickstart.md).

## Before and after

### Connect, list and download

```python
# webdavclient3
from webdav3.client import Client

client = Client({
    "webdav_hostname": "https://webdav.example.org",
    "webdav_login": "user",
    "webdav_password": "password",
})
for name in client.list("Documents"):
    print(name)
for item in client.list("Documents", get_info=True):
    print(item["path"], item["size"], item["isdir"])
client.download_sync(remote_path="Documents/Report.pdf", local_path="Report.pdf")
```

The same here:

```python
import webdav

with webdav.FileSystem("https://webdav.example.org", auth=("user", "password")) as fs:
    for resource in fs.ls("Documents"):
        print(resource, resource.size, resource.is_dir)
    fs.download_file("Documents/Report.pdf", "Report.pdf", overwrite=True)
```

Connection settings are keyword arguments. There is no options dict.
`ls` always returns {class}`~webdav.resource.Resource` objects, so there
is no `get_info` switch. A `Resource` is a string with the path relative
to the base URL (`Documents/Report.pdf`), and it carries `size`,
`modified`, `is_dir`, `etag` and more. The connection closes at the end of
the `with` block.

### Upload without overwriting

```python
# webdavclient3
if not client.check("Documents/Report.pdf"):
    client.upload_sync(remote_path="Documents/Report.pdf", local_path="Report.pdf")
```

```python
with webdav.FileSystem("https://webdav.example.org", auth=("user", "password")) as fs:
    try:
        fs.upload_file("Report.pdf", "Documents/Report.pdf")
    except webdav.ResourceAlreadyExistsError:
        print("already there, skipped")
```

`upload_file` takes the local path first. `upload_sync` takes the remote
path first. Positional calls have to swap the two arguments.

`upload_file` does not overwrite by default. The server does the check
(`If-None-Match: *`) in the same request. There is no second round trip
and no gap in which another client could create the file. Pass
`overwrite=True` to replace a file, as `upload_sync` does.

### Handling errors

```python
# webdavclient3
from webdav3.exceptions import (
    NoConnection,
    RemoteResourceNotFound,
    ResourceLocked,
    ResponseErrorCode,
)

try:
    client.download_sync(remote_path="Documents/Report.pdf", local_path="Report.pdf")
except RemoteResourceNotFound:
    print("not found")
except ResourceLocked:
    print("locked by someone else")
except ResponseErrorCode as exc:
    print("failed with status", exc.code)
except NoConnection:
    print("server not reachable")
```

```python
import requests
import webdav

with webdav.FileSystem("https://webdav.example.org", auth=("user", "password")) as fs:
    try:
        fs.download_file("Documents/Report.pdf", "Report.pdf", overwrite=True)
    except webdav.ResourceNotFoundError:
        print("not found")
    except webdav.ResourceLockedError:
        print("locked by someone else")
    except webdav.HTTPStatusError as exc:
        print("failed with status", exc.status_code)
    except requests.ConnectionError:
        print("server not reachable")
```

Every status the library gives a meaning to has its own class, for
example `ForbiddenError` (403), `ResourceConflictError` (409) and
`PreconditionFailedError` (412). All of them are subclasses of
`HTTPStatusError`. A network failure stays a `requests` exception. All
exceptions here derive from `requests.exceptions.RequestException`, so
one `except RequestException` catches both. See
[Exceptions](reference/exceptions.md).

### Locking

```python
# webdavclient3
with client.lock("Documents/Report.docx", timeout=300) as locked_client:
    locked_client.upload_sync(
        remote_path="Documents/Report.docx", local_path="Report.docx"
    )
```

```python
with webdav.FileSystem("https://webdav.example.org", auth=("user", "password")) as fs:
    with fs.locked("Documents/Report.docx", lock_timeout=300):
        fs.upload_file("Report.docx", "Documents/Report.docx", overwrite=True)
```

`client.lock()` returns a second client object that sends the token.
`fs.locked()` registers the token on `fs` itself. Writes inside the block
carry it, and the lock is released at the end of the block, also after
an exception. A conflicting lock raises `ResourceLockedError`. `depth`
and refreshing are in [Locking](reference/locking.md), the `scope`
argument for shared locks in the [API reference](reference/api.md#filesystem).

## Concept mapping

| `webdavclient3` | Here |
|---|---|
| `Client(options)` | {class}`~webdav.fs.client.FileSystem` as a context manager. For raw requests: {class}`~webdav.session.Session` |
| `webdav_hostname` plus `webdav_root` | `base_url`, the first argument, with the root path in it |
| `webdav_login`, `webdav_password` | `auth=("user", "password")` |
| `webdav_token` | `headers={"Authorization": "Bearer ..."}` |
| `webdav_cert_path`, `webdav_key_path` | `cert=("client.crt", "client.key")`, see [TLS and mTLS](reference/tls.md) |
| `webdav_timeout` | `timeout=` |
| `client.verify = False` | `verify=False` |
| `list(path)`, `list(path, get_info=True)` | `fs.ls(path)` |
| `list(path, recursive=True)` | `fs.walk(path)` |
| `info(path)` | `fs.info(path)` |
| `check(path)` | `fs.exists(path)` |
| `is_dir(path)` | `fs.isdir(path)` |
| `download_sync`, `download_file` | `fs.download_file(path, local_path)` |
| `upload_sync`, `upload_file` | `fs.upload_file(local_path, path)` (argument order swapped) |
| `download_from(buff, path)`, `upload_to(buff, path)` | `fs.download_fileobj`, `fs.upload_fileobj` |
| `download_iter`, `upload_iter` | `fs.open(path, "rb")`, `fs.open(path, "wb")` |
| `download_directory`, `upload_directory`, `pull`, `push` | fsspec `get(..., recursive=True)`, `put(..., recursive=True)`, see [fsspec: Local files](reference/fsspec.md#local-files) |
| `mkdir(path)` | `fs.mkdir(path)` |
| `mkdir(path, recursive=True)` | fsspec `makedirs(path, exist_ok=True)` |
| `clean(path)` | `fs.remove(path)` |
| `copy`, `move(..., overwrite=False)` | `fs.copy`, `fs.move`. Both take `overwrite=`, default `False` |
| `get_property(path, {"namespace": ns, "name": n})` | `fs.get_props(path, props=["{ns}n"]).text(ns, n)` |
| `set_property`, `set_property_batch` | `fs.set_props(path, set_props={"{ns}n": value})` |
| `lock(path, timeout=...)`, `LockClient` | `with fs.locked(path, lock_timeout=...):` |
| `client.resource(path)` | No handle object. Pass the path to the `FileSystem` methods. |
| `download_async`, `upload_async` | No counterpart. Run `download_file` or `upload_file` in a thread of your own. |
| `RemoteResourceNotFound` | `ResourceNotFoundError` |
| `ResourceLocked` | `ResourceLockedError` |
| `NotEnoughSpace` | `InsufficientStorageError` |
| `ResponseErrorCode` (`exc.code`) | `HTTPStatusError` (`exc.status_code`) or one of its subclasses |
| `NoConnection`, `ConnectionException` | `requests.ConnectionError`, `requests.RequestException` |
| The `wdc` command | The `dav` command, see [CLI](reference/cli.md) |

## Differences that trip people up

**Upload arguments are in the other order.** `upload_sync(remote_path,
local_path)` becomes `upload_file(local_path, path)`. Downloads keep the
order: remote first, local second.

**Nothing is overwritten by default.** `upload_file`, `download_file`,
`copy` and `move` refuse to replace an existing file unless you pass
`overwrite=True`. This includes the local file on a download, which
raises `FileExistsError`.

**Missing parent folders are not created.** `FileSystem.upload_file` into
a folder that does not exist raises `ResourceConflictError` (409). The
fsspec interface creates parent folders for `put`, and `makedirs` creates
a whole chain. See [fsspec: Directories](reference/fsspec.md#directories).

**Names come back as paths.** `client.list("Documents")` returns
`Report.pdf`, and a folder with a trailing slash. `fs.ls("Documents")`
returns `Documents/Report.pdf` and marks folders with `is_dir`. You can
pass each entry straight to `info`, `download_file` or `remove`.

**A lock has a timeout.** `client.lock()` without `timeout` sends no
`Timeout` header and leaves the duration to the server. `fs.locked()`
asks for 600 seconds unless you pass `lock_timeout=` (`None` for
infinite). See [Locking: Timeouts](reference/locking.md#timeouts).

**A path is encoded exactly once.** Pass the plain name: `a%20b.txt` is a
file called `a%20b.txt`. Details in
[FileSystem: Paths and names](reference/filesystem.md#paths-and-names).

**No credentials in the URL.** `https://user:pw@host/` is refused. Pass
`auth=` instead.

## Checks to run on your current setup

See [Checks to run on your current setup](migration.md#checks-to-run-on-your-current-setup) - same four criteria.

`webdavclient3` does not register an fsspec filesystem. That answers the
fsspec criterion for `webdavclient3` itself. If you reach the same server
through fsspec today, that goes through a different backend. Run
fsspec's own suite, `fsspec.tests.abstract`, against that backend.
