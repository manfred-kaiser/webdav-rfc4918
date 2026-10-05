# Migrating from other clients

How the usual patterns of other Python WebDAV clients map to this
library. For a first introduction, see the [Quickstart](quickstart.md).
This page is generic. Two clients have a page of their own that shows
both APIs side by side:

| Coming from | Page |
|---|---|
| `webdav4` | [Migrating from webdav4](migration-webdav4.md) |
| `webdavclient3` | [Migrating from webdavclient3](migration-webdavclient3.md) |

This library runs 1500+ tests in CI. 1200+ of them run against WsgiDAV on
every commit. Nextcloud (40+ tests), Apache `mod_dav` (100+) and nginx
`dav-ext` (25+) each get a CI job of their own. The suite checks RFC 4918
clause by clause and passes fsspec's own conformance suite. The numbers
per server are in
[Tested against four servers](index.md#tested-against-four-servers).

## Before and after

### List and download

Many clients put everything on one object and report failure through the
return value. A generic sketch of that pattern, not any specific library:

```python
# before: one client object, results checked by hand
client = Client("https://webdav.example.org", user="user", password="password")
for name in client.list("Documents"):
    print(name)
if not client.download("Documents/Report.pdf", "Report.pdf"):
    print("download failed")
```

The same here:

```python
import webdav

with webdav.FileSystem("https://webdav.example.org", auth=("user", "password")) as fs:
    for resource in fs.ls("Documents"):
        print(resource, resource.size)
    try:
        fs.download_file("Documents/Report.pdf", "Report.pdf")
    except webdav.WebDAVError as exc:
        print(f"download failed: {exc}")
```

`ls` returns {class}`~webdav.resource.Resource` objects. Each is a string
(its name) that also carries `size`, `modified`, `is_dir` and more. The
connection closes at the end of the `with` block.

### Upload without overwriting

```python
# before: check first, then upload
if not client.exists("Documents/Report.pdf"):
    client.upload("Report.pdf", "Documents/Report.pdf")
```

```python
with webdav.FileSystem("https://webdav.example.org", auth=("user", "password")) as fs:
    try:
        fs.upload_file("Report.pdf", "Documents/Report.pdf")
    except webdav.ResourceAlreadyExistsError:
        print("already there, skipped")
```

`upload_file` does not overwrite by default. The server does the check
(`If-None-Match: *`) in the same request, so there is no extra round trip
and no gap in which another client could create the file.

### Locking

```python
# before: lock, keep the token, unlock by hand
token = client.lock("Documents/Report.docx")
try:
    client.upload("Report.docx", "Documents/Report.docx", lock_token=token)
finally:
    client.unlock("Documents/Report.docx", token)
```

```python
with webdav.FileSystem("https://webdav.example.org", auth=("user", "password")) as fs:
    with fs.locked("Documents/Report.docx"):
        fs.upload_file("Report.docx", "Documents/Report.docx", overwrite=True)
```

Writes inside the block send the lock token for you. The lock is released
at the end of the block, also after an exception. A conflicting lock
raises `ResourceLockedError`, see [Locking](reference/locking.md).

### Status codes and headers

```python
# before: send the request, check the status yourself
response = client.request("PROPFIND", "Documents/", headers={"Depth": "1"})
if response.status_code != 207:
    print("failed:", response.status_code)
```

```python
with webdav.Session("https://webdav.example.org", auth=("user", "password")) as session:
    r = session.propfind("Documents/", depth=1)
    print(r.status_code, r.headers["Content-Type"])
    r.raise_for_status()
```

A `Session` verb returns the response and raises nothing on its own.
`raise_for_status()` turns an error status into the matching exception,
for example `ResourceNotFoundError` for a 404.

## Concept mapping

| If your previous client had... | ...use here |
|---|---|
| A client object kept open across calls | {class}`~webdav.fs.client.FileSystem` or {class}`~webdav.session.Session` as a context manager |
| A one-off call without a client object | A [short-form](reference/short-form.md) function: `webdav.ls(url)`, `webdav.upload_file(...)`, with the same names and arguments as `FileSystem` |
| Raw status codes, headers, response bodies | `Session` verbs (`get`, `propfind`, `lock`, ...). They return a {class}`~webdav.response.Response` and raise nothing by default. |
| Filesystem-style paths and listings | `FileSystem` operations (`ls`, `info`, `walk`, ...). They return {class}`~webdav.resource.Resource` objects and raise on errors. |
| Library-specific exceptions | The `WebDAVError` hierarchy, see [Exceptions](reference/exceptions.md) |
| A lock object or lock token handling | `with fs.locked(path):`, see [Locking](reference/locking.md). A token you already hold: `session.locks.add(url, token, depth)`, see [Session: `lock` and `unlock`](reference/session.md#lock-and-unlock) |
| URLs for pandas, Dask or other fsspec tools | `webdavs://host/path` with `storage_options={"auth": ...}`, see [fsspec](reference/fsspec.md) |
| A command-line tool | The `dav` command (`dav ls`, `dav get`, `dav put`, ...), see [CLI](reference/cli.md) |

## Differences that trip people up

**Raw verbs and file operations are on two classes.** `FileSystem` sends
its requests through a `Session`, and `fs.session` gives you that
session. It is not a subclass of `Session`, so a `FileSystem` has no
`propfind` or `lock` of its own. If your previous client had raw and
filesystem-style methods on one object, pick the class that matches the
call. To use both on one connection, wrap the session with
`FileSystem.from_session(session)`, see
[FileSystem: Opening and closing](reference/filesystem.md#opening-and-closing).
The [short form](reference/short-form.md) is a
shortcut for the `FileSystem` methods: same names, arguments and return
values, but its own connection per call. [One naming rule](reference/session.md#one-naming-rule)
explains the split, [Which form to use](quickstart.md#which-form-to-use)
when to pick which.

**Errors are exceptions.** A `FileSystem` operation raises a `WebDAVError`
subclass on an error status. It never returns `None`, `False` or a status
code. A `Session` verb raises nothing unless you call `raise_for_status()`
or create the session with `raise_on_error=True`. Code that checked a
return value needs a `try`/`except` instead. A network failure is still a
`requests` exception, not a `WebDAVError`, see
[Handling errors](quickstart.md#handling-errors).

**Nothing is overwritten by default.** `upload_file`, `download_file`,
`copy` and `move` refuse to replace an existing file unless you pass
`overwrite=True`.

**A path is encoded exactly once.** Pass the plain name: `a%20b.txt` is a
file called `a%20b.txt`, not `a b.txt`. If your previous client expected
pre-encoded paths, decode them first. Details in
[FileSystem: Paths and names](reference/filesystem.md#paths-and-names).

**No credentials in the URL.** `https://user:pw@host/` is refused. Pass
`auth=` instead.

## Checks to run on your current setup

Four tests you can run against the client you use today.

### fsspec conformance

If you use the client through fsspec, run fsspec's own suite,
`fsspec.tests.abstract`, against it. This library passes it (130+ tests),
see [fsspec: Conformance](reference/fsspec.md#conformance).

### Locking on more than one server

RFC 4918 leaves servers room to differ, and lock behaviour is where they
do. Run `LOCK`, a write with and without the token, and `UNLOCK` against
each server type you deploy to. The [Nextcloud](nextcloud-compliance-check.md),
[Apache](apache-compliance-check.md) and [nginx](nginx-compliance-check.md)
pages show what this library found on each.

### Names with spaces and special characters

Upload a file named like `a b #1 %20;ü.txt`, list its folder, and download
it again. The name should come back unchanged. This library encodes a path
exactly once, see [FileSystem: Paths and names](reference/filesystem.md#paths-and-names).

### Telling errors apart

Provoke a 404, a 423 Locked, a 412 Precondition Failed and a refused
connection. Check whether your code can catch each one on its own. Here
they are `ResourceNotFoundError`, `ResourceLockedError`,
`PreconditionFailedError` and the `requests` connection error, see
[Exceptions](reference/exceptions.md).
