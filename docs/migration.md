# Migrating from another WebDAV client

How the usual patterns of other Python WebDAV clients map to this library.
For a first introduction, see the [Quickstart](quickstart.md).

## Concept mapping

| If your previous client had... | ...use here |
|---|---|
| A client object kept open across calls | {class}`~webdav.fs.client.FileSystem` or {class}`~webdav.session.Session` as a context manager |
| A one-off call without a client object | A [short-form](reference/short-form.md) function: `webdav.ls(url)`, `webdav.upload_file(...)`, with the same names and arguments as `FileSystem` |
| Raw status codes, headers, response bodies | `Session` verbs (`get`, `propfind`, `lock`, ...). They return a {class}`~webdav.response.Response` and raise nothing by default. |
| Filesystem-style paths and listings | `FileSystem` operations (`ls`, `info`, `walk`, ...). They return {class}`~webdav.resource.Resource` objects and raise on errors. |
| Library-specific exceptions | The `WebDAVError` hierarchy, see [Exceptions](reference/exceptions.md) |
| A lock object or lock token handling | `with fs.locked(path):`, see [Locking](reference/locking.md) |

## Differences that trip people up

**`Session` and `FileSystem` are peers.** Neither is reached through the
other, and `FileSystem` is not a subclass of `Session`. If your previous
client had raw and filesystem-style methods on one object, pick the class
that matches the call. [One naming rule](reference/session.md#one-naming-rule)
explains the split, [Which form to use](reference/short-form.md#which-form-to-use)
when to pick which.

**Errors are exceptions.** A `FileSystem` operation raises a `WebDAVError`
subclass on an error status. It never returns `None`, `False` or a status
code. A `Session` verb raises nothing unless you call `raise_for_status()`
or create the session with `raise_on_error=True`. Code that checked a
return value needs a `try`/`except` instead.

**Nothing is overwritten by default.** `upload_file` and `download_file`
refuse to replace an existing file unless you pass `overwrite=True`.

**No credentials in the URL.** `https://user:pw@host/` is refused. Pass
`auth=` instead.
