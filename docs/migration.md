# Migrating from another WebDAV client

This page is for readers who already know a different Python WebDAV client
and want the concepts mapped over, not a from-scratch introduction. If
you're starting fresh, see the [quickstart](index.md) instead.

Why switch: the test suite runs 1500+ tests with over 90% code coverage,
including 70+ tests dedicated to the security defaults (TLS verification
on, same-origin redirects only, size limits on buffered responses - see
[Session](reference/session.md)), and is checked in CI on every commit
against four real servers (Nextcloud, Apache `mod_dav`, nginx, WsgiDAV). See the
project `README.md` for the current numbers and server matrix.

## Concept mapping

| If your previous library had this pattern... | ...the equivalent here is |
|---|---|
| Keep a connection/client object open across calls | {class}`~webdav.fs.client.FileSystem` or {class}`~webdav.session.Session` as a context manager (`with webdav.FileSystem(...) as fs:`) |
| A one-off call with no connection object | A module-level function: `webdav.ls(url)`, `webdav.upload_file(...)`, etc. - same names and arguments as `FileSystem`, opening and closing a throwaway one internally |
| Raw status codes / headers / response bodies | `Session` verbs (`get`, `propfind`, `lock`, ...) - return a {class}`~webdav.response.Response`, raise nothing by default |
| Filesystem-style paths and directory listings | `FileSystem` operations (`ls`, `info`, `walk`, ...) - return {class}`~webdav.resource.Resource` objects, raise a {class}`~webdav.exceptions.WebDAVError` subclass on error |
| Catching library-specific errors | The `WebDAVError` hierarchy - see [Exceptions](reference/exceptions) |

See [Session and FileSystem](reference/session.md) for the full rule behind
the verbs/file-system-operations split, and [Locking](reference/locking.md)
for `locked()`.

## Things that trip people up

**`Session` and `FileSystem` are peers.** `Session` is not reached through
`FileSystem`, and `FileSystem` is not a subclass of `Session`. A previous
client that exposed both raw and filesystem-like operations on the same
object won't map one-to-one here; expect to pick the class that matches
what you're calling.

**Errors come back as exceptions.** A `FileSystem` operation (`ls`, `info`,
`upload_file`, ...) raises a `WebDAVError` subclass on an error status
rather than returning `None`, `False`, or a raw status code. A `Session`
verb, by contrast, raises nothing by default -
call `raise_for_status()` on the `Response`, or construct the session with
`raise_on_error=True`. If your previous client's error handling relied on
checking a return value or a status code attribute, that check needs to
become a `try`/`except` around the `FileSystem` call, or an explicit
`raise_for_status()` after a `Session` verb.

## See also

- [Session and FileSystem](reference/session.md)
- [Locking](reference/locking.md)
- [fsspec](reference/fsspec.md)
- [Exceptions](reference/exceptions)
