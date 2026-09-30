# Locking (RFC 4918 Class 2)

```python
with fs.locked("Documents/report.docx") as active_lock:
    # writes made through this FileSystem (or a Session sharing its
    # connection) to the locked path automatically carry the lock token
    # in an `If` header
    fs.upload_file("report.docx", "Documents/report.docx", overwrite=True)
# lock released on exit, even if the block raised
```

`FileSystem.locked()` returns an {class}`~webdav.dav.locks.ActiveLock` describing
what the server actually granted (it may differ from what was requested -
e.g. a shorter timeout).

```{eval-rst}
.. autofunction:: webdav.fs.client.FileSystem.locked

.. autoclass:: webdav.dav.locks.ActiveLock
   :members:
```

## Refreshing a lock

A lock's timeout can be extended without releasing and re-acquiring it -
which would risk another client taking the lock in the gap between the
two (RFC 4918 §9.10.2):

```python
with fs.locked("Documents/report.docx", lock_timeout=60) as active_lock:
    ...  # still working past the original timeout
    active_lock = fs.refresh_lock(
        "Documents/report.docx", active_lock.token, lock_timeout=300
    )
```

```{eval-rst}
.. autofunction:: webdav.fs.client.FileSystem.refresh_lock
```

## What a lock is, and is not

- **Locking a URL that does not exist yet creates an empty resource** there
  (RFC 4918 §9.10.4: the server answers `201 Created`). It stays when the lock
  is released - also if the `with` block failed before writing anything.
- **A lock times out.** `lock_timeout=` (default 600 s) is a request; the server
  grants what it likes, and `active_lock.timeout` says what it granted, in seconds
  from the answer. Nothing refreshes a lock for you: once it has timed out
  (§6.6) the server drops it, the token that writes still carry no longer
  matches, and they fail with `412 Precondition Failed` - which is the safe
  way to learn the lock is gone. Refresh before that (see above), or ask for a
  longer `lock_timeout`. If the lock is already gone when the block ends, the
  release is reported in the `webdav` log ("was already gone when it was released").
- **A lock on a collection with `depth="infinity"`** (the default) covers its
  members; if one of them cannot be locked - it is locked by someone else - the
  server answers `207 Multi-Status` naming it (§9.10.6), and `locked()` raises
  a `MultiStatusError` instead of yielding a lock.
- **Releasing** (`UNLOCK`, §9.11) names the lock by its token alone - no `If`
  header - at the URL that was locked. `204` is the normal answer; `403` means
  you may not remove it; `409` that the resource was not locked (or the URL is
  outside the lock). `FileSystem.locked()` logs what it could not release
  instead of hiding it or replacing the error your block raised. If the
  session's `base_url` was pointed at another server inside the block, the
  release is refused - it would send the session's current credentials to a
  server it is no longer configured for - and the lock stays on the old server
  until it times out; release it with a `Session` for that server:
  `Session(old_base_url, auth=...).unlock(url, token)`.
- **At the protocol level** (`Session.lock()` / `unlock()`) a granted lock is
  recorded in `session.locks` - under the URL you asked for, never under a
  `lockroot` the server names - so your writes carry its token; `unlock()` drops
  it again once the server says the lock is gone (`2xx`; or `404`/`409` for the
  URL it was recorded for). A lock the server granted but the answer of which
  cannot be read is released again and the error raised, rather than left to
  block everyone until it times out. `track=False` gives you the bare answer
  instead: nothing recorded, nothing read, the token yours to keep.

## The `If` header

Writes through a held lock automatically carry an `If` header asserting
the lock token (RFC 4918 §10.4) - built by
{mod}`webdav.dav.conditional`, which is also usable directly for a custom
conditional request (e.g. an `ETag`-conditional write):

```{eval-rst}
.. automodule:: webdav.dav.conditional
   :members:
```
