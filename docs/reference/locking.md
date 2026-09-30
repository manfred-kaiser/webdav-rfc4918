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

## The `If` header

Writes through a held lock automatically carry an `If` header asserting
the lock token (RFC 4918 §10.4) - built by
{mod}`webdav.dav.conditional`, which is also usable directly for a custom
conditional request (e.g. an `ETag`-conditional write):

```{eval-rst}
.. automodule:: webdav.dav.conditional
   :members:
```
