# Locking (RFC 4918 Class 2)

```python
with client.lock("Documents/report.docx") as active_lock:
    # writes made through this client to the locked path automatically
    # carry the lock token in an `If` header
    client.upload_file("report.docx", "Documents/report.docx", overwrite=True)
# lock released on exit, even if the block raised
```

`Client.lock()` returns an {class}`~webdav.locks.ActiveLock` describing
what the server actually granted (it may differ from what was requested -
e.g. a shorter timeout).

```{eval-rst}
.. autofunction:: webdav.client.Client.lock

.. autoclass:: webdav.locks.ActiveLock
   :members:
```

## The `If` header

Writes through a held lock automatically carry an `If` header asserting
the lock token (RFC 4918 §10.4) - built by
{mod}`webdav.conditional`, which is also usable directly for a custom
conditional request (e.g. an `ETag`-conditional write):

```{eval-rst}
.. automodule:: webdav.conditional
   :members:
```
