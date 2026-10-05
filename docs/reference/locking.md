# Locking

A lock reserves a resource for one client, server-side, so that writes from
other clients are refused until it is released or times out.
`FileSystem.locked()` acquires one, carries its token on every write made
through the lock, and releases it again on exit.

Use one when several people or processes may write the same file. Without
a lock, two uploads to `Documents/report.docx` both succeed, and the later
one silently replaces the earlier one. With a lock, the other writer gets
an error instead and can retry later.

Not every WebDAV server supports locks. One that does lists class `2` in
`fs.dav_compliance()`. Apache lists it also when no lock database is
configured, see [Apache: Locking](../apache-compliance-check.md#locking).

```python
import webdav

with webdav.FileSystem("https://webdav.example.org", auth=("user", "password")) as fs:
    with fs.locked("Documents/report.docx") as active_lock:
        # writes made through this FileSystem (or a Session sharing its
        # connection) to the locked path carry the lock token automatically
        fs.upload_file("report.docx", "Documents/report.docx", overwrite=True)
    # lock released on exit, even if the block raised
```

While the lock is held, a write from any other client is refused with
`423 Locked`, raised as {class}`~webdav.exceptions.ResourceLockedError`.
This also applies to a second `FileSystem`, in another process or in the
same program, because it does not hold the token:

```python
import webdav

# a second FileSystem, opened while the lock above is held
with webdav.FileSystem("https://webdav.example.org", auth=("user", "password")) as fs:
    try:
        fs.upload_file("report.docx", "Documents/report.docx", overwrite=True)
    except webdav.ResourceLockedError:
        print("report.docx is being edited by someone else, try again later")
```

The error is not retried automatically. Once the lock is released or has
timed out, the same upload succeeds.

`FileSystem.locked()` returns an {class}`~webdav.dav.locks.ActiveLock` describing
what the server actually granted. That can differ from what was requested,
e.g. a shorter timeout.

The API reference lists the arguments of `locked()` under
[FileSystem](api.md#filesystem) and the attributes of `ActiveLock` under
[Locking](api.md#locking).

## Refreshing a lock

A lock's timeout can be extended without releasing it. Releasing and
locking again would leave a gap in which another client could take the
lock.

You need this when the work under the lock can take longer than the lock
lasts. Here a job applies several batches to `Reports/inventory.csv` and
saves the file after each one, so a crash loses at most one batch. A batch
takes up to two minutes, the lock lasts five. Before each batch the job
checks how much time is left, and refreshes if the batch might not finish
in it:

```python
import time

import webdav

path = "Reports/inventory.csv"
longest_batch = 120  # seconds one batch may take
batches = [["apples,3\n"], ["pears,5\n"]]


def update_inventory(batch, local_path):
    # your own slow, local step
    with open(local_path, "a") as f:
        f.writelines(batch)


with webdav.FileSystem("https://webdav.example.org", auth=("user", "password")) as fs:
    with fs.locked(path, lock_timeout=300) as active_lock:
        expires = time.monotonic() + active_lock.timeout
        for batch in batches:
            if expires - time.monotonic() < longest_batch:
                active_lock = fs.refresh_lock(path, active_lock.token, lock_timeout=300)
                expires = time.monotonic() + active_lock.timeout
            update_inventory(batch, "inventory.csv")
            fs.upload_file("inventory.csv", path, overwrite=True)
```

A refresh starts the timeout again from the server's answer. The token
stays the same. Use the `ActiveLock` that `refresh_lock()` returns: the one
`locked()` yielded keeps its old `timeout`.

Refresh while the lock is still held. A lock that has already timed out
cannot be refreshed: the server no longer knows the token and answers
`412 Precondition Failed`, raised as
{class}`~webdav.exceptions.PreconditionFailedError`. The lock is gone then,
and the job has to lock again and check whether someone else wrote in the
meantime.

Refresh while at least the time of the next step is left. The `timeout` a server reports can already be a little lower
than the time it granted: WsgiDAV answers a request for 300 seconds with
`Second-299`. Servers also cap the timeout. WsgiDAV grants at most four
weeks, also when asked for `Infinite`. If a server does grant `Infinite`,
`active_lock.timeout` is `None` and the lock needs no refresh, so the
arithmetic above does not apply.

`refresh_lock()` is a method of [`FileSystem`](api.md#filesystem).

## What a lock is, and is not

### Locking a path that does not exist yet

Locking a URL that does not exist yet creates an empty file there. It can
stay after the lock is released, also if the `with` block failed before
writing anything.

```{admonition} Server differences
:class: note
WsgiDAV keeps the empty file. Apache creates a *lock-null* resource
instead: `GET` answers it with `404`, and releasing the lock removes it
again unless a write through the lock filled it. See
[Apache: Locking](../apache-compliance-check.md#locking).
```

### Timeouts

`lock_timeout=` (default 600 s) is a request. The server grants what it
likes, and `active_lock.timeout` says what it granted, in seconds from the
answer.

Nothing refreshes a lock for you. Once it has timed out, the server drops
it. A write to a locked file still carries the old token, which no longer
matches, and fails with `412 Precondition Failed`, raised as
{class}`~webdav.exceptions.PreconditionFailedError`. Apache and WsgiDAV
both answer this way. That error tells you the lock is gone. Refresh before
that ([see above](#refreshing-a-lock)), or ask for a longer `lock_timeout`.

A lock on a collection gives no such signal for its existing members.
After the collection's lock has timed out, a write to an existing member is
accepted, on Apache and on WsgiDAV. With a collection lock, track the
remaining time yourself instead of waiting for the `412`.

```{admonition} Server differences
:class: note
A *new* member written after the collection's lock has timed out: Apache
answers `207 Multi-Status` (`412` for the collection, `424` for the new
member, nothing created), raised as
{class}`~webdav.exceptions.MultiStatusError`. WsgiDAV creates the member.
```

If the lock is already gone when the block ends, the release is reported in
the `webdav` log ("was already gone when it was released").

### Locks on a collection

A lock on a collection with `depth="infinity"` (the default) covers its
members. If one of them is already locked by someone else, the server
grants nothing, and `locked()` raises instead of yielding a lock. Catch both
{class}`~webdav.exceptions.MultiStatusError` and
{class}`~webdav.exceptions.ResourceLockedError`:

```python
try:
    with fs.locked("Documents") as active_lock:
        ...
except (webdav.MultiStatusError, webdav.ResourceLockedError):
    print("something in Documents is locked by someone else")
```

```{admonition} Server differences
:class: note
Apache answers `207 Multi-Status`: `423` for the locked member, `424` for
the collection. `locked()` raises it as `MultiStatusError`. WsgiDAV answers
a plain `423 Locked`, raised as `ResourceLockedError`.
```

The other direction: while someone else holds a `depth="infinity"` lock on
the collection, a write to an existing member is `423 Locked`
(`ResourceLockedError`) on Apache and WsgiDAV. A write that creates a new
member differs. Apache answers `207` (`423` for the collection, `424` for
the new member), raised as `MultiStatusError`, see
[Apache: the `If` header](../apache-compliance-check.md#the-if-header-and-what-a-lock-does-to-its-neighbours).
WsgiDAV answers `423`. Catch both exceptions here as well.

### Releasing a lock

A failed release is logged. The error your block raised stays the one you
see, and a release failure is not raised on top of it.

```{admonition} For debugging
:class: note
`UNLOCK` names the lock by its token alone, at the URL that was locked.
The specification lists `204` for a release, `403` if you may not remove the
lock, and `409` if the resource was not locked or the URL is outside the
lock. Apache answers `400` for any wrong or expired token, see
[Apache: Locking](../apache-compliance-check.md#locking).
```

```{note}
If the session's `base_url` was pointed at another server inside the block,
the release is refused, because it would send the session's current
credentials to a server it is no longer configured for. The lock then stays
on the old server until it times out. Release it with a `Session` for that
server: `Session(old_base_url, auth=...).unlock(url, token)`.
```

### At the protocol level

`Session.lock()` records a granted lock in `session.locks`, so your writes
carry its token. `Session.unlock()` drops it again once the server has
released the lock. If a lock is granted but its answer cannot be read, it
is released again right away and `lock()` raises
{class}`~webdav.exceptions.MalformedResponseError`. For `session.locks`
and `track=False`, see
[Session: `lock` and `unlock`](session.md#lock-and-unlock).

## Custom conditional requests

The library builds the `If` header that carries a lock token. To build one
yourself, for example for a write that needs both a lock token and a
matching `ETag`, use {mod}`webdav.dav.conditional`. Its functions are in
the [API reference](api.md#locking).
