# Performance and concurrency

Measured locally against a real WsgiDAV instance (not simulated), to
answer two questions: how fast is a transfer, and what actually breaks
under concurrent load.

## A single large transfer

A 1 GiB upload/download round-trip, verified byte-for-byte (SHA-256):

| | Throughput | Peak RSS |
|---|---|---|
| Upload | ~565 MB/s | 57 MB |
| Download | ~319 MB/s | 57 MB |

The low, flat memory figure confirms `upload_file`/`download_file` truly
stream through `chunk_size` (4 MiB default) rather than buffering the
whole file - the number does not grow with file size.

## Connection pool size: not the bottleneck

`Session` mounts its `HTTPAdapter` with no explicit `pool_maxsize`, so it
inherits `requests`'/`urllib3`'s default of 10 connections per host. That
looks like an obvious thing to tune up for high concurrency - it isn't,
in practice: flooding a shared `Session` with 50 threads performed
*identically* (if anything, slightly worse) after mounting a custom
adapter with `pool_maxsize=100`:

```python
from webdav.transport.deadline import DeadlineAdapter

session.mount("https://", DeadlineAdapter(pool_connections=20, pool_maxsize=100))
session.mount("http://", DeadlineAdapter(pool_connections=20, pool_maxsize=100))
```

| Pool size | Throughput (50 threads x 20 requests) |
|---|---|
| 10 (default) | ~297 req/s |
| 100 (mounted) | ~252 req/s |

The ceiling under concurrent load is the *server's* own capacity (a
single-process WsgiDAV/cheroot instance, bound by Python's GIL for
request handling), not the client's connection pool. A real deployment
target that handles requests across multiple processes (Apache, nginx)
should scale further before hitting a client-side limit - this project's
own Apache/nginx compliance suites run the same library against exactly
those, just not at this concurrency.

## Locking under contention: correct, not silently retried

50 threads, each acquiring and releasing an exclusive lock on the same
path 10 times in a tight loop (500 attempts total): no deadlocks, no
corrupted lock bookkeeping (`session.locks` is empty once every thread
finishes), and lock conflicts are reported correctly as
{class}`~webdav.exceptions.ResourceLockedError`.

Under this load, a small number of `LOCK`/`PUT`/`UNLOCK` calls got a
transient `requests.exceptions.ConnectionError` (the server resetting an
overloaded connection) that propagated to the caller instead of being
retried. **This is deliberate**, not a gap: `retry=True` (the default)
only retries safe, idempotent methods -

```python
RETRYABLE_METHODS = frozenset({Method.GET, Method.HEAD, Method.OPTIONS, Method.PROPFIND})
```

(`webdav.methods`) - `LOCK`, `UNLOCK`, `PUT`, `MKCOL`, `COPY`, `MOVE` and
`PROPPATCH` are excluded on purpose. Blindly retrying a `LOCK` whose
response was lost risks acquiring it twice (or masking a genuine
conflict); blindly retrying an `UNLOCK` that actually succeeded risks a
confusing `409` on the retry for a lock that is already gone. A caller
doing heavy concurrent locking and wanting resilience against transient
connection failures needs to catch `requests.exceptions.ConnectionError`
around those specific calls itself - the library will not paper over it.

## Many concurrent large transfers: memory scales with concurrency, predictably

8 independent `FileSystem` instances, each uploading and downloading its
own 100 MiB file concurrently (disk-based, not held in memory by the
caller): all 8 checksums matched, ~219 MB/s aggregate throughput, and
peak RSS grew by about 90 MB per concurrent transfer (not per megabyte
transferred) - consistent with each connection's own chunk buffers and
`requests`/`urllib3` overhead, not a leak. Plan memory for concurrent
large transfers roughly as *(number of simultaneous transfers) x 90 MB*,
not as a function of file size.

## Summary

| Question | Answer |
|---|---|
| Does a large transfer stream, or buffer the whole file? | Streams - flat ~57 MB regardless of file size |
| Is the default connection pool size a bottleneck? | No - a 10x larger pool made no measurable difference |
| Is lock bookkeeping safe under heavy concurrent contention? | Yes - no corruption, no deadlocks, observed under 500 concurrent attempts |
| Are LOCK/PUT/UNLOCK retried on a dropped connection? | No, deliberately - only GET/HEAD/OPTIONS/PROPFIND are |
| Does memory blow up with many concurrent large transfers? | No - grows linearly with concurrency, not file size |

## Against Apache `mod_dav`

One local run against an Apache 2.4.69 (prefork, default settings, loopback, no
TLS), to see what the WsgiDAV numbers above do on the deployment target. The
figures are a local sanity check, not a benchmark; correctness under the same
load is pinned by `tests/test_apache_compliance.py` (see
[Apache `mod_dav` compliance check](../apache-compliance-check.md)).

| | Result |
|---|---|
| 256 MiB upload / download, byte for byte (SHA-256) | ~690 MiB/s / ~1260 MiB/s |
| Upload of unknown length (`Transfer-Encoding: chunked`), 32 MiB | complete |
| 3000 members in one collection: `ls()` / `walk()` | 0.16 s each |
| `DELETE` of that collection | 0.03 s |
| 32 threads, 2 MiB upload each, one shared `FileSystem` | 32 of 32 intact |
| 100 threads, one `LOCK` each on 100 different files | 100 of 100 granted, 2.9 s |
| 32 threads, `LOCK` on one file | exactly 1 granted, 31 x `423` |

These were measured on an Apache built with sdbm as its DBM. On Debian and Ubuntu (Berkeley DB) locks and
properties set by many clients at once can be lost - see "The DBM type decides" in the compliance check.

Where Apache differs from WsgiDAV under load is not speed but what the losers of
a race are told, and what its DBM files keep: see "Parallel", "The DBM type decides"
and "Over time" in the compliance check - in particular that `If-None-Match: *` is
not atomic, and that an unreleased lock on a name nothing was written to breaks the
next listing of its collection.
