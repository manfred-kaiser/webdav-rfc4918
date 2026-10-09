# Session

A {class}`~webdav.session.Session` works at the protocol level. It has one
method per HTTP and WebDAV verb, returns the server's answer as a
{class}`~webdav.response.Response`, and works like a `requests.Session`.

```python
import webdav

with webdav.Session("https://webdav.example.org", auth=("user", "password")) as session:
    r = session.propfind("/Photos/", depth=1)
    r.raise_for_status()
    for href, resource in r.multistatus.responses.items():
        print(href, resource.properties.content_length)
```

Use a `Session` when you need the status code, a header or the raw
multistatus, or a request the file operations do not cover. For reading
and writing files, [`FileSystem`](filesystem.md) is shorter. It is built
on a `Session`, and the [short form](short-form.md) is built on
`FileSystem`. See [Which form to use](../quickstart.md#which-form-to-use)
for how the three layers fit together.

## All verbs and methods

Every verb sends the HTTP method of the same name, takes a path relative
to the base URL or a full URL, and returns a
{class}`~webdav.response.Response`.

| Verb | What it does | Own arguments |
|---|---|---|
| **[Reading](#reading-get-head-options)** | | |
| `get(url)` | Fetch a file's body | `params=` |
| `head(url)` | Headers only, no body | |
| `options(url)` | The methods and `DAV:` classes the server allows | |
| **[Writing](#writing-put-and-delete)** | | |
| `put(url, data)` | Create or replace a file | `if_match=`, `overwrite=` |
| `delete(url)` | Delete a file, or a folder with everything in it | `if_match=` |
| **[Properties](#properties-propfind-and-proppatch)** | | |
| `propfind(url, depth=...)` | Read properties, of the members too with `depth=1` | `depth=` (required), `props=`, `all_prop=`, `prop_name=`, `include=` |
| `proppatch(url)` | Set or remove properties | `set_props=`, `remove_props=` |
| **[Folders, copies and moves](#folders-copies-and-moves-mkcol-copy-move)** | | |
| `mkcol(url)` | Create a folder | `set_props=` |
| `copy(url, destination)` | Copy on the server, replaces only with `overwrite=True` | `overwrite=`, `depth=` |
| `move(url, destination)` | Move or rename on the server, replaces only with `overwrite=True` | `overwrite=` |
| **[Locks](#lock-and-unlock)** | | |
| `lock(url)` | Take or refresh a lock, 600 s unless `lock_timeout=` | `scope=`, `owner=`, `depth=`, `lock_timeout=`, `refresh=`, `track=` |
| `unlock(url, token)` | Release a lock | |
| **[Any other method](#any-other-method-request)** | | |
| `request(method, url)` | Send any method, e.g. `REPORT` | |

The other methods:

| Method | What it does |
|---|---|
| `features_for(path="")` | What the server supports, as a {class}`~webdav.dav.features.FeatureDetection`, from one cached `OPTIONS` request |
| `resolve_url(path)` | The full, percent-encoded URL a path stands for |
| `mount(prefix, adapter)` | Use your own transport adapter for a URL prefix |
| `close()` | Close all connections (also done by `with`) |

`session.locks` is an attribute: the locks the session holds. The session
also has `prepare_request`, `send`, `merge_environment_settings` and
`get_adapter`, which work as on a `requests.Session`. You rarely need
them. Their signatures are in the [API reference](api.md#session).

## One naming rule

A name that is an HTTP or WebDAV method behaves the same everywhere. A
name from the file-system vocabulary is a convenience that sends one or
several requests and interprets the answers.

| | Verbs | File operations |
|---|---|---|
| Names | `get`, `propfind`, `lock`, ... | `ls`, `info`, `upload_file`, `locked`, ... |
| Available on | `Session` only | `FileSystem` and the [short form](short-form.md) |
| First argument | `url` | `path` |
| Returns | a `Response` | plain Python values |
| On an error status | raises nothing, like `requests` | raises a {class}`~webdav.exceptions.WebDAVError` |

Both take a full URL, or a path if the session or filesystem was given a
base URL. Uploads are `(local_path, path)`, downloads
`(path, local_path)`. Everything after the first argument(s) of a file
operation (`props=`, `set_props=`, `data=`, `overwrite=`, ...) is
keyword-only.

## Responses and errors

Every verb returns a `Response`: a `requests.Response` with the parsed
WebDAV body on top, `.multistatus` and `.active_lock`. An error status
raises nothing by default:

```python
import webdav

with webdav.Session("https://webdav.example.org", auth=("user", "password")) as session:
    r = session.get("Documents/missing.txt")
    r.status_code                   # 404
    r.raise_for_status()            # raises ResourceNotFoundError
```

`raise_for_status()` raises the matching
{class}`~webdav.exceptions.WebDAVError` subclass, listed in
[Exceptions](exceptions.md). To raise on every error status, create the
session with `raise_on_error=True`. A single call can switch it back off:

```python
with webdav.Session(
    "https://webdav.example.org", auth=("user", "password"), raise_on_error=True
) as session:
    session.delete("Documents/old.txt", raise_on_error=False)
```

## Verbs

All verbs take the keyword arguments of `requests.Session.request`
(`auth=`, `headers=`, `timeout=`, `verify=`, `cert=`, `stream=`, ...),
plus `redirect_policy=` and `raise_on_error=` for one call. Headers you
pass yourself always win over the verb's own arguments.

The first block below is complete. The blocks after it, in all sections
under Verbs, reuse its `session`, which has a base URL.

### Reading: `get`, `head`, `options`

```python
import webdav

with webdav.Session("https://webdav.example.org", auth=("user", "password")) as session:
    r = session.get("Documents/Readme.md")
    print(r.text)

    r = session.head("Documents/Readme.md")
    print(r.headers["Content-Length"])

    r = session.options("/")
    print(r.headers["DAV"])  # "1, 2"
```

### Writing: `put` and `delete`

```python
session.put("Documents/a.txt", data=b"abc", headers={"Content-Type": "text/plain"})

r = session.put("Documents/a.txt", data=b"xyz", overwrite=False)
r.status_code  # 412: a.txt exists, nothing was replaced

etag = session.head("Documents/a.txt").headers["ETag"]
session.put("Documents/a.txt", data=b"abcd", if_match=etag)

session.delete("Documents/a.txt")
```

`overwrite=False` only creates the file. `if_match=` only replaces or
deletes it if its ETag is still the one you read.

### Properties: `propfind` and `proppatch`

```python
r = session.propfind("Documents/Readme.md", depth=0, props=["etag", "modified"])
for href, resource in r.multistatus.responses.items():
    print(href, resource.properties.etag, resource.properties.modified)

session.proppatch(
    "Documents/Readme.md",
    set_props={"{https://example.org/ns}color": "blue"},
    remove_props=["{https://example.org/ns}size"],
)
```

`propfind` has no default for `depth=`: `0` is the resource, `1` adds its
direct members. Without `props=` it asks for all properties.

### Folders, copies and moves: `mkcol`, `copy`, `move`

```python
session.mkcol("Archive")
session.copy("Documents/Readme.md", destination="Archive/Readme.md")
session.move("Archive/Readme.md", destination="Archive/Readme-old.md", overwrite=True)
session.delete("Archive")
```

`copy` and `move` send `Overwrite: F` unless you pass `overwrite=True`, so
an existing destination is answered with `412`.

### `lock` and `unlock`

```python
r = session.lock("Documents/report.docx", lock_timeout=60, timeout=10)
token = r.active_lock.token

session.put("Documents/report.docx", data=b"new")  # carries the lock token
session.lock("Documents/report.docx", refresh=token, lock_timeout=300)
session.unlock("Documents/report.docx", token)
```

`lock_timeout=` is the lock's timeout, `timeout=` stays the network
timeout. `refresh=` extends a lock you hold. A granted lock is recorded in
`session.locks`, and later writes to that URL carry its token. To use a
token you got elsewhere:

```python
session.locks.add(session.resolve_url("Documents/report.docx"), token, "infinity")
```

`lock(..., track=False)` records nothing and leaves the token to you.

### Any other method: `request`

```python
body = (
    '<?xml version="1.0"?>'
    '<D:version-tree xmlns:D="DAV:"><D:prop><D:version-name/></D:prop></D:version-tree>'
)
r = session.request(
    "REPORT",
    "Documents/Readme.md",
    data=body,
    headers={"Content-Type": "application/xml", "Depth": "0"},
)
r.status_code  # 405 on a server without versioning (RFC 3253)
```

`request` sends any method with the same handling as the verbs: base URL,
lock tokens, redirects, retries and limits.

### Server features and URLs

```python
features = session.features_for()
features.dav_compliances  # frozenset({"1", "2"})
features.supports_ranges  # True if OPTIONS says "Accept-Ranges: bytes"

session.resolve_url("Documents/a b.txt")  # "https://webdav.example.org/Documents/a%20b.txt"
```

`features_for` asks once per server and remembers the answer.
`FileSystem.dav_compliance` asks every time.

### Your own transport adapter: `mount`

```python
from webdav.transport.deadline import DeadlineAdapter

session.mount("https://", DeadlineAdapter(pool_maxsize=32))
```

A mounted adapter replaces
the one the session set up for that prefix, including one built from
`tls=`. Use a {class}`~webdav.transport.deadline.DeadlineAdapter`. A plain
`requests` `HTTPAdapter` is not covered by `max_response_time`.

```{tip}
`pool_maxsize=32` is only an example value. Without it, the pool holds
the `requests` default of 10 connections per host. With 50 threads on one
shared session, a pool of 100 was slower than the default (~252 vs. ~297
requests/s). Raise it only when a deployment is shown to be limited by it.
```

## Session options

The constructor takes the arguments of `requests` and a few of its own:

```python
import webdav

session = webdav.Session(
    "https://webdav.example.org",
    auth=("user", "password"),
    timeout=30,
    max_response_size=16 * 1024 * 1024,
    retry=False,
)
```

The options of this library are `redirect_policy`,
`trusted_redirect_origins`, `max_response_size`, `max_response_time`,
`max_redirects`, `retry`, `chunk_size`, `raise_on_error` and
`response_class`. `FileSystem(...)` and every short-form function take
them too. The next sections explain the limits and retries. Redirects and
certificates have their own pages: [Redirects](redirects.md) and
[TLS and mTLS](tls.md).

`response_class` lets you add parsing this library leaves out on purpose,
for example RFC 4316 `xsi:type` hints on a property value. Subclass
{class}`~webdav.response.Response`,
{class}`~webdav.dav.multistatus.MultiStatusResponse`,
{class}`~webdav.dav.multistatus.ResourceResponse` and
{class}`~webdav.dav.properties.DAVProperties`, link each to the next through
its matching class attribute, and pass the `Response` subclass here. The
{class}`~webdav.session.Session` entry in the
[API reference](api.md#session) describes the full chain.

## Limits on what a server can make the client do

These limits apply to a `Session`, a `FileSystem` and the short form alike.

- `max_response_size` (default 64 MiB) caps a response body after
  decompression. A response with stacked content-codings is refused.
- `max_response_time` (default 300 s) is a deadline for the whole request:
  connecting, headers, interim `1xx` answers, body and trailers. Every
  socket wait is capped to the time left, so no extra thread is started.
  When the time is up, the request fails with a `ClientError`. `timeout`
  only limits each single read.
- A streamed download (`stream=True`, `download_file`) is bounded per read
  only. It can be as large and take as long as the server makes it.
- Credentials in a URL (`https://user:pw@host/`) are refused. Pass `auth=`.

Both limits are constructor arguments and can also be set later as
attributes, e.g. `session.max_response_time = 60`.

```{warning}
`auth=` is only encrypted on the wire if `base_url` (or the URL you call) is
`https://`. Over plain `http://`, the username and password go out in clear
text with the very first request, not only after a redirect, and anyone on
the network path can read them. The session warns once per host
(`InsecureTransportWarning`, except for localhost) but still sends the
request. Use an `https://` URL.
```

## Retries

Transient failures (429, 5xx, timeouts, dropped connections) are retried
for the safe methods only: `GET`, `HEAD`, `OPTIONS`, `PROPFIND`. There
are three attempts, with exponential backoff.

Writes are never retried. If the server acted before the connection broke,
a retry would find the work done and report the opposite (`mkdir` "exists",
`remove` "not found"). A lost `LOCK` reply would leave an orphaned lock.
When the attempts run out, the last response is returned, as `requests`
does.

A `Retry-After` header (seconds or an HTTP-date) is honoured when it is
longer than the backoff, up to 30 s. If the server asks for more, the
failure is returned instead. `Session(retry=False)` turns retries off.

Because `LOCK`, `PUT` and `UNLOCK` are not retried, a dropped connection
reaches the caller. In a test with 50 threads making 500 lock/release
attempts on one path, the lock bookkeeping stayed consistent and nothing
deadlocked, but a few calls got a `requests.exceptions.ConnectionError`
from the overloaded server. Under heavy concurrent locking, catch it
around those calls yourself.

## Pickling and copying

`copy.copy(session)` and `pickle` give a session with fresh locks, caches
and TLS adapter. Pickling lets you hand a session to another process
(`multiprocessing`, `concurrent.futures`, file-system front ends). It
serialises the options you configured.

- The TLS adapter is rebuilt from your constructor arguments, including
  `tls=TLSOptions(...)`. So mTLS with a client certificate can be pickled.
  A raw `ssl.SSLContext` cannot.
- `auth`, headers and cookies are copied as they are.
- A callable you passed (`trusted_redirect_origins=` or `retry=` as a
  function) has to be picklable too: a module-level function, not a lambda.

```{warning}
A pickled `Session`/`FileSystem` contains its credentials in clear text.
Never write it to disk or send it anywhere untrusted.
```

## A note on `requests.Session`

`Session` is built on `requests`, but is not a subclass of
`requests.Session`.

- Everything you set (`auth=`, `headers=`, `verify=`, ...) and read
  (`session.cookies`, `session.hooks`, ...) works as on a
  `requests.Session`. It is forwarded to one the session holds internally.
- Redirects are handled by this library, not by `requests`, see
  [Redirects](redirects.md).
- `send` sends one prepared request as is. It does not follow redirects
  and does not add lock tokens. Use `request` for that.

The one visible difference: `isinstance(session, requests.Session)` is
`False`.

The full list of methods, attributes and arguments is in the
[API reference](api.md#session).
