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
and writing files, [`FileSystem`](filesystem.md) is shorter. See
[Which form to use](short-form.md#which-form-to-use).

## All verbs and methods

Every verb takes a path relative to the base URL, or a full URL, and
returns a {class}`~webdav.response.Response`.

| Verb | Sends | Own arguments |
|---|---|---|
| `get(url)` | `GET` | `params=` |
| `head(url)` | `HEAD` | |
| `options(url)` | `OPTIONS` | |
| `put(url, data)` | `PUT` | `if_match=`, `overwrite=` |
| `delete(url)` | `DELETE` | `if_match=` |
| `propfind(url, depth=...)` | `PROPFIND` | `depth=` (required), `props=`, `all_prop=`, `prop_name=`, `include=` |
| `proppatch(url)` | `PROPPATCH` | `set_props=`, `remove_props=` |
| `mkcol(url)` | `MKCOL` | `set_props=` |
| `copy(url, destination)` | `COPY` | `overwrite=`, `depth=` |
| `move(url, destination)` | `MOVE` | `overwrite=` |
| `lock(url)` | `LOCK` | `scope=`, `owner=`, `depth=`, `lock_timeout=`, `refresh=`, `track=` |
| `unlock(url, token)` | `UNLOCK` | |
| `request(method, url)` | any method | |

The other methods:

| Method | What it does |
|---|---|
| `features_for(path)` | What the server supports, from one cached `OPTIONS` request |
| `resolve_url(path)` | The full URL a path stands for |
| `close()` | Close all connections (also done by `with`) |
| `prepare_request(request)` | Build a `requests.PreparedRequest`, as in `requests` |
| `send(prepared)` | Send one prepared request, without following redirects |
| `merge_environment_settings(...)` | Proxy and TLS settings for one request, as in `requests` |
| `mount(prefix, adapter)` | Use your own transport adapter for a URL prefix |
| `get_adapter(url)` | The transport adapter used for a URL |

`session.locks` is an attribute, not a method: the locks the session holds.

## Verbs

All verbs take the keyword arguments of `requests.Session.request`
(`auth=`, `headers=`, `timeout=`, `verify=`, `cert=`, `stream=`, ...),
plus `redirect_policy=` and `raise_on_error=` for one call. Headers you
pass yourself always win over the verb's own arguments.

The examples assume an open `session` with a base URL, as in the first
example on this page.

### Reading: `get`, `head`, `options`

```python
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

### Folders, copies, moves: `mkcol`, `copy`, `move`

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

### The `requests` methods

`prepare_request`, `send`, `merge_environment_settings`, `mount`,
`get_adapter` and `close` work as in `requests`:

```python
import requests
from webdav.transport.deadline import DeadlineAdapter

prepared = session.prepare_request(
    requests.Request("GET", session.resolve_url("Documents/Readme.md"))
)
settings = session.merge_environment_settings(prepared.url, {}, None, None, None)
r = session.send(prepared, **settings)

session.mount("https://", DeadlineAdapter(pool_maxsize=32))
session.get_adapter("https://webdav.example.org/")  # the adapter mounted above

session.close()
```

`send` does not follow redirects and does not add lock tokens. Use
`request` for that. An adapter you mount replaces the one the session set
up for that prefix, including one built from `tls=`. Mount a
`DeadlineAdapter`, as above: a plain `requests` `HTTPAdapter` is not
covered by `max_response_time`.

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

## Session options

The constructor takes the arguments of `requests` and a few of its own:

```python
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
them too. The sections below and the pages on [Redirects](redirects.md)
and [TLS and mTLS](tls.md) explain them.

`response_class` is how a developer plugs in parsing this library
deliberately leaves alone (e.g. RFC 4316 `xsi:type` hints on a property
value): subclass {class}`~webdav.response.Response`,
{class}`~webdav.dav.multistatus.MultiStatusResponse`,
{class}`~webdav.dav.multistatus.ResourceResponse` and
{class}`~webdav.dav.properties.DAVProperties`, wiring each to the next via
its matching class attribute, and pass the `Response` subclass here. The
{class}`~webdav.session.Session` entry in the
[API reference](api.md#session) describes the full chain.

## Limits on what a server can make the client do

These limits apply to a `Session`, a `FileSystem` and the short form alike.

- **`max_response_size`** (constructor, default 64 MiB) caps a response body
  *after* decompression. A response with stacked content-codings is refused.
- **`max_response_time`** (attribute, default 300 s) is a deadline for the
  whole request - connecting, headers, interim `1xx` answers, body and
  trailers - enforced by closing the connection when it runs out. `timeout`
  only limits each single read.
- **A streamed download** (`stream=True`, `download_file`) is bounded per
  read, not in size or total time: it can be as large as the server makes it.
- A `HEAD`, `204` or `304` reply has no body, and its `Content-Length` is not
  a reason to refuse it.
- Credentials in a URL (`https://user:pw@host/`) are refused - pass `auth=`.

```{warning}
`auth=` is only encrypted on the wire if `base_url` (or the URL you call) is
`https://`. Over a plain `http://` URL the username and password go out in
clear text on the very first request, not only across a redirect to such a
URL - anyone on the network path can read them. The session warns once per
host (`InsecureTransportWarning`, skipped only for localhost) when this
happens, but still sends the request; use an `https://` URL instead of
relying on the warning.
```

## Retries

Transient failures (429, 5xx, timeouts, dropped connections) are retried -
with exponential backoff, three attempts - for the *safe* methods only:
`GET`, `HEAD`, `OPTIONS`, `PROPFIND`.

Never for a write: if the server acted before the connection broke, the retry
finds the work done and reports the opposite (`mkdir` "exists", `remove`
"not found"), and a lost `LOCK` reply would leave an orphaned lock. When the
attempts run out, the last response is returned, as `requests` would.

A `Retry-After` header (RFC 9110 §10.2.3, seconds or an HTTP-date) is waited
for when it is longer than the backoff - but a server that asks for more
than 30 s is not waited for: the failure is returned instead.
`Session(retry=False)` turns it off.

## Pickling and copying

`copy.copy(session)` and `pickle` give a session with fresh locks, caches
and TLS adapter. Pickling exists so a session can be handed to another
process - `multiprocessing`, `concurrent.futures`, file-system front ends; it
serialises the options you configured.

- The TLS adapter is rebuilt from the constructor arguments you gave,
  including `tls=TLSOptions(...)` - mTLS with a client certificate can be
  pickled too, unlike a raw `ssl.SSLContext`.
- Its `auth`, headers and cookies are copied *as they are*.
- A callable you passed (`trusted_redirect_origins=` or `retry=` as a
  function) has to be picklable too: a module-level function, not a lambda.

```{warning}
A pickled `Session`/`FileSystem` contains its credentials in clear text.
Never write it to disk or send it anywhere untrusted.
```

## A note on `requests.Session`

`Session` is built *on* `requests`, not a subclass of `requests.Session` -
deliberately.

- Everything you set (`auth=`, `headers=`, `verify=`, ...) and read
  (`session.cookies`, `session.hooks`, ...) works exactly as it does on a
  `requests.Session`, forwarded to one it holds internally.
- What it does not do is inherit `requests`' own redirect-following. WebDAV
  needs its own: `requests` turns a redirected `PROPFIND` into a bodiless
  request, or a `GET`, depending on the status - wrong either way (see
  [Redirects](redirects.md)). Building that safely on top of an inherited
  `resolve_redirects()` would mean fighting it more than using it.

An `isinstance(session, requests.Session)` check is the one thing that does
not hold; everything else about the shape of the API does.

The full list of methods, attributes and arguments is in the
[API reference](api.md#session).
