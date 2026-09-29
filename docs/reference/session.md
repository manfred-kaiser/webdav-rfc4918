# Session and module-level API

There is one class, {class}`~webdav.session.Session` - a
{class}`requests.Session` that speaks WebDAV - and the module-level
functions built on it, exactly as `requests.get` is built on
`requests.Session`. `webdav.get(url)`, `webdav.propfind(url, depth=1)` and
`webdav.ls(url)` take a full URL, open a session, do one thing and close it
again; for several calls use a `Session` - the names, arguments and return
values are the same (a test compares the signatures). The module-level
functions also take the connection options - `auth=`, `verify=`, `timeout=`,
`retry=`, ... - as keyword arguments.

```python
import webdav

r = webdav.propfind("https://webdav.example.org/Photos/", depth=1, auth=("user", "pw"))
r.raise_for_status()
for href, resource in r.multistatus.responses.items():
    print(href, resource.properties.content_length)

with webdav.Session("https://webdav.example.org", auth=("user", "pw")) as session:
    session.ls("Photos")
    session.upload_file("Gorilla.jpg", "Photos/Gorilla.jpg")
```

## One naming rule

| Kind | Names | Returns | On an error status |
|---|---|---|---|
| **Verbs** | `get`, `put`, `delete`, `head`, `options`, `propfind`, `proppatch`, `mkcol`, `copy`, `move`, `lock`, `unlock`, `request` | a {class}`~webdav.response.Response` | nothing raised, like `requests` - call `raise_for_status()`, or set `raise_on_error=True` |
| **File-system operations** | `ls`, `info`, `exists`, `isdir`, `isfile`, `get_props`, `set_props`, `mkdir`, `remove`, `open`, `upload_file`, `download_file`, `locked`, ... | plain Python values | a {class}`~webdav.exceptions.WebDAVError` is raised |

A name that is an HTTP/WebDAV method behaves the same everywhere. A name
from the file-system vocabulary is a convenience that sends one or several
requests and interprets the answers.

Both kinds take a full URL - or a path, if the session was given a
`base_url`. Verbs take a `url`, file-system operations a `path`; uploads are
`(local_path, path)`, downloads `(path, local_path)`. Everything after the first
argument(s) of a file-system operation - `names=`, `set_props=`, `data=`,
`overwrite=`, ... - is keyword-only.

## `ls`, `info` and `walk`: one type

{meth}`~webdav.session.Session.ls` returns a list of
{class}`~webdav.resource.Resource`, {meth}`~webdav.session.Session.info` returns one, and
{meth}`~webdav.session.Session.walk` yields `(path, directories, files)` whose members are
the same `Resource` objects - always the same fields, whatever the call. A `Resource` *is*
its name (a `str`, relative to `base_url` or to the server root without one), so it can be
passed unchanged to `get`, `info`, `remove`, ...; `.is_dir`, `.size`, `.modified`, `.etag`,
`.content_type`, ... carry what the server reported. `walk` yields full names, not
`os.walk`'s basenames; prune with `dirs[:] = [d for d in dirs if d != "a/tmp"]`.

## Arguments

The verbs take the keyword arguments of {meth}`requests.Session.request`
(`auth=`, `headers=`, `timeout=`, `verify=`, `cert=`, `stream=`, ...) plus
`redirect_policy=` for one call. A `copy`/`move` takes
`destination=`/`overwrite=`; a `PROPFIND` takes `depth=`; a `LOCK` takes
`lock_timeout=` (not `timeout=`, which stays the network timeout). Headers
you pass yourself always win over these conveniences. The session-level
options - `redirect_policy`, `trusted_redirect_origins`,
`max_response_size`, `retry`, `chunk_size`, `raise_on_error` - are
arguments of `Session(...)`, and of the module-level functions.

## Limits on what a server can make the client do

`max_response_size` (constructor, default 64 MiB) caps a response body *after*
decompression, and a response with stacked content-codings is refused.
`max_response_time` (attribute, default 300 s) is a deadline for the whole
request - connecting, headers, interim `1xx` answers, body and trailers -
enforced by closing the connection when it runs out; `timeout` only limits each
single read. A streamed download (`stream=True`, `download_file`) is bounded per
read, not in size or total time: it can be as large as the server makes it.
A `HEAD`, `204` or `304` reply has no body, and its `Content-Length` is not a
reason to refuse it. Credentials in a URL (`https://user:pw@host/`) are refused
- pass `auth=`.

## Paths and names

A path is the plain name - `a%20b.txt` is a file called `a%20b.txt` - and is
percent-encoded exactly once, entirely (`%`, `?`, `#`, `;`, `+` included).
A full URL is used as written. What `ls` and `walk` return is what `get`, `info`
and the others take. Unicode is never re-normalised on the way out.

## Locks

`session.locked(path)` (or `session.locks.add(...)`) makes later writes carry the
`If` header of the lock. A lock on a collection - `Depth: 0` or `infinity` -
also covers adding and removing its members (RFC 4918 §7.4); such a write gets
a tagged list naming the collection. Reads never carry a token. A lock is
requested for 600 s unless you say `lock_timeout=` (`None`: infinite).

## Retries

Transient failures (429, 5xx, timeouts, dropped connections) are
retried - with exponential backoff, three attempts - for the *safe*
methods only: `GET`, `HEAD`, `OPTIONS`, `PROPFIND`. Never for a write: if the
server acted before the connection broke, the retry finds the work done and
reports the opposite (`mkdir` "exists", `remove` "not found"), and a lost `LOCK`
reply would leave an orphaned lock. When the attempts run out, the last response is
returned, as `requests` would. `Session(retry=False)` turns it off.

## Pickling and copying

`copy.copy(session)` and `pickle` give a session with fresh locks and caches. Its
`auth`, headers and cookies are copied *as they are*: a pickled session contains its
credentials in clear text - do not write it to disk or send it anywhere untrusted.

```{eval-rst}
.. autoclass:: webdav.session.Session
   :members:
   :exclude-members: locked, refresh_lock

.. autoclass:: webdav.response.Response
   :members:

.. autoclass:: webdav.resource.Resource
   :members:
```
