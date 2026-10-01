# Session and FileSystem

Two peer classes, one rule each - neither lives inside the other, like `os`
and `pathlib.Path`. {class}`~webdav.fs.client.FileSystem` treats a server
like a local filesystem, and every one of its operations is also a
module-level one-off, exactly as `os.path.exists` is built on `os`:
`webdav.ls(url)`, `webdav.upload_file(...)` take a full URL, open a
throwaway `FileSystem`, do one thing and close it again; for several calls
use `FileSystem` itself - the names, arguments and return values are the
same (a test compares the signatures). {class}`~webdav.session.Session`
speaks the {class}`requests.Session` API - `get`, `propfind`, `lock`, ... -
for protocol-level control (the raw `Response`, a status code, a header).
It has no module-level mirror: open one explicitly with
`with webdav.Session(...) as session: ...`.

```python
import webdav

with webdav.FileSystem("https://webdav.example.org", auth=("user", "pw")) as fs:
    fs.ls("Photos")
    fs.upload_file("Gorilla.jpg", "Photos/Gorilla.jpg")

with webdav.Session("https://webdav.example.org", auth=("user", "pw")) as session:
    r = session.propfind("/Photos/", depth=1)
    r.raise_for_status()
    for href, resource in r.multistatus.responses.items():
        print(href, resource.properties.content_length)
```

## One naming rule

| Kind | Names | Returns | On an error status |
|---|---|---|---|
| **Verbs** (`Session` only, no module-level mirror) | `get`, `put`, `delete`, `head`, `options`, `propfind`, `proppatch`, `mkcol`, `copy`, `move`, `lock`, `unlock`, `request` | a {class}`~webdav.response.Response` | nothing raised, like `requests` - call `raise_for_status()`, or set `raise_on_error=True` |
| **File-system operations** (`FileSystem`, and `webdav.<name>` module-level) | `ls`, `info`, `exists`, `isdir`, `isfile`, `get_props`, `set_props`, `mkdir`, `remove`, `open`, `upload_file`, `download_file`, `locked`, ... | plain Python values | a {class}`~webdav.exceptions.WebDAVError` is raised |

A name that is an HTTP/WebDAV method behaves the same everywhere. A name
from the file-system vocabulary is a convenience that sends one or several
requests and interprets the answers.

Both kinds take a full URL - or a path, if the session/filesystem was given a
`base_url`. Verbs take a `url`, file-system operations a `path`; uploads are
`(local_path, path)`, downloads `(path, local_path)`. Everything after the first
argument(s) of a file-system operation - `props=`, `set_props=`, `data=`,
`overwrite=`, ... - is keyword-only.

## `ls`, `info` and `walk`: one type

{meth}`~webdav.fs.client.FileSystem.ls` returns a list of
{class}`~webdav.resource.Resource`, {meth}`~webdav.fs.client.FileSystem.info` returns one, and
{meth}`~webdav.fs.client.FileSystem.walk` yields `(path, directories, files)` whose members are
the same `Resource` objects - always the same fields, whatever the call. A `Resource` *is*
its name (a `str`, relative to `base_url` or to the server root without one), so it can be
passed unchanged to `info`, `remove`, `download_file`, ...; `.is_dir`, `.size`, `.modified`, `.etag`,
`.content_type`, ... carry what the server reported. `walk` yields full names, not
`os.walk`'s basenames; prune with `dirs[:] = [d for d in dirs if d != "a/tmp"]`.

## Arguments

The `Session` verbs take the same keyword arguments as `requests.Session.request`
(`auth=`, `headers=`, `timeout=`, `verify=`, `cert=`, `stream=`, ...) plus
`redirect_policy=` and `raise_on_error=` for one call. A `copy`/`move` takes
`destination=`/`overwrite=`; a `PROPFIND` takes `depth=`; a `LOCK` takes
`lock_timeout=` (not `timeout=`, which stays the network timeout). Headers
you pass yourself always win over these conveniences. The session-level
options - `redirect_policy`, `trusted_redirect_origins`,
`max_response_size`, `max_response_time`, `max_redirects`, `retry`, `chunk_size`,
`raise_on_error`, `response_class` - are
arguments of `Session(...)` and `FileSystem(...)` alike, and of the
module-level file-system functions. `response_class` is how a developer plugs
in parsing this library deliberately leaves alone (e.g. RFC 4316 `xsi:type`
hints on a property value): subclass {class}`~webdav.response.Response`,
{class}`~webdav.dav.multistatus.MultiStatusResponse`,
{class}`~webdav.dav.multistatus.ResourceResponse` and
{class}`~webdav.dav.properties.DAVProperties`, wiring each to the next via
its matching class attribute, and pass the `Response` subclass here - see
{class}`~webdav.session.Session`'s own docstring below for the full chain.

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
A full URL is used as written. What `ls` and `walk` return is what `info`,
`download_file` and the others take. Unicode is never re-normalised on the way out.

## Locks

`fs.locked(path)` (or `session.locks.add(...)` at the lower `Session` level) makes
later writes carry the `If` header of the lock. A lock on a collection - `Depth: 0`
or `infinity` - also covers adding and removing its members (RFC 4918 §7.4); such a
write gets a tagged list naming the collection. Reads never carry a token. A lock is
requested for 600 s unless you say `lock_timeout=` (`None`: infinite).

## Retries

Transient failures (429, 5xx, timeouts, dropped connections) are
retried - with exponential backoff, three attempts - for the *safe*
methods only: `GET`, `HEAD`, `OPTIONS`, `PROPFIND`. Never for a write: if the
server acted before the connection broke, the retry finds the work done and
reports the opposite (`mkdir` "exists", `remove` "not found"), and a lost `LOCK`
reply would leave an orphaned lock. When the attempts run out, the last response is
returned, as `requests` would. A `Retry-After` header (RFC 9110 §10.2.3, seconds
or an HTTP-date) is waited for when it is longer than the backoff - but a server
that asks for more than 30 s is not waited for: the failure is returned instead.
`Session(retry=False)` turns it off.

## Pickling and copying

`copy.copy(session)` and `pickle` give a session with fresh locks, caches and
TLS adapter - the last of these rebuilt from the constructor arguments you
gave, including `tls=TLSOptions(...)` (mTLS with a client certificate can be
pickled too, unlike a raw `ssl.SSLContext`). Its `auth`, headers and cookies
are copied *as they are*: a pickled session contains its credentials in clear
text - do not write it to disk or send it anywhere untrusted. (Pickling is
supported so that a session can be handed to another process - `multiprocessing`,
`concurrent.futures`, file-system front ends; it serialises the options you configured.) A callable you passed -
`trusted_redirect_origins=` or `retry=` as a function - has to be picklable
too: a module-level function, not a lambda.

## A note on `requests.Session`

`Session` is built *on* `requests`, not a subclass of `requests.Session` -
deliberately. Everything you set (`auth=`, `headers=`, `verify=`, ...) and
read (`session.cookies`, `session.hooks`, ...) works exactly as it does on a
`requests.Session`, forwarded to one it holds internally; what it does not
do is inherit `requests`' own redirect-following. WebDAV needs its own
(`requests` turns a redirected `PROPFIND` into a bodiless request, or a
`GET`, depending on the status - wrong either way; see
[Redirects](redirects.md)), and building that safely on top of an inherited
`resolve_redirects()` would mean fighting it more than using it. An
`isinstance(session, requests.Session)` check is the one thing that does not
hold; everything else about the shape of the API does.

```{eval-rst}
.. autoclass:: webdav.session.Session
   :members:

.. autoclass:: webdav.fs.client.FileSystem
   :members:

.. autoclass:: webdav.response.Response
   :members:
   :exclude-members: adopt

.. autoclass:: webdav.resource.Resource
   :members:
```
