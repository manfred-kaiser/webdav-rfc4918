# FileSystem

A {class}`~webdav.fs.client.FileSystem` treats a WebDAV server like a
local filesystem. It keeps one connection open for several calls, and
paths are relative to the URL you gave it.

```python
import webdav

with webdav.FileSystem("https://webdav.example.org", auth=("user", "password")) as fs:
    fs.ls("Photos")
    fs.upload_file("Gorilla.jpg", "Photos/Gorilla.jpg")
    fs.download_file("Documents/Readme.md", "Readme.md")
```

The methods have the same names, arguments and return values as the
[short form](short-form.md). A `FileSystem` sends its requests through a
[`Session`](session.md), and the short form opens a `FileSystem` for each
call. [Which form to use](../quickstart.md#which-form-to-use) explains the
three layers and when to use which.

## All methods

Paths are relative to the base URL. Uploads take the local path first.

| Method | What it does | Returns |
|---|---|---|
| **[Opening and closing](#opening-and-closing)** | | |
| `FileSystem(base_url, ...)` | Open a connection, takes the [Session options](session.md#session-options) | `FileSystem` |
| `FileSystem.from_session(session)` | Wrap an existing `Session` and share its connection | `FileSystem` |
| `close()` | Close the connection (also done by `with`) | `None` |
| `session` | Attribute: the `Session` underneath | {class}`~webdav.session.Session` |
| **[Listing and checking](#listing-and-checking)** | | |
| `ls(path)` | List the members of a folder | list of {class}`~webdav.resource.Resource` |
| `info(path)` | Describe one file or folder | {class}`~webdav.resource.Resource` |
| `walk(path)` | Go through a folder tree, like `os.walk` | iterator of `(path, dirs, files)` |
| `exists(path)` | Is something there? | `bool` |
| `isdir(path)` | Is it a folder? | `bool` |
| `isfile(path)` | Is it a file? | `bool` |
| **[Reading and writing](#reading-and-writing)** | | |
| `upload_file(local_path, path)` | Upload a local file | `None` |
| `download_file(path, local_path)` | Download to a local file | `None` |
| `upload_fileobj(fileobj, path)` | Upload from an open binary file object | `None` |
| `download_fileobj(path, fileobj)` | Download into an open binary file object | `None` |
| `open(path, mode="r")` | Read or write like the builtin `open` | file object, in a `with` block |
| **[Folders, copies and moves](#folders-copies-and-moves)** | | |
| `mkdir(path)` | Create a folder | `None` |
| `copy(path, destination)` | Copy on the server | `None` |
| `move(path, destination)` | Move or rename on the server | `None` |
| `remove(path)` | Delete a file, or a folder with everything in it | `None` |
| **[Properties](#properties)** | | |
| `get_props(path, props=...)` | Several properties in one request | {class}`~webdav.dav.properties.DAVProperties` |
| `set_props(path, set_props=...)` | Set or remove properties | `None` |
| `content_length(path)` | Size in bytes (`getcontentlength`) | `int \| None` |
| `content_type(path)` | MIME type (`getcontenttype`) | `str \| None` |
| `content_language(path)` | Language tag (`getcontentlanguage`) | `str \| None` |
| `created(path)` | Creation time (`creationdate`) | `datetime \| None` |
| `modified(path)` | Last modification time (`getlastmodified`) | `datetime \| None` |
| `etag(path)` | ETag as the server sends it (`getetag`) | `str \| None` |
| `dav_compliance(path="")` | WebDAV classes of the server, one `OPTIONS` per call | `set[str]` |
| **[Locks](#locks)** | | |
| `locked(path)` | Hold a lock for a `with` block, 600 s unless `lock_timeout=` | {class}`~webdav.dav.locks.ActiveLock`, in a `with` block |
| `refresh_lock(path, token)` | Extend the timeout of a held lock | {class}`~webdav.dav.locks.ActiveLock` |

`None` from a property method means the server did not report that
property. The first block of each section below is complete. The blocks
after it in the same section reuse its `fs`.

## Opening and closing

`FileSystem(...)` takes exactly the arguments of
[`Session(...)`](session.md): a base URL, `auth=`, `timeout=`, `verify=`
and so on. The `with` block closes the connection at the end. Without
`with`, call `fs.close()` yourself.

```python
import webdav

fs = webdav.FileSystem("https://webdav.example.org", auth=("user", "password"))
fs.exists("Documents/Readme.md")
fs.close()
```

Without a base URL, every method takes a full URL instead of a path.

If you already have a `Session`, wrap it:

```python
session = webdav.Session("https://webdav.example.org", auth=("user", "password"))
fs = webdav.FileSystem.from_session(session)
fs.session is session  # True
```

Both then share one connection, the cookies and the locks. Closing `fs`
does not close `session`. `fs.session` gives you the session of any
`FileSystem`, for the occasional raw request.

## Listing and checking

```python
import webdav

with webdav.FileSystem("https://webdav.example.org", auth=("user", "password")) as fs:
    for resource in fs.ls("Photos"):
        print(resource, resource.is_dir, resource.size, resource.modified)

    readme = fs.info("Documents/Readme.md")
    fs.download_file(readme, "Readme.md", overwrite=True)

    fs.exists("Documents/Readme.md")  # True
    fs.isdir("Photos")                # True
    fs.isfile("Photos")               # False
```

{meth}`~webdav.fs.client.FileSystem.ls` returns a list of
{class}`~webdav.resource.Resource` objects, `info` returns one. A
`Resource` *is* its name: a `str`, relative to the base URL (or to the
server root without one). You can pass it unchanged to `info`, `remove`,
`download_file` and the others. Its attributes carry what the server
reported: `.is_dir`, `.size`, `.modified`, `.created`, `.etag`,
`.content_type`, `.content_language`, `.display_name`.

`ls` on a file raises `IsAResourceError`. Use `info` to describe a single
resource.

```python
for path, dirs, files in fs.walk("Photos"):
    if "Photos/tmp" in dirs:
        dirs.remove("Photos/tmp")  # skip this subtree
    for f in files:
        print(f, f.size)
```

`walk` works like `os.walk`, but `dirs` and `files` hold the same
`Resource` objects as `ls`, with full names instead of basenames. Remove a
name from `dirs` to skip that subtree. `max_depth=` limits how deep it
goes. Each folder costs one request.

## Reading and writing

```python
import webdav

with webdav.FileSystem("https://webdav.example.org", auth=("user", "password")) as fs:
    fs.upload_file("Gorilla.jpg", "Photos/Gorilla.jpg", overwrite=True)
    fs.download_file("Documents/Readme.md", "Readme.md", overwrite=True)

    with fs.open("Documents/Notes.txt", "w") as f:
        f.write("Buy bananas\n")

    with fs.open("Documents/Notes.txt") as f:
        print(f.read())

    with fs.open("Photos/Gorilla.jpg", "rb") as f:
        header = f.read(16)

    with fs.open("Documents/New.txt", "x") as f:
        f.write("created only if nothing is there\n")
```

Uploads take `(local_path, path)`, downloads `(path, local_path)`. Without
`overwrite=True`, an existing target is an error:
`ResourceAlreadyExistsError` on the server, `FileExistsError` locally. A
download goes to a temporary file first and only a complete one is moved
into place. It never writes through a symlink.

`open` takes the modes of the builtin `open`. A write is uploaded only when
the `with` block ends without an exception, so a failed block never leaves
a half-written file on the server. `"x"` creates the file only if nothing
is there yet.

`upload_fileobj` and `download_fileobj` take an open binary file object
instead of a local path:

```python
import io

fs.upload_fileobj(io.BytesIO(b"hello"), "Documents/hello.txt")

buffer = io.BytesIO()
fs.download_fileobj("Documents/hello.txt", buffer)
buffer.getvalue()  # b"hello"
```

The transfer methods also take `chunk_size=` and a `callback=` that is
called with the number of bytes of each chunk, for a progress bar:

```python
fs.upload_file("Gorilla.jpg", "Photos/Gorilla.jpg", overwrite=True, callback=print)
```

Transfers stream in `chunk_size` pieces (4 MiB by default), so memory use
does not grow with the file size. Several transfers at once need
proportionally more: each connection keeps its own chunk buffer and
`requests` overhead.

## Folders, copies and moves

```python
import webdav

with webdav.FileSystem("https://webdav.example.org", auth=("user", "password")) as fs:
    fs.mkdir("Archive")
    fs.copy("Documents/Notes.txt", "Archive/Notes.txt")
    fs.move("Archive/Notes.txt", "Archive/Notes-2026.txt")
    fs.remove("Archive")
```

`mkdir` raises `ResourceAlreadyExistsError` if the folder exists. `copy`
and `move` do not replace an existing destination unless you pass
`overwrite=True`. `remove` deletes a folder with everything in it, but
refuses to remove the root of the base URL. The copy happens on the
server, nothing is downloaded.

## Properties

One method per common property:

```python
import webdav

with webdav.FileSystem("https://webdav.example.org", auth=("user", "password")) as fs:
    fs.content_length("Documents/Readme.md")    # 1234
    fs.content_type("Documents/Readme.md")      # "text/markdown; charset=utf-8"
    fs.content_language("Documents/Readme.md")  # None if the server has none
    fs.created("Documents/Readme.md")           # datetime
    fs.modified("Documents/Readme.md")          # datetime
    fs.etag("Documents/Readme.md")              # as the server sends it
```

Several at once, in one request:

```python
props = fs.get_props("Documents/Readme.md", props=["etag", "modified"])
print(props.etag, props.modified)
```

Set and remove properties of your own:

```python
fs.set_props("Documents/Readme.md", set_props={"{https://example.org/ns}color": "blue"})
fs.set_props("Documents/Readme.md", remove_props=["{https://example.org/ns}color"])
```

A property name is a short name like `"etag"`, a `DAV:` name like
`"getetag"`, Clark notation (`"{namespace}name"`) or a `(namespace, name)`
tuple.

Ask the server which WebDAV classes it supports:

```python
fs.dav_compliance()  # {"1", "2"}
```

## Locks

```python
import webdav

with webdav.FileSystem("https://webdav.example.org", auth=("user", "password")) as fs:
    with fs.locked("Documents/report.docx") as lock:
        fs.upload_file("report.docx", "Documents/report.docx", overwrite=True)
```

Inside the block, writes through this `FileSystem` (or a `Session` it
shares) carry the lock's token. The lock is released at the end, also if
the block raised.

- A lock on a folder also covers adding and removing members in it, with
  `depth="0"` as well as with the default `depth="infinity"`. The token is
  sent automatically. See [Locks on a collection](locking.md#locks-on-a-collection).
- Reads never carry a token.
- A lock is requested for 600 s unless you say `lock_timeout=` (`None`:
  infinite).

`refresh_lock` extends the timeout of a lock you hold:

```python
with fs.locked("Documents/report.docx", lock_timeout=60) as lock:
    lock = fs.refresh_lock("Documents/report.docx", lock.token, lock_timeout=300)
```

At the `Session` level, `session.lock(...)` records the lock it gets, and
`session.locks.add(url, token, depth)` records a token you already hold.
Later writes then carry it the same way, see
[Session: Locks](session.md#lock-and-unlock). Refreshing, timeouts and
what a lock does on the server are explained in [Locking](locking.md).

## Paths and names

A path is the plain name: `a%20b.txt` is a file called `a%20b.txt`. It is
percent-encoded exactly once, entirely (`%`, `?`, `#`, `;`, `+`
included). A full URL is used as written. What `ls` and `walk` return is
what `info`, `download_file` and the others take. Unicode is never
re-normalised on the way out.

## Errors

A `FileSystem` method raises a {class}`~webdav.exceptions.WebDAVError`
subclass when the server refuses a request, for example
`ResourceNotFoundError` for a 404. It never returns a status code.
[Exceptions](exceptions.md) lists every error.

## Limits, retries, pickling

A `FileSystem` sends its requests through a `Session`, so the session
options apply unchanged. They are described on the Session page:

- [Limits on what a server can make the client do](session.md#limits-on-what-a-server-can-make-the-client-do)
- [Retries](session.md#retries)
- [Pickling and copying](session.md#pickling-and-copying)

The full list of methods and arguments is in the
[API reference](api.md#filesystem).
