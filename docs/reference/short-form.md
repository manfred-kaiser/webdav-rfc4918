# Short form

Every file operation is also a plain function in the `webdav` module. It
takes a full URL, connects, does one thing and closes the connection again.

```python
import webdav

auth = ("user", "password")

webdav.exists("https://webdav.example.org/Documents/Readme.md", auth=auth)
```

Each function opens a [`FileSystem`](filesystem.md), makes one call and
closes it again. [Which form to use](../quickstart.md#which-form-to-use)
explains how the three forms build on each other.

The functions have the same names, arguments and return values as the
[`FileSystem`](filesystem.md) methods. The short form takes a full URL,
a `FileSystem` a path relative to its base URL.

## Limits of the short form

The short form is meant for one or two calls. Each call:

- opens its own connection, with its own TLS handshake,
- sends the credentials to the server again, without cookies or other
  state from earlier calls,
- holds no lock token beyond the call itself, see [Locks](#locks).

For two or more calls against the same server, use a
[`FileSystem`](filesystem.md).

## All functions

Every function takes a full URL as its first argument (uploads: the local
path first) and the [options](#options) as keyword arguments.

| Function | What it does | Returns |
|---|---|---|
| **[Listing and checking](#listing-and-checking)** | | |
| `ls(url)` | List the members of a folder | list of {class}`~webdav.resource.Resource` |
| `info(url)` | Describe one file or folder | {class}`~webdav.resource.Resource` |
| `walk(url)` | Go through a folder tree, like `os.walk` | iterator of `(path, dirs, files)` |
| `exists(url)` | Is something there? | `bool` |
| `isdir(url)` | Is it a folder? | `bool` |
| `isfile(url)` | Is it a file? | `bool` |
| **[Reading and writing](#reading-and-writing)** | | |
| `upload_file(local_path, url)` | Upload a local file | `None` |
| `download_file(url, local_path)` | Download to a local file | `None` |
| `upload_fileobj(fileobj, url)` | Upload from an open binary file object | `None` |
| `download_fileobj(url, fileobj)` | Download into an open binary file object | `None` |
| `open(url, mode="r")` | Read or write like the builtin `open` | file object, in a `with` block |
| **[Folders, copies and moves](#folders-copies-and-moves)** | | |
| `mkdir(url)` | Create a folder | `None` |
| `copy(url, destination)` | Copy on the server | `None` |
| `move(url, destination)` | Move or rename on the server | `None` |
| `remove(url)` | Delete a file, or a folder with everything in it | `None` |
| **[Properties](#properties)** | | |
| `get_props(url, props=...)` | Several properties in one request | {class}`~webdav.dav.properties.DAVProperties` |
| `set_props(url, set_props=...)` | Set or remove properties | `None` |
| `content_length(url)` | Size in bytes (`getcontentlength`) | `int \| None` |
| `content_type(url)` | MIME type (`getcontenttype`) | `str \| None` |
| `content_language(url)` | Language tag (`getcontentlanguage`) | `str \| None` |
| `created(url)` | Creation time (`creationdate`) | `datetime \| None` |
| `modified(url)` | Last modification time (`getlastmodified`) | `datetime \| None` |
| `etag(url)` | ETag as the server sends it (`getetag`) | `str \| None` |
| `dav_compliance(url)` | WebDAV classes of the server, one `OPTIONS` per call | `set[str]` |
| **[Locks](#locks)** | | |
| `locked(url)` | Hold a lock for a `with` block, 600 s unless `lock_timeout=` | {class}`~webdav.dav.locks.ActiveLock`, in a `with` block |
| `refresh_lock(url, token)` | Extend the timeout of a held lock | {class}`~webdav.dav.locks.ActiveLock` |

`None` from a property function means the server did not report that
property. The first block of each section below is complete. The blocks
after it in the same section reuse its `auth` and `url`.

## Listing and checking

```python
import webdav

auth = ("user", "password")

for resource in webdav.ls("https://webdav.example.org/Photos", auth=auth):
    print(resource, resource.size, resource.is_dir)

readme = webdav.info("https://webdav.example.org/Documents/Readme.md", auth=auth)
print(readme.size, readme.modified, readme.content_type)

webdav.exists("https://webdav.example.org/Documents/Readme.md", auth=auth)  # True
webdav.isdir("https://webdav.example.org/Photos", auth=auth)  # True
webdav.isfile("https://webdav.example.org/Photos", auth=auth)  # False
```

`ls` returns a list of {class}`~webdav.resource.Resource` objects, `info`
returns one. [FileSystem](filesystem.md#listing-and-checking) explains what
a `Resource` holds.

```python
for path, dirs, files in webdav.walk("https://webdav.example.org/Photos", auth=auth):
    for f in files:
        print(f, f.size)
```

`walk` yields `(path, dirs, files)` for every folder below the URL.
`max_depth=1` stops one level down.

## Reading and writing

```python
import webdav

auth = ("user", "password")

webdav.upload_file("Gorilla.jpg", "https://webdav.example.org/Photos/Gorilla.jpg", auth=auth)
webdav.download_file("https://webdav.example.org/Documents/Readme.md", "Readme.md", auth=auth)
```

Uploads take `(local_path, url)`, downloads `(url, local_path)`. Neither
replaces an existing file unless you pass `overwrite=True`.

`upload_fileobj` and `download_fileobj` take an open binary file object
instead of a path:

```python
import io

webdav.upload_fileobj(
    io.BytesIO(b"hello"), "https://webdav.example.org/Documents/hello.txt", auth=auth
)

buffer = io.BytesIO()
webdav.download_fileobj("https://webdav.example.org/Documents/hello.txt", buffer, auth=auth)
buffer.getvalue()  # b"hello"
```

`open` works like the builtin `open`:

```python
with webdav.open("https://webdav.example.org/Documents/Notes.txt", "w", auth=auth) as f:
    f.write("Buy bananas\n")

with webdav.open("https://webdav.example.org/Documents/Notes.txt", auth=auth) as f:
    print(f.read())

with webdav.open("https://webdav.example.org/Photos/Gorilla.jpg", "rb", auth=auth) as f:
    header = f.read(16)

with webdav.open("https://webdav.example.org/Documents/New.txt", "x", auth=auth) as f:
    f.write("created only if nothing is there\n")
```

`"r"` (the default) and `"rb"` read, `"w"` and `"wb"` write, `"x"` and
`"xb"` create only if nothing is there yet.

## Folders, copies and moves

```python
import webdav

auth = ("user", "password")

webdav.mkdir("https://webdav.example.org/Archive", auth=auth)
webdav.copy(
    "https://webdav.example.org/Documents/Notes.txt",
    "https://webdav.example.org/Archive/Notes.txt",
    auth=auth,
)
webdav.move(
    "https://webdav.example.org/Archive/Notes.txt",
    "https://webdav.example.org/Archive/Notes-2026.txt",
    auth=auth,
)
webdav.remove("https://webdav.example.org/Archive", auth=auth)
```

`remove` deletes a folder with everything in it. `copy` and `move` refuse
to replace an existing destination unless you pass `overwrite=True`.

## Properties

One function per common property:

```python
import webdav

auth = ("user", "password")

url = "https://webdav.example.org/Documents/Readme.md"

webdav.content_length(url, auth=auth)    # 1234
webdav.content_type(url, auth=auth)      # "text/markdown; charset=utf-8"
webdav.content_language(url, auth=auth)  # None if the server has none
webdav.created(url, auth=auth)           # datetime
webdav.modified(url, auth=auth)          # datetime
webdav.etag(url, auth=auth)              # as the server sends it
```

Several at once, in one request:

```python
props = webdav.get_props(url, props=["etag", "modified"], auth=auth)
print(props.etag, props.modified)
```

Set and remove properties of your own. The name is in Clark notation,
`{namespace}name`:

```python
webdav.set_props(url, set_props={"{https://example.org/ns}color": "blue"}, auth=auth)
webdav.set_props(url, remove_props=["{https://example.org/ns}color"], auth=auth)
```

Ask the server which WebDAV classes it supports:

```python
webdav.dav_compliance("https://webdav.example.org/", auth=auth)  # {"1", "2"}
```

## Locks

```python
import webdav

auth = ("user", "password")

url = "https://webdav.example.org/Documents/report.docx"

with webdav.locked(url, lock_timeout=60, auth=auth) as lock:
    print(lock.token, lock.timeout)
    lock = webdav.refresh_lock(url, lock.token, lock_timeout=300, auth=auth)
```

The lock is released when the `with` block ends. `refresh_lock` extends
its timeout. Other short-form calls open their own connection and do not
carry the lock's token, so a write from them is refused with
`ResourceLockedError` while the lock is held. To write under a lock, use
[`FileSystem.locked`](filesystem.md#locks). [Locking](locking.md) has the
details.

## Options

Every function takes the same keyword arguments as `FileSystem(...)` and
`Session(...)`:

```python
import webdav

webdav.exists(
    "https://webdav.example.org/Documents/Readme.md",
    auth=("user", "password"),
    timeout=10,
    verify="ca-bundle.pem",
    retry=False,
)
```

What these options do, and the limits that protect the client from a
misbehaving server, is described on the [Session](session.md) page:
[Limits](session.md#limits-on-what-a-server-can-make-the-client-do),
[Retries](session.md#retries). For certificates, see [TLS and mTLS](tls.md).

A refused request raises a {class}`~webdav.exceptions.WebDAVError`
subclass, see [Exceptions](exceptions.md).

The full signature of every function is in the
[API reference](api.md#module-level-functions).
