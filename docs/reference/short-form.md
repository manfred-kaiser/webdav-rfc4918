# Short form

Every file operation is also a plain function in the `webdav` module. It
takes a full URL, connects, does one thing and closes the connection again.

```python
import webdav

auth = ("user", "password")

webdav.exists("https://webdav.example.org/Documents/Readme.md", auth=auth)
```

## Which form to use

The library offers three ways to talk to a server:

| You want to | Use |
|---|---|
| Make one or two calls, for example in a script or a health check | The short form: `webdav.ls(url)`, `webdav.upload_file(...)` |
| Make several calls against the same server | [`FileSystem`](filesystem.md) |
| See status codes and headers, read the raw multistatus, or send a request the file operations do not cover | [`Session`](session.md) |

The short form and `FileSystem` have the same names, arguments and return
values. A test compares their signatures. The only difference is how a
remote resource is named: the short form takes a full URL, a `FileSystem`
a path relative to its base URL. `Session` has no short form.

Each short-form call opens its own connection. For many calls in a row,
a `FileSystem` is faster because it keeps one connection open.

## All functions

Every function takes a full URL as its first argument (uploads: the local
path first) and the [options](#options) as keyword arguments.

| Function | What it does |
|---|---|
| `ls(url)` | List the members of a folder |
| `info(url)` | Describe one file or folder |
| `walk(url)` | Go through a folder tree, like `os.walk` |
| `exists(url)` | `True` if something is there |
| `isdir(url)` | `True` if it is a folder |
| `isfile(url)` | `True` if it is a file |
| `upload_file(local_path, url)` | Upload a local file |
| `download_file(url, local_path)` | Download to a local file |
| `upload_fileobj(fileobj, url)` | Upload from an open binary file object |
| `download_fileobj(url, fileobj)` | Download into an open binary file object |
| `open(url, mode)` | Read or write like the builtin `open` |
| `mkdir(url)` | Create a folder |
| `copy(url, destination)` | Copy on the server |
| `move(url, destination)` | Move or rename on the server |
| `remove(url)` | Delete a file, or a folder with everything in it |
| `get_props(url)` | Read several properties in one request |
| `set_props(url)` | Set or remove properties |
| `content_length(url)` | Size in bytes |
| `content_type(url)` | MIME type |
| `content_language(url)` | Language tag |
| `created(url)` | Creation time |
| `modified(url)` | Last modification time |
| `etag(url)` | ETag |
| `dav_compliance(url)` | WebDAV compliance classes the server advertises |
| `locked(url)` | Hold a lock for the duration of a `with` block |
| `refresh_lock(url, token)` | Extend the timeout of a held lock |

Each of them has an example in the sections below.

## Listing and checking

```python
for resource in webdav.ls("https://webdav.example.org/Photos", auth=auth):
    print(resource, resource.size, resource.is_dir)

readme = webdav.info("https://webdav.example.org/Documents/Readme.md", auth=auth)
print(readme.size, readme.modified, readme.content_type)

webdav.exists("https://webdav.example.org/Documents/Readme.md", auth=auth)  # True
webdav.isdir("https://webdav.example.org/Photos", auth=auth)  # True
webdav.isfile("https://webdav.example.org/Photos", auth=auth)  # False
```

`ls` returns a list of {class}`~webdav.resource.Resource` objects, `info`
returns one. [FileSystem](filesystem.md#listing-ls-info-and-walk) explains
what a `Resource` holds.

```python
for path, dirs, files in webdav.walk("https://webdav.example.org/Photos", auth=auth):
    for f in files:
        print(f, f.size)
```

`walk` yields `(path, dirs, files)` for every folder below the URL.
`max_depth=1` stops one level down.

## Uploading and downloading

```python
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
[Retries](session.md#retries). For certificates, see
[TLS and mTLS](tls.md).

A refused request raises a {class}`~webdav.exceptions.WebDAVError`
subclass, see [Exceptions](exceptions.md).

The full signature of every function is in the
[API reference](api.md#module-level-functions).
