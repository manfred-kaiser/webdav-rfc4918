# fsspec

[`fsspec`](https://filesystem-spec.readthedocs.io) is the de-facto
standard storage-backend interface in the Python data ecosystem - this
wraps {class}`~webdav.fs.client.FileSystem` so other projects (pandas,
dask, ...) can read/write a WebDAV server without knowing anything
WebDAV-specific.

```console
$ pip install webdav-rfc4918[fsspec]
```

```python
from webdav.fsspec import WebdavFileSystem

fs = WebdavFileSystem("https://webdav.example.org", auth=("username", "password"))
fs.exists("Documents/Readme.md")
fs.ls("Photos", detail=False)         # ['/Photos/Gorilla.jpg', ...]
```

Importing `webdav.fsspec` registers `"webdavs"` with fsspec
([`fsspec.register_implementation`](https://filesystem-spec.readthedocs.io)),
so `fsspec.filesystem("webdavs", base_url=..., auth=...)` and
`fsspec.open("webdavs:///Documents/Readme.md", base_url=..., auth=...)` work right away, same
as the explicit import above - no separate setup step. The server is given by `base_url`; the
URL carries only the path, and a host in it is not interpreted.

## Paths

A filesystem is bound to one server, through its `base_url`, and its paths are those of the
server: they start at `/`, the root of the `base_url` (fsspec's `root_marker`, as for
`LocalFileSystem` or `MemoryFileSystem`). A `base_url` with a path - `https://host/dav/` - makes
`/dav/` the root; nothing above it can be reached.

- `a/b`, `/a/b` and `webdavs:///a/b` are one path (fsspec's `_strip_protocol` makes it absolute
  and drops a trailing `/`); there is no working directory.
- `.`, `..` and `//` inside a path are resolved; a path that would leave the `base_url` is
  refused with a `ClientError`.
- The names `ls`, `info`, `find`, `glob` and `walk` return are exactly what `_strip_protocol`
  returns for them, so every name can be handed back to any method.
- Without a `base_url` (or a `session` that has one) the constructor raises `ValueError`.

This differs from {class}`~webdav.fs.client.FileSystem`, whose names are relative to the
`base_url` without the leading `/` (`Photos/Gorilla.jpg`) and which also takes `/Photos`: the
fsspec name is always `"/" + name`.

**Why `"webdavs"` and not `"webdav"`:** fsspec's own registry already maps
`"webdav"` to [`webdav4`](https://pypi.org/project/webdav4/) by default -
this library would rather coexist with that than silently take it over the
moment it is imported. `"webdavs"` had no existing claim anywhere, so it is
the uncontested, cooperative starting point.

The filesystem follows fsspec's conventions (`ls(path, detail=...)`, `open`, `get`, `put`,
`rm`, ...), which differ in places from {class}`~webdav.fs.client.FileSystem`, whose `ls` always
returns {class}`~webdav.resource.Resource` objects.

- **Errors** are the stdlib ones fsspec expects: `FileNotFoundError`, `FileExistsError`
  (also for a failed `Overwrite: F`), `IsADirectoryError`, `NotADirectoryError`.
- **Writing** (`open(path, "wb")`, `"xb"`) uploads when the file is closed cleanly; a block that
  raises leaves the resource untouched. `"xb"` creates only if nothing is there (atomic on the
  server). Append mode is not supported.
- **`get`** replaces an existing local file, as fsspec's `get` means to, but through a temporary
  file: a failed download leaves the old file as it was, and a symlink is never followed. A
  remote collection becomes a local directory.
- **`rm`** refuses a non-empty collection unless `recursive=True`, because `DELETE` on a
  collection removes everything below it.
- **Credentials**: `to_json()` and pickling contain the password in clear text. Do not store or
  send them anywhere untrusted.

Checked against fsspec's own conformance test suite
(`fsspec.tests.abstract` - the same one real backends like `s3fs`/`gcsfs`
use), not just this project's own tests - see `tests/test_fsspec_abstract.py`.

```{eval-rst}
.. autoclass:: webdav.fsspec.WebdavFileSystem
   :members:
```
