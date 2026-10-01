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
fs.ls("Photos", detail=False)
```

Importing `webdav.fsspec` registers `"webdavs"` with fsspec
([`fsspec.register_implementation`](https://filesystem-spec.readthedocs.io)),
so `fsspec.open("webdavs://host/path", ...)` and
`fsspec.filesystem("webdavs", ...)` work right away, same as the explicit
import above - no separate setup step.

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
- **Known limitation**: a recursive `get`/`cp`/`put` of a directory that sits at the root of the
  WebDAV namespace (no `/` in its path), run a second time onto a destination that already
  exists, does not nest it the way fsspec documents - this is an
  [upstream fsspec bug](https://github.com/manfred-kaiser/webdav-rfc4918/issues/3), not specific
  to this library (confirmed structurally true of `s3fs` too); tracked as an `xfail` in
  `tests/test_fsspec_abstract.py`.

Checked against fsspec's own conformance test suite
(`fsspec.tests.abstract` - the same one real backends like `s3fs`/`gcsfs`
use), not just this project's own tests - see `tests/test_fsspec_abstract.py`.

```{eval-rst}
.. autoclass:: webdav.fsspec.WebdavFileSystem
   :members:
```
