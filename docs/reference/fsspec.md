# fsspec

[`fsspec`](https://filesystem-spec.readthedocs.io) is the de-facto
standard storage-backend interface in the Python data ecosystem - this
wraps the {class}`~webdav.session.Session` so other projects (pandas, dask,
...) can read/write a WebDAV server without knowing anything
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

The filesystem follows fsspec's conventions (`ls(path, detail=...)`, `open`, `get`, `put`,
`rm`, ...), which differ in places from {class}`~webdav.session.Session`, whose `ls` always
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

```{eval-rst}
.. autoclass:: webdav.fsspec.WebdavFileSystem
   :members:
```
