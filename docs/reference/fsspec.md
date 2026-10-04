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

Installing `webdav-rfc4918[fsspec]` registers both `"webdav"` and `"webdavs"` with fsspec
through the
[`fsspec.specs` entry point](https://filesystem-spec.readthedocs.io/en/latest/developer.html#implementing-a-backend)
(fsspec's own recommended way for a third-party backend to announce itself), so
`fsspec.filesystem("webdav"/"webdavs", base_url=..., auth=...)` and
`fsspec.open("webdav://..."/"webdavs://...", auth=...)` work right away - no import needed,
explicit or otherwise (`clobber=True`, like every entry-point registration fsspec itself
processes, claims both names outright).

The server is the `base_url`. A URL may also name it, as `sftp://host/path` does:
`webdav(s)://host[:port]/path` gives fsspec the `host`/`port`/transport to make the
filesystem with, and they are not part of the path. `webdavs` is WebDAV over TLS, `webdav`
plain HTTP - like `ftps`/`ftp` - so without a `base_url` the server is `https://host[:port]`
or `http://host[:port]` respectively; with one, the URL only has to name the same server
(its own scheme need not match - `webdav://` against an `https://` `base_url` is fine) -
another host or port is a `ValueError`, never a redirect. A user or password in the URL is
refused (it would end up in logs and reprs): pass `auth=`.

```python
import fsspec

fsspec.open("webdavs://webdav.example.org/Documents/Readme.md", auth=("user", "password"))
fsspec.open("webdavs:///Documents/Readme.md", base_url="http://localhost:8080", auth=...)
```

## Paths

A filesystem is bound to one server, through its `base_url`, and its paths are those of the
server: they start at `/`, the root of the `base_url` (fsspec's `root_marker`, as for
`LocalFileSystem` or `MemoryFileSystem`). A `base_url` with a path - `https://host/dav/` - makes
`/dav/` the root; nothing above it can be reached.

- `a/b`, `/a/b` and `webdavs:///a/b` are one path (fsspec's `_strip_protocol` makes it absolute
  and drops a trailing `/`); there is no working directory. Only what follows `webdav://`/
  `webdavs://` can be a host: `webdavs://a/b` is the path `/b` on the server `a`, while `//a/b`
  is the path `/a/b`.
- `.`, `..` and `//` inside a path are resolved; a path that would leave the `base_url` is
  refused with a `ClientError`.
- The names `ls`, `info`, `find`, `glob` and `walk` return are exactly what `_strip_protocol`
  returns for them, so every name can be handed back to any method.
- Without a `base_url` (or a `session` that has one, or a `host`) the constructor raises
  `ValueError`.
- fsspec reads `[...]`, `*` and `?` in a path as a glob wherever it expands one (`rm`, `cp`, `get`,
  `glob`): a file really named `[x]` is removed with `rm_file`.
- pyarrow compares the names a filesystem returns with the directory it was asked for, so give
  it absolute paths (`/data/ds`, not `data/ds`) - as for `MemoryFileSystem`, which has a root too.

This differs from {class}`~webdav.fs.client.FileSystem`, whose names are relative to the
`base_url` without the leading `/` (`Photos/Gorilla.jpg`) and which also takes `/Photos`: the
fsspec name is always `"/" + name`.

**Why both names:** this library claims `"webdav"` and `"webdavs"` outright through the
officially-sanctioned `fsspec.specs` entry point (`clobber=True`, like every entry-point
registration fsspec itself processes), having verified full conformance with fsspec's own
test suite (`fsspec.tests.abstract`; see `tests/test_fsspec_abstract.py`) - including a
fsspec bug it ran into and reported along the way
([fsspec/filesystem_spec#2215](https://github.com/fsspec/filesystem_spec/issues/2215),
partially fixed upstream since as
[fsspec/filesystem_spec#2217](https://github.com/fsspec/filesystem_spec/pull/2217)). A plain
`import webdav.fsspec` (without the package being installed with its entry-point metadata)
only ever claims `"webdavs"`, never `"webdav"` - silently winning a name away from whatever
already claimed it is a different, more surprising thing than the deliberate, opt-in
entry-point registration above.

The filesystem follows fsspec's conventions (`ls(path, detail=...)`, `open`, `get`, `put`,
`rm`, ...), which differ in places from {class}`~webdav.fs.client.FileSystem`, whose `ls` always
returns {class}`~webdav.resource.Resource` objects.

- **Errors** are the stdlib ones fsspec expects: `FileNotFoundError`, `FileExistsError`
  (`"xb"` on a file that is there, a directory in the way of a copy), `IsADirectoryError`
  (also for a write to a directory), `NotADirectoryError`, `PermissionError` (a 403, and a
  directory copied or moved into itself).
- **`cp` and `mv`** replace a file that is there, as `LocalFileSystem` does and as `open(path,
  "wb")` does here - but never a directory: a COPY/MOVE with `Overwrite: T` deletes the
  destination with everything in it, so a directory in the way is a `FileExistsError`. A
  directory is moved with everything in it, `recursive` or not, and `cp(d, "e/")` goes *into*
  `e` also when it does not exist yet, as in `cp -r d e/`. A directory is never copied or moved
  into itself, nor the root anywhere; `mv` of a path onto itself - however it is spelled - does
  nothing.
- **Parallel writers** may create the same parent directory at once (dask, zarr). RFC 4918 (sec.
  9.3.1) answers the MKCOL that loses the race with 405, "exists"; Apache answers some of them
  403 and WsgiDAV 500. Such an answer is not an error for `makedirs(exist_ok=True)` if the
  directory is there afterwards - a tolerance of this filesystem, not something the client does
  (`FileSystem.mkdir` is strict).
- **Reading** (`open(path, "rb")`, `cat_file(path, start, end)`) asks the server for blocks of
  the file - `Range: bytes=a-b`, through fsspec's block cache - and reads every answer to its
  end, so a reader that seeks (Parquet) does not cut off a stream with each seek and the
  connection is reused. `cat_file` with a range asks for exactly those bytes; a whole file is
  one request without a `Range`. The size comes from one `PROPFIND` when the file is opened, so a
  resource that has none cannot be read this way. A server that answers a part with the whole
  file (`200`) is refused rather than believed, and a file that changes between two blocks (its
  `ETag`) is an error.
- **Writing** (`open(path, "wb")`, `"xb"`) uploads when the file is closed cleanly; a block that
  raises leaves the resource untouched. `"xb"` creates only if nothing is there (`If-None-Match: *`,
  as atomic as the server makes it - Apache's `mod_dav` does not make it atomic). Append mode is not supported.
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
