# fsspec

[`fsspec`](https://filesystem-spec.readthedocs.io) is the storage
interface most of the Python data ecosystem uses. This package adds a
WebDAV backend to it. pandas, Dask and other fsspec users read and write a
WebDAV server through a `webdavs://` or `webdav://` URL, without any WebDAV
code. If you are not using one of those, use
[`FileSystem`](filesystem.md) directly instead - this page is only about
the fsspec integration.

```console
$ pip install webdav-rfc4918[fsspec]
```

```python
import fsspec
import pandas as pd

auth = ("user", "password")

df = pd.read_csv("webdavs://webdav.example.org/data.csv", storage_options={"auth": auth})

with fsspec.open("webdavs://webdav.example.org/Photos/Gorilla.jpg", auth=auth) as f:
    f.read()
```

Your code imports nothing from this package. The install registers two protocol
names with fsspec: `webdavs` for WebDAV over HTTPS and `webdav` for plain
HTTP, like `ftps` and `ftp`. For a server without TLS only the scheme
changes:

```python
df = pd.read_csv("webdav://webdav.example.org/data.csv", storage_options={"auth": auth})
```

`webdav://` sends the credentials in clear text, see
[Session: Limits](session.md#limits-on-what-a-server-can-make-the-client-do).

This replaces any other backend registered under these names. If another
package is also installed and only relies on fsspec's built-in fallback
for `webdav` instead of registering itself, this one wins.

## Connecting

A filesystem is bound to one server, its `base_url`. A URL can also name
the server, as `sftp://host/path` does. From `webdavs://host[:port]/path`
fsspec takes the host and port, and they are not part of the path. Without
a `base_url`, the server is `https://host[:port]` for `webdavs://` and
`http://host[:port]` for `webdav://`.

With a `base_url`, the URL may leave out the host (`webdavs:///path`) or
name the same server. The scheme does not have to match: `webdav://`
against an `https://` `base_url` still uses HTTPS. Another host or port
raises `ValueError` and is never followed like a redirect.

```python
import fsspec

auth = ("user", "password")

with fsspec.open("webdavs:///Photos/Gorilla.jpg", base_url="https://webdav.example.org", auth=auth) as f:
    f.read()
```

A user or password in the URL is refused, because it would end up in logs
and reprs. Pass `auth=` instead.

The entries of `storage_options`, and the keywords of `fsspec.open` that
are not its own (`mode`, `encoding`, ...), go to the filesystem
constructor - `timeout`, `verify`, `retry` and the rest are in the [API
reference](api.md#fsspec).

## pandas and Dask

pandas and Dask take the same `storage_options` as above:

```python
import pandas as pd

options = {"auth": ("user", "password")}
df = pd.read_csv("webdavs://webdav.example.org/Data/events.csv", storage_options=options)
```

pyarrow compares the names this filesystem returns with the directory it
was asked for, so give it absolute paths (`/Data/events-pq`, not
`Data/events-pq`).

`dask.dataframe.read_csv` works the same way. Tested with pandas 3.0.6,
Dask 2026.8.0 and fsspec 2026.9.0.

The filesystem is synchronous. Dask gets its parallelism from each worker,
process or thread, holding its own `WebdavFileSystem` and so its own
session. Several workers may create the same directory at once, see
[Parallel writers](#parallel-writers).

Dask distributed pickles the filesystem instance, credentials included, to
send it to each worker, see [Credentials](#credentials).

## Methods

Most methods do what their [`FileSystem`](filesystem.md#all-methods)
counterpart does, under fsspec's name. The rest of fsspec's
`AbstractFileSystem` API works as fsspec documents it.

| fsspec method | `FileSystem` counterpart |
|---|---|
| `ls(path, detail=True)`, `info(path)` | `ls`, `info`, with a `dict` instead of a `Resource` |
| `exists`, `isdir`, `isfile`, `walk` | same name |
| `find`, `glob`, `du` | none (all files below, pattern match, total size) |
| `open(path, mode="rb")` | `open`, whose default mode is `"r"` |
| `cat_file`, `cat`, `head`, `tail`, `read_bytes`, `read_text`, `pipe_file`, `pipe`, `write_text`, `touch` | none |
| `get`, `get_file` | `download_file` |
| `put`, `put_file` | `upload_file` |
| `upload_fileobj`, alias `put_fileobj` | `upload_fileobj` |
| `mkdir`, `makedirs` | `mkdir` |
| `rm_file`, `rmdir`, `rm` | `remove` |
| `cp`, `cp_file`, alias `copy` | `copy` |
| `mv` | `move` |
| `size`, `sizes`, `checksum` | `content_length`, `etag` |
| `created`, `modified` | same name |
| `unstrip_protocol` | none. Returns the `webdav(s)://` URL of a path |
| `sign` | none. Raises `NotImplementedError` |

The examples below call these methods on a filesystem made like this:

```python
import fsspec

fs = fsspec.filesystem("webdavs", base_url="https://webdav.example.org", auth=("user", "password"))
```

The sections below cover only what differs from `FileSystem`, or what
an fsspec user may not expect from a WebDAV server.

## Paths

Paths are those of the server. They start at `/`, the root of the
`base_url`, as for `LocalFileSystem` or `MemoryFileSystem` (fsspec's
`root_marker`). A `base_url` with a path, such as `https://host/dav/`,
makes `/dav/` the root. Nothing above it can be reached.

- `a/b`, `/a/b` and `webdavs:///a/b` are one path. There is no working
  directory, and a trailing `/` is dropped.
- Only what follows `webdav://` or `webdavs://` can be a host:
  `webdavs://a/b` is the path `/b` on the server `a`, while `//a/b` is the
  path `/a/b`.
- `.`, `..` and `//` inside a path are resolved. A path that would leave
  the `base_url` is refused with a `ClientError`.
- The names `ls`, `info`, `find`, `glob` and `walk` return can be passed
  back to any method as they are.
- fsspec expands `[...]`, `*` and `?` as a glob wherever it accepts a path,
  [as every fsspec backend does](https://filesystem-spec.readthedocs.io/en/latest/features.html#glob).
  A file really named `[x]` is removed with `rm_file`, which does not glob.

{class}`~webdav.fs.client.FileSystem` names the same file without the
leading `/` (`Photos/Gorilla.jpg`). It also accepts `/Photos`. The fsspec
name is always `"/" + name`.

## Listing

Beyond the keys fsspec requires (`name`, `size`, `type`), the info dict
has `href`, `created`, `modified`, `etag`, `content_type`,
`content_language` and `display_name`.

## Reading

- `open(path, "rb")` reads the file in blocks, one range request each.
- `cat_file` with a range asks for exactly those bytes.
- A whole file is one request.
- A server that answers a range request with the whole file (`200`) is
  refused, and so is a file whose `ETag` changes between two blocks. Both
  raise a `ClientError`.

`open()` asks for the size with one `PROPFIND` first, so a resource
without a size cannot be read this way. For a dataset of many small files,
such as a directory of Parquet part files, that is one extra round trip
per file. If the sizes are known already, pass them as
`open(path, "rb", size=n)` and the `PROPFIND` is skipped. `ls()` returns
the sizes of a whole directory in one `PROPFIND`: for 3000 members that
took 0.16 s against Apache, see
[Apache: Size and names](../apache-compliance-check.md#size-and-names).

## Caching

This filesystem adds no cache of its own; fsspec's own `cache_type`,
`block_size` and `cache_options` apply, [as for any fsspec
backend](https://filesystem-spec.readthedocs.io/en/latest/features.html#caching-files-locally).
Only `cat_file()` differs: it uses `cache_type="none"`, so a few
requested bytes do not pull in a whole cache block.

## Writing

- `open(path, "wb")` and `"xb"` upload when the file is closed without an
  error. A `with` block that raises leaves the resource unchanged.
- `"xb"` creates the file only if nothing is there (`If-None-Match: *`).
  That is as atomic as the server makes it, and Apache's `mod_dav` does
  not make it atomic.
- Appending is not possible, because a `PUT` always replaces the whole
  resource. `open(..., "ab")` raises `ValueError`, and
  `pipe_file(..., mode="append")` raises `NotImplementedError`.

## Local files

`get` and `put` copy one file, or with `recursive=True` a whole tree,
for example `fs.get("/Photos", "photos", recursive=True)`.

- `put` creates missing parent directories on the server, see
  [Directories](#directories).
- `get` replaces an existing local file. It writes to a temporary file
  first, so a failed download leaves the old local file as it was, and a
  symlink at the destination is never followed.

## Directories

- Uploads and copies create missing parent directories on the server,
  unlike `FileSystem.upload_file`.
- `rm(path, recursive=True)` is one `DELETE` for the whole tree: `DELETE`
  on a collection removes everything below it on the server, there is no
  way to ask for less.

## Parallel writers

Dask and zarr workers may create the same parent directory at once.
`makedirs(exist_ok=True)` accepts the error the losers get if the
directory is there afterwards. `FileSystem.mkdir` raises in that case.

```{admonition} Server differences
:class: note
RFC 4918 answers the losing `MKCOL` with `405`. Apache answers some of
them with `403`, WsgiDAV with `500`.
```

## Copying and moving

`cp` and `mv` replace an existing file, like `LocalFileSystem` does and
like `open(path, "wb")` here. They never replace a directory. A `COPY` or
`MOVE` with `Overwrite: T` would delete the destination with everything in
it, so a directory in the way raises `FileExistsError`.

- `cp(..., recursive=True)` is one `COPY` into a new destination.
- `cp(d, "e/")` copies into `e` even if `e` does not exist yet, as
  `cp -r d e/` does.
- A directory is moved with everything in it, with or without `recursive`.
- Nothing is copied or moved into itself, and the root is never copied or
  moved.
- `mv` of a path onto itself does nothing, however it is spelled.

## Errors

The common errors are the stdlib exceptions fsspec expects. The rest
are this library's own [exceptions](exceptions.md), unchanged:

| Exception | When |
|---|---|
| `FileNotFoundError` | Nothing is there |
| `FileExistsError` | `"xb"` or `mode="create"` on an existing file, a directory in the way of a copy or move |
| `IsADirectoryError` | Reading or writing a directory |
| `NotADirectoryError` | A file where a directory is needed |
| `PermissionError` | A `403`, or a directory copied or moved into itself |
| {class}`~webdav.exceptions.ClientError` | A path outside the `base_url`, a range request answered with `200`, an `ETag` that changed during a read |
| other {class}`~webdav.exceptions.WebDAVError` subclasses | Any other error status, e.g. `401` for wrong credentials, `423` or `507`, see [Exceptions](exceptions.md) |

## Credentials

```{warning}
This filesystem's `to_json()` output, or a pickled instance, contains its
credentials in clear text. Dask (distributed) pickles it with its
`storage_options` and sends it over the network to its workers, see
[pandas and Dask](#pandas-and-dask). Never write it to disk or send it
anywhere untrusted.
```

## Conformance

The backend passes fsspec's own conformance suite, `fsspec.tests.abstract`,
which `s3fs` and `gcsfs` use as well (see `tests/test_fsspec_abstract.py`).
Every method and argument of `WebdavFileSystem` is listed in the
[API reference](api.md#fsspec).
