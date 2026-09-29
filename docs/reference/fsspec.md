# fsspec

[`fsspec`](https://filesystem-spec.readthedocs.io) is the de-facto
standard storage-backend interface in the Python data ecosystem - this
wraps the {class}`~webdav.client.Client` so other projects (pandas, dask,
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

```{eval-rst}
.. autoclass:: webdav.fsspec.WebdavFileSystem
   :members:
```
