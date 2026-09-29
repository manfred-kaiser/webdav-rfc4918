# CLI

```console
$ pip install webdav-rfc4918[cli]
```

Every command takes one or more WebDAV URLs
(`webdav://host/path`/`webdavs://host/path`, or plain `http(s)://`).
Authentication is `user:pass@host` in the URL, `--user`/`--password`, or
the `WEBDAV_USER`/`WEBDAV_PASSWORD` environment variables.

```console
$ dav ls webdav://user:pass@webdav.example.org/Photos
$ dav get webdav://webdav.example.org/report.pdf ./report.pdf
$ dav put ./report.pdf webdav://webdav.example.org/report.pdf
$ dav mkdir webdav://webdav.example.org/NewFolder
$ dav rm webdav://webdav.example.org/old.txt
$ dav mv webdav://webdav.example.org/a.txt webdav://webdav.example.org/b.txt
$ dav cp webdav://webdav.example.org/a.txt webdav://webdav.example.org/copy.txt
$ dav cat webdav://webdav.example.org/notes.txt
$ dav info webdav://webdav.example.org/notes.txt
```

`mv`/`cp` are server-side operations (COPY/MOVE) and therefore require
both URLs to point at the same server.
