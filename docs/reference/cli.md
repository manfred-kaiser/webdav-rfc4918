# CLI

```console
$ pip install webdav-rfc4918   # the `dav` command is part of the package
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

## Connection options

The commonly needed {class}`~webdav.session.Session` options are available as a
flag on every subcommand, grouped in `--help`:

```console
$ dav ls --help
```

**mTLS / TLS**
: `--cert`/`--key` (client certificate), `--key-password` (default:
  `$WEBDAV_KEY_PASSWORD`), `--ca-cert` (custom CA bundle; server
  verification itself can never be disabled), `--crl-cert` (repeatable),
  `--ciphers`, `--tls-min-version`/`--tls-max-version` (`1.2`/`1.3`).

**Redirects** (see {doc}`redirects`)
: `--redirect-policy {never,same-origin,whitelist,all}` (default:
  `same-origin`), `--trusted-redirect-origin` (repeatable; requires
  `--redirect-policy whitelist`), `--max-redirects` (redirects in a row
  before a request is refused as a loop; default: 5).

**Connection tuning**
: `--max-response-size` (bytes, or `none` to disable the cap; default:
  64 MiB), `--max-response-time` (seconds for the whole request, or `none`;
  default: 300), `--chunk-size` (bytes; default: 4 MiB), `--no-retry` (don't
  automatically retry a transient failure).
