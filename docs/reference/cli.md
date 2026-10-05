# CLI

`dav` is a command-line WebDAV client that comes with this package. It is
meant for quick checks, scripts, or looking around a server without
writing Python. Each subcommand is one file operation.

```console
$ pip install webdav-rfc4918   # the `dav` command is part of the package
```

Every command takes one or more WebDAV URLs: `webdavs://host/path`,
`webdav://host/path`, or plain `http(s)://`. `webdavs://` is HTTPS,
`webdav://` is plain HTTP.

Authentication is `--user`/`--password`, `user:pass@host` in the URL, or
the `WEBDAV_USER`/`WEBDAV_PASSWORD` environment variables, in that order of
precedence. The `dav` command takes `user:pass@host` out of the URL itself
and passes it on as `auth=` before it creates a `Session`. The library
itself still refuses credentials in a URL, see
[Session: Limits](session.md#limits-on-what-a-server-can-make-the-client-do).

```{warning}
A `webdav://` or `http://` URL sends the username and password in clear
text. Anyone on the network path can read them. Use `webdavs://` or
`https://`.

`--password` is visible to other local users via the process list. A
password in the URL (`user:pass@host`) is part of the command line as
well and is visible in the same way. Set the password in
`$WEBDAV_PASSWORD` instead. For an encrypted client key, use
`$WEBDAV_KEY_PASSWORD` instead of `--key-password`.
```

```console
$ export WEBDAV_USER=user WEBDAV_PASSWORD=password
$ dav ls webdavs://webdav.example.org/Photos
$ dav get webdavs://webdav.example.org/report.pdf ./report.pdf
$ dav mkdir webdavs://webdav.example.org/NewFolder
$ dav put ./report.pdf webdavs://webdav.example.org/NewFolder/report.pdf
$ dav rm webdavs://webdav.example.org/old.txt
$ dav cp webdavs://webdav.example.org/a.txt webdavs://webdav.example.org/copy.txt
$ dav mv webdavs://webdav.example.org/a.txt webdavs://webdav.example.org/b.txt
$ dav cat webdavs://webdav.example.org/notes.txt
$ dav info webdavs://webdav.example.org/notes.txt
```

`mv` and `cp` run on the server (`MOVE` and `COPY`). Both URLs must
therefore point at the same server.

## Connection options

The commonly needed {class}`~webdav.session.Session` options are
available as flags on every subcommand. `--help` lists them in groups:

```console
$ dav ls --help
```

### mTLS and TLS

| Flag | Meaning |
|---|---|
| `--cert`, `--key` | Client certificate |
| `--key-password` | Default: `$WEBDAV_KEY_PASSWORD` |
| `--ca-cert` | Custom CA bundle. Server verification itself can never be disabled |
| `--crl-cert` | Repeatable |
| `--ciphers` | |
| `--tls-min-version`, `--tls-max-version` | `1.2` or `1.3` |

### Redirects

[Redirects](redirects.md) explains the policies.

| Flag | Meaning |
|---|---|
| `--redirect-policy {never,same-origin,whitelist,all}` | Default: `same-origin` |
| `--trusted-redirect-origin` | Repeatable. Requires `--redirect-policy whitelist` |
| `--max-redirects` | Redirects in a row before a request is refused as a loop. Default: 5 |

### Connection tuning

| Flag | Meaning |
|---|---|
| `--max-response-size` | Bytes, or `none` to disable the cap. Default: 64 MiB |
| `--max-response-time` | Seconds for the whole request, or `none`. Default: 300 |
| `--chunk-size` | Bytes. Default: 4 MiB |
| `--no-retry` | Do not retry a transient failure automatically |

`none` (or `unlimited`) removes the limit completely. A faulty or hostile
server can then send a response of any size, or keep a request open
without end. `0` is rejected, so a typo cannot remove a limit by accident.
`dav get` streams the download, so neither limit applies to it, see
[Session: Limits](session.md#limits-on-what-a-server-can-make-the-client-do).
