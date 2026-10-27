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

## Credentials

The user comes from `--user`, else from `user@host` in the URL, else from
`$WEBDAV_USER`, in that order. The password comes from `--password`,
`--password-stdin` or `--password-file`, else from `user:pass@host` in the
URL, else from `$WEBDAV_PASSWORD`, in that order. The `dav` command takes
`user:pass@host` out of the URL itself and passes it on as `auth=` before it
creates a `Session`. The library itself still refuses credentials in a URL,
see [Session: Limits](session.md#limits-on-what-a-server-can-make-the-client-do).

| Source | Visible in the process list and shell history? |
|---|---|
| `--password`, `user:pass@host` in the URL | Yes |
| `--password-stdin`: the first line of standard input | No |
| `--password-file PATH`: the first line of a file | No. Any file permissions are accepted (a mounted Kubernetes or Docker secret is `0644`) |
| `$WEBDAV_PASSWORD` | Not in the arguments. Other processes of the same user can read it from the environment |
| Prompt: `--user` and no password from any source, on a terminal | No |

```console
$ printf '%s\n' "$SECRET" | dav ls --user alice --password-stdin webdavs://webdav.example.org/
$ dav ls --user alice --password-file /run/secrets/dav webdavs://webdav.example.org/
$ dav ls --user alice webdavs://webdav.example.org/        # asks: Password for alice:
```

`--password`, `--password-stdin` and `--password-file` exclude each other.
Only the line ending is removed from the password, spaces stay. An empty
stdin or file is an error. `--password-stdin` cannot be combined with
`dav put /dev/stdin ...`, which reads the same stream.

Some rules you may trip over:

- **The prompt only appears on a terminal** (standard input and standard
  error both). In cron, CI and pipelines `dav --user alice URL` still sends
  an empty password and never waits for input.
- **A password needs a user.** A password from `--password`, `--password-stdin`,
  `--password-file` or `:pass@host`, but no user from any source, is an error
  and no request is sent. An exported `$WEBDAV_PASSWORD` alone is not: it
  is ignored when there is no user, so it does not break requests to an
  anonymous server.
- **`$WEBDAV_PASSWORD` belongs to `$WEBDAV_USER`.** If `$WEBDAV_USER` is set
  and the user of the URL or `--user` is a different one, using
  `$WEBDAV_PASSWORD` for it is an error, so the password of one account is
  not sent as another account's. Without `$WEBDAV_USER`,
  `dav ls https://alice@host/` with `$WEBDAV_PASSWORD` set uses it for
  `alice`. Mind that the password goes to whichever host the URL names.
- **The userinfo of a URL is percent-decoded** (RFC 3986): write
  `al%40ice:p%40ss` for `al@ice` and `p@ss`. `+` and a `%` that is not
  followed by two hex digits stay as they are. A password that
  contains a literal `%` followed by two hex digits (`pa%41ss`) is therefore
  read as `paAss`; write `%25` for the `%` (`pa%2541ss`), or give such a
  password with `--password-stdin` or `--password-file`, which are never decoded.

```{warning}
A `webdav://` or `http://` URL would send the username and password in
clear text, and anyone on the network path could read them. `dav` refuses
that for every host but loopback, and says so; `--allow-insecure` sends them
anyway, with a warning. Use `webdavs://` or `https://`.

`--password` is visible to other local users via the process list. A
password in the URL (`user:pass@host`) is part of the command line as
well and is visible in the same way, and both stay in the shell history. On a
terminal, `dav` prints a note when it sees one. Use `--password-stdin`,
`--password-file` or `$WEBDAV_PASSWORD` instead. For an encrypted client key, use
`$WEBDAV_KEY_PASSWORD` instead of `--key-password`.
```

## Commands

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
$ dav lock webdavs://webdav.example.org/notes.txt
opaquelocktoken:6c1e0b5a-2f4d-4c0a-9d3e-0f1a2b3c4d5e
$ dav unlock webdavs://webdav.example.org/notes.txt opaquelocktoken:6c1e0b5a-2f4d-4c0a-9d3e-0f1a2b3c4d5e
```

`mv` and `cp` run on the server (`MOVE` and `COPY`). Both URLs must
therefore point at the same server.

`lock` prints the lock token on one line and leaves the lock on the
server until `unlock` releases it or it times out. It takes `--shared`,
`--depth 0|infinity`, `--lock-timeout SECONDS|infinite` (default 600) and
`--owner TEXT`. While the lock is held, writes from another `dav` call are
refused with `423`, because that call does not know the token.

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
| `--allowed-origin` | Repeatable. Talk only to this origin; a request or redirect to another server is refused |
| `--allow-insecure` | Send credentials over plain `http://` to a host that is not loopback, with a warning |
| `--no-proxy` | Ignore `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` from the environment |

`none` (or `unlimited`) removes the limit completely. A faulty or hostile
server can then send a response of any size, or keep a request open
without end. `0` is rejected, so a typo cannot remove a limit by accident.
`dav get` streams the download, so neither limit applies to it, see
[Session: Limits](session.md#limits-on-what-a-server-can-make-the-client-do).

## The environment

`dav` is `requests` underneath, and `requests` reads the environment:

- **Proxies.** `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and `NO_PROXY` apply
  to every request. A proxy sees a `webdav://` request completely, including
  the credentials, and for `webdavs://` it sees which host you connect to.
  `--no-proxy` ignores the proxy variables.
- **CA bundles.** `REQUESTS_CA_BUNDLE` and `CURL_CA_BUNDLE` are ignored.
  Without a TLS flag, the server is verified against the `certifi` bundle
  (a distribution may patch it to the system store), or against the CA that
  OpenSSL's `SSL_CERT_FILE` or `SSL_CERT_DIR` name. With `--key-password`,
  `--ciphers`, `--tls-min-version`, `--tls-max-version` or `--crl-cert`, it is
  the operating system's store instead, plus those two. Whoever controls your
  environment can choose the CAs you trust. Use `--ca-cert` to name the CA
  explicitly: the environment does not change it. `--no-proxy` ignores
  `SSL_CERT_FILE` and `SSL_CERT_DIR` as well.
- **`~/.netrc`** is not read.
- **An encrypted client key.** `--key-password` and `$WEBDAV_KEY_PASSWORD`
  hold the passphrase as plain text. In a library call, the same
  `key_password` is part of what `pickle` keeps of a `Session`, see
  [Session: Pickling and copying](session.md#pickling-and-copying).
