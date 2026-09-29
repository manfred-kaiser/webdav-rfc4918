# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

The first release.

### Added

- An RFC 4918 WebDAV client on top of `requests`, in the shape of `requests`:
  - module-level functions for one-off calls (`webdav.get(url)`, `webdav.propfind(url, depth=1)`,
    `webdav.ls(url)`, ...) and one class, `webdav.Session` - a `requests.Session` - with the same names
    and arguments (a test keeps every `webdav.<name>` signature and return type identical to `Session.<name>`, and the
    module functions are typed - and completed by your IDE - like the methods; the HTTP verbs take a `url`, the file-system operations a `path`; uploads are
    `(local_path, path)`, downloads `(path, local_path)`; everything beyond the first argument(s) of a file-system
    operation - `names=`, `set_props=`, `data=`, `overwrite=`, ... - is keyword-only);
  - the HTTP/WebDAV **verbs** (`get`, `put`, `delete`, `head`, `options`, `propfind`, `proppatch`,
    `mkcol`, `copy`, `move`, `lock`, `unlock`) return a `webdav.Response` (a `requests.Response` with
    `.multistatus`, `.active_lock` and a WebDAV-aware `raise_for_status()`) and, like `requests`, do
    not raise for an error status unless asked to;
  - `walk()` is like `os.walk`, but its directories and files are the same `Resource`s `ls` returns
    (full names, usable as they are), and `open` is public like `gzip.open`;
  - the **file-system operations** (`ls`, `info`, `exists`, `isdir`, `isfile`, `get_props`,
    `set_props`, `mkdir`, `remove`, `open` (read and write), `walk`, `upload_file`, `download_file`,
    `upload_fileobj`, `download_fileobj`, `locked`, `refresh_lock`, ...) return plain values and raise
    a `WebDAVError` on failure;
  - `Session(base_url)` takes paths, without one every call takes a full URL. Paths are plain names,
    percent-encoded exactly once, and what `ls` returns can be passed straight back.
- Class 2 locking (`Session.locked()`, `refresh_lock()`): a held lock's token is attached to writes
  automatically, also for the members of a locked collection (RFC 4918 §7.4) and for COPY/MOVE, as
  tagged `If` lists (§10.4); reads never carry one. Locks are requested for 600 s unless told otherwise.
- Conditional writes (`put(if_match=..., overwrite=False)`, `delete(if_match=...)`), extended MKCOL,
  `propfind(props=...)`, `proppatch(set_props=..., remove_props=...)`, `Resource`
  (a `str` - the name - with `.href`, `.is_dir`, `.size`, `.created`, `.modified`, `.etag`,
  `.content_type`, `.content_language`, `.display_name`): the one type `ls` (a list of them) and `info`
  return, so what one shows the other can be passed to.
- Resumable, verified streaming downloads; `open(path, "w"/"wb"/"x"/"xb")` uploads on a clean `with`
  exit only; `walk()` like `os.walk` (one `Depth: 1` request per collection, cycle-safe).
- mTLS with encrypted keys, CRL checking and cipher restriction (`TLSOptions`).
- An fsspec filesystem (`webdav.fsspec.WebdavFileSystem`) and a `dav` command (`ls`, `info`, `cat`,
  `get`, `put`, `mkdir`, `rm`, `mv`, `cp`).
- Retries of transient failures with backoff - for the safe methods only (`GET`, `HEAD`, `OPTIONS`,
  `PROPFIND`): a retried write reports the opposite of what happened when the first try had worked.

### Security

A malicious or compromised server, or a path to one, is the attacker this library is written against.
The design decisions, each covered by tests (several found by independent audits and reproduced before
they were fixed):

- **Redirects** are followed by the library, never by `requests`, under an explicit `RedirectPolicy`
  (`NEVER`, `SAME_ORIGIN` - the default, `WHITELIST`, `ALL`). Every hop is judged against the origin the
  request *started at*. A request to another origin is built from scratch and sent through a plain
  adapter: no credentials (no `~/.netrc` either), no cookies - and none of the answer's are kept -, no
  session headers, no client certificate, no lock token; of the caller's own headers only the
  representation/conditional ones (plus `Session.redirect_forward_headers`). `https` -> `http` is never
  followed; `303` only for `GET`/`HEAD`; a body that cannot be re-sent is not re-sent; loops and
  ambiguous or unparseable targets are refused (the two URL parsers involved must agree on the host).
  `Session.send()` sends one request and never follows a redirect.
- **TLS verification cannot be switched off.** `verify=False` - and everything `requests` reads as
  false - is refused in the constructor, per call and as `session.verify`. `REQUESTS_CA_BUNDLE`/
  `CURL_CA_BUNDLE` never replace the configured CA, and a private CA given as `ca_files` is not widened
  by the public ones. TLS 1.2 is the floor; `key_password` is hidden from `repr`.
- **Credentials in a URL are refused** (`https://user:pw@host/`): pass `auth=`. A pickled `Session`
  or an fsspec `to_json()` carries its credentials in clear - treat it like a password file.
- **Credentials do not leak**: not into exception messages, warnings or logs (URL userinfo and the query
  of a signed URL are redacted); an `InsecureTransportWarning` names host and port only.
- **Limits on what a server can make the client do**: `max_response_size` (after decompression; stacked
  content-codings are refused), `max_response_time` (a deadline for the whole request, headers, trailers and interim responses
  included; streamed bodies are bounded per read, not in size), 200 000
  `<response>` elements per multistatus, hrefs of at most 8192 characters, `walk` limits, a positive
  `chunk_size`.
- **Server-controlled values are validated**: `Content-Length`/`Timeout` digits, XML encoding
  declarations, dates, lock tokens (a token that could close its `<...>` in an `If` header is refused),
  hrefs (an encoded `/` is refused; a listing entry outside the listed collection is refused; an
  unparseable or duplicate `<response>` can no longer hide a failure), 416 handling in resumed
  downloads. Nothing escapes as a bare `ValueError`.
- **The local side**: `download_file` writes a temporary file and moves it into place when complete
  (`overwrite=False` by default, atomic no-clobber, never through a symlink, permissions of a replaced
  file kept, no process-wide `umask` change); `dav rm` and fsspec `rm` refuse a non-empty collection
  without `-r`/`recursive=True`; the CLI escapes control characters in names and errors.
- **Safe defaults**: `propfind(depth=)` is required, `copy`/`move` do not overwrite unless told to,
  secondary parameters are keyword-only, `isdir`/`isfile` are `False` for what does not exist.
- **Supply chain**: `requests>=2.32.4`, `urllib3>=2.7.0` (past CVE-2024-35195, CVE-2024-47081,
  CVE-2025-66418, CVE-2026-21441, CVE-2026-44431, CVE-2026-44432), release job checks the tag against the
  version, workflows pinned by commit, no long-lived publishing token.

[Unreleased]: https://github.com/manfred-kaiser/webdav-rfc4918/compare/0.1.0...main
