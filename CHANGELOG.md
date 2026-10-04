# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `webdav`/`webdavs` are now registered with fsspec via its `fsspec.specs` entry point.
- Documentation is now hosted at https://webdav.readthedocs.io.
- The Apache compliance suite now pins what Apache's `mod_dav` does, traced in its 2.4.69 source:
  ETag weakness, lock-null resources, the `If-None-Match: *` race, `If` header tagging, `Timeout`
  handling, `UNLOCK` errors, the `207` for a new member of a locked collection, and more (see
  `docs/apache-compliance-check.md`) - and how it behaves over time (locks that run out, connections
  the server closes, `Timeout`, `LimitRequestBody`), with large files and odd names, and with many
  clients at once. `WEBDAV_TEST_APACHE_PREFIX` runs it against an Apache built from the release tarball.

### Fixed

- `FileSystem.mkdir()` took every bodyless `400` from `MKCOL` for "already exists". Apache answers the
  same `400` for a path *below* a plain file, which does not exist: the `400` now only means
  `ResourceAlreadyExistsError` if the resource is there, and is raised as it is otherwise.
- The documentation promised an atomic `overwrite=False` / `"xb"` (`If-None-Match: *`) and a strong
  ETag from Apache's `FileETag`. It is as atomic as the server makes it - Apache's `mod_dav` checks the
  condition before it reads the body, so two creators at once can both succeed - and a fresh Apache ETag
  is weak for one second whatever `FileETag` says. The docstrings and the Apache page now say so, as they
  now do for lock-null resources (what a `LOCK` on an unmapped URL creates on Apache).
- Leaving `locked()` after the lock had run out logged "could not release the lock" on Apache, which
  answers `UNLOCK` for a token it no longer knows with `400`; it is now logged as a lock that is
  already gone, like the `404`/`409` of other servers.

## [1.0.0] - 2026-10-01

The first release.

### Added

- An RFC 4918 WebDAV client with two peer classes, like `os`/`pathlib.Path`: `webdav.Session` - built
  on `requests`, speaking its API (`auth=`, `headers=`, `verify=`, ...) plus the WebDAV verbs, but not
  a `requests.Session` subclass - and `webdav.FileSystem`, which treats a server like a local
  filesystem. Every `FileSystem` operation is also a module-level one-off
  (`webdav.ls(url)`, `webdav.upload_file(...)`, ...) with an identical signature (a test compares them,
  and the module functions are typed - and completed by your IDE - like the methods); `Session` has no
  module-level mirror, open one explicitly for protocol-level control. The HTTP verbs take a `url`, the
  file-system operations a `path`; uploads are `(local_path, path)`, downloads `(path, local_path)`;
  everything beyond the first argument(s) of a file-system operation - `props=`, `set_props=`, `data=`,
  `overwrite=`, ... - is keyword-only;
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
  - `request()` (and so every verb) takes `raise_on_error=` for a single call; `propfind(prop_name=True)`
    asks for property names only (RFC 4918 §9.1);
  - `Session(base_url)` takes paths, without one every call takes a full URL. Paths are plain names,
    percent-encoded exactly once, and what `ls` returns can be passed straight back.
- Class 2 locking (`FileSystem.locked()`, `refresh_lock()`): a held lock's token is attached to writes
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
- A `dav` command (`ls`, `info`, `cat`, `get`, `put`, `mkdir`, `rm`, `mv`, `cp`).
- An optional fsspec filesystem (`pip install webdav-rfc4918[fsspec]`, `webdav.fsspec.WebdavFileSystem`,
  protocol `webdavs`), run against fsspec's own conformance suite and against pandas, dask, pyarrow,
  zarr and xarray (fsspec 2024.12.0 or newer). Its paths start at the root of the `base_url`;
  `webdavs://host[:port]/path` names the server (https; credentials in the URL are refused); files are
  read in bounded `Range` requests and `cat_file` asks for exactly the bytes wanted; `cp`/`mv` replace a
  file but never a directory, and never copy or move a directory into itself; writers that create the
  same parent directory at once do not fail.
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
- **TLS verification is on by default, and disabling it is never quiet.** `verify=False` - and
  everything `requests` reads as false - is accepted (in the constructor, per call, as
  `session.verify`), but raises and logs a `TLSHardeningDisabledWarning` every time, immune to a
  plain `urllib3.disable_warnings()`. The TLS 1.2 floor and strict chain checking get the same
  treatment. `REQUESTS_CA_BUNDLE`/`CURL_CA_BUNDLE` never replace the configured CA, and a private CA
  given as `ca_files` is not widened by the public ones; `key_password` is hidden from `repr`.
- **Credentials in a URL are refused** (`https://user:pw@host/`): pass `auth=`. A pickled `Session`
  carries its credentials in clear - treat it like a password file. (Pickling and copying are supported
  so a session can be handed to another process - `multiprocessing`, `concurrent.futures`, file-system
  front ends; a callable you pass has to be picklable too.)
- **A mistake fails loudly instead of doing the opposite**: an unknown keyword argument (`allow_redirect=False`,
  `verfiy=True`, `timout=5`) is a `TypeError` like in `requests`, not silently ignored; every limit and
  setting (`timeout`, `base_url`, `redirect_policy`, `max_response_size`, `max_response_time`,
  `max_redirects`, `chunk_size`, `retry`) is checked when it is set, in the constructor and later; a
  flag (`allow_redirects`, `stream`, `raise_on_error`, `trust_env`) has to be a real `bool` - `0`, `""` or
  `"no"` is a `TypeError`, not quietly read as false (or `"false"` as true);
  `RedirectPolicy.WHITELIST` needs trusted origins also when set later or for one call.
- **Credentials do not leak**: not into exception messages, warnings or logs (URL userinfo and the query
  of a signed URL are redacted); an `InsecureTransportWarning` names host and port only.
- **Limits on what a server can make the client do**: `max_redirects` (5 in a row), `Retry-After` is waited
  for but never longer than 30 s, `max_response_size` (after decompression; stacked
  content-codings are refused), `max_response_time` (a deadline for the whole request, headers, trailers and interim responses
  included; streamed bodies are bounded per read, not in size), 200 000
  `<response>` elements per multistatus, hrefs of at most 8192 characters, `walk` limits, a positive
  `chunk_size`.
- **Server-controlled values are validated**: `Content-Length`/`Timeout` digits, XML encoding
  declarations, dates, lock tokens (a token that could close its `<...>` in an `If` header is refused),
  hrefs (an encoded `/` is refused; a listing entry outside the listed collection is refused; an
  unparseable or duplicate `<response>` can no longer hide a failure), 416 handling in resumed
  downloads. Nothing escapes as a bare `ValueError`. `Session.unlock()` drops a released token from
  `session.locks` (also when the server says it is gone: `404`/`409` for the URL it was recorded for);
  `FileSystem.locked()` reports an UNLOCK the server refused (`403`) or found no lock for (`409`), and a
  `207` answer to a `Depth: infinity` LOCK is a `MultiStatusError` naming the member, not a "malformed response"; `Session.lock()` records what it was granted (`track=False` opts out) and releases a lock it cannot read; a
  lock token the caller passes that is unusable is a `ValueError`, not a "malformed server response"; the table of status-code exceptions (what a retry repeats) is read-only.
- **The local side**: `download_file` writes a temporary file and moves it into place when complete
  (`overwrite=False` by default, atomic no-clobber, never through a symlink, permissions of a replaced
  file kept, no process-wide `umask` change); `dav rm` refuses a non-empty collection
  without `-r`/`recursive=True`; the CLI escapes control characters in names and errors.
- **Safe defaults**: `propfind(depth=)` is required, `copy`/`move` do not overwrite unless told to,
  secondary parameters are keyword-only, `isdir`/`isfile` are `False` for what does not exist.
- **Supply chain**: `requests>=2.32.4`, `urllib3>=2.7.0` (past CVE-2024-35195, CVE-2024-47081,
  CVE-2025-66418, CVE-2026-21441, CVE-2026-44431, CVE-2026-44432), release job checks the tag against the
  version, workflows pinned by commit, no long-lived publishing token.

[Unreleased]: https://github.com/manfred-kaiser/webdav-rfc4918/compare/1.0.0...main
[1.0.0]: https://github.com/manfred-kaiser/webdav-rfc4918/releases/tag/1.0.0
