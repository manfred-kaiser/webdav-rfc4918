# Apache mod_dav compliance check

`tests/test_session_e2e.py` runs automatically against `wsgidav` (pure
Python, no system dependency). `tests/test_apache_compliance.py` is a
separate cross-check against a real Apache + `mod_dav` instance - an
independent implementation, useful because WebDAV servers are known to
disagree on locking/property edge cases in particular, and because this
project's primary deployment target is Apache specifically. It is an
ordinary `pytest` suite (over 100 tests, reproducible like any other) - not
"manual" in the sense of needing a human to drive it, just opt-in:

- **If Apache is installed** (`httpd` + the `mod_dav*` modules - see
  `tests/apache_instance.py`), running `pytest` - the whole suite, or just
  `pytest tests/test_apache_compliance.py` - automatically starts a
  throwaway instance, runs these tests against it, and stops it again
  afterwards. No flags, no environment variables, nothing to remember.
- **If it is not installed**, the same `pytest` run skips this file with a
  clear reason (visible in the `-ra` summary) instead of failing.
- **On GitHub**, this runs as its own workflow
  (`.github/workflows/apache-compliance.yml`, a separate status/badge from
  the main `ci.yml`), which installs Ubuntu's `apache2` package first -
  `ci.yml`'s own jobs still skip this file, same as any environment without
  Apache installed. It is a required status check on `main`: a failure
  here blocks a merge like one in `ci.yml`.
- **To point at a specific instance instead** (a remote one, or one with
  non-default configuration you want to test against), set
  `WEBDAV_TEST_APACHE_URL` (`WEBDAV_TEST_APACHE_USER`/`_PASSWORD` default to
  `testuser`/`testpass123`) - then that instance is used as-is and nothing
  is started or stopped automatically.

A handful of tests need a *second*, differently configured instance next to
the shared one (`FileETag`, `DavDepthInfinity`, `DavMinTimeout`, no
`DavLockDB`, no `mod_dav_lock`, `KeepAliveTimeout`, `MaxKeepAliveRequests`,
`Timeout`, `LimitRequestBody`: ports 8781-8789, see `_PORTS` in the test
module). The suite takes about forty seconds, most of it waiting for locks
to run out and connections to be closed. They start and stop it themselves, and are skipped when only a
remote instance (`WEBDAV_TEST_APACHE_URL`) is available.

## Automatic (plain `pytest`)

```console
$ sudo zypper install apache2 apache2-utils   # once, if not already installed
$ pytest tests/test_apache_compliance.py -v
```

That is the whole thing - `pytest`'s own `-n0`-equivalent single-worker
grouping is handled automatically too (see "Why single-worker" below), via
`@pytest.mark.xdist_group` and this project's `--dist=loadgroup` pytest
config, so this also works correctly as part of a full, parallel `pytest`
run (not just this one file in isolation).

Run it twice in a row to see for yourself that it is reproducible - each
run starts from a clean `dav-root` and tears Apache down at the end, so the
next run starts from the same state as the first.

## Against a build of your own

Set `WEBDAV_TEST_APACHE_PREFIX` to the install directory of an Apache built
from the release tarball (`bin/httpd`, `bin/htpasswd`, `modules/`) and the
fixture uses that one, before the distro layouts:

```console
$ ./configure --prefix=$HOME/.local/opt/httpd-2.4.69 --with-apr=... --with-apr-util=... \
      --with-pcre=.../pcre2-config --enable-dav --enable-dav-fs --enable-dav-lock \
      --enable-mods-shared=few --enable-so --with-mpm=prefork
$ make -j && make install
$ WEBDAV_TEST_APACHE_PREFIX=$HOME/.local/opt/httpd-2.4.69 pytest tests/test_apache_compliance.py
```

(The prefork MPM is compiled in, `mod_unixd` is a loadable module there -
`tests/apache_instance.py` knows both.) Reading the sources of the release you
test is the way to find out *why* it answers as it does: the findings below
name the function that decides each one - read the 2.4.x tarball, not trunk,
which has changed some of them (e.g. `dav_fs_get_resource` answers 404 there
where 2.4.69 answers 400).

## Manual control: `tools/apache_compliance_check.py`

For more control than the automatic fixture gives you - a specific
instance directory, leaving Apache running afterwards to poke at by hand,
or passing extra arguments through to pytest:

```console
$ python tools/apache_compliance_check.py
$ python tools/apache_compliance_check.py --keep-running   # inspect/retry by hand afterwards
$ python tools/apache_compliance_check.py --no-clean       # keep dav-root from the previous run
$ python tools/apache_compliance_check.py -- -k lock -v    # extra args go straight to pytest
$ python tools/apache_compliance_check.py --instance-dir /tmp/my-instance
```

This uses the exact same `tests/apache_instance.py` the automatic fixture
does (one implementation, so the two can never drift apart) - checks the
prerequisites (and says exactly what is missing, with the package name,
rather than failing confusingly later), writes a throwaway instance under
`/tmp/apache-webdav-test`, starts Apache, runs
`tests/test_apache_compliance.py` against it, and stops Apache again
afterwards - even on a test failure or Ctrl-C. Exit code is pytest's.

Both this script and the automatic fixture know two layouts out of the box
(`tests/apache_instance.py`'s `_PROFILES`): openSUSE/RPM
(`/usr/sbin/httpd`, `/usr/lib64/apache2-prefork/`) and Debian/Ubuntu
(`/usr/sbin/apache2`, `/usr/lib/apache2/modules/`) - the first one that is
actually fully present (binary and every required module) wins. On a
distro that is neither, add a profile there (the module filenames
themselves - `mod_dav.so` etc. - are the same everywhere; only the binary
name and install paths differ).

## Standing it up by hand (what `tests/apache_instance.py` automates)

Useful if you want to poke at the instance directly, or if its assumptions
do not fit your setup.

```console
$ sudo zypper install apache2 apache2-utils
```

`mod_dav`/`mod_dav_fs`/`mod_dav_lock` ship inside the base `apache2`
package (`/usr/lib64/apache2-prefork/mod_dav*.so`) - no extra package
needed.

```console
$ mkdir -p /tmp/apache-webdav-test/{logs,dav-root,locks}
$ htpasswd -bc /tmp/apache-webdav-test/htpasswd testuser testpass123
```

`/tmp/apache-webdav-test/httpd.conf`:

```apache
ServerRoot "/tmp/apache-webdav-test"
ServerName localhost
Listen 127.0.0.1:8765

PidFile "logs/httpd.pid"
ErrorLog "logs/error.log"
LogLevel warn

LoadModule authn_core_module   /usr/lib64/apache2-prefork/mod_authn_core.so
LoadModule authz_core_module   /usr/lib64/apache2-prefork/mod_authz_core.so
LoadModule authn_file_module   /usr/lib64/apache2-prefork/mod_authn_file.so
LoadModule authz_user_module   /usr/lib64/apache2-prefork/mod_authz_user.so
LoadModule auth_basic_module   /usr/lib64/apache2-prefork/mod_auth_basic.so
LoadModule mime_module         /usr/lib64/apache2-prefork/mod_mime.so
LoadModule log_config_module   /usr/lib64/apache2-prefork/mod_log_config.so
LoadModule dav_module          /usr/lib64/apache2-prefork/mod_dav.so
LoadModule dav_fs_module       /usr/lib64/apache2-prefork/mod_dav_fs.so
LoadModule dav_lock_module     /usr/lib64/apache2-prefork/mod_dav_lock.so

DavLockDB "locks/davlock"

# Must be an ABSOLUTE path in both directives, and they must match
# exactly - a relative "dav-root" in <Directory> silently failed to
# match this DocumentRoot on Apache/2.4.67, leaving the whole block
# (Dav On *and* the auth Require) inactive with no error logged.
DocumentRoot "/tmp/apache-webdav-test/dav-root"

<Directory "/tmp/apache-webdav-test/dav-root">
    Dav On
    Options None
    AllowOverride None
    AuthType Basic
    AuthName "webdav-rfc4918 test"
    AuthUserFile "/tmp/apache-webdav-test/htpasswd"
    Require valid-user
</Directory>
```

Runs as the invoking (non-root) user - no `User`/`Group` directive, since
this only binds to a local, unprivileged port.

```console
$ /usr/sbin/httpd -f /tmp/apache-webdav-test/httpd.conf -k start
$ WEBDAV_TEST_APACHE_URL=http://127.0.0.1:8765 \
  WEBDAV_TEST_APACHE_USER=testuser \
  WEBDAV_TEST_APACHE_PASSWORD=testpass123 \
  hatch test tests/test_apache_compliance.py -v
$ /usr/sbin/httpd -f /tmp/apache-webdav-test/httpd.conf -k stop
```

(`pytest tests/test_apache_compliance.py -v` works the same, without
`hatch`, from an already-activated virtualenv.)

### Why this is safe under parallel `pytest` (`-nauto`)

Unlike `wsgidav` (a fresh `tmp_path` per test, via the `server_url`
fixture), this Apache instance's `dav-root` is one shared, persistent
directory for the whole run - naive parallelism would race tests against
each other on it (two workers' `mkdir("compliance")` colliding, one test's
leftover file making the next one's `overwrite=False` fail, two workers'
`httpd -k start` both trying to bind the same port, ...). This project's
`[tool.pytest.ini_options].addopts` sets `--dist=loadgroup`, and every test
in `tests/test_apache_compliance.py` carries `@pytest.mark.xdist_group`
(applied once, via the module's `pytestmark`) - together these pin the
whole file to a single xdist worker, deterministically, so it is safe to
just run `pytest` (the whole suite, `-nauto` and all) without thinking
about this at all. (`xdist_group` alone does nothing - it is silently
ignored under the default `--dist=load`; `--dist=loadgroup` is what makes
it take effect, without changing how every *other* test file distributes.)

Running a subset with `-k` still needs whatever that subset depends on:
most of these tests build on a shared `compliance/` directory one of them
creates, so `-k` has to either include that test too or find the directory
already there from a previous, uncleaned run.

If you stand an instance up by hand (above) and use `WEBDAV_TEST_APACHE_URL`
to point at it, this project's own `dav-root` grouping does not apply to
*your* instance's state, obviously - clear it yourself between runs
(`rm -rf /tmp/apache-webdav-test/dav-root/*`) if a previous run left files
behind. The automatic fixture and `tools/apache_compliance_check.py` both
do this for you by default (`--no-clean` opts out, for the script).

## What Apache does, and why

Each of these was measured against a real 2.4.69 instance (`curl`, bypassing
this library entirely, and the tests named below) *and* traced in the source
of that release - the function that decides it is named. None of them is a bug
in `mod_dav`: RFC 4918 leaves most of them open. All of them matter if Apache is
the server this library talks to in production.

### ETags

- **`getetag` is weak (`W/"..."`) for a file changed less than a second
  ago, and strong after that.** The rule is `request_time - mtime < 1s` in
  the core (`ap_make_etag_ex`, `modules/http/http_etag.c`); no setting
  changes it. `FileETag INode MTime Size` only changes what the value is made
  of - the earlier advice to configure it to get a strong ETag was wrong.
  Pinned by `test_apache_etag_is_weak_right_after_a_write`,
  `..._is_strong_once_the_file_is_a_second_old` and
  `test_apache_file_etag_directive_does_not_make_a_fresh_etag_strong`.
- **So the ETag taken right after a write cannot be used for `If-Match`.**
  RFC 9110 sec. 13.1.1 requires strong comparison, `strong_etag()` refuses a
  weak one client-side (`ValueError`), and Apache itself answers a `W/...`
  `If-Match` with `412` - even its own current ETag. Ask again after a second.
  The answer to the `PUT` carries no `ETag` header at all. Pinned by
  `test_apache_a_weak_etag_taken_right_after_a_write_is_refused_client_side`,
  `..._if_match_with_the_strong_etag_of_an_aged_file_replaces_it`,
  `test_apache_refuses_a_weak_if_match_on_its_own` and
  `test_apache_put_response_carries_no_etag_header`.

### Creating things

- **`overwrite=False` (`If-None-Match: *`) is not atomic on Apache.**
  `dav_method_put` checks the condition (`dav_validate_request`) when the
  request arrives, then streams the body into a temporary file and renames it
  over the target (`dav_fs_close_stream`, `apr_file_rename`). A creator that
  arrives and finishes in between does not stop the one already let through:
  its file is replaced, and both are told `201`. A sequential second creator
  is refused with `412` as expected. Where exactly one writer must win, hold a
  lock (which Apache does enforce). Pinned by
  `test_apache_if_none_match_star_is_checked_before_the_body_is_read` (a
  deterministic demonstration: the first request is held up halfway through its
  body), `test_apache_concurrent_if_none_match_star_creators_only_ever_get_201_or_412`,
  `test_apache_a_sequential_second_creator_is_refused` and
  `test_apache_a_lock_makes_the_creator_exclusive`.
- **`MKCOL` on an existing plain resource: `405` without, `400` with the
  trailing slash.** `FileSystem.mkdir()` always sends the slash (RFC 4918 sec.
  5.2); `dav_fs_get_resource` then sees "extraneous path components" below a
  file and answers `400` (2.4; trunk: `404`). The same `400` answers a path
  *below* a file, which does not exist - so `mkdir()` only reports
  `ResourceAlreadyExistsError` for the `400` if a `PROPFIND` finds the
  resource (without the slash), and otherwise raises the `400`. Pinned by
  `test_apache_mkcol_on_an_existing_file_is_405_but_400_with_the_trailing_slash`,
  `..._mkdir_on_a_file_is_already_exists_but_below_a_file_it_is_not`, and, with
  a scripted server, the `test_a_400_from_mkcol_...` tests in
  `tests/test_rfc_compliance.py`.
- **Racing `MKCOL`s: one `201`, the others refused - mostly `405`, some `403`.**
  `dav_fs_create_collection` maps every `apr_dir_make` error except
  ENOSPC/ENOENT to `403`, so a loser that passed the "exists" check and then
  met EEXIST gets `403` ("Unable to create collection"), not the `405` of
  RFC 4918 sec. 9.3.1. `makedirs(exist_ok=True)` in the fsspec layer accepts
  that when the collection is there afterwards. Pinned by
  `test_apache_a_mkcol_race_has_one_winner_and_the_rest_are_refused`.
- **No RFC 5689 (Extended MKCOL):** `extended-mkcol` is absent from the `DAV`
  header, and *any* `MKCOL` body - whatever it says, with or without a
  `Content-Type` - gets `415` (`process_mkcol_body`) and creates nothing.
  `build_mkcol_body()`/`parse_mkcol_response()` still work against a server
  that supports it (unit-tested against RFC 5689's own examples).

### Locking

- **A `LOCK` on an unmapped URL creates a *lock-null* resource, not an empty
  file.** Apache implements RFC 2518 sec. 7.4 (`dav_fs_add_locknull_state`: an
  entry in `.DAV/.locknull`, no file): `PROPFIND` finds it (so `exists()` is
  true, and `isfile()` too - its `resourcetype` is empty and there is no
  `getetag`/`getcontentlength` to tell it from an empty file), `GET` and `HEAD`
  answer `404`, the parent's `Depth: 1` listing names it. It is gone after
  `UNLOCK` (`dav_fs_remove_locknull_member`) - unless a `PUT` through the lock
  filled it first: that makes a real file that outlives the lock. This is not
  Apache using RFC 4918's latitude ("SHOULD NOT disappear"); it is the model
  RFC 4918 replaced. wsgidav does create the empty resource. Pinned by
  `test_apache_lock_on_an_unmapped_url_is_lock_null_and_not_a_resource`,
  `..._looks_like_an_empty_file`, `..._put_with_the_token_makes_a_lock_null_resource_a_real_file`
  and `..._put_without_the_token_cannot_fill_a_lock_null_resource`.
- **`Timeout`:** the first token Apache understands wins, in the order sent
  (`Second-30, Second-3600` is 30, not the shorter or the longer one);
  `Infinite`, nothing it understands, and no header at all are all infinite
  (`dav_get_timeout`). The client's own default is 600 seconds
  (`DEFAULT_LOCK_TIMEOUT`), `lock_timeout=None` asks for infinite. `DavMinTimeout`
  raises a shorter timeout (not an infinite one) to its minimum. A refresh
  (`LOCK` with `If`, no body) answers the new timeout and no `Lock-Token`
  header. Pinned by `test_apache_lock_timeout_header`, `..._a_lock_without_a_timeout_never_runs_out`,
  `..._the_client_asks_for_600_seconds_by_default_and_for_none_with_none`,
  `..._a_refresh_answers_the_new_timeout_and_no_lock_token` and
  `test_apache_davmintimeout_raises_a_short_timeout_but_not_infinite`.
- **`UNLOCK` with anything but the right token is a `400`** - no header, no
  angle brackets, `<>`, garbage, an unknown token, the token of another
  resource, a token already released (and a second `UNLOCK` with the right
  one) - never `403`/`409`/`412` (`dav_method_unlock`, and the dummy `If`
  header `dav_validate_request` builds from the `Lock-Token`). The lock stays.
  Pinned by `test_apache_unlock_with_anything_but_the_right_token_is_a_400`.
- **Shared locks:** several coexist (also for one principal), any *one* of the
  tokens is enough to write, none is a `423`; an exclusive and a shared lock
  exclude each other in both directions. A `LOCK` without a `Depth` header is
  `infinity`. Pinned by `test_apache_any_one_shared_token_is_enough_to_write`
  and the lock-scope tests above it.
- **`DAV: 1,2` does not mean locking works.** The class comes from the
  provider having lock hooks (`dav_method_options`) - `mod_dav_fs` always has
  them. Without a `DavLockDB` it still advertises `2`, and a `LOCK` is a `500`
  ("A lock database was not specified"). `mod_dav_lock` is a different, generic
  provider's lock store and is not needed: locking works without it as long as
  `DavLockDB` is set. Pinned by
  `test_apache_without_a_lockdb_it_advertises_class_2_and_cannot_lock` and
  `test_apache_locking_needs_the_lockdb_of_mod_dav_fs_but_not_mod_dav_lock`.

### The `If` header and what a lock does to its neighbours

- **An untagged `If: (<token>)` is evaluated for every resource the method
  touches** (`dav_validate_resource_state`) - source and destination of a
  `COPY`/`MOVE`, the new member of a collection. A list that asserts a token the
  resource does not hold is false, so the whole request is `412`; a list *tagged*
  with another URL simply does not apply to it. That is why the session tags
  every token with the URL of the lock (what `Session.copy`/`move` and the
  write methods send): onto a locked file, `COPY` is `423` without a token, `412`
  with an untagged one, `204` with one tagged for the destination. Pinned by
  `test_apache_untagged_if_with_...` (three tests) and
  `test_apache_the_session_tags_the_tokens_it_sends`.
- **A new member of a locked collection is a `207`, not a `423`.** With the
  collection locked by someone else, a `PUT` or `MKCOL` of a *new* name answers
  `207 Multi-Status` (`DAV_VALIDATE_PARENT`): the new member is `424 Failed
  Dependency`, the collection `423 Locked` - and nothing is created. A status
  a `PUT` is not expected to answer; the client raises `MultiStatusError`
  naming the collection, not `ResourceLockedError`. An *existing* member of a
  collection locked with `Depth: infinity` is a plain `423`. The holder of the
  lock writes there normally. Pinned by
  `test_apache_a_new_member_of_a_locked_collection_is_a_207_and_not_created`,
  `..._an_existing_member_of_an_infinity_locked_collection_is_a_plain_423` and
  `..._the_client_reports_a_new_member_in_a_locked_collection_as_a_multistatuserror`.
- **A collection operation blocked by a locked member answers `424` (not
  `207`) with a full multistatus underneath, and does nothing.**
  `DAV_VALIDATE_USE_424` makes `DELETE`/`COPY`/`MOVE` refuse up front: the
  body names exactly the blocking resource (`423 Locked`) - for a `MOVE` out of
  a locked collection that is the collection - and the other members are left
  alone. RFC 4918 sec. 13 ties this detail to a `207`; handled transparently
  (`webdav.dav.multistatus.multistatus_failure`), the specific
  `MultiStatusError` is raised. Pinned by
  `test_apache_delete_blocked_by_a_locked_member_is_a_424_that_deletes_nothing`,
  `..._move_out_of_a_locked_collection_is_a_424_naming_the_collection` and, in
  `tests/test_rfc_compliance.py`,
  `test_a_multistatus_body_under_a_non_207_status_still_raises_multistatuserror`.
- **A `423` has no `<D:error>` body.** Nothing in `mod_dav` builds one for a
  lock (`dav_new_error_tag` has no caller), so it is the core's plain HTML
  error page; `error_codes` is empty. Pinned by
  `test_apache_423_is_the_cores_html_error_page_and_never_a_dav_error`.

### Properties and reading

- **A failed `PROPPATCH` is a `207` with a `409` and a status line of its
  own.** A live property (`getcontentlength`, ...) is read-only ("Property is
  read-only."); `dav_failed_proppatch` writes the status line itself with a
  literal `(status)` where the reason phrase belongs - `HTTP/1.1 409 (status)`.
  The update is all or nothing: a writable property in the same request fails
  with it. Pinned by `test_apache_a_failed_proppatch_is_a_207_with_a_409_and_a_status_line_of_its_own`,
  `..._the_client_names_the_read_only_property` and `..._a_proppatch_is_all_or_nothing`.
- **`PROPFIND` with `Depth: infinity` - or no `Depth` header, which means the
  same - on a collection is a `403`** unless `DavDepthInfinity On`
  (`dav_method_propfind`). A file needs no `Depth`. This library has no default
  depth on purpose. Pinned by
  `test_apache_depth_infinity_and_no_depth_at_all_are_forbidden_on_a_collection`,
  `..._a_file_needs_no_depth` and `..._depth_infinity_is_answered_with_davdepthinfinity_on`.
- **`GET` is the core's, not `mod_dav`'s** (`handle_get` is off for the
  filesystem provider): ranges work (`206`, `Content-Range`, `416` for an
  unsatisfiable one) and a collection is refused by the default handler
  ("Attempt to serve directory") with a `404` when no `mod_dir`/`mod_autoindex`
  is loaded - what `GET` on a collection answers depends on that configuration.
  `COPY` of a collection needs no trailing slash (unlike nginx); `Overwrite: F`
  onto an existing destination is `412` for `COPY` and `MOVE`; a destination
  with a missing parent is `409`. Pinned by `test_apache_ranges_are_answered_by_the_core`,
  `test_apache_get_on_a_collection_is_the_cores_404` and the `COPY`/`MOVE` tests
  after them.

### Over time

- **A lock that runs out is dropped when the next request looks at it** (no
  timer sweeps them). From then on the resource is free for everybody, and
  the old token is worth nothing: a write with it is `412`, a refresh is
  `412`, and `UNLOCK` of it is `400` (not `409`). Through the client, a write
  under an expired lock is `PreconditionFailedError`, and leaving the
  `locked()` block logs "already gone" - the `400` is treated like the `409`/`404`
  of other servers. Pinned by `test_apache_an_expired_lock_is_gone_and_its_token_is_refused`
  and `test_apache_the_client_meets_an_expired_lock_with_a_412_and_a_log_line`.
- **A lock on an unmapped URL that nobody released leaves a ghost.** Once its
  lock has run out, the lock-null entry (see "Locking") stays: `PROPFIND` on the
  path still answers, so `exists()` and `isfile()` stay true, `GET` is `404`, and
  `DELETE` cannot remove it (`404`). Another `LOCK` + `UNLOCK` of the path, or
  a `PUT`/`MKCOL` on it, clears it. Pinned by
  `test_apache_an_expired_lock_null_resource_stays_visible_until_it_is_locked_again`.
- **...and it breaks the next listing of its collection - an Apache bug.**
  `PROPFIND` with `Depth: 1` drops an expired lock-null entry while it has the
  lock database open read-only, which `mod_dav`'s `DAV_DEBUG` check (compiled
  in unconditionally - `#if 1` in `mod_dav.h` - not a setting) turns into
  "INTERNAL DESIGN ERROR: the lockdb was opened readonly" in the error log, after
  the answer has started: the client sees the connection closed with no
  response (`requests.exceptions.ConnectionError`). The entry is dropped all the
  same, so the next listing works: one failed listing per expired entry. A
  `PROPFIND` of the collection itself (`Depth: 0`) is not affected. `ls()` is
  retried (three attempts), which covers up to two entries; more raise
  `ConnectionError` on the first call and work on the next. The only way to
  avoid it is not to leave a lock on a name nothing is written to - release
  what `locked()` took, and give such a lock a short `lock_timeout`. Pinned by
  `test_apache_a_listing_that_meets_an_expired_lock_null_entry_is_aborted_once_per_entry`,
  `..._ls_gets_through_an_expired_lock_null_entry_by_retrying` and
  `..._ls_fails_once_past_the_retries_and_then_works_for_a_collection_with_many`.
- **Connections the server closes are not errors.** With `MaxKeepAliveRequests 3`
  (every third answer says `Connection: close`) and `KeepAliveTimeout 1` (the
  pooled connection is gone when the next request goes out) the client reconnects
  before it sends - writes included, which are never retried. Pinned by
  `test_apache_a_connection_the_server_closes_after_a_few_requests_is_not_an_error`
  and `..._that_idled_past_the_keepalive_timeout_is_not_an_error`.
- **A stalled upload is a `408`.** With `Timeout 1` a body that stops for longer
  than that is answered `408 Request Timeout` (`HTTPStatusError`, not retried:
  a `PUT`), nothing is stored - not even a temporary file the next listing
  could show - and a slow but moving upload is fine. Pinned by
  `test_apache_gives_up_on_a_stalled_upload_with_408_and_creates_nothing`.
- **`LimitRequestBody` is a `413` before anything is stored** - announced by its
  length (even 40 MiB, refused before it is sent), or streamed without one - and
  a file that was there stays as it was. Pinned by
  `test_apache_limitrequestbody_refuses_with_413_before_anything_is_stored`.

### Size and names

- **Large files and streams:** a 48 MiB file round-trips byte for byte, a range
  far into it (`bytes=40 MiB-`) is answered from the right place, an upload of
  unknown length goes out `Transfer-Encoding: chunked` and arrives complete, an
  empty file is stored empty. A collection of 1200 members is listed in full and
  removed with one `DELETE`. Pinned by `test_apache_a_large_file_round_trips_byte_for_byte`,
  `..._an_upload_of_unknown_length_is_streamed_chunked_and_complete`,
  `..._an_empty_file_is_stored_and_read_back_empty` and
  `..._a_collection_of_many_members_is_listed_in_full_and_removed_at_once`.
  (Throughput and memory are in [Performance and concurrency](reference/performance.md).)
- **Names survive being a URL.** Spaces, `#`, `?`, `%`, `%20` (stays six
  characters), `%2F`, `+`, `&`, `;`, `=`, quotes, `<>`, `|`, `[]`, non-ASCII
  (Japanese, emoji, a combining accent), leading and trailing spaces, dot names
  and a 255-byte name are stored and listed under exactly that name. Names that
  differ only in case are two resources. A name longer than 255 *bytes* (256
  ASCII characters, or 128 two-byte ones) is a `403` - the file system's
  limit, as `apr_file_open` fails - and `.DAV`, Apache's own state directory, is
  a `403` at any level (`dav_fs_is_state_path`). Pinned by
  `test_apache_a_name_survives_the_round_trip` (one case per name),
  `..._a_name_longer_than_255_bytes_is_a_403` and
  `..._the_lock_database_directory_cannot_be_written`.

### Parallel

Many clients at once, against Apache's prefork processes, one lock database and
temporary files that are renamed into place.

- **Parallel uploads** through one shared `FileSystem` arrive intact.
- **Simultaneous overwrites leave one whole file** - the temporary file is
  renamed over the target - and **a reader never sees a half-written file**.
- **A source can be copied any number of times at once, but only moved or
  deleted once.** The losers are told an error: `404` (gone when they looked),
  `500` (gone between looking and renaming - `dav_fs_move_resource`: "Could not
  rename resource" for the `ENOENT`) or `403` (a failed removal, seen on Ubuntu).
  Which one is timing, so only "exactly one wins" is pinned.
- **Many simultaneous `LOCK`s on one resource:** every answer is `200` or `423`,
  at least one is `200`. With sdbm exactly one is.
- **Simultaneous `LOCK`s on different resources:** every one is told `200`, with a
  token of its own. With sdbm every lock is there afterwards.
- **Simultaneous `PROPPATCH`es of different properties on one resource** are all
  told `207`, and no property ever has a wrong value. With sdbm all of them are
  there afterwards.
- **Through the client**, a contended `locked()` is held by one and refused
  (`ResourceLockedError`) for the others, and the session keeps no token. With
  sdbm no lock is left on the server.

"With sdbm" is the catch, see the next section. Pinned by the
`test_apache_parallel_...`, `..._simultaneous_...`, `..._of_many_simultaneous_locks_...`,
`..._a_reader_never_sees_a_half_written_file` and
`..._copy_move_and_delete_of_one_source_at_once_...` tests.

### The DBM type decides: Berkeley DB loses concurrent writes

`mod_dav_fs` keeps locks (one file for the whole server, `DavLockDB`) and dead
properties (one file per directory, in `.DAV/`) in DBM files. The DBM type is not
a `mod_dav_fs` setting: it is the default of the APR-util the server was built
with. A build from the release tarball uses **sdbm** - safe for several processes
writing at once; nothing was lost in any local run (600 locks, and sixteen
properties set at once, in every run of the suite). **Debian's and Ubuntu's APR-util
defaults to Berkeley DB**, which is not. Seen on GitHub Actions' `ubuntu-latest`
(Apache 2.4.58, `libaprutil1` 1.6.3, `apr_dbm_db`):

| Sixteen to forty requests at once | Result |
|---|---|
| 16 x `LOCK` on one resource | granted twice in 1 of 25 rounds (always at least once) |
| 40 x `LOCK` on 40 resources, all answered `200` | in 5 of 10 rounds 1 to 8 locks were not enforced a second later - the resource could be written without the token |
| 16 x `PROPPATCH` of 16 different properties on one file | one or more properties missing in 6 of 10 rounds (in the full suite sometimes most of them) |

Every request is answered as if it had worked. What this means in production:

- A lock taken *while other locks are being taken or released* is not reliable
  on such a server. Locks that are taken one at a time are.
- Properties set by several clients on the same resource at once can overwrite
  each other.
- The data files themselves are not affected (the temporary file is renamed
  into place), and sequential use is fine: the rest of the suite passes on
  Ubuntu.
- There is nothing to configure. Where this matters, build Apache with sdbm as
  the DBM default, or keep concurrent locking and `PROPPATCH` out of the picture
  (one writer per collection, or a lock taken by a single process in front of
  the server).

The tests above ask for the strict result only where the instance under test
uses sdbm (`_dbm_is_sdbm()`: the lock database is `davlock.pag`/`davlock.dir`),
and for what holds on both everywhere else.

## Troubleshooting

The automatic `pytest` fixture uses `$TMPDIR/webdav-rfc4918-apache-test`
(`/tmp/webdav-rfc4918-apache-test` on most systems); `tools/apache_compliance_check.py`
and the by-hand instructions above both default to `/tmp/apache-webdav-test`
instead (a different, separate instance) - adjust the paths below to
whichever one applies.

- **"Apache did not come up within 5s"**: check that instance's
  `logs/error.log` - usually a distro whose layout matches neither built-in
  profile (see `_PROFILES` in `tests/apache_instance.py`), or a stale PID
  file from a previous instance that was not shut down cleanly
  (`rm <instance-dir>/logs/httpd.pid`), or something else already listening
  on port 8765 (a manually-started instance you forgot about, most likely -
  `pgrep -fa 'httpd.*apache-webdav-test\|apache2.*apache-webdav-test\|httpd.*webdav-rfc4918-apache-test\|apache2.*webdav-rfc4918-apache-test'`).
- **A test fails with "already exists" / 409 on the very first test in a
  run**: `dav-root` has state left over from a previous, uncleaned run -
  `rm -rf <instance-dir>/dav-root/*` (the automatic fixture and the
  automation script both do this for you by default; `--no-clean` opts out
  for the script).
- **Running a single test with `-k` fails with 404/409 that a full run
  does not**: most tests share a `compliance/` directory that an earlier
  test in the file creates - run the full file, or create `compliance/`
  yourself first.
