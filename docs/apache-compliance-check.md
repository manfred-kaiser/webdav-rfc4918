# Apache mod_dav compliance check

`tests/test_session_e2e.py` runs automatically against `wsgidav` (pure
Python, no system dependency). `tests/test_apache_compliance.py` is a
separate cross-check against a real Apache + `mod_dav` instance - an
independent implementation, useful because WebDAV servers are known to
disagree on locking/property edge cases in particular, and because this
project's primary deployment target is Apache specifically. It is an
ordinary `pytest` suite (41 tests, reproducible like any other) - not
"manual" in the sense of needing a human to drive it, just opt-in:

- **If Apache is installed** (`httpd` + the `mod_dav*` modules - see
  `tests/apache_instance.py`), running `pytest` - the whole suite, or just
  `pytest tests/test_apache_compliance.py` - automatically starts a
  throwaway instance, runs these 41 tests against it, and stops it again
  afterwards. No flags, no environment variables, nothing to remember.
- **If it is not installed**, the same `pytest` run skips this file with a
  clear reason (visible in the `-ra` summary) instead of failing - this is
  why it is not part of CI (GitHub's runners do not have Apache, and the
  module paths this project checks are openSUSE's anyway - see below).
- **To point at a specific instance instead** (a remote one, or one with
  non-default configuration you want to test against), set
  `WEBDAV_TEST_APACHE_URL` (`WEBDAV_TEST_APACHE_USER`/`_PASSWORD` default to
  `testuser`/`testpass123`) - then that instance is used as-is and nothing
  is started or stopped automatically.

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

Both this script and the automatic fixture hardcode openSUSE's module path
(`/usr/lib64/apache2-prefork/`); on another distro, edit `MODULE_DIR` near
the top of `tools/apache_compliance_check.py` (the module filenames
themselves - `mod_dav.so` etc. - are the same everywhere).

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

## Known differences from the RFC text / from `wsgidav`

Found and confirmed independently (`curl`, bypassing this library entirely)
while building out `tests/test_apache_compliance.py`. None of these are bugs
in Apache's `mod_dav` - RFC 4918 explicitly leaves them open - but they are
real, and worth knowing if Apache is the server this library talks to in
production:

- **`getetag` is a weak validator (`W/"..."`) by default.** RFC 9110 sec.
  13.1.1 requires `If-Match` to use *strong* comparison, so
  `strong_etag()` correctly refuses a weak ETag - which means passing
  Apache's own current `getetag` straight into `Session.put(if_match=...)`
  fails client-side (`ValueError`) against a stock install. Configure
  Apache with a strong `FileETag` (e.g. `FileETag INode MTime Size`) to
  get a working If-Match-based conditional PUT. See
  `test_apache_default_getetag_is_weak_so_if_match_with_it_is_refused_client_side`.
- **The empty resource a `LOCK` on an unmapped URL creates (RFC 4918 sec.
  9.10.4) does not survive the lock being released.** The RFC only says it
  "SHOULD NOT disappear" (not a MUST) - Apache takes the RFC up on that
  latitude; `wsgidav` keeps it. `FileSystem.locked()`'s docstring notes
  this explicitly. See
  `test_apache_locking_an_unmapped_url_creates_a_resource_while_held`.
- **`MKCOL` on an already-existing plain resource answers `400 Bad
  Request`, not `405 Method Not Allowed`.** `FileSystem.mkdir()` always
  sends the trailing-slash form of the URL (RFC 4918 sec. 5.2); Apache's
  own path resolution rejects that against an existing non-collection
  resource before it would get to say "method not allowed". Handled
  transparently - `mkdir()` still raises `ResourceAlreadyExistsError` -
  since this release; see
  `test_mkcol_on_an_existing_plain_resource_is_still_recognized_when_the_server_says_400`
  in `tests/test_rfc_compliance.py` for the (server-agnostic, CI-running)
  regression test.
- **A collection operation (DELETE/COPY/MOVE) blocked by one member can
  answer a non-207 top-level status with a full multistatus body
  anyway.** Confirmed: a DELETE blocked by one locked member answers `424
  Failed Dependency` at the top level, with a `<D:multistatus>` body
  underneath naming exactly which member and why - RFC 4918 sec. 13 ties
  this detail to a 207 response, but nothing stops a server from wrapping
  the same shape under a different status. Handled transparently since
  this release (`webdav.dav.multistatus.multistatus_failure`) - the
  specific `MultiStatusError` is still raised, not a generic
  `FailedDependencyError`; see
  `test_a_multistatus_body_under_a_non_207_status_still_raises_multistatuserror`
  in `tests/test_rfc_compliance.py`.
- **No RFC 5689 (Extended MKCOL) support** - `extended-mkcol` is absent
  from the `DAV` header, and a `set_props=`/`data=` MKCOL body gets `415
  Unsupported Media Type`, same as `wsgidav`. `build_mkcol_body()`/
  `parse_mkcol_response()` still work correctly against a server that
  *does* support it (unit-tested in `tests/test_rfc_compliance.py`
  directly against RFC 5689's own worked examples).

## Troubleshooting

The automatic `pytest` fixture uses `$TMPDIR/webdav-rfc4918-apache-test`
(`/tmp/webdav-rfc4918-apache-test` on most systems); `tools/apache_compliance_check.py`
and the by-hand instructions above both default to `/tmp/apache-webdav-test`
instead (a different, separate instance) - adjust the paths below to
whichever one applies.

- **"Apache did not come up within 5s"**: check that instance's
  `logs/error.log` - usually a module path that does not match your distro
  (see `MODULE_DIR` in `tests/apache_instance.py`), or a stale PID file
  from a previous instance that was not shut down cleanly
  (`rm <instance-dir>/logs/httpd.pid`), or something else already listening
  on port 8765 (a manually-started instance you forgot about, most likely -
  `pgrep -fa 'httpd.*apache-webdav-test\|httpd.*webdav-rfc4918-apache-test'`).
- **A test fails with "already exists" / 409 on the very first test in a
  run**: `dav-root` has state left over from a previous, uncleaned run -
  `rm -rf <instance-dir>/dav-root/*` (the automatic fixture and the
  automation script both do this for you by default; `--no-clean` opts out
  for the script).
- **Running a single test with `-k` fails with 404/409 that a full run
  does not**: most tests share a `compliance/` directory that an earlier
  test in the file creates - run the full file, or create `compliance/`
  yourself first.
