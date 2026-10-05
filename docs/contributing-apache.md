---
orphan: true
---

# Running the Apache tests

This page is for running the Apache compliance tests yourself. What the
tests found is on the [Apache](apache-compliance-check.md) page.

| Test file | Instance helper | Script |
|---|---|---|
| `tests/test_apache_compliance.py` | `tests/apache_instance.py` | `tools/apache_compliance_check.py` |

All tests in the file share one server instance (one `dav-root`), so the
file must not be split across xdist workers. The module's `pytestmark`
sets `xdist_group(name="apache")`, and the project config sets
`--dist=loadgroup`. So the file always runs on one xdist worker, also
under the default `-nauto`.

## Setup

The primary development system is openSUSE Tumbleweed, hence `zypper`
below; `tests/apache_instance.py` also knows the Debian/Ubuntu layout.

```console
$ sudo zypper install apache2 apache2-utils   # once
$ pytest tests/test_apache_compliance.py -v
```

- **Apache installed** (`httpd` and the `mod_dav*` modules, see
  `tests/apache_instance.py`): `pytest` starts a throwaway instance with a
  clean `dav-root` on port 8765, runs the tests and stops it again.
- **Not installed**: the file is skipped, with the reason in the
  `-ra` summary.
- **On GitHub**: `.github/workflows/apache-compliance.yml` installs Ubuntu's
  `apache2` and runs it, as a required status check on `main`. `ci.yml`
  skips the file.
- **Another instance**: set `WEBDAV_TEST_APACHE_URL` (user and password
  default to `testuser`/`testpass123`, override with
  `WEBDAV_TEST_APACHE_USER`/`_PASSWORD`). It is used as it is: nothing is
  started, stopped or cleaned.

Some tests start an extra, differently configured instance
(`FileETag`, `DavDepthInfinity`, `DavMinTimeout`, no `DavLockDB`, no
`mod_dav_lock`, `KeepAliveTimeout`, `MaxKeepAliveRequests`, `Timeout`,
`LimitRequestBody`, the parallel tests) on ports 8781 to 8791 (`_PORTS` in
the test module). Without a local install they are skipped. The file takes
about forty seconds, mostly waiting for locks to run out.

Most tests build on a `compliance/` directory an earlier test creates, so
a `-k` subset has to include that test.

## Against a build of your own

Set `WEBDAV_TEST_APACHE_PREFIX` to the install directory of a tarball
build (`bin/httpd`, `bin/htpasswd`, `modules/`). It is tried first:

```console
$ ./configure --prefix=$HOME/.local/opt/httpd-2.4.69 --with-apr=... --with-apr-util=... \
      --with-pcre=.../pcre2-config --enable-dav --enable-dav-fs --enable-dav-lock \
      --enable-mods-shared=few --enable-so --with-mpm=prefork
$ make -j && make install
$ WEBDAV_TEST_APACHE_PREFIX=$HOME/.local/opt/httpd-2.4.69 pytest tests/test_apache_compliance.py
```

There the prefork MPM is compiled in and `mod_unixd` is loadable;
`tests/apache_instance.py` handles both. The [Apache](apache-compliance-check.md)
page names the source function behind each finding. Read the 2.4.x
tarball, not trunk, which differs in places (`dav_fs_get_resource` answers
404 there, 2.4.69 answers 400).

## `tools/apache_compliance_check.py`

For more control over the instance:

```console
$ python tools/apache_compliance_check.py
$ python tools/apache_compliance_check.py --keep-running   # inspect/retry by hand afterwards
$ python tools/apache_compliance_check.py --no-clean       # keep dav-root from the previous run
$ python tools/apache_compliance_check.py -- -k lock -v    # extra args go straight to pytest
$ python tools/apache_compliance_check.py --instance-dir /tmp/my-instance
```

It shares `tests/apache_instance.py` with the fixture, names any missing
package, and stops Apache also on failure or Ctrl-C. The exit code is
pytest's.

Both know two layouts (`_PROFILES` in `tests/apache_instance.py`):
openSUSE/RPM (`/usr/sbin/httpd`, `/usr/lib64/apache2-prefork/`) and
Debian/Ubuntu (`/usr/sbin/apache2`, `/usr/lib/apache2/modules/`). The first
complete one wins. For another distro, add a profile.

## By hand

This is what `tests/apache_instance.py` automates. On openSUSE, the `mod_dav*`
modules ship in the base `apache2` package.

```console
$ sudo zypper install apache2 apache2-utils
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

# ABSOLUTE and identical in both directives: a relative "dav-root" in
# <Directory> silently did not match on 2.4.67, so Dav On and Require
# were both inactive, with nothing logged.
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

Without `User`/`Group`, Apache runs as the invoking user.

```console
$ /usr/sbin/httpd -f /tmp/apache-webdav-test/httpd.conf -k start
$ WEBDAV_TEST_APACHE_URL=http://127.0.0.1:8765 \
  WEBDAV_TEST_APACHE_USER=testuser \
  WEBDAV_TEST_APACHE_PASSWORD=testpass123 \
  pytest tests/test_apache_compliance.py -v
$ /usr/sbin/httpd -f /tmp/apache-webdav-test/httpd.conf -k stop
```

Clear `dav-root/*` between such runs yourself.

## The DBM tests

The tests behind
[The DBM type decides](apache-compliance-check.md#the-dbm-type-decides-berkeley-db-loses-concurrent-writes)
run on an instance of their own, so a damaged database cannot break the
others. They expect the strict result only on sdbm (`_dbm_is_sdbm()`: the
lock database is `davlock.pag`/`davlock.dir`) and otherwise check what
holds for both. A clean start removes the previous run's lock database.

## Troubleshooting

The fixture's instance is `$TMPDIR/webdav-rfc4918-apache-test` (usually
`/tmp/...`); the script and the by-hand setup use `/tmp/apache-webdav-test`.

- **"Apache did not come up within 5s"**: see `logs/error.log` in the
  instance directory. Usual causes: a layout that matches no profile in
  `_PROFILES`, a stale `logs/httpd.pid` from an unclean shutdown (delete
  it), or something else on port 8765
  (`pgrep -fa 'httpd.*apache-webdav-test\|apache2.*apache-webdav-test\|httpd.*webdav-rfc4918-apache-test\|apache2.*webdav-rfc4918-apache-test'`).
- **"already exists" / 409 on the first test**: `dav-root` is left over
  from an uncleaned run. `rm -rf <instance-dir>/dav-root/*`.
- **`-k` fails with 404/409 where a full run does not**: the test needs the
  `compliance/` directory an earlier test creates. Run the full file, or
  create `compliance/` first.
