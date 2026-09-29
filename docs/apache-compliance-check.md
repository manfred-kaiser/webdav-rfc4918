# Apache mod_dav compliance check

`tests/test_client_e2e.py` runs automatically against `wsgidav` (pure
Python, no system dependency). `tests/test_apache_compliance.py` is a
separate, manual cross-check against a real Apache + `mod_dav` instance -
an independent implementation, useful because WebDAV servers are known to
disagree on locking/property edge cases in particular. It is skipped
unless `WEBDAV_TEST_APACHE_URL` is set, and is not part of CI.

## Standing up a throwaway instance (openSUSE)

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
  hatch run hatch-test:run tests/test_apache_compliance.py -v
$ /usr/sbin/httpd -f /tmp/apache-webdav-test/httpd.conf -k stop
```
