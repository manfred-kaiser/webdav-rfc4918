# nginx + dav-ext compliance check

`tests/test_session_e2e.py` runs automatically against `wsgidav`, and
`tests/test_apache_compliance.py` cross-checks against a real Apache +
`mod_dav` instance (see `docs/apache-compliance-check.md`).
`tests/test_nginx_compliance.py` adds a third, independent implementation:
nginx's own `ngx_http_dav_module` plus the `nginx-dav-ext-module`
(PROPFIND/PROPPATCH/OPTIONS/LOCK/UNLOCK). Worth having specifically because
this combination only implements *exclusive* locks - RFC 4918 sec. 7's
shared-lock support is simply not there, unlike Apache and wsgidav (both
Class 2, both scopes). Same opt-in shape as the Apache suite:

- **If nginx + the dav-ext module are installed** (see
  `tests/nginx_instance.py`), running `pytest` - the whole suite, or just
  `pytest tests/test_nginx_compliance.py` - automatically starts a
  throwaway instance, runs these tests against it, and stops it again
  afterwards.
- **If it is not installed**, the same `pytest` run skips this file with a
  clear reason (visible in the `-ra` summary) instead of failing.
- **On GitHub**, this runs as its own workflow
  (`.github/workflows/nginx-compliance.yml`, a separate status/badge from
  `ci.yml` and `apache-compliance.yml`), which installs nginx first.
  New and `continue-on-error: true` for now - promote once it has been
  green for a while.
- **To point at a specific instance instead**, set `WEBDAV_TEST_NGINX_URL`
  (`WEBDAV_TEST_NGINX_USER`/`_PASSWORD` default to
  `testuser`/`testpass123`) - then that instance is used as-is and nothing
  is started or stopped automatically.

## Automatic (plain `pytest`)

```console
$ sudo apt-get install nginx libnginx-mod-http-dav-ext apache2-utils   # once, if not already installed
$ pytest tests/test_nginx_compliance.py -v
```

Confirmed working on Debian/Ubuntu (including GitHub Actions'
`ubuntu-latest`) - no equivalent package was found on openSUSE at the time
this was written; see "Standing it up by hand" below if you want to build
the module yourself on another distro, and add a profile to
`tests/nginx_instance.py`'s `_PROFILES` once you have.

## Manual control: `tools/nginx_compliance_check.py`

```console
$ python tools/nginx_compliance_check.py
$ python tools/nginx_compliance_check.py --keep-running   # inspect/retry by hand afterwards
$ python tools/nginx_compliance_check.py --no-clean       # keep dav-root from the previous run
$ python tools/nginx_compliance_check.py -- -k lock -v    # extra args go straight to pytest
$ python tools/nginx_compliance_check.py --instance-dir /tmp/my-instance
```

Same shape as `tools/apache_compliance_check.py` - checks the
prerequisites (and says exactly what is missing), writes a throwaway
instance under `/tmp/nginx-webdav-test`, starts nginx, runs
`tests/test_nginx_compliance.py` against it, and stops nginx again
afterwards - even on a test failure or Ctrl-C.

## Standing it up by hand (what `tests/nginx_instance.py` automates)

```console
$ sudo apt-get install nginx libnginx-mod-http-dav-ext apache2-utils
$ mkdir -p /tmp/nginx-webdav-test/{dav-root,client_body}
$ htpasswd -bc /tmp/nginx-webdav-test/htpasswd testuser testpass123
```

`/tmp/nginx-webdav-test/nginx.conf`:

```nginx
pid "/tmp/nginx-webdav-test/nginx.pid";
error_log "/tmp/nginx-webdav-test/error.log" warn;

load_module "/usr/lib/nginx/modules/ngx_http_dav_ext_module.so";

events {
    worker_connections 64;
}

http {
    access_log off;
    client_body_temp_path "/tmp/nginx-webdav-test/client_body" 1 2;

    dav_ext_lock_zone zone=davlock:1m;

    server {
        listen 127.0.0.1:8766;

        location / {
            root "/tmp/nginx-webdav-test/dav-root";
            dav_methods PUT DELETE MKCOL COPY MOVE;
            dav_ext_methods PROPFIND OPTIONS LOCK UNLOCK;
            dav_ext_lock zone=davlock;
            create_full_put_path on;
            dav_access user:rw group:rw all:r;
            autoindex on;

            auth_basic "webdav-rfc4918 test";
            auth_basic_user_file "/tmp/nginx-webdav-test/htpasswd";
        }
    }
}
```

```console
$ nginx -c /tmp/nginx-webdav-test/nginx.conf
$ WEBDAV_TEST_NGINX_URL=http://127.0.0.1:8766 \
  WEBDAV_TEST_NGINX_USER=testuser \
  WEBDAV_TEST_NGINX_PASSWORD=testpass123 \
  hatch test tests/test_nginx_compliance.py -v
$ nginx -c /tmp/nginx-webdav-test/nginx.conf -s stop
```

(`pytest tests/test_nginx_compliance.py -v` works the same, without
`hatch`, from an already-activated virtualenv.)

### Why this is safe under parallel `pytest` (`-nauto`)

Same reasoning and mechanism as `test_apache_compliance.py` (see
`docs/apache-compliance-check.md`'s section of the same name): one shared,
persistent `dav-root` for the whole run, pinned to a single xdist worker
via `@pytest.mark.xdist_group(name="nginx")` plus this project's
`--dist=loadgroup` config - safe to just run `pytest` (`-nauto` and all)
without thinking about it.

## Known limitation

**Shared locks are not supported.** `nginx-dav-ext-module` only implements
*exclusive* locks - a `LOCK` request with `<D:shared/>` fails. Pinned by
`test_nginx_does_not_support_shared_locks`, so a future module release
that adds shared-lock support is noticed, not silently assumed to still
be missing.
