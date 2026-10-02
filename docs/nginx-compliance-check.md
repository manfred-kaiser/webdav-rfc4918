# nginx + dav-ext compliance check

`tests/test_session_e2e.py` runs automatically against `wsgidav`, and
`tests/test_apache_compliance.py` cross-checks against a real Apache +
`mod_dav` instance (see `docs/apache-compliance-check.md`).
`tests/test_nginx_compliance.py` adds a third, independent implementation:
nginx's own `ngx_http_dav_module` plus the `nginx-dav-ext-module`
(PROPFIND/PROPPATCH/OPTIONS/LOCK/UNLOCK). Worth having specifically for
the real limitations it has that Apache, wsgidav and Nextcloud don't share
(see "Known limitations" below) - confirmed against a real instance, not
assumed. Same opt-in shape as the Apache suite:

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

## Known limitations

Confirmed against a real instance, not assumed from documentation:

- **`DAV:` header lists only class `2`, never `1`.** Reproduced
  consistently (immediately after start, after a restart, repeatedly) -
  not a startup race. The server's actual *behavior* is still class 1
  (MKCOL/PUT/DELETE/COPY/MOVE all work); only the advertised header is
  incomplete, which is itself worth knowing if anything inspects
  `dav_compliance()` to decide what a server can do. Pinned by
  `test_nginx_advertises_class_2_but_not_class_1`.
- **No overwrite protection.** `ngx_http_dav_module` never evaluates
  `If-None-Match` on `PUT` - `overwrite=False` silently overwrites instead
  of refusing with `412`. Pinned by
  `test_nginx_does_not_honor_overwrite_protection`.
- **A shared lock request is silently granted as exclusive**, not refused
  and not honored as shared. `nginx-dav-ext-module` ignores the requested
  `<D:lockscope>` entirely. A real interop footgun: a caller asking for
  `scope=SHARED` against nginx believes it holds a shared lock and does
  not. Pinned by `test_nginx_silently_grants_a_shared_lock_request_as_exclusive`.
- **`PROPPATCH` is not supported at all** - not a partial limitation like
  the others, it's simply absent: `PROPPATCH` isn't even a legal value
  for nginx-dav-ext's own `dav_ext_methods` directive (`nginx -t` refuses
  the config outright), and the method itself gets a plain `405` from
  nginx's HTTP core. Pinned by `test_nginx_does_not_support_proppatch_at_all`.
- **PROPFIND never returns a `getetag` property**, for any resource -
  confirmed empirically, not just for one file. `get_props(...).etag` is
  always `None` against nginx. Pinned by `test_nginx_propfind_never_returns_an_etag`.
- **A locked-resource conflict (`423`) has no response body at all**
  (`Content-Length: 0`), not even Apache's plain HTML - `error_codes`
  degrades to an empty set here too, for a different underlying reason
  than Apache's unstructured-but-present body. Pinned by
  `test_nginx_423_response_is_never_crashed_on_even_without_a_structured_error_body`.

Each is pinned by a dedicated test rather than silently assumed to stay
true forever - a future nginx-dav-ext release that fixes any of these
would turn the matching test red, which is the point.

## Usage note: COPY/MOVE of a collection needs a trailing slash

Not a limitation - nginx just enforces something Apache/wsgidav/Nextcloud
don't: COPY/MOVE on a collection needs a trailing slash on *both* the
source path and the `Destination` - without one on either side, nginx
answers a plain `400 Bad Request` instead of recursing. This library
already preserves a caller-given trailing slash end to end
(`Session.resolve_url()`'s docstring: "a trailing / says this is a
collection"), so `fs.copy("src/", "dst/")` (not `fs.copy("src", "dst")`)
is all that's needed - see `test_nginx_copy_of_a_nested_collection_duplicates_the_whole_subtree`.
