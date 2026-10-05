---
orphan: true
---

# Running the nginx tests

This page is for running the nginx compliance tests yourself. What the
tests found is on the [nginx](nginx-compliance-check.md) page.

| Test file | Instance helper | Script |
|---|---|---|
| `tests/test_nginx_compliance.py` | `tests/nginx_instance.py` | `tools/nginx_compliance_check.py` |

All tests in the file share one server instance (one `dav-root`), so the
file must not be split across xdist workers. The module's `pytestmark`
sets `xdist_group(name="nginx")`, and the project config sets
`--dist=loadgroup`. So the file always runs on one xdist worker, also
under the default `-nauto`.

## Setup

```console
$ sudo apt-get install nginx libnginx-mod-http-dav-ext apache2-utils   # once
$ pytest tests/test_nginx_compliance.py -v
```

- **nginx and the dav-ext module installed** (see `tests/nginx_instance.py`):
  `pytest` starts a throwaway instance on port 8766, runs the tests and
  stops it again. This works for the whole suite and for the file alone.
- **Not installed**: the file is skipped, with the reason in the
  `-ra` summary.
- **On GitHub**: `.github/workflows/nginx-compliance.yml` installs nginx
  and runs the file, as a required status check on `main`.
- **Another instance**: set `WEBDAV_TEST_NGINX_URL` (user and password
  default to `testuser`/`testpass123`, override with
  `WEBDAV_TEST_NGINX_USER`/`_PASSWORD`). It is used as it is: nothing is
  started or stopped.

The packages exist on Debian and Ubuntu, including GitHub Actions'
`ubuntu-latest`. openSUSE had no package for the module when this was
written. On another distro, build the module yourself and add a profile to
`_PROFILES` in `tests/nginx_instance.py`.

## `tools/nginx_compliance_check.py`

For more control over the instance:

```console
$ python tools/nginx_compliance_check.py
$ python tools/nginx_compliance_check.py --keep-running   # inspect/retry by hand afterwards
$ python tools/nginx_compliance_check.py --no-clean       # keep dav-root from the previous run
$ python tools/nginx_compliance_check.py -- -k lock -v    # extra args go straight to pytest
$ python tools/nginx_compliance_check.py --instance-dir /tmp/my-instance
```

It shares `tests/nginx_instance.py` with the fixture, names any missing
package, writes the instance under `/tmp/nginx-webdav-test`, and stops nginx
also on failure or Ctrl-C.

## By hand

This is what `tests/nginx_instance.py` automates.

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
  pytest tests/test_nginx_compliance.py -v
$ nginx -c /tmp/nginx-webdav-test/nginx.conf -s stop
```
