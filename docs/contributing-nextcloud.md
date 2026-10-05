---
orphan: true
---

# Running the Nextcloud tests

This page is for running the Nextcloud compliance tests yourself. What the
tests found is on the [Nextcloud](nextcloud-compliance-check.md) page.

| Test file | Instance helper | Script |
|---|---|---|
| `tests/test_nextcloud_compliance.py` | `tests/nextcloud_instance.py` | `tools/nextcloud_compliance_check.py` |

All tests in the file share one server instance (one Nextcloud account),
so the file must not be split across xdist workers. The module's
`pytestmark` sets `xdist_group(name="nextcloud")`, and the project config
sets `--dist=loadgroup`. So the file always runs on one xdist worker, also
under the default `-nauto`.

## Setup

```console
$ pytest tests/test_nextcloud_compliance.py -v
```

The instance runs in Docker, because Nextcloud has no system package on
the distros this project otherwise uses.

- **Docker usable** (`docker info` works for the invoking user, see
  `tests/nextcloud_instance.py`): `pytest` starts a throwaway container
  (the pinned `nextcloud:35.0.1-apache` image, sqlite backend, port 8767),
  waits up to 180 seconds for it to finish installing, runs the tests and
  removes the container again.
- **Not usable**: the file is skipped, with the reason in the
  `-ra` summary.
- **On GitHub**: `.github/workflows/nextcloud-compliance.yml` runs it with
  `continue-on-error: true`. It is not a required status check, because
  every run pulls the image from Docker Hub.
- **Another instance**: set `WEBDAV_TEST_NEXTCLOUD_URL` to the full WebDAV
  endpoint (`https://your-instance/remote.php/dav/files/<user>`). User and
  password default to `admin`/`testpass123`, override with
  `WEBDAV_TEST_NEXTCLOUD_USER`/`_PASSWORD`. It is used as it is: nothing is
  started or stopped.

## `tools/nextcloud_compliance_check.py`

For more control over the container:

```console
$ python tools/nextcloud_compliance_check.py
$ python tools/nextcloud_compliance_check.py --keep-running   # inspect/retry by hand afterwards
$ python tools/nextcloud_compliance_check.py -- -k lock -v    # extra args go straight to pytest
```

It checks that Docker is usable, starts the container, runs the tests and
removes the container again, also on failure or Ctrl-C. With
`--keep-running`, the container stays.

## By hand

```console
$ docker run -d --name nextcloud-test \
    -p 8767:80 \
    -e SQLITE_DATABASE=nc.db \
    -e NEXTCLOUD_ADMIN_USER=admin \
    -e NEXTCLOUD_ADMIN_PASSWORD=testpass123 \
    -e NEXTCLOUD_TRUSTED_DOMAINS=127.0.0.1 \
    nextcloud:35.0.1-apache
$ curl http://127.0.0.1:8767/status.php   # poll until "installed":true
$ WEBDAV_TEST_NEXTCLOUD_URL=http://127.0.0.1:8767/remote.php/dav/files/admin \
  WEBDAV_TEST_NEXTCLOUD_USER=admin \
  WEBDAV_TEST_NEXTCLOUD_PASSWORD=testpass123 \
  pytest tests/test_nextcloud_compliance.py -v
$ docker rm -f nextcloud-test
```

## Image tag policy

The Nextcloud image tag (`IMAGE` in `tests/nextcloud_instance.py`) is
pinned instead of `:latest`, the same way this project pins `ruff` and
`mypy`. Bump it on purpose and review the result; see
<https://hub.docker.com/_/nextcloud/tags> for the current stable line.
An image bump to a release without WebDAV locking fails
`test_nextcloud_advertises_class_2` and
`test_nextcloud_lock_and_write_with_held_token`.
