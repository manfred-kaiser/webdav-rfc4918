# Nextcloud compliance check

`tests/test_nextcloud_compliance.py` cross-checks this library against a
real Nextcloud instance - one of the most common real-world WebDAV
deployments this library's users point it at, alongside Apache
(`docs/apache-compliance-check.md`) and nginx
(`docs/nginx-compliance-check.md`). **Scoped to core RFC 4918 only**:
no Nextcloud/ownCloud-namespaced properties (`oc:`/`nc:`), no
chunked-upload endpoint, no OCS/share APIs, no public-share
token-as-username auth convention. None of that is tested here - a
separate, later decision if ever wanted.

Docker-backed, not apt-backed (Nextcloud has no system package on either
distro this project otherwise targets):

- **If a usable Docker daemon is found** (see `tests/nextcloud_instance.py`),
  running `pytest tests/test_nextcloud_compliance.py` automatically starts
  a throwaway container (the pinned `nextcloud:35.0.1-apache` image,
  sqlite backend), waits for it to finish installing, runs these tests
  against it, and removes it again afterwards.
- **If Docker is not usable**, the same `pytest` run skips this file with
  a clear reason instead of failing.
- **On GitHub**, this runs as its own workflow
  (`.github/workflows/nextcloud-compliance.yml`, a separate status/badge
  from the other three). New and `continue-on-error: true` for now -
  promote once it has been green for a while.
- **To point at a specific instance instead** (a remote one, or one with
  non-default configuration), set `WEBDAV_TEST_NEXTCLOUD_URL` to the full
  WebDAV endpoint (`https://your-instance/remote.php/dav/files/<user>`),
  with `WEBDAV_TEST_NEXTCLOUD_USER`/`_PASSWORD` - then that instance is
  used as-is and nothing is started or stopped automatically.

## Automatic (plain `pytest`)

```console
$ pytest tests/test_nextcloud_compliance.py -v
```

Needs a Docker daemon the invoking user can talk to - nothing else.

## Manual control: `tools/nextcloud_compliance_check.py`

```console
$ python tools/nextcloud_compliance_check.py
$ python tools/nextcloud_compliance_check.py --keep-running   # inspect/retry by hand afterwards
$ python tools/nextcloud_compliance_check.py -- -k lock -v    # extra args go straight to pytest
```

Same shape as the Apache/nginx scripts - checks Docker is usable, starts
the throwaway container, runs the tests, removes it again afterwards
(even on failure or Ctrl-C), unless `--keep-running` is given.

## Standing it up by hand

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
  hatch test tests/test_nextcloud_compliance.py -v
$ docker rm -f nextcloud-test
```

### Why this is safe under parallel `pytest` (`-nauto`)

Same reasoning and mechanism as the Apache/nginx suites: one shared,
persistent account for the whole run, pinned to a single xdist worker via
`@pytest.mark.xdist_group(name="nextcloud")` plus this project's
`--dist=loadgroup` config.

## Known limitation

**No locking support at all (Class 1 only).** Nextcloud's SabreDAV-based
WebDAV endpoint never registers a plugin for the `LOCK`/`UNLOCK` methods -
a `LOCK` request gets a plain `501 Not Implemented`, and its `DAV:`
compliance header never lists class `2`. This is a long-standing,
by-design characteristic of Nextcloud's own WebDAV stack, not a
configuration issue on this project's side - confirmed against a real
instance and pinned by `test_nextcloud_advertises_class_1_but_not_class_2`
and `test_nextcloud_lock_fails_with_a_clean_webdaverror`.

## Image tag policy

The exact Nextcloud image tag (`tests/nextcloud_instance.py`'s `IMAGE`) is
deliberately pinned, not `:latest` - same policy this project already
applies to `ruff`/`mypy`. Bump it as a conscious, reviewed act; see
<https://hub.docker.com/_/nextcloud/tags> for the current stable line.
