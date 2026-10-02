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

## Locking support depends on the Nextcloud version

The pinned release (`nextcloud:35.0.1-apache`) **does** support WebDAV
locking (Class 2) - confirmed against a real instance: `LOCK` returns a
real token, and a write through a held lock succeeds. This was not
always true: Nextcloud **29** (tested earlier in this project's own
research) answers `LOCK` with a plain `501 Not Implemented` and never
lists class `2` at all - locking support was added to Nextcloud's own
WebDAV stack at some point between those releases. `test_nextcloud_advertises_class_2`
and `test_nextcloud_lock_and_write_with_held_token` pin the *current*
pinned version's behavior; if a future image bump lands on a release
where this regresses, these tests catch it rather than it being silently
assumed away.

## Known limitations in locking support, beyond the version gap above

Confirmed against a real instance, not assumed from Apache's own behavior:

- **A recursive DELETE does not check a locked member's token at all.**
  Apache answers this with `207 Multi-Status` (the locked member blocks
  the delete); Nextcloud deletes the whole collection, locked member
  included, with a plain `204`. Pinned by
  `test_nextcloud_deleting_a_collection_does_not_check_a_locked_members_token`.
- **An invalid UNLOCK token gets a bare `500 Internal Server Error`**,
  not a `4xx`. The real lock is still safe (not released by the bogus
  request) - just the error status is wrong. Pinned by
  `test_nextcloud_unlock_by_a_different_client_without_the_token_fails`.
- **`lockdiscovery`/`supportedlock` are not part of an `allprop`
  response** - unlike Apache, they have to be asked for by name. Pinned
  by `test_nextcloud_lockdiscovery_and_supportedlock_are_parsed_from_a_live_response`.

## Other confirmed differences from Apache

Not limitations - Nextcloud is more capable than Apache in each of
these, confirmed against a real instance:

- **`getetag` is strong by default** (Apache's is weak) - `If-Match`
  with it works directly, no client-side `ValueError`. Pinned by
  `test_nextcloud_default_getetag_is_strong`.
- **A `423` response carries a real precondition code**
  (`lock-token-submitted`), not Apache's plain HTML. Pinned by
  `test_nextcloud_423_response_has_a_structured_error_body`.
- **Extended MKCOL (RFC 5689) is refused with a plain `400`**, not
  Apache's `415` - SabreDAV's own `BadRequest` exception, naming the
  missing `{DAV:}resourcetype`. Pinned by
  `test_nextcloud_extended_mkcol_is_refused_with_400`.

## Image tag policy

The exact Nextcloud image tag (`tests/nextcloud_instance.py`'s `IMAGE`) is
deliberately pinned, not `:latest` - same policy this project already
applies to `ruff`/`mypy`. Bump it as a conscious, reviewed act; see
<https://hub.docker.com/_/nextcloud/tags> for the current stable line.
