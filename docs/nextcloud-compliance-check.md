# Nextcloud

This page is for pointing the library at a Nextcloud instance, one of the
servers users most often use it with, besides [Apache](apache-compliance-check.md)
and [nginx](nginx-compliance-check.md). The findings were measured against
the pinned `nextcloud:35.0.1-apache` image. Over 40 tests check them
against a real Nextcloud.

The WebDAV URL of a Nextcloud user is
`https://<host>/remote.php/dav/files/<user>`. Use it as the base URL.

The findings cover core RFC 4918 only. Nextcloud/ownCloud properties
(`oc:`/`nc:`), the chunked-upload endpoint, the OCS and share APIs, and a
public-share token used as the username are not tested.

## Summary

| Area | What matters in production |
|---|---|
| Locking | Works on the pinned 35.0.1; Nextcloud 29 answered `LOCK` with `501` |
| Locked members | A recursive `DELETE` removes a locked member without its token |
| `UNLOCK` | A wrong token gets `500`, not a `4xx`; the lock stays |
| `allprop` | `lockdiscovery` and `supportedlock` only when asked for by name |
| ETags and errors | `getetag` is strong; a `423` carries `lock-token-submitted` |
| Extended MKCOL | Refused with `400` (Apache: `415`) |

```{admonition} Before you deploy against Nextcloud
:class: warning

- A lock does not protect a member from a recursive `DELETE` of its
  collection: Nextcloud deletes it without the token.
- Locking depends on the version. 35.0.1 supports it, Nextcloud 29
  answered `LOCK` with `501`. Check `dav_compliance()` on your instance.
- An `UNLOCK` with a wrong token is a `500`, not a `4xx`. The lock stays.

See [Known limitations in locking](#known-limitations-in-locking).
```

## Behaviour in detail

### Locking support depends on the Nextcloud version

The pinned release (`nextcloud:35.0.1-apache`) supports WebDAV locking
(Class 2): `LOCK` returns a real token, and a write through a held lock
succeeds. Nextcloud 29, tested earlier in this project, answered `LOCK`
with `501 Not Implemented` and did not list class `2`. Locking was added
to Nextcloud's WebDAV stack somewhere between those releases. \
*Tests: `test_nextcloud_advertises_class_2` and
`test_nextcloud_lock_and_write_with_held_token`.*

### Known limitations in locking

- **A recursive DELETE does not check a locked member's token.** Apache
  answers `207 Multi-Status` (the locked member blocks the delete).
  Nextcloud deletes the whole collection, locked member included, with a
  plain `204`. \
  *Test: `test_nextcloud_deleting_a_collection_does_not_check_a_locked_members_token`.*
- **An invalid UNLOCK token gets `500 Internal Server Error`** instead of
  a `4xx`. The lock itself stays; only the status is wrong. \
  *Test: `test_nextcloud_unlock_by_a_different_client_without_the_token_fails`.*
- **`lockdiscovery` and `supportedlock` are not part of an `allprop`
  response.** Unlike on Apache, they have to be asked for by name. \
  *Test: `test_nextcloud_lockdiscovery_and_supportedlock_are_parsed_from_a_live_response`.*

### Other differences from Apache

Here Nextcloud does more than Apache:

- **`getetag` is strong by default** (Apache's is weak), so `If-Match`
  works with it directly and the client raises no `ValueError`. \
  *Test: `test_nextcloud_default_getetag_is_strong`.*
- **A `423` response carries a precondition code**
  (`lock-token-submitted`), where Apache sends a plain HTML page. \
  *Test: `test_nextcloud_423_response_has_a_structured_error_body`.*
- **Extended MKCOL (RFC 5689) is refused with a plain `400`** (Apache:
  `415`). It is SabreDAV's `BadRequest` exception, naming the missing
  `{DAV:}resourcetype`. \
  *Test: `test_nextcloud_extended_mkcol_is_refused_with_400`.*

## Running these tests

For running these tests yourself, see
[Running the Nextcloud tests](contributing-nextcloud.md).
