# Apache

This page is for deploying against Apache httpd with `mod_dav` and
`mod_dav_fs`, the primary deployment target of this project. It lists
where Apache behaves differently from what the RFC or other servers lead
you to expect. Over 100 tests check each finding against a real Apache;
the rest of the suite runs against WsgiDAV. Servers disagree most on
locking and properties, so most findings are about those.

## Summary

| Area | What matters in production |
|---|---|
| ETags | Weak for ~1s after a write; `If-Match` right after a `PUT` needs a different condition or a wait |
| Creating things | `overwrite=False` is not atomic; a lock is the only way to guarantee exactly one writer |
| Locking | Works once `DavLockDB` is set (`mod_dav_lock` is not required); shared locks coexist, exclusive ones don't |
| The `If` header / locked neighbours | A new member of a locked collection answers `207`/`424`, never a plain `423` |
| Properties and reading | `PROPFIND Depth: infinity` needs `DavDepthInfinity On`; a failed `PROPPATCH` is all-or-nothing |
| Over time | An expired lock is dropped lazily, on the next request that looks at it - and can break the collection's next listing once |
| Size and names | 255-byte name limit; `.DAV` is refused at any level |
| Parallel | Exactly one writer wins a race, reliably only with sdbm |
| The DBM type decides | Debian/Ubuntu's Berkeley-DB build can silently lose concurrent locks and properties |

```{admonition} Before you deploy against Apache
:class: warning

- On Debian and Ubuntu, Apache's DBM is Berkeley DB, which can lose
  locks and properties set by several clients at once, while every
  request is answered as if it had worked. See
  [The DBM type decides](#the-dbm-type-decides-berkeley-db-loses-concurrent-writes).
- `overwrite=False` is not atomic. Where exactly one writer must win,
  hold a lock. See [Creating things](#creating-things).
- `DAV: 1,2` does not mean locking works: without `DavLockDB` every
  `LOCK` is a `500`. See [Locking](#locking).
```

## Behaviour in detail

Each finding was measured against Apache 2.4.69, with `curl` and with the
named test in `tests/test_apache_compliance.py`, and traced in the source.
RFC 4918 leaves most of these open; one is an Apache bug.

### ETags

- **`getetag` is weak (`W/"..."`) for a file changed less than a second
  ago, strong after that.** The rule is `request_time - mtime < 1s` in the
  core (`ap_make_etag_ex`, `modules/http/http_etag.c`). No setting changes
  it; `FileETag INode MTime Size` only changes what the value is made of. \
  *Test: `test_apache_file_etag_directive_does_not_make_a_fresh_etag_strong`.*
- **So an ETag taken right after a write cannot be used for `If-Match`.**
  RFC 9110 sec. 13.1.1 requires strong comparison. `strong_etag()` refuses a
  weak one (`ValueError`), and Apache answers a `W/...` `If-Match` with
  `412`, even for its own current ETag. Ask again after a second. The `PUT`
  response has no `ETag` header. \
  *Test: `test_apache_refuses_a_weak_if_match_on_its_own`.*

### Creating things

```{warning}
`overwrite=False` (`If-None-Match: *`) is not atomic on Apache.
`dav_method_put` checks the condition (`dav_validate_request`) when the
request arrives, then streams the body into a temporary file and renames it
over the target (`dav_fs_close_stream`, `apr_file_rename`). A creator that
arrives and finishes in between replaces the file, and both get `201`. A
sequential second creator gets `412`. Where exactly one writer must win,
hold a lock; Apache enforces those. \
*Test: `test_apache_if_none_match_star_is_checked_before_the_body_is_read` (deterministic: the first request is held up halfway through its body).*
```

- **`MKCOL` on an existing file: `405` without, `400` with the trailing
  slash.** `FileSystem.mkdir()` always sends the slash (RFC 4918 sec. 5.2),
  and `dav_fs_get_resource` answers `400` for "extraneous path components"
  below a file (trunk: `404`). A path *below* a file gets the same `400`. So
  `mkdir()` raises `ResourceAlreadyExistsError` only if a `PROPFIND` without
  the slash finds the resource, and otherwise raises the `400`. \
  *Test: `test_apache_mkdir_on_a_file_is_already_exists_but_below_a_file_it_is_not`.*
- **Racing `MKCOL`s: one `201`, the others mostly `405`, some `403`.**
  `dav_fs_create_collection` maps every `apr_dir_make` error except
  ENOSPC/ENOENT to `403`, so a loser that passed the "exists" check and then
  hits EEXIST gets `403` ("Unable to create collection") instead of
  the `405` of RFC 4918 sec. 9.3.1. `makedirs(exist_ok=True)` in the fsspec
  layer accepts that if the collection exists afterwards. \
  *Test: `test_apache_a_mkcol_race_has_one_winner_and_the_rest_are_refused`.*
- **No RFC 5689 (Extended MKCOL).** `extended-mkcol` is not in the `DAV`
  header. *Any* `MKCOL` body, with or without `Content-Type`, gets `415` (`process_mkcol_body`) and creates
  nothing. `build_mkcol_body()` and `parse_mkcol_response()` still work
  with servers that support it.

### Locking

- **A `LOCK` on an unmapped URL creates a *lock-null* resource, not an empty
  file.** This is the RFC 2518 sec. 7.4 model that RFC 4918 replaced
  (`dav_fs_add_locknull_state`: an entry in `.DAV/.locknull`, no file).
  `PROPFIND` finds it, so `exists()` and `isfile()` are true. `GET` and
  `HEAD` answer `404`. The parent's listing names it. `UNLOCK` removes it
  (`dav_fs_remove_locknull_member`), unless a `PUT` through the lock made it
  a real file, which then outlives the lock. WsgiDAV creates an empty
  resource instead. \
  *Test: `test_apache_lock_on_an_unmapped_url_is_lock_null_and_not_a_resource`.*
- **`Timeout`.** The first token Apache understands wins (`Second-30,
  Second-3600` is 30). `Infinite`, nothing it understands, and no header are
  all infinite (`dav_get_timeout`). The client asks for 600 seconds by
  default (`DEFAULT_LOCK_TIMEOUT`), for infinite with `lock_timeout=None`.
  `DavMinTimeout` raises a shorter timeout to its minimum, but not an
  infinite one. A refresh answers the new timeout and no `Lock-Token`
  header. \
  *Test: `test_apache_lock_timeout_header`.*
- **`UNLOCK` with anything but the right token is a `400`**, never
  `403`/`409`/`412`: no header, no angle brackets, `<>`, garbage, an
  unknown or foreign token, one already released (`dav_method_unlock`, and
  the dummy `If` header `dav_validate_request` builds from `Lock-Token`).
  The lock stays. \
  *Test: `test_apache_unlock_with_anything_but_the_right_token_is_a_400`.*
- **Shared locks.** Several coexist, also for one principal, and any *one*
  token is enough to write. Exclusive and shared locks exclude each other.
  A `LOCK` without `Depth` is `infinity`. \
  *Test: `test_apache_any_one_shared_token_is_enough_to_write`.*
- **`DAV: 1,2` does not mean locking works.** `mod_dav_fs` always has lock
  hooks, so it advertises class 2 (`dav_method_options`). Without
  `DavLockDB` a `LOCK` is a `500` ("A lock database was not specified").
  `mod_dav_lock` belongs to a different provider and is not needed. \
  *Test: `test_apache_locking_needs_the_lockdb_of_mod_dav_fs_but_not_mod_dav_lock`.*

### The `If` header and what a lock does to its neighbours

- **An untagged `If: (<token>)` applies to every resource the method
  touches** (`dav_validate_resource_state`): source and destination of
  `COPY`/`MOVE`, the new member of a collection. If one of them does not
  hold the token, the request is `412`. A list *tagged* with another URL
  does not apply, so the session tags every token with its lock's URL.
  `COPY` onto a locked file: `423` without a token, `412` with an untagged
  one, `204` with one tagged for the destination. \
  *Test: `test_apache_the_session_tags_the_tokens_it_sends`.*
- **A new member of a locked collection is a `207`, not a `423`.** A `PUT`
  or `MKCOL` of a *new* name in a collection someone else locked answers
  `207` (`DAV_VALIDATE_PARENT`): `424` for the new member, `423` for the
  collection, nothing created. The client raises `MultiStatusError` naming
  the collection, not `ResourceLockedError`. An *existing* member of a
  `Depth: infinity` locked collection is a plain `423`. The lock holder
  writes normally. \
  *Test: `test_apache_a_new_member_of_a_locked_collection_is_a_207_and_not_created`.*
- **A `DELETE`/`COPY`/`MOVE` blocked by a locked member is a `424` with a
  multistatus body, and does nothing** (`DAV_VALIDATE_USE_424`). The body
  names the blocking resource (`423 Locked`); for a `MOVE` out of a locked
  collection, the collection. RFC 4918 sec. 13 ties such a body to `207`;
  the client raises the specific `MultiStatusError` anyway
  (`webdav.dav.multistatus.multistatus_failure`). \
  *Test: `test_apache_delete_blocked_by_a_locked_member_is_a_424_that_deletes_nothing`.*
- **A `423` has no `<D:error>` body.** `mod_dav` never builds one for a lock
  (`dav_new_error_tag` has no caller). It is the core's HTML error page;
  `error_codes` is empty. \
  *Test: `test_apache_423_is_the_cores_html_error_page_and_never_a_dav_error`.*

### Properties and reading

- **A failed `PROPPATCH` is a `207` with a `409`.** Live properties
  (`getcontentlength`, ...) are read-only ("Property is read-only."); the
  client names the property. `dav_failed_proppatch` writes the
  status line itself: `HTTP/1.1 409 (status)`. The update is all or
  nothing. \
  *Test: `test_apache_a_proppatch_is_all_or_nothing`.*
- **`PROPFIND` with `Depth: infinity`, or without `Depth`, on a collection
  is a `403`** unless `DavDepthInfinity On` (`dav_method_propfind`). A file
  needs no `Depth`. This library has no default depth on purpose. \
  *Test: `test_apache_depth_infinity_and_no_depth_at_all_are_forbidden_on_a_collection`.*
- **`GET` is served by the core, not `mod_dav`.** Ranges work (`206`,
  `Content-Range`, `416`). A collection gets `404` ("Attempt to serve
  directory") when no `mod_dir`/`mod_autoindex` is loaded. `COPY` of a
  collection needs no trailing slash (unlike nginx). `Overwrite: F` onto an
  existing destination is `412` for `COPY` and `MOVE`; a missing parent is
  `409`. \
  *Test: `test_apache_ranges_are_answered_by_the_core`.*

### Over time

- **An expired lock is dropped when the next request looks at it.** No timer
  sweeps them. The old token is then worthless: a write or refresh with it is
  `412`, `UNLOCK` is `400`. The client raises `PreconditionFailedError`, and
  leaving `locked()` logs "already gone" (the `400` is treated like the
  `409`/`404` of other servers). \
  *Test: `test_apache_the_client_meets_an_expired_lock_with_a_412_and_a_log_line`.*
- **An unreleased lock on an unmapped URL leaves a ghost.** After it expires,
  the lock-null entry stays: `exists()` and `isfile()` stay true, `GET` and
  `DELETE` are `404`. A new `LOCK` + `UNLOCK`, or a `PUT`/`MKCOL`, clears it. \
  *Test: `test_apache_an_expired_lock_null_resource_stays_visible_until_it_is_locked_again`.*
- **That ghost aborts the next listing of its collection (the Apache bug).**
  `PROPFIND` `Depth: 1` drops the entry while the lock database is open
  read-only. `mod_dav`'s `DAV_DEBUG` check (`#if 1` in `mod_dav.h`, not a
  setting) logs "INTERNAL DESIGN ERROR: the lockdb was opened readonly"
  after the answer has started, and the client sees the connection closed
  (`requests.exceptions.ConnectionError`). The next listing works: one
  failure per expired entry. `Depth: 0` is not affected. `ls()` tries three
  times, which covers two entries; with more, the first call raises and the
  next works. To avoid it, release what `locked()` took and give locks on
  unwritten names a short `lock_timeout`. \
  *Test: `test_apache_ls_gets_through_an_expired_lock_null_entry_by_retrying`.*

Limits, each on an instance of its own:

| Setting | What happens |
|---|---|
| `MaxKeepAliveRequests 3` | Every third answer says `Connection: close`. The client reconnects before it sends, writes included (those are never retried). No error. |
| `KeepAliveTimeout 1` | The pooled connection is gone by the next request. Same: reconnect, no error. |
| `Timeout 1`, stalled upload | `408` (`HTTPStatusError`, not retried). Nothing is stored, not even a temporary file. A slow but moving upload is fine. |
| `LimitRequestBody` | `413` before anything is stored, with an announced length (even 40 MiB, refused before it is sent) or streamed. An existing file stays as it was. |

*Test: `test_apache_limitrequestbody_refuses_with_413_before_anything_is_stored`.*

### Size and names

- **Large files.** A 48 MiB file round-trips byte for byte, and a range at
  40 MiB is answered from the right place. An upload of unknown length goes
  out chunked and arrives complete. An empty file stays empty. A collection
  of 1200 members is listed in full and removed with one `DELETE`. \
  *Test: `test_apache_a_large_file_round_trips_byte_for_byte`.*
- **Speed**, from one local run (prefork, default settings, loopback, no
  TLS, sdbm), so only a rough guide. A 256 MiB file uploads at
  ~690 MiB/s and downloads at ~1260 MiB/s, byte for byte. With 3000
  members in one collection, `ls()` and `walk()` take 0.16 s each, and
  the `DELETE` of the collection 0.03 s.
- **Names survive being a URL**: spaces, `#`, `?`, `%`, `%20` (stays six
  characters), `%2F`, `+`, `&`, `;`, `=`, quotes, `<>`, `|`, `[]`, Japanese,
  emoji, combining accents, leading and trailing spaces, dot names, 255
  bytes. Names
  that differ only in case are two resources. Over 255 *bytes* (256 ASCII or
  128 two-byte characters) is a `403` from the file system (`apr_file_open`).
  `.DAV` is a `403` at any level (`dav_fs_is_state_path`). \
  *Test: `test_apache_a_name_survives_the_round_trip` (one case per name).*

### Parallel

| Scenario | Result |
|---|---|
| Parallel uploads through one shared `FileSystem` | All arrive intact |
| Simultaneous overwrites of the same file | Exactly one whole file ends up written; a reader never sees a half-written file |
| A source copied several times at once | Any number of copies succeed |
| A source moved or deleted several times at once | Exactly one wins; the losers get `404` (gone when checked), `500` (gone between check and rename), or `403` (failed removal, seen on Ubuntu), depending on timing |
| Many simultaneous `LOCK`s on one resource | Every answer is `200` or `423`, at least one `200` |
| Simultaneous `LOCK`s on different resources | Every one is `200`, each with its own token |
| Simultaneous `PROPPATCH`es of different properties on one resource | All `207`, no property ever has a wrong value |
| A contended `locked()`, through the client | One holds it; the rest get `ResourceLockedError` and keep no token |

In the same local run as the speed figures: 32 threads uploading 2 MiB
each through one `FileSystem` left 32 of 32 files intact. 100 threads
locking 100 different files got 100 of 100 locks in 2.9 s. 32 threads
locking one file got exactly one lock and 31 `423`.

This holds reliably **only with sdbm** as Apache's DBM (next section). \
*Test: `test_apache_copy_move_and_delete_of_one_source_at_once_have_one_winner_where_one_is_possible`.*

### The DBM type decides: Berkeley DB loses concurrent writes

`mod_dav_fs` keeps locks (`DavLockDB`, one file) and dead properties (one
file per directory, in `.DAV/`) in DBM files. The DBM type is not a
`mod_dav_fs` setting but the default of the APR-util Apache was built
with. A tarball build uses **sdbm**, which
is safe with several writing processes: nothing was lost in any local run
(600 locks and sixteen simultaneous properties per run). **Debian's and
Ubuntu's APR-util defaults to Berkeley DB**, which is not. On GitHub
Actions' `ubuntu-latest` (Apache 2.4.58, `libaprutil1` 1.6.3,
`apr_dbm_db`):

| Requests at once | Result |
|---|---|
| 16 x `LOCK` on one resource | granted twice in 1 of 25 rounds (always at least once) |
| 40 x `LOCK` on 40 resources, all answered `200` | in 5 of 10 rounds 1 to 8 locks were not enforced a second later: the resource could be written without the token |
| 16 x `PROPPATCH` of 16 different properties on one file | one or more properties missing in 6 of 10 rounds (in the full suite sometimes most) |

Every request is answered as if it had worked. A `locked()` that was
granted can be unknown to the server a moment later; the write under it
gets `412` (`PreconditionFailedError`).

```{warning}
After such a burst the Ubuntu lock database stayed broken for the rest of
the run and for the next run that reused the directory: no lock enforced,
valid tokens refused with `412`, locks missing from `PROPFIND`. In
production:

- Locks taken while other locks are taken or released are not reliable.
  Locks taken one at a time are.
- Properties set by several clients on one resource at once can overwrite
  each other.
- File data is not affected, and sequential use is fine: the rest of the
  suite passes on Ubuntu.

There is nothing to configure. Build Apache with sdbm as the DBM default,
or avoid concurrent locking and `PROPPATCH` (one writer per collection, or
one process in front of the server that takes the locks).
```

## Running these tests

For running these tests yourself, see
[Running the Apache tests](contributing-apache.md).
