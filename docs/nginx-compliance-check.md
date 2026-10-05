# nginx

This page is for deploying against nginx with its own `ngx_http_dav_module`
(`PUT`, `DELETE`, `MKCOL`, `COPY`, `MOVE`) plus the `nginx-dav-ext-module`
(`PROPFIND`, `OPTIONS`, `LOCK`, `UNLOCK`). On Debian and Ubuntu the module
is the `libnginx-mod-http-dav-ext` package. nginx has limitations that
Nextcloud, Apache and WsgiDAV do not share, and two of them fail silently.
Over 25 tests check each finding against a real nginx.

## Summary

| Area | What matters in production |
|---|---|
| Compliance header | `DAV:` lists only class `2`, so `dav_compliance()` does not show class 1 |
| Creating things | `overwrite=False` is ignored: the file is overwritten, no `412` |
| Locking | Only exclusive locks; a shared lock request is granted as exclusive without saying so |
| Properties | No `PROPPATCH` (`405`); `PROPFIND` never returns `getetag` |
| Errors | A `423` has an empty body |
| Collections | `COPY`/`MOVE`, and `DELETE` of a non-empty collection, need a trailing slash |

```{admonition} Before you deploy against nginx
:class: warning

- `overwrite=False` does not protect anything: the file is overwritten
  and no `412` comes back.
- A request for a shared lock is granted as exclusive, without saying so.
- `PROPPATCH` is a `405`, and `get_props(...).etag` is always `None`.

See [Known limitations](#known-limitations).
```

## Behaviour in detail

### Known limitations

Each of these has a test of its own. A future nginx-dav-ext release that
fixes one of them turns that test red.

```{warning}
Two of them fail silently: there is no overwrite protection, and a shared
lock request is granted as exclusive without saying so. In both cases a
caller believes it has a guarantee it does not have.
```

- **The `DAV:` header lists only class `2`, never `1`.** This happens
  every time: right after start, after a restart, and on repeated checks. The
  server still behaves as class 1 (MKCOL/PUT/DELETE/COPY/MOVE all work);
  only the header is incomplete. That matters to anything that reads
  `dav_compliance()` to decide what a server can do. \
  *Test: `test_nginx_advertises_class_2_but_not_class_1`.*
- **No overwrite protection.** `ngx_http_dav_module` never evaluates
  `If-None-Match` on `PUT`, so `overwrite=False` overwrites the file
  instead of failing with `412`. \
  *Test: `test_nginx_does_not_honor_overwrite_protection`.*
- **A shared lock request is granted as exclusive.** `nginx-dav-ext-module`
  ignores the requested `<D:lockscope>`. A caller that asks for
  `scope=SHARED` believes it holds a shared lock, and it does not. \
  *Test: `test_nginx_silently_grants_a_shared_lock_request_as_exclusive`.*
- **`PROPPATCH` is not supported.** It is not a legal value for the
  module's `dav_ext_methods` directive (`nginx -t` refuses the config), and
  the method gets a plain `405` from nginx's HTTP core. \
  *Test: `test_nginx_does_not_support_proppatch_at_all`.*
- **PROPFIND never returns `getetag`**, for any resource.
  `get_props(...).etag` is always `None` against nginx. \
  *Test: `test_nginx_propfind_never_returns_an_etag`.*
- **A `423` has no body at all** (`Content-Length: 0`), not even the plain
  HTML page Apache sends. `error_codes` is an empty set, as on Apache, but
  for a different reason. \
  *Test: `test_nginx_423_response_is_never_crashed_on_even_without_a_structured_error_body`.*

### Collections need a trailing slash

nginx enforces something Nextcloud, Apache and WsgiDAV do not. COPY and
MOVE of a collection need a trailing slash on both the source path and the
`Destination`, and DELETE of a non-empty collection needs one on the path.
Without it, nginx answers `400 Bad Request` (COPY/MOVE) or `409 Conflict`
(DELETE). The library keeps a trailing slash you pass, so
`fs.copy("src/", "dst/")` and `fs.remove("dir/")` work. \
*Tests: `test_nginx_copy_of_a_nested_collection_duplicates_the_whole_subtree`
and `test_nginx_a_clean_delete_of_a_nested_collection_is_204`.*

## Running these tests

For running these tests yourself, see
[Running the nginx tests](contributing-nginx.md).
