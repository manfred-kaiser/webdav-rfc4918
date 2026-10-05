# Exceptions

Every exception this library raises derives from
{class}`~webdav.exceptions.WebDAVError`, a subclass of
`requests.exceptions.RequestException`. Code that already catches
`RequestException` catches these too, along with network failures.

A [`FileSystem`](filesystem.md) or [short-form](short-form.md) call
raises on an error status. A [`Session`](session.md) verb returns a
`Response` and raises nothing unless you call `raise_for_status()` or
create the session with `raise_on_error=True`. The
[Quickstart](../quickstart.md#handling-errors) has a short example.
Every exception class, with its attributes, is listed in the
[API reference](api.md#exceptions).

## Which exception for which failure

| Symptom / status code | Exception | Typical cause and reaction |
|---|---|---|
| 403 Forbidden | {class}`~webdav.exceptions.ForbiddenError` | Operation not permitted for the authenticated user. Not retried. |
| 404 Not Found | {class}`~webdav.exceptions.ResourceNotFoundError` | Resource does not exist at that path (wrong path, or already gone). Not retried. |
| 409 Conflict | {class}`~webdav.exceptions.ResourceConflictError` | E.g. the parent collection is missing. Not retried. |
| 412 Precondition Failed | {class}`~webdav.exceptions.PreconditionFailedError` | `If-Match`/`If-None-Match` lost, `Overwrite: F` on an existing destination, or an `If` header naming a lock token no longer held - check `error_codes` or re-read the resource's state. Not retried. |
| 412, on a create-only call | {class}`~webdav.exceptions.ResourceAlreadyExistsError` | `overwrite=False` or `mkdir` found the target already there. Subclass of `PreconditionFailedError`. |
| 415 Unsupported Media Type | {class}`~webdav.exceptions.UnsupportedMediaTypeError` | An Extended MKCOL (RFC 5689) body wasn't valid. Not retried. |
| 422 Unprocessable Entity | {class}`~webdav.exceptions.UnprocessableEntityError` | Request body well-formed but semantically invalid. Not retried. |
| 423 Locked | {class}`~webdav.exceptions.ResourceLockedError` | Resource is locked by someone else. Not retried - a lock won't go away in the seconds a retry would wait; see [Locking](locking.md). |
| 424 Failed Dependency | {class}`~webdav.exceptions.FailedDependencyError` | Another action in the same request failed first. Not retried. |
| 428 Precondition Required | {class}`~webdav.exceptions.PreconditionRequiredError` | Server requires a conditional request. Not retried. |
| 429 Too Many Requests | {class}`~webdav.exceptions.TooManyRequestsError` | Rate-limited. Retried automatically with backoff. |
| 500 Internal Server Error | {class}`~webdav.exceptions.InternalServerError` | Generic server-side failure. Retried automatically. |
| 502 Bad Gateway | {class}`~webdav.exceptions.BadGatewayError` | Upstream/proxy refused the request - on a COPY/MOVE, the destination server may have refused to accept the resource. Retried automatically. |
| 503 Service Unavailable | {class}`~webdav.exceptions.ServiceUnavailableError` | Server temporarily unable to handle the request. Retried automatically. |
| 504 Gateway Timeout | {class}`~webdav.exceptions.GatewayTimeoutError` | Upstream/proxy timed out. Retried automatically. |
| 507 Insufficient Storage | {class}`~webdav.exceptions.InsufficientStorageError` | Server has run out of storage space. Not retried. |
| 509 Bandwidth Limit Exceeded (non-standard) | {class}`~webdav.exceptions.BandwidthLimitExceededError` | A cPanel-hosted server's bandwidth allotment is exceeded. Retried automatically. |
| A 3xx the active redirect policy didn't follow | {class}`~webdav.exceptions.RedirectNotFollowedError` | See [Redirects](redirects.md) - the target is on `exc.response.headers["Location"]`. |
| 207 Multi-Status with a per-resource failure | {class}`~webdav.exceptions.MultiStatusError` | Some but not all resources in the request failed - e.g. one member under a `Depth: infinity` lock, or one property in a `PROPPATCH`. See [Locking](locking.md). |
| A resource is a collection, but was expected not to be | {class}`~webdav.exceptions.IsACollectionError` | Raised client-side, before any request that would conflict. |
| A resource is not a collection, but was expected to be | {class}`~webdav.exceptions.IsAResourceError` | Raised client-side, before any request that would conflict. |
| A client/CA certificate or key could not be loaded | {class}`~webdav.exceptions.TLSConfigError` | Wraps an undifferentiated `ssl` failure with the path that was actually being loaded. |
| A lock-token/`If`-header operation fails without a request | {class}`~webdav.exceptions.LockError` | E.g. refreshing a lock without holding its token, or writing through a stale lock the client already knows is gone. |
| A response body could not be parsed/understood | {class}`~webdav.exceptions.MalformedResponseError` | Non-well-formed XML in a 207/LOCK body, a multistatus reply missing an expected entry, or an `href`/lock token that doesn't make sense. The HTTP exchange itself succeeded. |

## Retryable failures and other edge cases

- **`retryable`** is a `ClassVar[bool]` on every `HTTPStatusError` subclass,
  read by the retry wrapper to decide whether a failed request is repeated -
  `True` for 429 and the 5xx-family errors above, `False` everywhere else.
  This only ever applies to the safe methods (`GET`, `HEAD`, `OPTIONS`,
  `PROPFIND`); see [Retries](session.md#retries) for why writes are never
  retried regardless of status.
- **`error_codes`** gives the RFC 4918 §16 precondition/postcondition codes
  from the response body (e.g. `{"no-conflicting-lock"}`,
  `{"lock-token-submitted"}`), when the server sent any - lazily parsed and
  cached, and an empty `frozenset` (never an exception) if the body is
  missing or not XML. On `HTTPStatusError` it's a property on the single
  failed response; on `MultiStatusError` it's a `dict` mapping each failed
  `href` (or `"href (property)"` for a PROPPATCH per-property failure) to
  its own codes.
- **`MultiStatusError.statuses`** is the same per-`href` mapping, but to a
  human-readable reason instead of RFC 4918 codes - this is what the
  exception's message is built from.
- **fsspec** translates this hierarchy into the stdlib exceptions its own
  callers expect (`FileNotFoundError`, `FileExistsError`,
  `PermissionError`, ...) instead of raising `WebDAVError` subclasses
  directly - see [fsspec](fsspec.md).
