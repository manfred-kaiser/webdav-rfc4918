# Exceptions

Every exception this library raises derives from
{class}`~webdav.exceptions.WebDAVError`, itself a subclass of
`requests.exceptions.RequestException` - code that already catches
`requests`' own exception hierarchy catches everything raised here too,
without needing to know about this library specifically. This page maps
what shows up at a call site - a status code, a malformed response, a
partial failure - to the exception raised and what to do about it.

```python
import webdav
from webdav.exceptions import WebDAVError

try:
    with webdav.FileSystem("https://webdav.example.org", auth=("user", "pw")) as fs:
        fs.upload_file("report.docx", "Documents/report.docx")
except WebDAVError as exc:
    print(f"upload failed: {exc}")
```

This works for every file-system operation, which raises on an error
status by default. A [`Session`](session.md) verb instead returns a
`Response` and raises nothing unless you call `raise_for_status()` or
construct the session with `raise_on_error=True` - see
[Session and FileSystem](session.md).

```{eval-rst}
.. autoclass:: webdav.exceptions.WebDAVError
   :members:
```

## Which exception for which failure

| Symptom / status code | Exception | Typical cause and reaction |
|---|---|---|
| 403 Forbidden | `ForbiddenError` | Operation not permitted for the authenticated user. Not retried. |
| 404 Not Found | `ResourceNotFoundError` | Resource does not exist at that path (wrong path, or already gone). Not retried. |
| 409 Conflict | `ResourceConflictError` | E.g. the parent collection is missing. Not retried. |
| 412 Precondition Failed | `PreconditionFailedError` | `If-Match`/`If-None-Match` lost, `Overwrite: F` on an existing destination, or an `If` header naming a lock token no longer held - check `error_codes` or re-read the resource's state. Not retried. |
| 412, on a create-only call | `ResourceAlreadyExistsError` | `overwrite=False` or `mkdir` found the target already there. Subclass of `PreconditionFailedError`. |
| 415 Unsupported Media Type | `UnsupportedMediaTypeError` | An Extended MKCOL (RFC 5689) body wasn't valid. Not retried. |
| 422 Unprocessable Entity | `UnprocessableEntityError` | Request body well-formed but semantically invalid. Not retried. |
| 423 Locked | `ResourceLockedError` | Resource is locked by someone else. Not retried - a lock won't go away in the seconds a retry would wait; see [Locking](locking.md). |
| 424 Failed Dependency | `FailedDependencyError` | Another action in the same request failed first. Not retried. |
| 428 Precondition Required | `PreconditionRequiredError` | Server requires a conditional request. Not retried. |
| 429 Too Many Requests | `TooManyRequestsError` | Rate-limited. Retried automatically with backoff. |
| 500 Internal Server Error | `InternalServerError` | Generic server-side failure. Retried automatically. |
| 502 Bad Gateway | `BadGatewayError` | Upstream/proxy refused the request - on a COPY/MOVE, the destination server may have refused to accept the resource. Retried automatically. |
| 503 Service Unavailable | `ServiceUnavailableError` | Server temporarily unable to handle the request. Retried automatically. |
| 504 Gateway Timeout | `GatewayTimeoutError` | Upstream/proxy timed out. Retried automatically. |
| 507 Insufficient Storage | `InsufficientStorageError` | Server has run out of storage space. Not retried. |
| 509 Bandwidth Limit Exceeded (non-standard) | `BandwidthLimitExceededError` | A cPanel-hosted server's bandwidth allotment is exceeded. Retried automatically. |
| A 3xx the active redirect policy didn't follow | `RedirectNotFollowedError` | See [Redirects](redirects.md) - the target is on `exc.response.headers["Location"]`. |
| 207 Multi-Status with a per-resource failure | `MultiStatusError` | Some but not all resources in the request failed - e.g. one member under a `Depth: infinity` lock, or one property in a `PROPPATCH`. See [Locking](locking.md). |
| A resource is a collection, but was expected not to be | `IsACollectionError` | Raised client-side, before any request that would conflict. |
| A resource is not a collection, but was expected to be | `IsAResourceError` | Raised client-side, before any request that would conflict. |
| A client/CA certificate or key could not be loaded | `TLSConfigError` | Wraps an undifferentiated `ssl` failure with the path that was actually being loaded. |
| A lock-token/`If`-header operation fails without a request | `LockError` | E.g. refreshing a lock without holding its token, or writing through a stale lock the client already knows is gone. |
| A response body could not be parsed/understood | `MalformedResponseError` | Non-well-formed XML in a 207/LOCK body, a multistatus reply missing an expected entry, or an `href`/lock token that doesn't make sense. The HTTP exchange itself succeeded. |

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

```{eval-rst}
.. autoclass:: webdav.exceptions.ClientError
   :members:

.. autoclass:: webdav.exceptions.IsACollectionError
   :members:

.. autoclass:: webdav.exceptions.IsAResourceError
   :members:

.. autoclass:: webdav.exceptions.TLSConfigError
   :members:

.. autoclass:: webdav.exceptions.LockError
   :members:

.. autoclass:: webdav.exceptions.MalformedResponseError
   :members:

.. autoclass:: webdav.exceptions.MultiStatusError
   :members:

.. autoclass:: webdav.exceptions.HTTPStatusError
   :members:

.. autoclass:: webdav.exceptions.ForbiddenError
   :members:

.. autoclass:: webdav.exceptions.ResourceNotFoundError
   :members:

.. autoclass:: webdav.exceptions.ResourceConflictError
   :members:

.. autoclass:: webdav.exceptions.PreconditionFailedError
   :members:

.. autoclass:: webdav.exceptions.ResourceAlreadyExistsError
   :members:

.. autoclass:: webdav.exceptions.UnprocessableEntityError
   :members:

.. autoclass:: webdav.exceptions.UnsupportedMediaTypeError
   :members:

.. autoclass:: webdav.exceptions.ResourceLockedError
   :members:

.. autoclass:: webdav.exceptions.FailedDependencyError
   :members:

.. autoclass:: webdav.exceptions.PreconditionRequiredError
   :members:

.. autoclass:: webdav.exceptions.TooManyRequestsError
   :members:

.. autoclass:: webdav.exceptions.InternalServerError
   :members:

.. autoclass:: webdav.exceptions.BadGatewayError
   :members:

.. autoclass:: webdav.exceptions.ServiceUnavailableError
   :members:

.. autoclass:: webdav.exceptions.GatewayTimeoutError
   :members:

.. autoclass:: webdav.exceptions.InsufficientStorageError
   :members:

.. autoclass:: webdav.exceptions.BandwidthLimitExceededError
   :members:

.. autoclass:: webdav.exceptions.RedirectNotFollowedError
   :members:
   :no-index:
```
