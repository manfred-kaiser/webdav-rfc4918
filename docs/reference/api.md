# API reference

Every public class and function, generated from the docstrings. This page
is for looking things up. For explanations and examples, start with
[Short form](short-form.md), [FileSystem](filesystem.md) and
[Session](session.md).

## Module-level functions

The short form: one call, one full URL. Each function takes the options
of `FileSystem(...)` as keyword arguments and behaves like the
`FileSystem` method of the same name.

```{eval-rst}
.. rubric:: Listing and checking

.. autofunction:: webdav.ls
.. autofunction:: webdav.info
.. autofunction:: webdav.walk
.. autofunction:: webdav.exists
.. autofunction:: webdav.isdir
.. autofunction:: webdav.isfile

.. rubric:: Transferring content

.. autofunction:: webdav.upload_file
.. autofunction:: webdav.download_file
.. autofunction:: webdav.upload_fileobj
.. autofunction:: webdav.download_fileobj
.. autofunction:: webdav.open

.. rubric:: Creating, copying, moving, removing

.. autofunction:: webdav.mkdir
.. autofunction:: webdav.copy
.. autofunction:: webdav.move
.. autofunction:: webdav.remove

.. rubric:: Properties

.. autofunction:: webdav.get_props
.. autofunction:: webdav.set_props
.. autofunction:: webdav.content_length
.. autofunction:: webdav.content_type
.. autofunction:: webdav.content_language
.. autofunction:: webdav.created
.. autofunction:: webdav.modified
.. autofunction:: webdav.etag
.. autofunction:: webdav.dav_compliance

.. rubric:: Locks

.. autofunction:: webdav.locked
.. autofunction:: webdav.refresh_lock
```

## FileSystem

```{eval-rst}
.. autoclass:: webdav.fs.client.FileSystem
   :members:
```

## Session

```{eval-rst}
.. autoclass:: webdav.session.Session
   :members:
```

## Response and Resource

A `Session` verb returns a `Response`. `FileSystem.ls`, `info` and `walk`
return `Resource` objects.

```{eval-rst}
.. autoclass:: webdav.response.Response
   :members:
   :exclude-members: adopt

.. autoclass:: webdav.resource.Resource
   :members:
```

## Locking

```{eval-rst}
.. autoclass:: webdav.dav.locks.ActiveLock
   :members:
```

The `If` header that writes through a held lock carry is built by this
module. It can also be used directly for a custom conditional request.

```{eval-rst}
.. automodule:: webdav.dav.conditional
   :members:
```

## Redirects

```{eval-rst}
.. autoclass:: webdav.transport.redirects.RedirectPolicy
   :members:
```

## TLS

```{eval-rst}
.. autoclass:: webdav.transport.tls.TLSOptions
   :members:

.. autofunction:: webdav.transport.tls.build_ssl_context
```

## fsspec

```{eval-rst}
.. autoclass:: webdav.fsspec.WebdavFileSystem
   :members:
```

## Exceptions

Base classes first, then the HTTP status errors in the order of the table
in [Exceptions](exceptions.md).

```{eval-rst}
.. rubric:: Base classes

.. autoclass:: webdav.exceptions.WebDAVError
   :members:

.. autoclass:: webdav.exceptions.ClientError
   :members:

.. autoclass:: webdav.exceptions.HTTPStatusError
   :members:

.. rubric:: HTTP status errors, by status code

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

.. autoclass:: webdav.exceptions.UnsupportedMediaTypeError
   :members:

.. autoclass:: webdav.exceptions.UnprocessableEntityError
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

.. rubric:: Failures without an error status

.. autoclass:: webdav.exceptions.MultiStatusError
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

.. rubric:: Warnings

.. autoclass:: webdav.exceptions.InsecureTransportWarning

.. autoclass:: webdav.exceptions.TLSHardeningDisabledWarning
```
