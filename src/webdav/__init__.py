"""RFC 4918 compliant WebDAV client, built on ``requests``."""

from webdav.client import Client, RedirectPolicy
from webdav.exceptions import (
    ClientError,
    ForbiddenError,
    HTTPStatusError,
    InsufficientStorageError,
    IsACollectionError,
    IsAResourceError,
    LockError,
    MalformedResponseError,
    MultiStatusError,
    RedirectNotFollowedError,
    ResourceAlreadyExistsError,
    ResourceConflictError,
    ResourceLockedError,
    ResourceNotFoundError,
    TLSConfigError,
    WebDAVError,
)

__version__ = "0.1.0"

__all__ = [
    "Client",
    "ClientError",
    "ForbiddenError",
    "HTTPStatusError",
    "InsufficientStorageError",
    "IsACollectionError",
    "IsAResourceError",
    "LockError",
    "MalformedResponseError",
    "MultiStatusError",
    "RedirectNotFollowedError",
    "RedirectPolicy",
    "ResourceAlreadyExistsError",
    "ResourceConflictError",
    "ResourceLockedError",
    "ResourceNotFoundError",
    "TLSConfigError",
    "WebDAVError",
    "__version__",
]
