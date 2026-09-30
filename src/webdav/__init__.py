"""RFC 4918 compliant WebDAV client, built on ``requests``."""

from webdav.dav.features import FeatureDetection
from webdav.dav.locks import ActiveLock
from webdav.exceptions import (
    ClientError,
    ForbiddenError,
    HTTPStatusError,
    InsecureTransportWarning,
    InsufficientStorageError,
    IsACollectionError,
    IsAResourceError,
    LockError,
    MalformedResponseError,
    MultiStatusError,
    PreconditionFailedError,
    RedirectNotFollowedError,
    ResourceAlreadyExistsError,
    ResourceConflictError,
    ResourceLockedError,
    ResourceNotFoundError,
    TLSConfigError,
    TLSHardeningDisabledWarning,
    WebDAVError,
)

# ``open`` mirrors FileSystem.open (like ``gzip.open`` / ``io.open``), so it is
# public and, as in those modules, ``from webdav import *`` shadows the builtin.
# pylint: disable-next=redefined-builtin
from webdav.fs import (
    FileSystem,
    content_language,
    content_length,
    content_type,
    copy,
    created,
    dav_compliance,
    download_file,
    download_fileobj,
    etag,
    exists,
    get_props,
    info,
    isdir,
    isfile,
    locked,
    ls,
    mkdir,
    modified,
    move,
    open,  # noqa: A004
    refresh_lock,
    remove,
    set_props,
    upload_file,
    upload_fileobj,
    walk,
)
from webdav.methods import Method
from webdav.resource import Resource
from webdav.response import Response
from webdav.session import Session
from webdav.transport.redirects import RedirectPolicy
from webdav.transport.tls import TLSOptions

__version__ = "0.1.0"


__all__ = [
    "ActiveLock",
    "ClientError",
    "FeatureDetection",
    "FileSystem",
    "ForbiddenError",
    "HTTPStatusError",
    "InsecureTransportWarning",
    "InsufficientStorageError",
    "IsACollectionError",
    "IsAResourceError",
    "LockError",
    "MalformedResponseError",
    "Method",
    "MultiStatusError",
    "PreconditionFailedError",
    "RedirectNotFollowedError",
    "RedirectPolicy",
    "Resource",
    "ResourceAlreadyExistsError",
    "ResourceConflictError",
    "ResourceLockedError",
    "ResourceNotFoundError",
    "Response",
    "Session",
    "TLSConfigError",
    "TLSHardeningDisabledWarning",
    "TLSOptions",
    "WebDAVError",
    "__version__",
    "content_language",
    "content_length",
    "content_type",
    "copy",
    "created",
    "dav_compliance",
    "download_file",
    "download_fileobj",
    "etag",
    "exists",
    "get_props",
    "info",
    "isdir",
    "isfile",
    "locked",
    "ls",
    "mkdir",
    "modified",
    "move",
    "open",
    "refresh_lock",
    "remove",
    "set_props",
    "upload_file",
    "upload_fileobj",
    "walk",
]
