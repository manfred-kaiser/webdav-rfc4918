"""File-system-shaped access to a WebDAV server.

:class:`~webdav.fs.client.FileSystem` (this package's main export) and the
module-level functions that mirror it one-to-one both live here - see
:mod:`webdav.fs.client` and :mod:`webdav.fs.api` for the two halves.
"""

# ``open`` mirrors FileSystem.open (like ``gzip.open`` / ``io.open``), so it is
# public and, as in those modules, ``from webdav.fs import *`` shadows the builtin.
# pylint: disable-next=redefined-builtin
from webdav.fs.api import (
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
from webdav.fs.client import FileSystem

__all__ = [
    "FileSystem",
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
