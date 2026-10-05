"""Module-level file-system API: ``webdav.ls(url)``, ``webdav.mkdir(url)``, ...

Mirrors :class:`~webdav.fs.client.FileSystem` exactly - same names,
arguments and return values (``tests/test_api_consistency.py`` compares
them); each function opens a throwaway :class:`~webdav.fs.client.FileSystem`,
does one thing, closes it again. There is no equivalent for
:class:`~webdav.session.Session`: its verbs are protocol-level tools for
callers who already need a ``Session`` open, not one-off calls, so use
``with webdav.Session(...) as session: session.get(...)`` directly instead.
"""

# Parameters mirror FileSystem, so they shadow module-level names (open, set_props).
# pylint: disable=redefined-builtin,redefined-outer-name
from collections.abc import Iterator
from contextlib import contextmanager
from typing import (
    TYPE_CHECKING,
    Any,
    BinaryIO,
    Concatenate,
    Literal,
    ParamSpec,
    TextIO,
    TypeVar,
    Unpack,
    overload,
)

from webdav.dav.locks import DEFAULT_LOCK_TIMEOUT, EXCLUSIVE, ActiveLock
from webdav.fs.client import FileSystem
from webdav.resource import Resource
from webdav.session import ConnectionOptions, SessionOptions

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable
    from datetime import datetime
    from os import PathLike
    from xml.etree.ElementTree import Element

    from webdav.dav.properties import DAVProperties, PropName

_P = ParamSpec("_P")
_R = TypeVar("_R")
_T = TypeVar("_T")


class _TransferOptions(ConnectionOptions, total=False):
    """For functions with their own ``chunk_size`` parameter."""

    headers: "dict[str, str] | None"


_Options = SessionOptions
#: For functions with their own ``chunk_size`` and ``headers`` parameters.
_UploadOptions = ConnectionOptions


def _new_filesystem(session_options: "dict[str, Any]") -> FileSystem:
    """A ``FileSystem`` (owning its own session) from the (already split off) session options."""
    return FileSystem(**session_options)


def _run(
    method: "Callable[Concatenate[FileSystem, _P], _R]",
    session_options: "Any",
    *args: _P.args,
    **kwargs: _P.kwargs,
) -> _R:
    with _new_filesystem(dict(session_options)) as filesystem:
        return method(filesystem, *args, **kwargs)


def _walk(
    method: "Callable[Concatenate[FileSystem, _P], Iterator[_T]]",
    session_options: "Any",
    *args: _P.args,
    **kwargs: _P.kwargs,
) -> "Iterator[_T]":
    filesystem = _new_filesystem(
        dict(session_options)
    )  # bad options fail now, not at the first item
    return _walk_with(filesystem, method, *args, **kwargs)


def _walk_with(
    filesystem: FileSystem,
    method: "Callable[Concatenate[FileSystem, _P], Iterator[_T]]",
    *args: _P.args,
    **kwargs: _P.kwargs,
) -> "Iterator[_T]":
    with filesystem:
        yield from method(filesystem, *args, **kwargs)


@contextmanager
def _context(
    name: str, session_options: "Any", *args: Any, **kwargs: Any
) -> "Iterator[Any]":
    with (
        _new_filesystem(dict(session_options)) as filesystem,
        getattr(filesystem, name)(*args, **kwargs) as value,
    ):
        yield value


def ls(path: str, **kwargs: Unpack[_Options]) -> list[Resource]:
    """List the members of a collection.

    See :meth:`~webdav.fs.client.FileSystem.ls`; ``path`` is a full URL.
    """
    return _run(FileSystem.ls, kwargs, path)


def info(path: str, **kwargs: Unpack[_Options]) -> Resource:
    """Describe one resource (a file or a collection - not its members).

    See :meth:`~webdav.fs.client.FileSystem.info`; ``path`` is a full URL.
    """
    return _run(FileSystem.info, kwargs, path)


def exists(path: str, **kwargs: Unpack[_Options]) -> bool:
    """Check whether a resource exists.

    See :meth:`~webdav.fs.client.FileSystem.exists`; ``path`` is a full URL.
    """
    return _run(FileSystem.exists, kwargs, path)


def isdir(path: str, **kwargs: Unpack[_Options]) -> bool:
    """Check whether a resource is a collection (``False`` if it does not exist).

    See :meth:`~webdav.fs.client.FileSystem.isdir`; ``path`` is a full URL.
    """
    return _run(FileSystem.isdir, kwargs, path)


def isfile(path: str, **kwargs: Unpack[_Options]) -> bool:
    """Check whether a resource exists and is not a collection.

    See :meth:`~webdav.fs.client.FileSystem.isfile`; ``path`` is a full URL.
    """
    return _run(FileSystem.isfile, kwargs, path)


def mkdir(
    path: str,
    *,
    data: str | None = None,
    set_props: "dict[str | PropName, Any] | None" = None,
    **kwargs: Unpack[_Options],
) -> None:
    """Create a collection.

    See :meth:`~webdav.fs.client.FileSystem.mkdir`; ``path`` is a full URL.
    """
    _run(FileSystem.mkdir, kwargs, path, data=data, set_props=set_props)


def remove(path: str, **kwargs: Unpack[_Options]) -> None:
    """Remove a resource (or a collection, with everything in it).

    See :meth:`~webdav.fs.client.FileSystem.remove`; ``path`` is a full URL.
    """
    _run(FileSystem.remove, kwargs, path)


def copy(
    path: str,
    destination: str,
    *,
    overwrite: "bool | None" = False,
    depth: "int | str | None" = None,
    **kwargs: Unpack[_Options],
) -> None:
    """Copy a resource (or a collection, with everything in it) server-side.

    See :meth:`~webdav.fs.client.FileSystem.copy`; ``path`` is a full URL.
    """
    _run(FileSystem.copy, kwargs, path, destination, overwrite=overwrite, depth=depth)


def move(
    path: str,
    destination: str,
    *,
    overwrite: "bool | None" = False,
    **kwargs: Unpack[_Options],
) -> None:
    """Move (rename) a resource server-side.

    See :meth:`~webdav.fs.client.FileSystem.move`; ``path`` is a full URL.
    """
    _run(FileSystem.move, kwargs, path, destination, overwrite=overwrite)


def get_props(
    path: str,
    *,
    props: "Iterable[str | PropName] | None" = None,
    all_prop: bool = False,
    include: "Iterable[str | PropName] | None" = None,
    **kwargs: Unpack[_Options],
) -> "DAVProperties":
    """Return properties of a resource via PROPFIND.

    See :meth:`~webdav.fs.client.FileSystem.get_props`; ``path`` is a full URL.
    """
    return _run(
        FileSystem.get_props,
        kwargs,
        path,
        props=props,
        all_prop=all_prop,
        include=include,
    )


def set_props(
    path: str,
    *,
    set_props: "dict[str | PropName, Any] | None" = None,
    remove_props: "Iterable[str | PropName] | None" = None,
    **kwargs: Unpack[_Options],
) -> None:
    """Set and/or remove properties via PROPPATCH (RFC 4918 sec. 9.2).

    See :meth:`~webdav.fs.client.FileSystem.set_props`; ``path`` is a full URL.
    """
    _run(
        FileSystem.set_props,
        kwargs,
        path,
        set_props=set_props,
        remove_props=remove_props,
    )


def refresh_lock(
    path: str,
    token: str,
    *,
    lock_timeout: "int | Iterable[int | None] | None" = DEFAULT_LOCK_TIMEOUT,
    **kwargs: Unpack[_Options],
) -> ActiveLock:
    """Refresh a held lock's timeout (RFC 4918 sec. 9.10.2).

    See :meth:`~webdav.fs.client.FileSystem.refresh_lock`; ``path`` is a full URL.
    """
    return _run(FileSystem.refresh_lock, kwargs, path, token, lock_timeout=lock_timeout)


def content_length(path: str, **kwargs: Unpack[_Options]) -> "int | None":
    """Return the ``getcontentlength`` property.

    See :meth:`~webdav.fs.client.FileSystem.content_length`; ``path`` is a full URL.
    """
    return _run(FileSystem.content_length, kwargs, path)


def created(path: str, **kwargs: Unpack[_Options]) -> "datetime | None":
    """Return the ``creationdate`` property.

    See :meth:`~webdav.fs.client.FileSystem.created`; ``path`` is a full URL.
    """
    return _run(FileSystem.created, kwargs, path)


def modified(path: str, **kwargs: Unpack[_Options]) -> "datetime | None":
    """Return the ``getlastmodified`` property.

    See :meth:`~webdav.fs.client.FileSystem.modified`; ``path`` is a full URL.
    """
    return _run(FileSystem.modified, kwargs, path)


def etag(path: str, **kwargs: Unpack[_Options]) -> "str | None":
    """Return the ``getetag`` property.

    See :meth:`~webdav.fs.client.FileSystem.etag`; ``path`` is a full URL.
    """
    return _run(FileSystem.etag, kwargs, path)


def content_type(path: str, **kwargs: Unpack[_Options]) -> "str | None":
    """Return the ``getcontenttype`` property.

    See :meth:`~webdav.fs.client.FileSystem.content_type`; ``path`` is a full URL.
    """
    return _run(FileSystem.content_type, kwargs, path)


def content_language(path: str, **kwargs: Unpack[_Options]) -> "str | None":
    """Return the ``getcontentlanguage`` property.

    See :meth:`~webdav.fs.client.FileSystem.content_language`; ``path`` is a full URL.
    """
    return _run(FileSystem.content_language, kwargs, path)


def dav_compliance(path: str = "", **kwargs: Unpack[_Options]) -> set[str]:
    """Return the ``DAV:`` compliance classes the server advertises.

    See :meth:`~webdav.fs.client.FileSystem.dav_compliance`; ``path`` is a full URL.
    """
    return _run(FileSystem.dav_compliance, kwargs, path)


def walk(
    path: str, *, max_depth: "int | None" = None, **kwargs: Unpack[_Options]
) -> "Iterator[tuple[str, list[Resource], list[Resource]]]":
    """Walk a collection tree top-down, like :func:`os.walk`.

    See :meth:`~webdav.fs.client.FileSystem.walk`; ``path`` is a full URL.
    """
    return _walk(FileSystem.walk, kwargs, path, max_depth=max_depth)


def download_file(
    path: str,
    local_path: "str | PathLike[str]",
    *,
    overwrite: bool = False,
    chunk_size: int | None = None,
    callback: "Callable[[int], Any] | None" = None,
    **kwargs: Unpack[_TransferOptions],
) -> None:
    """Download a resource to a local file.

    See :meth:`~webdav.fs.client.FileSystem.download_file`; ``path`` is a full URL.
    """
    _run(
        FileSystem.download_file,
        kwargs,
        path,
        local_path,
        overwrite=overwrite,
        chunk_size=chunk_size,
        callback=callback,
    )


def upload_file(
    local_path: "str | PathLike[str]",
    path: str,
    *,
    overwrite: bool = False,
    chunk_size: int | None = None,
    callback: "Callable[[int], Any] | None" = None,
    headers: dict[str, str] | None = None,
    **kwargs: Unpack[_UploadOptions],
) -> None:
    """Upload a local file to a remote path.

    See :meth:`~webdav.fs.client.FileSystem.upload_file`; ``path`` is a full URL.
    """
    _run(
        FileSystem.upload_file,
        kwargs,
        local_path,
        path,
        overwrite=overwrite,
        chunk_size=chunk_size,
        callback=callback,
        headers=headers,
    )


def download_fileobj(
    path: str,
    fileobj: BinaryIO,
    *,
    chunk_size: int | None = None,
    callback: "Callable[[int], Any] | None" = None,
    **kwargs: Unpack[_TransferOptions],
) -> None:
    """Write a resource's contents to an open, writable file object.

    See :meth:`~webdav.fs.client.FileSystem.download_fileobj`; ``path`` is a full URL.
    """
    _run(
        FileSystem.download_fileobj,
        kwargs,
        path,
        fileobj,
        chunk_size=chunk_size,
        callback=callback,
    )


def upload_fileobj(
    fileobj: BinaryIO,
    path: str,
    *,
    overwrite: bool = False,
    chunk_size: int | None = None,
    callback: "Callable[[int], Any] | None" = None,
    size: int | None = None,
    headers: dict[str, str] | None = None,
    **kwargs: Unpack[_UploadOptions],
) -> None:
    """Upload an open, readable file object to a remote path.

    See :meth:`~webdav.fs.client.FileSystem.upload_fileobj`; ``path`` is a full URL.
    """
    _run(
        FileSystem.upload_fileobj,
        kwargs,
        fileobj,
        path,
        overwrite=overwrite,
        chunk_size=chunk_size,
        callback=callback,
        size=size,
        headers=headers,
    )


@overload
@contextmanager
def open(  # noqa: A001
    path: str,
    mode: Literal["rb", "wb", "xb"],
    *,
    encoding: str | None = ...,
    chunk_size: int | None = ...,
    **kwargs: Unpack[_TransferOptions],
) -> Iterator[BinaryIO]: ...


@overload
@contextmanager
def open(  # noqa: A001
    path: str,
    mode: Literal["r", "rt", "w", "wt", "x", "xt"] = ...,
    *,
    encoding: str | None = ...,
    chunk_size: int | None = ...,
    **kwargs: Unpack[_TransferOptions],
) -> Iterator[TextIO]: ...


@contextmanager
def open(  # noqa: A001
    path: str,
    mode: str = "r",
    *,
    encoding: str | None = None,
    chunk_size: int | None = None,
    **kwargs: Unpack[_TransferOptions],
) -> "Iterator[TextIO | BinaryIO]":
    """Open a resource for reading or writing, like the builtin ``open``.

    See :meth:`~webdav.fs.client.FileSystem.open`; ``path`` is a full URL.
    """
    with _context(
        "open", kwargs, path, mode, encoding=encoding, chunk_size=chunk_size
    ) as value:
        yield value


@contextmanager
def locked(
    path: str,
    *,
    scope: str = EXCLUSIVE,
    depth: str = "infinity",
    lock_timeout: "int | Iterable[int | None] | None" = DEFAULT_LOCK_TIMEOUT,
    owner: "str | Element | None" = None,
    **kwargs: Unpack[_Options],
) -> "Iterator[ActiveLock]":
    """Hold a WebDAV lock on ``path`` for the duration of the ``with`` block.

    See :meth:`~webdav.fs.client.FileSystem.locked`; ``path`` is a full URL.
    """
    with _context(
        "locked",
        kwargs,
        path,
        scope=scope,
        depth=depth,
        lock_timeout=lock_timeout,
        owner=owner,
    ) as value:
        yield value
