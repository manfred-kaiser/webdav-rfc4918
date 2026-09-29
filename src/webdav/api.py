"""Module-level API: ``webdav.get(url)``, ``webdav.propfind(url)``, ``webdav.ls(url)``, ...

Same idea as :mod:`requests.api`: each function opens a
:class:`~webdav.session.Session`, does one thing and closes it again.
For more than one call against the same server use a
:class:`~webdav.session.Session` instead - it keeps the connection open,
and its methods have the same names, arguments and return values as these functions
(a test compares the signatures).

Every function takes a full ``http(s)`` URL first.

- The **verbs** (``get``, ``put``, ``delete``, ``head``, ``options``,
  ``propfind``, ``proppatch``, ``mkcol``, ``copy``, ``move``, ``lock``,
  ``unlock``) return a :class:`webdav.response.Response`, take the
  keyword arguments :meth:`requests.Session.request` takes (``auth=``,
  ``headers=``, ``timeout=``, ``verify=``, ``cert=``, ``stream=``, ...)
  and, like ``requests``, do not raise for an error status.
- The **file-system operations** (``ls``, ``info``, ``exists``, ``isdir``,
  ``isfile``, ``mkdir``, ``remove``, ``open``, ``locked``,
  ``download_file``, ``upload_file``) return plain values, raise a
  :class:`~webdav.exceptions.WebDAVError` on failure and take the
  connection options (``auth=``, ``headers=``, ``verify=``, ``cert=``,
  ``timeout=``, ...) as keyword arguments.
- Both also take the session options ``redirect_policy=``,
  ``trusted_redirect_origins=``, ``max_response_size=``, ``retry=``,
  ``chunk_size=`` and ``raise_on_error=``.
"""

# The parameters mirror Session, so they shadow module-level names (open, set_props).
# pylint: disable=redefined-builtin,redefined-outer-name
import inspect
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
    TypedDict,
    TypeVar,
    Unpack,
    overload,
)

from webdav.locks import DEFAULT_LOCK_TIMEOUT, EXCLUSIVE, ActiveLock
from webdav.resource import Resource
from webdav.response import Response
from webdav.session import Session

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable
    from datetime import datetime
    from os import PathLike
    from xml.etree.ElementTree import Element

    from webdav.properties import DAVProperties, PropName
    from webdav.redirects import RedirectPolicy
    from webdav.tls import TLSOptions

_P = ParamSpec("_P")
_R = TypeVar("_R")
_T = TypeVar("_T")


class _BaseOptions(TypedDict, total=False):
    """Connection options every function takes, as :class:`~webdav.session.Session` does."""

    auth: Any
    cert: Any
    verify: "Literal[True] | str"
    tls: "TLSOptions | None"
    timeout: "float | tuple[float, float] | None"
    redirect_policy: "RedirectPolicy"
    trusted_redirect_origins: "Iterable[str] | Callable[[str], bool] | None"
    max_response_size: "int | None"
    retry: "Callable[..., Any] | bool"
    raise_on_error: bool
    max_response_time: "float | None"


class _Options(_BaseOptions, total=False):
    headers: "dict[str, str] | None"
    chunk_size: int


class _TransferOptions(_BaseOptions, total=False):
    """For functions with their own ``chunk_size`` parameter."""

    headers: "dict[str, str] | None"


class _UploadOptions(_BaseOptions, total=False):
    """For functions with their own ``chunk_size`` and ``headers`` parameters."""


#: Options that configure the session itself. ``auth``/``headers``/
#: ``timeout``/``verify``/``cert`` are deliberately *not* here for the
#: verbs: ``requests`` takes them per call, and a per-call header - unlike
#: a session one - is what a redirect to a trusted origin keeps.
_SESSION_OPTIONS = (
    "redirect_policy",
    "trusted_redirect_origins",
    "max_response_size",
    "retry",
    "chunk_size",
    "raise_on_error",
    "tls",
    "max_response_time",
)


def _new_session(session_options: "dict[str, Any]") -> Session:
    """A session from the (already split off) session options.

    ``max_response_time`` is an attribute of the session, not a constructor
    argument, so it is set after construction.
    """
    max_response_time = session_options.pop("max_response_time", None)
    session = Session(**session_options)
    if max_response_time is not None:
        session.max_response_time = max_response_time
    return session


def _run(
    method: "Callable[Concatenate[Session, _P], _R]",
    session_options: "Any",
    *args: _P.args,
    **kwargs: _P.kwargs,
) -> _R:
    with _new_session(dict(session_options)) as session:
        return method(session, *args, **kwargs)


def _walk(
    method: "Callable[Concatenate[Session, _P], Iterator[_T]]",
    session_options: "Any",
    *args: _P.args,
    **kwargs: _P.kwargs,
) -> "Iterator[_T]":
    session = _new_session(
        dict(session_options)
    )  # bad options fail now, not at the first item
    return _walk_with(session, method, *args, **kwargs)


def _walk_with(
    session: Session,
    method: "Callable[Concatenate[Session, _P], Iterator[_T]]",
    *args: _P.args,
    **kwargs: _P.kwargs,
) -> "Iterator[_T]":
    with session:
        yield from method(session, *args, **kwargs)


@contextmanager
def _context(
    name: str, session_options: "Any", *args: Any, **kwargs: Any
) -> "Iterator[Any]":
    with (
        _new_session(dict(session_options)) as session,
        getattr(session, name)(*args, **kwargs) as value,
    ):
        yield value


def _verb(
    method: "Callable[Concatenate[Session, _P], Response]",
) -> "Callable[_P, Response]":
    name = method.__name__

    def caller(*args: _P.args, **kwargs: _P.kwargs) -> Response:
        session_options = {k: kwargs.pop(k) for k in _SESSION_OPTIONS if k in kwargs}
        with _new_session(session_options) as session:
            response: Response = getattr(session, name)(*args, **kwargs)
            return response

    signature = inspect.signature(method)
    caller.__signature__ = signature.replace(  # type: ignore[attr-defined]
        parameters=list(signature.parameters.values())[1:]
    )
    caller.__name__ = name
    caller.__qualname__ = name
    what = "a request" if name == "request" else f"a ``{name.upper()}`` request"
    caller.__doc__ = (
        f"Send {what}; see :meth:`webdav.session.Session.{name}`.\n\n"
        "Returns a :class:`webdav.response.Response`."
    )
    return caller


request = _verb(Session.request)
get = _verb(Session.get)
head = _verb(Session.head)
options = _verb(Session.options)
put = _verb(Session.put)
delete = _verb(Session.delete)
propfind = _verb(Session.propfind)
proppatch = _verb(Session.proppatch)
mkcol = _verb(Session.mkcol)
copy = _verb(Session.copy)
move = _verb(Session.move)
lock = _verb(Session.lock)
unlock = _verb(Session.unlock)


# --- generated by tools/gen_api.py from Session; do not edit below this line ---


def ls(path: str, **kwargs: Unpack[_Options]) -> list[Resource]:
    """List the members of a collection.

    See :meth:`webdav.session.Session.ls`; ``path`` is a full URL.
    """
    return _run(Session.ls, kwargs, path)


def info(path: str, **kwargs: Unpack[_Options]) -> Resource:
    """Describe one resource (a file or a collection - not its members).

    See :meth:`webdav.session.Session.info`; ``path`` is a full URL.
    """
    return _run(Session.info, kwargs, path)


def exists(path: str, **kwargs: Unpack[_Options]) -> bool:
    """Check whether a resource exists.

    See :meth:`webdav.session.Session.exists`; ``path`` is a full URL.
    """
    return _run(Session.exists, kwargs, path)


def isdir(path: str, **kwargs: Unpack[_Options]) -> bool:
    """Check whether a resource is a collection (``False`` if it does not exist).

    See :meth:`webdav.session.Session.isdir`; ``path`` is a full URL.
    """
    return _run(Session.isdir, kwargs, path)


def isfile(path: str, **kwargs: Unpack[_Options]) -> bool:
    """Check whether a resource exists and is not a collection.

    See :meth:`webdav.session.Session.isfile`; ``path`` is a full URL.
    """
    return _run(Session.isfile, kwargs, path)


def mkdir(path: str, *, data: str | None = None, **kwargs: Unpack[_Options]) -> None:
    """Create a collection.

    See :meth:`webdav.session.Session.mkdir`; ``path`` is a full URL.
    """
    _run(Session.mkdir, kwargs, path, data=data)


def remove(path: str, **kwargs: Unpack[_Options]) -> None:
    """Remove a resource (or a collection, with everything in it).

    See :meth:`webdav.session.Session.remove`; ``path`` is a full URL.
    """
    _run(Session.remove, kwargs, path)


def get_props(
    path: str,
    *,
    names: "Iterable[str | PropName] | None" = None,
    all_prop: bool = False,
    include: "Iterable[str | PropName] | None" = None,
    **kwargs: Unpack[_Options],
) -> "DAVProperties":
    """Return properties of a resource via PROPFIND.

    See :meth:`webdav.session.Session.get_props`; ``path`` is a full URL.
    """
    return _run(
        Session.get_props, kwargs, path, names=names, all_prop=all_prop, include=include
    )


def set_props(
    path: str,
    *,
    set_props: "dict[str | PropName, Any] | None" = None,
    remove_props: "Iterable[str | PropName] | None" = None,
    **kwargs: Unpack[_Options],
) -> None:
    """Set and/or remove properties via PROPPATCH (RFC 4918 sec. 9.2).

    See :meth:`webdav.session.Session.set_props`; ``path`` is a full URL.
    """
    _run(
        Session.set_props, kwargs, path, set_props=set_props, remove_props=remove_props
    )


def refresh_lock(
    path: str,
    token: str,
    *,
    lock_timeout: "int | Iterable[int | None] | None" = DEFAULT_LOCK_TIMEOUT,
    **kwargs: Unpack[_Options],
) -> ActiveLock:
    """Refresh a held lock's timeout (RFC 4918 sec. 9.10.2).

    See :meth:`webdav.session.Session.refresh_lock`; ``path`` is a full URL.
    """
    return _run(Session.refresh_lock, kwargs, path, token, lock_timeout=lock_timeout)


def content_length(path: str, **kwargs: Unpack[_Options]) -> "int | None":
    """Return the ``getcontentlength`` property.

    See :meth:`webdav.session.Session.content_length`; ``path`` is a full URL.
    """
    return _run(Session.content_length, kwargs, path)


def created(path: str, **kwargs: Unpack[_Options]) -> "datetime | None":
    """Return the ``creationdate`` property.

    See :meth:`webdav.session.Session.created`; ``path`` is a full URL.
    """
    return _run(Session.created, kwargs, path)


def modified(path: str, **kwargs: Unpack[_Options]) -> "datetime | None":
    """Return the ``getlastmodified`` property.

    See :meth:`webdav.session.Session.modified`; ``path`` is a full URL.
    """
    return _run(Session.modified, kwargs, path)


def etag(path: str, **kwargs: Unpack[_Options]) -> "str | None":
    """Return the ``getetag`` property.

    See :meth:`webdav.session.Session.etag`; ``path`` is a full URL.
    """
    return _run(Session.etag, kwargs, path)


def content_type(path: str, **kwargs: Unpack[_Options]) -> "str | None":
    """Return the ``getcontenttype`` property.

    See :meth:`webdav.session.Session.content_type`; ``path`` is a full URL.
    """
    return _run(Session.content_type, kwargs, path)


def content_language(path: str, **kwargs: Unpack[_Options]) -> "str | None":
    """Return the ``getcontentlanguage`` property.

    See :meth:`webdav.session.Session.content_language`; ``path`` is a full URL.
    """
    return _run(Session.content_language, kwargs, path)


def dav_compliance(path: str = "", **kwargs: Unpack[_Options]) -> set[str]:
    """Return the ``DAV:`` compliance classes the server advertises.

    See :meth:`webdav.session.Session.dav_compliance`; ``path`` is a full URL.
    """
    return _run(Session.dav_compliance, kwargs, path)


def walk(
    path: str, *, max_depth: "int | None" = None, **kwargs: Unpack[_Options]
) -> "Iterator[tuple[str, list[Resource], list[Resource]]]":
    """Walk a collection tree top-down, like :func:`os.walk`.

    See :meth:`webdav.session.Session.walk`; ``path`` is a full URL.
    """
    return _walk(Session.walk, kwargs, path, max_depth=max_depth)


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

    See :meth:`webdav.session.Session.download_file`; ``path`` is a full URL.
    """
    _run(
        Session.download_file,
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

    See :meth:`webdav.session.Session.upload_file`; ``path`` is a full URL.
    """
    _run(
        Session.upload_file,
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

    See :meth:`webdav.session.Session.download_fileobj`; ``path`` is a full URL.
    """
    _run(
        Session.download_fileobj,
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

    See :meth:`webdav.session.Session.upload_fileobj`; ``path`` is a full URL.
    """
    _run(
        Session.upload_fileobj,
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

    See :meth:`webdav.session.Session.open`; ``path`` is a full URL.
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

    See :meth:`webdav.session.Session.locked`; ``path`` is a full URL.
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
