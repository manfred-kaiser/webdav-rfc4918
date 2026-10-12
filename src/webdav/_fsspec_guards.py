"""What keeps the fsspec filesystem inside its server and its local trees.

The base class of :class:`~webdav.fsspec.WebdavFileSystem`: fsspec's own methods, with a check in
front of each - a URL names this filesystem's server (and no other), a
recursive ``get``/``put`` stays inside the local tree it was given. Kept apart from the
filesystem itself, which is long enough.
"""

import contextvars
import errno
import os
import types
from pathlib import Path, PurePath
from typing import Any, cast

from fsspec.callbacks import DEFAULT_CALLBACK
from fsspec.spec import AbstractFileSystem
from fsspec.utils import stringify_path

from webdav._webdavs_url import authority_of, check_host, host_and_port
from webdav.exceptions import ClientError
from webdav.fs import FileSystem
from webdav.resource import safe_local_name


def _on_windows() -> bool:
    """Whether local file names follow the Windows rules (a function, so a test can say so)."""
    return os.name == "nt"


class GetTree:
    """The destination tree of one ``get``: what it may write to."""

    def __init__(self, given: str, *, contained: bool) -> None:
        """The tree is ``given`` (a directory, or a symlink to one); ``contained``: stay inside it."""
        self.given = os.path.abspath(given)  # noqa: PTH100 - normalised, symlinks kept
        # The root may itself be a symlink (``~/data -> /mnt/storage``): what is compared is
        # where it leads. A symlink *below* it that leads out of it is what is refused.
        self.root = os.path.realpath(given)
        self.contained = contained
        self.written: dict[tuple[int, int], str] = {}

    def check(self, local: str) -> None:
        """Refuse ``local`` if a symlink leads it out of the destination, or the name cannot be a file here.

        On Windows a name that is not a Windows file name (``CON``, ``a:b``, a trailing dot,
        a backslash) is refused. On every platform a name that is the file of one written
        before (two names that differ only in case or Unicode form, on a file system that
        folds them) is refused, instead of one silently replacing the other. A name with a
        control character (a newline) is refused on every platform.

        Raises:
            OSError: ``local`` leads out of the destination through a symlink, is not a
                file name here, or is the file another name of this tree was written to.

        """
        self.check_names(local, windows=_on_windows())
        self.check_collision(local)
        if not self.contained:
            return
        real = os.path.realpath(local)
        if os.path.commonpath([self.root, real]) != self.root:
            msg = (
                "refusing to write outside the destination: a symlink inside it leads out "
                "of it (pass follow_symlinks=True to get() to allow it)"
            )
            raise OSError(errno.ELOOP, msg, local)

    # ``check`` calls these two. The collision check works on file identity, so it is the
    # same on every platform; the Windows names are enforced only where ``_on_windows()``.
    # Neither has run on real Windows/macOS yet (issue #5, Windows/macOS CI): they are pure
    # and unit-tested on Linux, with ``_on_windows`` and hard links standing in.
    def check_windows_names(self, local: str) -> None:
        """Refuse a ``local`` under the tree with a part that is not a file name on Windows.

        Raises:
            OSError: A part of the path below the tree is not usable on Windows.

        """
        self.check_names(local, windows=True)

    def check_names(self, local: str, *, windows: bool) -> None:
        """Refuse a ``local`` under the tree with a part that is not a usable file name.

        Control characters (a newline in a name) are refused everywhere, the Windows rules
        with ``windows``.

        Raises:
            OSError: A part of the path below the tree is not usable.

        """
        try:
            absolute_local = os.path.abspath(local)  # noqa: PTH100
            parts = PurePath(absolute_local).relative_to(self.given).parts
        except ValueError:
            return
        for part in parts:
            try:
                safe_local_name(part, windows=windows)
            except ValueError as exc:
                raise OSError(errno.EINVAL, str(exc), local) from exc

    def check_collision(self, local: str) -> None:
        """Refuse ``local`` if it is the file another name of this tree was :meth:`record`-ed for.

        That is what two names differing only in case or Unicode form are on a file system
        that folds them.

        Raises:
            OSError: ``local`` is the same file as a different name that was recorded.

        """
        known = self.written.get(_file_id(local))
        if known is not None and known != local:
            msg = (
                f"{local!r} is the same file as {known!r} on this file system (names that "
                "differ only in case or in Unicode form): the server has both"
            )
            raise OSError(errno.EEXIST, msg, local)

    def record(self, local: str) -> None:
        """Remember that ``local`` was written (for :meth:`check_collision`)."""
        if (file_id := _file_id(local)) != (0, 0):
            self.written[file_id] = local


def _file_id(path: str) -> "tuple[int, int]":
    """The identity of the file at ``path`` (``(0, 0)``: nothing there)."""
    try:
        status = Path(path).stat()
    except OSError:
        return (0, 0)
    return status.st_dev, status.st_ino


#: What the ``get`` / ``put`` in progress may write to / read from - ``None``: no tree
#: (a list of paths names every file itself). A context variable: ``get_file``/``put_file``
#: are called by fsspec's own ``get``/``put``, which know nothing of it.
GET_TREE: "contextvars.ContextVar[GetTree | None]" = contextvars.ContextVar(
    "webdav_get_tree", default=None
)
PUT_ROOT: "contextvars.ContextVar[str | None]" = contextvars.ContextVar(
    "webdav_put_root", default=None
)


class server_aware:  # noqa: N801  # pylint: disable=invalid-name  # used like ``classmethod``
    """A class method that, called on an instance, first checks the path names that instance's server.

    ``_strip_protocol`` is a class method in fsspec, and fsspec calls it as
    ``self._strip_protocol(path)`` in every method that takes a path (``open``, ``cat``,
    ``find``, ``glob``, ``expand_path``, ``pipe``, ``get_mapper``, ...) and as
    ``cls._strip_protocol(path)`` where there is no instance. Used on ``_strip_protocol``,
    this keeps both: the class-level call is a plain class method call, the instance-level
    one refuses a URL for another server (see :meth:`GuardedFileSystem._own_server`) before
    stripping it. One place, so a method fsspec adds later is covered without being listed.
    """

    def __init__(self, function: Any) -> None:
        """Remember the function (it takes the class first, like a class method's)."""
        self._function = function

    def __get__(self, instance: Any, owner: Any = None) -> Any:
        """A class method on the class; a checked one on an instance."""
        function = self._function
        if instance is None:
            return types.MethodType(function, owner)
        cls = type(instance)
        check = instance._own_server  # noqa: SLF001  # pylint: disable=protected-access

        def strip(path: Any) -> Any:
            check(path)
            return function(cls, path)

        return strip


# The rest of the abstract methods is the subclass's.
# pylint: disable-next=abstract-method
class GuardedFileSystem(AbstractFileSystem):
    """``fsspec``'s base class, for one server: see :meth:`_own_server`, :meth:`walk`, :meth:`get`, :meth:`put`."""

    filesystem: FileSystem

    def _own_server(self, path: Any) -> None:
        """Refuse a ``webdav(s)://host[:port]/...`` URL (in ``path``, or a list) for another server.

        ``_strip_protocol`` is a class method - it cannot know which server it is asked
        about, and drops the host. Every method of fsspec that takes a path calls it on the
        instance, so :class:`server_aware` makes that call come here first; ``walk``, ``get``
        and ``put`` also check at their start, before they do anything else.

        Raises:
            ValueError: The URL names another server - a filesystem is bound to one.

        """
        if isinstance(path, dict):
            path = list(path)
        for one in path if isinstance(path, list | tuple) else (path,):
            if isinstance(one, str | os.PathLike):
                authority, _ = authority_of(stringify_path(one))
                if authority:
                    host, port = host_and_port(authority)
                    check_host(
                        cast("str", self.filesystem.session.base_url), host, port
                    )

    # fsspec's ``exists`` and ``isfile`` swallow every exception from ``info`` and answer
    # "no": for another server that is wrong, so they check first.
    # pylint: disable=signature-differs
    def exists(self, path: Any, **kwargs: Any) -> bool:
        """``fsspec``'s ``exists`` - for the URL of this server only (not "no" for another)."""
        self._own_server(path)
        return cast("bool", super().exists(path, **kwargs))

    def isfile(self, path: Any) -> bool:
        """``fsspec``'s ``isfile`` - for the URL of this server only (not "no" for another)."""
        self._own_server(path)
        return cast("bool", super().isfile(path))

    def walk(
        self,
        path: Any,
        maxdepth: "int | None" = None,
        topdown: bool = True,
        on_error: Any = "omit",
        **kwargs: Any,
    ) -> Any:
        """``fsspec``'s ``walk``, for URLs of this server only; a tree too deep is a ``ClientError``.

        ``find``, ``du``, ``glob("**")``, ``expand_path`` and ``get(recursive=True)`` all walk.
        fsspec's own ``walk`` recurses until Python's ``RecursionError``, which is not one of
        this library's errors.
        """
        self._own_server(path)
        try:
            yield from super().walk(
                path, maxdepth=maxdepth, topdown=topdown, on_error=on_error, **kwargs
            )
        except RecursionError as exc:
            msg = f"walk gave up at {path!r}: the tree is too deep"
            raise ClientError(msg) from exc

    def get(
        self,
        rpath: Any,
        lpath: Any,
        recursive: bool = False,
        callback: Any = DEFAULT_CALLBACK,
        maxdepth: "int | None" = None,
        *,
        follow_symlinks: bool = False,
        **kwargs: Any,
    ) -> Any:
        """``fsspec``'s ``get`` - which does not write through a symlink out of the destination.

        With a destination directory (``lpath``) a symlink *below* it that leads out of it is
        refused with an ``OSError`` - a remote tree, or a name in it, does not get to choose
        where on your disk it lands. The destination itself may be a symlink
        (``~/data -> /mnt/storage``), and so may anything that leads to somewhere inside it;
        ``follow_symlinks=True`` allows symlinks that lead anywhere, as before. A list of
        destinations names every file itself and is not checked. (A file at ``lpath`` that
        is a symlink is refused either way, see ``get_file``.)

        This is a check of the resolved path just before the file is written: a local user
        who can swap a directory for a symlink in that moment is not stopped. Keep the
        destination to yourself. (Windows has no ``dir_fd`` to write without a race.)

        The names are the server's. On Windows ``get`` refuses a name that is not a plain file
        there (``CON``, ``a:b``, a trailing dot or space, a backslash) with an ``OSError``; on
        every platform it refuses a name that is the file of one it wrote before (two names that
        differ only in case or Unicode form, on a file system that folds them) instead of
        replacing it. Both are tested on Linux only (issue #5, Windows/macOS CI). For your own
        code, :func:`~webdav.resource.safe_local_name` (``windows=True``) is the check.
        """
        self._own_server(rpath)
        tree = None
        if isinstance(lpath, str | os.PathLike):
            tree = GetTree(os.fspath(lpath), contained=not follow_symlinks)
        token = GET_TREE.set(tree)
        try:
            return super().get(rpath, lpath, recursive, callback, maxdepth, **kwargs)
        finally:
            GET_TREE.reset(token)

    def put(
        self,
        lpath: Any,
        rpath: Any,
        recursive: bool = False,
        callback: Any = DEFAULT_CALLBACK,
        maxdepth: "int | None" = None,
        *,
        follow_symlinks: bool = False,
        **kwargs: Any,
    ) -> Any:
        """``fsspec``'s ``put`` - which does not follow a symlink out of the tree it uploads.

        ``lpath`` is a directory (``recursive``) or a pattern: a symlink *in* it that leads
        out of it is refused with an ``OSError`` rather than uploaded - a file you did not
        mean to send. The root it must stay in is the directory before the first ``*``, ``?``
        or ``[`` of ``lpath`` (and may itself be a symlink); symlinks that lead to somewhere
        inside it are fine, a file named by ``lpath`` itself is yours to choose, and so is
        every path of a list. ``follow_symlinks=True`` uploads whatever a symlink leads to,
        as before.

        This is a check of the resolved path just before the file is opened: a local user
        who can replace a file by a symlink in that moment is not stopped, and neither is one
        who can change what a symlink leads to between the check and the read. Keep the tree
        you upload to yourself. (Windows has no ``dir_fd`` to open it without a race.) And
        ``*``, ``?`` and ``[`` in ``lpath`` are patterns, as fsspec reads them: never pass
        a local path or pattern that someone else chose.
        """
        self._own_server(rpath)
        root = None
        if not follow_symlinks and isinstance(lpath, str | os.PathLike):
            text = os.fspath(lpath)
            magic = min(
                (i for i in (text.find(c) for c in "*?[") if i >= 0), default=-1
            )
            # The directory before the first pattern character: ``dirname`` keeps the one
            # in ``src/*.txt`` (``Path("src/").parent`` would be above it).
            head = os.path.dirname(text[:magic]) or "."  # noqa: PTH120
            root = os.path.realpath(text if magic < 0 else head)
        token = PUT_ROOT.set(root)
        try:
            return super().put(lpath, rpath, recursive, callback, maxdepth, **kwargs)
        finally:
            PUT_ROOT.reset(token)

    # pylint: enable=signature-differs
