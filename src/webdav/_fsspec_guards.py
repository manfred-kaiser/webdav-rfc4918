"""What keeps the fsspec filesystem inside its server and its local trees.

The base class of :class:`~webdav.fsspec.WebdavFileSystem`: fsspec's own methods, with a check in
front of each - a URL names this filesystem's server (and no other), a ``walk`` has a
bound. Kept apart from the filesystem itself, which is long enough.
"""

import os
from typing import Any, cast

from fsspec.spec import AbstractFileSystem
from fsspec.utils import stringify_path

from webdav._webdavs_url import authority_of, check_host, host_and_port
from webdav.exceptions import ClientError
from webdav.fs import FileSystem


class WalkBudget:
    """How deep, and over how many collections, one ``walk`` has gone - shared by its recursive calls."""

    def __init__(self, max_depth: "int | None", max_dirs: "int | None") -> None:
        """Start at nothing, with these limits (``None``: no limit)."""
        self.max_depth = max_depth
        self.max_dirs = max_dirs
        self.depth = 0
        self.dirs = 0

    def enter(self, path: str) -> None:
        """Count one more collection, one level deeper - refuse it if that is too much."""
        self.depth += 1
        self.dirs += 1
        if self.max_depth is not None and self.depth > self.max_depth:
            reason = f"more than {self.max_depth} levels deep (walk_max_depth)"
        elif self.max_dirs is not None and self.dirs > self.max_dirs:
            reason = f"more than {self.max_dirs} collections (walk_max_dirs)"
        else:
            return
        msg = (
            f"walk gave up at {path!r}: {reason} - a server that invents directories as you "
            "go never ends. Raise the limit in the WebdavFileSystem(...) arguments if the tree "
            "is really that big, or None to remove it."
        )
        raise ClientError(msg)

    def leave(self) -> None:
        """Back up one level."""
        self.depth -= 1


# The rest of the abstract methods is the subclass's.
# pylint: disable-next=abstract-method
class GuardedFileSystem(AbstractFileSystem):
    """``fsspec``'s base class, for one server: see :meth:`_own_server`, :meth:`walk`."""

    filesystem: FileSystem
    walk_max_depth: "int | None"
    walk_max_dirs: "int | None"

    def _own_server(self, path: Any) -> None:
        """Refuse a ``webdav(s)://host[:port]/...`` URL (in ``path``, or a list) for another server.

        ``_strip_protocol`` is a class method - it cannot know which server it is asked
        about, and drops the host. So this is called where a path *enters* an instance:
        by ``_strip``, and by the methods of fsspec's base class that strip a path
        themselves (``open``, ``cat``, ``find``, ``glob``, ``expand_path``, ``walk``, ``get``,
        ``put``, ``pipe``, ``rm``, ``copy``, ``mv``, ``get_mapper``, ...), overridden below.

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

    # fsspec's methods that take a path and strip it themselves, not through ``_strip``:
    # each passes it through ``_own_server`` first, and does nothing else.
    # pylint: disable=signature-differs
    def open(self, path: Any, *args: Any, **kwargs: Any) -> Any:
        """``fsspec``'s ``open`` - for the URL of this server only."""
        self._own_server(path)
        return super().open(path, *args, **kwargs)

    def cat(self, path: Any, *args: Any, **kwargs: Any) -> Any:
        """``fsspec``'s ``cat`` - for URLs of this server only."""
        self._own_server(path)
        return super().cat(path, *args, **kwargs)

    def exists(self, path: Any, **kwargs: Any) -> bool:
        """``fsspec``'s ``exists`` - for the URL of this server only (not "no" for another)."""
        self._own_server(path)
        return cast("bool", super().exists(path, **kwargs))

    def isfile(self, path: Any) -> bool:
        """``fsspec``'s ``isfile`` - for the URL of this server only (not "no" for another)."""
        self._own_server(path)
        return cast("bool", super().isfile(path))

    def find(self, path: Any, *args: Any, **kwargs: Any) -> Any:
        """``fsspec``'s ``find`` - for the URL of this server only."""
        self._own_server(path)
        return super().find(path, *args, **kwargs)

    def glob(self, path: Any, *args: Any, **kwargs: Any) -> Any:
        """``fsspec``'s ``glob`` - for the URL of this server only."""
        self._own_server(path)
        return super().glob(path, *args, **kwargs)

    def expand_path(self, path: Any, *args: Any, **kwargs: Any) -> Any:
        """``fsspec``'s ``expand_path`` - for URLs of this server only."""
        self._own_server(path)
        return super().expand_path(path, *args, **kwargs)

    def pipe(self, path: Any, *args: Any, **kwargs: Any) -> Any:
        """``fsspec``'s ``pipe`` - for URLs of this server only."""
        self._own_server(path)
        return super().pipe(path, *args, **kwargs)

    def get_mapper(
        self,
        root: str = "",
        check: bool = False,
        create: bool = False,
        missing_exceptions: Any = None,
    ) -> Any:
        """``fsspec``'s ``get_mapper`` - for the URL of this server only."""
        self._own_server(root)
        return super().get_mapper(root, check, create, missing_exceptions)

    def walk(
        self,
        path: Any,
        maxdepth: "int | None" = None,
        topdown: bool = True,
        on_error: Any = "omit",
        **kwargs: Any,
    ) -> Any:
        """``fsspec``'s ``walk`` - but a tree that never ends is refused, with a ``ClientError``.

        ``find``, ``du``, ``glob("**")``, ``expand_path`` and ``get(recursive=True)`` all walk.
        fsspec's own ``walk`` recurses without a limit, until Python's ``RecursionError``
        (which is not one of this library's errors); here the depth and the number of
        collections are bounded - ``walk_max_depth`` and ``walk_max_dirs`` of the
        constructor - and a ``RecursionError`` is a ``ClientError`` too. The budget travels
        with the recursive calls as a keyword argument fsspec hands on to them (and to
        ``ls``, which ignores it).
        """
        budget = kwargs.pop("_webdav_walk", None)
        if budget is None:
            self._own_server(path)
            budget = WalkBudget(self.walk_max_depth, self.walk_max_dirs)
        budget.enter(path)
        try:
            try:
                yield from super().walk(
                    path,
                    maxdepth=maxdepth,
                    topdown=topdown,
                    on_error=on_error,
                    _webdav_walk=budget,
                    **kwargs,
                )
            except RecursionError as exc:
                msg = f"walk gave up at {path!r}: the tree is too deep"
                raise ClientError(msg) from exc
        finally:
            budget.leave()

    # pylint: enable=signature-differs
