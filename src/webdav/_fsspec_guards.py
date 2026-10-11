"""What keeps the fsspec filesystem inside its server and its local trees.

The base class of :class:`~webdav.fsspec.WebdavFileSystem`: fsspec's own methods, with a check in
front of the ones that recurse: a ``walk`` has a bound. Kept apart from the
filesystem itself, which is long enough.
"""

from typing import Any

from fsspec.spec import AbstractFileSystem

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
    """``fsspec``'s base class, for one server: see :meth:`walk`."""

    filesystem: FileSystem
    walk_max_depth: "int | None"
    walk_max_dirs: "int | None"

    # pylint: disable=signature-differs
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
