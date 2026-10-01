"""fsspec-compliant filesystem over :class:`~webdav.fs.client.FileSystem`.

fsspec (https://filesystem-spec.readthedocs.io) is the de-facto standard
storage-backend interface in the Python data ecosystem - wrapping the
client this way is what lets other projects (pandas, dask, ...) read/write
a WebDAV server without knowing anything WebDAV-specific.

Importing this module registers ``"webdavs"`` with fsspec
(:func:`fsspec.register_implementation`) - deliberately not ``"webdav"``,
which fsspec's own registry already maps to ``webdav4`` by default; see the
module's own docstring note below for why that one is left alone.

Paths. A filesystem is bound to one server, through its ``base_url``, and its
paths are those of the server: they start at ``/``, the root of the ``base_url``
(``root_marker``), as they do for ``LocalFileSystem`` or ``MemoryFileSystem``.
fsspec leaves the normalising of a path to ``_strip_protocol``: here it removes
the ``webdavs://`` prefix and a trailing ``/`` and makes the path absolute, so
``a/b``, ``/a/b`` and ``webdavs:///a/b`` are one path and the root is ``/``. There
is no working directory. ``.``, ``..`` and ``//`` inside a path are resolved
by the session, which refuses to leave the ``base_url``. The names ``ls`` and
``info`` return are exactly what ``_strip_protocol`` returns for them, so
every name can be handed back to any method.
"""

import errno
import io
import posixpath
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    BinaryIO,
    Literal,
    NamedTuple,
    NoReturn,
    SupportsIndex,
    TextIO,
    cast,
    overload,
)

import fsspec
from fsspec import Callback
from fsspec.spec import AbstractBufferedFile, AbstractFileSystem

from webdav.dav.fs_utils import peek_filelike_length
from webdav.exceptions import (
    ForbiddenError,
    IsACollectionError,
    IsAResourceError,
    PreconditionFailedError,
    ResourceAlreadyExistsError,
    ResourceConflictError,
    ResourceNotFoundError,
)
from webdav.fs import FileSystem
from webdav.resource import Resource
from webdav.session import Session

if TYPE_CHECKING:
    from collections.abc import Callable
    from datetime import datetime
    from os import PathLike
    from typing import Self

    from typing_extensions import Buffer

    from webdav.session import AuthTypes


def _absolute(name: str) -> str:
    """``name`` (relative to the base URL, as :class:`~webdav.resource.Resource` names are) as an fsspec path.

    With its leading ``/``, and ``.``, ``..`` and ``//`` resolved, so that two spellings of
    one path are one string - what ``find``/``walk``/``glob`` build their names from. A ``..``
    that would leave the root stays in the path: the session refuses it, as it always did.
    """
    parts: list[str] = []
    for part in name.split("/"):
        if part in ("", "."):
            continue
        if part == ".." and parts and parts[-1] != "..":
            parts.pop()
        else:
            parts.append(part)
    return "/" + "/".join(parts)


def _tuple_from_json(value: Any) -> Any:
    """``value``, or the tuple a JSON array stands for."""
    return tuple(value) if isinstance(value, list) else value


def _is_root(path: str) -> bool:
    """Whether ``path`` names the root of the file system (``/``, ``//``, ``/a/..``, ...)."""
    return posixpath.normpath("/" + path.lstrip("/")) == "/"


def _info(resource: Resource) -> "dict[str, Any]":
    """A :class:`~webdav.resource.Resource` as fsspec's ``info`` dict (``name``, ``size``, ``type``, ...)."""
    fields = resource.as_dict()
    fields["name"] = _absolute(resource.name)
    fields["size"] = fields.pop("size")
    fields["type"] = "directory" if fields.pop("is_dir") else "file"
    return fields


@contextmanager
def _translate_exceptions() -> Iterator[None]:
    """Translate this library's exceptions into the stdlib ones fsspec expects."""
    try:
        yield
    except ResourceNotFoundError as exc:
        raise FileNotFoundError(
            errno.ENOENT, "No such file or directory", exc.path
        ) from exc
    except ResourceAlreadyExistsError as exc:
        raise FileExistsError(errno.EEXIST, "File exists", exc.path) from exc
    except (
        PreconditionFailedError
    ) as exc:  # e.g. Overwrite: F onto an existing destination
        raise FileExistsError(errno.EEXIST, "File exists", exc.path) from exc
    except IsACollectionError as exc:
        raise IsADirectoryError(errno.EISDIR, "Is a directory", exc.path) from exc
    except IsAResourceError as exc:
        raise NotADirectoryError(errno.ENOTDIR, "Not a directory", exc.path) from exc
    except (
        ForbiddenError
    ) as exc:  # also COPY/MOVE onto itself or into itself (RFC 4918)
        raise PermissionError(errno.EACCES, "Permission denied", exc.path) from exc


class WebdavFileSystem(AbstractFileSystem):
    """Provides access to a WebDAV server through the fsspec API."""

    # Deliberately not also "webdav": fsspec's own registry already maps that
    # to webdav4 by default, and this library would rather coexist than
    # fight over it - see register_implementation() below this class. "dav"/
    # "davs" (the other real-world spelling, used by GNOME/gvfs) and "webdav"
    # itself can be added later without touching anything else here.
    protocol = ("webdavs",)

    # Paths are WebDAV paths: they start at the root of the server (or of its
    # ``base_url``), ``/``. That is what fsspec's ``root_marker`` is for, and
    # it is not cosmetic: fsspec's bulk operations (``get``/``put``/``cp`` of a
    # directory into one that exists) work out where a source nests from the
    # ``/`` in the paths - which a filesystem with ``root_marker == ""`` leaves out
    # for a directory at its top level (fsspec/filesystem_spec#2215).
    root_marker = "/"

    # fsspec keeps one instance per set of constructor arguments, keyed on their
    # ``str`` - two credentials whose ``repr`` omits the secret (any careful auth
    # object) would be handed the same instance, and so the same session: user B
    # would act as user A. Every filesystem is its own.
    cachable = False

    def __init__(
        self,
        base_url: "str | None" = None,
        auth: "AuthTypes | list[str]" = None,
        session: Session | None = None,
        **session_opts: Any,
    ) -> None:
        """Instantiate with ``base_url``/``auth``, or an existing ``session``.

        A filesystem is bound to one server: every path is relative to the
        ``base_url`` (``/`` is its root).

        Args:
            base_url: Base URL of the WebDAV server.
            auth: Passed straight through to :class:`~webdav.session.Session`. A list
                of two is read as the ``(user, password)`` tuple it stands for, which is
                what ``from_json(fs.to_json())`` hands back (as for ``timeout`` and ``cert``).
            session: A pre-built session to use instead (e.g. for mocking,
                or to reuse a session's connection pool across filesystems);
                it needs a ``base_url``.
            session_opts: Extra keyword arguments forwarded to
                :class:`~webdav.session.Session`.

        Raises:
            ValueError: There is no ``base_url``, neither given nor on the ``session``.

        """
        if (session.base_url if session is not None else base_url) is None:
            msg = (
                "a WebdavFileSystem is bound to one server: pass base_url "
                "(or a session that has one) - its paths are relative to it"
            )
            raise ValueError(msg)
        super().__init__()
        # JSON has no tuple: fsspec's to_json()/from_json() hand ("user", "password"),
        # (connect, read) and (certfile, keyfile) back as lists, which the session rejects
        # (or, for auth, would try to call).
        credentials: AuthTypes = _tuple_from_json(auth)
        for name in ("timeout", "cert"):
            if name in session_opts:
                session_opts[name] = _tuple_from_json(session_opts[name])
        session_opts.setdefault("chunk_size", self.blocksize)
        self.filesystem = (
            FileSystem.from_session(session)
            if session is not None
            else FileSystem(base_url, auth=credentials, **session_opts)
        )

    @classmethod
    def _strip_protocol(cls, path: "str | list[str]") -> "str | list[str]":
        """Strip the ``webdavs://`` protocol prefix, and make the path absolute.

        Every path has its leading ``/`` (``root_marker``): ``/d`` and ``d`` are
        one path, and the root is ``/``. ``path`` is a list for some callers
        (``rm([...])``, ``cp`` with several sources) - the base implementation
        already recurses for that case, so the result is the same shape as the input.
        """
        stripped = super()._strip_protocol(path)
        if isinstance(stripped, list):
            return [_absolute(cast("str", p)) for p in stripped]
        return _absolute(cast("str", stripped))

    def _strip(self, path: str) -> str:
        """``_strip_protocol`` for the common single-path case - everywhere but ``rm``."""
        return cast("str", self._strip_protocol(path))

    # pylint's signature-differs check is confused by these @overload stubs
    # into comparing one of *them*, rather than the real implementation
    # below, against the base class - verified as a false positive by
    # reproducing it in isolation against a minimal @overload override of
    # an unrelated base class. The real, final signature here is identical
    # to `AbstractFileSystem.ls(self, path, detail=True, **kwargs)`.
    # pylint: disable=signature-differs
    @overload
    def ls(
        self, path: str, detail: Literal[True] = ..., **kwargs: Any
    ) -> "list[dict[str, Any]]": ...

    @overload
    def ls(self, path: str, detail: Literal[False], **kwargs: Any) -> "list[str]": ...

    def ls(
        self,
        path: str,
        detail: bool = True,
        **kwargs: Any,
    ) -> "list[str] | list[dict[str, Any]]":
        """List members of a collection. See ``fsspec.AbstractFileSystem.ls``."""
        path = self._strip(path).strip()
        with _translate_exceptions():
            try:
                resources = self.filesystem.ls(path)
            except IsAResourceError:
                # The listing of a file is that file, as for local files and S3 keys:
                # fsspec's walk() and find() depend on it.
                resources = [self.filesystem.info(path)]
        if not detail:
            return [_absolute(r.name) for r in resources]
        return [_info(r) for r in resources]

    # pylint: enable=signature-differs

    def info(self, path: str, **kwargs: Any) -> "dict[str, Any]":
        """Return metadata about a single path."""
        path = self._strip(path)
        with _translate_exceptions():
            resource = self.filesystem.info(path)
        return _info(resource)

    def rm_file(self, path: str) -> None:
        """Remove a file, or an *empty* directory.

        ``DELETE`` on a collection removes everything below it, so a
        directory that still has something in it is refused here (fsspec
        calls this for ``rm(path)`` without ``recursive=True``, and the
        local file system would refuse too). ``rm(path, recursive=True)`` is
        the deliberate way to delete a tree.
        """
        path = self._strip(path)
        if self.isdir(path):
            self.rmdir(path)
        else:
            self._delete(path)

    _rm = rm_file

    def _delete(self, path: str) -> None:
        path = self._strip(path)
        if _is_root(path):
            msg = "refusing to remove the root of the file system"
            raise ValueError(msg)
        with _translate_exceptions():
            self.filesystem.remove(path)

    def cp_file(self, path1: str, path2: str, **kwargs: Any) -> None:
        """Copy a single file/collection from ``path1`` to ``path2``.

        Unlike a local filesystem, WebDAV COPY refuses a destination whose
        parent collection does not exist yet (409 Conflict) - so, same as
        :meth:`upload_fileobj`, the parent is created first.
        """
        path1 = self._strip(path1)
        path2 = self._strip(path2)
        if self.isdir(path1):
            # A directory entry from a recursive expansion (super().copy()'s
            # own per-entry walk, not the whole-tree shortcut in copy()) -
            # makedirs() tolerates it already being there (e.g. created as a
            # side effect of an earlier sibling file's own parent creation
            # below), where a native COPY would refuse it as a conflict.
            self.makedirs(path2, exist_ok=True)
            return
        parent = self._parent(path2)
        if parent not in ("", self.root_marker):
            self.makedirs(parent, exist_ok=True)
        with _translate_exceptions():
            self.filesystem.copy(path1, path2, overwrite=False)

    def rmdir(self, path: str) -> None:
        """Remove a directory, if empty."""
        path = self._strip(path)
        if _is_root(path):
            msg = "refusing to remove the root of the file system"
            raise ValueError(msg)
        with _translate_exceptions():
            members = self.filesystem.ls(
                path
            )  # a file is not a directory: NotADirectoryError
        if members:
            raise OSError(errno.ENOTEMPTY, "Directory not empty", path)
        self._delete(path)

    def rm(
        self,
        path: "str | list[str]",
        recursive: bool = False,
        maxdepth: int | None = None,
    ) -> None:
        """Delete files and, optionally, directories recursively."""
        stripped = self._strip_protocol(path)
        if (
            recursive
            and not maxdepth
            and isinstance(stripped, str)
            and self.isdir(stripped)
        ):
            self._delete(stripped)
            return
        super().rm(stripped, recursive=recursive, maxdepth=maxdepth)

    def _whole_tree_shortcut(
        self,
        path1: "str | list[str]",
        path2: "str | list[str]",
        *,
        recursive: bool,
        maxdepth: "int | None",
    ) -> "tuple[str, str] | None":
        """The stripped ``(path1, path2)`` pair, if one native COPY/MOVE can do the whole job.

        Only when both are single paths, the call is recursive with no depth
        limit, ``path1`` is a directory, and ``path2`` does not exist yet - a
        native WebDAV COPY/MOVE replaces exactly at its destination, it does
        not merge into an existing one the way ``cp(dir, existing_dir)`` or a
        list of sources needs to (many requests, not one) - see
        :meth:`copy`/:meth:`mv`, which fall back to the generic
        ``super().copy()``/``super().mv()`` for those.
        """
        if not (
            isinstance(path1, str)
            and isinstance(path2, str)
            and recursive
            and maxdepth is None
        ):
            return None
        stripped1 = self._strip(path1)
        if not self.isdir(stripped1):
            return None
        stripped2 = self._strip(path2)
        if self.exists(stripped2):
            return None
        return stripped1, stripped2

    def _refuse_into_itself(
        self, path1: "str | list[str]", path2: "str | list[str]"
    ) -> None:
        """Refuse to copy or move a directory into itself, or anything below it.

        The server refuses the single COPY/MOVE of a tree into itself (RFC 4918: 403), but
        not the per-entry way ``super().copy()``/``mv()`` take when the destination
        exists: ``mv("d", "d/sub")`` copies ``d`` to ``d/sub/d``, then deletes ``d`` - and
        with it the copy. The root is the same case: every destination is below it.
        """
        if not isinstance(path2, str):
            return
        destination = self._strip(path2)
        for source in [path1] if isinstance(path1, str) else path1:
            stripped = self._strip(source)
            reaches = stripped in (self.root_marker, destination)
            reaches = reaches or destination.startswith(f"{stripped}/")
            if reaches and self.isdir(stripped):
                raise PermissionError(
                    errno.EACCES, "Permission denied", f"{stripped} -> {destination}"
                )

    def copy(
        self,
        path1: "str | list[str]",
        path2: "str | list[str]",
        recursive: bool = False,
        maxdepth: int | None = None,
        on_error: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Copy files and, optionally, directories recursively.

        ``path2`` is deliberately never stripped here before it reaches
        ``cp_file``/``super().copy()`` - each of those strips it themselves,
        and the base implementation's own directory-destination detection (a
        trailing ``/`` on ``path2``, e.g. ``cp(file, "dir/")``) depends on
        seeing it exactly as the caller wrote it.

        No special case for "not recursive, path1 is a directory": the base
        implementation already turns that into a no-op (a non-recursive copy
        never includes directory sources - see its own ``copy()``), which is
        also what fsspec's own test suite expects - not an empty directory
        created at the destination.
        """
        if recursive:  # a non-recursive copy never takes a directory along
            self._refuse_into_itself(path1, path2)
        shortcut = self._whole_tree_shortcut(
            path1, path2, recursive=recursive, maxdepth=maxdepth
        )
        if shortcut is not None:
            stripped1, stripped2 = shortcut
            # Not through cp_file(): its own isdir(path1) branch exists for
            # the *generic* per-entry walk below (a directory encountered
            # mid-traversal, already created as a side effect - a no-op is
            # right there), not for this shortcut, which must actually
            # transfer the directory's whole content in one COPY.
            parent = self._parent(stripped2)
            if parent not in ("", self.root_marker):
                self.makedirs(parent, exist_ok=True)
            with _translate_exceptions():
                self.filesystem.copy(stripped1, stripped2, overwrite=False)
            return

        super().copy(
            path1,
            path2,
            recursive=recursive,
            maxdepth=maxdepth,
            on_error=on_error,
            **kwargs,
        )

    def mv(
        self,
        path1: "str | list[str]",
        path2: "str | list[str]",
        recursive: bool = False,
        maxdepth: int | None = None,
        **kwargs: Any,
    ) -> None:
        """Move a file/directory from ``path1`` to ``path2``.

        Same reasoning as :meth:`copy` for why ``path2`` is not stripped
        before it reaches ``filesystem.move``/``super().mv()``, why there is
        no "not recursive, path1 is a directory" special case, and why a
        list ``path1``/``path2`` never takes the single-native-MOVE shortcut.

        A path onto itself is a no-op, as in fsspec - whatever its spelling: the base
        implementation compares the strings as given, so ``mv("d", "/d")`` would copy
        ``d`` into itself and then delete it.
        """
        if (
            isinstance(path1, str)
            and isinstance(path2, str)
            and self._strip(path1) == self._strip(path2)
        ):
            return
        if recursive:
            self._refuse_into_itself(path1, path2)
        shortcut = self._whole_tree_shortcut(
            path1, path2, recursive=recursive, maxdepth=maxdepth
        )
        if shortcut is not None:
            stripped1, stripped2 = shortcut
            with _translate_exceptions():
                self.filesystem.move(stripped1, stripped2, overwrite=False)
            return

        super().mv(path1, path2, recursive=recursive, maxdepth=maxdepth, **kwargs)

    def _mkdir(self, path: str, exist_ok: bool = False) -> None:
        """Create a collection, translating errors into their fsspec equivalent.

        Distinguishing "parent isn't a directory" from "path already
        exists" from "parent doesn't exist" costs an extra request or two
        on the error path, in exchange for the specific exception type
        fsspec callers generally expect.
        """
        # Outside the try: the two cases below are sorted out first, whatever else the
        # server answers (a 403, say) is translated like everywhere else.
        with _translate_exceptions():
            try:
                self.filesystem.mkdir(path)
            except ResourceAlreadyExistsError as exc:
                details = self.info(path)
                if details.get("type") == "directory" and exist_ok:
                    return
                raise FileExistsError(errno.EEXIST, "File exists", path) from exc
            except ResourceConflictError as exc:
                parent = self._parent(path)
                details = self.info(parent)
                if details.get("type") != "directory":
                    raise NotADirectoryError(
                        errno.ENOTDIR, "Not a directory", parent
                    ) from exc
                raise

    def mkdir(self, path: str, create_parents: bool = True, **kwargs: Any) -> None:
        """Create a collection."""
        path = self._strip(path)
        if create_parents:
            self.makedirs(path, exist_ok=True)
            return
        self._mkdir(path)

    def makedirs(self, path: str, exist_ok: bool = False) -> None:
        """Create a collection and any missing parents."""
        path = self._strip(path)
        parent = self._parent(path)
        if not ({"", self.root_marker} & {path, parent}) and not self.exists(parent):
            self.makedirs(parent, exist_ok=exist_ok)
        self._mkdir(path, exist_ok=exist_ok)

    def created(self, path: str) -> "datetime | None":
        """Return the ``creationdate`` property."""
        path = self._strip(path)
        with _translate_exceptions():
            return self.filesystem.created(path)

    def modified(self, path: str) -> "datetime | None":
        """Return the ``getlastmodified`` property."""
        path = self._strip(path)
        with _translate_exceptions():
            return self.filesystem.modified(path)

    def _open(
        self,
        path: str,
        mode: str = "rb",
        block_size: int | None = None,
        autocommit: bool = True,
        cache_options: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> "WebdavFile | UploadFile":
        """Return a file-like object for ``path``."""
        size = kwargs.pop("size", None)
        if "a" in mode:
            msg = "append mode is not supported"
            raise ValueError(msg)

        if set(mode) & {"w", "x"}:
            # The server is still what actually enforces "only if nothing is
            # there" (overwrite=False on the eventual PUT, in UploadFile.commit) -
            # that stays race-free. This check only exists because fsspec's
            # own contract for "x" mode is to fail from open() itself, before
            # a single byte is written, not from a later close()/commit();
            # between this check and the real PUT, "nothing is there" can
            # still change - the server's refusal is what a caller should
            # actually rely on, this is a fast, usually-right first answer.
            if "x" in mode and self.exists(path):
                raise FileExistsError(errno.EEXIST, "File exists", path)
            return UploadFile(
                self, path=path, mode=mode, block_size=block_size, exclusive="x" in mode
            )

        with _translate_exceptions():
            return WebdavFile(
                self,
                path,
                block_size=block_size,
                autocommit=autocommit,
                mode=mode,
                size=size,
                cache_options=cache_options,
                **kwargs,
            )

    def checksum(self, path: str) -> "str | None":
        """Return the ``getetag`` property."""
        path = self._strip(path)
        with _translate_exceptions():
            return self.filesystem.etag(path)

    def size(self, path: str) -> "int | None":
        """Return the ``getcontentlength`` property."""
        path = self._strip(path)
        with _translate_exceptions():
            return self.filesystem.content_length(path)

    def sign(self, path: str, expiration: int = 100, **kwargs: Any) -> NoReturn:
        """Not supported - WebDAV has no notion of a signed/pre-authorized URL."""
        raise NotImplementedError

    def pipe_file(
        self, path: str, value: bytes, mode: str = "overwrite", **kwargs: Any
    ) -> None:
        """Write ``value`` to ``path``.

        Args:
            path: Remote path.
            value: Content to write.
            mode: ``"overwrite"`` (default, replaces anything there),
                ``"create"`` (fails if ``path`` already exists), or
                ``"append"`` - WebDAV PUT always replaces a resource's whole
                content, so ``"append"`` isn't supported.
            kwargs: Forwarded to :meth:`upload_fileobj`.

        """
        if mode == "append":
            msg = "append mode is not supported (WebDAV PUT always replaces the whole resource)"
            raise NotImplementedError(msg)
        buff = io.BytesIO(value)
        kwargs.setdefault("overwrite", mode != "create")
        self.upload_fileobj(buff, path, **kwargs)

    def upload_fileobj(
        self,
        fobj: BinaryIO,
        rpath: str,
        callback: "Callback | None" = None,
        overwrite: bool = True,
        size: int | None = None,
        **kwargs: Any,
    ) -> None:
        """Upload from an open file object to ``rpath``."""
        rpath = self._strip(rpath)
        # `self._parent()` (not a raw PurePosixPath(rpath).parent, which
        # yields "." for a root-level path - not a valid WebDAV resource)
        # matches what `makedirs()` itself uses to recognize "no parent to
        # create" for a root-level upload.
        parent = self._parent(rpath)
        if parent not in ("", self.root_marker):
            self.makedirs(parent, exist_ok=True)

        if size is None:
            size = peek_filelike_length(fobj)

        cb = Callback.as_callback(callback)
        if size is not None:
            cb.set_size(size)

        with _translate_exceptions():
            self.filesystem.upload_fileobj(
                fobj,
                rpath,
                overwrite=overwrite,
                callback=cb.relative_update,
                size=size,
                **kwargs,
            )

    put_fileobj = upload_fileobj

    def put_file(
        self,
        lpath: "str | PathLike[str]",
        rpath: str,
        callback: "Callback | None" = None,
        mode: str = "overwrite",
        **kwargs: Any,
    ) -> None:
        """Copy a local file to the remote server.

        ``mode`` must be ``"overwrite"`` (the default) - see
        :meth:`pipe_file` for why ``"append"`` isn't supported.
        """
        if mode == "append":
            msg = "append mode is not supported (WebDAV PUT always replaces the whole resource)"
            raise NotImplementedError(msg)

        if Path(lpath).is_dir():
            rpath = self._strip(rpath)
            self.makedirs(rpath, exist_ok=True)
            return

        with Path(lpath).open(mode="rb") as fobj:
            kwargs.setdefault("overwrite", True)
            kwargs.setdefault("size", None)
            self.upload_fileobj(fobj, rpath, callback=callback, **kwargs)

    def get_file(  # pylint: disable=signature-differs
        self,
        rpath: str,
        lpath: "str | PathLike[str]",
        callback: "Callback | None" = None,
        outfile: "BinaryIO | None" = None,
        **kwargs: Any,
    ) -> None:
        """Copy a remote file to the local file system (or to ``outfile``).

        A local ``lpath`` is written the way :meth:`~webdav.fs.client.FileSystem.download_file`
        writes it: to a temporary file that replaces ``lpath`` only when the download
        is complete, and never through a symlink - a failed download leaves an
        existing ``lpath`` as it was. (Replacing an existing file *is* what
        ``get`` means in fsspec, so ``overwrite`` is on.)
        """
        rpath = self._strip(rpath)
        if hasattr(lpath, "write"):  # fsspec passes an open file as ``lpath`` too
            outfile = cast("BinaryIO", lpath)
        elif self.isdir(rpath):  # a collection becomes a local directory
            Path(lpath).mkdir(parents=True, exist_ok=True)
            return
        cb = Callback.as_callback(callback)
        with _translate_exceptions():
            size = self.filesystem.info(rpath).size
            if size is not None:
                cb.set_size(size)
            if outfile is not None:
                self.filesystem.download_fileobj(
                    rpath, outfile, callback=cb.relative_update
                )
            else:
                # Unlike a remote PUT/COPY destination, a local one is never
                # auto-vivified by anything downstream - fsspec's own
                # directory-destination resolution (get(file, "dir/")) expects
                # the parent to simply be there by the time get_file() runs it.
                Path(lpath).parent.mkdir(parents=True, exist_ok=True)
                self.filesystem.download_file(
                    rpath, lpath, overwrite=True, callback=cb.relative_update
                )


class WebdavFile(AbstractBufferedFile):
    """Read-only, file-like access to a remote resource."""

    size: int

    def __init__(
        self,
        fs: WebdavFileSystem,
        path: str,
        mode: str = "rb",
        block_size: "int | str | None" = None,
        autocommit: bool = True,
        cache_type: str = "readahead",
        cache_options: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> None:
        """Open ``path`` on ``fs`` for streaming reads. See ``fsspec`` for the rest."""
        size = kwargs.get("size")
        self.details = {"name": path, "size": size, "type": "file"}
        super().__init__(
            fs,
            path,
            mode=mode,
            block_size=block_size,
            autocommit=autocommit,
            cache_type=cache_type,
            cache_options=cache_options,
            **kwargs,
        )
        encoding = kwargs.get("encoding")
        self.fobj = fs.filesystem.open(
            self.path, mode=self.mode, encoding=encoding, chunk_size=self.blocksize
        )
        self.reader: TextIO | BinaryIO = self.fobj.__enter__()

        # Only ask for the size separately if the GET response didn't carry
        # a Content-Length (or the caller didn't already provide one).
        if not self.size:
            reader_size = getattr(self.reader, "size", None)
            self.size = reader_size or self.fs.size(self.path)

        self.closed: bool = False

    def read(self, length: int = -1) -> "str | bytes | None":
        """Read up to ``length`` bytes/characters.

        Nothing is left at or beyond the end: that reads as empty, as for any file, and
        costs no request - a range that starts there is one the server has to refuse (416).
        """
        if self.closed:
            msg = "I/O operation on closed file."
            raise ValueError(msg)
        if self.size is not None and self.loc >= self.size:
            return b""
        chunk = self.reader.read(length)
        if chunk:
            self.loc += len(chunk)
        return chunk

    def __enter__(self) -> "Self":
        """Return self; the stream is already open by ``__init__``."""
        return self

    def seek(self, loc: int, whence: int = 0) -> int:
        """Seek within the stream."""
        super().seek(loc, whence=whence)
        return self.reader.seek(loc, whence)

    def isatty(self) -> bool:
        """Never a TTY."""
        return False

    def close(self) -> None:
        """Close the underlying stream."""
        if self.closed:
            return
        if hasattr(self, "reader"):
            # fs.filesystem.open() may have raised before self.reader was set.
            self.reader.close()
        self.closed = True

    def __reduce_ex__(
        self, protocol: SupportsIndex
    ) -> "tuple[Callable[[ReopenArgs], WebdavFile], tuple[ReopenArgs]]":
        """Support (re)pickling: the file is opened again, at the same position, on restore."""
        return _reopen, (
            ReopenArgs(
                WebdavFile,
                self.fs,
                self.path,
                self.blocksize,
                self.mode,
                self.size,
                self.loc,
            ),
        )


class ReopenArgs(NamedTuple):
    """Arguments to reopen a :class:`WebdavFile`, for ``__reduce_ex__``."""

    file: type[WebdavFile]
    fs: WebdavFileSystem
    path: str
    blocksize: int | None
    mode: str
    size: int | None
    loc: int


def _reopen(args: ReopenArgs) -> WebdavFile:
    """Reopen a file when unpickled, where it was left."""
    file = args.file(
        args.fs,
        args.path,
        block_size=args.blocksize,
        mode=args.mode,
        size=args.size,
    )
    if args.loc:
        file.seek(args.loc)
    return file


class UploadFile(tempfile.SpooledTemporaryFile):
    """Write-mode file-like object for WebDAV.

    WebDAV has no standard chunked-upload protocol (Nextcloud/ownCloud
    each have their own, mutually incompatible extensions) - so a write-
    mode file buffers locally and uploads the whole thing as one PUT on
    ``close()``. ``AbstractFileSystem.pipe_file``/``put_file`` bypass this
    entirely and should be preferred when the full content is already in
    hand, since they avoid the extra buffering.
    """

    def __init__(
        self,
        fs: WebdavFileSystem,
        path: str,
        mode: str = "wb",
        block_size: "int | str | None" = None,
        *,
        exclusive: bool = False,
    ) -> None:
        """Set up local buffering for a deferred upload to ``path`` on ``fs``."""
        self.exclusive = exclusive
        self.blocksize: int = (
            block_size
            if isinstance(block_size, int)
            else AbstractBufferedFile.DEFAULT_BLOCK_SIZE
        )
        self.fs: WebdavFileSystem = fs
        self.path: str = path
        # Whatever mode was requested, buffer in read-write binary mode -
        # commit() needs to read it back to upload it.
        super().__init__(max_size=self.blocksize, mode="wb+")

    def __exit__(
        self,
        exc_type: object,
        exc_value: object,
        traceback: object,
    ) -> None:
        """Commit (upload) the buffered content - unless the block raised: then nothing is sent.

        A write that failed half way must not replace what is on the server with
        the half that was written.
        """
        if exc_type is not None:
            self.discard()
        else:
            self.close()

    def readable(self) -> bool:
        """Readable, so ``commit()`` can read the buffered content back."""
        return True

    def writable(self) -> bool:
        """Writable."""
        return True

    def seekable(self) -> bool:
        """Seekable."""
        return True

    def commit(self) -> None:
        """Upload the buffered content - this is where the real PUT happens.

        Through :meth:`WebdavFileSystem.upload_fileobj`, not
        ``self.fs.filesystem.upload_fileobj`` directly, so a missing parent
        collection is created first, same as :meth:`~WebdavFileSystem.put_file`/
        :meth:`~WebdavFileSystem.pipe_file` already do - WebDAV PUT, like
        COPY, refuses a destination whose parent does not exist yet.
        """
        self.seek(0)
        with _translate_exceptions():
            self.fs.upload_fileobj(
                cast("BinaryIO", self),
                self.path,
                chunk_size=self.blocksize,
                overwrite=not self.exclusive,
            )

    def close(self) -> None:
        """Commit and close - closed all the same when the upload fails, as ``io`` closes."""
        if not self.closed:
            try:
                self.commit()
            finally:
                super().close()

    def discard(self) -> None:
        """Close without uploading."""
        if not self.closed:
            super().close()

    def info(self) -> NoReturn:
        """Not available while a write is still in progress."""
        msg = "cannot provide info in write-mode"
        raise ValueError(msg)

    def readinto(self, b: "Buffer") -> int:
        """Read bytes into a pre-allocated buffer."""
        out = memoryview(b).cast("B")
        data = self.read(out.nbytes)
        out[: len(data)] = data
        return len(data)

    def readuntil(self, char: bytes = b"\n", blocks: int | None = None) -> bytes:
        """Read until ``char`` is found."""
        return cast(
            "bytes", AbstractBufferedFile.readuntil(self, char=char, blocks=blocks)
        )


# "webdavs" has no existing claim anywhere in fsspec's registry (unlike
# "webdav", which fsspec's own known_implementations already maps to
# webdav4) - this fills an empty slot in fsspec's live registry rather than
# overriding anyone's. No clobber=True: if something else has already
# claimed "webdavs" by the time this module is imported, that is a real
# conflict worth a loud error, not something to silently win.
fsspec.register_implementation("webdavs", WebdavFileSystem)
