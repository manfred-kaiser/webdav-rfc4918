"""fsspec-compliant filesystem over the WebDAV :class:`~webdav.session.Session`.

fsspec (https://filesystem-spec.readthedocs.io) is the de-facto standard
storage-backend interface in the Python data ecosystem - wrapping the
client this way is what lets other projects (pandas, dask, ...) read/write
a WebDAV server without knowing anything WebDAV-specific.
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

from fsspec import Callback
from fsspec.spec import AbstractBufferedFile, AbstractFileSystem

from webdav.exceptions import (
    IsACollectionError,
    IsAResourceError,
    PreconditionFailedError,
    ResourceAlreadyExistsError,
    ResourceConflictError,
    ResourceNotFoundError,
)
from webdav.fs_utils import peek_filelike_length
from webdav.resource import Resource
from webdav.session import Session

if TYPE_CHECKING:
    from collections.abc import Callable
    from datetime import datetime
    from os import PathLike
    from typing import Self

    from typing_extensions import Buffer

    from webdav.session import AuthTypes


def _info(resource: Resource) -> "dict[str, Any]":
    """A :class:`~webdav.resource.Resource` as fsspec's ``info`` dict (``name``, ``size``, ``type``, ...)."""
    fields = resource.as_dict()
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


class WebdavFileSystem(AbstractFileSystem):
    """Provides access to a WebDAV server through the fsspec API."""

    protocol = ("webdav", "dav")

    # fsspec keeps one instance per set of constructor arguments, keyed on their
    # ``str`` - two credentials whose ``repr`` omits the secret (any careful auth
    # object) would be handed the same instance, and so the same session: user B
    # would act as user A. Every filesystem is its own.
    cachable = False

    def __init__(
        self,
        base_url: str,
        auth: "AuthTypes" = None,
        session: Session | None = None,
        **session_opts: Any,
    ) -> None:
        """Instantiate with ``base_url``/``auth``, or an existing ``session``.

        Args:
            base_url: Base URL of the WebDAV server.
            auth: Passed straight through to :class:`~webdav.session.Session`.
            session: A pre-built session to use instead (e.g. for mocking,
                or to reuse a session's connection pool across filesystems).
            session_opts: Extra keyword arguments forwarded to
                :class:`~webdav.session.Session`.

        """
        super().__init__()
        session_opts.setdefault("chunk_size", self.blocksize)
        self.session = session or Session(base_url, auth=auth, **session_opts)

    @classmethod
    def _strip_protocol(cls, path: str) -> str:
        """Strip the ``webdav://``/``dav://`` protocol prefix - and a leading ``/``.

        Names ``ls`` returns have no leading slash; ``/d`` and ``d`` are one path.
        """
        return cast("str", super()._strip_protocol(path)).lstrip("/")

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
        path = self._strip_protocol(path).strip()
        with _translate_exceptions():
            resources = self.session.ls(path)
        return (
            [str(r) for r in resources] if not detail else [_info(r) for r in resources]
        )

    # pylint: enable=signature-differs

    def info(self, path: str, **kwargs: Any) -> "dict[str, Any]":
        """Return metadata about a single path."""
        path = self._strip_protocol(path)
        with _translate_exceptions():
            resource = self.session.info(path)
        return _info(resource)

    def rm_file(self, path: str) -> None:
        """Remove a file, or an *empty* directory.

        ``DELETE`` on a collection removes everything below it, so a
        directory that still has something in it is refused here (fsspec
        calls this for ``rm(path)`` without ``recursive=True``, and the
        local file system would refuse too). ``rm(path, recursive=True)`` is
        the deliberate way to delete a tree.
        """
        path = self._strip_protocol(path)
        if self.isdir(path):
            self.rmdir(path)
        else:
            self._delete(path)

    _rm = rm_file

    def _delete(self, path: str) -> None:
        path = self._strip_protocol(path)
        if posixpath.normpath("/" + path) == "/":
            msg = "refusing to remove the root of the file system"
            raise ValueError(msg)
        with _translate_exceptions():
            self.session.remove(path)

    def cp_file(self, path1: str, path2: str, **kwargs: Any) -> None:
        """Copy a single file/collection from ``path1`` to ``path2``."""
        path1 = self._strip_protocol(path1)
        path2 = self._strip_protocol(path2)
        with _translate_exceptions():
            self.session.copy(path1, path2, overwrite=False).raise_for_status()

    def rmdir(self, path: str) -> None:
        """Remove a directory, if empty."""
        path = self._strip_protocol(path)
        if posixpath.normpath("/" + path) == "/":
            msg = "refusing to remove the root of the file system"
            raise ValueError(msg)
        if self.ls(path):
            raise OSError(errno.ENOTEMPTY, "Directory not empty", path)
        self._delete(path)

    def rm(
        self, path: str, recursive: bool = False, maxdepth: int | None = None
    ) -> None:
        """Delete files and, optionally, directories recursively."""
        path = self._strip_protocol(path)
        if recursive and not maxdepth and self.isdir(path):
            self._delete(path)
            return
        super().rm(path, recursive=recursive, maxdepth=maxdepth)

    def copy(
        self,
        path1: str,
        path2: str,
        recursive: bool = False,
        maxdepth: int | None = None,
        on_error: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Copy files and, optionally, directories recursively."""
        path1 = self._strip_protocol(path1)
        path2 = self._strip_protocol(path2)

        if recursive and maxdepth is None and self.isdir(path1):
            self.cp_file(path1, path2)
            return
        if not recursive and self.isdir(path1):
            self.makedirs(path2)
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
        path1: str,
        path2: str,
        recursive: bool = False,
        maxdepth: int | None = None,
        **kwargs: Any,
    ) -> None:
        """Move a file/directory from ``path1`` to ``path2``."""
        path1 = self._strip_protocol(path1)
        path2 = self._strip_protocol(path2)

        if recursive and not maxdepth and self.isdir(path1):
            with _translate_exceptions():
                self.session.move(path1, path2, overwrite=False).raise_for_status()
            return
        if not recursive and self.isdir(path1):
            self.makedirs(path2)
            return

        super().mv(path1, path2, recursive=recursive, maxdepth=maxdepth, **kwargs)

    def _mkdir(self, path: str, exist_ok: bool = False) -> None:
        """Create a collection, translating errors into their fsspec equivalent.

        Distinguishing "parent isn't a directory" from "path already
        exists" from "parent doesn't exist" costs an extra request or two
        on the error path, in exchange for the specific exception type
        fsspec callers generally expect.
        """
        try:
            self.session.mkdir(path)
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
        path = self._strip_protocol(path)
        if create_parents:
            self.makedirs(path, exist_ok=True)
            return
        self._mkdir(path)

    def makedirs(self, path: str, exist_ok: bool = False) -> None:
        """Create a collection and any missing parents."""
        path = self._strip_protocol(path)
        parent = self._parent(path)
        if not ({"", self.root_marker} & {path, parent}) and not self.exists(parent):
            self.makedirs(parent, exist_ok=exist_ok)
        self._mkdir(path, exist_ok=exist_ok)

    def created(self, path: str) -> "datetime | None":
        """Return the ``creationdate`` property."""
        path = self._strip_protocol(path)
        with _translate_exceptions():
            return self.session.created(path)

    def modified(self, path: str) -> "datetime | None":
        """Return the ``getlastmodified`` property."""
        path = self._strip_protocol(path)
        with _translate_exceptions():
            return self.session.modified(path)

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
            # "x": created by the server only if nothing is there (atomic), not
            # by a check here and a write there.
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
        path = self._strip_protocol(path)
        with _translate_exceptions():
            return self.session.etag(path)

    def size(self, path: str) -> "int | None":
        """Return the ``getcontentlength`` property."""
        path = self._strip_protocol(path)
        with _translate_exceptions():
            return self.session.content_length(path)

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
            mode: ``"overwrite"`` (default) or ``"append"``. WebDAV PUT
                always replaces a resource's whole content - there is no
                partial/append upload - so ``"append"`` isn't supported.
            kwargs: Forwarded to :meth:`upload_fileobj`.

        """
        if mode == "append":
            msg = "append mode is not supported (WebDAV PUT always replaces the whole resource)"
            raise NotImplementedError(msg)
        buff = io.BytesIO(value)
        kwargs.setdefault("overwrite", True)
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
        rpath = self._strip_protocol(rpath)
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
            self.session.upload_fileobj(
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
            rpath = self._strip_protocol(rpath)
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

        A local ``lpath`` is written the way :meth:`~webdav.session.Session.download_file`
        writes it: to a temporary file that replaces ``lpath`` only when the download
        is complete, and never through a symlink - a failed download leaves an
        existing ``lpath`` as it was. (Replacing an existing file *is* what
        ``get`` means in fsspec, so ``overwrite`` is on.)
        """
        rpath = self._strip_protocol(rpath)
        if hasattr(lpath, "write"):  # fsspec passes an open file as ``lpath`` too
            outfile = cast("BinaryIO", lpath)
        elif self.isdir(rpath):  # a collection becomes a local directory
            Path(lpath).mkdir(parents=True, exist_ok=True)
            return
        cb = Callback.as_callback(callback)
        with _translate_exceptions():
            size = self.session.info(rpath).size
            if size is not None:
                cb.set_size(size)
            if outfile is not None:
                self.session.download_fileobj(
                    rpath, outfile, callback=cb.relative_update
                )
            else:
                self.session.download_file(
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
        self.fobj = fs.session.open(
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
        """Read up to ``length`` bytes/characters."""
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
            # fs.session.open() may have raised before self.reader was set.
            self.reader.close()
        self.closed = True

    def __reduce_ex__(
        self, protocol: SupportsIndex
    ) -> "tuple[Callable[[ReopenArgs], WebdavFile], ReopenArgs]":
        """Support (re)pickling by reopening the file on restore."""
        return _reopen, ReopenArgs(
            WebdavFile, self.fs, self.path, self.blocksize, self.mode, self.size
        )


class ReopenArgs(NamedTuple):
    """Arguments to reopen a :class:`WebdavFile`, for ``__reduce_ex__``."""

    file: type[WebdavFile]
    fs: WebdavFileSystem
    path: str
    blocksize: int | None
    mode: str
    size: int | None


def _reopen(args: ReopenArgs) -> WebdavFile:
    """Reopen a file when unpickled."""
    return args.file(
        args.fs, args.path, blocksize=args.blocksize, mode=args.mode, size=args.size
    )


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

    def __exit__(self, exc_type: object, *_exc: object) -> None:
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
        """Upload the buffered content - this is where the real PUT happens."""
        self.seek(0)
        with _translate_exceptions():
            self.fs.session.upload_fileobj(
                cast("BinaryIO", self),
                self.path,
                chunk_size=self.blocksize,
                overwrite=not self.exclusive,
            )

    def close(self) -> None:
        """Commit and close."""
        if not self.closed:
            self.commit()
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
