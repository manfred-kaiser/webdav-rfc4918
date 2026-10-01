"""What the fsspec filesystem does with a path, a resource and an error - apart from fsspec.

Moved out of ``webdav.fsspec`` unchanged: the module is long, and these have nothing to do with
fsspec's classes.
"""

import errno
import posixpath
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from webdav.exceptions import (
    ForbiddenError,
    IsACollectionError,
    IsAResourceError,
    PreconditionFailedError,
    ResourceAlreadyExistsError,
    ResourceNotFoundError,
)
from webdav.resource import Resource


def absolute(name: str) -> str:
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


def is_root(path: str) -> bool:
    """Whether ``path`` names the root of the file system (``/``, ``//``, ``/a/..``, ...)."""
    return posixpath.normpath("/" + path.lstrip("/")) == "/"


def info_of(resource: Resource) -> "dict[str, Any]":
    """A :class:`~webdav.resource.Resource` as fsspec's ``info`` dict (``name``, ``size``, ``type``, ...)."""
    fields = resource.as_dict()
    fields["name"] = absolute(resource.name)
    fields["size"] = fields.pop("size")
    fields["type"] = "directory" if fields.pop("is_dir") else "file"
    return fields


@contextmanager
def translate_exceptions() -> Iterator[None]:
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
