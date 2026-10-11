"""Local file-object utilities."""

import logging
import os
import shutil
import stat
from pathlib import Path
from typing import Any

_LOGGER = logging.getLogger("webdav")


def peek_filelike_length(stream: Any) -> int | None:
    """Return a file-like object's length in bytes, without reading it.

    Used to set ``Content-Length`` on an upload instead of falling back to
    chunked transfer encoding. Same technique as ``httpx``'s
    ``peek_filelike_length`` (Copyright (c) Encode OSS Ltd., BSD-3-Clause) -
    reimplemented here stdlib-only so this library doesn't need ``httpx``
    as a dependency just for this one helper.

    This is what is left to read, from the current position - a file object that is
    not at its start has less to send than the file is long.

    Returns ``None`` if the length can't be determined without reading
    (e.g. a pure generator/non-seekable stream, or a pipe, FIFO or character
    device such as ``/dev/stdin``, which has a ``st_size`` of 0 whatever it
    delivers) - callers fall back to chunked transfer encoding in that case.
    """
    try:
        offset: int | None = stream.tell()
    except (AttributeError, OSError):
        offset = None
    try:
        # An actual file: ask the OS for its size via the file descriptor - but only a
        # regular file's size says how much can be read from it.
        status = os.fstat(stream.fileno())
        if not stat.S_ISREG(status.st_mode):
            return None
        length = status.st_size
    except (AttributeError, OSError):
        # Not a real file, but maybe something seekable (e.g. io.BytesIO):
        # seek to the end to find the length, then put the position back.
        if offset is None:
            return None
        try:
            length = stream.seek(0, os.SEEK_END)
            stream.seek(offset)
        except (AttributeError, OSError):
            return None
    return max(length - (offset or 0), 0)


def claim_file(target: Path, flags: int, *, overwrite: bool) -> bool:
    """Create ``target`` empty, exclusively - ``False`` if it is there and may be replaced.

    O_EXCL is atomic on every file system (a hard link is not available on some), and only
    a complete download gets this far, so no half-written file is ever visible. The kernel
    applies the umask when it creates the claim: its mode is the one a new file is meant
    to get, which the finished file is given without anyone reading the umask.
    """
    try:
        os.close(os.open(target, flags, 0o666))
    except FileExistsError:
        if not overwrite:
            raise
        return False
    return True


def copy_mode(source: Path, destination: Path) -> None:
    """Give ``destination`` the permissions of ``source``, where the file system lets it."""
    try:
        shutil.copymode(source, destination)
    except (
        OSError
    ) as exc:  # a file system that refuses chmod (some network/FUSE mounts)
        _LOGGER.debug("could not set the mode of %s: %s", destination, exc)
