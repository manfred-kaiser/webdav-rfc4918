"""Local file-object utilities."""

import logging
import os
import shutil
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

    Returns ``None`` if the length can't be determined without reading
    (e.g. a pure generator/non-seekable stream) - callers fall back to
    chunked transfer encoding in that case.
    """
    try:
        # An actual file: ask the OS for its size via the file descriptor.
        fd = stream.fileno()
        length = os.fstat(fd).st_size
    except (AttributeError, OSError):
        # Not a real file, but maybe something seekable (e.g. io.BytesIO):
        # seek to the end to find the length, then put the position back.
        try:
            offset = stream.tell()
            length = stream.seek(0, os.SEEK_END)
            stream.seek(offset)
        except (AttributeError, OSError):
            return None

    return length


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
