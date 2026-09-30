"""Local file-object utilities."""

import os
from typing import Any


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
