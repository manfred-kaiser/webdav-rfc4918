"""Reading a response body into memory - within a size and a time budget.

``requests`` reads a body with no bound at all: a server that declares (or
just keeps sending) gigabytes, or drips one byte at a time, holds the client
for as long as it likes. Everything here reads a streamed response under
explicit limits instead.
"""

import time
from typing import TYPE_CHECKING

import requests
import urllib3.exceptions
import urllib3.response

from webdav.exceptions import ClientError
from webdav.methods import Method
from webdav.transport.parse_utils import parse_uint

if TYPE_CHECKING:
    from collections.abc import Iterator

#: Read granularity of :func:`read_bounded`.
_READ_CHUNK = 64 * 1024


def iter_body(response: requests.Response, chunk_size: int) -> "Iterator[bytes]":
    """Yield a streamed body in whatever pieces arrive, without waiting to fill ``chunk_size``.

    ``iter_content(n)`` blocks until ``n`` bytes have arrived, so a server
    sending one byte just inside the read timeout keeps it waiting for days;
    ``read1`` hands back what is there, up to ``chunk_size``, and gives the
    caller a chance to look at the clock - or run a callback - after every
    read. Used here for :func:`read_bounded`'s own deadline, and by
    :func:`webdav.fs.streams.iter_url` so a caller's progress ``callback``
    fires as data actually arrives rather than once per full chunk.
    """
    raw = response.raw
    read1 = getattr(raw, "read1", None)
    if not isinstance(raw, urllib3.response.BaseHTTPResponse) or read1 is None:
        # A body that is not urllib3's (a custom adapter's, a test double).
        yield from response.iter_content(chunk_size=chunk_size)
        return
    try:
        while chunk := read1(chunk_size, decode_content=True):
            yield chunk
    except urllib3.exceptions.ProtocolError as exc:
        raise requests.exceptions.ChunkedEncodingError(exc, response=response) from exc
    except urllib3.exceptions.DecodeError as exc:
        raise requests.exceptions.ContentDecodingError(exc) from exc
    except urllib3.exceptions.ReadTimeoutError as exc:
        raise requests.exceptions.ConnectionError(exc, response=response) from exc
    except urllib3.exceptions.SSLError as exc:
        raise requests.exceptions.SSLError(exc, response=response) from exc


def read_bounded(
    response: requests.Response,
    *,
    max_size: "int | None",
    max_time: "float | None",
) -> None:
    """Read the body of a streamed ``response`` into memory - within a size and a time budget.

    Counts the bytes *after* decoding (``Content-Encoding``), so a small
    gzip body that inflates to gigabytes is stopped as surely as a chunked
    response that never ends; a declared ``Content-Length`` over the cap
    is rejected without reading anything. ``max_time`` is a deadline for the
    *whole* body: the timeouts of ``requests`` apply to each single read, so
    on their own they let a server that drips one byte at a time keep a
    request alive indefinitely. ``None`` for either means no limit - which
    therefore has to be asked for: both limits are required arguments.

    Raises:
        ClientError: The body is larger than ``max_size`` or takes longer
            than ``max_time`` seconds.

    """
    if max_size is None and max_time is None:
        _ = response.content
        return
    codings = [
        c for c in response.headers.get("Content-Encoding", "").split(",") if c.strip()
    ]
    if len(codings) > 1:
        # ``gzip, gzip, gzip``: each layer multiplies what a few kilobytes
        # inflate to, and (before urllib3 2.6) is undone in one piece before
        # the size cap can look at it. No legitimate server stacks codings.
        response.close()
        msg = f"refusing a response with stacked content-codings ({', '.join(c.strip() for c in codings)})"
        raise ClientError(msg)
    declared = parse_uint(response.headers.get("Content-Length"))
    if max_size is not None and declared is not None and declared > max_size:
        response.close()
        msg = (
            f"response declared Content-Length {declared} bytes, "
            f"exceeding the configured limit of {max_size} bytes"
        )
        raise ClientError(msg)
    deadline = None if max_time is None else time.monotonic() + max_time
    chunks: list[bytes] = []
    total = 0
    for chunk in iter_body(response, _READ_CHUNK):
        total += len(chunk)
        if max_size is not None and total > max_size:
            response.close()
            msg = f"response body exceeds the configured limit of {max_size} bytes"
            raise ClientError(msg)
        if deadline is not None and time.monotonic() > deadline:
            response.close()
            msg = f"response body did not arrive within the configured time of {max_time} seconds"
            raise ClientError(msg)
        chunks.append(chunk)
    # What ``response.content`` would have stored, minus the unbounded read.
    body = b"".join(chunks)
    _set_body(response, body)


def _set_body(response: requests.Response, body: bytes) -> None:
    """Store ``body`` as what ``response.content`` returns (requests has no public way)."""
    # pylint: disable=protected-access
    response._content = body  # noqa: SLF001
    response._content_consumed = True  # type: ignore[attr-defined]  # noqa: SLF001


def read_response(
    response: requests.Response,
    method: str,
    *,
    max_size: "int | None",
    max_time: "float | None",
) -> None:
    """Read the body of a streamed ``response`` - if it has one - within the size and time budget.

    A ``HEAD`` reply, a ``1xx``/``204``/``304`` carries no body whatever its
    ``Content-Length`` says (the length of what a ``GET`` would have sent):
    nothing is read, and that length is no reason to refuse it.
    """
    status = response.status_code
    if method.upper() == Method.HEAD or status in (204, 304) or 100 <= status < 200:
        _set_body(response, b"")
        response.close()
        return
    read_bounded(response, max_size=max_size, max_time=max_time)


__all__ = ["iter_body", "read_bounded", "read_response"]
