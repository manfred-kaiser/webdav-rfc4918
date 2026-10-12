"""Reading a response body into memory - within a size and a time budget.

``requests`` reads a body with no bound at all: a server that declares (or
just keeps sending) gigabytes, or drips one byte at a time, holds the client
for as long as it likes. Everything here reads a streamed response under
explicit limits instead.
"""

import time
import zlib
from typing import TYPE_CHECKING

import requests
import urllib3.exceptions
import urllib3.response

from webdav._base_exceptions import ClientError
from webdav.methods import Method
from webdav.transport.parse_utils import parse_uint

if TYPE_CHECKING:
    from collections.abc import Iterator

#: Read granularity of :func:`read_bounded`.
_READ_CHUNK = 64 * 1024


def iter_body(
    response: requests.Response, chunk_size: int, *, decode: bool = True
) -> "Iterator[bytes]":
    """Yield a streamed body in whatever pieces arrive, without waiting to fill ``chunk_size``.

    ``iter_content(n)`` blocks until ``n`` bytes have arrived, so a server
    sending one byte just inside the read timeout keeps it waiting for days;
    ``read1`` hands back what is there, up to ``chunk_size``, and gives the
    caller a chance to look at the clock - or run a callback - after every
    read. Used here for :func:`read_bounded`'s own deadline, and by
    :func:`webdav.fs.streams.iter_url` so a caller's progress ``callback``
    fires as data actually arrives rather than once per full chunk.

    ``decode=False`` yields the bytes as they came, whatever ``Content-Encoding`` says. A
    download asks for ``Accept-Encoding: identity``; a server that labels the *stored*
    file anyway (Apache with ``AddEncoding x-gzip .gz``) means the file is the encoded
    bytes: they are what is counted, written and addressed by ``Range``.
    """
    raw = response.raw
    read1 = getattr(raw, "read1", None)
    if not isinstance(raw, urllib3.response.BaseHTTPResponse) or read1 is None:
        # A body that is not urllib3's (a custom adapter's, a test double).
        yield from response.iter_content(chunk_size=chunk_size)
        return
    try:
        while chunk := read1(chunk_size, decode_content=decode):
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
    coding = codings[0].strip().lower() if codings else ""
    inflate = coding in _INFLATED_HERE
    for chunk in iter_body(response, _READ_CHUNK, decode=not inflate):
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
    if inflate:
        body = _inflate(response, body, coding, max_size)
    _set_body(response, body)


#: The codings undone here, under the size limit and with a fallback for a wrong label.
_INFLATED_HERE = frozenset({"gzip", "x-gzip", "deflate"})


def _inflate(
    response: requests.Response, body: bytes, coding: str, max_size: "int | None"
) -> bytes:
    """``body`` undone from ``coding`` - or as it is, when it is not that.

    Apache with ``AddEncoding x-gzip .gz`` puts the encoding of the *file* ``a.gz`` on the
    answer to a PROPFIND or PUT for it, whose body is plain XML or HTML: such a body is
    taken as it came. A real one is inflated up to ``max_size`` (a few kilobytes that inflate
    to gigabytes are stopped, as before).

    Raises:
        ClientError: The inflated body is larger than ``max_size``.

    """
    if not body:
        return body
    windows = (
        (zlib.MAX_WBITS, -zlib.MAX_WBITS)
        if coding == "deflate"
        else (16 + zlib.MAX_WBITS,)
    )
    for bits in windows:
        try:
            inflated = zlib.decompressobj(bits).decompress(
                body, 0 if max_size is None else max_size + 1
            )
        except zlib.error:
            continue
        if max_size is not None and len(inflated) > max_size:
            response.close()
            msg = f"response body exceeds the configured limit of {max_size} bytes"
            raise ClientError(msg)
        return inflated
    return body


def _set_body(response: requests.Response, body: bytes) -> None:
    """Store ``body`` as what ``response.content`` returns (requests has no public way)."""
    # pylint: disable=protected-access
    response._content = body  # noqa: SLF001
    response._content_consumed = True  # type: ignore[attr-defined]  # noqa: SLF001


def content_within(
    response: requests.Response, *, max_size: int, max_time: "float | None" = None
) -> bytes:
    """``response.content``, bounded if the body hasn't been read yet.

    A response whose body :class:`~webdav.session.Session` already read (and
    size-capped, via :func:`read_response`) returns its cached content for
    free. One still streamed (``stream=True``) is read now, under the given
    bound - for a caller that only wants to peek at a small amount of RFC
    4918 detail (an ``<d:error>``/``<d:multistatus>`` body alongside a
    non-207 failure status) without becoming the one place that reads an
    unbounded amount of a hostile server's data into memory. Too large,
    already released (a caller that gave up on a streamed response without
    reading it closes it to free the connection, same as any other closed
    body), or otherwise unreadable (a dropped connection, a decoding error)
    is treated the same as "nothing useful here" - an empty body, never a
    raised exception: the caller already has the real HTTP status to
    report, this is only ever extra detail.
    """
    if getattr(response, "_content_consumed", False):
        return response.content
    if getattr(response.raw, "closed", False):
        return b""
    try:
        read_bounded(response, max_size=max_size, max_time=max_time)
    except (ClientError, requests.exceptions.RequestException):
        return b""
    return response.content


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
        # ``requests`` gives the connection back to the pool when the response
        # is closed but closes the socket's response only if its content was not
        # "consumed" - which setting the body below says it was. Read to the
        # end (nothing is there) first, or the pooled connection is still busy
        # with this response and the next request on it fails.
        if isinstance(response.raw, urllib3.response.BaseHTTPResponse):
            response.raw.drain_conn()
        _set_body(response, b"")
        response.close()
        return
    read_bounded(response, max_size=max_size, max_time=max_time)


__all__ = [
    "content_within",
    "iter_body",
    "read_bounded",
    "read_response",
]
