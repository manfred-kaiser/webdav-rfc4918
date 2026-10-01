"""Bounded ranged reads for the fsspec filesystem - the add-on's own, nothing the client uses.

fsspec reads files in blocks it asks for (``_fetch_range(start, end)``) and keeps in a cache.
One block is one ``Range: bytes=start-(end-1)`` request whose response is read to its end, so
the connection goes back to the pool - where a stream that is cut off at every seek (a Parquet
reader seeks all the time, ``cat_file(path, 10, 20)`` is a seek and a read) closes it.
"""

import time
from http import HTTPStatus
from typing import TYPE_CHECKING, NamedTuple

import requests.exceptions

from webdav.exceptions import ClientError, raise_for_status
from webdav.methods import Method

if TYPE_CHECKING:
    from requests import Response as HTTPResponse

    from webdav.session import Session

#: How often a broken connection is tried again, and how long to wait (times the attempt).
MAX_ATTEMPTS = 5
BACKOFF_SECONDS = 1.0

#: A timeout, a refused or reset connection, a body that ends in the middle: the same request
#: can be sent again.
_TRANSIENT_ERRORS = (
    requests.exceptions.Timeout,
    requests.exceptions.ConnectionError,
    requests.exceptions.ChunkedEncodingError,
)


class Validators(NamedTuple):
    """What identifies the representation the first byte range came from."""

    etag: "str | None" = None
    last_modified: "str | None" = None


class RangeRead(NamedTuple):
    """Bytes of one ranged read, and what the server said about the resource."""

    data: bytes
    validators: Validators
    accepts_ranges: bool


#: Nothing known yet about the resource.
UNKNOWN = Validators()


def _read_exactly(response: "HTTPResponse", length: int, chunk_size: int) -> bytes:
    """The body of ``response``, which has to be exactly ``length`` bytes - never more is read."""
    chunks: list[bytes] = []
    received = 0
    for chunk in response.iter_content(chunk_size=chunk_size):
        received += len(chunk)
        if received > length:
            msg = f"the server sent more than the {length} bytes asked for"
            raise ClientError(msg)
        chunks.append(chunk)
    if received != length:
        msg = f"the response ended after {received} of {length} bytes"
        raise ClientError(msg)
    return b"".join(chunks)


def _validate(
    response: "HTTPResponse", start: int, end: int, *, whole: bool, known: Validators
) -> Validators:
    """Check that ``response`` is bytes ``start`` to ``end`` of the representation ``known``.

    A server that ignores ``Range`` answers ``200`` with the whole body - never to be taken
    for the range - and one that serves another version of the resource than the earlier
    reads got would splice the two together unnoticed.

    Returns:
        What the response says identifies its representation - ``known`` where it says nothing.

    """
    if response.status_code == HTTPStatus.PARTIAL_CONTENT:
        content_range = response.headers.get("Content-Range", "")
        if not content_range.startswith(f"bytes {start}-"):
            msg = f"expected Content-Range starting at byte {start}, got {content_range!r}"
            raise ClientError(msg)
    elif not (whole and response.status_code == HTTPStatus.OK):
        msg = (
            f"expected a 206 Partial Content response for bytes {start}-{end - 1}, "
            f"got {response.status_code}"
        )
        raise ClientError(msg)

    etag = response.headers.get("ETag")
    if etag and etag.startswith("W/"):
        # A weak validator says "equivalent", not "the same bytes".
        etag = None
    last_modified = response.headers.get("Last-Modified")
    if known.etag and etag and etag != known.etag:
        msg = "resource changed while it was read (ETag mismatch)"
        raise ClientError(msg)
    if known.last_modified and last_modified and last_modified != known.last_modified:
        msg = "resource changed while it was read (Last-Modified mismatch)"
        raise ClientError(msg)
    return Validators(known.etag or etag, known.last_modified or last_modified)


def fetch_range(
    session: "Session",
    path: str,
    start: int,
    end: int,
    *,
    total: int,
    known: Validators = UNKNOWN,
) -> RangeRead:
    """Bytes ``start`` to ``end`` (exclusive) of the ``total`` bytes at ``path``, in one request.

    A read of the whole file (``start == 0``, ``end >= total``) sends no ``Range`` at all,
    which a server that does not know ranges answers too. A broken connection is tried again
    (the request can be repeated).

    Raises:
        ClientError: The server did not answer with exactly these bytes of this version.
        requests.exceptions.Timeout: The connection still broke after every attempt.
        requests.exceptions.ConnectionError: Likewise.
        requests.exceptions.ChunkedEncodingError: Likewise.

    """
    end = min(end, total)
    if start >= end:
        return RangeRead(b"", known, True)
    whole = start == 0 and end >= total
    headers = {"Accept-Encoding": "identity"}
    if not whole:
        headers["Range"] = f"bytes={start}-{end - 1}"
    attempts = 0
    while True:
        response = session.request(Method.GET, path, headers=headers, stream=True)
        try:
            raise_for_status(response)
            validators = _validate(response, start, end, whole=whole, known=known)
            data = _read_exactly(response, end - start, 65536)
            return RangeRead(
                data,
                validators,
                response.headers.get("Accept-Ranges") == "bytes"
                or response.status_code == HTTPStatus.PARTIAL_CONTENT,
            )
        except _TRANSIENT_ERRORS:
            attempts += 1
            if attempts > MAX_ATTEMPTS:
                raise
            time.sleep(BACKOFF_SECONDS * attempts)
        finally:
            response.close()
