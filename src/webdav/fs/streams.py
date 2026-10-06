"""Streaming file objects over a session: resumable downloads, and uploads of a known size.

A network hiccup mid-download reopens the connection with a ``Range``
request instead of failing the whole transfer - but only after verifying
the resumed response actually continues from the right byte, of the same
representation, which a server that silently ignores ``Range`` (or that
started serving a different, concurrently-modified version of the
resource) would otherwise let through unnoticed.
"""

import time
from collections.abc import Generator
from contextlib import contextmanager
from http import HTTPStatus
from io import RawIOBase
from typing import TYPE_CHECKING

import requests.exceptions

from webdav.exceptions import ClientError, raise_for_status
from webdav.methods import Method
from webdav.transport.body import iter_body
from webdav.transport.parse_utils import parse_uint

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from typing import Any, Self

    from requests import Response as HTTPResponse
    from typing_extensions import Buffer

    from webdav.session import Session

MAX_RESUME_ATTEMPTS = 5
RESUME_BACKOFF_SECONDS = 1.0


class SizedIterator:
    """A byte-chunk iterator with a known total length, for a non-chunked upload.

    ``requests`` only sends a real ``Content-Length`` for a streamed body
    (instead of falling back to ``Transfer-Encoding: chunked``) when it
    can determine the length itself - via ``len()``/``.len``/``fileno()``,
    see ``requests.utils.super_len()``. A plain generator has none of
    these, so ``requests.PreparedRequest.prepare_body()`` always falls
    back to chunked encoding for one, *regardless* of any
    ``Content-Length`` a caller already put in the headers - it doesn't
    even look. That leaves both headers set on the wire at once (RFC 7230
    forbids this), which was verified, against a real server, to hang the
    connection rather than cleanly reject it.

    Wrapping the generator with a ``.len`` attribute here - the same hook
    ``requests-toolbelt``'s ``StreamingIterator`` uses - lets ``requests``
    determine the real length itself and keep the upload streamed rather
    than either buffering it whole or corrupting the request framing.
    """

    def __init__(self, iterator: "Iterator[bytes]", length: int) -> None:
        """Wrap ``iterator``, advertising ``length`` as its total byte count."""
        self._iterator = iterator
        self.len = length

    def __iter__(self) -> "Iterator[bytes]":
        """Iterate the wrapped chunks."""
        return self._iterator


#: What a resumed download treats as "the connection broke, try again from
#: where we stopped": a timeout, a refused/reset connection, and a body that
#: ends before its declared length or in the middle of a chunk.
_TRANSIENT_ERRORS = (
    requests.exceptions.Timeout,
    requests.exceptions.ConnectionError,
    requests.exceptions.ChunkedEncodingError,
)


def _validate_resumed_response(
    response: "HTTPResponse",
    pos: int,
    etag: str | None,
    last_modified: str | None,
) -> None:
    """Ensure a ranged response actually continues from ``pos``.

    A server that silently ignores the ``Range`` header (returning ``200``
    with the full body instead of ``206`` starting at ``pos``), or that
    serves a different representation of the resource than the one the
    stream started with, would otherwise get spliced into the output with
    no indication that anything went wrong.
    """
    if response.status_code != HTTPStatus.PARTIAL_CONTENT:
        msg = (
            f"expected a 206 Partial Content response resuming at byte "
            f"{pos}, got {response.status_code}"
        )
        raise ClientError(msg)

    content_range = response.headers.get("Content-Range", "")
    if not content_range.startswith(f"bytes {pos}-"):
        msg = f"expected Content-Range starting at byte {pos}, got {content_range!r}"
        raise ClientError(msg)

    new_etag = response.headers.get("ETag")
    if etag and new_etag and new_etag != etag:
        msg = "resource changed during download (ETag mismatch)"
        raise ClientError(msg)

    new_last_modified = response.headers.get("Last-Modified")
    if last_modified and new_last_modified and new_last_modified != last_modified:
        msg = "resource changed during download (Last-Modified mismatch)"
        raise ClientError(msg)


def _get(session: "Session", url: str, pos: int = 0) -> "HTTPResponse":
    """Send a (possibly ranged) streaming GET.

    Always ``Accept-Encoding: identity``: a byte range addresses the
    *encoded* representation, while the bytes counted (and written) are the
    decoded ones - resuming a gzip-encoded body at "byte N" would splice the
    wrong data into the output, and ``Content-Length`` would not be the size
    of the file.
    """
    headers = {"Accept-Encoding": "identity"}
    if pos:
        headers["Range"] = f"bytes={pos}-"
    response = session.request(Method.GET, url, headers=headers, stream=True)
    # A 416 is only meaningful when resuming ("nothing left after pos"); on
    # the first request it is an error like any other, not an empty file.
    if not (pos and response.status_code == HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE):
        try:
            raise_for_status(response)
        except BaseException:
            # The body of an error response is neither wanted nor bounded (this is a
            # stream): give the connection back instead of leaving it checked out until
            # the exception, which holds the response, is garbage collected.
            response.close()
            raise
    return response


def _require_end_of_file(
    response: "HTTPResponse", pos: int, expected: int | None
) -> None:
    """A 416 on a resume means "nothing left after byte ``pos``" - if ``pos`` is the end.

    Anything else (a shorter file now, no total at all) means the download
    stopped short, and calling that a success would hand back a truncated
    file.

    Raises:
        ClientError: The transfer is not complete.

    """
    content_range = response.headers.get("Content-Range", "")
    total = (
        parse_uint(content_range.rpartition("/")[2])
        if content_range.startswith("bytes */")
        else None
    )
    if total is None or total != pos or (expected is not None and expected != pos):
        msg = (
            f"download stopped after {pos} bytes and the server "
            f"reports {content_range or 'no length'!r} - not a complete transfer"
        )
        raise ClientError(msg)


def _complete_length(response: "HTTPResponse") -> int | None:
    """The size of the whole resource, as far as ``response`` says."""
    content_range = response.headers.get("Content-Range", "")
    total = content_range.rpartition("/")[2]
    if content_range.startswith("bytes ") and total != "*":
        return parse_uint(total)
    if response.status_code == HTTPStatus.OK:
        return parse_uint(response.headers.get("Content-Length"))
    return None


def _can_resume(
    session: "Session",
    url: str,
    response: "HTTPResponse",
    etag: str | None,
    last_modified: str | None,
) -> bool:
    """Whether a broken download may be continued with a ``Range`` request.

    The server has to support ranges, and the *original* response has to have
    given a validator (a strong ETag, or Last-Modified): without one, a
    resumed response has no way to be verified as the same representation (see
    ``_validate_resumed_response``), and resuming anyway risks silently
    splicing together two different versions of the resource.
    """
    supports_ranges = (
        response.headers.get("Accept-Ranges") == "bytes"
        or session.features_for(url).supports_ranges
    )
    return bool(supports_ranges and (etag or last_modified))


@contextmanager
def iter_url(
    session: "Session",
    url: str,
    chunk_size: int | None = None,
    pos: int = 0,
) -> "Iterator[tuple[HTTPResponse, Iterator[bytes]]]":
    """Iterate over chunks requested from ``url``, reopening on network failure."""
    read_size = chunk_size or session.chunk_size

    def gen(response: "HTTPResponse") -> Generator[bytes, None, None]:
        nonlocal pos
        etag = response.headers.get("ETag")
        if etag and etag.startswith("W/"):
            # A weak validator says "equivalent", not "the same bytes" - no
            # basis for splicing a resumed range onto what was already written.
            etag = None
        last_modified = response.headers.get("Last-Modified")
        attempts = 0
        expected = _complete_length(response)
        try:
            while True:
                if response.status_code == HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE:
                    _require_end_of_file(response, pos, expected)
                    return

                if pos:
                    _validate_resumed_response(response, pos, etag, last_modified)

                try:
                    for chunk in iter_body(response, read_size):
                        pos += len(chunk)
                        yield chunk
                    if expected is not None and pos != expected:
                        msg = f"download ended after {pos} of {expected} bytes"
                        raise ClientError(msg)
                    break
                except _TRANSIENT_ERRORS:
                    response.close()
                    # Fail closed - surface the original error and let the
                    # caller restart the download fresh - unless this can be
                    # resumed *and* checked (see _can_resume).
                    attempts += 1
                    if attempts > MAX_RESUME_ATTEMPTS or not _can_resume(
                        session, url, response, etag, last_modified
                    ):
                        raise
                    time.sleep(RESUME_BACKOFF_SECONDS * attempts)
                    response = _get(session, url, pos=pos)
        finally:
            response.close()

    response = _get(session, url, pos=pos)
    chunks = gen(response)
    try:
        yield response, chunks
    finally:
        chunks.close()
        response.close()


class IterStream(RawIOBase):
    """A read-only, seekable, streaming file-like object over a GET response."""

    def __init__(
        self,
        session: "Session",
        url: str,
        chunk_size: int | None = None,
        on_chunk: "Callable[[int], Any] | None" = None,
    ) -> None:
        """Set up the stream; the actual request is sent on ``__enter__``.

        ``on_chunk``, if given, is called with the size of each piece as it
        actually arrives over the network - not once per ``chunk_size``
        worth of it, which a slow or stalling server might never deliver.
        """
        super().__init__()
        self.buffer = b""
        self.chunk_size = chunk_size or session.chunk_size
        self.session = session
        self.url = url
        self._loc: int = 0
        self._on_chunk = on_chunk
        self._cm = iter_url(session, self.url, chunk_size=chunk_size)
        self._iterator: Iterator[bytes] | None = None
        self._initial_response: HTTPResponse | None = None

    @property
    def supports_ranges(self) -> bool:
        """Whether the server supports byte-range requests for this resource."""
        response = self._initial_response
        if response and response.headers.get("Accept-Ranges") == "bytes":
            return True
        return self.session.features_for(self.url).supports_ranges

    @property
    def size(self) -> int | None:
        """Size of the resource, from ``Content-Length`` - ``None`` if unknown."""
        assert self._initial_response
        return parse_uint(self._initial_response.headers.get("Content-Length"))

    @property
    def loc(self) -> int:
        """Current stream position."""
        return self._loc

    @loc.setter
    def loc(self, value: int) -> None:
        self._loc = value

    def __enter__(self) -> "Self":
        """Send the initial streaming request."""
        self._initial_response, self._iterator = self._cm.__enter__()
        return self

    def __exit__(self, *args: object) -> None:
        """Close the response."""
        self.close()

    @property
    def encoding(self) -> str | None:
        """Encoding of the response, as detected by ``requests``."""
        assert self._initial_response
        return self._initial_response.encoding

    def close(self) -> None:
        """Close the underlying response, if not already closed."""
        if self._iterator:
            self._cm.__exit__(None, None, None)
        self._iterator = None
        self.buffer = b""

    def seek(self, offset: int, whence: int = 0) -> int:
        """Seek within the stream, re-requesting with ``Range`` if needed."""
        if whence == 0:
            loc = offset
        elif whence == 1:
            if offset >= 0:
                self.read(offset)
                return self.loc
            loc = self.loc + offset
        elif whence == 2:
            if not self.size:
                msg = "cannot seek to the end of file"
                raise ValueError(msg)
            loc = self.size + offset
        else:
            msg = f"invalid whence ({whence}, should be 0, 1 or 2)"
            raise ValueError(msg)
        if loc < 0:
            msg = "Seek before start of file"
            raise ValueError(msg)
        if loc and not self.supports_ranges:
            msg = "server does not support ranges"
            raise ValueError(msg)

        self.close()
        self._cm = iter_url(self.session, self.url, pos=loc, chunk_size=self.chunk_size)
        _, self._iterator = self._cm.__enter__()
        self.loc = loc
        return loc

    def tell(self) -> int:
        """Return the current stream position."""
        return self.loc

    @property
    def closed(self) -> bool:
        """Whether the stream is closed."""
        return self._iterator is None

    def readable(self) -> bool:
        """This stream supports reading."""
        return True

    def seekable(self) -> bool:
        """This stream supports seeking."""
        return True

    def writable(self) -> bool:
        """This stream does not support writing."""
        return False

    def readall(self) -> bytes:
        """Read until EOF."""
        chunks = []
        while chunk := self.read1(-1):
            chunks.append(chunk)
        return b"".join(chunks)

    def read(self, num: int = -1) -> bytes:
        """Read at most ``num`` bytes."""
        if num < 0:
            return self.readall()

        buff = b""
        while len(buff) < num:
            chunk = self.read1(num - len(buff))
            if not chunk:
                break
            buff += chunk
        return buff

    def read1(self, num: int = -1) -> bytes:
        """Read at most once from the underlying iterator."""
        assert self._iterator
        if self.buffer:
            chunk = self.buffer
        else:
            try:
                chunk = next(self._iterator)
            except StopIteration:
                return b""
            if self._on_chunk:
                self._on_chunk(len(chunk))

        if num <= 0:
            output, self.buffer = chunk, b""
        else:
            output, self.buffer = chunk[:num], chunk[num:]

        self.loc += len(output)
        return output

    def readinto(self, sequence: "Buffer") -> int:
        """Read into a pre-allocated buffer."""
        out = memoryview(sequence).cast("B")
        data = self.read(out.nbytes)
        out[: len(data)] = data
        return len(data)

    def readinto1(self, sequence: "Buffer") -> int:
        """Read into a pre-allocated buffer with at most one underlying read."""
        out = memoryview(sequence).cast("B")
        data = self.read1(out.nbytes)
        out[: len(data)] = data
        return len(data)
