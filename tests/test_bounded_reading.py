"""Reading a response body within a size and a time budget - and the deadline around a whole request."""

import io
import time
from typing import TYPE_CHECKING

import pytest
import requests
import urllib3.exceptions
import urllib3.response

from tests.scripted_server import (
    DRIP,
    NO_CONTENT_LENGTH,
    Reply,
    Seen,
    always,
    scripted_server,
)
from webdav import Session
from webdav.exceptions import ClientError
from webdav.session import DEFAULT_MAX_RESPONSE_SIZE
from webdav.transport.body import iter_body, read_bounded

if TYPE_CHECKING:
    from collections.abc import Callable

# ---------------------------------------------------------------------------
# The time budget of read_bounded
# ---------------------------------------------------------------------------


def test_a_body_that_drips_past_the_time_budget_is_cut_off() -> None:
    with scripted_server(always((200, {DRIP: "0.05"}, b"x" * 40))) as (url, _rec):
        session = Session(retry=False)
        prepared = session.prepare_request(requests.Request("GET", f"{url}/slow"))
        response = session.send(prepared, stream=True)
        with pytest.raises(ClientError, match="did not arrive within"):
            read_bounded(response, max_size=None, max_time=0.3)


# ---------------------------------------------------------------------------
# What happens to an error in the middle of a streamed body
# ---------------------------------------------------------------------------


class _FailingRaw(urllib3.response.HTTPResponse):
    """A urllib3 body whose ``read1`` raises ``exc``."""

    def __init__(self, exc: BaseException) -> None:
        super().__init__(body=io.BytesIO(b""), preload_content=False)
        self._exc = exc

    def read1(self, *args: object, **kwargs: object) -> bytes:
        raise self._exc


@pytest.mark.parametrize(
    ("raised", "expected"),
    [
        (
            urllib3.exceptions.ProtocolError("x"),
            requests.exceptions.ChunkedEncodingError,
        ),
        (urllib3.exceptions.DecodeError("x"), requests.exceptions.ContentDecodingError),
        (
            urllib3.exceptions.ReadTimeoutError(None, "http://x/", "x"),  # type: ignore[arg-type]
            requests.exceptions.ConnectionError,
        ),
        (urllib3.exceptions.SSLError("x"), requests.exceptions.SSLError),
    ],
)
def test_a_body_error_surfaces_as_the_matching_requests_error(
    raised: BaseException, expected: type[Exception]
) -> None:
    response = requests.Response()
    response.raw = _FailingRaw(raised)
    with pytest.raises(requests.exceptions.RequestException) as excinfo:
        list(iter_body(response, 65536))
    assert type(excinfo.value) is expected


def test_a_body_that_is_not_urllib3s_is_still_read() -> None:
    response = requests.Response()
    response.raw = io.BytesIO(b"abcdef")
    assert b"".join(iter_body(response, 65536)) == b"abcdef"


# ---------------------------------------------------------------------------
# The deadline around a whole request (Session.request and Session.send)
# ---------------------------------------------------------------------------


def _stalled(seconds: float) -> "Callable[[Seen], Reply]":
    def respond(_seen: Seen) -> Reply:
        time.sleep(seconds)
        return 200, {}, b"late"

    return respond


def test_request_enforces_the_deadline_while_waiting_for_the_answer() -> None:
    with scripted_server(_stalled(1.0)) as (url, _rec):
        session = Session(retry=False)
        session.max_response_time = 0.3
        started = time.monotonic()
        with pytest.raises(ClientError, match="did not complete within"):
            session.get(f"{url}/x")
        assert time.monotonic() - started < 0.9


def test_send_enforces_the_deadline_while_waiting_for_the_answer() -> None:
    with scripted_server(_stalled(1.0)) as (url, _rec):
        session = Session(retry=False)
        session.max_response_time = 0.3
        prepared = session.prepare_request(requests.Request("GET", f"{url}/x"))
        started = time.monotonic()
        with pytest.raises(ClientError, match="did not complete within"):
            session.send(prepared)
        assert time.monotonic() - started < 0.9


def test_send_never_hands_back_a_body_cut_short_by_the_deadline_as_complete() -> None:
    # No Content-Length: a socket shut down mid-body looks like a clean end of data.
    drip = (200, {DRIP: "0.1", NO_CONTENT_LENGTH: ""}, b"x" * 30)
    with scripted_server(always(drip)) as (url, _rec):
        session = Session(retry=False)
        session.max_response_time = 0.5
        prepared = session.prepare_request(requests.Request("GET", f"{url}/x"))
        with pytest.raises(ClientError, match="did not complete within"):
            session.send(prepared)


def test_the_limits_of_read_bounded_have_to_be_asked_for_by_name() -> None:
    response = requests.Response()
    response.raw = io.BytesIO(b"abc")
    with pytest.raises(TypeError):
        read_bounded(response)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        read_bounded(response, 10, 10)  # type: ignore[misc]


@pytest.mark.parametrize("size", [0, -1, 1.5, True, "big"])
def test_a_size_limit_that_is_no_positive_integer_is_refused_when_it_is_set(
    size: object,
) -> None:
    session = Session()
    with pytest.raises(ValueError, match="max_response_size"):
        session.max_response_size = size  # type: ignore[assignment]
    assert session.max_response_size == DEFAULT_MAX_RESPONSE_SIZE


def test_the_size_limit_can_be_lifted_and_set_again() -> None:
    session = Session()
    session.max_response_size = None
    assert session.max_response_size is None
    session.max_response_size = 10
    assert session.max_response_size == 10


@pytest.mark.parametrize("size", [0, -1, 1.5, True, None])
def test_a_chunk_size_that_is_no_positive_integer_is_refused_when_it_is_set(
    size: object,
) -> None:
    session = Session()
    before = session.chunk_size
    with pytest.raises(ValueError, match="chunk_size"):
        session.chunk_size = size  # type: ignore[assignment]
    assert session.chunk_size == before


def test_the_deadline_of_an_outer_block_wins_over_an_inner_one() -> None:
    from webdav.transport.deadline import enforce  # noqa: PLC0415

    started = time.monotonic()
    with pytest.raises(ClientError, match="configured time of 0.2 seconds"):
        with enforce(0.2):
            with enforce(30):
                time.sleep(0.3)
    assert time.monotonic() - started < 5


def test_a_block_without_a_deadline_is_left_alone() -> None:
    from webdav.transport.deadline import enforce  # noqa: PLC0415

    with enforce(None):
        pass
    with pytest.raises(ZeroDivisionError):
        with enforce(None):
            1 / 0  # noqa: B018
