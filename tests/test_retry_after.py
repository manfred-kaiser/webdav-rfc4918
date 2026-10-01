"""``Retry-After`` (RFC 9110 sec. 10.2.3): waited for when it is reasonable, never when it is not."""

import types
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from typing import TYPE_CHECKING

import pytest

from tests.scripted_server import Reply, Seen, scripted_server
from webdav import Session
from webdav import session as session_module
from webdav.transport import retry as retry_module
from webdav.transport.retry import MAX_RETRY_AFTER

if TYPE_CHECKING:
    from collections.abc import Callable


@pytest.fixture
def sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    waited: list[float] = []
    monkeypatch.setattr(retry_module, "BACKOFF", 0.5)
    monkeypatch.setattr(
        retry_module, "time", types.SimpleNamespace(sleep=waited.append)
    )
    return waited


@pytest.fixture
def redirect_sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Like ``sleeps``, but for the ``time`` reference ``Session._follow_redirects`` waits through.

    ``perf_counter`` is forwarded to the real one (not faked): session.py
    also uses it, unconditionally, to time every response's ``.elapsed``.
    """
    import time as real_time  # noqa: PLC0415

    waited: list[float] = []
    monkeypatch.setattr(
        session_module,
        "time",
        types.SimpleNamespace(sleep=waited.append, perf_counter=real_time.perf_counter),
    )
    return waited


def _answers(*replies: "tuple[int, dict[str, str]]") -> "Callable[[Seen], Reply]":
    pending = list(replies)

    def respond(_seen: Seen) -> Reply:
        status, headers = pending.pop(0) if len(pending) > 1 else pending[0]
        return status, headers, b""

    return respond


def test_a_retry_after_longer_than_the_backoff_is_waited_for(
    sleeps: list[float],
) -> None:
    with scripted_server(_answers((429, {"Retry-After": "7"}), (200, {}))) as (
        url,
        rec,
    ):
        assert Session().get(f"{url}/x").status_code == 200
    assert len(rec.requests) == 2
    assert sleeps == [7.0]


def test_the_backoff_still_applies_when_the_server_asks_for_less(
    sleeps: list[float],
) -> None:
    with scripted_server(_answers((503, {"Retry-After": "0"}), (200, {}))) as (
        url,
        _rec,
    ):
        Session().get(f"{url}/x")
    assert sleeps == [0.5]


def test_a_retry_after_as_an_http_date_is_read(sleeps: list[float]) -> None:
    when = format_datetime(datetime.now(UTC) + timedelta(seconds=10), usegmt=True)
    with scripted_server(_answers((503, {"Retry-After": when}), (200, {}))) as (
        url,
        _rec,
    ):
        Session().get(f"{url}/x")
    assert len(sleeps) == 1
    assert 8 <= sleeps[0] <= 10


@pytest.mark.parametrize("value", ["soon", "-5", "1e3", "", "12345678901234567890"])
def test_a_retry_after_that_makes_no_sense_is_ignored(
    sleeps: list[float], value: str
) -> None:
    with scripted_server(_answers((503, {"Retry-After": value}), (200, {}))) as (
        url,
        _rec,
    ):
        Session().get(f"{url}/x")
    assert sleeps == [0.5]


def test_a_server_cannot_park_the_client_for_longer_than_the_cap(
    sleeps: list[float],
) -> None:
    asked = str(int(MAX_RETRY_AFTER) + 1)
    with scripted_server(_answers((503, {"Retry-After": asked}))) as (url, rec):
        response = Session().get(f"{url}/x")
    assert response.status_code == 503  # handed back, as when the tries run out
    assert len(rec.requests) == 1
    assert sleeps == []


def test_a_write_is_not_retried_whatever_the_server_asks(sleeps: list[float]) -> None:
    with scripted_server(_answers((503, {"Retry-After": "1"}), (200, {}))) as (
        url,
        rec,
    ):
        assert Session().delete(f"{url}/x").status_code == 503
    assert len(rec.requests) == 1
    assert sleeps == []


def test_a_discarded_streamed_response_is_closed_before_the_retry(
    sleeps: list[float], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The 503 from the first attempt is never read or returned - only its
    connection matters, and it must go back to the pool before the next
    attempt, or a server that keeps failing leaks one connection per try."""
    from webdav.response import Response  # noqa: PLC0415

    closed: list[int] = []
    original_close = Response.close

    def tracking_close(self: Response) -> None:
        closed.append(self.status_code)
        original_close(self)

    monkeypatch.setattr(Response, "close", tracking_close)
    with scripted_server(_answers((503, {}), (200, {}))) as (url, rec):
        response = Session().get(f"{url}/x", stream=True)
    assert len(rec.requests) == 2
    assert sleeps == [0.5]
    assert closed == [503]  # the discarded attempt - not the one handed back
    assert response.status_code == 200
    assert response.content == b""  # still readable: not closed by the fix


# ---------------------------------------------------------------------------
# RFC 9110 §10.2.3: "sent with any 3xx response" - redirects, not just retries
# ---------------------------------------------------------------------------


def test_a_retry_after_on_a_redirect_is_waited_for(redirect_sleeps: list[float]) -> None:

    def respond(seen: Seen) -> "tuple[int, dict[str, str], bytes]":
        if seen.path == "/a":
            return 301, {"Location": "/b", "Retry-After": "2"}, b""
        return 200, {}, b"ok"

    with scripted_server(respond) as (url, rec):
        response = Session().get(f"{url}/a")
    assert response.status_code == 200
    assert len(rec.requests) == 2
    assert redirect_sleeps == [2.0]


def test_a_redirects_retry_after_past_the_cap_refuses_the_redirect(
    redirect_sleeps: list[float],
) -> None:

    asked = str(int(MAX_RETRY_AFTER) + 1)

    def respond(seen: Seen) -> "tuple[int, dict[str, str], bytes]":
        if seen.path == "/a":
            return 301, {"Location": "/b", "Retry-After": asked}, b""
        return 200, {}, b"ok"

    with scripted_server(respond) as (url, rec):
        response = Session().get(f"{url}/a")
    assert response.status_code == 301  # handed back unfollowed
    assert len(rec.requests) == 1
    assert redirect_sleeps == []
    assert response.redirect_refusal is not None


def test_a_redirects_retry_after_as_an_http_date_past_the_cap_also_refuses(
    redirect_sleeps: list[float],
) -> None:

    when = format_datetime(
        datetime.now(UTC) + timedelta(seconds=MAX_RETRY_AFTER + 60), usegmt=True
    )

    def respond(seen: Seen) -> "tuple[int, dict[str, str], bytes]":
        if seen.path == "/a":
            return 301, {"Location": "/b", "Retry-After": when}, b""
        return 200, {}, b"ok"

    with scripted_server(respond) as (url, rec):
        response = Session().get(f"{url}/a")
    assert response.status_code == 301
    assert len(rec.requests) == 1
    assert redirect_sleeps == []
