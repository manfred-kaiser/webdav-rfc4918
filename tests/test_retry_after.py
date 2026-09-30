"""``Retry-After`` (RFC 9110 sec. 10.2.3): waited for when it is reasonable, never when it is not."""

import types
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from typing import TYPE_CHECKING

import pytest

from tests.scripted_server import Reply, Seen, scripted_server
from webdav import Session
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
