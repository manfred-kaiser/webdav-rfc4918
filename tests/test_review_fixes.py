"""The size and content of an error body that was already read, and the log lines about XML."""

import logging

import pyexpat
import pytest
import requests

from webdav import _xml_guard
from webdav.exceptions import _MAX_ERROR_BODY_SIZE, _parse_error_codes


def _consumed(body: bytes) -> requests.Response:
    response = requests.Response()
    response.status_code = 423
    response._content = body  # noqa: SLF001
    response._content_consumed = True  # type: ignore[attr-defined]  # noqa: SLF001
    return response


def test_an_error_body_within_the_limit_is_read() -> None:
    body = b'<D:error xmlns:D="DAV:"><D:no-conflicting-lock/></D:error>'
    assert _parse_error_codes(_consumed(body)) == {"no-conflicting-lock"}


def test_an_error_body_already_read_but_over_the_limit_is_not_parsed() -> None:
    padding = b"<!--" + b"x" * _MAX_ERROR_BODY_SIZE + b"-->"
    body = b'<D:error xmlns:D="DAV:"><D:no-conflicting-lock/></D:error>' + padding
    assert _parse_error_codes(_consumed(body)) == frozenset()


def test_an_entity_in_an_error_body_is_logged_not_silent(
    caplog: pytest.LogCaptureFixture,
) -> None:
    body = b'<!DOCTYPE e [<!ENTITY a "x">]><D:error xmlns:D="DAV:"><D:no-conflicting-lock/></D:error>'
    with caplog.at_level(logging.WARNING, logger="webdav"):
        assert _parse_error_codes(_consumed(body)) == frozenset()
    assert "declares an entity" in caplog.text
    assert "423" in caplog.text


def test_an_old_expat_is_logged_once(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(pyexpat, "version_info", (2, 6, 0))
    monkeypatch.setattr(pyexpat, "EXPAT_VERSION", "expat_2.6.0")
    _xml_guard._warned.clear()  # noqa: SLF001
    try:
        with caplog.at_level(logging.WARNING, logger="webdav"):
            _xml_guard.check_xml(b"<a/>")
            _xml_guard.check_xml(b"<a/>")
        assert caplog.text.count("expat_2.6.0") == 1
        assert "2.7.2" in caplog.text
    finally:
        _xml_guard._warned.clear()  # noqa: SLF001


def test_a_current_expat_is_not_logged(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(pyexpat, "version_info", (2, 7, 2))
    _xml_guard._warned.clear()  # noqa: SLF001
    with caplog.at_level(logging.WARNING, logger="webdav"):
        _xml_guard.check_xml(b"<a/>")
    assert "expat" not in caplog.text
