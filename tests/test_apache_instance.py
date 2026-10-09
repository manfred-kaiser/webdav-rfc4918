"""The helpers that start and stop the local Apache instances of the compliance tests."""

import socket
import threading
import time

import pytest

from tests import apache_instance


def _listener() -> socket.socket:
    sock = socket.create_server((apache_instance.HOST, 0))
    sock.listen()
    return sock


def test_a_free_port_is_reported_free_at_once() -> None:
    with _listener() as sock:
        port = sock.getsockname()[1]
    started = time.monotonic()
    apache_instance.wait_until_port_free(port, timeout=5)
    assert time.monotonic() - started < 0.5


def test_a_port_is_waited_for_until_its_listener_is_gone() -> None:
    sock = _listener()
    port = sock.getsockname()[1]
    threading.Timer(0.5, sock.close).start()
    started = time.monotonic()
    apache_instance.wait_until_port_free(port, timeout=5)
    assert 0.4 < time.monotonic() - started < 3


def test_a_port_still_listened_on_is_an_error_naming_it() -> None:
    with _listener() as sock:
        port = sock.getsockname()[1]
        with pytest.raises(RuntimeError, match=f"{port} is still in use"):
            apache_instance.wait_until_port_free(port, timeout=0.3)


def test_a_connection_in_time_wait_does_not_block_the_port() -> None:
    """Apache binds with SO_REUSEADDR, so a closed connection's TIME_WAIT is no reason to wait."""
    with _listener() as sock:
        port = sock.getsockname()[1]
        client = socket.create_connection((apache_instance.HOST, port))
        server_side, _ = sock.accept()
        server_side.close()  # the server closes first: TIME_WAIT is on its port
        client.close()
    started = time.monotonic()
    apache_instance.wait_until_port_free(port, timeout=5)
    assert time.monotonic() - started < 0.5
