"""Shared pytest fixtures: a real WebDAV server + client pointed at it."""

from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.server import AUTH, webdav_server
from webdav import Client


@pytest.fixture
def storage_dir(tmp_path: Path) -> Path:
    """A fresh local directory backing the test WebDAV server."""
    return tmp_path


@pytest.fixture
def server_url(storage_dir: Path) -> Iterator[str]:
    """Run a real WebDAV server (wsgidav) for the duration of a test."""
    with webdav_server(str(storage_dir)) as url:
        yield url


@pytest.fixture
def client(server_url: str) -> Iterator[Client]:
    """A :class:`Client` authenticated against the test server."""
    with Client(server_url, auth=AUTH) as c:
        yield c
