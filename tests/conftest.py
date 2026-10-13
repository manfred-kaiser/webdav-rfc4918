"""Shared pytest fixtures: a real WebDAV server + client pointed at it."""

from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.credentials import AUTH
from tests.server import webdav_server
from webdav import FileSystem, Session
from webdav.fsspec import WebdavFileSystem

_PROXY_VARIABLES = (
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
)


@pytest.fixture(autouse=True)
def _no_proxy_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests talk to local servers directly, whatever proxy the machine running them is behind."""
    for name in _PROXY_VARIABLES:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def storage_dir(tmp_path: Path) -> Path:
    """A fresh local directory backing the test WebDAV server."""
    return tmp_path


@pytest.fixture
def server_url(storage_dir: Path) -> Iterator[str]:
    """Run a real WebDAV server (wsgidav) for the duration of a test."""
    # Imported here: tests that only use the scripted/rogue servers do not need it.

    with webdav_server(str(storage_dir)) as url:
        yield url


@pytest.fixture
def client(server_url: str) -> Iterator[Session]:
    """A :class:`Session` authenticated against the test server."""
    with Session(server_url, auth=AUTH) as c:
        yield c


@pytest.fixture
def fs(client: Session) -> FileSystem:
    """A :class:`FileSystem` sharing ``client``'s connection, cookies and locks."""
    return FileSystem.from_session(client)


@pytest.fixture
def ffs(server_url: str) -> Iterator[WebdavFileSystem]:
    """An fsspec file system on the test server."""
    filesystem = WebdavFileSystem(server_url, auth=AUTH)
    yield filesystem
    filesystem.filesystem.close()
