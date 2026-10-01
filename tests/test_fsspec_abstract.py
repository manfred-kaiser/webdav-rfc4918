"""Runs fsspec's own, official conformance test suite against WebdavFileSystem.

Unlike a hand-written set of fsspec tests, this is the same suite real
fsspec-ecosystem backends (s3fs, gcsfs, ...) are expected to pass - see
``fsspec.tests.abstract`` for what each class below actually checks.
"""

import posixpath
from typing import TYPE_CHECKING

import pytest
from fsspec.tests.abstract import (
    AbstractCopyTests,
    AbstractFixtures,
    AbstractGetTests,
    AbstractOpenTests,
    AbstractPipeTests,
    AbstractPutTests,
)

from tests.credentials import AUTH
from webdav.fsspec import WebdavFileSystem

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

# fsspec 2024.12 and 2025.x define the class-scoped fixtures of their own suite as instance
# methods, which pytest 9 warns about; fsspec has fixed that since. Not ours to change.
pytestmark = pytest.mark.filterwarnings(
    "ignore:Class-scoped fixture defined as instance method"
)


class WebdavAbstractFixtures(AbstractFixtures):
    """Supplies the ``fs``/``fs_join``/``fs_path`` fixtures the abstract suite needs.

    Each test gets its own :func:`tests.conftest.server_url` (a fresh WsgiDAV
    instance over a fresh temp directory - see ``tests/conftest.py``), so
    ``fs_path`` is just the root: nothing else has ever written there.
    """

    @pytest.fixture
    def fs(self, server_url: str) -> "Iterator[WebdavFileSystem]":
        """A :class:`~webdav.fsspec.WebdavFileSystem` against a fresh test server."""
        fs = WebdavFileSystem(server_url, auth=AUTH)
        yield fs
        fs.filesystem.close()

    @pytest.fixture
    def fs_join(self) -> "Callable[..., str]":
        """WebDAV paths are always POSIX-style, regardless of the host OS running the tests."""
        return posixpath.join

    @pytest.fixture
    def fs_path(self) -> str:
        """The root of a fresh server: nothing predates a test here.

        Paths start with ``/`` (``WebdavFileSystem.root_marker``), as they do for
        ``LocalFileSystem`` and ``MemoryFileSystem``.
        """
        return "/"


class TestWebdavCopy(AbstractCopyTests, WebdavAbstractFixtures):
    """``fs.copy``/``cp`` conformance, per fsspec's own suite."""


class TestWebdavGet(AbstractGetTests, WebdavAbstractFixtures):
    """``fs.get`` (remote -> local) conformance, per fsspec's own suite."""


class TestWebdavPut(AbstractPutTests, WebdavAbstractFixtures):
    """``fs.put`` (local -> remote) conformance, per fsspec's own suite."""


class TestWebdavPipe(AbstractPipeTests, WebdavAbstractFixtures):
    """``fs.pipe``/``fs.pipe_file`` conformance, per fsspec's own suite."""


class TestWebdavOpen(AbstractOpenTests, WebdavAbstractFixtures):
    """``fs.open`` conformance, per fsspec's own suite."""
